#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("process_runner.hrl").
-include("performance_idle_execution.hrl").
-include("performance_idle_execution_tests.hrl").
-include("retained_execution_tests.hrl").

main(["--self-test"]) -> guarded(fun self_test/0);
main(["--self-test-diagnostics"]) -> guarded(fun diagnostic_self_test/0);
main(["--invalidate"]) -> guarded(fun() -> invalidate("build/performance/current/idle-wakeup") end);
main([]) -> guarded(fun execute/0);
main(_) -> halt(2).

guarded(Function) ->
    try Function() catch Class:Reason:Stack ->
        io:format(standard_error, "idle runner failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

execute() ->
    Stem = "build/performance/current/idle-wakeup",
    ok = invalidate(Stem),
    %% Preserve the explicit Failed record while source identity is computed.
    Path = Stem ++ "-execution.json", Identity = evidence_identity(),
    ok = filelib:ensure_dir(Path),
    %% Invalidate every prior success before preflight. Raw stdout/stderr are
    %% neither retained nor hashed in any public evidence, including failures.
    Initial = #{schema => 1, status => <<"Failed">>, shareable => false,
        evidence_identity => Identity},
    write(Path, Initial),
    try
        fresh_with_verified_build("http3", fun(Snapshot) ->
            execute_locked(Stem, Path, Initial, Identity, Snapshot)
        end)
    catch Class:Reason:Stack ->
        Previous = evidence_json_decode(runtime_matrix_read(Path, 1048576)),
        write(Path, Previous#{<<"status">> => <<"Failed">>,
            <<"failure">> => diagnostic_failure_details(Class, Reason, Stack)}),
        erlang:raise(Class, Reason, Stack)
    end.

execute_locked(Stem, Path, Initial, Identity, Snapshot) ->
    Build = maps:get(report, Snapshot),
    Compiled = idw_compile_child(), Expected = idw_expected_instrumentation(Compiled),
    Execution = run_idle_child(Compiled, idw_deadline()),
    Report = maps:merge(Initial, Execution#{deadline_ms => idw_deadline(),
        build_identity => Build, runner_sha256 => idw_runner_digest(Compiled),
        execution_environment => execution_runtime(),
        replay_command => <<"escript scripts/performance_idle_runner.escript">>}),
    write(Path, Report),
    FinalSnapshot = fresh_verify_locked("http3"),
    Build = maps:get(report, FinalSnapshot),
    true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
    Final = evidence_complete(Report#{status => <<"Ready">>}, Identity),
    true = idw_execution_valid(runtime_matrix_json(Final), Identity, Build,
        idw_runner_digest(Compiled), Expected),
    true = idw_retained_execution_valid(runtime_matrix_json(Final),Compiled),
    Child = maps:get(child, Execution), Fixture = maps:get(<<"fixture">>, Child),
    write(Stem ++ ".raw.json", Fixture), write(Path, Final),
    io:put_chars("idle workload: typed fixture retained, bounded child exited, source and build reverified\n").

run_idle_child(Compiled, Deadline) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16)),
    Directory = filename:absname("build/performance/idle-runner/" ++ binary_to_list(Nonce)),
    ChildPath = filename:join(Directory, "child.json"), ok = filelib:ensure_dir(ChildPath),
    Loads = [begin
        File = filename:join(Directory, atom_to_list(Module) ++ ".beam"),
        ok = file:write_file(File, Bytes),
        io_lib:format("(fun()->{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),"
            "{module,~p}=code:load_binary(~p,~0tp,B) end)(),",
            [File, crypto:hash(sha256, Bytes), Module, Module, atom_to_list(Module) ++ ".beam"])
    end || {Module, Bytes} <- Compiled],
    Paths = [Directory | [filename:absname(P) ||
        P <- filelib:wildcard("packages/http3/build/dev/erlang/*/ebin")]],
    Eval = [Loads, io_lib:format("performance_idle_child:run(~0tp,~0tp).", [ChildPath, Nonce])],
    Start = erlang:monotonic_time(millisecond),
    {Exit, Output} = run_child_evaluation(filename:absname("packages/http3"), Paths,
        lists:flatten(Eval), Deadline),
    Elapsed = erlang:monotonic_time(millisecond) - Start,
    Child = try evidence_json_decode(runtime_matrix_read(ChildPath, 65536)) catch _:_ -> #{} end,
    Safe = case idw_child_valid(Child, Nonce) of
        true -> Child; false -> #{invalid_child_schema => true}
    end,
    %% Even the private child artifact is replaced with the validated object;
    %% a hostile child cannot leave payloads for later bundle discovery.
    write(ChildPath, Safe),
    #{nonce => Nonce, elapsed_ms => Elapsed, child => Safe, exit_status => Exit,
        process => maps:without([tail, output_sha256], Output)}.

write(Path, Value) -> file:write_file(Path, [json:encode(Value), $\n]).
hex(Bytes) -> binary:encode_hex(Bytes).

invalidate(Stem) ->
    ok = filelib:ensure_dir(Stem ++ ".json"),
    Failed = #{schema => 4, status => <<"Failed">>,
        failure => <<"execution_not_completed">>},
    write(Stem ++ ".json", Failed),
    write(Stem ++ "-execution.json", Failed),
    %% The typed raw fixture and the log are safe only after the new child has
    %% completed. Empty both before any preflight can fail.
    ok = file:write_file(Stem ++ ".raw.json", <<>>),
    ok = file:write_file(Stem ++ ".log", <<>>),
    ok.

self_test() ->
    ok = invalidation_self_test(),
    ok = idw_execution_self_test(),
    ok = diagnostic_self_test(),
    Compiled = idw_compile_child(),
    %% Stub only the workload; the real observer semantic controls and private
    %% child exception boundary execute for every regression.
    {Empty, AllCompiled} = fixture(Compiled, "nil", 30000),
    0 = maps:get(exit_status, Empty),
    #{invalid_child_schema := true} = maps:get(child, Empty),
    Retained = runtime_matrix_json(Empty),
    false = idw_retained_execution_valid(Retained, Compiled),
    retained_execution_self_test(fun() -> idw_retained_execution_valid(Retained, AllCompiled) end,
        idw_execution_paths(Retained, AllCompiled)),
    {Invalid, _} = fixture(Compiled,
        "http3_idle_wakeup_ffi:write(#{private=><<\"idle-private-marker\">>})", 30000),
    #{invalid_child_schema := true} = maps:get(child, Invalid),
    nomatch = binary:match(iolist_to_binary(json:encode(Invalid)), <<"idle-private-marker">>),
    {Private, _} = fixture(Compiled, "erlang:error({badmatch,<<\"idle-private-marker\">>})", 30000),
    1 = maps:get(exit_status, Private),
    nomatch = binary:match(iolist_to_binary(json:encode(Private)), <<"idle-private-marker">>),
    {Stalled, _} = fixture(Compiled, "receive never->nil end", 30000),
    124 = maps:get(exit_status, Stalled),
    true = process_deadline_verified(124, maps:get(process, Stalled)),
    {Flood, _} = fixture(Compiled,
        "lists:foreach(fun(_)->io:put_chars(standard_error,binary:copy(<<\"idle-private-marker\">>,65536)) end,lists:seq(1,64)),nil", 30000),
    125 = maps:get(exit_status, Flood),
    true = maps:get(output_limit_exceeded, maps:get(process, Flood)),
    true = process_output_limit_verified(125, maps:get(process, Flood)),
    nomatch = binary:match(iolist_to_binary(json:encode(Flood)), <<"idle-private-marker">>),
    io:put_chars("idle runner: malformed fixture rejected; private exception, stalled and flooding child VMs reaped\n").

invalidation_self_test() ->
    Stem = filename:absname("build/diagnostics/idle-bounds/invalidate-" ++
        binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    Marker = <<"private-stale-idle-marker">>,
    Paths = [Stem ++ ".json", Stem ++ ".raw.json", Stem ++ ".log",
        Stem ++ "-execution.json"],
    ok = filelib:ensure_dir(hd(Paths)),
    lists:foreach(fun(Path) -> ok = file:write_file(Path, Marker) end, Paths),
    ok = invalidate(Stem),
    Failed = evidence_json_decode(runtime_matrix_read(Stem ++ ".json", 4096)),
    ExecutionFailed = evidence_json_decode(runtime_matrix_read(
        Stem ++ "-execution.json", 4096)),
    <<"Failed">> = maps:get(<<"status">>, Failed),
    <<"Failed">> = maps:get(<<"status">>, ExecutionFailed),
    nomatch = binary:match(iolist_to_binary(json:encode(Failed)), Marker),
    nomatch = binary:match(iolist_to_binary(json:encode(ExecutionFailed)), Marker),
    <<>> = runtime_matrix_read(Stem ++ ".raw.json", 0),
    <<>> = runtime_matrix_read(Stem ++ ".log", 0),
    ok.

diagnostic_self_test() ->
    Compiled = idw_compile_child(),
    Fixture = idw_fixture_test_value(),
    Body = lists:flatten(io_lib:format("http3_idle_wakeup_ffi:write(~0tp),"
        "erlang:error({badmatch,<<\"idle-private-marker\">>})", [Fixture])),
    {Partial, _} = fixture(Compiled, Body, 30000),
    1 = maps:get(exit_status, Partial),
    Child = maps:get(child, Partial),
    %% Once observation has completed, a later cleanup failure must preserve
    %% its safe counters and the already verified instrumentation identity.
    Fixture = maps:get(<<"fixture">>, Child),
    true = idw_instrumentation_shape(maps:get(<<"instrumentation">>, Child)),
    nomatch = binary:match(iolist_to_binary(json:encode(Partial)), <<"idle-private-marker">>),
    {Quiescence, _} = fixture(Compiled,
        "http3_idle_wakeup_ffi:mark_phase(0),http3_idle_wakeup_ffi:mark_phase(8),"
        "http3_idle_wakeup_ffi:quiescence_progress(80,0,99,0,true,false,true),"
        "http3_idle_wakeup_ffi:fail(<<\"transport did not reach bounded quiescence\">>)", 30000),
    1 = maps:get(exit_status, Quiescence),
    QChild = maps:get(child, Quiescence),
    null = maps:get(<<"fixture">>, QChild),
    #{<<"phase">> := <<"fixture">>, <<"cause">> := <<"quiescence">>} = maps:get(<<"failure">>, QChild),
    #{<<"phase">> := 8, <<"quiescence">> := #{<<"sample">> := 80,
        <<"client_bytes_in_flight">> := 99, <<"client_in_recovery">> := true}} = maps:get(<<"diagnostics">>, QChild),
    true = idw_instrumentation_shape(maps:get(<<"instrumentation">>, QChild)),
    io:put_chars("idle failure diagnostics retain completed observation and instrumentation\n").

fixture(Compiled, Body, Deadline) ->
    Directory = filename:absname("build/diagnostics/idle-bounds/"++binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    Source = filename:join(Directory,"http3_idle_wakeup.erl"), Stage = filename:join(Directory,"entered"),
    ok = filelib:ensure_dir(Source),
    ok = file:write_file(Source, ["-module(http3_idle_wakeup).\n-export([main/0]).\nmain()->",
        io_lib:format("ok=file:write_file(~0tp,<<1>>,[exclusive]),",[Stage]), Body, ".\n"]),
    {ok, http3_idle_wakeup, Bytes, []} = compile:file(Source,
        [binary, return_errors, return_warnings]),
    AllCompiled = Compiled ++ [{http3_idle_wakeup, Bytes}],
    Result = run_idle_child(AllCompiled, Deadline),
    true = (try runtime_matrix_read(Stage,1)=:=<<1>> catch _:_ -> false end), {Result, AllCompiled}.
