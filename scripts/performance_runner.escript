#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("process_runner.hrl").
-include("performance_execution.hrl").
-include("retained_execution_tests.hrl").

main(["--self-test"]) ->
    try self_test() catch Class:Reason:Stack ->
        io:format(standard_error, "performance self-test failed: ~s~n", [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end;
main(["--invalidate", Mode]) when Mode =:= "benchmark"; Mode =:= "load"; Mode =:= "soak" ->
    Stem = "build/performance/current/" ++ Mode,
    invalidate(Stem, list_to_binary(Mode));
main([ModeText]) when ModeText =:= "benchmark"; ModeText =:= "load"; ModeText =:= "soak" ->
    try execute(list_to_binary(ModeText)) catch Class:Reason:Stack ->
        io:format(standard_error, "performance runner failed: ~s~n", [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end;
main(_) -> halt(2).

execute(Mode) ->
    Stem = "build/performance/current/" ++ binary_to_list(Mode),
    %% Keep direct runner invocation safe as well as the shell task: a new
    %% execution cannot inherit any public artifact from an earlier run.
    ok = invalidate(Stem, Mode),
    Path = Stem ++ "-execution.json", Log = Stem ++ ".log",
    %% invalidate/2 already replaced the old record. Compute identity without
    %% deleting that Failed evidence, so a source-read failure remains visible.
    Identity = evidence_identity(),
    ok = filelib:ensure_dir(Path), ok = file:write_file(Log, <<>>),
    Initial = #{schema => 1, status => <<"Failed">>, mode => Mode, shareable => false,
        evidence_identity => Identity, configured_samples => performance_samples(Mode), completed_samples => 0},
    write(Path, Initial),
    try
        fresh_with_verified_build("http3", fun(Snapshot) ->
            execute_locked(Mode, Stem, Path, Log, Initial, Identity, Snapshot)
        end)
    catch Class:Reason:Stack ->
        Previous = evidence_json_decode(runtime_matrix_read(Path, 1048576)),
        write(Path, Previous#{<<"status">> => <<"Failed">>,
            <<"failure">> => diagnostic_failure_details(Class, Reason, Stack)}),
        erlang:raise(Class, Reason, Stack)
    end.

execute_locked(Mode, Stem, Path, Log, Initial, Identity, Snapshot) ->
    Build = maps:get(report, Snapshot),
    Runner = performance_compile_child(), Deadline = performance_deadline(Mode),
    {Execution, Csv} = performance_run_child(Mode, Runner, Deadline),
    ok = file:write_file(Log, Csv),
    Child = maps:get(child, Execution),
    case maps:is_key(<<"host_start">>, Child) of
        true -> write(Stem ++ "-host-start.json", maps:get(<<"host_start">>, Child)),
                write(Stem ++ "-host-end.json", maps:get(<<"host_end">>, Child));
        false -> ok
    end,
    Report = maps:merge(Initial, Execution#{deadline_ms => Deadline, build_identity => Build,
        execution_environment => execution_runtime(), runner_sha256 => performance_runner_digest(Runner),
        replay_command => <<"escript scripts/performance_runner.escript ", Mode/binary>>}),
    write(Path, Report),
    ok = performance_export_execution(runtime_matrix_json(Report),Runner,Stem),
    FinalSnapshot = fresh_verify_locked("http3"),
    Build = maps:get(report, FinalSnapshot),
    true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
    Final = evidence_complete(Report#{status => <<"Ready">>}, Identity),
    true = performance_execution_valid(runtime_matrix_json(Final), Mode, Identity, Build,
                                        performance_runner_digest(Runner), Csv),
    true = performance_retained_execution_valid(runtime_matrix_json(Final),Runner),
    write(Path, Final),
    io:format("~s: ~B numeric samples retained, child VM exited and build reverified~n",
        [Mode, maps:get(completed_samples, Execution)]).

performance_run_child(Mode, Compiled, Deadline) ->
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Directory = filename:absname("build/performance/runner/" ++ binary_to_list(Nonce)),
    ChildPath = filename:join(Directory, "child.json"), ok = filelib:ensure_dir(ChildPath),
    Loads = [begin
        File = filename:join(Directory, atom_to_list(Module) ++ ".beam"), ok = file:write_file(File, Bytes),
        io_lib:format("(fun()->{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),"
            "{module,~p}=code:load_binary(~p,~0tp,B) end)(),",
            [File, crypto:hash(sha256, Bytes), Module, Module, atom_to_list(Module) ++ ".beam"])
    end || {Module, Bytes} <- Compiled],
    Paths = [Directory | [filename:absname(P) || P <- filelib:wildcard("packages/http3/build/dev/erlang/*/ebin")]],
    Eval = [Loads, io_lib:format("performance_child:run(~0tp,~0tp,~0tp).", [Mode, ChildPath, Nonce])],
    Start = erlang:monotonic_time(millisecond),
    {Exit, Output} = run_child_evaluation(filename:absname("packages/http3"), Paths, lists:flatten(Eval), Deadline),
    Elapsed = erlang:monotonic_time(millisecond) - Start,
    Child = try evidence_json_decode(runtime_matrix_read(ChildPath, 65536)) catch _:_ -> #{} end,
    Safe = case performance_child_valid(Child, Mode, Nonce) of true -> Child; false -> #{invalid_child_schema => true} end,
    ok = write(ChildPath,Safe),
    #{csv := Csv} = performance_filter_csv(output_tail(Output)),
    {#{nonce => Nonce, elapsed_ms => Elapsed, child => Safe, exit_status => Exit,
        completed_samples => performance_csv_samples(Csv, Mode), csv_sha256 => hex(crypto:hash(sha256, Csv)),
        process => maps:without([tail, output_sha256], Output)}, Csv}.

write(Path, Report) -> file:write_file(Path, [json:encode(Report), $\n]).
hex(Bytes) -> binary:encode_hex(Bytes).

invalidate(Stem, Mode) ->
    ok = filelib:ensure_dir(Stem ++ ".json"),
    Failed = #{schema => 4, status => <<"Failed">>, mode => Mode,
               failure => <<"execution_not_completed">>},
    %% Every file collected by CI is made harmless before any self-test,
    %% build, or workload can fail. In particular, never pair a current
    %% Failed JSON record with a previous run's CSV or host snapshots.
    write(Stem ++ ".json", Failed),
    write(Stem ++ "-execution.json", Failed),
    lists:foreach(fun(Path) -> ok = file:write_file(Path, <<>>) end,
        [Stem ++ ".csv", Stem ++ ".log", Stem ++ "-host-start.json",
         Stem ++ "-host-end.json"]),
    case file:delete(Stem ++ "-execution-proof.tar") of
        ok -> ok;
        {error, enoent} -> ok;
        _ -> erlang:error(cannot_invalidate_execution_proof)
    end.

self_test() ->
    ok = invalidation_self_test(),
    Runner = performance_compile_child(),
    {{Empty, <<>>}, AllCompiled} = fixture(Runner, "nil", 30000),
    #{exit_status := 0, completed_samples := 0} = Empty,
    Retained = runtime_matrix_json(Empty),
    false = performance_retained_execution_valid(Retained, Runner),
    retained_execution_self_test(fun() -> performance_retained_execution_valid(Retained, AllCompiled) end,
        performance_execution_paths(Retained, AllCompiled)),
    ok = performance_export_execution(Retained#{<<"mode">> => <<"benchmark">>},AllCompiled,
        "build/diagnostics/performance-bounds/export-self-test"),
    {{Private, <<>>}, _} = fixture(Runner, "erlang:error({badmatch,<<\"private-performance-marker\">>})", 30000),
    1 = maps:get(exit_status, Private),
    true = binary:match(iolist_to_binary(json:encode(Private)), <<"private-performance-marker">>) =:= nomatch,
    {{Stalled, <<>>}, _} = fixture(Runner, "receive never->nil end", 30000),
    124 = maps:get(exit_status, Stalled),
    true = process_deadline_verified(124, maps:get(process, Stalled)),
    {{Flood, <<>>}, _} = fixture(Runner,
        "lists:foreach(fun(_)->io:put_chars(standard_error,binary:copy(<<\"private-performance-marker\">>,65536)) end,lists:seq(1,64)),nil", 30000),
    125 = maps:get(exit_status, Flood),
    true = process_output_limit_verified(125, maps:get(process, Flood)),
    true = maps:get(output_limit_exceeded, maps:get(process, Flood)),
    true = binary:match(iolist_to_binary(json:encode(Flood)), <<"private-performance-marker">>) =:= nomatch,
    io:put_chars("performance runner: empty run cannot supply samples; private failure, stall and flood children joined\n").

invalidation_self_test() ->
    Stem = filename:absname("build/diagnostics/performance-bounds/invalidate-" ++
        binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    Marker = <<"private-stale-performance-marker">>,
    Paths = [Stem ++ ".json", Stem ++ ".csv", Stem ++ ".log",
        Stem ++ "-execution.json", Stem ++ "-execution-proof.tar",
        Stem ++ "-host-start.json", Stem ++ "-host-end.json"],
    ok = filelib:ensure_dir(hd(Paths)),
    lists:foreach(fun(Path) -> ok = file:write_file(Path, Marker) end, Paths),
    ok = invalidate(Stem, <<"benchmark">>),
    Failed = evidence_json_decode(runtime_matrix_read(Stem ++ ".json", 4096)),
    ExecutionFailed = evidence_json_decode(runtime_matrix_read(
        Stem ++ "-execution.json", 4096)),
    <<"Failed">> = maps:get(<<"status">>, Failed),
    <<"Failed">> = maps:get(<<"status">>, ExecutionFailed),
    nomatch = binary:match(iolist_to_binary(json:encode(Failed)), Marker),
    nomatch = binary:match(iolist_to_binary(json:encode(ExecutionFailed)), Marker),
    lists:foreach(fun(Path) -> <<>> = runtime_matrix_read(Path, 0) end,
        [Stem ++ ".csv", Stem ++ ".log", Stem ++ "-host-start.json",
         Stem ++ "-host-end.json"]),
    false = filelib:is_file(Stem ++ "-execution-proof.tar"),
    ok.
fixture(Runner, Body, Deadline) ->
    Fixture = filename:absname("build/diagnostics/performance-bounds/fixture-" ++ binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    Source = filename:join(Fixture, "http3_benchmark.erl"), ok = filelib:ensure_dir(Source),
    Stage = filename:join(Fixture, "entered"),
    Checkpoint = io_lib:format("ok=file:write_file(~0tp,<<1>>,[exclusive]),", [Stage]),
    ok = file:write_file(Source, ["-module(http3_benchmark).\n-export([run/1]).\nrun(_)->", Checkpoint, Body, ".\n"]),
    {ok, http3_benchmark, Bytes, []} = compile:file(Source, [binary, return_errors, return_warnings]),
    AllCompiled = Runner ++ [{http3_benchmark, Bytes}],
    Result = performance_run_child(<<"benchmark">>, AllCompiled, Deadline),
    %% A slow VM bootstrap must not masquerade as having exercised the stalled
    %% callback or flood. The checkpoint precedes the injected behavior, and
    %% does not alter or restart the absolute operation deadline.
    true = (try runtime_matrix_read(Stage, 1) =:= <<1>> catch _:_ -> false end),
    {Result, AllCompiled}.
