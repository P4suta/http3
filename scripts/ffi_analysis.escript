#!/usr/bin/env escript
%%! +S 2:2 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("process_runner.hrl").

main(Args) ->
    try run(Args) catch _:_ ->
        io:format(standard_error, "FFI analysis failed; see the bounded phase report~n", []),
        halt(1)
    end.
run(["--self-test"]) -> self_test();
run(["plt", Path]) -> execute(plt, Path, [], 600000);
run(["analyze", Path | Files]) -> execute(analyze, Path, Files, 180000);
run(_) -> error(invalid_arguments).

execute(Phase, Plt, Files, Timeout) ->
    Path = "build/ffi-analysis/" ++ atom_to_list(Phase) ++ ".json",
    ok = filelib:ensure_dir(Path),
    case file:delete(Path) of ok -> ok; {error, enoent} -> ok; _ -> error(old_report) end,
    case Phase of analyze -> true = Files =:= ffi_beams(); plt -> ok end,
    Inputs = input_identity(Files, case Phase of analyze -> [Plt]; _ -> [] end),
    Result = child(Phase, Plt, Files, Timeout),
    Unchanged = Inputs =:= input_identity(Files, case Phase of analyze -> [Plt]; _ -> [] end),
    Passed = maps:get(passed, Result) andalso Unchanged,
    PltHash = case filelib:is_regular(Plt) of true -> digest(Plt); false -> null end,
    Final = Result#{passed => Passed, inputs_unchanged => Unchanged,
                    inputs => Inputs, plt_sha256 => PltHash},
    ok = file:write_file(Path, json:encode(Final), [exclusive]),
    io:format("FFI ~p passed=~p exit=~B joined=~p~n", [Phase, Passed,
        maps:get(exit_status, Final), maps:get(child_exit_observed, maps:get(process, Final))]),
    case Passed of true -> ok; false -> halt(1) end.

child(Phase, Plt, Files, Timeout) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16)),
    Directory = filename:absname("build/ffi-analysis/" ++ binary_to_list(Nonce)),
    Path = filename:join(Directory, "child.json"), ok = filelib:ensure_dir(Path),
    {ok, ffi_analysis_child, Beam, []} = compile:file("scripts/ffi_analysis_child.erl",
        [binary, debug_info, deterministic, return_errors, return_warnings]),
    BeamPath = filename:join(Directory, "ffi_analysis_child.beam"),
    ok = file:write_file(BeamPath, Beam, [exclusive]),
    Evaluation = lists:flatten(io_lib:format(
        "{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),"
        "{module,ffi_analysis_child}=code:load_binary(ffi_analysis_child,~0tp,B),"
        "ffi_analysis_child:run(~p,~0tp,~0tp,~0tp,~0tp).",
        [BeamPath, crypto:hash(sha256, Beam), BeamPath, Phase,
         filename:absname(Plt), [filename:absname(F) || F <- Files], Path, Nonce])),
    {Exit, Output} = run_child_evaluation(filename:absname("."), [], Evaluation, Timeout),
    Child = read_child(Path),
    Valid = valid_child(Child, Phase, Nonce, length(Files)),
    Passed = process_status_verified(Exit, 0, Output) andalso
        process_vm_output_empty(Output)
        andalso Valid andalso maps:get(<<"passed">>, Child),
    Result = #{schema => 1, nonce => Nonce, phase => Phase, passed => Passed,
        exit_status => Exit, deadline_ms => Timeout, analysis_heap_words => 134217728,
        bootstrap_heap_words => 33554432, analysis_heap_includes_shared_binaries => true,
        process => maps:without([tail, output_sha256], Output), child => Child,
        child_valid => Valid, compiler => #{otp => list_to_binary(erlang:system_info(otp_release)),
            erts => list_to_binary(erlang:system_info(version)),
            compile_sha256 => digest(code:which(compile)), child_beam_sha256 => hex(crypto:hash(sha256, Beam))}},
    ok = file:write_file(filename:join(Directory, "execution.json"), json:encode(Result), [exclusive]),
    Result.

valid_child(C, Phase, Nonce, Count) when is_map(C) ->
    try
        true = lists:sort(maps:keys(C)) =:= lists:sort([<<"schema">>, <<"nonce">>,
            <<"phase">>, <<"passed">>, <<"failure">>, <<"module_count">>,
            <<"warning_count">>, <<"warnings">>, <<"memory">>]),
        #{<<"schema">> := 1, <<"nonce">> := Nonce, <<"phase">> := PhaseBytes,
          <<"passed">> := Passed, <<"failure">> := Failure,
          <<"module_count">> := Modules, <<"warning_count">> := Warnings,
          <<"warnings">> := Rows, <<"memory">> := Memory} = C,
        true = PhaseBytes =:= atom_to_binary(Phase), true = is_boolean(Passed),
        true = is_integer(Modules) andalso Modules >= 0 andalso Modules =< Count,
        true = is_list(Rows) andalso length(Rows) =< 4096,
        true = Warnings =:= length(Rows),
        true = lists:member(Failure, [<<"none">>, <<"type_findings">>, <<"analysis_failed">>,
            <<"analysis_worker_failed">>, <<"analysis_worker_killed">>]),
        true = lists:all(fun valid_warning/1, Rows),
        true = valid_memory(Memory),
        case Passed of
            true -> Modules =:= Count andalso Warnings =:= 0 andalso Failure =:= <<"none">>
                andalso maps:get(<<"joined">>, Memory);
            false -> Failure =/= <<"none">>
        end
    catch _:_ -> false end;
valid_child(_, _, _, _) -> false.
valid_warning(Row) ->
    try
        true = lists:sort(maps:keys(Row)) =:= [<<"category">>, <<"column">>, <<"kind">>, <<"line">>, <<"module">>],
        true = lists:all(fun(K) -> B = maps:get(K, Row), is_binary(B) andalso
            byte_size(B) > 0 andalso byte_size(B) =< 128 end,
            [<<"category">>, <<"kind">>, <<"module">>]),
        lists:all(fun(K) -> N = maps:get(K, Row), is_integer(N) andalso N >= 0 andalso
            N =< 1000000 end, [<<"line">>, <<"column">>])
    catch _:_ -> false end.
valid_memory(M) ->
    try
        true = lists:sort(maps:keys(M)) =:= lists:sort([<<"sampled">>, <<"interval_ms">>,
            <<"samples">>, <<"vm_total_peak_bytes">>, <<"largest_process_peak_bytes">>,
            <<"process_count_peak">>, <<"joined">>]),
        true = maps:get(<<"sampled">>, M), 200 = maps:get(<<"interval_ms">>, M),
        true = is_boolean(maps:get(<<"joined">>, M)),
        lists:all(fun(K) -> N = maps:get(K, M), is_integer(N) andalso N > 0 andalso
            N =< 9223372036854775807 end, [<<"samples">>, <<"vm_total_peak_bytes">>,
                <<"largest_process_peak_bytes">>, <<"process_count_peak">>])
    catch _:_ -> false end.
read_child(Path) ->
    try
        {ok, F} = file:open(Path, [read, binary, raw]),
        try {ok, B} = file:read(F, 2097153), true = byte_size(B) =< 2097152,
            eof = file:read(F, 1), json:decode(B)
        after file:close(F) end
    catch _:_ -> null end.

ffi_sources() ->
    {ok, B} = file:read_file("qualification.json"),
    #{<<"ffi_inventory">> := #{<<"schema">> := 1, <<"sources">> := S}} = json:decode(B),
    true = S =:= lists:usort(S), true = length(S) > 0 andalso length(S) =< 128,
    Paths = [binary_to_list(P) || P <- S],
    Actual = lists:sort(lists:append([filelib:fold_files(Root, ".*\\.erl$", true,
        fun(P, A) -> [lists:flatten(string:replace(P, "\\", "/", all)) | A] end, []) ||
        Root <- ["src", "packages/http3/src", "packages/quic_core/src"]])),
    true = Actual =:= Paths, Paths.
ffi_beams() -> [beam_path(S) || S <- ffi_sources()].
beam_path("packages/http3/src/" ++ Name) -> "build/dev/erlang/http3/ebin/" ++ filename:rootname(Name) ++ ".beam";
beam_path("packages/quic_core/src/" ++ Name) -> "build/dev/erlang/quic_core/ebin/" ++ filename:rootname(Name) ++ ".beam";
beam_path("src/" ++ Name) -> "build/dev/erlang/http/ebin/" ++ filename:rootname(Name) ++ ".beam".
input_identity(Files, Extra) ->
    Paths = lists:usort(ffi_sources() ++ Files ++ Extra ++
        ["qualification.json", "scripts/ffi_analysis.escript", "scripts/ffi_analysis_child.erl",
         "scripts/process_runner.hrl"] ++ filelib:wildcard("src/*.hrl")),
    [#{path => list_to_binary(P), sha256 => digest(P)} || P <- Paths].
digest(Path) -> {ok, B} = file:read_file(Path), hex(crypto:hash(sha256, B)).
hex(B) -> binary:encode_hex(B).

self_test() ->
    Before = process_info(self(), max_heap_size),
    Good = child(control_policy, "unused.plt", [], 10000), true = maps:get(passed, Good),
    Before = process_info(self(), max_heap_size),
    Private = child(control_private, "unused.plt", [], 10000),
    true = maps:get(child_valid, Private), false = maps:get(passed, Private),
    true = maps:get(<<"failure">>, maps:get(child, Private)) =:= <<"analysis_failed">>,
    false = binary:match(iolist_to_binary(json:encode(Private)), <<"ffi-private-control">>) =/= nomatch,
    Killed = child(control_killed, "unused.plt", [], 10000),
    true = maps:get(<<"failure">>, maps:get(child, Killed)) =:= <<"analysis_worker_killed">>,
    Timeout = child(control_timeout, "unused.plt", [], 1000),
    124 = maps:get(exit_status, Timeout), true = maps:get(timed_out, maps:get(process, Timeout)),
    Flood = child(control_flood, "unused.plt", [], 10000),
    125 = maps:get(exit_status, Flood), true = maps:get(output_limit_exceeded, maps:get(process, Flood)),
    false = binary:match(iolist_to_binary(json:encode(Flood)), <<"ffi-private-output">>) =/= nomatch,
    true = lists:all(fun(R) ->
        process_completion_attestation_verified(maps:get(process, R))
    end,
        [Good, Private, Killed, Timeout, Flood]),
    Child = maps:get(child, Good),
    false = valid_child(Child#{<<"unexpected">> => 1}, control_policy, maps:get(nonce, Good), 0),
    false = valid_child(Child, control_policy, <<"old">>, 0),
    false = valid_child(Child#{<<"module_count">> => 1}, control_policy, maps:get(nonce, Good), 0),
    Memory = maps:get(<<"memory">>, Child),
    false = valid_child(Child#{<<"memory">> => Memory#{<<"samples">> => 0}},
        control_policy, maps:get(nonce, Good), 0),
    io:format("FFI analysis controls passed=9 owned_vms_joined=5~n").
