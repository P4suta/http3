%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_EXECUTION_HRL).
-define(HTTP_PERFORMANCE_EXECUTION_HRL, true).
-include("runtime_matrix_evidence.hrl").
-include("performance_csv.hrl").
-include("performance_host_evidence.hrl").
-include("performance_failure.hrl").

performance_deadline(<<"benchmark">>) -> 5400000;
performance_deadline(<<"load">>) -> 3600000;
performance_deadline(<<"soak">>) -> 1800000.
performance_samples(<<"benchmark">>) -> 6;
performance_samples(<<"load">>) -> 4;
performance_samples(<<"soak">>) -> 2.
performance_child_valid(Child, Mode, Nonce) ->
    try
        true = suite_exact_keys(Child, [schema, mode, nonce, status, failure, host_start, host_end]),
        1 = maps:get(<<"schema">>, Child), Mode = maps:get(<<"mode">>, Child), Nonce = maps:get(<<"nonce">>, Child),
        HostStart = maps:get(<<"host_start">>, Child), HostEnd = maps:get(<<"host_end">>, Child),
        true = performance_host_valid(HostStart, <<"start">>),
        true = performance_host_valid(HostEnd, <<"end">>),
        true = maps:get(<<"runtime">>, HostStart) =:= maps:get(<<"runtime">>, HostEnd),
        true = maps:get(<<"captured_system_time_milliseconds">>, HostStart) =< maps:get(<<"captured_system_time_milliseconds">>, HostEnd),
        case maps:get(<<"status">>, Child) of
            <<"Passed">> -> maps:get(<<"failure">>, Child) =:= null;
            <<"Failed">> ->
                Failure = maps:get(<<"failure">>, Child),
                suite_exact_keys(Failure, [exception_class, classification, phase, results, counters, code_lines]) andalso
                lists:member(maps:get(<<"phase">>, Failure), [0, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16]) andalso
                performance_failure_list(maps:get(<<"code_lines">>, Failure), 2, 2147483647) andalso
                length(maps:get(<<"code_lines">>, Failure)) =:= 2 andalso
                performance_failure_list(maps:get(<<"results">>, Failure), 3, 99) andalso
                lists:all(fun(Code) -> lists:member(Code, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99]) end,
                    maps:get(<<"results">>, Failure)) andalso
                performance_failure_list(maps:get(<<"counters">>, Failure), 8, 9223372036854775807) andalso
                lists:member(maps:get(<<"exception_class">>, Failure), [<<"error">>, <<"exit">>, <<"throw">>, <<"unknown">>]) andalso
                lists:member(maps:get(<<"classification">>, Failure), [<<"pattern_mismatch">>, <<"unexpected_variant">>,
                    <<"assertion_failed">>, <<"callback_failed">>, <<"invalid_argument">>, <<"invalid_result">>,
                    <<"resource_limit">>, <<"validation_failed">>, <<"deadline_exceeded">>])
        end
    catch _:_ -> false end.
performance_failure_list(Values, Maximum, Upper) ->
    is_list(Values) andalso length(Values) =< Maximum andalso
    lists:all(fun(V) -> is_integer(V) andalso V >= 0 andalso V =< Upper end, Values).
performance_execution_valid(Report, Mode, Identity, Build, RunnerDigest, Csv) ->
    try
        true = suite_exact_keys(Report, [schema, status, shareable, mode, nonce, deadline_ms, elapsed_ms,
            build_identity, runner_sha256, configured_samples, completed_samples, child, exit_status,
            process, csv_sha256, replay_command, evidence_identity, execution_environment]),
        1 = maps:get(<<"schema">>, Report), <<"Ready">> = maps:get(<<"status">>, Report),
        false = maps:get(<<"shareable">>, Report), Mode = maps:get(<<"mode">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report), Build = maps:get(<<"build_identity">>, Report),
        Runtime = maps:get(<<"runtime">>, maps:get(<<"toolchain">>, Build)),
        Runtime = maps:get(<<"execution_environment">>, Report),
        RunnerDigest = maps:get(<<"runner_sha256">>, Report),
        Deadline = performance_deadline(Mode), Deadline = maps:get(<<"deadline_ms">>, Report),
        Elapsed = maps:get(<<"elapsed_ms">>, Report), true = is_integer(Elapsed) andalso Elapsed >= 0 andalso Elapsed < Deadline,
        Samples = performance_samples(Mode), Samples = maps:get(<<"configured_samples">>, Report),
        Samples = maps:get(<<"completed_samples">>, Report),
        0 = maps:get(<<"exit_status">>, Report), true = runtime_matrix_process_valid(maps:get(<<"process">>, Report)),
        Nonce = maps:get(<<"nonce">>, Report),
        true = is_binary(Nonce) andalso re:run(Nonce, <<"^[0-9A-F]{32}$">>, [{capture, none}]) =:= match,
        Child = maps:get(<<"child">>, Report), true = performance_child_valid(Child, Mode, Nonce),
        <<"Passed">> = maps:get(<<"status">>, Child),
        Replay = <<"escript scripts/performance_runner.escript ", Mode/binary>>,
        Replay = maps:get(<<"replay_command">>, Report),
        #{csv := Csv} = performance_filter_csv(Csv),
        Digest = binary:encode_hex(crypto:hash(sha256, Csv)), Digest = maps:get(<<"csv_sha256">>, Report),
        performance_csv_samples(Csv, Mode) =:= Samples
    catch _:_ -> false end.
performance_csv_samples(Csv, Mode) ->
    Lines = binary:split(Csv, <<"\n">>, [global]),
    case length([H || H <- Lines, H =:= ?PERFORMANCE_CSV_HEADER]) of
        1 -> length([Line || Line <- Lines, binary:match(Line, <<Mode/binary, ",">>) =:= {0, byte_size(Mode) + 1}]);
        _ -> 0
    end.
performance_compile_child() ->
    [begin
        {ok, Module, Bytes, []} = compile:file("scripts/" ++ atom_to_list(Module) ++ ".erl",
            [binary, deterministic, return_errors, return_warnings, {i, "scripts"}]), {Module, Bytes}
    end || Module <- [performance_child, performance_host]].
performance_runner_digest(Compiled) ->
    binary:encode_hex(crypto:hash(sha256, [[atom_to_binary(M), 0, B] || {M, B} <- Compiled])).

performance_verify_execution(Mode, Csv) ->
    Build = fresh_verified_report("http3"),
    Path = "build/performance/current/" ++ binary_to_list(Mode) ++ "-execution.json",
    Execution = evidence_json_decode(runtime_matrix_read(Path, 1048576)),
    Compiled = performance_compile_child(), Digest = performance_runner_digest(Compiled),
    true = performance_execution_valid(Execution, Mode, evidence_identity(), Build, Digest, Csv),
    true = performance_retained_execution_valid(Execution,Compiled), Execution.

performance_execution_paths(Execution,Compiled) ->
    Nonce = maps:get(<<"nonce">>,Execution),
    match = re:run(Nonce,<<"^[0-9A-F]{32}$">>,[{capture,none}]),
    Directory = "build/performance/runner/" ++ binary_to_list(Nonce),
    [filename:join(Directory,"child.json")|
        [filename:join(Directory,atom_to_list(M)++".beam")||{M,_}<-Compiled]].
performance_retained_execution_valid(Execution,Compiled) ->
    try
        [ChildPath|Paths] = performance_execution_paths(Execution,Compiled),
        true = lists:sort(filelib:wildcard(filename:join(filename:dirname(ChildPath),"*")))
            =:= lists:sort([ChildPath|Paths]),
        true = lists:all(fun({{_,Expected},Path})->runtime_matrix_read(Path,16777216)=:=Expected end,
            lists:zip(Compiled,Paths)),
        Child = evidence_json_decode(runtime_matrix_read(ChildPath,1048576)),
        Child = maps:get(<<"child">>,Execution), true
    catch _:_ -> false end.

%% Export only the selected execution, including a validated failure. Fixture
%% runs and raw child output must never enter CI's diagnostic artifact glob.
performance_export_execution(Execution,Compiled,Stem) ->
    true = performance_retained_execution_valid(Execution,Compiled),
    Child = maps:get(<<"child">>,Execution),
    Nonce = maps:get(<<"nonce">>,Execution),
    Mode = maps:get(<<"mode">>,Execution),
    true = performance_child_valid(Child,Mode,Nonce) orelse
        Child =:= #{<<"invalid_child_schema">> => true},
    Paths = performance_execution_paths(Execution,Compiled),
    Captured = [{string:replace(Path,"\\","/",all), runtime_matrix_read(Path,16777216)} || Path <- Paths],
    %% Recheck the captured bytes, so a change between inspection and capture
    %% cannot put unvalidated data into the archive.
    [{_,ChildBytes}|BeamEntries] = Captured,
    Child = evidence_json_decode(ChildBytes),
    true = [B || {_,B} <- BeamEntries] =:= [B || {_,B} <- Compiled],
    Entries = [{lists:flatten(Path),Bytes} || {Path,Bytes} <- Captured],
    Archive = Stem ++ "-execution-proof.tar",
    ok = erl_tar:create(Archive,Entries,[]),
    {ok,Entries} = erl_tar:extract(Archive,[memory]),
    ok.
-endif.
