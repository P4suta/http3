%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_IDLE_EXECUTION_HRL).
-define(HTTP_PERFORMANCE_IDLE_EXECUTION_HRL, true).
-include("runtime_matrix_evidence.hrl").
-include("performance_idle_evidence.hrl").

idw_deadline() -> 60000.
idw_compile_child() ->
    [begin
        {ok, Module, Bytes, []} = compile:file("scripts/" ++ atom_to_list(Module) ++ ".erl",
            [binary, deterministic, return_errors, return_warnings, {i, "scripts"}]),
        {Module, Bytes}
    end || Module <- [performance_idle_child, performance_idle_instrumentation]].
idw_runner_digest(Compiled) ->
    binary:encode_hex(crypto:hash(sha256,
        [[atom_to_binary(Module), 0, Bytes] || {Module, Bytes} <- Compiled])).

idw_instrumentation_shape(Value) ->
    try
        true = idw_exact_keys(Value, [schema, method, original_beam_sha256,
            instrumented_beam_sha256, select_ast_sha256,
            receive_expression_unchanged, payloads_observed, added_timers]),
        1 = maps:get(<<"schema">>, Value),
        <<"verified_select_ast_scalar_wrapper">> = maps:get(<<"method">>, Value),
        true = maps:get(<<"receive_expression_unchanged">>, Value),
        false = maps:get(<<"payloads_observed">>, Value),
        0 = maps:get(<<"added_timers">>, Value),
        lists:all(fun(Key) ->
            Digest = maps:get(Key, Value), is_binary(Digest) andalso
                re:run(Digest, <<"^[0-9A-F]{64}$">>, [{capture, none}]) =:= match
        end, [<<"original_beam_sha256">>, <<"instrumented_beam_sha256">>, <<"select_ast_sha256">>])
    catch _:_ -> false end.

idw_child_valid(Child, Nonce) ->
    try
        true = idw_exact_keys(Child, [schema, nonce, status, failure, fixture, instrumentation, diagnostics]),
        2 = maps:get(<<"schema">>, Child), Nonce = maps:get(<<"nonce">>, Child),
        Diagnostics = maps:get(<<"diagnostics">>, Child),
        true = Diagnostics =:= null orelse idw_diagnostics_shape(Diagnostics),
        case maps:get(<<"status">>, Child) of
            <<"Passed">> ->
                null = maps:get(<<"failure">>, Child),
                true = idw_diagnostics_complete(Diagnostics),
                true = idw_instrumentation_shape(maps:get(<<"instrumentation">>, Child)),
                idw_fixture_shape(maps:get(<<"fixture">>, Child));
            <<"Failed">> ->
                Fixture = maps:get(<<"fixture">>, Child),
                Instrumentation = maps:get(<<"instrumentation">>, Child),
                true = Fixture =:= null orelse idw_fixture_shape(Fixture),
                true = Instrumentation =:= null orelse idw_instrumentation_shape(Instrumentation),
                true = Fixture =:= null orelse Instrumentation =/= null,
                Failure = maps:get(<<"failure">>, Child),
                idw_exact_keys(Failure, [exception_class, classification, phase, cause]) andalso
                    lists:member(maps:get(<<"phase">>, Failure),
                        [<<"instrumentation_read">>, <<"instrumentation_controls">>,
                         <<"instrumentation_prepare">>, <<"instrumentation_load">>,
                         <<"instrumentation_restore">>, <<"fixture">>, <<"evidence">>, <<"unknown">>]) andalso
                    lists:member(maps:get(<<"cause">>, Failure),
                        [<<"quiescence">>, <<"client_closed_early">>, <<"server_stopped_early">>,
                         <<"periodic_wakeup">>, <<"client_cleanup">>, <<"server_cleanup">>,
                         <<"fixture_operation">>, <<"trace_operation">>, <<"unknown">>]) andalso
                    lists:member(maps:get(<<"exception_class">>, Failure),
                        [<<"error">>, <<"exit">>, <<"throw">>, <<"unknown">>]) andalso
                    lists:member(maps:get(<<"classification">>, Failure),
                        [<<"pattern_mismatch">>, <<"unexpected_variant">>, <<"assertion_failed">>,
                         <<"callback_failed">>, <<"invalid_argument">>, <<"invalid_result">>,
                         <<"resource_limit">>, <<"validation_failed">>, <<"deadline_exceeded">>])
        end
    catch _:_ -> false end.

idw_execution_valid(Report, Identity, Build, Digest, Metadata) ->
    try
        true = idw_exact_keys(Report, [schema, status, shareable, nonce, deadline_ms,
            elapsed_ms, build_identity, runner_sha256, child, exit_status, process,
            replay_command, evidence_identity, execution_environment]),
        1 = maps:get(<<"schema">>, Report), <<"Ready">> = maps:get(<<"status">>, Report),
        false = maps:get(<<"shareable">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Build = maps:get(<<"build_identity">>, Report), Digest = maps:get(<<"runner_sha256">>, Report),
        Runtime = maps:get(<<"runtime">>, maps:get(<<"toolchain">>, Build)),
        Runtime = maps:get(<<"execution_environment">>, Report),
        Deadline = idw_deadline(), Deadline = maps:get(<<"deadline_ms">>, Report),
        Elapsed = maps:get(<<"elapsed_ms">>, Report),
        true = is_integer(Elapsed) andalso Elapsed >= 0 andalso Elapsed < Deadline,
        0 = maps:get(<<"exit_status">>, Report),
        true = runtime_matrix_process_valid(maps:get(<<"process">>, Report)),
        Nonce = maps:get(<<"nonce">>, Report),
        true = is_binary(Nonce) andalso re:run(Nonce, <<"^[0-9A-F]{32}$">>, [{capture, none}]) =:= match,
        Child = maps:get(<<"child">>, Report), true = idw_child_valid(Child, Nonce),
        <<"Passed">> = maps:get(<<"status">>, Child),
        Metadata = maps:get(<<"instrumentation">>, Child),
        true = idw_observer_complete(maps:get(<<"observer">>, maps:get(<<"fixture">>, Child))),
        <<"escript scripts/performance_idle_runner.escript">> = maps:get(<<"replay_command">>, Report),
        true
    catch _:_ -> false end.

idw_expected_instrumentation(Compiled) ->
    {performance_idle_instrumentation, Code} = lists:keyfind(performance_idle_instrumentation, 1, Compiled),
    {module, performance_idle_instrumentation} = code:load_binary(
        performance_idle_instrumentation, "verified-current-instrumenter", Code),
    Original = runtime_matrix_read(
        "packages/http3/build/dev/erlang/gleam_erlang/ebin/gleam_erlang_ffi.beam", 1048576),
    {ok, _, Metadata} = performance_idle_instrumentation:prepare(Original),
    runtime_matrix_json(Metadata).

idw_verify_execution() ->
    Build = fresh_verified_report("http3"),
    Execution = evidence_json_decode(runtime_matrix_read(
        "build/performance/current/idle-wakeup-execution.json", 1048576)),
    Compiled = idw_compile_child(),
    true = idw_execution_valid(Execution, evidence_identity(), Build,
        idw_runner_digest(Compiled), idw_expected_instrumentation(Compiled)),
    true = idw_retained_execution_valid(Execution,Compiled),
    Execution.

idw_execution_paths(Execution,Compiled) ->
    Nonce = maps:get(<<"nonce">>,Execution),
    match = re:run(Nonce,<<"^[0-9A-F]{32}$">>,[{capture,none}]),
    Directory = "build/performance/idle-runner/" ++ binary_to_list(Nonce),
    [filename:join(Directory,"child.json")|
        [filename:join(Directory,atom_to_list(M)++".beam")||{M,_}<-Compiled]].
idw_retained_execution_valid(Execution,Compiled) ->
    try
        [ChildPath|Paths] = idw_execution_paths(Execution,Compiled),
        true = lists:sort(filelib:wildcard(filename:join(filename:dirname(ChildPath),"*")))
            =:= lists:sort([ChildPath|Paths]),
        true = lists:all(fun({{_,Expected},Path})->runtime_matrix_read(Path,16777216)=:=Expected end,
            lists:zip(Compiled,Paths)),
        Child = evidence_json_decode(runtime_matrix_read(ChildPath,1048576)),
        Child = maps:get(<<"child">>,Execution), true
    catch _:_ -> false end.
-endif.
