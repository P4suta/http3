%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_HOT_PATH_EVIDENCE_HRL).
-define(HTTP_HOT_PATH_EVIDENCE_HRL, true).
-include("runtime_matrix_evidence.hrl").

hpp_compile() ->
    [begin
        {ok, Module, Bytes, []} = compile:file("scripts/" ++ atom_to_list(Module) ++ ".erl",
            [binary, deterministic, return_errors, return_warnings, {i, "scripts"}]),
        {Module, Bytes}
    end || Module <- [hot_path_profile, hot_path_child]].
hpp_digest(Modules) -> binary:encode_hex(crypto:hash(sha256,
    [[atom_to_binary(Module), 0, Bytes] || {Module, Bytes} <- Modules])).
hpp_count(Value) -> is_integer(Value) andalso Value >= 0 andalso Value =< 9223372036854775807.
hpp_signal_shape(Row, Signal) ->
    try
        true = suite_exact_keys(Row, [id, purpose, module, function, arity,
            minimum_calls, maximum_calls, calls, status]),
        true = lists:all(fun(Key) -> maps:get(Key, Row) =:= maps:get(Key, Signal) end,
            [<<"id">>, <<"purpose">>, <<"module">>, <<"function">>, <<"arity">>,
                <<"minimum_calls">>, <<"maximum_calls">>]),
        Calls = maps:get(<<"calls">>, Row), true = hpp_count(Calls),
        ExpectedStatus = case Calls >= maps:get(<<"minimum_calls">>, Signal) andalso
            Calls =< maps:get(<<"maximum_calls">>, Signal) of true -> <<"Ready">>; false -> <<"Failed">> end,
        ExpectedStatus = maps:get(<<"status">>, Row), true
    catch _:_ -> false end.
hpp_rows_valid(Rows, Signals) ->
    is_list(Rows) andalso length(Rows) =:= length(Signals) andalso
        lists:all(fun({R,S}) -> hpp_signal_shape(R,S) end, lists:zip(Rows, Signals)).
hpp_child_valid(Child, Nonce, Signals) ->
    try
        true = suite_exact_keys(Child, [schema, nonce, status, signals, failure]),
        1 = maps:get(<<"schema">>, Child), Nonce = maps:get(<<"nonce">>, Child),
        case maps:get(<<"status">>, Child) of
            <<"Passed">> -> maps:get(<<"failure">>, Child) =:= null andalso
                hpp_rows_valid(maps:get(<<"signals">>, Child), Signals);
            <<"Failed">> ->
                Failure = maps:get(<<"failure">>, Child),
                true = suite_exact_keys(Failure, [exception_class, classification, phase, results, counters, code_lines]),
                true = lists:member(maps:get(<<"exception_class">>, Failure), [<<"error">>,<<"exit">>,<<"throw">>,<<"unknown">>]),
                true = lists:member(maps:get(<<"classification">>, Failure),
                    [<<"pattern_mismatch">>,<<"unexpected_variant">>,<<"assertion_failed">>,<<"callback_failed">>,
                     <<"invalid_argument">>,<<"invalid_result">>,<<"resource_limit">>,<<"validation_failed">>,<<"deadline_exceeded">>]),
                true = lists:member(maps:get(<<"phase">>, Failure), [0,2,3,4,5,6,7,10,11,12,13,14,15,16]),
                true = hpp_failure_numbers(maps:get(<<"results">>, Failure), 3, 99),
                true = lists:all(fun(C)->lists:member(C,[0,1,2,3,4,5,6,7,8,9,99]) end,maps:get(<<"results">>,Failure)),
                true = hpp_failure_numbers(maps:get(<<"counters">>, Failure), 8, 9223372036854775807),
                Lines = maps:get(<<"code_lines">>, Failure),
                true = hpp_failure_numbers(Lines, 2, 2147483647) andalso length(Lines) =:= 2,
                Rows = maps:get(<<"signals">>, Child), Rows =:= [] orelse hpp_rows_valid(Rows, Signals)
        end
    catch _:_ -> false end.
hpp_failure_numbers(Values, Max, Upper) -> is_list(Values) andalso length(Values) =< Max andalso
    lists:all(fun(V)->hpp_count(V) andalso V =< Upper end,Values).
hpp_execution_valid(Execution, Nonce, Signals, Build, Digest, Runtime) ->
    try
        true = suite_exact_keys(Execution, [nonce, elapsed_ms, deadline_ms, build_identity, runner_sha256,
            execution_environment, child, exit_status, process]),
        Nonce = maps:get(<<"nonce">>, Execution),
        match = re:run(Nonce, <<"^[0-9A-F]{32}$">>, [{capture, none}]),
        120000 = maps:get(<<"deadline_ms">>, Execution),
        Elapsed = maps:get(<<"elapsed_ms">>, Execution), true = hpp_count(Elapsed) andalso Elapsed < 120000,
        Build = maps:get(<<"build_identity">>, Execution), Digest = maps:get(<<"runner_sha256">>, Execution),
        Runtime = maps:get(<<"execution_environment">>, Execution),
        0 = maps:get(<<"exit_status">>, Execution), true = runtime_matrix_process_valid(maps:get(<<"process">>, Execution)),
        Child = maps:get(<<"child">>, Execution),
        true = hpp_child_valid(Child, Nonce, Signals), <<"Passed">> = maps:get(<<"status">>, Child), true
    catch _:_ -> false end.

hpp_execution_files_valid(Execution, Compiled) ->
    try
        Nonce = maps:get(<<"nonce">>,Execution),
        match = re:run(Nonce,<<"^[0-9A-F]{32}$">>,[{capture,none}]),
        Directory = "build/performance/hot-path-runner/" ++ binary_to_list(Nonce),
        Paths = [filename:join(Directory,atom_to_list(M)++".beam") || {M,_} <- Compiled],
        ChildPath = filename:join(Directory,"child.json"),
        true = lists:sort(filelib:wildcard(filename:join(Directory,"*"))) =:= lists:sort([ChildPath|Paths]),
        true = lists:all(fun({{_,Expected},Path}) -> runtime_matrix_read(Path,16777216) =:= Expected end,
            lists:zip(Compiled,Paths)),
        Child = evidence_json_decode(runtime_matrix_read(ChildPath,1048576)),
        Child = maps:get(<<"child">>,Execution), true
    catch _:_ -> false end.
-endif.
