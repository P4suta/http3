%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_SUITE_EVIDENCE_HRL).
-define(HTTP_SUITE_EVIDENCE_HRL, true).
-compile({nowarn_unused_function, [
    {suite_child_valid, 3},
    {suite_child_schema_valid, 3},
    {suite_child_results_valid, 3},
    {suite_attested_child_valid, 5},
    {suite_attested_child_schema_valid, 5},
    {suite_unit_valid, 3},
    {suite_safe_child, 3},
    {suite_safe_attested_child, 5},
    {suite_completed_tests, 1},
    {suite_test_counts, 3},
    {suite_attested_test_counts, 5},
    {suite_test_counts_valid, 1},
    {suite_sha256, 1}
]}).

suite_child_valid(Child, Units, Nonce) ->
    try
        true = suite_child_schema_valid(Child, Units, Nonce),
        true = suite_child_results_valid(Child, Units, Nonce),
        true
    catch _:_ -> false end.

suite_attested_child_valid(Child, Units, Nonce, RunnerSha, InventorySha) ->
    try
        true = suite_attested_child_schema_valid(
            Child, Units, Nonce, RunnerSha, InventorySha),
        true = suite_child_results_valid(Child, Units, Nonce),
        Attestation = maps:get(<<"execution_beam_identity">>, Child),
        true = maps:get(<<"loaded_beams_verified">>, Attestation),
        Count = maps:get(<<"loaded_beam_count">>, Attestation),
        true = Count > 0,
        true
    catch _:_ -> false end.

suite_child_results_valid(Child, Units, Nonce) ->
        Nonce = maps:get(<<"run_nonce">>, Child),
        true = maps:get(<<"listener_completed">>, Child),
        true = maps:get(<<"eunit_completed">>, Child),
        0 = maps:get(<<"unexpected_events">>, Child),
        0 = maps:get(<<"failure_count">>, Child),
        [] = maps:get(<<"failures">>, Child),
        0 = maps:get(<<"failures_dropped">>, Child),
        Rows = maps:get(<<"units">>, Child),
        true = length(Rows) =:= length(Units),
        lists:all(fun({{Id, Unit}, Row}) -> suite_unit_valid(Id, Unit, Row) end,
                  lists:zip(lists:zip(lists:seq(1, length(Units)), Units), Rows)).

suite_unit_valid(Id, Unit, Row) ->
    Id = maps:get(<<"ordinal">>, Row),
    true = lists:all(fun({Key, Value}) -> maps:get(atom_to_binary(Key), Row) =:= Value end,
                     maps:to_list(Unit)),
    Counts = maps:get(<<"counts">>, Row),
    Started = maps:get(<<"started">>, Counts),
    Completed = maps:get(<<"completed">>, Counts),
    Passed = maps:get(<<"passed">>, Counts),
    ExpectedStarts = case maps:get(kind, Unit) of
        <<"test">> -> Started =:= 1;
        <<"generator">> -> Started > 0
    end,
    ExpectedStarts andalso Started =:= Completed andalso Completed =:= Passed andalso
    maps:get(<<"failed">>, Counts) =:= 0 andalso
    maps:get(<<"skipped">>, Counts) =:= 0 andalso
    maps:get(<<"cancelled">>, Counts) =:= 0.

suite_safe_child(Child, Units, Nonce) ->
    case suite_child_schema_valid(Child, Units, Nonce) of
        true -> Child;
        false -> #{invalid => true}
    end.

suite_safe_attested_child(Child, Units, Nonce, RunnerSha, InventorySha) ->
    case suite_attested_child_schema_valid(
             Child, Units, Nonce, RunnerSha, InventorySha) of
        true -> Child;
        false -> #{invalid => true}
    end.

suite_child_schema_valid(Child, Units, Nonce) ->
    try
        true = suite_exact_keys(Child, [schema, run_nonce, listener_completed, eunit_completed,
                                  unexpected_events, units, failure_count, failures, failures_dropped]),
        1 = maps:get(<<"schema">>, Child),
        true = suite_child_payload_schema_valid(Child, Units, Nonce),
        true
    catch _:_ -> false end.

suite_attested_child_schema_valid(Child, Units, Nonce, RunnerSha, InventorySha) ->
    try
        true = suite_exact_keys(Child, [schema, run_nonce, listener_completed,
            eunit_completed, unexpected_events, units, failure_count, failures,
            failures_dropped, execution_beam_identity]),
        2 = maps:get(<<"schema">>, Child),
        true = suite_child_payload_schema_valid(Child, Units, Nonce),
        Attestation = maps:get(<<"execution_beam_identity">>, Child),
        true = suite_exact_keys(Attestation, [runner_sha256,
            expected_inventory_sha256, loaded_beam_sha256,
            loaded_beam_count, loaded_beams_verified]),
        true = suite_sha256(maps:get(<<"runner_sha256">>, Attestation)),
        RunnerSha = maps:get(<<"runner_sha256">>, Attestation),
        true = suite_sha256(maps:get(
            <<"expected_inventory_sha256">>, Attestation)),
        InventorySha = maps:get(<<"expected_inventory_sha256">>, Attestation),
        true = suite_sha256(maps:get(<<"loaded_beam_sha256">>, Attestation)),
        LoadedCount = maps:get(<<"loaded_beam_count">>, Attestation),
        true = is_integer(LoadedCount) andalso LoadedCount >= 0
            andalso LoadedCount =< 20000,
        true = is_boolean(maps:get(<<"loaded_beams_verified">>, Attestation)),
        true
    catch _:_ -> false end.

suite_child_payload_schema_valid(Child, Units, Nonce) ->
    try
        Nonce = maps:get(<<"run_nonce">>, Child),
        true = maps:get(<<"listener_completed">>, Child),
        true = is_boolean(maps:get(<<"eunit_completed">>, Child)),
        true = suite_count_value(maps:get(<<"unexpected_events">>, Child)),
        Failures = maps:get(<<"failures">>, Child),
        true = is_list(Failures) andalso length(Failures) =< 64,
        true = lists:all(fun(Failure) -> suite_failure_schema(Failure, length(Units)) end, Failures),
        FailureCount = maps:get(<<"failure_count">>, Child),
        Dropped = maps:get(<<"failures_dropped">>, Child),
        true = suite_count_value(FailureCount) andalso suite_count_value(Dropped),
        true = FailureCount =:= length(Failures) + Dropped,
        Rows = maps:get(<<"units">>, Child),
        true = is_list(Rows) andalso length(Rows) =:= length(Units),
        lists:all(fun({{Id, Unit}, Row}) -> suite_unit_schema(Id, Unit, Row) end,
                  lists:zip(lists:zip(lists:seq(1, length(Units)), Units), Rows))
    catch _:_ -> false end.

suite_sha256(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    re:run(Value, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
suite_sha256(_) -> false.

suite_unit_schema(Id, Unit, Row) ->
    true = suite_exact_keys(Row, [ordinal, module, function, kind, counts]),
    Id = maps:get(<<"ordinal">>, Row),
    true = lists:all(fun({Key, Value}) -> maps:get(atom_to_binary(Key), Row) =:= Value end,
                     maps:to_list(Unit)),
    Counts = maps:get(<<"counts">>, Row),
    suite_exact_keys(Counts, [started, completed, passed, failed, skipped, cancelled]) andalso
    lists:all(fun suite_count_value/1, maps:values(Counts)).

suite_failure_schema(Failure, UnitCount) ->
    true = suite_exact_keys(Failure, [unit, classification, stack]),
    Id = maps:get(<<"unit">>, Failure),
    true = is_integer(Id) andalso Id >= 0 andalso Id =< UnitCount,
    true = lists:member(maps:get(<<"classification">>, Failure),
        [<<"skipped">>, <<"cancelled">>, <<"invalid_test_status">>,
         <<"worker_killed">>, <<"worker_exit">>, <<"dependency_cancelled">>,
         <<"execution_aborted">>, <<"startup_failed">>,
         <<"pattern_mismatch">>, <<"unexpected_variant">>, <<"assertion_failed">>,
         <<"callback_failed">>, <<"invalid_argument">>, <<"resource_limit">>,
         <<"deadline_exceeded">>, <<"stale_source">>, <<"stale_build">>,
         <<"modified_build">>, <<"validation_failed">>]),
    Stack = maps:get(<<"stack">>, Failure),
    is_list(Stack) andalso length(Stack) =< 16 andalso lists:all(fun suite_frame_schema/1, Stack).

suite_frame_schema(Frame) ->
    true = suite_exact_keys(Frame, [module, function, arity, line]),
    Arity = maps:get(<<"arity">>, Frame),
    Line = maps:get(<<"line">>, Frame),
    suite_safe_identifier(maps:get(<<"module">>, Frame)) andalso
    suite_safe_identifier(maps:get(<<"function">>, Frame)) andalso
    is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255 andalso
    is_integer(Line) andalso Line >= 0 andalso Line =< 2147483647.

suite_safe_identifier(Value) ->
    is_binary(Value) andalso byte_size(Value) =< 128 andalso
    re:run(Value, <<"^[a-zA-Z0-9_@]+$">>, [{capture, none}]) =:= match.

suite_count_value(Value) -> is_integer(Value) andalso Value >= 0 andalso Value =< 2147483647.
suite_exact_keys(Map, Keys) -> is_map(Map) andalso lists:sort(maps:keys(Map)) =:=
    lists:sort([atom_to_binary(Key) || Key <- Keys]).

suite_completed_tests(#{<<"units">> := Rows}) ->
    lists:sum([maps:get(<<"completed">>, maps:get(<<"counts">>, Row)) || Row <- Rows]);
suite_completed_tests(_) -> 0.

suite_test_counts(Child, Units, Nonce) ->
    case suite_child_schema_valid(Child, Units, Nonce) of
        true ->
            Rows = maps:get(<<"units">>, Child),
            #{state => <<"verified">>,
              completed => lists:sum([maps:get(
                  <<"completed">>, maps:get(<<"counts">>, Row)) || Row <- Rows]),
              skipped => lists:sum([maps:get(
                  <<"skipped">>, maps:get(<<"counts">>, Row)) || Row <- Rows])};
        false ->
            #{state => <<"unavailable">>, completed => null, skipped => null}
    end.

suite_attested_test_counts(Child, Units, Nonce, RunnerSha, InventorySha) ->
    case suite_attested_child_schema_valid(
             Child, Units, Nonce, RunnerSha, InventorySha) of
        true ->
            Rows = maps:get(<<"units">>, Child),
            #{state => <<"verified">>,
              completed => lists:sum([maps:get(
                  <<"completed">>, maps:get(<<"counts">>, Row)) || Row <- Rows]),
              skipped => lists:sum([maps:get(
                  <<"skipped">>, maps:get(<<"counts">>, Row)) || Row <- Rows])};
        false ->
            #{state => <<"unavailable">>, completed => null, skipped => null}
    end.

suite_test_counts_valid(#{state := <<"verified">>, completed := Completed,
                          skipped := Skipped}) ->
    suite_count_value(Completed) andalso suite_count_value(Skipped);
suite_test_counts_valid(#{state := <<"unavailable">>, completed := null,
                          skipped := null}) ->
    true;
suite_test_counts_valid(_) ->
    false.
-endif.
