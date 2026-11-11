%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_IDLE_EVIDENCE_HRL).
-define(HTTP_PERFORMANCE_IDLE_EVIDENCE_HRL, true).

%% Shape validation precedes diagnostics, hashing and publication. Only these
%% finite scalars can reach the existing semantic counter checks.
idw_fixture_shape(Value) ->
    try
        true = idw_exact_keys(Value, [schema, status, shareable, redacted,
            quiescence_confirmed, quiescence_maximum_attempts,
            quiescence_milliseconds, quiescence_poll_milliseconds,
            quiescence_required_stable_samples, observation_milliseconds,
            minimum_observation_milliseconds, actor_set_stable,
            expected_actor_count, deadline_timeout_returns, unexpected_actor_exits,
            required_actor_liveness, trace_synchronized, trace_primitive, roles, observer]),
        true = idw_observer_shape(maps:get(<<"observer">>, Value)),
        true = lists:member(maps:get(<<"status">>, Value), [<<"Ready">>, <<"Failed">>]),
        <<"gleam_erlang_ffi:select/1,2">> = maps:get(<<"trace_primitive">>, Value),
        true = lists:all(fun(Key) -> is_boolean(maps:get(Key, Value)) end,
            [<<"shareable">>, <<"redacted">>, <<"quiescence_confirmed">>,
             <<"actor_set_stable">>, <<"required_actor_liveness">>, <<"trace_synchronized">>]),
        true = lists:all(fun(Key) -> idw_finite_integer(maps:get(Key, Value)) end,
            [<<"schema">>, <<"quiescence_maximum_attempts">>, <<"quiescence_milliseconds">>,
             <<"quiescence_poll_milliseconds">>, <<"quiescence_required_stable_samples">>,
             <<"observation_milliseconds">>, <<"minimum_observation_milliseconds">>,
             <<"expected_actor_count">>, <<"deadline_timeout_returns">>, <<"unexpected_actor_exits">>]),
        Roles = maps:get(<<"roles">>, Value),
        true = is_list(Roles) andalso length(Roles) =< 8,
        lists:all(fun idw_role_shape/1, Roles)
    catch _:_ -> false end.

idw_role_shape(Role) ->
    try
        Keys = idw_role_numeric_keys(),
        true = lists:sort(maps:keys(Role)) =:= lists:sort([<<"label">> | Keys]),
        true = lists:member(maps:get(<<"label">>, Role), idw_expected_roles()),
        lists:all(fun(Key) -> idw_finite_integer(maps:get(Key, Role)) end, Keys)
    catch _:_ -> false end.

idw_observer_shape(Observer) ->
    try
        true = idw_exact_keys(Observer, [event_limit, events_sent, events_received,
            events_dropped, invalid_events]),
        lists:all(fun(Value) -> is_integer(Value) andalso Value >= 0
            andalso Value =< 2147483647 end, maps:values(Observer))
    catch _:_ -> false end.

idw_observer_complete(Observer) ->
    idw_observer_shape(Observer) andalso
        maps:get(<<"event_limit">>, Observer) =:= 4096 andalso
        maps:get(<<"events_sent">>, Observer) =< 4096 andalso
        maps:get(<<"events_sent">>, Observer) =:= maps:get(<<"events_received">>, Observer) andalso
        maps:get(<<"events_dropped">>, Observer) =:= 0 andalso
        maps:get(<<"invalid_events">>, Observer) =:= 0.

idw_finite_integer(Value) ->
    is_integer(Value) andalso Value >= -2147483647 andalso Value =< 2147483647.

idw_exact_keys(Value, Keys) when is_map(Value) ->
    lists:sort(maps:keys(Value)) =:= lists:sort([atom_to_binary(K) || K <- Keys]);
idw_exact_keys(_, _) -> false.

idw_diagnostics_shape(Value) ->
    try
        true = idw_exact_keys(Value, [schema, phase, elapsed_milliseconds, phases, quiescence, topology]),
        1 = maps:get(<<"schema">>, Value),
        true = idw_phase_number(maps:get(<<"phase">>, Value)),
        true = idw_nonnegative(maps:get(<<"elapsed_milliseconds">>, Value)),
        Phases = maps:get(<<"phases">>, Value), true = is_list(Phases) andalso length(Phases) =< 15,
        Numbers = [maps:get(<<"phase">>, P) || P <- Phases],
        Numbers = lists:usort(Numbers),
        true = lists:all(fun(P) -> idw_exact_keys(P, [phase, elapsed_milliseconds]) andalso
            idw_phase_number(maps:get(<<"phase">>, P)) andalso
            idw_nonnegative(maps:get(<<"elapsed_milliseconds">>, P)) end, Phases),
        Q = maps:get(<<"quiescence">>, Value),
        true = Q =:= null orelse idw_quiescence_shape(Q),
        T = maps:get(<<"topology">>, Value),
        true = T =:= null orelse (is_list(T) andalso length(T) =:= 8 andalso
            [maps:get(<<"label">>, R) || R <- T] =:= idw_expected_roles() andalso
            lists:all(fun(R) -> idw_exact_keys(R, [label, observed]) andalso
                idw_nonnegative(maps:get(<<"observed">>, R)) end, T)),
        true
    catch _:_ -> false end.

idw_quiescence_shape(Q) ->
    try
        true = idw_exact_keys(Q, [sample, stable_samples, client_bytes_in_flight,
            server_bytes_in_flight, client_in_recovery, server_in_recovery, traffic_changed]),
        true = lists:all(fun(K) -> idw_nonnegative(maps:get(K, Q)) end,
            [<<"sample">>, <<"stable_samples">>, <<"client_bytes_in_flight">>, <<"server_bytes_in_flight">>]),
        true = maps:get(<<"sample">>, Q) =< 80 andalso maps:get(<<"stable_samples">>, Q) =< 5,
        lists:all(fun(K) -> is_boolean(maps:get(K, Q)) end,
            [<<"client_in_recovery">>, <<"server_in_recovery">>, <<"traffic_changed">>])
    catch _:_ -> false end.

idw_diagnostics_complete(D) ->
    idw_diagnostics_shape(D) andalso maps:get(<<"phase">>, D) =:= 14 andalso
        [maps:get(<<"phase">>, P) || P <- maps:get(<<"phases">>, D)] =:= lists:seq(0, 14).
idw_phase_number(N) -> is_integer(N) andalso N >= 0 andalso N =< 14.
idw_nonnegative(N) -> is_integer(N) andalso N >= 0 andalso N =< 2147483647.

idw_role_numeric_keys() ->
    [<<"expected_actors">>, <<"actors_start">>, <<"actors_end">>,
     <<"timed_wait_calls">>, <<"timed_message_returns">>,
     <<"timed_boundary_message_returns">>, <<"deadline_timeout_returns">>,
     <<"wait_zero_calls">>, <<"wait_short_calls">>, <<"wait_second_calls">>,
     <<"wait_long_calls">>, <<"timeout_zero_returns">>, <<"timeout_short_returns">>,
     <<"timeout_second_returns">>, <<"timeout_long_returns">>,
     <<"timeout_unclassified_returns">>, <<"unbounded_wait_calls">>,
     <<"unbounded_message_returns">>, <<"unbounded_boundary_message_returns">>].

idw_expected_roles() ->
    [<<"http3.client">>, <<"http3.listener">>, <<"http3.acceptor">>,
     <<"http3.connection">>, <<"quic_core.client">>, <<"quic_core.listener">>,
     <<"quic_core.connection">>, <<"quic_core.udp_relay">>].
-endif.
