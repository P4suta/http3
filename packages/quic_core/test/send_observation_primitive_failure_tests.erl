%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(send_observation_primitive_failure_tests).
-include_lib("eunit/include/eunit.hrl").

allocation_failure_is_disabled_and_has_no_live_table_test() ->
    Faults = [
        observation_tag,
        observation_ets,
        observation_insert,
        observation_alias
    ],
    ?assert(lists:all(fun(Fault) ->
        Observation = quic_core_send_observation_ffi:new_with_fault(Fault),
        disabled_and_released(Observation) andalso
            not quic_core_send_observation_ffi:available(Observation) andalso
            not quic_core_send_observation_ffi:park(Observation, true) andalso
            not quic_core_send_observation_ffi:publish(
                Observation, {ok, nil}
            ) andalso
            quic_core_send_observation_ffi:await(
                Observation, self(), 0
            ) =:= unavailable
    end, Faults)).

worker_monitor_failure_releases_table_and_alias_test() ->
    Before = monitor_count(),
    Observation = quic_core_send_observation_ffi:new_with_fault(
        await_worker_monitor
    ),
    ?assert(quic_core_send_observation_ffi:available(Observation)),
    ?assert(
        quic_core_send_observation_ffi:await(Observation, self(), 1000)
            =:= unavailable
    ),
    ?assert(released(Observation)),
    ?assert(monitor_count() =:= Before),
    ?assert(not quic_core_send_observation_ffi:publish(
        Observation, {ok, nil}
    )).

owner_monitor_failure_releases_worker_monitor_and_capability_test() ->
    Before = monitor_count(),
    Observation = quic_core_send_observation_ffi:new_with_fault(
        await_owner_monitor
    ),
    ?assert(quic_core_send_observation_ffi:available(Observation)),
    ?assert(
        quic_core_send_observation_ffi:await_with_owner(
            Observation, self(), self(), 1000
        ) =:= unavailable
    ),
    ?assert(released(Observation)),
    ?assert(monitor_count() =:= Before),
    ?assert(not quic_core_send_observation_ffi:park(Observation, false)).

already_released_table_cannot_override_the_typed_result_test() ->
    Before = monitor_count(),
    Observation = quic_core_send_observation_ffi:new(),
    State = maps:get(state, Observation),
    true = ets:delete(State),
    ?assert(
        quic_core_send_observation_ffi:await(Observation, self(), 0)
            =:= unavailable
    ),
    ?assert(released(Observation)),
    ?assert(monitor_count() =:= Before).

invalid_fault_plan_fails_closed_test() ->
    Observation = quic_core_send_observation_ffi:new_with_fault(
        unsupported_primitive
    ),
    ?assert(disabled_and_released(Observation)),
    ?assert(
        quic_core_send_observation_ffi:await(Observation, self(), 0)
            =:= unavailable
    ).

fault_seam_happy_path_mutation_control_test() ->
    Observation = quic_core_send_observation_ffi:new_with_fault(none),
    ?assert(quic_core_send_observation_ffi:available(Observation)),
    ?assert(quic_core_send_observation_ffi:publish(
        Observation, {ok, nil}
    )),
    ?assert(
        quic_core_send_observation_ffi:await(Observation, self(), 0)
            =:= {replied, {ok, nil}}
    ),
    ?assert(released(Observation)).

disabled_and_released(Observation) ->
    quic_core_send_observation_ffi:resource_state(Observation)
        =:= {disabled, released}.

released(Observation) ->
    case quic_core_send_observation_ffi:resource_state(Observation) of
        {enabled, released} -> true;
        {disabled, released} -> true;
        _ -> false
    end.

monitor_count() ->
    case process_info(self(), monitors) of
        {monitors, Monitors} -> length(Monitors);
        _ -> 0
    end.
