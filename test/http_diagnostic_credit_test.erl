%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_diagnostic_credit_test).
-include_lib("eunit/include/eunit.hrl").

-define(MAXIMUM_SEQUENCE, 9223372036854775807).
-define(DIAGNOSTIC_SEQUENCE, 6).

sequence_transition_refuses_reuse_at_the_signed_atomic_limit_test() ->
    ?assertEqual(
        {accepted, ?MAXIMUM_SEQUENCE},
        http_server_ffi:diagnostic_sequence_transition(?MAXIMUM_SEQUENCE - 1)
    ),
    ?assertEqual(
        exhausted,
        http_server_ffi:diagnostic_sequence_transition(?MAXIMUM_SEQUENCE)
    ),
    ?assertEqual(exhausted, http_server_ffi:diagnostic_sequence_transition(-1)).

sequence_exhaustion_rolls_back_the_reserved_in_flight_credit_test() ->
    {ok, Credit} = http_server_ffi:new_diagnostic_credit(1),
    Counters = diagnostic_counters(Credit),
    atomics:put(Counters, ?DIAGNOSTIC_SEQUENCE, ?MAXIMUM_SEQUENCE),
    ?assertEqual(0, http_server_ffi:diagnostic_reserve(Credit)),
    ?assertEqual({0, 0, 1, 0}, http_server_ffi:diagnostic_snapshot(Credit)).

last_sequence_is_admitted_once_then_every_later_offer_is_dropped_test() ->
    {ok, Credit} = http_server_ffi:new_diagnostic_credit(1),
    Counters = diagnostic_counters(Credit),
    atomics:put(Counters, ?DIAGNOSTIC_SEQUENCE, ?MAXIMUM_SEQUENCE - 1),
    ?assertEqual(?MAXIMUM_SEQUENCE, http_server_ffi:diagnostic_reserve(Credit)),
    nil = http_server_ffi:diagnostic_complete(Credit, true),
    ?assertEqual(0, http_server_ffi:diagnostic_reserve(Credit)),
    ?assertEqual({0, 1, 1, 0}, http_server_ffi:diagnostic_snapshot(Credit)).

failed_delivery_start_returns_its_credit_as_a_drop_test() ->
    {ok, Credit} = http_server_ffi:new_diagnostic_credit(1),
    ?assertEqual(1, http_server_ffi:diagnostic_reserve(Credit)),
    nil = http_server_ffi:diagnostic_abandon(Credit),
    ?assertEqual({0, 0, 1, 0}, http_server_ffi:diagnostic_snapshot(Credit)),
    ?assertEqual(2, http_server_ffi:diagnostic_reserve(Credit)),
    nil = http_server_ffi:diagnostic_complete(Credit, true).

parallel_boundary_reservations_publish_two_unique_sequences_and_drop_rest_test() ->
    {ok, Credit} = http_server_ffi:new_diagnostic_credit(4),
    Counters = diagnostic_counters(Credit),
    atomics:put(Counters, ?DIAGNOSTIC_SEQUENCE, ?MAXIMUM_SEQUENCE - 2),
    Parent = self(), Ref = make_ref(),
    Workers = [spawn_monitor(fun() ->
        Parent ! {Ref, http_server_ffi:diagnostic_reserve(Credit)}
     end)
     || _ <- lists:seq(1, 4)],
    Results = [receive {Ref, Result} -> Result after 1000 -> timeout end
               || _ <- lists:seq(1, 4)],
    Joined = [receive {'DOWN', Monitor, process, Pid, _} -> true
              after 1000 -> false end || {Pid, Monitor} <- Workers],
    lists:foreach(fun({Pid, Monitor}) ->
        exit(Pid, kill), demonitor(Monitor, [flush])
    end, Workers),
    ?assertEqual(
        [0, 0, ?MAXIMUM_SEQUENCE - 1, ?MAXIMUM_SEQUENCE],
        lists:sort(Results)
    ),
    ?assert(lists:all(fun(Confirmed) -> Confirmed end, Joined)),
    nil = http_server_ffi:diagnostic_complete(Credit, true),
    nil = http_server_ffi:diagnostic_complete(Credit, true),
    ?assertEqual({0, 2, 2, 0}, http_server_ffi:diagnostic_snapshot(Credit)).

primitive_creation_failure_is_a_typed_memory_refusal_test() ->
    Failed = fun() -> erlang:error(system_limit) end,
    ?assertEqual(
        {error, nil},
        http_server_ffi:new_diagnostic_credit_with_factory(1, Failed)
    ),
    ?assertEqual(
        {error, nil},
        http_server_ffi:new_diagnostic_credit_with_factory(1, fun() -> invalid end)
    ),
    ?assertEqual(
        {error, nil},
        http_server_ffi:new_diagnostic_credit_with_factory(1, fun make_ref/0)
    ),
    ?assertEqual({error, nil}, http_server_ffi:new_diagnostic_credit(0)).

%% Test-local access never places the opaque runtime reference in an assertion
%% or failure tuple. The catch-all yields an isolated cell whose later scalar
%% assertions fail without disclosing the rejected value.
diagnostic_counters({http_diagnostic_credit, Counters, _Maximum}) -> Counters;
diagnostic_counters(_) -> atomics:new(6, [{signed, true}]).
