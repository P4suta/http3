%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_masque_idle_lifetime_test).
-export([contracts/0, compare_exchange/4, force_idle_deadline_check/1,
         invalidate_idle_timeout/1,
         orphan_idle_wake/1, observe_idle_owner_stopped/1,
         pause_idle_owner/1, resume_idle_owner/1, idle_owner/1]).
-include_lib("eunit/include/eunit.hrl").

-define(PROBE, http_masque_idle_probe).
-define(MAX, 9223372036854775807).

%% Test-only corruption of the private validated clock input. The actual
%% public I/O operation must report the subsequent control failure itself.
invalidate_idle_timeout({udp_proxy_session, _, _, _, _,
                        {some, {udp_proxy_idle_guard, _, State, _, _}}}) ->
    atomics:put(State, 2, ?MAX),
    nil.

%% Exercise the exact production deadline transition after application close.
%% This replaces a wall-clock wait which could only infer that an old timer had
%% fired. The returned values are finite scalar observations; the private idle
%% state and process identities never cross the test boundary.
force_idle_deadline_check({udp_proxy_session, _, _, _, _,
                          {some, {udp_proxy_idle_guard, _, State, _, _}}}) ->
    {PublicState, _Remaining} = http_masque_udp_ffi:idle_due(State, ?MAX),
    Snapshot = http_masque_udp_ffi:idle_snapshot(State),
    {PublicState, element(11, Snapshot), element(12, Snapshot)}.

orphan_idle_wake({udp_proxy_session, _, _, _, _,
                 {some, {udp_proxy_idle_guard, _, State, _, Owner}}}) ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        1 = http_masque_udp_ffi:idle_activity(State, erlang:monotonic_time(millisecond), 1),
        Parent ! {Reference, reserved_without_send},
        receive after 2000 -> error(orphan_worker_not_killed) end
    end),
    try
        receive {Reference, reserved_without_send} -> ok
        after 1000 -> error(wake_credit_not_reserved) end,
        kill_join({Pid, Monitor, Reference}),
        Owner
    after ensure_joined({Pid, Monitor, Reference}) end.

observe_idle_owner_stopped(Owner) ->
    Monitor = monitor(process, Owner),
    receive {'DOWN', Monitor, process, Owner, _} -> true
    after 250 ->
        %% Called only after the public socket/request cleanup has completed.
        %% Reap the old broken fixture so the intended Red leaks no actor.
        exit(Owner, kill),
        receive {'DOWN', Monitor, process, Owner, _} -> false
        after 1000 -> error(idle_owner_not_joined) end
    end.

pause_idle_owner({udp_proxy_session, _, _, _, _,
                 {some, {udp_proxy_idle_guard, _, _, _, Owner}}}) ->
    true = erlang:suspend_process(Owner),
    Owner.

idle_owner({udp_proxy_session, _, _, _, _,
            {some, {udp_proxy_idle_guard, _, _, _, Owner}}}) -> Owner.

resume_idle_owner(Owner) ->
    true = erlang:resume_process(Owner),
    nil.

contracts() ->
    {setup, fun load_probe/0, fun unload_probe/1,
     [fun overflowing_clock_is_rejected_without_poisoning_readers/0,
      fun killed_control_writer_cannot_block_later_operations/0,
      fun delayed_old_activity_never_rolls_back_a_new_deadline/0,
      fun activity_winning_expiry_cas_preserves_the_new_deadline/0,
      fun expiry_winning_activity_cas_remains_terminal/0,
      fun killed_wake_holder_is_rechecked_at_the_old_deadline/0,
      fun contention_budget_is_an_explicit_unavailable_outcome/0,
      fun terminal_outcomes_cannot_be_reclassified_by_bad_activity/0,
      fun invalid_construction_and_malformed_handles_are_finite/0,
      fun directional_saturation_preserves_the_shared_total_ceiling/0,
      fun joined_concurrent_activity_counts_are_exact/0,
      fun duplicate_terminal_signals_have_one_mailbox_slot/0,
      fun join_timeout_does_not_kill_an_owner_doing_cleanup/0,
      fun owner_death_reclaims_the_stop_alias/0,
      fun stopping_does_not_reserve_an_activity_wake/0]}.

overflowing_clock_is_rejected_without_poisoning_readers() ->
    State = ?PROBE:idle_new(100, 0),
    ?assertEqual({ok, 2}, within(fun() -> ?PROBE:idle_activity(State, ?MAX, 1) end)),
    ?assertMatch({ok, {3, _, _, _, _, _, _, _, _, _, _, _}},
                 within(fun() -> ?PROBE:idle_snapshot(State) end)),
    ?assertEqual({ok, {3, 0}}, within(fun() -> ?PROBE:idle_due(State, 100) end)),
    ?assertMatch({ok, _}, within(fun() -> ?PROBE:idle_stop(State) end)).

killed_control_writer_cannot_block_later_operations() ->
    State = ?PROBE:idle_new(100, 0),
    Worker = held(fun() -> ?PROBE:idle_activity(State, 50, 1) end, 'after', 1),
    try
        await_held(Worker),
        kill_join(Worker),
        ?assertMatch({ok, {0, _, _, _, _, _, _, _, _, _, _, _}},
                     within(fun() -> ?PROBE:idle_snapshot(State) end)),
        ?assertEqual({ok, {0, 50}}, within(fun() -> ?PROBE:idle_due(State, 100) end)),
        ?assertMatch({ok, _}, within(fun() -> ?PROBE:idle_stop(State) end)),
        ?assertMatch({ok, {1, _, _, _, _, _, _, _, _, _, _, _}},
                     within(fun() -> ?PROBE:idle_snapshot(State) end))
    after ensure_joined(Worker) end.

delayed_old_activity_never_rolls_back_a_new_deadline() ->
    State = ?PROBE:idle_new(100, 0),
    Worker = held(fun() -> ?PROBE:idle_activity(State, 10, 1) end, before, 1),
    try
        await_held(Worker),
        ?assertMatch({ok, _}, within(fun() -> ?PROBE:idle_activity(State, 200, 2) end)),
        release_join(Worker),
        ?assertMatch({0, 100, 300, _, 2, 1, 1, _, _, _, _, _},
                     ?PROBE:idle_snapshot(State)),
        ?assertEqual({0, 100}, ?PROBE:idle_due(State, 200)),
        _ = ?PROBE:idle_stop(State)
    after ensure_joined(Worker) end.

activity_winning_expiry_cas_preserves_the_new_deadline() ->
    State = ?PROBE:idle_new(100, 0),
    Worker = held(fun() -> ?PROBE:idle_due(State, 100) end, before, 1),
    try
        await_held(Worker),
        ?assertMatch({ok, _}, within(fun() -> ?PROBE:idle_activity(State, 50, 1) end)),
        ?assertEqual({0, 50}, release_join(Worker)),
        _ = ?PROBE:idle_stop(State)
    after ensure_joined(Worker) end.

expiry_winning_activity_cas_remains_terminal() ->
    State = ?PROBE:idle_new(100, 0),
    Worker = held(fun() -> ?PROBE:idle_activity(State, 50, 1) end, before, 1),
    try
        await_held(Worker),
        ?assertEqual({ok, {2, 0}}, within(fun() -> ?PROBE:idle_due(State, 100) end)),
        ?assertEqual(0, release_join(Worker)),
        ?assertMatch({2, _, _, false, 0, 0, 0, _, _, _, 1, 0},
                     ?PROBE:idle_snapshot(State))
    after ensure_joined(Worker) end.

killed_wake_holder_is_rechecked_at_the_old_deadline() ->
    State = ?PROBE:idle_new(100, 0),
    Worker = held(fun() -> ?PROBE:idle_activity(State, 50, 1) end, 'after', 4),
    try
        await_held(Worker), kill_join(Worker),
        ?assertMatch({0, 100, 150, true, 1, 1, 0, _, _, _, _, _},
                     ?PROBE:idle_snapshot(State)),
        ?assertEqual({0, 50}, ?PROBE:idle_due(State, 100)),
        ?assertEqual({2, 0}, ?PROBE:idle_due(State, 150)),
        ?assertMatch({2, _, _, false, 1, 1, 0, _, _, _, 1, 0},
                     ?PROBE:idle_snapshot(State))
    after ensure_joined(Worker) end.

contention_budget_is_an_explicit_unavailable_outcome() ->
    State = ?PROBE:idle_new(100, 0),
    try
        put(idle_test_conflicts, {1, 0}),
        ?assertEqual(2, ?PROBE:idle_activity(State, 1000000, 1)),
        ?assertEqual({1, 256}, get(idle_test_conflicts)),
        erase(idle_test_conflicts),
        ?assertMatch({3, _, _, false, 0, 0, 0, _, _, _, 0, 0},
                     ?PROBE:idle_snapshot(State)),
        ?assertEqual({3, 0}, ?PROBE:idle_due(State, 100)),
        ?assertEqual(1, ?PROBE:idle_stop(State)),
        ?assertMatch({3, _, _, false, 0, 0, 0, _, _, _, 0, 1},
                     ?PROBE:idle_snapshot(State))
    after erase(idle_test_conflicts) end.

terminal_outcomes_cannot_be_reclassified_by_bad_activity() ->
    lists:foreach(fun(Terminal) ->
        State = ?PROBE:idle_new(100, 0),
        case Terminal of
            1 -> ?assertEqual(1, ?PROBE:idle_stop(State));
            2 -> ?assertEqual({2, 0}, ?PROBE:idle_due(State, 100))
        end,
        ?assertEqual(0, ?PROBE:idle_activity(State, ?MAX, 1)),
        ?assertEqual(0, ?PROBE:idle_activity(State, 500, 1)),
        ?assertEqual(0, ?PROBE:idle_stop(State)),
        ?assertEqual(Terminal, element(1, ?PROBE:idle_snapshot(State)))
    end, [1, 2]).

invalid_construction_and_malformed_handles_are_finite() ->
    lists:foreach(fun({Timeout, Now}) ->
        State = ?PROBE:idle_new(Timeout, Now),
        ?assertEqual(3, element(1, ?PROBE:idle_snapshot(State))),
        ?assertMatch({ok, _}, within(fun() -> ?PROBE:idle_stop(State) end))
    end, [{0, 0}, {-1, 0}, {1, ?MAX}, {1, -9223372036854775808},
          {1, invalid}, {invalid, 0}, {2147483648, 0}]),
    ?assertEqual(2, ?PROBE:idle_activity(invalid, 0, 1)),
    ?assertEqual(2, ?PROBE:idle_stop(invalid)),
    ?assertEqual({3, 0}, ?PROBE:idle_due(invalid, 0)),
    ?assertEqual(3, ?PROBE:idle_ack(invalid)),
    ?assertEqual(3, element(1, ?PROBE:idle_snapshot(invalid))).

directional_saturation_preserves_the_shared_total_ceiling() ->
    State = ?PROBE:idle_new(100, 0),
    atomics:put(State, 11, ?MAX - 1),
    atomics:put(State, 12, ?MAX - 1),
    _ = ?PROBE:idle_activity(State, 0, 1),
    _ = ?PROBE:idle_activity(State, 0, 1),
    _ = ?PROBE:idle_activity(State, 0, 2),
    Snapshot = ?PROBE:idle_snapshot(State),
    ?assertEqual(?MAX, element(5, Snapshot)),
    ?assertEqual(element(5, Snapshot), element(6, Snapshot) + element(7, Snapshot)),
    ?assertEqual(?MAX, atomics:get(State, 11)),
    ?assertEqual(?MAX, atomics:get(State, 12)),
    _ = ?PROBE:idle_stop(State).

joined_concurrent_activity_counts_are_exact() ->
    State = ?PROBE:idle_new(100, 0),
    Parent = self(), Reference = make_ref(),
    Workers = [spawn_monitor(fun() ->
        lists:foreach(fun(_) ->
            ?assert(?PROBE:idle_activity(State, 0, Direction) =/= 2)
        end, lists:seq(1, 20000)),
        Parent ! {Reference, complete}
    end) || Direction <- [1, 2]],
    try
        observe_joined(State, Workers, Reference,
                       erlang:monotonic_time(millisecond) + 3000),
        ?assertMatch({0, _, _, true, 40000, 20000, 20000, 1, 0, _, _, _},
                     ?PROBE:idle_snapshot(State)),
        _ = ?PROBE:idle_stop(State)
    after
        lists:foreach(fun({Pid, Monitor}) -> ensure_joined({Pid, Monitor, Reference}) end, Workers),
        flush_complete(Reference)
    end.

observe_joined(_State, [], _Reference, _Deadline) -> ok;
observe_joined(State, Workers, Reference, Deadline) ->
    Snapshot = ?PROBE:idle_snapshot(State),
    ?assertEqual(element(5, Snapshot), element(6, Snapshot) + element(7, Snapshot)),
    ?assert(erlang:monotonic_time(millisecond) < Deadline),
    receive
        {'DOWN', Monitor, process, Pid, normal} ->
            observe_joined(State, lists:delete({Pid, Monitor}, Workers), Reference, Deadline)
    after 0 -> erlang:yield(), observe_joined(State, Workers, Reference, Deadline)
    end.

flush_complete(Reference) ->
    receive {Reference, complete} -> flush_complete(Reference) after 0 -> ok end.

duplicate_terminal_signals_have_one_mailbox_slot() ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Alias = ?PROBE:idle_stop_alias(),
        Parent ! {Reference, alias, Alias},
        receive {Reference, inspect} ->
            {message_queue_len, Size} = process_info(self(), message_queue_len),
            Parent ! {Reference, size, Size}
        after 1000 -> error(inspect_not_received) end,
        receive {Alias} -> ok after 1000 -> error(stop_not_received) end
    end),
    try
        Alias = receive {Reference, alias, A} -> A after 1000 -> error(alias_not_created) end,
        lists:foreach(fun(_) -> nil = ?PROBE:idle_signal_stop(Alias) end, lists:seq(1, 10000)),
        Pid ! {Reference, inspect},
        Size = receive {Reference, size, S} -> S after 1000 -> error(inspect_not_completed) end,
        ?assertEqual(1, Size),
        ?assert(?PROBE:idle_join(Pid, 1000))
    after ensure_joined({Pid, Monitor, Reference}) end.

join_timeout_does_not_kill_an_owner_doing_cleanup() ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Alias = ?PROBE:idle_stop_alias(),
        Parent ! {Reference, alias, Alias},
        receive {Alias} -> Parent ! {Reference, cleanup_started} end,
        receive {Reference, cleanup_complete} -> ok after 1000 -> error(cleanup_not_released) end
    end),
    try
        Alias = receive {Reference, alias, A} -> A after 1000 -> error(alias_not_created) end,
        ?PROBE:idle_signal_stop(Alias),
        receive {Reference, cleanup_started} -> ok after 1000 -> error(cleanup_not_started) end,
        ?assertEqual(false, ?PROBE:idle_join(Pid, 5)),
        ?assert(is_process_alive(Pid)),
        Pid ! {Reference, cleanup_complete},
        ?assert(?PROBE:idle_join(Pid, 1000))
    after ensure_joined({Pid, Monitor, Reference}) end.

owner_death_reclaims_the_stop_alias() ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Parent ! {Reference, alias, ?PROBE:idle_stop_alias()},
        receive after 2000 -> error(owner_not_stopped) end
    end),
    try
        Alias = receive {Reference, alias, A} -> A after 1000 -> error(alias_not_created) end,
        kill_join({Pid, Monitor, Reference}),
        lists:foreach(fun(_) -> nil = ?PROBE:idle_signal_stop(Alias) end, lists:seq(1, 10000)),
        ?assert(?PROBE:idle_join(Pid, 5)),
        ?assertNot(is_process_alive(Pid))
    after ensure_joined({Pid, Monitor, Reference}) end.

stopping_does_not_reserve_an_activity_wake() ->
    State = ?PROBE:idle_new(100, 0),
    ?assertEqual(1, ?PROBE:idle_stop(State)),
    ?assertMatch({1, _, _, false, 0, 0, 0, 0, 0, _, 0, 1},
                 ?PROBE:idle_snapshot(State)).

%% These are actual atomics operations from the compiled production forms.
%% Only a selected call in the calling test worker is paused; unrelated calls
%% retain their original semantics. A killed worker cannot leave a test lock.
compare_exchange(State, Index, Expected, Desired) ->
    hook(before, Index),
    Result = case get(idle_test_conflicts) of
        {Index, Count} when Count < 1000 ->
            %% A real competing update advances the same deadline before the
            %% intended CAS. This proves the finite limit, not just a fake return.
            ok = atomics:compare_exchange(State, Index, Expected, Expected + 1),
            put(idle_test_conflicts, {Index, Count + 1}),
            atomics:compare_exchange(State, Index, Expected, Desired);
        _ -> atomics:compare_exchange(State, Index, Expected, Desired)
    end,
    case Result of ok -> hook('after', Index); _ -> ok end,
    Result.

hook(Stage, Index) ->
    case get(idle_test_hook) of
        {Stage, Index, Parent, Reference} ->
            erase(idle_test_hook),
            Parent ! {Reference, held},
            receive {Reference, continue} -> ok after 2000 -> error(hook_expired) end;
        _ -> ok
    end.

held(Action, Stage, Index) ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        put(idle_test_hook, {Stage, Index, Parent, Reference}),
        Parent ! {Reference, result, Action()}
    end),
    {Pid, Monitor, Reference}.

await_held({_Pid, _Monitor, Reference}) ->
    receive {Reference, held} -> ok after 1000 -> error(hook_not_reached) end.

release_join({Pid, Monitor, Reference}) ->
    Pid ! {Reference, continue},
    Result = receive {Reference, result, Value} -> Value
             after 1000 -> error(worker_did_not_complete) end,
    receive {'DOWN', Monitor, process, Pid, normal} -> Result
    after 1000 -> error(worker_not_joined) end.

kill_join({Pid, Monitor, _Reference}) ->
    exit(Pid, kill),
    receive {'DOWN', Monitor, process, Pid, _} -> ok
    after 1000 -> error(worker_not_joined) end.

ensure_joined({Pid, Monitor, Reference} = Worker) ->
    case is_process_alive(Pid) of
        true -> kill_join(Worker);
        false -> demonitor(Monitor, [flush])
    end,
    receive {Reference, result, _} -> ok after 0 -> ok end.

within(Action) ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Result = try {ok, Action()} catch _:_ -> raised end,
        Parent ! {Reference, result, Result}
    end),
    try
        receive {Reference, result, Result} ->
            receive {'DOWN', Monitor, process, Pid, normal} -> Result
            after 1000 -> error(worker_not_joined) end
        after 250 -> timed_out end
    after ensure_joined({Pid, Monitor, Reference}) end.

load_probe() ->
    {ok, Forms} = epp:parse_file("src/http_masque_udp_ffi.erl", [], []),
    Modified = [rewrite(Form) || Form <- Forms],
    {ok, ?PROBE, Beam, []} = compile:forms(Modified,
        [binary, return_errors, return_warnings]),
    {module, ?PROBE} = code:load_binary(?PROBE, "idle-test-only", Beam),
    ok.

rewrite({attribute, Line, module, http_masque_udp_ffi}) ->
    {attribute, Line, module, ?PROBE};
rewrite({remote, Line, {atom, ModuleLine, atomics}, {atom, FunctionLine, compare_exchange}}) ->
    {remote, Line, {atom, ModuleLine, ?MODULE}, {atom, FunctionLine, compare_exchange}};
rewrite(Tuple) when is_tuple(Tuple) ->
    list_to_tuple([rewrite(Item) || Item <- tuple_to_list(Tuple)]);
rewrite(List) when is_list(List) -> [rewrite(Item) || Item <- List];
rewrite(Value) -> Value.

unload_probe(_) ->
    code:purge(?PROBE),
    code:delete(?PROBE),
    ok.
