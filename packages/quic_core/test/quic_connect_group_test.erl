%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_connect_group_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

-define(PROBE, quic_connect_group_lifecycle_probe).
-define(REAPER_TEST_HEAP_WORDS, 16384).
-define(REAPER_PRESSURE_WORDS, 131072).

contracts() -> [
  fun stop_joins_every_worker_and_guardian/0,
  fun completed_workers_remain_within_total_admission/0,
  fun caller_death_terminates_workers/0,
  fun owner_death_terminates_workers/0,
  fun guardian_death_terminates_workers/0,
  fun reaper_death_terminates_workers/0,
  fun reaper_heap_limit_terminates_workers/0,
  fun callback_exception_is_contained/0,
  fun delegated_helpers_join_before_endpoint_publication/0,
  fun expired_publication_joins_the_endpoint/0,
  fun unpublished_endpoint_death_joins_delegated_workers/0,
  fun delegated_endpoint_cannot_detach_itself/0,
  fun failed_supervisor_still_joins_every_admitted_worker/0
].

stop_joins_every_worker_and_guardian() ->
    {ok, Group} = quic_core_udp_ffi:group_start(self()),
    Reaper = maps:get(reaper, Group),
    Ledger = maps:get(ledger, Group),
    {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun blocked/0),
    ?assertEqual({ok, nil}, quic_core_udp_ffi:group_stop(Group)),
    ?assertEqual(false, is_process_alive(Worker)),
    ?assertEqual(false, is_process_alive(maps:get(pid, Group))),
    ?assertEqual(false, is_process_alive(Reaper)),
    ?assertEqual(undefined, ets:info(Ledger)),
    assert_no_group_monitor_residue(Group).

completed_workers_remain_within_total_admission() ->
    {ok, Group} = quic_core_udp_ffi:group_start(self()),
    lists:foreach(fun(_) ->
        {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun() -> nil end),
        await_down(Worker)
    end, lists:seq(1, 18)),
    ?assertEqual({error, 1}, quic_core_udp_ffi:group_spawn(Group, 3, fun blocked/0)),
    ?assertEqual({ok, nil}, quic_core_udp_ffi:group_stop(Group)).

caller_death_terminates_workers() ->
    Parent = self(),
    Caller = spawn(fun() ->
        {ok, Group} = quic_core_udp_ffi:group_start(Parent),
        {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun blocked/0),
        Parent ! {owned, maps:get(pid, Group), maps:get(reaper, Group),
            maps:get(ledger, Group), Worker},
        blocked()
    end),
    {Guardian, Reaper, Ledger, Worker} = receive
        {owned, G, R, L, W} -> {G, R, L, W}
    after 1000 -> error(missing_ready)
    end,
    exit(Caller, kill),
    await_down(Worker),
    await_down(Guardian),
    await_down(Reaper),
    ?assertEqual(undefined, ets:info(Ledger)).

owner_death_terminates_workers() ->
    Owner = spawn(fun blocked/0),
    {ok, Group} = quic_core_udp_ffi:group_start(Owner),
    Reaper = maps:get(reaper, Group),
    Ledger = maps:get(ledger, Group),
    {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun blocked/0),
    exit(Owner, kill),
    await_down(Worker),
    await_down(maps:get(pid, Group)),
    await_down(Reaper),
    ?assertEqual(undefined, ets:info(Ledger)),
    ?assertMatch({error, _}, quic_core_udp_ffi:group_stop(Group)),
    assert_no_group_monitor_residue(Group).

guardian_death_terminates_workers() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start(self()),
    Reaper = maps:get(reaper, Group),
    Ledger = maps:get(ledger, Group),
    {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun() ->
        process_flag(trap_exit, true),
        Parent ! {guardian_trap_worker_ready, self()},
        blocked()
    end),
    receive {guardian_trap_worker_ready, Worker} -> ok
    after 1000 -> error(guardian_trap_worker_not_ready)
    end,
    Guardian = maps:get(pid, Group),
    exit(Guardian, kill),
    await_down(Guardian),
    await_down(Worker),
    await_down(Reaper),
    ?assertEqual(undefined, ets:info(Ledger)),
    ?assertMatch({error, _}, quic_core_udp_ffi:group_stop(Group)),
    assert_no_group_monitor_residue(Group).

reaper_death_terminates_workers() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start(self()),
    Guardian = maps:get(pid, Group),
    Reaper = maps:get(reaper, Group),
    Ledger = maps:get(ledger, Group),
    {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun() ->
        process_flag(trap_exit, true),
        Parent ! {reaper_trap_worker_ready, self()},
        blocked()
    end),
    receive {reaper_trap_worker_ready, Worker} -> ok
    after 1000 -> error(reaper_trap_worker_not_ready)
    end,
    exit(Reaper, kill),
    await_down(Reaper),
    await_down(Worker),
    await_down(Guardian),
    ?assertEqual(undefined, ets:info(Ledger)),
    ?assertMatch({error, _}, quic_core_udp_ffi:group_stop(Group)),
    assert_no_group_monitor_residue(Group).

reaper_heap_limit_terminates_workers() ->
    ok = load_probe(),
    try
        Parent = self(),
        {ok, Group} = ?PROBE:group_start_with_reaper_heap_words(
            self(),
            #{maximum => 18, endpoint => false, accepting => true},
            ?REAPER_TEST_HEAP_WORDS
        ),
        try
            Guardian = maps:get(pid, Group),
            Reaper = maps:get(reaper, Group),
            Ledger = maps:get(ledger, Group),
            {ok, Worker} = ?PROBE:group_spawn(Group, 3, fun() ->
                process_flag(trap_exit, true),
                Parent ! {reaper_heap_worker_ready, self()},
                blocked()
            end),
            try
                receive {reaper_heap_worker_ready, Worker} -> ok
                after 1000 -> error(reaper_heap_worker_not_ready)
                end,
                %% No flood actor is created. Suspending first makes this one
                %% fixed message exceed the injected on-heap limit.
                true = erlang:suspend_process(Reaper),
                Reaper ! {reaper_heap_pressure,
                    lists:seq(1, ?REAPER_PRESSURE_WORDS)},
                %% The runtime checks max_heap_size during garbage collection.
                Collection = make_ref(),
                async = erlang:garbage_collect(Reaper, [{async, Collection}]),
                resume_if_alive(Reaper),
                await_down(Reaper),
                receive {garbage_collect, Collection, _} -> ok
                after 1000 -> error(reaper_collection_unconfirmed)
                end,
                await_down(Worker),
                await_down(Guardian),
                ?assertEqual(undefined, ets:info(Ledger)),
                ?assertMatch({error, _}, ?PROBE:group_stop(Group)),
                assert_no_group_monitor_residue(Group)
            after
                cleanup_probe_group(Group, [Worker])
            end
        after
            cleanup_probe_group(Group, [])
        end
    after
        unload_probe()
    end.

callback_exception_is_contained() ->
    {ok, Group} = quic_core_udp_ffi:group_start(self()),
    {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 4,
        fun() -> error(<<"private-connect-fixture">>) end),
    await_down(Worker),
    ?assertEqual({ok, nil}, quic_core_udp_ffi:group_stop(Group)).

delegated_helpers_join_before_endpoint_publication() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start_establishment(self()),
    {ok, Endpoint} = quic_core_udp_ffi:group_spawn(Group, 1, fun() ->
        Workers = [begin
            {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun blocked/0),
            Worker
        end || _ <- lists:seq(1, 18)],
        Rejected = quic_core_udp_ffi:group_spawn(Group, 4, fun blocked/0) =:= {error, 1},
        Joined = quic_core_udp_ffi:group_quiesce(Group) =:= {ok, nil},
        Parent ! {quiesced, Rejected, Joined,
            lists:all(fun(Pid) -> not is_process_alive(Pid) end, Workers)},
        blocked()
    end),
    receive {quiesced, Rejected, Joined, AllDown} ->
        ?assert(Rejected), ?assert(Joined), ?assert(AllDown)
    after 1000 -> error(missing_quiescence) end,
    ?assert(is_process_alive(Endpoint)),
    ?assertEqual({ok, nil}, quic_core_udp_ffi:group_publish(Group, Endpoint,
        quic_core_udp_ffi:monotonic_millisecond()+1000)),
    ?assertNot(is_process_alive(maps:get(pid, Group))),
    ?assert(is_process_alive(Endpoint)),
    exit(Endpoint, kill),
    await_down(Endpoint).

expired_publication_joins_the_endpoint() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start_establishment(self()),
    {ok, Endpoint} = quic_core_udp_ffi:group_spawn(Group, 1, fun() ->
        {ok, nil} = quic_core_udp_ffi:group_quiesce(Group),
        Parent ! publication_ready,
        blocked()
    end),
    receive publication_ready -> ok after 1000 -> error(missing_ready) end,
    ?assertEqual({error, 2}, quic_core_udp_ffi:group_publish(Group, Endpoint,
        quic_core_udp_ffi:monotonic_millisecond())),
    ?assertNot(is_process_alive(Endpoint)),
    ?assertNot(is_process_alive(maps:get(pid, Group))).

unpublished_endpoint_death_joins_delegated_workers() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start_establishment(self()),
    {ok, Endpoint} = quic_core_udp_ffi:group_spawn(Group, 1, fun() ->
        {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 4, fun blocked/0),
        Parent ! {delegated, Worker},
        blocked()
    end),
    Worker = receive {delegated, Pid} -> Pid after 1000 -> error(missing_worker) end,
    exit(Endpoint, kill),
    await_down(Worker),
    await_down(maps:get(pid, Group)).

delegated_endpoint_cannot_detach_itself() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start_establishment(self()),
    {ok, Endpoint} = quic_core_udp_ffi:group_spawn(Group, 1, fun() ->
        {ok, nil} = quic_core_udp_ffi:group_quiesce(Group),
        Refused = quic_core_udp_ffi:group_publish(Group, self(),
            quic_core_udp_ffi:monotonic_millisecond()+1000) =:= {error, 1},
        Parent ! {detach_refused, Refused},
        blocked()
    end),
    receive {detach_refused, Refused} -> ?assert(Refused)
    after 1000 -> error(missing_refusal) end,
    ?assertEqual({ok, nil}, quic_core_udp_ffi:group_stop(Group)),
    ?assertNot(is_process_alive(Endpoint)).

failed_supervisor_still_joins_every_admitted_worker() ->
    Parent = self(),
    {ok, Group} = quic_core_udp_ffi:group_start(self()),
    {ok, Worker} = quic_core_udp_ffi:group_spawn(Group, 3, fun() ->
        process_flag(trap_exit, true),
        Parent ! trapping_worker_ready,
        blocked()
    end),
    try
        receive trapping_worker_ready -> ok after 1000 -> error(missing_ready) end,
        exit(maps:get(pid, Group), kill),
        await_down(maps:get(pid, Group)),
        Failure = quic_core_udp_ffi:group_stop(Group),
        ?assertMatch({error, _}, Failure),
        ?assertNot(is_process_alive(Worker))
    after
        exit(Worker, kill), await_down(Worker)
    end.

blocked() -> receive release -> nil after 5000 -> nil end.

await_down(Pid) ->
    Monitor = monitor(process, Pid),
    Observed = receive {'DOWN', Monitor, process, Pid, _} -> true after 1500 -> false end,
    demonitor(Monitor, [flush]),
    ?assert(Observed).

assert_no_group_monitor_residue(Group) ->
    GuardianMonitor = maps:get(monitor, Group),
    ReaperMonitor = maps:get(reaper_monitor, Group),
    receive
        {'DOWN', GuardianMonitor, process, _, _} ->
            error(guardian_down_residue)
    after 0 -> ok
    end,
    receive
        {'DOWN', ReaperMonitor, process, _, _} ->
            error(reaper_down_residue)
    after 0 -> ok
    end.

resume_if_alive(Pid) ->
    case is_process_alive(Pid) of
        true ->
            try erlang:resume_process(Pid)
            catch error:badarg -> ok
            end;
        false -> ok
    end.

cleanup_probe_group(Group, ExtraWorkers) ->
    Guardian = maps:get(pid, Group),
    Reaper = maps:get(reaper, Group),
    Ledger = maps:get(ledger, Group),
    resume_if_alive(Reaper),
    LedgerWorkers = try ets:select(
        Ledger, [{{'$1'}, [], ['$1']}]
    ) of
        Workers -> Workers
    catch error:badarg -> []
    end,
    Processes = lists:usort(
        [Guardian, Reaper | ExtraWorkers ++ LedgerWorkers]
    ),
    Pending = maps:from_list([
        {monitor(process, Process), Process} || Process <- Processes
    ]),
    maps:foreach(fun(_Monitor, Process) -> exit(Process, kill) end, Pending),
    cleanup_probe_join(
        Pending, erlang:monotonic_time(millisecond) + 1000
    ),
    demonitor(maps:get(monitor, Group), [flush]),
    demonitor(maps:get(reaper_monitor, Group), [flush]),
    ok.

cleanup_probe_join(Pending, _Deadline) when map_size(Pending) =:= 0 -> ok;
cleanup_probe_join(Pending, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, _Process, _Reason}
            when is_map_key(Monitor, Pending) ->
            cleanup_probe_join(maps:remove(Monitor, Pending), Deadline)
    after Remaining ->
        maps:foreach(fun(Monitor, _Process) ->
            demonitor(Monitor, [flush])
        end, Pending),
        ok
    end.

load_probe() ->
    {ok, Forms} = epp:parse_file("src/quic_core_udp_ffi.erl", [], []),
    Modified = [rewrite(Form) || Form <- Forms],
    {ok, ?PROBE, Beam, _Warnings} = compile:forms(
        Modified, [binary, export_all, return_errors, return_warnings]
    ),
    {module, ?PROBE} = code:load_binary(
        ?PROBE, "connect-group-lifecycle-test-only", Beam
    ),
    ok.

rewrite({attribute, Line, module, quic_core_udp_ffi}) ->
    {attribute, Line, module, ?PROBE};
rewrite(Value) -> Value.

unload_probe() ->
    code:purge(?PROBE),
    code:delete(?PROBE),
    ok.
