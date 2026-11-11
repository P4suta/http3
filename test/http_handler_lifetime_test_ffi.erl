%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Test-only process gates and scalar lifetime observations. Native capabilities
%% remain inside fixtures; failed assertions contain only booleans/counters.
-module(http_handler_lifetime_test_ffi).
-export([new_probe/0, record_handler/1, record_cleanup/1, snapshot/2,
    pause_worker/2, suspend/1, resume/1, executor/1, dispose/1, await_dispatch/1,
    join_reaper/1, reaper_retains_until_down/0, unadopted_reaper_does_not_release/0,
    quarantined_reaper_does_not_release/0, atomic_monitor_contracts/0,
    http1_handler_normal_contract/0, http1_handler_stop_contract/0,
    http1_handler_timeout_contract/0, http1_handler_crash_contract/0,
    http1_handler_owner_down_contract/0,
    http1_handler_unconfirmed_cleanup_contract/0,
    http1_handler_startup_deadline_contract/0,
    http1_handler_entry_deadline_contract/0,
    http1_handler_owner_startup_contract/0,
    http1_handler_cleanup_deadline_contract/0,
    http1_handler_quarantine_retry_deadline_contract/0]).

atomic_monitor_contracts() ->
    Parent = self(),
    Ref = make_ref(),
    {Unlinked, UnlinkedMonitor} = http_server_ffi:spawn_monitor(fun() ->
        {monitored_by, Watchers} = process_info(self(), monitored_by),
        {links, Links} = process_info(self(), links),
        Parent ! {Ref, unlinked, lists:member(Parent, Watchers),
                  not lists:member(Parent, Links)}
    end),
    UnlinkedObservation = receive
        {Ref, unlinked, UnlinkedMonitored, NotLinked} ->
            {UnlinkedMonitored, NotLinked}
    after 1000 -> {false, false}
    end,
    UnlinkedDown = receive
        {'DOWN', UnlinkedMonitor, process, Unlinked, _} -> true
    after 1000 -> false
    end,
    {Linked, LinkedMonitor} = http_server_ffi:spawn_link_monitor(fun() ->
        {monitored_by, Watchers} = process_info(self(), monitored_by),
        {links, Links} = process_info(self(), links),
        Parent ! {Ref, linked, lists:member(Parent, Watchers),
                  lists:member(Parent, Links)}
    end),
    LinkedObservation = receive
        {Ref, linked, LinkedMonitored, IsLinked} ->
            {LinkedMonitored, IsLinked}
    after 1000 -> {false, false}
    end,
    LinkedDown = receive
        {'DOWN', LinkedMonitor, process, Linked, _} -> true
    after 1000 -> false
    end,
    {UnlinkedObservation, UnlinkedDown, LinkedObservation, LinkedDown}.

%% These controls exercise the internal HTTP/1 guardian directly. Every public
%% result is a fixed-size list of booleans; process identifiers, monitor
%% references, callback values, and exit reasons remain inside this fixture.
http1_handler_normal_contract() ->
    bounded_contract(7, fun http1_handler_normal_contract_run/0).

http1_handler_stop_contract() ->
    bounded_contract(7, fun http1_handler_stop_contract_run/0).

http1_handler_timeout_contract() ->
    bounded_contract(6, fun http1_handler_timeout_contract_run/0).

http1_handler_crash_contract() ->
    bounded_contract(5, fun http1_handler_crash_contract_run/0).

http1_handler_owner_down_contract() ->
    bounded_contract(6, fun http1_handler_owner_down_contract_run/0).

http1_handler_unconfirmed_cleanup_contract() ->
    bounded_contract(8, fun http1_handler_unconfirmed_cleanup_contract_run/0).

http1_handler_startup_deadline_contract() ->
    bounded_contract(6, fun http1_handler_startup_deadline_contract_run/0).

http1_handler_entry_deadline_contract() ->
    bounded_contract(10, fun http1_handler_entry_deadline_contract_run/0).

http1_handler_owner_startup_contract() ->
    bounded_contract(7, fun http1_handler_owner_startup_contract_run/0).

http1_handler_cleanup_deadline_contract() ->
    bounded_contract(7, fun http1_handler_cleanup_deadline_contract_run/0).

http1_handler_quarantine_retry_deadline_contract() ->
    bounded_contract(8, fun http1_handler_quarantine_retry_deadline_contract_run/0).

bounded_contract(Count, Run) ->
    Parent = self(),
    Reference = make_ref(),
    {Worker, Monitor} = erlang:spawn_monitor(fun() ->
        Values = Run(),
        Parent ! {Reference, contract_result, Values}
    end),
    Deadline = erlang:monotonic_time(millisecond) + 6000,
    receive
        {Reference, contract_result, Values} ->
            Joined = receive
                {'DOWN', Monitor, process, Worker, _} -> true
            after contract_remaining(Deadline) -> false
            end,
            case Joined andalso valid_boolean_contract(Values, Count) of
                true -> Values;
                false -> lists:duplicate(Count, false)
            end;
        {'DOWN', Monitor, process, Worker, _} ->
            lists:duplicate(Count, false)
    after contract_remaining(Deadline) ->
        exit(Worker, kill),
        _ = receive
            {'DOWN', Monitor, process, Worker, _} -> true
        after 250 -> false
        end,
        lists:duplicate(Count, false)
    end.

valid_boolean_contract(Values, Count) when is_list(Values) ->
    length(Values) =:= Count
        andalso lists:all(fun(Value) -> is_boolean(Value) end, Values);
valid_boolean_contract(_Values, _Count) -> false.

http1_handler_normal_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() -> normal_result end,
    Probe = fun
        (0, _Guardian) ->
            Parent ! {
                Reference, owner_monitor_ready,
                guardian_monitors_owner(Parent)
            },
            nil;
        (1, Guardian) ->
            Parent ! {
                Reference, handler_entry_topology,
                handler_has_guardian(self(), Guardian)
            },
            %% A production spawn-then-monitor mutant can wait for this exact
            %% first-entry barrier before installing its late monitor. The
            %% observation above must already be false in that widened gap.
            Guardian ! {Reference, handler_entry_barrier},
            nil;
        (_, _) -> nil
    end,
    AfterResult = fun() ->
        Parent ! {Reference, handler_after_result, self()},
        receive {Reference, release_handler} -> nil after 1500 -> nil end
    end,
    case start_contract_guardian_with_probe(
        Events, Run, Counters, Probe, AfterResult, terminate_handler,
        erlang:monotonic_time(millisecond) + 2000, 250
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            Deadline = erlang:monotonic_time(millisecond) + 1000,
            case receive
                {Reference, handler_after_result, ObservedHandler} ->
                    {ok, ObservedHandler}
            after contract_remaining(Deadline) -> timeout
            end of
                {ok, Handler} ->
                    OwnerProtected = receive
                        {Reference, owner_monitor_ready, OwnerObserved} ->
                            OwnerObserved
                    after contract_remaining(Deadline) -> false
                    end,
                    HandlerAtomic = receive
                        {Reference, handler_entry_topology, EntryObserved} ->
                            EntryObserved
                    after contract_remaining(Deadline) -> false
                    end,
                    AtomicTopology = OwnerProtected andalso HandlerAtomic
                        andalso handler_has_guardian(Handler, Guardian),
                    NoEarlyResult = contract_subject_empty(Events),
                    Handler ! {Reference, release_handler},
                    Event = contract_receive_subject(Events, Deadline),
                    ResultPublished = Event =:= {ok, {handler_result, normal_result}},
                    HandlerDown = not is_process_alive(Handler),
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, Deadline
                    ),
                    NoDuplicate = contract_subject_empty(Events),
                    CountersUnused = contract_counters(Counters) =:= {0, 0},
                    [AtomicTopology, NoEarlyResult, ResultPublished,
                        HandlerDown, GuardianDown, NoDuplicate, CountersUnused];
                timeout ->
                    [false, false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false, false]
    end.

http1_handler_stop_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() -> stop_result end,
    AfterResult = fun() ->
        Parent ! {Reference, handler_after_result, self()},
        receive {Reference, release_handler} -> nil after 1500 -> nil end
    end,
    case start_contract_guardian(
        Events, Run, Counters, AfterResult, terminate_handler,
        erlang:monotonic_time(millisecond) + 2000, 250
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            Deadline = erlang:monotonic_time(millisecond) + 1000,
            case receive
                {Reference, handler_after_result, ObservedHandler} ->
                    {ok, ObservedHandler}
            after contract_remaining(Deadline) -> timeout
            end of
                {ok, Handler} ->
                    NoEarlyResult = contract_subject_empty(Events),
                    contract_send_subject(Commands, {
                        terminate_handler, handler_stopped,
                        erlang:monotonic_time(millisecond)
                    }),
                    Event = contract_receive_subject(Events, Deadline),
                    Terminated = Event =:= {
                        ok, {handler_terminated, handler_stopped}
                    },
                    HandlerDown = contract_process_down(Handler),
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, Deadline
                    ),
                    {CancelCalls, DiscardCalls} = contract_counters(Counters),
                    NoDuplicate = contract_subject_empty(Events),
                    [NoEarlyResult, Terminated, HandlerDown, GuardianDown,
                        CancelCalls =:= 1, DiscardCalls =:= 1, NoDuplicate];
                timeout ->
                    [false, false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false, false]
    end.

http1_handler_timeout_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() ->
        Parent ! {Reference, handler_started, self()},
        receive {Reference, never} -> timeout_result after 1500 -> timeout_result end
    end,
    case start_contract_guardian(
        Events, Run, Counters, fun() -> nil end, terminate_handler,
        erlang:monotonic_time(millisecond) + 100, 250
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            Deadline = erlang:monotonic_time(millisecond) + 1000,
            case receive
                {Reference, handler_started, ObservedHandler} ->
                    {ok, ObservedHandler}
            after contract_remaining(Deadline) -> timeout
            end of
                {ok, Handler} ->
                    Event = contract_receive_subject(Events, Deadline),
                    TimedOut = Event =:= {
                        ok, {handler_terminated, handler_timed_out}
                    },
                    HandlerDown = contract_process_down(Handler),
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, Deadline
                    ),
                    CountsExact = contract_counters(Counters) =:= {1, 0},
                    NoDuplicate = contract_subject_empty(Events),
                    [true, TimedOut, HandlerDown, GuardianDown,
                        CountsExact, NoDuplicate];
                timeout ->
                    [false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false]
    end.

http1_handler_crash_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() ->
        Parent ! {Reference, handler_started, self()},
        erlang:error(controlled_handler_failure)
    end,
    case start_contract_guardian(
        Events, Run, Counters, fun() -> nil end, terminate_handler,
        erlang:monotonic_time(millisecond) + 2000, 250
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            Deadline = erlang:monotonic_time(millisecond) + 1000,
            case receive
                {Reference, handler_started, ObservedHandler} ->
                    {ok, ObservedHandler}
            after contract_remaining(Deadline) -> timeout
            end of
                {ok, Handler} ->
                    Event = contract_receive_subject(Events, Deadline),
                    Failed = Event =:= {ok, handler_failed},
                    HandlerDown = contract_process_down(Handler),
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, Deadline
                    ),
                    CountsExact = contract_counters(Counters) =:= {1, 0},
                    [true, Failed, HandlerDown, GuardianDown, CountsExact];
                timeout ->
                    [false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false]
    end.

http1_handler_owner_down_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    {Owner, OwnerMonitor} = erlang:spawn_monitor(fun() ->
        Events = contract_subject(),
        Run = fun() ->
            Parent ! {Reference, handler_started, self()},
            receive {Reference, never} -> owner_result after 1500 -> owner_result end
        end,
        case start_contract_guardian(
            Events, Run, Counters, fun() -> nil end, terminate_handler,
            erlang:monotonic_time(millisecond) + 2000, 250
        ) of
            {ok, {_GuardianMonitor, Commands}} ->
                Parent ! {Reference, owner_ready, contract_subject_owner(Commands)},
                receive {Reference, hold_owner} -> nil after 1500 -> nil end;
            _StartFailure ->
                Parent ! {Reference, owner_start_failed}
        end
    end),
    Deadline = erlang:monotonic_time(millisecond) + 1000,
    OwnerReady = receive
        {Reference, owner_ready, ObservedGuardian} -> {ok, ObservedGuardian};
        {Reference, owner_start_failed} -> failed
    after contract_remaining(Deadline) -> timeout
    end,
    HandlerReady = receive
        {Reference, handler_started, ObservedHandler} -> {ok, ObservedHandler}
    after contract_remaining(Deadline) -> timeout
    end,
    case {OwnerReady, HandlerReady} of
        {{ok, Guardian}, {ok, Handler}} ->
            GuardianMonitor = erlang:monitor(process, Guardian),
            HandlerMonitor = erlang:monitor(process, Handler),
            exit(Owner, kill),
            OwnerDown = contract_await_down(Owner, OwnerMonitor, Deadline),
            HandlerDown = contract_await_down(Handler, HandlerMonitor, Deadline),
            GuardianDown = contract_await_down(
                Guardian, GuardianMonitor, Deadline
            ),
            CountsExact = contract_counters(Counters) =:= {1, 0},
            NoOrphan = not is_process_alive(Handler)
                andalso not is_process_alive(Guardian),
            [true, OwnerDown, HandlerDown, GuardianDown, CountsExact, NoOrphan];
        _ ->
            exit(Owner, kill),
            [false, false, false, false, false, false]
    end.

http1_handler_unconfirmed_cleanup_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() -> unconfirmed_result end,
    AfterResult = fun() ->
        Parent ! {Reference, handler_after_result, self()},
        receive {Reference, release_handler} -> nil after 1500 -> nil end
    end,
    case start_contract_guardian(
        Events, Run, Counters, AfterResult, keep_handler_alive,
        erlang:monotonic_time(millisecond) + 2000, 25
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            Deadline = erlang:monotonic_time(millisecond) + 1000,
            case receive
                {Reference, handler_after_result, ObservedHandler} ->
                    {ok, ObservedHandler}
            after contract_remaining(Deadline) -> timeout
            end of
                {ok, Handler} ->
                    contract_send_subject(Commands, {
                        terminate_handler, handler_stopped,
                        erlang:monotonic_time(millisecond)
                    }),
                    Event = contract_receive_subject(Events, Deadline),
                    Unconfirmed = Event =:= {
                        ok, {handler_cleanup_unconfirmed, handler_stopped}
                    },
                    HandlerRetained = is_process_alive(Handler),
                    GuardianRetained = is_process_alive(Guardian),
                    CancelOnce = contract_counters(Counters) =:= {1, 0},
                    NoDuplicate = contract_subject_empty(Events),
                    Handler ! {Reference, release_handler},
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, Deadline
                    ),
                    DiscardedOnce = contract_counters(Counters) =:= {1, 1},
                    NoLateTerminal = contract_subject_empty(Events),
                    [Unconfirmed, HandlerRetained, GuardianRetained, CancelOnce,
                        NoDuplicate, GuardianDown andalso not is_process_alive(Handler),
                        DiscardedOnce, NoLateTerminal];
                timeout ->
                    [false, false, false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false, false, false]
    end.

http1_handler_startup_deadline_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Calls = atomics:new(2, [{signed, false}]),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    HandlerDeadline = erlang:monotonic_time(millisecond) + 500,
    Run = fun() ->
        _ = atomics:add(Calls, 1, 1),
        startup_result
    end,
    Probe = fun
        (0, _Guardian) ->
            Parent ! {
                Reference, startup_probe,
                guardian_monitors_owner(Parent), self()
            },
            receive {Reference, release_startup} -> nil after 1250 -> nil end;
        (1, _Guardian) ->
            _ = atomics:add(Calls, 2, 1),
            Parent ! {
                Reference, entry_phase_one, self(),
                erlang:monotonic_time(millisecond) < HandlerDeadline
            },
            receive
                {Reference, release_entry_phase_one} -> nil
            after 1250 -> nil
            end;
        (_, _) -> nil
    end,
    case start_contract_guardian_with_probe(
        Events, Run, Counters, Probe, fun() -> nil end, terminate_handler,
        HandlerDeadline, 250
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            ProbeOutcome = receive
                {Reference, startup_probe, ObservedOwnerProtected,
                    ObservedGuardian} ->
                    {ok, ObservedOwnerProtected,
                        ObservedGuardian =:= Guardian}
            after 750 -> timeout
            end,
            case ProbeOutcome of
                {ok, OwnerProtected, GuardianMatched} ->
                    contract_wait_until(HandlerDeadline),
                    Guardian ! {Reference, release_startup},
                    EventDeadline = erlang:monotonic_time(millisecond) + 1000,
                    Event = contract_receive_subject(Events, EventDeadline),
                    TimedOut = Event =:= {
                        ok, {handler_terminated, handler_timed_out}
                    },
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, EventDeadline
                    ),
                    NeverExecuted = {
                        atomics:get(Calls, 1), atomics:get(Calls, 2)
                    } =:= {0, 0}
                        andalso contract_counters(Counters) =:= {1, 0},
                    NoDuplicate = contract_subject_empty(Events),
                    [true, OwnerProtected andalso GuardianMatched, TimedOut,
                        GuardianDown, NeverExecuted, NoDuplicate];
                timeout ->
                    [false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false]
    end.

http1_handler_entry_deadline_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Calls = atomics:new(2, [{signed, false}]),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    HandlerDeadline = erlang:monotonic_time(millisecond) + 1500,
    Run = fun() ->
        _ = atomics:add(Calls, 1, 1),
        entry_deadline_result
    end,
    Probe = fun
        (2, Handler) ->
            Guardian = self(),
            Parent ! {
                Reference, entry_deadline_probe, Guardian, Handler,
                handler_has_guardian(Handler, Guardian)
            },
            receive
                {Reference, release_entry_deadline} -> nil
            after 3000 -> nil
            end;
        (1, _Guardian) ->
            _ = atomics:add(Calls, 2, 1),
            Parent ! {
                Reference, entry_phase_one, self(),
                erlang:monotonic_time(millisecond) < HandlerDeadline
            },
            receive
                {Reference, release_entry_phase_one} -> nil
            after 3000 -> nil
            end;
        (_, _) -> nil
    end,
    case start_contract_guardian_with_probe(
        Events, Run, Counters, Probe, fun() -> nil end, terminate_handler,
        HandlerDeadline, 250
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            ProbeOutcome = receive
                {Reference, entry_deadline_probe, ObservedGuardian,
                    ObservedHandler, ObservedTopology} ->
                    {ok, ObservedGuardian, ObservedHandler, ObservedTopology}
            after 2000 -> timeout
            end,
            case ProbeOutcome of
                {ok, Guardian, Handler, AtomicTopology} ->
                    HandlerObserver = erlang:monitor(process, Handler),
                    PhaseTwoBeforeDeadline =
                        erlang:monotonic_time(millisecond) < HandlerDeadline,
                    Guardian ! {Reference, release_entry_deadline},
                    PhaseOneOutcome = receive
                        {Reference, entry_phase_one, Handler, BeforeDeadline} ->
                            {ok, BeforeDeadline}
                    after 2000 -> timeout
                    end,
                    contract_wait_until(HandlerDeadline),
                    Handler ! {Reference, release_entry_phase_one},
                    EventDeadline = erlang:monotonic_time(millisecond) + 2000,
                    Event = contract_receive_subject(Events, EventDeadline),
                    TimedOut = Event =:= {
                        ok, {handler_terminated, handler_timed_out}
                    },
                    HandlerDown = contract_await_down(
                        Handler, HandlerObserver, EventDeadline
                    ),
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, EventDeadline
                    ),
                    RunNeverExecuted = atomics:get(Calls, 1) =:= 0,
                    PhaseOneOnce = atomics:get(Calls, 2) =:= 1,
                    PhaseOneBeforeDeadline = PhaseOneOutcome =:= {ok, true},
                    CancelOnce = contract_counters(Counters) =:= {1, 0},
                    NoDuplicate = contract_subject_empty(Events),
                    [PhaseTwoBeforeDeadline, AtomicTopology,
                        PhaseOneBeforeDeadline, TimedOut, RunNeverExecuted,
                        PhaseOneOnce, HandlerDown, GuardianDown, CancelOnce,
                        NoDuplicate];
                timeout ->
                    [false, false, false, false, false, false, false, false,
                        false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false, false, false, false,
                false]
    end.

http1_handler_owner_startup_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Calls = atomics:new(2, [{signed, false}]),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    {Owner, OwnerMonitor} = erlang:spawn_monitor(fun() ->
        OwnerPid = self(),
        Run = fun() ->
            _ = atomics:add(Calls, 1, 1),
            owner_startup_result
        end,
        Probe = fun
            (0, Guardian) ->
                Parent ! {
                    Reference, owner_startup_probe, Guardian,
                    guardian_monitors_owner(OwnerPid)
                },
                receive
                    {Reference, release_owner_startup} -> nil
                after 1250 -> nil
                end;
            (1, _Guardian) ->
                _ = atomics:add(Calls, 2, 1),
                nil;
            (_, _) -> nil
        end,
        case start_contract_guardian_with_probe(
            Events, Run, Counters, Probe, fun() -> nil end,
            terminate_handler, erlang:monotonic_time(millisecond) + 2000, 250
        ) of
            {ok, {_GuardianMonitor, Commands}} ->
                Parent ! {
                    Reference, owner_startup_ready,
                    contract_subject_owner(Commands)
                },
                receive {Reference, hold_owner} -> nil after 1500 -> nil end;
            _StartFailure ->
                Parent ! {Reference, owner_startup_failed}
        end
    end),
    Deadline = erlang:monotonic_time(millisecond) + 1000,
    ProbeOutcome = receive
        {Reference, owner_startup_probe, ObservedGuardian,
            ObservedOwnerProtected} ->
            {ok, ObservedGuardian, ObservedOwnerProtected};
        {Reference, owner_startup_failed} -> failed
    after contract_remaining(Deadline) -> timeout
    end,
    ReadyOutcome = receive
        {Reference, owner_startup_ready, ReadyGuardian} -> {ok, ReadyGuardian};
        {Reference, owner_startup_failed} -> failed
    after contract_remaining(Deadline) -> timeout
    end,
    case {ProbeOutcome, ReadyOutcome} of
        {{ok, Guardian, OwnerProtected}, {ok, Guardian}} ->
            GuardianMonitor = erlang:monitor(process, Guardian),
            exit(Owner, kill),
            OwnerDown = contract_await_down(Owner, OwnerMonitor, Deadline),
            Guardian ! {Reference, release_owner_startup},
            GuardianDown = contract_await_down(
                Guardian, GuardianMonitor, Deadline
            ),
            NeverExecuted = {
                atomics:get(Calls, 1), atomics:get(Calls, 2)
            } =:= {0, 0},
            CancelOnce = contract_counters(Counters) =:= {1, 0},
            NoTerminal = contract_subject_empty(Events),
            NoOrphan = not is_process_alive(Owner)
                andalso not is_process_alive(Guardian),
            [OwnerProtected, OwnerDown, GuardianDown, NeverExecuted,
                CancelOnce, NoTerminal, NoOrphan];
        _ ->
            exit(Owner, kill),
            [false, false, false, false, false, false, false]
    end.

http1_handler_cleanup_deadline_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() -> cleanup_deadline_result end,
    AfterResult = fun() ->
        Parent ! {Reference, cleanup_handler_ready, self()},
        receive {Reference, release_handler} -> nil after 5000 -> nil end
    end,
    case start_contract_guardian(
        Events, Run, Counters, AfterResult, keep_handler_alive,
        erlang:monotonic_time(millisecond) + 4000, 1500
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            case receive
                {Reference, cleanup_handler_ready, ObservedHandler} ->
                    {ok, ObservedHandler}
            after 750 -> timeout
            end of
                {ok, Handler} ->
                    Suspended = contract_suspend(Guardian),
                    RequestedAt = erlang:monotonic_time(millisecond),
                    contract_send_subject(Commands, {
                        terminate_handler, handler_stopped, RequestedAt
                    }),
                    contract_wait_until(RequestedAt + 1500),
                    Resumed = contract_resume(Guardian),
                    EventDeadline = erlang:monotonic_time(millisecond) + 500,
                    Event = contract_receive_subject(Events, EventDeadline),
                    Unconfirmed = Event =:= {
                        ok, {handler_cleanup_unconfirmed, handler_stopped}
                    },
                    HandlerRetained = is_process_alive(Handler),
                    GuardianRetained = is_process_alive(Guardian),
                    CancelOnce = contract_counters(Counters) =:= {1, 0},
                    Handler ! {Reference, release_handler},
                    JoinDeadline = erlang:monotonic_time(millisecond) + 1000,
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, JoinDeadline
                    ),
                    JoinedAndDiscarded = GuardianDown
                        andalso not is_process_alive(Handler)
                        andalso contract_counters(Counters) =:= {1, 1},
                    NoDuplicate = contract_subject_empty(Events),
                    [Suspended andalso Resumed, Unconfirmed, HandlerRetained,
                        GuardianRetained, CancelOnce, JoinedAndDiscarded,
                        NoDuplicate];
                timeout ->
                    _ = contract_resume(Guardian),
                    [false, false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false, false]
    end.

http1_handler_quarantine_retry_deadline_contract_run() ->
    Parent = self(),
    Reference = make_ref(),
    Counters = atomics:new(2, [{signed, false}]),
    TerminationCalls = atomics:new(1, [{signed, false}]),
    Events = contract_subject(),
    Run = fun() -> quarantine_retry_result end,
    AfterResult = fun() ->
        Parent ! {Reference, quarantine_handler_ready, self()},
        receive {Reference, release_handler} -> nil after 5000 -> nil end
    end,
    Probe = fun
        (3, Handler) ->
            Parent ! {
                Reference, quarantine_duplicate_dispatched, self(), Handler
            },
            receive
                {Reference, release_quarantine_dispatch} -> nil
            after 3000 -> nil
            end;
        (_, _) -> nil
    end,
    case start_contract_guardian_with_probe(
        Events, Run, Counters, Probe, AfterResult,
        {record_termination, TerminationCalls, Parent, Reference},
        erlang:monotonic_time(millisecond) + 5000, 1000
    ) of
        {ok, {GuardianMonitor, Commands}} ->
            Guardian = contract_subject_owner(Commands),
            case receive
                {Reference, quarantine_handler_ready, ObservedHandler} ->
                    {ok, ObservedHandler}
            after 750 -> timeout
            end of
                {ok, Handler} ->
                    RequestedAt = erlang:monotonic_time(millisecond),
                    contract_send_subject(Commands, {
                        terminate_handler, handler_stopped, RequestedAt
                    }),
                    Event = contract_receive_subject(
                        Events, RequestedAt + 1500
                    ),
                    Unconfirmed = Event =:= {
                        ok, {handler_cleanup_unconfirmed, handler_stopped}
                    },
                    FirstTerminationObserved = receive
                        {Reference, termination_called, 1, Guardian, _FirstAt} ->
                            true
                    after 250 -> false
                    end,
                    contract_send_subject(Commands, {
                        terminate_handler, handler_stopped, RequestedAt
                    }),
                    FirstDispatch = receive
                        {Reference, quarantine_duplicate_dispatched, Guardian,
                            Handler} -> true
                    after 500 -> false
                    end,
                    contract_wait_until(RequestedAt + 2000),
                    contract_send_subject(Commands, {
                        terminate_handler, handler_stopped, RequestedAt
                    }),
                    Guardian ! {Reference, release_quarantine_dispatch},
                    BoundaryOutcome = receive
                        {Reference, termination_called, 2, Guardian, RetryAt} ->
                            case RetryAt >= RequestedAt + 2000
                                andalso RetryAt =< RequestedAt + 2500
                            of
                                true -> retry_at_boundary;
                                false -> retry_outside_boundary
                            end;
                        {Reference, quarantine_duplicate_dispatched, Guardian,
                            Handler} -> duplicate_dispatched_before_retry
                    after 750 -> timeout
                    end,
                    SecondDispatch = case BoundaryOutcome of
                        retry_at_boundary ->
                            receive
                                {Reference, quarantine_duplicate_dispatched,
                                    Guardian, Handler} ->
                                    Guardian ! {
                                        Reference, release_quarantine_dispatch
                                    },
                                    true
                            after 500 -> false
                            end;
                        duplicate_dispatched_before_retry ->
                            Guardian ! {Reference, release_quarantine_dispatch},
                            false;
                        _ -> false
                    end,
                    RetryWhileTrafficActive = FirstDispatch
                        andalso BoundaryOutcome =:= retry_at_boundary
                        andalso SecondDispatch,
                    HandlerRetained = is_process_alive(Handler),
                    GuardianRetained = is_process_alive(Guardian),
                    CancelOnce = contract_counters(Counters) =:= {1, 0},
                    Handler ! {Reference, release_handler},
                    JoinDeadline = erlang:monotonic_time(millisecond) + 1000,
                    GuardianDown = contract_await_down(
                        Guardian, GuardianMonitor, JoinDeadline
                    ),
                    JoinedAndDiscarded = GuardianDown
                        andalso not is_process_alive(Handler)
                        andalso contract_counters(Counters) =:= {1, 1},
                    NoDuplicate = contract_subject_empty(Events),
                    [Unconfirmed, FirstTerminationObserved,
                        RetryWhileTrafficActive, HandlerRetained,
                        GuardianRetained, CancelOnce, JoinedAndDiscarded,
                        NoDuplicate];
                timeout ->
                    [false, false, false, false, false, false, false, false]
            end;
        _StartFailure ->
            [false, false, false, false, false, false, false, false]
    end.

start_contract_guardian(
    Events, Run, Counters, AfterResult, TerminationMode,
    HandlerDeadline, CleanupMilliseconds
) ->
    start_contract_guardian_with_probe(
        Events, Run, Counters, fun(_Phase, _Actor) -> nil end,
        AfterResult, TerminationMode, HandlerDeadline, CleanupMilliseconds
    ).

start_contract_guardian_with_probe(
    Events, Run, Counters, Probe, AfterResult, TerminationMode,
    HandlerDeadline, CleanupMilliseconds
) ->
    Cancel = fun() ->
        _ = atomics:add(Counters, 1, 1),
        nil
    end,
    Discard = fun(_Result) ->
        _ = atomics:add(Counters, 2, 1),
        nil
    end,
    Terminate = case TerminationMode of
        terminate_handler -> fun(Handler) -> exit(Handler, kill), nil end;
        keep_handler_alive -> fun(_Handler) -> nil end;
        {record_termination, TerminationCalls, Observer, Reference} ->
          fun(_Handler) ->
            _ = atomics:add(TerminationCalls, 1, 1),
            Count = atomics:get(TerminationCalls, 1),
            Observer ! {
                Reference, termination_called, Count, self(),
                erlang:monotonic_time(millisecond)
            },
            nil
          end
    end,
    http_server_ffi:start_http1_handler_guardian(
        Events, Run, Cancel, Discard, Probe, AfterResult, Terminate,
        HandlerDeadline, CleanupMilliseconds, 250
    ).

contract_subject() -> {subject, self(), make_ref()}.

contract_subject_owner({subject, Owner, _Tag}) -> Owner.

contract_send_subject({subject, Owner, Tag}, Message) ->
    Owner ! {Tag, Message},
    ok.

contract_receive_subject({subject, _Owner, Tag}, Deadline) ->
    receive {Tag, Message} -> {ok, Message}
    after contract_remaining(Deadline) -> timeout
    end.

contract_subject_empty({subject, _Owner, Tag}) ->
    receive {Tag, _Message} -> false after 0 -> true end.

contract_await_down(Process, Monitor, Deadline) ->
    receive {'DOWN', Monitor, process, Process, _Reason} -> true
    after contract_remaining(Deadline) -> false
    end.

contract_process_down(Process) ->
    not is_process_alive(Process).

contract_counters(Counters) ->
    {atomics:get(Counters, 1), atomics:get(Counters, 2)}.

contract_suspend(Process) ->
    try erlang:suspend_process(Process) of
        true -> true;
        _ -> false
    catch
        _:_ -> false
    end.

contract_resume(Process) ->
    try erlang:resume_process(Process) of
        true -> true;
        _ -> false
    catch
        _:_ -> false
    end.

contract_wait_until(Deadline) ->
    case contract_remaining(Deadline) of
        0 -> ok;
        Remaining -> receive after Remaining -> ok end
    end.

handler_has_guardian(Handler, Guardian) ->
    case {process_info(Handler, monitored_by), process_info(Handler, links)} of
        {{monitored_by, Watchers}, {links, Links}} ->
            lists:member(Guardian, Watchers) andalso lists:member(Guardian, Links);
        _ -> false
    end.

guardian_monitors_owner(Owner) ->
    case process_info(self(), monitors) of
        {monitors, Monitors} -> lists:member({process, Owner}, Monitors);
        _ -> false
    end.

contract_remaining(Deadline) ->
    erlang:max(0, erlang:min(
        2147483647,
        Deadline - erlang:monotonic_time(millisecond)
    )).

new_probe() -> ets:new(?MODULE, [public, set]).
record_handler(Probe) -> ets:insert(Probe, {handler, self()}), nil.
record_cleanup(Probe) ->
    _ = ets:update_counter(Probe, cleanups, 1, {cleanups, 0}),
    case handler_alive(Probe) of
        true -> _ = ets:update_counter(Probe, premature, 1, {premature, 0});
        false -> ok
    end,
    nil.
snapshot(Probe, Server) ->
    {controller, Handle, _Limits} = element(5, Server),
    {Workers, _Memory} = http_server_ffi:resource_snapshot(Handle),
    {handler_alive(Probe), Workers, counter(Probe, cleanups), counter(Probe, premature)}.
handler_alive(Probe) ->
    case ets:lookup(Probe, handler) of
        [{handler, Handler}] -> is_process_alive(Handler);
        [] -> false
    end.
counter(Probe, Key) ->
    case ets:lookup(Probe, Key) of [{Key, Value}] -> Value; [] -> 0 end.
executor(Server) -> element(2, Server).
pause_worker(Probe, Server) ->
    [{handler, Handler}] = ets:lookup(Probe, handler),
    {monitors, Monitors} = process_info(executor(Server), monitors),
    Candidates = [{Pid, Guardian} || {process, Pid} <- Monitors,
        Guardian <- find_guardian(Pid, Handler)],
    [{Reaper, Worker}] = Candidates,
    ets:insert(Probe, {reaper, Reaper}),
    true = erlang:suspend_process(Worker),
    Worker.
find_guardian(Pid, Handler) -> find_guardian(Pid, Handler, 2).
find_guardian(_Pid, _Handler, 0) -> [];
find_guardian(Pid, Handler, Depth) ->
    case process_info(Pid, monitors) of
        {monitors, Monitors} ->
            case lists:member({process, Handler}, Monitors) of
                true -> [Pid];
                false -> lists:append([find_guardian(Child, Handler, Depth - 1)
                    || {process, Child} <- Monitors, Child =/= self()])
            end;
        _ -> []
    end.
join_reaper(Probe) ->
    [{reaper, Reaper}] = ets:lookup(Probe, reaper),
    Monitor = monitor(process, Reaper),
    receive {'DOWN', Monitor, process, Reaper, _} -> true
    after 1000 -> demonitor(Monitor, [flush]), false end.
suspend(Pid) -> true = erlang:suspend_process(Pid), nil.
resume(Pid) ->
    try erlang:resume_process(Pid) catch error:badarg -> false end,
    nil.
dispose(Probe) ->
    case ets:lookup(Probe, handler) of
        [{handler, Handler}] -> exit(Handler, kill);
        [] -> ok
    end,
    ets:delete(Probe),
    nil.

await_dispatch(Server) -> await_dispatch(Server, erlang:monotonic_time(millisecond) + 1000).
await_dispatch(Server, Deadline) ->
    {messages, Messages} = process_info(executor(Server), messages),
    Queued = lists:any(fun
        ({_Ref, Command}) when is_tuple(Command), element(1, Command) =:= dispatch -> true;
        (_) -> false
    end, Messages),
    case {Queued, erlang:monotonic_time(millisecond) < Deadline} of
        {true, _} -> true;
        {false, true} -> receive after 1 -> await_dispatch(Server, Deadline) end;
        {false, false} -> false
    end.

reaper_retains_until_down() ->
    Parent = self(),
    Controller = http_server_ffi:new_resource_controller(1, 64),
    {ok, Lease} = http_server_ffi:resource_acquire(Controller, 64),
    Token = http_server_ffi:new_token(),
    Ref = make_ref(),
    Run = fun() ->
        true = http_server_ffi:adopt_token(Token),
        {Child, ChildMonitor} = spawn_monitor(fun() -> ok end),
        receive {'DOWN', ChildMonitor, process, Child, _} -> ok end,
        Parent ! {Ref, guardian_ready, self()},
        receive {Ref, finish} -> release_lease after 1000 -> release_lease end
    end,
    Release = fun() ->
        http_server_ffi:resource_release(Controller, Lease),
        Parent ! {Ref, released}
    end,
    {Reaper, ReaperMonitor} = spawn_monitor(fun() ->
        http_server_ffi:reap_worker(Token, {subject, Parent, make_ref()}, Run, Release)
    end),
    receive {Ref, guardian_ready, Guardian} ->
        Held = http_server_ffi:resource_snapshot(Controller) =:= {1, 64},
        Refused = case http_server_ffi:resource_acquire(Controller, 64) of
            {error, _} -> true;
            {ok, Unexpected} -> http_server_ffi:resource_release(Controller, Unexpected), false
        end,
        NoEarlyRelease = receive {Ref, released} -> false after 0 -> true end,
        Guardian ! {Ref, finish},
        Joined = receive {'DOWN', ReaperMonitor, process, Reaper, _} -> true
            after 1000 -> false end,
        Released = receive {Ref, released} -> true after 0 -> false end,
        Final = http_server_ffi:resource_snapshot(Controller) =:= {0, 0},
        {Held, Refused, NoEarlyRelease, Joined andalso Released andalso Final,
            not is_process_alive(Guardian)}
    after 1000 -> exit(Reaper, kill), {false, false, false, false, false}
    end.

unadopted_reaper_does_not_release() ->
    Controller = http_server_ffi:new_resource_controller(1, 64),
    {ok, Lease} = http_server_ffi:resource_acquire(Controller, 64),
    Token = http_server_ffi:new_token(),
    true = http_server_ffi:abandon_token(Token),
    Calls = atomics:new(1, [{signed, false}]),
    {Reaper, Monitor} = spawn_monitor(fun() ->
        http_server_ffi:reap_worker(Token, {subject, self(), make_ref()},
            fun() -> release_lease end,
            fun() ->
                atomics:add(Calls, 1, 1),
                http_server_ffi:resource_release(Controller, Lease)
            end)
    end),
    Joined = receive {'DOWN', Monitor, process, Reaper, _} -> true
        after 1000 -> false end,
    Held = http_server_ffi:resource_snapshot(Controller) =:= {1, 64},
    CallsBeforeCallerCleanup = atomics:get(Calls, 1),
    http_server_ffi:resource_release(Controller, Lease),
    {Joined, Held, CallsBeforeCallerCleanup =:= 0}.

quarantined_reaper_does_not_release() ->
    Controller = http_server_ffi:new_resource_controller(1, 64),
    {ok, Lease} = http_server_ffi:resource_acquire(Controller, 64),
    Token = http_server_ffi:new_token(),
    Calls = atomics:new(1, [{signed, false}]),
    {Reaper, Monitor} = spawn_monitor(fun() ->
        http_server_ffi:reap_worker(
            Token,
            {subject, self(), make_ref()},
            fun() ->
                true = http_server_ffi:adopt_token(Token),
                quarantine_lease
            end,
            fun() ->
                atomics:add(Calls, 1, 1),
                http_server_ffi:resource_release(Controller, Lease)
            end
        )
    end),
    Joined = receive {'DOWN', Monitor, process, Reaper, _} -> true
        after 1000 -> false end,
    Held = http_server_ffi:resource_snapshot(Controller) =:= {1, 64},
    NotReleased = atomics:get(Calls, 1) =:= 0,
    http_server_ffi:resource_release(Controller, Lease),
    {Joined, Held, NotReleased}.
