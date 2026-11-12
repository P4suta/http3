%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_admission_recovery_tests).
-include_lib("eunit/include/eunit.hrl").

pending_ticket_reconciles_after_late_owner_join_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Reservation = required(quic_core_qlog_admission_ffi:reserve(
            Identity, 1, 1, 1)),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Reservation) =:=
            {ok, nil}),
        Cleanup = atomics:new(1, [{signed, false}]),
        Parent = self(), Gate = make_ref(),
        {Owner, Monitor} = spawn_monitor(fun() ->
            Parent ! {Gate, ready},
            receive
                {Gate, release} -> atomics:put(Cleanup, 1, 1)
            after 2000 -> ok
            end
        end),
        try
            receive {Gate, ready} -> ok after 1000 -> ?assert(false) end,
            Ticket = {qlog_cleanup_ticket, Owner, undefined, Cleanup},
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending),
            nil = quic_core_qlog_admission_ffi:collect(
                Reservation, Ticket),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1, 1}),
            Owner ! {Gate, release},
            ?assert(joined(Owner, Monitor)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= released),
            ?assert(await_snapshot(Identity, {0, 0}, 1000))
        after
            Owner ! {Gate, release},
            stop_owner(Owner, Monitor),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Reservation)
        end.

duplicate_collection_registers_and_releases_exactly_once_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Reservation = begun_reservation(Identity, 1),
        {Owner, Monitor, Gate, Cleanup} = cleanup_owner(),
        Ticket = {qlog_cleanup_ticket, Owner, undefined, Cleanup},
        try
            ?assert(parallel_collect(Reservation, Ticket, 16) =:= ok),
            ?assert(quic_core_qlog_admission_ffi:reconciliation_snapshot(
                Identity) =:= {16, 1, 0, 0, 0, 1}),
            Owner ! {Gate, release},
            ?assert(joined(Owner, Monitor)),
            ?assert(await_snapshot(Identity, {0, 0}, 1000)),
            ?assert(await_reconciliation(
                Identity, {16, 1, 0, 1, 0, 0}, 1000)),
            lists:foreach(fun(_) ->
                nil = quic_core_qlog_admission_ffi:release_confirmed(Reservation)
            end, lists:seq(1, 16)),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0})
        after
            Owner ! {Gate, release},
            stop_owner(Owner, Monitor),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Reservation)
        end.

every_ticket_owner_must_join_before_recovery_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Reservation = begun_reservation(Identity, 1),
        {Guardian, GuardianMonitor, GuardianGate, Cleanup} = cleanup_owner(),
        {Admission, AdmissionMonitor, AdmissionGate, _} = cleanup_owner(),
        Ticket = {qlog_cleanup_ticket, Guardian, Admission, Cleanup},
        try
            nil = quic_core_qlog_admission_ffi:collect(
                Reservation, Ticket),
            Guardian ! {GuardianGate, release},
            ?assert(joined(Guardian, GuardianMonitor)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1, 1}),
            ?assert(quic_core_qlog_admission_ffi:reconciliation_snapshot(
                Identity) =:= {1, 1, 0, 0, 0, 1}),
            Admission ! {AdmissionGate, release},
            ?assert(joined(Admission, AdmissionMonitor)),
            ?assert(await_snapshot(Identity, {0, 0}, 1000)),
            ?assert(await_reconciliation(
                Identity, {1, 1, 0, 1, 0, 0}, 1000))
        after
            Guardian ! {GuardianGate, release},
            Admission ! {AdmissionGate, release},
            stop_owner(Guardian, GuardianMonitor),
            stop_owner(Admission, AdmissionMonitor),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Reservation)
        end.

reconciliation_deadline_is_finite_and_keeps_unconfirmed_charge_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Reservation = begun_reservation(Identity, 1),
        {Owner, Monitor, Gate, Cleanup} = cleanup_owner(),
        Ticket = {qlog_cleanup_ticket, Owner, undefined, Cleanup},
        try
            nil = quic_core_qlog_admission_ffi:collect_with_deadline(
                Reservation, Ticket, 25),
            ?assert(await_reconciliation(
                Identity, {1, 1, 0, 0, 1, 0}, 1000)),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1, 1}),
            Owner ! {Gate, release},
            ?assert(joined(Owner, Monitor)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= released),
            ?assert(not await_snapshot(Identity, {0, 0}, 25)),
            nil = quic_core_qlog_admission_ffi:collect(
                Reservation, Ticket),
            ?assert(await_snapshot(Identity, {0, 0}, 1000))
        after
            Owner ! {Gate, release},
            stop_owner(Owner, Monitor),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Reservation)
        end.

retained_ticket_registry_has_a_hard_capacity_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Reservations = [begun_reservation(Identity, 65)
                        || _ <- lists:seq(1, 65)],
        Fixtures = [cleanup_owner() || _ <- lists:seq(1, 65)],
        Pairs = lists:zip(Reservations, Fixtures),
        try
            lists:foreach(fun({Reservation, {Owner, _, _, Cleanup}}) ->
                Ticket = {qlog_cleanup_ticket, Owner, undefined, Cleanup},
                nil = quic_core_qlog_admission_ffi:collect_with_deadline(
                    Reservation, Ticket, 2000)
            end, Pairs),
            ?assert(quic_core_qlog_admission_ffi:reconciliation_snapshot(
                Identity) =:= {65, 64, 1, 0, 0, 64}),
            release_fixtures(Fixtures),
            ?assert(await_reconciliation(
                Identity, {65, 64, 1, 64, 0, 0}, 1500)),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1, 1}),
            {LastReservation, {LastOwner, _, _, LastCleanup}} = lists:last(Pairs),
            LastTicket = {
                qlog_cleanup_ticket, LastOwner, undefined, LastCleanup
            },
            nil = quic_core_qlog_admission_ffi:collect(
                LastReservation, LastTicket),
            ?assert(await_snapshot(Identity, {0, 0}, 1000))
        after
            release_fixtures(Fixtures),
            lists:foreach(fun quic_core_qlog_admission_ffi:release_confirmed/1,
                          Reservations)
        end.

linked_scalar_releases_with_immediate_core_confirmation_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Dependent = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 1, 2)),
        Primary = required(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Dependent})),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Primary) =:= {ok, nil}),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Dependent) =:= {ok, nil}),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {2, 1}),
        nil = quic_core_qlog_admission_ffi:collect(
            Primary, no_cleanup),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}),
        nil = quic_core_qlog_admission_ffi:release_confirmed(Primary),
        nil = quic_core_qlog_admission_ffi:release_confirmed(Dependent),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}).

linked_unopened_scalar_releases_when_opened_core_confirms_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Dependent = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 1, 2)),
        Primary = required(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Dependent})),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Primary) =:= {ok, nil}),
        nil = quic_core_qlog_admission_ffi:collect(Primary, no_cleanup),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Dependent) =:=
            {error, nil}),
        nil = quic_core_qlog_admission_ffi:release_confirmed(Primary),
        nil = quic_core_qlog_admission_ffi:release_confirmed(Dependent),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}).

linked_scalar_begin_racing_core_settlement_releases_once_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Dependent = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 1, 2)),
        Primary = required(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Dependent})),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Primary) =:= {ok, nil}),
        Parent = self(), Gate = make_ref(),
        {Settler, Monitor} = spawn_monitor(fun() ->
            erlang:put({quic_core_qlog_admission_ffi, test_probe},
                {Parent, Gate, settlement_claimed}),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Primary)
        end),
        try
            receive {Gate, settlement_claimed} -> ok
            after 1000 -> ?assert(false) end,
            ?assert(quic_core_qlog_admission_ffi:begin_open(Dependent) =:=
                {ok, nil}),
            Settler ! {Gate, continue},
            ?assert(joined(Settler, Monitor)),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Primary),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Dependent),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0})
        after
            Settler ! {Gate, continue},
            stop_owner(Settler, Monitor),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Primary),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Dependent)
        end.

linked_scalar_releases_after_late_core_owner_join_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Dependent = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 1, 2)),
        Primary = required(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Dependent})),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Primary) =:= {ok, nil}),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Dependent) =:= {ok, nil}),
        {Owner, Monitor, Gate, Cleanup} = cleanup_owner(),
        Ticket = {qlog_cleanup_ticket, Owner, undefined, Cleanup},
        try
            nil = quic_core_qlog_admission_ffi:collect(
                Primary, Ticket),
            ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {2, 1}),
            Owner ! {Gate, release},
            ?assert(joined(Owner, Monitor)),
            ?assert(await_snapshot(Identity, {0, 0}, 1000)),
            ?assert(await_reconciliation(
                Identity, {1, 1, 0, 1, 0, 0}, 1000))
        after
            Owner ! {Gate, release},
            stop_owner(Owner, Monitor),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Primary),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Dependent)
        end.

linked_scalar_remains_unopened_when_core_start_is_unused_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Dependent = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 1, 2)),
        Primary = required(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Dependent})),
        nil = quic_core_qlog_admission_ffi:release_unused(Primary),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1, 0}),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Dependent) =:= {ok, nil}),
        nil = quic_core_qlog_admission_ffi:release_confirmed(Dependent),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}).

cross_identity_or_started_dependency_is_rejected_test() ->
        Identity = quic_core_qlog_admission_ffi:new(),
        Other = quic_core_qlog_admission_ffi:new(),
        Foreign = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Other, 1, 1)),
        Started = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 1, 2)),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Started) =:= {ok, nil}),
        ?assert(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Foreign}) =:= {error, 2}),
        ?assert(quic_core_qlog_admission_ffi:reserve_linked(
            Identity, 1, 2, 1, {some, Started}) =:= {error, 2}),
        nil = quic_core_qlog_admission_ffi:release_unused(Foreign),
        nil = quic_core_qlog_admission_ffi:release_confirmed(Started),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0, 0}),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Other) =:= {0, 0}).

required({ok, Value}) -> Value;
required(_) -> ?assert(false).

begun_reservation(Identity, Maximum) ->
    Reservation = required(quic_core_qlog_admission_ffi:reserve(
        Identity, 1, Maximum, Maximum)),
    case quic_core_qlog_admission_ffi:begin_open(Reservation) of
        {ok, nil} -> Reservation;
        _ -> erlang:error(begin_open_failed)
    end.

cleanup_owner() ->
    Parent = self(), Gate = make_ref(),
    Cleanup = atomics:new(1, [{signed, false}]),
    {Owner, Monitor} = spawn_monitor(fun() ->
        Parent ! {Gate, ready},
        receive
            {Gate, release} -> atomics:put(Cleanup, 1, 1)
        after 3000 -> ok
        end
    end),
    receive
        {Gate, ready} -> {Owner, Monitor, Gate, Cleanup}
    after 1000 ->
        exit(Owner, kill),
        _ = joined(Owner, Monitor),
        erlang:error(cleanup_owner_ready_timeout)
    end.

release_fixtures(Fixtures) ->
    lists:foreach(fun({Owner, _, Gate, _}) ->
        Owner ! {Gate, release}
    end, Fixtures),
    lists:foreach(fun({Owner, Monitor, _, _}) ->
        case joined(Owner, Monitor) of
            true -> ok;
            false -> exit(Owner, kill), _ = joined(Owner, Monitor), ok
        end
    end, Fixtures).

parallel_collect(Reservation, Ticket, Count) ->
    Parent = self(), Gate = make_ref(),
    Workers = [spawn_monitor(fun() ->
        receive
            {Gate, start} ->
                nil = quic_core_qlog_admission_ffi:collect(
                    Reservation, Ticket),
                Parent ! {Gate, completed}
        after 1000 -> ok
        end
    end) || _ <- lists:seq(1, Count)],
    lists:foreach(fun({Pid, _}) -> Pid ! {Gate, start} end, Workers),
    Completed = collect_completions(Gate, Count, 1000),
    Joined = lists:all(fun({Pid, Monitor}) -> joined(Pid, Monitor) end, Workers),
    case Completed andalso Joined of
        true -> ok;
        false -> error
    end.

collect_completions(_Gate, 0, _Milliseconds) -> true;
collect_completions(Gate, Remaining, Milliseconds) ->
    receive
        {Gate, completed} ->
            collect_completions(Gate, Remaining - 1, Milliseconds)
    after Milliseconds -> false
    end.

await_snapshot(Identity, Expected, Milliseconds) ->
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    await_snapshot_until(Identity, Expected, Deadline).

await_snapshot_until(Identity, Expected, Deadline) ->
    Current = quic_core_qlog_admission_ffi:snapshot(Identity),
    case Current =:= Expected orelse
            erlang:monotonic_time(millisecond) >= Deadline of
        true -> Current =:= Expected;
        false -> receive after 1 ->
            await_snapshot_until(Identity, Expected, Deadline)
        end
    end.

await_reconciliation(Identity, Expected, Milliseconds) ->
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    await_reconciliation_until(Identity, Expected, Deadline).

await_reconciliation_until(Identity, Expected, Deadline) ->
    Current = quic_core_qlog_admission_ffi:reconciliation_snapshot(Identity),
    case Current =:= Expected orelse
            erlang:monotonic_time(millisecond) >= Deadline of
        true -> Current =:= Expected;
        false -> receive after 1 ->
            await_reconciliation_until(Identity, Expected, Deadline)
        end
    end.

joined(Pid, Monitor) ->
    case is_process_alive(Pid) of
        false -> erlang:demonitor(Monitor, [flush]), true;
        true ->
            receive {'DOWN', Monitor, process, Pid, _} -> true
            after 1000 -> false
            end
    end.

stop_owner(Pid, Monitor) ->
    case is_process_alive(Pid) of
        true -> exit(Pid, kill), _ = joined(Pid, Monitor), ok;
        false -> erlang:demonitor(Monitor, [flush]), ok
    end.
