%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Garbage-collected admission identity shared by Client copies. Static writer
%% working sets and accepted-but-unfinished events use one finite packed ledger.
%% Pending native cleanup is retained by a bounded, deadline-owned reconciler;
%% unused configuration still allocates no actor, table, timer, path or ticket.
-module(quic_core_qlog_admission_ffi).
-export([new/0, reserve/4, reserve_linked/5, reserve_auxiliary/3,
         reserve_auxiliary/4,
         begin_open/1, release_unused/1,
         release_confirmed/1, collect/2, collect_with_deadline/3,
         bind_writer/2, reserve_event/2, release_events/3, snapshot/1,
         event_snapshot/1, reconciliation_snapshot/1,
         reservation_snapshot/1]).
-define(BASE, 4294967296).
-define(MAXIMUM, 2147483647).
-define(MAX_RECONCILIATIONS, 64).
-define(MAX_CLEANUP_OWNERS, 2).
-define(RECONCILIATION_MILLISECONDS, 7000).
-opaque identity() :: {qlog_admission, atomics:atomics_ref(),
                       atomics:atomics_ref(), atomics:atomics_ref()}.
-opaque reservation() :: {qlog_reservation, atomics:atomics_ref(),
                           pos_integer(), pos_integer(), atomics:atomics_ref(),
                           atomics:atomics_ref(), atomics:atomics_ref(),
                           atomics:atomics_ref(), atomics:atomics_ref(),
                           atomics:atomics_ref(), atomics:atomics_ref(),
                           none | {dependent, reservation()}}.
-export_type([identity/0, reservation/0]).

-spec new() -> identity().
new() ->
    {qlog_admission, atomics:new(1, [{signed,true}]),
     atomics:new(5, [{signed,true}]),
     atomics:new(6, [{signed,true}])}.

-spec reserve(identity(), pos_integer(), pos_integer(), pos_integer()) ->
    {ok, reservation()} | {error, 1 | 2}.
reserve({qlog_admission, Ledger, Counters, Registry}, Charge, Maximum, Connections)
  when is_integer(Charge), Charge > 0, Charge =< ?MAXIMUM,
       is_integer(Maximum), Maximum > 0, Maximum =< ?MAXIMUM,
       is_integer(Connections), Connections > 0, Connections =< ?MAXIMUM ->
    %% 0 = held but no qlog opening has begun, 1 = opening may own I/O,
    %% 2 = closing excludes new operations, 3 = one closer owns settlement,
    %% 4 = returned. Active counts operations which observed state 1. Closing
    %% first changes the lifecycle and then waits for that count, so it cannot
    %% race a dynamic debit/credit. An interrupted operation or settler can
    %% only quarantine capacity; no interleaving can invent credit.
    State = atomics:new(1, [{signed,true}]),
    Active = atomics:new(1, [{signed,true}]),
    HeldEvents = atomics:new(1, [{signed,true}]),
    EventBytes = atomics:new(1, [{signed,true}]),
    Recovery = atomics:new(1, [{signed,true}]),
    reserve(
        Ledger, Counters, Charge, Maximum, Connections, State,
        Active, HeldEvents, EventBytes, Registry, Recovery, none, 32
    );
reserve(_, _, _, _) -> {error, 1}.

%% Attach one already funded higher-layer scalar reservation to the next core
%% writer without importing any higher-layer type. Both tokens must share the
%% same identity ledger, and the dependent must still be unopened.
-spec reserve_linked(
    identity(), pos_integer(), pos_integer(), pos_integer(),
    none | {some, reservation()}
) -> {ok, reservation()} | {error, 1 | 2}.
reserve_linked(
    {qlog_admission, Ledger, Counters, Registry},
    Charge, Maximum, Connections, Dependency
) when is_integer(Charge), Charge > 0, Charge =< ?MAXIMUM,
       is_integer(Maximum), Maximum > 0, Maximum =< ?MAXIMUM,
       is_integer(Connections), Connections > 0, Connections =< ?MAXIMUM ->
    case normalize_dependency(Dependency, Ledger) of
        error -> {error, 2};
        Dependent ->
            State = atomics:new(1, [{signed,true}]),
            Active = atomics:new(1, [{signed,true}]),
            HeldEvents = atomics:new(1, [{signed,true}]),
            EventBytes = atomics:new(1, [{signed,true}]),
            Recovery = atomics:new(1, [{signed,true}]),
            reserve(
                Ledger, Counters, Charge, Maximum, Connections, State,
                Active, HeldEvents, EventBytes, Registry, Recovery,
                Dependent, 32
            )
    end;
reserve_linked(_, _, _, _, _) -> {error, 1}.

normalize_dependency(none, _Ledger) -> none;
normalize_dependency(
    {some, Token = {qlog_reservation, Ledger, _, _, State, _, _, _, _, _,
                    _, none}},
    Ledger
) ->
    case atomics:get(State, 1) of
        0 -> {dependent, Token};
        _ -> error
    end;
normalize_dependency(_, _) -> error.

%% Reserve higher-layer diagnostic state in the same byte ledger without
%% claiming a second connection slot. The core writer reservation remains the
%% sole owner of that slot, while both charges compete atomically for the same
%% EndpointMemory ceiling.
-spec reserve_auxiliary(identity(), pos_integer(), pos_integer()) ->
    {ok, reservation()} | {error, 1 | 2}.
reserve_auxiliary(Identity, Charge, Maximum) ->
    reserve_auxiliary(Identity, Charge, Maximum, ?MAXIMUM).

%% Reject a diagnostic contender from an already full shared connection set
%% before byte pressure is classified. This is a preflight only: the linked
%% core writer remains the sole operation that actually claims a slot.
-spec reserve_auxiliary(
    identity(), pos_integer(), pos_integer(), pos_integer()
) -> {ok, reservation()} | {error, 1 | 2}.
reserve_auxiliary(
    {qlog_admission, Ledger, Counters, Registry}, Charge, Maximum, Connections
)
  when is_integer(Charge), Charge > 0, Charge =< ?MAXIMUM,
       is_integer(Maximum), Maximum > 0, Maximum =< ?MAXIMUM,
       is_integer(Connections), Connections > 0, Connections =< ?MAXIMUM ->
    State = atomics:new(1, [{signed,true}]),
    Active = atomics:new(1, [{signed,true}]),
    HeldEvents = atomics:new(1, [{signed,true}]),
    EventBytes = atomics:new(1, [{signed,true}]),
    Recovery = atomics:new(1, [{signed,true}]),
    reserve_auxiliary(
        Ledger, Counters, Charge, Maximum, Connections, State,
        Active, HeldEvents, EventBytes, Registry, Recovery, none, 1024
    );
reserve_auxiliary(_, _, _, _) -> {error, 1}.

reserve_auxiliary(_, _, _, _, _, _, _, _, _, _, _, _, 0) -> {error, 2};
reserve_auxiliary(Ledger, Counters, Charge, Maximum, Connections, State,
                  Active, HeldEvents, EventBytes, Registry, Recovery,
                  Dependent, Attempts) ->
    Current = atomics:get(Ledger, 1),
    Bytes = Current div ?BASE, Count = Current rem ?BASE,
    case Count >= Connections of
        true -> {error, 2};
        false when Bytes + Charge > Maximum -> {error, 1};
        false ->
            Amount = Charge * ?BASE,
            case atomics:compare_exchange(Ledger, 1, Current, Current + Amount) of
                ok -> {ok, {qlog_reservation, Ledger, Amount, Maximum, State,
                            Active, HeldEvents, EventBytes, Counters,
                            Registry, Recovery, Dependent}};
                _ -> reserve_auxiliary(
                    Ledger, Counters, Charge, Maximum, Connections, State,
                    Active, HeldEvents, EventBytes, Registry, Recovery,
                    Dependent, Attempts - 1
                )
            end
    end.

reserve(_, _, _, _, _, _, _, _, _, _, _, _, 0) -> {error, 2};
reserve(Ledger, Counters, Charge, Maximum, Connections, State,
        Active, HeldEvents, EventBytes, Registry, Recovery, Dependent,
        Attempts) ->
    Current = atomics:get(Ledger, 1),
    Bytes = Current div ?BASE, Count = Current rem ?BASE,
    case Count >= Connections of
        true -> {error, 2};
        false when Bytes + Charge > Maximum -> {error, 1};
        false ->
            Amount = Charge * ?BASE + 1,
            case atomics:compare_exchange(Ledger, 1, Current, Current + Amount) of
                ok -> {ok, {qlog_reservation, Ledger, Amount, Maximum, State,
                            Active, HeldEvents, EventBytes, Counters,
                            Registry, Recovery, Dependent}};
                _ -> reserve(Ledger, Counters, Charge, Maximum, Connections,
                             State, Active, HeldEvents, EventBytes,
                             Registry, Recovery, Dependent, Attempts-1)
            end
    end.

-spec begin_open(reservation()) -> {ok, nil} | {error, nil}.
begin_open({qlog_reservation, _, _, _, State, _, _, _, _, _, _, _}) ->
    case atomics:compare_exchange(State, 1, 0, 1) of
        ok -> {ok,nil};
        _ -> {error,nil}
    end.

%% Call only after the established bootstrap group has actually joined.
-spec release_unused(reservation()) -> nil.
release_unused(
    {qlog_reservation, Ledger, Amount, _, State, _, _, _, _, _, _, _}
) ->
    case atomics:compare_exchange(State, 1, 0, 3) of
        ok ->
            case ledger_release(Ledger, Amount, 1024) of
                true -> atomics:put(State, 1, 4), nil;
                false -> nil
            end;
        _ -> nil
    end.

%% The caller must first observe qlog cleanup_state = Released. A pending
%% native opening never reaches this function, including before publication.
-spec release_confirmed(reservation()) -> nil.
release_confirmed(
    Token = {qlog_reservation, _, _, _, State, _, _, _, _, _, _, _}
) ->
    try
        case atomics:get(State, 1) of
            1 ->
                _ = atomics:compare_exchange(State, 1, 1, 2),
                maybe_checkpoint(closing),
                settle_confirmed(Token);
            2 -> settle_confirmed(Token);
            _ -> nil
        end
    catch _:_ -> nil end.

settle_confirmed({qlog_reservation, Ledger, Amount, _, State, Active,
                  HeldEvents, EventBytes, Counters, _, _, Dependent}) ->
    case await_quiescent(Active, 1024) andalso
         atomics:compare_exchange(State, 1, 2, 3) =:= ok of
        false -> nil;
        true ->
            maybe_checkpoint(settlement_claimed),
            Events = erlang:max(0, atomics:exchange(HeldEvents, 1, 0)),
            Bytes = erlang:max(0, atomics:get(EventBytes, 1)),
            Dynamic = Events * Bytes,
            case ledger_release(Ledger, Amount + Dynamic * ?BASE, 1024) of
                true ->
                    counter_add(Counters, 4, Events),
                    counter_sub(Counters, 5, Events),
                    release_dependent(Dependent),
                    atomics:put(State, 1, 4),
                    nil;
                false ->
                    %% Nothing was credited. Restore the locally known events
                    %% and permit a later confirmed collection to retry.
                    _ = atomics:add_get(HeldEvents, 1, Events),
                    atomics:put(State, 1, 2),
                    nil
            end
    end.

release_dependent(none) -> nil;
release_dependent({dependent, Token}) ->
    %% The higher layer may not have crossed its opening boundary when the core
    %% cleanup wins.  Trying both affine transitions closes that race: exactly
    %% one of State 0 -> 3 or State 1/2 -> 3 can own the ledger credit.
    release_unused(Token),
    release_confirmed(Token).

%% Retain one opaque native cleanup ticket only while its finite owner set can
%% still prove a later join. The reservation-local CAS admits one reconciler;
%% the existing lifecycle CAS remains the sole authority that returns credit.
-spec collect(reservation(), term()) -> nil.
collect(Token, Ticket) ->
    collect_with_deadline(Token, Ticket, ?RECONCILIATION_MILLISECONDS).

%% Injectable deadline for deterministic qualification. Production always
%% uses the fixed seven-second bound above.
-spec collect_with_deadline(reservation(), term(), pos_integer()) -> nil.
collect_with_deadline(
    Token = {qlog_reservation, _, _, _, State, _, _, _, _, Registry, Recovery,
             _},
    Ticket,
    Milliseconds
) when is_integer(Milliseconds), Milliseconds > 0,
       Milliseconds =< ?RECONCILIATION_MILLISECONDS ->
    try
        case quic_core_qlog_ffi:cleanup_state(Ticket) of
            released -> release_confirmed(Token);
            pending ->
                case atomics:get(State, 1) of
                    1 -> register_reconciliation(
                        Token, Ticket, Registry, Recovery, Milliseconds
                    );
                    _ -> nil
                end
        end
    catch _:_ -> nil end;
collect_with_deadline(_, _, _) -> nil.

register_reconciliation(Token, Ticket, Registry, Recovery, Milliseconds) ->
    counter_add(Registry, 1, 1),
    case atomics:compare_exchange(Recovery, 1, 0, 1) of
        ok ->
            Owners = lists:usort(quic_core_qlog_ffi:cleanup_owners(Ticket)),
            case valid_cleanup_owners(Owners) andalso
                    claim_reconciliation_slot(Registry, 32) of
                false ->
                    atomics:put(Recovery, 1, 3),
                    counter_add(Registry, 3, 1),
                    nil;
                true ->
                    atomics:put(Recovery, 1, 2),
                    counter_add(Registry, 2, 1),
                    try
                        _ = spawn_opt(fun() ->
                            reconcile_cleanup(
                                Token, Ticket, Owners, Registry, Recovery,
                                Milliseconds
                            )
                        end, [{message_queue_data, off_heap},
                              {max_heap_size, #{size => 65536, kill => true,
                                                error_logger => false}}]),
                        nil
                    catch _:_ ->
                        counter_sub(Registry, 2, 1),
                        counter_add(Registry, 3, 1),
                        release_reconciliation_slot(Registry),
                        atomics:put(Recovery, 1, 3),
                        nil
                    end
            end;
        _ -> nil
    end.

valid_cleanup_owners(Owners) ->
    Owners =/= [] andalso length(Owners) =< ?MAX_CLEANUP_OWNERS andalso
        lists:all(fun erlang:is_pid/1, Owners).

claim_reconciliation_slot(_Registry, 0) -> false;
claim_reconciliation_slot(Registry, Attempts) ->
    Held = atomics:get(Registry, 6),
    case Held >= ?MAX_RECONCILIATIONS of
        true -> false;
        false ->
            case atomics:compare_exchange(Registry, 6, Held, Held + 1) of
                ok -> true;
                _ -> claim_reconciliation_slot(Registry, Attempts - 1)
            end
    end.

release_reconciliation_slot(Registry) -> counter_sub(Registry, 6, 1).

reconcile_cleanup(Token, Ticket, Owners, Registry, Recovery, Milliseconds) ->
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    Monitors = [{erlang:monitor(process, Owner), Owner} || Owner <- Owners],
    try
        case await_cleanup_release(Ticket, Monitors, Deadline) of
            released ->
                release_confirmed(Token),
                case await_reservation_return(Token, Deadline) of
                    true ->
                        atomics:put(Recovery, 1, 4),
                        counter_add(Registry, 4, 1);
                    false ->
                        atomics:put(Recovery, 1, 3),
                        counter_add(Registry, 5, 1)
                end;
            expired ->
                atomics:put(Recovery, 1, 3),
                counter_add(Registry, 5, 1)
        end
    catch _:_ ->
        atomics:put(Recovery, 1, 3),
        counter_add(Registry, 5, 1)
    after
        lists:foreach(fun({Monitor, _}) ->
            erlang:demonitor(Monitor, [flush])
        end, Monitors),
        release_reconciliation_slot(Registry)
    end.

await_cleanup_release(Ticket, Monitors, Deadline) ->
    case quic_core_qlog_ffi:cleanup_state(Ticket) of
        released -> released;
        pending ->
            Remaining = erlang:max(
                0, Deadline - erlang:monotonic_time(millisecond)
            ),
            case Remaining of
                0 -> expired;
                _ ->
                    receive
                        {'DOWN', Monitor, process, Owner, _}
                          when is_reference(Monitor), is_pid(Owner) ->
                            await_cleanup_release(
                                Ticket,
                                lists:keydelete(Monitor, 1, Monitors),
                                Deadline
                            )
                    after Remaining -> expired
                    end
            end
    end.

await_reservation_return(
    {qlog_reservation, _, _, _, State, _, _, _, _, _, _, _}, Deadline
) ->
    case atomics:get(State, 1) of
        4 -> true;
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false -> receive after 1 ->
                    await_reservation_return_state(State, Deadline)
                end
            end
    end.

await_reservation_return_state(State, Deadline) ->
    case atomics:get(State, 1) of
        4 -> true;
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false -> receive after 1 ->
                    await_reservation_return_state(State, Deadline)
                end
            end
    end.

%% One accepted-but-unfinished event is charged to the stable Client identity.
%% Error 1 is resource refusal; error 2 is a stale or malformed token.
-spec bind_writer(reservation(), pos_integer()) -> boolean().
bind_writer(Token = {qlog_reservation, _, _, _, _, _, _, _, _, _, _, _}, Bytes)
  when is_integer(Bytes), Bytes > 0, Bytes =< ?MAXIMUM ->
    case active_enter(Token) of
        false -> false;
        true ->
            try bind_event_bytes(Token, Bytes)
            catch _:_ -> false
            after active_leave(Token)
            end
    end;
bind_writer(_, _) -> false.

-spec reserve_event(reservation(), pos_integer()) -> {ok, nil} | {error, 1 | 2}.
reserve_event(
    Token = {qlog_reservation, _, _, _, _, _, _, _, Counters, _, _, _}, Bytes
)
  when is_integer(Bytes), Bytes > 0, Bytes =< ?MAXIMUM ->
    try
        counter_add(Counters, 1, 1),
        case active_enter(Token) of
            false -> counter_add(Counters, 3, 1), {error, 2};
            true ->
                try reserve_event_active(Token, Bytes)
                after active_leave(Token)
                end
        end
    catch _:_ -> {error, 2} end;
reserve_event(_, _) -> {error, 2}.

reserve_event_active(Token, Bytes) ->
    case bind_event_bytes(Token, Bytes) of
        false ->
            counter_add(reservation_counters(Token), 3, 1),
            {error, 2};
        true -> reserve_event_cas(Token, Bytes, 32)
    end.

reserve_event_cas({qlog_reservation, _, _, _, _, _, _, _, Counters, _, _, _},
                  _Bytes, 0) ->
    counter_add(Counters, 3, 1), {error, 1};
reserve_event_cas(Token = {qlog_reservation, Ledger, _, Maximum, _, _,
                           HeldEvents, _, Counters, _, _, _}, Bytes, Attempts) ->
    Current = atomics:get(Ledger, 1), CurrentBytes = Current div ?BASE,
    case CurrentBytes + Bytes > Maximum of
        true -> counter_add(Counters, 3, 1), {error, 1};
        false ->
            Delta = Bytes * ?BASE,
            case atomics:compare_exchange(
                Ledger, 1, Current, Current + Delta
            ) of
                ok ->
                    maybe_checkpoint(dynamic_debited),
                    _ = atomics:add_get(HeldEvents, 1, 1),
                    counter_add(Counters, 2, 1),
                    counter_add(Counters, 5, 1),
                    {ok, nil};
                _ -> reserve_event_cas(Token, Bytes, Attempts - 1)
            end
    end.

-spec release_events(reservation(), pos_integer(), pos_integer()) -> nil.
release_events(Token = {qlog_reservation, _, _, _, _, _, _, _, _, _, _, _},
               Bytes, Count)
  when is_integer(Bytes), Bytes > 0, is_integer(Count), Count > 0 ->
    case active_enter(Token) of
        false -> nil;
        true ->
            try release_events_active(Token, Bytes, Count)
            catch _:_ -> nil
            after active_leave(Token)
            end
    end;
release_events(_, _, _) -> nil.

release_events_active({qlog_reservation, Ledger, _, _, _, _, HeldEvents,
                       EventBytes, Counters, _, _, _}, Bytes, Count) ->
    Expected = atomics:get(EventBytes, 1),
    case Expected > 0 andalso Bytes =:= Expected * Count andalso
         claim_events(HeldEvents, Count, 32) of
        false -> nil;
        true ->
            maybe_checkpoint(events_claimed),
            case ledger_release(Ledger, Bytes * ?BASE, 1024) of
                true ->
                    counter_sub(Counters, 5, Count),
                    counter_add(Counters, 4, Count),
                    nil;
                false ->
                    %% The aggregate credit did not move, so restore the local
                    %% claim. This is safe while the operation barrier is held.
                    _ = atomics:add_get(HeldEvents, 1, Count),
                    nil
            end
    end.

claim_events(_HeldEvents, _Count, 0) -> false;
claim_events(HeldEvents, Count, Attempts) ->
    Held = atomics:get(HeldEvents, 1),
    case Count =< Held of
        false -> false;
        true ->
            case atomics:compare_exchange(HeldEvents, 1, Held, Held - Count) of
                ok -> true;
                _ -> claim_events(HeldEvents, Count, Attempts - 1)
            end
    end.

bind_event_bytes({qlog_reservation, _, _, _, _, _, _, EventBytes, _, _, _, _},
                 Bytes) ->
    case atomics:get(EventBytes, 1) of
        Bytes -> true;
        0 ->
            case atomics:compare_exchange(EventBytes, 1, 0, Bytes) of
                ok -> true;
                _ -> atomics:get(EventBytes, 1) =:= Bytes
            end;
        _ -> false
    end.

reservation_counters(
    {qlog_reservation, _, _, _, _, _, _, _, Counters, _, _, _}
) ->
    Counters.

active_enter(
    Token = {qlog_reservation, _, _, _, State, Active, _, _, _, _, _, _}
) ->
    case atomics:get(State, 1) of
        1 ->
            _ = atomics:add_get(Active, 1, 1),
            maybe_checkpoint(active_registered),
            case atomics:get(State, 1) of
                1 -> true;
                _ -> active_leave(Token), false
            end;
        _ -> false
    end.

active_leave(
    Token = {qlog_reservation, _, _, _, State, Active, _, _, _, _, _, _}
) ->
    Remaining = atomics:sub_get(Active, 1, 1),
    %% A confirmed collector uses a finite wait. If it exhausted that wait,
    %% the last operation which actually makes the token quiescent completes
    %% settlement. The Closing -> Settling CAS still gives exactly one owner.
    case Remaining =:= 0 andalso atomics:get(State, 1) =:= 2 of
        true -> settle_confirmed(Token);
        false -> ok
    end.

await_quiescent(_Active, 0) -> false;
await_quiescent(Active, Attempts) ->
    case atomics:get(Active, 1) of
        0 -> true;
        _ -> erlang:yield(), await_quiescent(Active, Attempts - 1)
    end.

ledger_release(_Ledger, _Amount, 0) -> false;
ledger_release(Ledger, Amount, Attempts) ->
    Current = atomics:get(Ledger, 1),
    case Amount =< Current of
        false -> false;
        true ->
            case atomics:compare_exchange(Ledger, 1, Current, Current - Amount) of
                ok -> true;
                _ -> ledger_release(Ledger, Amount, Attempts - 1)
            end
    end.

%% Deterministic tests may install an unforgeable, process-local checkpoint as
%% `{{module,test_probe},{Controller,Reference,Stage}}`. Production callers do
%% not have that dictionary entry, so no actor, table or global test switch is
%% introduced. A forgotten probe is bounded by five seconds.
maybe_checkpoint(Stage) ->
    %% Consume the process-local probe before stopping. A linked dependent may
    %% settle in the same call stack and reach the same lifecycle stage; that
    %% second settlement must remain observable as progress rather than being
    %% stopped by a checkpoint which was configured for the primary only.
    case erlang:get({?MODULE, test_probe}) of
        {Controller, Reference, Stage}
          when is_pid(Controller), is_reference(Reference) ->
            _ = erlang:erase({?MODULE, test_probe}),
            Controller ! {Reference, Stage},
            receive
                {Reference, continue} -> ok
            after 5000 -> ok
            end;
        _ -> ok
    end.

-spec snapshot(identity()) -> {non_neg_integer(), non_neg_integer()}.
snapshot({qlog_admission, Ledger, _, _}) ->
    Value = atomics:get(Ledger, 1), {Value div ?BASE, Value rem ?BASE}.

-spec event_snapshot(identity()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
event_snapshot({qlog_admission, _, Counters, _}) ->
    {counter_get(Counters, 1), counter_get(Counters, 2),
     counter_get(Counters, 3), counter_get(Counters, 4),
     counter_get(Counters, 5)}.

%% Payload-free, finite evidence: attempts, admitted, refused, recovered,
%% expired, and currently retained cleanup tickets.
-spec reconciliation_snapshot(identity()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer()}.
reconciliation_snapshot({qlog_admission, _, _, Registry}) ->
    {counter_get(Registry, 1), counter_get(Registry, 2),
     counter_get(Registry, 3), counter_get(Registry, 4),
     counter_get(Registry, 5), counter_get(Registry, 6)}.

%% Payload-free lifecycle evidence for adversarial interleaving tests.
-spec reservation_snapshot(reservation()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
reservation_snapshot({qlog_reservation, _, _, _, State, Active, HeldEvents,
                      EventBytes, _, _, _, _}) ->
    {counter_get(State, 1), counter_get(Active, 1),
     counter_get(HeldEvents, 1), counter_get(EventBytes, 1)}.

counter_get(Counters, Index) -> erlang:max(0, atomics:get(Counters, Index)).

counter_add(Counters, Index, Increment) ->
    counter_add(Counters, Index, Increment, 32).

counter_add(_Counters, _Index, _Increment, 0) -> ok;
counter_add(_Counters, _Index, 0, _Attempts) -> ok;
counter_add(Counters, Index, Increment, Attempts) ->
    Current = atomics:get(Counters, Index),
    Wanted = erlang:min(?MAXIMUM, Current + erlang:max(0, Increment)),
    case atomics:compare_exchange(Counters, Index, Current, Wanted) of
        ok -> ok;
        _ -> counter_add(Counters, Index, Increment, Attempts - 1)
    end.

counter_sub(Counters, Index, Decrement) ->
    counter_sub(Counters, Index, Decrement, 32).

counter_sub(_Counters, _Index, _Decrement, 0) -> ok;
counter_sub(_Counters, _Index, 0, _Attempts) -> ok;
counter_sub(Counters, Index, Decrement, Attempts) ->
    Current = atomics:get(Counters, Index),
    Wanted = erlang:max(0, Current - erlang:max(0, Decrement)),
    case atomics:compare_exchange(Counters, Index, Current, Wanted) of
        ok -> ok;
        _ -> counter_sub(Counters, Index, Decrement, Attempts - 1)
    end.
