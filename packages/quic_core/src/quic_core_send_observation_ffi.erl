%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(quic_core_send_observation_ffi).

-export([new/0, available/1, park/2, publish/2, await/3, await_with_owner/4,
         new_with_fault/1, resource_state/1]).

%% Exactly one fixed row belongs to the synchronous caller. The connection
%% actor may replace pending cause with one bounded typed terminal result.
%% Taking the row closes admission atomically; owner exit deletes it as well.
%% Primitive allocation failure produces a disabled capability which maps to
%% a typed resource failure without retaining a table, alias, process, queue,
%% or application payload.
-type observation() :: #{
    state := ets:tid() | unavailable,
    alias := reference() | unavailable,
    tag := reference() | unavailable,
    faults := [atom()],
    cleanup_probe := ets:tid() | unavailable
}.

-spec new() -> observation().
new() -> new_observation([]).

%% Native-only deterministic fault seam. It does not appear in the Gleam API
%% and accepts only the finite primitive sites listed below.
-spec new_with_fault(atom() | [atom()]) -> observation().
new_with_fault(Faults) ->
    case normalize_faults(Faults) of
        {ok, Plan} -> new_observation(Plan);
        error -> disabled_observation([], unavailable)
    end.

new_observation(Faults) ->
    case primitive_reference(Faults, observation_tag) of
        {error, unavailable} -> disabled_observation(Faults, unavailable);
        {ok, Tag} -> new_observation_table(Faults, Tag)
    end.

new_observation_table(Faults, Tag) ->
    case primitive_table(Faults, observation_ets) of
        {error, unavailable} -> disabled_observation(Faults, unavailable);
        {ok, State} ->
            case primitive_insert(Faults, observation_insert, State) of
                {error, unavailable} ->
                    safe_delete(State),
                    disabled_observation(Faults, State);
                ok -> new_observation_alias(Faults, State, Tag)
            end
    end.

new_observation_alias(Faults, State, Tag) ->
    case primitive_alias(Faults, observation_alias) of
        {error, unavailable} ->
            safe_delete(State),
            disabled_observation(Faults, State);
        {ok, Alias} -> #{
            state => State,
            alias => Alias,
            tag => Tag,
            faults => Faults,
            cleanup_probe => unavailable
        }
    end.

disabled_observation(Faults, Probe) -> #{
    state => unavailable,
    alias => unavailable,
    tag => unavailable,
    faults => Faults,
    cleanup_probe => Probe
}.

-spec available(observation()) -> boolean().
available(Observation) ->
    case observation_parts(Observation) of
        unavailable ->
            finish_observation(Observation),
            false;
        {State, _Alias, _Tag, _Faults} ->
            case table_is_live(State) of
                true -> true;
                false ->
                    finish_observation(Observation),
                    false
            end
    end.

-spec park(observation(), boolean()) -> boolean().
park(#{state := State}, HeldByGrant) when State =/= unavailable ->
    replace_pending(State, {1, pending, HeldByGrant});
park(_, _) -> false.

-spec publish(observation(), term()) -> boolean().
publish(#{state := State, alias := Alias, tag := Tag}, Result)
        when State =/= unavailable, is_reference(Alias), is_reference(Tag) ->
    case replace_pending(State, {1, done, Result}) of
        true -> safe_notify(Alias, Tag), true;
        false -> false
    end;
publish(_, _) -> false.

%% select_replace and the owner's take determine exactly one terminal winner.
%% A dead owner's table is gone, so every late admission/publication fails.
-spec replace_pending(ets:tid(), tuple()) -> boolean().
replace_pending(State, Next) ->
    try ets:select_replace(
        State, [{{1, pending, '_'}, [], [{const, Next}]}]
    ) of
        Count -> Count =:= 1
    catch
        _:_ -> false
    end.

-spec await(observation(), pid(), non_neg_integer()) ->
    {replied, term()} | {deadline_expired, boolean()} |
    worker_exited | unavailable.
await(Observation, Worker, Timeout)
        when is_map(Observation), is_pid(Worker),
             is_integer(Timeout), Timeout >= 0 ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case observation_parts(Observation) of
        unavailable ->
            finish_observation(Observation),
            unavailable;
        {State, Alias, Tag, Faults} ->
            case primitive_monitor(Faults, await_worker_monitor, Worker) of
                {error, unavailable} ->
                    finish_observation(Observation),
                    unavailable;
                {ok, Monitor} ->
                    try
                        Remaining = remaining(Deadline),
                        receive
                            {Tag, ready} -> terminal(State, deadline);
                            {'DOWN', Monitor, process, Worker, _} ->
                                terminal(State, exited)
                        after Remaining -> terminal(State, deadline)
                        end
                    catch
                        _:_ -> unavailable
                    after
                        safe_demonitor(Monitor),
                        safe_unalias(Alias),
                        safe_delete(State),
                        drain_ready(Tag)
                    end
            end
    end;
await(Observation, _Worker, _Timeout) ->
    finish_observation(Observation),
    unavailable.

%% A connection-scoped relay must not wait for its long-poll timeout after the
%% actor that owns the connection has exited. The observation caller remains
%% the ETS owner, so returning also destroys the capability and makes every
%% late publication a bounded no-op.
-spec await_with_owner(observation(), pid(), pid(), non_neg_integer()) ->
    {replied, term()} | {deadline_expired, boolean()} |
    worker_exited | owner_exited | unavailable.
await_with_owner(Observation, Worker, Owner, Timeout)
        when is_map(Observation), is_pid(Worker), is_pid(Owner),
             is_integer(Timeout), Timeout >= 0 ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case observation_parts(Observation) of
        unavailable ->
            finish_observation(Observation),
            unavailable;
        {State, Alias, Tag, Faults} ->
            await_with_owner_monitors(
                Observation, State, Alias, Tag, Faults,
                Worker, Owner, Deadline
            )
    end;
await_with_owner(Observation, _Worker, _Owner, _Timeout) ->
    finish_observation(Observation),
    unavailable.

await_with_owner_monitors(
    Observation, State, Alias, Tag, Faults, Worker, Owner, Deadline
) ->
    case primitive_monitor(Faults, await_worker_monitor, Worker) of
        {error, unavailable} ->
            finish_observation(Observation),
            unavailable;
        {ok, WorkerMonitor} ->
            case primitive_monitor(Faults, await_owner_monitor, Owner) of
                {error, unavailable} ->
                    safe_demonitor(WorkerMonitor),
                    finish_observation(Observation),
                    unavailable;
                {ok, OwnerMonitor} ->
                    try
                        Remaining = remaining(Deadline),
                        receive
                            {Tag, ready} ->
                                %% Owner liveness is the success linearization
                                %% point. Ready and DOWN have different senders.
                                case safe_alive(Owner) of
                                    true -> terminal(State, deadline);
                                    false -> terminal_owner_exited(State)
                                end;
                            {'DOWN', WorkerMonitor, process, Worker, _} ->
                                terminal(State, exited);
                            {'DOWN', OwnerMonitor, process, Owner, _} ->
                                terminal_owner_exited(State)
                        after Remaining -> terminal(State, deadline)
                        end
                    catch
                        _:_ -> unavailable
                    after
                        safe_demonitor(WorkerMonitor),
                        safe_demonitor(OwnerMonitor),
                        safe_unalias(Alias),
                        safe_delete(State),
                        drain_ready(Tag)
                    end
            end
    end.

-spec terminal_owner_exited(ets:tid()) -> owner_exited.
terminal_owner_exited(State) ->
    %% Consume either pending or done. Once the enclosing owner is observed
    %% dead no completion may escape into an abandoned protocol connection.
    _ = safe_take(State),
    owner_exited.

-spec terminal(ets:tid(), deadline | exited) ->
    {replied, term()} | {deadline_expired, boolean()} |
    worker_exited | unavailable.
terminal(State, Reason) ->
    case safe_take(State) of
        [{1, done, Result}] -> {replied, Result};
        [{1, pending, HeldByGrant}] when Reason =:= deadline ->
            {deadline_expired, HeldByGrant};
        [{1, pending, _}] -> worker_exited;
        _ -> unavailable
    end.

observation_parts(#{
    state := State, alias := Alias, tag := Tag, faults := Faults
}) when State =/= unavailable, is_reference(Alias), is_reference(Tag),
        is_list(Faults) ->
    {State, Alias, Tag, Faults};
observation_parts(_) -> unavailable.

finish_observation(#{
    state := State, alias := Alias, tag := Tag, cleanup_probe := Probe
}) ->
    safe_unalias(Alias),
    safe_delete(State),
    safe_delete(Probe),
    drain_ready(Tag),
    ok;
finish_observation(_) -> ok.

safe_take(State) ->
    try ets:take(State, 1)
    catch _:_ -> []
    end.

safe_delete(State) when State =/= unavailable ->
    try ets:delete(State), true
    catch _:_ -> false
    end;
safe_delete(_) -> false.

safe_unalias(Alias) when is_reference(Alias) ->
    try erlang:unalias(Alias)
    catch _:_ -> false
    end;
safe_unalias(_) -> false.

safe_demonitor(Monitor) when is_reference(Monitor) ->
    try erlang:demonitor(Monitor, [flush])
    catch _:_ -> false
    end;
safe_demonitor(_) -> false.

safe_notify(Alias, Tag) ->
    try Alias ! {Tag, ready}, ok
    catch _:_ -> ok
    end.

safe_alive(Pid) ->
    try erlang:is_process_alive(Pid)
    catch _:_ -> false
    end.

drain_ready(Tag) when is_reference(Tag) ->
    receive {Tag, ready} -> ok after 0 -> ok end;
drain_ready(_) -> ok.

remaining(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

primitive_reference(Faults, Site) ->
    primitive_call(
        Faults, Site, fun() -> make_ref() end, fun erlang:is_reference/1
    ).

primitive_table(Faults, Site) ->
    primitive_call(
        Faults,
        Site,
        fun() -> ets:new(send_observation, [set, public]) end,
        fun table_is_live/1
    ).

primitive_insert(Faults, Site, State) ->
    try
        _ = case fault_enabled(Faults, Site) of
            true -> throw(observation_primitive_unavailable);
            false -> ets:insert(State, {1, pending, false})
        end,
        ok
    catch
        _:_ -> {error, unavailable}
    end.

primitive_alias(Faults, Site) ->
    primitive_call(
        Faults, Site, fun() -> erlang:alias() end,
        fun erlang:is_reference/1
    ).

primitive_monitor(Faults, Site, Pid) ->
    primitive_call(
        Faults,
        Site,
        fun() -> erlang:monitor(process, Pid) end,
        fun erlang:is_reference/1
    ).

primitive_call(Faults, Site, Fun, Validator) ->
    try
        Value = case fault_enabled(Faults, Site) of
            true -> throw(observation_primitive_unavailable);
            false -> Fun()
        end,
        case Validator(Value) of
            true -> {ok, Value};
            false -> {error, unavailable}
        end
    catch
        _:_ -> {error, unavailable}
    end.

fault_enabled(Faults, Site) -> lists:member(Site, Faults).

normalize_faults(none) -> {ok, []};
normalize_faults(Fault) when is_atom(Fault) ->
    case allowed_fault(Fault) of
        true -> {ok, [Fault]};
        false -> error
    end;
normalize_faults(Faults) when is_list(Faults) ->
    normalize_fault_list(Faults, 4, []);
normalize_faults(_) -> error.

normalize_fault_list([], _Remaining, Acc) -> {ok, lists:usort(Acc)};
normalize_fault_list([Fault | Rest], Remaining, Acc) when Remaining > 0 ->
    case allowed_fault(Fault) of
        true -> normalize_fault_list(Rest, Remaining - 1, [Fault | Acc]);
        false -> error
    end;
normalize_fault_list(_, _, _) -> error.

allowed_fault(observation_tag) -> true;
allowed_fault(observation_ets) -> true;
allowed_fault(observation_insert) -> true;
allowed_fault(observation_alias) -> true;
allowed_fault(await_worker_monitor) -> true;
allowed_fault(await_owner_monitor) -> true;
allowed_fault(_) -> false.

table_is_live(State) ->
    try ets:info(State, type) =:= set
    catch _:_ -> false
    end.

%% Payload-free state for native regression tests. It never returns the ETS
%% identifier, alias, tag, PID, or an exception reason.
-spec resource_state(observation()) ->
    {enabled | disabled, active | released}.
resource_state(#{state := unavailable, cleanup_probe := Probe}) ->
    case table_is_live(Probe) of
        true -> {disabled, active};
        false -> {disabled, released}
    end;
resource_state(#{state := State}) ->
    case table_is_live(State) of
        true -> {enabled, active};
        false -> {enabled, released}
    end;
resource_state(_) -> {disabled, released}.
