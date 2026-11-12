%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_send_completion_test_ffi).
-export([registered_waiter/4, observation_storage_is_bounded/0,
         history_storage_is_bounded/0, saturate_waiters/3,
         concurrent_observers/5, owner_exit_releases_waiter/3,
         owner_death_wins_ready_race/0]).

owner_death_wins_ready_race() ->
    Observation = quic_core_send_observation_ffi:new(),
    {Owner, Monitor} = spawn_monitor(fun() -> receive stop -> ok end end),
    exit(Owner, kill),
    receive {'DOWN',Monitor,process,Owner,_} -> ok
    after 1000 -> error(owner_alive) end,
    true = quic_core_send_observation_ffi:publish(Observation, late_success),
    owner_exited = quic_core_send_observation_ffi:await_with_owner(
        Observation, self(), Owner, 100),
    true.

concurrent_observers(Actor, Feed, Await, Action, Counts) ->
    Parent = self(), FeedRef = make_ref(), StreamRef = make_ref(),
    ActorMonitor = monitor(process, Actor),
    {FeedPid, FeedMonitor} = spawn_monitor(fun() -> Parent ! {FeedRef, Feed()} end),
    {StreamPid, StreamMonitor} = spawn_monitor(fun() -> Parent ! {StreamRef, Await()} end),
    Registered = count_is(fun() -> element(1, Counts()) end, 2,
        erlang:monotonic_time(millisecond) + 1000),
    ActionResult = Action(),
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    FeedResult = receive {FeedRef, Value1} -> Value1
        after max(0, Deadline-erlang:monotonic_time(millisecond)) -> missing end,
    StreamResult = receive {StreamRef, Value2} -> Value2
        after max(0, Deadline-erlang:monotonic_time(millisecond)) -> missing end,
    FeedJoined = receive {'DOWN',FeedMonitor,process,FeedPid,_}->true
        after max(0,Deadline-erlang:monotonic_time(millisecond))->false end,
    StreamJoined = receive {'DOWN',StreamMonitor,process,StreamPid,_}->true
        after max(0,Deadline-erlang:monotonic_time(millisecond))->false end,
    Released = release_observed(Actor, ActorMonitor, Counts, Deadline),
    demonitor(ActorMonitor, [flush]),
    {Registered, ActionResult, FeedResult, StreamResult,
     FeedJoined andalso StreamJoined, Released}.

release_observed(Actor, Monitor, Counts, Deadline) ->
    receive
        {'DOWN',Monitor,process,Actor,_} -> true
    after 0 ->
        case Counts() of
            {0,_,_} -> true;
            _ -> case erlang:monotonic_time(millisecond) < Deadline of
                true -> receive after 1 ->
                    release_observed(Actor,Monitor,Counts,Deadline)
                end;
                false -> false
            end
        end
    end.

owner_exit_releases_waiter(CaptureOwner, Await, Counts) ->
    Parent = self(), Ref = make_ref(), CapabilityRef = make_ref(),
    Owner = spawn(fun() ->
        Capability = CaptureOwner(),
        Parent ! {CapabilityRef, Capability},
        receive stop -> ok end
    end),
    Capability = receive {CapabilityRef, CapturedCapability} -> CapturedCapability
        after 1000 -> error(owner_capability_missing) end,
    {Caller, Monitor} = spawn_monitor(fun() ->
        Parent ! {Ref, Await(Capability)}
    end),
    Registered = count_is(fun() -> element(1, Counts()) end, 1,
        erlang:monotonic_time(millisecond) + 1000),
    Started = erlang:monotonic_time(millisecond),
    exit(Owner, kill),
    Deadline = Started + 1000,
    Result = receive {Ref, CompletionResult} -> CompletionResult
        after max(0,Deadline-erlang:monotonic_time(millisecond))->missing end,
    Joined = receive {'DOWN',Monitor,process,Caller,_}->true
        after max(0,Deadline-erlang:monotonic_time(millisecond))->false end,
    Removed = count_is(fun() -> element(1, Counts()) end, 0, Deadline),
    Prompt = erlang:monotonic_time(millisecond) - Started =< 250,
    {Registered, Result, Joined, Removed, Prompt}.

history_storage_is_bounded() ->
    Maximum = (1 bsl 62)-1,
    Original = lists:foldl(fun(Index,History)->
        'quic_core@internal@stream_completion':record(History,Maximum-Index,{stopped,Maximum-Index})
    end,'quic_core@internal@stream_completion':new(32),lists:seq(1,32)),
    Replaced = 'quic_core@internal@stream_completion':record(Original,Maximum,{reset,Maximum}),
    %% Include both live versions during replacement. size/1 counts real
    %% sharing of unchanged entry tuples, including maximum QUIC bignums.
    Bytes = erts_debug:size({Original,Replaced}) * erlang:system_info(wordsize),
    Bytes > 0 andalso Bytes =< 'quic_core@internal@stream_completion':reserved_bytes().

saturate_waiters(Callbacks, Counts, Limit) when length(Callbacks) =< 16 ->
    Parent = self(), Deadline = erlang:monotonic_time(millisecond)+1000,
    {Workers, Admitted, Rejected, Within} = start_waiters(Callbacks, Counts, Limit,
        Parent, Deadline, [], 0, 0, true),
    [exit(Pid, kill) || {Pid,_} <- Workers],
    CleanupDeadline = erlang:monotonic_time(millisecond)+1000,
    Joined = lists:all(fun({Pid,Monitor}) ->
        receive {'DOWN',Monitor,process,Pid,_}->true
        after max(0,CleanupDeadline-erlang:monotonic_time(millisecond))->false end
    end, Workers),
    Removed = count_is(fun()->element(1,Counts()) end, 0, CleanupDeadline),
    {Admitted, Rejected, Within, Joined andalso Removed}.

start_waiters([], _, _, _, _, Workers, Admitted, Rejected, Within) ->
    {Workers, Admitted, Rejected, Within};
start_waiters([Callback|Rest], Counts, Limit, Parent, Deadline, Workers, Admitted, Rejected, Within) ->
    Ref=make_ref(),
    {Pid,Monitor}=spawn_monitor(fun()->Parent!{Ref,Callback()} end),
    Outcome=wait_registration(Ref,Counts,Admitted,Deadline),
    {_Count,_History,Bytes}=Counts(),
    case Outcome of
        admitted -> start_waiters(Rest,Counts,Limit,Parent,Deadline,[{Pid,Monitor}|Workers],Admitted+1,Rejected,Within andalso Bytes=<Limit);
        rejected -> start_waiters(Rest,Counts,Limit,Parent,Deadline,[{Pid,Monitor}|Workers],Admitted,Rejected+1,Within andalso Bytes=<Limit);
        failed -> {[{Pid,Monitor}|Workers],Admitted,Rejected,false}
    end.

wait_registration(Ref, Counts, Previous, Deadline) ->
    receive
        {Ref,true}->rejected;
        {Ref,false}->failed
    after 0 ->
        case Counts() of
            {Count,_,_} when Count > Previous -> admitted;
            _ -> case erlang:monotonic_time(millisecond)<Deadline of
                true -> receive after 1 -> wait_registration(Ref,Counts,Previous,Deadline) end;
                false -> failed
            end
        end
    end.

observation_storage_is_bounded() ->
    Observation = quic_core_send_observation_ffi:new(),
    Table = maps:get(state, Observation),
    Bytes = (ets:info(Table, memory) + erts_debug:flat_size(Observation)) * erlang:system_info(wordsize),
    {deadline_expired, false} = quic_core_send_observation_ffi:await(Observation, self(), 0),
    %% The 8-KiB admission leaves at least half for actor-side monitor,
    %% selector and waiter terms in addition to this actual one-row ETS store.
    Bytes > 0 andalso Bytes =< 4096 andalso ets:info(Table) =:= undefined.

registered_waiter(Connection, Await, Action, Counts) ->
    {ok, Actor} = quic_core_test_ffi:labelled_pid(Connection, <<"quic_core.connection">>),
    {Caller, Monitor} = spawn_monitor(fun() -> Await() end),
    try
        Registered = monitored_by(Actor, Caller, true, erlang:monotonic_time(millisecond)+1000)
            andalso Counts() =:= 1,
        Result = Action(),
        exit(Caller, kill),
        Joined = receive {'DOWN',Monitor,process,Caller,_}->true after 1000->false end,
        Removed = monitored_by(Actor, Caller, false, erlang:monotonic_time(millisecond)+1000)
            andalso count_is(Counts, 0, erlang:monotonic_time(millisecond)+1000),
        {Registered, Result, Joined andalso Removed}
    after
        exit(Caller, kill),
        demonitor(Monitor, [flush])
    end.

count_is(Counts, Expected, Deadline) ->
    case Counts() =:= Expected of
        true -> true;
        false -> case erlang:monotonic_time(millisecond) < Deadline of
            true -> receive after 1 -> count_is(Counts,Expected,Deadline) end;
            false -> false
        end
    end.

monitored_by(Actor, Caller, Expected, Deadline) ->
    case process_info(Actor, monitors) of
        {monitors, Monitors} ->
            case lists:member({process,Caller},Monitors)=:=Expected of
                true -> true;
                false -> case erlang:monotonic_time(millisecond)<Deadline of
                    true -> receive after 1 -> monitored_by(Actor,Caller,Expected,Deadline) end;
                    false -> false
                end
            end;
        _ -> false
    end.
