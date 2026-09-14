%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_server_ffi).

-export([
    call_bounded_adapter/3,
    call_bounded_adapter_traced/3,
    cancel_handle_snapshot/1,
    claim_close_guard/1,
    close_guard_snapshot/1,
    diagnostic_close/1,
    diagnostic_complete/2,
    diagnostic_reserve/1,
    diagnostic_snapshot/1,
    get_context_attribute/2,
    is_cancelled/1,
    mark_cancelled/1,
    mark_server_draining/1,
    mark_server_stopped/1,
    monotonic_millisecond/0,
    new_cancel_handle/0,
    new_close_guard/0,
    new_context_attributes/0,
    new_context_key/0,
    new_diagnostic_credit/1,
    new_diagnostic_request_id/0,
    new_resource_controller/2,
    new_server_lifecycle/0,
    new_token/0,
    new_udp_proxy_termination_guard/0,
    put_context_attribute/3,
    record_udp_proxy_termination/2,
    resource_acquire/2,
    resource_release/2,
    resource_resize/3,
    resource_snapshot/1,
    resource_stop/1,
    run_guarded/1,
    server_lifecycle_state/1,
    spawn_monitor/1,
    subscribe_cancel_handle/2,
    finish_close_guard/2,
    unsubscribe_cancel_handle/1,
    udp_proxy_termination_snapshot/1
]).

-define(RESOURCE_WORKERS, 1).
-define(RESOURCE_MEMORY, 2).
-define(RESOURCE_STOPPED, 3).

-define(DIAGNOSTIC_CLOSED, 1).
-define(DIAGNOSTIC_IN_FLIGHT, 2).
-define(DIAGNOSTIC_DELIVERED, 3).
-define(DIAGNOSTIC_DROPPED, 4).
-define(DIAGNOSTIC_FAILURES, 5).
-define(DIAGNOSTIC_SEQUENCE, 6).

-define(CLOSE_STATE, 1).
-define(CLOSE_CALLS, 2).
-define(CLOSE_ATTEMPTS, 3).
-define(CLOSE_FAILURES, 4).
-define(CLOSE_TIMEOUTS, 5).
-define(CANCELLED, 1).
-define(CANCEL_ACTIVE_SUBSCRIPTIONS, 2).
-define(CANCEL_NOTIFICATIONS, 3).
-define(CANCEL_UNSUBSCRIPTIONS, 4).
-define(CANCEL_ABANDONED_SUBSCRIPTIONS, 5).
-define(CANCEL_BROKER_STOPPED, 6).
-define(UDP_TERMINATION_REASON, 1).
-define(UDP_TERMINATION_NOTIFICATIONS, 2).
-define(MAXIMUM_COUNTER, 9223372036854775807).

-type resource_controller() ::
    {http_resource, atomics:atomics_ref(), pos_integer(), pos_integer()}.
-type resource_lease() :: atomics:atomics_ref().
-type diagnostic_credit() ::
    {http_diagnostic_credit, atomics:atomics_ref(), pos_integer()}.
-type cancel_handle() ::
    {http_cancel_handle, atomics:atomics_ref(), pid()}.
-type cancel_subscription() ::
    {http_cancel_subscription, pid(), reference(), term(), atomics:atomics_ref()}.

-spec new_context_key() -> reference().
new_context_key() ->
    make_ref().

-spec new_token() -> reference().
new_token() ->
    make_ref().

-spec new_context_attributes() -> map().
new_context_attributes() ->
    #{}.

-spec put_context_attribute(map(), reference(), term()) -> map().
put_context_attribute(Attributes, Key, Value)
    when is_map(Attributes), is_reference(Key) ->
    maps:put(Key, Value, Attributes);
put_context_attribute(_Attributes, _Key, _Value) ->
    #{}.

-spec get_context_attribute(map(), reference()) -> none | {some, term()}.
get_context_attribute(Attributes, Key)
    when is_map(Attributes), is_reference(Key) ->
    case maps:find(Key, Attributes) of
        {ok, Value} -> {some, Value};
        error -> none
    end;
get_context_attribute(_Attributes, _Key) ->
    none.

-spec new_cancel_handle() -> cancel_handle().
new_cancel_handle() ->
    State = atomics:new(6, [{signed, false}]),
    Owner = self(),
    Broker = spawn(fun() -> cancel_broker_init(Owner, State) end),
    {http_cancel_handle, State, Broker}.

-spec new_close_guard() -> atomics:atomics_ref().
new_close_guard() ->
    atomics:new(5, [{signed, false}]).

-spec new_udp_proxy_termination_guard() -> atomics:atomics_ref().
new_udp_proxy_termination_guard() ->
    atomics:new(2, [{signed, false}]).

-spec record_udp_proxy_termination(atomics:atomics_ref(), 1..4) -> 1..4.
record_udp_proxy_termination(Guard, Reason)
    when is_integer(Reason), Reason >= 1, Reason =< 4 ->
    _ = saturating_atomic_increment(Guard, ?UDP_TERMINATION_NOTIFICATIONS),
    try atomics:compare_exchange(
        Guard, ?UDP_TERMINATION_REASON, 0, Reason
    ) of
        ok -> Reason;
        Existing when is_integer(Existing), Existing >= 1, Existing =< 4 ->
            Existing;
        _ -> 3
    catch
        _:_ -> 3
    end;
record_udp_proxy_termination(_Guard, _Reason) ->
    3.

-spec udp_proxy_termination_snapshot(atomics:atomics_ref()) ->
    {0..4, non_neg_integer()}.
udp_proxy_termination_snapshot(Guard) ->
    try
        {
            atomics:get(Guard, ?UDP_TERMINATION_REASON),
            atomics:get(Guard, ?UDP_TERMINATION_NOTIFICATIONS)
        }
    catch
        _:_ -> {3, 0}
    end.

-spec claim_close_guard(atomics:atomics_ref()) ->
    close_acquired | close_in_progress | close_completed.
claim_close_guard(Guard) ->
    _ = saturating_atomic_increment(Guard, ?CLOSE_CALLS),
    try atomics:compare_exchange(Guard, ?CLOSE_STATE, 0, 1) of
        ok ->
            _ = saturating_atomic_increment(Guard, ?CLOSE_ATTEMPTS),
            close_acquired;
        1 -> close_in_progress;
        _ -> close_completed
    catch
        _:_ -> close_in_progress
    end.

-spec finish_close_guard(
    atomics:atomics_ref(), close_succeeded | close_failed | close_timed_out
) -> nil.
finish_close_guard(Guard, Completion) ->
    try
        case Completion of
            close_succeeded ->
                _ = atomics:exchange(Guard, ?CLOSE_STATE, 2);
            close_failed ->
                _ = saturating_atomic_increment(Guard, ?CLOSE_FAILURES),
                _ = atomics:compare_exchange(
                    Guard, ?CLOSE_STATE, 1, 0
                );
            close_timed_out ->
                _ = saturating_atomic_increment(Guard, ?CLOSE_FAILURES),
                _ = saturating_atomic_increment(Guard, ?CLOSE_TIMEOUTS),
                _ = atomics:compare_exchange(
                    Guard, ?CLOSE_STATE, 1, 0
                )
        end
    catch
        _:_ -> ok
    end,
    nil.

-spec close_guard_snapshot(atomics:atomics_ref()) ->
    {0 | 1 | 2, non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
close_guard_snapshot(Guard) ->
    try
        {
            atomics:get(Guard, ?CLOSE_STATE),
            atomics:get(Guard, ?CLOSE_CALLS),
            atomics:get(Guard, ?CLOSE_ATTEMPTS),
            atomics:get(Guard, ?CLOSE_FAILURES),
            atomics:get(Guard, ?CLOSE_TIMEOUTS)
        }
    catch
        _:_ -> {2, 0, 0, 0, 0}
    end.

-spec saturating_atomic_increment(atomics:atomics_ref(), pos_integer()) ->
    non_neg_integer().
saturating_atomic_increment(Atomics, Index) ->
    Current = atomics:get(Atomics, Index),
    case Current >= ?MAXIMUM_COUNTER of
        true -> Current;
        false ->
            case atomics:compare_exchange(
                Atomics, Index, Current, Current + 1
            ) of
                ok -> Current + 1;
                _ -> saturating_atomic_increment(Atomics, Index)
            end
    end.

-spec mark_cancelled(cancel_handle()) -> boolean().
mark_cancelled({http_cancel_handle, State, Broker}) ->
    try atomics:exchange(State, ?CANCELLED, 1) of
        0 ->
            Broker ! cancel,
            true;
        _ ->
            false
    catch
        _:_ -> false
    end;
mark_cancelled(_Handle) ->
    false.

-spec is_cancelled(cancel_handle()) -> boolean().
is_cancelled({http_cancel_handle, State, _Broker}) ->
    try atomics:get(State, ?CANCELLED) of
        0 -> false;
        _ -> true
    catch
        _:_ -> true
    end;
is_cancelled(_Handle) ->
    true.

-spec cancel_handle_snapshot(cancel_handle()) ->
    {0 | 1, 0 | 1, non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
cancel_handle_snapshot({http_cancel_handle, State, _Broker}) ->
    try
        {
            atomics:get(State, ?CANCELLED),
            atomics:get(State, ?CANCEL_BROKER_STOPPED),
            atomics:get(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS),
            atomics:get(State, ?CANCEL_NOTIFICATIONS),
            atomics:get(State, ?CANCEL_UNSUBSCRIPTIONS),
            atomics:get(State, ?CANCEL_ABANDONED_SUBSCRIPTIONS)
        }
    catch
        _:_ -> {1, 1, 0, 0, 0, 0}
    end;
cancel_handle_snapshot(_Handle) ->
    {1, 1, 0, 0, 0, 0}.

-spec subscribe_cancel_handle(cancel_handle(), term()) ->
    cancel_subscription().
subscribe_cancel_handle(
    {http_cancel_handle, State, Broker},
    Subject
) when is_pid(Broker) ->
    Token = make_ref(),
    Delivery = atomics:new(1, [{signed, false}]),
    Subscription =
        {http_cancel_subscription, Broker, Token, Subject, Delivery},
    case cancel_state(State) of
        cancelled ->
            send_cancel_signal(State, Subject, Delivery),
            Subscription;
        active ->
            subscribe_cancel_broker(
                State,
                Broker,
                Token,
                Subject,
                Delivery,
                Subscription
            )
    end;
subscribe_cancel_handle(_Handle, Subject) ->
    Delivery = atomics:new(1, [{signed, false}]),
    _ = claim_cancel_delivery(Delivery),
    send_subject(Subject, nil),
    {http_cancel_subscription, self(), make_ref(), Subject, Delivery}.

-spec unsubscribe_cancel_handle(cancel_subscription()) -> nil.
unsubscribe_cancel_handle(
    {http_cancel_subscription, Broker, Token, Subject, Delivery}
) when is_pid(Broker), is_reference(Token) ->
    _ = suppress_cancel_delivery(Delivery),
    Ref = make_ref(),
    Monitor = monitor(process, Broker),
    Broker ! {unsubscribe, self(), Ref, Token},
    receive
        {Ref, unsubscribed} ->
            demonitor(Monitor, [flush]);
        {'DOWN', Monitor, process, Broker, _Reason} ->
            ok
    after 1000 ->
        demonitor(Monitor, [flush])
    end,
    flush_subject(Subject),
    nil;
unsubscribe_cancel_handle(_Subscription) ->
    nil.

-spec subscribe_cancel_broker(
    atomics:atomics_ref(), pid(), reference(), term(), atomics:atomics_ref(),
    cancel_subscription()
) -> cancel_subscription().
subscribe_cancel_broker(
    State,
    Broker,
    Token,
    Subject,
    Delivery,
    Subscription
) ->
    Ref = make_ref(),
    Monitor = monitor(process, Broker),
    Broker ! {subscribe, self(), Ref, Token, Subject, Delivery},
    receive
        {Ref, subscribed} ->
            demonitor(Monitor, [flush]),
            Subscription;
        {'DOWN', Monitor, process, Broker, _Reason} ->
            send_cancel_signal(State, Subject, Delivery),
            Subscription
    after 1000 ->
        demonitor(Monitor, [flush]),
        send_cancel_signal(State, Subject, Delivery),
        Subscription
    end.

-spec cancel_broker_init(pid(), atomics:atomics_ref()) -> no_return().
cancel_broker_init(Owner, State) ->
    OwnerMonitor = monitor(process, Owner),
    try cancel_broker_loop(State, OwnerMonitor, #{})
    after
        atomics:put(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS, 0),
        atomics:put(State, ?CANCEL_BROKER_STOPPED, 1)
    end.

-spec cancel_broker_loop(
    atomics:atomics_ref(), reference(), map()
) -> no_return().
cancel_broker_loop(State, OwnerMonitor, Subscriptions) ->
    receive
        cancel ->
            notify_cancel_subscriptions(State, Subscriptions),
            exit(normal);
        {subscribe, From, Ref, Token, Subject, Delivery}
            when is_pid(From), is_reference(Ref), is_reference(Token) ->
            case cancel_state(State) of
                cancelled ->
                    send_cancel_signal(State, Subject, Delivery),
                    From ! {Ref, subscribed},
                    notify_cancel_subscriptions(State, Subscriptions),
                    exit(normal);
                active ->
                    SubscriberMonitor = monitor(process, From),
                    Next = maps:put(
                        Token,
                        {Subject, SubscriberMonitor, Delivery},
                        Subscriptions
                    ),
                    atomics:put(
                        State,
                        ?CANCEL_ACTIVE_SUBSCRIPTIONS,
                        map_size(Next)
                    ),
                    From ! {Ref, subscribed},
                    cancel_broker_loop(
                        State,
                        OwnerMonitor,
                        Next
                    )
            end;
        {unsubscribe, From, Ref, Token}
            when is_pid(From), is_reference(Ref), is_reference(Token) ->
            Next = remove_cancel_subscription(State, Token, Subscriptions),
            From ! {Ref, unsubscribed},
            case map_size(Next) of
                0 -> exit(normal);
                _ -> cancel_broker_loop(State, OwnerMonitor, Next)
            end;
        {'DOWN', OwnerMonitor, process, _Owner, _Reason} ->
            record_abandoned_subscriptions(State, map_size(Subscriptions)),
            exit(normal);
        {'DOWN', SubscriberMonitor, process, _Subscriber, _Reason} ->
            Next = remove_cancel_monitor(
                State,
                SubscriberMonitor,
                Subscriptions
            ),
            case map_size(Next) of
                0 -> exit(normal);
                _ -> cancel_broker_loop(State, OwnerMonitor, Next)
            end;
        _Other ->
            cancel_broker_loop(State, OwnerMonitor, Subscriptions)
    end.

-spec cancel_state(atomics:atomics_ref()) -> active | cancelled.
cancel_state(State) ->
    try atomics:get(State, ?CANCELLED) of
        0 -> active;
        _ -> cancelled
    catch
        _:_ -> cancelled
    end.

-spec remove_cancel_subscription(
    atomics:atomics_ref(), reference(), map()
) -> map().
remove_cancel_subscription(State, Token, Subscriptions) ->
    case maps:take(Token, Subscriptions) of
        {{_Subject, Monitor, _Delivery}, Next} ->
            demonitor(Monitor, [flush]),
            atomics:put(
                State,
                ?CANCEL_ACTIVE_SUBSCRIPTIONS,
                map_size(Next)
            ),
            _ = saturating_atomic_increment(State, ?CANCEL_UNSUBSCRIPTIONS),
            Next;
        error ->
            Subscriptions
    end.

-spec remove_cancel_monitor(atomics:atomics_ref(), reference(), map()) -> map().
remove_cancel_monitor(State, Monitor, Subscriptions) ->
    Next = maps:filter(
        fun(_Token, {_Subject, Candidate, _Delivery}) ->
            Candidate =/= Monitor
        end,
        Subscriptions
    ),
    Removed = map_size(Subscriptions) - map_size(Next),
    atomics:put(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS, map_size(Next)),
    record_abandoned_subscriptions(State, Removed),
    Next.

-spec notify_cancel_subscriptions(atomics:atomics_ref(), map()) -> ok.
notify_cancel_subscriptions(State, Subscriptions) ->
    maps:foreach(
        fun(_Token, {Subject, _Monitor, Delivery}) ->
            send_cancel_signal(State, Subject, Delivery)
        end,
        Subscriptions
    ),
    atomics:put(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS, 0).

-spec send_cancel_signal(
    atomics:atomics_ref(), term(), atomics:atomics_ref()
) -> ok.
send_cancel_signal(State, Subject, Delivery) ->
    case claim_cancel_delivery(Delivery) of
        true ->
            _ = saturating_atomic_increment(
                State,
                ?CANCEL_NOTIFICATIONS
            ),
            send_subject(Subject, nil);
        false ->
            ok
    end.

-spec claim_cancel_delivery(atomics:atomics_ref()) -> boolean().
claim_cancel_delivery(Delivery) ->
    try atomics:compare_exchange(Delivery, 1, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec suppress_cancel_delivery(atomics:atomics_ref()) -> boolean().
suppress_cancel_delivery(Delivery) ->
    try atomics:compare_exchange(Delivery, 1, 0, 2) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec record_abandoned_subscriptions(
    atomics:atomics_ref(), non_neg_integer()
) -> ok.
record_abandoned_subscriptions(_State, 0) ->
    ok;
record_abandoned_subscriptions(State, Remaining) ->
    _ = saturating_atomic_increment(
        State,
        ?CANCEL_ABANDONED_SUBSCRIPTIONS
    ),
    record_abandoned_subscriptions(State, Remaining - 1).

-spec send_subject(term(), term()) -> ok.
send_subject({subject, Pid, Tag}, Message) when is_pid(Pid) ->
    Pid ! {Tag, Message},
    ok;
send_subject(_Subject, _Message) ->
    ok.

-spec flush_subject(term()) -> ok.
flush_subject({subject, _Pid, Tag}) ->
    receive
        {Tag, _Message} -> flush_subject({subject, self(), Tag})
    after 0 ->
        ok
    end;
flush_subject(_Subject) ->
    ok.

-spec monotonic_millisecond() -> integer().
monotonic_millisecond() ->
    erlang:monotonic_time(millisecond).

-spec run_guarded(fun(() -> Value)) -> {ok, Value} | {error, nil}.
run_guarded(Fun) when is_function(Fun, 0) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        _Class:_Reason -> {error, nil}
    end;
run_guarded(_Fun) ->
    {error, nil}.

-spec call_bounded_adapter(fun(() -> term()), pos_integer(), pos_integer()) ->
    {ok, {ok, term()} | {error, term()}} |
    {error, bounded_adapter_failed | bounded_adapter_timed_out}.
call_bounded_adapter(Run, TimeoutMilliseconds, MaximumHeapWords)
    when is_function(Run, 0),
         is_integer(TimeoutMilliseconds), TimeoutMilliseconds > 0,
         TimeoutMilliseconds =< 2147483647,
         is_integer(MaximumHeapWords), MaximumHeapWords >= 1024,
         MaximumHeapWords =< 16777216 ->
    Parent = self(),
    Reference = make_ref(),
    Options = [
        monitor,
        {max_heap_size, #{
            size => MaximumHeapWords,
            kill => true,
            error_logger => false
        }}
    ],
    {Worker, Monitor} = spawn_opt(fun() ->
        Parent ! {Reference, bounded_adapter_outcome(Run)}
    end, Options),
    receive
        {Reference, {outcome, Outcome}} ->
            erlang:demonitor(Monitor, [flush]),
            {ok, Outcome};
        {Reference, adapter_failed} ->
            erlang:demonitor(Monitor, [flush]),
            {error, bounded_adapter_failed};
        {'DOWN', Monitor, process, Worker, _Reason} ->
            drain_adapter_reply(Reference),
            {error, bounded_adapter_failed}
    after TimeoutMilliseconds ->
        exit(Worker, kill),
        receive
            {'DOWN', Monitor, process, Worker, _Reason} -> ok
        end,
        drain_adapter_reply(Reference),
        {error, bounded_adapter_timed_out}
    end;
call_bounded_adapter(_Run, _TimeoutMilliseconds, _MaximumHeapWords) ->
    {error, bounded_adapter_failed}.

%% Return the same bounded outcome together with payload-free scheduling
%% evidence.  The two atomics let the caller distinguish a worker which never
%% began executing from a callback which exhausted its budget after starting;
%% neither the callback result nor its arguments are retained in the trace.
-spec call_bounded_adapter_traced(
    fun(() -> term()), pos_integer(), pos_integer()
) ->
    {{ok, {ok, term()} | {error, term()}} |
     {error, bounded_adapter_failed | bounded_adapter_timed_out},
     boolean(), non_neg_integer(), non_neg_integer(), boolean()}.
call_bounded_adapter_traced(Run, TimeoutMilliseconds, MaximumHeapWords)
    when is_function(Run, 0),
         is_integer(TimeoutMilliseconds), TimeoutMilliseconds > 0,
         TimeoutMilliseconds =< 2147483647,
         is_integer(MaximumHeapWords), MaximumHeapWords >= 1024,
         MaximumHeapWords =< 16777216 ->
    Parent = self(),
    Reference = make_ref(),
    ParentStarted = erlang:monotonic_time(millisecond),
    Deadline = ParentStarted + TimeoutMilliseconds,
    Trace = atomics:new(2, [{signed, true}]),
    Options = [
        monitor,
        {max_heap_size, #{
            size => MaximumHeapWords,
            kill => true,
            error_logger => false
        }}
    ],
    {Worker, Monitor} = spawn_opt(fun() ->
        WorkerStarted = erlang:monotonic_time(millisecond),
        atomics:put(Trace, 2, WorkerStarted),
        atomics:put(Trace, 1, 1),
        AdapterOutcome = bounded_adapter_outcome(Run),
        WorkerFinished = erlang:monotonic_time(millisecond),
        Parent ! {
            Reference,
            {traced_adapter_outcome, AdapterOutcome, WorkerStarted,
             WorkerFinished}
        }
    end, Options),
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {Reference,
         {traced_adapter_outcome, {outcome, Outcome}, WorkerStarted,
          WorkerFinished}} ->
            erlang:demonitor(Monitor, [flush]),
            {
                {ok, Outcome},
                true,
                bounded_elapsed(ParentStarted, WorkerStarted),
                bounded_elapsed(WorkerStarted, WorkerFinished),
                false
            };
        {Reference,
         {traced_adapter_outcome, adapter_failed, WorkerStarted,
          WorkerFinished}} ->
            erlang:demonitor(Monitor, [flush]),
            {
                {error, bounded_adapter_failed},
                true,
                bounded_elapsed(ParentStarted, WorkerStarted),
                bounded_elapsed(WorkerStarted, WorkerFinished),
                false
            };
        {'DOWN', Monitor, process, Worker, _Reason} ->
            drain_traced_adapter_reply(Reference),
            traced_adapter_failure(
                {error, bounded_adapter_failed}, ParentStarted, Trace, false
            )
    after Remaining ->
        exit(Worker, kill),
        receive
            {'DOWN', Monitor, process, Worker, _Reason} -> ok
        end,
        drain_traced_adapter_reply(Reference),
        traced_adapter_failure(
            {error, bounded_adapter_timed_out}, ParentStarted, Trace, true
        )
    end;
call_bounded_adapter_traced(_Run, _TimeoutMilliseconds, _MaximumHeapWords) ->
    {{error, bounded_adapter_failed}, false, 0, 0, false}.

-spec traced_adapter_failure(
    {error, bounded_adapter_failed | bounded_adapter_timed_out},
    integer(), atomics:atomics_ref(), boolean()
) ->
    {{error, bounded_adapter_failed | bounded_adapter_timed_out},
     boolean(), non_neg_integer(), non_neg_integer(), boolean()}.
traced_adapter_failure(Outcome, ParentStarted, Trace, SupervisorTimedOut) ->
    Observed = erlang:monotonic_time(millisecond),
    case atomics:get(Trace, 1) of
        1 ->
            WorkerStarted = atomics:get(Trace, 2),
            {
                Outcome,
                true,
                bounded_elapsed(ParentStarted, WorkerStarted),
                bounded_elapsed(WorkerStarted, Observed),
                SupervisorTimedOut
            };
        _ ->
            {
                Outcome,
                false,
                bounded_elapsed(ParentStarted, Observed),
                0,
                SupervisorTimedOut
            }
    end.

-spec bounded_elapsed(integer(), integer()) -> non_neg_integer().
bounded_elapsed(Started, Finished) when Finished =< Started ->
    0;
bounded_elapsed(Started, Finished) ->
    erlang:min(Finished - Started, 2147483647).

-spec drain_traced_adapter_reply(reference()) -> ok.
drain_traced_adapter_reply(Reference) ->
    receive
        {Reference, _LateOutcome} -> ok
    after 0 ->
        ok
    end.

-spec bounded_adapter_outcome(fun(() -> term())) ->
    {outcome, {ok, term()} | {error, term()}} | adapter_failed.
bounded_adapter_outcome(Run) ->
    try Run() of
        {ok, _Value} = Outcome -> {outcome, Outcome};
        {error, _Failure} = Outcome -> {outcome, Outcome};
        _Malformed -> adapter_failed
    catch
        _Class:_Reason -> adapter_failed
    end.

-spec drain_adapter_reply(reference()) -> ok.
drain_adapter_reply(Reference) ->
    receive
        {Reference, _LateOutcome} -> ok
    after 0 ->
        ok
    end.

-spec spawn_monitor(fun(() -> term())) -> {pid(), reference()}.
spawn_monitor(Fun) when is_function(Fun, 0) ->
    erlang:spawn_monitor(Fun).

-spec new_server_lifecycle() -> atomics:atomics_ref().
new_server_lifecycle() ->
    atomics:new(1, [{signed, false}]).

-spec server_lifecycle_state(atomics:atomics_ref()) -> 0 | 1 | 2.
server_lifecycle_state(Lifecycle) ->
    try atomics:get(Lifecycle, 1) of
        0 -> 0;
        1 -> 1;
        _ -> 2
    catch
        _:_ -> 2
    end.

-spec mark_server_draining(atomics:atomics_ref()) -> boolean().
mark_server_draining(Lifecycle) ->
    try atomics:compare_exchange(Lifecycle, 1, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec mark_server_stopped(atomics:atomics_ref()) -> boolean().
mark_server_stopped(Lifecycle) ->
    try atomics:exchange(Lifecycle, 1, 2) of
        2 -> false;
        _ -> true
    catch
        _:_ -> false
    end.

-spec new_resource_controller(pos_integer(), pos_integer()) ->
    resource_controller().
new_resource_controller(MaximumWorkers, MaximumMemory)
    when is_integer(MaximumWorkers), MaximumWorkers > 0,
         is_integer(MaximumMemory), MaximumMemory > 0 ->
    Counters = atomics:new(3, [{signed, true}]),
    {http_resource, Counters, MaximumWorkers, MaximumMemory}.

-spec resource_acquire(resource_controller(), non_neg_integer()) ->
    {ok, resource_lease()} | {error, 1 | 2 | 3}.
resource_acquire(
    {http_resource, Counters, MaximumWorkers, MaximumMemory},
    Memory
) when is_integer(Memory), Memory >= 0 ->
    case safe_atomic_get(Counters, ?RESOURCE_STOPPED, 1) of
        0 ->
            case reserve_bounded(
                Counters,
                ?RESOURCE_WORKERS,
                1,
                MaximumWorkers
            ) of
                false ->
                    {error, 1};
                true ->
                    case reserve_bounded(
                        Counters,
                        ?RESOURCE_MEMORY,
                        Memory,
                        MaximumMemory
                    ) of
                        false ->
                            _ = atomics:add(
                                Counters,
                                ?RESOURCE_WORKERS,
                                -1
                            ),
                            {error, 2};
                        true ->
                            finish_resource_acquire(Counters, Memory)
                    end
            end;
        _ ->
            {error, 3}
    end;
resource_acquire(_Controller, _Memory) ->
    {error, 3}.

-spec finish_resource_acquire(atomics:atomics_ref(), non_neg_integer()) ->
    {ok, resource_lease()} | {error, 3}.
finish_resource_acquire(Counters, Memory) ->
    case safe_atomic_get(Counters, ?RESOURCE_STOPPED, 1) of
        0 ->
            Lease = atomics:new(1, [{signed, true}]),
            ok = atomics:put(Lease, 1, Memory + 1),
            {ok, Lease};
        _ ->
            _ = atomics:add(Counters, ?RESOURCE_MEMORY, -Memory),
            _ = atomics:add(Counters, ?RESOURCE_WORKERS, -1),
            {error, 3}
    end.

-spec resource_resize(
    resource_controller(),
    resource_lease(),
    non_neg_integer()
) -> {ok, nil} | {error, 2 | 3}.
resource_resize(
    {http_resource, Counters, _MaximumWorkers, MaximumMemory},
    Lease,
    Memory
) when is_integer(Memory), Memory >= 0 ->
    resize_loop(Counters, MaximumMemory, Lease, Memory);
resource_resize(_Controller, _Lease, _Memory) ->
    {error, 3}.

-spec resize_loop(
    atomics:atomics_ref(),
    pos_integer(),
    resource_lease(),
    non_neg_integer()
) -> {ok, nil} | {error, 2 | 3}.
resize_loop(Counters, MaximumMemory, Lease, Memory) ->
    try atomics:get(Lease, 1) of
        0 ->
            {error, 3};
        Encoded ->
            Current = Encoded - 1,
            resize_from(
                Counters,
                MaximumMemory,
                Lease,
                Encoded,
                Current,
                Memory
            )
    catch
        _:_ -> {error, 3}
    end.

-spec resize_from(
    atomics:atomics_ref(),
    pos_integer(),
    resource_lease(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer()
) -> {ok, nil} | {error, 2 | 3}.
resize_from(_Counters, _Maximum, _Lease, _Encoded, Current, Current) ->
    {ok, nil};
resize_from(Counters, Maximum, Lease, Encoded, Current, Memory)
    when Memory < Current ->
    case atomics:compare_exchange(Lease, 1, Encoded, Memory + 1) of
        ok ->
            _ = atomics:add(
                Counters,
                ?RESOURCE_MEMORY,
                -(Current - Memory)
            ),
            {ok, nil};
        _ ->
            resize_loop(Counters, Maximum, Lease, Memory)
    end;
resize_from(Counters, Maximum, Lease, Encoded, Current, Memory) ->
    case safe_atomic_get(Counters, ?RESOURCE_STOPPED, 1) of
        0 ->
            Delta = Memory - Current,
            case reserve_bounded(
                Counters,
                ?RESOURCE_MEMORY,
                Delta,
                Maximum
            ) of
                false ->
                    {error, 2};
                true ->
                    case atomics:compare_exchange(
                        Lease,
                        1,
                        Encoded,
                        Memory + 1
                    ) of
                        ok ->
                            {ok, nil};
                        _ ->
                            _ = atomics:add(
                                Counters,
                                ?RESOURCE_MEMORY,
                                -Delta
                            ),
                            resize_loop(Counters, Maximum, Lease, Memory)
                    end
            end;
        _ ->
            {error, 3}
    end.

-spec resource_release(resource_controller(), resource_lease()) -> nil.
resource_release(
    {http_resource, Counters, _MaximumWorkers, _MaximumMemory},
    Lease
) ->
    release_loop(Counters, Lease),
    nil;
resource_release(_Controller, _Lease) ->
    nil.

-spec release_loop(atomics:atomics_ref(), resource_lease()) -> ok.
release_loop(Counters, Lease) ->
    try atomics:get(Lease, 1) of
        0 ->
            ok;
        Encoded ->
            case atomics:compare_exchange(Lease, 1, Encoded, 0) of
                ok ->
                    Memory = Encoded - 1,
                    _ = atomics:add(
                        Counters,
                        ?RESOURCE_MEMORY,
                        -Memory
                    ),
                    _ = atomics:add(
                        Counters,
                        ?RESOURCE_WORKERS,
                        -1
                    ),
                    ok;
                _ ->
                    release_loop(Counters, Lease)
            end
    catch
        _:_ -> ok
    end.

-spec resource_snapshot(resource_controller()) ->
    {non_neg_integer(), non_neg_integer()}.
resource_snapshot(
    {http_resource, Counters, _MaximumWorkers, _MaximumMemory}
) ->
    {
        nonnegative(safe_atomic_get(Counters, ?RESOURCE_WORKERS, 0)),
        nonnegative(safe_atomic_get(Counters, ?RESOURCE_MEMORY, 0))
    };
resource_snapshot(_Controller) ->
    {0, 0}.

-spec resource_stop(resource_controller()) -> nil.
resource_stop(
    {http_resource, Counters, _MaximumWorkers, _MaximumMemory}
) ->
    _ = atomics:exchange(Counters, ?RESOURCE_STOPPED, 1),
    nil;
resource_stop(_Controller) ->
    nil.

-spec reserve_bounded(
    atomics:atomics_ref(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer()
) -> boolean().
reserve_bounded(_Counters, _Index, 0, _Maximum) ->
    true;
reserve_bounded(Counters, Index, Amount, Maximum) ->
    Current = atomics:get(Counters, Index),
    case Current + Amount =< Maximum of
        false ->
            false;
        true ->
            case atomics:compare_exchange(
                Counters,
                Index,
                Current,
                Current + Amount
            ) of
                ok -> true;
                _ -> reserve_bounded(Counters, Index, Amount, Maximum)
            end
    end.

-spec new_diagnostic_credit(pos_integer()) -> diagnostic_credit().
new_diagnostic_credit(Maximum)
    when is_integer(Maximum), Maximum > 0 ->
    Counters = atomics:new(6, [{signed, true}]),
    {http_diagnostic_credit, Counters, Maximum}.

-spec new_diagnostic_request_id() -> pos_integer().
new_diagnostic_request_id() ->
    erlang:unique_integer([monotonic, positive]).

-spec diagnostic_reserve(diagnostic_credit()) -> non_neg_integer().
diagnostic_reserve({http_diagnostic_credit, Counters, Maximum}) ->
    case safe_atomic_get(Counters, ?DIAGNOSTIC_CLOSED, 1) of
        0 -> diagnostic_reserve_loop(Counters, Maximum);
        _ ->
            _ = saturating_atomic_increment(
                Counters,
                ?DIAGNOSTIC_DROPPED
            ),
            0
    end;
diagnostic_reserve(_Credit) ->
    0.

-spec diagnostic_reserve_loop(atomics:atomics_ref(), pos_integer()) ->
    non_neg_integer().
diagnostic_reserve_loop(Counters, Maximum) ->
    Current = atomics:get(Counters, ?DIAGNOSTIC_IN_FLIGHT),
    case Current >= Maximum of
        true ->
            _ = saturating_atomic_increment(
                Counters,
                ?DIAGNOSTIC_DROPPED
            ),
            0;
        false ->
            case atomics:compare_exchange(
                Counters,
                ?DIAGNOSTIC_IN_FLIGHT,
                Current,
                Current + 1
            ) of
                ok -> finish_diagnostic_reserve(Counters);
                _ -> diagnostic_reserve_loop(Counters, Maximum)
            end
    end.

-spec finish_diagnostic_reserve(atomics:atomics_ref()) -> non_neg_integer().
finish_diagnostic_reserve(Counters) ->
    case safe_atomic_get(Counters, ?DIAGNOSTIC_CLOSED, 1) of
        0 ->
            saturating_atomic_increment(
                Counters,
                ?DIAGNOSTIC_SEQUENCE
            );
        _ ->
            _ = atomics:add(Counters, ?DIAGNOSTIC_IN_FLIGHT, -1),
            _ = saturating_atomic_increment(
                Counters,
                ?DIAGNOSTIC_DROPPED
            ),
            0
    end.

-spec diagnostic_complete(diagnostic_credit(), boolean()) -> nil.
diagnostic_complete(
    {http_diagnostic_credit, Counters, _Maximum},
    Delivered
) ->
    Index = case Delivered of
        true -> ?DIAGNOSTIC_DELIVERED;
        false -> ?DIAGNOSTIC_FAILURES
    end,
    _ = saturating_atomic_increment(Counters, Index),
    _ = atomics:add(Counters, ?DIAGNOSTIC_IN_FLIGHT, -1),
    nil;
diagnostic_complete(_Credit, _Delivered) ->
    nil.

-spec diagnostic_snapshot(diagnostic_credit()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
diagnostic_snapshot({http_diagnostic_credit, Counters, _Maximum}) ->
    {
        nonnegative(atomics:get(Counters, ?DIAGNOSTIC_IN_FLIGHT)),
        nonnegative(atomics:get(Counters, ?DIAGNOSTIC_DELIVERED)),
        nonnegative(atomics:get(Counters, ?DIAGNOSTIC_DROPPED)),
        nonnegative(atomics:get(Counters, ?DIAGNOSTIC_FAILURES))
    };
diagnostic_snapshot(_Credit) ->
    {0, 0, 0, 0}.

-spec diagnostic_close(diagnostic_credit()) -> nil.
diagnostic_close({http_diagnostic_credit, Counters, _Maximum}) ->
    _ = atomics:exchange(Counters, ?DIAGNOSTIC_CLOSED, 1),
    nil;
diagnostic_close(_Credit) ->
    nil.

-spec safe_atomic_get(atomics:atomics_ref(), pos_integer(), integer()) ->
    integer().
safe_atomic_get(Atomics, Index, Default) ->
    try atomics:get(Atomics, Index)
    catch
        _:_ -> Default
    end.

-spec nonnegative(integer()) -> non_neg_integer().
nonnegative(Value) when Value >= 0 -> Value;
nonnegative(_Value) -> 0.
