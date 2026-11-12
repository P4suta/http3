%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_server_ffi).

-define(ADAPTER_JOIN_MILLISECONDS, 1000).

-export([
    call_bounded_adapter/3,
    call_bounded_adapter_registration_probe/4,
    call_bounded_adapter_traced/3,
    cancel_handle_snapshot/1,
    claim_close_guard/1,
    client_trace_new_state/0,
    client_trace_phase_transition/3,
    client_trace_phase_transition_if_missing/3,
    client_trace_publish_finished/1,
    client_trace_publish_headers/1,
    client_trace_publish_read/1,
    client_trace_publish_release/1,
    client_trace_record_finished/2,
    client_trace_record_finished_if_missing/2,
    client_trace_record_headers/1,
    client_trace_record_read/1,
    client_trace_record_release/3,
    client_trace_record_release_if_missing/3,
    client_trace_request_success/1,
    client_trace_snapshot/1,
    client_trace_success_ready/1,
    client_trace_take_release/1,
    close_guard_snapshot/1,
    diagnostic_abandon/1,
    diagnostic_close/1,
    diagnostic_complete/2,
    diagnostic_reserve/1,
    diagnostic_sequence_transition/1,
    diagnostic_snapshot/1,
    get_context_attribute/2,
    is_cancelled/1,
    mark_cancelled/1,
    mark_server_draining/1,
    mark_server_stopped/1,
    record_server_shutdown_provisional/2,
    record_server_shutdown_outcome/2,
    server_shutdown_provisional/1,
    server_shutdown_outcome/1,
    monotonic_millisecond/0,
    new_cancel_handle/0,
    new_cancel_handle_checked/0,
    new_cancel_handle_checked_with_factories/2,
    new_cancel_handle_with_factories/2,
    new_close_guard/0,
    new_context_attributes/0,
    new_context_key/0,
    new_diagnostic_credit/1,
    new_diagnostic_credit_with_factory/2,
    new_diagnostic_request_id/0,
    new_resource_controller/2,
    new_resource_controller_with_factory/3,
    new_server_lifecycle/0,
    new_token/0,
    adopt_token/1,
    abandon_token/1,
    worker_subject/2,
    worker_reports/2,
    reap_worker/4,
    new_udp_proxy_termination_guard/0,
    put_context_attribute/3,
    record_udp_proxy_termination/2,
    resource_acquire/2,
    resource_acquire_with_lease_factory/3,
    resource_controller_available/1,
    resource_release/2,
    resource_resize/3,
    resource_snapshot/1,
    resource_stop/1,
    run_guarded/1,
    server_lifecycle_state/1,
    start_http1_handler_guardian/10,
    spawn_link_monitor/1,
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

-define(CLIENT_TRACE_BITS, 1).
-define(CLIENT_TRACE_RELEASE_PROTOCOL, 2).
-define(CLIENT_TRACE_RELEASE_OUTCOME, 3).
-define(CLIENT_TRACE_DUPLICATES, 4).
-define(CLIENT_TRACE_OUT_OF_ORDER, 5).
-define(CLIENT_TRACE_LATE, 6).
-define(CLIENT_TRACE_HEADERS_RECORDED, 1).
-define(CLIENT_TRACE_HEADERS_PUBLISHED, 2).
-define(CLIENT_TRACE_FINISHED_RECORDED, 4).
-define(CLIENT_TRACE_FINISHED_OK, 8).
-define(CLIENT_TRACE_FINISHED_PUBLISHED, 16).
-define(CLIENT_TRACE_READ_RECORDED, 32).
-define(CLIENT_TRACE_READ_PUBLISHED, 64).
-define(CLIENT_TRACE_RELEASE_RECORDED, 128).
-define(CLIENT_TRACE_RELEASE_READY, 256).
-define(CLIENT_TRACE_RELEASE_TAKEN, 512).
-define(CLIENT_TRACE_RELEASE_PUBLISHED, 1024).
-define(CLIENT_TRACE_SUCCESS_REQUESTED, 2048).
-define(CLIENT_TRACE_PHASE_BASE, 6).
-define(CLIENT_TRACE_PHASE_COUNT, 20).

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
-define(SERVER_SHUTDOWN_SUCCESS, 1).
-define(SERVER_SHUTDOWN_SERVICE, 34).
-define(SERVER_SHUTDOWN_MAXIMUM, 34).
-define(MAXIMUM_COUNTER, 9223372036854775807).

-type resource_controller() ::
    {http_resource, atomics:atomics_ref(), pos_integer(), pos_integer()} |
    {http_resource_unavailable, pos_integer(), pos_integer()}.
-type resource_lease() :: atomics:atomics_ref().
-type diagnostic_credit() ::
    {http_diagnostic_credit, atomics:atomics_ref(), pos_integer()}.
-type client_trace_state() ::
    {http_client_trace_state, atomics:atomics_ref()}.
-type cancel_handle() ::
    {http_cancel_handle, atomics:atomics_ref(), pid()} |
    http_cancel_handle_unavailable.
-type cancel_subscription() ::
    {http_cancel_subscription, pid(), reference(), term(), atomics:atomics_ref()} |
    http_cancel_subscription_unavailable.

-spec new_context_key() -> reference().
new_context_key() ->
    make_ref().

-spec new_token() -> {reference(), reference(), atomics:atomics_ref()}.
new_token() ->
    {make_ref(), make_ref(), atomics:new(1, [{signed, false}])}.

%% Dispatch ownership is transferred exactly once, before user code starts.
%% An executor can die with its Dispatch still queued; the submitting process
%% may reclaim only an unadopted token. Adopted requests retain their guardian.
adopt_token({_Ref, _ReportRef, State}) -> atomics:compare_exchange(State, 1, 0, 1) =:= ok.
abandon_token({_Ref, _ReportRef, State}) -> atomics:compare_exchange(State, 1, 0, 2) =:= ok.

%% Construct the same private Subject capability in the executor and guardian
%% without a startup handshake or a second unbounded command channel.
worker_subject({Ref, _ReportRef, _State}, Pid) -> {subject, Pid, Ref}.
worker_reports({_Ref, ReportRef, _State}, Pid) -> {subject, Pid, ReportRef}.

%% One finite reaper per admitted request. It drops the handler closure after
%% spawning its guardian, relays the two completion messages in signal order,
%% and releases the grant only after guardian DOWN. It never executes user
%% code or stores a request/body in its steady-state loop.
reap_worker({Ref, ReportRef, State}, Commands, Run, Release) ->
    ok = proc_lib:set_label(<<"http.reaper">>),
    Reaper = self(),
    {Guardian, Monitor} = erlang:spawn_monitor(fun() ->
        ok = proc_lib:set_label(<<"http.guardian">>),
        Disposition = try Run() of
            release_lease -> release_lease;
            _ -> quarantine_lease
        catch
            _Class:_Reason -> quarantine_lease
        end,
        Reaper ! {guardian_disposition, self(), Disposition}
    end),
    reap_worker_loop(
        Ref, ReportRef, State, Commands, Guardian, Monitor,
        quarantine_lease, Release
    ).

reap_worker_loop(
    Ref, ReportRef, State, Commands, Guardian, Monitor, Disposition, Release
) ->
    receive
        {Ref, Command} ->
            Guardian ! {Ref, Command},
            reap_worker_loop(
                Ref, ReportRef, State, Commands, Guardian, Monitor,
                Disposition, Release
            );
        {ReportRef, Command} ->
            send_subject(Commands, Command),
            reap_worker_loop(
                Ref, ReportRef, State, Commands, Guardian, Monitor,
                Disposition, Release
            );
        {guardian_disposition, Guardian, NextDisposition}
          when NextDisposition =:= release_lease;
               NextDisposition =:= quarantine_lease ->
            reap_worker_loop(
                Ref, ReportRef, State, Commands, Guardian, Monitor,
                NextDisposition, Release
            );
        {'DOWN', Monitor, process, Guardian, _Reason} ->
            %% An abandoned dispatch is still owned by the submitting process,
            %% which may be inside input cleanup. A late guardian must not free
            %% that reservation before its actual owner has finished cleanup.
            %% A crashed guardian or an unconfirmed child join likewise keeps
            %% the finite scalar charge quarantined instead of inventing room.
            case {atomics:get(State, 1), Disposition} of
                {1, release_lease} -> Release();
                _ -> nil
            end
    end.

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
    new_cancel_handle_with_factories(
        fun() -> atomics:new(6, [{signed, false}]) end,
        fun(Work) -> spawn(Work) end
    ).

-spec new_cancel_handle_checked() ->
    {ok, cancel_handle()} | {error, nil}.
new_cancel_handle_checked() ->
    new_cancel_handle_checked_with_factories(
        fun() -> atomics:new(6, [{signed, false}]) end,
        fun(Work) -> spawn(Work) end
    ).

-spec new_cancel_handle_checked_with_factories(
    fun(() -> term()), fun((fun(() -> term())) -> term())
) -> {ok, cancel_handle()} | {error, nil}.
new_cancel_handle_checked_with_factories(StateFactory, SpawnFactory) ->
    case new_cancel_handle_with_factories(StateFactory, SpawnFactory) of
        http_cancel_handle_unavailable -> {error, nil};
        Handle -> {ok, Handle}
    end.

%% Keep both fallible VM primitives inside one unpublished construction
%% transaction. The factory seam lets deterministic tests prove that neither
%% atomics nor process exhaustion escapes through `context.new`.
-spec new_cancel_handle_with_factories(
    fun(() -> term()), fun((fun(() -> term())) -> term())
) -> cancel_handle().
new_cancel_handle_with_factories(StateFactory, SpawnFactory)
        when is_function(StateFactory, 0), is_function(SpawnFactory, 1) ->
    try
        State = StateFactory(),
        _ = atomics:get(State, ?CANCEL_BROKER_STOPPED),
        Owner = self(),
        Work = fun() ->
            ok = proc_lib:set_label(<<"http.cancel_broker">>),
            cancel_broker_init(Owner, State)
        end,
        Broker = SpawnFactory(Work),
        true = is_pid(Broker),
        {http_cancel_handle, State, Broker}
    catch
        _Class:_Reason -> http_cancel_handle_unavailable
    end;
new_cancel_handle_with_factories(_StateFactory, _SpawnFactory) ->
    http_cancel_handle_unavailable.

-spec new_close_guard() -> atomics:atomics_ref().
new_close_guard() ->
    atomics:new(5, [{signed, false}]).

-spec new_udp_proxy_termination_guard() -> atomics:atomics_ref().
new_udp_proxy_termination_guard() ->
    atomics:new(2, [{signed, false}]).

-spec record_udp_proxy_termination(atomics:atomics_ref(), 1..5) -> 1..5.
record_udp_proxy_termination(Guard, Reason)
    when is_integer(Reason), Reason >= 1, Reason =< 5 ->
    _ = saturating_atomic_increment(Guard, ?UDP_TERMINATION_NOTIFICATIONS),
    try atomics:compare_exchange(
        Guard, ?UDP_TERMINATION_REASON, 0, Reason
    ) of
        ok -> Reason;
        Existing when is_integer(Existing), Existing >= 1, Existing =< 5 ->
            Existing;
        _ -> 3
    catch
        _:_ -> 3
    end;
record_udp_proxy_termination(_Guard, _Reason) ->
    3.

-spec udp_proxy_termination_snapshot(atomics:atomics_ref()) ->
    {0..5, non_neg_integer()}.
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
    try atomics:get(Atomics, Index) of
        Current when Current >= ?MAXIMUM_COUNTER -> Current;
        Current ->
            case atomics:compare_exchange(
                Atomics, Index, Current, Current + 1
            ) of
                ok -> Current + 1;
                _ -> saturating_atomic_increment(Atomics, Index)
            end
    catch
        _Class:_Reason -> 0
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
    case new_cancel_delivery() of
        {ok, Delivery} ->
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
        error ->
            send_subject(Subject, nil),
            http_cancel_subscription_unavailable
    end;
subscribe_cancel_handle(_Handle, Subject) ->
    send_subject(Subject, nil),
    http_cancel_subscription_unavailable.

-spec new_cancel_delivery() -> {ok, atomics:atomics_ref()} | error.
new_cancel_delivery() ->
    try atomics:new(1, [{signed, false}]) of
        Delivery ->
            _ = atomics:get(Delivery, 1),
            {ok, Delivery}
    catch
        _Class:_Reason -> error
    end.

-spec unsubscribe_cancel_handle(cancel_subscription()) -> nil.
unsubscribe_cancel_handle(
    {http_cancel_subscription, Broker, Token, Subject, Delivery}
) when is_pid(Broker), is_reference(Token) ->
    _ = suppress_cancel_delivery(Delivery),
    Ref = make_ref(),
    case safe_monitor_process(Broker) of
        {ok, Monitor} ->
            Broker ! {unsubscribe, self(), Ref, Token},
            receive
                {Ref, unsubscribed} ->
                    safe_demonitor_process(Monitor);
                {'DOWN', Monitor, process, Broker, _Reason} ->
                    ok
            after 1000 ->
                safe_demonitor_process(Monitor)
            end;
        error ->
            ok
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
    case safe_monitor_process(Broker) of
        {ok, Monitor} ->
            Broker ! {subscribe, self(), Ref, Token, Subject, Delivery},
            receive
                {Ref, subscribed} ->
                    safe_demonitor_process(Monitor),
                    Subscription;
                {'DOWN', Monitor, process, Broker, _Reason} ->
                    send_cancel_signal(State, Subject, Delivery),
                    Subscription
            after 1000 ->
                safe_demonitor_process(Monitor),
                send_cancel_signal(State, Subject, Delivery),
                Subscription
            end;
        error ->
            send_cancel_signal(State, Subject, Delivery),
            Subscription
    end.

-spec cancel_broker_init(pid(), atomics:atomics_ref()) -> no_return() | ok.
cancel_broker_init(Owner, State) ->
    try
        case safe_monitor_process(Owner) of
            {ok, OwnerMonitor} ->
                cancel_broker_loop(State, OwnerMonitor, #{});
            error ->
                ok
        end
    after
        safe_atomic_put(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS, 0),
        safe_atomic_put(State, ?CANCEL_BROKER_STOPPED, 1)
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
                    case safe_monitor_process(From) of
                        {ok, SubscriberMonitor} ->
                            Next = maps:put(
                                Token,
                                {Subject, SubscriberMonitor, Delivery},
                                Subscriptions
                            ),
                            safe_atomic_put(
                                State,
                                ?CANCEL_ACTIVE_SUBSCRIPTIONS,
                                map_size(Next)
                            ),
                            From ! {Ref, subscribed},
                            cancel_broker_loop(
                                State,
                                OwnerMonitor,
                                Next
                            );
                        error ->
                            send_cancel_signal(State, Subject, Delivery),
                            From ! {Ref, subscribed},
                            cancel_broker_loop(
                                State,
                                OwnerMonitor,
                                Subscriptions
                            )
                    end
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
            safe_demonitor_process(Monitor),
            safe_atomic_put(
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
    safe_atomic_put(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS, map_size(Next)),
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
    safe_atomic_put(State, ?CANCEL_ACTIVE_SUBSCRIPTIONS, 0).

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

-spec safe_monitor_process(pid()) -> {ok, reference()} | error.
safe_monitor_process(Process) when is_pid(Process) ->
    try erlang:monitor(process, Process) of
        Monitor when is_reference(Monitor) -> {ok, Monitor}
    catch
        _Class:_Reason -> error
    end.

-spec safe_demonitor_process(reference()) -> ok.
safe_demonitor_process(Monitor) when is_reference(Monitor) ->
    try erlang:demonitor(Monitor, [flush]) of
        _ -> ok
    catch
        _Class:_Reason -> ok
    end;
safe_demonitor_process(_Monitor) ->
    ok.

-spec safe_atomic_put(term(), pos_integer(), integer()) -> ok.
safe_atomic_put(Atomics, Index, Value) ->
    try atomics:put(Atomics, Index, Value) of
        ok -> ok
    catch
        _Class:_Reason -> ok
    end.

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
    Started = erlang:monotonic_time(millisecond),
    Result = run_bounded_adapter(
        Run, TimeoutMilliseconds, MaximumHeapWords, untraced, no_probe, Started
    ),
    bounded_adapter_result(Result);
call_bounded_adapter(_Run, _TimeoutMilliseconds, _MaximumHeapWords) ->
    {error, bounded_adapter_failed}.

%% Internal payload-free lifecycle probe for proving the pre-registration
%% failure path. The observer receives only the two actor identifiers and a
%% fresh synchronization reference; no callback argument, callback result,
%% request, body, endpoint, or exception is copied into the observation event.
-spec call_bounded_adapter_registration_probe(
    fun(() -> term()), pos_integer(), pos_integer(), pid()
) ->
    {ok, {ok, term()} | {error, term()}} |
    {error, bounded_adapter_failed | bounded_adapter_timed_out}.
call_bounded_adapter_registration_probe(
    Run, TimeoutMilliseconds, MaximumHeapWords, Observer
)
    when is_function(Run, 0),
         is_integer(TimeoutMilliseconds), TimeoutMilliseconds > 0,
         TimeoutMilliseconds =< 2147483647,
         is_integer(MaximumHeapWords), MaximumHeapWords >= 1024,
         MaximumHeapWords =< 16777216,
         is_pid(Observer) ->
    ProbeReference = make_ref(),
    Result = run_bounded_adapter(
        Run,
        TimeoutMilliseconds,
        MaximumHeapWords,
        untraced,
        {registration_probe, Observer, ProbeReference},
        erlang:monotonic_time(millisecond)
    ),
    bounded_adapter_result(Result);
call_bounded_adapter_registration_probe(
    _Run, _TimeoutMilliseconds, _MaximumHeapWords, _Observer
) ->
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
    ParentStarted = erlang:monotonic_time(millisecond),
    Trace = atomics:new(2, [{signed, true}]),
    Result = run_bounded_adapter(
        Run,
        TimeoutMilliseconds,
        MaximumHeapWords,
        {traced, Trace},
        no_probe,
        ParentStarted
    ),
    case Result of
        {completed,
         {traced_adapter_outcome, {outcome, Outcome}, WorkerStarted,
          WorkerFinished}} ->
            traced_completed_adapter_result(
                {ok, Outcome},
                ParentStarted,
                WorkerStarted,
                WorkerFinished,
                false
            );
        {completed,
         {traced_adapter_outcome, adapter_failed, WorkerStarted,
          WorkerFinished}} ->
            traced_completed_adapter_result(
                {error, bounded_adapter_failed},
                ParentStarted,
                WorkerStarted,
                WorkerFinished,
                false
            );
        timed_out ->
            traced_adapter_failure(
                {error, bounded_adapter_timed_out},
                ParentStarted,
                Trace,
                true
            );
        cleanup_failed ->
            traced_adapter_failure(
                {error, bounded_adapter_failed},
                ParentStarted,
                Trace,
                true
            );
        failed ->
            traced_adapter_failure(
                {error, bounded_adapter_failed},
                ParentStarted,
                Trace,
                false
            )
    end;
call_bounded_adapter_traced(_Run, _TimeoutMilliseconds, _MaximumHeapWords) ->
    {{error, bounded_adapter_failed}, false, 0, 0, false}.

-spec bounded_adapter_result(
    {completed, term()} | timed_out | cleanup_failed | failed
) ->
    {ok, {ok, term()} | {error, term()}} |
    {error, bounded_adapter_failed | bounded_adapter_timed_out}.
bounded_adapter_result({completed, {outcome, Outcome}}) -> {ok, Outcome};
bounded_adapter_result({completed, adapter_failed}) ->
    {error, bounded_adapter_failed};
bounded_adapter_result(timed_out) -> {error, bounded_adapter_timed_out};
bounded_adapter_result(cleanup_failed) -> {error, bounded_adapter_failed};
bounded_adapter_result(failed) -> {error, bounded_adapter_failed}.

-spec run_bounded_adapter(
    fun(() -> term()), pos_integer(), pos_integer(),
    untraced | {traced, atomics:atomics_ref()},
    no_probe | {registration_probe, pid(), reference()}, integer()
) -> {completed, term()} | timed_out | cleanup_failed | failed.
run_bounded_adapter(
    Run, TimeoutMilliseconds, MaximumHeapWords, Mode, RegistrationProbe,
    Started
) ->
    Parent = self(),
    Reference = make_ref(),
    WorkerReference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = Started + TimeoutMilliseconds,
    TerminationDeadline = Deadline + ?ADAPTER_JOIN_MILLISECONDS,
    try
        {Worker, WorkerMonitor} = spawn_opt(fun() ->
            bounded_adapter_gated_worker(
                Parent, WorkerReference, Run, Mode, Deadline
            )
        end, bounded_adapter_spawn_options(MaximumHeapWords)),
        start_bounded_adapter_supervisor(
            Parent,
            ReplyAlias,
            Reference,
            Worker,
            WorkerMonitor,
            WorkerReference,
            MaximumHeapWords,
            Deadline,
            TerminationDeadline,
            RegistrationProbe
        )
    catch
        _:_ -> failed
    after
        _ = erlang:unalias(ReplyAlias)
    end.

-spec start_bounded_adapter_supervisor(
    pid(), reference(), reference(), pid(), reference(), reference(),
    pos_integer(), integer(), integer(),
    no_probe | {registration_probe, pid(), reference()}
) -> {completed, term()} | timed_out | cleanup_failed | failed.
start_bounded_adapter_supervisor(
    Parent,
    ReplyAlias,
    Reference,
    Worker,
    WorkerMonitor,
    WorkerReference,
    MaximumHeapWords,
    Deadline,
    TerminationDeadline,
    RegistrationProbe
) ->
    try spawn_opt(fun() ->
            bounded_adapter_supervisor(
                Parent,
                ReplyAlias,
                Reference,
                Worker,
                WorkerReference,
                Deadline,
                TerminationDeadline,
                RegistrationProbe
            )
        end, bounded_adapter_spawn_options(MaximumHeapWords)) of
        {Supervisor, Monitor} ->
            try await_bounded_adapter_supervisor(
                Reference,
                Supervisor,
                Monitor,
                Worker,
                WorkerMonitor,
                Deadline,
                TerminationDeadline
            )
            catch
                _:_ ->
                    case stop_registered_bounded_adapter(
                        Supervisor,
                        Monitor,
                        Worker,
                        WorkerMonitor,
                        TerminationDeadline
                    ) of
                        confirmed -> failed;
                        unconfirmed -> cleanup_failed
                    end
            end
    catch
        _:_ ->
            case stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ) of
                confirmed -> failed;
                unconfirmed -> cleanup_failed
            end
    end.

-spec bounded_adapter_gated_worker(
    pid(), reference(), fun(() -> term()),
    untraced | {traced, atomics:atomics_ref()}, integer()
) -> ok.
bounded_adapter_gated_worker(Owner, WorkerReference, Run, Mode, Deadline) ->
    ok = proc_lib:set_label(<<"http.adapter_callback_gated">>),
    OwnerMonitor = erlang:monitor(process, Owner),
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            ok;
        {WorkerReference, start, Supervisor} when is_pid(Supervisor) ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    erlang:demonitor(OwnerMonitor, [flush]),
                    bounded_adapter_worker(
                        Supervisor, WorkerReference, Run, Mode
                    );
                false ->
                    erlang:demonitor(OwnerMonitor, [flush]),
                    ok
            end
    after Remaining ->
        erlang:demonitor(OwnerMonitor, [flush]),
        ok
    end.

%% The supervisor installs the caller monitor before the callback is allowed
%% to start. The API caller created and monitored the still-gated worker before
%% this supervisor existed; the supervisor adds its own monitor and link before
%% registration. Either survivor can therefore reap the callback. A result is
%% published only after the supervisor's worker DOWN signal has been consumed,
%% and the API caller confirms both of its DOWN signals before accepting it.
-spec bounded_adapter_supervisor(
    pid(), reference(), reference(), pid(), reference(), integer(), integer(),
    no_probe | {registration_probe, pid(), reference()}
) -> ok.
bounded_adapter_supervisor(
    Owner,
    ReplyTo,
    Reference,
    Worker,
    WorkerReference,
    Deadline,
    TerminationDeadline,
    RegistrationProbe
) ->
    ok = proc_lib:set_label(<<"http.adapter_supervisor">>),
    _ = process_flag(trap_exit, true),
    OwnerMonitor = erlang:monitor(process, Owner),
    WorkerMonitor = erlang:monitor(process, Worker),
    _ = link(Worker),
    RegistrationReference = make_ref(),
    case bounded_adapter_registration_probe(
        RegistrationProbe,
        Owner,
        OwnerMonitor,
        Worker,
        WorkerMonitor,
        Deadline
    ) of
        continue ->
            %% Registration proves this supervisor's monitor and link already
            %% exist. The caller's monitor was returned atomically with worker
            %% creation, so acknowledgement can safely release the gate.
            ReplyTo ! {
                Reference,
                {bounded_adapter_worker_registered,
                 Worker, RegistrationReference}
            },
            bounded_adapter_supervisor_await_registration(
                Owner,
                ReplyTo,
                OwnerMonitor,
                Reference,
                Worker,
                WorkerMonitor,
                WorkerReference,
                RegistrationReference,
                Deadline,
                TerminationDeadline
            );
        owner_down ->
            _ = stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ),
            ok;
        worker_down ->
            ok;
        timed_out ->
            bounded_adapter_supervisor_timeout(
                Owner,
                ReplyTo,
                Reference,
                Worker,
                WorkerMonitor,
                TerminationDeadline
            )
    end.

-spec bounded_adapter_registration_probe(
    no_probe | {registration_probe, pid(), reference()},
    pid(), reference(), pid(), reference(), integer()
) -> continue | owner_down | worker_down | timed_out.
bounded_adapter_registration_probe(
    no_probe, _Owner, _OwnerMonitor, _Worker, _WorkerMonitor, _Deadline
) ->
    continue;
bounded_adapter_registration_probe(
    {registration_probe, Observer, ProbeReference},
    Owner,
    OwnerMonitor,
    Worker,
    WorkerMonitor,
    Deadline
) ->
    Observer ! {
        bounded_adapter_pre_registration,
        ProbeReference,
        self(),
        Worker
    },
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {ProbeReference, continue_registration} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> continue;
                false -> timed_out
            end;
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            owner_down;
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            worker_down
    after Remaining ->
        timed_out
    end.

%% Do not release the callback gate until the API caller confirms that its
%% independent worker monitor exists. Without this acknowledgement a short
%% callback can exit between registration delivery and monitor installation;
%% the caller would then observe a synthetic `noproc` DOWN and misclassify a
%% successful result as a worker failure.
-spec bounded_adapter_supervisor_await_registration(
    pid(), reference(), reference(), reference(), pid(), reference(),
    reference(), reference(), integer(), integer()
) -> ok.
bounded_adapter_supervisor_await_registration(
    Owner,
    ReplyTo,
    OwnerMonitor,
    Reference,
    Worker,
    WorkerMonitor,
    WorkerReference,
    RegistrationReference,
    Deadline,
    TerminationDeadline
) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            _ = stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ),
            ok;
        {RegistrationReference, bounded_adapter_worker_monitored} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    Worker ! {WorkerReference, start, self()},
                    bounded_adapter_supervisor_loop(
                        Owner,
                        ReplyTo,
                        OwnerMonitor,
                        Reference,
                        Worker,
                        WorkerMonitor,
                        WorkerReference,
                        Deadline,
                        TerminationDeadline
                    );
                false ->
                    bounded_adapter_supervisor_timeout(
                        Owner,
                        ReplyTo,
                        Reference,
                        Worker,
                        WorkerMonitor,
                        TerminationDeadline
                    )
            end;
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            publish_bounded_adapter_result(
                ReplyTo,
                Reference,
                bounded_adapter_terminal_result(Deadline, failed)
            )
    after Remaining ->
        bounded_adapter_supervisor_timeout(
            Owner,
            ReplyTo,
            Reference,
            Worker,
            WorkerMonitor,
            TerminationDeadline
        )
    end.

-spec bounded_adapter_spawn_options(pos_integer()) -> [term()].
bounded_adapter_spawn_options(MaximumHeapWords) ->
    [
        monitor,
        {max_heap_size, #{
            size => MaximumHeapWords,
            kill => true,
            error_logger => false,
            include_shared_binaries => true
        }}
    ].

-spec bounded_adapter_worker(
    pid(), reference(), fun(() -> term()),
    untraced | {traced, atomics:atomics_ref()}
) -> ok.
bounded_adapter_worker(Supervisor, WorkerReference, Run, untraced) ->
    ok = proc_lib:set_label(<<"http.adapter_callback">>),
    Supervisor ! {
        WorkerReference,
        bounded_adapter_outcome(Run)
    },
    ok;
bounded_adapter_worker(
    Supervisor, WorkerReference, Run, {traced, Trace}
) ->
    ok = proc_lib:set_label(<<"http.adapter_callback">>),
    WorkerStarted = erlang:monotonic_time(millisecond),
    atomics:put(Trace, 2, WorkerStarted),
    atomics:put(Trace, 1, 1),
    AdapterOutcome = bounded_adapter_outcome(Run),
    WorkerFinished = erlang:monotonic_time(millisecond),
    Supervisor ! {
        WorkerReference,
        {traced_adapter_outcome, AdapterOutcome, WorkerStarted,
         WorkerFinished}
    },
    ok.

-spec bounded_adapter_supervisor_loop(
    pid(), reference(), reference(), reference(), pid(), reference(),
    reference(), integer(), integer()
) -> ok.
bounded_adapter_supervisor_loop(
    Owner,
    ReplyTo,
    OwnerMonitor,
    Reference,
    Worker,
    WorkerMonitor,
    WorkerReference,
    Deadline,
    TerminationDeadline
) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            _ = stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ),
            ok;
        {WorkerReference, Outcome} ->
            bounded_adapter_supervisor_after_outcome(
                Owner,
                ReplyTo,
                OwnerMonitor,
                Reference,
                Worker,
                WorkerMonitor,
                Outcome,
                Deadline,
                TerminationDeadline
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            publish_bounded_adapter_result(
                ReplyTo,
                Reference,
                bounded_adapter_terminal_result(Deadline, failed)
            )
    after Remaining ->
        bounded_adapter_supervisor_timeout(
            Owner,
            ReplyTo,
            Reference,
            Worker,
            WorkerMonitor,
            TerminationDeadline
        )
    end.

-spec bounded_adapter_supervisor_after_outcome(
    pid(), reference(), reference(), reference(), pid(), reference(), term(),
    integer(), integer()
) -> ok.
bounded_adapter_supervisor_after_outcome(
    Owner,
    ReplyTo,
    OwnerMonitor,
    Reference,
    Worker,
    WorkerMonitor,
    Outcome,
    Deadline,
    TerminationDeadline
) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            _ = stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ),
            ok;
        {'DOWN', WorkerMonitor, process, Worker, normal} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    publish_bounded_adapter_result(
                        ReplyTo, Reference, {completed, Outcome}
                    );
                false ->
                    publish_bounded_adapter_result(
                        ReplyTo, Reference, timed_out
                    )
            end;
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            publish_bounded_adapter_result(
                ReplyTo,
                Reference,
                bounded_adapter_terminal_result(Deadline, failed)
            )
    after Remaining ->
        bounded_adapter_supervisor_timeout(
            Owner,
            ReplyTo,
            Reference,
            Worker,
            WorkerMonitor,
            TerminationDeadline
        )
    end.

-spec bounded_adapter_terminal_result(
    integer(), failed
) -> timed_out | failed.
bounded_adapter_terminal_result(Deadline, BeforeDeadline) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        true -> BeforeDeadline;
        false -> timed_out
    end.

-spec bounded_adapter_supervisor_timeout(
    pid(), reference(), reference(), pid(), reference(), integer()
) -> ok.
bounded_adapter_supervisor_timeout(
    _Owner, ReplyTo, Reference, Worker, WorkerMonitor, TerminationDeadline
) ->
    Result = case stop_bounded_adapter(
        Worker, WorkerMonitor, TerminationDeadline
    ) of
        confirmed -> timed_out;
        unconfirmed -> cleanup_failed
    end,
    publish_bounded_adapter_result(ReplyTo, Reference, Result).

-spec publish_bounded_adapter_result(
    pid() | reference(), reference(),
    {completed, term()} | timed_out | cleanup_failed | failed
) -> ok.
publish_bounded_adapter_result(ReplyTo, Reference, Result) ->
    ReplyTo ! {Reference, {bounded_adapter_supervisor_result, Result}},
    ok.

-spec await_bounded_adapter_supervisor(
    reference(), pid(), reference(), pid(), reference(), integer(), integer()
) -> {completed, term()} | timed_out | cleanup_failed | failed.
await_bounded_adapter_supervisor(
    Reference,
    Supervisor,
    Monitor,
    Worker,
    WorkerMonitor,
    Deadline,
    TerminationDeadline
) ->
    Remaining = erlang:max(
        0, TerminationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {Reference,
         {bounded_adapter_worker_registered, Worker, RegistrationReference}}
                when is_reference(RegistrationReference) ->
            Supervisor ! {
                RegistrationReference, bounded_adapter_worker_monitored
            },
            await_registered_bounded_adapter_supervisor(
                Reference,
                Supervisor,
                Monitor,
                Worker,
                WorkerMonitor,
                Deadline,
                TerminationDeadline
            );
        {Reference, {bounded_adapter_supervisor_result, _Result}} ->
            %% A result before worker registration violates the causal
            %% protocol. The caller nevertheless owns both original monitors,
            %% so it can prove both actors are down before reporting failure.
            StopResult = stop_registered_bounded_adapter(
                Supervisor,
                Monitor,
                Worker,
                WorkerMonitor,
                TerminationDeadline
            ),
            drain_bounded_adapter_supervisor_reply(Reference),
            case StopResult of
                confirmed -> failed;
                unconfirmed -> cleanup_failed
            end;
        {'DOWN', Monitor, process, Supervisor, _Reason} ->
            drain_bounded_adapter_supervisor_reply(Reference),
            case stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ) of
                confirmed -> failed;
                unconfirmed -> cleanup_failed
            end
    after Remaining ->
        StopResult = stop_registered_bounded_adapter(
            Supervisor,
            Monitor,
            Worker,
            WorkerMonitor,
            TerminationDeadline
        ),
        drain_bounded_adapter_supervisor_reply(Reference),
        stopped_supervisor_result(StopResult)
    end.

-spec await_registered_bounded_adapter_supervisor(
    reference(), pid(), reference(), pid(), reference(), integer(), integer()
) -> {completed, term()} | timed_out | cleanup_failed | failed.
await_registered_bounded_adapter_supervisor(
    Reference,
    Supervisor,
    Monitor,
    Worker,
    WorkerMonitor,
    Deadline,
    TerminationDeadline
) ->
    Remaining = erlang:max(
        0, TerminationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {Reference, {bounded_adapter_supervisor_result, Result}} ->
            CompletionDeadline = case Result of
                timed_out -> TerminationDeadline;
                cleanup_failed -> TerminationDeadline;
                _ -> Deadline
            end,
            finish_registered_bounded_adapter_result(
                Result,
                Supervisor,
                Monitor,
                Worker,
                WorkerMonitor,
                CompletionDeadline,
                TerminationDeadline
            );
        {'DOWN', Monitor, process, Supervisor, _Reason} ->
            drain_bounded_adapter_supervisor_reply(Reference),
            case stop_bounded_adapter(
                Worker, WorkerMonitor, TerminationDeadline
            ) of
                confirmed -> failed;
                unconfirmed -> cleanup_failed
            end
    after Remaining ->
        StopResult = stop_registered_bounded_adapter(
            Supervisor,
            Monitor,
            Worker,
            WorkerMonitor,
            TerminationDeadline
        ),
        drain_bounded_adapter_supervisor_reply(Reference),
        stopped_supervisor_result(StopResult)
    end.

-spec finish_registered_bounded_adapter_result(
    {completed, term()} | timed_out | cleanup_failed | failed,
    pid(), reference(), pid(), reference(), integer(), integer()
) -> {completed, term()} | timed_out | cleanup_failed | failed.
finish_registered_bounded_adapter_result(
    Result,
    Supervisor,
    Monitor,
    Worker,
    WorkerMonitor,
    CompletionDeadline,
    TerminationDeadline
) ->
    case await_bounded_adapter_down(
        Worker, WorkerMonitor, CompletionDeadline
    ) of
        timed_out ->
            stopped_supervisor_result(
                stop_registered_bounded_adapter(
                    Supervisor,
                    Monitor,
                    Worker,
                    WorkerMonitor,
                    TerminationDeadline
                )
            );
        WorkerExit ->
            case await_bounded_adapter_down(
                Supervisor, Monitor, CompletionDeadline
            ) of
                normal ->
                    case {WorkerExit, Result} of
                        {normal, _AnyResult} -> Result;
                        {abnormal, {completed, _Outcome}} -> failed;
                        {abnormal, _Failure} -> Result
                    end;
                abnormal -> failed;
                timed_out ->
                    stopped_supervisor_result(
                        stop_bounded_adapter(
                            Supervisor, Monitor, TerminationDeadline
                        )
                    )
            end
    end.

-spec stop_registered_bounded_adapter(
    pid(), reference(), pid(), reference(), integer()
) -> confirmed | unconfirmed.
stop_registered_bounded_adapter(
    Supervisor, Monitor, Worker, WorkerMonitor, TerminationDeadline
) ->
    %% Fan out both stops before joining either process. Both joins use the
    %% same precomputed absolute deadline, so a delayed first DOWN cannot grant
    %% a fresh cleanup interval to the second process.
    exit(Supervisor, kill),
    exit(Worker, kill),
    WorkerStopped = await_bounded_adapter_stop(
        Worker, WorkerMonitor, TerminationDeadline
    ),
    SupervisorStopped = await_bounded_adapter_stop(
        Supervisor, Monitor, TerminationDeadline
    ),
    case {WorkerStopped, SupervisorStopped} of
        {confirmed, confirmed} -> confirmed;
        _ -> unconfirmed
    end.

-spec stopped_supervisor_result(confirmed | unconfirmed) ->
    timed_out | cleanup_failed.
stopped_supervisor_result(confirmed) -> timed_out;
stopped_supervisor_result(unconfirmed) -> cleanup_failed.

-spec drain_bounded_adapter_supervisor_reply(reference()) -> ok.
drain_bounded_adapter_supervisor_reply(Reference) ->
    receive
        {Reference, {bounded_adapter_supervisor_result, _Result}} ->
            drain_bounded_adapter_supervisor_reply(Reference);
        {Reference,
         {bounded_adapter_worker_registered, _Worker,
          _RegistrationReference}} ->
            drain_bounded_adapter_supervisor_reply(Reference)
    after 0 ->
        ok
    end.

%% A callback result is not complete until its monitored worker has exited.
%% This prevents a successful adapter call from leaving a short-lived actor
%% behind and gives callers a causal cleanup barrier instead of forcing them to
%% guess a scheduler delay. The callback's original absolute deadline bounds
%% normal completion; forced cleanup has one finite join allowance.
-spec await_bounded_adapter_down(pid(), reference(), integer()) ->
    normal | abnormal | timed_out.
await_bounded_adapter_down(Worker, Monitor, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, Worker, normal} -> normal;
        {'DOWN', Monitor, process, Worker, _Reason} -> abnormal
    after Remaining ->
        timed_out
    end.

-spec stop_bounded_adapter(pid(), reference(), integer()) ->
    confirmed | unconfirmed.
stop_bounded_adapter(Worker, Monitor, TerminationDeadline) ->
    exit(Worker, kill),
    await_bounded_adapter_stop(Worker, Monitor, TerminationDeadline).

-spec await_bounded_adapter_stop(pid(), reference(), integer()) ->
    confirmed | unconfirmed.
await_bounded_adapter_stop(Worker, Monitor, TerminationDeadline) ->
    Remaining = erlang:max(
        0, TerminationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, Worker, _Reason} -> confirmed
    after Remaining ->
        erlang:demonitor(Monitor, [flush]),
        unconfirmed
    end.

-spec traced_completed_adapter_result(
    {ok, term()} | {error, bounded_adapter_failed | bounded_adapter_timed_out},
    integer(), integer(), integer(), boolean()
) ->
    {{ok, term()} | {error, bounded_adapter_failed | bounded_adapter_timed_out},
     true, non_neg_integer(), non_neg_integer(), boolean()}.
traced_completed_adapter_result(
    Outcome, ParentStarted, WorkerStarted, WorkerFinished, SupervisorTimedOut
) ->
    {
        Outcome,
        true,
        bounded_elapsed(ParentStarted, WorkerStarted),
        bounded_elapsed(WorkerStarted, WorkerFinished),
        SupervisorTimedOut
    }.

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

%% The connection atomically monitors one guardian. The guardian installs its
%% owner monitor before it atomically links to and monitors the handler. Only
%% the guardian owns the handler monitor, and every successful publication is
%% ordered after consuming that original monitor's DOWN signal.
-spec start_http1_handler_guardian(
    term(), fun(() -> term()), fun(() -> term()), fun((term()) -> term()),
    fun((integer(), pid()) -> term()), fun(() -> term()),
    fun((pid()) -> term()), integer(), pos_integer(), pos_integer()
) -> {ok, {reference(), term()}} |
     {error, handler_start_timed_out | handler_start_failed}.
start_http1_handler_guardian(
    Events, Run, Cancel, Discard, Probe, AfterResult, Terminate,
    HandlerDeadline, CleanupMilliseconds, StartupMilliseconds
) when is_function(Run, 0),
       is_function(Cancel, 0),
       is_function(Discard, 1),
       is_function(Probe, 2),
       is_function(AfterResult, 0),
       is_function(Terminate, 1),
       is_integer(HandlerDeadline),
       is_integer(CleanupMilliseconds), CleanupMilliseconds > 0,
       CleanupMilliseconds =< 2147483647,
       is_integer(StartupMilliseconds), StartupMilliseconds > 0,
       StartupMilliseconds =< 2147483647 ->
    StartedAt = monotonic_millisecond(),
    case StartedAt >= HandlerDeadline of
        true ->
            {error, handler_start_timed_out};
        false ->
            Owner = self(),
            ReadyReference = make_ref(),
            StartupDeadline = StartedAt + StartupMilliseconds,
            EffectiveStartupDeadline = erlang:min(
                StartupDeadline, HandlerDeadline
            ),
            {Guardian, GuardianMonitor} = erlang:spawn_monitor(fun() ->
                http1_handler_guardian_boot(
                    Owner, ReadyReference, Events, Run, Cancel, Discard,
                    Probe, AfterResult, Terminate, HandlerDeadline,
                    CleanupMilliseconds, EffectiveStartupDeadline
                )
            end),
            http1_handler_guardian_await_ready(
                Guardian, GuardianMonitor, ReadyReference,
                EffectiveStartupDeadline, HandlerDeadline,
                CleanupMilliseconds
            )
    end;
start_http1_handler_guardian(
    _Events, _Run, _Cancel, _Discard, _Probe, _AfterResult, _Terminate,
    _HandlerDeadline, _CleanupMilliseconds, _StartupMilliseconds
) ->
    {error, handler_start_failed}.

http1_handler_guardian_await_ready(
    Guardian, GuardianMonitor, ReadyReference, StartupDeadline,
    HandlerDeadline, CleanupMilliseconds
) ->
    receive
        {ReadyReference, Guardian, Commands, ReadyAt}
          when is_integer(ReadyAt), ReadyAt =< StartupDeadline ->
            Guardian ! {ReadyReference, start},
            {ok, {GuardianMonitor, Commands}};
        {ReadyReference, Guardian, _Commands, _ReadyAt} ->
            http1_handler_guardian_abort_start(
                Guardian, GuardianMonitor, ReadyReference, CleanupMilliseconds,
                http1_handler_start_failure(HandlerDeadline)
            );
        {'DOWN', GuardianMonitor, process, Guardian, _} ->
            {error, http1_handler_start_failure(HandlerDeadline)}
    after http1_handler_guardian_remaining(StartupDeadline) ->
        http1_handler_guardian_abort_start(
            Guardian, GuardianMonitor, ReadyReference, CleanupMilliseconds,
            http1_handler_start_failure(HandlerDeadline)
        )
    end.

http1_handler_guardian_abort_start(
    Guardian, GuardianMonitor, ReadyReference, CleanupMilliseconds, Failure
) ->
    Guardian ! {ReadyReference, abort},
    exit(Guardian, kill),
    CleanupDeadline = monotonic_millisecond() + CleanupMilliseconds,
    _ = receive
        {'DOWN', GuardianMonitor, process, Guardian, _} -> true
    after http1_handler_guardian_remaining(CleanupDeadline) -> false
    end,
    {error, Failure}.

http1_handler_start_failure(HandlerDeadline) ->
    case monotonic_millisecond() >= HandlerDeadline of
        true -> handler_start_timed_out;
        false -> handler_start_failed
    end.

http1_handler_guardian_boot(
    Owner, ReadyReference, Events, Run, Cancel, Discard, Probe, AfterResult,
    Terminate, HandlerDeadline, CleanupMilliseconds, StartupDeadline
) ->
    ok = proc_lib:set_label(<<"http.http1_handler_guardian">>),
    process_flag(trap_exit, true),
    OwnerMonitor = erlang:monitor(process, Owner),
    CommandTag = make_ref(),
    Commands = {subject, self(), CommandTag},
    Owner ! {ReadyReference, self(), Commands, monotonic_millisecond()},
    receive
        {ReadyReference, start} ->
            receive
                {'DOWN', OwnerMonitor, process, Owner, _} ->
                    http1_handler_guardian_safe_call(Cancel, [])
            after 0 ->
                http1_handler_guardian_safe_probe(Probe, 0, self()),
                receive
                    {'DOWN', OwnerMonitor, process, Owner, _} ->
                        http1_handler_guardian_safe_call(Cancel, [])
                after 0 ->
                    case monotonic_millisecond() >= HandlerDeadline of
                        true ->
                            http1_handler_guardian_safe_call(Cancel, []),
                            send_subject(
                                Events,
                                {handler_terminated, handler_timed_out}
                            ),
                            erlang:demonitor(OwnerMonitor, [flush]),
                            ok;
                        false ->
                            http1_handler_guardian_start_handler(
                                Owner, OwnerMonitor, Events, CommandTag, Run,
                                Cancel, Discard, Probe, AfterResult, Terminate,
                                HandlerDeadline, CleanupMilliseconds
                            )
                    end
                end
            end;
        {ReadyReference, abort} ->
            erlang:demonitor(OwnerMonitor, [flush]),
            ok;
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            http1_handler_guardian_safe_call(Cancel, [])
    after http1_handler_guardian_remaining(StartupDeadline) ->
        erlang:demonitor(OwnerMonitor, [flush]),
        ok
    end.

http1_handler_guardian_start_handler(
    Owner, OwnerMonitor, Events, CommandTag, Run, Cancel, Discard, Probe,
    AfterResult, Terminate, HandlerDeadline, CleanupMilliseconds
) ->
    Guardian = self(),
    HandlerReference = make_ref(),
    {Handler, HandlerMonitor} = erlang:spawn_opt(fun() ->
        http1_handler_guardian_handler_entry(
            Guardian, HandlerReference, Run, Probe, AfterResult,
            HandlerDeadline
        )
    end, [link, monitor]),
    State = #{
        owner => Owner,
        owner_monitor => OwnerMonitor,
        owner_alive => true,
        events => Events,
        command_tag => CommandTag,
        cancel => Cancel,
        discard => Discard,
        probe => Probe,
        terminate => Terminate,
        handler => Handler,
        handler_monitor => HandlerMonitor,
        handler_reference => HandlerReference,
        handler_deadline => HandlerDeadline,
        cleanup_milliseconds => CleanupMilliseconds,
        result => none,
        exit_at => none,
        failure_at => none,
        timed_out => false
    },
    %% The handler is atomically linked and monitored but cannot enter user
    %% code until this guardian issues its start token. Tests may hold phase 2
    %% to prove the handler's own absolute-deadline check closes a scheduler
    %% preemption window after the guardian's earlier check.
    http1_handler_guardian_safe_probe(Probe, 2, Handler),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            OwnerDownAt = monotonic_millisecond(),
            http1_handler_guardian_begin_termination(
                State#{owner_alive => false}, handler_stopped, false,
                OwnerDownAt + CleanupMilliseconds
            )
    after 0 ->
        Handler ! {HandlerReference, handler_start, Guardian},
        http1_handler_guardian_active(State)
    end.

http1_handler_guardian_handler_entry(
    Guardian, HandlerReference, Run, Probe, AfterResult, HandlerDeadline
) ->
    ok = proc_lib:set_label(<<"http.http1_handler">>),
    receive
        {HandlerReference, handler_start, Guardian} ->
            case monotonic_millisecond() >= HandlerDeadline of
                true ->
                    http1_handler_guardian_handler_timed_out(
                        Guardian, HandlerReference
                    );
                false ->
                    http1_handler_guardian_safe_probe(Probe, 1, Guardian),
                    case monotonic_millisecond() >= HandlerDeadline of
                        true ->
                            http1_handler_guardian_handler_timed_out(
                                Guardian, HandlerReference
                            );
                        false ->
                            try Run() of
                                Result ->
                                    Guardian ! {
                                        HandlerReference, handler_result,
                                        self(), Result
                                    },
                                    try AfterResult() of
                                        _ ->
                                            ExitAt = monotonic_millisecond(),
                                            Guardian ! {
                                                HandlerReference,
                                                handler_exit_ready,
                                                self(), ExitAt
                                            },
                                            nil
                                    catch
                                        _:_ ->
                                            Guardian ! {
                                                HandlerReference,
                                                handler_failed, self(),
                                                monotonic_millisecond()
                                            },
                                            nil
                                    end
                            catch
                                _:_ ->
                                    Guardian ! {
                                        HandlerReference, handler_failed,
                                        self(), monotonic_millisecond()
                                    },
                                    nil
                            end
                    end
            end
    after http1_handler_guardian_remaining(HandlerDeadline) ->
        http1_handler_guardian_handler_timed_out(Guardian, HandlerReference)
    end.

http1_handler_guardian_handler_timed_out(Guardian, HandlerReference) ->
    Guardian ! {
        HandlerReference, handler_timed_out, self(), monotonic_millisecond()
    },
    nil.

http1_handler_guardian_active(State) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    CommandTag = maps:get(command_tag, State),
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    HandlerReference = maps:get(handler_reference, State),
    HandlerDeadline = maps:get(handler_deadline, State),
    receive
        {HandlerReference, handler_result, Handler, Result} ->
            http1_handler_guardian_active(State#{result => {some, Result}});
        {HandlerReference, handler_exit_ready, Handler, ExitAt}
          when is_integer(ExitAt) ->
            http1_handler_guardian_active(State#{exit_at => {some, ExitAt}});
        {HandlerReference, handler_failed, Handler, FailureAt}
          when is_integer(FailureAt) ->
            http1_handler_guardian_active(State#{
                failure_at => {some, FailureAt}
            });
        {HandlerReference, handler_timed_out, Handler, TimedOutAt}
          when is_integer(TimedOutAt) ->
            http1_handler_guardian_active(State#{timed_out => true});
        {CommandTag, {terminate_handler, Termination, RequestedAt}}
          when is_integer(RequestedAt),
               (Termination =:= handler_timed_out orelse
                Termination =:= handler_stopped) ->
            EffectiveTermination = case
                Termination =:= handler_stopped
                    andalso RequestedAt =< HandlerDeadline
            of
                true -> handler_stopped;
                false -> handler_timed_out
            end,
            %% RequestedAt is stamped by the connection before it sends the
            %% command. Both processes therefore spend the same finite cleanup
            %% budget even when the guardian mailbox is delayed.
            CleanupDeadline = RequestedAt
                + maps:get(cleanup_milliseconds, State),
            http1_handler_guardian_begin_termination(
                State, EffectiveTermination, true, CleanupDeadline
            );
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            %% No live connection can supply a request timestamp after owner
            %% death. The first observed DOWN is the cleanup-budget origin.
            OwnerDownAt = monotonic_millisecond(),
            http1_handler_guardian_begin_termination(
                State#{owner_alive => false}, handler_stopped, false,
                OwnerDownAt + maps:get(cleanup_milliseconds, State)
            );
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_down(State);
        {'EXIT', Handler, _} ->
            http1_handler_guardian_active(State)
    after http1_handler_guardian_remaining(HandlerDeadline) ->
        %% The request's absolute operation deadline is also the origin of the
        %% guardian's internal-timeout cleanup budget.
        http1_handler_guardian_begin_termination(
            State, handler_timed_out, true,
            HandlerDeadline + maps:get(cleanup_milliseconds, State)
        )
    end.

http1_handler_guardian_down(State) ->
    Deadline = maps:get(handler_deadline, State),
    Events = maps:get(events, State),
    case {
        maps:get(timed_out, State),
        maps:get(result, State),
        maps:get(exit_at, State),
        maps:get(failure_at, State)
    } of
        {true, Result, _ExitAt, _FailureAt} ->
            http1_handler_guardian_safe_cancel(State),
            http1_handler_guardian_discard_optional(State, Result),
            send_subject(Events, {handler_terminated, handler_timed_out}),
            http1_handler_guardian_finish(State);
        {false, {some, Result}, {some, ExitAt}, none}
          when ExitAt =< Deadline ->
            http1_handler_guardian_publish_result(Events, Result),
            http1_handler_guardian_finish(State);
        {false, {some, Result}, {some, _LateExitAt}, none} ->
            http1_handler_guardian_safe_cancel(State),
            http1_handler_guardian_safe_discard(State, Result),
            send_subject(Events, {handler_terminated, handler_timed_out}),
            http1_handler_guardian_finish(State);
        {false, Result, _ExitAt, {some, FailureAt}}
          when FailureAt >= Deadline ->
            http1_handler_guardian_safe_cancel(State),
            http1_handler_guardian_discard_optional(State, Result),
            send_subject(Events, {handler_terminated, handler_timed_out}),
            http1_handler_guardian_finish(State);
        {false, Result, _ExitAt, {some, _FailureAt}} ->
            http1_handler_guardian_safe_cancel(State),
            http1_handler_guardian_discard_optional(State, Result),
            send_subject(Events, handler_failed),
            http1_handler_guardian_finish(State);
        {false, Result, _ExitAt, none} ->
            http1_handler_guardian_safe_cancel(State),
            http1_handler_guardian_discard_optional(State, Result),
            send_subject(Events, handler_failed),
            http1_handler_guardian_finish(State)
    end.

http1_handler_guardian_begin_termination(
    State, Termination, Notify, CleanupDeadline
) ->
    http1_handler_guardian_safe_terminate(State),
    http1_handler_guardian_safe_cancel(State),
    http1_handler_guardian_terminating(
        State, Termination, Notify, CleanupDeadline
    ).

http1_handler_guardian_terminating(
    State, Termination, Notify, CleanupDeadline
) ->
    %% Check the absolute cleanup boundary before inspecting even one queued
    %% message. A permanently nonempty mailbox must not keep resetting or
    %% starving the handler cleanup transition.
    case monotonic_millisecond() >= CleanupDeadline of
        true ->
            http1_handler_guardian_termination_expired(
                State, Termination, Notify, CleanupDeadline
            );
        false ->
            http1_handler_guardian_terminating_receive(
                State, Termination, Notify, CleanupDeadline
            )
    end.

http1_handler_guardian_terminating_receive(
    State, Termination, Notify, CleanupDeadline
) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    CommandTag = maps:get(command_tag, State),
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    HandlerReference = maps:get(handler_reference, State),
    receive
        {HandlerReference, handler_result, Handler, Result} ->
            http1_handler_guardian_terminating(
                State#{result => {some, Result}}, Termination, Notify,
                CleanupDeadline
            );
        {HandlerReference, handler_exit_ready, Handler, ExitAt}
          when is_integer(ExitAt) ->
            http1_handler_guardian_terminating(
                State#{exit_at => {some, ExitAt}}, Termination, Notify,
                CleanupDeadline
            );
        {HandlerReference, handler_failed, Handler, FailureAt}
          when is_integer(FailureAt) ->
            http1_handler_guardian_terminating(
                State#{failure_at => {some, FailureAt}}, Termination, Notify,
                CleanupDeadline
            );
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            http1_handler_guardian_terminating(
                State#{owner_alive => false}, Termination, false,
                CleanupDeadline
            );
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_discard_optional(
                State, maps:get(result, State)
            ),
            case Notify of
                true -> send_subject(
                    maps:get(events, State),
                    {handler_terminated, Termination}
                );
                false -> ok
            end,
            http1_handler_guardian_finish(State);
        {CommandTag, {terminate_handler, _NextTermination, _RequestedAt}} ->
            http1_handler_guardian_terminating(
                State, Termination, Notify, CleanupDeadline
            );
        {'EXIT', Handler, _} ->
            http1_handler_guardian_terminating(
                State, Termination, Notify, CleanupDeadline
            )
    after http1_handler_guardian_remaining(CleanupDeadline) ->
        http1_handler_guardian_termination_expired(
            State, Termination, Notify, CleanupDeadline
        )
    end.

http1_handler_guardian_termination_expired(
    State, Termination, Notify, CleanupDeadline
) ->
    case Notify of
        true -> send_subject(
            maps:get(events, State),
            {handler_cleanup_unconfirmed, Termination}
        );
        false -> ok
    end,
    http1_handler_guardian_quarantine(
        State, Termination,
        CleanupDeadline + maps:get(cleanup_milliseconds, State)
    ).

http1_handler_guardian_quarantine(State, Termination, RetryDeadline) ->
    %% Retry from the prior absolute boundary before dispatching queued
    %% duplicates. This bounds progress even under continuous matching input.
    case monotonic_millisecond() >= RetryDeadline of
        true ->
            http1_handler_guardian_quarantine_retry(
                State, Termination, RetryDeadline
            );
        false ->
            http1_handler_guardian_quarantine_receive(
                State, Termination, RetryDeadline
            )
    end.

http1_handler_guardian_quarantine_receive(
    State, Termination, RetryDeadline
) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    CommandTag = maps:get(command_tag, State),
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    HandlerReference = maps:get(handler_reference, State),
    receive
        {HandlerReference, handler_result, Handler, Result} ->
            http1_handler_guardian_quarantine(
                State#{result => {some, Result}}, Termination, RetryDeadline
            );
        {HandlerReference, handler_exit_ready, Handler, ExitAt}
          when is_integer(ExitAt) ->
            http1_handler_guardian_quarantine(
                State#{exit_at => {some, ExitAt}}, Termination, RetryDeadline
            );
        {HandlerReference, handler_failed, Handler, FailureAt}
          when is_integer(FailureAt) ->
            http1_handler_guardian_quarantine(
                State#{failure_at => {some, FailureAt}}, Termination,
                RetryDeadline
            );
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            http1_handler_guardian_quarantine(
                State#{owner_alive => false}, Termination, RetryDeadline
            );
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_discard_optional(
                State, maps:get(result, State)
            ),
            http1_handler_guardian_finish(State);
        {CommandTag, {terminate_handler, _NextTermination, _RequestedAt}} ->
            http1_handler_guardian_safe_probe(
                maps:get(probe, State), 3, Handler
            ),
            http1_handler_guardian_quarantine(
                State, Termination, RetryDeadline
            );
        {'EXIT', Handler, _} ->
            http1_handler_guardian_quarantine(
                State, Termination, RetryDeadline
            )
    after http1_handler_guardian_remaining(RetryDeadline) ->
        http1_handler_guardian_quarantine_retry(
            State, Termination, RetryDeadline
        )
    end.

http1_handler_guardian_quarantine_retry(
    State, Termination, RetryDeadline
) ->
    http1_handler_guardian_safe_terminate(State),
    NextRetryDeadline = RetryDeadline
        + maps:get(cleanup_milliseconds, State),
    http1_handler_guardian_quarantine(
        State, Termination, NextRetryDeadline
    ).

http1_handler_guardian_finish(State) ->
    case maps:get(owner_alive, State) of
        true -> erlang:demonitor(maps:get(owner_monitor, State), [flush]);
        false -> ok
    end,
    ok.

http1_handler_guardian_publish_result(Events, Result) ->
    send_subject(Events, {handler_result, Result}).

http1_handler_guardian_safe_cancel(State) ->
    http1_handler_guardian_safe_call(maps:get(cancel, State), []).

http1_handler_guardian_safe_terminate(State) ->
    http1_handler_guardian_safe_call(
        maps:get(terminate, State), [maps:get(handler, State)]
    ).

http1_handler_guardian_discard_optional(State, {some, Result}) ->
    http1_handler_guardian_safe_discard(State, Result);
http1_handler_guardian_discard_optional(_State, none) ->
    ok.

http1_handler_guardian_safe_discard(State, Result) ->
    http1_handler_guardian_safe_call(maps:get(discard, State), [Result]).

http1_handler_guardian_safe_probe(Probe, Phase, Actor) ->
    http1_handler_guardian_safe_call(Probe, [Phase, Actor]).

http1_handler_guardian_safe_call(Function, Arguments) ->
    try erlang:apply(Function, Arguments) of
        _ -> ok
    catch
        _:_ -> ok
    end.

http1_handler_guardian_remaining(Deadline) ->
    erlang:max(0, erlang:min(
        2147483647,
        Deadline - monotonic_millisecond()
    )).

-spec spawn_monitor(fun(() -> term())) -> {pid(), reference()}.
spawn_monitor(Fun) when is_function(Fun, 0) ->
    erlang:spawn_monitor(fun() ->
        ok = proc_lib:set_label(<<"http.worker">>),
        Fun()
    end).

-spec spawn_link_monitor(fun(() -> term())) -> {pid(), reference()}.
spawn_link_monitor(Fun) when is_function(Fun, 0) ->
    erlang:spawn_opt(fun() ->
        ok = proc_lib:set_label(<<"http.worker">>),
        Fun()
    end, [link, monitor]).

-spec new_server_lifecycle() -> atomics:atomics_ref().
new_server_lifecycle() ->
    %% Index 1 is the existing running/draining/stopped state. Index 2 is the
    %% first terminal shutdown outcome. Index 3 is the coordinator's
    %% provisional cleanup outcome, finalized only after coordinator DOWN.
    %% Outcome zero is pending, one is success, and 2..34 are the finite
    %% redacted error classifications defined by the Gleam adapter.
    atomics:new(3, [{signed, false}]).

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

-spec record_server_shutdown_outcome(atomics:atomics_ref(), pos_integer()) ->
    pos_integer().
record_server_shutdown_outcome(Lifecycle, Outcome)
        when is_integer(Outcome),
             Outcome >= ?SERVER_SHUTDOWN_SUCCESS,
             Outcome =< ?SERVER_SHUTDOWN_MAXIMUM ->
    record_server_shutdown_cell(Lifecycle, 2, Outcome);
record_server_shutdown_outcome(_, _) -> ?SERVER_SHUTDOWN_SERVICE.

-spec record_server_shutdown_provisional(atomics:atomics_ref(), pos_integer()) ->
    pos_integer().
record_server_shutdown_provisional(Lifecycle, Outcome)
        when is_integer(Outcome),
             Outcome >= ?SERVER_SHUTDOWN_SUCCESS,
             Outcome =< ?SERVER_SHUTDOWN_MAXIMUM ->
    record_server_shutdown_cell(Lifecycle, 3, Outcome);
record_server_shutdown_provisional(_, _) -> ?SERVER_SHUTDOWN_SERVICE.

-spec record_server_shutdown_cell(atomics:atomics_ref(), 2 | 3, pos_integer()) ->
    pos_integer().
record_server_shutdown_cell(Lifecycle, Index, Outcome) ->
    try atomics:compare_exchange(Lifecycle, Index, 0, Outcome) of
        ok -> Outcome;
        Recorded when is_integer(Recorded),
                      Recorded >= ?SERVER_SHUTDOWN_SUCCESS,
                      Recorded =< ?SERVER_SHUTDOWN_MAXIMUM -> Recorded;
        _ -> ?SERVER_SHUTDOWN_SERVICE
    catch
        _:_ -> ?SERVER_SHUTDOWN_SERVICE
    end.

-spec server_shutdown_outcome(atomics:atomics_ref()) -> non_neg_integer().
server_shutdown_outcome(Lifecycle) ->
    server_shutdown_cell(Lifecycle, 2).

-spec server_shutdown_provisional(atomics:atomics_ref()) -> non_neg_integer().
server_shutdown_provisional(Lifecycle) ->
    server_shutdown_cell(Lifecycle, 3).

-spec server_shutdown_cell(atomics:atomics_ref(), 2 | 3) -> non_neg_integer().
server_shutdown_cell(Lifecycle, Index) ->
    try atomics:get(Lifecycle, Index) of
        0 -> 0;
        Recorded when is_integer(Recorded),
                      Recorded >= ?SERVER_SHUTDOWN_SUCCESS,
                      Recorded =< ?SERVER_SHUTDOWN_MAXIMUM -> Recorded;
        _ -> ?SERVER_SHUTDOWN_SERVICE
    catch
        _:_ -> ?SERVER_SHUTDOWN_SERVICE
    end.

-spec new_resource_controller(pos_integer(), pos_integer()) ->
    resource_controller().
new_resource_controller(MaximumWorkers, MaximumMemory)
    when is_integer(MaximumWorkers), MaximumWorkers > 0,
         is_integer(MaximumMemory), MaximumMemory > 0 ->
    new_resource_controller_with_factory(
        MaximumWorkers,
        MaximumMemory,
        fun() -> atomics:new(3, [{signed, true}]) end
    );
new_resource_controller(_MaximumWorkers, _MaximumMemory) ->
    {http_resource_unavailable, 1, 1}.

-spec new_resource_controller_with_factory(
    pos_integer(), pos_integer(), fun(() -> term())
) -> resource_controller().
new_resource_controller_with_factory(
    MaximumWorkers, MaximumMemory, Factory
) when is_integer(MaximumWorkers), MaximumWorkers > 0,
       is_integer(MaximumMemory), MaximumMemory > 0,
       is_function(Factory, 0) ->
    try
        Counters = Factory(),
        _ = atomics:get(Counters, ?RESOURCE_STOPPED),
        {http_resource, Counters, MaximumWorkers, MaximumMemory}
    catch
        _Class:_Reason ->
            {http_resource_unavailable, MaximumWorkers, MaximumMemory}
    end;
new_resource_controller_with_factory(
    _MaximumWorkers, _MaximumMemory, _Factory
) ->
    {http_resource_unavailable, 1, 1}.

-spec resource_controller_available(resource_controller()) -> boolean().
resource_controller_available(
    {http_resource, Counters, _MaximumWorkers, _MaximumMemory}
) ->
    safe_atomic_get(Counters, ?RESOURCE_STOPPED, 1) =:= 0;
resource_controller_available(_Controller) ->
    false.

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
                            _ = safe_atomic_add(
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

-spec resource_acquire_with_lease_factory(
    resource_controller(), non_neg_integer(), fun(() -> term())
) -> {ok, resource_lease()} | {error, 1 | 2 | 3}.
resource_acquire_with_lease_factory(
    {http_resource, Counters, MaximumWorkers, MaximumMemory},
    Memory,
    LeaseFactory
) when is_integer(Memory), Memory >= 0, is_function(LeaseFactory, 0) ->
    case safe_atomic_get(Counters, ?RESOURCE_STOPPED, 1) of
        0 ->
            case reserve_bounded(
                Counters, ?RESOURCE_WORKERS, 1, MaximumWorkers
            ) of
                false -> {error, 1};
                true ->
                    case reserve_bounded(
                        Counters, ?RESOURCE_MEMORY, Memory, MaximumMemory
                    ) of
                        false ->
                            _ = safe_atomic_add(
                                Counters, ?RESOURCE_WORKERS, -1
                            ),
                            {error, 2};
                        true ->
                            finish_resource_acquire_with_factory(
                                Counters, Memory, LeaseFactory
                            )
                    end
            end;
        _ -> {error, 3}
    end;
resource_acquire_with_lease_factory(_Controller, _Memory, _LeaseFactory) ->
    {error, 3}.

-spec finish_resource_acquire(atomics:atomics_ref(), non_neg_integer()) ->
    {ok, resource_lease()} | {error, 2 | 3}.
finish_resource_acquire(Counters, Memory) ->
    finish_resource_acquire_with_factory(
        Counters,
        Memory,
        fun() -> atomics:new(1, [{signed, true}]) end
    ).

-spec finish_resource_acquire_with_factory(
    atomics:atomics_ref(), non_neg_integer(), fun(() -> term())
) -> {ok, resource_lease()} | {error, 2 | 3}.
finish_resource_acquire_with_factory(Counters, Memory, LeaseFactory) ->
    case safe_atomic_get(Counters, ?RESOURCE_STOPPED, 1) of
        0 ->
            try
                Lease = LeaseFactory(),
                ok = atomics:put(Lease, 1, Memory + 1),
                {ok, Lease}
            catch
                _Class:_Reason ->
                    rollback_resource_reservation(Counters, Memory),
                    {error, 2}
            end;
        _ ->
            rollback_resource_reservation(Counters, Memory),
            {error, 3}
    end.

-spec rollback_resource_reservation(
    atomics:atomics_ref(), non_neg_integer()
) -> ok.
rollback_resource_reservation(Counters, Memory) ->
    _ = safe_atomic_add(Counters, ?RESOURCE_MEMORY, -Memory),
    _ = safe_atomic_add(Counters, ?RESOURCE_WORKERS, -1),
    ok.

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
    try atomics:exchange(Counters, ?RESOURCE_STOPPED, 1) of
        _ -> ok
    catch
        _Class:_Reason -> ok
    end,
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
    try atomics:get(Counters, Index) of
        Current ->
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
                        _ -> reserve_bounded(
                            Counters, Index, Amount, Maximum
                        )
                    end
            end
    catch
        _Class:_Reason -> false
    end.

-spec new_diagnostic_credit(pos_integer()) ->
    {ok, diagnostic_credit()} | {error, nil}.
new_diagnostic_credit(Maximum)
    when is_integer(Maximum), Maximum > 0 ->
    new_diagnostic_credit_with_factory(
        Maximum,
        fun() -> atomics:new(6, [{signed, true}]) end
    );
new_diagnostic_credit(_Maximum) ->
    {error, nil}.

%% Keep VM resource creation behind the same typed boundary as the public
%% diagnostics constructor. The factory seam is used only by deterministic
%% failure tests; neither an exception nor an invalid primitive can escape.
-spec new_diagnostic_credit_with_factory(pos_integer(), fun(() -> term())) ->
    {ok, diagnostic_credit()} | {error, nil}.
new_diagnostic_credit_with_factory(Maximum, Factory)
    when is_integer(Maximum), Maximum > 0, is_function(Factory, 0) ->
    try
        Counters = Factory(),
        %% Validate the complete fixed-width cell before publishing it.
        _ = atomics:get(Counters, 6),
        {ok, {http_diagnostic_credit, Counters, Maximum}}
    catch
        _Class:_Reason -> {error, nil}
    end;
new_diagnostic_credit_with_factory(_Maximum, _Factory) ->
    {error, nil}.

-spec new_diagnostic_request_id() -> pos_integer().
new_diagnostic_request_id() ->
    erlang:unique_integer([monotonic, positive]).

%% One finite, payload-free state machine per client attempt. It retains only
%% phase bits, a stable protocol/error code for a release that races ahead of
%% wire completion, and saturating anomaly counters. No callback value,
%% endpoint, process, socket, header, body, or exception is stored here.
-spec client_trace_new_state() -> client_trace_state().
client_trace_new_state() ->
    {http_client_trace_state,
     atomics:new(
         ?CLIENT_TRACE_PHASE_BASE + ?CLIENT_TRACE_PHASE_COUNT,
         [{signed, false}]
     )}.

%% Claim a typed phase transition without retaining the phase payload. Each
%% phase cell is 0 (not started), 1 (started), or 2 (finished). Duplicate and
%% out-of-order calls only increment the existing saturating counters.
-spec client_trace_phase_transition(
    client_trace_state(), pos_integer(), 1 | 2
) -> boolean().
client_trace_phase_transition(
    Trace, Phase, Transition
) ->
    client_trace_phase_transition(Trace, Phase, Transition, true).

-spec client_trace_phase_transition_if_missing(
    client_trace_state(), pos_integer(), 1 | 2
) -> boolean().
client_trace_phase_transition_if_missing(Trace, Phase, Transition) ->
    client_trace_phase_transition(Trace, Phase, Transition, false).

-spec client_trace_phase_transition(
    client_trace_state(), pos_integer(), 1 | 2, boolean()
) -> boolean().
client_trace_phase_transition(
    {http_client_trace_state, State}, Phase, Transition, CountDuplicate
) when is_integer(Phase), Phase >= 1, Phase =< ?CLIENT_TRACE_PHASE_COUNT,
       (Transition =:= 1 orelse Transition =:= 2) ->
    client_trace_phase_transition_loop(
        State,
        ?CLIENT_TRACE_PHASE_BASE + Phase,
        Transition,
        CountDuplicate
    );
client_trace_phase_transition(_, _, _, _) -> false.

-spec client_trace_phase_transition_loop(
    atomics:atomics_ref(), pos_integer(), 1 | 2, boolean()
) -> boolean().
client_trace_phase_transition_loop(State, Index, 1, CountDuplicate) ->
    try atomics:get(State, Index) of
        0 ->
            case atomics:compare_exchange(State, Index, 0, 1) of
                ok -> true;
                _ -> client_trace_phase_transition_loop(State, Index, 1, CountDuplicate)
            end;
        _ ->
            case CountDuplicate of
                true -> client_trace_increment(State, ?CLIENT_TRACE_DUPLICATES);
                false -> ok
            end,
            false
    catch
        _:_ -> false
    end;
client_trace_phase_transition_loop(State, Index, 2, CountDuplicate) ->
    try atomics:get(State, Index) of
        0 ->
            client_trace_increment(State, ?CLIENT_TRACE_OUT_OF_ORDER),
            false;
        1 ->
            case atomics:compare_exchange(State, Index, 1, 2) of
                ok -> true;
                _ -> client_trace_phase_transition_loop(State, Index, 2, CountDuplicate)
            end;
        _ ->
            case CountDuplicate of
                true -> client_trace_increment(State, ?CLIENT_TRACE_DUPLICATES);
                false -> ok
            end,
            false
    catch
        _:_ -> false
    end.

-spec client_trace_record_headers(client_trace_state()) -> boolean().
client_trace_record_headers({http_client_trace_state, State}) ->
    client_trace_record(
        State,
        ?CLIENT_TRACE_HEADERS_RECORDED,
        ?CLIENT_TRACE_FINISHED_RECORDED bor ?CLIENT_TRACE_RELEASE_RECORDED
    );
client_trace_record_headers(_) -> false.

-spec client_trace_publish_headers(client_trace_state()) -> nil.
client_trace_publish_headers(Trace) ->
    client_trace_publish(Trace, ?CLIENT_TRACE_HEADERS_PUBLISHED).

-spec client_trace_record_finished(client_trace_state(), boolean()) -> boolean().
client_trace_record_finished(Trace, Succeeded) ->
    client_trace_record_finished_loop(Trace, Succeeded, true).

%% An outer protocol dispatcher may need to supply a terminal only when a
%% lower adapter failed before it could identify the selected protocol. A
%% lower adapter's already-recorded terminal is expected here, not anomalous.
-spec client_trace_record_finished_if_missing(client_trace_state(), boolean()) ->
    boolean().
client_trace_record_finished_if_missing(Trace, Succeeded) ->
    client_trace_record_finished_loop(Trace, Succeeded, false).

-spec client_trace_record_finished_loop(
    client_trace_state(), boolean(), boolean()
) -> boolean().
client_trace_record_finished_loop(
    {http_client_trace_state, State}, Succeeded, CountDuplicate
)
        when is_boolean(Succeeded) ->
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits when (Bits band ?CLIENT_TRACE_FINISHED_RECORDED) =/= 0 ->
            case CountDuplicate of
                true -> client_trace_increment(State, ?CLIENT_TRACE_DUPLICATES);
                false -> ok
            end,
            false;
        Bits when Succeeded,
                  (Bits band ?CLIENT_TRACE_HEADERS_RECORDED) =:= 0 ->
            client_trace_increment(State, ?CLIENT_TRACE_OUT_OF_ORDER),
            false;
        Bits ->
            Added = case Succeeded of
                true -> ?CLIENT_TRACE_FINISHED_RECORDED bor
                        ?CLIENT_TRACE_FINISHED_OK;
                false -> ?CLIENT_TRACE_FINISHED_RECORDED
            end,
            case atomics:compare_exchange(
                State, ?CLIENT_TRACE_BITS, Bits, Bits bor Added
            ) of
                ok -> true;
                _ -> client_trace_record_finished_loop(
                    {http_client_trace_state, State},
                    Succeeded,
                    CountDuplicate
                )
            end
    catch
        _:_ -> false
    end;
client_trace_record_finished_loop(_, _, _) -> false.

-spec client_trace_publish_finished(client_trace_state()) -> nil.
client_trace_publish_finished(Trace) ->
    client_trace_publish(Trace, ?CLIENT_TRACE_FINISHED_PUBLISHED).

-spec client_trace_record_read(client_trace_state()) -> boolean().
client_trace_record_read({http_client_trace_state, State}) ->
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits when (Bits band ?CLIENT_TRACE_READ_RECORDED) =/= 0 ->
            client_trace_increment(State, ?CLIENT_TRACE_DUPLICATES),
            false;
        Bits when (Bits band ?CLIENT_TRACE_FINISHED_RECORDED) =/= 0,
                  (Bits band ?CLIENT_TRACE_FINISHED_OK) =:= 0 ->
            client_trace_increment(State, ?CLIENT_TRACE_LATE),
            false;
        Bits when (Bits band ?CLIENT_TRACE_HEADERS_RECORDED) =:= 0;
                  (Bits band ?CLIENT_TRACE_FINISHED_RECORDED) =:= 0 ->
            client_trace_increment(State, ?CLIENT_TRACE_OUT_OF_ORDER),
            false;
        Bits ->
            case atomics:compare_exchange(
                State,
                ?CLIENT_TRACE_BITS,
                Bits,
                Bits bor ?CLIENT_TRACE_READ_RECORDED
            ) of
                ok -> true;
                _ -> client_trace_record_read({http_client_trace_state, State})
            end
    catch
        _:_ -> false
    end;
client_trace_record_read(_) -> false.

-spec client_trace_publish_read(client_trace_state()) -> nil.
client_trace_publish_read(Trace) ->
    client_trace_publish(Trace, ?CLIENT_TRACE_READ_PUBLISHED).

-spec client_trace_record_release(client_trace_state(), non_neg_integer(),
                                  pos_integer()) -> boolean().
client_trace_record_release(
    Trace, Protocol, Outcome
) ->
    client_trace_record_release_loop(Trace, Protocol, Outcome, true).

%% The unified dispatcher may need to close a request that failed before a
%% protocol adapter established ownership. A protocol adapter's earlier or
%% concurrent release remains authoritative and is not a duplicate anomaly.
-spec client_trace_record_release_if_missing(
    client_trace_state(), non_neg_integer(), pos_integer()
) -> boolean().
client_trace_record_release_if_missing(Trace, Protocol, Outcome) ->
    client_trace_record_release_loop(Trace, Protocol, Outcome, false).

-spec client_trace_record_release_loop(
    client_trace_state(), non_neg_integer(), pos_integer(), boolean()
) -> boolean().
client_trace_record_release_loop(
    {http_client_trace_state, State}, Protocol, Outcome, CountDuplicate
) when is_integer(Protocol), Protocol >= 0, Protocol =< 3,
       is_integer(Outcome), Outcome >= 1, Outcome =< 34,
       is_boolean(CountDuplicate) ->
    case client_trace_claim_release(State, CountDuplicate) of
        false -> false;
        true ->
            atomics:put(State, ?CLIENT_TRACE_RELEASE_PROTOCOL, Protocol),
            atomics:put(State, ?CLIENT_TRACE_RELEASE_OUTCOME, Outcome),
            _ = client_trace_set_bits(State, ?CLIENT_TRACE_RELEASE_READY),
            case (atomics:get(State, ?CLIENT_TRACE_BITS) band
                  ?CLIENT_TRACE_FINISHED_RECORDED) of
                0 -> client_trace_increment(
                    State, ?CLIENT_TRACE_OUT_OF_ORDER
                );
                _ -> ok
            end,
            true
    end;
client_trace_record_release_loop(_, _, _, _) -> false.

-spec client_trace_take_release(client_trace_state()) ->
    {boolean(), non_neg_integer(), non_neg_integer()}.
client_trace_take_release({http_client_trace_state, State}) ->
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits when (Bits band ?CLIENT_TRACE_RELEASE_READY) =:= 0;
                  (Bits band ?CLIENT_TRACE_FINISHED_PUBLISHED) =:= 0;
                  (Bits band ?CLIENT_TRACE_RELEASE_TAKEN) =/= 0 ->
            {false, 0, 0};
        Bits ->
            case atomics:compare_exchange(
                State,
                ?CLIENT_TRACE_BITS,
                Bits,
                Bits bor ?CLIENT_TRACE_RELEASE_TAKEN
            ) of
                ok ->
                    {
                        true,
                        atomics:get(State, ?CLIENT_TRACE_RELEASE_PROTOCOL),
                        atomics:get(State, ?CLIENT_TRACE_RELEASE_OUTCOME)
                    };
                _ -> client_trace_take_release(
                    {http_client_trace_state, State}
                )
            end
    catch
        _:_ -> {false, 0, 0}
    end;
client_trace_take_release(_) -> {false, 0, 0}.

-spec client_trace_publish_release(client_trace_state()) -> nil.
client_trace_publish_release(Trace) ->
    client_trace_publish(Trace, ?CLIENT_TRACE_RELEASE_PUBLISHED).

-spec client_trace_request_success(client_trace_state()) -> nil.
client_trace_request_success(Trace) ->
    client_trace_publish(Trace, ?CLIENT_TRACE_SUCCESS_REQUESTED).

-spec client_trace_success_ready(client_trace_state()) -> boolean().
client_trace_success_ready({http_client_trace_state, State}) ->
    Required = ?CLIENT_TRACE_HEADERS_PUBLISHED bor
               ?CLIENT_TRACE_FINISHED_RECORDED bor
               ?CLIENT_TRACE_FINISHED_OK bor
               ?CLIENT_TRACE_FINISHED_PUBLISHED bor
               ?CLIENT_TRACE_READ_PUBLISHED bor
               ?CLIENT_TRACE_RELEASE_PUBLISHED bor
               ?CLIENT_TRACE_SUCCESS_REQUESTED,
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits ->
            (Bits band Required) =:= Required
                andalso atomics:get(State, ?CLIENT_TRACE_RELEASE_OUTCOME) =:= 1
    catch
        _:_ -> false
    end;
client_trace_success_ready(_) -> false.

-spec client_trace_snapshot(client_trace_state()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
client_trace_snapshot({http_client_trace_state, State}) ->
    try
        {
            atomics:get(State, ?CLIENT_TRACE_BITS),
            atomics:get(State, ?CLIENT_TRACE_DUPLICATES),
            atomics:get(State, ?CLIENT_TRACE_OUT_OF_ORDER),
            atomics:get(State, ?CLIENT_TRACE_LATE)
        }
    catch
        _:_ -> {0, 0, 0, 0}
    end;
client_trace_snapshot(_) -> {0, 0, 0, 0}.

-spec client_trace_record(atomics:atomics_ref(), pos_integer(),
                          non_neg_integer()) -> boolean().
client_trace_record(State, Bit, Rejected) ->
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits when (Bits band Bit) =/= 0 ->
            client_trace_increment(State, ?CLIENT_TRACE_DUPLICATES),
            false;
        Bits when (Bits band Rejected) =/= 0 ->
            client_trace_increment(State, ?CLIENT_TRACE_LATE),
            false;
        Bits ->
            case atomics:compare_exchange(
                State, ?CLIENT_TRACE_BITS, Bits, Bits bor Bit
            ) of
                ok -> true;
                _ -> client_trace_record(State, Bit, Rejected)
            end
    catch
        _:_ -> false
    end.

-spec client_trace_claim_release(atomics:atomics_ref(), boolean()) -> boolean().
client_trace_claim_release(State, CountDuplicate) ->
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits when (Bits band ?CLIENT_TRACE_RELEASE_RECORDED) =/= 0 ->
            case CountDuplicate of
                true -> client_trace_increment(State, ?CLIENT_TRACE_DUPLICATES);
                false -> ok
            end,
            false;
        Bits ->
            case atomics:compare_exchange(
                State,
                ?CLIENT_TRACE_BITS,
                Bits,
                Bits bor ?CLIENT_TRACE_RELEASE_RECORDED
            ) of
                ok -> true;
                _ -> client_trace_claim_release(State, CountDuplicate)
            end
    catch
        _:_ -> false
    end.

-spec client_trace_publish(client_trace_state(), pos_integer()) -> nil.
client_trace_publish({http_client_trace_state, State}, Bit) ->
    _ = client_trace_set_bits(State, Bit),
    nil;
client_trace_publish(_, _) -> nil.

-spec client_trace_set_bits(atomics:atomics_ref(), pos_integer()) -> boolean().
client_trace_set_bits(State, Added) ->
    try atomics:get(State, ?CLIENT_TRACE_BITS) of
        Bits when (Bits band Added) =:= Added -> true;
        Bits ->
            case atomics:compare_exchange(
                State, ?CLIENT_TRACE_BITS, Bits, Bits bor Added
            ) of
                ok -> true;
                _ -> client_trace_set_bits(State, Added)
            end
    catch
        _:_ -> false
    end.

-spec client_trace_increment(atomics:atomics_ref(), pos_integer()) -> ok.
client_trace_increment(State, Index) ->
    try saturating_atomic_increment(State, Index), ok
    catch
        _:_ -> ok
    end.

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
            case claim_diagnostic_sequence(Counters) of
                exhausted -> rollback_diagnostic_reserve(Counters);
                Sequence -> Sequence
            end;
        _ ->
            rollback_diagnostic_reserve(Counters)
    end.

%% Pure transition used by the CAS loop and deterministic boundary tests.
%% Exhaustion is a typed drop; an admitted reporter-local sequence is never
%% saturated and reused.
-spec diagnostic_sequence_transition(integer()) ->
    exhausted | {accepted, pos_integer()}.
diagnostic_sequence_transition(Current)
        when is_integer(Current), Current >= 0,
             Current < ?MAXIMUM_COUNTER ->
    {accepted, Current + 1};
diagnostic_sequence_transition(_) -> exhausted.

-spec claim_diagnostic_sequence(atomics:atomics_ref()) ->
    exhausted | pos_integer().
claim_diagnostic_sequence(Counters) ->
    Current = atomics:get(Counters, ?DIAGNOSTIC_SEQUENCE),
    case diagnostic_sequence_transition(Current) of
        exhausted -> exhausted;
        {accepted, Next} ->
            case atomics:compare_exchange(
                Counters, ?DIAGNOSTIC_SEQUENCE, Current, Next
            ) of
                ok -> Next;
                _ -> claim_diagnostic_sequence(Counters)
            end
    end.

-spec rollback_diagnostic_reserve(atomics:atomics_ref()) -> 0.
rollback_diagnostic_reserve(Counters) ->
    _ = atomics:add(Counters, ?DIAGNOSTIC_IN_FLIGHT, -1),
    _ = saturating_atomic_increment(Counters, ?DIAGNOSTIC_DROPPED),
    0.

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

-spec diagnostic_abandon(diagnostic_credit()) -> nil.
diagnostic_abandon({http_diagnostic_credit, Counters, _Maximum}) ->
    _ = rollback_diagnostic_reserve(Counters),
    nil;
diagnostic_abandon(_) -> nil.

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

-spec safe_atomic_add(term(), pos_integer(), integer()) -> integer().
safe_atomic_add(Atomics, Index, Amount) ->
    try atomics:add(Atomics, Index, Amount)
    catch
        _Class:_Reason -> 0
    end.

-spec nonnegative(integer()) -> non_neg_integer().
nonnegative(Value) when Value >= 0 -> Value;
nonnegative(_Value) -> 0.
