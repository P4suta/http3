%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_transport_guardian_test).
-include_lib("eunit/include/eunit.hrl").

-define(COORDINATOR_KIND, 0).
-define(RESOLVER_KIND, 1).
-define(CANDIDATE_KIND, 2).
-define(REAPER_KIND, 3).
-define(OBSERVATION_MILLISECONDS, 5000).

pre_start_coordinator_death_reaps_both_guardians_without_callback_test() ->
    Registry = registry(),
    Observer = self(),
    ProbeReference = make_ref(),
    CallbackReference = make_ref(),
    ReturnReference = make_ref(),
    BaseRuntime = runtime(
        Registry,
        fun(_Host, _Family) ->
            Observer ! {CallbackReference, callback_started},
            {error, private_resolver_reason}
        end,
        fun(_Address, _Port, _Options, _Timeout) ->
            {error, private_dial_reason}
        end
    ),
    Runtime = BaseRuntime#{lifecycle_probe => {
        http_transport_lifecycle_probe,
        Observer,
        ProbeReference
    }},
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Outcome = dial(Runtime, 1000),
        Observer ! {ReturnReference, Outcome, mailbox_state()}
    end),
    Deadline = deadline(),
    Observation = receive
        {
            http_transport_connect_pre_start,
            ProbeReference,
            ConnectReference,
            ReplyAlias,
            Reaper,
            Coordinator
        } ->
            ReaperMonitor = erlang:monitor(process, Reaper),
            CoordinatorMonitor = erlang:monitor(process, Coordinator),
            GuardianHeap = {
                bounded_heap_contract(Reaper, 1048576),
                bounded_heap_contract(Coordinator, 1048576)
            },
            exit(Coordinator, kill),
            ReplyAlias ! {
                ConnectReference,
                http_transport_continue_pre_start,
                ProbeReference
            },
            Returned = await_return(ReturnReference, Deadline),
            {
                Returned,
                named_down(CoordinatorMonitor, Coordinator, Deadline),
                named_down(ReaperMonitor, Reaper, Deadline),
                named_down(CallerMonitor, Caller, Deadline),
                callback_state(CallbackReference),
                GuardianHeap
            }
    after remaining(Deadline) ->
        exit(Caller, kill),
        pre_start_probe_not_observed
    end,
    ?assertEqual(
        {
            {{error, 5}, queue_empty},
            down,
            down,
            down,
            callback_not_started,
            {bounded_heap, bounded_heap}
        },
        Observation
    ),
    require_registered_down(Registry, Deadline),
    destroy_registry(Registry).

coordinator_death_reaps_trapping_callbacks_before_return_test() ->
    Registry = registry(),
    Observer = self(),
    StartedReference = make_ref(),
    ReturnReference = make_ref(),
    Runtime = runtime(
        Registry,
        fun(_Host, _Family) ->
            process_flag(trap_exit, true),
            Observer ! {StartedReference, self()},
            receive callback_remains_blocked -> {ok, []} end
        end,
        fun(_Address, _Port, _Options, _Timeout) ->
            {error, private_dial_reason}
        end
    ),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Outcome = dial(Runtime, 4000),
        Observer ! {ReturnReference, Outcome, mailbox_state()}
    end),
    Deadline = deadline(),
    _Resolver = await_callback_started(StartedReference, Deadline),
    Coordinator = await_kind(Registry, ?COORDINATOR_KIND, Deadline),
    Reaper = await_kind(Registry, ?REAPER_KIND, Deadline),
    ResolverPids = registered(Registry, ?RESOLVER_KIND),
    CoordinatorMonitor = erlang:monitor(process, Coordinator),
    ReaperMonitor = erlang:monitor(process, Reaper),
    ResolverMonitors = monitor_processes(ResolverPids),
    exit(Coordinator, kill),
    Returned = await_return(ReturnReference, Deadline),
    ?assertEqual({{error, 5}, queue_empty}, Returned),
    ?assertEqual(down, named_down(CoordinatorMonitor, Coordinator, Deadline)),
    ?assertEqual(down, named_down(ReaperMonitor, Reaper, Deadline)),
    ?assertEqual(#{}, await_monitors(ResolverMonitors, Deadline)),
    ?assertEqual(down, named_down(CallerMonitor, Caller, Deadline)),
    ?assert(lists:all(fun(Pid) -> not erlang:is_process_alive(Pid) end,
        registered(Registry))),
    destroy_registry(Registry).

absolute_timeout_reaps_trapping_callbacks_and_leaves_no_caller_messages_test() ->
    Registry = registry(),
    Observer = self(),
    StartedReference = make_ref(),
    ReturnReference = make_ref(),
    Runtime = runtime(
        Registry,
        fun(_Host, _Family) ->
            process_flag(trap_exit, true),
            Observer ! {StartedReference, self()},
            receive callback_remains_blocked -> {ok, []} end
        end,
        fun(_Address, _Port, _Options, _Timeout) ->
            {error, private_dial_reason}
        end
    ),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Outcome = dial(Runtime, 250),
        Observer ! {ReturnReference, Outcome, mailbox_state()}
    end),
    Deadline = deadline(),
    _Resolver = await_callback_started(StartedReference, Deadline),
    Returned = await_return(ReturnReference, Deadline),
    ?assertEqual({{error, 17}, queue_empty}, Returned),
    ?assertEqual(down, named_down(CallerMonitor, Caller, Deadline)),
    require_registered_down(Registry, Deadline),
    destroy_registry(Registry).

caller_death_reaps_trapping_callbacks_test() ->
    Registry = registry(),
    Observer = self(),
    StartedReference = make_ref(),
    Runtime = runtime(
        Registry,
        fun(_Host, _Family) ->
            process_flag(trap_exit, true),
            Observer ! {StartedReference, self()},
            receive callback_remains_blocked -> {ok, []} end
        end,
        fun(_Address, _Port, _Options, _Timeout) ->
            {error, private_dial_reason}
        end
    ),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        _ = dial(Runtime, 4000)
    end),
    Deadline = deadline(),
    _Resolver = await_callback_started(StartedReference, Deadline),
    exit(Caller, kill),
    ?assertEqual(down, named_down(CallerMonitor, Caller, Deadline)),
    require_registered_down(Registry, Deadline),
    destroy_registry(Registry).

post_transfer_coordinator_death_closes_provisional_socket_test() ->
    Registry = registry(),
    Observer = self(),
    ProbeReference = make_ref(),
    ReturnReference = make_ref(),
    {ok, Listener} = gen_tcp:listen(
        0, [binary, inet, {active, false}, {ip, {127, 0, 0, 1}}]
    ),
    try
        {ok, {_, Port}} = inet:sockname(Listener),
        BaseRuntime = runtime(
            Registry,
            fun(_Host, inet6) -> {ok, []};
               (_Host, inet) -> {ok, [{127, 0, 0, 1}]} end,
            fun(Address, TargetPort, Options, Timeout) ->
                gen_tcp:connect(Address, TargetPort, Options, Timeout)
            end
        ),
        Runtime = BaseRuntime#{handoff_probe => {
            http_transport_handoff_probe,
            Observer,
            ProbeReference
        }},
        {Caller, CallerMonitor} = spawn_monitor(fun() ->
            Outcome = http_transport_ffi:connect_with_runtime(
                <<"handoff.invalid">>,
                Port,
                1000,
                2500,
                3000,
                1000,
                Runtime,
                none
            ),
            Observer ! {ReturnReference, Outcome, mailbox_state()},
            receive release_handoff_caller -> ok end
        end),
        try
            Deadline = deadline(),
            Coordinator = receive
                {
                    http_transport_connect_post_transfer,
                    ProbeReference,
                    CoordinatorPid
                } when is_pid(CoordinatorPid) -> CoordinatorPid
            after remaining(Deadline) ->
                error(post_transfer_probe_not_observed)
            end,
            {ok, Peer} = gen_tcp:accept(Listener, remaining(Deadline)),
            try
                CoordinatorMonitor = erlang:monitor(process, Coordinator),
                try
                    exit(Coordinator, kill),
                    {{error, Code}, QueueState} = await_return(
                        ReturnReference, Deadline
                    ),
                    ?assert(Code >= 1 andalso Code =< 18),
                    ?assertEqual(5, Code),
                    ?assertEqual(queue_empty, QueueState),
                    ?assert(is_process_alive(Caller)),
                    ?assertEqual(
                        closed,
                        await_peer_closed(Peer, Deadline)
                    ),
                    ?assertEqual(
                        down,
                        named_down(
                            CoordinatorMonitor, Coordinator, Deadline
                        )
                    ),
                    require_registered_down(Registry, Deadline)
                after
                    erlang:demonitor(CoordinatorMonitor, [flush])
                end
            after
                gen_tcp:close(Peer)
            end,
            Caller ! release_handoff_caller,
            ?assertEqual(
                down,
                named_down(CallerMonitor, Caller, Deadline)
            )
        after
            Caller ! release_handoff_caller,
            cleanup_monitored_process(Caller, CallerMonitor)
        end
    after
        gen_tcp:close(Listener),
        cleanup_registered(Registry),
        flush_handoff_test_messages(ProbeReference, ReturnReference),
        destroy_registry(Registry)
    end.

resolver_rows_are_cut_off_before_unbounded_duplicate_scan_test() ->
    Registry = registry(),
    Runtime = runtime(
        Registry,
        fun(_Host, _Family) ->
            {ok, lists:duplicate(256, invalid_address) ++
                [{127, 0, 0, 1}]}
        end,
        fun(_Address, _Port, _Options, _Timeout) ->
            {error, should_not_dial}
        end
    ),
    Outcome = dial(Runtime, 1000),
    ?assertEqual({error, 4}, Outcome),
    ?assertEqual([], registered(Registry, ?CANDIDATE_KIND)),
    require_registered_down(Registry, deadline()),
    destroy_registry(Registry).

callback_heap_counts_shared_binaries_and_kills_on_limit_test() ->
    Registry = registry(),
    Observer = self(),
    HeapReference = make_ref(),
    Runtime = runtime(
        Registry,
        fun(_Host, _Family) ->
            Observer ! {
                HeapReference,
                bounded_heap_contract(self(), 2097152)
            },
            {error, private_resolver_reason}
        end,
        fun(_Address, _Port, _Options, _Timeout) ->
            {error, should_not_dial}
        end
    ),
    ?assertEqual({error, 4}, dial(Runtime, 1000)),
    HeapContract = receive
        {HeapReference, Contract} -> Contract
    after ?OBSERVATION_MILLISECONDS ->
        heap_contract_not_observed
    end,
    ?assertEqual(bounded_heap, HeapContract),
    require_registered_down(Registry, deadline()),
    destroy_registry(Registry).

runtime(Registry, Resolve, Connect) ->
    #{
        resolve => Resolve,
        connect => Connect,
        lifecycle_observer => observer_capability(Registry)
    }.

dial(Runtime, TotalMilliseconds) ->
    http_transport_ffi:connect_with_runtime(
        <<"guardian.invalid">>,
        9,
        1000,
        1000,
        TotalMilliseconds,
        1000,
        Runtime,
        none
    ).

registry() ->
    #{
        table => ets:new(?MODULE, [set, public]),
        owner => self(),
        reference => make_ref()
    }.

destroy_registry(#{table := Table, reference := Reference}) ->
    flush_registry_messages(Reference),
    ets:delete(Table),
    ok.

observer_capability(#{table := Table, owner := Owner, reference := Reference}) ->
    {http_transport_lifecycle_observer, Table, Owner, Reference}.

registered(#{table := Table}) ->
    [Pid || {{http_transport_worker, Pid}, _Kind} <- ets:tab2list(Table)].

registered(#{table := Table}, Kind) ->
    [Pid || {{http_transport_worker, Pid}, FoundKind} <- ets:tab2list(Table),
        FoundKind =:= Kind].

await_kind(Registry, Kind, Deadline) ->
    case registered(Registry, Kind) of
        [Pid | _] -> Pid;
        [] ->
            Reference = maps:get(reference, Registry),
            receive
                {http_transport_worker_observed, Reference} ->
                    await_kind(Registry, Kind, Deadline)
            after remaining(Deadline) ->
                erlang:error({process_kind_not_observed, Kind})
            end
    end.

await_callback_started(Reference, Deadline) ->
    receive
        {Reference, Pid} when is_pid(Pid) -> Pid
    after remaining(Deadline) ->
        erlang:error(callback_not_started)
    end.

await_return(Reference, Deadline) ->
    receive
        {Reference, Outcome, QueueState} -> {Outcome, QueueState}
    after remaining(Deadline) ->
        caller_did_not_return
    end.

callback_state(Reference) ->
    receive
        {Reference, callback_started} -> callback_started
    after 0 ->
        callback_not_started
    end.

mailbox_state() ->
    case process_info(self(), message_queue_len) of
        {message_queue_len, 0} -> queue_empty;
        {message_queue_len, _} -> queue_not_empty
    end.

bounded_heap_contract(Process, ExpectedWords) ->
    case process_info(Process, max_heap_size) of
        {max_heap_size, Options} when is_map(Options) ->
            case maps:get(size, Options, 0) =:= ExpectedWords
                andalso maps:get(kill, Options, false) =:= true
                andalso maps:get(error_logger, Options, true) =:= false
                andalso maps:get(
                    include_shared_binaries, Options, false) =:= true
            of
                true -> bounded_heap;
                false -> unbounded_heap
            end;
        _ ->
            unbounded_heap
    end.

monitor_processes(Pids) ->
    maps:from_list([
        {erlang:monitor(process, Pid), Pid} || Pid <- lists:usort(Pids)
    ]).

require_registered_down(Registry, Deadline) ->
    Pending = await_monitors(monitor_processes(registered(Registry)), Deadline),
    ?assertEqual(#{}, Pending),
    ?assert(lists:all(fun(Pid) -> not erlang:is_process_alive(Pid) end,
        registered(Registry))),
    ok.

cleanup_registered(Registry) ->
    Monitors = monitor_processes(registered(Registry)),
    maps:foreach(fun(_Monitor, Pid) -> exit(Pid, kill) end, Monitors),
    _ = await_monitors(Monitors, deadline()),
    ok.

cleanup_monitored_process(Pid, Monitor) ->
    case erlang:is_process_alive(Pid) of
        false ->
            erlang:demonitor(Monitor, [flush]),
            ok;
        true ->
            exit(Pid, kill),
            receive
                {'DOWN', Monitor, process, Pid, _Reason} -> ok
            after remaining(deadline()) ->
                erlang:demonitor(Monitor, [flush]),
                ok
            end
    end.

flush_handoff_test_messages(ProbeReference, ReturnReference) ->
    receive
        {
            http_transport_connect_post_transfer,
            ProbeReference,
            _Coordinator
        } ->
            flush_handoff_test_messages(ProbeReference, ReturnReference);
        {ReturnReference, _Outcome, _QueueState} ->
            flush_handoff_test_messages(ProbeReference, ReturnReference)
    after 0 ->
        ok
    end.

await_monitors(Monitors, _Deadline) when map_size(Monitors) =:= 0 ->
    #{};
await_monitors(Monitors, Deadline) ->
    receive
        {'DOWN', Monitor, process, _Pid, _Reason}
            when is_map_key(Monitor, Monitors) ->
            await_monitors(maps:remove(Monitor, Monitors), Deadline)
    after remaining(Deadline) ->
        maps:foreach(fun(Monitor, _Pid) ->
            erlang:demonitor(Monitor, [flush])
        end, Monitors),
        Monitors
    end.

named_down(Monitor, Pid, Deadline) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> down
    after remaining(Deadline) ->
        erlang:demonitor(Monitor, [flush]),
        still_alive
    end.

await_peer_closed(Peer, Deadline) ->
    case inet:setopts(Peer, [{active, once}]) of
        ok ->
            receive
                {tcp_closed, Peer} -> closed;
                {tcp_error, Peer, Reason}
                    when Reason =:= closed; Reason =:= econnreset;
                         Reason =:= enotconn -> closed;
                {tcp, Peer, _UnexpectedData} -> unexpected_data
            after remaining(Deadline) ->
                still_open
            end;
        {error, Reason}
            when Reason =:= closed; Reason =:= einval;
                 Reason =:= econnreset; Reason =:= enotconn -> closed;
        {error, _Reason} -> socket_observation_failed
    end.

flush_registry_messages(Reference) ->
    receive
        {http_transport_worker_observed, Reference} ->
            flush_registry_messages(Reference)
    after 0 ->
        ok
    end.

deadline() ->
    erlang:monotonic_time(millisecond) + ?OBSERVATION_MILLISECONDS.

remaining(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).
