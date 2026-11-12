-module(http3_benchmark_ffi).

-export([
    arguments/0,
    await_priming_metrics/0,
    await_cleanup_metrics/4,
    await_task/1,
    diagnostic_metrics/0,
    fail/1,
    monotonic_microseconds/0,
    network_port_count/0,
    qlog_directory/0,
    runtime_metrics/0,
    socket_count/0,
    start_task/2,
    priming_cleanup_self_test/0,
    priming_capture_self_test/0,
    cleanup_capture_self_test/0,
    write_line/1
]).

-define(MAXIMUM_BENCHMARK_TIMEOUT_MICROSECONDS, 900000000).
-define(CLEANUP_TIMEOUT, 10000).

-spec arguments() -> [binary()].
arguments() ->
    [unicode:characters_to_binary(Argument) || Argument <- init:get_plain_arguments()].

-spec qlog_directory() -> binary().
qlog_directory() ->
    case os:getenv("HTTP3_BENCHMARK_QLOG_DIR") of
        false -> <<>>;
        [] -> <<>>;
        Directory -> unicode:characters_to_binary(Directory)
    end.

-spec start_task(fun(() -> term()), integer()) -> tuple().
start_task(Fun, RequestedDeadline) when is_function(Fun, 0), is_integer(RequestedDeadline) ->
    Owner = self(),
    Ref = make_ref(),
    Now = erlang:monotonic_time(microsecond),
    Deadline = min(RequestedDeadline, Now + ?MAXIMUM_BENCHMARK_TIMEOUT_MICROSECONDS),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Result = Fun(),
        Owner ! {Ref, benchmark_result, Result}
    end),
    {http3_benchmark_task, Pid, Monitor, Ref, Deadline}.

-spec await_task(tuple()) -> term().
await_task({http3_benchmark_task, Pid, Monitor, Ref, Deadline}) ->
    RemainingMicroseconds = max(0, Deadline - erlang:monotonic_time(microsecond)),
    RemainingMilliseconds = (RemainingMicroseconds + 999) div 1000,
    receive
        {Ref, benchmark_result, Result} ->
            await_process_down(Pid, Monitor),
            Result;
        {'DOWN', Monitor, process, Pid, Reason} ->
            receive
                {Ref, benchmark_result, Result} -> Result
            after 0 ->
                erlang:error({benchmark_worker_stopped, Reason})
            end
    after RemainingMilliseconds ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(benchmark_worker_timeout)
    end.

-spec monotonic_microseconds() -> integer().
monotonic_microseconds() ->
    erlang:monotonic_time(microsecond).

-spec runtime_metrics() ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer()}.
runtime_metrics() ->
    _ = erlang:garbage_collect(),
    {
        erlang:system_info(process_count),
        erlang:memory(total),
        mailbox_messages(),
        erlang:system_info(port_count),
        network_port_count(),
        socket_count()
    }.

%% Local QUIC close first enters its finite wire-closing period. A successful
%% close command is therefore not a quiescent benchmark baseline. Wait for
%% actual socket and project-actor disposal before measuring that baseline.
await_priming_metrics() ->
    priming_capture_metrics(erlang:monotonic_time(millisecond)+?CLEANUP_TIMEOUT,
        fun priming_actors/0,fun priming_counts/0,fun runtime_metrics/0,
        fun()->erlang:monotonic_time(millisecond) end,
        fun()->timer:sleep(20) end).

priming_snapshot() ->
    {nil,priming_counts()}.
priming_counts() ->
    [network_port_count(),socket_count(),length(priming_actors())].
priming_actors() ->
    [Pid || Pid<-erlang:processes(), project_actor(Pid)].
project_actor(Pid) ->
    try proc_lib:get_label(Pid) of
        <<"http3.",_/binary>>->true;
        <<"quic_core.",_/binary>>->true;
        _->false
    catch _:_ -> false end.
priming_cleanup(Deadline,Observe,Clock,Wait) ->
    {Metrics,Counts}=Observe(),
    case Counts of
        [0,0,0]->Metrics;
        _->case Clock()>=Deadline of
            true->erlang:error({benchmark_priming_cleanup_limit,Counts});
            false->Wait(),priming_cleanup(Deadline,Observe,Clock,Wait)
        end
    end.

%% Wire closing can legitimately retain an actor for seconds. Its DOWN signal
%% is the cheap wait boundary; full GC and VM inventories are measurements,
%% not polling operations. At most one actor monitor is retained at a time.
priming_capture_metrics(Deadline,Actors,Observe,Capture,Clock,Wait) ->
    priming_await_actors(Deadline,Actors,Observe,Clock),
    nil=priming_cleanup(Deadline,fun()->{nil,Observe()} end,Clock,Wait),
    Metrics={_,_,_,_,Ports,Sockets}=Capture(),
    case [Ports,Sockets,length(Actors())] of
        [0,0,0]->Metrics;
        Counts->error({benchmark_priming_cleanup_limit,Counts})
    end.

priming_await_actors(Deadline,Actors,Observe,Clock) ->
    case Actors() of
        []->ok;
        [Pid|_]->
            Monitor=erlang:monitor(process,Pid),
            Outcome=try
                receive {'DOWN',Monitor,process,Pid,_}->down
                after max(0,Deadline-Clock())->timeout end
            after erlang:demonitor(Monitor,[flush]) end,
            case Outcome of
                down->priming_await_actors(Deadline,Actors,Observe,Clock);
                timeout->error({benchmark_priming_cleanup_limit,Observe()})
            end
    end.

priming_capture_self_test() ->
    priming_capture_control(fun priming_capture_metrics/6).

cleanup_capture_self_test() ->
    nil=priming_capture_control(fun(Deadline,Actors,Observe,Capture,Clock,Wait)->
        Counts=fun()->[Ports,Sockets,Processes]=Observe(),[Processes,Ports,Ports,Sockets] end,
        try cleanup_capture_metrics(Deadline,[0,0,0,0],Actors,Counts,Capture,Clock,Wait)
        catch error:{benchmark_cleanup_resource_limit,Values}->
            error({benchmark_priming_cleanup_limit,[maps:get(observed_network_ports,Values),
                maps:get(observed_sockets,Values),maps:get(observed_processes,Values)]})
        end
    end),
    %% Keep every original threshold independent, including exact equality.
    lists:foreach(fun(Counts)->
        true=try cleanup_capture_metrics(1,[0,0,0,0],fun()->[] end,
            fun()->Counts end,fun()->error(over_limit_capture) end,
            fun()->1 end,fun()->error(cleanup_deadline_extended) end) of _->false
            catch error:{benchmark_cleanup_resource_limit,_}->true end
    end,[[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]]),
    {3,0,0,2,1,1}=cleanup_capture_metrics(1,[3,2,1,1],fun()->[] end,
        fun()->[3,2,1,1] end,fun()->{3,0,0,2,1,1} end,
        fun()->1 end,fun()->error(equal_cleanup_waited) end),nil.

priming_capture_control(Run) ->
    Parent=self(),Ref=make_ref(),Captures=atomics:new(1,[]),
    {Owner,OwnerMon}=spawn_monitor(fun()->
        ok=proc_lib:set_label(<<"quic_core.client">>),
        {ok,Socket}=gen_udp:open(0,[{inet_backend,inet},binary,{active,false},{ip,{127,0,0,1}}]),
        Parent!{Ref,ready,Socket},
        try receive {Ref,release}->ok after 3000->error(priming_capture_owner_deadline) end
        after gen_udp:close(Socket) end
    end),
    try
        Socket=receive {Ref,ready,S}->S after 3000->error(priming_capture_owner_missing) end,
        Find=fun()->case is_process_alive(Owner) of true->[Owner];false->[] end end,
        Observe=fun()->{_,Counts}=priming_owned_snapshot(Owner,Socket),Counts end,
        %% An expired absolute deadline removes its monitor without touching
        %% the retained owner, without a full capture, and without waiting.
        {monitors,BeforeMonitors}=process_info(self(),monitors),
        true=try Run(1,Find,Observe,
            fun()->error(expired_priming_captured) end,fun()->1 end,
            fun()->error(expired_priming_waited) end) of _->false
            catch error:{benchmark_priming_cleanup_limit,[1,0,1]}->true end,
        {monitors,AfterMonitors}=process_info(self(),monitors),
        true=lists:sort(BeforeMonitors)=:=lists:sort(AfterMonitors),
        true=is_process_alive(Owner),0=atomics:get(Captures,1),
        {Waiter,WaiterMon}=spawn_monitor(fun()->
            Capture=fun()->atomics:add(Captures,1,1),{Metrics,_}=priming_owned_snapshot(Owner,Socket),Metrics end,
            Metrics=Run(erlang:monotonic_time(millisecond)+3000,
                Find,Observe,Capture,fun()->erlang:monotonic_time(millisecond) end,
                fun()->timer:sleep(20) end),
            Parent!{Ref,captured,Metrics}
        end),
        try
            priming_capture_waiting(Waiter,Owner,Captures,
                erlang:monotonic_time(millisecond)+3000),
            0=atomics:get(Captures,1),
            Owner!{Ref,release},
            receive {'DOWN',OwnerMon,process,Owner,normal}->ok
                after 3000->error(priming_capture_owner_not_joined) end,
            receive {Ref,captured,{0,0,0,0,0,0}}->ok
                after 3000->error(priming_capture_result_missing) end,
            receive {'DOWN',WaiterMon,process,Waiter,normal}->ok
                after 3000->error(priming_capture_waiter_not_joined) end,
            1=atomics:get(Captures,1),
            %% A resource appearing in the final full sample fails closed.
            true=try Run(1,fun()->[] end,fun()->[0,0,0] end,
                fun()->atomics:add(Captures,1,1),{0,0,0,1,1,0} end,
                fun()->1 end,fun()->error(final_priming_waited) end) of _->false
                catch error:{benchmark_priming_cleanup_limit,[1,0,0]}->true end,
            2=atomics:get(Captures,1),nil
        after
            stop_priming_fixture(Waiter,WaiterMon),
            stop_priming_fixture(Owner,OwnerMon),
            await_priming_test_socket_closed(Socket,erlang:monotonic_time(millisecond)+3000),
            priming_control_mailbox_empty(Ref)
        end
    after stop_priming_fixture(Owner,OwnerMon) end.

priming_capture_waiting(Waiter,Owner,Captures,Deadline) ->
    case atomics:get(Captures,1) of
        0->case process_info(Waiter,monitors) of
            {monitors,Monitors}->case lists:member({process,Owner},Monitors) of
                true->ok;
                false->priming_capture_waiting_again(Waiter,Owner,Captures,Deadline)
            end;
            undefined->error(priming_capture_waiter_stopped)
        end;
        _->error(premature_full_priming_capture)
    end.
priming_capture_waiting_again(Waiter,Owner,Captures,Deadline) ->
    case erlang:monotonic_time(millisecond)>=Deadline of
        true->error(priming_capture_monitor_missing);
        false->timer:sleep(1),priming_capture_waiting(Waiter,Owner,Captures,Deadline)
    end.

priming_cleanup_self_test() ->
    %% Other ordinary tests may still own bounded wire-closing connections.
    %% Keep one unrelated labelled UDP owner alive throughout this contract.
    Parent=self(), Ref=make_ref(),
    {Foreign,ForeignMonitor}=spawn_monitor(fun()->
        ok=proc_lib:set_label(<<"quic_core.connection">>),
        {ok,Socket}=gen_udp:open(0,[{inet_backend,inet},binary,{active,false},{ip,{127,0,0,1}}]),
        Parent!{Ref,foreign_ready,Socket},
        try receive {Ref,release}->ok after 15000->error(priming_foreign_deadline) end
        after gen_udp:close(Socket) end
    end),
    try
        ForeignSocket=receive {Ref,foreign_ready,S}->S
            after 3000->error(priming_foreign_not_ready) end,
        try
            nil=priming_owned_cleanup_control(),
            true=is_process_alive(Foreign),
            true=erlang:port_info(ForeignSocket)=/=undefined,
            nil
        after
            stop_priming_fixture(Foreign,ForeignMonitor),
            await_priming_test_socket_closed(ForeignSocket,
                erlang:monotonic_time(millisecond)+3000),
            priming_control_mailbox_empty(Ref)
        end
    after stop_priming_fixture(Foreign,ForeignMonitor) end.

priming_owned_cleanup_control() ->
    nil=priming_owned_cleanup_control(fun priming_cleanup/4),
    %% The historical zero-wait bypass must fail while the owned socket is
    %% still retained. The first actual wait callback supplies the barrier;
    %% no sleep or scheduler guess decides whether cleanup waited.
    Bypass=fun(_Deadline,Observe,_Clock,_Wait)->{Metrics,_}=Observe(),Metrics end,
    true=try priming_owned_cleanup_control(Bypass) of _->false
        catch error:premature_priming_baseline->true end,
    true=try priming_owned_cleanup_control(fun(_,_,_,_)->error(injected_priming_failure) end) of _->false
        catch error:priming_control_failed->true end,
    %% Each independent nonzero resource blocks the same production loop at
    %% its absolute deadline, and never reaches the supplied wait callback.
    lists:foreach(fun(Counts)->
        true=try priming_cleanup(10,fun()->{unused,Counts} end,
            fun()->10 end,fun()->error(deadline_was_extended) end) of _->false
            catch error:{benchmark_priming_cleanup_limit,Counts}->true end
    end, [[1,0,0],[0,1,0],[0,0,1]]),
    %% The deliberately unrelated actor is still visible to the real global
    %% sampler. Scoped test observation never weakens the production baseline.
    true=try priming_cleanup(0,fun priming_snapshot/0,fun()->0 end,
        fun()->error(global_deadline_was_extended) end) of _->false
        catch error:{benchmark_priming_cleanup_limit,[Ports,Sockets,Actors]}->
            Ports+Sockets>0 andalso Actors>0 end,
    nil.

priming_owned_cleanup_control(Cleanup) ->
    Parent=self(), Ref=make_ref(),
    {Owner,OwnerMon}=spawn_monitor(fun()->
        ok=proc_lib:set_label(<<"quic_core.client">>),
        {ok,Socket}=gen_udp:open(0,[{inet_backend,inet},binary,{active,false},{ip,{127,0,0,1}}]),
        Parent!{Ref,ready,Socket},
        try receive {Ref,release}->ok after 3000->error(priming_fixture_deadline) end
        after gen_udp:close(Socket) end
    end),
    try
        OwnedSocket=receive {Ref,ready,S}->S
            after 3000->error(priming_fixture_not_ready) end,
        true=is_port(OwnedSocket),
        {Waiter,WaitMon}=spawn_monitor(fun()->
            Observe=fun()->
                Snapshot={_,Counts}=priming_owned_snapshot(Owner,OwnedSocket),
                case get({Ref,observed}) of
                    undefined->put({Ref,observed},true),Parent!{Ref,observed,Counts};
                    _->ok
                end,Snapshot
            end,
            Wait=fun()->
                case get({Ref,released}) of
                    undefined->
                        Parent!{Ref,waiting},
                        receive {Ref,poll}->put({Ref,released},true),ok
                        after 3000->error(priming_poll_not_released) end;
                    _->timer:sleep(1)
                end
            end,
            Result=Cleanup(erlang:monotonic_time(millisecond)+3000,
                Observe,fun()->erlang:monotonic_time(millisecond) end,Wait),
            {Actors,_,_,_,Ports,Sockets}=Result,
            Parent!{Ref,finished,Actors=:=0 andalso Ports=:=0 andalso Sockets=:=0}
        end),
        try
            receive
                {Ref,observed,[1,0,1]}->ok;
                {'DOWN',WaitMon,process,Waiter,_}->error(priming_control_failed)
            after 3000->error(priming_retained_resource_not_observed) end,
            receive
                {Ref,waiting}->ok;
                {Ref,finished,_}->error(premature_priming_baseline);
                {'DOWN',WaitMon,process,Waiter,_}->error(priming_control_failed)
            after 3000->error(priming_wait_not_observed) end,
            Owner!{Ref,release},
            receive {'DOWN',OwnerMon,process,Owner,normal}->ok
                after 3000->error(priming_owner_not_joined) end,
            undefined=erlang:port_info(OwnedSocket),
            Waiter!{Ref,poll},
            receive {Ref,finished,true}->ok
                after 3000->error(priming_cleanup_incomplete) end,
            receive {'DOWN',WaitMon,process,Waiter,normal}->ok
                after 3000->error(priming_waiter_not_joined) end,
            nil
        after
            stop_priming_fixture(Waiter,WaitMon),
            stop_priming_fixture(Owner,OwnerMon),
            await_priming_test_socket_closed(OwnedSocket,
                erlang:monotonic_time(millisecond)+3000),
            priming_control_mailbox_empty(Ref)
        end
    after stop_priming_fixture(Owner,OwnerMon) end.

%% The test controls only this actor and this explicitly selected inet socket.
%% The opaque Metrics value returned by priming_cleanup must describe that
%% same sample; production still checks all actors, network ports and sockets.
priming_owned_snapshot(Owner,Socket) ->
    Actors=case is_process_alive(Owner) of true->1;false->0 end,
    Ports=case erlang:port_info(Socket) of undefined->0;_->1 end,
    {{Actors,0,0,Ports,Ports,0},[Ports,0,Actors]}.

await_priming_test_socket_closed(Socket,Deadline) ->
    case erlang:port_info(Socket) of
        undefined->ok;
        _->case erlang:monotonic_time(millisecond)>=Deadline of
            true->error(priming_owned_socket_not_closed);
            false->timer:sleep(1),await_priming_test_socket_closed(Socket,Deadline)
        end
    end.

priming_control_mailbox_empty(Ref) ->
    receive
        {Ref,_}->error(priming_control_message_retained);
        {Ref,_,_}->error(priming_control_message_retained)
    after 0->ok end.

stop_priming_fixture(Pid,OriginalMonitor) ->
    Join=erlang:monitor(process,Pid),exit(Pid,kill),
    receive {'DOWN',Join,process,Pid,_}->ok
    after 3000->erlang:error(priming_fixture_not_joined) end,
    erlang:demonitor(OriginalMonitor,[flush]),ok.

-spec network_port_count() -> non_neg_integer().
network_port_count() ->
    length([
        Port
     || Port <- erlang:ports(),
        {name, Name} <- [erlang:port_info(Port, name)],
        lists:member(Name, ["udp_inet", "tcp_inet", "sctp_inet"])
    ]).

-spec socket_count() -> non_neg_integer().
socket_count() ->
    case code:ensure_loaded(socket) of
        {module, socket} ->
            case erlang:function_exported(socket, which_sockets, 0) of
                true -> length(socket:which_sockets());
                false -> erlang:error(benchmark_socket_inventory_unavailable)
            end;
        {error, Reason} ->
            erlang:error({benchmark_socket_inventory_unavailable, Reason})
    end.

-spec diagnostic_metrics() ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
diagnostic_metrics() ->
    {RuntimeMilliseconds, _RuntimeSinceLastCall} = erlang:statistics(runtime),
    {Reductions, _ReductionsSinceLastCall} = erlang:statistics(reductions),
    {ContextSwitches, _ContextSwitchesSinceLastCall} =
        erlang:statistics(context_switches),
    {GarbageCollections, GarbageCollectedWords, _} =
        erlang:statistics(garbage_collection),
    {{input, InputBytes}, {output, OutputBytes}} = erlang:statistics(io),
    RunQueue = erlang:statistics(run_queue),
    {RuntimeMilliseconds, Reductions, ContextSwitches, GarbageCollections,
     GarbageCollectedWords, InputBytes, OutputBytes, RunQueue}.

-spec await_cleanup_metrics(
    non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()
) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer()}.
await_cleanup_metrics(
  MaximumProcesses, MaximumPorts, MaximumNetworkPorts, MaximumSockets
) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CLEANUP_TIMEOUT,
    await_cleanup_metrics(
      MaximumProcesses, MaximumPorts, MaximumNetworkPorts, MaximumSockets,
      Deadline).

cleanup_capture_metrics(Deadline,Limits,Actors,Observe,Capture,Clock,Wait) ->
    try priming_await_actors(Deadline,Actors,Observe,Clock)
    catch error:{benchmark_priming_cleanup_limit,Counts}->cleanup_limit(Limits,Counts) end,
    cleanup_await_counts(Deadline,Limits,Observe,Clock,Wait),
    Metrics={Processes,_,_,Ports,NetworkPorts,Sockets}=Capture(),
    Final=[Processes,Ports,NetworkPorts,Sockets],
    case cleanup_within_limits(Final,Limits) of
        true->Metrics;
        false->cleanup_limit(Limits,Final)
    end.

cleanup_await_counts(Deadline,Limits,Observe,Clock,Wait) ->
    Counts=Observe(),
    case cleanup_within_limits(Counts,Limits) of
        true->ok;
        false->case Clock()>=Deadline of
            true->cleanup_limit(Limits,Counts);
            false->Wait(),cleanup_await_counts(Deadline,Limits,Observe,Clock,Wait)
        end
    end.

cleanup_counts() ->
    [erlang:system_info(process_count),erlang:system_info(port_count),
     network_port_count(),socket_count()].

cleanup_within_limits(Counts,Limits) ->
    lists:all(fun({Observed,Maximum})->Observed=<Maximum end,lists:zip(Counts,Limits)).
cleanup_limit([MaximumProcesses,MaximumPorts,MaximumNetworkPorts,MaximumSockets],
              [Processes,Ports,NetworkPorts,Sockets]) ->
    error({benchmark_cleanup_resource_limit,
        #{observed_processes=>Processes,maximum_processes=>MaximumProcesses,
          observed_ports=>Ports,maximum_ports=>MaximumPorts,
          observed_network_ports=>NetworkPorts,maximum_network_ports=>MaximumNetworkPorts,
          observed_sockets=>Sockets,maximum_sockets=>MaximumSockets}}).

-spec write_line(binary()) -> nil.
write_line(Line) ->
    io:put_chars([Line, $\n]),
    nil.

-spec fail(term()) -> no_return().
fail(Message) ->
    erlang:error({http3_benchmark_failed, Message}).

await_cleanup_metrics(
  MaximumProcesses, MaximumPorts, MaximumNetworkPorts, MaximumSockets, Deadline
) ->
    cleanup_capture_metrics(Deadline,
        [MaximumProcesses,MaximumPorts,MaximumNetworkPorts,MaximumSockets],
        fun priming_actors/0,fun cleanup_counts/0,fun runtime_metrics/0,
        fun()->erlang:monotonic_time(millisecond) end,fun()->timer:sleep(10) end).

mailbox_messages() ->
    lists:sum([
        Length
     || Process <- processes(),
        {message_queue_len, Length} <- [process_info(Process, message_queue_len)]
    ]).

await_process_down(Pid, Monitor) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after 5000 ->
        exit(Pid, kill),
        receive
            {'DOWN', Monitor, process, Pid, _Reason} -> ok
        after 5000 ->
            erlang:error(benchmark_worker_cleanup_timeout)
        end
    end.
