-module(http3_benchmark_ffi).

-export([
    arguments/0,
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
    Metrics = {Processes, _Memory, _Messages, Ports, NetworkPorts, Sockets} =
        runtime_metrics(),
    case Processes =< MaximumProcesses
         andalso Ports =< MaximumPorts
         andalso NetworkPorts =< MaximumNetworkPorts
         andalso Sockets =< MaximumSockets of
        true -> Metrics;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    erlang:error(
                        {benchmark_cleanup_resource_limit,
                         #{observed_processes => Processes,
                           maximum_processes => MaximumProcesses,
                           observed_ports => Ports,
                           maximum_ports => MaximumPorts,
                           observed_network_ports => NetworkPorts,
                           maximum_network_ports => MaximumNetworkPorts,
                           observed_sockets => Sockets,
                           maximum_sockets => MaximumSockets,
                           final_metrics => Metrics}}
                    );
                false ->
                    receive
                    after 10 ->
                        await_cleanup_metrics(
                          MaximumProcesses, MaximumPorts, MaximumNetworkPorts,
                          MaximumSockets, Deadline)
                    end
            end
    end.

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
