-module(http3_benchmark_ffi).

-export([
    arguments/0,
    await_cleanup_metrics/1,
    await_task/1,
    fail/1,
    monotonic_microseconds/0,
    runtime_metrics/0,
    start_task/1,
    write_line/1
]).

-define(BENCHMARK_TIMEOUT, 900000).
-define(CLEANUP_TIMEOUT, 10000).

-spec arguments() -> [binary()].
arguments() ->
    [unicode:characters_to_binary(Argument) || Argument <- init:get_plain_arguments()].

-spec start_task(fun(() -> term())) -> tuple().
start_task(Fun) when is_function(Fun, 0) ->
    Owner = self(),
    Ref = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Result = Fun(),
        Owner ! {Ref, benchmark_result, Result}
    end),
    {http3_benchmark_task, Pid, Monitor, Ref}.

-spec await_task(tuple()) -> term().
await_task({http3_benchmark_task, Pid, Monitor, Ref}) ->
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
    after ?BENCHMARK_TIMEOUT ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(benchmark_worker_timeout)
    end.

-spec monotonic_microseconds() -> integer().
monotonic_microseconds() ->
    erlang:monotonic_time(microsecond).

-spec runtime_metrics() -> {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
runtime_metrics() ->
    _ = erlang:garbage_collect(),
    {
        erlang:system_info(process_count),
        erlang:memory(total),
        mailbox_messages()
    }.

-spec await_cleanup_metrics(non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
await_cleanup_metrics(MaximumProcesses) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CLEANUP_TIMEOUT,
    await_cleanup_metrics(MaximumProcesses, Deadline).

-spec write_line(binary()) -> nil.
write_line(Line) ->
    io:put_chars([Line, $\n]),
    nil.

-spec fail(term()) -> no_return().
fail(Message) ->
    erlang:error({http3_benchmark_failed, Message}).

await_cleanup_metrics(MaximumProcesses, Deadline) ->
    Processes = erlang:system_info(process_count),
    case Processes =< MaximumProcesses of
        true -> runtime_metrics();
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    erlang:error(
                        {benchmark_cleanup_process_limit, Processes, MaximumProcesses}
                    );
                false ->
                    receive
                    after 10 -> await_cleanup_metrics(MaximumProcesses, Deadline)
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
