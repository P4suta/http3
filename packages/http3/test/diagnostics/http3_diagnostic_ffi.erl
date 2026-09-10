-module(http3_diagnostic_ffi).

-export([
    arguments/0,
    await_cleanup/3,
    fail/1,
    qlog_directory/0,
    runtime_metrics/0,
    write_line/1
]).

-spec arguments() -> [binary()].
arguments() ->
    [unicode:characters_to_binary(Argument) ||
        Argument <- init:get_plain_arguments()].

-spec qlog_directory() -> binary().
qlog_directory() ->
    case os:getenv("HTTP3_DIAGNOSTIC_QLOG_DIR") of
        false -> <<>>;
        Directory -> unicode:characters_to_binary(Directory)
    end.

-spec runtime_metrics() -> {non_neg_integer(), non_neg_integer()}.
runtime_metrics() ->
    _ = erlang:garbage_collect(),
    {erlang:system_info(process_count), mailbox_messages()}.

-spec await_cleanup(non_neg_integer(), non_neg_integer(), pos_integer()) ->
    boolean().
await_cleanup(MaximumProcesses, MaximumMailboxMessages, TimeoutMilliseconds)
        when is_integer(MaximumProcesses), MaximumProcesses >= 0,
             is_integer(MaximumMailboxMessages), MaximumMailboxMessages >= 0,
             is_integer(TimeoutMilliseconds), TimeoutMilliseconds > 0 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    await_cleanup_loop(MaximumProcesses, MaximumMailboxMessages, Deadline);
await_cleanup(_MaximumProcesses, _MaximumMailboxMessages, _TimeoutMilliseconds) ->
    false.

-spec write_line(binary()) -> nil.
write_line(Line) ->
    io:put_chars([Line, $\n]),
    nil.

-spec fail(term()) -> no_return().
fail(Reason) ->
    erlang:error({http3_diagnostic_failed, Reason}).

await_cleanup_loop(MaximumProcesses, MaximumMailboxMessages, Deadline) ->
    {Processes, MailboxMessages} = runtime_metrics(),
    case Processes =< MaximumProcesses andalso
            MailboxMessages =< MaximumMailboxMessages of
        true -> true;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false ->
                    receive
                    after 10 ->
                        await_cleanup_loop(
                            MaximumProcesses,
                            MaximumMailboxMessages,
                            Deadline
                        )
                    end
            end
    end.

mailbox_messages() ->
    lists:sum([
        Length
     || Process <- processes(),
        {message_queue_len, Length} <-
            [process_info(Process, message_queue_len)]
    ]).
