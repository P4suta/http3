%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_CSV_HRL).
-define(HTTP_PERFORMANCE_CSV_HRL, true).
-define(PERFORMANCE_CSV_HEADER,
        <<"mode,iteration,warmup,concurrency,requests_per_worker,total_requests,"
          "payload_bytes,elapsed_microseconds,requests_per_second,"
          "processes_before,processes_after,memory_before_bytes,"
          "memory_after_bytes,mailbox_messages_before,mailbox_messages_after,"
          "ports_before,ports_after,network_ports_before,network_ports_after,"
          "sockets_before,sockets_after,"
          "runtime_milliseconds,reductions,context_switches,garbage_collections,"
          "garbage_collected_words,io_input_bytes,io_output_bytes,"
          "run_queue_before,run_queue_after,"
          "client_initial_smoothed_rtt_min_us,"
          "client_initial_smoothed_rtt_avg_us,"
          "client_initial_smoothed_rtt_max_us,"
          "client_final_smoothed_rtt_min_us,client_final_smoothed_rtt_avg_us,"
          "client_final_smoothed_rtt_max_us,client_initial_cwnd_min,"
          "client_initial_cwnd_avg,client_initial_cwnd_max,client_final_cwnd_min,"
          "client_final_cwnd_avg,client_final_cwnd_max,"
          "client_retransmissions_total,client_retransmissions_max,"
          "client_packets_received_total,client_packets_sent_total,"
          "client_batch_flushes_total,client_packets_coalesced_total,"
          "client_connections_in_recovery,client_connections_congested">>).
performance_filter_csv(Bytes) when is_binary(Bytes), byte_size(Bytes) =< 1048576 ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    {Accepted, Discarded} = lists:foldl(fun(Line0, {Rows, Lost}) ->
        Line = string:trim(Line0, trailing, "\r"),
        case performance_csv_line(Line) of
            {ok, Safe} -> {[Safe | Rows], Lost};
            invalid -> {Rows, Lost + 1}
        end
    end, {[], 0}, Lines),
    #{csv => iolist_to_binary([[Line, $\n] || Line <- lists:reverse(Accepted)]),
      discarded_lines => Discarded};
performance_filter_csv(_) -> erlang:error(performance_log_limit).
performance_csv_line(?PERFORMANCE_CSV_HEADER) -> {ok, ?PERFORMANCE_CSV_HEADER};
performance_csv_line(Line) ->
    try
        true = byte_size(Line) =< 2048,
        Fields = binary:split(Line, <<",">>, [global]),
        50 = length(Fields),
        [Mode, Iteration, Warmup | Rest] = Fields,
        true = lists:member(Mode, [<<"benchmark">>, <<"load">>, <<"soak">>]),
        true = lists:member(Warmup, [<<"True">>, <<"False">>]),
        Numbers = [performance_csv_integer(N) || N <- [Iteration | Rest]],
        [Number | Others] = Numbers,
        {ok, iolist_to_binary(lists:join($,, [Mode, integer_to_binary(Number), Warmup |
            [integer_to_binary(N) || N <- Others]]))}
    catch _:_ -> invalid end.
performance_csv_integer(Bytes) ->
    true = byte_size(Bytes) =< 19 andalso byte_size(Bytes) > 0,
    true = lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bytes)),
    Value = binary_to_integer(Bytes), true = Value =< 9223372036854775807, Value.

%% Independently reconstruct the report rows from the retained numeric wire
%% format. Unknown report fields and changed derived values cannot survive an
%% equality comparison against this projection.
performance_csv_rows(Csv, Mode) ->
    Columns = binary:split(?PERFORMANCE_CSV_HEADER, <<",">>, [global]),
    [begin
        {ok, Line} = performance_csv_line(Line),
        Fields = binary:split(Line, <<",">>, [global]),
        Raw = maps:from_list([{performance_column(Key), performance_column_value(Key, Value)}
            || {Key, Value} <- lists:zip(Columns, Fields)]),
        Raw#{<<"beam_runtime_basis_points">> => maps:get(<<"runtime_milliseconds">>, Raw) * 10000000
                div maps:get(<<"elapsed_microseconds">>, Raw),
             <<"reductions_per_request">> => maps:get(<<"reductions">>, Raw) div maps:get(<<"total_requests">>, Raw)}
    end || Line <- binary:split(Csv, <<"\n">>, [global]),
        binary:match(Line, <<Mode/binary, ",">>) =:= {0, byte_size(Mode) + 1}].
performance_column(<<"requests_per_worker">>) -> <<"requests_per_connection">>;
performance_column(Key) -> Key.
performance_column_value(<<"mode">>, Value) -> Value;
performance_column_value(<<"warmup">>, <<"True">>) -> true;
performance_column_value(<<"warmup">>, <<"False">>) -> false;
performance_column_value(_, Value) -> performance_csv_integer(Value).
bounded_log_evidence(Log, LogPath) ->
    #{csv := Safe, discarded_lines := Discarded} = performance_filter_csv(Log),
    Size = byte_size(Safe),
    TailSize = erlang:min(Size, 16384),
    Tail = binary:part(Safe, Size - TailSize, TailSize),
    #{path => list_to_binary(LogPath), bytes => Size,
      sha256 => binary:encode_hex(crypto:hash(sha256, Safe)), tail_bytes => TailSize,
      tail_base64 => base64:encode(Tail), truncated => Size > TailSize,
      content_kind => <<"validated_numeric_csv">>, discarded_lines => Discarded,
      shareable => true}.

-endif.
