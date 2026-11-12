%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_model_protocols).
-export([run/3]).

-define(H1, 'http@internal@http1@body').
-define(H2, 'http@internal@http2@stream_state').
-define(FLOW, 'http@internal@http2@flow_control').
-define(TABLE, 'http@internal@http2@hpack@dynamic_table').
-define(MAX_WINDOW, 16#7fffffff).

%% The expected states deliberately differ from the implementation: a byte
%% language with a known following message; two independently closed halves;
%% cumulative credit/debit entries; and an oldest-first field FIFO.
run(http1, Seed, _Steps) -> http1(Seed);
run(http2, Seed, Steps) ->
    {ok, Window} = ?FLOW:new(17),
    stream_steps(Seed, Steps, 1, idle, {false, none, false, false, false},
                 Window, {17, 0, 0});
run(hpack, Seed, Steps) ->
    {ok, Table} = ?TABLE:new(256),
    table_steps(Seed, Steps, 1, Table, 256, []).

next(Seed) -> ((Seed + 1) * 48271) rem 2147483647.
check(true, _Step, _Code) -> ok;
check(false, Step, Code) -> throw({model_failure, Step, Code}).

http1(Seed) ->
    Length = Seed rem 25,
    Payload = binary:copy(<<(97 + Seed rem 26)>>, Length),
    Tail = <<"NEXT\r\n">>,
    {Framing, Wire, ExpectedTail} = case Seed rem 4 of
        0 -> {no_body, Tail, Tail};
        1 -> {{content_length, Length}, <<Payload/binary, Tail/binary>>, Tail};
        2 ->
            Chunk = case Payload of
                <<>> -> <<>>;
                _ -> iolist_to_binary([integer_to_binary(Length, 16),
                                        ";x=\"v\"\r\n", Payload, "\r\n"])
            end,
            {chunked, <<Chunk/binary, "0\r\nx-model: y\r\n\r\n", Tail/binary>>, Tail};
        3 -> {close_delimited, Payload, <<>>}
    end,
    Expected = case Framing of no_body -> <<>>; _ -> Payload end,
    Limits = {limits, 256, 256, 128, 8, 128},
    {ok, Decoder} = ?H1:decoder(Framing, Limits),
    {Count, Actual, Trailers, Rest} =
        feed_message(Decoder, Wire, Seed, 1, []),
    check(Actual =:= Expected, Count, 101),
    check(Rest =:= ExpectedTail, Count, 102),
    ExpectedTrailers = case Framing of
        chunked -> [{header, <<"x-model">>, <<"y">>}];
        _ -> []
    end,
    check(Trailers =:= ExpectedTrailers, Count, 103),
    %% EOF before the declared fixed length must never be confused with a
    %% complete message or consume a following response as body bytes.
    {ok, Short} = ?H1:decoder({content_length, Length + 1}, Limits),
    {ok, Incomplete} = case ?H1:feed(Short, Payload) of
        {ok, {body_data, _, D}} -> {ok, D};
        {ok, {body_need_more, D}} -> {ok, D}
    end,
    check(?H1:finish(Incomplete) =:= {error, unexpected_end_of_body}, Count + 1, 104),
    %% This grammar has a missing CRLF after chunk data, independent of the
    %% decoder's internal chunk states.
    {ok, Chunked} = ?H1:decoder(chunked, Limits),
    check(?H1:feed(Chunked, <<"1\r\na!\r\n0\r\n\r\n">>)
          =:= {error, invalid_chunk_terminator}, Count + 2, 105),
    {Count + 2, {byte_size(Actual), byte_size(Rest), length(Trailers)}}.

feed_message(Decoder, <<>>, _Seed, Step, Acc) ->
    case ?H1:finish(Decoder) of
        {ok, {body_complete, Data, Trailers, Rest}} ->
            {Step, iolist_to_binary(lists:reverse([Data | Acc])), Trailers, Rest};
        _ -> throw({model_failure, Step, 106})
    end;
feed_message(Decoder, Wire, Seed, Step, Acc) when Step =< 128 ->
    Width = min(byte_size(Wire), 1 + Seed rem 13),
    <<Chunk:Width/binary, Following/binary>> = Wire,
    case ?H1:feed(Decoder, Chunk) of
        {ok, {body_need_more, Next}} ->
            feed_message(Next, Following, next(Seed), Step + 1, Acc);
        {ok, {body_data, Data, Next}} ->
            feed_message(Next, Following, next(Seed), Step + 1, [Data | Acc]);
        {ok, {body_complete, Data, Trailers, Rest}} ->
            {Step, iolist_to_binary(lists:reverse([Data | Acc])), Trailers,
             <<Rest/binary, Following/binary>>};
        _ -> throw({model_failure, Step, 107})
    end;
feed_message(_, _, _, Step, _) -> throw({model_failure, Step, 108}).

stream_steps(_Seed, 0, Step, State, Bits, Window, Ledger) ->
    {2 * (Step - 1), {State, Bits, ?FLOW:available(Window), Ledger}};
stream_steps(Seed, Remaining, Step, State, Bits, Window, Ledger) ->
    Operation = Seed rem 8,
    End = (Seed div 8) rem 2 =:= 1,
    Expected = halves(Operation, End, Bits),
    Actual = stream_operation(Operation, End, State),
    {NextState, NextBits} = case {Expected, Actual} of
        {invalid, {error, _}} -> {State, Bits};
        {{valid, NewBits}, {ok, NewState}} ->
            check(NewState =:= represented_state(NewBits), Step, 201),
            {NewState, NewBits};
        _ -> throw({model_failure, Step, 202})
    end,
    {NextWindow, NextLedger} = flow_step(next(Seed), Step, Window, Ledger),
    stream_steps(next(next(Seed)), Remaining - 1, Step + 1,
                 NextState, NextBits, NextWindow, NextLedger).

stream_operation(0, _, S) -> ?H2:reserve_local(S);
stream_operation(1, _, S) -> ?H2:reserve_remote(S);
stream_operation(2, E, S) -> ?H2:send_headers(S, E);
stream_operation(3, E, S) -> ?H2:receive_headers(S, E);
stream_operation(4, E, S) -> ?H2:send_data(S, E);
stream_operation(5, E, S) -> ?H2:receive_data(S, E);
stream_operation(6, _, S) -> ?H2:send_reset(S);
stream_operation(7, _, S) -> ?H2:receive_reset(S).

%% {opened, promised_by, local_finished, peer_finished, reset}
halves(Op, _, {false, none, false, false, false}) when Op < 2 ->
    case Op of
        0 -> {valid, {false, local, false, true, false}};
        1 -> {valid, {false, peer, true, false, false}}
    end;
halves(Op, _, _) when Op < 2 -> invalid;
halves(Op, _, {Opened, Promise, L, R, Reset}) when Op >= 6 ->
    case Opened orelse Promise =/= none orelse Reset of
        true -> {valid, {Opened, Promise, L, R, true}};
        false -> invalid
    end;
halves(Op, End, {Opened, Promise, L, R, Reset}) ->
    Local = Op rem 2 =:= 0,
    IsData = Op >= 4,
    Done = case Local of true -> L; false -> R end,
    WrongPromise = case Local of true -> Promise =:= peer; false -> Promise =:= local end,
    case Reset orelse Done orelse WrongPromise orelse (IsData andalso not Opened) of
        true -> invalid;
        false ->
            case Local of
                true -> {valid, {true, none, End, R, false}};
                false -> {valid, {true, none, L, End, false}}
            end
    end.

represented_state({_, _, _, _, true}) -> closed;
represented_state({true, _, true, true, _}) -> closed;
represented_state({false, local, _, _, _}) -> reserved_local;
represented_state({false, peer, _, _, _}) -> reserved_remote;
represented_state({false, none, _, _, _}) -> idle;
represented_state({true, _, true, false, _}) -> half_closed_local;
represented_state({true, _, false, true, _}) -> half_closed_remote;
represented_state({true, _, false, false, _}) -> open.

flow_step(Seed, Step, Window, {Initial, Credits, Debits} = Ledger) ->
    Value = lists:nth(1 + Seed rem 8, [-1, 0, 1, 7, 17, 255, ?MAX_WINDOW, ?MAX_WINDOW + 1]),
    Available = Initial + Credits - Debits,
    {Actual, Expected} = case (Seed div 8) rem 3 of
        0 ->
            Outcome = if Value < 0 -> invalid;
                         Value =:= 0 -> {valid, Ledger};
                         Value > Available -> invalid;
                         true -> {valid, {Initial, Credits, Debits + Value}} end,
            {?FLOW:consume(Window, Value), Outcome};
        1 ->
            Outcome = if Value =< 0; Value > ?MAX_WINDOW -> invalid;
                         Available + Value > ?MAX_WINDOW -> invalid;
                         true -> {valid, {Initial, Credits + Value, Debits}} end,
            {?FLOW:increase(Window, Value), Outcome};
        2 ->
            Outcome = if Value < 0; Value > ?MAX_WINDOW -> invalid;
                         Value + Credits - Debits > ?MAX_WINDOW -> invalid;
                         true -> {valid, {Value, Credits, Debits}} end,
            {?FLOW:apply_initial_window_size(Window, Initial, Value), Outcome}
    end,
    case {Actual, Expected} of
        {{error, _}, invalid} ->
            check(?FLOW:available(Window) =:= Available, Step, 203),
            {Window, Ledger};
        {{ok, Updated}, {valid, {I, C, D} = UpdatedLedger}} ->
            check(?FLOW:available(Updated) =:= I + C - D, Step, 204),
            {Updated, UpdatedLedger};
        _ -> throw({model_failure, Step, 205})
    end.

table_steps(_Seed, 0, Step, Table, Capacity, Queue) ->
    {Step - 1, {Capacity, ?TABLE:size(Table), length(Queue)}};
table_steps(Seed, Remaining, Step, Table, Capacity, Queue) ->
    {Updated, NewCapacity, NewQueue} = case Seed rem 4 of
        0 ->
            New = lists:nth(1 + (Seed div 4) rem 7, [-1, 0, 31, 64, 128, 256, 257]),
            case ?TABLE:set_capacity(Table, New) of
                {error, _} ->
                    check(New < 0 orelse New > 256, Step, 301),
                    {Table, Capacity, Queue};
                {ok, T} ->
                    check(New >= 0 andalso New =< 256, Step, 302),
                    {T, New, fit(Queue, New)}
            end;
        _ ->
            Name = <<(97 + (Seed div 4) rem 4)>>,
            Size = lists:nth(1 + (Seed div 16) rem 7, [0, 1, 7, 31, 63, 127, 257]),
            Value = binary:copy(<<(97 + Seed rem 26)>>, Size),
            Field = {field, Name, Value},
            {ok, {T, Inserted}} = ?TABLE:insert(Table, Field),
            ExpectedInserted = 33 + Size =< Capacity,
            check(Inserted =:= ExpectedInserted, Step, 303),
            Entries = case ExpectedInserted of
                true -> fit(Queue ++ [{Name, Value}], Capacity);
                false -> []
            end,
            {T, Capacity, Entries}
    end,
    check(?TABLE:size(Updated) =:= queue_bytes(NewQueue), Step, 304),
    check(?TABLE:capacity(Updated) =:= NewCapacity, Step, 305),
    check(?TABLE:length(Updated) =:= length(NewQueue), Step, 306),
    compare_indexes(Updated, lists:reverse(NewQueue), 0, Step),
    table_steps(next(Seed), Remaining - 1, Step + 1, Updated, NewCapacity, NewQueue).

queue_bytes(Queue) -> lists:sum([32 + byte_size(N) + byte_size(V) || {N, V} <- Queue]).
fit([], _) -> [];
fit([_ | Rest] = Queue, Capacity) ->
    case queue_bytes(Queue) =< Capacity of true -> Queue; false -> fit(Rest, Capacity) end.
compare_indexes(Table, [], Index, Step) ->
    check(?TABLE:get_relative(Table, Index) =:= none, Step, 307),
    check(?TABLE:get_relative(Table, -1) =:= none, Step, 308);
compare_indexes(Table, [{Name, Value} | Rest], Index, Step) ->
    Field = {field, Name, Value},
    check(?TABLE:get_relative(Table, Index) =:= {some, Field}, Step, 309),
    %% Duplicate fields resolve to the newest equal resident, never an
    %% evicted insertion or an older duplicate.
    case ?TABLE:find(Table, Field) of
        {some, Found} -> check(Found =< Index, Step, 310);
        _ -> throw({model_failure, Step, 311})
    end,
    compare_indexes(Table, Rest, Index + 1, Step).
