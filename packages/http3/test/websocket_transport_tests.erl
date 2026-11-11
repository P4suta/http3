%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(websocket_transport_tests).
-include_lib("eunit/include/eunit.hrl").

%% RFC 9220 section 3 maps an abort to H3_REQUEST_CANCELLED, not orderly FIN.
server_cancel_resets_the_websocket_stream_test() ->
    with_raw_client(fun(_Connection, Stream, _Incoming, Socket) ->
        Cancelled = 'http3@websocket':cancel(Socket),
        Peer = 'http3@client':next_event(Stream),
        observe(server_cancel, peer_event(Peer)),
        ?assert(is_ok(Cancelled)),
        ?assert(peer_cancelled(Peer))
    end).

client_cancel_marks_both_local_directions_closed_test() ->
    with_raw_server(fun(_Connection, _Incoming, Socket) ->
        Closed = need_ok('http3@websocket':cancel(Socket)),
        Read = 'http3@websocket':'receive'(Closed),
        observe(client_cancel, websocket_event(Read)),
        ?assert(Read =:= {error, already_closed})
    end).

%% RFC 6455 section 5.5.1 + RFC 9220: the Close exchange finishes the stream.
server_close_exchange_sends_response_fin_test() ->
    with_raw_client(fun(_Connection, Stream, Incoming, Socket) ->
        need_ok('http3@client':send_chunk(Stream, masked(8, true, <<>>))),
        Received = 'http3@websocket':'receive'(Socket),
        Echo = 'http3@client':next_event(Stream),
        End = 'http3@client':next_event(Stream),
        need_ok('http3@client':finish(Stream)),
        RequestEnd = 'http3@server':next_event(Incoming),
        observe(server_close, peer_event(End)),
        ?assert(close_event(Received)),
        ?assert(Echo =:= {ok, {data, <<16#88, 0>>}}),
        ?assert(End =:= {ok, 'end'}),
        ?assert(RequestEnd =:= {ok, 'end'})
    end).

client_close_exchange_sends_request_fin_test() ->
    with_raw_server(fun(_Connection, Incoming, Socket) ->
        need_ok('http3@server':send_chunk(Incoming, <<16#88, 0>>)),
        need_ok('http3@server':finish_response(Incoming)),
        Received = 'http3@websocket':'receive'(Socket),
        Echo = 'http3@server':next_event(Incoming),
        End = 'http3@server':next_event(Incoming),
        observe(client_close, peer_event(End)),
        ?assert(close_event(Received)),
        ?assert(masked_empty_close(Echo)),
        ?assert(End =:= {ok, 'end'})
    end).

invalid_utf8_fails_and_releases_the_stream_test() ->
    with_raw_client(fun(_Connection, Stream, _Incoming, Socket) ->
        need_ok('http3@client':send_chunk(Stream, masked(1, true, <<16#ff>>))),
        Failure = 'http3@websocket':'receive'(Socket),
        Close = 'http3@client':next_event(Stream),
        End = 'http3@client':next_event(Stream),
        observe(invalid_utf8, peer_event(Close)),
        ?assert(Failure =:= {error, invalid_utf8}),
        ?assert(wire_event(Close, client, 8, <<1007:16>>)),
        ?assert(End =:= {ok, 'end'})
    end).

server_protocol_failure_sends_close_before_reclaim_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        {Stream, Incoming, Socket} = accept_raw_client(
            Listener, Connection, Request, 'http3@websocket':new()),
        need_ok('http3@client':send_chunk(
            Stream, masked(1, true, <<16#ff, "private-peer-marker">>))),
        Failure = 'http3@websocket':'receive'(Socket),
        Close = 'http3@client':next_event(Stream),
        End = 'http3@client':next_event(Stream),
        ?assert(Failure =:= {error, invalid_utf8}),
        ?assert(wire_event(Close, client, 8, <<1007:16>>)),
        ?assert(End =:= {ok, 'end'}),
        ?assert('http3@client':cancel(Stream) =:= {ok, cancelled}),
        reused(Listener, Connection, Request, Incoming)
    end).

client_protocol_failure_sends_close_before_reclaim_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Task = http3_test_ffi:start_task(fun() ->
            'http3@websocket':connect(
                'http3@websocket':new(), Connection, Request)
        end),
        with_cleanup(fun() ->
            Incoming = need_ok('http3@server':accept(Listener)),
            need_ok('http3@server':send_response(Incoming, 200, [])),
            Socket = need_ok(http3_test_ffi:await_task(Task)),
            need_ok('http3@server':send_chunk(
                Incoming, wire(client, 1, true,
                               <<16#ff, "private-peer-marker">>))),
            Failure = 'http3@websocket':'receive'(Socket),
            Close = 'http3@server':next_event(Incoming),
            End = 'http3@server':next_event(Incoming),
            ?assert(Failure =:= {error, invalid_utf8}),
            ?assert(wire_event(Close, server, 8, <<1007:16>>)),
            ?assert(End =:= {ok, 'end'}),
            client_reused(Listener, Connection, Request, Incoming)
        end, fun() -> stop_task(Task), {ok, nil} end)
    end).

server_protocol_failure_records_one_typed_payload_free_qlog_event_test() ->
    {{ErrorEvents, TypedEvents, PayloadLeaked}, Files} =
        http3_test_ffi:with_qlog_directory(fun(Directory) ->
            with_connection_configuration(fun(Server) ->
                Qlog = need_ok('http3@transport':qlog(Directory)),
                'http3@server':with_qlog(Server, Qlog)
            end, fun(Listener, Connection, Request) ->
                {Stream, _Incoming, Socket} = accept_raw_client(
                    Listener, Connection, Request, 'http3@websocket':new()),
                need_ok('http3@client':send_chunk(Stream, masked(
                    1, true, <<16#ff, "private-peer-marker">>))),
                ?assert('http3@websocket':'receive'(Socket) =:= {error, invalid_utf8}),
                ?assert(wire_event('http3@client':next_event(Stream), client,
                                   8, <<1007:16>>)),
                ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
                need_ok('http3@client':cancel(Stream))
            end),
            {qlog_pattern_count(Directory, <<"\"name\":\"loglevel:error\"">>),
             qlog_pattern_count(Directory, <<"\"code\":2402">>),
             qlog_pattern_count(Directory, <<"private-peer-marker">>) > 0}
        end),
    ?assert({ErrorEvents, TypedEvents, PayloadLeaked, Files} =:= {1, 1, false, 1}).

client_protocol_failure_records_one_typed_payload_free_qlog_event_test() ->
    {{ErrorEvents, TypedEvents, PayloadLeaked}, Files} =
        http3_test_ffi:with_qlog_directory(fun(Directory) ->
            with_client_connection_configuration(fun(Client) ->
                Qlog = need_ok('http3@transport':qlog(Directory)),
                'http3@client':with_qlog(Client, Qlog)
            end, fun(Listener, Connection, Request) ->
                Task = http3_test_ffi:start_task(fun() ->
                    'http3@websocket':connect(
                        'http3@websocket':new(), Connection, Request)
                end),
                with_cleanup(fun() ->
                    Incoming = need_ok('http3@server':accept(Listener)),
                    need_ok('http3@server':send_response(Incoming, 200, [])),
                    Socket = need_ok(http3_test_ffi:await_task(Task)),
                    need_ok('http3@server':send_chunk(
                        Incoming, wire(client, 1, true,
                                       <<16#ff, "private-peer-marker">>))),
                    ?assert('http3@websocket':'receive'(Socket) =:=
                            {error, invalid_utf8}),
                    ?assert(wire_event('http3@server':next_event(Incoming),
                                       server, 8, <<1007:16>>)),
                    ?assert('http3@server':next_event(Incoming) =:= {ok, 'end'})
                end, fun() -> stop_task(Task), {ok, nil} end)
            end),
            {qlog_pattern_count(Directory, <<"\"name\":\"loglevel:error\"">>),
             qlog_pattern_count(Directory, <<"\"code\":2402">>),
             qlog_pattern_count(Directory, <<"private-peer-marker">>) > 0}
        end),
    ?assert({ErrorEvents, TypedEvents, PayloadLeaked, Files} =:=
            {1, 1, false, 1}).

fragmented_utf8_allows_ping_and_one_complete_message_test() ->
    with_raw_client(fun(_Connection, Stream, _Incoming, Socket) ->
        First = masked(1, false, <<16#e2>>),
        Ping = masked(9, true, <<"probe">>),
        Last = masked(0, true, <<16#82, 16#ac>>),
        need_ok('http3@client':send_chunk(Stream, <<First/binary, Ping/binary, Last/binary>>)),
        {Next, Event} = need_ok('http3@websocket':'receive'(Socket)),
        Pong = 'http3@client':next_event(Stream),
        Message = 'http3@websocket':'receive'(Next),
        ?assert(Event =:= {ping, <<"probe">>}),
        ?assert(Pong =:= {ok, {data, <<16#8a, 5, "probe">>}}),
        ?assert(text_event(Message, <<16#e2, 16#82, 16#ac>>))
    end).

%% Complete response ACK is a protocol synchronization point. Request FIN
%% must remain observable even when the response is already fully retired.
request_fin_after_response_ack_is_delivered_test() ->
    with_raw_client(fun(_Connection, Stream, Incoming, _Socket) ->
        need_ok('http3@server':finish_response(Incoming)),
        ResponseEnd = 'http3@client':next_event(Stream),
        ?assert(ResponseEnd =:= {ok, 'end'}),
        need_ok('http3@server':await_response_completion(Incoming)),
        need_ok('http3@client':finish(Stream)),
        RequestEnd = 'http3@server':next_event(Incoming),
        observe(acknowledged_response_request_fin, peer_event(RequestEnd)),
        ?assert(RequestEnd =:= {ok, 'end'})
    end).

malformed_frames_abort_both_roles_test_() ->
    [{atom_to_list(Role) ++ " malformed frame " ++ integer_to_list(Index), fun() ->
        with_websocket(Role, small_configuration(), fun(Socket, Send, Next) ->
            need_ok(Send(Bytes)),
            Result = 'http3@websocket':'receive'(Socket),
            Peer = Next(),
            ?assert(Result =:= {error, Expected}),
            assert_failure_disposition(Role, Expected, Peer, Next)
        end)
    end} || Role <- [client, server],
            {Index, {Bytes, Expected}} <- lists:enumerate(malformed_frames(Role))].

malformed_frames(Role) ->
    Frame = fun(Opcode, Fin, Bytes) -> wire(Role, Opcode, Fin, Bytes) end,
    InvalidMask = case Role of client -> masked(1, true, <<>>); server -> <<16#81, 0>> end,
    First = Frame(1, false, <<"pending">>),
    NewMessage = Frame(2, true, <<>>),
    Fragment = Frame(2, false, binary:copy(<<0>>, 16)),
    Last = Frame(0, true, binary:copy(<<0>>, 17)),
    [{InvalidMask, frame_error},
     {<<16#c1, 0>>, frame_error},
     {<<16#83, 0>>, frame_error},
     {Frame(9, false, <<>>), frame_error},
     {<<16#81, 126, 0, 1>>, frame_error},
     {Frame(0, true, <<>>), protocol_violation},
     {<<First/binary, NewMessage/binary>>, protocol_violation},
     {<<Fragment/binary, Last/binary>>, {message_too_large, 32}},
     {Frame(1, true, <<16#ff>>), invalid_utf8},
     {Frame(8, true, <<1>>), invalid_close},
     {Frame(8, true, <<1005:16>>), invalid_close},
     {Frame(8, true, <<1000:16, 16#ff>>), invalid_utf8}].

messages_and_control_frames_round_trip_both_roles_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            Text = <<"message", 16#e2, 16#82, 16#ac>>,
            Binary = <<0, 255, 128, 1>>,
            Out1 = need_ok('http3@websocket':send_text(Socket, Text)),
            ?assert(wire_event(Next(), opposite(Role), 1, Text)),
            Out2 = need_ok('http3@websocket':send_binary(Out1, Binary)),
            ?assert(wire_event(Next(), opposite(Role), 2, Binary)),
            Out3 = need_ok('http3@websocket':ping(Out2, <<"probe">>)),
            ?assert(wire_event(Next(), opposite(Role), 9, <<"probe">>)),
            need_ok(Send(wire(Role, 10, true, <<"probe">>))),
            {Out4, Pong} = need_ok('http3@websocket':'receive'(Out3)),
            ?assert(Pong =:= {pong, <<"probe">>}),
            need_ok(Send(wire(Role, 2, true, Binary))),
            {Out5, Message} = need_ok('http3@websocket':'receive'(Out4)),
            ?assert(Message =:= {binary_message, Binary}),
            need_ok(Send(wire(Role, 1, true, Text))),
            ?assert(text_event('http3@websocket':'receive'(Out5), Text))
        end)
    end || Role <- [client, server]].

control_payload_is_independent_of_message_limit_test_() ->
    [fun() ->
        with_websocket(Role, minimum_control_configuration(), fun(Socket, Send, Next) ->
            Payload = binary:copy(<<42>>, 125),
            need_ok(Send(wire(Role, 9, true, Payload))),
            Result = 'http3@websocket':'receive'(Socket),
            Peer = Next(),
            ?assert(ping_event(Result, Payload)),
            ?assert(wire_event(Peer, opposite(Role), 10, Payload))
        end)
    end || Role <- [client, server]].

control_buffer_invariant_rejects_message_plus_header_only_test() ->
    ?assert('http3@websocket':with_limits(
        'http3@websocket':new(), 1, 15) =:= {error, invalid_buffer_limit}).

local_argument_failures_leave_the_stream_usable_test_() ->
    [fun() ->
        with_websocket(Role, small_configuration(), fun(Socket, _Send, Next) ->
            ?assert('http3@websocket':send_binary(Socket, <<1:1>>) =:= {error, protocol_violation}),
            ?assert('http3@websocket':send_binary(Socket, binary:copy(<<0>>, 33)) =:=
                {error, {message_too_large, 32}}),
            ?assert('http3@websocket':send_text(Socket, binary:copy(<<"x">>, 33)) =:=
                {error, {message_too_large, 32}}),
            ?assert('http3@websocket':ping(Socket, <<1:1>>) =:= {error, protocol_violation}),
            ?assert('http3@websocket':ping(Socket, binary:copy(<<0>>, 126)) =:= {error, protocol_violation}),
            lists:foreach(fun({Code, Reason}) ->
                Result = 'http3@websocket':close(Socket, Code, Reason),
                ?assert(Result =:= {error, invalid_close})
            end, [{none, <<"reason without status">>}, {{some, 999}, <<>>},
                  {{some, 1004}, <<>>}, {{some, 1005}, <<>>}, {{some, 1006}, <<>>},
                  {{some, 1015}, <<>>}, {{some, 2999}, <<>>}, {{some, 5000}, <<>>},
                  {{some, 1000}, binary:copy(<<"x">>, 124)}]),
            need_ok('http3@websocket':send_text(Socket, <<"still usable">>)),
            ?assert(wire_event(Next(), opposite(Role), 1, <<"still usable">>))
        end)
    end || Role <- [client, server]].

close_echoes_status_and_disables_future_operations_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            Payload = <<Code:16, "done">>,
            need_ok(Send(wire(Role, 8, true, Payload))),
            {Closed, Event} = need_ok('http3@websocket':'receive'(Socket)),
            ?assert(Event =:= {close_received, {some, Code}, <<"done">>}),
            ?assert(wire_event(Next(), opposite(Role), 8, Payload)),
            ?assert(Next() =:= {ok, 'end'}),
            ?assert('http3@websocket':'receive'(Closed) =:= {error, already_closed}),
            ?assert('http3@websocket':send_text(Closed, <<>>) =:= {error, already_closed}),
            ?assert('http3@websocket':send_binary(Closed, <<>>) =:= {error, already_closed}),
            ?assert('http3@websocket':ping(Closed, <<>>) =:= {error, already_closed}),
            ?assert('http3@websocket':close(Closed, none, <<>>) =:= {error, already_closed})
        end)
    end || Role <- [client, server], Code <- [1000, 1001, 1002, 1003, 1007, 1008, 1009,
                                             1010, 1011, 1012, 1013, 1014, 3000, 4999]].

initiated_close_is_not_echoed_twice_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            Closing = need_ok('http3@websocket':close(Socket, none, <<>>)),
            ?assert(wire_event(Next(), opposite(Role), 8, <<>>)),
            need_ok(Send(wire(Role, 8, true, <<>>))),
            ?assert(close_event('http3@websocket':'receive'(Closing))),
            ?assert(Next() =:= {ok, 'end'})
        end)
    end || Role <- [client, server]].

cancelled_websocket_does_not_prevent_next_request_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        {Stream, Incoming, Socket} = accept_raw_client(Listener, Connection, Request, 'http3@websocket':new()),
        need_ok('http3@websocket':cancel(Socket)),
        ?assert(peer_cancelled('http3@client':next_event(Stream))),
        Next = need_ok('http3@client':open_stream(Connection, Request)),
        need_ok('http3@client':finish(Next)),
        Accepted = need_ok('http3@server':accept(Listener)),
        ?assert('http3@server':next_event(Accepted) =:= {ok, 'end'}),
        need_ok('http3@server':respond(Accepted, 204, [], <<>>)),
        ?assert(response_status('http3@client':next_event(Next), 204)),
        ?assert('http3@client':next_event(Next) =:= {ok, 'end'}),
        need_ok('http3@server':await_response_completion(Accepted)),
        %% The completion waiter belongs to core. Wake the HTTP/3 owner once
        %% so its next loop retires the now-acknowledged completed request.
        need_ok('http3@server':request_state_stats(Incoming)),
        Stats = need_ok('http3@server':request_state_stats(Incoming)),
        ?assert(element(1, Stats) =:= 0)
    end).

terminal_sockets_release_fragment_and_buffered_payload_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            Fragment = wire(Role, 2, false, binary:copy(<<42>>, 131072)),
            ControlOpcode = case Terminal of cancel -> 9; close -> 8 end,
            Control = wire(Role, ControlOpcode, true, <<>>),
            Buffered = wire(Role, 2, true, binary:copy(<<43>>, 131072)),
            need_ok(Send(<<Fragment/binary, Control/binary, Buffered/binary>>)),
            {Received, _Event} = need_ok('http3@websocket':'receive'(Socket)),
            Closed = case Terminal of
                cancel ->
                    ?assert(erlang:external_size(Received) > 131072),
                    ?assert(wire_event(Next(), opposite(Role), 10, <<>>)),
                    need_ok('http3@websocket':cancel(Received));
                close ->
                    ?assert(wire_event(Next(), opposite(Role), 8, <<>>)),
                    Received
            end,
            %% Serialization size detects retained payload in an opaque
            %% handle. It is not a claim about allocator or VM memory usage.
            ?assert(erlang:external_size(Closed) =< erlang:external_size(Socket) + 16),
            ?assert('http3@websocket':'receive'(Closed) =:= {error, already_closed})
        end)
    end || Role <- [client, server], Terminal <- [cancel, close]].

oversized_initial_fragment_is_rejected_before_a_control_reply_test_() ->
    [fun() ->
        Configuration = need_ok('http3@websocket':with_limits('http3@websocket':new(), 32, 256)),
        with_websocket(Role, Configuration, fun(Socket, Send, Next) ->
            First = wire(Role, Opcode, false, binary:copy(<<97>>, 33)),
            Ping = wire(Role, 9, true, <<>>),
            need_ok(Send(<<First/binary, Ping/binary>>)),
            Result = 'http3@websocket':'receive'(Socket),
            Peer = Next(),
            observe(oversized_initial_fragment, case Result of
                {error, {message_too_large, 32}} -> message_limit;
                {ok, {_, {ping, _}}} -> control_reply_after_oversized_fragment;
                _ -> other
            end),
            ?assert(Result =:= {error, {message_too_large, 32}}),
            assert_failure_disposition(
                Role, {message_too_large, 32}, Peer, Next)
        end)
    end || Role <- [client, server], Opcode <- [1, 2]].

one_receive_deadline_survives_fragment_progress_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            First = wire(Role, 2, false, <<1>>),
            Middle = wire(Role, 0, false, <<2>>),
            Last = wire(Role, 0, true, <<3>>),
            need_ok(Send(<<First/binary, Middle/binary, Last/binary>>)),
            Base = 'quic_core@diagnostics':monotonic_milliseconds(),
            Reads = atomics:new(1, []),
            Clock = fun() ->
                N = atomics:add_get(Reads, 1, 1),
                case N =< ReadsBeforeExpiry of true -> Base; false -> Base + 751 end
            end,
            Result = 'http3@websocket':receive_with_clock(Socket, Clock),
            Peer = Next(),
            ?assert(websocket_timeout(Role, Result)),
            ?assert(peer_cancelled(Peer)),
            ?assert(atomics:get(Reads, 1) > ReadsBeforeExpiry)
        end)
    end || Role <- [client, server], ReadsBeforeExpiry <- [2, 4]].

expired_transport_deadline_is_not_replaced_by_a_new_read_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            need_ok(Send(wire(Role, 2, true, <<4>>))),
            %% Hold the adapter's injected clock behind the transport clock.
            %% The adapter permits a read, but its absolute deadline is already
            %% past at the real transport boundary and must reject queued data.
            Base = 'quic_core@diagnostics':monotonic_milliseconds() - 1000,
            Result = 'http3@websocket':receive_with_clock(Socket, fun() -> Base end),
            ?assert(websocket_timeout(Role, Result)),
            ?assert(peer_cancelled(Next()))
        end)
    end || Role <- [client, server]].

receive_does_not_deliver_a_message_after_processing_crosses_its_deadline_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, Next) ->
            need_ok(Send(wire(Role, 2, true, <<5>>))),
            Base = 'quic_core@diagnostics':monotonic_milliseconds(),
            Reads = atomics:new(1, []),
            Clock = fun() ->
                N = atomics:add_get(Reads, 1, 1),
                case N =< 3 of true -> Base; false -> Base + 751 end
            end,
            Result = 'http3@websocket':receive_with_clock(Socket, Clock),
            ?assert(websocket_timeout(Role, Result)),
            ?assert(peer_cancelled(Next()))
        end)
    end || Role <- [client, server]].

one_receive_budget_accepts_progress_before_its_deadline_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, Send, _Next) ->
            First = wire(Role, 2, false, <<1>>),
            Last = wire(Role, 0, true, <<2>>),
            need_ok(Send(<<First/binary, Last/binary>>)),
            Base = 'quic_core@diagnostics':monotonic_milliseconds(),
            Result = 'http3@websocket':receive_with_clock(Socket, fun() -> Base end),
            ?assert(binary_event(Result, <<1, 2>>))
        end)
    end || Role <- [client, server]].

closed_receive_does_not_consult_its_clock_test_() ->
    [fun() ->
        with_websocket(Role, 'http3@websocket':new(), fun(Socket, _Send, _Next) ->
            Closed = need_ok('http3@websocket':cancel(Socket)),
            Reads = atomics:new(1, []),
            Clock = fun() -> atomics:add_get(Reads, 1, 1) end,
            Result = 'http3@websocket':receive_with_clock(Closed, Clock),
            ?assert(Result =:= {error, already_closed}),
            ?assert(atomics:get(Reads, 1) =:= 0)
        end)
    end || Role <- [client, server]].

with_websocket(server, Configuration, Work) ->
    with_raw_client(Configuration, fun(_Connection, Stream, _Incoming, Socket) ->
        Work(Socket, fun(Bytes) -> 'http3@client':send_chunk(Stream, Bytes) end,
             fun() -> 'http3@client':next_event(Stream) end)
    end);
with_websocket(client, Configuration, Work) ->
    with_raw_server(Configuration, fun(_Connection, Incoming, Socket) ->
        Work(Socket, fun(Bytes) -> 'http3@server':send_chunk(Incoming, Bytes) end,
             fun() -> 'http3@server':next_event(Incoming) end)
    end).

small_configuration() ->
    need_ok('http3@websocket':with_limits('http3@websocket':new(), 32, 256)).

minimum_control_configuration() ->
    need_ok('http3@websocket':with_limits('http3@websocket':new(), 1, 139)).

with_raw_client(Work) ->
    with_raw_client('http3@websocket':new(), Work).

with_raw_client(Configuration, Work) ->
    with_connection(fun(Listener, Connection, Request) ->
        {Stream, Incoming, Socket} = accept_raw_client(Listener, Connection, Request, Configuration),
        Work(Connection, Stream, Incoming, Socket)
    end).

accept_raw_client(Listener, Connection, Request, Configuration) ->
    Headers = 'gleam@http@request':set_header(Request, <<"sec-websocket-version">>, <<"13">>),
    Stream = need_ok('http3@client':open_extended_connect(Connection, Headers, <<"websocket">>)),
    Incoming = need_ok('http3@server':accept(Listener)),
    Socket = need_ok('http3@websocket':accept(Configuration, Incoming)),
    Head = 'http3@client':next_event(Stream),
    ?assert(Head =:= {ok, {response, 200, []}}),
    {Stream, Incoming, Socket}.

with_raw_server(Work) ->
    with_raw_server('http3@websocket':new(), Work).

with_raw_server(Configuration, Work) ->
    with_connection(fun(Listener, Connection, Request) ->
        Task = http3_test_ffi:start_task(fun() ->
            'http3@websocket':connect(Configuration, Connection, Request)
        end),
        with_cleanup(fun() ->
            Incoming = need_ok('http3@server':accept(Listener)),
            need_ok('http3@server':send_response(Incoming, 200, [])),
            Socket = need_ok(http3_test_ffi:await_task(Task)),
            Work(Connection, Incoming, Socket)
        end, fun() ->
            %% A failed fixture must join its asynchronous handshake as well.
            stop_task(Task), {ok, nil}
        end)
    end).

with_connection(Work) ->
    with_connection_configuration(fun(Server) -> Server end, Work).

with_connection_configuration(Configure, Work) ->
    with_connection_configurations(Configure, fun(Client) -> Client end, Work).

with_client_connection_configuration(Configure, Work) ->
    with_connection_configurations(fun(Server) -> Server end, Configure, Work).

with_connection_configurations(ConfigureServer, ConfigureClient, Work) ->
    {Certificate, Key, Ca} = http3_test_ffi:server_credentials(),
    Deadlines = need_ok('http3@config':with_deadline('http3@config':default_deadlines(), operation, 750)),
    Server0 = need_ok('http3@server':new(Certificate, Key)),
    Server = ConfigureServer('http3@server':with_deadlines(Server0, Deadlines)),
    Listener = need_ok('http3@server':start(Server)),
    with_cleanup(fun() ->
        Port = need_ok('http3@server':port(Listener)),
        Client0 = need_ok('http3@client':with_ca_certificate('http3@client':new(), Ca)),
        Address = need_ok('http3@address':parse(<<"127.0.0.1">>)),
        Client1 = 'http3@client':with_connect_address(Client0, Address),
        Client = ConfigureClient('http3@client':with_deadlines(Client1, Deadlines)),
        Connection = need_ok('http3@client':connect(Client, <<"localhost">>, Port)),
        with_cleanup(fun() ->
            Request0 = 'gleam@http@request':set_host('gleam@http@request':new(), <<"localhost">>),
            Request1 = 'gleam@http@request':set_port(Request0, Port),
            Request2 = 'gleam@http@request':set_path(Request1, <<"/websocket-lifecycle">>),
            Request = 'gleam@http@request':set_body(Request2, nil),
            Work(Listener, Connection, Request)
        end, fun() -> 'http3@client':close_within(Connection, 5000) end)
    end, fun() -> 'http3@server':stop(Listener) end).

qlog_pattern_count(Directory, Pattern) ->
    Files = filelib:wildcard(filename:join(binary_to_list(Directory), "*.qlog")),
    lists:sum([case file:read_file(File) of
        {ok, Contents} -> length(binary:matches(Contents, Pattern));
        {error, _} -> 0
    end || File <- Files]).

reused(Listener, Connection, Request, Previous) ->
    Next = need_ok('http3@client':open_stream(Connection, Request)),
    need_ok('http3@client':finish(Next)),
    Incoming = need_ok('http3@server':accept(Listener)),
    ?assert('http3@server':next_event(Incoming) =:= {ok, 'end'}),
    need_ok('http3@server':respond(Incoming, 204, [], <<>>)),
    ?assert(response_status('http3@client':next_event(Next), 204)),
    ?assert('http3@client':next_event(Next) =:= {ok, 'end'}),
    need_ok('http3@server':await_response_completion(Incoming)),
    _ = need_ok('http3@server':request_state_stats(Previous)),
    Stats = need_ok('http3@server':request_state_stats(Previous)),
    ?assert(element(1, Stats) =:= 0),
    ?assert(element(7, Stats) =:= 0),
    ClientStats = need_ok('http3@client':resource_state_stats(Connection)),
    ?assert(element(1, ClientStats) =:= 0),
    ?assert(element(7, ClientStats) =:= 0).

client_reused(Listener, Connection, Request, RawPeerRequest) ->
    PeerStats = await_server_stream_retirement(RawPeerRequest, 100),
    ?assert(element(1, PeerStats) =:= 0),
    ?assert(element(7, PeerStats) =:= 0),
    %% The automatic peer-stop path already owns cleanup. The stale public
    %% handle must remain idempotent and cannot create a second release.
    need_ok('http3@server':cancel(RawPeerRequest)),
    Next = need_ok('http3@client':open_stream(Connection, Request)),
    need_ok('http3@client':finish(Next)),
    Incoming = need_ok('http3@server':accept(Listener)),
    ?assert('http3@server':next_event(Incoming) =:= {ok, 'end'}),
    need_ok('http3@server':respond(Incoming, 204, [], <<>>)),
    ?assert(response_status('http3@client':next_event(Next), 204)),
    ?assert('http3@client':next_event(Next) =:= {ok, 'end'}),
    need_ok('http3@server':await_response_completion(Incoming)),
    ClientStats = need_ok('http3@client':resource_state_stats(Connection)),
    ?assert(element(1, ClientStats) =:= 0),
    ?assert(element(7, ClientStats) =:= 0).

await_server_stream_retirement(Request, Remaining) ->
    Stats = need_ok('http3@server':request_state_stats(Request)),
    case element(1, Stats) =:= 0 andalso element(7, Stats) =:= 0 of
        true -> Stats;
        false when Remaining > 0 ->
            timer:sleep(5),
            await_server_stream_retirement(Request, Remaining - 1);
        false -> Stats
    end.

with_cleanup(Work, Cleanup) ->
    Outcome = try {ok, Work()} catch C:R:S -> {error, C, R, S} end,
    Cleaned = try is_ok(Cleanup()) catch _:_ -> false end,
    case Outcome of
        {error, Class, Reason, Stack} ->
            observe(cleanup_after_failure, case Cleaned of true -> joined; false -> cleanup_failed end),
            erlang:raise(Class, Reason, Stack);
        {ok, Value} ->
            case Cleaned of true -> Value; false -> error(websocket_fixture_cleanup_failed) end
    end.

stop_task({http3_test_task, Pid, Monitor, Ref}) ->
    Joined = erlang:monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Joined, process, Pid, _} -> ok
    after 1000 -> error(websocket_fixture_task_not_joined) end,
    erlang:demonitor(Monitor, [flush]),
    receive {Ref, task_result, _} -> ok after 0 -> ok end.

%% Test wire bytes are encoded directly from RFC 6455, independently of the
%% implementation's encoder. Assertions receive booleans, never socket state.
masked(Opcode, Fin, Payload) ->
    First = Opcode bor case Fin of true -> 16#80; false -> 0 end,
    Mask = <<1, 2, 3, 4>>,
    Encoded = << <<(B bxor binary:at(Mask, I rem 4))>> ||
        {B, I} <- lists:zip(binary_to_list(Payload), lists:seq(0, byte_size(Payload) - 1)) >>,
    Length = wire_length(1, byte_size(Payload)),
    <<First, Length/binary, Mask/binary, Encoded/binary>>.

wire(server, Opcode, Fin, Payload) -> masked(Opcode, Fin, Payload);
wire(client, Opcode, Fin, Payload) ->
    First = Opcode bor case Fin of true -> 16#80; false -> 0 end,
    Length = wire_length(0, byte_size(Payload)),
    <<First, Length/binary, Payload/binary>>.

wire_length(Masked, Length) when Length =< 125 -> <<Masked:1, Length:7>>;
wire_length(Masked, Length) when Length =< 65535 -> <<Masked:1, 126:7, Length:16>>;
wire_length(Masked, Length) -> <<Masked:1, 127:7, Length:64>>.

opposite(client) -> server;
opposite(server) -> client.

wire_event({ok, {data, Bytes}}, client, Opcode, Expected) ->
    Bytes =:= wire(client, Opcode, true, Expected);
wire_event({ok, {data, <<First, 1:1, Length:7, Mask:4/binary, Payload/binary>>}}, server, Opcode, Expected)
  when Length =< 125, byte_size(Payload) =:= Length ->
    Decoded = << <<(B bxor binary:at(Mask, I rem 4))>> ||
        {B, I} <- lists:zip(binary_to_list(Payload), lists:seq(0, Length - 1)) >>,
    First =:= (16#80 bor Opcode) andalso Decoded =:= Expected;
wire_event(_, _, _, _) -> false.

need_ok({ok, Value}) -> Value;
need_ok(_) -> error(websocket_fixture_operation_failed).
is_ok({ok, _}) -> true;
is_ok(_) -> false.
close_event({ok, {_, {close_received, none, <<>>}}}) -> true;
close_event(_) -> false.
text_event({ok, {_, {text_message, Value}}}, Expected) -> Value =:= Expected;
text_event(_, _) -> false.
ping_event({ok, {_, {ping, Value}}}, Expected) -> Value =:= Expected;
ping_event(_, _) -> false.
binary_event({ok, {_, {binary_message, Value}}}, Expected) -> Value =:= Expected;
binary_event(_, _) -> false.
websocket_timeout(client, {error, {client_failure, {failure, {timeout, operation}}}}) -> true;
websocket_timeout(server, {error, {server_failure, {failure, {timeout, operation}}}}) -> true;
websocket_timeout(_, _) -> false.
response_status({ok, {response, Status, _}}, Expected) -> Status =:= Expected;
response_status(_, _) -> false.
peer_cancelled({error, {failure, {closed, peer, {some, 16#10c}}}}) -> true;
peer_cancelled(_) -> false.
masked_empty_close({ok, {data, <<16#88, 16#80, _:32>>}}) -> true;
masked_empty_close(_) -> false.

assert_failure_disposition(client, Failure, Peer, Next) ->
    Code = failure_close_code(Failure),
    ?assert(wire_event(Peer, server, 8, <<Code:16>>)),
    ?assertEqual(orderly_fin, peer_event(Next()));
assert_failure_disposition(server, Failure, Peer, Next) ->
    Code = failure_close_code(Failure),
    ?assert(wire_event(Peer, client, 8, <<Code:16>>)),
    ?assertEqual(orderly_fin, peer_event(Next())).

failure_close_code(frame_error) -> 1002;
failure_close_code(protocol_violation) -> 1002;
failure_close_code(invalid_close) -> 1002;
failure_close_code(invalid_utf8) -> 1007;
failure_close_code({message_too_large, _}) -> 1009.

%% Optional isolated-runner observations retain only fixed local categories.
observe(Key, Category) ->
    case whereis(websocket_test_observer) of
        undefined -> ok;
        Owner -> Owner ! {websocket_observation, Key, Category}, ok
    end.
peer_event({ok, 'end'}) -> orderly_fin;
peer_event({ok, {data, _}}) -> data;
peer_event({error, {failure, {timeout, operation}}}) -> operation_timeout;
peer_event({error, {failure, {http3, local, none}}}) -> local_http3_failure;
peer_event(Value) -> case peer_cancelled(Value) of true -> request_cancelled; false -> other end.
websocket_event({error, already_closed}) -> locally_closed;
websocket_event({error, {client_failure, _}}) -> client_failure;
websocket_event(_) -> other.
