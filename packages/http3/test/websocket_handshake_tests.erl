%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(websocket_handshake_tests).
-include_lib("eunit/include/eunit.hrl").

%% The isolated wire-control runner suppresses only the core reset callback's
%% STOP_SENDING frame. The peer still sends a real RESET_STREAM over UDP.
client_reset_only_peer_observes_request_abort_test() ->
    {Certificate, Key, Ca} = http3_test_ffi:server_credentials(),
    CoreDeadline = need_ok('quic_core@config':with_deadline(
        'quic_core@config':default_deadlines(), operation, 1000)),
    CoreConfig = need_ok('quic_core@server':new(Certificate, Key, <<"h3">>)),
    Listener = need_ok('quic_core@server':start('quic_core@server':with_deadlines(
        'quic_core@server':with_address_family(CoreConfig, ipv4), CoreDeadline))),
    with_cleanup(fun() ->
        Port = need_ok('quic_core@server':port(Listener)),
        Parent = self(), Ref = make_ref(),
        with_task(fun() -> reset_only_server(Listener, Parent, Ref) end, fun(Task) ->
            Deadlines = need_ok('http3@config':with_deadline('http3@config':default_deadlines(), operation, 1000)),
            Limits = need_ok('http3@config':with_limit('http3@config':default_limits(), bidirectional_streams, 2)),
            Address = need_ok('http3@address':parse(<<"127.0.0.1">>)),
            Client0 = need_ok('http3@client':with_ca_certificate('http3@client':new(), Ca)),
            Client = 'http3@client':with_limits('http3@client':with_deadlines(
                'http3@client':with_connect_address(Client0, Address), Deadlines), Limits),
            Connection = need_ok('http3@client':connect(Client, <<"localhost">>, Port)),
            Owner = connection_worker(Connection), Monitor = monitor(process, Owner),
            with_cleanup(fun() ->
                Request = 'gleam@http@request':set_body('gleam@http@request':set_port(
                    'gleam@http@request':set_host('gleam@http@request':new(), <<"localhost">>), Port), nil),
                lists:foreach(fun(Code) ->
                    Opened = 'http3@client':open_stream(Connection, Request),
                    ?assert(is_ok(Opened)), Stream = need_ok(Opened),
                    ?assert(response_status('http3@client':next_event(Stream), 200)),
                    receive {Ref, ready, Peer} -> Peer ! {Ref, reset}
                    after 1000 -> error(raw_peer_head_barrier_timeout) end,
                    Result = 'http3@client':next_event(Stream),
                    ?assert(Result =:= {error, {failure, {closed, peer, {some, Code}}}}),
                    Observed = receive {Ref, request_aborted, Value} -> Value
                        after 1500 -> false end,
                    observe(reset_only_request_abort, case Observed of true -> observed; false -> missing end),
                    ?assert(Observed),
                    Stats = need_ok('http3@client':resource_state_stats(Connection)),
                    ?assert(element(1, Stats) =:= 0 andalso element(3, Stats) =< 6
                        andalso element(6, Stats) =< 3 andalso element(7, Stats) =:= 0)
                end, [16#10c, 16#123, 16#10c, 16#123]),
                Last = need_ok('http3@client':open_stream(Connection, Request)),
                need_ok('http3@client':finish(Last)),
                ?assert(response_status('http3@client':next_event(Last), 200)),
                ?assert('http3@client':next_event(Last) =:= {ok, 'end'}),
                receive {Ref, completed, Peer} -> Peer ! {Ref, release}
                after 1000 -> error(raw_peer_completion_barrier_timeout) end,
                ?assert(is_ok(await(Task)))
            end, fun() ->
                Closed = 'http3@client':close(Connection),
                receive {'DOWN', Monitor, process, Owner, _} -> observe(connection_owner, joined)
                after 1500 -> error(raw_peer_client_owner_not_joined) end,
                Closed
            end)
        end)
    end, fun() -> 'quic_core@server':stop(Listener) end).

reset_only_server(Listener, Parent, Ref) ->
    Connection = need_ok('quic_core@server':accept(Listener)),
    with_cleanup(fun() ->
        lists:foreach(fun(Preface) ->
            Control = need_ok('quic_core@server':open_unidirectional(Connection)),
            need_ok('quic_core@server':send(Control, Preface))
        end, [<<0, 4, 0>>, <<2>>, <<3>>]),
        lists:foreach(fun(Code) ->
            Stream = raw_peer_request(Connection, 4),
            ?assert(raw_request_head('quic_core@server':receive_next(Stream, 65536))),
            need_ok('quic_core@server':send(Stream, <<1, 3, 0, 0, 16#d9>>)),
            Parent ! {Ref, ready, self()},
            receive {Ref, reset} -> ok after 1000 -> error(raw_peer_reset_barrier_timeout) end,
            need_ok('quic_core@server':reset(Stream, Code)),
            Received = 'quic_core@server':receive_next(Stream, 65536),
            %% The ordinary core reset also sends STOP_SENDING, whose lawful
            %% automatic RESET can retain its application code. 16#123 is a
            %% deliberate QUIC-varint control which distinguishes that echo
            %% from the adapter's H3_REQUEST_CANCELLED (16#10c). The isolated
            %% RESET-only probe suppresses STOP_SENDING and requires 16#10c.
            ResetCode = case Received of
                {ok, {reset, 16#10c}} -> request_cancelled;
                {ok, {reset, Code}} -> echoed_peer;
                _ -> missing
            end,
            observe(reset_only_request_code, ResetCode),
            Observed = case whereis(websocket_reset_only_wire_control) of
                undefined -> ResetCode =/= missing;
                _ -> ResetCode =:= request_cancelled
            end,
            Parent ! {Ref, request_aborted, Observed}
        end, [16#10c, 16#123, 16#10c, 16#123]),
        Last = raw_peer_request(Connection, 4),
        ?assert(raw_peer_finished(Last, 4)),
        need_ok('quic_core@server':send_and_finish(Last, <<1, 3, 0, 0, 16#d9>>)),
        ?assert('quic_core@server':await_send_completion(Last, 1000) =:= {ok, send_acknowledged}),
        Parent ! {Ref, completed, self()},
        receive {Ref, release} -> {ok, nil} after 1000 -> error(raw_peer_release_timeout) end
    end, fun() -> 'quic_core@server':close(Connection) end).

raw_peer_request(Connection, Remaining) when Remaining > 0 ->
    case need_ok('quic_core@server':accept_stream_next(Connection)) of
        {incoming_stream, Stream, bidirectional} -> Stream;
        _ -> raw_peer_request(Connection, Remaining - 1)
    end;
raw_peer_request(_, _) -> error(raw_peer_request_limit).
raw_request_head({ok, {data, Bytes, false}}) -> byte_size(Bytes) > 0;
raw_request_head(_) -> false.
raw_peer_finished(_, 0) -> false;
raw_peer_finished(Stream, Remaining) ->
    case 'quic_core@server':receive_next(Stream, 65536) of
        {ok, finished} -> true;
        {ok, {data, _, true}} -> true;
        {ok, {data, _, false}} -> raw_peer_finished(Stream, Remaining - 1);
        _ -> false
    end.

%% RFC 9220 section 3 imports RFC 8441 section 5, which retains RFC 6455
%% sections 4.1, 4.2.2, 4.3 and 11.3.4 subprotocol negotiation. Assertions
%% below project live connection results to booleans and fixed categories.
repeated_half_close_cancellation_reuses_two_transaction_limit_test_() ->
    [?_test(begin
        Limits = need_ok('http3@config':with_limit('http3@config':default_limits(), bidirectional_streams, 2)),
        with_connection_limits(Limits, fun(Listener, Connection, Request) ->
            Previous = lists:foldl(fun(_, _) ->
                Stream = open_raw(Connection, with_headers(Request, version(<<"12">>))),
                Incoming = need_ok('http3@server':accept(Listener)),
                case Mode of
                    version_refusal ->
                        ?assert('http3@websocket':accept('http3@websocket':new(), Incoming) =:= {error, unsupported_version});
                    client_cancellation ->
                        need_ok('http3@server':respond(Incoming, 400, [], <<>>)),
                        need_ok('http3@server':await_response_completion(Incoming))
                end,
                ?assert(response_status('http3@client':next_event(Stream), 400)),
                ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
                ?assert('http3@client':cancel(Stream) =:= {ok, cancelled}),
                case Mode of
                    client_cancellation -> ?assert(peer_cancelled('http3@server':next_event(Incoming)));
                    version_refusal -> ok
                end,
                ?assert(element(1, need_ok('http3@server':request_state_stats(Incoming))) =:= 0),
                ?assert(client_streams(Connection) =:= 0),
                observe(repeated_cancellation, admitted_and_reclaimed),
                Incoming
            end, nil, lists:seq(1, 4)),
            reused(Listener, Connection, Request, Previous)
        end)
    end) || Mode <- [version_refusal, client_cancellation]].

repeated_peer_reset_reuses_two_transaction_limit_test_() ->
    [?_test(begin
        Limits = need_ok('http3@config':with_limit('http3@config':default_limits(), bidirectional_streams, 2)),
        with_connection_limits(Limits, fun(Listener, Connection, Request) ->
            Previous = lists:foldl(fun(_, _) ->
                Opened = 'http3@client':open_extended_connect(Connection,
                    with_headers(Request, version(<<"13">>)), <<"websocket">>),
                ?assert(is_ok(Opened)),
                Stream = need_ok(Opened),
                Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':send_response(Incoming, 200, [])),
                ?assert(response_status('http3@client':next_event(Stream), 200)),
                case Initiator of
                    client ->
                        need_ok('http3@client':cancel(Stream)),
                        ?assert(peer_cancelled('http3@server':next_event(Incoming)));
                    server ->
                        need_ok('http3@server':cancel(Incoming)),
                        ?assert(peer_cancelled('http3@client':next_event(Stream)))
                end,
                ?assert(client_streams(Connection) =:= 0),
                ?assert(element(1, need_ok('http3@server':request_state_stats(Incoming))) =:= 0),
                observe(repeated_peer_reset, Initiator),
                Incoming
            end, nil, lists:seq(1, 4)),
            reused(Listener, Connection, Request, Previous)
        end)
    end) || Initiator <- [client, server]].

client_subprotocol_response_test_() ->
    [?_test(client_response(Offer, Reply, Accepted)) ||
        {Offer, Reply, Accepted} <- response_cases()].

server_subprotocol_selection_test_() ->
    [?_test(server_selection(Offer, Reply, Accepted)) ||
        {Offer, Reply, Accepted} <- response_cases()].

response_cases() ->
    [{[], [], true},
     {protocol(<<"chat, superchat">>), [], true},
     {protocol(<<"chat, superchat">>), protocol(<<"superchat">>), true},
     {protocol(<<"chat">>) ++ protocol(<<"superchat">>), protocol(<<"superchat">>), true},
     {protocol(<<"Chat,chat">>), protocol(<<"Chat">>), true},
     {protocol(<<"chat,\t superchat">>), protocol(<<"superchat">>), true},
     {protocol(<<",,chat,,superchat,,">>), protocol(<<"chat">>), true},
     {[], protocol(<<"chat">>), false},
     {protocol(<<"chat">>), protocol(<<"unrequested">>), false},
     {protocol(<<"Chat">>), protocol(<<"chat">>), false},
     {protocol(<<"chat">>), protocol(<<>>), false},
     {protocol(<<"chat, superchat">>), protocol(<<"chat, superchat">>), false},
     {protocol(<<"chat">>), protocol(<<"chat">>) ++ protocol(<<"chat">>), false},
     {protocol(<<"chat,superchat">>), protocol(<<"chat">>) ++ protocol(<<"superchat">>), false},
     {protocol(<<"chat">>), protocol(<<"\"chat\"">>), false},
     {protocol(<<"chat">>), protocol(<<"chat other">>), false}].

server_invalid_request_subprotocol_test_() ->
    [?_test(server_invalid_offer(Offer)) || Offer <- invalid_offers()].

server_invalid_request_mapping_gets_http_error_and_reclaims_test_() ->
    [?_test(server_invalid_mapping(Kind, Status)) ||
        {Kind, Status} <- [{regular_get, 400}, {unknown_protocol, 501}]].

server_local_response_validation_precedes_peer_rejection_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = need_ok('http3@client':open_extended_connect(
            Connection, Request, <<"unknown-protocol">>)),
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept_with_headers(
            'http3@websocket':new(), Incoming,
            [{<<"sec-websocket-key">>, <<"local-invalid-response">>}]),
        ?assert(Result =:= {error, invalid_handshake}),
        need_ok('http3@server':respond(Incoming, 418, [], <<>>)),
        ?assert(response_status('http3@client':next_event(Stream), 418)),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
        need_ok('http3@server':await_response_completion(Incoming)),
        need_ok('http3@server':cancel(Incoming)),
        need_ok('http3@client':cancel(Stream)),
        reused(Listener, Connection, Request, Incoming)
    end).

client_invalid_request_subprotocol_test_() ->
    [?_test(with_connection(fun(_Listener, Connection, Request) ->
        Result = 'http3@websocket':connect('http3@websocket':new(), Connection,
                                          with_headers(Request, Offer)),
        observe(client_invalid_offer, result_category(Result)),
        ?assert(Result =:= {error, invalid_handshake}),
        ?assert(client_streams(Connection) =:= 0)
    end)) || Offer <- invalid_offers()].

invalid_offers() ->
    [protocol(<<>>), protocol(<<"chat,chat">>),
     protocol(<<"chat">>) ++ protocol(<<"chat">>), protocol(<<"\"chat\"">>),
     protocol(<<"chat other">>), protocol(<<"caf", 16#c3, 16#a9>>)].

server_version_test_() ->
    [?_test(with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, Versions)),
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        ?assert(Result =:= {error, unsupported_version}),
        ?assert(version_advertised('http3@client':next_event(Stream))),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
        ?assert(element(1, need_ok('http3@server':request_state_stats(Incoming))) =:= 0),
        ?assert('http3@client':cancel(Stream) =:= {ok, cancelled}),
        reused(Listener, Connection, Request, Incoming)
    end)) || Versions <- [[], version(<<"12">>), version(<<"013">>),
        version(<<"13,12">>), version(<<"13">>) ++ version(<<"13">>) ]].

client_supplies_one_current_version_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection,
            with_headers(Request, version(<<"12">>) ++ version(<<"8">>))) end,
            fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                Values = [V || {<<"sec-websocket-version">>, V} <- 'http3@server':headers(Incoming)],
                ?assert(Values =:= [<<"13">>]),
                need_ok('http3@server':send_response(Incoming, 200, [])),
                Socket = need_ok(await(Task)),
                need_ok('http3@websocket':cancel(Socket)),
                ?assert(peer_cancelled('http3@server':next_event(Incoming)))
            end)
    end).

server_version_does_not_trim_non_ascii_whitespace_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Headers = version(<<16#c2, 16#a0, "13", 16#c2, 16#a0>>),
        Stream = open_raw(Connection, with_headers(Request, Headers)),
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        observe(non_ascii_version, result_category(Result)),
        ?assert(Result =:= {error, unsupported_version}),
        ?assert(version_advertised('http3@client':next_event(Stream))),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'})
    end).

server_unsupported_version_advertises_and_reclaims_unfinished_request_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, version(<<"12">>))),
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        ?assert(Result =:= {error, unsupported_version}),
        Head = 'http3@client':next_event(Stream),
        observe(version_response, response_category(Head)),
        ?assert(version_advertised(Head)),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
        %% Deliberately never call client.finish(Stream). Version refusal
        %% must reclaim the peer's still-open request direction itself.
        ?assert(element(1, need_ok('http3@server':request_state_stats(Incoming))) =:= 0),
        ?assert('http3@client':cancel(Stream) =:= {ok, cancelled}),
        reused(Listener, Connection, Request, Incoming)
    end).

client_cancel_after_response_fin_reclaims_unfinished_request_test_() ->
    [?_test(with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, version(<<"13">>))),
        Incoming = need_ok('http3@server':accept(Listener)),
        need_ok('http3@server':respond(Incoming, 400, [], <<>>)),
        need_ok('http3@server':await_response_completion(Incoming)),
        case PeerCancels of
            true -> need_ok('http3@server':cancel(Incoming));
            false -> ok
        end,
        ?assert(response_status('http3@client':next_event(Stream), 400)),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
        ?assert(client_streams(Connection) =:= 1),
        Cancelled = 'http3@client':cancel(Stream),
        observe(half_closed_cancel, cancellation_category(Cancelled)),
        ?assert(Cancelled =:= {ok, cancelled}),
        ?assert('http3@client':cancel(Stream) =:= {ok, already_cancelled}),
        ?assert(client_streams(Connection) =:= 0),
        case PeerCancels of
            false -> ?assert(peer_cancelled('http3@server':next_event(Incoming)));
            true -> ok
        end,
        reused(Listener, Connection, Request, Incoming)
    end)) || PeerCancels <- [false, true]].

server_unsupported_version_after_peer_reset_preserves_send_failure_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, version(<<"12">>))),
        Incoming = need_ok('http3@server':accept(Listener)),
        need_ok('http3@client':cancel(Stream)),
        ?assert(peer_cancelled('http3@server':next_event(Incoming))),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        observe(version_send_failure, result_category(Result)),
        ?assert(is_server_failure(Result)),
        reused(Listener, Connection, Request, Incoming)
    end).

client_accepts_successful_connect_status_test_() ->
    [?_test(with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection, Request) end,
            fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':send_response(Incoming, Status, [])),
                case Status of
                    204 -> need_ok('http3@server':finish_response(Incoming));
                    _ -> ok
                end,
                Result = await(Task),
                observe(success_status, result_category(Result)),
                ?assert(is_ok(Result)),
                Socket = need_ok(Result),
                case Status of
                    204 -> ok;
                    _ ->
                        need_ok('http3@server':send_chunk(Incoming, <<16#81, 2, "ok">>)),
                        ?assert(text_event('http3@websocket':'receive'(Socket)))
                end,
                need_ok('http3@websocket':cancel(Socket)),
                ?assert(peer_cancelled('http3@server':next_event(Incoming))),
                reused(Listener, Connection, Request, Incoming)
            end)
    end)) || Status <- [200, 201, 202, 204, 299]].

client_subprotocol_parsing_budget_test_() ->
    [?_test(with_connection(fun(_Listener, Connection, Request) ->
        Result = 'http3@websocket':connect('http3@websocket':new(), Connection,
            with_headers(Request, Offer)),
        ?assert(Result =:= {error, invalid_handshake}),
        ?assert(client_streams(Connection) =:= 0)
    end)) || Offer <- [protocol(binary:copy(<<"x">>, 65536)),
        protocol(<<"chat">>) ++ lists:duplicate(65532, {<<"sec-websocket-protocol">>, <<>>})]].

client_subprotocol_at_parsing_budget_reaches_transport_test() ->
    with_connection(fun(_Listener, Connection, Request) ->
        Result = 'http3@websocket':connect('http3@websocket':new(), Connection,
            with_headers(Request, protocol(binary:copy(<<"x">>, 65535)))),
        %% The 65,535-byte token plus one field is within the parser budget.
        %% This fixture's smaller HTTP field-section bound rejects it later.
        ?assert(is_client_failure(Result)),
        ?assert(client_streams(Connection) =:= 0)
    end).

nonce_and_extension_profile_test_() ->
    [?_test(profile_field(Role, Field)) || Role <- [client_input, server_input, client_response, server_response],
        Field <- [<<"sec-websocket-key">>, <<"sec-websocket-accept">>, <<"sec-websocket-extensions">>]].

client_informational_progress_does_not_renew_deadline_test_() ->
    [?_test(with_connection(fun(Listener, Connection, Request) ->
        Base = 'quic_core@diagnostics':monotonic_milliseconds(),
        Reads = atomics:new(1, []),
        Release = make_ref(),
        Clock = fun() ->
            N = atomics:add_get(Reads, 1, 1),
            case N of
                1 -> receive {handshake_clock_release, Release} -> ok
                    after 1000 -> error(handshake_clock_barrier_timeout) end;
                _ -> ok
            end,
            case N =< ReadsBeforeExpiry of true -> Base; false -> Base + 750 end
        end,
        with_task(fun() -> 'http3@websocket':connect_with_clock(
            'http3@websocket':new(), Connection, Request, Clock) end,
            fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                lists:foreach(fun(_) -> need_ok('http3@server':send_informational(Incoming, 103, [])) end,
                    lists:seq(1, 6)),
                need_ok('http3@server':send_response(Incoming, 200, [])),
                element(2, Task) ! {handshake_clock_release, Release},
                Result = await(Task),
                observe(informational_deadline, result_category(Result)),
                ?assert(Result =:= {error, {client_failure, {failure, {timeout, operation}}}}),
                ?assert(atomics:get(Reads, 1) > ReadsBeforeExpiry),
                ?assert(peer_cancelled('http3@server':next_event(Incoming))),
                reused(Listener, Connection, Request, Incoming)
            end)
    end)) || ReadsBeforeExpiry <- [2, 4, 12, 14]].

client_informational_progress_within_deadline_succeeds_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Base = 'quic_core@diagnostics':monotonic_milliseconds(),
        with_task(fun() -> 'http3@websocket':connect_with_clock(
            'http3@websocket':new(), Connection, Request, fun() -> Base end) end,
            fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                lists:foreach(fun(_) -> need_ok('http3@server':send_informational(Incoming, 103, [])) end,
                    lists:seq(1, 6)),
                need_ok('http3@server':send_response(Incoming, 200, [])),
                Socket = need_ok(await(Task)),
                need_ok('http3@websocket':cancel(Socket)),
                ?assert(peer_cancelled('http3@server':next_event(Incoming))),
                reused(Listener, Connection, Request, Incoming)
            end)
    end).

invalid_handshake_does_not_consult_clock_test() ->
    with_connection(fun(_Listener, Connection, Request) ->
        Reads = atomics:new(1, []),
        Clock = fun() -> atomics:add_get(Reads, 1, 1) end,
        Result = 'http3@websocket':connect_with_clock('http3@websocket':new(), Connection,
            with_headers(Request, protocol(<<"chat,chat">>)), Clock),
        ?assert(Result =:= {error, invalid_handshake}),
        ?assert(atomics:get(Reads, 1) =:= 0),
        ?assert(client_streams(Connection) =:= 0)
    end).

client_informational_then_final_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection,
            with_headers(Request, protocol(<<"chat">>))) end, fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':send_informational(Incoming, 103, protocol(<<"not-selected">>))),
                need_ok('http3@server':send_response(Incoming, 200, protocol(<<"chat">>))),
                Socket = need_ok(await(Task)),
                need_ok('http3@websocket':cancel(Socket)),
                ?assert(peer_cancelled('http3@server':next_event(Incoming)))
        end)
    end).

client_non_success_status_cancels_test_() ->
    [?_test(with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection, Request) end,
            fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':send_response(Incoming, Status, [])),
                ?assert(await(Task) =:= {error, {unexpected_status, Status}}),
                ?assert(peer_cancelled('http3@server':next_event(Incoming))),
                reused(Listener, Connection, Request, Incoming)
            end)
    end)) || Status <- [302, 400, 401, 403, 404, 500]].

client_peer_reset_during_handshake_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection, Request) end,
            fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':cancel(Incoming)),
                Result = await(Task),
                ?assert(Result =:= {error, {client_failure, {failure, {closed, peer, {some, 16#10c}}}}}),
                reused(Listener, Connection, Request, Incoming)
            end)
    end).

client_peer_shutdown_during_handshake_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection, Request) end,
            fun(Task) ->
                _Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':stop(Listener)),
                Result = await(Task),
                observe(peer_shutdown, result_category(Result)),
                ?assert(is_client_failure(Result))
            end)
    end).

server_accept_after_peer_reset_test() ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, version(<<"13">>))),
        Incoming = need_ok('http3@server':accept(Listener)),
        need_ok('http3@client':cancel(Stream)),
        ?assert(peer_cancelled('http3@server':next_event(Incoming))),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        ?assert(is_server_failure(Result)),
        reused(Listener, Connection, Request, Incoming)
    end).

client_response(Offer, Reply, Accepted) ->
    with_connection(fun(Listener, Connection, Request) ->
        with_task(fun() -> 'http3@websocket':connect('http3@websocket':new(), Connection,
            with_headers(Request, Offer)) end, fun(Task) ->
                Incoming = need_ok('http3@server':accept(Listener)),
                need_ok('http3@server':send_response(Incoming, 200, Reply)),
                Result = await(Task),
                observe(client_response, result_category(Result)),
                ?assert(is_ok(Result) =:= Accepted),
                case Result of
                    {ok, Socket} -> need_ok('http3@websocket':cancel(Socket));
                    _ -> ?assert(Result =:= {error, invalid_handshake})
                end,
                ?assert(peer_cancelled('http3@server':next_event(Incoming))),
                reused(Listener, Connection, Request, Incoming)
        end)
    end).

server_selection(Offer, Reply, Accepted) ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, version(<<"13">>) ++ Offer)),
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept_with_headers('http3@websocket':new(), Incoming, Reply),
        observe(server_response, result_category(Result)),
        ?assert(is_ok(Result) =:= Accepted),
        case Result of
            {ok, Socket} ->
                ?assert(response_status('http3@client':next_event(Stream), 200)),
                need_ok('http3@websocket':cancel(Socket));
            _ ->
                ?assert(Result =:= {error, invalid_handshake}),
                %% Invalid application response headers have not committed a
                %% response. The application may still send a normal refusal.
                need_ok('http3@server':send_response(Incoming, 400, [])),
                ?assert(response_status('http3@client':next_event(Stream), 400)),
                need_ok('http3@server':cancel(Incoming))
        end,
        ?assert(peer_cancelled('http3@client':next_event(Stream))),
        reused(Listener, Connection, Request, Incoming)
    end).

server_invalid_offer(Offer) ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = open_raw(Connection, with_headers(Request, version(<<"13">>) ++ Offer)),
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        observe(server_invalid_offer, result_category(Result)),
        ?assert(Result =:= {error, invalid_handshake}),
        ?assert(response_status('http3@client':next_event(Stream), 400)),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
        ?assert(element(1, need_ok('http3@server':request_state_stats(Incoming))) =:= 0),
        ?assert('http3@client':cancel(Stream) =:= {ok, cancelled}),
        reused(Listener, Connection, Request, Incoming)
    end).

server_invalid_mapping(Kind, Status) ->
    with_connection(fun(Listener, Connection, Request) ->
        Stream = case Kind of
            regular_get -> need_ok('http3@client':open_stream(Connection, Request));
            unknown_protocol -> need_ok('http3@client':open_extended_connect(
                Connection, Request, <<"unknown-protocol">>))
        end,
        Incoming = need_ok('http3@server':accept(Listener)),
        Result = 'http3@websocket':accept('http3@websocket':new(), Incoming),
        ?assert(Result =:= {error, invalid_handshake}),
        ?assert(response_status('http3@client':next_event(Stream), Status)),
        ?assert('http3@client':next_event(Stream) =:= {ok, 'end'}),
        ?assert(element(1, need_ok('http3@server':request_state_stats(Incoming))) =:= 0),
        ?assert('http3@client':cancel(Stream) =:= {ok, cancelled}),
        reused(Listener, Connection, Request, Incoming)
    end).

profile_field(client_input, Field) ->
    with_connection(fun(_Listener, Connection, Request) ->
        Result = 'http3@websocket':connect('http3@websocket':new(), Connection,
            with_headers(Request, [{Field, <<"private-handshake-marker">>}])),
        ?assert(Result =:= {error, invalid_handshake}),
        ?assert(client_streams(Connection) =:= 0)
    end);
profile_field(server_input, Field) -> server_invalid_offer([{Field, <<"private-handshake-marker">>}]);
profile_field(client_response, Field) -> client_response([], [{Field, <<"private-handshake-marker">>}], false);
profile_field(server_response, Field) -> server_selection([], [{Field, <<"private-handshake-marker">>}], false).

protocol(Value) -> [{<<"sec-websocket-protocol">>, Value}].
version(Value) -> [{<<"sec-websocket-version">>, Value}].
with_headers(Request, Headers) ->
    lists:foldr(fun({Name, Value}, Acc) -> 'gleam@http@request':prepend_header(Acc, Name, Value) end,
                Request, Headers).
open_raw(Connection, Request) -> need_ok('http3@client':open_extended_connect(Connection, Request, <<"websocket">>)).

reused(Listener, Connection, Request, Previous) ->
    Next = need_ok('http3@client':open_stream(Connection, Request)),
    need_ok('http3@client':finish(Next)),
    Incoming = need_ok('http3@server':accept(Listener)),
    ?assert('http3@server':next_event(Incoming) =:= {ok, 'end'}),
    need_ok('http3@server':respond(Incoming, 204, [], <<>>)),
    ?assert(response_status('http3@client':next_event(Next), 204)),
    ?assert('http3@client':next_event(Next) =:= {ok, 'end'}),
    need_ok('http3@server':await_response_completion(Incoming)),
    %% The completion observer is separate from the connection actor. Join
    %% that actor's next command turn before observing terminal retirement.
    _ = need_ok('http3@server':request_state_stats(Previous)),
    ServerStats = need_ok('http3@server':request_state_stats(Previous)),
    ?assert(element(1, ServerStats) =:= 0),
    observe(server_transaction, case element(7, ServerStats) of 0 -> empty; _ -> retained end),
    ?assert(element(7, ServerStats) =:= 0),
    ?assert(element(3, ServerStats) =< 6),
    ?assert(element(6, ServerStats) =< 3),
    ?assert(element(8, ServerStats) =:= 0),
    ?assert(element(9, ServerStats) =:= 0),
    Stats = need_ok('http3@client':resource_state_stats(Connection)),
    ?assert(element(1, Stats) =:= 0),
    %% The six connection-level control/QPACK stream handles may remain.
    %% There is no request transaction, blocked stream, or push to retain.
    ?assert(element(3, Stats) =< 6),
    ?assert(element(6, Stats) =< 3),
    ?assert(element(7, Stats) =:= 0),
    ?assert(element(8, Stats) =:= 0),
    ?assert(element(9, Stats) =:= 0).

client_streams(Connection) -> element(1, need_ok('http3@client':resource_state_stats(Connection))).

with_connection(Work) ->
    with_connection_limits('http3@config':default_limits(), Work).

with_connection_limits(Limits, Work) ->
    {Certificate, Key, Ca} = http3_test_ffi:server_credentials(),
    Deadlines = need_ok('http3@config':with_deadline('http3@config':default_deadlines(), operation, 750)),
    Server = need_ok('http3@server':new(Certificate, Key)),
    Listener = need_ok('http3@server':start('http3@server':with_limits(
        'http3@server':with_deadlines(Server, Deadlines), Limits))),
    with_cleanup(fun() ->
        Port = need_ok('http3@server':port(Listener)),
        Client0 = need_ok('http3@client':with_ca_certificate('http3@client':new(), Ca)),
        Address = need_ok('http3@address':parse(<<"127.0.0.1">>)),
        Client = 'http3@client':with_limits('http3@client':with_deadlines(
            'http3@client':with_connect_address(Client0, Address), Deadlines), Limits),
        Connection = need_ok('http3@client':connect(Client, <<"localhost">>, Port)),
        Worker = connection_worker(Connection),
        Monitor = monitor(process, Worker),
        with_cleanup(fun() ->
            Request0 = 'gleam@http@request':set_host('gleam@http@request':new(), <<"localhost">>),
            Request1 = 'gleam@http@request':set_port(Request0, Port),
            Request2 = 'gleam@http@request':set_path(Request1, <<"/websocket-handshake">>),
            Work(Listener, Connection, 'gleam@http@request':set_body(Request2, nil))
        end, fun() ->
            Result = 'http3@client':close_within(Connection, 5000),
            receive {'DOWN', Monitor, process, Worker, _} ->
                observe(connection_owner, joined), Result
            after 1500 -> error(handshake_connection_owner_not_joined) end
        end)
    end, fun() -> 'http3@server':stop(Listener) end).

connection_worker(Connection) ->
    {ok, Worker} = http3_test_ffi:connection_worker(Connection),
    Worker.

with_task(Work, Body) ->
    Task = http3_test_ffi:start_task(Work),
    with_cleanup(fun() -> Body(Task) end, fun() -> stop_task(Task), {ok, nil} end).
await(Task) -> http3_test_ffi:await_task(Task).
stop_task({http3_test_task, Pid, Monitor, Ref}) ->
    Joined = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Joined, process, Pid, _} -> observe(handshake_task, joined)
    after 1000 -> error(handshake_task_not_joined) end,
    demonitor(Monitor, [flush]),
    receive {Ref, task_result, _} -> ok after 0 -> ok end.
with_cleanup(Work, Cleanup) ->
    Outcome = try {ok, Work()} catch C:R:S -> {error, C, R, S} end,
    Cleaned = try is_ok(Cleanup()) catch _:_ -> false end,
    observe(cleanup, case Cleaned of true -> joined; false -> failed end),
    case Outcome of
        {error, Class, Reason, Stack} -> erlang:raise(Class, Reason, Stack);
        {ok, Value} -> case Cleaned of true -> Value; false -> error(handshake_fixture_cleanup_failed) end
    end.
need_ok({ok, Value}) -> Value;
need_ok(_) -> error(handshake_fixture_operation_failed).
is_ok({ok, _}) -> true;
is_ok(_) -> false.
response_status({ok, {response, Status, _}}, Expected) -> Status =:= Expected;
response_status(_, _) -> false.
version_advertised({ok, {response, 400, Headers}}) ->
    [V || {<<"sec-websocket-version">>, V} <- Headers] =:= [<<"13">>];
version_advertised(_) -> false.
response_category({ok, {response, 400, _}}) -> version_rejection;
response_category({error, {failure, {timeout, operation}}}) -> operation_timeout;
response_category(_) -> other.
text_event({ok, {_, {text_message, <<"ok">>}}}) -> true;
text_event(_) -> false.
peer_cancelled({error, {failure, {closed, peer, {some, 16#10c}}}}) -> true;
peer_cancelled(_) -> false.
is_client_failure({error, {client_failure, _}}) -> true;
is_client_failure(_) -> false.
is_server_failure({error, {server_failure, _}}) -> true;
is_server_failure(_) -> false.
cancellation_category({ok, cancelled}) -> cancelled;
cancellation_category({ok, already_completed}) -> already_completed;
cancellation_category({error, {failure, {closed, peer, _}}}) -> peer_closed;
cancellation_category({error, {failure, {closed, local, _}}}) -> local_closed;
cancellation_category({error, {failure, {http3, local, _}}}) -> local_http3;
cancellation_category({error, {failure, {http3, peer, _}}}) -> peer_http3;
cancellation_category({error, {failure, {quic, _, _}}}) -> quic_failure;
cancellation_category({error, {failure, {timeout, _}}}) -> timeout;
cancellation_category({error, _}) -> other_error;
cancellation_category(_) -> other.
result_category({ok, _}) -> accepted;
result_category({error, invalid_handshake}) -> invalid_handshake;
result_category({error, unsupported_version}) -> unsupported_version;
result_category({error, {client_failure, _}}) -> client_failure;
result_category({error, {server_failure, _}}) -> server_failure;
result_category(_) -> other.
observe(Key, Value) ->
    case whereis(websocket_test_observer) of
        undefined -> ok;
        Observer -> Observer ! {websocket_observation, Key, Value}, ok
    end.
