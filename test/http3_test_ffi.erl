-module(http3_test_ffi).

-export([handle_request/5, with_lossy_server/1, with_reordering_proxy/1, with_server/1]).

-define(SERVER, http3_loopback_test).
-define(FIXTURE_TIMEOUT, 2000).
-define(MAX_ECHO_BODY, 1048576).

-spec with_server(fun((inet:port_number(), binary()) -> Result)) -> Result.
with_server(Fun) when is_function(Fun, 2) ->
    with_test_server(Fun).

-spec with_lossy_server(fun((inet:port_number(), binary()) -> Result)) -> Result.
with_lossy_server(Fun) when is_function(Fun, 2) ->
    with_test_server(fun(ServerPort, CaCert) ->
        with_proxy(ServerPort, packet_loss, Fun, CaCert)
    end).

-spec with_reordering_proxy(fun((inet:port_number(), binary()) -> Result)) -> Result.
with_reordering_proxy(Fun) when is_function(Fun, 2) ->
    with_test_server(fun(ServerPort, CaCert) ->
        with_proxy(ServerPort, reordering, Fun, CaCert)
    end).

with_test_server(Fun) ->
    {ok, _} = application:ensure_all_started(quic),
    stop_stale_server(),
    Cert = read_certificate("server.pem"),
    Key = read_private_key("server-key.pem"),
    CaCert = read_certificate("ca.pem"),
    {ok, Server} = quic_h3:start_server(?SERVER, 0, #{
        cert => Cert,
        key => Key,
        handler => ?MODULE,
        quic_opts => #{pool_size => 0}
    }),
    Monitor = monitor(process, Server),
    {ok, Port} = quic:get_server_port(?SERVER),
    try
        Fun(Port, CaCert)
    after
        stop_server(Server, Monitor)
    end.

-spec handle_request(pid(), non_neg_integer(), binary(), binary(), list()) -> ok.
handle_request(Conn, StreamId, Method, Path, Headers) ->
    case Path of
        <<"/echo", _/binary>> ->
            TestHeader = proplists:get_value(<<"x-test">>, Headers, <<"missing">>),
            receive_request_body(Conn, StreamId, Method, Path, TestHeader);
        <<"/large", _/binary>> ->
            respond(Conn, StreamId, 200, binary:copy(<<"x">>, 64));
        <<"/timeout", _/binary>> ->
            ok;
        <<"/close", _/binary>> ->
            ok = quic_h3:close(Conn),
            ok;
        <<"/empty", _/binary>> ->
            ok = quic_h3:respond(Conn, StreamId, 204, [], <<"ignored">>),
            ok;
        <<"/chunks", _/binary>> ->
            respond_in_chunks(Conn, StreamId);
        _ ->
            respond(Conn, StreamId, 404, <<"not found">>)
    end.

with_proxy(ServerPort, Mode, Fun, CaCert) ->
    {Proxy, Monitor, ProxyPort} = start_proxy(ServerPort, Mode),
    try
        Fun(ProxyPort, CaCert)
    after
        stop_proxy(Proxy, Monitor)
    end.

start_proxy(ServerPort, Mode) ->
    Parent = self(),
    ReadyRef = make_ref(),
    {Proxy, Monitor} = spawn_monitor(fun() ->
        start_proxy_socket(Parent, ReadyRef, ServerPort, Mode)
    end),
    receive
        {ReadyRef, ready, ProxyPort} ->
            {Proxy, Monitor, ProxyPort};
        {ReadyRef, error, Reason} ->
            await_proxy_down(Proxy, Monitor),
            erlang:error({proxy_start_failed, Reason});
        {'DOWN', Monitor, process, Proxy, Reason} ->
            erlang:error({proxy_start_failed, Reason})
    after ?FIXTURE_TIMEOUT ->
        exit(Proxy, kill),
        await_proxy_down(Proxy, Monitor),
        erlang:error(proxy_start_timeout)
    end.

start_proxy_socket(Parent, ReadyRef, ServerPort, Mode) ->
    case gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]) of
        {ok, Socket} ->
            {ok, {{127, 0, 0, 1}, ProxyPort}} = inet:sockname(Socket),
            Parent ! {ReadyRef, ready, ProxyPort},
            proxy_loop(Socket, ServerPort, Mode, undefined, initial_proxy_state(Mode));
        {error, Reason} ->
            Parent ! {ReadyRef, error, Reason}
    end.

initial_proxy_state(packet_loss) ->
    #{drop_client => true};
initial_proxy_state(reordering) ->
    #{held_client => undefined, reordering_done => false}.

proxy_loop(Socket, ServerPort, Mode, Client, State) ->
    receive
        {udp, Socket, _Address, ServerPort, Packet} ->
            NewState = proxy_server_packet(Socket, Mode, Client, Packet, State),
            proxy_loop(Socket, ServerPort, Mode, Client, NewState);
        {udp, Socket, Address, ClientPort, Packet} ->
            NewState = proxy_client_packet(Socket, ServerPort, Mode, Packet, State),
            proxy_loop(Socket, ServerPort, Mode, {Address, ClientPort}, NewState);
        stop ->
            gen_udp:close(Socket)
    after ?FIXTURE_TIMEOUT * 4 ->
        gen_udp:close(Socket)
    end.

proxy_client_packet(_Socket, _ServerPort, packet_loss, _Packet, #{drop_client := true} = State) ->
    State#{drop_client => false};
proxy_client_packet(
    _Socket,
    _ServerPort,
    reordering,
    Packet,
    #{held_client := undefined, reordering_done := false} = State
) ->
    State#{held_client => Packet};
proxy_client_packet(
    Socket,
    ServerPort,
    reordering,
    Packet,
    #{held_client := Held, reordering_done := false} = State
) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Held),
    State#{held_client => undefined, reordering_done => true};
proxy_client_packet(Socket, ServerPort, _Mode, Packet, State) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
    State.

proxy_server_packet(_Socket, _Mode, undefined, _Packet, State) ->
    State;
proxy_server_packet(Socket, _Mode, Client, Packet, State) ->
    ok = send_to_client(Socket, Client, Packet),
    State.

send_to_client(Socket, {Address, Port}, Packet) ->
    gen_udp:send(Socket, Address, Port, Packet).

stop_proxy(Proxy, Monitor) ->
    Proxy ! stop,
    await_proxy_down(Proxy, Monitor).

await_proxy_down(Proxy, Monitor) ->
    receive
        {'DOWN', Monitor, process, Proxy, _Reason} -> ok
    after ?FIXTURE_TIMEOUT ->
        exit(Proxy, kill),
        receive
            {'DOWN', Monitor, process, Proxy, _Reason} -> ok
        after ?FIXTURE_TIMEOUT ->
            demonitor(Monitor, [flush]),
            ok
        end
    end.

receive_request_body(Conn, StreamId, Method, Path, TestHeader) ->
    case quic_h3:set_stream_handler(Conn, StreamId, self()) of
        ok ->
            receive_request_body(Conn, StreamId, Method, Path, TestHeader, [], 0);
        {ok, Buffered} ->
            consume_buffered(Conn, StreamId, Method, Path, TestHeader, Buffered, [], 0);
        {error, _Reason} ->
            respond(Conn, StreamId, 500, <<"stream handler error">>)
    end.

consume_buffered(Conn, StreamId, Method, Path, TestHeader, Buffered, Chunks, Size) ->
    case Buffered of
        [] ->
            receive_request_body(Conn, StreamId, Method, Path, TestHeader, Chunks, Size);
        [{Data, Fin} | Rest] ->
            NewSize = Size + byte_size(Data),
            case NewSize > ?MAX_ECHO_BODY of
                true ->
                    respond(Conn, StreamId, 413, <<"request body too large">>);
                false when Fin =:= true ->
                    Body = iolist_to_binary(lists:reverse([Data | Chunks])),
                    respond_echo(Conn, StreamId, Method, Path, TestHeader, Body);
                false ->
                    consume_buffered(
                        Conn,
                        StreamId,
                        Method,
                        Path,
                        TestHeader,
                        Rest,
                        [Data | Chunks],
                        NewSize
                    )
            end
    end.

receive_request_body(Conn, StreamId, Method, Path, TestHeader, Chunks, Size) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, Fin}} ->
            NewSize = Size + byte_size(Data),
            case NewSize > ?MAX_ECHO_BODY of
                true ->
                    respond(Conn, StreamId, 413, <<"request body too large">>);
                false when Fin =:= true ->
                    Body = iolist_to_binary(lists:reverse([Data | Chunks])),
                    respond_echo(Conn, StreamId, Method, Path, TestHeader, Body);
                false ->
                    receive_request_body(
                        Conn,
                        StreamId,
                        Method,
                        Path,
                        TestHeader,
                        [Data | Chunks],
                        NewSize
                    )
            end
    after ?FIXTURE_TIMEOUT ->
        respond(Conn, StreamId, 408, <<"request body timeout">>)
    end.

respond_echo(Conn, StreamId, Method, Path, TestHeader, Body) ->
    Headers = [
        {<<"content-type">>, <<"application/octet-stream">>},
        {<<"x-request-method">>, Method},
        {<<"x-request-path">>, Path},
        {<<"x-received-test">>, TestHeader}
    ],
    ok = quic_h3:respond(Conn, StreamId, 200, Headers, Body),
    ok.

respond(Conn, StreamId, Status, Body) ->
    ok = quic_h3:respond(
        Conn,
        StreamId,
        Status,
        [{<<"content-type">>, <<"text/plain">>}],
        Body
    ),
    ok.

respond_in_chunks(Conn, StreamId) ->
    ok = quic_h3:send_response(
        Conn,
        StreamId,
        200,
        [{<<"content-type">>, <<"text/plain">>}]
    ),
    ok = quic_h3:send_data(Conn, StreamId, <<"one-">>, false),
    ok = quic_h3:send_data(Conn, StreamId, <<"two">>, true),
    ok.

stop_stale_server() ->
    ignore_stop_error().

stop_server(Server, Monitor) ->
    ok = ignore_stop_error(),
    receive
        {'DOWN', Monitor, process, Server, _Reason} ->
            ok
    after ?FIXTURE_TIMEOUT ->
        exit(Server, kill),
        receive
            {'DOWN', Monitor, process, Server, _Reason} -> ok
        after ?FIXTURE_TIMEOUT -> ok
        end
    end.

ignore_stop_error() ->
    try quic_h3:stop_server(?SERVER) of
        _ -> ok
    catch
        _:_ -> ok
    end.

read_certificate(Name) ->
    {ok, Pem} = file:read_file(fixture_path(Name)),
    [{_, Der, _}] = public_key:pem_decode(Pem),
    Der.

read_private_key(Name) ->
    {ok, Pem} = file:read_file(fixture_path(Name)),
    [Entry] = public_key:pem_decode(Pem),
    public_key:pem_entry_decode(Entry).

fixture_path(Name) ->
    filename:join(["test", "fixtures", Name]).
