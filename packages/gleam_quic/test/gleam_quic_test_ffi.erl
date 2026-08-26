-module(gleam_quic_test_ffi).

-export([fixture/1, inject_relay_connection_reset/1, socket_buffer_bytes/1]).

-spec inject_relay_connection_reset(term()) -> nil.
inject_relay_connection_reset(#{pid := Pid, socket := Socket}) ->
    Pid ! {udp_error, Socket, econnreset},
    timer:sleep(50),
    nil.

%% Report the inet user-level receive buffer (`buffer`) of every socket behind
%% a production UDP handle, so tests can pin the per-datagram allocation size.
-spec socket_buffer_bytes(term()) -> [integer()].
socket_buffer_bytes(Handle) ->
    lists:filtermap(fun(Socket) ->
        case inet:getopts(Socket, [buffer, recbuf, sndbuf]) of
            {ok, Options} ->
                {buffer, Bytes} = lists:keyfind(buffer, 1, Options),
                {true, Bytes};
            {error, _Reason} -> false
        end
    end, handle_sockets(Handle)).

-spec handle_sockets(term()) -> [gen_udp:socket()].
handle_sockets(#{socket := Socket6, ipv4_socket := Socket4}) ->
    [Socket6, Socket4];
handle_sockets(#{socket := Socket}) ->
    [Socket].

-spec fixture(binary()) -> {ok, binary()} | {error, nil}.
fixture(Name) when Name =:= <<"ca.pem">>;
                   Name =:= <<"client.pem">>;
                   Name =:= <<"client-key.pem">>;
                   Name =:= <<"server.pem">>;
                   Name =:= <<"server-key.pem">> ->
    read_fixture(Name, [
        <<"../../test/fixtures/">>,
        <<"test/fixtures/">>
    ]);
fixture(_Name) ->
    {error, nil}.

-spec read_fixture(binary(), [binary()]) -> {ok, binary()} | {error, nil}.
read_fixture(_Name, []) ->
    {error, nil};
read_fixture(Name, [Prefix | Rest]) ->
    case file:read_file(<<Prefix/binary, Name/binary>>) of
        {ok, Bytes} -> {ok, Bytes};
        {error, _Reason} -> read_fixture(Name, Rest)
    end.
