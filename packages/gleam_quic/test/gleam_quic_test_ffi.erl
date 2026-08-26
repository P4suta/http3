-module(gleam_quic_test_ffi).

-export([
    fixture/1,
    inject_relay_connection_reset/1,
    linux_platform/0,
    processes_labelled/1,
    socket_buffer_bytes/1,
    socket_dont_fragment_values/1
]).

%% IPPROTO_IP / IP_MTU_DISCOVER and IPPROTO_IPV6 / IPV6_MTU_DISCOVER, the
%% Linux socket options that carry the Don't-Fragment policy DPLPMTUD needs
%% (RFC 8899 section 3). Read back as native-endian 32-bit integers.
-define(IPPROTO_IP, 0).
-define(IP_MTU_DISCOVER, 10).
-define(IPPROTO_IPV6, 41).
-define(IPV6_MTU_DISCOVER, 23).

-spec inject_relay_connection_reset(term()) -> nil.
inject_relay_connection_reset(#{pid := Pid, socket := Socket}) ->
    Pid ! {udp_error, Socket, econnreset},
    timer:sleep(50),
    nil.

%% Count the live processes carrying one fixed `proc_lib:set_label/1` label,
%% so topology tests can pin how many actors of a role exist right now.
-spec processes_labelled(binary()) -> integer().
processes_labelled(Label) ->
    length([Pid || Pid <- erlang:processes(), proc_lib:get_label(Pid) =:= Label]).

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

%% Report whether the Linux raw socket options this test reads back exist.
-spec linux_platform() -> boolean().
linux_platform() ->
    os:type() =:= {unix, linux}.

%% Report the kernel Don't-Fragment policy of every socket behind a production
%% UDP handle, so tests can pin that QUIC datagrams are never fragmented
%% locally. A socket whose option cannot be read reports -1.
-spec socket_dont_fragment_values(term()) -> [integer()].
socket_dont_fragment_values(#{socket := Socket6, ipv4_socket := Socket4}) ->
    [dont_fragment_value(Socket6, 6), dont_fragment_value(Socket4, 4)];
socket_dont_fragment_values(#{socket := Socket, family := Family}) ->
    [dont_fragment_value(Socket, Family)].

-spec dont_fragment_value(gen_udp:socket(), 4 | 6) -> integer().
dont_fragment_value(Socket, 4) ->
    raw_integer(Socket, ?IPPROTO_IP, ?IP_MTU_DISCOVER);
dont_fragment_value(Socket, 6) ->
    raw_integer(Socket, ?IPPROTO_IPV6, ?IPV6_MTU_DISCOVER).

-spec raw_integer(gen_udp:socket(), integer(), integer()) -> integer().
raw_integer(Socket, Level, Option) ->
    case inet:getopts(Socket, [{raw, Level, Option, 4}]) of
        {ok, [{raw, Level, Option, <<Value:32/native>>}]} -> Value;
        _Other -> -1
    end.

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
