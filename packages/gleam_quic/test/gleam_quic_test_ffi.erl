-module(gleam_quic_test_ffi).

-export([fixture/1, inject_relay_connection_reset/1]).

-spec inject_relay_connection_reset(term()) -> nil.
inject_relay_connection_reset(#{pid := Pid, socket := Socket}) ->
    Pid ! {udp_error, Socket, econnreset},
    timer:sleep(50),
    nil.

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
