-module(http3_quicgo_interop).

-export([
    run_client/1,
    run_client/2,
    run_client/3,
    run_server/0,
    run_server/1,
    run_aioquic_server/0,
    run_aioquic_server/1
]).

run_client(Port) ->
    run_client(Port, quic_v1).

run_client(Port, QuicVersion) ->
    run_client(Port, QuicVersion, undefined).

run_client(Port, QuicVersion, QlogDirectory) ->
    {ok, Pem} = file:read_file("test/fixtures/ca.pem"),
    [{_, CaCertificate, _}] = public_key:pem_decode(Pem),
    {ok, Client0} = http3@client:with_timeout(http3@client:new(), 10000),
    {ok, Client1} = http3@client:with_ca_certificate(Client0, CaCertificate),
    Client2 = http3@client:with_quic_version(Client1, QuicVersion),
    Client = case QlogDirectory of
        undefined -> Client2;
        _ ->
            {ok, Qlog} = http3@transport:qlog(QlogDirectory),
            http3@client:with_qlog(Client2, Qlog)
    end,
    Request0 = gleam@http@request:new(),
    Request1 = gleam@http@request:set_method(Request0, post),
    Request2 = gleam@http@request:set_host(Request1, <<"localhost">>),
    Request3 = gleam@http@request:set_port(Request2, Port),
    Request4 = gleam@http@request:set_path(Request3, <<"/quicgo">>),
    Request = gleam@http@request:set_body(Request4, nil),
    {ok, Connection} = http3@client:connect(Client, <<"localhost">>, Port),
    {ok, Stream} = http3@client:open_stream(Connection, Request),
    {ok, nil} = http3@client:send_chunk(Stream, <<"native-request">>),
    {ok, nil} = http3@client:finish(Stream),
    {201, Headers, <<"quic-go-response">>} = collect(Stream),
    {<<"x-interop-peer">>, <<"quic-go-v0.61.0">>} =
        lists:keyfind(<<"x-interop-peer">>, 1, Headers),
    {ok, closed} = http3@client:close(Connection),
    io:format("native client to quic-go server (~p) interop ok~n", [
        QuicVersion
    ]),
    ok.

run_server() ->
    run_server(undefined).

run_server(QlogDirectory) ->
    run_native_server(
        QlogDirectory,
        <<"/native">>,
        <<"quic-go-request">>,
        201,
        <<"native-response">>,
        "native server to quic-go client interop ok"
    ).

run_aioquic_server() ->
    run_aioquic_server(undefined).

run_aioquic_server(QlogDirectory) ->
    run_native_server(
        QlogDirectory,
        <<"/aioquic">>,
        <<"aioquic-request">>,
        202,
        <<"native-aioquic-response">>,
        "native server to aioquic client interop ok"
    ).

run_native_server(
    QlogDirectory,
    ExpectedPath,
    ExpectedBody,
    Status,
    ResponseBody,
    SuccessMessage
) ->
    {ok, Certificate} = file:read_file("test/fixtures/server.pem"),
    {ok, PrivateKey} = file:read_file("test/fixtures/server-key.pem"),
    {ok, Configuration0} = http3@server:new(Certificate, PrivateKey),
    Configuration1 = case QlogDirectory of
        undefined -> Configuration0;
        _ ->
            {ok, Qlog} = http3@transport:qlog(QlogDirectory),
            http3@server:with_qlog(Configuration0, Qlog)
    end,
    {ok, Configuration} = http3@server:with_timeout(Configuration1, 30000),
    {ok, Listener} = http3@server:start(Configuration),
    {ok, Port} = http3@server:port(Listener),
    io:format("PORT=~B~n", [Port]),
    {ok, Request} = http3@server:accept(Listener),
    post = http3@server:method(Request),
    ExpectedPath = http3@server:path(Request),
    {ok, ExpectedBody} = http3@server:read_body(Request),
    {ok, nil} = http3@server:respond(
        Request,
        Status,
        [{<<"x-interop-peer">>, <<"gleam-native">>}],
        ResponseBody
    ),
    {ok, DrainResult} = http3@server:graceful_stop(Listener),
    true = DrainResult =:= drained orelse DrainResult =:= forced,
    io:format("~s~n", [SuccessMessage]),
    ok.

collect(Stream) ->
    collect(Stream, undefined, [], <<>>).

collect(Stream, Status, Headers, Body) ->
    case http3@client:next_event(Stream) of
        {ok, {response, NewStatus, NewHeaders}} ->
            collect(Stream, NewStatus, NewHeaders, Body);
        {ok, {data, Chunk}} ->
            collect(Stream, Status, Headers, <<Body/binary, Chunk/binary>>);
        {ok, {trailers, _}} ->
            collect(Stream, Status, Headers, Body);
        {ok, 'end'} ->
            {Status, Headers, Body};
        Other ->
            erlang:error({unexpected_stream_event, Other})
    end.
