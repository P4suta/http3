-module(http3_phase4_interop).

-export([run/3]).

run(Port, ResumptionPort, QlogDirectory) ->
    {ok, Pem} = file:read_file("test/fixtures/ca.pem"),
    [{_, CaCertificate, _}] = public_key:pem_decode(Pem),
    {ok, Client0} = http3@client:with_timeout(http3@client:new(), 5000),
    {ok, Client1} = http3@client:with_ca_certificate(Client0, CaCertificate),
    Client2 = http3@client:with_http_datagrams(Client1),
    {ok, Qlog} = http3@transport:qlog(QlogDirectory),
    Client = http3@client:with_qlog(Client2, Qlog),
    {ok, Connection} = http3@client:connect(Client, <<"localhost">>, Port),
    ConnectionTransport = http3@client:connection_transport(Connection),
    {ok, {capabilities, true, true, false, true}} =
        http3@transport:capabilities(ConnectionTransport),

    Stream = open_request(Connection, Port, <<"/advanced">>),
    StreamTransport = http3@client:stream_transport(Stream),
    {ok, Priority} = http3@transport:priority(1, true),
    {ok, nil} = http3@transport:set_priority(StreamTransport, Priority),
    {ok, Priority} = http3@transport:get_priority(StreamTransport),
    {ok, Maximum} = http3@transport:maximum_datagram_size(StreamTransport),
    true = Maximum > 0,
    {ok, nil} = http3@transport:send_datagram(StreamTransport, <<"gleam-ping">>),
    {ok, <<"aioquic-pong">>} = http3@transport:next_datagram(StreamTransport),
    {ok, nil} = http3@client:finish(Stream),
    {200, Headers, <<"aioquic-advanced">>} = collect(Stream),
    {<<"x-interop-peer">>, <<"aioquic-1.3.0">>} =
        lists:keyfind(<<"x-interop-peer">>, 1, Headers),

    {ok, nil} = http3@transport:set_congestion_control(ConnectionTransport, cubic),
    {ok, nil} = http3@transport:ping(ConnectionTransport),
    {ok, Mtu} = http3@transport:maximum_transmission_unit(ConnectionTransport),
    true = Mtu >= 1200,
    {ok, {path_stats, _, _, _, _, Window, _, _, _}} =
        http3@transport:path_stats(ConnectionTransport),
    true = Window > 0,
    {ok, nil} = http3@transport:migrate(ConnectionTransport),

    Migrated = open_request(Connection, Port, <<"/after-migration">>),
    {ok, nil} = http3@client:finish(Migrated),
    {200, _, <<"aioquic-migrated">>} = collect(Migrated),
    {ok, {connection_stats, Received, Sent, _, _, _, _, _, _}} =
        http3@transport:connection_stats(ConnectionTransport),
    true = Received > 0,
    true = Sent > 0,
    {ok, closed} = http3@client:close(Connection),

    TicketConnection = connect(Client, ResumptionPort),
    TicketStream = open_request(TicketConnection, ResumptionPort, <<"/ticket">>),
    {ok, nil} = http3@client:finish(TicketStream),
    {200, _, <<"aioquic-ticket">>} = collect(TicketStream),
    TicketTransport = http3@client:connection_transport(TicketConnection),
    {ok, Ticket} = http3@transport:resumption_ticket(TicketTransport),
    {ok, closed} = http3@client:close(TicketConnection),

    ResumedClient = http3@client:with_resumption_ticket(Client, Ticket),
    ResumedConnection = connect(ResumedClient, ResumptionPort),
    ResumedTransport = http3@client:connection_transport(ResumedConnection),
    {ok, ResumptionState} = http3@transport:early_data_status(ResumedTransport),
    true = ResumptionState =/= not_attempted,
    EarlyStream = open_request(ResumedConnection, ResumptionPort, <<"/early">>),
    {ok, nil} = http3@client:finish(EarlyStream),
    {200, _, <<"aioquic-resumed">>} = collect(EarlyStream),
    {ok, accepted} = http3@transport:early_data_status(ResumedTransport),
    {ok, accepted} = http3@transport:stream_early_data_status(
        http3@client:stream_transport(EarlyStream)
    ),
    {ok, closed} = http3@client:close(ResumedConnection),

    QlogPattern = binary_to_list(filename:join(QlogDirectory, "*.qlog")),
    [_ | _] = filelib:wildcard(QlogPattern),
    io:format("phase4 aioquic advanced interop ok~n"),
    ok.

connect(Client, Port) ->
    {ok, Connection} = http3@client:connect(Client, <<"localhost">>, Port),
    Connection.

open_request(Connection, Port, Path) ->
    Request0 = gleam@http@request:new(),
    Request1 = gleam@http@request:set_host(Request0, <<"localhost">>),
    Request2 = gleam@http@request:set_port(Request1, Port),
    Request3 = gleam@http@request:set_path(Request2, Path),
    Request = gleam@http@request:set_body(Request3, nil),
    {ok, Stream} = http3@client:open_stream(Connection, Request),
    Stream.

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
