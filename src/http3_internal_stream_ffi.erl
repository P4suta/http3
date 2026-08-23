-module(http3_internal_stream_ffi).

-export([
    cancel/1,
    close/1,
    connect/8,
    connection_stats/1,
    early_data_status/1,
    finish/1,
    get_priority/1,
    max_datagram_size/1,
    maximum_transmission_unit/1,
    migrate/1,
    next_datagram/1,
    next_event/1,
    open_stream/5,
    path_stats/1,
    ping/1,
    resumption_ticket/1,
    send_chunk/2,
    send_datagram/2,
    set_congestion_control/2,
    set_priority/3,
    stream_early_data_status/1,
    transport_capabilities/1,
    transport_stream_capabilities/1
]).

-define(CLEANUP_TIMEOUT, 250).
-define(WORKER_GRACE, 600).
-define(RETRY_INTERVAL, 2).
-define(MAX_REASON_BYTES, 1024).
-define(MAX_FIELD_SECTION_SIZE, 65536).

-define(ERROR_CONNECT, 1).
-define(ERROR_REQUEST, 2).
-define(ERROR_TIMEOUT, 3).
-define(ERROR_CLOSED, 5).
-define(ERROR_STREAM_RESET, 6).
-define(ERROR_PROTOCOL, 7).
-define(ERROR_BACKEND, 8).
-define(ERROR_CONTENT_LENGTH, 14).
-define(ERROR_CONSUMER_SLOW, 15).
-define(ERROR_CONCURRENT_RECEIVE, 16).
-define(ERROR_REQUEST_FINISHED, 17).
-define(ERROR_STREAM_FINISHED, 18).
-define(ERROR_STREAM_CANCELLED, 19).
-define(ERROR_ORIGIN, 20).
-define(ERROR_EARLY_METHOD, 21).
-define(ERROR_RESUMPTION_ORIGIN, 22).

-define(TRANSPORT_ERROR_CLOSED, 1).
-define(TRANSPORT_ERROR_TIMEOUT, 2).
-define(TRANSPORT_ERROR_DATAGRAMS_DISABLED, 3).
-define(TRANSPORT_ERROR_DATAGRAM_TOO_LARGE, 4).
-define(TRANSPORT_ERROR_CONGESTION, 5).
-define(TRANSPORT_ERROR_UNKNOWN_STREAM, 6).
-define(TRANSPORT_ERROR_DATAGRAM_BUFFER, 7).
-define(TRANSPORT_ERROR_CONCURRENT_DATAGRAM, 8).
-define(TRANSPORT_ERROR_MIGRATION, 9).
-define(TRANSPORT_ERROR_NOT_CONNECTED, 10).
-define(TRANSPORT_ERROR_BACKEND, 99).

-define(EVENT_INFORMATIONAL, 1).
-define(EVENT_RESPONSE, 2).
-define(EVENT_DATA, 3).
-define(EVENT_TRAILERS, 4).
-define(EVENT_END, 5).

-type raw_error() :: {integer(), integer(), binary()}.
-type result(Value) :: {ok, Value} | {error, raw_error()}.
-type connection_handle() :: {http3_connection, pid(), pos_integer()}.
-type stream_handle() :: {http3_stream, pid(), non_neg_integer(), pos_integer()}.
-type resumption_ticket_handle() ::
    {
        http3_resumption_ticket,
        binary(),
        inet:port_number(),
        inet:ip_address(),
        term()
    }.

-spec connect(
    binary(),
    inet:port_number(),
    [binary()],
    pos_integer(),
    pos_integer(),
    boolean(),
    binary(),
    [resumption_ticket_handle()]
) ->
    result(connection_handle()).
connect(Host, Port, CaCertificates, Timeout, BufferLimit, Datagrams, QlogDirectory, Tickets) when
    is_binary(Host),
    is_integer(Port),
    Port > 0,
    Port =< 65535,
    is_list(CaCertificates),
    is_integer(Timeout),
    Timeout > 0,
    is_integer(BufferLimit),
    BufferLimit > 0,
    is_boolean(Datagrams),
    is_binary(QlogDirectory),
    is_list(Tickets)
->
    case ticket_for_origin(Tickets, Host, Port) of
        {ok, Resumption} ->
            Owner = self(),
            ReplyRef = make_ref(),
            {Worker, Monitor} = spawn_monitor(fun() ->
                initialise(
                    Owner,
                    ReplyRef,
                    Host,
                    Port,
                    CaCertificates,
                    Timeout,
                    BufferLimit,
                    Datagrams,
                    QlogDirectory,
                    Resumption
                )
            end),
            receive
                {ReplyRef, {ok, ready}} ->
                    demonitor(Monitor, [flush]),
                    {ok, {http3_connection, Worker, Timeout}};
                {ReplyRef, {error, _} = Error} ->
                    await_worker_down(Worker, Monitor),
                    Error;
                {'DOWN', Monitor, process, Worker, Reason} ->
                    receive
                        {ReplyRef, {error, _} = Error} -> Error
                    after 0 ->
                        backend_error({connection_worker_stopped, Reason})
                    end
            after Timeout + ?WORKER_GRACE ->
                exit(Worker, kill),
                await_worker_down(Worker, Monitor),
                timeout_error()
            end;
        {error, _} = Error ->
            Error
    end;
connect(
    _Host,
    _Port,
    _CaCertificates,
    _Timeout,
    _BufferLimit,
    _Datagrams,
    _QlogDirectory,
    _Tickets
) ->
    backend_error(invalid_connect_arguments).

ticket_for_origin([], _Host, _Port) ->
    {ok, undefined};
ticket_for_origin(
    [{http3_resumption_ticket, TicketHost, TicketPort, PeerAddress, Ticket}], Host, Port
) when is_binary(TicketHost), is_integer(TicketPort), is_tuple(PeerAddress) ->
    case TicketPort =:= Port andalso string:equal(TicketHost, Host, true) of
        true -> {ok, {Ticket, PeerAddress}};
        false -> resumption_origin_error()
    end;
ticket_for_origin(_Tickets, _Host, _Port) ->
    resumption_origin_error().

-spec open_stream(connection_handle(), binary(), inet:port_number(), list(), integer()) ->
    result(stream_handle()).
open_stream(
    {http3_connection, Worker, Timeout}, Host, Port, Headers, DeclaredContentLength
) when
    is_pid(Worker),
    is_binary(Host),
    is_integer(Port),
    is_list(Headers),
    is_integer(DeclaredContentLength)
->
    call_worker(
        Worker,
        {open_stream, Host, Port, Headers, declared_length(DeclaredContentLength)},
        Timeout
    );
open_stream(_Connection, _Host, _Port, _Headers, _DeclaredContentLength) ->
    backend_error(invalid_open_stream_arguments).

-spec send_chunk(stream_handle(), bitstring()) -> result(nil).
send_chunk({http3_stream, Worker, StreamId, Timeout}, Chunk) when
    is_pid(Worker), is_integer(StreamId), is_binary(Chunk)
->
    call_worker(Worker, {send_chunk, StreamId, Chunk}, Timeout);
send_chunk(_Stream, _Chunk) ->
    backend_error(invalid_send_chunk_arguments).

-spec finish(stream_handle()) -> result(nil).
finish({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId)
->
    call_worker(Worker, {finish, StreamId}, Timeout);
finish(_Stream) ->
    backend_error(invalid_finish_arguments).

-spec next_event(stream_handle()) -> result(tuple()).
next_event({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId)
->
    call_worker(Worker, {next_event, StreamId}, Timeout);
next_event(_Stream) ->
    backend_error(invalid_next_event_arguments).

-spec cancel(stream_handle()) -> result(integer()).
cancel({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId)
->
    call_worker(Worker, {cancel, StreamId}, Timeout);
cancel(_Stream) ->
    backend_error(invalid_cancel_arguments).

-spec close(connection_handle()) -> result(integer()).
close({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    case is_process_alive(Worker) of
        true -> call_worker_for_close(Worker, Timeout);
        false -> {ok, 2}
    end;
close(_Connection) ->
    backend_error(invalid_close_arguments).

-spec transport_capabilities(connection_handle()) -> result(tuple()).
transport_capabilities({http3_connection, Worker, Timeout}) when
    is_pid(Worker), is_integer(Timeout)
->
    call_transport_worker(Worker, transport_capabilities, Timeout);
transport_capabilities(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec transport_stream_capabilities(stream_handle()) -> result(tuple()).
transport_stream_capabilities({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId), is_integer(Timeout)
->
    call_transport_worker(Worker, {transport_stream_capabilities, StreamId}, Timeout);
transport_stream_capabilities(_Stream) ->
    transport_backend_error(invalid_stream_handle).

-spec max_datagram_size(stream_handle()) -> result(non_neg_integer()).
max_datagram_size({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId), is_integer(Timeout)
->
    call_transport_worker(Worker, {max_datagram_size, StreamId}, Timeout);
max_datagram_size(_Stream) ->
    transport_backend_error(invalid_stream_handle).

-spec send_datagram(stream_handle(), bitstring()) -> result(nil).
send_datagram({http3_stream, Worker, StreamId, Timeout}, Payload) when
    is_pid(Worker), is_integer(StreamId), is_integer(Timeout), is_binary(Payload)
->
    call_transport_worker(Worker, {send_datagram, StreamId, Payload}, Timeout);
send_datagram(_Stream, _Payload) ->
    transport_backend_error(invalid_datagram_arguments).

-spec next_datagram(stream_handle()) -> result(binary()).
next_datagram({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId), is_integer(Timeout)
->
    call_transport_worker(Worker, {next_datagram, StreamId}, Timeout);
next_datagram(_Stream) ->
    transport_backend_error(invalid_stream_handle).

-spec set_priority(stream_handle(), 0..7, boolean()) -> result(nil).
set_priority({http3_stream, Worker, StreamId, Timeout}, Urgency, Incremental) when
    is_pid(Worker),
    is_integer(StreamId),
    is_integer(Timeout),
    is_integer(Urgency),
    Urgency >= 0,
    Urgency =< 7,
    is_boolean(Incremental)
->
    call_transport_worker(Worker, {set_priority, StreamId, Urgency, Incremental}, Timeout);
set_priority(_Stream, _Urgency, _Incremental) ->
    transport_backend_error(invalid_priority).

-spec get_priority(stream_handle()) -> result({0..7, boolean()}).
get_priority({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId), is_integer(Timeout)
->
    call_transport_worker(Worker, {get_priority, StreamId}, Timeout);
get_priority(_Stream) ->
    transport_backend_error(invalid_stream_handle).

-spec early_data_status(connection_handle()) -> result(0..3).
early_data_status({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_transport_worker(Worker, early_data_status, Timeout);
early_data_status(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec stream_early_data_status(stream_handle()) -> result(0..3).
stream_early_data_status({http3_stream, Worker, StreamId, Timeout}) when
    is_pid(Worker), is_integer(StreamId), is_integer(Timeout)
->
    call_transport_worker(Worker, {stream_early_data_status, StreamId}, Timeout);
stream_early_data_status(_Stream) ->
    transport_backend_error(invalid_stream_handle).

-spec resumption_ticket(connection_handle()) -> result(resumption_ticket_handle()).
resumption_ticket({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_transport_worker(Worker, resumption_ticket, Timeout);
resumption_ticket(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec migrate(connection_handle()) -> result(nil).
migrate({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_transport_worker(Worker, migrate, Timeout);
migrate(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec set_congestion_control(connection_handle(), 1..3) -> result(nil).
set_congestion_control({http3_connection, Worker, Timeout}, Algorithm) when
    is_pid(Worker), is_integer(Timeout), is_integer(Algorithm)
->
    call_transport_worker(Worker, {set_congestion_control, Algorithm}, Timeout);
set_congestion_control(_Connection, _Algorithm) ->
    transport_backend_error(invalid_connection_handle).

-spec ping(connection_handle()) -> result(nil).
ping({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_transport_worker(Worker, ping, Timeout);
ping(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec maximum_transmission_unit(connection_handle()) -> result(pos_integer()).
maximum_transmission_unit({http3_connection, Worker, Timeout}) when
    is_pid(Worker), is_integer(Timeout)
->
    call_transport_worker(Worker, maximum_transmission_unit, Timeout);
maximum_transmission_unit(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec path_stats(connection_handle()) -> result(tuple()).
path_stats({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_transport_worker(Worker, path_stats, Timeout);
path_stats(_Connection) ->
    transport_backend_error(invalid_connection_handle).

-spec connection_stats(connection_handle()) -> result(tuple()).
connection_stats({http3_connection, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_transport_worker(Worker, connection_stats, Timeout);
connection_stats(_Connection) ->
    transport_backend_error(invalid_connection_handle).

declared_length(-1) -> undefined;
declared_length(Length) when Length >= 0 -> Length;
declared_length(_Length) -> invalid.

call_worker(Worker, Request, Timeout) ->
    case is_process_alive(Worker) of
        false -> closed_error();
        true ->
            Ref = make_ref(),
            Monitor = monitor(process, Worker),
            Worker ! {http3_call, self(), Ref, Request},
            await_call(Worker, Monitor, Ref, Timeout + ?WORKER_GRACE)
    end.

call_transport_worker(Worker, Request, Timeout) ->
    case is_process_alive(Worker) of
        false -> transport_closed_error();
        true ->
            Ref = make_ref(),
            Monitor = monitor(process, Worker),
            Worker ! {http3_call, self(), Ref, Request},
            await_transport_call(Worker, Monitor, Ref, Timeout + ?WORKER_GRACE)
    end.

await_transport_call(Worker, Monitor, Ref, Timeout) ->
    receive
        {Ref, Result} ->
            demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Worker, _Reason} ->
            receive
                {Ref, Result} -> Result
            after 0 ->
                transport_closed_error()
            end
    after Timeout ->
        exit(Worker, kill),
        await_worker_down(Worker, Monitor),
        transport_timeout_error()
    end.

call_worker_for_close(Worker, Timeout) ->
    Ref = make_ref(),
    Monitor = monitor(process, Worker),
    Worker ! {http3_call, self(), Ref, close},
    receive
        {Ref, Result} ->
            demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Worker, _Reason} ->
            receive
                {Ref, Result} -> Result
            after 0 ->
                {ok, 2}
            end
    after Timeout + ?WORKER_GRACE ->
        exit(Worker, kill),
        await_worker_down(Worker, Monitor),
        timeout_error()
    end.

await_call(Worker, Monitor, Ref, Timeout) ->
    receive
        {Ref, Result} ->
            demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Worker, Reason} ->
            receive
                {Ref, Result} -> Result
            after 0 ->
                case Reason of
                    normal -> closed_error();
                    _ -> backend_error({connection_worker_stopped, Reason})
                end
            end
    after Timeout ->
        exit(Worker, kill),
        await_worker_down(Worker, Monitor),
        timeout_error()
    end.

initialise(
    Owner,
    ReplyRef,
    Host,
    Port,
    CaCertificates,
    Timeout,
    BufferLimit,
    Datagrams,
    QlogDirectory,
    ResumptionTicket
) ->
    process_flag(trap_exit, true),
    Result = try
        initialise_connection(
            Host,
            Port,
            CaCertificates,
            Timeout,
            Datagrams,
            QlogDirectory,
            ResumptionTicket
        )
    of
        Value -> Value
    catch
        exit:timeout -> timeout_error();
        exit:{timeout, _} -> timeout_error();
        Class:Reason -> backend_error({Class, Reason})
    end,
    case Result of
        {ok, Connection, PeerAddress} ->
            OwnerMonitor = monitor(process, Owner),
            Owner ! {ReplyRef, {ok, ready}},
            loop(#{
                owner => Owner,
                owner_monitor => OwnerMonitor,
                connection => Connection,
                host => Host,
                port => Port,
                peer_address => PeerAddress,
                timeout => Timeout,
                buffer_limit => BufferLimit,
                datagrams_configured => Datagrams,
                qlog_enabled => QlogDirectory =/= <<>>,
                early_attempted => ResumptionTicket =/= undefined,
                latest_ticket => undefined,
                ticket_waiter => undefined,
                accepting => true,
                streams => #{}
            });
        {error, _} = Error ->
            Owner ! {ReplyRef, Error}
    end.

initialise_connection(
    Host, Port, CaCertificates, Timeout, Datagrams, QlogDirectory, Resumption
) ->
    case application:ensure_all_started(quic) of
        {ok, _Started} ->
            QuicOptions0 = maybe_add_qlog(#{}, QlogDirectory),
            QuicOptions = maybe_add_resumption_ticket(QuicOptions0, Resumption, Host),
            BaseOptions = #{
                verify => verify_peer,
                settings => #{max_field_section_size => ?MAX_FIELD_SECTION_SIZE},
                sync => Resumption =:= undefined,
                connect_timeout => Timeout,
                h3_datagram_enabled => Datagrams,
                quic_opts => QuicOptions
            },
            Options = maybe_add_ca_certificates(BaseOptions, CaCertificates),
            Target = resumption_target(Host, Resumption),
            case quic_h3:connect(Target, Port, Options) of
                {ok, Connection} ->
                    case connection_peer_address(Connection) of
                        {ok, PeerAddress} -> {ok, Connection, PeerAddress};
                        {error, Reason} ->
                            close_connection(Connection),
                            connect_error({peer_address, Reason})
                    end;
                {error, connect_timeout} -> timeout_error();
                {error, timeout} -> timeout_error();
                {error, Reason} -> connect_error(Reason)
            end;
        {error, Reason} ->
            connect_error(Reason)
    end.

maybe_add_ca_certificates(Options, []) -> Options;
maybe_add_ca_certificates(Options, Certificates) -> Options#{cacerts => Certificates}.

maybe_add_qlog(Options, <<>>) -> Options;
maybe_add_qlog(Options, Directory) ->
    Options#{qlog => #{enabled => true, dir => binary_to_list(Directory)}}.

maybe_add_resumption_ticket(Options, undefined, _Host) -> Options;
%% The backend's Happy Eyeballs coordinator selects a winner only after the
%% handshake, which necessarily turns every resumed request into 1-RTT. A
%% ticket is already bound to one explicit origin, so take the backend's
%% single-address asynchronous path for the resumption attempt and preserve
%% the opportunity to transmit replay-safe request data with early keys.
maybe_add_resumption_ticket(Options, {Ticket, _PeerAddress}, Host) ->
    Options#{
        session_ticket => Ticket,
        happy_eyeballs => false,
        server_name => Host
    }.

resumption_target(Host, undefined) -> Host;
resumption_target(_Host, {_Ticket, PeerAddress}) -> PeerAddress.

connection_peer_address(Connection) ->
    try quic_h3:get_quic_conn(Connection) of
        QuicConnection ->
            case quic:peername(QuicConnection) of
                {ok, {PeerAddress, _PeerPort}} -> {ok, PeerAddress};
                {error, _} = Error -> Error
            end
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

loop(State) ->
    Wait = next_deadline_wait(State),
    Connection = maps:get(connection, State, undefined),
    OwnerMonitor = maps:get(owner_monitor, State),
    receive
        {http3_call, From, Ref, close} ->
            reply(From, Ref, {ok, 1}),
            shutdown(State);
        {http3_call, From, Ref, Request} ->
            case safely_handle_call(Request, State) of
                {reply, Result, NextState} ->
                    reply(From, Ref, Result),
                    loop(NextState);
                {wait, StreamId, NextState} ->
                    Stream = maps:get(StreamId, maps:get(streams, NextState)),
                    Streams = maps:get(streams, NextState),
                    Waiting = Stream#{waiter => {From, Ref}},
                    loop(NextState#{streams => Streams#{StreamId => Waiting}});
                {wait_datagram, StreamId, NextState} ->
                    Stream = maps:get(StreamId, maps:get(streams, NextState)),
                    Streams = maps:get(streams, NextState),
                    Waiting = Stream#{datagram_waiter => {From, Ref}},
                    loop(NextState#{streams => Streams#{StreamId => Waiting}});
                {wait_ticket, NextState} ->
                    Deadline = erlang:monotonic_time(millisecond) + maps:get(timeout, State),
                    loop(NextState#{ticket_waiter => {From, Ref, Deadline}})
            end;
        {quic_h3, Connection, Event} ->
            loop(handle_h3_event(Event, State));
        {'DOWN', OwnerMonitor, process, _Owner, _Reason} ->
            shutdown(State);
        {'EXIT', Connection, Reason} ->
            loop(fail_connection(Reason, State));
        _Other ->
            loop(State)
    after Wait ->
        loop(expire_streams(State))
    end.

safely_handle_call(Request, State) ->
    try handle_call(Request, State) of
        Result -> Result
    catch
        exit:timeout -> {reply, call_timeout_error(Request), State};
        exit:{timeout, _} -> {reply, call_timeout_error(Request), State};
        Class:Reason -> {reply, call_backend_error(Request, {Class, Reason}), State}
    end.

call_timeout_error(Request) ->
    case is_transport_call(Request) of
        true -> transport_timeout_error();
        false -> timeout_error()
    end.

call_backend_error(Request, Reason) ->
    case is_transport_call(Request) of
        true -> transport_backend_error(Reason);
        false -> backend_error(Reason)
    end.

is_transport_call(transport_capabilities) -> true;
is_transport_call({transport_stream_capabilities, _}) -> true;
is_transport_call({max_datagram_size, _}) -> true;
is_transport_call({send_datagram, _, _}) -> true;
is_transport_call({next_datagram, _}) -> true;
is_transport_call({set_priority, _, _, _}) -> true;
is_transport_call({get_priority, _}) -> true;
is_transport_call(early_data_status) -> true;
is_transport_call({stream_early_data_status, _}) -> true;
is_transport_call(resumption_ticket) -> true;
is_transport_call(migrate) -> true;
is_transport_call({set_congestion_control, _}) -> true;
is_transport_call(ping) -> true;
is_transport_call(maximum_transmission_unit) -> true;
is_transport_call(path_stats) -> true;
is_transport_call(connection_stats) -> true;
is_transport_call(_) -> false.

handle_call({open_stream, Host, Port, Headers, DeclaredLength}, State) ->
    Connection = maps:get(connection, State, undefined),
    case Connection of
        undefined ->
            {reply, closed_error(), State};
        _ ->
            case same_origin(Host, Port, State) of
                false ->
                    {reply, origin_error(), State};
                true ->
                    case maps:get(accepting, State) of
                        false ->
                            {reply, request_error(goaway_received), State};
                        true ->
                            do_open_stream(Connection, Headers, DeclaredLength, State)
                    end
            end
    end;
handle_call({send_chunk, StreamId, Chunk}, State) ->
    with_stream(StreamId, State, fun(Stream) ->
        send_chunk_on_stream(StreamId, Chunk, Stream, State)
    end);
handle_call({finish, StreamId}, State) ->
    with_stream(StreamId, State, fun(Stream) ->
        finish_stream(StreamId, Stream, State)
    end);
handle_call({next_event, StreamId}, State) ->
    next_stream_event(StreamId, State);
handle_call({cancel, StreamId}, State) ->
    cancel_stream(StreamId, State);
handle_call(transport_capabilities, State) ->
    connection_capabilities(State);
handle_call({transport_stream_capabilities, StreamId}, State) ->
    with_transport_stream(StreamId, State, fun(_Stream) -> connection_capabilities(State) end);
handle_call({max_datagram_size, StreamId}, State) ->
    with_transport_stream(StreamId, State, fun(Stream) ->
        stream_max_datagram_size(Stream, State)
    end);
handle_call({send_datagram, StreamId, Payload}, State) ->
    with_transport_stream(StreamId, State, fun(Stream) ->
        send_stream_datagram(Stream, Payload, State)
    end);
handle_call({next_datagram, StreamId}, State) ->
    next_stream_datagram(StreamId, State);
handle_call({set_priority, StreamId, Urgency, Incremental}, State) ->
    with_transport_stream(StreamId, State, fun(Stream) ->
        set_stream_priority(Stream, Urgency, Incremental, State)
    end);
handle_call({get_priority, StreamId}, State) ->
    with_transport_stream(StreamId, State, fun(Stream) ->
        get_stream_priority(Stream, State)
    end);
handle_call(early_data_status, State) ->
    {reply, connection_early_data_status(State), State};
handle_call({stream_early_data_status, StreamId}, State) ->
    with_transport_stream(StreamId, State, fun(_Stream) ->
        {reply, connection_early_data_status(State), State}
    end);
handle_call(resumption_ticket, State) ->
    current_resumption_ticket(State);
handle_call(migrate, State) ->
    migrate_connection(State);
handle_call({set_congestion_control, Algorithm}, State) ->
    set_connection_congestion_control(Algorithm, State);
handle_call(ping, State) ->
    ping_connection(State);
handle_call(maximum_transmission_unit, State) ->
    connection_mtu(State);
handle_call(path_stats, State) ->
    connection_path_stats(State);
handle_call(connection_stats, State) ->
    connection_statistics(State);
handle_call(_Request, State) ->
    {reply, backend_error(unknown_worker_call), State}.

do_open_stream(_Connection, _Headers, invalid, State) ->
    {reply, content_length_error(), State};
do_open_stream(Connection, Headers, DeclaredLength, State) ->
    case early_method_allowed(Headers, State) of
        false ->
            {reply, unsafe_early_method_error(request_method(Headers)), State};
        true ->
            open_backend_stream(Connection, Headers, DeclaredLength, State)
    end.

open_backend_stream(Connection, Headers, DeclaredLength, State) ->
    Timeout = maps:get(timeout, State),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case request_when_ready(Connection, Headers, State, Deadline) of
        {ok, StreamId} ->
            Stream = #{
                id => StreamId,
                deadline => Deadline,
                request_state => open,
                sent => 0,
                declared_length => DeclaredLength,
                response_state => awaiting_headers,
                queue => queue:new(),
                queued_bytes => 0,
                waiter => undefined,
                terminal => undefined,
                datagram_queue => queue:new(),
                datagram_bytes => 0,
                datagram_waiter => undefined,
                datagram_error => undefined
            },
            Streams = maps:get(streams, State),
            Handle = {http3_stream, self(), StreamId, Timeout},
            {reply, {ok, Handle}, State#{streams => Streams#{StreamId => Stream}}};
        {error, timeout} ->
            {reply, timeout_error(), State};
        {error, Reason} ->
            {reply, request_error(Reason), State}
    end.

%% A resumed H3 connection can leave `early_data' as soon as QUIC completes
%% its handshake, then briefly reject requests in `h3_connecting' while it
%% waits for the peer SETTINGS frame. This is a transient readiness state,
%% not a failed request. Retry only that exact backend result, only for a
%% resumed connection, and never beyond the caller's fixed deadline.
request_when_ready(Connection, Headers, #{early_attempted := true} = State, Deadline) ->
    case quic_h3:request(Connection, Headers, #{end_stream => false}) of
        {error, not_connected} ->
            case Deadline - erlang:monotonic_time(millisecond) of
                Remaining when Remaining > 0 ->
                    receive
                    after erlang:min(?RETRY_INTERVAL, Remaining) ->
                        request_when_ready(Connection, Headers, State, Deadline)
                    end;
                _ ->
                    {error, timeout}
            end;
        Result ->
            Result
    end;
request_when_ready(Connection, Headers, _State, _Deadline) ->
    quic_h3:request(Connection, Headers, #{end_stream => false}).

early_method_allowed(_Headers, #{early_attempted := false}) -> true;
early_method_allowed(Headers, #{early_attempted := true}) ->
    lists:member(request_method(Headers), [<<"GET">>, <<"HEAD">>, <<"OPTIONS">>]).

request_method(Headers) ->
    proplists:get_value(<<":method">>, Headers, <<"UNKNOWN">>).

with_transport_stream(StreamId, State, Fun) ->
    case maps:find(StreamId, maps:get(streams, State)) of
        {ok, Stream} -> Fun(Stream);
        error -> {reply, transport_unknown_stream_error(), State}
    end.

connection_capabilities(State) ->
    case connection_processes(State) of
        {ok, H3Connection, QuicConnection} ->
            Datagrams = quic_h3:h3_datagrams_enabled(H3Connection),
            Migration = active_migration_allowed(QuicConnection),
            Early = maps:get(early_attempted, State),
            Qlog = maps:get(qlog_enabled, State),
            {reply, {ok, {Datagrams, Migration, Early, Qlog}}, State};
        {error, Error} ->
            {reply, Error, State}
    end.

active_migration_allowed(QuicConnection) ->
    case quic:get_peer_transport_params(QuicConnection) of
        {ok, Parameters} -> not maps:get(disable_active_migration, Parameters, false);
        {error, _} -> false
    end.

stream_max_datagram_size(Stream, State) ->
    case stream_transport_available(Stream, State) of
        {ok, Connection} ->
            case quic_h3:h3_datagrams_enabled(Connection) of
                false -> {reply, transport_datagrams_disabled_error(), State};
                true ->
                    Maximum = quic_h3:max_datagram_size(Connection, maps:get(id, Stream)),
                    {reply, {ok, Maximum}, State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

send_stream_datagram(Stream, Payload, State) ->
    case stream_transport_available(Stream, State) of
        {ok, Connection} ->
            StreamId = maps:get(id, Stream),
            Maximum = quic_h3:max_datagram_size(Connection, StreamId),
            case {quic_h3:h3_datagrams_enabled(Connection), byte_size(Payload) =< Maximum} of
                {false, _} ->
                    {reply, transport_datagrams_disabled_error(), State};
                {true, false} ->
                    {reply, transport_datagram_too_large_error(Maximum), State};
                {true, true} ->
                    case quic_h3:send_datagram(Connection, StreamId, Payload) of
                        ok -> {reply, {ok, nil}, State};
                        {error, h3_datagrams_disabled} ->
                            {reply, transport_datagrams_disabled_error(), State};
                        {error, unknown_stream} ->
                            {reply, transport_unknown_stream_error(), State};
                        {error, datagram_too_large} ->
                            {reply, transport_datagram_too_large_error(Maximum), State};
                        {error, datagram_too_large_for_path} ->
                            {reply, transport_datagram_too_large_error(Maximum), State};
                        {error, congestion_limited} ->
                            {reply, transport_congestion_error(), State};
                        {error, Reason} ->
                            {reply, transport_backend_error(Reason), State}
                    end
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

next_stream_datagram(StreamId, State) ->
    case maps:find(StreamId, maps:get(streams, State)) of
        error ->
            {reply, transport_unknown_stream_error(), State};
        {ok, Stream} ->
            case queue:out(maps:get(datagram_queue, Stream)) of
                {{value, Payload}, Queue} ->
                    Bytes = max(0, maps:get(datagram_bytes, Stream) - byte_size(Payload)),
                    update_transport_stream_reply(
                        Stream#{datagram_queue => Queue, datagram_bytes => Bytes},
                        {ok, Payload},
                        State
                    );
                {empty, _} ->
                    next_empty_datagram(StreamId, Stream, State)
            end
    end.

next_empty_datagram(StreamId, Stream, State) ->
    case maps:get(datagram_error, Stream) of
        undefined ->
            case {
                maps:get(terminal, Stream),
                maps:get(response_state, Stream),
                maps:get(datagram_waiter, Stream)
            } of
                {Terminal, _, _} when Terminal =/= undefined ->
                    {reply, transport_closed_error(), State};
                {_, complete, _} ->
                    {reply, transport_unknown_stream_error(), State};
                {_, _, undefined} ->
                    {wait_datagram, StreamId, State};
                _ ->
                    {reply, transport_concurrent_datagram_error(), State}
            end;
        Error ->
            update_transport_stream_reply(
                Stream#{datagram_error => undefined}, {error, Error}, State
            )
    end.

update_transport_stream_reply(Stream, Result, State) ->
    StreamId = maps:get(id, Stream),
    Streams = maps:get(streams, State),
    {reply, Result, State#{streams => Streams#{StreamId => Stream}}}.

set_stream_priority(Stream, Urgency, Incremental, State) ->
    case stream_quic_connection(Stream, State) of
        {ok, QuicConnection} ->
            case quic:set_stream_priority(
                QuicConnection, maps:get(id, Stream), Urgency, Incremental
            ) of
                ok -> {reply, {ok, nil}, State};
                {error, unknown_stream} -> {reply, transport_unknown_stream_error(), State};
                {error, Reason} -> {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

get_stream_priority(Stream, State) ->
    case stream_quic_connection(Stream, State) of
        {ok, QuicConnection} ->
            case quic:get_stream_priority(QuicConnection, maps:get(id, Stream)) of
                {ok, Priority} -> {reply, {ok, Priority}, State};
                {error, unknown_stream} -> {reply, transport_unknown_stream_error(), State};
                {error, Reason} -> {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

connection_early_data_status(#{early_attempted := false}) ->
    {ok, 0};
connection_early_data_status(State) ->
    case maps:get(connection, State, undefined) of
        undefined -> transport_closed_error();
        Connection ->
            case quic_h3:early_data_accepted(Connection) of
                unknown -> {ok, 1};
                true -> {ok, 2};
                false -> {ok, 3}
            end
    end.

current_resumption_ticket(State) ->
    case {maps:get(connection, State, undefined), maps:get(latest_ticket, State)} of
        {undefined, _} -> {reply, transport_closed_error(), State};
        {_, undefined} -> {wait_ticket, State};
        {_, Ticket} ->
            Handle = {
                http3_resumption_ticket,
                maps:get(host, State),
                maps:get(port, State),
                maps:get(peer_address, State),
                Ticket
            },
            {reply, {ok, Handle}, State}
    end.

migrate_connection(State) ->
    case connection_processes(State) of
        {ok, _H3Connection, QuicConnection} ->
            case active_migration_allowed(QuicConnection) of
                false -> {reply, transport_migration_error(), State};
                true ->
                    case quic:migrate(QuicConnection, #{timeout => maps:get(timeout, State)}) of
                        ok -> {reply, {ok, nil}, State};
                        {error, _} -> {reply, transport_migration_error(), State}
                    end
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

set_connection_congestion_control(AlgorithmCode, State) ->
    case connection_processes(State) of
        {ok, _H3Connection, QuicConnection} ->
            Algorithm = congestion_algorithm(AlgorithmCode),
            case quic:set_congestion_control(QuicConnection, Algorithm) of
                ok -> {reply, {ok, nil}, State};
                {error, not_connected} -> {reply, transport_not_connected_error(), State};
                {error, Reason} -> {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

congestion_algorithm(1) -> newreno;
congestion_algorithm(2) -> cubic;
congestion_algorithm(3) -> bbr;
congestion_algorithm(_) -> invalid.

ping_connection(State) ->
    with_quic_connection(State, fun(QuicConnection) -> quic:send_ping(QuicConnection) end).

connection_mtu(State) ->
    with_quic_connection(State, fun(QuicConnection) -> quic:get_mtu(QuicConnection) end).

connection_path_stats(State) ->
    case connection_processes(State) of
        {ok, _H3Connection, QuicConnection} ->
            case quic:get_path_stats(QuicConnection) of
                {ok, Stats} ->
                    Value = {
                        maps:get(srtt, Stats),
                        maps:get(latest_rtt, Stats),
                        maps:get(min_rtt, Stats),
                        maps:get(rtt_var, Stats),
                        maps:get(cwnd, Stats),
                        maps:get(bytes_in_flight, Stats),
                        maps:get(in_recovery, Stats),
                        maps:get(congested, Stats)
                    },
                    {reply, {ok, Value}, State};
                {error, not_connected} ->
                    {reply, transport_not_connected_error(), State};
                {error, Reason} ->
                    {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

connection_statistics(State) ->
    case connection_processes(State) of
        {ok, _H3Connection, QuicConnection} ->
            case quic:get_stats(QuicConnection) of
                {ok, Stats} ->
                    Value = {
                        maps:get(packets_received, Stats),
                        maps:get(packets_sent, Stats),
                        maps:get(data_received, Stats),
                        maps:get(data_sent, Stats),
                        maps:get(ack_sent, Stats),
                        maps:get(retransmits, Stats),
                        maps:get(batch_flushes, Stats),
                        maps:get(packets_coalesced, Stats)
                    },
                    {reply, {ok, Value}, State};
                {error, Reason} ->
                    {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

with_quic_connection(State, Operation) ->
    case connection_processes(State) of
        {ok, _H3Connection, QuicConnection} ->
            case Operation(QuicConnection) of
                ok -> {reply, {ok, nil}, State};
                {ok, Value} -> {reply, {ok, Value}, State};
                {error, not_connected} -> {reply, transport_not_connected_error(), State};
                {error, Reason} -> {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

stream_transport_available(Stream, State) ->
    case maps:get(response_state, Stream) of
        complete -> {error, transport_unknown_stream_error()};
        _ ->
            case maps:get(terminal, Stream) of
                undefined ->
                    case maps:get(connection, State, undefined) of
                        undefined -> {error, transport_closed_error()};
                        Connection -> {ok, Connection}
                    end;
                _ -> {error, transport_closed_error()}
            end
    end.

stream_quic_connection(Stream, State) ->
    case stream_transport_available(Stream, State) of
        {ok, Connection} ->
            try {ok, quic_h3:get_quic_conn(Connection)} catch
                _:_ -> {error, transport_closed_error()}
            end;
        {error, Error} -> {error, Error}
    end.

connection_processes(State) ->
    case maps:get(connection, State, undefined) of
        undefined -> {error, transport_closed_error()};
        H3Connection ->
            try {ok, H3Connection, quic_h3:get_quic_conn(H3Connection)} catch
                _:_ -> {error, transport_closed_error()}
            end
    end.

with_stream(StreamId, State, Fun) ->
    case maps:find(StreamId, maps:get(streams, State)) of
        {ok, Stream} -> Fun(Stream);
        error -> {reply, stream_finished_error(), State}
    end.

send_chunk_on_stream(StreamId, Chunk, Stream, State) ->
    case request_operation_error(Stream) of
        {error, Error} -> {reply, Error, State};
        ok ->
            NewSent = maps:get(sent, Stream) + byte_size(Chunk),
            case exceeds_declared_length(NewSent, maps:get(declared_length, Stream)) of
                true ->
                    {reply, content_length_error(), State};
                false ->
                    Deadline = maps:get(deadline, Stream),
                    case send_with_backpressure(
                        maps:get(connection, State),
                        StreamId,
                        Chunk,
                        false,
                        Deadline,
                        maps:get(early_attempted, State)
                    ) of
                        ok ->
                            update_stream_reply(StreamId, Stream#{sent => NewSent}, {ok, nil}, State);
                        {error, _} = Error ->
                            {reply, Error, State}
                    end
            end
    end.

finish_stream(StreamId, Stream, State) ->
    case request_operation_error(Stream) of
        {error, Error} -> {reply, Error, State};
        ok ->
            case content_length_matches(Stream) of
                false ->
                    {reply, content_length_error(), State};
                true ->
                    Deadline = maps:get(deadline, Stream),
                    case send_with_backpressure(
                        maps:get(connection, State),
                        StreamId,
                        <<>>,
                        true,
                        Deadline,
                        maps:get(early_attempted, State)
                    ) of
                        ok ->
                            update_stream_reply(
                                StreamId, Stream#{request_state => finished}, {ok, nil}, State
                            );
                        {error, _} = Error ->
                            {reply, Error, State}
                    end
            end
    end.

request_operation_error(Stream) ->
    case maps:get(request_state, Stream) of
        open -> ok;
        finished -> {error, request_finished_error()};
        cancelled -> {error, stream_cancelled_error()};
        failed -> {error, terminal_or_finished(Stream)}
    end.

terminal_or_finished(Stream) ->
    case maps:get(terminal, Stream) of
        undefined -> stream_finished_error();
        Error -> {error, Error}
    end.

exceeds_declared_length(_Sent, undefined) -> false;
exceeds_declared_length(Sent, Declared) -> Sent > Declared.

content_length_matches(Stream) ->
    case maps:get(declared_length, Stream) of
        undefined -> true;
        Declared -> maps:get(sent, Stream) =:= Declared
    end.

send_with_backpressure(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted) ->
    case remaining(Deadline) of
        0 -> timeout_error();
        _ ->
            case send_backend_data(Connection, StreamId, Data, Fin, EarlyAttempted) of
                ok -> ok;
                {error, {flow_control_blocked, _}} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted);
                {error, flow_control_blocked} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted);
                {error, send_queue_full} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted);
                {error, congestion_limited} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted);
                {error, not_connected} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted);
                {error, timeout} -> timeout_error();
                {error, unknown_stream} -> stream_finished_error();
                {error, Reason} -> request_error(Reason)
            end
    end.

send_backend_data(Connection, StreamId, Data, Fin, true) ->
    case quic_h3:early_data_accepted(Connection) of
        unknown -> send_early_stream_data(Connection, StreamId, Data, Fin);
        _ -> quic_h3:send_data(Connection, StreamId, Data, Fin)
    end;
send_backend_data(Connection, StreamId, Data, Fin, false) ->
    quic_h3:send_data(Connection, StreamId, Data, Fin).

%% The selected backend accepts request HEADERS in its early-data state but
%% does not handle its own send_data call there. The H3 request stream and
%% QPACK state were already registered by quic_h3:request/3, so frame the
%% request DATA at this private boundary and send it over the same QUIC stream.
%% The zero-length DATA frame on finish matches the backend's normal path and
%% ensures every conforming peer reports request-body completion.
send_early_stream_data(Connection, StreamId, Data, Fin) ->
    try quic_h3:get_quic_conn(Connection) of
        QuicConnection ->
            Payload = quic_h3_frame:encode_data(Data),
            quic:send_data(QuicConnection, StreamId, Payload, Fin)
    catch
        exit:{noproc, _} -> {error, not_connected};
        exit:normal -> {error, not_connected};
        Class:Reason -> {error, {Class, Reason}}
    end.

retry_send(Connection, StreamId, Data, Fin, Deadline, EarlyAttempted) ->
    Wait = min(?RETRY_INTERVAL, remaining(Deadline)),
    receive after Wait -> ok end,
    send_with_backpressure(
        Connection, StreamId, Data, Fin, Deadline, EarlyAttempted
    ).

next_stream_event(StreamId, State) ->
    case maps:find(StreamId, maps:get(streams, State)) of
        error ->
            {reply, stream_finished_error(), State};
        {ok, Stream} ->
            case queue:out(maps:get(queue, Stream)) of
                {{value, Event}, Queue} ->
                    Size = max(0, maps:get(queued_bytes, Stream) - event_size(Event)),
                    update_stream_reply(
                        StreamId,
                        Stream#{queue => Queue, queued_bytes => Size},
                        {ok, Event},
                        State
                    );
                {empty, _} ->
                    next_empty_stream_event(StreamId, Stream, State)
            end
    end.

next_empty_stream_event(StreamId, Stream, State) ->
    case maps:get(terminal, Stream) of
        undefined ->
            case maps:get(response_state, Stream) of
                complete -> {reply, stream_finished_error(), State};
                _ ->
                    case maps:get(waiter, Stream) of
                        undefined -> {wait, StreamId, State};
                        _ -> {reply, concurrent_receive_error(), State}
                    end
            end;
        Error ->
            {reply, {error, Error}, State}
    end.

cancel_stream(StreamId, State) ->
    case maps:find(StreamId, maps:get(streams, State)) of
        error ->
            {reply, {ok, 3}, State};
        {ok, Stream} ->
            case maps:get(response_state, Stream) of
                complete ->
                    {reply, {ok, 3}, State};
                _ ->
                    case maps:get(request_state, Stream) of
                        cancelled ->
                            {reply, {ok, 2}, State};
                        _ ->
                            safe_cancel(maps:get(connection, State, undefined), StreamId),
                            Cancelled = set_terminal(Stream, stream_cancelled_error()),
                            update_stream_reply(
                                StreamId,
                                Cancelled#{request_state => cancelled},
                                {ok, 1},
                                State
                            )
                    end
            end
    end.

update_stream_reply(StreamId, Stream, Result, State) ->
    Streams = maps:get(streams, State),
    {reply, Result, State#{streams => Streams#{StreamId => Stream}}}.

handle_h3_event({response, StreamId, Status, Headers}, State) when
    is_integer(Status), Status >= 100, Status < 200
->
    update_event_stream(StreamId, State, fun(Stream) ->
        case maps:get(response_state, Stream) of
            awaiting_headers -> enqueue_event({?EVENT_INFORMATIONAL, Status, public_headers(Headers), <<>>}, Stream, State);
            _ -> protocol_fail_stream(Stream, <<"informational response after final headers">>)
        end
    end);
handle_h3_event({response, StreamId, Status, Headers}, State) when is_integer(Status) ->
    update_event_stream(StreamId, State, fun(Stream) ->
        case maps:get(response_state, Stream) of
            awaiting_headers ->
                Enqueued = enqueue_event(
                    {?EVENT_RESPONSE, Status, public_headers(Headers), <<>>}, Stream, State
                ),
                Enqueued#{response_state => response_body};
            _ -> protocol_fail_stream(Stream, <<"duplicate final response headers">>)
        end
    end);
handle_h3_event({data, StreamId, Data, Fin}, State) when is_binary(Data) ->
    update_event_stream(StreamId, State, fun(Stream) ->
        handle_response_data(Data, Fin, Stream, State)
    end);
handle_h3_event({trailers, StreamId, Headers}, State) ->
    update_event_stream(StreamId, State, fun(Stream) ->
        case maps:get(response_state, Stream) of
            response_body ->
                WithTrailers = enqueue_event(
                    {?EVENT_TRAILERS, 0, public_headers(Headers), <<>>}, Stream, State
                ),
                complete_stream(WithTrailers, State);
            _ -> protocol_fail_stream(Stream, <<"trailers before final response headers">>)
        end
    end);
handle_h3_event({stream_reset, StreamId, ErrorCode}, State) ->
    update_event_stream(StreamId, State, fun(Stream) ->
        set_terminal(Stream#{request_state => failed}, stream_reset_error(ErrorCode))
    end);
handle_h3_event({datagram, StreamId, Payload}, State) when is_binary(Payload) ->
    update_event_stream(StreamId, State, fun(Stream) ->
        enqueue_stream_datagram(Payload, Stream, State)
    end);
handle_h3_event({session_ticket, Ticket}, State) ->
    case maps:get(ticket_waiter, State) of
        {From, Ref, _Deadline} ->
            Handle = {
                http3_resumption_ticket,
                maps:get(host, State),
                maps:get(port, State),
                maps:get(peer_address, State),
                Ticket
            },
            reply(From, Ref, {ok, Handle}),
            State#{latest_ticket => Ticket, ticket_waiter => undefined};
        undefined ->
            State#{latest_ticket => Ticket}
    end;
handle_h3_event({early_data_rejected, StreamIds}, State) when is_list(StreamIds) ->
    lists:foldl(
        fun(StreamId, Acc) ->
            update_event_stream(StreamId, Acc, fun(Stream) ->
                set_terminal(
                    Stream#{request_state => failed}, request_error(early_data_rejected)
                )
            end)
        end,
        State,
        StreamIds
    );
handle_h3_event({error, ErrorCode, Reason}, State) ->
    fail_all_streams(protocol_error(ErrorCode, reason_text(Reason)), State);
handle_h3_event({closed, Reason}, State) ->
    fail_connection(Reason, State);
handle_h3_event(closed, State) ->
    fail_connection(connection_closed, State);
handle_h3_event({goaway, _LastStreamId}, State) ->
    State#{accepting => false};
handle_h3_event(_Event, State) ->
    State.

enqueue_stream_datagram(Payload, Stream, State) ->
    case {maps:get(datagram_waiter, Stream), maps:get(datagram_error, Stream)} of
        {{From, Ref}, undefined} ->
            reply(From, Ref, {ok, Payload}),
            Stream#{datagram_waiter => undefined};
        {undefined, undefined} ->
            Bytes = maps:get(datagram_bytes, Stream) + byte_size(Payload),
            Limit = maps:get(buffer_limit, State),
            case Bytes > Limit of
                true ->
                    Stream#{
                        datagram_queue => queue:new(),
                        datagram_bytes => 0,
                        datagram_error => transport_datagram_buffer_raw(Limit)
                    };
                false ->
                    Stream#{
                        datagram_queue => queue:in(Payload, maps:get(datagram_queue, Stream)),
                        datagram_bytes => Bytes
                    }
            end;
        _ ->
            Stream
    end.

handle_response_data(Data, Fin, Stream, State) ->
    case maps:get(response_state, Stream) of
        response_body ->
            WithData = case byte_size(Data) of
                0 -> Stream;
                _ -> enqueue_event({?EVENT_DATA, 0, [], Data}, Stream, State)
            end,
            case {Fin, maps:get(terminal, WithData)} of
                {true, undefined} -> complete_stream(WithData, State);
                _ -> WithData
            end;
        _ ->
            protocol_fail_stream(Stream, <<"response data before final headers">>)
    end.

complete_stream(Stream, State) ->
    case maps:get(terminal, Stream) of
        undefined ->
            Completed = (enqueue_event({?EVENT_END, 0, [], <<>>}, Stream, State))#{
                response_state => complete
            },
            close_datagram_waiter(Completed, transport_unknown_stream_error());
        _ -> Stream
    end.

protocol_fail_stream(Stream, Message) ->
    set_terminal(Stream#{request_state => failed}, protocol_error(0, Message)).

update_event_stream(StreamId, State, Fun) ->
    Streams = maps:get(streams, State),
    case maps:find(StreamId, Streams) of
        {ok, Stream} -> State#{streams => Streams#{StreamId => Fun(Stream)}};
        error -> State
    end.

enqueue_event(Event, Stream, State) ->
    case maps:get(terminal, Stream) of
        undefined ->
            case maps:get(waiter, Stream) of
                {From, Ref} ->
                    reply(From, Ref, {ok, Event}),
                    Stream#{waiter => undefined};
                undefined ->
                    NewSize = maps:get(queued_bytes, Stream) + event_size(Event),
                    Limit = maps:get(buffer_limit, State),
                    case NewSize > Limit of
                        true ->
                            safe_cancel(maps:get(connection, State, undefined), maps:get(id, Stream)),
                            set_terminal(
                                Stream#{request_state => cancelled}, consumer_slow_error(Limit)
                            );
                        false ->
                            Stream#{
                                queue => queue:in(Event, maps:get(queue, Stream)),
                                queued_bytes => NewSize
                            }
                    end
            end;
        _ -> Stream
    end.

event_size({?EVENT_DATA, _Status, _Headers, Data}) -> byte_size(Data);
event_size(_Event) -> 0.

set_terminal(Stream, ErrorResult) ->
    Error = case ErrorResult of
        {error, RawError} -> RawError;
        RawError -> RawError
    end,
    case maps:get(waiter, Stream) of
        {From, Ref} -> reply(From, Ref, {error, Error});
        undefined -> ok
    end,
    case maps:get(datagram_waiter, Stream) of
        {DatagramFrom, DatagramRef} ->
            reply(DatagramFrom, DatagramRef, transport_closed_error());
        undefined -> ok
    end,
    Stream#{
        queue => queue:new(),
        queued_bytes => 0,
        waiter => undefined,
        datagram_queue => queue:new(),
        datagram_bytes => 0,
        datagram_waiter => undefined,
        terminal => Error,
        response_state => failed
    }.

close_datagram_waiter(Stream, Result) ->
    case maps:get(datagram_waiter, Stream) of
        {From, Ref} ->
            reply(From, Ref, Result),
            Stream#{datagram_waiter => undefined};
        undefined ->
            Stream
    end.

fail_connection(_Reason, State) ->
    State1 = case maps:get(ticket_waiter, State) of
        {From, Ref, _Deadline} ->
            reply(From, Ref, transport_closed_error()),
            State#{ticket_waiter => undefined};
        undefined -> State
    end,
    fail_all_streams(
        closed_error(), State1#{connection => undefined, accepting => false}
    ).

fail_all_streams(ErrorResult, State) ->
    Streams = maps:map(
        fun(_StreamId, Stream) ->
            case {maps:get(response_state, Stream), maps:get(terminal, Stream)} of
                {complete, _} -> Stream;
                {_, undefined} -> set_terminal(Stream#{request_state => failed}, ErrorResult);
                _ -> Stream
            end
        end,
        maps:get(streams, State)
    ),
    State#{streams => Streams}.

expire_streams(State) ->
    Now = erlang:monotonic_time(millisecond),
    Connection = maps:get(connection, State, undefined),
    Streams = maps:map(
        fun(StreamId, Stream) ->
            case stream_is_active(Stream) andalso maps:get(deadline, Stream) =< Now of
                true ->
                    safe_cancel(Connection, StreamId),
                    set_terminal(Stream#{request_state => failed}, timeout_error());
                false -> Stream
            end
        end,
        maps:get(streams, State)
    ),
    State1 = State#{streams => Streams},
    case maps:get(ticket_waiter, State1) of
        {From, Ref, Deadline} when Deadline =< Now ->
            reply(From, Ref, transport_timeout_error()),
            State1#{ticket_waiter => undefined};
        _ ->
            State1
    end.

stream_is_active(Stream) ->
    maps:get(response_state, Stream) =/= complete andalso
        maps:get(terminal, Stream) =:= undefined.

next_deadline_wait(State) ->
    Now = erlang:monotonic_time(millisecond),
    Deadlines = [
        maps:get(deadline, Stream)
     || {_StreamId, Stream} <- maps:to_list(maps:get(streams, State)),
        stream_is_active(Stream)
    ],
    TicketDeadlines = case maps:get(ticket_waiter, State) of
        {_From, _Ref, Deadline} -> [Deadline];
        undefined -> []
    end,
    case Deadlines ++ TicketDeadlines of
        [] -> infinity;
        AllDeadlines -> max(0, lists:min(AllDeadlines) - Now)
    end.

same_origin(Host, Port, State) ->
    Port =:= maps:get(port, State) andalso string:equal(Host, maps:get(host, State), true).

public_headers(Headers) ->
    [
        {Name, Value}
     || {Name, Value} <- Headers,
        is_binary(Name),
        is_binary(Value),
        not is_pseudo_header(Name)
    ].

is_pseudo_header(<<":", _/binary>>) -> true;
is_pseudo_header(_) -> false.

safe_cancel(undefined, _StreamId) -> ok;
safe_cancel(Connection, StreamId) ->
    try quic_h3:cancel(Connection, StreamId) of
        _ -> ok
    catch
        _:_ -> ok
    end.

shutdown(State) ->
    case maps:get(ticket_waiter, State) of
        {TicketFrom, TicketRef, _Deadline} ->
            reply(TicketFrom, TicketRef, transport_closed_error());
        undefined -> ok
    end,
    fail_all_streams(closed_error(), State),
    case maps:get(connection, State, undefined) of
        undefined -> ok;
        Connection -> close_connection(Connection)
    end,
    ok.

close_connection(Connection) ->
    Monitor = monitor(process, Connection),
    unlink(Connection),
    try quic_h3:close(Connection) catch _:_ -> ok end,
    receive
        {'DOWN', Monitor, process, Connection, _Reason} -> ok
    after ?CLEANUP_TIMEOUT ->
        exit(Connection, kill),
        receive
            {'DOWN', Monitor, process, Connection, _Reason} -> ok
        after ?CLEANUP_TIMEOUT ->
            demonitor(Monitor, [flush]),
            ok
        end
    end.

reply(To, Ref, Result) -> To ! {Ref, Result}.

await_worker_down(Worker, Monitor) ->
    receive
        {'DOWN', Monitor, process, Worker, _Reason} -> ok
    after ?CLEANUP_TIMEOUT ->
        demonitor(Monitor, [flush]),
        ok
    end.

remaining(Deadline) -> max(0, Deadline - erlang:monotonic_time(millisecond)).

connect_error(Reason) -> {error, {?ERROR_CONNECT, 0, reason_text(Reason)}}.
request_error(Reason) -> {error, {?ERROR_REQUEST, 0, reason_text(Reason)}}.
timeout_error() -> {error, {?ERROR_TIMEOUT, 0, <<"stream timeout">>}}.
closed_error() -> {error, {?ERROR_CLOSED, 0, <<"connection closed">>}}.
stream_reset_error(Code) -> {error, {?ERROR_STREAM_RESET, Code, <<"stream reset">>}}.
protocol_error(Code, Message) -> {error, {?ERROR_PROTOCOL, Code, reason_text(Message)}}.
content_length_error() -> {error, {?ERROR_CONTENT_LENGTH, 0, <<"invalid content length">>}}.
consumer_slow_error(Limit) ->
    {error, {?ERROR_CONSUMER_SLOW, Limit, <<"stream receive buffer limit exceeded">>}}.
concurrent_receive_error() ->
    {error, {?ERROR_CONCURRENT_RECEIVE, 0, <<"concurrent stream receive">>}}.
request_finished_error() ->
    {error, {?ERROR_REQUEST_FINISHED, 0, <<"request stream already finished">>}}.
stream_finished_error() ->
    {error, {?ERROR_STREAM_FINISHED, 0, <<"response stream finished">>}}.
stream_cancelled_error() ->
    {error, {?ERROR_STREAM_CANCELLED, 0, <<"stream cancelled">>}}.
origin_error() -> {error, {?ERROR_ORIGIN, 0, <<"request origin mismatch">>}}.
unsafe_early_method_error(Method) ->
    {error, {?ERROR_EARLY_METHOD, 0, reason_text(Method)}}.
resumption_origin_error() ->
    {error, {?ERROR_RESUMPTION_ORIGIN, 0, <<"resumption ticket origin mismatch">>}}.
backend_error(Reason) -> {error, {?ERROR_BACKEND, 0, reason_text(Reason)}}.

transport_closed_error() ->
    {error, {?TRANSPORT_ERROR_CLOSED, 0, <<"transport connection closed">>}}.
transport_timeout_error() ->
    {error, {?TRANSPORT_ERROR_TIMEOUT, 0, <<"transport operation timeout">>}}.
transport_datagrams_disabled_error() ->
    {error, {?TRANSPORT_ERROR_DATAGRAMS_DISABLED, 0, <<"HTTP Datagrams not negotiated">>}}.
transport_datagram_too_large_error(Maximum) ->
    {error, {?TRANSPORT_ERROR_DATAGRAM_TOO_LARGE, Maximum, <<"HTTP Datagram too large">>}}.
transport_congestion_error() ->
    {error, {?TRANSPORT_ERROR_CONGESTION, 0, <<"datagram congestion limited">>}}.
transport_unknown_stream_error() ->
    {error, {?TRANSPORT_ERROR_UNKNOWN_STREAM, 0, <<"unknown transport stream">>}}.
transport_datagram_buffer_raw(Limit) ->
    {?TRANSPORT_ERROR_DATAGRAM_BUFFER, Limit, <<"datagram receive buffer limit exceeded">>}.
transport_concurrent_datagram_error() ->
    {error, {?TRANSPORT_ERROR_CONCURRENT_DATAGRAM, 0, <<"concurrent datagram receive">>}}.
transport_migration_error() ->
    {error, {?TRANSPORT_ERROR_MIGRATION, 0, <<"active migration unavailable">>}}.
transport_not_connected_error() ->
    {error, {?TRANSPORT_ERROR_NOT_CONNECTED, 0, <<"transport not connected">>}}.
transport_backend_error(Reason) ->
    {error, {?TRANSPORT_ERROR_BACKEND, 0, reason_text(Reason)}}.

reason_text(Reason) when is_binary(Reason) -> truncate_reason(Reason);
reason_text(Reason) -> truncate_reason(iolist_to_binary(io_lib:format("~0p", [Reason]))).

truncate_reason(Reason) when byte_size(Reason) =< ?MAX_REASON_BYTES -> Reason;
truncate_reason(Reason) -> binary:part(Reason, 0, ?MAX_REASON_BYTES).
