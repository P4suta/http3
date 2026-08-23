-module(http3_internal_server_ffi).

-export([
    accept/1,
    early_data_status/1,
    finish_response/1,
    get_priority/1,
    max_datagram_size/1,
    next_event/1,
    next_datagram/1,
    port/1,
    respond/4,
    send_chunk/2,
    send_datagram/2,
    send_response/4,
    set_priority/3,
    start/9,
    stop/1,
    transport_stream_capabilities/1,
    valid_certificate/1,
    valid_private_key/1
]).

-define(CLEANUP_TIMEOUT, 250).
-define(WORKER_GRACE, 600).
-define(RETRY_INTERVAL, 2).
-define(MAX_REASON_BYTES, 1024).
-define(MAX_PENDING_REQUESTS, 1024).

-define(ERROR_START, 1).
-define(ERROR_TIMEOUT, 2).
-define(ERROR_LISTENER_CLOSED, 3).
-define(ERROR_CONNECTION_CLOSED, 4).
-define(ERROR_STREAM_RESET, 5).
-define(ERROR_PROTOCOL, 6).
-define(ERROR_REQUEST_LIMIT, 7).
-define(ERROR_RESPONSE_LIMIT, 8).
-define(ERROR_CONSUMER_SLOW, 9).
-define(ERROR_CONCURRENT_ACCEPT, 10).
-define(ERROR_CONCURRENT_RECEIVE, 11).
-define(ERROR_RESPONSE_STARTED, 12).
-define(ERROR_RESPONSE_NOT_STARTED, 13).
-define(ERROR_RESPONSE_FINISHED, 14).
-define(ERROR_CONTENT_LENGTH, 15).
-define(ERROR_BACKEND, 99).

-define(TRANSPORT_ERROR_CLOSED, 1).
-define(TRANSPORT_ERROR_TIMEOUT, 2).
-define(TRANSPORT_ERROR_DATAGRAMS_DISABLED, 3).
-define(TRANSPORT_ERROR_DATAGRAM_TOO_LARGE, 4).
-define(TRANSPORT_ERROR_CONGESTION, 5).
-define(TRANSPORT_ERROR_UNKNOWN_STREAM, 6).
-define(TRANSPORT_ERROR_DATAGRAM_BUFFER, 7).
-define(TRANSPORT_ERROR_CONCURRENT_DATAGRAM, 8).
-define(TRANSPORT_ERROR_NOT_CONNECTED, 10).
-define(TRANSPORT_ERROR_BACKEND, 99).

-define(EVENT_DATA, 1).
-define(EVENT_TRAILERS, 2).
-define(EVENT_END, 3).

-type raw_error() :: {integer(), integer(), binary()}.
-type result(Value) :: {ok, Value} | {error, raw_error()}.
-type listener_handle() :: {http3_listener, pid(), pos_integer()}.
-type request_handle() :: {http3_request, pid(), non_neg_integer(), pos_integer()}.

-spec valid_certificate(bitstring()) -> boolean().
valid_certificate(Pem) when is_binary(Pem), byte_size(Pem) > 0 ->
    case decode_certificate(Pem) of
        {ok, _Certificate} -> true;
        {error, _Reason} -> false
    end;
valid_certificate(_Pem) ->
    false.

-spec valid_private_key(bitstring()) -> boolean().
valid_private_key(Pem) when is_binary(Pem), byte_size(Pem) > 0 ->
    case decode_private_key(Pem) of
        {ok, _PrivateKey} -> true;
        {error, _Reason} -> false
    end;
valid_private_key(_Pem) ->
    false.

-spec start(
    binary(),
    binary(),
    non_neg_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    boolean(),
    binary()
) ->
    result(listener_handle()).
start(
    CertificatePem,
    PrivateKeyPem,
    Port,
    Timeout,
    RequestLimit,
    ResponseLimit,
    BufferLimit,
    Datagrams,
    QlogDirectory
) when
    is_binary(CertificatePem),
    is_binary(PrivateKeyPem),
    is_integer(Port),
    Port >= 0,
    Port =< 65535,
    is_integer(Timeout),
    Timeout > 0,
    is_integer(RequestLimit),
    RequestLimit > 0,
    is_integer(ResponseLimit),
    ResponseLimit > 0,
    is_integer(BufferLimit),
    BufferLimit > 0,
    is_boolean(Datagrams),
    is_binary(QlogDirectory)
->
    Owner = self(),
    ReplyRef = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        initialise(
            Owner,
            ReplyRef,
            CertificatePem,
            PrivateKeyPem,
            Port,
            Timeout,
            RequestLimit,
            ResponseLimit,
            BufferLimit,
            Datagrams,
            QlogDirectory
        )
    end),
    receive
        {ReplyRef, {ok, ready}} ->
            demonitor(Monitor, [flush]),
            {ok, {http3_listener, Worker, Timeout}};
        {ReplyRef, {error, _} = Error} ->
            await_worker_down(Worker, Monitor),
            Error;
        {'DOWN', Monitor, process, Worker, Reason} ->
            receive
                {ReplyRef, {error, _} = Error} -> Error
            after 0 ->
                backend_error({listener_worker_stopped, Reason})
            end
    after Timeout + ?WORKER_GRACE ->
        exit(Worker, kill),
        await_worker_down(Worker, Monitor),
        timeout_error()
    end;
start(
    _Certificate,
    _PrivateKey,
    _Port,
    _Timeout,
    _RequestLimit,
    _ResponseLimit,
    _BufferLimit,
    _Datagrams,
    _QlogDirectory
) ->
    backend_error(invalid_start_arguments).

-spec port(listener_handle()) -> result(inet:port_number()).
port({http3_listener, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_worker(Worker, port, Timeout);
port(_Listener) ->
    backend_error(invalid_listener_handle).

-spec accept(listener_handle()) -> result(tuple()).
accept({http3_listener, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    call_worker(Worker, accept, Timeout);
accept(_Listener) ->
    backend_error(invalid_listener_handle).

-spec next_event(request_handle()) -> result(tuple()).
next_event({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout)
->
    call_worker(Worker, {next_event, RequestId}, Timeout);
next_event(_Request) ->
    backend_error(invalid_request_handle).

-spec respond(request_handle(), integer(), list(), bitstring()) -> result(nil).
respond({http3_request, Worker, RequestId, Timeout}, Status, Headers, Body) when
    is_pid(Worker),
    is_integer(RequestId),
    is_integer(Status),
    is_list(Headers),
    is_binary(Body)
->
    call_worker(Worker, {respond, RequestId, Status, Headers, Body}, Timeout);
respond(_Request, _Status, _Headers, _Body) ->
    backend_error(invalid_respond_arguments).

-spec send_response(request_handle(), integer(), list(), integer()) -> result(nil).
send_response(
    {http3_request, Worker, RequestId, Timeout}, Status, Headers, DeclaredContentLength
) when
    is_pid(Worker),
    is_integer(RequestId),
    is_integer(Status),
    is_list(Headers),
    is_integer(DeclaredContentLength)
->
    call_worker(
        Worker,
        {send_response, RequestId, Status, Headers, declared_length(DeclaredContentLength)},
        Timeout
    );
send_response(_Request, _Status, _Headers, _DeclaredContentLength) ->
    backend_error(invalid_send_response_arguments).

declared_length(-1) -> undefined;
declared_length(Length) when Length >= 0 -> Length;
declared_length(_Length) -> invalid.

-spec send_chunk(request_handle(), bitstring()) -> result(nil).
send_chunk({http3_request, Worker, RequestId, Timeout}, Chunk) when
    is_pid(Worker), is_integer(RequestId), is_binary(Chunk)
->
    call_worker(Worker, {send_chunk, RequestId, Chunk}, Timeout);
send_chunk(_Request, _Chunk) ->
    backend_error(invalid_send_chunk_arguments).

-spec finish_response(request_handle()) -> result(nil).
finish_response({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId)
->
    call_worker(Worker, {finish_response, RequestId}, Timeout);
finish_response(_Request) ->
    backend_error(invalid_finish_response_arguments).

-spec transport_stream_capabilities(request_handle()) -> result(tuple()).
transport_stream_capabilities({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout)
->
    call_transport_worker(Worker, {transport_stream_capabilities, RequestId}, Timeout);
transport_stream_capabilities(_Request) ->
    transport_backend_error(invalid_request_handle).

-spec max_datagram_size(request_handle()) -> result(non_neg_integer()).
max_datagram_size({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout)
->
    call_transport_worker(Worker, {max_datagram_size, RequestId}, Timeout);
max_datagram_size(_Request) ->
    transport_backend_error(invalid_request_handle).

-spec send_datagram(request_handle(), bitstring()) -> result(nil).
send_datagram({http3_request, Worker, RequestId, Timeout}, Payload) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout), is_binary(Payload)
->
    call_transport_worker(Worker, {send_datagram, RequestId, Payload}, Timeout);
send_datagram(_Request, _Payload) ->
    transport_backend_error(invalid_datagram_arguments).

-spec next_datagram(request_handle()) -> result(binary()).
next_datagram({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout)
->
    call_transport_worker(Worker, {next_datagram, RequestId}, Timeout);
next_datagram(_Request) ->
    transport_backend_error(invalid_request_handle).

-spec set_priority(request_handle(), 0..7, boolean()) -> result(nil).
set_priority({http3_request, Worker, RequestId, Timeout}, Urgency, Incremental) when
    is_pid(Worker),
    is_integer(RequestId),
    is_integer(Timeout),
    is_integer(Urgency),
    Urgency >= 0,
    Urgency =< 7,
    is_boolean(Incremental)
->
    call_transport_worker(Worker, {set_priority, RequestId, Urgency, Incremental}, Timeout);
set_priority(_Request, _Urgency, _Incremental) ->
    transport_backend_error(invalid_priority).

-spec get_priority(request_handle()) -> result({0..7, boolean()}).
get_priority({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout)
->
    call_transport_worker(Worker, {get_priority, RequestId}, Timeout);
get_priority(_Request) ->
    transport_backend_error(invalid_request_handle).

-spec early_data_status(request_handle()) -> result(0..3).
early_data_status({http3_request, Worker, RequestId, Timeout}) when
    is_pid(Worker), is_integer(RequestId), is_integer(Timeout)
->
    call_transport_worker(Worker, {early_data_status, RequestId}, Timeout);
early_data_status(_Request) ->
    transport_backend_error(invalid_request_handle).

-spec stop(listener_handle()) -> result(integer()).
stop({http3_listener, Worker, Timeout}) when is_pid(Worker), is_integer(Timeout) ->
    case is_process_alive(Worker) of
        true -> call_worker_for_stop(Worker, Timeout);
        false -> {ok, 2}
    end;
stop(_Listener) ->
    backend_error(invalid_listener_handle).

call_worker(Worker, Request, Timeout) ->
    case is_process_alive(Worker) of
        false -> listener_closed_error();
        true ->
            Ref = make_ref(),
            Monitor = monitor(process, Worker),
            Worker ! {server_call, self(), Ref, Request},
            await_call(Worker, Monitor, Ref, Timeout + ?WORKER_GRACE)
    end.

call_transport_worker(Worker, Request, Timeout) ->
    case is_process_alive(Worker) of
        false -> transport_closed_error();
        true ->
            Ref = make_ref(),
            Monitor = monitor(process, Worker),
            Worker ! {server_call, self(), Ref, Request},
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

call_worker_for_stop(Worker, Timeout) ->
    Ref = make_ref(),
    Monitor = monitor(process, Worker),
    Worker ! {server_call, self(), Ref, stop},
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
                    normal -> listener_closed_error();
                    _ -> backend_error({listener_worker_stopped, Reason})
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
    CertificatePem,
    PrivateKeyPem,
    Port,
    Timeout,
    RequestLimit,
    ResponseLimit,
    BufferLimit,
    Datagrams,
    QlogDirectory
) ->
    process_flag(trap_exit, true),
    Result = try
        initialise_listener(
            CertificatePem,
            PrivateKeyPem,
            Port,
            Timeout,
            Datagrams,
            QlogDirectory
        )
    of
        Value -> Value
    catch
        Class:Reason -> start_error({Class, Reason})
    end,
    case Result of
        {ok, Name, Server, BoundPort} ->
            OwnerMonitor = monitor(process, Owner),
            Owner ! {ReplyRef, {ok, ready}},
            loop(#{
                owner => Owner,
                owner_monitor => OwnerMonitor,
                name => Name,
                server => Server,
                port => BoundPort,
                timeout => Timeout,
                request_limit => RequestLimit,
                response_limit => ResponseLimit,
                buffer_limit => BufferLimit,
                datagrams_configured => Datagrams,
                qlog_enabled => QlogDirectory =/= <<>>,
                next_id => 0,
                requests => #{},
                stream_index => #{},
                orphan_errors => #{},
                orphan_datagrams => #{},
                pending => queue:new(),
                accept_waiter => undefined
            });
        {error, _} = Error ->
            Owner ! {ReplyRef, Error}
    end.

initialise_listener(CertificatePem, PrivateKeyPem, Port, Timeout, Datagrams, QlogDirectory) ->
    case {decode_certificate(CertificatePem), decode_private_key(PrivateKeyPem)} of
        {{ok, Certificate}, {ok, PrivateKey}} ->
            case application:ensure_all_started(quic) of
                {ok, _Started} ->
                    ok = ensure_resumption_ticket_store(),
                    start_with_available_name(
                        Certificate,
                        PrivateKey,
                        Port,
                        Timeout,
                        Datagrams,
                        QlogDirectory
                    );
                {error, Reason} -> start_error(Reason)
            end;
        {{error, Reason}, _} -> start_error({invalid_certificate, Reason});
        {_, {error, Reason}} -> start_error({invalid_private_key, Reason})
    end.

ensure_resumption_ticket_store() ->
    case whereis(http3_quic_ticket_keeper) of
        Keeper when is_pid(Keeper) ->
            ok;
        undefined ->
            Parent = self(),
            Ref = make_ref(),
            _ = spawn(fun() -> start_ticket_keeper(Parent, Ref) end),
            receive
                {Ref, ticket_keeper_ready} -> ok;
                {Ref, ticket_keeper_existing} -> ok
            after ?CLEANUP_TIMEOUT ->
                ok
            end
    end.

start_ticket_keeper(Parent, Ref) ->
    try register(http3_quic_ticket_keeper, self()) of
        true ->
            own_ticket_table(),
            Parent ! {Ref, ticket_keeper_ready},
            ticket_keeper_loop()
    catch
        error:badarg ->
            Parent ! {Ref, ticket_keeper_existing}
    end.

own_ticket_table() ->
    case ets:whereis(quic_server_tickets) of
        undefined ->
            _ = ets:new(quic_server_tickets, [
                named_table,
                public,
                ordered_set,
                {read_concurrency, true},
                {write_concurrency, auto}
            ]),
            ok;
        _Existing ->
            ok
    end.

ticket_keeper_loop() ->
    case whereis(quic_sup) of
        Supervisor when is_pid(Supervisor) ->
            Monitor = monitor(process, Supervisor),
            receive
                {'DOWN', Monitor, process, Supervisor, _Reason} -> ok
            end;
        undefined ->
            ok
    end.

start_with_available_name(Certificate, PrivateKey, Port, Timeout, Datagrams, QlogDirectory) ->
    Worker = self(),
    Handler = fun(Conn, StreamId, Method, Path, Headers) ->
        request_handler(Worker, Conn, StreamId, Method, Path, Headers, Timeout)
    end,
    QuicOptions = maybe_add_qlog(#{pool_size => 0}, QlogDirectory),
    Options = #{
        cert => Certificate,
        key => PrivateKey,
        handler => Handler,
        connection_handler => fun(_QuicConnection) -> #{owner => Worker} end,
        settings => #{max_field_section_size => 65536},
        h3_datagram_enabled => Datagrams,
        quic_opts => QuicOptions
    },
    try_server_names(server_names(), Port, Options).

maybe_add_qlog(Options, <<>>) -> Options;
maybe_add_qlog(Options, Directory) ->
    Options#{qlog => #{enabled => true, dir => binary_to_list(Directory)}}.

try_server_names([], _Port, _Options) ->
    start_error(listener_capacity_exhausted);
try_server_names([Name | Names], Port, Options) ->
    case quic_h3:start_server(Name, Port, Options) of
        {ok, Server} ->
            case quic:get_server_port(Name) of
                {ok, BoundPort} -> {ok, Name, Server, BoundPort};
                {error, Reason} ->
                    _ = quic_h3:stop_server(Name),
                    start_error(Reason)
            end;
        {error, {already_started, _}} ->
            try_server_names(Names, Port, Options);
        {error, Reason} ->
            start_error(Reason)
    end.

server_names() ->
    [
        http3_public_server_01,
        http3_public_server_02,
        http3_public_server_03,
        http3_public_server_04,
        http3_public_server_05,
        http3_public_server_06,
        http3_public_server_07,
        http3_public_server_08,
        http3_public_server_09,
        http3_public_server_10,
        http3_public_server_11,
        http3_public_server_12,
        http3_public_server_13,
        http3_public_server_14,
        http3_public_server_15,
        http3_public_server_16
    ].

request_handler(Worker, Conn, StreamId, Method, Path, Headers, Timeout) ->
    WorkerMonitor = monitor(process, Worker),
    ConnectionMonitor = monitor(process, Conn),
    case safe_set_stream_handler(Conn, StreamId) of
        {ok, Buffered} ->
            Worker ! {incoming_request, Conn, StreamId, Method, Path, Headers},
            case forward_buffered(Worker, Conn, StreamId, Buffered) of
                complete -> ok;
                open -> request_handler_loop(
                    Worker,
                    WorkerMonitor,
                    Conn,
                    ConnectionMonitor,
                    StreamId,
                    Timeout
                )
            end;
        ok ->
            Worker ! {incoming_request, Conn, StreamId, Method, Path, Headers},
            request_handler_loop(
                Worker,
                WorkerMonitor,
                Conn,
                ConnectionMonitor,
                StreamId,
                Timeout
            );
        {error, Reason} ->
            Worker ! {request_handler_error, Conn, StreamId, Reason}
    end.

safe_set_stream_handler(Conn, StreamId) ->
    try quic_h3:set_stream_handler(Conn, StreamId, self()) of
        Result -> Result
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

forward_buffered(_Worker, _Conn, _StreamId, []) -> open;
forward_buffered(Worker, Conn, StreamId, [{Data, Fin} | Rest]) ->
    Worker ! {request_data, Conn, StreamId, Data, Fin},
    case Fin of
        true -> complete;
        false -> forward_buffered(Worker, Conn, StreamId, Rest)
    end.

request_handler_loop(Worker, WorkerMonitor, Conn, ConnectionMonitor, StreamId, Timeout) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, Fin}} ->
            Worker ! {request_data, Conn, StreamId, Data, Fin},
            case Fin of
                true -> ok;
                false -> request_handler_loop(
                    Worker, WorkerMonitor, Conn, ConnectionMonitor, StreamId, Timeout
                )
            end;
        {quic_h3, Conn, {trailers, StreamId, Trailers}} ->
            Worker ! {request_trailers, Conn, StreamId, Trailers};
        {quic_h3, Conn, {stream_reset, StreamId, ErrorCode}} ->
            Worker ! {request_reset, Conn, StreamId, ErrorCode};
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            ok;
        {'DOWN', ConnectionMonitor, process, Conn, Reason} ->
            Worker ! {request_connection_closed, Conn, StreamId, Reason}
    after Timeout ->
        safe_cancel(Conn, StreamId),
        Worker ! {request_timeout, Conn, StreamId}
    end.

loop(State) ->
    Wait = next_deadline_wait(State),
    OwnerMonitor = maps:get(owner_monitor, State),
    Server = maps:get(server, State),
    receive
        {server_call, From, Ref, stop} ->
            reply(From, Ref, {ok, 1}),
            shutdown(State);
        {server_call, From, Ref, Request} ->
            case safely_handle_call(Request, State) of
                {reply, Result, NextState} ->
                    reply(From, Ref, Result),
                    loop(NextState);
                {wait_accept, NextState} ->
                    Deadline = erlang:monotonic_time(millisecond) + maps:get(timeout, State),
                    loop(NextState#{accept_waiter => {From, Ref, Deadline}});
                {wait_request, RequestId, NextState} ->
                    Streams = maps:get(requests, NextState),
                    RequestState = maps:get(RequestId, Streams),
                    Waiting = RequestState#{waiter => {From, Ref}},
                    loop(NextState#{requests => Streams#{RequestId => Waiting}});
                {wait_datagram_request, RequestId, NextState} ->
                    Requests = maps:get(requests, NextState),
                    RequestState = maps:get(RequestId, Requests),
                    Waiting = RequestState#{datagram_waiter => {From, Ref}},
                    loop(NextState#{requests => Requests#{RequestId => Waiting}})
            end;
        {incoming_request, Conn, StreamId, Method, Path, Headers} ->
            loop(add_request(Conn, StreamId, Method, Path, Headers, State));
        {request_data, Conn, StreamId, Data, Fin} ->
            loop(handle_request_data(Conn, StreamId, Data, Fin, State));
        {request_trailers, Conn, StreamId, Trailers} ->
            loop(handle_request_trailers(Conn, StreamId, Trailers, State));
        {request_reset, Conn, StreamId, ErrorCode} ->
            loop(fail_request_by_stream(Conn, StreamId, stream_reset_error(ErrorCode), State));
        {request_connection_closed, Conn, StreamId, _Reason} ->
            loop(fail_request_by_stream(Conn, StreamId, connection_closed_error(), State));
        {request_timeout, Conn, StreamId} ->
            loop(fail_request_by_stream(Conn, StreamId, timeout_error(), State));
        {request_handler_error, Conn, StreamId, Reason} ->
            loop(fail_request_by_stream(Conn, StreamId, protocol_error(0, reason_text(Reason)), State));
        {quic_h3, Conn, {stream_reset, StreamId, ErrorCode}} ->
            loop(fail_request_by_stream(Conn, StreamId, stream_reset_error(ErrorCode), State));
        {quic_h3, Conn, {datagram, StreamId, Payload}} when is_binary(Payload) ->
            loop(handle_request_datagram(Conn, StreamId, Payload, State));
        {quic_h3, Conn, {closed, _Reason}} ->
            loop(fail_connection_requests(Conn, State));
        {quic_h3, Conn, closed} ->
            loop(fail_connection_requests(Conn, State));
        {quic_h3, _Conn, _Event} ->
            loop(State);
        {'DOWN', OwnerMonitor, process, _Owner, _Reason} ->
            shutdown(State);
        {'EXIT', Server, _Reason} ->
            shutdown(State);
        _Other ->
            loop(State)
    after Wait ->
        loop(expire_waiters(State))
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

is_transport_call({transport_stream_capabilities, _}) -> true;
is_transport_call({max_datagram_size, _}) -> true;
is_transport_call({send_datagram, _, _}) -> true;
is_transport_call({next_datagram, _}) -> true;
is_transport_call({set_priority, _, _, _}) -> true;
is_transport_call({get_priority, _}) -> true;
is_transport_call({early_data_status, _}) -> true;
is_transport_call(_) -> false.

handle_call(port, State) ->
    {reply, {ok, maps:get(port, State)}, State};
handle_call(accept, State) ->
    case queue:out(maps:get(pending, State)) of
        {{value, RequestId}, Pending} ->
            Request = maps:get(RequestId, maps:get(requests, State)),
            Accepted = Request#{accepted => true},
            Requests = maps:get(requests, State),
            {reply,
                {ok, incoming_value(Accepted, State)},
                State#{pending => Pending, requests => Requests#{RequestId => Accepted}}};
        {empty, _} ->
            case maps:get(accept_waiter, State) of
                undefined -> {wait_accept, State};
                _ -> {reply, concurrent_accept_error(), State}
            end
    end;
handle_call({next_event, RequestId}, State) ->
    next_request_event(RequestId, State);
handle_call({respond, RequestId, Status, Headers, Body}, State) ->
    with_request(RequestId, State, fun(Request) ->
        bounded_respond(Status, Headers, Body, Request, State)
    end);
handle_call({send_response, RequestId, Status, Headers, DeclaredLength}, State) ->
    with_request(RequestId, State, fun(Request) ->
        streaming_response_head(Status, Headers, DeclaredLength, Request, State)
    end);
handle_call({send_chunk, RequestId, Chunk}, State) ->
    with_request(RequestId, State, fun(Request) ->
        streaming_response_chunk(Chunk, Request, State)
    end);
handle_call({finish_response, RequestId}, State) ->
    with_request(RequestId, State, fun(Request) ->
        finish_streaming_response(Request, State)
    end);
handle_call({transport_stream_capabilities, RequestId}, State) ->
    with_transport_request(RequestId, State, fun(Request) ->
        request_transport_capabilities(Request, State)
    end);
handle_call({max_datagram_size, RequestId}, State) ->
    with_transport_request(RequestId, State, fun(Request) ->
        request_max_datagram_size(Request, State)
    end);
handle_call({send_datagram, RequestId, Payload}, State) ->
    with_transport_request(RequestId, State, fun(Request) ->
        send_request_datagram(Request, Payload, State)
    end);
handle_call({next_datagram, RequestId}, State) ->
    next_request_datagram(RequestId, State);
handle_call({set_priority, RequestId, Urgency, Incremental}, State) ->
    with_transport_request(RequestId, State, fun(Request) ->
        set_request_priority(Request, Urgency, Incremental, State)
    end);
handle_call({get_priority, RequestId}, State) ->
    with_transport_request(RequestId, State, fun(Request) ->
        get_request_priority(Request, State)
    end);
handle_call({early_data_status, RequestId}, State) ->
    with_transport_request(RequestId, State, fun(Request) ->
        request_early_data_status(Request, State)
    end);
handle_call(_Request, State) ->
    {reply, backend_error(unknown_server_call), State}.

add_request(Conn, StreamId, Method, Path, Headers, State) ->
    case map_size(maps:get(requests, State)) >= ?MAX_PENDING_REQUESTS of
        true ->
            safe_cancel(Conn, StreamId),
            State;
        false ->
            RequestId = maps:get(next_id, State),
            Timeout = maps:get(timeout, State),
            DeclaredLength = request_content_length(Headers),
            Request0 = #{
                id => RequestId,
                conn => Conn,
                stream_id => StreamId,
                method => Method,
                path => Path,
                headers => public_headers(Headers),
                deadline => erlang:monotonic_time(millisecond) + Timeout,
                body_size => 0,
                declared_length => DeclaredLength,
                body_state => open,
                queue => queue:new(),
                queued_bytes => 0,
                waiter => undefined,
                terminal => undefined,
                terminal_delivered => false,
                accepted => false,
                response_state => idle,
                response_size => 0,
                response_declared => undefined,
                datagram_queue => queue:new(),
                datagram_bytes => 0,
                datagram_waiter => undefined,
                datagram_error => undefined
            },
            Request1 = case DeclaredLength of
                invalid ->
                    safe_cancel(Conn, StreamId),
                    set_terminal(
                        Request0, protocol_error(0, <<"invalid request content length">>)
                    );
                _ -> Request0
            end,
            StreamKey = {Conn, StreamId},
            OrphanErrors = maps:get(orphan_errors, State),
            {Request, RemainingOrphans} = case maps:take(StreamKey, OrphanErrors) of
                {Error, Rest} -> {set_terminal(Request1, Error), Rest};
                error -> {Request1, OrphanErrors}
            end,
            OrphanDatagrams = maps:get(orphan_datagrams, State),
            {RequestWithDatagrams, RemainingDatagrams} =
                case maps:take(StreamKey, OrphanDatagrams) of
                    {{Payloads, _Bytes}, RestDatagrams} ->
                        BufferedRequest = lists:foldl(
                            fun(Payload, Acc) ->
                                enqueue_request_datagram(Payload, Acc, State)
                            end,
                            Request,
                            lists:reverse(Payloads)
                        ),
                        {BufferedRequest, RestDatagrams};
                    error ->
                        {Request, OrphanDatagrams}
                end,
            Requests = maps:get(requests, State),
            Index = maps:get(stream_index, State),
            NextState = State#{
                next_id => RequestId + 1,
                requests => Requests#{RequestId => RequestWithDatagrams},
                stream_index => Index#{StreamKey => RequestId},
                orphan_errors => RemainingOrphans,
                orphan_datagrams => RemainingDatagrams
            },
            dispatch_request(RequestId, NextState)
    end.

dispatch_request(RequestId, State) ->
    case maps:get(accept_waiter, State) of
        {From, Ref, _Deadline} ->
            Requests = maps:get(requests, State),
            Request = maps:get(RequestId, Requests),
            Accepted = Request#{accepted => true},
            reply(From, Ref, {ok, incoming_value(Accepted, State)}),
            State#{
                accept_waiter => undefined,
                requests => Requests#{RequestId => Accepted}
            };
        undefined ->
            State#{pending => queue:in(RequestId, maps:get(pending, State))}
    end.

incoming_value(Request, State) ->
    Handle = {
        http3_request,
        self(),
        maps:get(id, Request),
        maps:get(timeout, State)
    },
    {
        Handle,
        maps:get(method, Request),
        maps:get(path, Request),
        maps:get(headers, Request)
    }.

handle_request_datagram(Conn, StreamId, Payload, State) ->
    StreamKey = {Conn, StreamId},
    case maps:find(StreamKey, maps:get(stream_index, State)) of
        {ok, RequestId} ->
            Requests = maps:get(requests, State),
            Request = maps:get(RequestId, Requests),
            Updated = enqueue_request_datagram(Payload, Request, State),
            State#{requests => Requests#{RequestId => Updated}};
        error ->
            store_orphan_datagram(StreamKey, Payload, State)
    end.

store_orphan_datagram(StreamKey, Payload, State) ->
    Orphans = maps:get(orphan_datagrams, State),
    Limit = maps:get(buffer_limit, State),
    {Payloads, Bytes} = maps:get(StreamKey, Orphans, {[], 0}),
    NewBytes = Bytes + byte_size(Payload),
    HasStream = maps:is_key(StreamKey, Orphans),
    HasCapacity = HasStream orelse map_size(Orphans) < ?MAX_PENDING_REQUESTS,
    case NewBytes =< Limit andalso HasCapacity of
        true ->
            State#{orphan_datagrams => Orphans#{StreamKey => {[Payload | Payloads], NewBytes}}};
        false ->
            State
    end.

enqueue_request_datagram(Payload, Request, State) ->
    case {maps:get(datagram_waiter, Request), maps:get(datagram_error, Request)} of
        {{From, Ref}, undefined} ->
            reply(From, Ref, {ok, Payload}),
            Request#{datagram_waiter => undefined};
        {undefined, undefined} ->
            Bytes = maps:get(datagram_bytes, Request) + byte_size(Payload),
            Limit = maps:get(buffer_limit, State),
            case Bytes > Limit of
                true ->
                    Request#{
                        datagram_queue => queue:new(),
                        datagram_bytes => 0,
                        datagram_error => transport_datagram_buffer_raw(Limit)
                    };
                false ->
                    Request#{
                        datagram_queue => queue:in(Payload, maps:get(datagram_queue, Request)),
                        datagram_bytes => Bytes
                    }
            end;
        _ ->
            Request
    end.

handle_request_data(Conn, StreamId, Data, Fin, State) when is_binary(Data) ->
    update_request_by_stream(Conn, StreamId, State, fun(Request) ->
        case maps:get(terminal, Request) of
            undefined -> add_request_data(Data, Fin, Request, State);
            _ -> Request
        end
    end);
handle_request_data(_Conn, _StreamId, _Data, _Fin, State) ->
    State.

add_request_data(Data, Fin, Request, State) ->
    Size = maps:get(body_size, Request) + byte_size(Data),
    Limit = maps:get(request_limit, State),
    case {Size > Limit, exceeds_declared(Size, maps:get(declared_length, Request))} of
        {true, _} ->
            safe_cancel(maps:get(conn, Request), maps:get(stream_id, Request)),
            set_terminal(Request, request_limit_error(Limit));
        {_, true} ->
            safe_cancel(maps:get(conn, Request), maps:get(stream_id, Request)),
            set_terminal(
                Request, protocol_error(0, <<"request content length exceeded">>)
            );
        {false, false} ->
            WithData = case byte_size(Data) of
                0 -> Request#{body_size => Size};
                _ -> enqueue_request_event(
                    {?EVENT_DATA, [], Data}, Request#{body_size => Size}, State
                )
            end,
            case {Fin, maps:get(terminal, WithData)} of
                {true, undefined} -> complete_request_body(WithData, State);
                _ -> WithData
            end
    end.

handle_request_trailers(Conn, StreamId, Trailers, State) ->
    update_request_by_stream(Conn, StreamId, State, fun(Request) ->
        case {maps:get(body_state, Request), maps:get(terminal, Request)} of
            {open, undefined} ->
                WithTrailers = enqueue_request_event(
                    {?EVENT_TRAILERS, public_headers(Trailers), <<>>}, Request, State
                ),
                complete_request_body(WithTrailers, State);
            _ -> Request
        end
    end).

complete_request_body(Request, State) ->
    case maps:get(terminal, Request) of
        undefined ->
            case request_content_length_matches(Request) of
                true ->
                    (enqueue_request_event({?EVENT_END, [], <<>>}, Request, State))#{
                        body_state => complete
                    };
                false ->
                    safe_cancel(maps:get(conn, Request), maps:get(stream_id, Request)),
                    set_terminal(
                        Request, protocol_error(0, <<"request content length mismatch">>)
                    )
            end;
        _ -> Request
    end.

enqueue_request_event(Event, Request, State) ->
    case maps:get(waiter, Request) of
        {From, Ref} ->
            reply(From, Ref, {ok, Event}),
            Request#{waiter => undefined};
        undefined ->
            NewSize = maps:get(queued_bytes, Request) + event_size(Event),
            Limit = maps:get(buffer_limit, State),
            case NewSize > Limit of
                true ->
                    safe_cancel(maps:get(conn, Request), maps:get(stream_id, Request)),
                    set_terminal(Request, consumer_slow_error(Limit));
                false ->
                    Request#{
                        queue => queue:in(Event, maps:get(queue, Request)),
                        queued_bytes => NewSize
                    }
            end
    end.

event_size({?EVENT_DATA, _Headers, Data}) -> byte_size(Data);
event_size(_Event) -> 0.

request_content_length(Headers) ->
    Values = [Value || {<<"content-length">>, Value} <- Headers],
    case Values of
        [] -> undefined;
        [Value] -> parse_request_content_length(Value);
        _ -> invalid
    end.

parse_request_content_length(Value) ->
    try binary_to_integer(string:trim(Value)) of
        Length when Length >= 0 -> Length;
        _ -> invalid
    catch
        _:_ -> invalid
    end.

request_content_length_matches(Request) ->
    case maps:get(declared_length, Request) of
        undefined -> true;
        invalid -> false;
        Declared -> maps:get(body_size, Request) =:= Declared
    end.

next_request_event(RequestId, State) ->
    case maps:find(RequestId, maps:get(requests, State)) of
        error -> {reply, connection_closed_error(), State};
        {ok, Request} ->
            case queue:out(maps:get(queue, Request)) of
                {{value, Event}, Queue} ->
                    Size = max(0, maps:get(queued_bytes, Request) - event_size(Event)),
                    maybe_finalize_request_reply(
                        Request#{queue => Queue, queued_bytes => Size}, {ok, Event}, State
                    );
                {empty, _} -> next_empty_request_event(RequestId, Request, State)
            end
    end.

next_empty_request_event(RequestId, Request, State) ->
    case maps:get(terminal, Request) of
        undefined ->
            case maps:get(body_state, Request) of
                complete -> {reply, response_finished_error(), State};
                open ->
                    case maps:get(waiter, Request) of
                        undefined -> {wait_request, RequestId, State};
                        _ -> {reply, concurrent_receive_error(), State}
                    end
            end;
        Error ->
            {reply, {error, Error}, remove_request(RequestId, State)}
    end.

with_request(RequestId, State, Fun) ->
    case maps:find(RequestId, maps:get(requests, State)) of
        {ok, Request} -> Fun(Request);
        error -> {reply, connection_closed_error(), State}
    end.

with_transport_request(RequestId, State, Fun) ->
    case maps:find(RequestId, maps:get(requests, State)) of
        {ok, Request} -> Fun(Request);
        error -> {reply, transport_unknown_stream_error(), State}
    end.

request_transport_capabilities(Request, State) ->
    case request_connections(Request) of
        {ok, H3Connection, QuicConnection} ->
            Datagrams = quic_h3:h3_datagrams_enabled(H3Connection),
            Migration = active_migration_allowed(QuicConnection),
            Early = quic_h3:early_data_accepted(H3Connection) =:= true,
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

request_max_datagram_size(Request, State) ->
    H3Connection = maps:get(conn, Request),
    case quic_h3:h3_datagrams_enabled(H3Connection) of
        false -> {reply, transport_datagrams_disabled_error(), State};
        true ->
            Maximum = quic_h3:max_datagram_size(
                H3Connection, maps:get(stream_id, Request)
            ),
            {reply, {ok, Maximum}, State}
    end.

send_request_datagram(Request, Payload, State) ->
    H3Connection = maps:get(conn, Request),
    StreamId = maps:get(stream_id, Request),
    Maximum = quic_h3:max_datagram_size(H3Connection, StreamId),
    case {quic_h3:h3_datagrams_enabled(H3Connection), byte_size(Payload) =< Maximum} of
        {false, _} ->
            {reply, transport_datagrams_disabled_error(), State};
        {true, false} ->
            {reply, transport_datagram_too_large_error(Maximum), State};
        {true, true} ->
            case quic_h3:send_datagram(H3Connection, StreamId, Payload) of
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
    end.

next_request_datagram(RequestId, State) ->
    case maps:find(RequestId, maps:get(requests, State)) of
        error ->
            {reply, transport_unknown_stream_error(), State};
        {ok, Request} ->
            case queue:out(maps:get(datagram_queue, Request)) of
                {{value, Payload}, Queue} ->
                    Bytes = max(0, maps:get(datagram_bytes, Request) - byte_size(Payload)),
                    update_transport_request_reply(
                        Request#{datagram_queue => Queue, datagram_bytes => Bytes},
                        {ok, Payload},
                        State
                    );
                {empty, _} ->
                    next_empty_request_datagram(RequestId, Request, State)
            end
    end.

next_empty_request_datagram(RequestId, Request, State) ->
    case maps:get(datagram_error, Request) of
        undefined ->
            case {maps:get(terminal, Request), maps:get(datagram_waiter, Request)} of
                {Terminal, _} when Terminal =/= undefined ->
                    {reply, transport_closed_error(), State};
                {_, undefined} ->
                    {wait_datagram_request, RequestId, State};
                _ ->
                    {reply, transport_concurrent_datagram_error(), State}
            end;
        Error ->
            update_transport_request_reply(
                Request#{datagram_error => undefined}, {error, Error}, State
            )
    end.

update_transport_request_reply(Request, Result, State) ->
    RequestId = maps:get(id, Request),
    Requests = maps:get(requests, State),
    {reply, Result, State#{requests => Requests#{RequestId => Request}}}.

set_request_priority(Request, Urgency, Incremental, State) ->
    case request_connections(Request) of
        {ok, _H3Connection, QuicConnection} ->
            case quic:set_stream_priority(
                QuicConnection, maps:get(stream_id, Request), Urgency, Incremental
            ) of
                ok -> {reply, {ok, nil}, State};
                {error, unknown_stream} -> {reply, transport_unknown_stream_error(), State};
                {error, Reason} -> {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

get_request_priority(Request, State) ->
    case request_connections(Request) of
        {ok, _H3Connection, QuicConnection} ->
            case quic:get_stream_priority(QuicConnection, maps:get(stream_id, Request)) of
                {ok, Priority} -> {reply, {ok, Priority}, State};
                {error, unknown_stream} -> {reply, transport_unknown_stream_error(), State};
                {error, Reason} -> {reply, transport_backend_error(Reason), State}
            end;
        {error, Error} ->
            {reply, Error, State}
    end.

request_early_data_status(Request, State) ->
    case maps:get(conn, Request, undefined) of
        undefined ->
            {reply, transport_closed_error(), State};
        H3Connection ->
            Status = case quic_h3:early_data_accepted(H3Connection) of
                unknown -> 1;
                true -> 2;
                false -> 0
            end,
            {reply, {ok, Status}, State}
    end.

request_connections(Request) ->
    case maps:get(conn, Request, undefined) of
        undefined -> {error, transport_closed_error()};
        H3Connection ->
            try {ok, H3Connection, quic_h3:get_quic_conn(H3Connection)} catch
                _:_ -> {error, transport_closed_error()}
            end
    end.

bounded_respond(Status, Headers, Body, Request, State) ->
    case response_operation_error(Request, idle) of
        {error, Error} -> {reply, Error, State};
        ok ->
            Limit = maps:get(response_limit, State),
            case byte_size(Body) > Limit of
                true -> {reply, response_limit_error(Limit), State};
                false ->
                    case quic_h3:respond(
                        maps:get(conn, Request),
                        maps:get(stream_id, Request),
                        Status,
                        Headers,
                        Body
                    ) of
                        ok -> maybe_finalize_request_reply(
                            Request#{response_state => finished, response_size => byte_size(Body)},
                            {ok, nil},
                            State
                        );
                        {error, Reason} -> {reply, protocol_error(0, reason_text(Reason)), State}
                    end
            end
    end.

streaming_response_head(_Status, _Headers, invalid, _Request, State) ->
    {reply, content_length_error(), State};
streaming_response_head(Status, Headers, DeclaredLength, Request, State) ->
    case response_operation_error(Request, idle) of
        {error, Error} -> {reply, Error, State};
        ok ->
            case quic_h3:send_response(
                maps:get(conn, Request), maps:get(stream_id, Request), Status, Headers
            ) of
                ok -> update_request_reply(
                    Request#{response_state => started, response_declared => DeclaredLength},
                    {ok, nil},
                    State
                );
                {error, Reason} -> {reply, protocol_error(0, reason_text(Reason)), State}
            end
    end.

streaming_response_chunk(Chunk, Request, State) ->
    case response_operation_error(Request, started) of
        {error, Error} -> {reply, Error, State};
        ok ->
            Size = maps:get(response_size, Request) + byte_size(Chunk),
            Limit = maps:get(response_limit, State),
            case {Size > Limit, exceeds_declared(Size, maps:get(response_declared, Request))} of
                {true, _} -> {reply, response_limit_error(Limit), State};
                {_, true} -> {reply, content_length_error(), State};
                {false, false} ->
                    case send_with_backpressure(Request, Chunk, false) of
                        ok -> update_request_reply(
                            Request#{response_size => Size}, {ok, nil}, State
                        );
                        {error, _} = Error -> {reply, Error, State}
                    end
            end
    end.

finish_streaming_response(Request, State) ->
    case response_operation_error(Request, started) of
        {error, Error} -> {reply, Error, State};
        ok ->
            case content_length_matches(Request) of
                false -> {reply, content_length_error(), State};
                true ->
                    case send_with_backpressure(Request, <<>>, true) of
                        ok -> maybe_finalize_request_reply(
                            Request#{response_state => finished}, {ok, nil}, State
                        );
                        {error, _} = Error -> {reply, Error, State}
                    end
            end
    end.

exceeds_declared(_Size, undefined) -> false;
exceeds_declared(Size, Declared) -> Size > Declared.

content_length_matches(Request) ->
    case maps:get(response_declared, Request) of
        undefined -> true;
        Declared -> maps:get(response_size, Request) =:= Declared
    end.

response_operation_error(Request, Expected) ->
    case maps:get(terminal, Request) of
        undefined -> response_state_error(maps:get(response_state, Request), Expected);
        Error -> {error, {error, Error}}
    end.

response_state_error(Expected, Expected) -> ok;
response_state_error(idle, started) -> {error, response_not_started_error()};
response_state_error(started, idle) -> {error, response_started_error()};
response_state_error(finished, _Expected) -> {error, response_finished_error()}.

send_with_backpressure(Request, Data, Fin) ->
    Deadline = maps:get(deadline, Request),
    case remaining(Deadline) of
        0 -> timeout_error();
        _ ->
            case quic_h3:send_data(
                maps:get(conn, Request), maps:get(stream_id, Request), Data, Fin
            ) of
                ok -> ok;
                {error, {flow_control_blocked, _}} -> retry_send(Request, Data, Fin);
                {error, flow_control_blocked} -> retry_send(Request, Data, Fin);
                {error, send_queue_full} -> retry_send(Request, Data, Fin);
                {error, congestion_limited} -> retry_send(Request, Data, Fin);
                {error, timeout} -> timeout_error();
                {error, Reason} -> protocol_error(0, reason_text(Reason))
            end
    end.

retry_send(Request, Data, Fin) ->
    Wait = min(?RETRY_INTERVAL, remaining(maps:get(deadline, Request))),
    receive after Wait -> ok end,
    send_with_backpressure(Request, Data, Fin).

update_request_reply(Request, Result, State) ->
    Requests = maps:get(requests, State),
    RequestId = maps:get(id, Request),
    {reply, Result, State#{requests => Requests#{RequestId => Request}}}.

maybe_finalize_request_reply(Request, Result, State) ->
    FinalRequest = case {maps:get(body_state, Request), maps:get(response_state, Request)} of
        {complete, finished} ->
            close_request_datagram_waiter(Request, transport_unknown_stream_error());
        _ ->
            Request
    end,
    case request_can_be_removed(FinalRequest) of
        true ->
            Requests = maps:get(requests, State),
            RequestId = maps:get(id, FinalRequest),
            NextState = State#{requests => Requests#{RequestId => FinalRequest}},
            {reply, Result, remove_request(RequestId, NextState)};
        false ->
            update_request_reply(FinalRequest, Result, State)
    end.

update_request_by_stream(Conn, StreamId, State, Fun) ->
    Index = maps:get(stream_index, State),
    case maps:find({Conn, StreamId}, Index) of
        {ok, RequestId} ->
            Requests = maps:get(requests, State),
            Request = maps:get(RequestId, Requests),
            Updated = Fun(Request),
            NextState = State#{requests => Requests#{RequestId => Updated}},
            case request_can_be_removed(Updated) of
                true -> remove_request(RequestId, NextState);
                false -> NextState
            end;
        error -> State
    end.

fail_request_by_stream(Conn, StreamId, Error, State) ->
    Index = maps:get(stream_index, State),
    case maps:is_key({Conn, StreamId}, Index) of
        true ->
            update_request_by_stream(Conn, StreamId, State, fun(Request) ->
                case maps:get(terminal, Request) of
                    undefined -> set_terminal(Request, Error);
                    _ -> Request
                end
            end);
        false ->
            Orphans = maps:get(orphan_errors, State),
            case map_size(Orphans) < ?MAX_PENDING_REQUESTS of
                true -> State#{orphan_errors => Orphans#{{Conn, StreamId} => Error}};
                false -> State
            end
    end.

fail_connection_requests(Conn, State) ->
    Requests = maps:map(
        fun(_RequestId, Request) ->
            case {maps:get(conn, Request) =:= Conn, maps:get(terminal, Request)} of
                {true, undefined} -> set_terminal(Request, connection_closed_error());
                _ -> Request
            end
        end,
        maps:get(requests, State)
    ),
    OrphanErrors = maps:filter(
        fun({Connection, _StreamId}, _Error) -> Connection =/= Conn end,
        maps:get(orphan_errors, State)
    ),
    OrphanDatagrams = maps:filter(
        fun({Connection, _StreamId}, _Payloads) -> Connection =/= Conn end,
        maps:get(orphan_datagrams, State)
    ),
    sweep_removable(
        State#{
            requests => Requests,
            orphan_errors => OrphanErrors,
            orphan_datagrams => OrphanDatagrams
        }
    ).

set_terminal(Request, ErrorResult) ->
    Error = case ErrorResult of
        {error, RawError} -> RawError;
        RawError -> RawError
    end,
    Delivered = case maps:get(waiter, Request) of
        {From, Ref} ->
            reply(From, Ref, {error, Error}),
            true;
        undefined -> false
    end,
    case maps:get(datagram_waiter, Request) of
        {DatagramFrom, DatagramRef} ->
            reply(DatagramFrom, DatagramRef, transport_closed_error());
        undefined -> ok
    end,
    Request#{
        queue => queue:new(),
        queued_bytes => 0,
        waiter => undefined,
        datagram_queue => queue:new(),
        datagram_bytes => 0,
        datagram_waiter => undefined,
        terminal => Error,
        terminal_delivered => Delivered,
        body_state => failed
    }.

close_request_datagram_waiter(Request, Result) ->
    case maps:get(datagram_waiter, Request) of
        {From, Ref} ->
            reply(From, Ref, Result),
            Request#{datagram_waiter => undefined};
        undefined ->
            Request
    end.

request_can_be_removed(Request) ->
    maps:get(accepted, Request) andalso
        (maps:get(terminal_delivered, Request) orelse
            (maps:get(body_state, Request) =:= complete andalso
                maps:get(response_state, Request) =:= finished andalso
                queue:is_empty(maps:get(queue, Request)) andalso
                maps:get(waiter, Request) =:= undefined)).

remove_request(RequestId, State) ->
    Requests = maps:get(requests, State),
    case maps:take(RequestId, Requests) of
        error -> State;
        {Request, Remaining} ->
            Index = maps:get(stream_index, State),
            StreamKey = {maps:get(conn, Request), maps:get(stream_id, Request)},
            State#{requests => Remaining, stream_index => maps:remove(StreamKey, Index)}
    end.

sweep_removable(State) ->
    RequestIds = [
        RequestId
     || {RequestId, Request} <- maps:to_list(maps:get(requests, State)),
        request_can_be_removed(Request)
    ],
    lists:foldl(fun remove_request/2, State, RequestIds).

expire_waiters(State) ->
    Now = erlang:monotonic_time(millisecond),
    State1 = case maps:get(accept_waiter, State) of
        {From, Ref, Deadline} when Deadline =< Now ->
            reply(From, Ref, timeout_error()),
            State#{accept_waiter => undefined};
        _ -> State
    end,
    Requests = maps:map(
        fun(_RequestId, Request) ->
            case request_is_active(Request) andalso maps:get(deadline, Request) =< Now of
                true ->
                    safe_cancel(maps:get(conn, Request), maps:get(stream_id, Request)),
                    set_terminal(Request, timeout_error());
                false -> Request
            end
        end,
        maps:get(requests, State1)
    ),
    sweep_removable(State1#{requests => Requests}).

request_is_active(Request) ->
    maps:get(terminal, Request) =:= undefined andalso
        (maps:get(body_state, Request) =/= complete orelse
            maps:get(response_state, Request) =/= finished).

next_deadline_wait(State) ->
    Now = erlang:monotonic_time(millisecond),
    AcceptDeadlines = case maps:get(accept_waiter, State) of
        {_From, _Ref, Deadline} -> [Deadline];
        undefined -> []
    end,
    RequestDeadlines = [
        maps:get(deadline, Request)
     || {_RequestId, Request} <- maps:to_list(maps:get(requests, State)),
        request_is_active(Request)
    ],
    case AcceptDeadlines ++ RequestDeadlines of
        [] -> infinity;
        Deadlines -> max(0, lists:min(Deadlines) - Now)
    end.

shutdown(State) ->
    close_waiters(State),
    Name = maps:get(name, State),
    Server = maps:get(server, State),
    Monitor = monitor(process, Server),
    _ = try quic_h3:stop_server(Name) catch _:_ -> ok end,
    receive
        {'DOWN', Monitor, process, Server, _Reason} -> ok
    after ?CLEANUP_TIMEOUT ->
        exit(Server, kill),
        receive
            {'DOWN', Monitor, process, Server, _Reason} -> ok
        after ?CLEANUP_TIMEOUT ->
            demonitor(Monitor, [flush]),
            ok
        end
    end.

close_waiters(State) ->
    case maps:get(accept_waiter, State) of
        {AcceptFrom, AcceptRef, _Deadline} ->
            reply(AcceptFrom, AcceptRef, listener_closed_error());
        undefined -> ok
    end,
    _ = maps:map(
        fun(_RequestId, Request) ->
            case maps:get(waiter, Request) of
                {RequestFrom, RequestRef} ->
                    reply(RequestFrom, RequestRef, listener_closed_error());
                undefined -> ok
            end,
            case maps:get(datagram_waiter, Request) of
                {DatagramFrom, DatagramRef} ->
                    reply(DatagramFrom, DatagramRef, transport_closed_error());
                undefined -> ok
            end,
            Request
        end,
        maps:get(requests, State)
    ),
    ok.

decode_certificate(Pem) ->
    try public_key:pem_decode(Pem) of
        Entries -> find_certificate(Entries)
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

find_certificate([]) -> {error, certificate_not_found};
find_certificate([{'Certificate', Der, _} | _]) when is_binary(Der) -> {ok, Der};
find_certificate([_ | Entries]) -> find_certificate(Entries).

decode_private_key(Pem) ->
    try public_key:pem_decode(Pem) of
        [] -> {error, private_key_not_found};
        Entries -> decode_private_key_entries(Entries)
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

decode_private_key_entries([]) -> {error, private_key_not_found};
decode_private_key_entries([Entry | Entries]) ->
    try public_key:pem_entry_decode(Entry) of
        PrivateKey -> {ok, PrivateKey}
    catch
        _:_ -> decode_private_key_entries(Entries)
    end.

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

safe_cancel(Conn, StreamId) ->
    try quic_h3:cancel(Conn, StreamId) of _ -> ok catch _:_ -> ok end.

reply(To, Ref, Result) -> To ! {Ref, Result}.

await_worker_down(Worker, Monitor) ->
    receive
        {'DOWN', Monitor, process, Worker, _Reason} -> ok
    after ?CLEANUP_TIMEOUT ->
        demonitor(Monitor, [flush]),
        ok
    end.

remaining(Deadline) -> max(0, Deadline - erlang:monotonic_time(millisecond)).

start_error(Reason) -> {error, {?ERROR_START, 0, reason_text(Reason)}}.
timeout_error() -> {error, {?ERROR_TIMEOUT, 0, <<"server operation timeout">>}}.
listener_closed_error() -> {error, {?ERROR_LISTENER_CLOSED, 0, <<"listener closed">>}}.
connection_closed_error() ->
    {error, {?ERROR_CONNECTION_CLOSED, 0, <<"request connection closed">>}}.
stream_reset_error(Code) -> {error, {?ERROR_STREAM_RESET, Code, <<"request stream reset">>}}.
protocol_error(Code, Message) -> {error, {?ERROR_PROTOCOL, Code, reason_text(Message)}}.
request_limit_error(Limit) ->
    {error, {?ERROR_REQUEST_LIMIT, Limit, <<"request body limit exceeded">>}}.
response_limit_error(Limit) ->
    {error, {?ERROR_RESPONSE_LIMIT, Limit, <<"response body limit exceeded">>}}.
consumer_slow_error(Limit) ->
    {error, {?ERROR_CONSUMER_SLOW, Limit, <<"request receive buffer limit exceeded">>}}.
concurrent_accept_error() ->
    {error, {?ERROR_CONCURRENT_ACCEPT, 0, <<"concurrent listener accept">>}}.
concurrent_receive_error() ->
    {error, {?ERROR_CONCURRENT_RECEIVE, 0, <<"concurrent request receive">>}}.
response_started_error() ->
    {error, {?ERROR_RESPONSE_STARTED, 0, <<"response already started">>}}.
response_not_started_error() ->
    {error, {?ERROR_RESPONSE_NOT_STARTED, 0, <<"response not started">>}}.
response_finished_error() ->
    {error, {?ERROR_RESPONSE_FINISHED, 0, <<"response already finished">>}}.
content_length_error() ->
    {error, {?ERROR_CONTENT_LENGTH, 0, <<"invalid response content length">>}}.
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
transport_backend_error(Reason) ->
    {error, {?TRANSPORT_ERROR_BACKEND, 0, reason_text(Reason)}}.

reason_text(Reason) when is_binary(Reason) -> truncate_reason(Reason);
reason_text(Reason) -> truncate_reason(iolist_to_binary(io_lib:format("~0p", [Reason]))).

truncate_reason(Reason) when byte_size(Reason) =< ?MAX_REASON_BYTES -> Reason;
truncate_reason(Reason) -> binary:part(Reason, 0, ?MAX_REASON_BYTES).
