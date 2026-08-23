-module(http3_internal_client_ffi).

-export([send/7, valid_ca_certificate/1]).

-define(CLEANUP_TIMEOUT, 250).
-define(WORKER_GRACE, 600).
-define(MAX_REASON_BYTES, 1024).
-define(MAX_FIELD_SECTION_SIZE, 65536).

-define(ERROR_CONNECT, 1).
-define(ERROR_REQUEST, 2).
-define(ERROR_TIMEOUT, 3).
-define(ERROR_BODY_LIMIT, 4).
-define(ERROR_CLOSED, 5).
-define(ERROR_STREAM_RESET, 6).
-define(ERROR_PROTOCOL, 7).
-define(ERROR_BACKEND, 8).

-type headers() :: [{binary(), binary()}].
-type response() :: {integer(), headers(), binary()}.
-type raw_error() :: {integer(), integer(), binary()}.
-type result() :: {ok, response()} | {error, raw_error()}.

-spec valid_ca_certificate(bitstring()) -> boolean().
valid_ca_certificate(Certificate) when is_binary(Certificate), byte_size(Certificate) > 0 ->
    try public_key:pkix_decode_cert(Certificate, otp) of
        Decoded ->
            is_tuple(Decoded) andalso
                tuple_size(Decoded) > 0 andalso
                element(1, Decoded) =:= 'OTPCertificate'
    catch
        _:_ -> false
    end;
valid_ca_certificate(_Certificate) ->
    false.

-spec send(
    binary(),
    inet:port_number(),
    headers(),
    bitstring(),
    [bitstring()],
    pos_integer(),
    pos_integer()
) -> result().
send(Host, Port, Headers, Body, CaCertificates, Timeout, BodyLimit) when
    is_binary(Host),
    is_integer(Port),
    is_list(Headers),
    is_binary(Body),
    is_list(CaCertificates),
    is_integer(Timeout),
    Timeout > 0,
    is_integer(BodyLimit),
    BodyLimit > 0
->
    Parent = self(),
    ReplyRef = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Result = safe_request(Host, Port, Headers, Body, CaCertificates, Timeout, BodyLimit),
        Parent ! {ReplyRef, Result}
    end),
    await_worker(Worker, Monitor, ReplyRef, Timeout + ?WORKER_GRACE);
send(_Host, _Port, _Headers, _Body, _CaCertificates, _Timeout, _BodyLimit) ->
    backend_error(invalid_ffi_arguments).

await_worker(Worker, Monitor, ReplyRef, Timeout) ->
    receive
        {ReplyRef, Result} ->
            demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Worker, Reason} ->
            receive
                {ReplyRef, Result} -> Result
            after 0 ->
                backend_error({worker_stopped, Reason})
            end
    after Timeout ->
        exit(Worker, kill),
        await_worker_down(Worker, Monitor),
        flush_worker_reply(ReplyRef),
        timeout_error()
    end.

await_worker_down(Worker, Monitor) ->
    receive
        {'DOWN', Monitor, process, Worker, _Reason} -> ok
    after ?CLEANUP_TIMEOUT ->
        demonitor(Monitor, [flush]),
        ok
    end.

flush_worker_reply(ReplyRef) ->
    receive
        {ReplyRef, _Result} -> ok
    after 0 ->
        ok
    end.

safe_request(Host, Port, Headers, Body, CaCertificates, Timeout, BodyLimit) ->
    try
        request(Host, Port, Headers, Body, CaCertificates, Timeout, BodyLimit)
    catch
        exit:timeout -> timeout_error();
        exit:{timeout, _} -> timeout_error();
        Class:Reason -> backend_error({Class, Reason})
    end.

request(Host, Port, Headers, Body, CaCertificates, Timeout, BodyLimit) ->
    case application:ensure_all_started(quic) of
        {ok, _Started} ->
            Deadline = erlang:monotonic_time(millisecond) + Timeout,
            connect_and_request(
                Host,
                Port,
                Headers,
                Body,
                CaCertificates,
                Deadline,
                BodyLimit
            );
        {error, Reason} ->
            connect_error(Reason)
    end.

connect_and_request(Host, Port, Headers, Body, CaCertificates, Deadline, BodyLimit) ->
    case remaining(Deadline) of
        0 ->
            timeout_error();
        _ConnectTimeout ->
            BaseOptions = #{
                verify => verify_peer,
                settings => #{max_field_section_size => ?MAX_FIELD_SECTION_SIZE}
            },
            Options = maybe_add_ca_certificates(BaseOptions, CaCertificates),
            case quic_h3:connect(Host, Port, Options) of
                {ok, Connection} ->
                    try
                        case await_connected(Connection, Deadline) of
                            ok ->
                                request_on_connection(
                                    Connection, Headers, Body, Deadline, BodyLimit
                                );
                            {error, _} = Error ->
                                Error
                        end
                    after
                        close_connection(Connection)
                    end;
                {error, connect_timeout} ->
                    timeout_error();
                {error, timeout} ->
                    timeout_error();
                {error, Reason} ->
                    connect_error(Reason)
            end
    end.

await_connected(Connection, Deadline) ->
    case remaining(Deadline) of
        0 ->
            timeout_error();
        Wait ->
            receive
                {quic_h3, Connection, connected} ->
                    ok;
                {quic_h3, Connection, {closed, Reason}} ->
                    connect_error(Reason);
                {quic_h3, Connection, closed} ->
                    connect_error(connection_closed_during_handshake);
                {quic_h3, Connection, {error, _Code, Reason}} ->
                    connect_error(Reason);
                {quic_h3, Connection, _OtherEvent} ->
                    await_connected(Connection, Deadline)
            after Wait ->
                timeout_error()
            end
    end.

maybe_add_ca_certificates(Options, []) ->
    Options;
maybe_add_ca_certificates(Options, Certificates) ->
    Options#{cacerts => Certificates}.

request_on_connection(Connection, Headers, Body, Deadline, BodyLimit) ->
    EndStream = byte_size(Body) =:= 0,
    case quic_h3:request(Connection, Headers, #{end_stream => EndStream}) of
        {ok, StreamId} ->
            case send_request_body(Connection, StreamId, Body) of
                ok ->
                    receive_response(
                        Connection,
                        StreamId,
                        Deadline,
                        BodyLimit,
                        undefined,
                        [],
                        [],
                        0
                    );
                {error, Reason} ->
                    request_error(Reason)
            end;
        {error, Reason} ->
            request_error(Reason)
    end.

send_request_body(_Connection, _StreamId, <<>>) ->
    ok;
send_request_body(Connection, StreamId, Body) ->
    quic_h3:send_data(Connection, StreamId, Body, true).

receive_response(Connection, StreamId, Deadline, BodyLimit, Status, Headers, Chunks, Size) ->
    case remaining(Deadline) of
        0 ->
            quic_h3:cancel(Connection, StreamId),
            timeout_error();
        Wait ->
            receive
                {quic_h3, Connection, {response, StreamId, Interim, _InterimHeaders}} when
                    is_integer(Interim), Interim >= 100, Interim < 200
                ->
                    receive_response(
                        Connection, StreamId, Deadline, BodyLimit, Status, Headers, Chunks, Size
                    );
                {quic_h3, Connection, {response, StreamId, FinalStatus, ResponseHeaders}} ->
                    receive_response(
                        Connection,
                        StreamId,
                        Deadline,
                        BodyLimit,
                        FinalStatus,
                        ResponseHeaders,
                        Chunks,
                        Size
                    );
                {quic_h3, Connection, {data, StreamId, Data, Fin}} when is_binary(Data) ->
                    receive_response_data(
                        Connection,
                        StreamId,
                        Deadline,
                        BodyLimit,
                        Status,
                        Headers,
                        Data,
                        Fin,
                        Chunks,
                        Size
                    );
                {quic_h3, Connection, {trailers, StreamId, _Trailers}} ->
                    complete_response(Status, Headers, Chunks);
                {quic_h3, Connection, {stream_reset, StreamId, ErrorCode}} ->
                    {error, {?ERROR_STREAM_RESET, ErrorCode, <<"stream reset">>}};
                {quic_h3, Connection, {error, ErrorCode, Reason}} ->
                    {error, {?ERROR_PROTOCOL, ErrorCode, reason_text(Reason)}};
                {quic_h3, Connection, {closed, _Reason}} ->
                    closed_error();
                {quic_h3, Connection, closed} ->
                    closed_error();
                {quic_h3, Connection, {goaway, _LastStreamId}} ->
                    receive_response(
                        Connection, StreamId, Deadline, BodyLimit, Status, Headers, Chunks, Size
                    );
                {quic_h3, Connection, _OtherEvent} ->
                    receive_response(
                        Connection, StreamId, Deadline, BodyLimit, Status, Headers, Chunks, Size
                    )
            after Wait ->
                quic_h3:cancel(Connection, StreamId),
                timeout_error()
            end
    end.

receive_response_data(
    Connection,
    StreamId,
    Deadline,
    BodyLimit,
    Status,
    Headers,
    Data,
    Fin,
    Chunks,
    Size
) ->
    case Status of
        undefined ->
            protocol_error(<<"response data arrived before final headers">>);
        _ ->
            NewSize = Size + byte_size(Data),
            case NewSize > BodyLimit of
                true ->
                    quic_h3:cancel(Connection, StreamId),
                    body_limit_error();
                false when Fin =:= true ->
                    complete_response(Status, Headers, [Data | Chunks]);
                false ->
                    receive_response(
                        Connection,
                        StreamId,
                        Deadline,
                        BodyLimit,
                        Status,
                        Headers,
                        [Data | Chunks],
                        NewSize
                    )
            end
    end.

complete_response(undefined, _Headers, _Chunks) ->
    protocol_error(<<"response ended before final headers">>);
complete_response(Status, Headers, Chunks) when is_integer(Status) ->
    Body = iolist_to_binary(lists:reverse(Chunks)),
    {ok, {Status, public_headers(Headers), Body}}.

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

close_connection(Connection) ->
    Monitor = monitor(process, Connection),
    unlink(Connection),
    _ = safe_close(Connection),
    receive
        {'DOWN', Monitor, process, Connection, _Reason} ->
            ok
    after ?CLEANUP_TIMEOUT ->
        exit(Connection, kill),
        receive
            {'DOWN', Monitor, process, Connection, _Reason} -> ok
        after ?CLEANUP_TIMEOUT ->
            demonitor(Monitor, [flush]),
            ok
        end
    end.

safe_close(Connection) ->
    try quic_h3:close(Connection) of
        Result -> Result
    catch
        _:_ -> ok
    end.

remaining(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).

connect_error(Reason) ->
    {error, {?ERROR_CONNECT, 0, reason_text(Reason)}}.

request_error(Reason) ->
    {error, {?ERROR_REQUEST, 0, reason_text(Reason)}}.

timeout_error() ->
    {error, {?ERROR_TIMEOUT, 0, <<"request timeout">>}}.

body_limit_error() ->
    {error, {?ERROR_BODY_LIMIT, 0, <<"response body limit exceeded">>}}.

closed_error() ->
    {error, {?ERROR_CLOSED, 0, <<"connection closed before response completed">>}}.

protocol_error(Message) ->
    {error, {?ERROR_PROTOCOL, 0, Message}}.

backend_error(Reason) ->
    {error, {?ERROR_BACKEND, 0, reason_text(Reason)}}.

reason_text(Reason) when is_binary(Reason) ->
    truncate_reason(Reason);
reason_text(Reason) ->
    truncate_reason(iolist_to_binary(io_lib:format("~0p", [Reason]))).

truncate_reason(Reason) when byte_size(Reason) =< ?MAX_REASON_BYTES ->
    Reason;
truncate_reason(Reason) ->
    binary:part(Reason, 0, ?MAX_REASON_BYTES).
