-module(http3_internal_stream_ffi).

-export([cancel/1, close/1, connect/5, finish/1, next_event/1, open_stream/5, send_chunk/2]).

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

-define(EVENT_INFORMATIONAL, 1).
-define(EVENT_RESPONSE, 2).
-define(EVENT_DATA, 3).
-define(EVENT_TRAILERS, 4).
-define(EVENT_END, 5).

-type raw_error() :: {integer(), integer(), binary()}.
-type result(Value) :: {ok, Value} | {error, raw_error()}.
-type connection_handle() :: {http3_connection, pid(), pos_integer()}.
-type stream_handle() :: {http3_stream, pid(), non_neg_integer(), pos_integer()}.

-spec connect(binary(), inet:port_number(), [binary()], pos_integer(), pos_integer()) ->
    result(connection_handle()).
connect(Host, Port, CaCertificates, Timeout, BufferLimit) when
    is_binary(Host),
    is_integer(Port),
    Port > 0,
    Port =< 65535,
    is_list(CaCertificates),
    is_integer(Timeout),
    Timeout > 0,
    is_integer(BufferLimit),
    BufferLimit > 0
->
    Owner = self(),
    ReplyRef = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        initialise(Owner, ReplyRef, Host, Port, CaCertificates, Timeout, BufferLimit)
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
connect(_Host, _Port, _CaCertificates, _Timeout, _BufferLimit) ->
    backend_error(invalid_connect_arguments).

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

initialise(Owner, ReplyRef, Host, Port, CaCertificates, Timeout, BufferLimit) ->
    process_flag(trap_exit, true),
    Result = try initialise_connection(Host, Port, CaCertificates, Timeout) of
        Value -> Value
    catch
        exit:timeout -> timeout_error();
        exit:{timeout, _} -> timeout_error();
        Class:Reason -> backend_error({Class, Reason})
    end,
    case Result of
        {ok, Connection} ->
            OwnerMonitor = monitor(process, Owner),
            Owner ! {ReplyRef, {ok, ready}},
            loop(#{
                owner => Owner,
                owner_monitor => OwnerMonitor,
                connection => Connection,
                host => Host,
                port => Port,
                timeout => Timeout,
                buffer_limit => BufferLimit,
                accepting => true,
                streams => #{}
            });
        {error, _} = Error ->
            Owner ! {ReplyRef, Error}
    end.

initialise_connection(Host, Port, CaCertificates, Timeout) ->
    case application:ensure_all_started(quic) of
        {ok, _Started} ->
            BaseOptions = #{
                verify => verify_peer,
                settings => #{max_field_section_size => ?MAX_FIELD_SECTION_SIZE},
                sync => true,
                connect_timeout => Timeout
            },
            Options = maybe_add_ca_certificates(BaseOptions, CaCertificates),
            case quic_h3:connect(Host, Port, Options) of
                {ok, Connection} -> {ok, Connection};
                {error, connect_timeout} -> timeout_error();
                {error, timeout} -> timeout_error();
                {error, Reason} -> connect_error(Reason)
            end;
        {error, Reason} ->
            connect_error(Reason)
    end.

maybe_add_ca_certificates(Options, []) -> Options;
maybe_add_ca_certificates(Options, Certificates) -> Options#{cacerts => Certificates}.

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
                    loop(NextState#{streams => Streams#{StreamId => Waiting}})
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
        exit:timeout -> {reply, timeout_error(), State};
        exit:{timeout, _} -> {reply, timeout_error(), State};
        Class:Reason -> {reply, backend_error({Class, Reason}), State}
    end.

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
handle_call(_Request, State) ->
    {reply, backend_error(unknown_worker_call), State}.

do_open_stream(_Connection, _Headers, invalid, State) ->
    {reply, content_length_error(), State};
do_open_stream(Connection, Headers, DeclaredLength, State) ->
    case quic_h3:request(Connection, Headers, #{end_stream => false}) of
        {ok, StreamId} ->
            Timeout = maps:get(timeout, State),
            Stream = #{
                id => StreamId,
                deadline => erlang:monotonic_time(millisecond) + Timeout,
                request_state => open,
                sent => 0,
                declared_length => DeclaredLength,
                response_state => awaiting_headers,
                queue => queue:new(),
                queued_bytes => 0,
                waiter => undefined,
                terminal => undefined
            },
            Streams = maps:get(streams, State),
            Handle = {http3_stream, self(), StreamId, Timeout},
            {reply, {ok, Handle}, State#{streams => Streams#{StreamId => Stream}}};
        {error, Reason} ->
            {reply, request_error(Reason), State}
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
                    case send_with_backpressure(maps:get(connection, State), StreamId, Chunk, false, Deadline) of
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
                    case send_with_backpressure(maps:get(connection, State), StreamId, <<>>, true, Deadline) of
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

send_with_backpressure(Connection, StreamId, Data, Fin, Deadline) ->
    case remaining(Deadline) of
        0 -> timeout_error();
        _ ->
            case quic_h3:send_data(Connection, StreamId, Data, Fin) of
                ok -> ok;
                {error, {flow_control_blocked, _}} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline);
                {error, flow_control_blocked} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline);
                {error, send_queue_full} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline);
                {error, congestion_limited} ->
                    retry_send(Connection, StreamId, Data, Fin, Deadline);
                {error, timeout} -> timeout_error();
                {error, unknown_stream} -> stream_finished_error();
                {error, Reason} -> request_error(Reason)
            end
    end.

retry_send(Connection, StreamId, Data, Fin, Deadline) ->
    Wait = min(?RETRY_INTERVAL, remaining(Deadline)),
    receive after Wait -> ok end,
    send_with_backpressure(Connection, StreamId, Data, Fin, Deadline).

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
            (enqueue_event({?EVENT_END, 0, [], <<>>}, Stream, State))#{
                response_state => complete
            };
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
    Stream#{
        queue => queue:new(),
        queued_bytes => 0,
        waiter => undefined,
        terminal => Error,
        response_state => failed
    }.

fail_connection(_Reason, State) ->
    fail_all_streams(closed_error(), State#{connection => undefined, accepting => false}).

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
    State#{streams => Streams}.

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
    case Deadlines of
        [] -> infinity;
        _ -> max(0, lists:min(Deadlines) - Now)
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
backend_error(Reason) -> {error, {?ERROR_BACKEND, 0, reason_text(Reason)}}.

reason_text(Reason) when is_binary(Reason) -> truncate_reason(Reason);
reason_text(Reason) -> truncate_reason(iolist_to_binary(io_lib:format("~0p", [Reason]))).

truncate_reason(Reason) when byte_size(Reason) =< ?MAX_REASON_BYTES -> Reason;
truncate_reason(Reason) -> binary:part(Reason, 0, ?MAX_REASON_BYTES).
