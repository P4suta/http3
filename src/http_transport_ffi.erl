-module(http_transport_ffi).

-export([
    accept/2,
    client_tls_options/3,
    close/1,
    connect/4,
    connect_with_deadlines/6,
    connect_with_diagnostics/7,
    connect_with_runtime/8,
    connect_with_timeouts/5,
    diagnostics_new/0,
    diagnostics_snapshot/1,
    enable_half_close/1,
    listen/4,
    local_endpoint/1,
    monotonic_millisecond/0,
    peer_endpoint/1,
    read/3,
    read_or_message/4,
    read_or_select/4,
    read_end_is_terminal/1,
    send/2,
    server_tls_options/2,
    sort_destinations/2,
    interleave_families/1,
    resolve_families/1,
    resolve_host/1,
    shutdown_write/1,
    socket_local_endpoint/1,
    stop/1,
    transfer_listener_owner/2,
    transfer_owner/2,
    unix_millisecond/0,
    upgrade_client_tls/5,
    upgrade_server_tls/5,
    with_listener_diagnostics/2
]).

-define(MAXIMUM_RESOLVED_ADDRESSES, 16).
%% Nothing is sent to it; the port only completes the connect.
-define(SOURCE_PROBE_PORT, 9).
%% RFC 8305 section 8: the recommended Resolution Delay.
-define(RESOLUTION_DELAY, 50).
%% RFC 8305 section 8: the recommended Connection Attempt Delay.
-define(CONNECTION_ATTEMPT_DELAY, 250).
%% A TLS alert description carries peer-supplied certificate names, so the text
%% read out of one is bounded rather than taken whole.
-define(MAXIMUM_ALERT_TEXT_BYTES, 4096).
-define(MAXIMUM_RESOLVER_ROWS_INSPECTED, 256).
-define(MAXIMUM_CONNECT_CALLBACKS, 18).
-define(MAXIMUM_DIAGNOSTIC_EVENTS, 64).
-define(CONNECT_CLEANUP_ALLOWANCE_MILLISECONDS, 500).
-define(CONNECT_FORCED_JOIN_MILLISECONDS, 500).
-define(CONNECT_REAPER_KILL_JOIN_MILLISECONDS, 50).
-define(CONNECT_CALLBACK_MAX_HEAP_WORDS, 2097152).
-define(CONNECT_GUARDIAN_MAX_HEAP_WORDS, 1048576).

-type family() :: inet | inet6.
-type listener() :: #{
    kind := listener,
    socket := gen_tcp:socket(),
    send_timeout := pos_integer(),
    diagnostics => tuple()
}.
-type stream() :: #{
    kind := tcp | tls,
    socket := term(),
    buffered := binary(),
    armed => boolean(),
    diagnostics => tuple()
}.

%% Wall-clock milliseconds since the Unix epoch.
%%
%% This is the only clock here that can be compared with a date a peer sent,
%% which is what an HTTP field carrying an absolute time needs. It is read once
%% at the moment such a field is parsed and turned into a remaining duration, so
%% nothing retains it and no deadline is measured against it.
-spec unix_millisecond() -> integer().
unix_millisecond() ->
    erlang:system_time(millisecond).

-spec monotonic_millisecond() -> integer().
monotonic_millisecond() ->
    erlang:monotonic_time(millisecond).

-spec listen(binary(), integer(), integer(), integer()) ->
    {ok, listener()} | {error, integer()}.
listen(Address, Port, Backlog, SendTimeout)
    when is_binary(Address), is_integer(Port), Port >= 0, Port =< 65535,
         is_integer(Backlog), Backlog > 0, Backlog =< 1024,
         is_integer(SendTimeout), SendTimeout > 0,
         SendTimeout =< 2147483647 ->
    case decode_address(Address) of
        {ok, IpAddress, Family} ->
            Options = listener_options(
                Family,
                IpAddress,
                Backlog,
                SendTimeout
            ),
            try gen_tcp:listen(Port, Options) of
                {ok, Socket} ->
                    {ok, #{
                        kind => listener,
                        socket => Socket,
                        send_timeout => SendTimeout
                    }};
                {error, Reason} ->
                    {error, socket_error_code(Reason)}
            catch
                _Class:_Reason -> {error, 12}
            end;
        error ->
            {error, 1}
    end;
listen(_Address, _Port, _Backlog, _SendTimeout) ->
    {error, 1}.

-spec local_endpoint(listener()) ->
    {ok, {binary(), integer()}} | {error, integer()}.
local_endpoint(#{kind := listener, socket := Socket}) ->
    try inet:sockname(Socket) of
        {ok, {Address, Port}} ->
            case encode_address(Address) of
                {ok, Bytes} -> {ok, {Bytes, Port}};
                error -> {error, 12}
            end;
        {error, Reason} ->
            {error, socket_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 12}
    end;
local_endpoint(_Listener) ->
    {error, 1}.

-spec socket_local_endpoint(stream()) ->
    {ok, {binary(), integer()}} | {error, integer()}.
socket_local_endpoint(#{kind := Kind, socket := Socket})
    when Kind =:= tcp; Kind =:= tls ->
    stream_endpoint(Kind, Socket, local);
socket_local_endpoint(_Socket) ->
    {error, 1}.

-spec peer_endpoint(stream()) ->
    {ok, {binary(), integer()}} | {error, integer()}.
peer_endpoint(#{kind := Kind, socket := Socket})
    when Kind =:= tcp; Kind =:= tls ->
    stream_endpoint(Kind, Socket, peer);
peer_endpoint(_Socket) ->
    {error, 1}.

-spec accept(listener(), integer()) ->
    {ok, stream()} | {error, integer()}.
accept(
    Handle = #{kind := listener, socket := Listener, send_timeout := SendTimeout},
    Timeout
)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    trace_operation(maps:get(diagnostics, Handle, none), 7, 8, fun() ->
    try gen_tcp:accept(Listener, Timeout) of
        {ok, Socket} ->
            case configure_stream(Socket, SendTimeout) of
                ok -> {ok, stream(Socket)};
                {error, Reason} ->
                    _ = safe_close(Socket),
                    {error, socket_error_code(Reason)}
            end;
        {error, timeout} ->
            {error, 2};
        {error, Reason} ->
            {error, socket_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 12}
    end
    end);
accept(_Listener, _Timeout) ->
    {error, 1}.

-spec connect(binary(), integer(), integer(), integer()) ->
    {ok, stream()} | {error, integer()}.
connect(Host, Port, ConnectTimeout, SendTimeout)
    ->
    connect_with_timeouts(
        Host,
        Port,
        ConnectTimeout,
        ConnectTimeout,
        SendTimeout
    ).

-spec connect_with_timeouts(
    binary(), integer(), integer(), integer(), integer()
) -> {ok, stream()} | {error, integer()}.
connect_with_timeouts(Host, Port, DnsTimeout, ConnectTimeout, SendTimeout)
    when is_binary(Host), byte_size(Host) > 0, byte_size(Host) =< 253,
         is_integer(Port), Port > 0, Port =< 65535,
         is_integer(DnsTimeout), DnsTimeout > 0,
         DnsTimeout =< 2147483647,
         is_integer(ConnectTimeout), ConnectTimeout > 0,
         ConnectTimeout =< 2147483647,
         is_integer(SendTimeout), SendTimeout > 0,
         SendTimeout =< 2147483647 ->
    TotalTimeout = erlang:min(
        2147483647,
        DnsTimeout + ConnectTimeout
    ),
    connect_with_deadlines(
        Host,
        Port,
        DnsTimeout,
        ConnectTimeout,
        TotalTimeout,
        SendTimeout
    );
connect_with_timeouts(
    _Host,
    _Port,
    _DnsTimeout,
    _ConnectTimeout,
    _SendTimeout
) ->
    {error, 1}.

-spec connect_with_deadlines(
    binary(), integer(), integer(), integer(), integer(), integer()
) -> {ok, stream()} | {error, integer()}.
connect_with_deadlines(
    Host,
    Port,
    DnsTimeout,
    ConnectTimeout,
    TotalTimeout,
    SendTimeout
) ->
    connect_with_diagnostics(Host, Port, DnsTimeout, ConnectTimeout,
        TotalTimeout, SendTimeout, none).

-spec connect_with_diagnostics(binary(), integer(), integer(), integer(),
    integer(), integer(), term()) -> {ok, stream()} | {error, integer()}.
connect_with_diagnostics(Host, Port, DnsTimeout, ConnectTimeout,
    TotalTimeout, SendTimeout, Trace) ->
    connect_with_runtime(Host, Port, DnsTimeout, ConnectTimeout, TotalTimeout,
        SendTimeout, #{resolve => fun inet:getaddrs/2,
            connect => fun gen_tcp:connect/4}, Trace).

%% Internal runtime seam: the production path and deterministic fault tests
%% use the same finite resolver/dial implementation. No adapter crosses the
%% public HTTP API, and only fixed-shape scalar metadata enters diagnostics.
-spec connect_with_runtime(binary(), integer(), integer(), integer(), integer(),
    integer(), map(), term()) -> {ok, stream()} | {error, integer()}.
connect_with_runtime(
    Host, Port, DnsTimeout, ConnectTimeout, TotalTimeout, SendTimeout,
    Runtime, Trace
)
    when is_binary(Host), byte_size(Host) > 0, byte_size(Host) =< 253,
         is_integer(Port), Port > 0, Port =< 65535,
         is_integer(DnsTimeout), DnsTimeout > 0,
         DnsTimeout =< 2147483647,
         is_integer(ConnectTimeout), ConnectTimeout > 0,
         ConnectTimeout =< 2147483647,
         is_integer(TotalTimeout), TotalTimeout > 0,
         TotalTimeout =< 2147483647,
         is_integer(SendTimeout), SendTimeout > 0,
         SendTimeout =< 2147483647 ->
    case binary:match(Host, <<0>>) of
        nomatch ->
            start_connect(Host, Port, DnsTimeout, ConnectTimeout,
                TotalTimeout, SendTimeout, Runtime, Trace);
        _Match ->
            {error, 1}
    end;
connect_with_runtime(
    _Host,
    _Port,
    _DnsTimeout,
    _ConnectTimeout,
    _TotalTimeout,
    _SendTimeout,
    _Runtime,
    _Trace
) ->
    {error, 1}.

-spec diagnostics_new() -> tuple().
diagnostics_new() ->
    {http_transport_diagnostics,
        atomics:new(2 + ?MAXIMUM_DIAGNOSTIC_EVENTS * 5, [{signed, true}]),
        monotonic_millisecond()}.

-spec with_listener_diagnostics(listener(), tuple()) -> listener().
with_listener_diagnostics(Listener = #{kind := listener}, Trace) ->
    Listener#{diagnostics => Trace}.

-spec trace_operation(term(), pos_integer(), pos_integer(), fun(() -> term())) -> term().
trace_operation(Trace, Started, Completed, Operation) ->
    record_diagnostic(Trace, Started, 0, 0, 0),
    Result = Operation(),
    Code = case Result of
        {error, Failure} -> Failure;
        _ -> 0
    end,
    record_diagnostic(Trace, Completed, 0, 0, Code),
    case {Trace, Result} of
        {none, _} -> Result;
        {_, {ok, Stream = #{kind := _}}} ->
            {ok, Stream#{diagnostics => Trace}};
        {_, {ok, {Stream = #{kind := _}, Protocol, Version}}} ->
            {ok, {Stream#{diagnostics => Trace}, Protocol, Version}};
        _ -> Result
    end.

-spec diagnostics_snapshot(tuple()) ->
    {boolean(), non_neg_integer(), [tuple()]}.
diagnostics_snapshot({http_transport_diagnostics, Counters, _Started}) ->
    Count = atomics:get(Counters, 1),
    Events = [list_to_tuple([atomics:get(Counters, 2 + Index * 5 + Field)
        || Field <- lists:seq(1, 5)]) || Index <- lists:seq(0, Count - 1)],
    Consistent = Count =:= atomics:get(Counters, 1) andalso
        lists:all(fun(Event) -> element(1, Event) > 0 end, Events),
    {Consistent, atomics:get(Counters, 2), Events}.

-spec record_diagnostic(term(), pos_integer(), 0 | 4 | 6,
    non_neg_integer(), non_neg_integer()) -> ok.
record_diagnostic(none, _Kind, _Family, _Attempt, _Outcome) -> ok;
record_diagnostic({http_transport_diagnostics, Counters, Started},
    Kind, Family, Attempt, Outcome) ->
    case reserve_diagnostic(Counters, 16) of
        full ->
            increment_dropped_diagnostics(Counters, 16);
        Index ->
            Offset = 2 + Index * 5,
            atomics:put(Counters, Offset + 2, Family),
            atomics:put(Counters, Offset + 3, Attempt),
            atomics:put(Counters, Offset + 4,
                erlang:max(0, monotonic_millisecond() - Started)),
            atomics:put(Counters, Offset + 5, Outcome),
            %% Publish the kind last so an overlapping snapshot is explicit.
            atomics:put(Counters, Offset + 1, Kind)
    end.

-spec reserve_diagnostic(atomics:atomics_ref(), non_neg_integer()) ->
    full | non_neg_integer().
reserve_diagnostic(_Counters, 0) -> full;
reserve_diagnostic(Counters, Remaining) ->
    Index = atomics:get(Counters, 1),
    case Index >= ?MAXIMUM_DIAGNOSTIC_EVENTS of
        true -> full;
        false ->
            case atomics:compare_exchange(Counters, 1, Index, Index + 1) of
                ok -> Index;
                _ -> reserve_diagnostic(Counters, Remaining - 1)
            end
    end.

-spec increment_dropped_diagnostics(atomics:atomics_ref(), non_neg_integer()) -> ok.
increment_dropped_diagnostics(_Counters, 0) -> ok;
increment_dropped_diagnostics(Counters, Remaining) ->
    Count = atomics:get(Counters, 2),
    case Count >= 2147483647 of
        true -> ok;
        false ->
            case atomics:compare_exchange(Counters, 2, Count, Count + 1) of
                ok -> ok;
                _ -> increment_dropped_diagnostics(Counters, Remaining - 1)
            end
    end.

-spec upgrade_client_tls(
    stream(), binary(), [binary()], [binary()], integer()
) -> {ok, {stream(), binary(), 12 | 13}} | {error, integer()}.
upgrade_client_tls(
    Handle = #{kind := tcp, socket := Socket},
    ServerName,
    CaCertificates,
    AlpnProtocols,
    Timeout
)
    when is_binary(ServerName), byte_size(ServerName) > 0,
         byte_size(ServerName) =< 253,
         is_list(CaCertificates), is_list(AlpnProtocols),
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    trace_operation(maps:get(diagnostics, Handle, none), 9, 10, fun() ->
    case valid_server_name(ServerName) andalso
        valid_alpn_protocols(AlpnProtocols)
    of
        true ->
            case trusted_certificates(CaCertificates) of
                {ok, TrustedCertificates} ->
                    _ = application:ensure_all_started(ssl),
                    Options = client_tls_options(
                        ServerName,
                        TrustedCertificates,
                        AlpnProtocols
                    ),
                    try ssl:connect(Socket, Options, Timeout) of
                        {ok, TlsSocket} -> tls_ready(TlsSocket);
                        {error, Reason} ->
                            _ = safe_close(Socket),
                            {error, tls_error_code(Reason)}
                    catch
                        _Class:_Reason ->
                            _ = safe_close(Socket),
                            {error, 13}
                    end;
                {error, _Reason} ->
                    {error, 1}
            end;
        false ->
            {error, 1}
    end
    end);
upgrade_client_tls(
    _Socket,
    _ServerName,
    _CaCertificates,
    _AlpnProtocols,
    _Timeout
) ->
    {error, 1}.

-spec upgrade_server_tls(
    stream(), binary(), binary(), [binary()], integer()
) -> {ok, {stream(), binary(), 12 | 13}} | {error, integer()}.
upgrade_server_tls(
    Handle = #{kind := tcp, socket := Socket},
    CertificatePem,
    PrivateKeyPem,
    AlpnProtocols,
    Timeout
)
    when is_binary(CertificatePem), byte_size(CertificatePem) > 0,
         is_binary(PrivateKeyPem), byte_size(PrivateKeyPem) > 0,
         is_list(AlpnProtocols),
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    trace_operation(maps:get(diagnostics, Handle, none), 11, 12, fun() ->
    case valid_alpn_protocols(AlpnProtocols) of
        true ->
            case server_credentials(CertificatePem, PrivateKeyPem) of
                {ok, CertsKeys} ->
                    _ = application:ensure_all_started(ssl),
                    Options = server_tls_options(CertsKeys, AlpnProtocols),
                    try ssl:handshake(Socket, Options, Timeout) of
                        {ok, TlsSocket} -> tls_ready(TlsSocket);
                        {error, Reason} ->
                            _ = safe_close(Socket),
                            {error, tls_error_code(Reason)}
                    catch
                        _Class:_Reason ->
                            _ = safe_close(Socket),
                            {error, 13}
                    end;
                {error, _Reason} ->
                    {error, 1}
            end;
        false ->
            {error, 1}
    end
    end);
upgrade_server_tls(
    _Socket,
    _CertificatePem,
    _PrivateKeyPem,
    _AlpnProtocols,
    _Timeout
) ->
    {error, 1}.

-spec transfer_owner(stream(), pid()) -> {ok, nil} | {error, integer()}.
transfer_owner(#{kind := tcp, socket := Socket}, Owner) when is_pid(Owner) ->
    try gen_tcp:controlling_process(Socket, Owner) of
        ok -> {ok, nil};
        {error, Reason} -> {error, owner_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 11}
    end;
transfer_owner(#{kind := tls, socket := Socket}, Owner) when is_pid(Owner) ->
    try ssl:controlling_process(Socket, Owner) of
        ok -> {ok, nil};
        {error, Reason} -> {error, owner_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 11}
    end;
transfer_owner(_Socket, _Owner) ->
    {error, 1}.

-spec transfer_listener_owner(listener(), pid()) ->
    {ok, nil} | {error, integer()}.
transfer_listener_owner(
    #{kind := listener, socket := Socket},
    Owner
) when is_pid(Owner) ->
    try gen_tcp:controlling_process(Socket, Owner) of
        ok -> {ok, nil};
        {error, Reason} -> {error, owner_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 11}
    end;
transfer_listener_owner(_Listener, _Owner) ->
    {error, 1}.

-spec send(stream(), binary()) -> {ok, nil} | {error, integer()}.
send(#{kind := tcp, socket := Socket}, Bytes) when is_binary(Bytes) ->
    try gen_tcp:send(Socket, Bytes) of
        ok -> {ok, nil};
        {error, Reason} -> {error, write_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 7}
    end;
send(#{kind := tls, socket := Socket}, Bytes) when is_binary(Bytes) ->
    try ssl:send(Socket, Bytes) of
        ok -> {ok, nil};
        {error, Reason} -> {error, write_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 7}
    end;
send(_Socket, _Bytes) ->
    {error, 1}.

-spec enable_half_close(stream()) -> {ok, nil} | {error, integer()}.
enable_half_close(#{kind := tcp, socket := Socket}) ->
    try inet:setopts(Socket, [{exit_on_close, false}]) of
        ok -> {ok, nil};
        {error, Reason} -> {error, socket_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 12}
    end;
enable_half_close(_Socket) ->
    {error, 1}.

-spec shutdown_write(stream()) -> {ok, nil} | {error, integer()}.
shutdown_write(#{kind := tcp, socket := Socket}) ->
    try gen_tcp:shutdown(Socket, write) of
        ok -> {ok, nil};
        {error, Reason} -> {error, socket_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 12}
    end;
shutdown_write(#{kind := tls, socket := Socket}) ->
    try ssl:shutdown(Socket, write) of
        ok -> {ok, nil};
        {error, Reason} -> {error, socket_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 12}
    end;
shutdown_write(_Socket) ->
    {error, 1}.

-spec read(stream(), integer(), integer()) ->
    {ok, {stream(), binary(), 0 | 1}} | {error, integer()}.
read(Handle = #{kind := Kind, buffered := Buffered}, Maximum, Timeout)
    when is_integer(Maximum), Maximum > 0,
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647,
         (Kind =:= tcp orelse Kind =:= tls) ->
    case Buffered of
        <<>> -> active_read(Handle, Maximum, Timeout);
        _ -> bounded_data(Handle, Buffered, Maximum)
    end;
read(_Socket, _Maximum, _Timeout) ->
    {error, 1}.

%% Select a single bounded producer completion alongside socket input. When
%% the producer wins, the same active-once credit remains armed; a following
%% receive must consume it instead of granting another socket message.
read_or_message(Handle = #{kind := Kind, buffered := Buffered}, Maximum, Timeout,
        {subject, Owner, Ref})
    when (Kind =:= tcp orelse Kind =:= tls), Owner =:= self(),
         is_reference(Ref), is_integer(Maximum), Maximum > 0,
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    case Buffered of
        <<>> -> selective_active_read(Handle, Maximum, Timeout, Ref);
        _ -> selected_data(Handle, Buffered, Maximum)
    end;
read_or_message(_Handle, _Maximum, _Timeout, _Subject) -> {error, 1}.

read_end_is_terminal(#{kind := tcp}) -> false;
read_end_is_terminal(_) -> true.

%% The pinned Gleam selector contains only typed control and monitor mappings.
%% Match this socket before those mappings; unrelated sockets remain queued.
read_or_select(Handle = #{kind := Kind, socket := Socket, buffered := Buffered},
        Maximum, Timeout, {selector, Handlers})
    when (Kind =:= tcp orelse Kind =:= tls), is_map(Handlers),
         map_size(Handlers) =< 32, is_integer(Maximum), Maximum > 0,
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    case Buffered of
        <<>> -> case arm_read(Handle) of
            ok ->
                Armed = Handle#{armed => true},
                receive
                    {tcp, Socket, Data} when Kind =:= tcp, is_binary(Data) ->
                        selected_data(Armed#{armed => false}, Data, Maximum);
                    {ssl, Socket, Data} when Kind =:= tls, is_binary(Data) ->
                        selected_data(Armed#{armed => false}, Data, Maximum);
                    {tcp_closed, Socket} when Kind =:= tcp ->
                        {ok, {Armed#{armed => false}, <<>>, 1, none}};
                    {ssl_closed, Socket} when Kind =:= tls ->
                        {ok, {Armed#{armed => false}, <<>>, 1, none}};
                    {tcp_error, Socket, Reason} when Kind =:= tcp ->
                        {error, read_error_code(Reason)};
                    {ssl_error, Socket, Reason} when Kind =:= tls ->
                        {error, read_error_code(Reason)};
                    {'DOWN', Ref, Type, Pid, Reason} when is_map_key(Ref, Handlers) ->
                        Transform = maps:get(Ref, Handlers),
                        Tag = case Type of
                            process -> process_down;
                            port -> port_down
                        end,
                        Exit = case Reason of
                            normal -> normal;
                            killed -> killed;
                            _ -> {abnormal, Reason}
                        end,
                        {ok, {Armed, <<>>, 2, {some, Transform({Tag, Ref, Pid, Exit})}}};
                    Message when is_map_key({element(1, Message), tuple_size(Message)}, Handlers) ->
                        Transform = maps:get({element(1, Message), tuple_size(Message)}, Handlers),
                        {ok, {Armed, <<>>, 2, {some, Transform(Message)}}}
                after Timeout ->
                    _ = safe_close_stream(Kind, Socket),
                    flush_socket_messages(Socket),
                    {error, 2}
                end;
            {error, closed} -> {ok, {Handle, <<>>, 1, none}};
            {error, einval} -> {ok, {Handle, <<>>, 1, none}};
            {error, Reason} -> {error, read_error_code(Reason)}
        end;
        _ -> selected_data(Handle, Buffered, Maximum)
    end;
read_or_select(_, _, _, _) -> {error, 1}.

selective_active_read(Handle = #{kind := Kind, socket := Socket}, Maximum, Timeout, Ref) ->
    case arm_read(Handle) of
        ok ->
            Armed = Handle#{armed => true},
            receive
                {Ref, Message} -> {ok, {Armed, <<>>, 2, {some, Message}}};
                {tcp, Socket, Data} when Kind =:= tcp, is_binary(Data) ->
                    selected_data(Armed#{armed => false}, Data, Maximum);
                {ssl, Socket, Data} when Kind =:= tls, is_binary(Data) ->
                    selected_data(Armed#{armed => false}, Data, Maximum);
                {tcp_closed, Socket} when Kind =:= tcp ->
                    {ok, {Armed#{armed => false}, <<>>, 1, none}};
                {ssl_closed, Socket} when Kind =:= tls ->
                    {ok, {Armed#{armed => false}, <<>>, 1, none}};
                {tcp_error, Socket, Reason} when Kind =:= tcp ->
                    {error, read_error_code(Reason)};
                {ssl_error, Socket, Reason} when Kind =:= tls ->
                    {error, read_error_code(Reason)}
            after Timeout ->
                _ = safe_close_stream(Kind, Socket),
                flush_socket_messages(Socket),
                {error, 2}
            end;
        {error, closed} -> {ok, {Handle, <<>>, 1, none}};
        {error, einval} -> {ok, {Handle, <<>>, 1, none}};
        {error, Reason} -> {error, read_error_code(Reason)}
    end.

selected_data(Handle, Data, Maximum) ->
    {ok, {Next, Chunk, 0}} = bounded_data(Handle, Data, Maximum),
    {ok, {Next, Chunk, 0, none}}.

arm_read(#{armed := true}) -> ok;
arm_read(#{kind := tcp, socket := Socket}) -> inet:setopts(Socket, [{active, once}]);
arm_read(#{kind := tls, socket := Socket}) -> ssl:setopts(Socket, [{active, once}]).

-spec close(stream()) -> {ok, nil} | {error, integer()}.
close(#{kind := Kind, socket := Socket}) when Kind =:= tcp; Kind =:= tls ->
    ok = safe_close_stream(Kind, Socket),
    {ok, nil};
close(_Socket) ->
    {error, 1}.

-spec stop(listener()) -> {ok, nil} | {error, integer()}.
stop(#{kind := listener, socket := Socket}) ->
    ok = safe_close(Socket),
    {ok, nil};
stop(_Listener) ->
    {error, 1}.

-spec active_read(stream(), pos_integer(), pos_integer()) ->
    {ok, {stream(), binary(), 0 | 1}} | {error, integer()}.
active_read(Handle = #{kind := tcp, socket := Socket}, Maximum, Timeout) ->
    case arm_read(Handle) of
        ok ->
            receive
                {tcp, Socket, Data} when is_binary(Data) ->
                    bounded_data(Handle#{armed => false}, Data, Maximum);
                {tcp_closed, Socket} ->
                    {ok, {Handle, <<>>, 1}};
                {tcp_error, Socket, Reason} ->
                    {error, read_error_code(Reason)}
            after Timeout ->
                _ = safe_close(Socket),
                flush_socket_messages(Socket),
                {error, 2}
            end;
        {error, closed} ->
            {ok, {Handle, <<>>, 1}};
        {error, einval} ->
            {ok, {Handle, <<>>, 1}};
        {error, Reason} ->
            {error, read_error_code(Reason)}
    end;
active_read(Handle = #{kind := tls, socket := Socket}, Maximum, Timeout) ->
    case arm_read(Handle) of
        ok ->
            receive
                {ssl, Socket, Data} when is_binary(Data) ->
                    bounded_data(Handle#{armed => false}, Data, Maximum);
                {ssl_closed, Socket} ->
                    {ok, {Handle, <<>>, 1}};
                {ssl_error, Socket, Reason} ->
                    {error, read_error_code(Reason)}
            after Timeout ->
                _ = safe_close_stream(tls, Socket),
                flush_socket_messages(Socket),
                {error, 2}
            end;
        {error, closed} ->
            {ok, {Handle, <<>>, 1}};
        {error, einval} ->
            {ok, {Handle, <<>>, 1}};
        {error, Reason} ->
            {error, read_error_code(Reason)}
    end.

-spec bounded_data(stream(), binary(), pos_integer()) ->
    {ok, {stream(), binary(), 0}}.
bounded_data(Handle, Data, Maximum) when byte_size(Data) =< Maximum ->
    {ok, {Handle#{buffered => <<>>}, Data, 0}};
bounded_data(Handle, Data, Maximum) ->
    <<Chunk:Maximum/binary, Remaining/binary>> = Data,
    {ok, {Handle#{buffered => Remaining}, Chunk, 0}}.

-spec flush_socket_messages(term()) -> ok.
flush_socket_messages(Socket) ->
    receive
        {tcp, Socket, _Data} -> flush_socket_messages(Socket);
        {tcp_closed, Socket} -> flush_socket_messages(Socket);
        {tcp_error, Socket, _Reason} -> flush_socket_messages(Socket);
        {ssl, Socket, _Data} -> flush_socket_messages(Socket);
        {ssl_closed, Socket} -> flush_socket_messages(Socket);
        {ssl_error, Socket, _Reason} -> flush_socket_messages(Socket)
    after 0 ->
        ok
    end.

-spec safe_close(gen_tcp:socket()) -> ok.
safe_close(Socket) ->
    try gen_tcp:close(Socket) of
        Result -> Result
    catch
        _Class:_Reason -> ok
    end.

-spec safe_close_stream(tcp | tls, term()) -> ok.
safe_close_stream(tcp, Socket) ->
    safe_close(Socket);
safe_close_stream(tls, Socket) ->
    try ssl:close(Socket) of
        _Result -> ok
    catch
        _Class:_Reason -> ok
    end.

-spec stream_endpoint(tcp | tls, term(), local | peer) ->
    {ok, {binary(), integer()}} | {error, integer()}.
stream_endpoint(tcp, Socket, local) ->
    encode_stream_endpoint(fun inet:sockname/1, Socket);
stream_endpoint(tcp, Socket, peer) ->
    encode_stream_endpoint(fun inet:peername/1, Socket);
stream_endpoint(tls, Socket, local) ->
    encode_stream_endpoint(fun ssl:sockname/1, Socket);
stream_endpoint(tls, Socket, peer) ->
    encode_stream_endpoint(fun ssl:peername/1, Socket).

-spec encode_stream_endpoint(fun((term()) -> term()), term()) ->
    {ok, {binary(), integer()}} | {error, integer()}.
encode_stream_endpoint(EndpointFun, Socket) ->
    try EndpointFun(Socket) of
        {ok, {Address, Port}} ->
            case encode_address(Address) of
                {ok, Bytes} -> {ok, {Bytes, Port}};
                error -> {error, 12}
            end;
        {error, Reason} ->
            {error, socket_error_code(Reason)}
    catch
        _Class:_Reason -> {error, 12}
    end.

%% RFC 8305: two asynchronous family queries, a 50 ms resolution delay,
%% 250 ms stagger, and a 100 ms minimum after a failed attempt. The existing
%% 16-address limit also bounds candidate processes and simultaneous sockets.
%% A private coordinator owns every completed socket until the winner is
%% handed to the caller. A separately monitored reaper keeps a payload-free,
%% finite ledger of coordinator and callback identities. No resolver or dial
%% callback starts until both the coordinator and reaper own monitors for it.
-spec start_connect(binary(), inet:port_number(), pos_integer(), pos_integer(),
    pos_integer(), pos_integer(), map(), term()) ->
    {ok, stream()} | {error, integer()}.
start_connect(Host, Port, DnsTimeout, ConnectTimeout, TotalTimeout,
    SendTimeout, Runtime, Trace) ->
    Parent = self(),
    Reference = make_ref(),
    %% Registration, handoff, result, and reaper sealing share this finite
    %% lifecycle bus. It must remain active until the after-clause unaliases it.
    ReplyAlias = erlang:alias(),
    Now = monotonic_millisecond(),
    TotalDeadline = Now + TotalTimeout,
    CleanupDeadline = TotalDeadline + ?CONNECT_CLEANUP_ALLOWANCE_MILLISECONDS,
    TerminationDeadline = CleanupDeadline + ?CONNECT_FORCED_JOIN_MILLISECONDS,
    try start_connect_guardians(
        Parent, ReplyAlias, Reference, Host, Port, DnsTimeout, ConnectTimeout,
        SendTimeout, Runtime, Trace, Now, TotalDeadline, CleanupDeadline,
        TerminationDeadline
    ) of
        {ok, Lifecycle} ->
            run_guarded_connect(Lifecycle, Runtime, Trace, TotalDeadline,
                CleanupDeadline, TerminationDeadline);
        {error, Lifecycle} ->
            {_FinalLifecycle, _Join} = force_connect_lifecycle(
                Lifecycle, TerminationDeadline),
            record_diagnostic(Trace, 6, 0, 0, 5),
            {error, 5};
        spawn_failed ->
            record_diagnostic(Trace, 6, 0, 0, 5),
            {error, 5}
    after
        erlang:unalias(ReplyAlias),
        flush_connect_caller_messages(Reference)
    end.

-spec start_connect_guardians(
    pid(), reference(), reference(), binary(), inet:port_number(),
    pos_integer(), pos_integer(), pos_integer(), map(), term(), integer(),
    integer(), integer(), integer()
) -> {ok, map()} | {error, map()} | spawn_failed.
start_connect_guardians(
    Parent, ReplyAlias, Reference, Host, Port, DnsTimeout, ConnectTimeout,
    SendTimeout, Runtime, Trace, Now, TotalDeadline, CleanupDeadline,
    TerminationDeadline
) ->
    ReaperRun = fun() ->
        connect_reaper(Parent, ReplyAlias, Reference, TerminationDeadline)
    end,
    case spawn_connect_guardian(ReaperRun) of
        spawn_failed ->
            spawn_failed;
        {Reaper, ReaperMonitor} ->
            CoordinatorRun = fun() ->
                connect_coordinator(
                    Parent, ReplyAlias, Reaper, Reference, Host, Port,
                    DnsTimeout, ConnectTimeout, SendTimeout, Runtime, Trace,
                    Now, TotalDeadline, CleanupDeadline
                )
            end,
            case spawn_connect_guardian(CoordinatorRun) of
                spawn_failed ->
                    exit(Reaper, kill),
                    Lifecycle = connect_lifecycle(
                        none, none, Reaper, ReaperMonitor, Reference,
                        ReplyAlias),
                    {error, Lifecycle};
                {Coordinator, CoordinatorMonitor} ->
                    observe_runtime_process(Runtime, 3, Reaper),
                    observe_runtime_process(Runtime, 0, Coordinator),
                    Lifecycle = connect_lifecycle(
                        Coordinator, CoordinatorMonitor, Reaper,
                        ReaperMonitor, Reference, ReplyAlias),
                    case connect_pre_start_probe(
                        Runtime, ReplyAlias, Reference, Reaper, Coordinator,
                        TotalDeadline
                    ) of
                        continue ->
                            Reaper ! {
                                Reference,
                                http_transport_register_coordinator,
                                Coordinator
                            },
                            {ok, Lifecycle};
                        stop ->
                            {error, Lifecycle}
                    end
            end
    end.

-spec spawn_connect_guardian(fun(() -> ok)) ->
    {pid(), reference()} | spawn_failed.
spawn_connect_guardian(Run) ->
    try spawn_opt(Run, connect_guardian_spawn_options()) of
        {Pid, Monitor} when is_pid(Pid), is_reference(Monitor) ->
            {Pid, Monitor};
        _ ->
            spawn_failed
    catch
        _Class:_Reason -> spawn_failed
    end.

-spec connect_guardian_spawn_options() -> list().
connect_guardian_spawn_options() ->
    [monitor, {max_heap_size, #{
        size => ?CONNECT_GUARDIAN_MAX_HEAP_WORDS,
        kill => true,
        error_logger => false,
        include_shared_binaries => true
    }}].

-spec connect_callback_spawn_options() -> list().
connect_callback_spawn_options() ->
    [link, monitor, {max_heap_size, #{
        size => ?CONNECT_CALLBACK_MAX_HEAP_WORDS,
        kill => true,
        error_logger => false,
        include_shared_binaries => true
    }}].

-spec connect_lifecycle(
    none | pid(), none | reference(), pid(), reference(), reference(),
    reference()
) -> map().
connect_lifecycle(
    Coordinator, CoordinatorMonitor, Reaper, ReaperMonitor, Reference,
    ReplyAlias
) ->
    #{
        reference => Reference,
        reply_alias => ReplyAlias,
        coordinator => Coordinator,
        coordinator_monitor => CoordinatorMonitor,
        coordinator_down => Coordinator =:= none,
        reaper => Reaper,
        reaper_monitor => ReaperMonitor,
        reaper_down => false,
        reaper_status => none,
        workers => #{},
        provisional_socket => none,
        result => none,
        forced => false,
        ledger_overflow => false
    }.

%% This internal diagnostic synchronization point carries process identities
%% and a reference only. It never carries hosts, addresses, results, or errors.
-spec connect_pre_start_probe(
    map(), reference(), reference(), pid(), pid(), integer()
) -> continue | stop.
connect_pre_start_probe(
    Runtime, ReplyAlias, Reference, Reaper, Coordinator, Deadline
) ->
    case maps:get(lifecycle_probe, Runtime, none) of
        {http_transport_lifecycle_probe, Observer, ProbeReference}
            when is_pid(Observer), is_reference(ProbeReference) ->
            Observer ! {
                http_transport_connect_pre_start,
                ProbeReference,
                Reference,
                ReplyAlias,
                Reaper,
                Coordinator
            },
            receive
                {
                    Reference,
                    http_transport_continue_pre_start,
                    ProbeReference
                } ->
                    case monotonic_millisecond() < Deadline of
                        true -> continue;
                        false -> stop
                    end
            after remaining_milliseconds(Deadline) ->
                stop
            end;
        _ ->
            continue
    end.

-spec flush_connect_caller_messages(reference()) -> ok.
flush_connect_caller_messages(Reference) ->
    receive
        {http_transport_dial, Reference, Result} ->
            close_connect_result_if_present(Result),
            flush_connect_caller_messages(Reference);
        {
            Reference,
            http_transport_socket_handoff,
            _Coordinator,
            Socket,
            _HandoffReference
        } ->
            safe_close(Socket),
            flush_connect_caller_messages(Reference);
        {
            Reference,
            http_transport_coordinator_registered,
            _Reaper,
            _Coordinator,
            _RegistrationReference
        } ->
            flush_connect_caller_messages(Reference);
        {
            Reference,
            http_transport_worker_registered,
            _Reaper,
            Worker,
            _Kind
        } ->
            exit(Worker, kill),
            flush_connect_caller_messages(Reference);
        {Reference, http_transport_reaper_sealed, _Reaper, _Status} ->
            flush_connect_caller_messages(Reference);
        {
            Reference,
            http_transport_continue_pre_start,
            _ProbeReference
        } ->
            flush_connect_caller_messages(Reference)
    after 0 ->
        ok
    end.

-spec run_guarded_connect(
    map(), map(), term(), integer(), integer(), integer()
) -> {ok, stream()} | {error, integer()}.
run_guarded_connect(
    Lifecycle, _Runtime, Trace, TotalDeadline, CleanupDeadline,
    TerminationDeadline
) ->
    case await_connect_registration(Lifecycle, TotalDeadline) of
        {started, StartedLifecycle} ->
            case await_connect_lifecycle(StartedLifecycle, CleanupDeadline) of
                {complete, CompletedLifecycle} ->
                    finalize_guarded_connect(
                        CompletedLifecycle, Trace, TotalDeadline);
                {deadline, PendingLifecycle} ->
                    {FinalLifecycle, Join} = force_connect_lifecycle(
                        PendingLifecycle, TerminationDeadline),
                    finalize_forced_connect(
                        FinalLifecycle, Join, Trace, TotalDeadline)
            end;
        {failed, FailedLifecycle} ->
            {FinalLifecycle, Join} = force_connect_lifecycle(
                FailedLifecycle, TerminationDeadline),
            finalize_forced_connect(
                FinalLifecycle, Join, Trace, TotalDeadline)
    end.

-spec await_connect_registration(map(), integer()) ->
    {started, map()} | {failed, map()}.
await_connect_registration(
    Lifecycle = #{
        reference := Reference,
        coordinator := Coordinator,
        reaper := Reaper,
        coordinator_monitor := CoordinatorMonitor,
        reaper_monitor := ReaperMonitor
    },
    Deadline
) ->
    receive
        {
            Reference,
            http_transport_coordinator_registered,
            Reaper,
            Coordinator,
            RegistrationReference
        } when is_reference(RegistrationReference) ->
            case monotonic_millisecond() < Deadline
                andalso erlang:is_process_alive(Coordinator)
                andalso erlang:is_process_alive(Reaper)
            of
                true ->
                    Coordinator ! {
                        RegistrationReference,
                        http_transport_connect_start,
                        self(),
                        Reaper
                    },
                    {started, Lifecycle};
                false ->
                    {failed, Lifecycle}
            end;
        {'DOWN', CoordinatorMonitor, process, Coordinator, _Reason} ->
            {failed, Lifecycle#{coordinator_down => true}};
        {'DOWN', ReaperMonitor, process, Reaper, _Reason} ->
            {failed, Lifecycle#{reaper_down => true}}
    after remaining_milliseconds(Deadline) ->
        {failed, Lifecycle}
    end.

-spec await_connect_lifecycle(map(), integer()) ->
    {complete, map()} | {deadline, map()}.
await_connect_lifecycle(Lifecycle, Deadline) ->
    case connect_lifecycle_complete(Lifecycle) of
        true ->
            {complete, Lifecycle};
        false ->
            await_connect_lifecycle_message(Lifecycle, Deadline)
    end.

-spec await_connect_lifecycle_message(map(), integer()) ->
    {complete, map()} | {deadline, map()}.
await_connect_lifecycle_message(
    Lifecycle = #{
        reference := Reference,
        coordinator := Coordinator,
        coordinator_monitor := CoordinatorMonitor,
        reaper := Reaper,
        reaper_monitor := ReaperMonitor,
        workers := Workers
    },
    Deadline
) ->
    receive
        {http_transport_dial, Reference, Result} ->
            await_connect_lifecycle(
                store_connect_result(Result, Lifecycle), Deadline);
        {
            Reference,
            http_transport_socket_handoff,
            Coordinator,
            Socket,
            HandoffReference
        } when is_reference(HandoffReference) ->
            await_connect_lifecycle(
                store_connect_handoff(
                    Coordinator, Socket, HandoffReference, Lifecycle
                ),
                Deadline
            );
        {
            Reference,
            http_transport_worker_registered,
            Reaper,
            Worker,
            Kind
        } when is_pid(Worker), (Kind =:= 1 orelse Kind =:= 2) ->
            await_connect_lifecycle(
                caller_register_connect_worker(Worker, Lifecycle), Deadline);
        {Reference, http_transport_reaper_sealed, Reaper, Status}
            when Status =:= ok; Status =:= timeout ->
            await_connect_lifecycle(
                Lifecycle#{reaper_status => Status}, Deadline);
        {'DOWN', CoordinatorMonitor, process, Coordinator, _Reason} ->
            await_connect_lifecycle(
                close_uncommitted_handoff(
                    Lifecycle#{coordinator_down => true}
                ),
                Deadline
            );
        {'DOWN', ReaperMonitor, process, Reaper, _Reason} ->
            await_connect_lifecycle(
                Lifecycle#{reaper_down => true}, Deadline);
        {'DOWN', WorkerMonitor, process, _Worker, _Reason}
            when is_map_key(WorkerMonitor, Workers) ->
            await_connect_lifecycle(
                Lifecycle#{workers => maps:remove(WorkerMonitor, Workers)},
                Deadline);
        {
            Reference,
            http_transport_coordinator_registered,
            Reaper,
            Coordinator,
            _RegistrationReference
        } ->
            await_connect_lifecycle(Lifecycle, Deadline);
        {
            Reference,
            http_transport_continue_pre_start,
            _ProbeReference
        } ->
            await_connect_lifecycle(Lifecycle, Deadline)
    after remaining_milliseconds(Deadline) ->
        {deadline, Lifecycle}
    end.

-spec store_connect_handoff(pid(), term(), reference(), map()) -> map().
store_connect_handoff(
    Coordinator,
    Socket,
    HandoffReference,
    Lifecycle = #{provisional_socket := none}
) ->
    Recorded = Lifecycle#{
        provisional_socket => {Socket, HandoffReference}
    },
    Coordinator ! {
        HandoffReference,
        http_transport_socket_handoff_ready,
        self()
    },
    Recorded;
store_connect_handoff(
    Coordinator,
    Socket,
    HandoffReference,
    Lifecycle = #{provisional_socket := {Socket, HandoffReference}}
) ->
    Coordinator ! {
        HandoffReference,
        http_transport_socket_handoff_ready,
        self()
    },
    Lifecycle;
store_connect_handoff(_Coordinator, Socket, _HandoffReference, Lifecycle) ->
    safe_close(Socket),
    Lifecycle#{ledger_overflow => true}.

-spec caller_register_connect_worker(pid(), map()) -> map().
caller_register_connect_worker(Worker, Lifecycle = #{workers := Workers}) ->
    case map_size(Workers) >= ?MAXIMUM_CONNECT_CALLBACKS orelse
        lists:member(Worker, maps:values(Workers))
    of
        true ->
            exit(Worker, kill),
            Lifecycle#{ledger_overflow => true};
        false ->
            try erlang:monitor(process, Worker) of
                Monitor when is_reference(Monitor) ->
                    Lifecycle#{
                        workers => maps:put(Monitor, Worker, Workers)
                    }
            catch
                _Class:_Reason ->
                    exit(Worker, kill),
                    Lifecycle#{ledger_overflow => true}
            end
    end.

-spec store_connect_result(term(), map()) -> map().
store_connect_result(
    Result,
    Lifecycle = #{result := none, provisional_socket := Provisional}
) ->
    Stored = case Result of
        {ok, Stream = #{kind := Kind, socket := Socket}}
            when Kind =:= tcp; Kind =:= tls ->
            case Provisional of
                {Socket, _HandoffReference} ->
                    Lifecycle#{result => {ok, Stream}};
                _ ->
                    close_connect_result({ok, Stream}),
                    Lifecycle#{result => {error, 5}}
            end;
        {error, Code} when is_integer(Code), Code >= 1, Code =< 18 ->
            Lifecycle#{result => {error, Code}};
        _ ->
            Lifecycle#{result => {error, 5}}
    end,
    close_uncommitted_handoff(Stored);
store_connect_result(Result, Lifecycle) ->
    close_connect_result_if_present(Result),
    Lifecycle.

-spec close_uncommitted_handoff(map()) -> map().
close_uncommitted_handoff(
    Lifecycle = #{
        provisional_socket := {Socket, _HandoffReference},
        result := {ok, #{socket := Socket}}
    }
) ->
    Lifecycle;
close_uncommitted_handoff(
    Lifecycle = #{provisional_socket := {Socket, _HandoffReference}}
) ->
    safe_close(Socket),
    Lifecycle#{provisional_socket => none};
close_uncommitted_handoff(Lifecycle) ->
    Lifecycle.

-spec connect_lifecycle_complete(map()) -> boolean().
connect_lifecycle_complete(#{
    coordinator_down := true,
    reaper_down := true,
    workers := Workers
}) ->
    map_size(Workers) =:= 0;
connect_lifecycle_complete(_) ->
    false.

-spec force_connect_lifecycle(map(), integer()) ->
    {map(), forced | timeout}.
force_connect_lifecycle(Lifecycle, TerminationDeadline) ->
    Stopping = kill_connect_lifecycle(Lifecycle#{forced => true}),
    ReaperKillDeadline = erlang:max(
        monotonic_millisecond(),
        TerminationDeadline - ?CONNECT_REAPER_KILL_JOIN_MILLISECONDS
    ),
    case await_connect_lifecycle(Stopping, ReaperKillDeadline) of
        {complete, Completed} ->
            {Completed, forced};
        {deadline, Pending} ->
            HardStopping = hard_kill_connect_lifecycle(Pending),
            case await_connect_lifecycle(
                HardStopping, TerminationDeadline
            ) of
                {complete, Completed} ->
                    {Completed, forced};
                {deadline, Final} ->
                    demonitor_connect_lifecycle(Final),
                    {Final, timeout}
            end
    end.

-spec kill_connect_lifecycle(map()) -> map().
kill_connect_lifecycle(InitialLifecycle) ->
    Lifecycle = close_connect_lifecycle_sockets(InitialLifecycle),
    kill_connect_lifecycle_processes(Lifecycle).

-spec kill_connect_lifecycle_processes(map()) -> map().
kill_connect_lifecycle_processes(Lifecycle = #{
    coordinator := Coordinator,
    coordinator_down := CoordinatorDown,
    reaper := Reaper,
    reaper_down := ReaperDown,
    workers := Workers
}) ->
    case CoordinatorDown orelse Coordinator =:= none of
        true -> ok;
        false -> exit(Coordinator, kill)
    end,
    maps:foreach(fun(_Monitor, Worker) -> exit(Worker, kill) end, Workers),
    case ReaperDown of
        true -> ok;
        false -> Reaper ! {maps:get(reference, Lifecycle),
            http_transport_force_reap, self()}
    end,
    Lifecycle.

-spec close_connect_lifecycle_sockets(map()) -> map().
close_connect_lifecycle_sockets(Lifecycle = #{result := Result}) ->
    close_connect_result_if_present(Result),
    case maps:get(provisional_socket, Lifecycle, none) of
        {Socket, _HandoffReference} -> safe_close(Socket);
        none -> ok
    end,
    Lifecycle#{provisional_socket => none}.

-spec hard_kill_connect_lifecycle(map()) -> map().
hard_kill_connect_lifecycle(Lifecycle = #{
    reaper := Reaper,
    reaper_down := ReaperDown
}) ->
    Stopping = kill_connect_lifecycle(Lifecycle),
    case ReaperDown of
        true -> ok;
        false -> exit(Reaper, kill)
    end,
    Stopping.

-spec demonitor_connect_lifecycle(map()) -> ok.
demonitor_connect_lifecycle(#{
    coordinator_monitor := CoordinatorMonitor,
    reaper_monitor := ReaperMonitor,
    workers := Workers
}) ->
    case CoordinatorMonitor of
        none -> ok;
        _ -> erlang:demonitor(CoordinatorMonitor, [flush])
    end,
    erlang:demonitor(ReaperMonitor, [flush]),
    maps:foreach(fun(Monitor, _Worker) ->
        erlang:demonitor(Monitor, [flush])
    end, Workers),
    ok.

-spec finalize_guarded_connect(map(), term(), integer()) ->
    {ok, stream()} | {error, integer()}.
finalize_guarded_connect(
    Lifecycle = #{
        result := Result,
        reaper_status := ReaperStatus,
        ledger_overflow := LedgerOverflow
    },
    Trace,
    TotalDeadline
) ->
    demonitor_connect_lifecycle(Lifecycle),
    case {ReaperStatus, LedgerOverflow, Result} of
        {ok, false, {ok, _} = Success} ->
            finalize_connect_result(Trace, Success, TotalDeadline);
        {ok, false, {error, _} = Failure} ->
            finalize_connect_result(Trace, Failure, TotalDeadline);
        {_, _, {ok, _} = Success} ->
            close_connect_result(Success),
            record_diagnostic(Trace, 6, 0, 0, 5),
            {error, 5};
        _ ->
            record_diagnostic(Trace, 6, 0, 0, 5),
            {error, 5}
    end.

-spec finalize_forced_connect(
    map(), forced | timeout, term(), integer()
) -> {error, integer()}.
finalize_forced_connect(Lifecycle, Join, Trace, TotalDeadline) ->
    Result = maps:get(result, Lifecycle),
    close_connect_result_if_present(Result),
    demonitor_connect_lifecycle(Lifecycle),
    Code = case {Join, Result, monotonic_millisecond() >= TotalDeadline} of
        {timeout, _, _} -> 5;
        {_, {error, 5}, _} -> 5;
        {_, _, true} -> 17;
        _ -> 5
    end,
    record_diagnostic(Trace, 6, 0, 0, Code),
    {error, Code}.

-spec connect_coordinator(
    pid(), reference(), pid(), reference(), binary(), inet:port_number(),
    pos_integer(), pos_integer(), pos_integer(), map(), term(), integer(),
    integer(), integer()
) -> ok.
connect_coordinator(
    Parent, ReplyAlias, Reaper, Reference, Host, Port, DnsTimeout,
    ConnectTimeout, SendTimeout, Runtime, Trace, Now, TotalDeadline,
    CleanupDeadline
) ->
    ok = proc_lib:set_label(<<"http.connect_coordinator">>),
    process_flag(trap_exit, true),
    OwnerMonitor = erlang:monitor(process, Parent),
    ReaperMonitor = erlang:monitor(process, Reaper),
    receive
        {
            RegistrationReference,
            http_transport_connect_start,
            Parent,
            Reaper
        } when is_reference(RegistrationReference) ->
            case monotonic_millisecond() < TotalDeadline
                andalso erlang:is_process_alive(Parent)
                andalso erlang:is_process_alive(Reaper)
            of
                true ->
                    State = #{
                        parent => Parent,
                        reply_alias => ReplyAlias,
                        owner_monitor => OwnerMonitor,
                        reaper => Reaper,
                        reaper_monitor => ReaperMonitor,
                        reference => Reference,
                        runtime => Runtime,
                        trace => Trace,
                        host => binary_to_list(Host),
                        port => Port,
                        send_timeout => SendTimeout,
                        total_deadline => TotalDeadline,
                        worker_cleanup_deadline => CleanupDeadline,
                        dns_deadline => erlang:min(
                            Now + DnsTimeout, TotalDeadline),
                        connect_timeout => ConnectTimeout,
                        connect_deadline => undefined,
                        dns_pending => #{},
                        answers => #{inet6 => [], inet => []},
                        attempted => [],
                        active => #{},
                        workers => #{},
                        next_launch => Now,
                        last_launch => undefined,
                        resolution_ready => undefined,
                        last_code => 5,
                        dns_timed_out => false
                    },
                    connect_loop(start_resolution(State));
                false ->
                    ReplyAlias ! {http_transport_dial, Reference, {error, 17}},
                    ok
            end;
        {'DOWN', OwnerMonitor, process, Parent, _Reason} ->
            ok;
        {'DOWN', ReaperMonitor, process, Reaper, _Reason} ->
            ok
    after remaining_milliseconds(TotalDeadline) ->
        ReplyAlias ! {http_transport_dial, Reference, {error, 17}},
        ok
    end.

-spec connect_reaper(pid(), reference(), reference(), integer()) -> ok.
connect_reaper(Caller, ReplyAlias, Reference, TerminationDeadline) ->
    ok = proc_lib:set_label(<<"http.connect_reaper">>),
    process_flag(trap_exit, true),
    CallerMonitor = erlang:monitor(process, Caller),
    connect_reaper_wait_for_coordinator(#{
        caller => Caller,
        caller_monitor => CallerMonitor,
        caller_down => false,
        reply_alias => ReplyAlias,
        reference => Reference,
        coordinator => none,
        coordinator_monitor => none,
        coordinator_down => true,
        workers => #{},
        termination_deadline => TerminationDeadline
    }).

-spec connect_reaper_wait_for_coordinator(map()) -> ok.
connect_reaper_wait_for_coordinator(
    State = #{
        caller := Caller,
        caller_monitor := CallerMonitor,
        reply_alias := ReplyAlias,
        reference := Reference,
        termination_deadline := TerminationDeadline
    }
) ->
    receive
        {Reference, http_transport_register_coordinator, Coordinator}
            when is_pid(Coordinator) ->
            CoordinatorMonitor = erlang:monitor(process, Coordinator),
            RegistrationReference = make_ref(),
            Registered = State#{
                coordinator => Coordinator,
                coordinator_monitor => CoordinatorMonitor,
                coordinator_down => false
            },
            case erlang:is_process_alive(Caller)
                andalso erlang:is_process_alive(Coordinator)
                andalso monotonic_millisecond() < TerminationDeadline
            of
                true ->
                    ReplyAlias ! {
                        Reference,
                        http_transport_coordinator_registered,
                        self(),
                        Coordinator,
                        RegistrationReference
                    },
                    connect_reaper_loop(Registered);
                false ->
                    connect_reaper_stop(Registered)
            end;
        {Reference, http_transport_force_reap, Caller} ->
            connect_reaper_seal(State, ok);
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            connect_reaper_seal(State#{caller_down => true}, ok)
    after remaining_milliseconds(TerminationDeadline) ->
        connect_reaper_seal(State, timeout)
    end.

-spec connect_reaper_loop(map()) -> ok.
connect_reaper_loop(
    State = #{
        caller := Caller,
        caller_monitor := CallerMonitor,
        reference := Reference,
        coordinator := Coordinator,
        coordinator_monitor := CoordinatorMonitor,
        workers := Workers,
        termination_deadline := TerminationDeadline
    }
) ->
    receive
        {
            Reference,
            http_transport_spawn_worker,
            Coordinator,
            Kind,
            RegistrationReference,
            Label,
            Deadline,
            Run,
            FailureMessage
        } when is_reference(RegistrationReference), is_binary(Label),
               is_integer(Deadline), is_function(Run, 0),
               is_function(FailureMessage, 0),
               (Kind =:= 1 orelse Kind =:= 2) ->
            connect_reaper_loop(connect_reaper_spawn_worker(
                Kind, RegistrationReference, Label, Deadline, Run,
                FailureMessage, State));
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            connect_reaper_stop(State#{caller_down => true});
        {'DOWN', CoordinatorMonitor, process, Coordinator, _Reason} ->
            connect_reaper_stop(State#{coordinator_down => true});
        {'DOWN', WorkerMonitor, process, _Worker, _Reason}
            when is_map_key(WorkerMonitor, Workers) ->
            connect_reaper_loop(
                State#{workers => maps:remove(WorkerMonitor, Workers)});
        {'EXIT', _Worker, _Reason} ->
            connect_reaper_loop(State);
        {Reference, http_transport_force_reap, Caller} ->
            connect_reaper_stop(State)
    after remaining_milliseconds(TerminationDeadline) ->
        connect_reaper_stop(State)
    end.

-spec connect_reaper_spawn_worker(
    1 | 2, reference(), binary(), integer(), fun(() -> term()),
    fun(() -> term()), map()
) -> map().
connect_reaper_spawn_worker(
    Kind,
    RegistrationReference,
    Label,
    Deadline,
    Run,
    FailureMessage,
    State = #{
        caller := Caller,
        reply_alias := ReplyAlias,
        reference := Reference,
        coordinator := Coordinator,
        workers := Workers
    }
) ->
    case map_size(Workers) < ?MAXIMUM_CONNECT_CALLBACKS
        andalso erlang:is_process_alive(Caller)
        andalso erlang:is_process_alive(Coordinator)
        andalso monotonic_millisecond() < Deadline
    of
        true ->
            Reaper = self(),
            WorkerRun = fun() ->
                connect_callback_worker(
                    Caller, Coordinator, Reaper, RegistrationReference,
                    Label, Deadline, Run, FailureMessage)
            end,
            try spawn_opt(WorkerRun, connect_callback_spawn_options()) of
                {Worker, WorkerMonitor}
                    when is_pid(Worker), is_reference(WorkerMonitor) ->
                    %% The persistent ledger stores only monitor and process
                    %% identities; callback closures are discarded here.
                    ReplyAlias ! {
                        Reference,
                        http_transport_worker_registered,
                        self(),
                        Worker,
                        Kind
                    },
                    Coordinator ! {
                        RegistrationReference,
                        http_transport_worker_spawned,
                        self(),
                        Worker
                    },
                    State#{
                        workers => maps:put(WorkerMonitor, Worker, Workers)
                    };
                _ ->
                    Coordinator ! {
                        RegistrationReference,
                        http_transport_worker_rejected,
                        self()
                    },
                    State
            catch
                _Class:_Reason ->
                    Coordinator ! {
                        RegistrationReference,
                        http_transport_worker_rejected,
                        self()
                    },
                    State
            end;
        false ->
            Coordinator ! {
                RegistrationReference,
                http_transport_worker_rejected,
                self()
            },
            State
    end.

-spec connect_reaper_stop(map()) -> ok.
connect_reaper_stop(State) ->
    Stopping = connect_reaper_kill(State),
    connect_reaper_await_down(Stopping).

-spec connect_reaper_kill(map()) -> map().
connect_reaper_kill(State = #{
    coordinator := Coordinator,
    coordinator_down := CoordinatorDown,
    workers := Workers
}) ->
    case CoordinatorDown of
        true -> ok;
        false -> exit(Coordinator, kill)
    end,
    maps:foreach(fun(_Monitor, Worker) -> exit(Worker, kill) end, Workers),
    State.

-spec connect_reaper_await_down(map()) -> ok.
connect_reaper_await_down(
    State = #{
        caller := Caller,
        caller_monitor := CallerMonitor,
        reference := Reference,
        coordinator := Coordinator,
        coordinator_monitor := CoordinatorMonitor,
        coordinator_down := CoordinatorDown,
        workers := Workers,
        termination_deadline := TerminationDeadline
    }
) ->
    case CoordinatorDown andalso map_size(Workers) =:= 0 of
        true ->
            connect_reaper_seal(State, ok);
        false ->
            receive
                {'DOWN', CallerMonitor, process, Caller, _Reason} ->
                    connect_reaper_await_down(State#{caller_down => true});
                {'DOWN', CoordinatorMonitor, process, Coordinator, _Reason} ->
                    connect_reaper_await_down(
                        State#{coordinator_down => true});
                {'DOWN', WorkerMonitor, process, _Worker, _Reason}
                    when is_map_key(WorkerMonitor, Workers) ->
                    connect_reaper_await_down(State#{
                        workers => maps:remove(WorkerMonitor, Workers)
                    });
                {
                    Reference,
                    http_transport_spawn_worker,
                    Coordinator,
                    _Kind,
                    RegistrationReference,
                    _Label,
                    _WorkerDeadline,
                    _Run,
                    _FailureMessage
                } when is_reference(RegistrationReference) ->
                    %% The coordinator is the sole request sender. Its DOWN
                    %% seals all earlier requests, and no callback is spawned
                    %% after shutdown begins.
                    Coordinator ! {
                        RegistrationReference,
                        http_transport_worker_rejected,
                        self()
                    },
                    connect_reaper_await_down(State);
                {'EXIT', _Worker, _Reason} ->
                    connect_reaper_await_down(State);
                {Reference, http_transport_force_reap, Caller} ->
                    connect_reaper_await_down(connect_reaper_kill(State))
            after remaining_milliseconds(TerminationDeadline) ->
                connect_reaper_seal(connect_reaper_kill(State), timeout)
            end
    end.

-spec connect_reaper_seal(map(), ok | timeout) -> ok.
connect_reaper_seal(
    #{
        caller_monitor := CallerMonitor,
        reply_alias := ReplyAlias,
        reference := Reference,
        coordinator_monitor := CoordinatorMonitor,
        workers := Workers
    },
    Status
) ->
    erlang:demonitor(CallerMonitor, [flush]),
    case CoordinatorMonitor of
        none -> ok;
        _ -> erlang:demonitor(CoordinatorMonitor, [flush])
    end,
    maps:foreach(fun(Monitor, _Worker) ->
        erlang:demonitor(Monitor, [flush])
    end, Workers),
    ReplyAlias ! {
        Reference,
        http_transport_reaper_sealed,
        self(),
        Status
    },
    ok.

-spec finalize_connect_result(term(), {ok, stream()} | {error, integer()},
    integer()) ->
    {ok, stream()} | {error, integer()}.
finalize_connect_result(Trace, Result = {ok, _}, TotalDeadline) ->
    case monotonic_millisecond() < TotalDeadline of
        true ->
            record_connect_completion(Trace, Result),
            Result;
        false ->
            close_connect_result(Result),
            record_diagnostic(Trace, 6, 0, 0, 17),
            {error, 17}
    end;
finalize_connect_result(Trace, Result = {error, _}, _TotalDeadline) ->
    record_connect_completion(Trace, Result),
    Result.

-spec close_connect_result({ok, stream()}) -> ok.
close_connect_result({ok, Stream}) ->
    _ = close(Stream),
    ok.

-spec close_connect_result_if_present(term()) -> ok.
close_connect_result_if_present({ok, _} = Result) ->
    close_connect_result(Result);
close_connect_result_if_present(_) -> ok.

-spec record_connect_completion(term(), {ok, stream()} | {error, integer()}) -> ok.
record_connect_completion(Trace, Result) ->
    Code = case Result of
        {ok, _} -> 0;
        {error, Failure} -> Failure
    end,
    record_diagnostic(Trace, 6, 0, 0, Code).

%% An internal runtime may carry a private lifecycle capability. Guardians are
%% recorded by the caller and callbacks by the coordinator before start. This
%% never enters transport diagnostics.
-spec observe_runtime_process(map(), 0 | 1 | 2 | 3, pid()) -> ok.
observe_runtime_process(Runtime, Kind, Pid) ->
    case maps:get(lifecycle_observer, Runtime, none) of
        {http_transport_lifecycle_observer, Table, Owner, Reference}
            when is_pid(Owner), is_reference(Reference) ->
            try
                _ = ets:insert(Table, {{http_transport_worker, Pid}, Kind}),
                Owner ! {http_transport_worker_observed, Reference},
                ok
            catch
                _:_ -> ok
            end;
        _ -> ok
    end.

-spec start_resolution(map()) -> map().
start_resolution(State = #{host := Host, trace := Trace}) ->
    case inet:parse_address(Host) of
        {ok, Address} ->
            Family = case tuple_size(Address) of
                4 -> inet;
                8 -> inet6
            end,
            record_diagnostic(Trace, 1, family_code(Family), 0, 0),
            record_diagnostic(Trace, 2, family_code(Family), 0, 0),
            State#{answers => maps:put(Family, [Address],
                maps:get(answers, State))};
        {error, _} ->
            start_resolver(inet, start_resolver(inet6, State))
    end.

-spec start_resolver(family(), map()) -> map().
start_resolver(Family, State = #{host := Host, reference := Ref,
    runtime := #{resolve := Resolve}, trace := Trace,
    dns_pending := Pending, dns_deadline := DnsDeadline}) ->
    record_diagnostic(Trace, 1, family_code(Family), 0, 0),
    Run = fun() ->
        Result = try Resolve(Host, Family) of
            {ok, Addresses} ->
                {ok, bounded_unique_addresses(Addresses, Family)};
            _ -> {error, 4}
        catch _:_ -> {error, 4}
        end,
        {resolved, Ref, self(), Family, Result}
    end,
    Failure = fun() ->
        {resolved, Ref, self(), Family, {error, 4}}
    end,
    case start_connect_callback_worker(
        1, <<"http.dns_resolver">>, DnsDeadline, Run, Failure, State
    ) of
        {ok, Pid, Started} ->
            Started#{dns_pending => maps:put(Family, Pid, Pending)};
        {error, Failed} ->
            record_diagnostic(Trace, 2, family_code(Family), 0, 4),
            Failed
    end.

-spec start_connect_callback_worker(
    1 | 2, binary(), integer(), fun(() -> term()), fun(() -> term()), map()
) -> {ok, pid(), map()} | {error, map()}.
start_connect_callback_worker(
    Kind,
    Label,
    Deadline,
    Run,
    FailureMessage,
    State = #{
        reaper := Reaper,
        reference := Reference
    }
) ->
    Coordinator = self(),
    RegistrationReference = make_ref(),
    Reaper ! {
        Reference,
        http_transport_spawn_worker,
        Coordinator,
        Kind,
        RegistrationReference,
        Label,
        Deadline,
        Run,
        FailureMessage
    },
    await_connect_worker_registration(
        Kind, RegistrationReference, Deadline, State).

-spec await_connect_worker_registration(
    1 | 2, reference(), integer(), map()
) -> {ok, pid(), map()} | {error, map()}.
await_connect_worker_registration(
    Kind,
    RegistrationReference,
    Deadline,
    State = #{
        parent := Caller,
        owner_monitor := CallerMonitor,
        reaper := Reaper,
        reaper_monitor := ReaperMonitor,
        workers := Workers
    }
) ->
    receive
        {
            RegistrationReference,
            http_transport_worker_spawned,
            Reaper,
            Worker
        } when is_pid(Worker) ->
            WorkerMonitor = erlang:monitor(process, Worker),
            erlang:link(Worker),
            observe_runtime_process(maps:get(runtime, State), Kind, Worker),
            Registered = State#{
                workers => maps:put(Worker, WorkerMonitor, Workers)
            },
            case monotonic_millisecond() < Deadline
                andalso erlang:is_process_alive(Caller)
                andalso erlang:is_process_alive(Reaper)
                andalso erlang:is_process_alive(Worker)
            of
                true ->
                    Worker ! {
                        RegistrationReference,
                        http_transport_worker_start,
                        self()
                    },
                    {ok, Worker, Registered};
                false ->
                    exit(Worker, kill),
                    {error, Registered}
            end;
        {
            RegistrationReference,
            http_transport_worker_rejected,
            Reaper
        } ->
            {error, State};
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            abort_connect_coordinator(State);
        {'DOWN', ReaperMonitor, process, Reaper, _Reason} ->
            abort_connect_coordinator(State);
        {'EXIT', _Worker, _Reason} ->
            await_connect_worker_registration(
                Kind, RegistrationReference, Deadline, State)
    after remaining_milliseconds(Deadline) ->
        {error, State}
    end.

-spec abort_connect_coordinator(map()) -> no_return().
abort_connect_coordinator(State) ->
    _ = cleanup_connect_workers(State),
    exit(normal).

-spec connect_callback_worker(
    pid(), pid(), pid(), reference(), binary(), integer(), fun(() -> term()),
    fun(() -> term())
) -> ok.
connect_callback_worker(
    Caller, Coordinator, Reaper, RegistrationReference, Label, Deadline,
    Run, FailureMessage
) ->
    process_flag(trap_exit, false),
    ok = proc_lib:set_label(Label),
    CallerMonitor = erlang:monitor(process, Caller),
    CoordinatorMonitor = erlang:monitor(process, Coordinator),
    ReaperMonitor = erlang:monitor(process, Reaper),
    receive
        {
            RegistrationReference,
            http_transport_worker_start,
            Coordinator
        } ->
            case monotonic_millisecond() < Deadline
                andalso erlang:is_process_alive(Caller)
                andalso erlang:is_process_alive(Coordinator)
                andalso erlang:is_process_alive(Reaper)
            of
                true ->
                    Message = try Run() of
                        CallbackMessage -> CallbackMessage
                    catch
                        _Class:_Reason -> FailureMessage()
                    end,
                    Coordinator ! Message,
                    ok;
                false ->
                    ok
            end;
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            ok;
        {'DOWN', CoordinatorMonitor, process, Coordinator, _Reason} ->
            ok;
        {'DOWN', ReaperMonitor, process, Reaper, _Reason} ->
            ok
    after remaining_milliseconds(Deadline) ->
        ok
    end.

-spec bounded_unique_addresses(term(), family()) -> [inet:ip_address()].
bounded_unique_addresses(Addresses, Family) ->
    bounded_unique_addresses(Addresses, Family, [], 0, 0).

-spec bounded_unique_addresses(term(), family(), [inet:ip_address()],
    non_neg_integer(), non_neg_integer()) -> [inet:ip_address()].
bounded_unique_addresses(
    _Addresses, _Family, Found, ?MAXIMUM_RESOLVED_ADDRESSES, _Inspected
) ->
    lists:reverse(Found);
bounded_unique_addresses(
    _Addresses, _Family, Found, _Count, ?MAXIMUM_RESOLVER_ROWS_INSPECTED
) ->
    lists:reverse(Found);
bounded_unique_addresses([], _Family, Found, _Count, _Inspected) ->
    lists:reverse(Found);
bounded_unique_addresses(
    [Address | Rest], Family, Found, Count, Inspected
) ->
    %% Capacity counts distinct usable candidates, never duplicate DNS rows.
    %% A separate finite inspection bound prevents duplicate-heavy or
    %% improper callback values from consuming unbounded CPU or memory.
    case valid_resolved_address(Address, Family) andalso not lists:member(Address, Found) of
        true -> bounded_unique_addresses(
            Rest, Family, [Address | Found], Count + 1, Inspected + 1);
        false -> bounded_unique_addresses(
            Rest, Family, Found, Count, Inspected + 1)
    end;
bounded_unique_addresses(_Improper, _Family, Found, _Count, _Inspected) ->
    lists:reverse(Found).

-spec valid_resolved_address(term(), family()) -> boolean().
valid_resolved_address(Address, inet) when is_tuple(Address),
    tuple_size(Address) =:= 4 ->
    lists:all(fun(N) -> is_integer(N) andalso N >= 0 andalso N =< 255 end,
        tuple_to_list(Address));
valid_resolved_address(Address, inet6) when is_tuple(Address),
    tuple_size(Address) =:= 8 ->
    lists:all(fun(N) -> is_integer(N) andalso N >= 0 andalso N =< 65535 end,
        tuple_to_list(Address));
valid_resolved_address(_, _) -> false.

-spec family_code(family()) -> 4 | 6.
family_code(inet) -> 4;
family_code(inet6) -> 6.

-spec connect_loop(map()) -> ok.
connect_loop(Initial) ->
    State = expire_resolution(Initial),
    Now = monotonic_millisecond(),
    Total = maps:get(total_deadline, State),
    Connect = maps:get(connect_deadline, State),
    case Now >= Total of
        true -> finish_connect(State, {error, 17});
        false when is_integer(Connect), Now >= Connect ->
            finish_connect(State, {error, timeout_code(Connect, Total, 2)});
        false -> connect_progress(State, Now)
    end.

-spec connect_progress(map(), integer()) -> ok.
connect_progress(State, Now) ->
    Candidates = remaining_candidates(State),
    Active = maps:get(active, State),
    Pending = maps:get(dns_pending, State),
    Attempted = maps:get(attempted, State),
    case {Candidates, map_size(Active), map_size(Pending)} of
        {[], 0, 0} -> finish_connect(State, {error, exhausted_code(State)});
        {[], 0, _} when length(Attempted) >= ?MAXIMUM_RESOLVED_ADDRESSES ->
            finish_connect(State, {error, maps:get(last_code, State)});
        {[Candidate | _], _, _} ->
            Ready = launch_ready(State, Now),
            case Now >= Ready of
                true -> connect_loop(start_candidate(Candidate, State, Now));
                false -> await_connect_event(State, erlang:min(Ready,
                    next_deadline(State)))
            end;
        {[], _, _} -> await_connect_event(State, next_deadline(State))
    end.

-spec exhausted_code(map()) -> integer().
exhausted_code(#{attempted := [], dns_timed_out := true,
    dns_deadline := Dns, total_deadline := Total}) ->
    timeout_code(Dns, Total, 16);
exhausted_code(#{attempted := []}) -> 4;
exhausted_code(#{last_code := Code}) -> Code.

-spec remaining_candidates(map()) -> [{family(), inet:ip_address()}].
remaining_candidates(#{answers := Answers, attempted := Attempted}) ->
    V6 = [{inet6, A} || A <- maps:get(inet6, Answers)],
    V4 = [{inet, A} || A <- maps:get(inet, Answers)],
    Ordered = interleave_candidates(V6, V4),
    lists:sublist([A || A <- Ordered, not lists:member(A, Attempted)],
        ?MAXIMUM_RESOLVED_ADDRESSES - length(Attempted)).

-spec interleave_candidates([term()], [term()]) -> [term()].
interleave_candidates([], Right) -> Right;
interleave_candidates(Left, []) -> Left;
interleave_candidates([Left | LeftRest], [Right | RightRest]) ->
    [Left, Right | interleave_candidates(LeftRest, RightRest)].

-spec launch_ready(map(), integer()) -> integer().
launch_ready(#{last_launch := undefined, answers := Answers,
    dns_pending := Pending, resolution_ready := Ready}, Now) ->
    case {maps:get(inet6, Answers), maps:is_key(inet6, Pending), Ready} of
        {[], true, At} when is_integer(At) -> At;
        _ -> Now
    end;
launch_ready(#{next_launch := Ready}, _Now) -> Ready.

-spec next_deadline(map()) -> integer().
next_deadline(#{dns_deadline := Dns, dns_pending := Pending,
    total_deadline := Total, connect_deadline := Connect}) ->
    WithDns = case map_size(Pending) > 0 of
        true -> erlang:min(Dns, Total);
        false -> Total
    end,
    case Connect of
        undefined -> WithDns;
        _ -> erlang:min(Connect, WithDns)
    end.

-spec expire_resolution(map()) -> map().
expire_resolution(State = #{dns_deadline := Dns, dns_pending := Pending,
    total_deadline := Total, trace := Trace}) ->
    case monotonic_millisecond() >= Dns andalso map_size(Pending) > 0 of
        false -> State;
        true ->
            maps:foreach(fun(Family, Pid) ->
                record_diagnostic(Trace, 2, family_code(Family), 0,
                    timeout_code(Dns, Total, 16)),
                exit(Pid, kill)
            end, Pending),
            State#{dns_pending => #{}, dns_timed_out => true}
    end.

-spec start_candidate({family(), inet:ip_address()}, map(), integer()) -> map().
start_candidate(Candidate = {Family, Address}, State = #{
    reference := Ref, runtime := #{connect := Dial},
    port := Port, send_timeout := SendTimeout, total_deadline := Total,
    connect_timeout := Timeout, connect_deadline := Previous,
    attempted := Attempted, active := Active,
    trace := Trace}, Now) ->
    Deadline = case Previous of
        undefined -> erlang:min(Now + Timeout, Total);
        _ -> Previous
    end,
    Coordinator = self(),
    Index = length(Attempted) + 1,
    record_diagnostic(Trace, 3, family_code(Family), Index, 0),
    Launching = State#{connect_deadline => Deadline, last_launch => Now,
        next_launch => Now + 250, attempted => Attempted ++ [Candidate],
        active => Active},
    Run = fun() ->
        Result = run_connect_candidate(
            Dial, Address, Port, Family, SendTimeout, Deadline, Coordinator),
        {candidate, Ref, self(), Result}
    end,
    Failure = fun() ->
        {candidate, Ref, self(), {error_code, 5}}
    end,
    case start_connect_callback_worker(
        2, <<"http.connect_candidate">>, Deadline, Run, Failure, Launching
    ) of
        {ok, Pid, Started} ->
            Started#{active => maps:put(Pid, {Index, Family}, Active)};
        {error, Failed} ->
            record_diagnostic(Trace, 4, family_code(Family), Index, 5),
            Failed#{last_code => 5,
                next_launch => erlang:max(Now + 100,
                    monotonic_millisecond())}
    end.

-spec run_connect_candidate(
    fun(), inet:ip_address(), inet:port_number(), family(), pos_integer(),
    integer(), pid()
) -> {ok, gen_tcp:socket()} | {error, timeout} | {error_code, integer()}.
run_connect_candidate(
    Dial, Address, Port, Family, SendTimeout, Deadline, Coordinator
) ->
    Result = try
        case remaining_milliseconds(Deadline) of
            0 -> {error, timeout};
            Remaining ->
                Dial(Address, Port, stream_options(Family, SendTimeout),
                    Remaining)
        end
    of
        {ok, DialSocket} -> {ok, DialSocket};
        {error, timeout} -> {error, timeout};
        {error, DialReason} -> {error_code, connect_error_code(DialReason)};
        _ -> {error_code, 5}
    catch
        _:_ -> {error_code, 5}
    end,
    case Result of
        {ok, Socket} ->
            try gen_tcp:controlling_process(Socket, Coordinator) of
                ok -> {ok, Socket};
                {error, Reason} ->
                    safe_close(Socket),
                    {error_code, connect_error_code(Reason)}
            catch
                _:_ ->
                    safe_close(Socket),
                    {error_code, 5}
            end;
        _ ->
            Result
    end.

-spec await_connect_event(map(), integer()) -> ok.
await_connect_event(State = #{reference := Ref, owner_monitor := OwnerMonitor,
    parent := Parent, reaper := Reaper, reaper_monitor := ReaperMonitor},
    Deadline) ->
    receive
        {resolved, Ref, Pid, Family, Result} ->
            connect_loop(resolved_candidate_family(Pid, Family, Result, State));
        {candidate, Ref, Pid, Result} ->
            candidate_finished(Pid, Result, State);
        {'DOWN', OwnerMonitor, process, Parent, _Reason} ->
            abort_connect_coordinator(State);
        {'DOWN', ReaperMonitor, process, Reaper, _Reason} ->
            abort_connect_coordinator(State);
        {'DOWN', Monitor, process, Pid, _Reason} ->
            connect_loop(connect_worker_down(Pid, Monitor, State));
        {'EXIT', _Pid, _Reason} ->
            connect_loop(State)
    after remaining_milliseconds(Deadline) ->
        connect_loop(State)
    end.

-spec resolved_candidate_family(pid(), family(), term(), map()) -> map().
resolved_candidate_family(Pid, Family, Result, State = #{
    dns_pending := Pending, answers := Answers, trace := Trace,
    resolution_ready := Ready, dns_deadline := Dns}) ->
    case maps:find(Family, Pending) of
        {ok, Pid} ->
            {Addresses, Code} = case Result of
                {ok, Values} when Values =/= [] -> {Values, 0};
                _ -> {[], 4}
            end,
            record_diagnostic(Trace, 2, family_code(Family), 0, Code),
            NextReady = case {Family, Addresses, Ready} of
                {inet, [_ | _], undefined} ->
                    erlang:min(monotonic_millisecond() + 50, Dns);
                _ -> Ready
            end,
            State#{answers => maps:put(Family, Addresses, Answers),
                dns_pending => maps:remove(Family, Pending),
                resolution_ready => NextReady};
        _ -> State
    end.

-spec candidate_finished(pid(), term(), map()) -> ok.
candidate_finished(Pid, Result, State = #{active := Active, trace := Trace,
    connect_deadline := Deadline, total_deadline := Total, last_launch := Last}) ->
    case maps:find(Pid, Active) of
        {ok, {Index, Family}} ->
            Next = State#{active => maps:remove(Pid, Active)},
            case Result of
                {ok, Socket} ->
                    record_diagnostic(Trace, 4, family_code(Family), Index, 0),
                    finish_connect(Next, {ok, Socket});
                {error, timeout} ->
                    Code = timeout_code(Deadline, Total, 2),
                    record_diagnostic(Trace, 4, family_code(Family), Index, Code),
                    connect_loop(Next#{last_code => Code,
                        next_launch => erlang:max(Last + 100,
                            monotonic_millisecond())});
                {error_code, Code}
                    when is_integer(Code), Code >= 1, Code =< 18 ->
                    record_diagnostic(Trace, 4, family_code(Family), Index, Code),
                    connect_loop(Next#{last_code => Code,
                        next_launch => erlang:max(Last + 100,
                            monotonic_millisecond())});
                _ ->
                    record_diagnostic(Trace, 4, family_code(Family), Index, 5),
                    connect_loop(Next#{last_code => 5,
                        next_launch => erlang:max(Last + 100,
                            monotonic_millisecond())})
            end;
        error -> connect_loop(State)
    end.

-spec connect_worker_down(pid(), reference(), map()) -> map().
connect_worker_down(Pid, Monitor, State = #{workers := Workers,
    dns_pending := Pending, active := Active}) ->
    case maps:find(Pid, Workers) of
        {ok, Monitor} ->
            Without = State#{workers => maps:remove(Pid, Workers)},
            case [Family || {Family, Worker} <- maps:to_list(Pending),
                Worker =:= Pid] of
                [Family] -> resolved_candidate_family(Pid, Family,
                    {error, 4}, Without);
                [] ->
                    case maps:find(Pid, Active) of
                        error -> Without;
                        {ok, {Index, Family}} ->
                            record_diagnostic(maps:get(trace, State), 4,
                                family_code(Family), Index, 5),
                            Without#{active => maps:remove(Pid, Active),
                                last_code => 5,
                                next_launch => erlang:max(
                                    maps:get(last_launch, State) + 100,
                                    monotonic_millisecond())}
                    end
            end;
        _ -> State
    end.

-spec finish_connect(map(), {ok, gen_tcp:socket()} | {error, integer()}) -> ok.
finish_connect(State = #{parent := Parent, reply_alias := ReplyAlias,
    reference := Ref,
    runtime := Runtime, trace := Trace, connect_deadline := Connect,
    total_deadline := Total},
    Result) ->
    Cleanup = cleanup_connect_workers(State),
    Final = case {Cleanup, Result} of
        {timeout, {ok, Socket}} ->
            safe_close(Socket),
            {error, 5};
        {timeout, {error, _}} -> {error, 5};
        {ok, {ok, Socket}} ->
            record_diagnostic(Trace, 5, 0, 0, 0),
            Deadline = case Connect of
                undefined -> Total;
                _ -> Connect
            end,
            case remaining_milliseconds(Deadline) of
                0 ->
                    safe_close(Socket),
                    {error, timeout_code(Deadline, Total, 2)};
                _ ->
                    connect_socket_handoff(
                        State, Runtime, Socket, Parent, Ref, Deadline, Trace
                    )
            end;
        {ok, {error, _}} -> Result
    end,
    ReplyAlias ! {http_transport_dial, Ref, Final},
    ok.

-spec connect_socket_handoff(
    map(), map(), gen_tcp:socket(), pid(), reference(), integer(), term()
) -> {ok, stream()} | {error, integer()}.
connect_socket_handoff(
    State, Runtime, Socket, Parent, Reference, Deadline, Trace
) ->
    HandoffReference = make_ref(),
    OwnerMonitor = maps:get(owner_monitor, State),
    ReaperMonitor = maps:get(reaper_monitor, State),
    ReplyAlias = maps:get(reply_alias, State),
    ReplyAlias ! {
        Reference,
        http_transport_socket_handoff,
        self(),
        Socket,
        HandoffReference
    },
    receive
        {
            HandoffReference,
            http_transport_socket_handoff_ready,
            Parent
        } ->
            case remaining_milliseconds(Deadline) of
                0 ->
                    safe_close(Socket),
                    {error, timeout_code(
                        Deadline, maps:get(total_deadline, State), 2
                    )};
                _ ->
                    connect_socket_transfer(
                        Runtime, Socket, Parent, Deadline, Trace,
                        maps:get(total_deadline, State)
                    )
            end;
        {'DOWN', OwnerMonitor, process, Parent, _Reason} ->
            safe_close(Socket),
            {error, 5};
        {'DOWN', ReaperMonitor, process, _Reaper, _Reason} ->
            safe_close(Socket),
            {error, 5}
    after remaining_milliseconds(Deadline) ->
        safe_close(Socket),
        {error, timeout_code(
            Deadline, maps:get(total_deadline, State), 2
        )}
    end.

-spec connect_socket_transfer(
    map(), gen_tcp:socket(), pid(), integer(), term(), integer()
) -> {ok, stream()} | {error, integer()}.
connect_socket_transfer(
    Runtime, Socket, Parent, Deadline, Trace, TotalDeadline
) ->
    case gen_tcp:controlling_process(Socket, Parent) of
        ok ->
            case connect_post_transfer_probe(Runtime, Deadline) of
                continue ->
                    Stream = stream(Socket),
                    case Trace of
                        none -> {ok, Stream};
                        _ -> {ok, Stream#{diagnostics => Trace}}
                    end;
                stop ->
                    safe_close(Socket),
                    {error, timeout_code(Deadline, TotalDeadline, 2)}
            end;
        {error, Reason} ->
            safe_close(Socket),
            {error, owner_error_code(Reason)}
    end.

%% This private synchronization point contains process identities and
%% references only. It lets lifecycle tests stop the coordinator after the
%% ownership transfer while the caller still treats the socket as provisional.
-spec connect_post_transfer_probe(map(), integer()) ->
    continue | stop.
connect_post_transfer_probe(Runtime, Deadline) ->
    case maps:get(handoff_probe, Runtime, none) of
        {http_transport_handoff_probe, Observer, ProbeReference}
            when is_pid(Observer), is_reference(ProbeReference) ->
            Observer ! {
                http_transport_connect_post_transfer,
                ProbeReference,
                self()
            },
            receive
                {
                    http_transport_continue_post_transfer,
                    ProbeReference
                } ->
                    case remaining_milliseconds(Deadline) of
                        0 -> stop;
                        _ -> continue
                    end
            after remaining_milliseconds(Deadline) ->
                stop
            end;
        _ ->
            continue
    end.

-spec cleanup_connect_workers(map()) -> ok | timeout.
cleanup_connect_workers(#{workers := Workers, active := Active,
    dns_pending := Pending, trace := Trace,
    worker_cleanup_deadline := CleanupDeadline}) ->
    maps:foreach(fun(_Pid, {Index, Family}) ->
        record_diagnostic(Trace, 4, family_code(Family), Index, 18)
    end, Active),
    maps:foreach(fun(Family, _Pid) ->
        record_diagnostic(Trace, 2, family_code(Family), 0, 18)
    end, Pending),
    maps:foreach(fun(Pid, _Monitor) -> exit(Pid, kill) end, Workers),
    PendingMonitors = await_connect_workers(Workers, CleanupDeadline),
    maps:foreach(fun(_Pid, Monitor) ->
        erlang:demonitor(Monitor, [flush])
    end, PendingMonitors),
    case map_size(PendingMonitors) of
        0 -> ok;
        _ -> timeout
    end.

-spec await_connect_workers(#{pid() => reference()}, integer()) ->
    #{pid() => reference()}.
await_connect_workers(Workers, _Deadline) when map_size(Workers) =:= 0 -> #{};
await_connect_workers(Workers, Deadline) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} ->
            case maps:find(Pid, Workers) of
                {ok, Monitor} ->
                    await_connect_workers(maps:remove(Pid, Workers), Deadline);
                _ -> await_connect_workers(Workers, Deadline)
            end
    after remaining_milliseconds(Deadline) -> Workers
    end.

-spec resolve_host(string()) ->
    {ok, [{family(), inet:ip_address()}]} | {error, term()}.
resolve_host(Host) ->
    %% RFC 8305 section 3: both queries are issued together rather than one
    %% after the other, so neither family waits on the other's answer, and the
    %% second answer is waited for only until the Resolution Delay expires. A
    %% name that has no AAAA record therefore costs that delay rather than a
    %% full lookup, and one whose AAAA answer is slow is not held behind it.
    {V6, V4} = resolved_families(Host),
    %% Each family is cut to the ceiling before sorting, so the number of source
    %% probes is bounded by twice it however many addresses the name carries,
    %% and the ordered list is cut again afterwards.
    Candidates = lists:sublist(V6, ?MAXIMUM_RESOLVED_ADDRESSES)
        ++ lists:sublist(V4, ?MAXIMUM_RESOLVED_ADDRESSES),
    Sorted = sort_destinations(Candidates, fun connected_source/2),
    Addresses = lists:sublist(
        interleave_families(Sorted), ?MAXIMUM_RESOLVED_ADDRESSES
    ),
    case Addresses of
        [] -> {error, nxdomain};
        _ -> {ok, Addresses}
    end.

%% Ask for both families at once and return what answered, waiting for the
%% second answer only until the Resolution Delay runs out.
-spec resolved_families(string()) ->
    {[{family(), inet:ip_address()}], [{family(), inet:ip_address()}]}.
resolved_families(Host) ->
    Answers = resolve_families([
        {inet6, fun() -> resolved_family(Host, inet6) end},
        {inet, fun() -> resolved_family(Host, inet) end}
    ]),
    {maps:get(inet6, Answers, []), maps:get(inet, Answers, [])}.

%% Run every query at once and return the answers that arrived, keyed by family.
%%
%% RFC 8305 section 3 asks for the queries to be issued as close together as
%% possible and for resolution to be asynchronous, and it bounds the wait for a
%% straggler by the Resolution Delay rather than by the whole lookup: the first
%% answer starts that clock, and whatever has not arrived when it runs out is
%% left out. A query that dies without answering counts as answering nothing, so
%% one broken family never holds the other.
-spec resolve_families([{family(), fun(() -> term())}]) -> map().
resolve_families(Queries) ->
    Parent = self(),
    Reference = make_ref(),
    Pending = maps:from_list([
        spawn_monitor(fun() -> Parent ! {Reference, self(), Family, Query()} end)
     || {Family, Query} <- Queries
    ]),
    Answers = collect_family_answers(Reference, Pending, #{}, infinity),
    %% RFC 8305 section 5: a query whose answer came too late to be used is left
    %% to finish rather than killed, because the answer still populates the
    %% platform's resolver cache and a later connection can use it. Only the
    %% monitor is dropped, and a late answer is flushed from the mailbox.
    maps:foreach(
        fun(_Worker, Monitor) -> erlang:demonitor(Monitor, [flush]) end,
        Pending
    ),
    flush_family_answers(Reference),
    Answers.

-spec collect_family_answers(reference(), map(), map(), timeout()) -> map().
collect_family_answers(Reference, Pending, Answers, Timeout) ->
    case map_size(Pending) of
        0 -> Answers;
        _ ->
            receive
                {Reference, Worker, Family, Addresses}
                    when is_map_key(Worker, Pending) ->
                    Next = case map_size(Answers) of
                        0 -> ?RESOLUTION_DELAY;
                        _ -> Timeout
                    end,
                    collect_family_answers(
                        Reference,
                        maps:remove(Worker, Pending),
                        Answers#{Family => Addresses},
                        Next
                    );
                {'DOWN', Monitor, process, Worker, _Reason}
                    when is_map_key(Worker, Pending) ->
                    case maps:get(Worker, Pending) of
                        Monitor ->
                            collect_family_answers(
                                Reference,
                                maps:remove(Worker, Pending),
                                Answers,
                                Timeout
                            );
                        _Other ->
                            collect_family_answers(
                                Reference, Pending, Answers, Timeout
                            )
                    end
            after Timeout ->
                Answers
            end
    end.

-spec flush_family_answers(reference()) -> ok.
flush_family_answers(Reference) ->
    receive
        {Reference, _Worker, _Family, _Addresses} ->
            flush_family_answers(Reference)
    after 0 ->
        ok
    end.

-spec resolved_family(string(), family()) ->
    [{family(), inet:ip_address()}].
resolved_family(Host, Family) ->
    case inet:getaddrs(Host, Family) of
        {ok, Addresses} -> [{Family, Address} || Address <- Addresses];
        {error, _Reason} -> []
    end.

%% RFC 8305 section 4 and RFC 6724 section 6: order the resolved addresses
%% before any of them is attempted.
%%
%% The source address for each destination is the one the kernel would choose,
%% asked for by connecting an unbound datagram socket and reading back the local
%% end. Nothing is sent, so the probe costs a bind and a route lookup. Delegating
%% that is deliberate: RFC 6724 section 5 source selection needs the interface
%% addresses, their lifetimes, and which are deprecated or temporary, and the
%% kernel has all of it. Rule 3, avoid deprecated source addresses, follows from
%% delegating rather than from a rule here, because a kernel that offers a
%% deprecated source is one that has no other.
%%
%% Rule 4, prefer home addresses, has no subject: Mobile IPv6 home and care-of
%% addresses are not a distinction the platform exposes or this package makes.
-spec sort_destinations(
    [{family(), inet:ip_address()}],
    fun((family(), inet:ip_address()) -> {ok, inet:ip_address()} | error)
) -> [{family(), inet:ip_address()}].
sort_destinations(Destinations, Source) ->
    Ranked = [
        {rank(Destination, Source), Index, Destination}
     || {Index, Destination} <- lists:enumerate(Destinations)
    ],
    %% Rule 10 leaves the order unchanged, which the original index carries.
    [Destination || {_Rank, _Index, Destination} <- lists:sort(Ranked)].

%% Every rule but rule 9 compares one destination against the other through a
%% value that depends on that destination alone, so the whole comparison is a
%% sort key. Rule 9 is written for two destinations of one family, and under the
%% default policy table two destinations of different families never reach it:
%% rule 6 separates them first, because no IPv6 prefix in the table carries the
%% precedence the IPv4-mapped prefix does.
-spec rank({family(), inet:ip_address()}, fun()) -> tuple().
rank({Family, Address}, Source) ->
    Destination = mapped_bytes(Family, Address),
    {DestinationPrecedence, DestinationLabel} = address_policy(Destination),
    DestinationScope = address_scope(Destination),
    case Source(Family, Address) of
        error ->
            %% Rule 1: a destination with no source address sorts last, and
            %% nothing after rule 1 can bring it back.
            {1, 0, 0, 0, 0, 0, 0};
        {ok, Chosen} ->
            Selected = mapped_bytes(Family, Chosen),
            {_SourcePrecedence, SourceLabel} = address_policy(Selected),
            {
                0,
                %% Rule 2: prefer a source whose scope matches.
                case address_scope(Selected) =:= DestinationScope of
                    true -> 0;
                    false -> 1
                end,
                %% Rule 5: prefer a source whose label matches.
                case SourceLabel =:= DestinationLabel of
                    true -> 0;
                    false -> 1
                end,
                %% Rule 6: prefer higher precedence.
                -DestinationPrecedence,
                %% Rule 7: prefer native transport over an encapsulating one.
                case encapsulating_prefix(Selected) of
                    true -> 1;
                    false -> 0
                end,
                %% Rule 8: prefer smaller scope.
                DestinationScope,
                %% Rule 9: prefer the longer common prefix.
                -common_prefix_length(Selected, Destination)
            }
    end.

%% RFC 8305 section 4: whichever family leads the sorted list is followed by one
%% address of the other, and so on, so a family whose connectivity is impaired
%% costs one attempt rather than a run of them. The First Address Family Count
%% is one here.
-spec interleave_families([{family(), inet:ip_address()}]) ->
    [{family(), inet:ip_address()}].
interleave_families([]) ->
    [];
interleave_families([{Family, _} = First | Rest]) ->
    {Same, Other} = lists:partition(
        fun({Candidate, _}) -> Candidate =:= Family end, Rest
    ),
    [First | alternate(Other, Same)].

-spec alternate([term()], [term()]) -> [term()].
alternate([], Rest) -> Rest;
alternate(Rest, []) -> Rest;
alternate([Next | Rest], Other) -> [Next | alternate(Other, Rest)].

%% RFC 6724 section 3.2: an IPv4 address is looked up as the IPv4-mapped IPv6
%% address, so one comparison covers both families.
-spec mapped_bytes(family(), inet:ip_address()) -> binary().
mapped_bytes(inet, {A, B, C, D}) ->
    <<0:80, 16#ffff:16, A, B, C, D>>;
mapped_bytes(inet6, {A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%% RFC 6724 section 2.1, the default policy table, read longest prefix first.
-spec address_policy(binary()) -> {integer(), integer()}.
address_policy(Address) ->
    Table = [
        {128, <<0:127, 1:1>>, 50, 0},
        {96, <<0:80, 16#ffff:16>>, 35, 4},
        {96, <<0:96>>, 1, 3},
        {32, <<16#2001:16, 0:16>>, 5, 5},
        {16, <<16#2002:16>>, 30, 2},
        {16, <<16#3ffe:16>>, 1, 12},
        {10, <<16#fec0:16>>, 1, 11},
        {7, <<16#fc00:16>>, 3, 13},
        {0, <<>>, 40, 1}
    ],
    policy_row(Table, Address).

-spec policy_row([{non_neg_integer(), binary(), integer(), integer()}], binary()) ->
    {integer(), integer()}.
policy_row([{Length, Prefix, Precedence, Label} | Rest], Address) ->
    case prefix_matches(Length, Prefix, Address) of
        true -> {Precedence, Label};
        false -> policy_row(Rest, Address)
    end;
policy_row([], _Address) ->
    {40, 1}.

-spec prefix_matches(non_neg_integer(), binary(), binary()) -> boolean().
prefix_matches(0, _Prefix, _Address) ->
    true;
prefix_matches(Length, Prefix, Address) ->
    <<Wanted:Length/bits, _/bits>> = <<Prefix/binary, 0:128>>,
    <<Actual:Length/bits, _/bits>> = Address,
    Wanted =:= Actual.

%% RFC 6724 section 3.1: a multicast address carries its scope, a unicast one is
%% mapped onto the same ladder, and RFC 6724 section 3.2 gives the two IPv4
%% prefixes that are link-local while every other IPv4 address is global.
-spec address_scope(binary()) -> non_neg_integer().
address_scope(<<16#ff, _:4, Scope:4, _/binary>>) ->
    Scope;
address_scope(<<0:127, 1:1>>) ->
    2;
address_scope(<<16#fe, Top:2, _:6, _/binary>>) when Top =:= 2#10 ->
    2;
address_scope(<<16#fe, Top:2, _:6, _/binary>>) when Top =:= 2#11 ->
    5;
address_scope(<<0:80, 16#ffff:16, 169, 254, _, _>>) ->
    2;
address_scope(<<0:80, 16#ffff:16, 127, _, _, _>>) ->
    2;
address_scope(_Address) ->
    14.

%% RFC 6724 section 6 rule 7: 6to4 and Teredo are the encapsulating transition
%% mechanisms whose source address says so from its prefix alone. A configured
%% tunnel cannot be told apart from a native interface here, which the rule's
%% own discussion allows for.
-spec encapsulating_prefix(binary()) -> boolean().
encapsulating_prefix(Address) ->
    prefix_matches(16, <<16#2002:16>>, Address) orelse
        prefix_matches(32, <<16#2001:16, 0:16>>, Address).

%% RFC 6724 section 2.2: the longest common leading prefix, capped at the length
%% of the source's own prefix, which is why CommonPrefixLen(fe80::1, fe80::2) is
%% 64 rather than 127.
-spec common_prefix_length(binary(), binary()) -> non_neg_integer().
common_prefix_length(Source, Destination) ->
    common_bits(Source, Destination, 0).

-spec common_bits(binary(), binary(), non_neg_integer()) -> non_neg_integer().
common_bits(_Source, _Destination, 64) ->
    64;
common_bits(<<Bit:1, Source/bits>>, <<Bit:1, Destination/bits>>, Count) ->
    common_bits(Source, Destination, Count + 1);
common_bits(_Source, _Destination, Count) ->
    Count.

%% The source address the kernel would use for this destination. The socket is
%% connected and never written to, so no packet leaves the host.
-spec connected_source(family(), inet:ip_address()) ->
    {ok, inet:ip_address()} | error.
connected_source(Family, Address) ->
    case gen_udp:open(0, [Family, binary, {active, false}]) of
        {ok, Socket} ->
            Source = probed_source(Socket, Address),
            _ = gen_udp:close(Socket),
            Source;
        {error, _Reason} ->
            error
    end.

-spec probed_source(gen_udp:socket(), inet:ip_address()) ->
    {ok, inet:ip_address()} | error.
probed_source(Socket, Address) ->
    case gen_udp:connect(Socket, Address, ?SOURCE_PROBE_PORT) of
        ok ->
            case inet:sockname(Socket) of
                {ok, {Source, _Port}} -> {ok, Source};
                {error, _Reason} -> error
            end;
        {error, _Reason} ->
            error
    end.

-spec timeout_code(integer(), integer(), integer()) -> integer().
timeout_code(Deadline, TotalDeadline, _PhaseCode)
    when Deadline =:= TotalDeadline ->
    17;
timeout_code(_Deadline, _TotalDeadline, PhaseCode) ->
    PhaseCode.

-spec remaining_milliseconds(integer()) -> non_neg_integer().
remaining_milliseconds(Deadline) ->
    case Deadline - erlang:monotonic_time(millisecond) of
        Remaining when Remaining > 0 -> Remaining;
        _ -> 0
    end.

-spec stream(gen_tcp:socket()) -> stream().
stream(Socket) ->
    #{kind => tcp, socket => Socket, buffered => <<>>}.

-spec tls_stream(ssl:sslsocket()) -> stream().
tls_stream(Socket) ->
    #{kind => tls, socket => Socket, buffered => <<>>}.

-spec tls_ready(ssl:sslsocket()) ->
    {ok, {stream(), binary(), 12 | 13}} | {error, integer()}.
tls_ready(Socket) ->
    case tls_version(Socket) of
        {ok, Version} ->
            case ssl:negotiated_protocol(Socket) of
                {ok, Protocol} when is_binary(Protocol) ->
                    {ok, {tls_stream(Socket), Protocol, Version}};
                {error, protocol_not_negotiated} ->
                    {ok, {tls_stream(Socket), <<>>, Version}};
                {error, _Reason} ->
                    _ = safe_close_stream(tls, Socket),
                    {error, 15}
            end;
        {error, _Reason} ->
            _ = safe_close_stream(tls, Socket),
            {error, 13}
    end.

-spec tls_version(ssl:sslsocket()) -> {ok, 12 | 13} | {error, term()}.
tls_version(Socket) ->
    case ssl:connection_information(Socket, [protocol]) of
        {ok, [{protocol, 'tlsv1.3'}]} -> {ok, 13};
        {ok, [{protocol, 'tlsv1.2'}]} -> {ok, 12};
        {ok, Information} -> {error, {unexpected_tls_version, Information}};
        {error, Reason} -> {error, Reason}
    end.

-spec client_tls_options(binary(), [binary()], [binary()]) -> list().
client_tls_options(ServerName, TrustedCertificates, AlpnProtocols) ->
    [
        %% Native alert reports can contain the requested name and certificate
        %% SANs. The transport's bounded typed diagnostics carry their outcome.
        {log_level, none},
        {verify, verify_peer},
        {cacerts, TrustedCertificates},
        {server_name_indication, binary_to_list(ServerName)},
        {customize_hostname_check, [
            {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
        ]},
        {versions, ['tlsv1.3', 'tlsv1.2']},
        {ciphers, forward_secret_cipher_suites()},
        {alpn_advertised_protocols, AlpnProtocols},
        {depth, 10},
        {active, false},
        binary
    ].

-spec server_tls_options(map(), [binary()]) -> list().
server_tls_options(CertsKeys, AlpnProtocols) ->
    [
        {log_level, none},
        {certs_keys, [CertsKeys]},
        {verify, verify_none},
        {versions, ['tlsv1.3', 'tlsv1.2']},
        {ciphers, forward_secret_cipher_suites()},
        {alpn_preferred_protocols, AlpnProtocols},
        {honor_cipher_order, true},
        {reuse_sessions, false},
        {active, false},
        binary
    ].

%% RFC 9325 sections 4.1 and 4.2: a cipher suite built on non-ephemeral
%% Diffie-Hellman, finite-field or elliptic curve, is not to be negotiated, the
%% ephemeral finite-field suites are not to be negotiated by a TLS 1.2 peer
%% either, and forward secrecy is to be supported and preferred. The platform's
%% default TLS 1.2 list carries static ECDH and TLS_DHE_* suites, so the list is
%% pinned here rather than inherited. A CBC suite needs the encrypt_then_mac
%% extension to be safe under section 4.2, which is simpler to satisfy by
%% carrying no suite that needs it: only AEAD survives. TLS 1.3 spells its own
%% always-ephemeral key schedule `any`.
-spec forward_secret_cipher_suites() -> [ssl:erl_cipher_suite()].
forward_secret_cipher_suites() ->
    Filters = [
        {key_exchange, fun(KeyExchange) ->
            lists:member(KeyExchange, [any, ecdhe_ecdsa, ecdhe_rsa])
        end},
        {mac, fun(Mac) -> Mac =:= aead end}
    ],
    Offered =
        ssl:cipher_suites(default, 'tlsv1.3') ++
            ssl:cipher_suites(default, 'tlsv1.2'),
    distinct_cipher_suites(ssl:filter_cipher_suites(Offered, Filters), []).

%% The two version lists overlap, and preference is the list order, so the
%% first occurrence of a suite is the one that is kept.
-spec distinct_cipher_suites(
    [ssl:erl_cipher_suite()], [ssl:erl_cipher_suite()]
) -> [ssl:erl_cipher_suite()].
distinct_cipher_suites([], Seen) ->
    lists:reverse(Seen);
distinct_cipher_suites([Suite | Rest], Seen) ->
    case lists:member(Suite, Seen) of
        true -> distinct_cipher_suites(Rest, Seen);
        false -> distinct_cipher_suites(Rest, [Suite | Seen])
    end.

-spec valid_server_name(binary()) -> boolean().
valid_server_name(ServerName) ->
    byte_size(ServerName) > 0 andalso
        byte_size(ServerName) =< 253 andalso
        binary:match(ServerName, <<0>>) =:= nomatch.

-spec valid_alpn_protocols([term()]) -> boolean().
valid_alpn_protocols([]) ->
    false;
valid_alpn_protocols(Protocols) ->
    lists:all(
        fun(Protocol) ->
            is_binary(Protocol) andalso
                byte_size(Protocol) > 0 andalso
                byte_size(Protocol) =< 255
        end,
        Protocols
    ).

-spec trusted_certificates([binary()]) ->
    {ok, [binary()]} | {error, term()}.
trusted_certificates([]) ->
    try public_key:cacerts_get() of
        Certificates when is_list(Certificates), Certificates =/= [] ->
            {ok, Certificates};
        _ ->
            {error, no_system_trust}
    catch
        _Class:Reason -> {error, Reason}
    end;
trusted_certificates(Certificates) ->
    case lists:all(fun valid_der_certificate/1, Certificates) of
        true -> {ok, Certificates};
        false -> {error, invalid_ca_certificate}
    end.

-spec valid_der_certificate(term()) -> boolean().
valid_der_certificate(Certificate) when is_binary(Certificate) ->
    try public_key:pkix_decode_cert(Certificate, otp) of
        _Decoded -> true
    catch
        _Class:_Reason -> false
    end;
valid_der_certificate(_Certificate) ->
    false.

-spec server_credentials(binary(), binary()) ->
    {ok, map()} | {error, term()}.
server_credentials(CertificatePem, PrivateKeyPem) ->
    try
        CertificateEntries = public_key:pem_decode(CertificatePem),
        PrivateKeyEntries = public_key:pem_decode(PrivateKeyPem),
        Certificates = [
            Der
         || {'Certificate', Der, _Encryption} <- CertificateEntries,
            is_binary(Der)
        ],
        case {Certificates, first_private_key(PrivateKeyEntries)} of
            {[_ | _], {ok, Key}} ->
                {ok, #{cert => Certificates, key => Key}};
            _ ->
                {error, invalid_credentials}
        end
    catch
        _Class:Reason -> {error, Reason}
    end.

-spec first_private_key([term()]) ->
    {ok, {atom(), binary()}} | {error, invalid_private_key}.
first_private_key([]) ->
    {error, invalid_private_key};
first_private_key([{Type, Der, _Encryption} | _Rest])
    when is_binary(Der),
         (Type =:= 'PrivateKeyInfo' orelse
             Type =:= 'ECPrivateKey' orelse
             Type =:= 'RSAPrivateKey' orelse
             Type =:= 'DSAPrivateKey') ->
    {ok, {Type, Der}};
first_private_key([_Entry | Rest]) ->
    first_private_key(Rest).

-spec configure_stream(gen_tcp:socket(), pos_integer()) ->
    ok | {error, term()}.
configure_stream(Socket, SendTimeout) ->
    inet:setopts(Socket, [
        {active, false},
        {nodelay, true},
        {keepalive, true},
        {send_timeout, SendTimeout},
        {send_timeout_close, true}
    ]).

-spec listener_options(
    family(),
    inet:ip_address(),
    pos_integer(),
    pos_integer()
) -> list().
listener_options(Family, Address, Backlog, SendTimeout) ->
    family_options(Family) ++ [
        binary,
        {packet, raw},
        {active, false},
        {ip, Address},
        {reuseaddr, true},
        {backlog, Backlog},
        {nodelay, true},
        {keepalive, true},
        {send_timeout, SendTimeout},
        {send_timeout_close, true}
    ].

-spec stream_options(family(), pos_integer()) -> list().
stream_options(Family, SendTimeout) ->
    family_options(Family) ++ [
        binary,
        {packet, raw},
        {active, false},
        {nodelay, true},
        {keepalive, true},
        {send_timeout, SendTimeout},
        {send_timeout_close, true}
    ].

-spec family_options(family()) -> [inet | inet6].
family_options(inet) -> [inet];
family_options(inet6) -> [inet6].

-spec decode_address(binary()) ->
    {ok, inet:ip_address(), family()} | error.
decode_address(<<A, B, C, D>>) ->
    {ok, {A, B, C, D}, inet};
decode_address(
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>
) ->
    {ok, {A, B, C, D, E, F, G, H}, inet6};
decode_address(_Address) ->
    error.

-spec encode_address(inet:ip_address()) -> {ok, binary()} | error.
encode_address({A, B, C, D}) ->
    {ok, <<A, B, C, D>>};
encode_address({A, B, C, D, E, F, G, H}) ->
    {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
encode_address(_Address) ->
    error.

-spec socket_error_code(term()) -> integer().
socket_error_code(timeout) -> 2;
socket_error_code(closed) -> 3;
socket_error_code(einval) -> 3;
socket_error_code(enotconn) -> 3;
socket_error_code(eacces) -> 8;
socket_error_code(eperm) -> 8;
socket_error_code(eaddrinuse) -> 9;
socket_error_code(eaddrnotavail) -> 10;
socket_error_code(not_owner) -> 11;
socket_error_code(_) -> 12.

-spec connect_error_code(term()) -> integer().
connect_error_code(timeout) -> 2;
connect_error_code(eacces) -> 8;
connect_error_code(eperm) -> 8;
connect_error_code(eaddrnotavail) -> 10;
connect_error_code(_) -> 5.

-spec read_error_code(term()) -> integer().
read_error_code(closed) -> 3;
read_error_code(einval) -> 3;
read_error_code(enotconn) -> 3;
read_error_code(eacces) -> 8;
read_error_code(eperm) -> 8;
read_error_code(not_owner) -> 11;
read_error_code(_) -> 6.

-spec write_error_code(term()) -> integer().
write_error_code(closed) -> 3;
write_error_code(einval) -> 3;
write_error_code(enotconn) -> 3;
write_error_code(timeout) -> 2;
write_error_code(eacces) -> 8;
write_error_code(eperm) -> 8;
write_error_code(not_owner) -> 11;
write_error_code(_) -> 7.

-spec owner_error_code(term()) -> integer().
owner_error_code(closed) -> 3;
owner_error_code(einval) -> 3;
owner_error_code(eacces) -> 8;
owner_error_code(eperm) -> 8;
owner_error_code(not_owner) -> 11;
owner_error_code(_) -> 11.

-spec tls_error_code(term()) -> integer().
tls_error_code(timeout) -> 2;
tls_error_code(Reason) ->
    case contains_reason(Reason, [
        no_application_protocol,
        unsupported_extension
    ]) of
        true -> 15;
        false ->
            case
                contains_reason(Reason, certificate_reasons())
                    orelse contains_reason_text(Reason, certificate_reasons())
            of
                true -> 14;
                false -> 13
            end
    end.

-spec certificate_reasons() -> [atom()].
certificate_reasons() ->
    [
        bad_cert,
        bad_certificate,
        certificate_expired,
        certificate_revoked,
        certificate_unknown,
        hostname_check_failed,
        invalid_issuer,
        invalid_signature,
        selfsigned_peer,
        unknown_ca,
        unsupported_certificate
    ].

%% Whether the human-readable description inside an alert names a certificate
%% reason.
%%
%% Which of the two forms a release produces is not stable. OTP 28.5 reports a
%% hostname mismatch as `{tls_alert, {handshake_failure, Description}}' whose
%% description spells out `bad_cert' and `hostname_check_failed', while 28.5.0.6
%% and 29 report `bad_certificate' as the alert itself. Reading only the alert
%% atom therefore answers `tls_handshake' on one build of a release and
%% `tls_authentication' on another, for one refusal.
%%
%% This is asked only for the certificate class, never for the ALPN one. A
%% description embeds peer-supplied certificate fields, so text can move a
%% classification toward "the certificate was refused" and never away from it.
-spec contains_reason_text(term(), [atom()]) -> boolean().
contains_reason_text(Reason, Atoms) ->
    case alert_text(Reason, <<>>) of
        <<>> -> false;
        Text ->
            lists:any(
                fun(Atom) ->
                    binary:match(Text, atom_to_binary(Atom, utf8)) =/= nomatch
                end,
                Atoms
            )
    end.

%% Collect the printable text inside one reason, up to a fixed ceiling.
%%
%% The ceiling is there because the description carries peer-supplied names
%% from the certificate that was refused, which is not this endpoint's to size.
-spec alert_text(term(), binary()) -> binary().
alert_text(_Term, Accumulated)
    when byte_size(Accumulated) >= ?MAXIMUM_ALERT_TEXT_BYTES ->
    Accumulated;
alert_text(Binary, Accumulated) when is_binary(Binary) ->
    <<Accumulated/binary, Binary/binary>>;
alert_text(Tuple, Accumulated) when is_tuple(Tuple) ->
    alert_text(tuple_to_list(Tuple), Accumulated);
alert_text(List, Accumulated) when is_list(List) ->
    case printable_text(List) of
        {ok, Text} -> <<Accumulated/binary, Text/binary>>;
        error ->
            lists:foldl(
                fun(Item, Inner) -> alert_text(Item, Inner) end,
                Accumulated,
                List
            )
    end;
alert_text(_Other, Accumulated) ->
    Accumulated.

-spec printable_text(list()) -> {ok, binary()} | error.
printable_text(List) ->
    case io_lib:printable_unicode_list(List) of
        false -> error;
        true ->
            case unicode:characters_to_binary(List) of
                Text when is_binary(Text) -> {ok, Text};
                _Other -> error
            end
    end.

-spec contains_reason(term(), [atom()]) -> boolean().
contains_reason(Reason, Atoms) when is_atom(Reason) ->
    lists:member(Reason, Atoms);
contains_reason(Reason, Atoms) when is_tuple(Reason) ->
    contains_reason(tuple_to_list(Reason), Atoms);
contains_reason([Head | Rest], Atoms) ->
    contains_reason(Head, Atoms) orelse contains_reason(Rest, Atoms);
contains_reason([], _Atoms) ->
    false;
contains_reason(_Reason, _Atoms) ->
    false.
