-module(http_transport_ffi).

-export([
    accept/2,
    close/1,
    connect/4,
    connect_with_deadlines/6,
    connect_with_timeouts/5,
    enable_half_close/1,
    listen/4,
    local_endpoint/1,
    monotonic_millisecond/0,
    peer_endpoint/1,
    read/3,
    send/2,
    shutdown_write/1,
    socket_local_endpoint/1,
    stop/1,
    transfer_listener_owner/2,
    transfer_owner/2,
    upgrade_client_tls/5,
    upgrade_server_tls/5
]).

-define(MAXIMUM_RESOLVED_ADDRESSES, 16).

-type family() :: inet | inet6.
-type listener() :: #{
    kind := listener,
    socket := gen_tcp:socket(),
    send_timeout := pos_integer()
}.
-type stream() :: #{
    kind := tcp | tls,
    socket := term(),
    buffered := binary()
}.

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
    #{kind := listener, socket := Listener, send_timeout := SendTimeout},
    Timeout
)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
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
    end;
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
            Now = erlang:monotonic_time(millisecond),
            TotalDeadline = Now + TotalTimeout,
            DnsDeadline = erlang:min(Now + DnsTimeout, TotalDeadline),
            DnsTimeoutCode = timeout_code(DnsDeadline, TotalDeadline, 16),
            case resolve_with_deadline(
                binary_to_list(Host),
                DnsDeadline,
                DnsTimeoutCode
            ) of
                {ok, Addresses} ->
                    ConnectDeadline = erlang:min(
                        erlang:monotonic_time(millisecond) + ConnectTimeout,
                        TotalDeadline
                    ),
                    ConnectTimeoutCode = timeout_code(
                        ConnectDeadline,
                        TotalDeadline,
                        2
                    ),
                    connect_addresses(
                        Addresses,
                        Port,
                        SendTimeout,
                        ConnectDeadline,
                        ConnectTimeoutCode,
                        5
                    );
                {error, Code} ->
                    {error, Code}
            end;
        _Match ->
            {error, 1}
    end;
connect_with_deadlines(
    _Host,
    _Port,
    _DnsTimeout,
    _ConnectTimeout,
    _TotalTimeout,
    _SendTimeout
) ->
    {error, 1}.

-spec upgrade_client_tls(
    stream(), binary(), [binary()], [binary()], integer()
) -> {ok, {stream(), binary(), 12 | 13}} | {error, integer()}.
upgrade_client_tls(
    #{kind := tcp, socket := Socket},
    ServerName,
    CaCertificates,
    AlpnProtocols,
    Timeout
)
    when is_binary(ServerName), byte_size(ServerName) > 0,
         byte_size(ServerName) =< 253,
         is_list(CaCertificates), is_list(AlpnProtocols),
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
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
    end;
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
    #{kind := tcp, socket := Socket},
    CertificatePem,
    PrivateKeyPem,
    AlpnProtocols,
    Timeout
)
    when is_binary(CertificatePem), byte_size(CertificatePem) > 0,
         is_binary(PrivateKeyPem), byte_size(PrivateKeyPem) > 0,
         is_list(AlpnProtocols),
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
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
    end;
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
    case inet:setopts(Socket, [{active, once}]) of
        ok ->
            receive
                {tcp, Socket, Data} when is_binary(Data) ->
                    bounded_data(Handle, Data, Maximum);
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
    case ssl:setopts(Socket, [{active, once}]) of
        ok ->
            receive
                {ssl, Socket, Data} when is_binary(Data) ->
                    bounded_data(Handle, Data, Maximum);
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

-spec resolve_with_deadline(string(), integer(), integer()) ->
    {ok, [{family(), inet:ip_address()}]} | {error, integer()}.
resolve_with_deadline(Host, Deadline, TimeoutCode) ->
    Parent = self(),
    Reference = make_ref(),
    {Resolver, Monitor} = spawn_monitor(fun() ->
        Parent ! {Reference, resolve_host(Host)}
    end),
    Timeout = remaining_milliseconds(Deadline),
    receive
        {Reference, {ok, Addresses}} ->
            erlang:demonitor(Monitor, [flush]),
            {ok, Addresses};
        {Reference, {error, _Reason}} ->
            erlang:demonitor(Monitor, [flush]),
            {error, 4};
        {'DOWN', Monitor, process, Resolver, _Reason} ->
            {error, 4}
    after Timeout ->
        exit(Resolver, kill),
        receive
            {'DOWN', Monitor, process, Resolver, _Reason} -> ok
        end,
        receive
            {Reference, _LateResult} -> ok
        after 0 ->
            ok
        end,
        {error, TimeoutCode}
    end.

-spec resolve_host(string()) ->
    {ok, [{family(), inet:ip_address()}]} | {error, term()}.
resolve_host(Host) ->
    V6 = resolved_family(Host, inet6),
    V4 = resolved_family(Host, inet),
    Addresses = lists:sublist(V6 ++ V4, ?MAXIMUM_RESOLVED_ADDRESSES),
    case Addresses of
        [] -> {error, nxdomain};
        _ -> {ok, Addresses}
    end.

-spec resolved_family(string(), family()) ->
    [{family(), inet:ip_address()}].
resolved_family(Host, Family) ->
    case inet:getaddrs(Host, Family) of
        {ok, Addresses} -> [{Family, Address} || Address <- Addresses];
        {error, _Reason} -> []
    end.

-spec connect_addresses(
    [{family(), inet:ip_address()}],
    inet:port_number(),
    pos_integer(),
    integer(),
    integer(),
    integer()
) -> {ok, stream()} | {error, integer()}.
connect_addresses(
    [],
    _Port,
    _SendTimeout,
    _Deadline,
    _TimeoutCode,
    LastCode
) ->
    {error, LastCode};
connect_addresses(
    [{Family, Address} | Rest],
    Port,
    SendTimeout,
    Deadline,
    TimeoutCode,
    _LastCode
) ->
    case remaining_milliseconds(Deadline) of
        0 ->
            {error, TimeoutCode};
        Remaining ->
            Options = stream_options(Family, SendTimeout),
            try gen_tcp:connect(Address, Port, Options, Remaining) of
                {ok, Socket} ->
                    {ok, stream(Socket)};
                {error, timeout} ->
                    {error, TimeoutCode};
                {error, Reason} ->
                    connect_addresses(
                        Rest,
                        Port,
                        SendTimeout,
                        Deadline,
                        TimeoutCode,
                        connect_error_code(Reason)
                    )
            catch
                _Class:_Reason ->
                    connect_addresses(
                        Rest,
                        Port,
                        SendTimeout,
                        Deadline,
                        TimeoutCode,
                        5
                    )
            end
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
        {verify, verify_peer},
        {cacerts, TrustedCertificates},
        {server_name_indication, binary_to_list(ServerName)},
        {customize_hostname_check, [
            {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
        ]},
        {versions, ['tlsv1.3', 'tlsv1.2']},
        {alpn_advertised_protocols, AlpnProtocols},
        {depth, 10},
        {active, false},
        binary
    ].

-spec server_tls_options(map(), [binary()]) -> list().
server_tls_options(CertsKeys, AlpnProtocols) ->
    [
        {certs_keys, [CertsKeys]},
        {verify, verify_none},
        {versions, ['tlsv1.3', 'tlsv1.2']},
        {alpn_preferred_protocols, AlpnProtocols},
        {honor_cipher_order, true},
        {reuse_sessions, false},
        {active, false},
        binary
    ].

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
            case contains_reason(Reason, [
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
            ]) of
                true -> 14;
                false -> 13
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
