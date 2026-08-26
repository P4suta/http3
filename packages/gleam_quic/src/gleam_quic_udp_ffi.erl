-module(gleam_quic_udp_ffi).

-on_load(init/0).

-export([
    active_datagram/2,
    active_once/1,
    close/1,
    continue_relay/1,
    dont_fragment_active/1,
    local_endpoint/1,
    maximum_relay_batch/0,
    monotonic_millisecond/0,
    unix_millisecond/0,
    open/2,
    open_dual_stack/1,
    recv/2,
    relay_batch/2,
    resolve/2,
    resolve_timeout/3,
    send/5,
    start_relay/1,
    stop_relay/1,
    supports_ecn/1,
    transfer_owner/2
]).

%% Raw socket options that make the kernel set the Don't-Fragment bit on every
%% datagram a socket sends. RFC 8899 section 3 reads an acknowledged DPLPMTUD
%% probe as proof the path carries that size only when the probe could not have
%% been fragmented on the way, and RFC 9000 section 14.2 requires the same of
%% QUIC, so every QUIC socket asks for this at open.
%%
%% Each constant is the value of the C header macro named beside it; Erlang's
%% inet raw options take the numbers rather than the names.

%% <netinet/in.h> IPPROTO_IP and IPPROTO_IPV6, the option levels.
-define(IPPROTO_IP, 0).
-define(IPPROTO_IPV6, 41).

%% Linux <linux/in.h> IP_MTU_DISCOVER and <linux/in6.h> IPV6_MTU_DISCOVER,
%% which carry a path-MTU-discovery policy rather than a boolean.
%% IP_PMTUDISC_PROBE sets Don't-Fragment and ignores the kernel's cached path
%% MTU, which is exactly what a DPLPMTUD search wants; IP_PMTUDISC_DO also sets
%% Don't-Fragment but clamps sends to the cached MTU, and is the fallback when
%% a kernel refuses PROBE.
-define(LINUX_IP_MTU_DISCOVER, 10).
-define(LINUX_IPV6_MTU_DISCOVER, 23).
-define(LINUX_PMTUDISC_DO, 2).
-define(LINUX_PMTUDISC_PROBE, 3).

%% Darwin <netinet/in.h> IP_DONTFRAG and <netinet6/in6.h> IPV6_DONTFRAG,
%% boolean integers.
-define(DARWIN_IP_DONTFRAG, 28).
-define(DARWIN_IPV6_DONTFRAG, 62).

%% FreeBSD <netinet/in.h> IP_DONTFRAG and <netinet6/in6.h> IPV6_DONTFRAG,
%% boolean integers. FreeBSD numbers IP_DONTFRAG differently from Darwin.
-define(FREEBSD_IP_DONTFRAG, 67).
-define(FREEBSD_IPV6_DONTFRAG, 62).

%% Windows <ws2ipdef.h> IP_DONTFRAGMENT and IPV6_DONTFRAG, boolean integers.
%% Windows may not accept these through inet raw options at all, which the
%% caller handles the same way as any other refusal.
-define(WINDOWS_IP_DONTFRAGMENT, 14).
-define(WINDOWS_IPV6_DONTFRAG, 14).

-define(CLOCK_ORIGIN, {?MODULE, clock_origin}).
-define(DEFAULT_SOCKET_BUFFER_BYTES, 4 * 1024 * 1024).
-define(MAXIMUM_RESOLVED_ADDRESSES, 16).

-type socket_family() :: 4 | 6.
-type handle() :: #{
    socket := gen_udp:socket(),
    family := socket_family() | dual,
    ecn := boolean(),
    dont_fragment := boolean(),
    ipv4_socket => gen_udp:socket(),
    ipv4_ecn => boolean()
}.
-type relay() :: #{
    pid := pid(),
    reference := reference(),
    socket := gen_udp:socket(),
    sockets := [gen_udp:socket()]
}.

-define(MAXIMUM_RELAY_BATCH, 64).
-define(RELAY_STOP_TIMEOUT, 1000).

-spec init() -> ok.
init() ->
    case persistent_term:get(?CLOCK_ORIGIN, undefined) of
        undefined ->
            persistent_term:put(?CLOCK_ORIGIN, erlang:monotonic_time(millisecond));
        _Origin ->
            ok
    end.

-spec open(binary(), integer()) -> {ok, handle()} | {error, integer()}.
open(Address, Port)
    when is_binary(Address), is_integer(Port), Port >= 0, Port =< 65535 ->
    case decode_address(Address) of
        {ok, IpAddress, Family} -> open_address(IpAddress, Family, Port);
        error -> {error, 1}
    end;
open(_Address, _Port) ->
    {error, 1}.

-spec open_dual_stack(integer()) -> {ok, handle()} | {error, integer()}.
open_dual_stack(Port) when is_integer(Port), Port >= 0, Port =< 65535 ->
    open_split_dual_stack(Port);
open_dual_stack(_Port) ->
    {error, 1}.

-spec local_endpoint(handle()) ->
    {ok, {binary(), integer()}} | {error, integer()}.
local_endpoint(#{socket := Socket}) ->
    try inet:sockname(Socket) of
        {ok, {Address, Port}} ->
            case encode_address(Address) of
                {ok, Bytes} -> {ok, {Bytes, Port}};
                error -> {error, 8}
            end;
        {error, Reason} ->
            {error, error_code(Reason)}
    catch
        _Class:_Reason -> {error, 3}
    end;
local_endpoint(_Socket) ->
    {error, 1}.

-spec resolve(binary(), 0 | 4 | 6) -> {ok, [binary()]} | {error, integer()}.
resolve(Host, Family)
    when is_binary(Host), byte_size(Host) > 0, byte_size(Host) =< 253,
         (Family =:= 0 orelse Family =:= 4 orelse Family =:= 6) ->
    case binary:match(Host, <<0>>) of
        nomatch -> resolve_host(binary_to_list(Host), Family);
        _Match -> {error, 1}
    end;
resolve(_Host, _Family) ->
    {error, 1}.

-spec resolve_timeout(binary(), 0 | 4 | 6, integer()) ->
    {ok, [binary()]} | {error, integer()}.
resolve_timeout(Host, Family, Timeout)
    when is_binary(Host), byte_size(Host) > 0, byte_size(Host) =< 253,
         (Family =:= 0 orelse Family =:= 4 orelse Family =:= 6),
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    case binary:match(Host, <<0>>) of
        nomatch -> resolve_with_deadline(binary_to_list(Host), Family, Timeout);
        _Match -> {error, 1}
    end;
resolve_timeout(_Host, _Family, _Timeout) ->
    {error, 1}.

-spec resolve_with_deadline(string(), 0 | 4 | 6, pos_integer()) ->
    {ok, [binary()]} | {error, integer()}.
resolve_with_deadline(Host, Family, Timeout) ->
    Parent = self(),
    Reference = make_ref(),
    {Resolver, Monitor} = spawn_monitor(fun() ->
        nil = gleam_quic_process_label_ffi:set_role(4),
        Parent ! {Reference, resolve_host(Host, Family)}
    end),
    receive
        {Reference, Result} ->
            erlang:demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Resolver, _Reason} ->
            {error, 8}
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
        {error, 2}
    end.

-spec send(handle(), binary(), integer(), binary(), integer()) ->
    {ok, nil} | {error, integer()}.
send(Handle = #{socket := _Socket}, Address, Port, Payload, Ecn)
    when is_binary(Address), is_integer(Port), Port > 0, Port =< 65535,
         is_binary(Payload), byte_size(Payload) =< 65527,
         is_integer(Ecn), Ecn >= 0, Ecn =< 2 ->
    case decode_address(Address) of
        {ok, IpAddress, Family} ->
            case send_target(Handle, IpAddress, Family) of
                {ok, Socket, SendAddress, SendFamily, EcnSupported} ->
                    send_datagram(
                        Socket,
                        SendFamily,
                        EcnSupported,
                        SendAddress,
                        Port,
                        Payload,
                        Ecn
                    );
                error ->
                    {error, 1}
            end;
        _Other ->
            {error, 1}
    end;
send(_Socket, _Address, _Port, _Payload, _Ecn) ->
    {error, 1}.

-spec recv(handle(), integer()) ->
    {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}.
recv(#{socket := Socket6, ipv4_socket := Socket4}, Timeout)
    when is_integer(Timeout), Timeout >= 0, Timeout =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    recv_split([Socket6, Socket4], Deadline);
recv(#{socket := Socket}, Timeout)
    when is_integer(Timeout), Timeout >= 0, Timeout =< 2147483647 ->
    try gen_udp:recv(Socket, 0, Timeout) of
        {ok, {Address, Port, Payload}} ->
            receive_result(Address, Port, Payload, 0);
        {ok, {Address, Port, Ancillary, Payload}} ->
            receive_result(Address, Port, Payload, received_ecn(Ancillary));
        {error, Reason} ->
            {error, error_code(Reason)}
    catch
        _Class:_Reason -> {error, 3}
    end;
recv(_Socket, _Timeout) ->
    {error, 1}.

-spec active_once(handle()) -> {ok, nil} | {error, integer()}.
active_once(#{socket := Socket6, ipv4_socket := Socket4}) ->
    activate_once_all([Socket6, Socket4]);
active_once(#{socket := Socket}) ->
    try inet:setopts(Socket, [{active, once}]) of
        ok -> {ok, nil};
        {error, Reason} -> {error, error_code(Reason)}
    catch
        _Class:_Reason -> {error, 3}
    end;
active_once(_Socket) ->
    {error, 1}.

-spec active_datagram(handle(), term()) ->
    {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}.
active_datagram(#{socket := Socket6, ipv4_socket := Socket4},
                {udp, Socket, Address, Port, Payload})
    when Socket =:= Socket6; Socket =:= Socket4 ->
    receive_result(Address, Port, Payload, 0);
active_datagram(#{socket := Socket6, ipv4_socket := Socket4},
                {udp, Socket, Address, Port, Ancillary, Payload})
    when Socket =:= Socket6; Socket =:= Socket4 ->
    receive_result(Address, Port, Payload, received_ecn(Ancillary));
active_datagram(#{socket := Socket6, ipv4_socket := Socket4},
                {udp_error, Socket, Reason})
    when Socket =:= Socket6; Socket =:= Socket4 ->
    {error, error_code(Reason)};
active_datagram(#{socket := Socket6, ipv4_socket := Socket4},
                {udp_closed, Socket})
    when Socket =:= Socket6; Socket =:= Socket4 ->
    {error, 3};
active_datagram(#{socket := Socket}, {udp, Socket, Address, Port, Payload}) ->
    receive_result(Address, Port, Payload, 0);
active_datagram(#{socket := Socket},
                {udp, Socket, Address, Port, Ancillary, Payload}) ->
    receive_result(Address, Port, Payload, received_ecn(Ancillary));
active_datagram(#{socket := Socket}, {udp_error, Socket, Reason}) ->
    {error, error_code(Reason)};
active_datagram(#{socket := Socket}, {udp_closed, Socket}) ->
    {error, 3};
active_datagram(_Socket, _Message) ->
    {error, 1}.

-spec start_relay(handle()) -> {ok, relay()} | {error, integer()}.
start_relay(Handle = #{socket := Socket}) ->
    Owner = self(),
    Reference = make_ref(),
    Sockets = handle_sockets(Handle),
    Relay = spawn(fun() ->
        nil = gleam_quic_process_label_ffi:set_role(5),
        receive
            {start, Owner, Reference, Sockets} ->
                Monitor = erlang:monitor(process, Owner),
                relay_loop(Sockets, Owner, Reference, Monitor)
        end
    end),
    case transfer_sockets(Sockets, Relay, []) of
        {ok, _OwnedSockets} ->
            Relay ! {start, Owner, Reference, Sockets},
            {ok, #{
                pid => Relay,
                reference => Reference,
                socket => Socket,
                sockets => Sockets
            }};
        {error, Reason, _OwnedSockets} ->
            exit(Relay, kill),
            close_sockets(Sockets),
            {error, error_code(Reason)}
    end;
start_relay(_Socket) ->
    {error, 1}.

%% The most datagrams one relay batch can carry. The listener derives its
%% per-connection delivery window from this: the whole batch is routed in a
%% single step and no acknowledgement can widen a window part way through it,
%% so a window narrower than a batch sheds part of a burst that a healthy
%% connection is keeping up with.
-spec maximum_relay_batch() -> integer().
maximum_relay_batch() ->
    ?MAXIMUM_RELAY_BATCH.

-spec relay_batch(relay(), term()) ->
    {ok, [{binary(), integer(), binary(), 0..3}]} | {error, integer()}.
relay_batch(#{reference := Reference},
            {gleam_quic_udp_batch, Reference, {ok, Batch}})
    when is_list(Batch) ->
    {ok, Batch};
relay_batch(#{reference := Reference},
            {gleam_quic_udp_batch, Reference, {error, Code}})
    when is_integer(Code) ->
    {error, Code};
relay_batch(_Relay, _Message) ->
    {error, 1}.

-spec continue_relay(relay()) -> {ok, nil} | {error, integer()}.
continue_relay(#{pid := Pid, reference := Reference}) ->
    case erlang:is_process_alive(Pid) of
        true ->
            Pid ! {gleam_quic_udp_continue, Reference},
            {ok, nil};
        false ->
            {error, 3}
    end;
continue_relay(_Relay) ->
    {error, 1}.

-spec stop_relay(relay()) -> {ok, nil} | {error, integer()}.
stop_relay(#{pid := Pid, reference := Reference}) ->
    case erlang:is_process_alive(Pid) of
        false -> {ok, nil};
        true ->
            StopReference = make_ref(),
            Pid ! {gleam_quic_udp_stop, Reference, self(), StopReference},
            receive
                {gleam_quic_udp_stopped, StopReference} -> {ok, nil}
            after ?RELAY_STOP_TIMEOUT ->
                {error, 2}
            end
    end;
stop_relay(_Relay) ->
    {error, 1}.

%% Report whether every socket behind this handle sets Don't-Fragment on the
%% datagrams it sends. Path MTU discovery may only raise the confirmed size
%% above the 1200-byte floor when it does.
-spec dont_fragment_active(term()) -> boolean().
dont_fragment_active(#{dont_fragment := Active}) ->
    Active;
dont_fragment_active(_Handle) ->
    false.

-spec supports_ecn(term()) -> boolean().
supports_ecn(#{ecn := Ipv6, ipv4_ecn := Ipv4}) -> Ipv6 andalso Ipv4;
supports_ecn(#{ecn := Supported}) -> Supported;
supports_ecn(_Socket) -> false.

-spec close(term()) -> {ok, nil} | {error, integer()}.
close(#{socket := Socket6, ipv4_socket := Socket4}) ->
    close_sockets([Socket6, Socket4]),
    {ok, nil};
close(#{socket := Socket}) ->
    try gen_udp:close(Socket) of
        ok -> {ok, nil}
    catch
        _Class:_Reason -> {ok, nil}
    end;
close(_Socket) ->
    {error, 1}.

%% Transfer a passive client socket between bounded connection-attempt actors.
%% Only the current controlling process can succeed, and the opaque handle
%% remains unchanged.
-spec transfer_owner(handle(), pid()) -> {ok, nil} | {error, integer()}.
transfer_owner(#{socket := Socket6, ipv4_socket := Socket4}, Owner)
    when is_pid(Owner) ->
    case transfer_sockets([Socket6, Socket4], Owner, []) of
        {ok, _Sockets} -> {ok, nil};
        {error, Reason, _Sockets} ->
            close_sockets([Socket6, Socket4]),
            {error, error_code(Reason)}
    end;
transfer_owner(#{socket := Socket}, Owner) when is_pid(Owner) ->
    try gen_udp:controlling_process(Socket, Owner) of
        ok -> {ok, nil};
        {error, Reason} -> {error, error_code(Reason)}
    catch
        _Class:_Reason -> {error, 3}
    end;
transfer_owner(_Socket, _Owner) ->
    {error, 1}.

-spec relay_loop([gen_udp:socket()], pid(), reference(), reference()) -> no_return().
relay_loop(Sockets, Owner, Reference, Monitor) ->
    case activate_once_all(Sockets) of
        {ok, nil} -> relay_receive(Sockets, Owner, Reference, Monitor);
        {error, Reason} ->
            Owner ! {gleam_quic_udp_batch, Reference,
                     {error, Reason}},
            relay_wait(Sockets, Owner, Reference, Monitor)
    end.

-spec relay_receive([gen_udp:socket()], pid(), reference(), reference()) ->
    no_return().
relay_receive(Sockets, Owner, Reference, Monitor) ->
    receive
        {udp, Socket, Address, Port, Payload} ->
            case lists:member(Socket, Sockets) of
                true -> relay_deliver(Sockets, Owner, Reference, Monitor,
                                      Address, Port, Payload, 0);
                false -> relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {udp, Socket, Address, Port, Ancillary, Payload} ->
            case lists:member(Socket, Sockets) of
                true -> relay_deliver(Sockets, Owner, Reference, Monitor,
                                      Address, Port, Payload,
                                      received_ecn(Ancillary));
                false -> relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {udp_error, Socket, Reason}
            when Reason =:= econnreset; Reason =:= econnrefused;
                 Reason =:= ehostunreach; Reason =:= enetunreach ->
            %% A shared listener can receive an asynchronous ICMP error after
            %% replying to a client which has already closed its UDP socket.
            %% This is connection-local feedback, not a listener failure.
            case lists:member(Socket, Sockets) of
                true ->
                    deactivate_sockets(Sockets),
                    relay_loop(Sockets, Owner, Reference, Monitor);
                false ->
                    relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {udp_error, Socket, Reason} ->
            case lists:member(Socket, Sockets) of
                true ->
                    deactivate_sockets(Sockets),
                    Owner ! {gleam_quic_udp_batch, Reference,
                             {error, error_code(Reason)}},
                    relay_wait(Sockets, Owner, Reference, Monitor);
                false ->
                    relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {udp_closed, Socket} ->
            case lists:member(Socket, Sockets) of
                true ->
                    Owner ! {gleam_quic_udp_batch, Reference, {error, 3}},
                    close_sockets(Sockets),
                    exit(normal);
                false ->
                    relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {gleam_quic_udp_stop, Reference, Caller, StopReference} ->
            relay_close(Sockets, Caller, StopReference);
        {'DOWN', Monitor, process, Owner, _Reason} ->
            close_sockets(Sockets),
            exit(normal)
    end.

-spec relay_deliver(
    [gen_udp:socket()], pid(), reference(), reference(), inet:ip_address(),
    inet:port_number(), binary(), 0..3
) -> no_return().
relay_deliver(Sockets, Owner, Reference, Monitor,
              Address, Port, Payload, Ecn) ->
    deactivate_sockets(Sockets),
    case normalise_relay_datagram(Address, Port, Payload, Ecn) of
        {error, Code} ->
            Owner ! {gleam_quic_udp_batch, Reference, {error, Code}};
        {ok, First} ->
            {Remaining, Reversed} = drain_relay_sockets(
                Sockets, ?MAXIMUM_RELAY_BATCH - 1, [First]
            ),
            Batch = drain_relay_mailbox(Sockets, Remaining, Reversed),
            Owner ! {gleam_quic_udp_batch, Reference, {ok, Batch}}
    end,
    relay_wait(Sockets, Owner, Reference, Monitor).

-spec relay_wait([gen_udp:socket()], pid(), reference(), reference()) ->
    no_return().
relay_wait(Sockets, Owner, Reference, Monitor) ->
    receive
        {gleam_quic_udp_continue, Reference} ->
            relay_loop(Sockets, Owner, Reference, Monitor);
        {gleam_quic_udp_stop, Reference, Caller, StopReference} ->
            relay_close(Sockets, Caller, StopReference);
        {'DOWN', Monitor, process, Owner, _Reason} ->
            close_sockets(Sockets),
            exit(normal)
    end.

-spec relay_close([gen_udp:socket()], pid(), reference()) -> no_return().
relay_close(Sockets, Caller, StopReference) ->
    close_sockets(Sockets),
    Caller ! {gleam_quic_udp_stopped, StopReference},
    exit(normal).

-spec drain_relay_sockets(
    [gen_udp:socket()], non_neg_integer(),
    [{binary(), integer(), binary(), 0..3}]
) -> {non_neg_integer(), [{binary(), integer(), binary(), 0..3}]}.
drain_relay_sockets([], Remaining, Reversed) ->
    {Remaining, Reversed};
drain_relay_sockets(_Sockets, 0, Reversed) ->
    {0, Reversed};
drain_relay_sockets([Socket | Rest], Remaining, Reversed) ->
    {NextRemaining, NextReversed} = drain_relay_socket(
        Socket, Remaining, Reversed
    ),
    drain_relay_sockets(Rest, NextRemaining, NextReversed).

-spec drain_relay_socket(
    gen_udp:socket(), non_neg_integer(),
    [{binary(), integer(), binary(), 0..3}]
) -> {non_neg_integer(), [{binary(), integer(), binary(), 0..3}]}.
drain_relay_socket(_Socket, 0, Reversed) ->
    {0, Reversed};
drain_relay_socket(Socket, Remaining, Reversed) ->
    case gen_udp:recv(Socket, 0, 0) of
        {ok, {Address, Port, Payload}} ->
            drain_normalised(Socket, Remaining, Reversed,
                             Address, Port, Payload, 0);
        {ok, {Address, Port, Ancillary, Payload}} ->
            drain_normalised(Socket, Remaining, Reversed,
                             Address, Port, Payload, received_ecn(Ancillary));
        {error, _Reason} ->
            {Remaining, Reversed}
    end.

-spec drain_normalised(
    gen_udp:socket(), pos_integer(),
    [{binary(), integer(), binary(), 0..3}], inet:ip_address(),
    inet:port_number(), binary(), 0..3
) -> {non_neg_integer(), [{binary(), integer(), binary(), 0..3}]}.
drain_normalised(Socket, Remaining, Reversed,
                 Address, Port, Payload, Ecn) ->
    case normalise_relay_datagram(Address, Port, Payload, Ecn) of
        {ok, Datagram} ->
            drain_relay_socket(Socket, Remaining - 1, [Datagram | Reversed]);
        {error, _Code} ->
            drain_relay_socket(Socket, Remaining - 1, Reversed)
    end.

-spec drain_relay_mailbox(
    [gen_udp:socket()], non_neg_integer(),
    [{binary(), integer(), binary(), 0..3}]
) -> [{binary(), integer(), binary(), 0..3}].
drain_relay_mailbox(_Sockets, 0, Reversed) ->
    lists:reverse(Reversed);
drain_relay_mailbox(Sockets, Remaining, Reversed) ->
    receive
        {udp, Socket, Address, Port, Payload} ->
            drain_mailbox_datagram(
                Sockets, Remaining, Reversed, Socket,
                Address, Port, Payload, 0
            );
        {udp, Socket, Address, Port, Ancillary, Payload} ->
            drain_mailbox_datagram(
                Sockets, Remaining, Reversed, Socket,
                Address, Port, Payload, received_ecn(Ancillary)
            )
    after 0 ->
        lists:reverse(Reversed)
    end.

-spec drain_mailbox_datagram(
    [gen_udp:socket()], pos_integer(),
    [{binary(), integer(), binary(), 0..3}], gen_udp:socket(),
    inet:ip_address(), inet:port_number(), binary(), 0..3
) -> [{binary(), integer(), binary(), 0..3}].
drain_mailbox_datagram(Sockets, Remaining, Reversed, Socket,
                       Address, Port, Payload, Ecn) ->
    case lists:member(Socket, Sockets) of
        false -> drain_relay_mailbox(Sockets, Remaining, Reversed);
        true ->
            case normalise_relay_datagram(Address, Port, Payload, Ecn) of
                {ok, Datagram} ->
                    drain_relay_mailbox(
                        Sockets, Remaining - 1, [Datagram | Reversed]
                    );
                {error, _Code} ->
                    drain_relay_mailbox(Sockets, Remaining - 1, Reversed)
            end
    end.

-spec normalise_relay_datagram(
    inet:ip_address(), inet:port_number(), binary(), 0..3
) -> {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}.
normalise_relay_datagram(Address, Port, Payload, Ecn)
    when is_binary(Payload) ->
    case encode_address(Address) of
        {ok, Bytes} -> {ok, {Bytes, Port, Payload, Ecn}};
        error -> {error, 8}
    end.

-spec monotonic_millisecond() -> non_neg_integer().
monotonic_millisecond() ->
    Origin = persistent_term:get(?CLOCK_ORIGIN),
    erlang:monotonic_time(millisecond) - Origin.

-spec unix_millisecond() -> non_neg_integer().
unix_millisecond() ->
    erlang:system_time(millisecond).

%% Present portable separate IPv4 and IPv6 protocol stacks as one bounded
%% same-port logical handle. This is required on Windows and avoids depending
%% on platform-specific IPv4-mapped IPv6 socket defaults elsewhere.
-spec open_split_dual_stack(inet:port_number()) ->
    {ok, handle()} | {error, integer()}.
open_split_dual_stack(Port) ->
    Ipv6Options = [
        binary,
        {active, false},
        {reuseaddr, true},
        {recbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {sndbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {ip, {0, 0, 0, 0, 0, 0, 0, 0}}
        | family_options(6)
    ],
    case open_socket(Port, Ipv6Options, {recvtclass, true}, 6) of
        {error, Reason} -> {error, Reason};
        {ok, #{socket := Socket6, ecn := Ecn6, dont_fragment := Df6}} ->
            case inet:port(Socket6) of
                {error, Reason} ->
                    close_sockets([Socket6]),
                    {error, error_code(Reason)};
                {ok, BoundPort} ->
                    open_split_ipv4(Socket6, Ecn6, Df6, BoundPort)
            end
    end.

-spec open_split_ipv4(
    gen_udp:socket(), boolean(), boolean(), inet:port_number()
) ->
    {ok, handle()} | {error, integer()}.
open_split_ipv4(Socket6, Ecn6, Df6, Port) ->
    Ipv4Options = [
        binary,
        {active, false},
        {reuseaddr, true},
        {recbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {sndbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {ip, {0, 0, 0, 0}}
        | family_options(4)
    ],
    case open_socket(Port, Ipv4Options, {recvtos, true}, 4) of
        {error, Reason} ->
            close_sockets([Socket6]),
            {error, Reason};
        {ok, #{socket := Socket4, ecn := Ecn4, dont_fragment := Df4}} ->
            {ok, #{
                socket => Socket6,
                ipv4_socket => Socket4,
                family => dual,
                ecn => Ecn6,
                ipv4_ecn => Ecn4,
                dont_fragment => Df6 andalso Df4
            }}
    end.

-spec send_target(handle(), inet:ip_address(), socket_family()) ->
    {ok, gen_udp:socket(), inet:ip_address(), socket_family(), boolean()} |
    error.
send_target(#{ipv4_socket := Socket, ipv4_ecn := Ecn}, Address, 4) ->
    {ok, Socket, Address, 4, Ecn};
send_target(#{socket := Socket, family := dual, ecn := Ecn}, Address, 6) ->
    {ok, Socket, Address, 6, Ecn};
send_target(#{socket := Socket, family := Family, ecn := Ecn},
            Address, Family) ->
    {ok, Socket, Address, Family, Ecn};
send_target(_Handle, _Address, _Family) ->
    error.

-spec recv_split([gen_udp:socket()], integer()) ->
    {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}.
recv_split(Sockets, Deadline) ->
    case recv_split_once(Sockets, false, none) of
        {ok, Result} -> Result;
        {error, Reason} -> {error, error_code(Reason)};
        retry ->
            Remaining = Deadline - erlang:monotonic_time(millisecond),
            case Remaining =< 0 of
                true -> {error, 2};
                false ->
                    receive after erlang:min(Remaining, 1) -> ok end,
                    recv_split(Sockets, Deadline)
            end
    end.

-spec recv_split_once([gen_udp:socket()], boolean(), none | inet:posix()) ->
    {ok, {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}} |
    {error, inet:posix()} | retry.
recv_split_once([], true, _Error) ->
    retry;
recv_split_once([], false, none) ->
    {error, closed};
recv_split_once([], false, Reason) ->
    {error, Reason};
recv_split_once([Socket | Rest], SawTimeout, FirstError) ->
    try gen_udp:recv(Socket, 0, 0) of
        {ok, {Address, Port, Payload}} ->
            {ok, receive_result(Address, Port, Payload, 0)};
        {ok, {Address, Port, Ancillary, Payload}} ->
            {ok, receive_result(
                Address, Port, Payload, received_ecn(Ancillary)
            )};
        {error, timeout} ->
            recv_split_once(Rest, true, FirstError);
        {error, Reason} ->
            NextError = case FirstError of
                none -> Reason;
                Existing -> Existing
            end,
            recv_split_once(Rest, SawTimeout, NextError)
    catch
        _Class:_Reason ->
            recv_split_once(Rest, SawTimeout, closed)
    end.

-spec activate_once_all([gen_udp:socket()]) -> {ok, nil} | {error, integer()}.
activate_once_all(Sockets) ->
    activate_once_all(Sockets, []).

-spec activate_once_all([gen_udp:socket()], [gen_udp:socket()]) ->
    {ok, nil} | {error, integer()}.
activate_once_all([], _Activated) ->
    {ok, nil};
activate_once_all([Socket | Rest], Activated) ->
    try inet:setopts(Socket, [{active, once}]) of
        ok -> activate_once_all(Rest, [Socket | Activated]);
        {error, Reason} ->
            deactivate_sockets(Activated),
            {error, error_code(Reason)}
    catch
        _Class:_Reason ->
            deactivate_sockets(Activated),
            {error, 3}
    end.

-spec deactivate_sockets([gen_udp:socket()]) -> ok.
deactivate_sockets(Sockets) ->
    lists:foreach(fun(Socket) ->
        try inet:setopts(Socket, [{active, false}]) of
            _Result -> ok
        catch
            _Class:_Reason -> ok
        end
    end, Sockets).

-spec handle_sockets(handle()) -> [gen_udp:socket(), ...].
handle_sockets(#{socket := Socket6, ipv4_socket := Socket4}) ->
    [Socket6, Socket4];
handle_sockets(#{socket := Socket}) ->
    [Socket].

-spec transfer_sockets(
    [gen_udp:socket()], pid(), [gen_udp:socket()]
) -> {ok, [gen_udp:socket()]} |
     {error, inet:posix() | not_owner, [gen_udp:socket()]}.
transfer_sockets([], _Owner, Transferred) ->
    {ok, lists:reverse(Transferred)};
transfer_sockets([Socket | Rest], Owner, Transferred) ->
    case gen_udp:controlling_process(Socket, Owner) of
        ok -> transfer_sockets(Rest, Owner, [Socket | Transferred]);
        {error, Reason} -> {error, Reason, Transferred}
    end.

-spec close_sockets([gen_udp:socket()]) -> ok.
close_sockets(Sockets) ->
    lists:foreach(fun(Socket) ->
        try gen_udp:close(Socket) of
            _Result -> ok
        catch
            _Class:_Reason -> ok
        end
    end, Sockets).

-spec open_address(inet:ip_address(), 4 | 6, inet:port_number()) ->
    {ok, handle()} | {error, integer()}.
open_address(Address, Family, Port) ->
    BaseOptions = [
        binary,
        {active, false},
        {reuseaddr, true},
        {recbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {sndbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {ip, Address}
        | family_options(Family)
    ],
    EcnOption = case Family of
        4 -> {recvtos, true};
        6 -> {recvtclass, true}
    end,
    open_socket(Port, BaseOptions, EcnOption, Family).

-spec open_socket(
    inet:port_number(), [gen_udp:open_option()], gen_udp:option(), 4 | 6
) ->
    {ok, handle()} | {error, integer()}.
open_socket(Port, BaseOptions, EcnOption, Family) ->
    case runtime_supports_ecn() of
        false -> open_socket_without_ecn(Port, BaseOptions, Family);
        true -> open_socket_with_ecn(Port, BaseOptions, EcnOption, Family)
    end.

-spec open_socket_with_ecn(
    inet:port_number(), [gen_udp:open_option()], gen_udp:option(), 4 | 6
) -> {ok, handle()} | {error, integer()}.
open_socket_with_ecn(Port, BaseOptions, EcnOption, Family) ->
    case gen_udp:open(Port, [EcnOption | BaseOptions]) of
        {ok, Socket} ->
            {ok, #{
                socket => Socket,
                family => Family,
                ecn => true,
                dont_fragment => set_dont_fragment(Socket, Family)
            }};
        {error, Reason} when Reason =:= einval; Reason =:= enoprotoopt ->
            open_socket_without_ecn(Port, BaseOptions, Family);
        {error, Reason} ->
            {error, error_code(Reason)}
    end.

-spec open_socket_without_ecn(
    inet:port_number(), [gen_udp:open_option()], 4 | 6
) ->
    {ok, handle()} | {error, integer()}.
open_socket_without_ecn(Port, BaseOptions, Family) ->
    case gen_udp:open(Port, BaseOptions) of
        {ok, Socket} ->
            {ok, #{
                socket => Socket,
                family => Family,
                ecn => false,
                dont_fragment => set_dont_fragment(Socket, Family)
            }};
        {error, Reason} ->
            {error, error_code(Reason)}
    end.

%% Ask the kernel to set the Don't-Fragment bit on every datagram this socket
%% sends and report whether it agreed.
%%
%% A platform that does not expose the option through inet raw options leaves
%% the socket usable: the caller is told Don't-Fragment is inactive and keeps
%% path discovery at the 1200-byte floor every path carries, rather than
%% failing to open a socket at all.
-spec set_dont_fragment(gen_udp:socket(), socket_family()) -> boolean().
set_dont_fragment(Socket, Family) ->
    apply_dont_fragment(Socket, dont_fragment_options(os:type(), Family)).

-spec apply_dont_fragment(gen_udp:socket(), [gen_udp:option()]) -> boolean().
apply_dont_fragment(_Socket, []) ->
    false;
apply_dont_fragment(Socket, [Option | Rest]) ->
    try inet:setopts(Socket, [Option]) of
        ok -> true;
        {error, _Reason} -> apply_dont_fragment(Socket, Rest)
    catch
        _Class:_Reason -> apply_dont_fragment(Socket, Rest)
    end.

%% The socket options that set Don't-Fragment on this platform, most preferred
%% first, and none for a platform whose option this runtime cannot express.
-spec dont_fragment_options(term(), socket_family()) -> [gen_udp:option()].
dont_fragment_options({unix, linux}, 4) ->
    [
        raw_integer_option(
            ?IPPROTO_IP, ?LINUX_IP_MTU_DISCOVER, ?LINUX_PMTUDISC_PROBE
        ),
        raw_integer_option(
            ?IPPROTO_IP, ?LINUX_IP_MTU_DISCOVER, ?LINUX_PMTUDISC_DO
        )
    ];
dont_fragment_options({unix, linux}, 6) ->
    [
        raw_integer_option(
            ?IPPROTO_IPV6, ?LINUX_IPV6_MTU_DISCOVER, ?LINUX_PMTUDISC_PROBE
        ),
        raw_integer_option(
            ?IPPROTO_IPV6, ?LINUX_IPV6_MTU_DISCOVER, ?LINUX_PMTUDISC_DO
        )
    ];
dont_fragment_options({unix, darwin}, 4) ->
    [raw_integer_option(?IPPROTO_IP, ?DARWIN_IP_DONTFRAG, 1)];
dont_fragment_options({unix, darwin}, 6) ->
    [raw_integer_option(?IPPROTO_IPV6, ?DARWIN_IPV6_DONTFRAG, 1)];
dont_fragment_options({unix, freebsd}, 4) ->
    [raw_integer_option(?IPPROTO_IP, ?FREEBSD_IP_DONTFRAG, 1)];
dont_fragment_options({unix, freebsd}, 6) ->
    [raw_integer_option(?IPPROTO_IPV6, ?FREEBSD_IPV6_DONTFRAG, 1)];
dont_fragment_options({win32, _Name}, 4) ->
    [raw_integer_option(?IPPROTO_IP, ?WINDOWS_IP_DONTFRAGMENT, 1)];
dont_fragment_options({win32, _Name}, 6) ->
    [raw_integer_option(?IPPROTO_IPV6, ?WINDOWS_IPV6_DONTFRAG, 1)];
dont_fragment_options(_Platform, _Family) ->
    [].

-spec raw_integer_option(integer(), integer(), integer()) -> gen_udp:option().
raw_integer_option(Level, Option, Value) ->
    {raw, Level, Option, <<Value:32/native>>}.

-spec runtime_supports_ecn() -> boolean().
runtime_supports_ecn() ->
    case os:type() of
        {win32, _Name} -> false;
        _Other -> true
    end.

-spec resolve_host(string(), 0 | 4 | 6) -> {ok, [binary()]} | {error, integer()}.
resolve_host(Host, 4) ->
    resolve_family(Host, inet);
resolve_host(Host, 6) ->
    resolve_family(Host, inet6);
resolve_host(Host, 0) ->
    case {inet:getaddrs(Host, inet6), inet:getaddrs(Host, inet)} of
        {{ok, V6}, {ok, V4}} ->
            encode_addresses(lists:sublist(
                interleave_addresses(lists:uniq(V6), lists:uniq(V4)),
                ?MAXIMUM_RESOLVED_ADDRESSES
            ));
        {{ok, V6}, {error, _}} -> encode_addresses(V6);
        {{error, _}, {ok, V4}} -> encode_addresses(V4);
        {{error, _}, {error, Reason}} -> {error, error_code(Reason)}
    end.

%% RFC 8305 starts with the first IPv6 result, then alternates address
%% families so one long family-specific list cannot starve the other.
-spec interleave_addresses([inet:ip6_address()], [inet:ip4_address()]) ->
    [inet:ip_address()].
interleave_addresses([], V4) -> V4;
interleave_addresses(V6, []) -> V6;
interleave_addresses([V6 | V6Rest], [V4 | V4Rest]) ->
    [V6, V4 | interleave_addresses(V6Rest, V4Rest)].

-spec resolve_family(string(), inet | inet6) ->
    {ok, [binary()]} | {error, integer()}.
resolve_family(Host, Family) ->
    case inet:getaddrs(Host, Family) of
        {ok, Addresses} -> encode_addresses(Addresses);
        {error, Reason} -> {error, error_code(Reason)}
    end.

-spec encode_addresses([inet:ip_address()]) ->
    {ok, [binary()]} | {error, integer()}.
encode_addresses(Addresses) ->
    %% Resolvers may return the same address more than once. Keep the first
    %% occurrence so Happy Eyeballs never races duplicate connection candidates.
    try [
        Bytes
     || Address <- lists:uniq(Addresses),
        {ok, Bytes} <- [encode_address(Address)]
    ] of
        [] -> {error, 6};
        Encoded -> {ok, Encoded}
    catch
        _Class:_Reason -> {error, 8}
    end.

-spec family_options(4 | 6) -> [gen_udp:open_option()].
family_options(4) -> [inet];
family_options(6) -> [inet6, {ipv6_v6only, true}].

-spec send_datagram(
    gen_udp:socket(),
    4 | 6,
    boolean(),
    inet:ip_address(),
    inet:port_number(),
    binary(),
    0..2
) -> {ok, nil} | {error, integer()}.
send_datagram(_Socket, _Family, false, _Address, _Port, _Payload, Ecn)
    when Ecn =/= 0 ->
    {error, 7};
send_datagram(Socket, Family, _EcnSupported, Address, Port, Payload, Ecn) ->
    Option = case Family of
        4 -> {tos, Ecn};
        6 -> {tclass, Ecn}
    end,
    try inet:setopts(Socket, [Option]) of
        ok ->
            case gen_udp:send(Socket, Address, Port, Payload) of
                ok -> {ok, nil};
                {error, Reason} -> {error, error_code(Reason)}
            end;
        {error, _Reason} when Ecn =:= 0 ->
            case gen_udp:send(Socket, Address, Port, Payload) of
                ok -> {ok, nil};
                {error, SendReason} -> {error, error_code(SendReason)}
            end;
        {error, _Reason} ->
            {error, 7}
    catch
        _Class:_Reason -> {error, 3}
    end.

-spec receive_result(inet:ip_address(), inet:port_number(), binary(), 0..3) ->
    {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}.
receive_result(Address, Port, Payload, Ecn) when is_binary(Payload) ->
    case encode_address(Address) of
        {ok, Bytes} -> {ok, {Bytes, Port, Payload, Ecn}};
        error -> {error, 8}
    end.

-spec received_ecn(inet:ancillary_data()) -> 0..3.
received_ecn(Ancillary) ->
    Value = case lists:keyfind(tos, 1, Ancillary) of
        {tos, Tos} -> Tos;
        false ->
            case lists:keyfind(tclass, 1, Ancillary) of
                {tclass, TrafficClass} -> TrafficClass;
                false -> 0
            end
    end,
    Value band 3.

-spec decode_address(binary()) ->
    {ok, inet:ip_address(), 4 | 6} | error.
decode_address(<<A, B, C, D>>) ->
    {ok, {A, B, C, D}, 4};
decode_address(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {ok, {A, B, C, D, E, F, G, H}, 6};
decode_address(_Address) ->
    error.

-spec encode_address(inet:ip_address()) -> {ok, binary()} | error.
encode_address({A, B, C, D}) ->
    {ok, <<A, B, C, D>>};
encode_address({A, B, C, D, E, F, G, H}) ->
    {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
encode_address(_Address) ->
    error.

%% Map one POSIX reason onto the small integer the Gleam side decodes. Code 8
%% is the catch-all, so a reason that needs its own name takes the next number
%% above it: 9 is emsgsize, which a Don't-Fragment socket returns for a
%% datagram larger than the local interface carries whole and which the path
%% MTU search owns rather than the socket.
-spec error_code(term()) -> 2..9.
error_code(timeout) -> 2;
error_code(closed) -> 3;
error_code(not_owner) -> 3;
error_code(eacces) -> 4;
error_code(eperm) -> 4;
error_code(eaddrinuse) -> 5;
error_code(eaddrnotavail) -> 6;
error_code(enoprotoopt) -> 7;
error_code(eafnosupport) -> 6;
error_code(emsgsize) -> 9;
error_code(_Reason) -> 8.
