-module(gleam_quic_udp_ffi).

-on_load(init/0).

-export([
    active_datagram/2,
    active_once/1,
    close/1,
    continue_relay/1,
    local_endpoint/1,
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

-define(CLOCK_ORIGIN, {?MODULE, clock_origin}).
-define(DEFAULT_SOCKET_BUFFER_BYTES, 4 * 1024 * 1024).
-define(MAXIMUM_RESOLVED_ADDRESSES, 16).

-type handle() :: #{socket := gen_udp:socket(), family := 4 | 6, ecn := boolean()}.
-type relay() :: #{pid := pid(), reference := reference(), socket := gen_udp:socket()}.

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
    BaseOptions = [
        binary,
        {active, false},
        {reuseaddr, true},
        {recbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {sndbuf, ?DEFAULT_SOCKET_BUFFER_BYTES},
        {ip, {0, 0, 0, 0, 0, 0, 0, 0}},
        inet6,
        {ipv6_v6only, false}
    ],
    case gen_udp:open(Port, [{recvtclass, true} | BaseOptions]) of
        {ok, Socket} ->
            {ok, #{socket => Socket, family => 6, ecn => true}};
        {error, Reason} when Reason =:= einval; Reason =:= enoprotoopt ->
            case gen_udp:open(Port, BaseOptions) of
                {ok, Socket} ->
                    {ok, #{socket => Socket, family => 6, ecn => false}};
                {error, FallbackReason} ->
                    {error, error_code(FallbackReason)}
            end;
        {error, Reason} ->
            {error, error_code(Reason)}
    end;
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
send(#{socket := Socket, family := Family, ecn := EcnSupported}, Address,
     Port, Payload, Ecn)
    when is_binary(Address), is_integer(Port), Port > 0, Port =< 65535,
         is_binary(Payload), byte_size(Payload) =< 65527,
         is_integer(Ecn), Ecn >= 0, Ecn =< 2 ->
    case decode_address(Address) of
        {ok, IpAddress, Family} ->
            send_datagram(Socket, Family, EcnSupported, IpAddress, Port, Payload, Ecn);
        _Other ->
            {error, 1}
    end;
send(_Socket, _Address, _Port, _Payload, _Ecn) ->
    {error, 1}.

-spec recv(handle(), integer()) ->
    {ok, {binary(), integer(), binary(), 0..3}} | {error, integer()}.
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
start_relay(#{socket := Socket}) ->
    Owner = self(),
    Reference = make_ref(),
    Relay = spawn(fun() ->
        nil = gleam_quic_process_label_ffi:set_role(5),
        receive
            {start, Owner, Reference, Socket} ->
                Monitor = erlang:monitor(process, Owner),
                relay_loop(Socket, Owner, Reference, Monitor)
        end
    end),
    case gen_udp:controlling_process(Socket, Relay) of
        ok ->
            Relay ! {start, Owner, Reference, Socket},
            {ok, #{pid => Relay, reference => Reference, socket => Socket}};
        {error, Reason} ->
            exit(Relay, kill),
            {error, error_code(Reason)}
    end;
start_relay(_Socket) ->
    {error, 1}.

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

-spec supports_ecn(term()) -> boolean().
supports_ecn(#{ecn := Supported}) -> Supported;
supports_ecn(_Socket) -> false.

-spec close(term()) -> {ok, nil} | {error, integer()}.
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
transfer_owner(#{socket := Socket}, Owner) when is_pid(Owner) ->
    try gen_udp:controlling_process(Socket, Owner) of
        ok -> {ok, nil};
        {error, Reason} -> {error, error_code(Reason)}
    catch
        _Class:_Reason -> {error, 3}
    end;
transfer_owner(_Socket, _Owner) ->
    {error, 1}.

-spec relay_loop(gen_udp:socket(), pid(), reference(), reference()) -> no_return().
relay_loop(Socket, Owner, Reference, Monitor) ->
    case inet:setopts(Socket, [{active, once}]) of
        ok -> relay_receive(Socket, Owner, Reference, Monitor);
        {error, Reason} ->
            Owner ! {gleam_quic_udp_batch, Reference,
                     {error, error_code(Reason)}},
            relay_wait(Socket, Owner, Reference, Monitor)
    end.

-spec relay_receive(gen_udp:socket(), pid(), reference(), reference()) ->
    no_return().
relay_receive(Socket, Owner, Reference, Monitor) ->
    receive
        {udp, Socket, Address, Port, Payload} ->
            relay_deliver(Socket, Owner, Reference, Monitor,
                          Address, Port, Payload, 0);
        {udp, Socket, Address, Port, Ancillary, Payload} ->
            relay_deliver(Socket, Owner, Reference, Monitor,
                          Address, Port, Payload, received_ecn(Ancillary));
        {udp_error, Socket, Reason}
            when Reason =:= econnreset; Reason =:= econnrefused;
                 Reason =:= ehostunreach; Reason =:= enetunreach ->
            %% A shared listener can receive an asynchronous ICMP error after
            %% replying to a client which has already closed its UDP socket.
            %% This is connection-local feedback, not a listener failure.
            relay_loop(Socket, Owner, Reference, Monitor);
        {udp_error, Socket, Reason} ->
            Owner ! {gleam_quic_udp_batch, Reference,
                     {error, error_code(Reason)}},
            relay_wait(Socket, Owner, Reference, Monitor);
        {udp_closed, Socket} ->
            Owner ! {gleam_quic_udp_batch, Reference, {error, 3}},
            exit(normal);
        {gleam_quic_udp_stop, Reference, Caller, StopReference} ->
            relay_close(Socket, Caller, StopReference);
        {'DOWN', Monitor, process, Owner, _Reason} ->
            _ = gen_udp:close(Socket),
            exit(normal)
    end.

-spec relay_deliver(
    gen_udp:socket(), pid(), reference(), reference(), inet:ip_address(),
    inet:port_number(), binary(), 0..3
) -> no_return().
relay_deliver(Socket, Owner, Reference, Monitor,
              Address, Port, Payload, Ecn) ->
    case normalise_relay_datagram(Address, Port, Payload, Ecn) of
        {error, Code} ->
            Owner ! {gleam_quic_udp_batch, Reference, {error, Code}};
        {ok, First} ->
            Batch = drain_relay_batch(
                Socket, ?MAXIMUM_RELAY_BATCH - 1, [First]
            ),
            Owner ! {gleam_quic_udp_batch, Reference, {ok, Batch}}
    end,
    relay_wait(Socket, Owner, Reference, Monitor).

-spec relay_wait(gen_udp:socket(), pid(), reference(), reference()) ->
    no_return().
relay_wait(Socket, Owner, Reference, Monitor) ->
    receive
        {gleam_quic_udp_continue, Reference} ->
            relay_loop(Socket, Owner, Reference, Monitor);
        {gleam_quic_udp_stop, Reference, Caller, StopReference} ->
            relay_close(Socket, Caller, StopReference);
        {'DOWN', Monitor, process, Owner, _Reason} ->
            _ = gen_udp:close(Socket),
            exit(normal)
    end.

-spec relay_close(gen_udp:socket(), pid(), reference()) -> no_return().
relay_close(Socket, Caller, StopReference) ->
    _ = gen_udp:close(Socket),
    Caller ! {gleam_quic_udp_stopped, StopReference},
    exit(normal).

-spec drain_relay_batch(
    gen_udp:socket(), non_neg_integer(),
    [{binary(), integer(), binary(), 0..3}]
) -> [{binary(), integer(), binary(), 0..3}].
drain_relay_batch(_Socket, 0, Reversed) ->
    lists:reverse(Reversed);
drain_relay_batch(Socket, Remaining, Reversed) ->
    case gen_udp:recv(Socket, 0, 0) of
        {ok, {Address, Port, Payload}} ->
            drain_normalised(Socket, Remaining, Reversed,
                             Address, Port, Payload, 0);
        {ok, {Address, Port, Ancillary, Payload}} ->
            drain_normalised(Socket, Remaining, Reversed,
                             Address, Port, Payload, received_ecn(Ancillary));
        {error, _Reason} ->
            lists:reverse(Reversed)
    end.

-spec drain_normalised(
    gen_udp:socket(), pos_integer(),
    [{binary(), integer(), binary(), 0..3}], inet:ip_address(),
    inet:port_number(), binary(), 0..3
) -> [{binary(), integer(), binary(), 0..3}].
drain_normalised(Socket, Remaining, Reversed,
                 Address, Port, Payload, Ecn) ->
    case normalise_relay_datagram(Address, Port, Payload, Ecn) of
        {ok, Datagram} ->
            drain_relay_batch(Socket, Remaining - 1, [Datagram | Reversed]);
        {error, _Code} ->
            drain_relay_batch(Socket, Remaining - 1, Reversed)
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
    case gen_udp:open(Port, [EcnOption | BaseOptions]) of
        {ok, Socket} ->
            {ok, #{socket => Socket, family => Family, ecn => true}};
        {error, Reason} when Reason =:= einval; Reason =:= enoprotoopt ->
            case gen_udp:open(Port, BaseOptions) of
                {ok, Socket} ->
                    {ok, #{socket => Socket, family => Family, ecn => false}};
                {error, FallbackReason} ->
                    {error, error_code(FallbackReason)}
            end;
        {error, Reason} ->
            {error, error_code(Reason)}
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
                interleave_addresses(V6, V4), ?MAXIMUM_RESOLVED_ADDRESSES
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
    try [Bytes || Address <- Addresses, {ok, Bytes} <- [encode_address(Address)]] of
        [] -> {error, 6};
        Encoded -> {ok, Encoded}
    catch
        _Class:_Reason -> {error, 8}
    end.

-spec family_options(4 | 6) -> [gen_udp:option()].
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

-spec error_code(term()) -> 2..8.
error_code(timeout) -> 2;
error_code(closed) -> 3;
error_code(not_owner) -> 3;
error_code(eacces) -> 4;
error_code(eperm) -> 4;
error_code(eaddrinuse) -> 5;
error_code(eaddrnotavail) -> 6;
error_code(enoprotoopt) -> 7;
error_code(eafnosupport) -> 6;
error_code(_Reason) -> 8.
