-module(gleam_quic_udp_ffi).

-on_load(init/0).

-export([
    close/1,
    local_endpoint/1,
    monotonic_millisecond/0,
    open/2,
    recv/2,
    send/5,
    supports_ecn/1
]).

-define(CLOCK_ORIGIN, {?MODULE, clock_origin}).

-type handle() :: #{socket := gen_udp:socket(), family := 4 | 6, ecn := boolean()}.

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

-spec monotonic_millisecond() -> non_neg_integer().
monotonic_millisecond() ->
    Origin = persistent_term:get(?CLOCK_ORIGIN),
    erlang:monotonic_time(millisecond) - Origin.

-spec open_address(inet:ip_address(), 4 | 6, inet:port_number()) ->
    {ok, handle()} | {error, integer()}.
open_address(Address, Family, Port) ->
    BaseOptions = [
        binary,
        {active, false},
        {reuseaddr, true},
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
