%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_masque_packet_too_big_ffi).

-export([
    build/7,
    claim/2,
    diagnostics_buffered/2,
    diagnostics_new/2,
    diagnostics_record/8,
    diagnostics_snapshot/1,
    deliver/7,
    new_limiter/1,
    send/7
]).

-define(MAXIMUM_RESPONSE_BURST, 10).
-define(RESPONSE_REFILL_PER_SECOND, 10).
-define(TOKEN_UNITS, 1000).
-define(MAXIMUM_SEND_DEADLINE_MILLISECONDS, 100).
-define(MAXIMUM_COUNTER, 9223372036854775807).
-define(MAXIMUM_SNAPSHOT_RETRIES, 64).
-define(MAXIMUM_WRITE_LOCK_RETRIES, 64).

-define(SEQUENCE, 1).
-define(TARGET_PAYLOAD_LIMIT, 2).
-define(BUFFERED_EVENTS, 3).
-define(OVERSIZED_TARGET_PACKETS, 4).
-define(OVERSIZED_TARGET_BYTES, 5).
-define(DELIVERY_ATTEMPTS, 6).
-define(DELIVERED_MESSAGES, 7).
-define(DELIVERED_BYTES, 8).
-define(RATE_LIMITED, 9).
-define(PERMISSION_DENIED, 10).
-define(UNSUPPORTED, 11).
-define(TIMED_OUT, 12).
-define(PROHIBITED, 13).
-define(FAILURES, 14).
-define(CACHED_RESULTS, 15).
-define(MAXIMUM_QUOTE_BYTES, 16).
-define(ADVERTISED_MTU_BYTES, 17).
-define(MAXIMUM_SEND_MICROSECONDS, 18).
-define(TOKEN_BALANCE, 19).
-define(TOKEN_TIMESTAMP_MILLISECONDS, 20).
-define(PERMANENT_CAPABILITY, 21).

-type socket_family() :: 4 | 6.
-type delivery() :: 1..7.
-type diagnostics() :: #{
    tag := http_masque_packet_too_big_diagnostics,
    counters := atomics:atomics_ref()
}.
-type limiter() :: {
    http_masque_packet_too_big_limiter,
    non_neg_integer(),
    integer()
}.

%% Delivery codes are deliberately payload-free and stable at the FFI edge:
%% 1 delivered, 2 rate-limited, 3 permission-denied, 4 unsupported,
%% 5 other failure, 6 prohibited source, 7 timed out.

-spec diagnostics_new(non_neg_integer(), socket_family()) -> diagnostics().
diagnostics_new(TargetPayloadLimit, Family)
    when is_integer(TargetPayloadLimit), TargetPayloadLimit >= 0,
         TargetPayloadLimit =< 65527, (Family =:= 4 orelse Family =:= 6) ->
    Counters = atomics:new(21, [{signed, true}]),
    atomics:put(Counters, ?TARGET_PAYLOAD_LIMIT, TargetPayloadLimit),
    atomics:put(
        Counters,
        ?ADVERTISED_MTU_BYTES,
        advertised_mtu(Family, TargetPayloadLimit)
    ),
    atomics:put(
        Counters,
        ?TOKEN_BALANCE,
        ?MAXIMUM_RESPONSE_BURST * ?TOKEN_UNITS
    ),
    atomics:put(
        Counters,
        ?TOKEN_TIMESTAMP_MILLISECONDS,
        erlang:monotonic_time(millisecond)
    ),
    #{
        tag => http_masque_packet_too_big_diagnostics,
        counters => Counters
    }.

-spec diagnostics_buffered(diagnostics(), boolean()) -> ok.
diagnostics_buffered(Diagnostics, Buffered) when is_boolean(Buffered) ->
    with_write_lock(Diagnostics, fun(Counters) ->
        atomics:put(Counters, ?BUFFERED_EVENTS, boolean_integer(Buffered))
    end);
diagnostics_buffered(_Diagnostics, _Buffered) ->
    ok.

-spec diagnostics_record(
    diagnostics(), non_neg_integer(), delivery(), boolean(), boolean(),
    non_neg_integer(), non_neg_integer(), non_neg_integer()
) -> ok.
diagnostics_record(
    Diagnostics,
    PayloadBytes,
    Delivery,
    Attempted,
    Cached,
    SentBytes,
    QuoteBytes,
    SendMicroseconds
)
    when is_integer(PayloadBytes), PayloadBytes >= 0,
         is_integer(Delivery), Delivery >= 1, Delivery =< 7,
         is_boolean(Attempted), is_boolean(Cached),
         is_integer(SentBytes), SentBytes >= 0,
         is_integer(QuoteBytes), QuoteBytes >= 0,
         is_integer(SendMicroseconds), SendMicroseconds >= 0 ->
    with_write_lock(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?OVERSIZED_TARGET_PACKETS),
        saturating_add(Counters, ?OVERSIZED_TARGET_BYTES, PayloadBytes),
        maybe_increment(Counters, ?DELIVERY_ATTEMPTS, Attempted),
        maybe_increment(Counters, ?CACHED_RESULTS, Cached),
        record_delivery(Counters, Delivery, SentBytes),
        put_maximum(Counters, ?MAXIMUM_QUOTE_BYTES, QuoteBytes),
        put_maximum(
            Counters, ?MAXIMUM_SEND_MICROSECONDS, SendMicroseconds
        )
    end);
diagnostics_record(
    _Diagnostics,
    _PayloadBytes,
    _Delivery,
    _Attempted,
    _Cached,
    _SentBytes,
    _QuoteBytes,
    _SendMicroseconds
) ->
    ok.

%% Apply the per-tunnel token bucket and permanent capability cache before a
%% raw socket is opened. Every oversized packet receives exactly one terminal
%% diagnostic outcome, while only an uncached and admitted outcome performs a
%% privileged operating-system operation.
-spec deliver(
    diagnostics(), socket_family(), gen_udp:socket(), inet:ip_address(),
    inet:port_number(), binary(), pos_integer()
) -> {delivery(), non_neg_integer(), non_neg_integer()}.
deliver(
    Diagnostics,
    Family,
    UdpSocket,
    PeerAddress,
    PeerPort,
    Payload,
    RequestedTimeout
) ->
    MaximumPayload = target_payload_limit(Diagnostics),
    Now = erlang:monotonic_time(millisecond),
    case reserve_delivery(Diagnostics, Now) of
        rate_limited ->
            Mtu = advertised_mtu(Family, MaximumPayload),
            ok = diagnostics_record(
                Diagnostics,
                byte_size(Payload),
                2,
                false,
                false,
                0,
                0,
                0
            ),
            {2, Mtu, 0};
        {cached, Delivery} ->
            Mtu = advertised_mtu(Family, MaximumPayload),
            ok = diagnostics_record(
                Diagnostics,
                byte_size(Payload),
                Delivery,
                false,
                true,
                0,
                0,
                0
            ),
            {Delivery, Mtu, 0};
        attempt ->
            {Delivery, Mtu, QuoteBytes, SentBytes, Elapsed} = send(
                Family,
                UdpSocket,
                PeerAddress,
                PeerPort,
                Payload,
                MaximumPayload,
                RequestedTimeout
            ),
            maybe_cache_capability(Diagnostics, Delivery),
            ok = diagnostics_record(
                Diagnostics,
                byte_size(Payload),
                Delivery,
                Delivery =/= 6,
                false,
                SentBytes,
                QuoteBytes,
                Elapsed
            ),
            {Delivery, Mtu, QuoteBytes}
    end.

-spec diagnostics_snapshot(term()) -> tuple().
diagnostics_snapshot(Diagnostics) ->
    case valid_diagnostics(Diagnostics) of
        false -> default_snapshot(false);
        true -> diagnostics_snapshot(Diagnostics, ?MAXIMUM_SNAPSHOT_RETRIES)
    end.

-spec new_limiter(integer()) -> limiter().
new_limiter(NowMilliseconds) when is_integer(NowMilliseconds) ->
    {
        http_masque_packet_too_big_limiter,
        ?MAXIMUM_RESPONSE_BURST * ?TOKEN_UNITS,
        NowMilliseconds
    }.

-spec claim(limiter(), integer()) -> {0 | 1, limiter()}.
claim(
    {http_masque_packet_too_big_limiter, Units, LastMilliseconds},
    NowMilliseconds
)
    when is_integer(Units), Units >= 0,
         is_integer(LastMilliseconds), is_integer(NowMilliseconds) ->
    Elapsed = erlang:max(0, NowMilliseconds - LastMilliseconds),
    Capacity = ?MAXIMUM_RESPONSE_BURST * ?TOKEN_UNITS,
    Refilled = erlang:min(
        Capacity,
        Units + Elapsed * ?RESPONSE_REFILL_PER_SECOND
    ),
    NextMilliseconds = erlang:max(LastMilliseconds, NowMilliseconds),
    case Refilled >= ?TOKEN_UNITS of
        true ->
            {
                1,
                {
                    http_masque_packet_too_big_limiter,
                    Refilled - ?TOKEN_UNITS,
                    NextMilliseconds
                }
            };
        false ->
            {
                0,
                {
                    http_masque_packet_too_big_limiter,
                    Refilled,
                    NextMilliseconds
                }
            }
    end;
claim(_Limiter, NowMilliseconds) ->
    {0, new_limiter(NowMilliseconds)}.

%% Build the ICMP body only. The raw socket supplies the outer IP header.
%% The quoted invoking packet is canonicalized from the connected UDP tuple
%% and the exact received payload so that the target kernel can identify the
%% originating UDP flow without retaining any packet after this call.
-spec build(
    socket_family(), inet:ip_address(), inet:port_number(),
    inet:ip_address(), inet:port_number(), binary(), non_neg_integer()
) -> {ok, binary(), non_neg_integer(), non_neg_integer()} |
     {error, 5 | 6}.
build(
    Family,
    LocalAddress,
    LocalPort,
    PeerAddress,
    PeerPort,
    Payload,
    MaximumPayload
)
    when (Family =:= 4 orelse Family =:= 6),
         is_integer(LocalPort), LocalPort > 0, LocalPort =< 65535,
         is_integer(PeerPort), PeerPort > 0, PeerPort =< 65535,
         is_binary(Payload),
         is_integer(MaximumPayload), MaximumPayload >= 0,
         MaximumPayload =< 65527 ->
    case eligible_unicast(Family, LocalAddress, PeerAddress) of
        false ->
            {error, 6};
        true ->
            build_family(
                Family,
                LocalAddress,
                LocalPort,
                PeerAddress,
                PeerPort,
                Payload,
                MaximumPayload
            )
    end;
build(
    _Family,
    _LocalAddress,
    _LocalPort,
    _PeerAddress,
    _PeerPort,
    _Payload,
    _MaximumPayload
) ->
    {error, 5}.

-spec send(
    socket_family(), gen_udp:socket(), inet:ip_address(), inet:port_number(),
    binary(), non_neg_integer(), pos_integer()
) -> {delivery(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
       non_neg_integer()}.
send(
    Family,
    UdpSocket,
    PeerAddress,
    PeerPort,
    Payload,
    MaximumPayload,
    RequestedTimeout
) ->
    Started = erlang:monotonic_time(microsecond),
    Timeout = bounded_timeout(RequestedTimeout),
    Result = case inet:sockname(UdpSocket) of
        {ok, {LocalAddress, LocalPort}} ->
            case build(
                Family,
                LocalAddress,
                LocalPort,
                PeerAddress,
                PeerPort,
                Payload,
                MaximumPayload
            ) of
                {error, BuildDelivery} ->
                    {BuildDelivery, advertised_mtu(Family, MaximumPayload), 0, 0};
                {ok, Message, BuiltMtu, BuiltQuoteBytes} ->
                    case send_raw(
                        Family,
                        LocalAddress,
                        PeerAddress,
                        Message,
                        Timeout
                    ) of
                        1 ->
                            {1, BuiltMtu, BuiltQuoteBytes, byte_size(Message)};
                        RawDelivery ->
                            {RawDelivery, BuiltMtu, BuiltQuoteBytes, 0}
                    end
            end;
        {error, _Reason} ->
            {5, advertised_mtu(Family, MaximumPayload), 0, 0}
    end,
    Finished = erlang:monotonic_time(microsecond),
    {FinalDelivery, FinalMtu, FinalQuoteBytes, FinalSentBytes} = Result,
    {
        FinalDelivery,
        FinalMtu,
        FinalQuoteBytes,
        FinalSentBytes,
        erlang:max(0, Finished - Started)
    }.

-spec build_family(
    socket_family(), inet:ip_address(), inet:port_number(),
    inet:ip_address(), inet:port_number(), binary(), non_neg_integer()
) -> {ok, binary(), non_neg_integer(), non_neg_integer()} | {error, 5}.
build_family(4, LocalAddress, LocalPort, PeerAddress, PeerPort, Payload,
             MaximumPayload) ->
    case {ipv4_bytes(LocalAddress), ipv4_bytes(PeerAddress)} of
        {{ok, LocalBytes}, {ok, PeerBytes}} ->
            UdpLength = 8 + byte_size(Payload),
            TotalLength = 20 + UdpLength,
            case UdpLength =< 65535 andalso TotalLength =< 65535 of
                false ->
                    {error, 5};
                true ->
                    Udp = udp_ipv4(
                        PeerBytes,
                        LocalBytes,
                        PeerPort,
                        LocalPort,
                        Payload
                    ),
                    Header0 = <<
                        4:4, 5:4, 0:8, TotalLength:16,
                        0:16, 0:16, 64:8, 17:8, 0:16,
                        PeerBytes/binary, LocalBytes/binary
                    >>,
                    HeaderChecksum = internet_checksum(Header0),
                    Header = <<
                        4:4, 5:4, 0:8, TotalLength:16,
                        0:16, 0:16, 64:8, 17:8, HeaderChecksum:16,
                        PeerBytes/binary, LocalBytes/binary
                    >>,
                    Quote = truncate_binary(
                        <<Header/binary, Udp/binary>>, 548
                    ),
                    Mtu = advertised_mtu(4, MaximumPayload),
                    Icmp0 = <<3, 4, 0:16, 0:16, Mtu:16, Quote/binary>>,
                    IcmpChecksum = internet_checksum(Icmp0),
                    Message = <<
                        3, 4, IcmpChecksum:16, 0:16, Mtu:16, Quote/binary
                    >>,
                    {ok, Message, Mtu, byte_size(Quote)}
            end;
        _ ->
            {error, 5}
    end;
build_family(6, LocalAddress, LocalPort, PeerAddress, PeerPort, Payload,
             MaximumPayload) ->
    case {ipv6_bytes(LocalAddress), ipv6_bytes(PeerAddress)} of
        {{ok, LocalBytes}, {ok, PeerBytes}} ->
            UdpLength = 8 + byte_size(Payload),
            case UdpLength =< 65535 of
                false ->
                    {error, 5};
                true ->
                    Udp = udp_ipv6(
                        PeerBytes,
                        LocalBytes,
                        PeerPort,
                        LocalPort,
                        Payload
                    ),
                    Header = <<
                        6:4, 0:8, 0:20, UdpLength:16,
                        17:8, 64:8, PeerBytes/binary, LocalBytes/binary
                    >>,
                    Quote = truncate_binary(
                        <<Header/binary, Udp/binary>>, 1232
                    ),
                    Mtu = advertised_mtu(6, MaximumPayload),
                    Icmp0 = <<2, 0, 0:16, Mtu:32, Quote/binary>>,
                    IcmpLength = byte_size(Icmp0),
                    PseudoHeader = <<
                        LocalBytes/binary,
                        PeerBytes/binary,
                        IcmpLength:32,
                        0:24,
                        58:8,
                        Icmp0/binary
                    >>,
                    IcmpChecksum = internet_checksum(PseudoHeader),
                    Message = <<
                        2, 0, IcmpChecksum:16, Mtu:32, Quote/binary
                    >>,
                    {ok, Message, Mtu, byte_size(Quote)}
            end;
        _ ->
            {error, 5}
    end.

-spec udp_ipv4(binary(), binary(), inet:port_number(), inet:port_number(),
               binary()) -> binary().
udp_ipv4(Source, Destination, SourcePort, DestinationPort, Payload) ->
    Length = 8 + byte_size(Payload),
    Header0 = <<SourcePort:16, DestinationPort:16, Length:16, 0:16>>,
    Pseudo = <<
        Source/binary, Destination/binary, 0, 17, Length:16,
        Header0/binary, Payload/binary
    >>,
    Checksum = udp_checksum(internet_checksum(Pseudo)),
    <<
        SourcePort:16, DestinationPort:16, Length:16, Checksum:16,
        Payload/binary
    >>.

-spec udp_ipv6(binary(), binary(), inet:port_number(), inet:port_number(),
               binary()) -> binary().
udp_ipv6(Source, Destination, SourcePort, DestinationPort, Payload) ->
    Length = 8 + byte_size(Payload),
    Header0 = <<SourcePort:16, DestinationPort:16, Length:16, 0:16>>,
    Pseudo = <<
        Source/binary, Destination/binary, Length:32, 0:24, 17,
        Header0/binary, Payload/binary
    >>,
    Checksum = udp_checksum(internet_checksum(Pseudo)),
    <<
        SourcePort:16, DestinationPort:16, Length:16, Checksum:16,
        Payload/binary
    >>.

-spec udp_checksum(0..65535) -> 1..65535.
udp_checksum(0) -> 65535;
udp_checksum(Value) -> Value.

-spec internet_checksum(binary()) -> 0..65535.
internet_checksum(Bytes) ->
    Sum = checksum_words(Bytes, 0),
    Folded = fold_checksum(Sum),
    Folded bxor 16#ffff.

-spec checksum_words(binary(), non_neg_integer()) -> non_neg_integer().
checksum_words(<<Word:16, Rest/binary>>, Sum) ->
    checksum_words(Rest, Sum + Word);
checksum_words(<<Byte>>, Sum) ->
    Sum + (Byte bsl 8);
checksum_words(<<>>, Sum) ->
    Sum.

-spec fold_checksum(non_neg_integer()) -> 0..65535.
fold_checksum(Sum) when Sum > 16#ffff ->
    fold_checksum((Sum band 16#ffff) + (Sum bsr 16));
fold_checksum(Sum) ->
    Sum.

-spec send_raw(
    socket_family(), inet:ip_address(), inet:ip_address(), binary(),
    pos_integer()
) -> delivery().
send_raw(Family, LocalAddress, PeerAddress, Message, Timeout) ->
    {Domain, Protocol} = case Family of
        4 -> {inet, 1};
        6 -> {inet6, 58}
    end,
    case socket:open(Domain, raw, Protocol) of
        {error, Reason} ->
            socket_error_delivery(Reason);
        {ok, Socket} ->
            try
                Source = socket_address(Family, LocalAddress),
                Destination = socket_address(Family, PeerAddress),
                case socket:bind(Socket, Source) of
                    {error, Reason} -> socket_error_delivery(Reason);
                    ok ->
                        case socket:sendto(
                            Socket, Message, Destination, Timeout
                        ) of
                            ok -> 1;
                            {ok, <<>>} -> 1;
                            {ok, _Rest} -> 5;
                            {error, Reason} -> socket_error_delivery(Reason);
                            _Other -> 5
                        end
                end
            catch
                _:_ -> 5
            after
                try socket:close(Socket) of
                    _ -> ok
                catch
                    _:_ -> ok
                end
            end
    end.

-spec socket_address(socket_family(), inet:ip_address()) -> map().
socket_address(4, Address) ->
    #{family => inet, addr => Address, port => 0};
socket_address(6, Address) ->
    #{family => inet6, addr => Address, port => 0, flowinfo => 0, scope_id => 0}.

-spec socket_error_delivery(term()) -> 3 | 4 | 5 | 7.
socket_error_delivery(eacces) -> 3;
socket_error_delivery(eperm) -> 3;
socket_error_delivery(eafnosupport) -> 4;
socket_error_delivery(epfnosupport) -> 4;
socket_error_delivery(eprotonosupport) -> 4;
socket_error_delivery(enoprotoopt) -> 4;
socket_error_delivery(enotsup) -> 4;
socket_error_delivery(eopnotsupp) -> 4;
socket_error_delivery(timeout) -> 7;
socket_error_delivery(etimedout) -> 7;
socket_error_delivery(_Reason) -> 5.

-spec eligible_unicast(
    socket_family(), inet:ip_address(), inet:ip_address()
) -> boolean().
eligible_unicast(4, Local, Peer) ->
    valid_ipv4_unicast(Local) andalso valid_ipv4_unicast(Peer);
eligible_unicast(6, Local, Peer) ->
    valid_ipv6_unicast(Local) andalso valid_ipv6_unicast(Peer).

-spec valid_ipv4_unicast(term()) -> boolean().
valid_ipv4_unicast({A, B, C, D})
    when A >= 0, A =< 255, B >= 0, B =< 255,
         C >= 0, C =< 255, D >= 0, D =< 255 ->
    not (
        A =:= 0 orelse A >= 224 orelse
        {A, B, C, D} =:= {255, 255, 255, 255}
    );
valid_ipv4_unicast(_Address) ->
    false.

-spec valid_ipv6_unicast(term()) -> boolean().
valid_ipv6_unicast(Address) ->
    case ipv6_bytes(Address) of
        {ok, <<16#ff, _/binary>>} -> false;
        {ok, <<0:128>>} -> false;
        {ok, _Bytes} -> true;
        error -> false
    end.

-spec ipv4_bytes(term()) -> {ok, binary()} | error.
ipv4_bytes({A, B, C, D})
    when A >= 0, A =< 255, B >= 0, B =< 255,
         C >= 0, C =< 255, D >= 0, D =< 255 ->
    {ok, <<A, B, C, D>>};
ipv4_bytes(_Address) ->
    error.

-spec ipv6_bytes(term()) -> {ok, binary()} | error.
ipv6_bytes({A, B, C, D, E, F, G, H})
    when A >= 0, A =< 65535, B >= 0, B =< 65535,
         C >= 0, C =< 65535, D >= 0, D =< 65535,
         E >= 0, E =< 65535, F >= 0, F =< 65535,
         G >= 0, G =< 65535, H >= 0, H =< 65535 ->
    {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
ipv6_bytes(_Address) ->
    error.

-spec advertised_mtu(socket_family(), non_neg_integer()) -> non_neg_integer().
advertised_mtu(4, MaximumPayload) ->
    erlang:min(65535, MaximumPayload + 28);
advertised_mtu(6, MaximumPayload) ->
    MaximumPayload + 48.

-spec truncate_binary(binary(), non_neg_integer()) -> binary().
truncate_binary(Bytes, Maximum) when byte_size(Bytes) =< Maximum ->
    Bytes;
truncate_binary(Bytes, Maximum) ->
    binary:part(Bytes, 0, Maximum).

-spec bounded_timeout(term()) -> pos_integer().
bounded_timeout(Value) when is_integer(Value), Value > 0 ->
    erlang:min(Value, ?MAXIMUM_SEND_DEADLINE_MILLISECONDS);
bounded_timeout(_Value) ->
    1.

-spec diagnostics_snapshot(diagnostics(), non_neg_integer()) -> tuple().
diagnostics_snapshot(Diagnostics, 0) ->
    snapshot_values(Diagnostics, false);
diagnostics_snapshot(#{counters := Counters} = Diagnostics, Remaining) ->
    SequenceBefore = safe_atomic_get(Counters, ?SEQUENCE, 1),
    case SequenceBefore band 1 of
        1 ->
            erlang:yield(),
            diagnostics_snapshot(Diagnostics, Remaining - 1);
        0 ->
            Snapshot = snapshot_values(Diagnostics, true),
            SequenceAfter = safe_atomic_get(Counters, ?SEQUENCE, 1),
            case SequenceBefore =:= SequenceAfter andalso
                 SequenceAfter band 1 =:= 0 of
                true -> Snapshot;
                false ->
                    erlang:yield(),
                    diagnostics_snapshot(Diagnostics, Remaining - 1)
            end
    end.

-spec snapshot_values(diagnostics(), boolean()) -> tuple().
snapshot_values(#{counters := Counters}, Consistent) ->
    {
        Consistent,
        safe_atomic_get(Counters, ?TARGET_PAYLOAD_LIMIT, 0),
        ?MAXIMUM_RESPONSE_BURST,
        ?RESPONSE_REFILL_PER_SECOND,
        ?MAXIMUM_SEND_DEADLINE_MILLISECONDS,
        safe_atomic_get(Counters, ?BUFFERED_EVENTS, 0),
        0,
        safe_atomic_get(Counters, ?OVERSIZED_TARGET_PACKETS, 0),
        safe_atomic_get(Counters, ?OVERSIZED_TARGET_BYTES, 0),
        safe_atomic_get(Counters, ?DELIVERY_ATTEMPTS, 0),
        safe_atomic_get(Counters, ?DELIVERED_MESSAGES, 0),
        safe_atomic_get(Counters, ?DELIVERED_BYTES, 0),
        safe_atomic_get(Counters, ?RATE_LIMITED, 0),
        safe_atomic_get(Counters, ?PERMISSION_DENIED, 0),
        safe_atomic_get(Counters, ?UNSUPPORTED, 0),
        safe_atomic_get(Counters, ?TIMED_OUT, 0),
        safe_atomic_get(Counters, ?PROHIBITED, 0),
        safe_atomic_get(Counters, ?FAILURES, 0),
        safe_atomic_get(Counters, ?CACHED_RESULTS, 0),
        safe_atomic_get(Counters, ?MAXIMUM_QUOTE_BYTES, 0),
        safe_atomic_get(Counters, ?ADVERTISED_MTU_BYTES, 0),
        safe_atomic_get(Counters, ?MAXIMUM_SEND_MICROSECONDS, 0)
    }.

-spec default_snapshot(boolean()) -> tuple().
default_snapshot(Consistent) ->
    {
        Consistent, 0, ?MAXIMUM_RESPONSE_BURST,
        ?RESPONSE_REFILL_PER_SECOND, ?MAXIMUM_SEND_DEADLINE_MILLISECONDS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    }.

-spec with_write_lock(diagnostics(), fun((atomics:atomics_ref()) -> term())) ->
    ok.
with_write_lock(#{counters := Counters}, Update) ->
    case acquire_write_lock(Counters) of
        {ok, Sequence} ->
            try Update(Counters) of
                _ -> ok
            catch
                _:_ -> ok
            after
                atomics:put(Counters, ?SEQUENCE, Sequence + 2)
            end;
        error -> ok
    end;
with_write_lock(_Diagnostics, _Update) ->
    ok.

-spec acquire_write_lock(atomics:atomics_ref()) ->
    {ok, non_neg_integer()} | error.
acquire_write_lock(Counters) ->
    acquire_write_lock(Counters, ?MAXIMUM_WRITE_LOCK_RETRIES).

-spec acquire_write_lock(atomics:atomics_ref(), non_neg_integer()) ->
    {ok, non_neg_integer()} | error.
acquire_write_lock(_Counters, 0) ->
    error;
acquire_write_lock(Counters, Remaining) ->
    Sequence = safe_atomic_get(Counters, ?SEQUENCE, 1),
    case Sequence band 1 of
        1 ->
            erlang:yield(),
            acquire_write_lock(Counters, Remaining - 1);
        0 ->
            try atomics:compare_exchange(
                Counters, ?SEQUENCE, Sequence, Sequence + 1
            ) of
                ok -> {ok, Sequence};
                _ -> acquire_write_lock(Counters, Remaining - 1)
            catch
                _:_ -> error
            end
    end.

-spec record_delivery(
    atomics:atomics_ref(), delivery(), non_neg_integer()
) -> ok.
record_delivery(Counters, 1, SentBytes) ->
    saturating_increment(Counters, ?DELIVERED_MESSAGES),
    saturating_add(Counters, ?DELIVERED_BYTES, SentBytes);
record_delivery(Counters, 2, _SentBytes) ->
    saturating_increment(Counters, ?RATE_LIMITED);
record_delivery(Counters, 3, _SentBytes) ->
    saturating_increment(Counters, ?PERMISSION_DENIED);
record_delivery(Counters, 4, _SentBytes) ->
    saturating_increment(Counters, ?UNSUPPORTED);
record_delivery(Counters, 5, _SentBytes) ->
    saturating_increment(Counters, ?FAILURES);
record_delivery(Counters, 6, _SentBytes) ->
    saturating_increment(Counters, ?PROHIBITED);
record_delivery(Counters, 7, _SentBytes) ->
    saturating_increment(Counters, ?TIMED_OUT).

-spec target_payload_limit(diagnostics()) -> non_neg_integer().
target_payload_limit(#{counters := Counters}) ->
    safe_atomic_get(Counters, ?TARGET_PAYLOAD_LIMIT, 0);
target_payload_limit(_Diagnostics) ->
    0.

-spec reserve_delivery(term(), integer()) ->
    attempt | rate_limited | {cached, 3 | 4}.
reserve_delivery(#{counters := Counters} = Diagnostics, Now) ->
    acquire_delivery_lock(Diagnostics, Counters, Now).

-spec acquire_delivery_lock(
    diagnostics(), atomics:atomics_ref(), integer()
) -> attempt | rate_limited | {cached, 3 | 4}.
acquire_delivery_lock(_Diagnostics, Counters, Now) ->
    case acquire_write_lock(Counters) of
        error ->
            rate_limited;
        {ok, Sequence} ->
            try
                Permanent = safe_atomic_get(
                    Counters, ?PERMANENT_CAPABILITY, 0
                ),
                Units = safe_atomic_get(Counters, ?TOKEN_BALANCE, 0),
                Last = safe_atomic_integer(
                    Counters, ?TOKEN_TIMESTAMP_MILLISECONDS, Now
                ),
                {Allowed, {
                    http_masque_packet_too_big_limiter,
                    NextUnits,
                    NextTimestamp
                }} = claim(
                    {
                        http_masque_packet_too_big_limiter,
                        Units,
                        Last
                    },
                    Now
                ),
                atomics:put(Counters, ?TOKEN_BALANCE, NextUnits),
                atomics:put(
                    Counters,
                    ?TOKEN_TIMESTAMP_MILLISECONDS,
                    NextTimestamp
                ),
                case {Allowed, Permanent} of
                    {0, _} -> rate_limited;
                    {1, 3} -> {cached, 3};
                    {1, 4} -> {cached, 4};
                    {1, _} -> attempt
                end
            catch
                _:_ -> rate_limited
            after
                atomics:put(Counters, ?SEQUENCE, Sequence + 2)
            end
    end.

-spec maybe_cache_capability(diagnostics(), delivery()) -> ok.
maybe_cache_capability(#{counters := Counters}, Delivery)
    when Delivery =:= 3; Delivery =:= 4 ->
    with_write_lock(
        #{
            tag => http_masque_packet_too_big_diagnostics,
            counters => Counters
        },
        fun(State) ->
            atomics:put(State, ?PERMANENT_CAPABILITY, Delivery)
        end
    );
maybe_cache_capability(_Diagnostics, _Delivery) ->
    ok.

-spec maybe_increment(atomics:atomics_ref(), pos_integer(), boolean()) -> ok.
maybe_increment(Counters, Index, true) ->
    saturating_increment(Counters, Index);
maybe_increment(_Counters, _Index, false) ->
    ok.

-spec put_maximum(
    atomics:atomics_ref(), pos_integer(), non_neg_integer()
) -> ok.
put_maximum(Counters, Index, Value) ->
    Current = safe_atomic_get(Counters, Index, 0),
    case Value =< Current of
        true -> ok;
        false -> atomics:put(Counters, Index, Value)
    end.

-spec saturating_increment(atomics:atomics_ref(), pos_integer()) -> ok.
saturating_increment(Counters, Index) ->
    saturating_add(Counters, Index, 1).

-spec saturating_add(
    atomics:atomics_ref(), pos_integer(), non_neg_integer()
) -> ok.
saturating_add(_Counters, _Index, 0) ->
    ok;
saturating_add(Counters, Index, Amount) ->
    Current = safe_atomic_get(Counters, Index, 0),
    Next = case Amount >= ?MAXIMUM_COUNTER - Current of
        true -> ?MAXIMUM_COUNTER;
        false -> Current + Amount
    end,
    atomics:put(Counters, Index, Next).

-spec boolean_integer(boolean()) -> 0 | 1.
boolean_integer(true) -> 1;
boolean_integer(false) -> 0.

-spec valid_diagnostics(term()) -> boolean().
valid_diagnostics(#{
    tag := http_masque_packet_too_big_diagnostics,
    counters := Counters
}) ->
    try atomics:get(Counters, ?SEQUENCE) of
        _ -> true
    catch
        _:_ -> false
    end;
valid_diagnostics(_Diagnostics) ->
    false.

-spec safe_atomic_get(
    atomics:atomics_ref(), pos_integer(), integer()
) -> integer().
safe_atomic_get(Counters, Index, Default) ->
    try atomics:get(Counters, Index) of
        Value when is_integer(Value), Value >= 0 -> Value;
        _ -> Default
    catch
        _:_ -> Default
    end.

%% BEAM monotonic time has an opaque epoch and commonly uses negative values.
%% Keep signed time state separate from the non-negative diagnostic counters so
%% counter corruption remains fail-closed without disabling legitimate refill.
-spec safe_atomic_integer(
    atomics:atomics_ref(), pos_integer(), integer()
) -> integer().
safe_atomic_integer(Counters, Index, Default) ->
    try atomics:get(Counters, Index) of
        Value -> Value
    catch
        _:_ -> Default
    end.
