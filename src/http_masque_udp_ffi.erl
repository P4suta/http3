%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_masque_udp_ffi).

-export([
    adopt/3,
    close/2,
    idle_ack/1,
    idle_activity/3,
    idle_due/2,
    idle_new/2,
    idle_snapshot/1,
    idle_stop/1,
    open/4,
    open/5,
    packet_too_big_snapshot/1,
    recv/2,
    send/3,
    snapshot/1,
    wait_event/2,
    wait_event_forever/1
]).

-define(MAXIMUM_QUEUED_COMMANDS, 8).
-define(MAXIMUM_UDP_PAYLOAD_BYTES, 65527).
-define(SOCKET_BUFFER_BYTES, 262144).
-define(CALL_GRACE_MILLISECONDS, 1000).
-define(MAXIMUM_COUNTER, 9223372036854775807).

-define(STATE, 1).
-define(QUEUED_COMMANDS, 2).
-define(REJECTED_COMMANDS, 3).
-define(SENT_PACKETS, 4).
-define(SENT_BYTES, 5).
-define(RECEIVED_PACKETS, 6).
-define(RECEIVED_BYTES, 7).
-define(RECEIVE_TIMEOUTS, 8).
-define(SOCKET_FAILURES, 9).
-define(DONT_FRAGMENT, 10).
-define(NOT_ECT, 11).
-define(BUFFERED_PACKETS, 12).
-define(RECEIVE_WAITING, 13).
-define(RECEIVE_BUFFER_BYTES, 14).
-define(SEND_BUFFER_BYTES, 15).
-define(EVENT_WAITING, 16).
-define(EVENT_TIMEOUTS, 17).
-define(RELAY_TIMING_SAMPLES, 18).
-define(MAXIMUM_RELAY_DELAY_MICROSECONDS, 19).
-define(MAXIMUM_SEND_SERVICE_MICROSECONDS, 20).
-define(LAST_RELAY_INGRESS_MICROSECONDS, 21).
-define(LAST_RELAY_EGRESS_MICROSECONDS, 22).
-define(MATERIAL_BURST_COMPRESSIONS, 23).
-define(MAXIMUM_BURST_COMPRESSION_MICROSECONDS, 24).
-define(MESSAGE_TOO_LARGE_SENDS, 25).
-define(FRAGMENTATION_RETRIES, 26).
-define(BUFFERED_PAYLOAD_BYTES, 27).

-define(MATERIAL_BURST_COMPRESSION_MICROSECONDS, 1000).

-define(IDLE_STATE, 1).
-define(IDLE_TIMEOUT, 2).
-define(IDLE_DEADLINE, 3).
-define(IDLE_PENDING, 4).
-define(IDLE_ACTIVITIES, 5).
-define(IDLE_WAKE_SIGNALS, 6).
-define(IDLE_OWNER_WAKEUPS, 7).
-define(IDLE_DEADLINE_CHECKS, 8).
-define(IDLE_EXPIRATIONS, 9).
-define(IDLE_STOP_SIGNALS, 10).
-define(IDLE_OUTBOUND_ACTIVITIES, 11).
-define(IDLE_INBOUND_ACTIVITIES, 12).

-define(IDLE_ACTIVE, 0).
-define(IDLE_STOPPED, 1).
-define(IDLE_EXPIRED, 2).
-define(IDLE_LOCKED, 3).

-define(STATE_SETUP, 0).
-define(STATE_OPEN, 1).
-define(STATE_UNUSABLE, 2).
-define(STATE_CLOSED, 3).

-define(IPPROTO_IP, 0).
-define(IPPROTO_IPV6, 41).
-define(LINUX_IP_MTU_DISCOVER, 10).
-define(LINUX_IPV6_MTU_DISCOVER, 23).
-define(LINUX_PMTUDISC_DO, 2).
-define(LINUX_PMTUDISC_PROBE, 3).
-define(DARWIN_IP_DONTFRAG, 28).
-define(DARWIN_IPV6_DONTFRAG, 62).
-define(FREEBSD_IP_DONTFRAG, 67).
-define(FREEBSD_IPV6_DONTFRAG, 62).
-define(WINDOWS_IP_DONTFRAGMENT, 14).
-define(WINDOWS_IPV6_DONTFRAG, 14).

-type socket_family() :: 4 | 6.
-type counters() :: atomics:atomics_ref().
-type idle_state() :: atomics:atomics_ref().
-type handle() :: #{
    tag := http_masque_udp_socket,
    pid := pid(),
    reference := reference(),
    owner := pid(),
    counters := counters(),
    packet_too_big := term()
}.
-type waiter() :: none | {pid(), reference(), reference() | none}.
-type buffered_datagram() ::
    none |
    {packet, inet:ip_address(), inet:port_number(), binary()} |
    {packet_too_big, socket_family(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), integer()}.
-type packet_too_big_config() :: {
    socket_family(), non_neg_integer(), term(), pos_integer()
}.

-spec open(binary(), integer(), pid(), integer()) ->
    {ok, handle()} | {error, integer()}.
open(Address, Port, Owner, Timeout)
    when is_binary(Address), is_integer(Port), Port > 0, Port =< 65535,
         is_pid(Owner), is_integer(Timeout), Timeout > 0,
         Timeout =< 2147483647 ->
    open(Address, Port, Owner, ?MAXIMUM_UDP_PAYLOAD_BYTES, Timeout);
open(_Address, _Port, _Owner, _Timeout) ->
    {error, 1}.

-spec open(binary(), integer(), pid(), integer(), integer()) ->
    {ok, handle()} | {error, integer()}.
open(Address, Port, Owner, TargetPayloadLimit, Timeout)
    when is_binary(Address), is_integer(Port), Port > 0, Port =< 65535,
         is_pid(Owner), is_integer(Timeout), Timeout > 0,
         Timeout =< 2147483647, is_integer(TargetPayloadLimit),
         TargetPayloadLimit >= 0,
         TargetPayloadLimit =< ?MAXIMUM_UDP_PAYLOAD_BYTES ->
    case decode_address(Address) of
        error ->
            {error, 1};
        {ok, PeerAddress, Family} ->
            open_owner(
                PeerAddress,
                Family,
                Port,
                Owner,
                TargetPayloadLimit,
                Timeout
            )
    end;
open(_Address, _Port, _Owner, _TargetPayloadLimit, _Timeout) ->
    {error, 1}.

-spec adopt(handle(), pid(), integer()) -> {ok, nil} | {error, integer()}.
adopt(Handle, Owner, Timeout)
    when is_pid(Owner), is_integer(Timeout), Timeout > 0,
         Timeout =< 2147483647 ->
    case valid_handle(Handle) of
        false -> {error, 1};
        true -> direct_call(Handle, {adopt, Owner}, Timeout)
    end;
adopt(_Handle, _Owner, _Timeout) ->
    {error, 1}.

-spec send(handle(), bitstring(), integer()) -> {ok, nil} | {error, integer()}.
send(Handle, Payload, Timeout)
    when is_binary(Payload), byte_size(Payload) =< ?MAXIMUM_UDP_PAYLOAD_BYTES,
         is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    command_call(
        Handle,
        {send, Payload, erlang:monotonic_time(microsecond)},
        Timeout
    );
send(_Handle, _Payload, _Timeout) ->
    {error, 1}.

-spec recv(handle(), integer()) -> {ok, tuple()} | {error, integer()}.
recv(Handle, Timeout)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    command_call(Handle, {receive_udp, Timeout}, Timeout);
recv(_Handle, _Timeout) ->
    {error, 1}.

-spec wait_event(handle(), integer()) ->
    {ok, integer()} | {error, integer()}.
wait_event(Handle, Timeout)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    event_command_call(Handle, {receive_event, Timeout}, Timeout);
wait_event(_Handle, _Timeout) ->
    {error, 1}.

%% Install the single terminal-event waiter without a polling deadline.
%%
%% This entry point is intentionally separate from wait_event/2: ordinary
%% callers always retain a finite operation deadline, while the MASQUE
%% session-lifetime owner holds this wait until either resource terminates.
%% The UDP owner retains a typed unusable state, so a failure that races the
%% registration is returned immediately rather than being lost.
-spec wait_event_forever(handle()) -> {ok, integer()} | {error, integer()}.
wait_event_forever(Handle) ->
    case valid_handle(Handle) of
        false ->
            {error, 1};
        true ->
            case reserve_event_command(Handle) of
                {error, Reason} -> {error, Reason};
                ok -> monitored_call_forever(Handle, receive_event_forever)
            end
    end.

%% One lock-protected monotonic idle deadline. Activity and expiry compete for
%% the same state slot, so an expiry can never commit against a deadline that
%% a concurrent activity update has already replaced. The pending bit grants
%% mailbox credit before a wake signal is sent; at most one command is queued.
-spec idle_new(pos_integer(), integer()) -> idle_state().
idle_new(Timeout, Now)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647,
         is_integer(Now) ->
    State = atomics:new(12, [{signed, true}]),
    atomics:put(State, ?IDLE_TIMEOUT, Timeout),
    atomics:put(State, ?IDLE_DEADLINE, Now + Timeout),
    State.

-spec idle_activity(idle_state(), integer(), 1 | 2) -> 0 | 1.
idle_activity(State, Now, Direction)
    when is_integer(Now), (Direction =:= 1 orelse Direction =:= 2) ->
    case acquire_idle_state(State) of
        active ->
            Timeout = atomics:get(State, ?IDLE_TIMEOUT),
            atomics:put(State, ?IDLE_DEADLINE, Now + Timeout),
            saturating_increment(State, ?IDLE_ACTIVITIES),
            case Direction of
                1 -> saturating_increment(State, ?IDLE_OUTBOUND_ACTIVITIES);
                2 -> saturating_increment(State, ?IDLE_INBOUND_ACTIVITIES)
            end,
            Wake = reserve_idle_wake(State),
            atomics:put(State, ?IDLE_STATE, ?IDLE_ACTIVE),
            Wake;
        stopped -> 0;
        expired -> 0;
        invalid -> 0
    end;
idle_activity(_State, _Now, _Direction) ->
    0.

-spec idle_ack(idle_state()) -> integer().
idle_ack(State) ->
    try atomics:exchange(State, ?IDLE_PENDING, 0) of
        1 ->
            saturating_increment(State, ?IDLE_OWNER_WAKEUPS),
            idle_public_state(State);
        _ -> idle_public_state(State)
    catch
        _:_ -> ?IDLE_STOPPED
    end.

-spec idle_due(idle_state(), integer()) -> {integer(), non_neg_integer()}.
idle_due(State, Now) when is_integer(Now) ->
    case acquire_idle_state(State) of
        active ->
            saturating_increment(State, ?IDLE_DEADLINE_CHECKS),
            Deadline = atomics:get(State, ?IDLE_DEADLINE),
            case Now >= Deadline of
                true ->
                    atomics:put(State, ?IDLE_PENDING, 0),
                    saturating_increment(State, ?IDLE_EXPIRATIONS),
                    atomics:put(State, ?IDLE_STATE, ?IDLE_EXPIRED),
                    {?IDLE_EXPIRED, 0};
                false ->
                    atomics:put(State, ?IDLE_STATE, ?IDLE_ACTIVE),
                    {?IDLE_ACTIVE, Deadline - Now}
            end;
        stopped -> {?IDLE_STOPPED, 0};
        expired -> {?IDLE_EXPIRED, 0};
        invalid -> {?IDLE_STOPPED, 0}
    end;
idle_due(_State, _Now) ->
    {?IDLE_STOPPED, 0}.

-spec idle_stop(idle_state()) -> 0 | 1.
idle_stop(State) ->
    case acquire_idle_state(State) of
        active ->
            saturating_increment(State, ?IDLE_STOP_SIGNALS),
            Wake = reserve_idle_wake(State),
            atomics:put(State, ?IDLE_STATE, ?IDLE_STOPPED),
            Wake;
        stopped -> 0;
        expired -> 0;
        invalid -> 0
    end.

-spec idle_snapshot(idle_state()) ->
    {integer(), integer(), integer(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer()}.
idle_snapshot(State) ->
    case acquire_idle_state(State) of
        active ->
            %% A diagnostic read participates in the same lock as activity and
            %% expiry. In particular, total and directional activity counters
            %% can never be returned from different transitions.
            try idle_snapshot_values(State, ?IDLE_ACTIVE)
            catch
                _:_ -> idle_snapshot_default()
            after
                atomics:put(State, ?IDLE_STATE, ?IDLE_ACTIVE)
            end;
        stopped -> safe_idle_snapshot_values(State, ?IDLE_STOPPED);
        expired -> safe_idle_snapshot_values(State, ?IDLE_EXPIRED);
        invalid -> idle_snapshot_default()
    end.

-spec safe_idle_snapshot_values(idle_state(), integer()) ->
    {integer(), integer(), integer(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer()}.
safe_idle_snapshot_values(State, PublicState) ->
    try
        idle_snapshot_values(State, PublicState)
    catch
        _:_ -> idle_snapshot_default()
    end.

-spec idle_snapshot_values(idle_state(), integer()) ->
    {integer(), integer(), integer(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer()}.
idle_snapshot_values(State, PublicState) ->
    {
        PublicState,
        atomics:get(State, ?IDLE_TIMEOUT),
        atomics:get(State, ?IDLE_DEADLINE),
        atomics:get(State, ?IDLE_PENDING) =:= 1,
        atomics:get(State, ?IDLE_ACTIVITIES),
        atomics:get(State, ?IDLE_OUTBOUND_ACTIVITIES),
        atomics:get(State, ?IDLE_INBOUND_ACTIVITIES),
        atomics:get(State, ?IDLE_WAKE_SIGNALS),
        atomics:get(State, ?IDLE_OWNER_WAKEUPS),
        atomics:get(State, ?IDLE_DEADLINE_CHECKS),
        atomics:get(State, ?IDLE_EXPIRATIONS),
        atomics:get(State, ?IDLE_STOP_SIGNALS)
    }.

-spec idle_snapshot_default() ->
    {integer(), integer(), integer(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer()}.
idle_snapshot_default() ->
    {?IDLE_STOPPED, 0, 0, false, 0, 0, 0, 0, 0, 0, 0, 0}.

-spec close(handle(), integer()) -> {ok, nil} | {error, integer()}.
close(Handle, Timeout)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    case valid_handle(Handle) of
        false ->
            {error, 1};
        true ->
            case counter(Handle, ?STATE, ?STATE_CLOSED) of
                ?STATE_CLOSED -> {ok, nil};
                _ ->
                    case direct_call(Handle, close, Timeout) of
                        {error, Reason}
                            when Reason =:= 2; Reason =:= 4 ->
                            case counter(Handle, ?STATE, ?STATE_CLOSED) of
                                ?STATE_CLOSED -> {ok, nil};
                                _ -> {error, Reason}
                            end;
                        Result -> Result
                    end
            end
    end;
close(_Handle, _Timeout) ->
    {error, 1}.

-spec snapshot(term()) ->
    {integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), boolean(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(),
     boolean(), boolean(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer()}.
snapshot(Handle) ->
    case valid_handle(Handle) of
        false ->
            {?STATE_CLOSED, ?MAXIMUM_QUEUED_COMMANDS, ?SOCKET_BUFFER_BYTES,
             0, 0, ?MAXIMUM_UDP_PAYLOAD_BYTES, 0, 0, 0, false, false, 0, 0,
             0, 0, 0, 0, 0, 0, false, false, 0, 1, 0, 0, 0, 0, 0, 0};
        true ->
            {
                counter(Handle, ?STATE, ?STATE_CLOSED),
                ?MAXIMUM_QUEUED_COMMANDS,
                ?SOCKET_BUFFER_BYTES,
                counter(Handle, ?RECEIVE_BUFFER_BYTES, 0),
                counter(Handle, ?SEND_BUFFER_BYTES, 0),
                ?MAXIMUM_UDP_PAYLOAD_BYTES,
                counter(Handle, ?QUEUED_COMMANDS, 0),
                counter(Handle, ?BUFFERED_PACKETS, 0),
                counter(Handle, ?BUFFERED_PAYLOAD_BYTES, 0),
                counter(Handle, ?RECEIVE_WAITING, 0) =:= 1,
                counter(Handle, ?EVENT_WAITING, 0) =:= 1,
                counter(Handle, ?REJECTED_COMMANDS, 0),
                counter(Handle, ?SENT_PACKETS, 0),
                counter(Handle, ?SENT_BYTES, 0),
                counter(Handle, ?RECEIVED_PACKETS, 0),
                counter(Handle, ?RECEIVED_BYTES, 0),
                counter(Handle, ?RECEIVE_TIMEOUTS, 0),
                counter(Handle, ?EVENT_TIMEOUTS, 0),
                counter(Handle, ?SOCKET_FAILURES, 0),
                counter(Handle, ?DONT_FRAGMENT, 0) =:= 1,
                counter(Handle, ?NOT_ECT, 0) =:= 1,
                counter(Handle, ?RELAY_TIMING_SAMPLES, 0),
                1,
                counter(Handle, ?MAXIMUM_RELAY_DELAY_MICROSECONDS, 0),
                counter(Handle, ?MAXIMUM_SEND_SERVICE_MICROSECONDS, 0),
                counter(Handle, ?MATERIAL_BURST_COMPRESSIONS, 0),
                counter(
                    Handle, ?MAXIMUM_BURST_COMPRESSION_MICROSECONDS, 0
                ),
                counter(Handle, ?MESSAGE_TOO_LARGE_SENDS, 0),
                counter(Handle, ?FRAGMENTATION_RETRIES, 0)
            }
    end.

-spec packet_too_big_snapshot(term()) -> tuple().
packet_too_big_snapshot(#{packet_too_big := Diagnostics}) ->
    http_masque_packet_too_big_ffi:diagnostics_snapshot(Diagnostics);
packet_too_big_snapshot(_Handle) ->
    http_masque_packet_too_big_ffi:diagnostics_snapshot(invalid).

-spec open_owner(
    inet:ip_address(), socket_family(), inet:port_number(), pid(),
    non_neg_integer(), pos_integer()
) -> {ok, handle()} | {error, integer()}.
open_owner(PeerAddress, Family, Port, Owner, TargetPayloadLimit, Timeout) ->
    Caller = self(),
    StartReference = make_ref(),
    SocketReference = make_ref(),
    Counters = atomics:new(27, [{signed, true}]),
    PacketTooBig = http_masque_packet_too_big_ffi:diagnostics_new(
        TargetPayloadLimit, Family
    ),
    {Pid, Monitor} = spawn_monitor(fun() ->
        owner_init(
            Caller,
            StartReference,
            SocketReference,
            Counters,
            PeerAddress,
            Family,
            Port,
            Owner,
            {Family, TargetPayloadLimit, PacketTooBig, Timeout},
            Timeout
        )
    end),
    receive
        {StartReference,
         {ok, DontFragment, NotEct, ReceiveBufferBytes, SendBufferBytes}} ->
            erlang:demonitor(Monitor, [flush]),
            set_boolean(Counters, ?DONT_FRAGMENT, DontFragment),
            set_boolean(Counters, ?NOT_ECT, NotEct),
            atomics:put(
                Counters, ?RECEIVE_BUFFER_BYTES, ReceiveBufferBytes
            ),
            atomics:put(Counters, ?SEND_BUFFER_BYTES, SendBufferBytes),
            {ok, #{
                tag => http_masque_udp_socket,
                pid => Pid,
                reference => SocketReference,
                owner => Owner,
                counters => Counters,
                packet_too_big => PacketTooBig
            }};
        {StartReference, {error, Reason}} ->
            await_down(Pid, Monitor),
            {error, open_error_code(Reason)};
        {'DOWN', Monitor, process, Pid, _Reason} ->
            drain_start_reply(StartReference),
            {error, 8}
    after Timeout ->
        exit(Pid, kill),
        await_down(Pid, Monitor),
        drain_start_reply(StartReference),
        {error, 2}
    end.

-spec owner_init(
    pid(), reference(), reference(), counters(), inet:ip_address(),
    socket_family(), inet:port_number(), pid(), packet_too_big_config(),
    pos_integer()
) -> no_return().
owner_init(
    Caller,
    StartReference,
    SocketReference,
    Counters,
    PeerAddress,
    Family,
    Port,
    Owner,
    PacketTooBig,
    SetupTimeout
) ->
    case open_socket(Family, PeerAddress, Port) of
        {error, Reason} ->
            Caller ! {StartReference, {error, Reason}},
            exit(normal);
        {ok, Socket, DontFragment, NotEct, ReceiveBufferBytes,
         SendBufferBytes} ->
            OwnerMonitor = erlang:monitor(process, Owner),
            case activate_once(Socket) of
                ok ->
                    Caller ! {
                        StartReference,
                        {ok, DontFragment, NotEct, ReceiveBufferBytes,
                         SendBufferBytes}
                    },
                    SetupDeadline =
                        erlang:monotonic_time(millisecond) + SetupTimeout,
                    setup_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        SetupDeadline,
                        none
                    );
                {error, Reason} ->
                    gen_udp:close(Socket),
                    erlang:demonitor(OwnerMonitor, [flush]),
                    Caller ! {StartReference, {error, Reason}},
                    exit(normal)
            end
    end.

-spec setup_loop(
    gen_udp:socket(), inet:ip_address(), inet:port_number(), pid(), reference(),
    reference(), counters(), packet_too_big_config(), integer(),
    buffered_datagram()
) -> no_return().
setup_loop(
    Socket,
    PeerAddress,
    Port,
    Owner,
    OwnerMonitor,
    SocketReference,
    Counters,
    PacketTooBig,
    Deadline,
    Buffered
) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         {adopt, ClaimedOwner}} ->
            case Caller =:= Owner andalso ClaimedOwner =:= Owner of
                true ->
                    Caller ! {http_masque_udp_reply, CallReference, {ok, nil}},
                    atomics:put(Counters, ?STATE, ?STATE_OPEN),
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        none,
                        none
                    );
                false ->
                    Caller ! {http_masque_udp_reply, CallReference, {error, 1}},
                    setup_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Deadline,
                        Buffered
                    )
            end;
        {http_masque_udp_call, SocketReference, CallReference, Caller, close} ->
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            Caller ! {http_masque_udp_reply, CallReference, {ok, nil}},
            exit(normal);
        {udp, Socket, Address, SourcePort, Payload} ->
            Event = classify_target_datagram(
                Socket,
                Address,
                SourcePort,
                Payload,
                PeerAddress,
                Port,
                Counters,
                PacketTooBig
            ),
            mark_buffered(Event, Counters, PacketTooBig),
            setup_loop(
                Socket,
                PeerAddress,
                Port,
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                PacketTooBig,
                Deadline,
                Event
            );
        {udp_error, Socket, _Reason} ->
            mark_unusable(Counters, PacketTooBig),
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            exit(normal);
        {udp_closed, Socket} ->
            mark_unusable(Counters, PacketTooBig),
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            exit(normal);
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            exit(normal);
        _Foreign ->
            setup_loop(
                Socket,
                PeerAddress,
                Port,
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                PacketTooBig,
                Deadline,
                Buffered
            )
    after Remaining ->
        close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
        exit(normal)
    end.

-spec owner_loop(
    gen_udp:socket(), inet:ip_address(), inet:port_number(), pid(), reference(),
    reference(), counters(), packet_too_big_config(), buffered_datagram(),
    waiter(), waiter()
) -> no_return().
owner_loop(
    Socket,
    PeerAddress,
    Port,
    Owner,
    OwnerMonitor,
    SocketReference,
    Counters,
    PacketTooBig,
    Buffered,
    DatagramWaiter,
    EventWaiter
) ->
    receive
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         {send, Payload, IngressMicroseconds}} ->
            release_command(Counters),
            SendStarted = erlang:monotonic_time(microsecond),
            Result = send_datagram(Socket, PeerAddress, Port, Payload),
            SendFinished = erlang:monotonic_time(microsecond),
            case Result of
                {ok, nil} ->
                    record_relay_timing(
                        Counters,
                        IngressMicroseconds,
                        SendStarted,
                        SendFinished
                    ),
                    saturating_increment(Counters, ?SENT_PACKETS),
                    saturating_add(Counters, ?SENT_BYTES, byte_size(Payload)),
                    Caller ! {http_masque_udp_reply, CallReference, Result},
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    );
                {error, 7} ->
                    saturating_increment(Counters, ?MESSAGE_TOO_LARGE_SENDS),
                    Caller ! {http_masque_udp_reply, CallReference, Result},
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    );
                {error, Reason} ->
                    mark_unusable(Counters, PacketTooBig),
                    fail_waiter(DatagramWaiter, Counters, 8),
                    complete_event_waiter(
                        EventWaiter, Counters, Reason
                    ),
                    Caller ! {http_masque_udp_reply, CallReference, Result},
                    safe_close(Socket),
                    unusable_loop(
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        Reason
                    )
            end;
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         {receive_udp, Timeout}} ->
            release_command(Counters),
            case {DatagramWaiter, Buffered} of
                {none, BufferedEvent} when BufferedEvent =/= none ->
                    clear_buffered(BufferedEvent, Counters, PacketTooBig),
                    case reply_buffered_event(
                        Caller, CallReference, Counters, BufferedEvent
                    ) of
                        {error, Reason} ->
                            mark_unusable(Counters, PacketTooBig),
                            complete_event_waiter(
                                EventWaiter, Counters, Reason
                            ),
                            Caller ! {
                                http_masque_udp_reply,
                                CallReference,
                                {error, Reason}
                            },
                            safe_close(Socket),
                            unusable_loop(
                                Owner,
                                OwnerMonitor,
                                SocketReference,
                                Counters,
                                Reason
                            );
                        ok ->
                            rearm_after_datagram(
                                Socket,
                                PeerAddress,
                                Port,
                                Owner,
                                OwnerMonitor,
                                SocketReference,
                                Counters,
                                PacketTooBig,
                                EventWaiter
                            )
                    end;
                {none, none} ->
                    atomics:put(Counters, ?RECEIVE_WAITING, 1),
                    Timer = erlang:send_after(
                        Timeout,
                        self(),
                        {http_masque_udp_receive_timeout, CallReference}
                    ),
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        none,
                        {Caller, CallReference, Timer},
                        EventWaiter
                    );
                {_Existing, _Buffered} ->
                    saturating_increment(Counters, ?REJECTED_COMMANDS),
                    Caller ! {
                        http_masque_udp_reply, CallReference, {error, 3}
                    },
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    )
            end;
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         {receive_event, Timeout}} ->
            release_command(Counters),
            case EventWaiter of
                none ->
                    atomics:put(Counters, ?EVENT_WAITING, 1),
                    Timer = erlang:send_after(
                        Timeout,
                        self(),
                        {http_masque_udp_event_timeout, CallReference}
                    ),
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        {Caller, CallReference, Timer}
                    );
                _Existing ->
                    saturating_increment(Counters, ?REJECTED_COMMANDS),
                    Caller ! {
                        http_masque_udp_reply, CallReference, {error, 3}
                    },
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    )
            end;
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         receive_event_forever} ->
            release_command(Counters),
            case EventWaiter of
                none ->
                    atomics:put(Counters, ?EVENT_WAITING, 1),
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        {Caller, CallReference, none}
                    );
                _Existing ->
                    saturating_increment(Counters, ?REJECTED_COMMANDS),
                    Caller ! {
                        http_masque_udp_reply, CallReference, {error, 3}
                    },
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    )
            end;
        {http_masque_udp_call, SocketReference, CallReference, Caller, close} ->
            fail_waiter(DatagramWaiter, Counters, 4),
            fail_event_waiter(EventWaiter, Counters, 4),
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            Caller ! {http_masque_udp_reply, CallReference, {ok, nil}},
            exit(normal);
        {udp, Socket, Address, SourcePort, Payload} ->
            Event = classify_target_datagram(
                Socket,
                Address,
                SourcePort,
                Payload,
                PeerAddress,
                Port,
                Counters,
                PacketTooBig
            ),
            case DatagramWaiter of
                none ->
                    mark_buffered(Event, Counters, PacketTooBig),
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Event,
                        none,
                        EventWaiter
                    );
                {Caller, CallReference, Timer} ->
                    cancel_timer(Timer),
                    atomics:put(Counters, ?RECEIVE_WAITING, 0),
                    case reply_buffered_event(
                        Caller, CallReference, Counters, Event
                    ) of
                        {error, Reason} ->
                            mark_unusable(Counters, PacketTooBig),
                            complete_event_waiter(
                                EventWaiter, Counters, Reason
                            ),
                            Caller ! {
                                http_masque_udp_reply,
                                CallReference,
                                {error, Reason}
                            },
                            safe_close(Socket),
                            unusable_loop(
                                Owner,
                                OwnerMonitor,
                                SocketReference,
                                Counters,
                                Reason
                            );
                        ok ->
                            rearm_after_datagram(
                                Socket,
                                PeerAddress,
                                Port,
                                Owner,
                                OwnerMonitor,
                                SocketReference,
                                Counters,
                                PacketTooBig,
                                EventWaiter
                            )
                    end
            end;
        {udp_error, Socket, _Reason} ->
            mark_unusable(Counters, PacketTooBig),
            fail_waiter(DatagramWaiter, Counters, 8),
            complete_event_waiter(EventWaiter, Counters, 8),
            safe_close(Socket),
            unusable_loop(
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                8
            );
        {udp_closed, Socket} ->
            mark_unusable(Counters, PacketTooBig),
            fail_waiter(DatagramWaiter, Counters, 4),
            complete_event_waiter(EventWaiter, Counters, 4),
            unusable_loop(
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                4
            );
        {http_masque_udp_receive_timeout, CallReference} ->
            case DatagramWaiter of
                {Caller, CallReference, _Timer} ->
                    atomics:put(Counters, ?RECEIVE_WAITING, 0),
                    saturating_increment(Counters, ?RECEIVE_TIMEOUTS),
                    Caller ! {
                        http_masque_udp_reply, CallReference, {error, 2}
                    },
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        none,
                        EventWaiter
                    );
                _ ->
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    )
            end;
        {http_masque_udp_event_timeout, CallReference} ->
            case EventWaiter of
                {Caller, CallReference, _Timer} ->
                    atomics:put(Counters, ?EVENT_WAITING, 0),
                    saturating_increment(Counters, ?EVENT_TIMEOUTS),
                    Caller ! {
                        http_masque_udp_reply, CallReference, {error, 2}
                    },
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        none
                    );
                _ ->
                    owner_loop(
                        Socket,
                        PeerAddress,
                        Port,
                        Owner,
                        OwnerMonitor,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Buffered,
                        DatagramWaiter,
                        EventWaiter
                    )
            end;
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            fail_waiter(DatagramWaiter, Counters, 4),
            fail_event_waiter(EventWaiter, Counters, 4),
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            exit(normal);
        _Foreign ->
            owner_loop(
                Socket,
                PeerAddress,
                Port,
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                PacketTooBig,
                Buffered,
                DatagramWaiter,
                EventWaiter
            )
    end.

-spec unusable_loop(pid(), reference(), reference(), counters(), integer()) ->
    no_return().
unusable_loop(Owner, OwnerMonitor, SocketReference, Counters, FailureCode) ->
    receive
        {http_masque_udp_call, SocketReference, CallReference, Caller, close} ->
            finish_unusable_owner(OwnerMonitor, Counters),
            Caller ! {http_masque_udp_reply, CallReference, {ok, nil}},
            exit(normal);
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         {receive_event, _Timeout}} ->
            release_command(Counters),
            Caller ! {
                http_masque_udp_reply, CallReference, {ok, FailureCode}
            },
            unusable_loop(
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                FailureCode
            );
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         receive_event_forever} ->
            release_command(Counters),
            Caller ! {
                http_masque_udp_reply, CallReference, {ok, FailureCode}
            },
            unusable_loop(
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                FailureCode
            );
        {http_masque_udp_call, SocketReference, CallReference, Caller,
         _Command} ->
            release_command(Counters),
            Caller ! {http_masque_udp_reply, CallReference, {error, 8}},
            unusable_loop(
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                FailureCode
            );
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            finish_unusable_owner(OwnerMonitor, Counters),
            exit(normal);
        _Foreign ->
            unusable_loop(
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                FailureCode
            )
    end.

-spec command_call(handle(), term(), pos_integer()) ->
    {ok, term()} | {error, integer()}.
command_call(Handle, Command, Timeout) ->
    case valid_handle(Handle) of
        false ->
            {error, 1};
        true ->
            case reserve_command(Handle) of
                {error, Reason} -> {error, Reason};
                ok -> monitored_call(Handle, Command, Timeout)
            end
    end.

-spec event_command_call(handle(), term(), pos_integer()) ->
    {ok, term()} | {error, integer()}.
event_command_call(Handle, Command, Timeout) ->
    case valid_handle(Handle) of
        false ->
            {error, 1};
        true ->
            case reserve_event_command(Handle) of
                {error, Reason} -> {error, Reason};
                ok -> monitored_call(Handle, Command, Timeout)
            end
    end.

-spec direct_call(handle(), term(), pos_integer()) ->
    {ok, term()} | {error, integer()}.
direct_call(Handle, Command, Timeout) ->
    monitored_call(Handle, Command, Timeout).

-spec monitored_call(handle(), term(), pos_integer()) ->
    {ok, term()} | {error, integer()}.
monitored_call(
    #{pid := Pid, reference := SocketReference, counters := Counters,
      packet_too_big := PacketTooBigDiagnostics},
    Command,
    Timeout
) ->
    CallReference = make_ref(),
    Monitor = erlang:monitor(process, Pid),
    Pid ! {
        http_masque_udp_call,
        SocketReference,
        CallReference,
        self(),
        Command
    },
    Wait = call_wait(Timeout),
    receive
        {http_masque_udp_reply, CallReference, Result} ->
            erlang:demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            mark_owner_down(Counters, PacketTooBigDiagnostics),
            drain_call_reply(CallReference),
            {error, 4}
    after Wait ->
        exit(Pid, kill),
        await_down(Pid, Monitor),
        mark_owner_down(Counters, PacketTooBigDiagnostics),
        drain_call_reply(CallReference),
        {error, 8}
    end.

-spec monitored_call_forever(handle(), term()) ->
    {ok, term()} | {error, integer()}.
monitored_call_forever(
    #{pid := Pid, reference := SocketReference, counters := Counters,
      packet_too_big := PacketTooBigDiagnostics},
    Command
) ->
    CallReference = make_ref(),
    Monitor = erlang:monitor(process, Pid),
    Pid ! {
        http_masque_udp_call,
        SocketReference,
        CallReference,
        self(),
        Command
    },
    receive
        {http_masque_udp_reply, CallReference, Result} ->
            erlang:demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            mark_owner_down(Counters, PacketTooBigDiagnostics),
            drain_call_reply(CallReference),
            {error, 4}
    end.

-spec reserve_command(handle()) -> ok | {error, integer()}.
reserve_command(#{counters := Counters}) ->
    case safe_atomic_get(Counters, ?STATE, ?STATE_CLOSED) of
        ?STATE_OPEN -> reserve_command_counter(Counters);
        ?STATE_UNUSABLE -> {error, 8};
        ?STATE_CLOSED -> {error, 4};
        _ -> {error, 1}
    end.

-spec reserve_event_command(handle()) -> ok | {error, integer()}.
reserve_event_command(#{counters := Counters}) ->
    case safe_atomic_get(Counters, ?STATE, ?STATE_CLOSED) of
        ?STATE_OPEN -> reserve_command_counter(Counters);
        ?STATE_UNUSABLE -> reserve_command_counter(Counters);
        ?STATE_CLOSED -> {error, 4};
        _ -> {error, 1}
    end.

-spec reserve_command_counter(counters()) -> ok | {error, 3}.
reserve_command_counter(Counters) ->
    Current = safe_atomic_get(Counters, ?QUEUED_COMMANDS, 0),
    case Current >= ?MAXIMUM_QUEUED_COMMANDS of
        true ->
            saturating_increment(Counters, ?REJECTED_COMMANDS),
            {error, 3};
        false ->
            case atomics:compare_exchange(
                Counters, ?QUEUED_COMMANDS, Current, Current + 1
            ) of
                ok -> ok;
                _ -> reserve_command_counter(Counters)
            end
    end.

-spec release_command(counters()) -> ok.
release_command(Counters) ->
    try atomics:add(Counters, ?QUEUED_COMMANDS, -1) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec open_socket(socket_family(), inet:ip_address(), inet:port_number()) ->
    {ok, gen_udp:socket(), boolean(), boolean(), non_neg_integer(),
     non_neg_integer()} | {error, term()}.
open_socket(Family, PeerAddress, Port) ->
    Options = [
        binary,
        {active, false},
        {recbuf, ?SOCKET_BUFFER_BYTES},
        {sndbuf, ?SOCKET_BUFFER_BYTES}
        | family_options(Family)
    ],
    case gen_udp:open(0, Options) of
        {error, Reason} ->
            {error, Reason};
        {ok, Socket} ->
            case gen_udp:connect(Socket, PeerAddress, Port) of
                {error, Reason} ->
                    gen_udp:close(Socket),
                    {error, Reason};
                ok ->
                    DontFragment = set_dont_fragment(Socket, Family),
                    NotEct = set_not_ect(Socket, Family),
                    {ReceiveBufferBytes, SendBufferBytes} =
                        socket_buffer_sizes(Socket),
                    {ok, Socket, DontFragment, NotEct, ReceiveBufferBytes,
                     SendBufferBytes}
            end
    end.

-spec send_datagram(
    gen_udp:socket(), inet:ip_address(), inet:port_number(), binary()
) -> {ok, nil} | {error, integer()}.
send_datagram(Socket, Address, Port, Payload) ->
    try gen_udp:send(Socket, Address, Port, Payload) of
        ok -> {ok, nil};
        {error, Reason} -> {error, runtime_error_code(Reason)}
    catch
        _:_ -> {error, 8}
    end.

-spec classify_target_datagram(
    gen_udp:socket(), inet:ip_address(), inet:port_number(), binary(),
    inet:ip_address(), inet:port_number(), counters(),
    packet_too_big_config()
) -> buffered_datagram().
classify_target_datagram(
    Socket,
    Address,
    SourcePort,
    Payload,
    PeerAddress,
    PeerPort,
    Counters,
    {Family, MaximumPayload, Diagnostics, Timeout}
) ->
    case Address =:= PeerAddress andalso SourcePort =:= PeerPort andalso
         byte_size(Payload) > MaximumPayload of
        false ->
            {packet, Address, SourcePort, Payload};
        true ->
            {Delivery, Mtu, QuoteBytes} =
                http_masque_packet_too_big_ffi:deliver(
                    Diagnostics,
                    Family,
                    Socket,
                    PeerAddress,
                    PeerPort,
                    Payload,
                    Timeout
                ),
            saturating_increment(Counters, ?RECEIVED_PACKETS),
            saturating_add(Counters, ?RECEIVED_BYTES, byte_size(Payload)),
            {packet_too_big, Family, MaximumPayload, Mtu, QuoteBytes,
             Delivery}
    end.

-spec mark_buffered(
    term(), counters(), packet_too_big_config()
) -> ok.
mark_buffered(Event, Counters, PacketTooBig) ->
    atomics:put(Counters, ?BUFFERED_PACKETS, 1),
    case Event of
        {packet, _Address, _Port, Payload} ->
            atomics:put(
                Counters, ?BUFFERED_PAYLOAD_BYTES, byte_size(Payload)
            );
        {packet_too_big, _Family, _Maximum, _Mtu, _Quote, _Delivery} ->
            atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
            mark_packet_too_big_buffer(PacketTooBig, true)
    end,
    ok.

-spec clear_buffered(
    buffered_datagram(), counters(), packet_too_big_config()
) -> ok.
clear_buffered(Event, Counters, PacketTooBig) ->
    atomics:put(Counters, ?BUFFERED_PACKETS, 0),
    atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
    case Event of
        {packet_too_big, _Family, _Maximum, _Mtu, _Quote, _Delivery} ->
            mark_packet_too_big_buffer(PacketTooBig, false);
        _ -> ok
    end.

-spec mark_packet_too_big_buffer(packet_too_big_config(), boolean()) -> ok.
mark_packet_too_big_buffer({_Family, _Maximum, Diagnostics, _Timeout}, Value) ->
    http_masque_packet_too_big_ffi:diagnostics_buffered(
        Diagnostics, Value
    ).

-spec clear_packet_too_big_buffer(packet_too_big_config()) -> ok.
clear_packet_too_big_buffer(PacketTooBig) ->
    mark_packet_too_big_buffer(PacketTooBig, false).

-spec reply_buffered_event(
    pid(), reference(), counters(), buffered_datagram()
) -> ok | {error, 8}.
reply_buffered_event(
    Caller,
    CallReference,
    Counters,
    {packet, Address, Port, Payload}
) ->
    AddressBytes = encode_address(Address),
    saturating_increment(Counters, ?RECEIVED_PACKETS),
    saturating_add(Counters, ?RECEIVED_BYTES, byte_size(Payload)),
    Caller ! {
        http_masque_udp_reply,
        CallReference,
        {ok, {raw_system_udp_packet, AddressBytes, Port, Payload}}
    },
    ok;
reply_buffered_event(
    Caller,
    CallReference,
    _Counters,
    {packet_too_big, Family, MaximumPayload, Mtu, QuoteBytes, Delivery}
) ->
    Caller ! {
        http_masque_udp_reply,
        CallReference,
        {ok, {
            raw_system_udp_payload_too_large,
            Family,
            MaximumPayload,
            Mtu,
            QuoteBytes,
            Delivery
        }}
    },
    ok;
reply_buffered_event(_Caller, _CallReference, _Counters, none) ->
    {error, 8}.

-spec rearm_after_datagram(
    gen_udp:socket(), inet:ip_address(), inet:port_number(), pid(), reference(),
    reference(), counters(), packet_too_big_config(), waiter()
) -> no_return().
rearm_after_datagram(
    Socket,
    PeerAddress,
    Port,
    Owner,
    OwnerMonitor,
    SocketReference,
    Counters,
    PacketTooBig,
    EventWaiter
) ->
    case activate_once(Socket) of
        ok ->
            owner_loop(
                Socket,
                PeerAddress,
                Port,
                Owner,
                OwnerMonitor,
                SocketReference,
                Counters,
                PacketTooBig,
                none,
                none,
                EventWaiter
            );
        {error, _Reason} ->
            mark_unusable(Counters, PacketTooBig),
            complete_event_waiter(EventWaiter, Counters, 8),
            safe_close(Socket),
            unusable_loop(
                Owner, OwnerMonitor, SocketReference, Counters, 8
            )
    end.

-spec fail_waiter(waiter(), counters(), integer()) -> ok.
fail_waiter(none, _Counters, _Reason) ->
    ok;
fail_waiter({Caller, CallReference, Timer}, Counters, Reason) ->
    cancel_timer(Timer),
    atomics:put(Counters, ?RECEIVE_WAITING, 0),
    Caller ! {http_masque_udp_reply, CallReference, {error, Reason}},
    ok.

-spec complete_event_waiter(waiter(), counters(), integer()) -> ok.
complete_event_waiter(none, _Counters, _Reason) ->
    ok;
complete_event_waiter({Caller, CallReference, Timer}, Counters, Reason) ->
    cancel_timer(Timer),
    atomics:put(Counters, ?EVENT_WAITING, 0),
    Caller ! {http_masque_udp_reply, CallReference, {ok, Reason}},
    ok.

-spec fail_event_waiter(waiter(), counters(), integer()) -> ok.
fail_event_waiter(none, _Counters, _Reason) ->
    ok;
fail_event_waiter({Caller, CallReference, Timer}, Counters, Reason) ->
    cancel_timer(Timer),
    atomics:put(Counters, ?EVENT_WAITING, 0),
    Caller ! {http_masque_udp_reply, CallReference, {error, Reason}},
    ok.

-spec cancel_timer(reference() | none) -> ok.
cancel_timer(none) ->
    ok;
cancel_timer(Timer) ->
    _ = erlang:cancel_timer(Timer),
    ok.

-spec activate_once(gen_udp:socket()) -> ok | {error, term()}.
activate_once(Socket) ->
    try inet:setopts(Socket, [{active, once}]) of
        ok -> ok;
        {error, Reason} -> {error, Reason}
    catch
        _:_ -> {error, closed}
    end.

-spec close_owner(
    gen_udp:socket(), reference(), counters(), packet_too_big_config()
) -> ok.
close_owner(Socket, OwnerMonitor, Counters, PacketTooBig) ->
    atomics:put(Counters, ?QUEUED_COMMANDS, 0),
    atomics:put(Counters, ?BUFFERED_PACKETS, 0),
    atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
    atomics:put(Counters, ?RECEIVE_WAITING, 0),
    atomics:put(Counters, ?EVENT_WAITING, 0),
    clear_packet_too_big_buffer(PacketTooBig),
    atomics:put(Counters, ?STATE, ?STATE_CLOSED),
    erlang:demonitor(OwnerMonitor, [flush]),
    safe_close(Socket).

-spec safe_close(gen_udp:socket()) -> ok.
safe_close(Socket) ->
    try gen_udp:close(Socket) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec mark_unusable(counters(), packet_too_big_config()) -> ok.
mark_unusable(Counters, PacketTooBig) ->
    case safe_atomic_get(Counters, ?STATE, ?STATE_CLOSED) of
        State when State =:= ?STATE_SETUP; State =:= ?STATE_OPEN ->
            case atomics:compare_exchange(
                Counters, ?STATE, State, ?STATE_UNUSABLE
            ) of
                ok ->
                    atomics:put(Counters, ?BUFFERED_PACKETS, 0),
                    atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
                    atomics:put(Counters, ?RECEIVE_WAITING, 0),
                    clear_packet_too_big_buffer(PacketTooBig),
                    saturating_increment(Counters, ?SOCKET_FAILURES),
                    ok;
                _ -> mark_unusable(Counters, PacketTooBig)
            end;
        ?STATE_UNUSABLE ->
            atomics:put(Counters, ?BUFFERED_PACKETS, 0),
            atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
            atomics:put(Counters, ?RECEIVE_WAITING, 0),
            clear_packet_too_big_buffer(PacketTooBig),
            ok;
        ?STATE_CLOSED ->
            ok
    end.

-spec mark_owner_down(counters(), term()) -> ok.
mark_owner_down(Counters, PacketTooBigDiagnostics) ->
    Previous = try atomics:exchange(Counters, ?STATE, ?STATE_CLOSED) of
        State -> State
    catch
        _:_ -> ?STATE_CLOSED
    end,
    atomics:put(Counters, ?QUEUED_COMMANDS, 0),
    atomics:put(Counters, ?BUFFERED_PACKETS, 0),
    atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
    atomics:put(Counters, ?RECEIVE_WAITING, 0),
    atomics:put(Counters, ?EVENT_WAITING, 0),
    http_masque_packet_too_big_ffi:diagnostics_buffered(
        PacketTooBigDiagnostics, false
    ),
    case Previous of
        ?STATE_SETUP -> saturating_increment(Counters, ?SOCKET_FAILURES);
        ?STATE_OPEN -> saturating_increment(Counters, ?SOCKET_FAILURES);
        ?STATE_UNUSABLE -> ok;
        ?STATE_CLOSED -> ok
    end,
    ok.

-spec finish_unusable_owner(reference(), counters()) -> ok.
finish_unusable_owner(OwnerMonitor, Counters) ->
    atomics:put(Counters, ?QUEUED_COMMANDS, 0),
    atomics:put(Counters, ?BUFFERED_PACKETS, 0),
    atomics:put(Counters, ?BUFFERED_PAYLOAD_BYTES, 0),
    atomics:put(Counters, ?RECEIVE_WAITING, 0),
    atomics:put(Counters, ?EVENT_WAITING, 0),
    atomics:put(Counters, ?STATE, ?STATE_CLOSED),
    erlang:demonitor(OwnerMonitor, [flush]),
    ok.

-spec set_not_ect(gen_udp:socket(), socket_family()) -> boolean().
set_not_ect(Socket, Family) ->
    Option = case Family of
        4 -> {tos, 0};
        6 -> {tclass, 0}
    end,
    try inet:setopts(Socket, [Option]) of
        ok -> true;
        {error, _Reason} ->
            %% A newly opened OTP UDP socket has the default Not-ECT marking.
            %% No operation in this owner can install a non-zero marking.
            true
    catch
        _:_ -> true
    end.

-spec socket_buffer_sizes(gen_udp:socket()) ->
    {non_neg_integer(), non_neg_integer()}.
socket_buffer_sizes(Socket) ->
    try inet:getopts(Socket, [recbuf, sndbuf]) of
        {ok, Options} ->
            {
                buffer_size(recbuf, Options),
                buffer_size(sndbuf, Options)
            };
        {error, _Reason} ->
            {?SOCKET_BUFFER_BYTES, ?SOCKET_BUFFER_BYTES}
    catch
        _:_ -> {?SOCKET_BUFFER_BYTES, ?SOCKET_BUFFER_BYTES}
    end.

-spec buffer_size(atom(), [{atom(), term()}]) -> non_neg_integer().
buffer_size(Name, Options) ->
    case lists:keyfind(Name, 1, Options) of
        {Name, Value} when is_integer(Value), Value > 0,
                           Value =< 16777216 -> Value;
        _ -> ?SOCKET_BUFFER_BYTES
    end.

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
        _:_ -> apply_dont_fragment(Socket, Rest)
    end.

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
            ?IPPROTO_IPV6,
            ?LINUX_IPV6_MTU_DISCOVER,
            ?LINUX_PMTUDISC_PROBE
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

-spec family_options(socket_family()) -> [gen_udp:open_option()].
family_options(4) -> [inet, {ip, {0, 0, 0, 0}}];
family_options(6) -> [inet6, {ipv6_v6only, true}, {ip, {0, 0, 0, 0, 0, 0, 0, 0}}].

-spec decode_address(binary()) ->
    {ok, inet:ip_address(), socket_family()} | error.
decode_address(<<A, B, C, D>>) ->
    {ok, {A, B, C, D}, 4};
decode_address(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {ok, {A, B, C, D, E, F, G, H}, 6};
decode_address(_Address) ->
    error.

-spec encode_address(inet:ip_address()) -> binary().
encode_address({A, B, C, D}) ->
    <<A, B, C, D>>;
encode_address({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

-spec valid_handle(term()) -> boolean().
valid_handle(#{
    tag := http_masque_udp_socket,
    pid := Pid,
    reference := Reference,
    owner := Owner,
    counters := Counters,
    packet_too_big := PacketTooBig
}) ->
    is_pid(Pid) andalso is_reference(Reference) andalso is_pid(Owner) andalso
        is_reference(Counters) andalso is_map(PacketTooBig);
valid_handle(_Handle) ->
    false.

-spec counter(handle(), pos_integer(), integer()) -> integer().
counter(#{counters := Counters}, Index, Default) ->
    safe_atomic_get(Counters, Index, Default).

-spec safe_atomic_get(counters(), pos_integer(), integer()) -> integer().
safe_atomic_get(Counters, Index, Default) ->
    try atomics:get(Counters, Index) of
        Value when is_integer(Value), Value >= 0 -> Value;
        _ -> Default
    catch
        _:_ -> Default
    end.

-spec record_relay_timing(
    counters(), integer(), integer(), integer()
) -> ok.
record_relay_timing(Counters, Ingress, SendStarted, SendFinished) ->
    RelayDelay = erlang:max(0, SendStarted - Ingress),
    SendService = erlang:max(0, SendFinished - SendStarted),
    set_maximum_counter(
        Counters, ?MAXIMUM_RELAY_DELAY_MICROSECONDS, RelayDelay
    ),
    set_maximum_counter(
        Counters, ?MAXIMUM_SEND_SERVICE_MICROSECONDS, SendService
    ),
    Samples = safe_atomic_get(Counters, ?RELAY_TIMING_SAMPLES, 0),
    case Samples > 0 of
        true ->
            PreviousIngress = atomics:get(
                Counters, ?LAST_RELAY_INGRESS_MICROSECONDS
            ),
            PreviousEgress = atomics:get(
                Counters, ?LAST_RELAY_EGRESS_MICROSECONDS
            ),
            IngressGap = erlang:max(0, Ingress - PreviousIngress),
            EgressGap = erlang:max(0, SendStarted - PreviousEgress),
            Compression = erlang:max(0, IngressGap - EgressGap),
            set_maximum_counter(
                Counters,
                ?MAXIMUM_BURST_COMPRESSION_MICROSECONDS,
                Compression
            ),
            case Compression > ?MATERIAL_BURST_COMPRESSION_MICROSECONDS of
                true -> saturating_increment(
                    Counters, ?MATERIAL_BURST_COMPRESSIONS
                );
                false -> ok
            end;
        false -> ok
    end,
    atomics:put(Counters, ?LAST_RELAY_INGRESS_MICROSECONDS, Ingress),
    atomics:put(Counters, ?LAST_RELAY_EGRESS_MICROSECONDS, SendStarted),
    saturating_increment(Counters, ?RELAY_TIMING_SAMPLES).

-spec set_maximum_counter(counters(), pos_integer(), non_neg_integer()) -> ok.
set_maximum_counter(Counters, Index, Value) ->
    Current = safe_atomic_get(Counters, Index, 0),
    case Value =< Current of
        true -> ok;
        false ->
            case atomics:compare_exchange(Counters, Index, Current, Value) of
                ok -> ok;
                _ -> set_maximum_counter(Counters, Index, Value)
            end
    end.

-spec saturating_increment(counters(), pos_integer()) -> ok.
saturating_increment(Counters, Index) ->
    saturating_add(Counters, Index, 1).

-spec saturating_add(counters(), pos_integer(), non_neg_integer()) -> ok.
saturating_add(_Counters, _Index, 0) ->
    ok;
saturating_add(Counters, Index, Amount) ->
    Current = safe_atomic_get(Counters, Index, 0),
    case Current >= ?MAXIMUM_COUNTER of
        true ->
            ok;
        false ->
            Next = erlang:min(?MAXIMUM_COUNTER, Current + Amount),
            case atomics:compare_exchange(Counters, Index, Current, Next) of
                ok -> ok;
                _ -> saturating_add(Counters, Index, Amount)
            end
    end.

-spec set_boolean(counters(), pos_integer(), boolean()) -> ok.
set_boolean(Counters, Index, Value) ->
    atomics:put(Counters, Index, case Value of
        true -> 1;
        false -> 0
    end).

-spec acquire_idle_state(idle_state()) ->
    active | stopped | expired | invalid.
acquire_idle_state(State) ->
    try atomics:get(State, ?IDLE_STATE) of
        ?IDLE_ACTIVE ->
            case atomics:compare_exchange(
                State, ?IDLE_STATE, ?IDLE_ACTIVE, ?IDLE_LOCKED
            ) of
                ok -> active;
                _ -> acquire_idle_state(State)
            end;
        ?IDLE_LOCKED ->
            erlang:yield(),
            acquire_idle_state(State);
        ?IDLE_STOPPED -> stopped;
        ?IDLE_EXPIRED -> expired;
        _ -> invalid
    catch
        _:_ -> invalid
    end.

-spec reserve_idle_wake(idle_state()) -> 0 | 1.
reserve_idle_wake(State) ->
    case atomics:compare_exchange(
        State, ?IDLE_PENDING, 0, 1
    ) of
        ok ->
            saturating_increment(State, ?IDLE_WAKE_SIGNALS),
            1;
        _ -> 0
    end.

-spec idle_public_state(idle_state()) -> integer().
idle_public_state(State) ->
    try atomics:get(State, ?IDLE_STATE) of
        ?IDLE_LOCKED -> ?IDLE_ACTIVE;
        Value -> Value
    catch
        _:_ -> ?IDLE_STOPPED
    end.

-spec call_wait(pos_integer()) -> pos_integer().
call_wait(Timeout) ->
    erlang:min(2147483647, Timeout + ?CALL_GRACE_MILLISECONDS).

-spec await_down(pid(), reference()) -> ok.
await_down(Pid, Monitor) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after ?CALL_GRACE_MILLISECONDS ->
        exit(Pid, kill),
        receive
            {'DOWN', Monitor, process, Pid, _Reason} -> ok
        end
    end.

-spec drain_start_reply(reference()) -> ok.
drain_start_reply(Reference) ->
    receive
        {Reference, _Outcome} -> ok
    after 0 ->
        ok
    end.

-spec drain_call_reply(reference()) -> ok.
drain_call_reply(Reference) ->
    receive
        {http_masque_udp_reply, Reference, _Outcome} -> ok
    after 0 ->
        ok
    end.

-spec open_error_code(term()) -> integer().
open_error_code(timeout) -> 2;
open_error_code(econnrefused) -> 5;
open_error_code(enetunreach) -> 6;
open_error_code(ehostunreach) -> 6;
open_error_code(eafnosupport) -> 6;
open_error_code(eaddrnotavail) -> 6;
open_error_code(_Reason) -> 8.

-spec runtime_error_code(term()) -> integer().
runtime_error_code(timeout) -> 2;
runtime_error_code(eagain) -> 3;
runtime_error_code(closed) -> 4;
runtime_error_code(emsgsize) -> 7;
runtime_error_code(_Reason) -> 8.
