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
    idle_stop_alias/0,
    idle_signal_stop/1,
    idle_join/2,
    idle_snapshot/1,
    material_burst_compression/2,
    idle_stop/1,
    not_ect_configuration/2,
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
-define(CALL_COMPLETION_TAIL_MILLISECONDS, 20).
-define(FORCE_JOIN_MILLISECONDS, 10).
-define(OWNER_MAX_HEAP_WORDS, 524288).
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
-define(TERMINAL_CAUSE, 28).

-define(TERMINAL_CAUSE_NONE, 0).
-define(TERMINAL_CAUSE_SETUP_TIMEOUT, 2).

-define(MATERIAL_BURST_COMPRESSION_MICROSECONDS, 1000).
%% The owner loop sends one datagram per send command and never
%% coalesces two, which the snapshot reports as the maximum batch.
-define(SEND_BATCH_PACKETS, 1).

-define(IDLE_STATE, 1).
-define(IDLE_TIMEOUT, 2).

-define(IDLE_PENDING, 4).
-define(IDLE_FAILURE, 5).
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
-define(IDLE_UNAVAILABLE, 3).
-define(IDLE_STOP_WORD, -9223372036854775808).
-define(IDLE_EXPIRED_WORD, -9223372036854775807).
-define(IDLE_MIN_CLOCK, -9223372036854775806).
-define(IDLE_CAS_ATTEMPTS, 256).

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

%% One terminal notification is independent of activity wake admission. OTP
%% deactivates a reply alias on its first accepted message; repeated senders
%% need no application-side reservation which could outlive a killed sender.
%% The alias is reclaimed automatically when its creating idle owner exits.
-spec idle_stop_alias() -> reference().
idle_stop_alias() -> erlang:alias([reply]).

-spec idle_signal_stop(reference()) -> nil.
idle_signal_stop(Alias) when is_reference(Alias) ->
    Alias ! {Alias},
    nil.

%% Joining never kills the owner: it may be running an already bounded resource
%% cleanup. The caller must preserve false as an incomplete close result.
-spec idle_join(pid(), pos_integer()) -> boolean().
idle_join(Owner, Timeout) when is_pid(Owner), is_integer(Timeout),
                             Timeout > 0, Timeout =< 2147483647 ->
    case Owner =:= self() of
        true -> true;
        false ->
            Monitor = erlang:monitor(process, Owner),
            receive
                {'DOWN', Monitor, process, Owner, _} -> true
            after Timeout ->
                erlang:demonitor(Monitor, [flush]),
                false
            end
    end;
idle_join(_, _) -> false.

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

%% The control word contains either an absolute monotonic deadline or one of
%% two reserved terminal values. No process owns a writer lock. Every CAS loop
%% has a fixed budget; failure is latched and reported as unavailable, never as
%% a successful activity or an idle expiry. The existing owner rechecks this
%% word at its previous deadline even if a wake-credit holder dies before send.
-spec idle_new(pos_integer(), integer()) -> idle_state().
idle_new(Timeout, Now) ->
    State = atomics:new(12, [{signed, true}]),
    atomics:put(State, ?IDLE_STATE, ?IDLE_STOP_WORD),
    case idle_clock(Timeout, Now) of
        {ok, Deadline} ->
            atomics:put(State, ?IDLE_TIMEOUT, Timeout),
            atomics:put(State, ?IDLE_STATE, Deadline);
        error -> atomics:put(State, ?IDLE_FAILURE, 1)
    end,
    State.

-spec idle_activity(idle_state(), integer(), 1 | 2) -> 0 | 1 | 2.
idle_activity(State, Now, Direction) when Direction =:= 1; Direction =:= 2 ->
    try
        case idle_clock(atomics:get(State, ?IDLE_TIMEOUT), Now) of
            {ok, Deadline} ->
                case idle_extend(State, Deadline, ?IDLE_CAS_ATTEMPTS) of
                    active -> idle_record_activity(State, Direction);
                    terminal -> 0;
                    unavailable -> 2
                end;
            error -> idle_fail(State, 1)
        end
    catch
        error:badarg -> 2
    end;
idle_activity(State, _Now, _Direction) ->
    try idle_fail(State, 1)
    catch error:badarg -> 2
    end.

-spec idle_ack(idle_state()) -> integer().
idle_ack(State) ->
    try
        case atomics:exchange(State, ?IDLE_PENDING, 0) of
            1 -> _ = idle_increment(State, ?IDLE_OWNER_WAKEUPS);
            _ -> ok
        end,
        idle_public_state(State)
    catch error:badarg -> ?IDLE_UNAVAILABLE
    end.

-spec idle_due(idle_state(), integer()) -> {integer(), non_neg_integer()}.
idle_due(State, Now) ->
    try
        case is_integer(Now) andalso Now >= ?IDLE_MIN_CLOCK andalso Now =< ?MAXIMUM_COUNTER of
            true ->
                case idle_increment(State, ?IDLE_DEADLINE_CHECKS) of
                    ok -> idle_expire(State, Now, ?IDLE_CAS_ATTEMPTS);
                    unavailable -> {?IDLE_UNAVAILABLE, 0}
                end;
            false ->
                _ = idle_fail(State, 1),
                {idle_public_state(State), 0}
        end
    catch error:badarg -> {?IDLE_UNAVAILABLE, 0}
    end.

-spec idle_stop(idle_state()) -> 0 | 1 | 2.
idle_stop(State) ->
    try idle_stop_loop(State, ?IDLE_CAS_ATTEMPTS)
    catch error:badarg -> 2
    end.

-spec idle_snapshot(idle_state()) ->
    {integer(), integer(), integer(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer()}.
idle_snapshot(State) ->
    try
        %% This is an observational read, not a multi-field transaction. The
        %% directional sum is exact by construction, including saturation.
        %% At the shared ceiling, inbound is clipped to remaining total credit.
        Outbound = atomics:get(State, ?IDLE_OUTBOUND_ACTIVITIES),
        Inbound = erlang:min(atomics:get(State, ?IDLE_INBOUND_ACTIVITIES),
                            ?MAXIMUM_COUNTER - Outbound),
        Control = atomics:get(State, ?IDLE_STATE),
        PublicState = idle_state_value(State, Control),
        Deadline = case Control >= ?IDLE_MIN_CLOCK of
            true -> Control;
            false -> 0
        end,
        {PublicState, atomics:get(State, ?IDLE_TIMEOUT), Deadline,
         atomics:get(State, ?IDLE_PENDING) =:= 1, Outbound + Inbound,
         Outbound, Inbound, atomics:get(State, ?IDLE_WAKE_SIGNALS),
         atomics:get(State, ?IDLE_OWNER_WAKEUPS), atomics:get(State, ?IDLE_DEADLINE_CHECKS),
         atomics:get(State, ?IDLE_EXPIRATIONS), atomics:get(State, ?IDLE_STOP_SIGNALS)}
    catch
        error:badarg -> {?IDLE_UNAVAILABLE, 0, 0, false, 0, 0, 0, 0, 0, 0, 0, 0}
    end.

idle_clock(Timeout, Now)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647,
         is_integer(Now), Now >= ?IDLE_MIN_CLOCK,
         Now =< ?MAXIMUM_COUNTER - Timeout -> {ok, Now + Timeout};
idle_clock(_, _) -> error.

idle_extend(State, Deadline, Remaining) ->
    Current = atomics:get(State, ?IDLE_STATE),
    case idle_state_value(State, Current) of
        ?IDLE_ACTIVE when Current >= Deadline -> active;
        ?IDLE_ACTIVE when Remaining > 0 ->
            case atomics:compare_exchange(State, ?IDLE_STATE, Current, Deadline) of
                ok -> active;
                _ -> idle_extend(State, Deadline, Remaining - 1)
            end;
        ?IDLE_ACTIVE -> _ = idle_fail(State, 2), unavailable;
        ?IDLE_UNAVAILABLE -> unavailable;
        _ -> terminal
    end.

idle_record_activity(State, Direction) ->
    Index = case Direction of
        1 -> ?IDLE_OUTBOUND_ACTIVITIES;
        2 -> ?IDLE_INBOUND_ACTIVITIES
    end,
    case idle_increment(State, Index) of
        ok -> reserve_idle_wake(State);
        unavailable -> 2
    end.

idle_expire(State, Now, Remaining) ->
    Current = atomics:get(State, ?IDLE_STATE),
    case idle_state_value(State, Current) of
        ?IDLE_ACTIVE when Current > Now ->
            {?IDLE_ACTIVE, erlang:min(atomics:get(State, ?IDLE_TIMEOUT), Current - Now)};
        ?IDLE_ACTIVE when Remaining > 0 ->
            case atomics:compare_exchange(State, ?IDLE_STATE, Current, ?IDLE_EXPIRED_WORD) of
                ok ->
                    atomics:put(State, ?IDLE_PENDING, 0),
                    atomics:put(State, ?IDLE_EXPIRATIONS, 1),
                    {?IDLE_EXPIRED, 0};
                _ -> idle_expire(State, Now, Remaining - 1)
            end;
        ?IDLE_ACTIVE -> _ = idle_fail(State, 2), {?IDLE_UNAVAILABLE, 0};
        PublicState -> {PublicState, 0}
    end.

idle_stop_loop(State, Remaining) ->
    Current = atomics:get(State, ?IDLE_STATE),
    case Current of
        ?IDLE_STOP_WORD -> atomics:put(State, ?IDLE_PENDING, 0), 0;
        ?IDLE_EXPIRED_WORD -> 0;
        _ when Remaining > 0 ->
            case atomics:compare_exchange(State, ?IDLE_STATE, Current, ?IDLE_STOP_WORD) of
                ok ->
                    atomics:put(State, ?IDLE_STOP_SIGNALS, 1),
                    atomics:put(State, ?IDLE_PENDING, 0),
                    1;
                _ -> idle_stop_loop(State, Remaining - 1)
            end;
        _ -> idle_fail(State, 2)
    end.

idle_fail(State, Cause) ->
    case atomics:get(State, ?IDLE_STATE) of
        ?IDLE_STOP_WORD -> 0;
        ?IDLE_EXPIRED_WORD -> 0;
        _ ->
            _ = atomics:compare_exchange(State, ?IDLE_FAILURE, 0, Cause),
            2
    end.

idle_increment(State, Index) -> idle_increment(State, Index, ?IDLE_CAS_ATTEMPTS).
idle_increment(State, Index, Remaining) ->
    Current = atomics:get(State, Index),
    case Current >= ?MAXIMUM_COUNTER of
        true -> ok;
        false when Remaining > 0 ->
            case atomics:compare_exchange(State, Index, Current, Current + 1) of
                ok -> ok;
                _ -> idle_increment(State, Index, Remaining - 1)
            end;
        false -> _ = idle_fail(State, 2), unavailable
    end.
-spec close(handle(), integer()) -> {ok, nil} | {error, integer()}.
close(Handle, Timeout)
    when is_integer(Timeout), Timeout > 0, Timeout =< 2147483647 ->
    case valid_handle(Handle) of
        false ->
            {error, 1};
        true ->
            Deadlines = call_deadlines(Timeout),
            case counter(Handle, ?STATE, ?STATE_CLOSED) of
                ?STATE_CLOSED ->
                    confirm_closed_owner(Handle, Deadlines);
                _ -> close_call(Handle, Deadlines)
            end
    end;
close(_Handle, _Timeout) ->
    {error, 1}.

-spec snapshot(term()) ->
    {integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), boolean(), boolean(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(),
     boolean(), boolean(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer()}.
snapshot(Handle) ->
    case valid_handle(Handle) of
        false ->
            {?STATE_CLOSED, ?MAXIMUM_QUEUED_COMMANDS, ?SOCKET_BUFFER_BYTES,
             0, 0, ?MAXIMUM_UDP_PAYLOAD_BYTES, 0, 0, 0, false, false, 0, 0,
             0, 0, 0, 0, 0, 0, false, false, 0, 1, 0, 0, 0, 0, 0, 0, 0};
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
                counter(Handle, ?NOT_ECT, 0) > 0,
                counter(Handle, ?RELAY_TIMING_SAMPLES, 0),
                ?SEND_BATCH_PACKETS,
                counter(Handle, ?MAXIMUM_RELAY_DELAY_MICROSECONDS, 0),
                counter(Handle, ?MAXIMUM_SEND_SERVICE_MICROSECONDS, 0),
                counter(Handle, ?MATERIAL_BURST_COMPRESSIONS, 0),
                counter(
                    Handle, ?MAXIMUM_BURST_COMPRESSION_MICROSECONDS, 0
                ),
                counter(Handle, ?MESSAGE_TOO_LARGE_SENDS, 0),
                counter(Handle, ?FRAGMENTATION_RETRIES, 0),
                counter(Handle, ?NOT_ECT, 0)
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
    {OperationDeadline, CompletionDeadline} = call_deadlines(Timeout),
    Counters = atomics:new(28, [{signed, true}]),
    PacketTooBig = http_masque_packet_too_big_ffi:diagnostics_new(
        TargetPayloadLimit, Family
    ),
    OwnerSpawn = try spawn_opt(fun() ->
        owner_start_gate(
            Caller,
            StartReference,
            SocketReference,
            Counters,
            PeerAddress,
            Family,
            Port,
            Owner,
            {Family, TargetPayloadLimit, PacketTooBig, Timeout},
            OperationDeadline
        )
    end, [monitor, {max_heap_size, #{
        size => ?OWNER_MAX_HEAP_WORDS,
        kill => true,
        error_logger => false,
        include_shared_binaries => true
    }}]) of
        {SpawnedPid, SpawnedMonitor} -> {ok, SpawnedPid, SpawnedMonitor}
    catch _:_ -> error
    end,
    case OwnerSpawn of
        {ok, Pid, Monitor} ->
            open_wait_ready(
                Pid,
                Monitor,
                Caller,
                StartReference,
                SocketReference,
                Counters,
                PacketTooBig,
                Owner,
                OperationDeadline,
                CompletionDeadline
            );
        error -> {error, 8}
    end.

open_wait_ready(
    Pid,
    Monitor,
    Caller,
    StartReference,
    SocketReference,
    Counters,
    PacketTooBig,
    Owner,
    OperationDeadline,
    CompletionDeadline
) ->
    Remaining = erlang:max(
        0, OperationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {StartReference, owner_ready, Pid} ->
            case operation_reply_is_timely(
                erlang:monotonic_time(millisecond), OperationDeadline
            ) of
                true ->
                    Pid ! {StartReference, start_owner, Caller},
                    open_wait_result(
                        Pid,
                        Monitor,
                        StartReference,
                        SocketReference,
                        Counters,
                        PacketTooBig,
                        Owner,
                        OperationDeadline,
                        CompletionDeadline
                    );
                false ->
                    Pid ! {StartReference, cancel_owner, Caller},
                    open_force_join(
                        Pid, Monitor, StartReference, CompletionDeadline, 2
                    )
            end;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            drain_start_reply(StartReference),
            {error, 8}
    after Remaining ->
        Pid ! {StartReference, cancel_owner, Caller},
        open_force_join(Pid, Monitor, StartReference, CompletionDeadline, 2)
    end.

open_wait_result(
    Pid,
    Monitor,
    StartReference,
    SocketReference,
    Counters,
    PacketTooBig,
    Owner,
    OperationDeadline,
    CompletionDeadline
) ->
    Remaining = erlang:max(
        0, OperationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {StartReference,
         {ok, DontFragment, NotEct, ReceiveBufferBytes, SendBufferBytes}} ->
            case operation_reply_is_timely(
                erlang:monotonic_time(millisecond), OperationDeadline
            ) of
                true ->
                    erlang:demonitor(Monitor, [flush]),
                    set_boolean(Counters, ?DONT_FRAGMENT, DontFragment),
                    atomics:put(Counters, ?NOT_ECT, NotEct),
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
                false ->
                    open_force_join(
                        Pid, Monitor, StartReference, CompletionDeadline, 2
                    )
            end;
        {StartReference, {error, Reason}} ->
            case operation_reply_is_timely(
                erlang:monotonic_time(millisecond), OperationDeadline
            ) of
                true ->
                    ForceAt = force_join_at(
                        OperationDeadline, CompletionDeadline
                    ),
                    case join_or_force_until(
                        Pid, Monitor, ForceAt, CompletionDeadline
                    ) of
                        true -> {error, open_error_code(Reason)};
                        false -> {error, 8}
                    end;
                false ->
                    open_force_join(
                        Pid, Monitor, StartReference, CompletionDeadline, 2
                    )
            end;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            drain_start_reply(StartReference),
            {error, 8}
    after Remaining ->
        open_force_join(Pid, Monitor, StartReference, CompletionDeadline, 2)
    end.

open_force_join(Pid, Monitor, StartReference, CompletionDeadline, ErrorCode) ->
    exit(Pid, kill),
    Joined = await_down_until(Pid, Monitor, CompletionDeadline),
    drain_start_reply(StartReference),
    case Joined of
        true -> {error, ErrorCode};
        false -> {error, 8}
    end.

owner_start_gate(
    Caller,
    StartReference,
    SocketReference,
    Counters,
    PeerAddress,
    Family,
    Port,
    Owner,
    PacketTooBig,
    OperationDeadline
) ->
    CallerMonitor = erlang:monitor(process, Caller),
    Caller ! {StartReference, owner_ready, self()},
    Remaining = erlang:max(
        0, OperationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {StartReference, start_owner, Caller} ->
            case operation_reply_is_timely(
                erlang:monotonic_time(millisecond), OperationDeadline
            ) of
                true ->
                    owner_init(
                        Caller,
                        CallerMonitor,
                        StartReference,
                        SocketReference,
                        Counters,
                        PeerAddress,
                        Family,
                        Port,
                        Owner,
                        PacketTooBig,
                        OperationDeadline
                    );
                false ->
                    Caller ! {StartReference, {error, timeout}},
                    exit(normal)
            end;
        {StartReference, cancel_owner, Caller} -> exit(normal);
        {'DOWN', CallerMonitor, process, Caller, _Reason} -> exit(normal)
    after Remaining ->
        Caller ! {StartReference, {error, timeout}},
        exit(normal)
    end.

-spec owner_init(
    pid(), reference(), reference(), reference(), counters(), inet:ip_address(),
    socket_family(), inet:port_number(), pid(), packet_too_big_config(),
    integer()
) -> no_return().
owner_init(
    Caller,
    CallerMonitor,
    StartReference,
    SocketReference,
    Counters,
    PeerAddress,
    Family,
    Port,
    Owner,
    PacketTooBig,
    SetupDeadline
) ->
    case erlang:is_process_alive(Caller) of
        false ->
            erlang:demonitor(CallerMonitor, [flush]),
            exit(normal);
        true -> owner_init_socket(
            Caller,
            CallerMonitor,
            StartReference,
            SocketReference,
            Counters,
            PeerAddress,
            Family,
            Port,
            Owner,
            PacketTooBig,
            SetupDeadline
        )
    end.

owner_init_socket(
    Caller,
    CallerMonitor,
    StartReference,
    SocketReference,
    Counters,
    PeerAddress,
    Family,
    Port,
    Owner,
    PacketTooBig,
    SetupDeadline
) ->
    case open_socket(Family, PeerAddress, Port) of
        {error, Reason} ->
            Caller ! {StartReference, {error, Reason}},
            erlang:demonitor(CallerMonitor, [flush]),
            exit(normal);
        {ok, Socket, DontFragment, NotEct, ReceiveBufferBytes,
         SendBufferBytes} ->
            case erlang:is_process_alive(Caller) of
                false ->
                    gen_udp:close(Socket),
                    erlang:demonitor(CallerMonitor, [flush]),
                    exit(normal);
                true ->
                    OwnerMonitor = erlang:monitor(process, Owner),
                    case activate_once(Socket) of
                        ok ->
                            Caller ! {
                                StartReference,
                                {ok, DontFragment, NotEct,
                                 ReceiveBufferBytes, SendBufferBytes}
                            },
                            erlang:demonitor(CallerMonitor, [flush]),
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
                            erlang:demonitor(CallerMonitor, [flush]),
                            exit(normal)
                    end
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
    case operation_reply_is_timely(
        erlang:monotonic_time(millisecond), Deadline
    ) of
        false ->
            mark_setup_timeout(Counters),
            close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
            exit(normal);
        true ->
            setup_loop_wait(
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
    end.

setup_loop_wait(
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
                    case operation_reply_is_timely(
                        erlang:monotonic_time(millisecond), Deadline
                    ) of
                        true ->
                            publish_adoption(
                                Counters,
                                Caller,
                                CallReference,
                                fun() -> ok end
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
                                none,
                                none
                            );
                        false ->
                            reject_expired_adoption(
                                Socket,
                                OwnerMonitor,
                                Counters,
                                PacketTooBig,
                                Caller,
                                CallReference,
                                fun() -> ok end
                            )
                    end;
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
        mark_setup_timeout(Counters),
        close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
        exit(normal)
    end.

-spec publish_adoption(
    counters(), pid(), reference(), fun(() -> term())
) -> ok.
publish_adoption(Counters, Caller, CallReference, AfterPublish) ->
    %% Publish the open state before acknowledging adoption. Once the caller
    %% observes success, its next command must not race the setup-state gate.
    atomics:put(Counters, ?STATE, ?STATE_OPEN),
    _ = AfterPublish(),
    Caller ! {http_masque_udp_reply, CallReference, {ok, nil}},
    ok.

-spec reject_expired_adoption(
    gen_udp:socket(), reference(), counters(), packet_too_big_config(),
    pid(), reference(), fun(() -> term())
) -> no_return().
reject_expired_adoption(
    Socket,
    OwnerMonitor,
    Counters,
    PacketTooBig,
    Caller,
    CallReference,
    AfterClose
) ->
    %% The hook is private and production supplies a no-op. Source-probe tests
    %% stop here to prove explicit socket closure precedes the typed timeout;
    %% this function contains the stale-adoption path's only close_owner call.
    mark_setup_timeout(Counters),
    close_owner(Socket, OwnerMonitor, Counters, PacketTooBig),
    _ = AfterClose(),
    Caller ! {
        http_masque_udp_reply,
        CallReference,
        {error, 2}
    },
    exit(normal).

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
         {receive_udp, Deadline}} ->
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
                        erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
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
         {receive_event, Deadline}} ->
            release_command(Counters),
            case EventWaiter of
                none ->
                    atomics:put(Counters, ?EVENT_WAITING, 1),
                    Timer = erlang:send_after(
                        erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
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
    {OperationDeadline, CompletionDeadline} = call_deadlines(Timeout),
    CallReference = make_ref(),
    Monitor = erlang:monitor(process, Pid),
    case operation_reply_is_timely(
        erlang:monotonic_time(millisecond), OperationDeadline
    ) of
        true ->
            Pid ! {
                http_masque_udp_call,
                SocketReference,
                CallReference,
                self(),
                waiter_command_deadline(Command, OperationDeadline, CompletionDeadline)
            },
            monitored_call_wait(
                Pid,
                Monitor,
                CallReference,
                Counters,
                PacketTooBigDiagnostics,
                OperationDeadline,
                CompletionDeadline,
                is_waiter_command(Command)
            );
        false ->
            force_failed_call(
                Pid,
                Monitor,
                CallReference,
                Counters,
                PacketTooBigDiagnostics,
                CompletionDeadline
            )
    end.

-spec waiter_command_deadline(term(), integer(), integer()) -> term().
waiter_command_deadline({receive_udp, _Timeout}, Deadline, CompletionDeadline) ->
    {receive_udp, Deadline - erlang:max(1, CompletionDeadline - Deadline)};
waiter_command_deadline({receive_event, _Timeout}, Deadline, CompletionDeadline) ->
    {receive_event, Deadline - erlang:max(1, CompletionDeadline - Deadline)};
waiter_command_deadline(Command, _Deadline, _CompletionDeadline) -> Command.

-spec is_waiter_command(term()) -> boolean().
is_waiter_command({receive_udp, _Timeout}) -> true;
is_waiter_command({receive_event, _Timeout}) -> true;
is_waiter_command(_Command) -> false.

monitored_call_wait(
    Pid,
    Monitor,
    CallReference,
    Counters,
    PacketTooBigDiagnostics,
    OperationDeadline,
    CompletionDeadline,
    Waiting
) ->
    Remaining = erlang:max(
        0, OperationDeadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {http_masque_udp_reply, CallReference, Result} ->
            case operation_result_is_timely(
                erlang:monotonic_time(millisecond), OperationDeadline,
                CompletionDeadline, Waiting, Result
            ) of
                true ->
                    erlang:demonitor(Monitor, [flush]),
                    Result;
                false ->
                    force_failed_call(
                        Pid,
                        Monitor,
                        CallReference,
                        Counters,
                        PacketTooBigDiagnostics,
                        CompletionDeadline
                    )
            end;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            mark_owner_down(Counters, PacketTooBigDiagnostics),
            drain_call_reply(CallReference),
            terminal_down_error(Counters, 4)
    after Remaining ->
        case Waiting of
            true ->
                await_waiter_timeout(
                    Pid, Monitor, CallReference, Counters,
                    PacketTooBigDiagnostics, OperationDeadline,
                    CompletionDeadline
                );
            false ->
                force_failed_call(
                    Pid, Monitor, CallReference, Counters,
                    PacketTooBigDiagnostics, CompletionDeadline
                )
        end
    end.

%% The owner's timeout is a negative acknowledgement that its receive credit
%% is already returned. Its confirmation may use the existing cleanup tail;
%% payloads and other successful replies must still precede the operation deadline.
-spec await_waiter_timeout(
    pid(), reference(), reference(), counters(), term(), integer(), integer()
) -> {error, integer()}.
await_waiter_timeout(
    Pid, Monitor, CallReference, Counters, PacketTooBigDiagnostics,
    OperationDeadline, CompletionDeadline
) ->
    ForceAt = force_join_at(OperationDeadline, CompletionDeadline),
    Remaining = erlang:max(0, ForceAt - erlang:monotonic_time(millisecond)),
    receive
        {http_masque_udp_reply, CallReference, {error, 2}} ->
            case erlang:monotonic_time(millisecond) < ForceAt of
                true ->
                    erlang:demonitor(Monitor, [flush]),
                    {error, 2};
                false ->
                    force_failed_call(
                        Pid, Monitor, CallReference, Counters,
                        PacketTooBigDiagnostics, CompletionDeadline
                    )
            end;
        {http_masque_udp_reply, CallReference, _LateResult} ->
            force_failed_call(
                Pid, Monitor, CallReference, Counters,
                PacketTooBigDiagnostics, CompletionDeadline
            );
        {'DOWN', Monitor, process, Pid, _Reason} ->
            mark_owner_down(Counters, PacketTooBigDiagnostics),
            drain_call_reply(CallReference),
            terminal_down_error(Counters, 4)
    after Remaining ->
        force_failed_call(
            Pid, Monitor, CallReference, Counters,
            PacketTooBigDiagnostics, CompletionDeadline
        )
    end.

-spec operation_result_is_timely(integer(), integer(), integer(), boolean(), term()) ->
    boolean().
operation_result_is_timely(Now, OperationDeadline, CompletionDeadline, Waiting, Result) ->
    operation_reply_is_timely(Now, OperationDeadline) orelse
        (Waiting andalso Result =:= {error, 2} andalso
         Now < force_join_at(OperationDeadline, CompletionDeadline)).

force_failed_call(
    Pid,
    Monitor,
    CallReference,
    Counters,
    PacketTooBigDiagnostics,
    CompletionDeadline
) ->
    exit(Pid, kill),
    _Joined = await_down_until(Pid, Monitor, CompletionDeadline),
    mark_owner_down(Counters, PacketTooBigDiagnostics),
    drain_call_reply(CallReference),
    {error, 8}.

close_call(
    #{pid := Pid, reference := SocketReference, counters := Counters,
      packet_too_big := PacketTooBigDiagnostics},
    {OperationDeadline, CompletionDeadline}
) ->
    CallReference = make_ref(),
    Monitor = erlang:monitor(process, Pid),
    case operation_reply_is_timely(
        erlang:monotonic_time(millisecond), OperationDeadline
    ) of
        true ->
            Pid ! {
                http_masque_udp_call,
                SocketReference,
                CallReference,
                self(),
                close
            },
            close_call_wait(
                Pid,
                Monitor,
                CallReference,
                Counters,
                PacketTooBigDiagnostics,
                OperationDeadline,
                CompletionDeadline,
                none,
                false
            );
        false ->
            force_failed_close(
                Pid,
                Monitor,
                CallReference,
                Counters,
                PacketTooBigDiagnostics,
                CompletionDeadline
            )
    end.

close_call_wait(
    Pid,
    Monitor,
    CallReference,
    Counters,
    PacketTooBigDiagnostics,
    OperationDeadline,
    CompletionDeadline,
    Reply,
    Down
) ->
    case {Reply, Down} of
        {{some, Result}, true} ->
            drain_call_reply(CallReference),
            case erlang:monotonic_time(millisecond) =< CompletionDeadline of
                true -> Result;
                false ->
                    mark_owner_down(Counters, PacketTooBigDiagnostics),
                    {error, 8}
            end;
        {none, true} ->
            mark_owner_down(Counters, PacketTooBigDiagnostics),
            drain_call_reply(CallReference),
            terminal_down_error(Counters, 8);
        _ ->
            WaitUntil = case Reply of
                none -> OperationDeadline;
                {some, _} -> force_join_at(
                    OperationDeadline, CompletionDeadline
                )
            end,
            Remaining = erlang:max(
                0, WaitUntil - erlang:monotonic_time(millisecond)
            ),
            receive
                {http_masque_udp_reply, CallReference, Result} ->
                    case operation_reply_is_timely(
                        erlang:monotonic_time(millisecond),
                        OperationDeadline
                    ) of
                        true ->
                            close_call_wait(
                                Pid,
                                Monitor,
                                CallReference,
                                Counters,
                                PacketTooBigDiagnostics,
                                OperationDeadline,
                                CompletionDeadline,
                                {some, Result},
                                Down
                            );
                        false ->
                            force_failed_close(
                                Pid,
                                Monitor,
                                CallReference,
                                Counters,
                                PacketTooBigDiagnostics,
                                CompletionDeadline
                            )
                    end;
                {'DOWN', Monitor, process, Pid, normal} ->
                    close_call_wait(
                        Pid,
                        Monitor,
                        CallReference,
                        Counters,
                        PacketTooBigDiagnostics,
                        OperationDeadline,
                        CompletionDeadline,
                        Reply,
                        true
                    );
                {'DOWN', Monitor, process, Pid, _Reason} ->
                    mark_owner_down(Counters, PacketTooBigDiagnostics),
                    drain_call_reply(CallReference),
                    terminal_down_error(Counters, 8)
            after Remaining ->
                force_failed_close(
                    Pid,
                    Monitor,
                    CallReference,
                    Counters,
                    PacketTooBigDiagnostics,
                    CompletionDeadline
                )
            end
    end.

force_failed_close(
    Pid,
    Monitor,
    CallReference,
    Counters,
    PacketTooBigDiagnostics,
    CompletionDeadline
) ->
    exit(Pid, kill),
    _Joined = await_down_until(Pid, Monitor, CompletionDeadline),
    mark_owner_down(Counters, PacketTooBigDiagnostics),
    drain_call_reply(CallReference),
    {error, 8}.

confirm_closed_owner(
    #{pid := Pid, counters := Counters,
      packet_too_big := PacketTooBigDiagnostics},
    {OperationDeadline, CompletionDeadline}
) ->
    Monitor = erlang:monitor(process, Pid),
    Remaining = erlang:max(
        0, force_join_at(OperationDeadline, CompletionDeadline)
            - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, Pid, normal} ->
            closed_join_result(CompletionDeadline);
        {'DOWN', Monitor, process, Pid, noproc} ->
            closed_join_result(CompletionDeadline);
        {'DOWN', Monitor, process, Pid, _Reason} ->
            mark_owner_down(Counters, PacketTooBigDiagnostics),
            {error, 8}
    after Remaining ->
        exit(Pid, kill),
        case await_down_until(Pid, Monitor, CompletionDeadline) of
            true ->
                mark_owner_down(Counters, PacketTooBigDiagnostics),
                {error, 8};
            false ->
                mark_owner_down(Counters, PacketTooBigDiagnostics),
                {error, 8}
        end
    end.

closed_join_result(CompletionDeadline) ->
    case erlang:monotonic_time(millisecond) =< CompletionDeadline of
        true -> {ok, nil};
        false -> {error, 8}
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
    {ok, gen_udp:socket(), boolean(), 1..3, non_neg_integer(),
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
                    case NotEct of
                        0 ->
                            gen_udp:close(Socket),
                            {error, not_ect_configuration_failed};
                        _ ->
                            {ReceiveBufferBytes, SendBufferBytes} =
                                socket_buffer_sizes(Socket),
                            {ok, Socket, DontFragment, NotEct, ReceiveBufferBytes,
                             SendBufferBytes}
                    end
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

-spec mark_setup_timeout(counters()) -> ok.
mark_setup_timeout(Counters) ->
    try atomics:compare_exchange(
        Counters,
        ?TERMINAL_CAUSE,
        ?TERMINAL_CAUSE_NONE,
        ?TERMINAL_CAUSE_SETUP_TIMEOUT
    ) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec terminal_down_error(counters(), integer()) -> {error, integer()}.
terminal_down_error(Counters, Default) ->
    case safe_atomic_get(
        Counters, ?TERMINAL_CAUSE, ?TERMINAL_CAUSE_NONE
    ) of
        ?TERMINAL_CAUSE_SETUP_TIMEOUT -> {error, 2};
        _ -> {error, Default}
    end.

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

-spec set_not_ect(gen_udp:socket(), socket_family()) -> 0..3.
set_not_ect(Socket, Family) ->
    Option = case Family of
        4 -> {tos, 0};
        6 -> {tclass, 0}
    end,
    Name = element(1, Option),
    not_ect_configuration(fun() -> inet:setopts(Socket, [Option]) end,
        fun() -> inet:getopts(Socket, [Name]) end).

%% Production-used option boundary, also exercised by deterministic platform
%% capability faults without changing machine-wide socket configuration.
-spec not_ect_configuration(fun(() -> term()), fun(() -> term())) -> 0..3.
not_ect_configuration(SetOption, ReadOption) ->
    Configured = try SetOption() of
        ok -> true;
        _ -> false
    catch _:_ -> false
    end,
    Observed = try ReadOption() of
        {ok, [{Name, Value}]} when (Name =:= tos orelse Name =:= tclass),
            is_integer(Value), Value >= 0, Value =< 255 ->
            {observed, Value band 3};
        _ -> unobserved
    catch _:_ -> unobserved
    end,
    case {Observed, Configured} of
        {{observed, 0}, _} -> 3;
        {{observed, _}, _} -> 0;
        {unobserved, true} -> 2;
        %% Only fresh sockets reach this boundary. This owner never installs
        %% a nonzero ECN marking, but an unreadable default is not evidence
        %% of an observed socket option or of a packet captured on the wire.
        {unobserved, false} -> 1
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
            case material_burst_compression(Compression, ?SEND_BATCH_PACKETS) of
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

%% Whether a measured compression came from coalescing rather than from the
%% relay's own queue draining.
%%
%% For a relay that sends one packet per send, the compression figure reduces
%% algebraically to the decrease in this relay's per-packet delay between two
%% consecutive packets: a packet that waited fifteen milliseconds for a
%% scheduler slot followed by one that waited two hundred microseconds measures
%% as a fourteen millisecond compression with nothing coalesced. What the
%% counter's name claims, and what an operator reading it would act on, is that
%% packets were put on the wire together, and that cannot happen while the batch
%% is one. So the batch decides, and the microsecond figure beside it keeps
%% reporting the raw measurement either way.
-spec material_burst_compression(non_neg_integer(), pos_integer()) ->
    boolean().
material_burst_compression(Compression, BatchPackets) ->
    BatchPackets > 1 andalso
        Compression > ?MATERIAL_BURST_COMPRESSION_MICROSECONDS.

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

-spec reserve_idle_wake(idle_state()) -> 0 | 1 | 2.
reserve_idle_wake(State) ->
    case atomics:compare_exchange(State, ?IDLE_PENDING, 0, 1) of
        ok ->
            case idle_public_state(State) of
                ?IDLE_ACTIVE ->
                    case idle_increment(State, ?IDLE_WAKE_SIGNALS) of
                        ok -> 1;
                        unavailable -> 2
                    end;
                ?IDLE_UNAVAILABLE -> atomics:put(State, ?IDLE_PENDING, 0), 2;
                _ -> atomics:put(State, ?IDLE_PENDING, 0), 0
            end;
        _ -> 0
    end.

-spec idle_public_state(idle_state()) -> integer().
idle_public_state(State) -> idle_state_value(State, atomics:get(State, ?IDLE_STATE)).

idle_state_value(_State, ?IDLE_EXPIRED_WORD) -> ?IDLE_EXPIRED;
idle_state_value(State, Control) ->
    case atomics:get(State, ?IDLE_FAILURE) of
        0 when Control =:= ?IDLE_STOP_WORD -> ?IDLE_STOPPED;
        0 -> ?IDLE_ACTIVE;
        _ -> ?IDLE_UNAVAILABLE
    end.
-spec call_deadlines(pos_integer()) -> {integer(), integer()}.
call_deadlines(Timeout) ->
    call_deadlines_at(erlang:monotonic_time(millisecond), Timeout).

-spec call_deadlines_at(integer(), pos_integer()) -> {integer(), integer()}.
call_deadlines_at(Now, Timeout) ->
    CompletionDeadline = Now + Timeout,
    CleanupTail = erlang:min(
        ?CALL_COMPLETION_TAIL_MILLISECONDS, Timeout div 4
    ),
    {CompletionDeadline - CleanupTail, CompletionDeadline}.

-spec operation_reply_is_timely(integer(), integer()) -> boolean().
operation_reply_is_timely(Now, OperationDeadline) ->
    Now < OperationDeadline.

-spec force_join_at(integer(), integer()) -> integer().
force_join_at(OperationDeadline, CompletionDeadline) ->
    CleanupTail = erlang:max(
        0, CompletionDeadline - OperationDeadline
    ),
    ForceTail = erlang:min(
        ?FORCE_JOIN_MILLISECONDS, CleanupTail div 2
    ),
    erlang:max(OperationDeadline, CompletionDeadline - ForceTail).

-spec await_down_until(pid(), reference(), integer()) -> boolean().
await_down_until(Pid, Monitor, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> true
    after Remaining ->
        erlang:demonitor(Monitor, [flush]),
        false
    end.

-spec join_or_force_until(pid(), reference(), integer(), integer()) -> boolean().
join_or_force_until(Pid, Monitor, ForceAt, CompletionDeadline) ->
    case await_down_until(Pid, Monitor, ForceAt) of
        true -> true;
        false ->
            %% await_down_until released its monitor on expiry, so the forced
            %% phase installs exactly one replacement monitor before kill.
            ForceMonitor = erlang:monitor(process, Pid),
            exit(Pid, kill),
            await_down_until(Pid, ForceMonitor, CompletionDeadline)
    end.

-spec drain_start_reply(reference()) -> ok.
drain_start_reply(Reference) ->
    receive
        {Reference, _Outcome} -> drain_start_reply(Reference)
    after 0 ->
        ok
    end.

-spec drain_call_reply(reference()) -> ok.
drain_call_reply(Reference) ->
    receive
        {http_masque_udp_reply, Reference, _Outcome} ->
            drain_call_reply(Reference)
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
