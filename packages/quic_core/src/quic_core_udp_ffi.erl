-module(quic_core_udp_ffi).

-on_load(init/0).

-export([
    active_datagram/2,
    active_once/1,
    close/1,
    continue_relay/1,
    dont_fragment_active/1,
    group_start/1,
    group_start_establishment/1,
    group_spawn/3,
    group_stop/1,
    group_stop_after_owner_exit/1,
    group_quiesce/1,
    group_publish/3,
    group_pid/1,
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
    route_source/2,
    send/5,
    start_relay/1,
    stop_relay/1,
    stop_relay_until/2,
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
-define(RELAY_FORCE_JOIN_MILLISECONDS, 10).
-define(GROUP_OPERATION_TIMEOUT_MILLISECONDS, 1500).
-define(GROUP_COMPLETION_TAIL_MILLISECONDS, 20).
-define(RESOLVER_COMPLETION_TAIL_MILLISECONDS, 20).
-define(RESOLVER_SUPERVISOR_JOIN_MILLISECONDS, 5).
-define(RESOLVER_MAX_HEAP_WORDS, 262144).
-define(MAXIMUM_MILLISECONDS, 9223372036854775807).

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
        nomatch ->
            Now = monotonic_millisecond(),
            case resolver_deadlines(Now, Timeout) of
                {ok, OperationDeadline, CompletionDeadline} ->
                    resolve_with_deadline(
                        binary_to_list(Host),
                        Family,
                        OperationDeadline,
                        CompletionDeadline
                    );
                error -> {error, 1}
            end;
        _Match -> {error, 1}
    end;
resolve_timeout(_Host, _Family, _Timeout) ->
    {error, 1}.

%% One establishment owns at most two resolver callbacks and sixteen dial
%% callbacks. The guardian holds no protocol state or callback result. Its
%% independent reaper owns a protected, payload-free identity ledger; either
%% controller's death causes fanout cleanup and original DOWN confirmation.
-spec group_start(pid()) -> {ok, map()} | {error, integer()}.
group_start(Owner) when is_pid(Owner) ->
    group_start(Owner, #{maximum => 18, endpoint => false, accepting => true});
group_start(_) -> {error, 1}.

%% The public bootstrap actor belongs to the same finite group as its helpers.
%% It can delegate admission but cannot detach itself from supervision.
-spec group_start_establishment(pid()) -> {ok, map()} | {error, integer()}.
group_start_establishment(Owner) when is_pid(Owner) ->
    group_start(Owner, #{maximum => 19, endpoint => undefined, accepting => true});
group_start_establishment(_) -> {error, 1}.

group_start(Owner, Policy) ->
    group_start_with_reaper_heap_words(
        Owner,
        Policy,
        ?RESOLVER_MAX_HEAP_WORDS
    ).

%% Kept private: source-probe tests use a small limit to make the reaper
%% max-heap failure path deterministic without changing production limits or
%% exposing a runtime tuning API. On-heap delivery makes every finite ledger
%% control message part of the configured bound.
group_start_with_reaper_heap_words(Owner, Policy, HeapWords)
    when is_pid(Owner), is_integer(HeapWords), HeapWords >= 1024,
         HeapWords =< ?RESOLVER_MAX_HEAP_WORDS ->
    group_start_with_reaper_options(
        Owner,
        Policy,
        [{message_queue_data, on_heap} | group_spawn_options(HeapWords)]
    ).

group_start_with_reaper_options(Owner, Policy, ReaperSpawnOptions) ->
    Caller = self(),
    Ref = make_ref(),
    ReaperRef = make_ref(),
    {ReadyDeadline, CompletionDeadline} = group_deadlines(
        ?GROUP_OPERATION_TIMEOUT_MILLISECONDS
    ),
    GuardianSpawnOptions = group_spawn_options(?RESOLVER_MAX_HEAP_WORDS),
    %% An independent reaper owns the finite, payload-free identity ledger.
    %% The guardian and reaper monitor one another, so either one's isolated
    %% failure causes an untrappable fanout kill of every admitted callback.
    ReaperSpawn = group_spawn_monitored(fun() ->
        group_reaper_start(
            Caller, Owner, ReaperRef, ReadyDeadline
        )
    end, ReaperSpawnOptions),
    case ReaperSpawn of
        error -> {error, 8};
        {ok, Reaper, ReaperMonitor} ->
            group_start_with_reaper(
                Caller,
                Owner,
                Policy,
                Ref,
                ReaperRef,
                Reaper,
                ReaperMonitor,
                ReadyDeadline,
                CompletionDeadline,
                GuardianSpawnOptions
            )
    end.

group_spawn_options(HeapWords) ->
    [
        monitor,
        {max_heap_size, #{
            size => HeapWords,
            kill => true,
            error_logger => false,
            include_shared_binaries => true
        }}
    ].

group_worker_spawn_options(1) -> [link, monitor];
group_worker_spawn_options(_) ->
    [link | group_spawn_options(?RESOLVER_MAX_HEAP_WORDS)].

group_start_with_reaper(
    Caller,
    Owner,
    Policy,
    Ref,
    ReaperRef,
    Reaper,
    ReaperMonitor,
    ReadyDeadline,
    CompletionDeadline,
    SpawnOptions
) ->
    Ledger = receive
        {ReaperRef, reaper_ready, Reaper, ReaperLedger} -> ReaperLedger
    after erlang:max(0, ReadyDeadline - monotonic_millisecond()) ->
        undefined
    end,
    case Ledger of
        undefined ->
            exit(Reaper, kill),
            Joined = group_join_until(
                Reaper, ReaperMonitor, CompletionDeadline
            ),
            group_drain_reaper_start_messages(Reaper, ReaperRef),
            case Joined of
                ok -> {error, 2};
                timeout -> {error, 8}
            end;
        _ ->
            GuardianSpawn = group_spawn_monitored(fun() ->
                process_flag(trap_exit, true),
                nil = quic_core_process_label_ffi:set_role(9),
                CallerMonitor = monitor(process, Caller),
                OwnerMonitor = monitor(process, Owner),
                ReaperGuardianMonitor = monitor(process, Reaper),
                Caller ! {Ref, guardian_ready, self()},
                group_loop(
                    Caller,
                    CallerMonitor,
                    OwnerMonitor,
                    Reaper,
                    ReaperGuardianMonitor,
                    Ref,
                    #{},
                    0,
                    Policy
                )
            end, SpawnOptions),
            case GuardianSpawn of
                error ->
                    exit(Reaper, kill),
                    _ = group_join_until(
                        Reaper, ReaperMonitor, CompletionDeadline
                    ),
                    group_drain_reaper_start_messages(
                        Reaper, ReaperRef
                    ),
                    {error, 8};
                {ok, Guardian, Monitor} ->
                    Group = #{
                        pid => Guardian,
                        monitor => Monitor,
                        reaper => Reaper,
                        reaper_monitor => ReaperMonitor,
                        ref => Ref,
                        reaper_ref => ReaperRef,
                        caller => Caller,
                        ledger => Ledger
                    },
                    Reaper ! {
                        ReaperRef, arm_reaper, Caller, Guardian, Ref
                    },
                    group_start_wait(
                        Group,
                        ReadyDeadline,
                        CompletionDeadline,
                        false,
                        false
                    )
            end
    end.

group_spawn_monitored(Work, Options) ->
    try spawn_opt(Work, Options) of
        {Process, Monitor} -> {ok, Process, Monitor}
    catch _:_ -> error
    end.

group_start_wait(
    Group = #{pid := Guardian, reaper := Reaper, ref := Ref,
              reaper_ref := ReaperRef},
    ReadyDeadline,
    CompletionDeadline,
    GuardianReady,
    ReaperReady
) ->
    case {GuardianReady, ReaperReady} of
        {true, true} ->
            case monotonic_millisecond() < ReadyDeadline
                andalso is_process_alive(Guardian)
                andalso is_process_alive(Reaper) of
                true -> {ok, Group};
                false -> group_start_force(Group, CompletionDeadline)
            end;
        _ ->
            Remaining = erlang:max(
                0, ReadyDeadline - monotonic_millisecond()
            ),
            receive
                {Ref, guardian_ready, Guardian} ->
                    group_start_wait(
                        Group,
                        ReadyDeadline,
                        CompletionDeadline,
                        true,
                        ReaperReady
                    );
                {ReaperRef, reaper_armed, Reaper} ->
                    group_start_wait(
                        Group,
                        ReadyDeadline,
                        CompletionDeadline,
                        GuardianReady,
                        true
                    )
            after Remaining ->
                group_start_force(Group, CompletionDeadline)
            end
    end.

group_start_force(Group, CompletionDeadline) ->
    Joined = group_force_and_join(Group, none, CompletionDeadline),
    group_release_controller_monitors(Group),
    group_drain_start_messages(Group),
    case Joined of
        true -> {error, 2};
        false -> {error, 8}
    end.

group_reaper_start(Caller, Owner, ReaperRef, ReadyDeadline) ->
    nil = quic_core_process_label_ffi:set_role(9),
    CallerMonitor = monitor(process, Caller),
    OwnerMonitor = monitor(process, Owner),
    %% The table stores only callback identities and is bounded by the WorkGroup
    %% admission limit. Ownership by this actor makes table reclamation
    %% independent of the API caller surviving long enough to call stop.
    Ledger = ets:new(connect_workers, [set, protected]),
    Caller ! {ReaperRef, reaper_ready, self(), Ledger},
    group_reaper_wait_arm(
        Caller,
        CallerMonitor,
        Owner,
        OwnerMonitor,
        ReaperRef,
        Ledger,
        ReadyDeadline
    ).

group_reaper_wait_arm(
    Caller,
    CallerMonitor,
    Owner,
    OwnerMonitor,
    ReaperRef,
    Ledger,
    ReadyDeadline
) ->
    Remaining = erlang:max(0, ReadyDeadline - monotonic_millisecond()),
    receive
        {ReaperRef, arm_reaper, Caller, Guardian, GroupRef}
            when is_pid(Guardian), is_reference(GroupRef) ->
            GuardianMonitor = monitor(process, Guardian),
            Caller ! {ReaperRef, reaper_armed, self()},
            group_reaper_loop(
                Caller,
                CallerMonitor,
                Owner,
                OwnerMonitor,
                Guardian,
                GuardianMonitor,
                GroupRef,
                Ledger,
                none
            );
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            ets:delete(Ledger),
            exit(normal);
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            ets:delete(Ledger),
            exit(normal)
    after Remaining ->
        ets:delete(Ledger),
        exit(group_start_timeout)
    end.

group_reaper_loop(
    Caller,
    CallerMonitor,
    Owner,
    OwnerMonitor,
    Guardian,
    GuardianMonitor,
    GroupRef,
    Ledger,
    Cleanup
) ->
    receive
        {GroupRef, register_worker, Worker, Registration,
         OperationDeadline}
            when is_pid(Worker), is_reference(Registration),
                 is_integer(OperationDeadline) ->
            case monotonic_millisecond() < OperationDeadline of
                true ->
                    true = ets:insert(Ledger, {Worker}),
                    Worker ! {Registration, registered, self()};
                false ->
                    Worker ! {Registration, expired, self()}
            end,
            group_reaper_loop(
                Caller,
                CallerMonitor,
                Owner,
                OwnerMonitor,
                Guardian,
                GuardianMonitor,
                GroupRef,
                Ledger,
                Cleanup
            );
        {GroupRef, prepare_cleanup, Guardian, Deadline, Retain}
            when is_integer(Deadline), Deadline >= 0,
                 (Retain =:= none orelse is_pid(Retain)) ->
            group_reaper_loop(
                Caller,
                CallerMonitor,
                Owner,
                OwnerMonitor,
                Guardian,
                GuardianMonitor,
                GroupRef,
                Ledger,
                {Deadline, Retain}
            );
        {GroupRef, clear_cleanup, Guardian} ->
            group_reaper_loop(
                Caller,
                CallerMonitor,
                Owner,
                OwnerMonitor,
                Guardian,
                GuardianMonitor,
                GroupRef,
                Ledger,
                none
            );
        {GroupRef, force_cleanup, Caller, Deadline, Retain}
            when is_integer(Deadline), Deadline >= 0,
                 (Retain =:= none orelse is_pid(Retain)) ->
            exit(Guardian, kill),
            group_reaper_finish(Ledger, Retain, Deadline);
        {'DOWN', GuardianMonitor, process, Guardian, _Reason} ->
            {Deadline, Retain} = case Cleanup of
                {PreparedDeadline, PreparedRetain} ->
                    {PreparedDeadline, PreparedRetain};
                none -> {group_cleanup_deadline(), none}
            end,
            group_reaper_finish(Ledger, Retain, Deadline);
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            exit(Guardian, kill),
            group_reaper_finish(
                Ledger, none, group_cleanup_deadline()
            );
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            exit(Guardian, kill),
            group_reaper_finish(
                Ledger, none, group_cleanup_deadline()
            );
        _Foreign ->
            group_reaper_loop(
                Caller,
                CallerMonitor,
                Owner,
                OwnerMonitor,
                Guardian,
                GuardianMonitor,
                GroupRef,
                Ledger,
                Cleanup
            )
    end.

group_reaper_finish(Ledger, Retain, CleanupDeadline) ->
    Outcome = group_reap_ledger_table(
        Ledger, Retain, CleanupDeadline
    ),
    try ets:delete(Ledger) catch error:badarg -> ok end,
    case Outcome of
        ok -> exit(normal);
        timeout -> exit(cleanup_timeout)
    end.

-spec group_pid(map()) -> pid().
group_pid(#{pid := Pid}) -> Pid.

-spec route_source(binary(), integer()) -> {ok, {binary(), integer()}} | {error, integer()}.
route_source(Address, Port) when is_binary(Address), is_integer(Port), Port > 0, Port =< 65535 ->
    case decode_address(Address) of
        {ok, Destination, Family} ->
            %% UDP connect chooses the local route/source without sending data.
            %% This temporary socket never receives application payload.
            Options = [binary, {active, false}, {recbuf, 2048}, {sndbuf, 2048}
                | family_options(Family)],
            case gen_udp:open(0, Options) of
                {ok, Socket} ->
                    try route_source_connected(Socket, Destination, Port)
                    catch _:_ -> {error, 8}
                    after gen_udp:close(Socket)
                    end;
                {error, Reason} -> {error, error_code(Reason)}
            end;
        error -> {error, 1}
    end;
route_source(_, _) -> {error, 1}.

route_source_connected(Socket, Destination, Port) ->
    case gen_udp:connect(Socket, Destination, Port) of
        ok -> case inet:sockname(Socket) of
            {ok, {Source, _}} -> case encode_address(Source) of
                {ok, Bytes} -> {ok, {Bytes, source_prefix(Source)}};
                error -> {error, 8}
            end;
            {error, Reason} -> {error, error_code(Reason)}
        end;
        {error, enetunreach} -> {error, 6};
        {error, ehostunreach} -> {error, 6};
        {error, Reason} -> {error, error_code(Reason)}
    end.

source_prefix(Source) ->
    %% OTP exposes address/netmask pairs, but not portable deprecated/home or
    %% encapsulation attributes. A refused/missing query leaves prefix unknown.
    try net:getifaddrs(default) of
        {ok, Interfaces} -> source_prefix(Source, Interfaces, 256);
        _ -> -1
    catch _:_ -> -1
    end.

source_prefix(_, _, 0) -> -1;
source_prefix(_, [], _) -> -1;
source_prefix(Source, [#{addr := #{addr := Source}, netmask := #{addr := Mask}} | _], _) ->
    case encode_address(Mask) of
        {ok, Bytes} -> mask_prefix(Bytes, 0);
        error -> -1
    end;
source_prefix(Source, [_ | Rest], Remaining) -> source_prefix(Source, Rest, Remaining-1).

mask_prefix(<<1:1, Rest/bitstring>>, Count) -> mask_prefix(Rest, Count+1);
mask_prefix(Rest, Count) ->
    case Rest of
        <<0:(bit_size(Rest))>> -> Count;
        _ -> -1
    end.

-spec group_spawn(map(), 1 | 3 | 4, fun(() -> term())) -> {ok, pid()} | {error, integer()}.
group_spawn(Group = #{caller := _}, Role, Callback)
    when (Role =:= 1 orelse Role =:= 3 orelse Role =:= 4), is_function(Callback, 0) ->
    group_call(Group, {spawn, Role, Callback});
group_spawn(_, _, _) -> {error, 1}.

-spec group_stop(map()) -> {ok, nil} | {error, integer()}.
group_stop(Group = #{caller := Caller}) when Caller =:= self() ->
    {OperationDeadline, CompletionDeadline} = group_deadlines(
        ?GROUP_OPERATION_TIMEOUT_MILLISECONDS
    ),
    Result = group_call_until(
        Group, stop, OperationDeadline, CompletionDeadline
    ),
    Joined = group_join_controllers(Group, CompletionDeadline),
    case {Result, Joined, group_ledger_released(Group)} of
        {{ok, nil}, orderly, true} -> {ok, nil};
        {{error, 2}, orderly, true} -> {error, 2};
        {{error, 2}, failed, true} -> {error, 2};
        {{error, 3}, orderly, true} -> {error, 3};
        {{error, 3}, failed, true} -> {error, 3};
        _ -> {error, 8}
    end;
group_stop(_) -> {error, 1}.

-spec group_stop_after_owner_exit(map()) -> {ok, nil} | {error, integer()}.
group_stop_after_owner_exit(
    Group = #{caller := Caller}
) when Caller =:= self() ->
    {OperationDeadline, CompletionDeadline} = group_deadlines(
        ?GROUP_OPERATION_TIMEOUT_MILLISECONDS
    ),
    Result = group_call_until(
        Group, stop, OperationDeadline, CompletionDeadline
    ),
    Joined = group_join_controllers(Group, CompletionDeadline),
    Released = group_ledger_released(Group),
    %% The owner monitor is allowed to win the race with this explicit stop.
    %% Only its already-stopped result is normalized, and only after both the
    %% guardian join and the finite identity ledger independently converge.
    case {Result, Joined, Released} of
        {{ok, nil}, orderly, true} -> {ok, nil};
        {{error, 3}, orderly, true} -> {ok, nil};
        {{error, 3}, failed, true} -> {ok, nil};
        _ -> {error, 8}
    end;
group_stop_after_owner_exit(_) -> {error, 1}.

-spec group_quiesce(map()) -> {ok, nil} | {error, integer()}.
group_quiesce(Group) ->
    {OperationDeadline, CompletionDeadline} = group_deadlines(
        ?GROUP_OPERATION_TIMEOUT_MILLISECONDS
    ),
    group_call_until(
        Group, quiesce, OperationDeadline, CompletionDeadline
    ).

-spec group_publish(map(), pid(), integer()) -> {ok, nil} | {error, integer()}.
group_publish(Group = #{caller := Caller}, Endpoint, Deadline)
    when Caller =:= self(), is_pid(Endpoint), is_integer(Deadline) ->
    Now = monotonic_millisecond(),
    CompletionDeadline = case Deadline > Now of
        true -> Deadline;
        false -> Now + ?GROUP_COMPLETION_TAIL_MILLISECONDS
    end,
    OperationDeadline = erlang:max(
        Now,
        Deadline - ?GROUP_COMPLETION_TAIL_MILLISECONDS
    ),
    Result = group_call_until(
        Group,
        {publish, Endpoint, Deadline},
        OperationDeadline,
        CompletionDeadline
    ),
    Joined = group_join_controllers(Group, CompletionDeadline),
    Retain = case {Result, Joined, monotonic_millisecond() < Deadline} of
        {{ok, nil}, orderly, true} -> Endpoint;
        _ -> none
    end,
    case {Joined, group_ledger_released(Group), Retain} of
        {orderly, true, Endpoint} -> Result;
        {orderly, true, none} ->
            case Result of
                {ok, nil} -> {error, 2};
                _ -> Result
            end;
        {failed, true, none} ->
            case Result of
                {ok, nil} -> {error, 2};
                _ -> Result
            end;
        _ -> {error, 8}
    end;
group_publish(_, _, _) -> {error, 1}.

group_call(Group = #{pid := _Guardian, ref := _Ref}, Command) ->
    {OperationDeadline, CompletionDeadline} = group_deadlines(
        ?GROUP_OPERATION_TIMEOUT_MILLISECONDS
    ),
    group_call_until(
        Group,
        Command,
        OperationDeadline,
        CompletionDeadline
    ).

group_call_until(
    Group = #{pid := Guardian, ref := Ref},
    Command,
    OperationDeadline,
    CompletionDeadline
) ->
    Call = make_ref(),
    Monitor = monitor(process, Guardian),
    case monotonic_millisecond() < OperationDeadline of
        true ->
            Guardian ! {
                Ref,
                self(),
                Call,
                Command,
                OperationDeadline,
                CompletionDeadline
            },
            group_call_wait(
                Group,
                Guardian,
                Monitor,
                Call,
                OperationDeadline,
                CompletionDeadline
            );
        false ->
            group_call_force(
                Group, Guardian, Monitor, CompletionDeadline
            )
    end.

group_call_wait(
    Group,
    Guardian,
    Monitor,
    Call,
    OperationDeadline,
    CompletionDeadline
) ->
    Remaining = erlang:max(
        0, OperationDeadline - monotonic_millisecond()
    ),
    receive
        {Call, Result} ->
            case monotonic_millisecond() < OperationDeadline of
                true -> demonitor(Monitor, [flush]), Result;
                false ->
                    demonitor(Monitor, [flush]),
                    case group_force_and_join(
                        Group, none, CompletionDeadline
                    ) of
                        true -> {error, 2};
                        false -> {error, 8}
                    end
            end;
        {'DOWN', Monitor, process, Guardian, _} ->
            case group_force_and_join(
                Group, none, CompletionDeadline
            ) of
                true -> {error, 3};
                false -> {error, 8}
            end
    after Remaining ->
        group_call_force(Group, Guardian, Monitor, CompletionDeadline)
    end.

group_call_force(Group, Guardian, Monitor, CompletionDeadline) ->
    exit(Guardian, kill),
    demonitor(Monitor, [flush]),
    case group_force_and_join(Group, none, CompletionDeadline) of
        true -> {error, 2};
        false -> {error, 8}
    end.

group_loop(
    Caller,
    CallerMonitor,
    OwnerMonitor,
    Reaper,
    ReaperMonitor,
    Ref,
    Workers,
    Count,
    Policy = #{maximum := Maximum, endpoint := Endpoint,
               accepting := Accepting}
) ->
    receive
        {Ref, From, Call, {spawn, Role, Callback},
         OperationDeadline, CompletionDeadline}
            when Count < Maximum, Accepting,
                 is_integer(OperationDeadline),
                 is_integer(CompletionDeadline),
                 OperationDeadline =< CompletionDeadline,
                 (From =:= Caller orelse From =:= Endpoint),
                 ((Role =:= 1 andalso From =:= Caller
                    andalso Endpoint =:= undefined)
                  orelse Role =:= 3 orelse Role =:= 4) ->
            Reaper ! {
                Ref,
                prepare_cleanup,
                self(),
                CompletionDeadline,
                none
            },
            Supervisor = self(),
            Ready = make_ref(),
            {Worker, Monitor} = spawn_opt(fun() ->
                try
                    nil = quic_core_process_label_ffi:set_role(Role),
                    %% Registration precedes readiness and callback execution.
                    %% If the independent reaper has died, insertion fails and
                    %% the user callback is never entered.
                    Registration = make_ref(),
                    Reaper ! {
                        Ref,
                        register_worker,
                        self(),
                        Registration,
                        OperationDeadline
                    },
                    receive
                        {Registration, registered, Reaper} ->
                            Supervisor ! {Ready, self()},
                            receive begin_callback -> Callback()
                            after erlang:max(
                                0,
                                OperationDeadline
                                    - monotonic_millisecond()
                            ) -> nil
                            end;
                        {Registration, expired, Reaper} -> nil
                    after erlang:max(
                        0, OperationDeadline - monotonic_millisecond()
                    ) -> nil
                    end
                catch _:_ -> nil
                end
            end, group_worker_spawn_options(Role)),
            WorkerState = receive {Ready, Worker} ->
                case monotonic_millisecond() < OperationDeadline of
                    true ->
                        From ! {Call, {ok, Worker}},
                        Worker ! begin_callback,
                        active;
                    false ->
                        exit(Worker, kill),
                        case group_join_until(
                            Worker, Monitor, CompletionDeadline
                        ) of
                            ok -> From ! {Call, {error, 2}}, retired;
                            timeout -> exit(cleanup_timeout)
                        end
                end
            after erlang:max(
                0, OperationDeadline - monotonic_millisecond()
            ) ->
                exit(Worker, kill),
                case group_join_until(
                    Worker, Monitor, CompletionDeadline
                ) of
                    ok -> From ! {Call, {error, 2}}, retired;
                    timeout -> exit(cleanup_timeout)
                end
            end,
            Reaper ! {Ref, clear_cleanup, self()},
            case WorkerState of
                active ->
                    NextPolicy = case Role of
                        1 -> Policy#{endpoint := Worker};
                        _ -> Policy
                    end,
                    group_loop(
                        Caller,
                        CallerMonitor,
                        OwnerMonitor,
                        Reaper,
                        ReaperMonitor,
                        Ref,
                        Workers#{Monitor => Worker},
                        Count + 1,
                        NextPolicy
                    );
                retired ->
                    group_loop(
                        Caller,
                        CallerMonitor,
                        OwnerMonitor,
                        Reaper,
                        ReaperMonitor,
                        Ref,
                        Workers,
                        Count + 1,
                        Policy
                    )
            end;
        {Ref, From, Call, {spawn, _, _},
         _OperationDeadline, _CompletionDeadline} ->
            From ! {Call, {error, 1}},
            group_loop(
                Caller,
                CallerMonitor,
                OwnerMonitor,
                Reaper,
                ReaperMonitor,
                Ref,
                Workers,
                Count,
                Policy
            );
        {Ref, Endpoint, Call, quiesce,
         OperationDeadline, CompletionDeadline}
            when is_pid(Endpoint), is_integer(OperationDeadline),
                 is_integer(CompletionDeadline),
                 OperationDeadline =< CompletionDeadline ->
            Reaper ! {
                Ref,
                prepare_cleanup,
                self(),
                CompletionDeadline,
                none
            },
            {Retained, Helpers} = group_partition(Workers, Endpoint),
            group_reap(Helpers, OperationDeadline),
            Reaper ! {Ref, clear_cleanup, self()},
            Endpoint ! {Call, {ok, nil}},
            group_loop(
                Caller,
                CallerMonitor,
                OwnerMonitor,
                Reaper,
                ReaperMonitor,
                Ref,
                Retained,
                Count,
                Policy#{accepting := false}
            );
        {Ref, Caller, Call, {publish, Endpoint, Deadline},
         OperationDeadline, CompletionDeadline}
            when is_pid(Endpoint), is_integer(Deadline),
                 is_integer(OperationDeadline),
                 is_integer(CompletionDeadline),
                 OperationDeadline =< CompletionDeadline,
                 not Accepting ->
            Reaper ! {
                Ref,
                prepare_cleanup,
                self(),
                CompletionDeadline,
                Endpoint
            },
            {Retained, Helpers} = group_partition(Workers, Endpoint),
            group_reap(Helpers, OperationDeadline),
            %% Only the original API caller can publish the established actor.
            %% Remove its link before supervisor exit; every helper is DOWN.
            case monotonic_millisecond() < Deadline of
                false ->
                    Reaper ! {
                        Ref,
                        prepare_cleanup,
                        self(),
                        CompletionDeadline,
                        none
                    },
                    group_reap(Retained, OperationDeadline),
                    Caller ! {Call, {error, 2}};
                true ->
                    maps:foreach(fun(WorkerMonitor, Worker) ->
                        unlink(Worker), demonitor(WorkerMonitor, [flush])
                    end, Retained),
                    Caller ! {Call, case is_process_alive(Endpoint) of
                        true -> {ok, nil};
                        false -> {error, 3}
                    end}
            end;
        {Ref, Caller, Call, stop,
         OperationDeadline, CompletionDeadline}
            when is_integer(OperationDeadline),
                 is_integer(CompletionDeadline),
                 OperationDeadline =< CompletionDeadline ->
            Reaper ! {
                Ref,
                prepare_cleanup,
                self(),
                CompletionDeadline,
                none
            },
            group_reap(Workers, OperationDeadline),
            Caller ! {Call, {ok, nil}};
        {'DOWN', CallerMonitor, process, Caller, _} ->
            group_reap(Workers, group_cleanup_deadline());
        {'DOWN', OwnerMonitor, process, _, _} ->
            group_reap(Workers, group_cleanup_deadline());
        {'DOWN', ReaperMonitor, process, Reaper, _} ->
            group_reap(Workers, group_cleanup_deadline());
        {'DOWN', WorkerMonitor, process, Endpoint, _}
            when is_pid(Endpoint) ->
            group_reap(
                maps:remove(WorkerMonitor, Workers),
                group_cleanup_deadline()
            );
        {'DOWN', WorkerMonitor, process, _, _} ->
            group_loop(
                Caller,
                CallerMonitor,
                OwnerMonitor,
                Reaper,
                ReaperMonitor,
                Ref,
                maps:remove(WorkerMonitor, Workers),
                Count,
                Policy
            );
        {'EXIT', _, _} ->
            group_loop(
                Caller,
                CallerMonitor,
                OwnerMonitor,
                Reaper,
                ReaperMonitor,
                Ref,
                Workers,
                Count,
                Policy
            );
        {Ref, From, Call, _, _OperationDeadline, _CompletionDeadline} ->
            From ! {Call, {error, 1}},
            group_loop(
                Caller,
                CallerMonitor,
                OwnerMonitor,
                Reaper,
                ReaperMonitor,
                Ref,
                Workers,
                Count,
                Policy
            )
    end.

group_partition(Workers, Endpoint) ->
    {maps:filter(fun(_, Pid) -> Pid =:= Endpoint end, Workers),
     maps:filter(fun(_, Pid) -> Pid =/= Endpoint end, Workers)}.

group_reap_ledger_table(Ledger, Retain, CleanupDeadline) ->
    try ets:select(Ledger, [{{'$1'}, [], ['$1']}], 19) of
        '$end_of_table' -> ok;
        {Workers, _} ->
            Owned = maps:from_list([{monitor(process, Pid), Pid}
                || Pid <- Workers, Pid =/= Retain]),
            try group_reap(Owned, CleanupDeadline) of
                ok -> ok
            catch exit:cleanup_timeout -> timeout
            end
    catch error:badarg -> timeout
    end.

group_force_and_join(
    Group = #{pid := Guardian, reaper := Reaper,
              ref := Ref, caller := Caller},
    Retain,
    CompletionDeadline
) ->
    %% The caller can read the protected identity ledger even though the reaper
    %% owns it. Monitor every original identity before fanout, then join the
    %% complete set under one absolute deadline. No callback count can multiply
    %% this wait.
    WorkerMonitors = group_monitor_ledger(Group, Retain),
    maps:foreach(fun(_, Worker) -> exit(Worker, kill) end, WorkerMonitors),
    Reaper ! {
        Ref,
        force_cleanup,
        Caller,
        CompletionDeadline,
        Retain
    },
    exit(Guardian, kill),
    Controllers = group_fresh_controller_monitors(Group),
    Pending = maps:merge(WorkerMonitors, Controllers),
    Joined = resolver_join_set(Pending, CompletionDeadline),
    case Joined of
        true -> group_ledger_released(Group);
        false ->
            maps:foreach(fun(_, Process) -> exit(Process, kill) end, Pending),
            exit(Reaper, kill),
            false
    end.

group_join_controllers(Group, CompletionDeadline) ->
    group_join_controller_set(
        group_controller_monitors(Group), CompletionDeadline, true
    ).

group_join_controller_set(Pending, _Deadline, AllNormal)
    when map_size(Pending) =:= 0 ->
    case AllNormal of
        true -> orderly;
        false -> failed
    end;
group_join_controller_set(Pending, Deadline, AllNormal) ->
    Remaining = erlang:max(0, Deadline - monotonic_millisecond()),
    receive
        {'DOWN', Monitor, process, _Process, Reason}
            when is_map_key(Monitor, Pending) ->
            group_join_controller_set(
                maps:remove(Monitor, Pending),
                Deadline,
                AllNormal andalso Reason =:= normal
            )
    after Remaining ->
        maps:foreach(fun(Monitor, _Process) ->
            demonitor(Monitor, [flush])
        end, Pending),
        timeout
    end.

group_fresh_controller_monitors(
    #{pid := Guardian, reaper := Reaper}
) ->
    #{monitor(process, Guardian) => Guardian,
      monitor(process, Reaper) => Reaper}.

group_controller_monitors(
    #{pid := Guardian, monitor := GuardianMonitor,
      reaper := Reaper, reaper_monitor := ReaperMonitor}
) ->
    #{GuardianMonitor => Guardian, ReaperMonitor => Reaper}.

group_release_controller_monitors(
    #{monitor := GuardianMonitor, reaper_monitor := ReaperMonitor}
) ->
    demonitor(GuardianMonitor, [flush]),
    demonitor(ReaperMonitor, [flush]),
    ok.

group_monitor_ledger(#{ledger := Ledger}, Retain) ->
    try ets:select(Ledger, [{{'$1'}, [], ['$1']}], 19) of
        '$end_of_table' -> #{};
        {Workers, _} ->
            maps:from_list([
                {monitor(process, Pid), Pid}
                || Pid <- Workers,
                   is_pid(Pid),
                   Pid =/= Retain
            ])
    catch error:badarg -> #{}
    end.

group_ledger_released(#{ledger := undefined}) -> true;
group_ledger_released(#{ledger := Ledger}) ->
    ets:info(Ledger) =:= undefined.

group_drain_start_messages(
    #{pid := Guardian, reaper := Reaper, ref := Ref,
      reaper_ref := ReaperRef}
) ->
    receive
        {Ref, guardian_ready, Guardian} ->
            group_drain_start_messages(#{
                pid => Guardian,
                reaper => Reaper,
                ref => Ref,
                reaper_ref => ReaperRef
            });
        {ReaperRef, reaper_ready, Reaper, _Ledger} ->
            group_drain_start_messages(#{
                pid => Guardian,
                reaper => Reaper,
                ref => Ref,
                reaper_ref => ReaperRef
            });
        {ReaperRef, reaper_armed, Reaper} ->
            group_drain_start_messages(#{
                pid => Guardian,
                reaper => Reaper,
                ref => Ref,
                reaper_ref => ReaperRef
            })
    after 0 -> ok
    end.

group_drain_reaper_start_messages(Reaper, ReaperRef) ->
    receive
        {ReaperRef, reaper_ready, Reaper, _Ledger} ->
            group_drain_reaper_start_messages(Reaper, ReaperRef);
        {ReaperRef, reaper_armed, Reaper} ->
            group_drain_reaper_start_messages(Reaper, ReaperRef)
    after 0 -> ok
    end.

group_reap(Workers, CleanupDeadline) ->
    maps:foreach(fun(_, Worker) -> exit(Worker, kill) end, Workers),
    %% Join the complete monitor set concurrently. One stalled callback can no
    %% longer multiply a per-process timeout across the finite worker bound.
    case resolver_join_set(Workers, CleanupDeadline) of
        true -> ok;
        false -> exit(cleanup_timeout)
    end.

group_join_until(Pid, Monitor, CleanupDeadline) ->
    Remaining = erlang:max(
        0, CleanupDeadline - monotonic_millisecond()
    ),
    receive {'DOWN', Monitor, process, Pid, _} -> ok
    after Remaining ->
        demonitor(Monitor, [flush]),
        case is_process_alive(Pid) of
            false -> ok;
            true -> timeout
        end
    end.

group_deadlines(OperationTimeout) ->
    group_deadlines_at(monotonic_millisecond(), OperationTimeout).

group_deadlines_at(Now, OperationTimeout) ->
    OperationDeadline = Now + OperationTimeout,
    {
        OperationDeadline,
        OperationDeadline + ?GROUP_COMPLETION_TAIL_MILLISECONDS
    }.

group_cleanup_deadline() ->
    monotonic_millisecond() + ?GROUP_OPERATION_TIMEOUT_MILLISECONDS.

-spec resolver_deadlines(non_neg_integer(), pos_integer()) ->
    {ok, non_neg_integer(), non_neg_integer()} | error.
resolver_deadlines(Now, Timeout)
    when is_integer(Now), Now >= 0,
         is_integer(Timeout), Timeout > 0,
         Now =< ?MAXIMUM_MILLISECONDS - Timeout ->
    CompletionDeadline = Now + Timeout,
    CleanupTail = erlang:min(
        ?RESOLVER_COMPLETION_TAIL_MILLISECONDS, Timeout div 4
    ),
    {ok, CompletionDeadline - CleanupTail, CompletionDeadline};
resolver_deadlines(_, _) -> error.

%% The caller first creates the gated resolver and its original monitor, then
%% creates the supervisor which links and independently monitors that resolver.
%% A callback result is provisional until both original caller monitors report
%% normal DOWN. The small completion tail is included once, at API entry, and
%% shared by resolver and supervisor cleanup; no timeout branch starts a fresh
%% wait.
-spec resolve_with_deadline(
    string(), 0 | 4 | 6, non_neg_integer(), non_neg_integer()
) -> {ok, [binary()]} | {error, integer()}.
resolve_with_deadline(Host, Family, OperationDeadline, CompletionDeadline) ->
    resolve_operation_with_deadline(
        fun() -> resolve_host(Host, Family) end,
        OperationDeadline,
        CompletionDeadline
    ).

resolve_operation_with_deadline(
    Resolve, OperationDeadline, CompletionDeadline
) ->
    resolve_operation_with_hooks(
        Resolve,
        fun() -> ok end,
        OperationDeadline,
        CompletionDeadline
    ).

resolve_operation_with_hooks(
    Resolve, AfterResult, OperationDeadline, CompletionDeadline
) ->
    resolve_operation_with_supervisor_hook(
        Resolve,
        AfterResult,
        fun() -> ok end,
        OperationDeadline,
        CompletionDeadline
    ).

resolve_operation_with_supervisor_hook(
    Resolve,
    AfterResult,
    BeforeSupervisorReady,
    OperationDeadline,
    CompletionDeadline
) ->
    case resolver_may_start(
        monotonic_millisecond(), OperationDeadline, CompletionDeadline
    ) of
        true ->
            resolve_operation_start(
                Resolve,
                AfterResult,
                BeforeSupervisorReady,
                OperationDeadline,
                CompletionDeadline
            );
        false -> {error, 2}
    end.

resolver_may_start(Now, OperationDeadline, CompletionDeadline) ->
    is_integer(Now)
        andalso is_integer(OperationDeadline)
        andalso is_integer(CompletionDeadline)
        andalso Now >= 0
        andalso Now < OperationDeadline
        andalso OperationDeadline =< CompletionDeadline
        andalso CompletionDeadline =< ?MAXIMUM_MILLISECONDS.

resolver_result_is_timely(Now, OperationDeadline) ->
    is_integer(Now)
        andalso is_integer(OperationDeadline)
        andalso Now >= 0
        andalso Now < OperationDeadline.

resolve_operation_start(
    Resolve,
    AfterResult,
    BeforeSupervisorReady,
    OperationDeadline,
    CompletionDeadline
) ->
    Caller = self(),
    Reference = make_ref(),
    WorkerReference = make_ref(),
    SpawnOptions = [
        monitor,
        {max_heap_size, #{
            size => ?RESOLVER_MAX_HEAP_WORDS,
            kill => true,
            error_logger => false,
            include_shared_binaries => true
        }}
    ],
    %% The API caller creates and monitors the gated resolver before a
    %% supervisor exists. There is therefore no spawn-to-registration window:
    %% every later failure path already holds the original resolver identity
    %% and monitor, while the callback cannot start before the supervisor gate.
    ResolverSpawn = try spawn_opt(fun() ->
        resolver_worker(
            Caller,
            Reference,
            WorkerReference,
            Resolve,
            AfterResult,
            OperationDeadline
        )
    end, SpawnOptions) of
        {SpawnedResolver, SpawnedResolverMonitor} ->
            {ok, SpawnedResolver, SpawnedResolverMonitor}
    catch
        _:_ -> error
    end,
    case ResolverSpawn of
        {ok, Resolver, ResolverMonitor} ->
            resolve_caller_wait_worker_ready(
                Resolver,
                ResolverMonitor,
                Reference,
                WorkerReference,
                BeforeSupervisorReady,
                OperationDeadline,
                CompletionDeadline,
                SpawnOptions
            );
        error -> {error, 8}
    end.

resolver_worker(
    Caller,
    Reference,
    WorkerReference,
    Resolve,
    AfterResult,
    OperationDeadline
) ->
    nil = quic_core_process_label_ffi:set_role(4),
    CallerMonitor = monitor(process, Caller),
    Caller ! {Reference, resolver_worker_ready, self()},
    Remaining = erlang:max(0, OperationDeadline - monotonic_millisecond()),
    receive
        {WorkerReference, begin_resolver, Supervisor}
            when is_pid(Supervisor) ->
            case is_process_alive(Caller)
                andalso monotonic_millisecond() < OperationDeadline of
                true ->
                    Result = Resolve(),
                    Supervisor ! {
                        WorkerReference, resolver_callback_result, Result
                    },
                    _ = AfterResult(),
                    demonitor(CallerMonitor, [flush]),
                    ok;
                false -> exit(resolver_start_timeout)
            end;
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            exit(normal)
    after Remaining ->
        demonitor(CallerMonitor, [flush]),
        exit(resolver_start_timeout)
    end.

resolve_caller_wait_worker_ready(
    Resolver,
    ResolverMonitor,
    Reference,
    WorkerReference,
    BeforeSupervisorReady,
    OperationDeadline,
    CompletionDeadline,
    SpawnOptions
) ->
    Remaining = erlang:max(0, OperationDeadline - monotonic_millisecond()),
    receive
        {Reference, resolver_worker_ready, Resolver} ->
            case monotonic_millisecond() < OperationDeadline of
                true ->
                    resolve_caller_start_supervisor(
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        BeforeSupervisorReady,
                        OperationDeadline,
                        CompletionDeadline,
                        SpawnOptions
                    );
                false ->
                    resolver_caller_force_worker(
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        CompletionDeadline,
                        {error, 2}
                    )
            end;
        {'DOWN', ResolverMonitor, process, Resolver, _Reason} ->
            drain_resolver_messages(Reference),
            {error, 8}
    after Remaining ->
        resolver_caller_force_worker(
            Resolver,
            ResolverMonitor,
            Reference,
            CompletionDeadline,
            {error, 2}
        )
    end.

resolve_caller_start_supervisor(
    Resolver,
    ResolverMonitor,
    Reference,
    WorkerReference,
    BeforeSupervisorReady,
    OperationDeadline,
    CompletionDeadline,
    SpawnOptions
) ->
    Caller = self(),
    SupervisorSpawn = try spawn_opt(fun() ->
        resolver_supervisor(
            Caller,
            Reference,
            WorkerReference,
            Resolver,
            BeforeSupervisorReady,
            OperationDeadline,
            CompletionDeadline
        )
    end, SpawnOptions) of
        {SpawnedSupervisor, SpawnedSupervisorMonitor} ->
            {ok, SpawnedSupervisor, SpawnedSupervisorMonitor}
    catch
        _:_ -> error
    end,
    case SupervisorSpawn of
        {ok, Supervisor, SupervisorMonitor} ->
            resolve_caller_wait_ready(
                Supervisor,
                SupervisorMonitor,
                Resolver,
                ResolverMonitor,
                Reference,
                WorkerReference,
                OperationDeadline,
                CompletionDeadline
            );
        error ->
            resolver_caller_force_worker(
                Resolver,
                ResolverMonitor,
                Reference,
                CompletionDeadline,
                {error, 8}
            )
    end.

-spec resolve_caller_wait_ready(
    pid(), reference(), pid(), reference(), reference(), reference(), integer(), integer()
) -> {ok, term()} | {error, integer()}.
resolve_caller_wait_ready(
    Supervisor,
    SupervisorMonitor,
    Resolver,
    ResolverMonitor,
    Reference,
    WorkerReference,
    OperationDeadline,
    CompletionDeadline
) ->
    Remaining = erlang:max(0, OperationDeadline - monotonic_millisecond()),
    receive
        {Reference, resolver_supervisor_ready, Supervisor} ->
            case monotonic_millisecond() < OperationDeadline of
                true ->
                    Supervisor ! {Reference, start_resolution, self()},
                    resolve_caller_wait_result(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline,
                        none,
                        waiting,
                        waiting
                    );
                false ->
                    resolver_caller_force(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        CompletionDeadline,
                        waiting,
                        waiting,
                        {error, 2}
                    )
            end;
        {'DOWN', ResolverMonitor, process, Resolver, _Reason} ->
            resolver_caller_force(
                Supervisor,
                SupervisorMonitor,
                Resolver,
                ResolverMonitor,
                Reference,
                CompletionDeadline,
                waiting,
                failed,
                {error, 8}
            );
        {'DOWN', SupervisorMonitor, process, Supervisor, _Reason} ->
            resolver_caller_force(
                Supervisor,
                SupervisorMonitor,
                Resolver,
                ResolverMonitor,
                Reference,
                CompletionDeadline,
                failed,
                waiting,
                {error, 8}
            )
    after Remaining ->
        resolver_caller_force(
            Supervisor,
            SupervisorMonitor,
            Resolver,
            ResolverMonitor,
            Reference,
            CompletionDeadline,
            waiting,
            waiting,
            {error, 2}
        )
    end.

resolve_caller_wait_result(
    Supervisor,
    SupervisorMonitor,
    Resolver,
    ResolverMonitor,
    Reference,
    WorkerReference,
    OperationDeadline,
    CompletionDeadline,
    Result,
    SupervisorState,
    ResolverState
) ->
    case {Result, SupervisorState, ResolverState} of
        {{some, Value}, normal, normal} ->
            drain_resolver_messages(Reference),
            case monotonic_millisecond() =< CompletionDeadline of
                true -> Value;
                false -> {error, 8}
            end;
        {none, normal, _} ->
            resolver_caller_force(
                Supervisor,
                SupervisorMonitor,
                Resolver,
                ResolverMonitor,
                Reference,
                CompletionDeadline,
                normal,
                ResolverState,
                {error, 8}
            );
        {_, failed, _} ->
            resolver_caller_force(
                Supervisor,
                SupervisorMonitor,
                Resolver,
                ResolverMonitor,
                Reference,
                CompletionDeadline,
                failed,
                ResolverState,
                {error, 8}
            );
        {_, _, failed} ->
            resolver_caller_force(
                Supervisor,
                SupervisorMonitor,
                Resolver,
                ResolverMonitor,
                Reference,
                CompletionDeadline,
                SupervisorState,
                failed,
                {error, 8}
            );
        _ ->
            ForceAt = resolver_supervisor_force_at(
                OperationDeadline, CompletionDeadline
            ),
            Remaining = erlang:max(
                0, ForceAt - monotonic_millisecond()
            ),
            receive
                {Reference, resolver_result, Value} ->
                    resolve_caller_wait_result(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline,
                        case Result of
                            none -> {some, Value};
                            _ -> Result
                        end,
                        SupervisorState,
                        ResolverState
                    );
                {'DOWN', SupervisorMonitor, process, Supervisor, normal} ->
                    resolve_caller_wait_result(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline,
                        Result,
                        normal,
                        ResolverState
                    );
                {'DOWN', SupervisorMonitor, process, Supervisor, _Reason} ->
                    resolve_caller_wait_result(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline,
                        Result,
                        failed,
                        ResolverState
                    );
                {'DOWN', ResolverMonitor, process, Resolver, normal} ->
                    resolve_caller_wait_result(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline,
                        Result,
                        SupervisorState,
                        normal
                    );
                {'DOWN', ResolverMonitor, process, Resolver, _Reason} ->
                    resolve_caller_wait_result(
                        Supervisor,
                        SupervisorMonitor,
                        Resolver,
                        ResolverMonitor,
                        Reference,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline,
                        Result,
                        SupervisorState,
                        failed
                    )
            after Remaining ->
                Desired = case Result of
                    none -> {error, 2};
                    _ -> {error, 8}
                end,
                resolver_caller_force(
                    Supervisor,
                    SupervisorMonitor,
                    Resolver,
                    ResolverMonitor,
                    Reference,
                    CompletionDeadline,
                    SupervisorState,
                    ResolverState,
                    Desired
                )
            end
    end.

resolver_caller_force_worker(
    Resolver,
    ResolverMonitor,
    Reference,
    CompletionDeadline,
    Desired
) ->
    exit(Resolver, kill),
    Joined = resolver_join_set(
        #{ResolverMonitor => Resolver}, CompletionDeadline
    ),
    drain_resolver_messages(Reference),
    case Joined of
        true -> Desired;
        false -> {error, 8}
    end.

resolver_caller_force(
    Supervisor,
    SupervisorMonitor,
    Resolver,
    ResolverMonitor,
    Reference,
    CompletionDeadline,
    SupervisorState,
    ResolverState,
    Desired
) ->
    PendingSupervisor = case SupervisorState of
        waiting -> #{SupervisorMonitor => Supervisor};
        _ -> #{}
    end,
    PendingResolver = case ResolverState of
        waiting -> #{ResolverMonitor => Resolver};
        _ -> #{}
    end,
    Pending = maps:merge(PendingSupervisor, PendingResolver),
    maps:foreach(fun(_, Process) -> exit(Process, kill) end, Pending),
    Joined = resolver_join_set(Pending, CompletionDeadline),
    drain_resolver_messages(Reference),
    case Joined of
        true -> Desired;
        false -> {error, 8}
    end.

resolver_supervisor_force_at(OperationDeadline, CompletionDeadline) ->
    CleanupTail = erlang:max(0, CompletionDeadline - OperationDeadline),
    SupervisorTail = erlang:min(
        ?RESOLVER_SUPERVISOR_JOIN_MILLISECONDS, CleanupTail div 2
    ),
    erlang:max(OperationDeadline, CompletionDeadline - SupervisorTail).

resolver_supervisor(
    Caller,
    Reference,
    WorkerReference,
    Resolver,
    BeforeSupervisorReady,
    OperationDeadline,
    CompletionDeadline
) ->
    process_flag(trap_exit, true),
    nil = quic_core_process_label_ffi:set_role(9),
    CallerMonitor = erlang:monitor(process, Caller),
    link(Resolver),
    ResolverMonitor = monitor(process, Resolver),
    _ = BeforeSupervisorReady(),
    Caller ! {Reference, resolver_supervisor_ready, self()},
    Remaining = erlang:max(0, OperationDeadline - monotonic_millisecond()),
    receive
        {Reference, start_resolution, Caller} ->
            case monotonic_millisecond() < OperationDeadline of
                true ->
                    Resolver ! {
                        WorkerReference, begin_resolver, self()
                    },
                    resolver_supervisor_wait(
                        Caller,
                        CallerMonitor,
                        Reference,
                        Resolver,
                        ResolverMonitor,
                        WorkerReference,
                        OperationDeadline,
                        CompletionDeadline
                    );
                false ->
                    resolver_supervisor_force(
                        Caller,
                        CallerMonitor,
                        Reference,
                        Resolver,
                        ResolverMonitor,
                        WorkerReference,
                        resolver_supervisor_force_at(
                            OperationDeadline, CompletionDeadline
                        ),
                        {error, 2}
                    )
            end;
        {Reference, cancel_resolution, Caller} ->
            resolver_supervisor_force(
                Caller,
                CallerMonitor,
                Reference,
                Resolver,
                ResolverMonitor,
                WorkerReference,
                resolver_supervisor_force_at(
                    OperationDeadline, CompletionDeadline
                ),
                {error, 2}
            );
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            resolver_supervisor_force(
                Caller,
                CallerMonitor,
                Reference,
                Resolver,
                ResolverMonitor,
                WorkerReference,
                CompletionDeadline,
                caller_down
            )
    after Remaining ->
        resolver_supervisor_force(
            Caller,
            CallerMonitor,
            Reference,
            Resolver,
            ResolverMonitor,
            WorkerReference,
            resolver_supervisor_force_at(
                OperationDeadline, CompletionDeadline
            ),
            {error, 2}
        )
    end.

-spec resolver_supervisor_wait(
    pid(), reference(), reference(), pid(), reference(), reference(), integer(), integer()
) -> no_return().
resolver_supervisor_wait(
    Caller,
    CallerMonitor,
    Reference,
    Resolver,
    ResolverMonitor,
    WorkerReference,
    OperationDeadline,
    CompletionDeadline
) ->
    WorkerCleanupDeadline = resolver_supervisor_force_at(
        OperationDeadline, CompletionDeadline
    ),
    Remaining = erlang:max(0, OperationDeadline - monotonic_millisecond()),
    receive
        {WorkerReference, resolver_callback_result, Value} ->
            case resolver_result_is_timely(
                monotonic_millisecond(), OperationDeadline
            ) of
                true ->
                    resolver_supervisor_wait_down(
                        Caller,
                        CallerMonitor,
                        Reference,
                        Resolver,
                        ResolverMonitor,
                        WorkerReference,
                        WorkerCleanupDeadline,
                        Value
                    );
                false ->
                    resolver_supervisor_force(
                        Caller,
                        CallerMonitor,
                        Reference,
                        Resolver,
                        ResolverMonitor,
                        WorkerReference,
                        WorkerCleanupDeadline,
                        {error, 2}
                    )
            end;
        {'DOWN', ResolverMonitor, process, Resolver, normal} ->
            drain_resolver_callback(WorkerReference),
            resolver_supervisor_publish(
                Caller, CallerMonitor, Reference, {error, 8}
            );
        {'DOWN', ResolverMonitor, process, Resolver, _Reason} ->
            drain_resolver_callback(WorkerReference),
            resolver_supervisor_publish(
                Caller, CallerMonitor, Reference, {error, 8}
            );
        {'EXIT', Resolver, _Reason} ->
            resolver_supervisor_wait(
                Caller,
                CallerMonitor,
                Reference,
                Resolver,
                ResolverMonitor,
                WorkerReference,
                OperationDeadline,
                CompletionDeadline
            );
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            resolver_supervisor_force(
                Caller,
                CallerMonitor,
                Reference,
                Resolver,
                ResolverMonitor,
                WorkerReference,
                WorkerCleanupDeadline,
                caller_down
            )
    after Remaining ->
        resolver_supervisor_force(
            Caller,
            CallerMonitor,
            Reference,
            Resolver,
            ResolverMonitor,
            WorkerReference,
            WorkerCleanupDeadline,
            {error, 2}
        )
    end.

-spec resolver_supervisor_wait_down(
    pid(), reference(), reference(), pid(), reference(), reference(), integer(), term()
) -> no_return().
resolver_supervisor_wait_down(
    Caller,
    CallerMonitor,
    Reference,
    Resolver,
    ResolverMonitor,
    WorkerReference,
    CompletionDeadline,
    Value
) ->
    Remaining = erlang:max(0, CompletionDeadline - monotonic_millisecond()),
    receive
        {'DOWN', ResolverMonitor, process, Resolver, normal} ->
            case monotonic_millisecond() =< CompletionDeadline of
                true ->
                    resolver_supervisor_publish(
                        Caller, CallerMonitor, Reference, Value
                    );
                false ->
                    resolver_supervisor_publish(
                        Caller, CallerMonitor, Reference, {error, 8}
                    )
            end;
        {'DOWN', ResolverMonitor, process, Resolver, _Reason} ->
            resolver_supervisor_publish(
                Caller, CallerMonitor, Reference, {error, 8}
            );
        {'EXIT', Resolver, _Reason} ->
            resolver_supervisor_wait_down(
                Caller,
                CallerMonitor,
                Reference,
                Resolver,
                ResolverMonitor,
                WorkerReference,
                CompletionDeadline,
                Value
            );
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            resolver_supervisor_force(
                Caller,
                CallerMonitor,
                Reference,
                Resolver,
                ResolverMonitor,
                WorkerReference,
                CompletionDeadline,
                caller_down
            )
    after Remaining ->
        resolver_supervisor_force(
            Caller,
            CallerMonitor,
            Reference,
            Resolver,
            ResolverMonitor,
            WorkerReference,
            CompletionDeadline,
            {error, 8}
        )
    end.

-spec resolver_supervisor_force(
    pid(), reference(), reference(), pid(), reference(), reference(), integer(),
    caller_down | {error, integer()}
) -> no_return().
resolver_supervisor_force(
    Caller,
    CallerMonitor,
    Reference,
    Resolver,
    ResolverMonitor,
    WorkerReference,
    CompletionDeadline,
    Outcome
) ->
    exit(Resolver, kill),
    Remaining = erlang:max(0, CompletionDeadline - monotonic_millisecond()),
    receive
        {'DOWN', ResolverMonitor, process, Resolver, _Reason} ->
            drain_resolver_callback(WorkerReference),
            case Outcome of
                caller_down ->
                    erlang:demonitor(CallerMonitor, [flush]),
                    exit(normal);
                _ ->
                    resolver_supervisor_publish(
                        Caller, CallerMonitor, Reference, Outcome
                    )
            end
    after Remaining ->
        erlang:demonitor(ResolverMonitor, [flush]),
        erlang:demonitor(CallerMonitor, [flush]),
        exit(resolver_cleanup_timeout)
    end.

resolver_supervisor_publish(Caller, CallerMonitor, Reference, Result) ->
    case erlang:is_process_alive(Caller) of
        true -> Caller ! {Reference, resolver_result, Result};
        false -> ok
    end,
    erlang:demonitor(CallerMonitor, [flush]),
    exit(normal).

resolver_join_set(Pending, _CompletionDeadline) when map_size(Pending) =:= 0 ->
    true;
resolver_join_set(Pending, CompletionDeadline) ->
    Remaining = erlang:max(
        0, CompletionDeadline - monotonic_millisecond()
    ),
    receive
        {'DOWN', Monitor, process, _Pid, _Reason}
            when is_map_key(Monitor, Pending) ->
            resolver_join_set(
                maps:remove(Monitor, Pending), CompletionDeadline
            )
    after Remaining ->
        maps:foreach(fun(Monitor, _Pid) ->
            erlang:demonitor(Monitor, [flush])
        end, Pending),
        false
    end.

drain_resolver_callback(WorkerReference) ->
    receive
        {WorkerReference, resolver_callback_result, _Value} -> ok
    after 0 ->
        ok
    end.

drain_resolver_messages(Reference) ->
    receive
        {Reference, resolver_worker_ready, _Resolver} ->
            drain_resolver_messages(Reference);
        {Reference, resolver_supervisor_ready, _Supervisor} ->
            drain_resolver_messages(Reference);
        {Reference, resolver_result, _Result} ->
            drain_resolver_messages(Reference)
    after 0 ->
        ok
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
    {error, active_error_code(Reason)};
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
    {error, active_error_code(Reason)};
active_datagram(#{socket := Socket}, {udp_closed, Socket}) ->
    {error, 3};
active_datagram(_Socket, _Message) ->
    {error, 1}.

%% UDP reset/refusal messages describe an earlier datagram, without the
%% offending packet required to authenticate the affected QUIC path. Windows
%% reports ICMP Port Unreachable as econnreset even while received stream bytes
%% remain usable. Keep these advisories distinct from a closed native socket.
-spec active_error_code(term()) -> 2..10.
active_error_code(Reason)
    when Reason =:= econnreset; Reason =:= econnrefused;
         Reason =:= ehostunreach; Reason =:= enetunreach -> 10;
active_error_code(Reason) -> error_code(Reason).

-spec start_relay(handle()) -> {ok, relay()} | {error, integer()}.
start_relay(Handle = #{socket := Socket}) ->
    Owner = self(),
    Reference = make_ref(),
    Sockets = handle_sockets(Handle),
    Relay = spawn(fun() ->
        nil = quic_core_process_label_ffi:set_role(5),
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
            {quic_core_udp_batch, Reference, {ok, Batch}})
    when is_list(Batch) ->
    {ok, Batch};
relay_batch(#{reference := Reference},
            {quic_core_udp_batch, Reference, {error, Code}})
    when is_integer(Code) ->
    {error, Code};
relay_batch(_Relay, _Message) ->
    {error, 1}.

-spec continue_relay(relay()) -> {ok, nil} | {error, integer()}.
continue_relay(#{pid := Pid, reference := Reference}) ->
    case erlang:is_process_alive(Pid) of
        true ->
            Pid ! {quic_core_udp_continue, Reference},
            {ok, nil};
        false ->
            {error, 3}
    end;
continue_relay(_Relay) ->
    {error, 1}.

-spec stop_relay(relay()) -> {ok, nil} | {error, integer()}.
stop_relay(Relay) ->
    stop_relay_until(
        Relay,
        monotonic_millisecond() + ?RELAY_STOP_TIMEOUT
    ).

%% Stop, close, and join the relay inside one caller-owned monotonic deadline.
%% The last ten milliseconds are part of that deadline and are reserved for an
%% untrappable forced exit. A forced path is always reported as timeout even
%% when DOWN is observed, so callers cannot mistake incomplete orderly cleanup
%% for success. DOWN proves every socket port owned by the relay is closed.
-spec stop_relay_until(relay(), integer()) ->
    {ok, nil} | {error, integer()}.
stop_relay_until(#{pid := Pid, reference := Reference}, Deadline)
    when is_integer(Deadline), Deadline >= 0,
         Deadline =< ?MAXIMUM_MILLISECONDS ->
    Now = monotonic_millisecond(),
    case Deadline > Now of
        false ->
            exit(Pid, kill),
            {error, 2};
        true ->
            Monitor = erlang:monitor(process, Pid),
            case erlang:is_process_alive(Pid) of
                false ->
                    relay_observe_down(Pid, Monitor, Deadline);
                true ->
                    StopReference = make_ref(),
                    Pid ! {quic_core_udp_stop,
                           Reference, self(), StopReference},
                    ForceAt = erlang:max(
                        Now,
                        Deadline - ?RELAY_FORCE_JOIN_MILLISECONDS
                    ),
                    relay_stop_until(
                        Pid, Monitor, StopReference, ForceAt, Deadline
                    )
            end
    end;
stop_relay_until(_Relay, _Deadline) ->
    {error, 1}.

-spec relay_observe_down(pid(), reference(), integer()) ->
    {ok, nil} | {error, integer()}.
relay_observe_down(Pid, Monitor, Deadline) ->
    Remaining = erlang:max(0, Deadline - monotonic_millisecond()),
    receive
        {'DOWN', Monitor, process, Pid, _Reason} ->
            erlang:demonitor(Monitor, [flush]),
            case monotonic_millisecond() < Deadline of
                true -> {ok, nil};
                false -> {error, 2}
            end
    after Remaining ->
        erlang:demonitor(Monitor, [flush]),
        {error, 2}
    end.

-spec relay_stop_until(pid(), reference(), reference(), integer(), integer()) ->
    {ok, nil} | {error, integer()}.
relay_stop_until(Pid, Monitor, StopReference, ForceAt, Deadline) ->
    Remaining = erlang:max(0, ForceAt - monotonic_millisecond()),
    receive
        {quic_core_udp_stopped, StopReference} ->
            relay_stop_until(
                Pid, Monitor, StopReference, ForceAt, Deadline
            );
        {'DOWN', Monitor, process, Pid, _Reason} ->
            flush_relay_stop_ack(StopReference),
            erlang:demonitor(Monitor, [flush]),
            case monotonic_millisecond() < Deadline of
                true -> {ok, nil};
                false -> {error, 2}
            end
    after Remaining ->
        exit(Pid, kill),
        relay_force_join(Pid, Monitor, StopReference, Deadline)
    end.

-spec relay_force_join(pid(), reference(), reference(), integer()) ->
    {error, integer()}.
relay_force_join(Pid, Monitor, StopReference, Deadline) ->
    Remaining = erlang:max(0, Deadline - monotonic_millisecond()),
    receive
        {quic_core_udp_stopped, StopReference} ->
            relay_force_join(Pid, Monitor, StopReference, Deadline);
        {'DOWN', Monitor, process, Pid, _Reason} ->
            flush_relay_stop_ack(StopReference),
            erlang:demonitor(Monitor, [flush]),
            {error, 2}
    after Remaining ->
        exit(Pid, kill),
        erlang:demonitor(Monitor, [flush]),
        flush_relay_stop_ack(StopReference),
        {error, 2}
    end.

-spec flush_relay_stop_ack(reference()) -> ok.
flush_relay_stop_ack(StopReference) ->
    receive
        {quic_core_udp_stopped, StopReference} -> ok
    after 0 ->
        ok
    end.

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
            Owner ! {quic_core_udp_batch, Reference,
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
                    Owner ! {quic_core_udp_batch, Reference,
                             {error, error_code(Reason)}},
                    relay_wait(Sockets, Owner, Reference, Monitor);
                false ->
                    relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {udp_closed, Socket} ->
            case lists:member(Socket, Sockets) of
                true ->
                    Owner ! {quic_core_udp_batch, Reference, {error, 3}},
                    close_sockets(Sockets),
                    exit(normal);
                false ->
                    relay_receive(Sockets, Owner, Reference, Monitor)
            end;
        {quic_core_udp_probe, Reference, Owner, ProbeReference}
            when is_reference(ProbeReference) ->
            %% The opaque, owner-only probe carries no socket or datagram data.
            %% Erlang preserves message order from one sender, so this reply
            %% proves every earlier owner-injected relay message was handled.
            Owner ! {quic_core_udp_probed, Reference, ProbeReference},
            relay_receive(Sockets, Owner, Reference, Monitor);
        {quic_core_udp_stop, Reference, Caller, StopReference} ->
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
            Owner ! {quic_core_udp_batch, Reference, {error, Code}};
        {ok, First} ->
            {Remaining, Reversed} = drain_relay_sockets(
                Sockets, ?MAXIMUM_RELAY_BATCH - 1, [First]
            ),
            Batch = drain_relay_mailbox(Sockets, Remaining, Reversed),
            Owner ! {quic_core_udp_batch, Reference, {ok, Batch}}
    end,
    relay_wait(Sockets, Owner, Reference, Monitor).

-spec relay_wait([gen_udp:socket()], pid(), reference(), reference()) ->
    no_return().
relay_wait(Sockets, Owner, Reference, Monitor) ->
    receive
        {quic_core_udp_continue, Reference} ->
            relay_loop(Sockets, Owner, Reference, Monitor);
        {quic_core_udp_probe, Reference, Owner, ProbeReference}
            when is_reference(ProbeReference) ->
            Owner ! {quic_core_udp_probed, Reference, ProbeReference},
            relay_wait(Sockets, Owner, Reference, Monitor);
        {quic_core_udp_stop, Reference, Caller, StopReference} ->
            relay_close(Sockets, Caller, StopReference);
        {'DOWN', Monitor, process, Owner, _Reason} ->
            close_sockets(Sockets),
            exit(normal)
    end.

-spec relay_close([gen_udp:socket()], pid(), reference()) -> no_return().
relay_close(Sockets, Caller, StopReference) ->
    close_sockets(Sockets),
    Caller ! {quic_core_udp_stopped, StopReference},
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
%% on platform-specific IPv4-mapped IPv6 socket defaults elsewhere. Neither
%% backing socket enables SO_REUSEADDR: IPv6 is v6-only, so the IPv4 partner
%% can bind the same number without allowing a second listener to steal it.
-spec open_split_dual_stack(inet:port_number()) ->
    {ok, handle()} | {error, integer()}.
open_split_dual_stack(Port) ->
    Ipv6Options = [
        binary,
        {active, false},
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
    %% QUIC endpoints own their address exclusively. In particular, Linux can
    %% assign one live listener's ephemeral UDP port to another reuseaddr
    %% socket and route all later datagrams to the second binder.
    BaseOptions = [
        binary,
        {active, false},
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
