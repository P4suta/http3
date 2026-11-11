-module(quic_core_qlog_ffi).

-export([bind_owner/2, bind_budget/4, bind_admission/3, close/1,
         close_completion_allowance_milliseconds/0, event/5,
         frame_event/6, open/3, stats/1, terminal_snapshot/1,
         validate_directory/1, open_accounted/3, cleanup_state/1, cleanup_owners/1,
         close_confirmed/1, close_confirmed_within/2, close_confirmed_until/2,
         open_accounted_with_fault/4, writer_call_with_fault/2,
         primitive_probe_with_fault/1]).
-export_type([cleanup_ticket/0]).

-define(MAX_DIRECTORY_BYTES, 4096).
-define(CALL_TIMEOUT_MILLISECONDS, 5000).
-define(CLOSE_TIMEOUT_MILLISECONDS, 4000).
-define(CHILD_JOIN_MILLISECONDS, 1000).
-define(MAX_CLOSE_WAITERS, 32).
-define(MAX_COUNTER, 2147483647).
-define(MAX_SCALAR, 9223372036854775807).

-define(MAX_STREAM_ID, 4611686018427387903).
-define(MAX_RECORD_BYTES, 512).

-record(startup_state, {
    owner, owner_monitor, worker, worker_monitor, operation,
    alias, token, deadline, cleanup,
    device = undefined, path = undefined,
    admission = undefined, admission_monitor = undefined,
    faults = []
}).

-opaque cleanup_ticket() :: no_cleanup |
    {qlog_cleanup_ticket, pid(), pid() | undefined, atomics:atomics_ref()}.

-spec close_completion_allowance_milliseconds() -> non_neg_integer().
close_completion_allowance_milliseconds() ->
    ?CALL_TIMEOUT_MILLISECONDS.

-spec open_accounted(binary(), 1 | 2, pos_integer()) ->
    {{ok, pid()} | {error, 1 | 2 | 3}, cleanup_ticket()}.
open_accounted(Directory, Vantage, MaximumEvents)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES,
         (Vantage =:= 1 orelse Vantage =:= 2),
         is_integer(MaximumEvents), MaximumEvents > 0,
         MaximumEvents =< 2147483647 ->
    case binary:match(Directory, <<0>>) of
        nomatch -> bounded_startup_accounted({open, Directory, Vantage, MaximumEvents});
        _ -> {{error, 1}, no_cleanup}
    end;
open_accounted(_, _, _) -> {{error, 1}, no_cleanup}.

%% Deterministic, payload-free VM primitive failure injection for the native
%% lifecycle tests. It is deliberately absent from the Gleam API. The same
%% implementation and cleanup paths serve production calls with an empty plan.
-spec open_accounted_with_fault(binary(), 1 | 2, pos_integer(), atom() | [atom()]) ->
    {{ok, pid()} | {error, 1 | 2 | 3}, cleanup_ticket()}.
open_accounted_with_fault(Directory, Vantage, MaximumEvents, Faults)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES,
         (Vantage =:= 1 orelse Vantage =:= 2),
         is_integer(MaximumEvents), MaximumEvents > 0,
         MaximumEvents =< 2147483647 ->
    case {binary:match(Directory, <<0>>), normalize_faults(Faults)} of
        {nomatch, {ok, Plan}} ->
            bounded_startup_accounted(
                {open, Directory, Vantage, MaximumEvents}, Plan
            );
        _ -> {{error, 1}, no_cleanup}
    end;
open_accounted_with_fault(_, _, _, _) -> {{error, 1}, no_cleanup}.

-spec cleanup_state(cleanup_ticket()) -> pending | released.
cleanup_state(no_cleanup) -> released;
cleanup_state({qlog_cleanup_ticket, Guardian, Admission, Flag})
    when is_pid(Guardian), (is_pid(Admission) orelse Admission =:= undefined) ->
    try atomics:get(Flag, 1) =:= 1 andalso
            snapshot_down(Guardian) andalso snapshot_down(Admission) of
        true -> released;
        false -> pending
    catch error:badarg -> pending end;
cleanup_state(_) -> pending.

-spec cleanup_owners(cleanup_ticket()) -> [pid()].
cleanup_owners({qlog_cleanup_ticket, Guardian, undefined, Flag})
    when is_pid(Guardian), is_reference(Flag) -> [Guardian];
cleanup_owners({qlog_cleanup_ticket, Guardian, Admission, Flag})
    when is_pid(Guardian), is_pid(Admission), is_reference(Flag) ->
    lists:usort([Guardian, Admission]);
cleanup_owners(_) -> [].

snapshot_down(undefined) -> true;
snapshot_down(Pid) ->
    %% This is a non-blocking snapshot. A fresh monitor followed immediately
    %% by receive-after-zero can miss its own asynchronous noproc signal and
    %% would repeatedly discard that confirmation while polling.
    not erlang:is_process_alive(Pid).

-record(writer_state, {
    owner_monitor,
    connection_owner = undefined,
    connection_owner_monitor = undefined,
    binding = undefined,
    device_writer,
    device_writer_monitor,
    file_device,
    file_device_monitor,
    guardian,
    guardian_monitor,
    guardian_stop_sent = false,
    device_close_result = undefined,
    events,
    busy = false,
    busy_funded = false,
    failed = false,
    close_timed_out = false,
    closing = false,
    close_sent = false,
    close_waiters = [],
    close_waiter_count = 0,
    close_deadline = infinity,
    terminating = false,
    maximum_events,
    budget = undefined,
    funded_events = 0,
    terminal_event_state = unavailable,
    terminal_duplicates = 0,
    last_event_time = 0,
    dropped = 0,
    write_errors = 0,
    faults = []
}).

-spec open(binary(), 1 | 2, pos_integer()) -> {ok, pid()} | {error, 1 | 2 | 3}.
open(Directory, Vantage, MaximumEvents)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES,
         (Vantage =:= 1 orelse Vantage =:= 2),
         is_integer(MaximumEvents), MaximumEvents > 0,
         MaximumEvents =< 2147483647 ->
    case binary:match(Directory, <<0>>) of
        nomatch -> bounded_startup({open, Directory, Vantage, MaximumEvents});
        _ -> {error, 1}
    end;
open(_Directory, _Vantage, _MaximumEvents) ->
    {error, 1}.

-spec validate_directory(binary()) -> {ok, nil} | {error, 1 | 2}.
validate_directory(Directory)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES ->
    case binary:match(Directory, <<0>>) of
        nomatch -> bounded_startup({validate, Directory});
        _ -> {error, 1}
    end;
validate_directory(_Directory) ->
    {error, 1}.

-spec event(pid(), integer(), integer(), integer(), integer()) ->
    {ok, nil} | {error, 1 | 3 | 4 | 5}.
event(Writer, Event, Time, Value, Auxiliary)
    when is_pid(Writer), is_integer(Event), Event >= 1, Event =< 18,
         is_integer(Time), Time >= 0,
         Time =< ?MAX_SCALAR,
         is_integer(Value), Value >= 0,
         Value =< ?MAX_SCALAR,
         is_integer(Auxiliary), Auxiliary >= 0,
         Auxiliary =< ?MAX_SCALAR ->
    case valid_event(Event, Value, Auxiliary) of
        true ->
            Metadata = {scalar, Event, Time, Value, Auxiliary},
            writer_call(Writer, {event, Metadata}, {error, 3});
        false ->
            {error, 1}
    end;
event(_Writer, _Event, _Time, _Value, _Auxiliary) ->
    {error, 1}.

-spec frame_event(pid(), 12 | 13, non_neg_integer(), non_neg_integer(),
                  1..8, non_neg_integer()) ->
    {ok, nil} | {error, 1 | 3 | 4}.
frame_event(Writer, Event, Time, StreamId, FrameType, PayloadBytes)
    when is_pid(Writer) ->
    case valid_frame_event(
        Event, Time, StreamId, FrameType, PayloadBytes
    ) of
        true ->
            Metadata = {frame, Event, Time, StreamId, FrameType, PayloadBytes},
            writer_call(Writer, {event, Metadata}, {error, 3});
        false ->
            {error, 1}
    end;
frame_event(_Writer, _Event, _Time, _StreamId, _FrameType, _PayloadBytes) ->
    {error, 1}.

-spec stats(pid()) ->
    {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}}
    | {error, 1 | 3}.
stats(Writer) when is_pid(Writer) ->
    writer_call(Writer, stats, {error, 3});
stats(_Writer) ->
    {error, 1}.

%% Payload-free endpoint-terminal evidence for deterministic admission tests.
%% State 0 has no prepaid slot, 1 is available, and 2 is accepted. The second
%% value is a saturating count of rejected duplicate terminal records.
-spec terminal_snapshot(pid()) ->
    {ok, {0 | 1 | 2, non_neg_integer()}} | {error, 1 | 3}.
terminal_snapshot(Writer) when is_pid(Writer) ->
    writer_call(Writer, terminal_snapshot, {error, 3});
terminal_snapshot(_) ->
    {error, 1}.

-spec close(pid()) -> {ok, nil} | {error, 1 | 3}.
close(Writer) when is_pid(Writer) ->
    %% Treat an already-terminated diagnostic writer as closed. This keeps
    %% connection teardown idempotent even after a filesystem failure.
    writer_call(Writer, close, {ok, nil});
close(_Writer) ->
    {error, 1}.

%% An affine endpoint handoff still owns an unclosed writer. Unlike the
%% explicit idempotent diagnostics API, a dead writer proves no successful
%% flush here. Only its actual close reply followed by DOWN can succeed.
-spec close_confirmed(pid()) -> {ok, nil} | {error, 1 | 3}.
close_confirmed(Writer) when is_pid(Writer) ->
    writer_call(Writer, close, {error, 3});
close_confirmed(_) ->
    {error, 1}.

%% Compatibility entrance for callers that only retain a duration. Establish
%% one absolute boundary here, then use the same path as lifecycle callers.
-spec close_confirmed_within(pid(), pos_integer()) ->
    {ok, nil} | {error, 1 | 3 | 6}.
close_confirmed_within(Writer, Milliseconds)
    when is_pid(Writer), is_integer(Milliseconds),
         Milliseconds > 0, Milliseconds =< ?MAX_SCALAR ->
    Now = monotonic_millisecond(),
    Share = erlang:min(Milliseconds, ?CALL_TIMEOUT_MILLISECONDS),
    close_confirmed_until(Writer, Now + Share);
close_confirmed_within(_, _) ->
    {error, 1}.

%% Complete within an absolute deadline in the same origin-relative monotonic
%% domain as quic_core/diagnostics. The native maximum can only shorten the
%% caller's boundary. A scheduler stall between layers therefore expires this
%% call instead of reconstructing a later `now + remaining` deadline.
-spec close_confirmed_until(pid(), non_neg_integer()) ->
    {ok, nil} | {error, 1 | 3 | 6}.
close_confirmed_until(Writer, Deadline)
    when is_pid(Writer), is_integer(Deadline),
         Deadline >= 0, Deadline =< ?MAX_SCALAR ->
    Now = monotonic_millisecond(),
    case Deadline > Now of
        true ->
            Effective = erlang:min(
                Deadline, Now + ?CALL_TIMEOUT_MILLISECONDS
            ),
            writer_call_until(
                Writer, close, {error, 3}, {error, 6}, Effective
            );
        false ->
            %% Use the same dispatch gate so the no-message guarantee is one
            %% tested invariant rather than a separate early-return path.
            writer_call_until(
                Writer, close, {error, 3}, {error, 6}, Deadline
            )
    end;
close_confirmed_until(_, _) ->
    {error, 1}.

%% The listener creates the server trace before its connection actor exists.
%% Retain listener supervision and additionally bind that actor's lifetime.
-spec bind_owner(pid(), pid()) -> {ok, nil} | {error, 1 | 3}.
bind_owner(Writer, Owner) when is_pid(Writer), is_pid(Owner) ->
    writer_call(Writer, {bind_owner, Owner}, {error, 3});
bind_owner(_, _) -> {error, 1}.

%% Bind one endpoint-owned writer to its aggregate transport-memory ledger.
%% The subject is opaque to this module; requests contain only a reservation
%% key and finite counters. Binding is allowed exactly once before any event.
-spec bind_budget(pid(), term(), bitstring(), pos_integer()) ->
    {ok, nil} | {error, 1 | 3}.
bind_budget(Writer, Subject, Reservation, EventBytes)
    when is_pid(Writer), is_tuple(Subject), is_bitstring(Reservation),
         is_integer(EventBytes), EventBytes > 0, EventBytes =< ?MAX_COUNTER ->
    writer_call(
        Writer,
        {bind_budget, Subject, Reservation, EventBytes},
        {error, 3}
    );
bind_budget(_, _, _, _) -> {error, 1}.

%% Bind a client writer to the stable admission identity shared by copies of
%% its Client configuration. The opaque token is validated by its owner module.
-spec bind_admission(pid(), quic_core_qlog_admission_ffi:reservation(), pos_integer()) ->
    {ok, nil} | {error, 1 | 3}.
bind_admission(Writer, Reservation, EventBytes)
    when is_pid(Writer), is_integer(EventBytes),
         EventBytes > 0, EventBytes =< ?MAX_COUNTER ->
    writer_call(
        Writer,
        {bind_admission, Reservation, EventBytes},
        {error, 3}
    );
bind_admission(_, _, _) -> {error, 1}.

%% The guardian starts before any filesystem operation. The I/O opener stays
%% alive as the eventual device writer: OTP monitors that opener's lifetime.
%% Startup uses the same three steady-state children as an established writer.
bounded_startup(Operation) ->
    {Result, _Ticket} = bounded_startup_accounted(Operation),
    Result.

bounded_startup_accounted(Operation) ->
    bounded_startup_accounted(Operation, []).

bounded_startup_accounted(Operation, Faults) ->
    Failure = startup_failure(Operation),
    Deadline = erlang:monotonic_time(millisecond) + ?CALL_TIMEOUT_MILLISECONDS,
    case primitive_alias(Faults, startup_alias) of
        {error, unavailable} -> {Failure, no_cleanup};
        {ok, Alias} ->
            case primitive_atomics(Faults, startup_atomics) of
                {error, unavailable} ->
                    safe_unalias(Alias),
                    {Failure, no_cleanup};
                {ok, Cleanup} ->
                    start_guarded_startup(
                        Operation, Failure, Deadline, Alias, Cleanup, Faults
                    )
            end
    end.

start_guarded_startup(Operation, Failure, Deadline, Alias, Cleanup, Faults) ->
    Owner = self(),
    case primitive_reference(Faults, startup_reference) of
        {error, unavailable} ->
            safe_unalias(Alias),
            {Failure, no_cleanup};
        {ok, Token} ->
            Start = primitive_spawn_monitor(
                Faults, startup_guardian_spawn, fun() ->
                    safe_set_diagnostic_role(),
                    startup_guardian(
                        Owner, Alias, Token, Deadline, Operation, Cleanup,
                        Faults
                    )
                end
            ),
            case Start of
                {error, unavailable} ->
                    safe_unalias(Alias),
                    {Failure, no_cleanup};
                {ok, Guardian, Monitor} ->
                    await_guarded_startup(
                        Operation, Failure, Deadline, Alias, Cleanup, Faults,
                        Token, Guardian, Monitor
                    )
            end
    end.

await_guarded_startup(
    _Operation, Failure, Deadline, Alias, Cleanup, Faults,
    Token, Guardian, Monitor
) ->
    Wait = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
    try
        Result = receive
            {qlog_startup_reply, Token, Reply} ->
                case erlang:monotonic_time(millisecond) < Deadline of
                    true -> Reply;
                    false -> Failure
                end;
            {'DOWN', Monitor, process, Guardian, _} -> Failure
        after Wait -> Failure
        end,
        Accepted = case Result of
            {ok, Writer} when is_pid(Writer) ->
                case owned_alive(Writer) andalso owned_alive(Guardian) of
                    true -> Result;
                    false ->
                        _ = cancel_startup(Guardian, Token, Faults),
                        Failure
                end;
            _ ->
                safe_unalias(Alias),
                case cancel_startup(Guardian, Token, Faults) of
                    true -> Result;
                    false -> Failure
                end
        end,
        Admission = case Accepted of
            {ok, Pid} when is_pid(Pid) -> Pid;
            _ -> undefined
        end,
        {Accepted, {qlog_cleanup_ticket, Guardian, Admission, Cleanup}}
    after
        safe_unalias(Alias), safe_demonitor(Monitor),
        receive {qlog_startup_reply, Token, _} -> ok after 0 -> ok end
    end.

startup_failure({validate, _}) -> {error, 2};
startup_failure({open, _, _, _}) -> {error, 3}.

cancel_startup(Guardian, Token, Faults) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CHILD_JOIN_MILLISECONDS,
    case primitive_monitor(Faults, cancel_monitor, Guardian) of
        {ok, Monitor} ->
            Guardian ! {qlog_cancel_startup, Token},
            try
                Remaining = erlang:max(
                    0, Deadline - erlang:monotonic_time(millisecond)
                ),
                receive {'DOWN', Monitor, process, Guardian, _} -> true
                after Remaining -> false end
            after safe_demonitor(Monitor) end;
        {error, unavailable} ->
            Guardian ! {qlog_cancel_startup, Token},
            await_process_down(Guardian, Deadline)
    end.

startup_guardian(Owner, Alias, Token, Deadline, Operation, Cleanup, Faults) ->
    process_flag(trap_exit, true),
    case primitive_monitor(Faults, startup_owner_monitor, Owner) of
        {error, unavailable} ->
            safe_cleanup_released(Cleanup),
            safe_startup_reply(Alias, Token, startup_failure(Operation));
        {ok, OwnerMonitor} ->
            Guardian = self(),
            Start = primitive_spawn_opt(
                Faults, startup_worker_spawn,
                fun() ->
                    safe_set_diagnostic_role(),
                    startup_worker(Guardian, Token, Operation)
                end,
                [link, monitor]
            ),
            case Start of
                {error, unavailable} ->
                    safe_demonitor(OwnerMonitor),
                    safe_cleanup_released(Cleanup),
                    safe_startup_reply(
                        Alias, Token, startup_failure(Operation)
                    );
                {ok, Worker, WorkerMonitor} ->
                    startup_receive(#startup_state{
                        owner = Owner,
                        owner_monitor = OwnerMonitor,
                        worker = Worker,
                        worker_monitor = WorkerMonitor,
                        operation = Operation,
                        alias = Alias,
                        token = Token,
                        deadline = Deadline,
                        cleanup = Cleanup,
                        faults = Faults
                    })
            end
    end.

startup_receive(State) ->
    Remaining = erlang:max(0, State#startup_state.deadline - erlang:monotonic_time(millisecond)),
    case Remaining of
        0 -> finish_startup(State, startup_failure(State#startup_state.operation));
        _ -> startup_wait(State, Remaining)
    end.

startup_wait(State = #startup_state{worker = Worker, token = Token}, Remaining) ->
    receive
        {qlog_startup_device, Worker, Token, Device}
            when is_pid(Device), State#startup_state.device =:= undefined ->
            Worker ! {qlog_device_tracked, Token},
            startup_receive(State#startup_state{device = Device});
        {qlog_startup_path, Worker, Token, Path}
            when is_list(Path), State#startup_state.path =:= undefined ->
            startup_receive(State#startup_state{path = Path});
        {qlog_header_written, Worker, Token} when is_pid(State#startup_state.device) ->
            Guardian = self(),
            {open, _, _, MaximumEvents} = State#startup_state.operation,
            Start = primitive_spawn_opt(
                State#startup_state.faults,
                startup_admission_spawn,
                fun() ->
                    safe_set_diagnostic_role(),
                    writer_admission(
                        State#startup_state.owner,
                        State#startup_state.device,
                        MaximumEvents,
                        Worker,
                        Guardian,
                        Token,
                        State#startup_state.faults
                    )
                end,
                [link, monitor]
            ),
            case Start of
                {ok, Admission, AdmissionMonitor} ->
                    Worker ! {qlog_device_begin, Token, Admission},
                    startup_receive(State#startup_state{
                        admission = Admission,
                        admission_monitor = AdmissionMonitor
                    });
                {error, unavailable} ->
                    finish_startup(
                        State, startup_failure(State#startup_state.operation)
                    )
            end;
        {qlog_admission_ready, Admission, Token}
            when Admission =:= State#startup_state.admission ->
            publish_startup(State);
        {qlog_startup_result, Worker, Token, Result} ->
            finish_startup(State, Result);
        {qlog_cancel_startup, Token} -> finish_startup(State, startup_failure(State#startup_state.operation));
        {'DOWN', Monitor, process, _, _}
            when Monitor =:= State#startup_state.owner_monitor;
                 Monitor =:= State#startup_state.worker_monitor;
                 Monitor =:= State#startup_state.admission_monitor ->
            finish_startup(State, startup_failure(State#startup_state.operation));
        _ -> startup_receive(State)
    after Remaining -> finish_startup(State, startup_failure(State#startup_state.operation))
    end.

publish_startup(State) ->
    Alive = lists:all(fun owned_alive/1, [State#startup_state.owner,
        State#startup_state.worker, State#startup_state.device, State#startup_state.admission]),
    case Alive andalso erlang:monotonic_time(millisecond) < State#startup_state.deadline of
        false -> finish_startup(State, startup_failure(State#startup_state.operation));
        true ->
            %% Admission now has its own guardian monitor. Preserve the
            %% established lifecycle's monitor-driven failure/close protocol.
            unlink(State#startup_state.admission),
            demonitor_owned(State#startup_state.worker_monitor),
            safe_startup_reply(
                State#startup_state.alias,
                State#startup_state.token,
                {ok, State#startup_state.admission}
            ),
            try guardian_receive(State#startup_state.owner_monitor,
                    State#startup_state.admission_monitor, State#startup_state.admission,
                    State#startup_state.worker, State#startup_state.device, infinity,
                    undefined, State#startup_state.token, State#startup_state.cleanup,
                    State#startup_state.faults)
            after demonitor_owned(State#startup_state.owner_monitor),
                  demonitor_owned(State#startup_state.admission_monitor) end
    end.

finish_startup(State, Result) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CHILD_JOIN_MILLISECONDS,
    {Discovered, Devices} = startup_devices(State, Deadline),
    Pids = [P || P <- [State#startup_state.admission, State#startup_state.worker,
                       State#startup_state.device | Devices], is_pid(P)],
    Joined = join_owned(Pids, Deadline, State#startup_state.faults),
    Paths = startup_paths(State),
    Deleted = case Joined of
        true -> lists:all(fun(Path) ->
            safe_delete_path(Path, Deadline)
        end, Paths);
        false -> false
    end,
    %% No known real device means an OTP request might still execute later.
    %% A device without its owned path cannot prove removal of a partial file.
    %% Keep that ticket pending even when all current library actors exit.
    KnownDevice = is_pid(State#startup_state.device) orelse Devices =/= [],
    PathProven = not KnownDevice orelse Paths =/= [],
    CleanupProven = Discovered andalso KnownDevice andalso PathProven,
    case Joined andalso CleanupProven andalso Deleted of
        true -> safe_cleanup_released(State#startup_state.cleanup);
        false -> ok
    end,
    Reply = case Joined andalso CleanupProven andalso Deleted andalso
                  owned_alive(State#startup_state.owner) andalso
                  erlang:monotonic_time(millisecond) <
                      State#startup_state.deadline of
        true -> Result;
        false -> startup_failure(State#startup_state.operation)
    end,
    safe_startup_reply(
        State#startup_state.alias, State#startup_state.token, Reply
    ),
    demonitor_owned(State#startup_state.owner_monitor),
    demonitor_owned(State#startup_state.worker_monitor),
    demonitor_owned(State#startup_state.admission_monitor),
    ok.

%% A real file device monitors its opener before file:open returns. Recover
%% that one device even when cancellation wins before the ownership message.
%% Introspection itself runs under a small heap cap and the cleanup deadline;
%% an external local monitor cannot turn this into unbounded guardian work.
startup_devices(#startup_state{device = Device}, _Deadline) when is_pid(Device) ->
    {true, []};
startup_devices(
    #startup_state{worker = Worker, token = Token, faults = Faults}, Deadline
) ->
    receive
        {qlog_startup_device, Worker, Token, Device} when is_pid(Device) ->
            {true, [Device]}
    after 0 ->
        case primitive_reference(Faults, startup_probe_reference) of
            {error, unavailable} -> {false, []};
            {ok, Ref} ->
                Guardian = self(),
                Start = primitive_spawn_opt(
                    Faults,
                    startup_probe_spawn,
                    fun() ->
                        safe_set_diagnostic_role(),
                        Result = discover_opener_device(Worker, Guardian),
                        Guardian ! {qlog_device_discovered, Ref, Result}
                    end,
                    [link, monitor, {max_heap_size,
                        #{size => 65536, kill => true,
                          error_logger => false}}]
                ),
                case Start of
                    {error, unavailable} -> {false, []};
                    {ok, Probe, Monitor} ->
                        Remaining = erlang:max(
                            0,
                            Deadline - erlang:monotonic_time(millisecond)
                        ),
                        Found = receive
                            {qlog_device_discovered, Ref, Value} -> Value;
                            {'DOWN', Monitor, process, Probe, _} ->
                                {false, []}
                        after Remaining -> {false, []}
                        end,
                        Joined = join_owned([Probe], Deadline, Faults),
                        safe_demonitor(Monitor),
                        {element(1, Found) andalso Joined, element(2, Found)}
                end
        end
    end.

startup_paths(#startup_state{
    worker = Worker, token = Token, path = Known
}) ->
    Initial = case Known of
        KnownPath when is_list(KnownPath) -> [KnownPath];
        _ -> []
    end,
    receive
        {qlog_startup_path, Worker, Token, Path} when is_list(Path) ->
            lists:usort([Path | Initial])
    after 0 -> Initial
    end.

safe_delete_path(Path, Deadline) when is_list(Path) ->
    try file:delete(Path, [raw]) of
        ok -> true;
        {error, enoent} -> true;
        {error, Reason} when Reason =:= eacces; Reason =:= eperm ->
            Remaining = erlang:max(
                0, Deadline - erlang:monotonic_time(millisecond)
            ),
            case Remaining of
                0 -> false;
                _ ->
                    receive after erlang:min(1, Remaining) -> ok end,
                    safe_delete_path(Path, Deadline)
            end;
        _ -> false
    catch
        _:_ -> false
    end;
safe_delete_path(_, _) -> false.

discover_opener_device(Worker, Guardian) ->
    case process_info(Worker, monitored_by) of
        undefined -> {true, []};
        {monitored_by, Watchers} ->
            case bounded_watchers(Watchers, 4) of
                false -> {false, []};
                true -> discover_file_watchers(Watchers, Worker, Guardian, [])
            end
    end.

bounded_watchers([], _Remaining) -> true;
bounded_watchers([_ | Tail], Remaining) when Remaining > 0 ->
    bounded_watchers(Tail, Remaining - 1);
bounded_watchers(_, _) -> false.

discover_file_watchers([], _Worker, _Guardian, Devices) -> {true, Devices};
discover_file_watchers([Guardian | Rest], Worker, Guardian, Devices) ->
    discover_file_watchers(Rest, Worker, Guardian, Devices);
discover_file_watchers([Candidate | Rest], Worker, Guardian, Devices)
    when is_pid(Candidate) ->
    case process_info(Candidate, [monitors, current_stacktrace]) of
        undefined -> discover_file_watchers(Rest, Worker, Guardian, Devices);
        [{monitors, Monitors}, {current_stacktrace, Stack}] ->
            File = bounded_watchers(Monitors, 2) andalso
                lists:member({process, Worker}, Monitors) andalso
                lists:any(fun({Module, _, _, _}) -> Module =:= file_io_server end, Stack),
            case File andalso Devices =:= [] of
                true -> discover_file_watchers(Rest, Worker, Guardian, [Candidate]);
                false -> {false, Devices}
            end
    end;
discover_file_watchers(_, _, _, Devices) -> {false, Devices}.

startup_worker(Guardian, Token, {validate, Directory}) ->
    Result = validate_writable_directory(Directory, Guardian, Token),
    Guardian ! {qlog_startup_result, self(), Token, Result};
startup_worker(Guardian, Token, {open, Directory, Vantage, MaximumEvents}) ->
    case open_valid_directory(Directory, Vantage, MaximumEvents, Guardian, Token) of
        {ok, Device} ->
            Guardian ! {qlog_header_written, self(), Token},
            receive {qlog_device_begin, Token, Admission} -> device_writer_loop(Admission, Device)
            after ?CALL_TIMEOUT_MILLISECONDS -> exit(qlog_startup_unconfirmed) end;
        Error -> Guardian ! {qlog_startup_result, self(), Token, Error}
    end.

track_startup_device(Guardian, Token, Device, Path) ->
    Guardian ! {qlog_startup_path, self(), Token, Path},
    Guardian ! {qlog_startup_device, self(), Token, Device},
    receive {qlog_device_tracked, Token} -> ok
    after ?CALL_TIMEOUT_MILLISECONDS -> exit(qlog_startup_unconfirmed) end.

open_valid_directory(Directory, Vantage, MaximumEvents, Guardian, Token) ->
    case ensure_directory(Directory) of
        {ok, DirectoryList} ->
            open_unique(DirectoryList, Vantage, MaximumEvents, 0, Guardian, Token);
        {error, _} = Error -> Error
    end.

validate_writable_directory(Directory, Guardian, Token) ->
    case ensure_directory(Directory) of
        {ok, DirectoryList} -> validate_writable_unique(DirectoryList, 0, Guardian, Token);
        {error, _} = Error -> Error
    end.

ensure_directory(Directory) ->
    DirectoryList = unicode:characters_to_list(Directory, utf8),
    case is_list(DirectoryList) of
        false -> {error, 1};
        true ->
            Placeholder = filename:join(DirectoryList, ".http3-qlog-dir"),
            case filelib:ensure_dir(Placeholder) of
                ok -> {ok, DirectoryList};
                {error, _Reason} -> {error, 2}
            end
    end.

validate_writable_unique(_Directory, Attempts, _Guardian, _Token) when Attempts >= 8 ->
    {error, 2};
validate_writable_unique(Directory, Attempts, Guardian, Token) ->
    Unique = erlang:unique_integer([positive, monotonic]),
    Filename = lists:flatten(io_lib:format(".http3-qlog-probe-~B", [Unique])),
    Path = filename:join(Directory, Filename),
    case file:open(Path, [write, exclusive, binary]) of
        {ok, Device} ->
            ok = track_startup_device(Guardian, Token, Device, Path),
            Close = file:close(Device),
            Delete = file:delete(Path),
            case Close =:= ok andalso Delete =:= ok of
                true -> {ok, nil};
                false -> {error, 2}
            end;
        {error, eexist} -> validate_writable_unique(Directory, Attempts + 1, Guardian, Token);
        {error, _Reason} -> {error, 2}
    end.

open_unique(_Directory, _Vantage, _MaximumEvents, Attempts, _Guardian, _Token) when Attempts >= 8 ->
    {error, 2};
open_unique(Directory, Vantage, MaximumEvents, Attempts, Guardian, Token) ->
    Unique = erlang:unique_integer([positive, monotonic]),
    Role = role(Vantage),
    Filename = lists:flatten(io_lib:format("http3-~s-~B.qlog", [Role, Unique])),
    Path = filename:join(Directory, Filename),
    case file:open(Path, [write, exclusive, binary]) of
        {ok, Device} ->
            ok = track_startup_device(Guardian, Token, Device, Path),
            case write_record(Device, header(Vantage)) of
                {ok, nil} ->
                    {ok, Device};
                {error, _} = Error ->
                    _ = file:close(Device),
                    _ = file:delete(Path),
                    Error
            end;
        {error, eexist} ->
            open_unique(Directory, Vantage, MaximumEvents, Attempts + 1, Guardian, Token);
        {error, _Reason} -> {error, 2}
    end.

writer_admission(
    Owner, Device, MaximumEvents, DeviceWriter, Guardian, Token, Faults
) ->
    Targets = [
        {admission_owner_monitor, Owner},
        {admission_file_monitor, Device},
        {admission_device_writer_monitor, DeviceWriter},
        {admission_guardian_monitor, Guardian}
    ],
    case install_monitors(Targets, Faults, []) of
        {error, unavailable} -> exit(qlog_monitor_unavailable);
        {ok, [OwnerMonitor, FileMonitor, DeviceWriterMonitor,
              GuardianMonitor]} ->
            Guardian ! {qlog_admission_ready, self(), Token},
            writer_admission_loop(#writer_state{
                owner_monitor = OwnerMonitor,
                device_writer = DeviceWriter,
                device_writer_monitor = DeviceWriterMonitor,
                file_device = Device,
                file_device_monitor = FileMonitor,
                guardian = Guardian,
                guardian_monitor = GuardianMonitor,
                events = queue:new(),
                maximum_events = MaximumEvents,
                faults = Faults
            })
    end.

writer_admission_loop(State = #writer_state{closing = true,
        device_writer = undefined, file_device = undefined, guardian = undefined}) ->
    finish_writer(State);
writer_admission_loop(State = #writer_state{closing = true,
        device_writer = undefined, file_device = undefined, guardian_stop_sent = false}) ->
    State#writer_state.guardian ! {qlog_guardian_release, self()},
    writer_admission_loop(State#writer_state{guardian_stop_sent = true});
writer_admission_loop(State) ->
    %% Check the absolute deadline before inspecting another mailbox message.
    %% A continuous stream of stats/events must not postpone shutdown.
    case close_remaining(State) of
        0 -> timeout_writer(State);
        Remaining -> writer_receive(State, Remaining)
    end.

writer_receive(State, Remaining) ->
    receive
        {qlog_call, From, Ref, {bind_owner, Owner}} when is_pid(Owner) ->
            bind_connection_owner(State, From, Ref, Owner);
        {qlog_call, From, Ref, {bind_budget, Subject, Reservation, EventBytes}} ->
            bind_endpoint_budget(
                State, From, Ref, Subject, Reservation, EventBytes
            );
        {qlog_call, From, Ref, {bind_admission, Reservation, EventBytes}} ->
            bind_client_budget(State, From, Ref, Reservation, EventBytes);
        {qlog_owner_bound, Guardian, BindRef, Result}
            when Guardian =:= State#writer_state.guardian ->
            case State#writer_state.binding of
                {From, Ref, BindRef} ->
                    Accepted = Result =:= {ok, nil} andalso
                        not State#writer_state.closing andalso not State#writer_state.failed
                        andalso owned_alive(State#writer_state.connection_owner)
                        andalso owned_alive(Guardian),
                    case Accepted of
                        true -> reply(From, Ref, {ok, nil}),
                            writer_admission_loop(State#writer_state{binding = undefined});
                        false -> reply(From, Ref, {error, 3}),
                            continue_writer(begin_close(State#writer_state{binding = undefined}))
                    end;
                _ -> writer_admission_loop(State)
            end;
        {qlog_call, From, Ref, {event, _Metadata}}
            when State#writer_state.closing ->
            reply(From, Ref, {error, 3}),
            writer_admission_loop(State);
        {qlog_call, From, Ref, {event, _Metadata}}
            when State#writer_state.failed ->
            reply(From, Ref, {error, 3}),
            writer_admission_loop(State#writer_state{
                dropped = counter_add(State#writer_state.dropped, 1)
            });
        {qlog_call, From, Ref, {event, Metadata}} ->
            InFlight = case State#writer_state.busy of
                true -> 1;
                false -> 0
            end,
            case event_queue_admission(State, Metadata, InFlight) of
                duplicate_terminal ->
                    reply(From, Ref, {error, 5}),
                    writer_admission_loop(State#writer_state{
                        terminal_duplicates = counter_add(
                            State#writer_state.terminal_duplicates, 1
                        ),
                        dropped = counter_add(State#writer_state.dropped, 1)
                    });
                full ->
                    reply(From, Ref, {error, 4}),
                    writer_admission_loop(State#writer_state{
                        dropped = counter_add(State#writer_state.dropped, 1)
                    });
                admitted ->
                    case normalize_event(
                        Metadata,
                        State#writer_state.last_event_time
                    ) of
                        {ok, Time, Json} when byte_size(Json) + 2 =< ?MAX_RECORD_BYTES ->
                            case acquire_event_budget(State, Metadata) of
                                {granted, Funding, FundedState} ->
                                    Funded = case Funding of
                                        funded -> 1;
                                        unfunded -> 0
                                    end,
                                    reply(From, Ref, {ok, nil}),
                                    continue_writer(FundedState#writer_state{
                                        events = queue:in(
                                            {Json, Funded =:= 1},
                                            FundedState#writer_state.events
                                        ),
                                        funded_events =
                                            FundedState#writer_state.funded_events + Funded,
                                        last_event_time = Time
                                    });
                                refused ->
                                    reply(From, Ref, {error, 4}),
                                    writer_admission_loop(State#writer_state{
                                        dropped = counter_add(State#writer_state.dropped, 1)
                                    });
                                unavailable ->
                                    reply(From, Ref, {error, 3}),
                                    writer_admission_loop(State#writer_state{
                                        dropped = counter_add(State#writer_state.dropped, 1),
                                        write_errors = counter_add(State#writer_state.write_errors, 1)
                                    })
                            end;
                        _ ->
                            reply(From, Ref, {error, 1}),
                            writer_admission_loop(State)
                    end
            end;
        {qlog_call, From, Ref, stats} ->
            InFlight = case State#writer_state.busy of
                true -> 1;
                false -> 0
            end,
            reply(From, Ref, {ok, {
                State#writer_state.dropped,
                State#writer_state.write_errors,
                queue:len(State#writer_state.events) + InFlight
            }}),
            writer_admission_loop(State);
        {qlog_call, From, Ref, terminal_snapshot} ->
            reply(From, Ref, {ok, {
                terminal_state_code(State#writer_state.terminal_event_state),
                State#writer_state.terminal_duplicates
            }}),
            writer_admission_loop(State);
        {qlog_call, From, Ref, close} ->
            case State#writer_state.close_waiter_count < ?MAX_CLOSE_WAITERS of
                true ->
                    continue_writer(begin_close(State#writer_state{
                        close_waiters = [{From, Ref} | State#writer_state.close_waiters],
                        close_waiter_count = State#writer_state.close_waiter_count + 1
                    }));
                false ->
                    reply(From, Ref, {error, 3}),
                    writer_admission_loop(State)
            end;
        {qlog_device_written, DeviceWriter, {ok, nil}}
            when DeviceWriter =:= State#writer_state.device_writer ->
            Funded = case State#writer_state.busy_funded of
                true -> 1;
                false -> 0
            end,
            continue_writer(release_event_budget(
                State#writer_state{busy = false, busy_funded = false}, Funded
            ));
        {qlog_device_written, DeviceWriter, {error, 3}}
            when DeviceWriter =:= State#writer_state.device_writer ->
            Queued = queue:len(State#writer_state.events),
            Released = release_event_budget(
                State, State#writer_state.funded_events
            ),
            continue_writer(Released#writer_state{
                events = queue:new(),
                busy = false,
                busy_funded = false,
                failed = true,
                dropped = counter_add(State#writer_state.dropped, Queued),
                write_errors = counter_add(State#writer_state.write_errors, 1)
            });
        {qlog_device_closed, DeviceWriter, Result}
            when DeviceWriter =:= State#writer_state.device_writer ->
            %% The acknowledgement precedes worker exit. Confirm both the
            %% worker and its file I/O process before reporting close success.
            writer_admission_loop(State#writer_state{device_close_result = Result});
        {'DOWN', Monitor, process, _Owner, _Reason}
            when Monitor =:= State#writer_state.owner_monitor;
                 Monitor =:= State#writer_state.connection_owner_monitor ->
            %% An abrupt owner exit has no process left which can make the
            %% synchronous terminal call. Consume the same prepaid slot here
            %% before closing; if the owner already emitted it, the one-way
            %% state leaves the accepted record untouched.
            continue_writer(begin_close(ensure_prepaid_terminal(State)));
        {'DOWN', Monitor, process, _Writer, _Reason}
            when Monitor =:= State#writer_state.device_writer_monitor ->
            Queued = queue:len(State#writer_state.events),
            InFlight = case State#writer_state.busy of
                true -> 1;
                false -> 0
            end,
            Unexpected = State#writer_state.device_close_result =:= undefined,
            case Unexpected of
                true -> kill_owned(State#writer_state.file_device);
                false -> ok
            end,
            Errors = case Unexpected of
                true -> counter_add(State#writer_state.write_errors, 1);
                false -> State#writer_state.write_errors
            end,
            Released = release_event_budget(
                State, State#writer_state.funded_events
            ),
            continue_writer(Released#writer_state{
                device_writer = undefined,
                device_writer_monitor = undefined,
                events = queue:new(),
                busy = false,
                busy_funded = false,
                failed = State#writer_state.failed orelse Unexpected,
                dropped = counter_add(State#writer_state.dropped, Queued + InFlight),
                write_errors = Errors
            });
        {'DOWN', Monitor, process, _File, _Reason}
            when Monitor =:= State#writer_state.file_device_monitor ->
            case State#writer_state.closing of
                true -> ok;
                false -> kill_owned(State#writer_state.device_writer)
            end,
            writer_admission_loop(State#writer_state{
                file_device = undefined,
                file_device_monitor = undefined
            });
        {'DOWN', Monitor, process, _Guardian, Reason}
            when Monitor =:= State#writer_state.guardian_monitor ->
            Expected = State#writer_state.guardian_stop_sent andalso Reason =:= normal,
            Next = State#writer_state{guardian = undefined, guardian_monitor = undefined,
                failed = State#writer_state.failed orelse not Expected},
            case Expected of
                true -> writer_admission_loop(Next);
                false -> terminate_writer(begin_close(Next))
            end;
        _Other ->
            writer_admission_loop(State)
    after Remaining ->
        timeout_writer(State)
    end.

bind_connection_owner(State = #writer_state{closing = false, failed = false,
        connection_owner = undefined, binding = undefined}, From, Ref, Owner) ->
    case owned_alive(Owner) andalso owned_alive(State#writer_state.guardian) of
        false ->
            reply(From, Ref, {error, 3}),
            continue_writer(begin_close(State));
        true ->
            case primitive_monitor(
                State#writer_state.faults, admission_bind_monitor, Owner
            ) of
                {error, unavailable} ->
                    reply(From, Ref, {error, 3}),
                    continue_writer(begin_close(State));
                {ok, Monitor} ->
                    case primitive_reference(
                        State#writer_state.faults,
                        admission_bind_reference
                    ) of
                        {error, unavailable} ->
                            safe_demonitor(Monitor),
                            reply(From, Ref, {error, 3}),
                            continue_writer(begin_close(State));
                        {ok, BindRef} ->
                            State#writer_state.guardian ! {
                                qlog_bind_owner, self(), BindRef, Owner
                            },
                            writer_admission_loop(State#writer_state{
                                connection_owner = Owner,
                                connection_owner_monitor = Monitor,
                                binding = {From, Ref, BindRef}
                            })
                    end
            end
    end;
bind_connection_owner(State = #writer_state{closing = false, failed = false,
        connection_owner = Owner, binding = undefined}, From, Ref, Owner) ->
    case owned_alive(Owner) andalso owned_alive(State#writer_state.guardian) of
        true -> reply(From, Ref, {ok, nil}), writer_admission_loop(State);
        false -> reply(From, Ref, {error, 3}), continue_writer(begin_close(State))
    end;
bind_connection_owner(State, From, Ref, _Owner) ->
    reply(From, Ref, {error, 3}), writer_admission_loop(State).

bind_endpoint_budget(
    State = #writer_state{
        budget = undefined,
        funded_events = 0,
        busy = false,
        closing = false,
        failed = false
    },
    From,
    Ref,
    Subject = {subject, Owner, _Tag},
    Reservation,
    EventBytes
) when is_pid(Owner), is_bitstring(Reservation),
       is_integer(EventBytes), EventBytes > 0, EventBytes =< ?MAX_COUNTER ->
    case queue:is_empty(State#writer_state.events) andalso owned_alive(Owner) of
        true ->
            reply(From, Ref, {ok, nil}),
            writer_admission_loop(State#writer_state{
                budget = {endpoint, Subject, Owner, Reservation, EventBytes},
                terminal_event_state = available
            });
        false ->
            reply(From, Ref, {error, 3}), writer_admission_loop(State)
    end;
bind_endpoint_budget(State, From, Ref, _Subject, _Reservation, _EventBytes) ->
    reply(From, Ref, {error, 3}), writer_admission_loop(State).

bind_client_budget(
    State = #writer_state{
        budget = undefined,
        funded_events = 0,
        busy = false,
        closing = false,
        failed = false
    },
    From,
    Ref,
    Reservation,
    EventBytes
) when is_integer(EventBytes),
       EventBytes > 0, EventBytes =< ?MAX_COUNTER ->
    case queue:is_empty(State#writer_state.events) andalso
         quic_core_qlog_admission_ffi:bind_writer(Reservation, EventBytes) of
        true ->
            reply(From, Ref, {ok, nil}),
            writer_admission_loop(State#writer_state{
                budget = {admission, Reservation, EventBytes}
            });
        false ->
            reply(From, Ref, {error, 3}), writer_admission_loop(State)
    end;
bind_client_budget(State, From, Ref, _Reservation, _EventBytes) ->
    reply(From, Ref, {error, 3}), writer_admission_loop(State).

%% An endpoint-bound writer has one prepaid terminal slot in addition to the
%% ordinary queue limit. This keeps maximum_events=1 useful for an in-flight
%% ordinary record while guaranteeing that local shutdown can still record its
%% one terminal observation without calling the synchronously blocked endpoint.
%% The one-way terminal state also makes duplicate terminal emission explicit.
event_queue_admission(State, Metadata, InFlight) ->
    Occupancy = queue:len(State#writer_state.events) + InFlight,
    case {prepaid_terminal(State, Metadata),
          State#writer_state.terminal_event_state} of
        {true, accepted} -> duplicate_terminal;
        {true, available} -> admitted;
        _ when Occupancy >= State#writer_state.maximum_events -> full;
        _ -> admitted
    end.

prepaid_terminal(
    #writer_state{budget = {endpoint, _, _, _, _}},
    {scalar, 5, _, _, _}
) -> true;
prepaid_terminal(_State, _Metadata) -> false.

terminal_state_code(unavailable) -> 0;
terminal_state_code(available) -> 1;
terminal_state_code(accepted) -> 2.

ensure_prepaid_terminal(
    State = #writer_state{
        budget = {endpoint, _, _, _, _},
        terminal_event_state = available
    }
) ->
    %% The writer stores relative time only. Reusing the last accepted value is
    %% monotonic and avoids retaining an epoch or endpoint identity solely for
    %% an owner-loss fallback.
    case event_json(5, State#writer_state.last_event_time, 0, 0) of
        {ok, Json} when byte_size(Json) + 2 =< ?MAX_RECORD_BYTES ->
            State#writer_state{
                events = queue:in({Json, false}, State#writer_state.events),
                terminal_event_state = accepted
            };
        _ -> State#writer_state{failed = true}
    end;
ensure_prepaid_terminal(State) -> State.

%% The one terminal connection_closed record is part of the fixed writer
%% working set. A listener synchronously joining its connection actors cannot
%% service a callback from those actors, so this prepaid record avoids a close
%% cycle without losing the terminal observation. Every other endpoint record
%% uses the dynamic ledger.
acquire_event_budget(
    State = #writer_state{
        budget = {endpoint, _, _, _, _},
        terminal_event_state = available
    },
    {scalar, 5, _, _, _}
) ->
    {granted, unfunded, State#writer_state{terminal_event_state = accepted}};
acquire_event_budget(State = #writer_state{budget = undefined}, _Metadata) ->
    {granted, unfunded, State};
acquire_event_budget(State = #writer_state{
    budget = {admission, Reservation, EventBytes}
}, _Metadata) ->
    case quic_core_qlog_admission_ffi:reserve_event(Reservation, EventBytes) of
        {ok, nil} -> {granted, funded, State};
        {error, 1} -> refused;
        _ -> unavailable
    end;
acquire_event_budget(State = #writer_state{
    budget = {endpoint, Subject, Owner, Reservation, EventBytes}
}, _Metadata) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CALL_TIMEOUT_MILLISECONDS,
    case primitive_reference(
        State#writer_state.faults, event_budget_reference
    ) of
        {error, unavailable} -> unavailable;
        {ok, Tag} ->
            case primitive_alias(
                State#writer_state.faults, event_budget_alias
            ) of
                {error, unavailable} ->
                    unavailable;
                {ok, Alias} ->
                    case primitive_monitor(
                        State#writer_state.faults,
                        event_budget_monitor,
                        Owner
                    ) of
                        {error, unavailable} ->
                            safe_unalias(Alias),
                            unavailable;
                        {ok, Monitor} ->
                            Reply = {subject, Alias, Tag},
                            try
                                ok = send_budget_message(
                                    Subject,
                                    {reserve_event, Reservation,
                                     EventBytes, Reply}
                                ),
                                Wait = erlang:max(
                                    0,
                                    Deadline
                                        - erlang:monotonic_time(millisecond)
                                ),
                                receive
                                    {Tag, true} -> before_budget_deadline(
                                        {granted, funded, State}, Deadline
                                    );
                                    {Tag, false} ->
                                        before_budget_deadline(
                                            refused, Deadline
                                        );
                                    {'DOWN', Monitor, process, Owner, _} ->
                                        unavailable
                                after Wait -> unavailable
                                end
                            catch
                                _:_ -> unavailable
                            after
                                safe_unalias(Alias),
                                safe_demonitor(Monitor)
                            end
                    end
            end
    end.

before_budget_deadline(Result, Deadline) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        true -> Result;
        false -> unavailable
    end.

release_event_budget(State, Requested) ->
    Count = erlang:min(erlang:max(0, Requested), State#writer_state.funded_events),
    release_event_budget_request(State#writer_state.budget, Count),
    State#writer_state{funded_events = State#writer_state.funded_events - Count}.

release_event_budget_request(undefined, _Count) -> ok;
release_event_budget_request(_Budget, 0) -> ok;
release_event_budget_request(
    {admission, Reservation, EventBytes}, Count
) ->
    quic_core_qlog_admission_ffi:release_events(
        Reservation, EventBytes * Count, Count
    );
release_event_budget_request(
    {endpoint, Subject, _Owner, Reservation, EventBytes}, Count
) ->
    try
        ok = send_budget_message(
            Subject,
            {release_events, Reservation, EventBytes * Count, Count}
        ),
        ok
    catch
        _:_ -> ok
    end.

begin_close(State = #writer_state{closing = true}) -> State;
begin_close(State) ->
    State#writer_state{closing = true,
        close_deadline = erlang:monotonic_time(millisecond) + ?CLOSE_TIMEOUT_MILLISECONDS}.

close_remaining(#writer_state{close_deadline = infinity}) -> infinity;
close_remaining(#writer_state{close_deadline = Deadline}) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

timeout_writer(State) ->
    terminate_writer(State#writer_state{
        close_timed_out = State#writer_state.close_timed_out orelse
            not State#writer_state.failed
    }).

terminate_writer(State = #writer_state{terminating = true}) ->
    %% A missed native join remains a failure; it can never acknowledge release.
    kill_owned(State#writer_state.device_writer),
    kill_owned(State#writer_state.file_device),
    kill_owned(State#writer_state.guardian),
    finish_writer(State#writer_state{failed = true});
terminate_writer(State) ->
    kill_owned(State#writer_state.device_writer),
    kill_owned(State#writer_state.file_device),
    writer_admission_loop(State#writer_state{failed = true, terminating = true,
        closing = true, close_sent = true, events = queue:new(), busy = false,
        busy_funded = false,
        close_deadline = erlang:monotonic_time(millisecond) + ?CHILD_JOIN_MILLISECONDS}).

finish_writer(State0) ->
    State = release_event_budget(State0, State0#writer_state.funded_events),
    Result = case {State#writer_state.failed, State#writer_state.device_close_result,
                   State#writer_state.close_timed_out} of
        {false, {ok, nil}, false} -> {ok, nil};
        {_, _, true} -> {error, 6};
        _ -> {error, 3}
    end,
    reply_waiters(State#writer_state.close_waiters, Result),
    case State#writer_state.binding of
        {From, Ref, _} -> reply(From, Ref, {error, 3});
        undefined -> ok
    end,
    demonitor_owned(State#writer_state.owner_monitor),
    demonitor_owned(State#writer_state.connection_owner_monitor),
    demonitor_owned(State#writer_state.device_writer_monitor),
    demonitor_owned(State#writer_state.file_device_monitor),
    demonitor_owned(State#writer_state.guardian_monitor),
    ok.

guardian_receive(
    OwnerMonitor, AdmissionMonitor, Admission, DeviceWriter, Device, Deadline,
    ConnectionWatch, StartupToken, Cleanup, Faults
) ->
    Remaining = case Deadline of
        infinity -> infinity;
        _ -> erlang:max(0, Deadline - erlang:monotonic_time(millisecond))
    end,
    case Remaining of
        0 ->
            kill_owned(Admission),
            guardian_join([DeviceWriter, Device], Cleanup, Faults);
        _ -> guardian_wait(OwnerMonitor, AdmissionMonitor, Admission,
                           DeviceWriter, Device, Deadline, Remaining,
                           ConnectionWatch, StartupToken, Cleanup, Faults)
    end.

guardian_wait(
    OwnerMonitor, AdmissionMonitor, Admission, DeviceWriter, Device, Deadline,
    Remaining, ConnectionWatch, StartupToken, Cleanup, Faults
) ->
    receive
        {qlog_cancel_startup, StartupToken} ->
            %% A caller that rejected queued readiness waits for this guardian;
            %% include admission itself in the observed cleanup completion.
            guardian_join(
                [Admission, DeviceWriter, Device], Cleanup, Faults
            );
        {qlog_bind_owner, Admission, BindRef, Owner} when is_pid(Owner), ConnectionWatch =:= undefined ->
            case primitive_monitor(Faults, guardian_bind_monitor, Owner) of
                {ok, Monitor} ->
                    %% The admission acknowledgement follows actual independent
                    %% monitor installation, so publishing a connection cannot
                    %% race it.
                    Admission ! {
                        qlog_owner_bound, self(), BindRef, {ok, nil}
                    },
                    guardian_receive(
                        OwnerMonitor, AdmissionMonitor, Admission,
                        DeviceWriter, Device, Deadline, {Owner, Monitor},
                        StartupToken, Cleanup, Faults
                    );
                {error, unavailable} ->
                    Admission ! {
                        qlog_owner_bound, self(), BindRef, {error, 3}
                    },
                    guardian_receive(
                        OwnerMonitor, AdmissionMonitor, Admission,
                        DeviceWriter, Device, Deadline, ConnectionWatch,
                        StartupToken, Cleanup, Faults
                    )
            end;
        {qlog_guardian_release, Admission} ->
            guardian_join([DeviceWriter, Device], Cleanup, Faults);
        {'DOWN', AdmissionMonitor, process, Admission, _} ->
            guardian_join([DeviceWriter, Device], Cleanup, Faults);
        {'DOWN', WatchMonitor, process, _Owner, _}
            when WatchMonitor =:= OwnerMonitor;
                 is_tuple(ConnectionWatch), WatchMonitor =:= element(2, ConnectionWatch) ->
            Armed = case Deadline of
                infinity -> erlang:monotonic_time(millisecond) + ?CALL_TIMEOUT_MILLISECONDS;
                _ -> Deadline
            end,
            guardian_receive(
                OwnerMonitor, AdmissionMonitor, Admission, DeviceWriter,
                Device, Armed, ConnectionWatch, StartupToken, Cleanup, Faults
            );
        _Other ->
            guardian_receive(
                OwnerMonitor, AdmissionMonitor, Admission, DeviceWriter,
                Device, Deadline, ConnectionWatch, StartupToken, Cleanup,
                Faults
            )
    after Remaining ->
        kill_owned(Admission),
        guardian_join([DeviceWriter, Device], Cleanup, Faults)
    end.

guardian_join(Pids, Cleanup, Faults) ->
    case join_owned(Pids, Faults) of
        true ->
            case safe_cleanup_released(Cleanup) of
                true -> ok;
                false -> exit(qlog_cleanup_state_unavailable)
            end;
        false -> exit(qlog_child_join_unconfirmed)
    end.

join_owned(Pids) ->
    join_owned(Pids, []).

join_owned(Pids, Faults) ->
    join_owned(
        Pids,
        erlang:monotonic_time(millisecond) + ?CHILD_JOIN_MILLISECONDS,
        Faults
    ).

join_owned(Pids0, Deadline, Faults) ->
    Pids = lists:usort([Pid || Pid <- Pids0, is_pid(Pid)]),
    Watched = prepare_join_monitors(Pids, Faults, []),
    lists:foreach(fun kill_owned/1, Pids),
    Joined = lists:all(fun({Pid, Monitor}) ->
        await_joined(Pid, Monitor, Deadline)
    end, Watched),
    lists:foreach(fun({_Pid, Monitor}) -> safe_demonitor(Monitor) end, Watched),
    Joined.

prepare_join_monitors([], _Faults, Acc) -> lists:reverse(Acc);
prepare_join_monitors([Pid | Rest], Faults, Acc) ->
    Monitor = case primitive_monitor(Faults, join_monitor, Pid) of
        {ok, Ref} -> Ref;
        {error, unavailable} -> undefined
    end,
    prepare_join_monitors(Rest, Faults, [{Pid, Monitor} | Acc]).

await_joined(Pid, Monitor, Deadline) when is_reference(Monitor) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, Pid, _} -> true
    after Remaining -> not owned_alive(Pid)
    end;
await_joined(Pid, undefined, Deadline) ->
    await_process_down(Pid, Deadline).

await_process_down(Pid, Deadline) ->
    case owned_alive(Pid) of
        false -> true;
        true ->
            Remaining = erlang:max(
                0, Deadline - erlang:monotonic_time(millisecond)
            ),
            case Remaining of
                0 -> false;
                _ ->
                    receive after erlang:min(1, Remaining) -> ok end,
                    await_process_down(Pid, Deadline)
            end
    end.

install_monitors([], _Faults, Acc) -> {ok, lists:reverse(Acc)};
install_monitors([{Site, Pid} | Rest], Faults, Acc) ->
    case primitive_monitor(Faults, Site, Pid) of
        {ok, Monitor} ->
            install_monitors(Rest, Faults, [Monitor | Acc]);
        {error, unavailable} ->
            lists:foreach(fun safe_demonitor/1, Acc),
            {error, unavailable}
    end.

kill_owned(Pid) when is_pid(Pid) -> exit(Pid, kill), ok;
kill_owned(undefined) -> ok.

owned_alive(Pid) when is_pid(Pid) ->
    try is_process_alive(Pid)
    catch _:_ -> false
    end;
owned_alive(undefined) -> false.

demonitor_owned(Monitor) when is_reference(Monitor) ->
    safe_demonitor(Monitor), ok;
demonitor_owned(undefined) -> ok.

safe_demonitor(Monitor) when is_reference(Monitor) ->
    try erlang:demonitor(Monitor, [flush])
    catch _:_ -> false
    end;
safe_demonitor(_) -> false.

safe_unalias(Alias) when is_reference(Alias) ->
    try erlang:unalias(Alias)
    catch _:_ -> false
    end;
safe_unalias(_) -> false.

-spec safe_cleanup_released(atomics:atomics_ref()) -> boolean().
safe_cleanup_released(Cleanup) ->
    try atomics:put(Cleanup, 1, 1), true
    catch _:_ -> false
    end.

-spec send_budget_message({subject, pid(), reference()}, term()) -> ok.
send_budget_message({subject, Owner, Tag}, Message) ->
    Owner ! {Tag, Message},
    ok.

safe_startup_reply(Alias, Token, Reply) ->
    try Alias ! {qlog_startup_reply, Token, Reply}, ok
    catch _:_ -> ok
    end.

safe_set_diagnostic_role() ->
    try
        _ = quic_core_process_label_ffi:set_role(7),
        ok
    catch
        _:_ -> ok
    end.

primitive_reference(Faults, Site) ->
    primitive_call(
        Faults, Site, fun() -> make_ref() end, fun erlang:is_reference/1
    ).

primitive_alias(Faults, Site) ->
    primitive_call(Faults, Site, fun() -> erlang:alias([reply]) end,
        fun erlang:is_reference/1).

-spec primitive_atomics([atom()], atom()) ->
    {ok, atomics:atomics_ref()} | {error, unavailable}.
primitive_atomics(Faults, Site) ->
    try
        case fault_enabled(Faults, Site) of
            true -> {error, unavailable};
            false -> {ok, atomics:new(1, [{signed, false}])}
        end
    catch
        _:_ -> {error, unavailable}
    end.

primitive_monitor(Faults, Site, Pid) when is_pid(Pid) ->
    primitive_call(
        Faults,
        Site,
        fun() -> erlang:monitor(process, Pid) end,
        fun erlang:is_reference/1
    );
primitive_monitor(_, _, _) -> {error, unavailable}.

primitive_spawn_monitor(Faults, Site, Fun) when is_function(Fun, 0) ->
    Result = primitive_call(
        Faults,
        Site,
        fun() -> spawn_monitor(Fun) end,
        fun
            ({Pid, Monitor}) -> is_pid(Pid) andalso is_reference(Monitor);
            (_) -> false
        end
    ),
    primitive_spawn_result(Result).

primitive_spawn_opt(Faults, Site, Fun, Options)
    when is_function(Fun, 0), is_list(Options) ->
    Result = primitive_call(
        Faults,
        Site,
        fun() -> spawn_opt(Fun, Options) end,
        fun
            ({Pid, Monitor}) -> is_pid(Pid) andalso is_reference(Monitor);
            (_) -> false
        end
    ),
    primitive_spawn_result(Result).

primitive_spawn_result({ok, {Pid, Monitor}}) -> {ok, Pid, Monitor};
primitive_spawn_result({error, unavailable}) -> {error, unavailable}.

primitive_call(Faults, Site, Fun, Validator) ->
    try
        Value = case fault_enabled(Faults, Site) of
            true -> throw(qlog_primitive_unavailable);
            false -> Fun()
        end,
        case Validator(Value) of
            true -> {ok, Value};
            false -> {error, unavailable}
        end
    catch
        _:_ -> {error, unavailable}
    end.

fault_enabled(Faults, Site) -> lists:member(Site, Faults).

normalize_faults(none) -> {ok, []};
normalize_faults(Fault) when is_atom(Fault) ->
    case allowed_fault(Fault) of
        true -> {ok, [Fault]};
        false -> error
    end;
normalize_faults(Faults) when is_list(Faults) ->
    normalize_fault_list(Faults, 8, []);
normalize_faults(_) -> error.

normalize_fault_list([], _Remaining, Acc) -> {ok, lists:usort(Acc)};
normalize_fault_list([Fault | Rest], Remaining, Acc) when Remaining > 0 ->
    case allowed_fault(Fault) of
        true -> normalize_fault_list(Rest, Remaining - 1, [Fault | Acc]);
        false -> error
    end;
normalize_fault_list(_, _, _) -> error.

allowed_fault(startup_alias) -> true;
allowed_fault(startup_atomics) -> true;
allowed_fault(startup_reference) -> true;
allowed_fault(startup_guardian_spawn) -> true;
allowed_fault(startup_owner_monitor) -> true;
allowed_fault(startup_worker_spawn) -> true;
allowed_fault(startup_admission_spawn) -> true;
allowed_fault(admission_owner_monitor) -> true;
allowed_fault(admission_file_monitor) -> true;
allowed_fault(admission_device_writer_monitor) -> true;
allowed_fault(admission_guardian_monitor) -> true;
allowed_fault(admission_bind_monitor) -> true;
allowed_fault(admission_bind_reference) -> true;
allowed_fault(guardian_bind_monitor) -> true;
allowed_fault(startup_probe_spawn) -> true;
allowed_fault(startup_probe_reference) -> true;
allowed_fault(join_monitor) -> true;
allowed_fault(cancel_monitor) -> true;
allowed_fault(writer_call_reference) -> true;
allowed_fault(writer_call_alias) -> true;
allowed_fault(writer_call_monitor) -> true;
allowed_fault(event_budget_reference) -> true;
allowed_fault(event_budget_alias) -> true;
allowed_fault(event_budget_monitor) -> true;
allowed_fault(_) -> false.

%% Exercise the otherwise race-dependent discovery-spawn failure without
%% exposing a child identifier or exception payload to the assertion layer.
-spec primitive_probe_with_fault(atom()) -> unavailable | unexpected.
primitive_probe_with_fault(startup_probe_reference) ->
    case primitive_reference(
        [startup_probe_reference], startup_probe_reference
    ) of
        {error, unavailable} -> unavailable;
        {ok, _Ref} -> unexpected
    end;
primitive_probe_with_fault(startup_probe_spawn) ->
    case primitive_spawn_opt(
        [startup_probe_spawn], startup_probe_spawn, fun() -> ok end, [monitor]
    ) of
        {error, unavailable} -> unavailable;
        {ok, Pid, Monitor} ->
            _ = join_owned([Pid]),
            safe_demonitor(Monitor),
            unexpected
    end;
primitive_probe_with_fault(_) -> unexpected.

counter_add(Value, Increment) -> erlang:min(?MAX_COUNTER, Value + Increment).

continue_writer(State0) ->
    State1 = dispatch_next_event(State0),
    State2 = maybe_close_device(State1),
    writer_admission_loop(State2).

dispatch_next_event(State = #writer_state{busy = true}) ->
    State;
dispatch_next_event(State = #writer_state{failed = true}) ->
    State;
dispatch_next_event(State) ->
    case queue:out(State#writer_state.events) of
        {empty, _} -> State;
        {{value, {Json, Funded}}, Remaining} ->
            State#writer_state.device_writer ! {qlog_write, Json},
            State#writer_state{
                events = Remaining, busy = true, busy_funded = Funded
            }
    end.

maybe_close_device(State = #writer_state{closing = false}) ->
    State;
maybe_close_device(State = #writer_state{close_sent = true}) ->
    State;
maybe_close_device(State = #writer_state{busy = true}) ->
    State;
maybe_close_device(State = #writer_state{device_writer = undefined}) ->
    State;
maybe_close_device(State) ->
    case queue:is_empty(State#writer_state.events) of
        false -> State;
        true ->
            State#writer_state.device_writer ! qlog_close,
            State#writer_state{close_sent = true}
    end.

device_writer_loop(Admission, Device) ->
    receive
        {qlog_write, Json} ->
            Admission ! {qlog_device_written, self(), write_record(Device, Json)},
            device_writer_loop(Admission, Device);
        qlog_close ->
            Result = close_device(Device),
            Admission ! {qlog_device_closed, self(), Result},
            ok
    end.

writer_call(Writer, Request, DownResult) ->
    case writer_call_within(
        Writer, Request, DownResult, {error, 3},
        ?CALL_TIMEOUT_MILLISECONDS
    ) of
        {error, 6} -> {error, 3};
        Result -> Result
    end.

writer_call_within(Writer, Request, DownResult, TimeoutResult, Milliseconds) ->
    Deadline = monotonic_millisecond() + Milliseconds,
    writer_call_until(Writer, Request, DownResult, TimeoutResult, Deadline).

writer_call_until(Writer, Request, DownResult, TimeoutResult, Deadline) ->
    writer_call_until(
        Writer, Request, DownResult, TimeoutResult, Deadline, []
    ).

writer_call_until(
    Writer, Request, DownResult, TimeoutResult, Deadline, Faults
) ->
    %% Expiration is checked before allocating reply machinery and again at
    %% dispatch. Setup time consumes this same absolute deadline.
    case monotonic_millisecond() < Deadline of
        false -> TimeoutResult;
        true ->
            case primitive_reference(Faults, writer_call_reference) of
                {error, unavailable} -> {error, 3};
                {ok, Ref} ->
                    case primitive_alias(Faults, writer_call_alias) of
                        {error, unavailable} ->
                            {error, 3};
                        {ok, Alias} ->
                            case primitive_monitor(
                                Faults, writer_call_monitor, Writer
                            ) of
                                {error, unavailable} ->
                                    safe_unalias(Alias),
                                    {error, 3};
                                {ok, Monitor} ->
                                    try writer_call_wait(
                                        Writer, Request, DownResult,
                                        TimeoutResult, Deadline, Alias, Ref,
                                        Monitor
                                    )
                                    catch
                                        _:_ -> {error, 3}
                                    after
                                        safe_unalias(Alias),
                                        safe_demonitor(Monitor)
                                    end
                            end
                    end
            end
    end.

writer_call_wait(
    Writer, Request, DownResult, TimeoutResult, Deadline, Alias, Ref, Monitor
) ->
    case monotonic_millisecond() < Deadline of
        false -> TimeoutResult;
        true ->
            Writer ! {qlog_call, Alias, Ref, Request},
            Wait = erlang:max(0, Deadline - monotonic_millisecond()),
            receive
                {qlog_reply, Ref, Reply} ->
                    accept_writer_reply(
                        Writer, Monitor, Request, Reply,
                        Deadline, TimeoutResult
                    );
                {'DOWN', Monitor, process, Writer, Reason} ->
                    case Reason =:= normal orelse Reason =:= noproc of
                        true -> before_deadline(
                            DownResult, Deadline, TimeoutResult
                        );
                        false -> {error, 3}
                    end
            after Wait -> TimeoutResult
            end
    end.

%% Native-only deterministic seam. No request data or process identity is
%% returned; callers can only observe the established typed qlog result.
-spec writer_call_with_fault(pid(), atom() | [atom()]) ->
    {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}}
    | {error, 1 | 3}.
writer_call_with_fault(Writer, Faults) when is_pid(Writer) ->
    case normalize_faults(Faults) of
        {ok, Plan} ->
            writer_call_until(
                Writer,
                stats,
                {error, 3},
                {error, 3},
                monotonic_millisecond() + ?CALL_TIMEOUT_MILLISECONDS,
                Plan
            );
        error -> {error, 1}
    end;
writer_call_with_fault(_, _) -> {error, 1}.

accept_writer_reply(
    Writer, Monitor, close, {ok, nil}, Deadline, TimeoutResult
) ->
    Remaining = erlang:max(0, Deadline - monotonic_millisecond()),
    receive
        {'DOWN', Monitor, process, Writer, normal} ->
            before_deadline({ok, nil}, Deadline, TimeoutResult);
        {'DOWN', Monitor, process, Writer, _} -> {error, 3}
    after Remaining -> TimeoutResult end;
accept_writer_reply(
    _Writer, _Monitor, _Request, Reply, Deadline, TimeoutResult
) ->
    before_deadline(Reply, Deadline, TimeoutResult).

before_deadline(Reply, Deadline, TimeoutResult) ->
    case monotonic_millisecond() < Deadline of
        true -> Reply;
        false -> TimeoutResult
    end.

%% Share the exact persistent origin used by every QUIC lifecycle deadline.
%% Calling through the UDP boundary also ensures its on-load initialization
%% completed before any absolute qlog deadline is interpreted.
monotonic_millisecond() ->
    quic_core_udp_ffi:monotonic_millisecond().

reply(To, Ref, Value) ->
    try To ! {qlog_reply, Ref, Value}, ok
    catch _:_ -> ok
    end.

reply_waiters(Waiters, Value) ->
    lists:foreach(fun({To, Ref}) -> reply(To, Ref, Value) end, Waiters).

%% The admission process is the only cross-producer ordering point. Keep one
%% scalar watermark and clamp an accepted event to it before JSON construction;
%% no timestamp history or producer identity is retained.
normalize_event({scalar, Event, Time0, Value, Auxiliary}, LastTime)
    when is_integer(Time0), Time0 >= 0, Time0 =< ?MAX_SCALAR ->
    case valid_event(Event, Value, Auxiliary) of
        true ->
            Time = erlang:max(Time0, LastTime),
            case event_json(Event, Time, Value, Auxiliary) of
                {ok, Json} -> {ok, Time, Json};
                error -> error
            end;
        false ->
            error
    end;
normalize_event(
    {frame, Event, Time0, StreamId, FrameType, PayloadBytes},
    LastTime
) ->
    case valid_frame_event(
        Event, Time0, StreamId, FrameType, PayloadBytes
    ) of
        true ->
            Time = erlang:max(Time0, LastTime),
            case frame_event_json(Event, Time, StreamId, FrameType, PayloadBytes) of
                {ok, Json} -> {ok, Time, Json};
                error -> error
            end;
        false ->
            error
    end;
normalize_event(_Metadata, _LastTime) ->
    error.

valid_event(_Event, Value, Auxiliary)
    when not is_integer(Value); Value < 0; Value > ?MAX_SCALAR;
         not is_integer(Auxiliary); Auxiliary < 0; Auxiliary > ?MAX_SCALAR ->
    false;
valid_event(Event, Value, Auxiliary)
    when Event =:= 1 orelse Event =:= 4 orelse Event =:= 5 orelse
         Event =:= 10 orelse Event =:= 16 orelse Event =:= 17 ->
    is_integer(Value) andalso Value >= 0 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(Event, Count, Bytes) when Event =:= 2 orelse Event =:= 3 ->
    is_integer(Count) andalso Count > 0 andalso Count =< 65535 andalso
        is_integer(Bytes) andalso Bytes >= 0;
valid_event(Event, PacketType, Bytes) when Event =:= 6 orelse Event =:= 7 ->
    is_integer(PacketType) andalso PacketType >= 1 andalso PacketType =< 8 andalso
        is_integer(Bytes) andalso Bytes >= 0;
valid_event(Event, KeyType, Auxiliary) when Event =:= 8 orelse Event =:= 9 ->
    is_integer(KeyType) andalso KeyType >= 1 andalso KeyType =< 8 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(11, State, Auxiliary) ->
    is_integer(State) andalso State >= 1 andalso State =< 4 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(12, State, Trigger) ->
    is_integer(State) andalso State >= 1 andalso State =< 4 andalso
        is_integer(Trigger) andalso Trigger >= 1 andalso Trigger =< 3;
valid_event(14, Initiator, Auxiliary) ->
    is_integer(Initiator) andalso Initiator >= 1 andalso Initiator =< 2 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(15, StreamId, StreamType) ->
    is_integer(StreamId) andalso StreamId >= 0 andalso
        is_integer(StreamType) andalso StreamType >= 1 andalso StreamType =< 7;
valid_event(18, Code, Auxiliary) ->
    is_integer(Code) andalso Code >= 0 andalso Code =< 2147483647 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(_Event, _Value, _Auxiliary) ->
    false.

valid_frame_event(Event, Time, StreamId, FrameType, PayloadBytes) ->
    is_integer(Event) andalso (Event =:= 12 orelse Event =:= 13) andalso
        is_integer(Time) andalso Time >= 0 andalso Time =< ?MAX_SCALAR andalso
        is_integer(StreamId) andalso StreamId >= 0 andalso StreamId =< ?MAX_STREAM_ID andalso
        is_integer(FrameType) andalso FrameType >= 1 andalso FrameType =< 8 andalso
        is_integer(PayloadBytes) andalso PayloadBytes >= 0 andalso PayloadBytes =< ?MAX_SCALAR.

header(Vantage) ->
    Role = role(Vantage),
    iolist_to_binary([
        <<"{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," >>,
        <<"\"serialization_format\":\"application/qlog+json-seq\"," >>,
        <<"\"title\":\"quic_core HTTP/3 diagnostics\"," >>,
        <<"\"description\":\"draft-ietf-quic-qlog-main-schema-14; privacy=strict\"," >>,
        <<"\"trace\":{" >>,
        <<"\"common_fields\":{" >>,
        <<"\"time_format\":\"relative_to_epoch\"," >>,
        <<"\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}}," >>,
        <<"\"vantage_point\":{\"name\":\"quic_core\",\"type\":\"" >>,
        Role,
        <<"\"},\"event_schemas\":[" >>,
        <<"\"urn:ietf:params:qlog:events:quic-13\"," >>,
        <<"\"urn:ietf:params:qlog:events:http3-13\"," >>,
        <<"\"urn:ietf:params:qlog:events:loglevel\"]}}" >>
    ]).

event_json(1, Time, _Value, _Auxiliary) ->
    %% The draft-13 event schema requires both endpoint objects.  Their
    %% members are optional, so empty objects preserve the strict diagnostic
    %% privacy profile without fabricating or retaining addresses.
    event_with_data(
        Time,
        <<"quic:connection_started">>,
        <<"{\"local\":{},\"remote\":{}}">>
    );
event_json(2, Time, Count, Bytes) ->
    event_with_datagrams(Time, <<"quic:udp_datagrams_received">>, Count, Bytes);
event_json(3, Time, Count, Bytes) ->
    event_with_datagrams(Time, <<"quic:udp_datagrams_sent">>, Count, Bytes);
event_json(4, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_complete\"}">>
    );
event_json(5, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:connection_closed">>,
        <<"{\"initiator\":\"local\",\"trigger\":\"application\"}">>
    );
event_json(6, Time, PacketType, Bytes) ->
    event_with_packet(Time, <<"quic:packet_received">>, PacketType, Bytes);
event_json(7, Time, PacketType, Bytes) ->
    event_with_packet(Time, <<"quic:packet_sent">>, PacketType, Bytes);
event_json(8, Time, KeyType, _Auxiliary) ->
    event_with_key(Time, <<"quic:key_updated">>, KeyType);
event_json(9, Time, KeyType, _Auxiliary) ->
    event_with_key(Time, <<"quic:key_discarded">>, KeyType);
event_json(10, Time, CongestionWindow, BytesInFlight) ->
    event_with_data(
        Time,
        <<"quic:recovery_metrics_updated">>,
        iolist_to_binary(io_lib:format(
            "{\"congestion_window\":~B,\"bytes_in_flight\":~B}",
            [CongestionWindow, BytesInFlight]
        ))
    );
event_json(11, Time, State, _Auxiliary) ->
    case congestion_state(State) of
        error -> error;
        Name -> event_with_data(
            Time,
            <<"quic:congestion_state_updated">>,
            iolist_to_binary([<<"{\"new\":\"">>, Name, <<"\"}">>])
        )
    end;
event_json(12, Time, State, Trigger) ->
    case {congestion_state(State), congestion_trigger(Trigger)} of
        {error, _} -> error;
        {_, error} -> error;
        {Name, Cause} -> event_with_data(
            Time,
            <<"quic:congestion_state_updated">>,
            iolist_to_binary([
                <<"{\"new\":\"">>, Name,
                <<"\",\"trigger\":\"">>, Cause, <<"\"}">>
            ])
        )
    end;
event_json(14, Time, Initiator, _Auxiliary) ->
    case initiator(Initiator) of
        error -> error;
        Name -> event_with_data(
            Time,
            <<"http3:parameters_set">>,
            iolist_to_binary([<<"{\"initiator\":\"">>, Name, <<"\"}">>])
        )
    end;
event_json(15, Time, StreamId, StreamType) ->
    case stream_type(StreamType) of
        error -> error;
        Name -> event_with_data(
            Time,
            <<"http3:stream_type_set">>,
            iolist_to_binary(io_lib:format(
                "{\"initiator\":\"local\",\"stream_id\":~B,"
                "\"stream_type\":\"~s\"}",
                [StreamId, Name]
            ))
        )
    end;
event_json(16, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_started\"}">>
    );
event_json(17, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_abandoned\"}">>
    );
event_json(18, Time, Code, _Auxiliary) when Code =< 2147483647 ->
    %% The main-schema loglevel:error event permits a numeric code without a
    %% message. Deliberately emit only that bounded code: the public bridge
    %% has no text or arbitrary-data parameter that could retain a payload.
    event_with_data(
        Time,
        <<"loglevel:error">>,
        iolist_to_binary(io_lib:format("{\"code\":~B}", [Code]))
    );
event_json(_Event, _Time, _Value, _Auxiliary) ->
    error.

frame_event_json(Event, Time, StreamId, FrameType, PayloadBytes) ->
    Name = frame_event_name(Event),
    case frame_json(FrameType, PayloadBytes) of
        error -> error;
        Frame ->
            event_with_data(
                Time,
                Name,
                iolist_to_binary([
                    <<"{\"stream_id\":" >>,
                    integer_to_binary(StreamId),
                    <<",\"frame\":" >>,
                    Frame,
                    <<"}">>
                ])
            )
    end.

frame_event_name(12) -> <<"http3:frame_created">>;
frame_event_name(13) -> <<"http3:frame_parsed">>.

frame_json(FrameType, PayloadBytes) ->
    case frame_type(FrameType) of
        error -> error;
        {Name, Required} ->
            Raw = case PayloadBytes of
                0 -> <<>>;
                _ -> iolist_to_binary(io_lib:format(
                    ",\"raw\":{\"length\":~B}", [PayloadBytes]
                ))
            end,
            iolist_to_binary([
                <<"{\"frame_type\":\"">>, Name, <<"\"">>, Required, Raw,
                <<"}">>
            ])
    end.

frame_type(1) -> {<<"data">>, <<>>};
frame_type(2) -> {<<"headers">>, <<",\"headers\":[]">>};
frame_type(3) -> {<<"cancel_push">>, <<",\"push_id\":0">>};
frame_type(4) -> {<<"settings">>, <<",\"settings\":[]">>};
frame_type(5) ->
    {<<"push_promise">>, <<",\"push_id\":0,\"headers\":[]">>};
frame_type(6) -> {<<"goaway">>, <<",\"id\":0">>};
frame_type(7) -> {<<"max_push_id">>, <<",\"push_id\":0">>};
frame_type(8) -> {<<"unknown">>, <<",\"frame_type_bytes\":0">>};
frame_type(_) -> error.

event_with_packet(Time, Name, PacketType, Bytes) ->
    case packet_type(PacketType) of
        error -> error;
        Type ->
            Raw = case Bytes of
                0 -> <<>>;
                _ -> iolist_to_binary(io_lib:format(
                    ",\"raw\":{\"length\":~B}", [Bytes]
                ))
            end,
            event_with_data(
                Time,
                Name,
                iolist_to_binary([
                    <<"{\"header\":{\"packet_type\":\"">>,
                    Type,
                    <<"\"}">>,
                    Raw,
                    <<"}">>
                ])
            )
    end.

event_with_key(Time, Name, KeyType) ->
    case key_type(KeyType) of
        error -> error;
        Type -> event_with_data(
            Time,
            Name,
            iolist_to_binary([
                <<"{\"key_type\":\"">>, Type,
                <<"\",\"trigger\":\"tls\"}">>
            ])
        )
    end.

packet_type(1) -> <<"initial">>;
packet_type(2) -> <<"handshake">>;
packet_type(3) -> <<"0RTT">>;
packet_type(4) -> <<"1RTT">>;
packet_type(5) -> <<"retry">>;
packet_type(6) -> <<"version_negotiation">>;
packet_type(7) -> <<"stateless_reset">>;
packet_type(8) -> <<"unknown">>;
packet_type(_) -> error.

key_type(1) -> <<"server_initial_secret">>;
key_type(2) -> <<"client_initial_secret">>;
key_type(3) -> <<"server_handshake_secret">>;
key_type(4) -> <<"client_handshake_secret">>;
key_type(5) -> <<"server_0rtt_secret">>;
key_type(6) -> <<"client_0rtt_secret">>;
key_type(7) -> <<"server_1rtt_secret">>;
key_type(8) -> <<"client_1rtt_secret">>;
key_type(_) -> error.

congestion_state(1) -> <<"slow_start">>;
congestion_state(2) -> <<"congestion_avoidance">>;
congestion_state(3) -> <<"recovery">>;
congestion_state(4) -> <<"application_limited">>;
congestion_state(_) -> error.

congestion_trigger(1) -> <<"packet_loss">>;
congestion_trigger(2) -> <<"ecn_ce">>;
congestion_trigger(3) -> <<"persistent_congestion">>;
congestion_trigger(_) -> error.

initiator(1) -> <<"local">>;
initiator(2) -> <<"remote">>;
initiator(_) -> error.

stream_type(1) -> <<"request">>;
stream_type(2) -> <<"control">>;
stream_type(3) -> <<"push">>;
stream_type(4) -> <<"reserved">>;
stream_type(5) -> <<"unknown">>;
stream_type(6) -> <<"qpack_encode">>;
stream_type(7) -> <<"qpack_decode">>;
stream_type(_) -> error.

event_with_datagrams(Time, Name, 1, Bytes) when Bytes > 0 ->
    event_with_data(
        Time,
        Name,
        iolist_to_binary(
            io_lib:format("{\"count\":1,\"raw\":[{\"length\":~B}]}", [Bytes])
        )
    );
event_with_datagrams(Time, Name, Count, _Bytes) when Count > 0, Count =< 65535 ->
    event_with_data(
        Time,
        Name,
        iolist_to_binary(io_lib:format("{\"count\":~B}", [Count]))
    );
event_with_datagrams(_Time, _Name, _Count, _Bytes) ->
    error.

event_with_data(Time, Name, Data) ->
    {ok, iolist_to_binary([
        <<"{\"time\":" >>,
        integer_to_binary(Time),
        <<",\"name\":\"" >>,
        Name,
        <<"\",\"data\":" >>,
        Data,
        <<"}">>
    ])}.

write_record(Device, Json) ->
    try file:write(Device, [<<16#1e>>, Json, <<"\n">>]) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, 3}
    catch
        _Class:_Reason -> {error, 3}
    end.

close_device(Device) ->
    try file:close(Device) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, 3}
    catch
        _Class:_Reason -> {error, 3}
    end.

role(1) -> <<"client">>;
role(2) -> <<"server">>.
