-module(http_test_ffi).

-export([
    await_task/1,
    close_system_udp_port_and_notify_owner/1,
    closed_system_udp_socket/0,
    exit_now/0,
    http1_listener_orphaned_writer_trace/0,
    http1_listener_snapshot_race/1,
    http2_listener_orphaned_writer_trace/0,
    http2_listener_snapshot_race/1,
    idle_direction_snapshot_race/1,
    malformed_dns_adapter/2,
    malformed_udp_socket_adapter/2,
    message_queue_length/0,
    kill_system_udp_owner/1,
    masque_listener_orphaned_writer_trace/0,
    masque_listener_snapshot_race/1,
    masque_listener_setup_snapshot_race/1,
    notify_system_udp_error/1,
    packet_too_big_builder_boundary_trace/0,
    packet_too_big_limiter_trace/0,
    packet_too_big_negative_epoch_refill_trace/0,
    packet_too_big_orphaned_seqlock_trace/0,
    packet_too_big_snapshot_race/1,
    packet_too_big_wire_vectors/0,
    server_credentials/0,
    start_exclusive_udp_port_guard/0,
    start_task/1,
    start_udp_ecn_echo_server/0,
    start_udp_echo_server/0,
    start_udp_fixed_response_server/1,
    stop_udp_echo_server/1,
    stop_exclusive_udp_port_guard/1,
    suspend_system_udp_owner/1,
    udp_ecn_echo_snapshot/1,
    udp_loopback_packet/1
]).

-define(TASK_TIMEOUT, 10000).

-spec http1_listener_snapshot_race(pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
http1_listener_snapshot_race(Iterations)
    when is_integer(Iterations), Iterations > 0, Iterations =< 1000000 ->
    Diagnostics = http_http1_listener_ffi:new(),
    Parent = self(),
    Reference = make_ref(),
    Workers = [
        fun() -> http1_successful_connection_worker(
            Diagnostics, Iterations, 0
        ) end,
        fun() -> http1_failed_connection_worker(
            Diagnostics, Iterations, 0
        ) end,
        fun() -> http1_handler_worker(Diagnostics, true, Iterations) end,
        fun() -> http1_handler_worker(Diagnostics, false, Iterations) end,
        fun() -> http1_accept_failure_worker(Diagnostics, Iterations) end
    ],
    lists:foreach(
        fun(Worker) ->
            spawn_link(fun() ->
                Worker(),
                Parent ! {Reference, http1_listener_worker_done}
            end)
        end,
        Workers
    ),
    Violations = observe_http1_listener_invariant(
        Diagnostics, Reference, length(Workers), 0
    ),
    {true, 0, _, Accepted, AcceptFailures, StartAttempts, Started,
     StartFailures, Active, Exited, ParsedHeads, HandlerDispatches,
     HandlerCompletions, HandlerFailures, ConnectionFailures, _, MaximumStart} =
        http_http1_listener_ffi:snapshot(Diagnostics),
    {Violations, Accepted, AcceptFailures, StartAttempts, Started,
     StartFailures, Active, Exited, ParsedHeads, HandlerDispatches,
     HandlerCompletions, HandlerFailures, ConnectionFailures, MaximumStart}.

-spec http1_listener_orphaned_writer_trace() ->
    {boolean(), boolean(), boolean()}.
http1_listener_orphaned_writer_trace() ->
    Diagnostics = http_http1_listener_ffi:new(),
    {http_http1_listener_diagnostics, Counters} = Diagnostics,
    ok = atomics:put(Counters, 18, 1),
    {SnapshotFinished, Snapshot} = bounded_listener_diagnostic_call(fun() ->
        http_http1_listener_ffi:snapshot(Diagnostics)
    end),
    {WriterFinished, _WriterResult} = bounded_listener_diagnostic_call(fun() ->
        http_http1_listener_ffi:record_accept(Diagnostics, true)
    end),
    ExplicitlyInconsistent = SnapshotFinished
        andalso is_tuple(Snapshot)
        andalso tuple_size(Snapshot) =:= 17
        andalso element(1, Snapshot) =:= false,
    {SnapshotFinished, WriterFinished, ExplicitlyInconsistent}.

-spec http2_listener_snapshot_race(pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer()}.
http2_listener_snapshot_race(Iterations)
    when is_integer(Iterations), Iterations > 0, Iterations =< 1000000 ->
    Diagnostics = http_http2_listener_ffi:new(),
    Parent = self(),
    Reference = make_ref(),
    Workers = [
        fun() -> http2_successful_connection_worker(
            Diagnostics, Iterations, 0
        ) end,
        fun() -> http2_failed_connection_worker(
            Diagnostics, Iterations, 0
        ) end,
        fun() -> http2_accept_failure_worker(Diagnostics, Iterations) end,
        fun() -> http2_drain_worker(Diagnostics, Iterations, 0) end,
        fun() -> http2_connection_failure_worker(Diagnostics, Iterations) end
    ],
    lists:foreach(
        fun(Worker) ->
            spawn_link(fun() ->
                Worker(),
                Parent ! {Reference, http2_listener_worker_done}
            end)
        end,
        Workers
    ),
    Violations = observe_http2_listener_invariant(
        Diagnostics, Reference, length(Workers), 0
    ),
    {true, 0, _, Accepted, AcceptFailures, StartAttempts, Started,
     StartFailures, Active, Exited, DrainRequests, DrainCommands,
     DrainReceipts, GoawayAttempts, GoawaysSent, GoawayFailures,
     DrainCompletions, ConnectionFailures, _, MaximumStart, _, MaximumGoaway} =
        http_http2_listener_ffi:snapshot(Diagnostics),
    {Violations, Accepted, AcceptFailures, StartAttempts, Started,
     StartFailures, Active, Exited, DrainRequests, DrainCommands,
     DrainReceipts, GoawayAttempts, GoawaysSent, GoawayFailures,
     DrainCompletions, ConnectionFailures, MaximumStart, MaximumGoaway}.

-spec http2_listener_orphaned_writer_trace() ->
    {boolean(), boolean(), boolean()}.
http2_listener_orphaned_writer_trace() ->
    Diagnostics = http_http2_listener_ffi:new(),
    {http_http2_listener_diagnostics, Counters} = Diagnostics,
    ok = atomics:put(Counters, 23, 1),
    {SnapshotFinished, Snapshot} = bounded_listener_diagnostic_call(fun() ->
        http_http2_listener_ffi:snapshot(Diagnostics)
    end),
    {WriterFinished, _WriterResult} = bounded_listener_diagnostic_call(fun() ->
        http_http2_listener_ffi:record_accept(Diagnostics, true)
    end),
    ExplicitlyInconsistent = SnapshotFinished
        andalso is_tuple(Snapshot)
        andalso tuple_size(Snapshot) =:= 22
        andalso element(1, Snapshot) =:= false,
    {SnapshotFinished, WriterFinished, ExplicitlyInconsistent}.

-spec http2_successful_connection_worker(
    term(), non_neg_integer(), non_neg_integer()
) -> ok.
http2_successful_connection_worker(_Diagnostics, 0, _Elapsed) ->
    ok;
http2_successful_connection_worker(Diagnostics, Remaining, Elapsed) ->
    nil = http_http2_listener_ffi:record_accept(Diagnostics, true),
    nil = http_http2_listener_ffi:record_connection_start(
        Diagnostics, true, Elapsed
    ),
    nil = http_http2_listener_ffi:record_connection_exit(Diagnostics),
    http2_successful_connection_worker(
        Diagnostics, Remaining - 1, Elapsed + 1
    ).

-spec http2_failed_connection_worker(
    term(), non_neg_integer(), non_neg_integer()
) -> ok.
http2_failed_connection_worker(_Diagnostics, 0, _Elapsed) ->
    ok;
http2_failed_connection_worker(Diagnostics, Remaining, Elapsed) ->
    nil = http_http2_listener_ffi:record_accept(Diagnostics, true),
    nil = http_http2_listener_ffi:record_connection_start(
        Diagnostics, false, Elapsed
    ),
    http2_failed_connection_worker(
        Diagnostics, Remaining - 1, Elapsed + 1
    ).

-spec http2_accept_failure_worker(term(), non_neg_integer()) -> ok.
http2_accept_failure_worker(_Diagnostics, 0) ->
    ok;
http2_accept_failure_worker(Diagnostics, Remaining) ->
    nil = http_http2_listener_ffi:record_accept(Diagnostics, false),
    http2_accept_failure_worker(Diagnostics, Remaining - 1).

-spec http2_drain_worker(
    term(), non_neg_integer(), non_neg_integer()
) -> ok.
http2_drain_worker(_Diagnostics, 0, _Elapsed) ->
    ok;
http2_drain_worker(Diagnostics, Remaining, Elapsed) ->
    nil = http_http2_listener_ffi:record_drain_request(Diagnostics, 2),
    nil = http_http2_listener_ffi:record_drain_receipt(Diagnostics),
    nil = http_http2_listener_ffi:record_drain_receipt(Diagnostics),
    nil = http_http2_listener_ffi:record_goaway(
        Diagnostics, true, Elapsed
    ),
    nil = http_http2_listener_ffi:record_goaway(
        Diagnostics, false, Elapsed
    ),
    nil = http_http2_listener_ffi:record_drain_completion(Diagnostics),
    http2_drain_worker(Diagnostics, Remaining - 1, Elapsed + 1).

-spec http2_connection_failure_worker(term(), non_neg_integer()) -> ok.
http2_connection_failure_worker(_Diagnostics, 0) ->
    ok;
http2_connection_failure_worker(Diagnostics, Remaining) ->
    nil = http_http2_listener_ffi:record_connection_failure(Diagnostics),
    http2_connection_failure_worker(Diagnostics, Remaining - 1).

-spec observe_http2_listener_invariant(
    term(), reference(), non_neg_integer(), non_neg_integer()
) -> non_neg_integer().
observe_http2_listener_invariant(
    _Diagnostics, _Reference, 0, Violations
) ->
    Violations;
observe_http2_listener_invariant(
    Diagnostics, Reference, Workers, Violations
) ->
    {Consistent, State, _, Accepted, _AcceptFailures, StartAttempts, Started,
     StartFailures, Active, Exited, DrainRequests, DrainCommands,
     DrainReceipts, GoawayAttempts, GoawaysSent, GoawayFailures,
     DrainCompletions, _ConnectionFailures, LastStart, MaximumStart,
     LastGoaway, MaximumGoaway} =
        http_http2_listener_ffi:snapshot(Diagnostics),
    Valid = not Consistent orelse (
        State =:= 0
        andalso StartAttempts =:= Started + StartFailures
        andalso Accepted >= StartAttempts
        andalso Active + Exited =:= Started
        andalso DrainCommands >= DrainReceipts
        andalso DrainReceipts >= GoawayAttempts
        andalso GoawayAttempts =:= GoawaysSent + GoawayFailures
        andalso DrainRequests >= DrainCompletions
        andalso MaximumStart >= LastStart
        andalso MaximumGoaway >= LastGoaway
    ),
    NextViolations = case Valid of
        true -> Violations;
        false -> Violations + 1
    end,
    receive
        {Reference, http2_listener_worker_done} ->
            observe_http2_listener_invariant(
                Diagnostics, Reference, Workers - 1, NextViolations
            )
    after 0 ->
        erlang:yield(),
        observe_http2_listener_invariant(
            Diagnostics, Reference, Workers, NextViolations
        )
    end.

-spec http1_successful_connection_worker(
    term(), non_neg_integer(), non_neg_integer()
) -> ok.
http1_successful_connection_worker(_Diagnostics, 0, _Elapsed) ->
    ok;
http1_successful_connection_worker(Diagnostics, Remaining, Elapsed) ->
    nil = http_http1_listener_ffi:record_accept(Diagnostics, true),
    nil = http_http1_listener_ffi:record_connection_start(
        Diagnostics, true, Elapsed
    ),
    nil = http_http1_listener_ffi:record_connection_exit(Diagnostics),
    http1_successful_connection_worker(
        Diagnostics, Remaining - 1, Elapsed + 1
    ).

-spec http1_failed_connection_worker(
    term(), non_neg_integer(), non_neg_integer()
) -> ok.
http1_failed_connection_worker(_Diagnostics, 0, _Elapsed) ->
    ok;
http1_failed_connection_worker(Diagnostics, Remaining, Elapsed) ->
    nil = http_http1_listener_ffi:record_accept(Diagnostics, true),
    nil = http_http1_listener_ffi:record_connection_start(
        Diagnostics, false, Elapsed
    ),
    http1_failed_connection_worker(
        Diagnostics, Remaining - 1, Elapsed + 1
    ).

-spec http1_handler_worker(term(), boolean(), non_neg_integer()) -> ok.
http1_handler_worker(_Diagnostics, _Succeeded, 0) ->
    ok;
http1_handler_worker(Diagnostics, Succeeded, Remaining) ->
    nil = http_http1_listener_ffi:record_request_head(Diagnostics),
    nil = http_http1_listener_ffi:record_handler_dispatch(Diagnostics),
    nil = http_http1_listener_ffi:record_handler_completion(
        Diagnostics, Succeeded
    ),
    case Succeeded of
        true -> ok;
        false ->
            nil = http_http1_listener_ffi:record_connection_failure(
                Diagnostics
            )
    end,
    http1_handler_worker(Diagnostics, Succeeded, Remaining - 1).

-spec http1_accept_failure_worker(term(), non_neg_integer()) -> ok.
http1_accept_failure_worker(_Diagnostics, 0) ->
    ok;
http1_accept_failure_worker(Diagnostics, Remaining) ->
    nil = http_http1_listener_ffi:record_accept(Diagnostics, false),
    http1_accept_failure_worker(Diagnostics, Remaining - 1).

-spec observe_http1_listener_invariant(
    term(), reference(), non_neg_integer(), non_neg_integer()
) -> non_neg_integer().
observe_http1_listener_invariant(
    _Diagnostics, _Reference, 0, Violations
) ->
    Violations;
observe_http1_listener_invariant(
    Diagnostics, Reference, Workers, Violations
) ->
    {Consistent, State, _, Accepted, _AcceptFailures, StartAttempts, Started,
     StartFailures, Active, Exited, ParsedHeads, HandlerDispatches,
     HandlerCompletions, HandlerFailures, _ConnectionFailures, LastStart,
     MaximumStart} = http_http1_listener_ffi:snapshot(Diagnostics),
    Valid = not Consistent orelse (
        State =:= 0
        andalso StartAttempts =:= Started + StartFailures
        andalso Accepted >= StartAttempts
        andalso Active + Exited =:= Started
        andalso ParsedHeads >= HandlerDispatches
        andalso HandlerDispatches >= HandlerCompletions
        andalso HandlerCompletions >= HandlerFailures
        andalso MaximumStart >= LastStart
    ),
    NextViolations = case Valid of
        true -> Violations;
        false -> Violations + 1
    end,
    receive
        {Reference, http1_listener_worker_done} ->
            observe_http1_listener_invariant(
                Diagnostics, Reference, Workers - 1, NextViolations
            )
    after 0 ->
        erlang:yield(),
        observe_http1_listener_invariant(
            Diagnostics, Reference, Workers, NextViolations
        )
    end.

-spec start_exclusive_udp_port_guard() ->
    {{http_udp_port_guard, pid()}, inet:port_number()}.
start_exclusive_udp_port_guard() ->
    Parent = self(),
    Reference = make_ref(),
    Pid = spawn_link(fun() ->
        {ok, Socket} = gen_udp:open(0, [
            binary,
            {active, false},
            {ip, {127, 0, 0, 1}},
            {reuseaddr, false}
        ]),
        {ok, {_Address, Port}} = inet:sockname(Socket),
        Parent ! {Reference, exclusive_udp_port_ready, Port},
        exclusive_udp_port_guard_loop(Socket)
    end),
    receive
        {Reference, exclusive_udp_port_ready, Port} ->
            {{http_udp_port_guard, Pid}, Port}
    after ?TASK_TIMEOUT ->
        exit(Pid, kill),
        erlang:error(exclusive_udp_port_guard_timeout)
    end.

-spec stop_exclusive_udp_port_guard(term()) -> nil.
stop_exclusive_udp_port_guard({http_udp_port_guard, Pid}) when is_pid(Pid) ->
    Monitor = erlang:monitor(process, Pid),
    Pid ! stop_exclusive_udp_port_guard,
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> nil
    after ?TASK_TIMEOUT ->
        erlang:demonitor(Monitor, [flush]),
        exit(Pid, kill),
        nil
    end;
stop_exclusive_udp_port_guard(_Guard) ->
    nil.

-spec exclusive_udp_port_guard_loop(gen_udp:socket()) -> no_return().
exclusive_udp_port_guard_loop(Socket) ->
    receive
        stop_exclusive_udp_port_guard ->
            gen_udp:close(Socket),
            exit(normal);
        _Foreign -> exclusive_udp_port_guard_loop(Socket)
    end.

-spec masque_listener_snapshot_race(pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer()}.
masque_listener_snapshot_race(Iterations)
    when is_integer(Iterations), Iterations > 0, Iterations =< 1000000 ->
    Diagnostics = http_masque_listener_ffi:new(),
    Parent = self(),
    Reference = make_ref(),
    lists:foreach(
        fun(Outcome) ->
            spawn_link(fun() ->
                masque_listener_worker(Diagnostics, Outcome, Iterations),
                Parent ! {Reference, masque_listener_worker_done}
            end)
        end,
        [1, 2, 3, 4]
    ),
    Violations = observe_masque_listener_invariant(
        Diagnostics, Reference, 4, 0
    ),
    {true, _, Calls, Accepted, Rejected, Failures, ResponseFailures,
     _, _, _, _, _, _, _, _, _, _, _} =
        http_masque_listener_ffi:snapshot(Diagnostics),
    {Violations, Calls, Accepted, Rejected, Failures, ResponseFailures}.

-spec masque_listener_orphaned_writer_trace() ->
    {boolean(), boolean(), boolean()}.
masque_listener_orphaned_writer_trace() ->
    Diagnostics = http_masque_listener_ffi:new(),
    {http_masque_listener_diagnostics, Counters} = Diagnostics,
    ok = atomics:put(Counters, 19, 1),
    {SnapshotFinished, Snapshot} = bounded_listener_diagnostic_call(fun() ->
        http_masque_listener_ffi:snapshot(Diagnostics)
    end),
    {WriterFinished, _WriterResult} = bounded_listener_diagnostic_call(fun() ->
        http_masque_listener_ffi:record_accept(Diagnostics, 1)
    end),
    ExplicitlyInconsistent = SnapshotFinished
        andalso is_tuple(Snapshot)
        andalso tuple_size(Snapshot) =:= 18
        andalso element(1, Snapshot) =:= false,
    {SnapshotFinished, WriterFinished, ExplicitlyInconsistent}.

-spec bounded_listener_diagnostic_call(fun(() -> term())) ->
    {boolean(), term()}.
bounded_listener_diagnostic_call(Run) ->
    Parent = self(),
    Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Parent ! {Reference, listener_diagnostic_result, Run()}
    end),
    receive
        {Reference, listener_diagnostic_result, Result} ->
            erlang:demonitor(Monitor, [flush]),
            {true, Result};
        {'DOWN', Monitor, process, Pid, _Reason} ->
            {false, crashed}
    after 25 ->
        exit(Pid, kill),
        receive
            {'DOWN', Monitor, process, Pid, _Reason} ->
                {false, timed_out}
        end
    end.

-spec masque_listener_worker(term(), 1..4, non_neg_integer()) -> ok.
masque_listener_worker(_Diagnostics, _Outcome, 0) ->
    ok;
masque_listener_worker(Diagnostics, Outcome, Remaining) ->
    nil = http_masque_listener_ffi:record_accept(Diagnostics, Outcome),
    masque_listener_worker(Diagnostics, Outcome, Remaining - 1).

-spec observe_masque_listener_invariant(
    term(), reference(), non_neg_integer(), non_neg_integer()
) -> non_neg_integer().
observe_masque_listener_invariant(
    _Diagnostics, _Reference, 0, Violations
) ->
    Violations;
observe_masque_listener_invariant(
    Diagnostics, Reference, Workers, Violations
) ->
    {Consistent, State, Calls, Accepted, Rejected, Failures, ResponseFailures,
     _, _, _, _, _, _, _, _, _, _, _} =
        http_masque_listener_ffi:snapshot(Diagnostics),
    Valid = not Consistent orelse (
        State =:= 1
        andalso Calls =:= Accepted + Rejected + Failures
        andalso ResponseFailures =< Rejected
    ),
    NextViolations = case Valid of
        true -> Violations;
        false -> Violations + 1
    end,
    receive
        {Reference, masque_listener_worker_done} ->
            observe_masque_listener_invariant(
                Diagnostics, Reference, Workers - 1, NextViolations
            )
    after 0 ->
        erlang:yield(),
        observe_masque_listener_invariant(
            Diagnostics, Reference, Workers, NextViolations
        )
    end.

-spec masque_listener_setup_snapshot_race(pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer()}.
masque_listener_setup_snapshot_race(Iterations)
    when is_integer(Iterations), Iterations > 0, Iterations =< 1000000 ->
    Diagnostics = http_masque_listener_ffi:new(),
    Parent = self(),
    Reference = make_ref(),
    lists:foreach(
        fun(Outcome) ->
            spawn_link(fun() ->
                masque_listener_setup_worker(
                    Diagnostics, Outcome, Iterations
                ),
                Parent ! {Reference, masque_listener_setup_worker_done}
            end)
        end,
        [1, 2, 3, 4, duplicate]
    ),
    Violations = observe_masque_listener_setup_invariant(
        Diagnostics, Reference, 5, 0
    ),
    {true, _, _, _, _, _, _, Calls, Established, PolicyRejections,
     SetupRejections, ResponseFailures, Duplicates, _, _, _, _, _} =
        http_masque_listener_ffi:snapshot(Diagnostics),
    {Violations, Calls, Established, PolicyRejections, SetupRejections,
     ResponseFailures, Duplicates}.

-spec masque_listener_setup_worker(
    term(), 1..4 | duplicate, non_neg_integer()
) -> ok.
masque_listener_setup_worker(_Diagnostics, _Outcome, 0) ->
    ok;
masque_listener_setup_worker(Diagnostics, duplicate, Remaining) ->
    nil = http_masque_listener_ffi:record_setup_duplicate(Diagnostics),
    masque_listener_setup_worker(Diagnostics, duplicate, Remaining - 1);
masque_listener_setup_worker(Diagnostics, Outcome, Remaining) ->
    nil = http_masque_listener_ffi:record_setup(Diagnostics, Outcome),
    masque_listener_setup_worker(Diagnostics, Outcome, Remaining - 1).

-spec observe_masque_listener_setup_invariant(
    term(), reference(), non_neg_integer(), non_neg_integer()
) -> non_neg_integer().
observe_masque_listener_setup_invariant(
    _Diagnostics, _Reference, 0, Violations
) ->
    Violations;
observe_masque_listener_setup_invariant(
    Diagnostics, Reference, Workers, Violations
) ->
    {Consistent, State, _, _, _, _, _, Calls, Established, PolicyRejections,
     SetupRejections, ResponseFailures, _Duplicates, _, _, _, _, _} =
        http_masque_listener_ffi:snapshot(Diagnostics),
    Valid = not Consistent orelse (
        State =:= 1
        andalso Calls =:= Established + PolicyRejections
            + SetupRejections + ResponseFailures
    ),
    NextViolations = case Valid of
        true -> Violations;
        false -> Violations + 1
    end,
    receive
        {Reference, masque_listener_setup_worker_done} ->
            observe_masque_listener_setup_invariant(
                Diagnostics, Reference, Workers - 1, NextViolations
            )
    after 0 ->
        erlang:yield(),
        observe_masque_listener_setup_invariant(
            Diagnostics, Reference, Workers, NextViolations
        )
    end.

-spec idle_direction_snapshot_race(pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer()}.
idle_direction_snapshot_race(Iterations)
    when is_integer(Iterations), Iterations > 0, Iterations =< 1000000 ->
    State = http_masque_udp_ffi:idle_new(1000000, 0),
    Parent = self(),
    Reference = make_ref(),
    spawn_link(fun() ->
        idle_direction_worker(State, 1, Iterations),
        Parent ! {Reference, idle_direction_worker_done}
    end),
    spawn_link(fun() ->
        idle_direction_worker(State, 2, Iterations),
        Parent ! {Reference, idle_direction_worker_done}
    end),
    Violations = observe_idle_direction_invariant(State, Reference, 2, 0),
    {_, _, _, _, Total, Outbound, Inbound, _, _, _, _, _} =
        http_masque_udp_ffi:idle_snapshot(State),
    _ = http_masque_udp_ffi:idle_stop(State),
    {Violations, Total, Outbound, Inbound}.

-spec idle_direction_worker(term(), 1 | 2, non_neg_integer()) -> ok.
idle_direction_worker(_State, _Direction, 0) ->
    ok;
idle_direction_worker(State, Direction, Remaining) ->
    _ = http_masque_udp_ffi:idle_activity(State, 0, Direction),
    idle_direction_worker(State, Direction, Remaining - 1).

-spec observe_idle_direction_invariant(
    term(), reference(), non_neg_integer(), non_neg_integer()
) -> non_neg_integer().
observe_idle_direction_invariant(_State, _Reference, 0, Violations) ->
    Violations;
observe_idle_direction_invariant(State, Reference, Workers, Violations) ->
    {_, _, _, _, Total, Outbound, Inbound, _, _, _, _, _} =
        http_masque_udp_ffi:idle_snapshot(State),
    NextViolations = case Total =:= Outbound + Inbound of
        true -> Violations;
        false -> Violations + 1
    end,
    receive
        {Reference, idle_direction_worker_done} ->
            observe_idle_direction_invariant(
                State, Reference, Workers - 1, NextViolations
            )
    after 0 ->
        erlang:yield(),
        observe_idle_direction_invariant(
            State, Reference, Workers, NextViolations
        )
    end.

-spec start_task(fun(() -> term())) -> tuple().
start_task(Fun) when is_function(Fun, 0) ->
    Owner = self(),
    Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Outcome = try Fun() of
            Result -> {ok, Result}
        catch
            Class:Reason:Stacktrace -> {raised, Class, Reason, Stacktrace}
        end,
        Owner ! {Reference, task_result, Outcome}
    end),
    {http_test_task, Pid, Monitor, Reference}.

-spec await_task(tuple()) -> term().
await_task({http_test_task, Pid, Monitor, Reference}) ->
    receive
        {Reference, task_result, {ok, Result}} ->
            await_process_down(Pid, Monitor),
            Result;
        {Reference, task_result, {raised, Class, Reason, Stacktrace}} ->
            await_process_down(Pid, Monitor),
            erlang:raise(Class, Reason, Stacktrace);
        {'DOWN', Monitor, process, Pid, Reason} ->
            receive
                {Reference, task_result, {ok, Result}} -> Result;
                {Reference, task_result, {raised, Class, Raised, Stacktrace}} ->
                    erlang:raise(Class, Raised, Stacktrace)
            after 0 ->
                erlang:error({test_task_stopped, Reason})
            end
    after ?TASK_TIMEOUT ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(test_task_timeout)
    end.

-spec server_credentials() -> {binary(), binary(), binary()}.
server_credentials() ->
    Root = "packages/http3/test/fixtures",
    {ok, CertificatePem} =
        file:read_file(filename:join(Root, "server.pem")),
    {ok, PrivateKeyPem} =
        file:read_file(filename:join(Root, "server-key.pem")),
    {ok, CaPem} = file:read_file(filename:join(Root, "ca.pem")),
    [CaDer | _] = [
        Der
     || {'Certificate', Der, _Encryption} <- public_key:pem_decode(CaPem)
    ],
    {CertificatePem, PrivateKeyPem, CaDer}.

-spec exit_now() -> no_return().
exit_now() ->
    exit({handler_exit, redacted_test_reason}).

-spec malformed_dns_adapter(binary(), integer()) -> {ok, atom()}.
malformed_dns_adapter(_Host, _TimeoutMilliseconds) ->
    {ok, malformed_dns_answer}.

-spec malformed_udp_socket_adapter(term(), integer()) -> {ok, atom()}.
malformed_udp_socket_adapter(_Endpoint, _TimeoutMilliseconds) ->
    {ok, malformed_udp_socket_resource}.

-spec udp_loopback_packet(binary()) -> {tuple(), tuple(), binary()}.
udp_loopback_packet(Payload) when is_binary(Payload) ->
    {ok, Receiver} = gen_udp:open(
        0, [binary, inet, {active, false}, {ip, {127, 0, 0, 1}}]
    ),
    try
        {ok, {{127, 0, 0, 1}, ReceiverPort}} = inet:sockname(Receiver),
        {ok, Sender} = gen_udp:open(
            0, [binary, inet, {active, false}, {ip, {127, 0, 0, 1}}]
        ),
        try
            {ok, {{127, 0, 0, 1}, SenderPort}} = inet:sockname(Sender),
            ok = gen_udp:send(
                Sender, {127, 0, 0, 1}, ReceiverPort, Payload
            ),
            {ok, {SourceAddress, SourcePort, Received}} =
                gen_udp:recv(Receiver, 0, 1000),
            {
                test_udp_endpoint({127, 0, 0, 1}, SenderPort),
                test_udp_endpoint(SourceAddress, SourcePort),
                Received
            }
        after
            gen_udp:close(Sender)
        end
    after
        gen_udp:close(Receiver)
    end.

-spec start_udp_echo_server() -> {tuple(), tuple()}.
start_udp_echo_server() ->
    Caller = self(),
    Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        {ok, Socket} = gen_udp:open(
            0,
            [binary, inet, {active, once}, {ip, {127, 0, 0, 1}}]
        ),
        {ok, {{127, 0, 0, 1}, Port}} = inet:sockname(Socket),
        Caller ! {Reference, udp_echo_ready, Port},
        udp_echo_loop(Socket, Reference)
    end),
    receive
        {Reference, udp_echo_ready, Port} ->
            {
                {http_test_udp_echo, Pid, Monitor, Reference},
                test_udp_endpoint({127, 0, 0, 1}, Port)
            };
        {'DOWN', Monitor, process, Pid, Reason} ->
            erlang:error({udp_echo_start_failed, Reason})
    after ?TASK_TIMEOUT ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(udp_echo_start_timeout)
    end.

-spec start_udp_fixed_response_server(binary()) -> {tuple(), tuple()}.
start_udp_fixed_response_server(Response)
    when is_binary(Response), byte_size(Response) =< 65527 ->
    Caller = self(),
    Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        {ok, Socket} = gen_udp:open(
            0,
            [binary, inet, {active, once}, {ip, {127, 0, 0, 1}}]
        ),
        {ok, {{127, 0, 0, 1}, Port}} = inet:sockname(Socket),
        Caller ! {Reference, udp_fixed_response_ready, Port},
        udp_fixed_response_loop(Socket, Reference, Response)
    end),
    receive
        {Reference, udp_fixed_response_ready, Port} ->
            {
                {http_test_udp_fixed_response, Pid, Monitor, Reference},
                test_udp_endpoint({127, 0, 0, 1}, Port)
            };
        {'DOWN', Monitor, process, Pid, Reason} ->
            erlang:error({udp_fixed_response_start_failed, Reason})
    after ?TASK_TIMEOUT ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(udp_fixed_response_start_timeout)
    end.

-spec start_udp_ecn_echo_server() -> {tuple(), tuple()}.
start_udp_ecn_echo_server() ->
    Caller = self(),
    Reference = make_ref(),
    Counters = atomics:new(3, [{signed, true}]),
    atomics:put(Counters, 2, -1),
    atomics:put(Counters, 3, -1),
    {Pid, Monitor} = spawn_monitor(fun() ->
        {ok, Socket} = gen_udp:open(
            0,
            [
                binary,
                inet,
                {active, once},
                {ip, {127, 0, 0, 1}},
                {recvtos, true},
                {tos, 3}
            ]
        ),
        {ok, [{tos, ReplyTos}]} = inet:getopts(Socket, [tos]),
        atomics:put(Counters, 3, ReplyTos),
        {ok, {{127, 0, 0, 1}, Port}} = inet:sockname(Socket),
        Caller ! {Reference, udp_ecn_echo_ready, Port},
        udp_ecn_echo_loop(Socket, Reference, Counters)
    end),
    receive
        {Reference, udp_ecn_echo_ready, Port} ->
            {
                {http_test_udp_ecn_echo, Pid, Monitor, Reference, Counters},
                test_udp_endpoint({127, 0, 0, 1}, Port)
            };
        {'DOWN', Monitor, process, Pid, Reason} ->
            erlang:error({udp_ecn_echo_start_failed, Reason})
    after ?TASK_TIMEOUT ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(udp_ecn_echo_start_timeout)
    end.

-spec udp_ecn_echo_snapshot(tuple()) -> {integer(), integer(), integer()}.
udp_ecn_echo_snapshot(
    {http_test_udp_ecn_echo, _Pid, _Monitor, _Reference, Counters}
) ->
    {
        atomics:get(Counters, 1),
        atomics:get(Counters, 2),
        atomics:get(Counters, 3)
    }.

-spec stop_udp_echo_server(tuple()) -> nil.
stop_udp_echo_server({http_test_udp_echo, Pid, Monitor, Reference}) ->
    Pid ! {Reference, stop_udp_echo},
    await_process_down(Pid, Monitor),
    nil;
stop_udp_echo_server(
    {http_test_udp_ecn_echo, Pid, Monitor, Reference, _Counters}
) ->
    Pid ! {Reference, stop_udp_echo},
    await_process_down(Pid, Monitor),
    nil;
stop_udp_echo_server(
    {http_test_udp_fixed_response, Pid, Monitor, Reference}
) ->
    Pid ! {Reference, stop_udp_echo},
    await_process_down(Pid, Monitor),
    nil.

-spec udp_echo_loop(gen_udp:socket(), reference()) -> no_return().
udp_echo_loop(Socket, Reference) ->
    receive
        {udp, Socket, Address, Port, Payload} ->
            ok = gen_udp:send(Socket, Address, Port, Payload),
            ok = inet:setopts(Socket, [{active, once}]),
            udp_echo_loop(Socket, Reference);
        {Reference, stop_udp_echo} ->
            gen_udp:close(Socket),
            exit(normal);
        {udp_error, Socket, Reason} ->
            gen_udp:close(Socket),
            exit({udp_echo_error, Reason});
        {udp_closed, Socket} ->
            exit(normal);
        _Foreign ->
            udp_echo_loop(Socket, Reference)
    end.

-spec udp_fixed_response_loop(gen_udp:socket(), reference(), binary()) ->
    no_return().
udp_fixed_response_loop(Socket, Reference, Response) ->
    receive
        {udp, Socket, Address, Port, _Payload} ->
            ok = gen_udp:send(Socket, Address, Port, Response),
            ok = inet:setopts(Socket, [{active, once}]),
            udp_fixed_response_loop(Socket, Reference, Response);
        {Reference, stop_udp_echo} ->
            gen_udp:close(Socket),
            exit(normal);
        {udp_error, Socket, Reason} ->
            gen_udp:close(Socket),
            exit({udp_fixed_response_error, Reason});
        {udp_closed, Socket} ->
            exit(normal);
        _Foreign ->
            udp_fixed_response_loop(Socket, Reference, Response)
    end.

-spec packet_too_big_wire_vectors() -> {binary(), binary()}.
packet_too_big_wire_vectors() ->
    Payload = <<"oversized">>,
    {ok, Ipv4, 32, 37} = http_masque_packet_too_big_ffi:build(
        4,
        {192, 0, 2, 1},
        5555,
        {198, 51, 100, 2},
        443,
        Payload,
        4
    ),
    {ok, Ipv6, 52, 57} = http_masque_packet_too_big_ffi:build(
        6,
        {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
        5555,
        {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
        443,
        Payload,
        4
    ),
    {Ipv4, Ipv6}.

-spec packet_too_big_builder_boundary_trace() ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     integer(), integer(), integer(), integer()}.
packet_too_big_builder_boundary_trace() ->
    Ipv4Payload = binary:copy(<<0>>, 65507),
    {ok, Ipv4, Ipv4Mtu, Ipv4Quote} =
        http_masque_packet_too_big_ffi:build(
            4,
            {192, 0, 2, 1},
            5555,
            {198, 51, 100, 2},
            443,
            Ipv4Payload,
            65507
        ),
    Ipv6Payload = binary:copy(<<0>>, 65527),
    {ok, Ipv6, Ipv6Mtu, Ipv6Quote} =
        http_masque_packet_too_big_ffi:build(
            6,
            {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
            5555,
            {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
            443,
            Ipv6Payload,
            65527
        ),
    {error, Ipv4Overflow} = http_masque_packet_too_big_ffi:build(
        4,
        {192, 0, 2, 1},
        5555,
        {198, 51, 100, 2},
        443,
        binary:copy(<<0>>, 65508),
        65507
    ),
    {error, Ipv6Overflow} = http_masque_packet_too_big_ffi:build(
        6,
        {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
        5555,
        {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
        443,
        binary:copy(<<0>>, 65528),
        65527
    ),
    {error, Ipv4Prohibited} = http_masque_packet_too_big_ffi:build(
        4,
        {192, 0, 2, 1},
        5555,
        {224, 0, 0, 1},
        443,
        <<0>>,
        32
    ),
    {error, Ipv6Prohibited} = http_masque_packet_too_big_ffi:build(
        6,
        {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
        5555,
        {16#ff02, 0, 0, 0, 0, 0, 0, 1},
        443,
        <<0>>,
        32
    ),
    {
        byte_size(Ipv4), Ipv4Quote, Ipv4Mtu,
        byte_size(Ipv6), Ipv6Quote, Ipv6Mtu,
        Ipv4Overflow, Ipv6Overflow, Ipv4Prohibited, Ipv6Prohibited
    }.

-spec packet_too_big_limiter_trace() ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
packet_too_big_limiter_trace() ->
    Initial = http_masque_packet_too_big_ffi:new_limiter(1000),
    {Allowed, Limited, Exhausted} = packet_too_big_claims(
        11, 1000, Initial, 0, 0
    ),
    {Refilled, _Next} = http_masque_packet_too_big_ffi:claim(
        Exhausted, 1100
    ),
    {Allowed, Limited, Refilled}.

-spec packet_too_big_negative_epoch_refill_trace() ->
    {integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
packet_too_big_negative_epoch_refill_trace() ->
    Diagnostics = http_masque_packet_too_big_ffi:diagnostics_new(32, 4),
    #{counters := Counters} = Diagnostics,
    Now = erlang:monotonic_time(millisecond),
    NegativePrevious = erlang:min(-1, Now - 100),
    ok = atomics:put(Counters, 19, 0),
    ok = atomics:put(Counters, 20, NegativePrevious),
    {ok, Socket} = gen_udp:open(0, [
        binary,
        {active, false},
        {ip, {127, 0, 0, 1}}
    ]),
    ok = gen_udp:close(Socket),
    {Delivery, _, _} = http_masque_packet_too_big_ffi:deliver(
        Diagnostics,
        4,
        Socket,
        {127, 0, 0, 1},
        9,
        <<"oversized">>,
        1
    ),
    {_, _, _, _, _, _, _, _, _, Attempts, _, _, RateLimited, _, _, _, _,
     Failures, _, _, _, _} =
        http_masque_packet_too_big_ffi:diagnostics_snapshot(Diagnostics),
    {Delivery, Attempts, RateLimited, Failures}.

-spec packet_too_big_orphaned_seqlock_trace() -> {boolean(), boolean()}.
packet_too_big_orphaned_seqlock_trace() ->
    Diagnostics = http_masque_packet_too_big_ffi:diagnostics_new(32, 4),
    #{counters := Counters} = Diagnostics,
    ok = atomics:put(Counters, 1, 1),
    {Pid, Monitor} = spawn_monitor(fun() ->
        ok = http_masque_packet_too_big_ffi:diagnostics_record(
            Diagnostics, 64, 5, true, false, 0, 0, 0
        )
    end),
    WriterFinished = receive
        {'DOWN', Monitor, process, Pid, normal} -> true
    after 25 ->
        exit(Pid, kill),
        receive
            {'DOWN', Monitor, process, Pid, _Reason} -> false
        end
    end,
    Snapshot = http_masque_packet_too_big_ffi:diagnostics_snapshot(
        Diagnostics
    ),
    {WriterFinished, element(1, Snapshot)}.

-spec packet_too_big_claims(
    non_neg_integer(), integer(), term(), non_neg_integer(),
    non_neg_integer()
) -> {non_neg_integer(), non_neg_integer(), term()}.
packet_too_big_claims(0, _Now, Limiter, Allowed, Limited) ->
    {Allowed, Limited, Limiter};
packet_too_big_claims(Remaining, Now, Limiter, Allowed, Limited) ->
    {Decision, Next} = http_masque_packet_too_big_ffi:claim(Limiter, Now),
    packet_too_big_claims(
        Remaining - 1,
        Now,
        Next,
        Allowed + Decision,
        Limited + (1 - Decision)
    ).

-spec packet_too_big_snapshot_race(pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
packet_too_big_snapshot_race(Iterations)
    when is_integer(Iterations), Iterations > 0, Iterations =< 1000000 ->
    Diagnostics = http_masque_packet_too_big_ffi:diagnostics_new(32, 4),
    Parent = self(),
    Reference = make_ref(),
    spawn_link(fun() ->
        packet_too_big_snapshot_writer(Diagnostics, Iterations, 0),
        Parent ! {Reference, packet_too_big_snapshot_writer_done}
    end),
    Violations = observe_packet_too_big_snapshot(
        Diagnostics, Reference, 0
    ),
    Snapshot = http_masque_packet_too_big_ffi:diagnostics_snapshot(
        Diagnostics
    ),
    {true, _, _, _, _, _, 0, Oversized, _, Attempts, Delivered, _,
     RateLimited, PermissionDenied, Unsupported, TimedOut, Prohibited,
     Failures, Cached, _, _, _} = Snapshot,
    Outcomes = Delivered + RateLimited + PermissionDenied + Unsupported
        + TimedOut + Prohibited + Failures,
    {Violations, Oversized, Outcomes, Attempts, Cached}.

-spec packet_too_big_snapshot_writer(term(), non_neg_integer(),
                                     non_neg_integer()) -> ok.
packet_too_big_snapshot_writer(_Diagnostics, 0, _Index) ->
    ok;
packet_too_big_snapshot_writer(Diagnostics, Remaining, Index) ->
    Attempted = Index rem 2 =:= 0,
    ok = http_masque_packet_too_big_ffi:diagnostics_record(
        Diagnostics,
        64,
        3,
        Attempted,
        not Attempted,
        0,
        92,
        1
    ),
    packet_too_big_snapshot_writer(
        Diagnostics, Remaining - 1, Index + 1
    ).

-spec observe_packet_too_big_snapshot(
    term(), reference(), non_neg_integer()
) -> non_neg_integer().
observe_packet_too_big_snapshot(Diagnostics, Reference, Violations) ->
    Snapshot = http_masque_packet_too_big_ffi:diagnostics_snapshot(
        Diagnostics
    ),
    {Consistent, 32, 10, 10, 100, Buffered, 0, Oversized, Bytes,
     Attempts, Delivered, DeliveredBytes, RateLimited, PermissionDenied,
     Unsupported, TimedOut, Prohibited, Failures, Cached, MaximumQuote,
     60, _MaximumSend} = Snapshot,
    Outcomes = Delivered + RateLimited + PermissionDenied + Unsupported
        + TimedOut + Prohibited + Failures,
    Valid = not Consistent orelse (
        Buffered >= 0 andalso Buffered =< 1 andalso
        Oversized =:= Outcomes andalso Bytes =:= Oversized * 64 andalso
        Attempts + Cached =:= Oversized andalso DeliveredBytes =:= 0 andalso
        MaximumQuote =< 92
    ),
    NextViolations = case Valid of
        true -> Violations;
        false -> Violations + 1
    end,
    receive
        {Reference, packet_too_big_snapshot_writer_done} ->
            NextViolations
    after 0 ->
        erlang:yield(),
        observe_packet_too_big_snapshot(
            Diagnostics, Reference, NextViolations
        )
    end.

-spec udp_ecn_echo_loop(gen_udp:socket(), reference(), atomics:atomics_ref()) ->
    no_return().
udp_ecn_echo_loop(Socket, Reference, Counters) ->
    receive
        {udp, Socket, Address, Port, Ancillary, Payload} ->
            IncomingTos = case lists:keyfind(tos, 1, Ancillary) of
                {tos, Value} when is_integer(Value) -> Value;
                false -> -1
            end,
            atomics:add(Counters, 1, 1),
            atomics:put(Counters, 2, IncomingTos),
            ok = gen_udp:send(Socket, Address, Port, Payload),
            ok = inet:setopts(Socket, [{active, once}]),
            udp_ecn_echo_loop(Socket, Reference, Counters);
        {Reference, stop_udp_echo} ->
            gen_udp:close(Socket),
            exit(normal);
        {udp_error, Socket, Reason} ->
            gen_udp:close(Socket),
            exit({udp_ecn_echo_error, Reason});
        {udp_closed, Socket} ->
            exit(normal);
        _Foreign ->
            udp_ecn_echo_loop(Socket, Reference, Counters)
    end.

-spec closed_system_udp_socket() -> map().
closed_system_udp_socket() ->
    Counters = atomics:new(27, [{signed, true}]),
    PacketTooBig = http_masque_packet_too_big_ffi:diagnostics_new(65527, 4),
    ok = atomics:put(Counters, 1, 3),
    Pid = spawn(fun() -> ok end),
    Monitor = erlang:monitor(process, Pid),
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> ok
    end,
    #{
        tag => http_masque_udp_socket,
        pid => Pid,
        reference => make_ref(),
        owner => self(),
        counters => Counters,
        packet_too_big => PacketTooBig
    }.

-spec kill_system_udp_owner(map()) -> nil.
kill_system_udp_owner(#{tag := http_masque_udp_socket, pid := Pid}) ->
    Monitor = erlang:monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> nil
    after ?TASK_TIMEOUT ->
        erlang:error(system_udp_owner_did_not_stop)
    end.

-spec close_system_udp_port_and_notify_owner(map()) -> nil.
close_system_udp_port_and_notify_owner(
    #{tag := http_masque_udp_socket, pid := Pid}
) ->
    Socket = system_udp_port(Pid),
    ok = gen_udp:close(Socket),
    Pid ! {udp_closed, Socket},
    nil.

-spec notify_system_udp_error(map()) -> nil.
notify_system_udp_error(#{tag := http_masque_udp_socket, pid := Pid}) ->
    Socket = system_udp_port(Pid),
    Pid ! {udp_error, Socket, econnrefused},
    nil.

-spec system_udp_port(pid()) -> port().
system_udp_port(Pid) ->
    case process_info(Pid, links) of
        {links, Links} ->
            case [Link || Link <- Links, is_port(Link)] of
                [Socket] -> Socket;
                Sockets ->
                    erlang:error({unexpected_system_udp_ports, length(Sockets)})
            end;
        undefined ->
            erlang:error(system_udp_owner_already_stopped)
    end.

-spec suspend_system_udp_owner(map()) -> nil.
suspend_system_udp_owner(#{tag := http_masque_udp_socket, pid := Pid}) ->
    true = erlang:suspend_process(Pid),
    nil.

-spec test_udp_endpoint(inet:ip4_address(), inet:port_number()) -> tuple().
test_udp_endpoint({A, B, C, D}, Port) ->
    {udp_endpoint, {ipv4, <<A, B, C, D>>}, Port}.

-spec message_queue_length() -> non_neg_integer().
message_queue_length() ->
    {message_queue_len, Length} = process_info(self(), message_queue_len),
    Length.

-spec await_process_down(pid(), reference()) -> ok.
await_process_down(Pid, Monitor) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after ?TASK_TIMEOUT ->
        exit(Pid, kill),
        receive
            {'DOWN', Monitor, process, Pid, _Reason} -> ok
        end
    end.
