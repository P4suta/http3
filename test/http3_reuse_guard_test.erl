%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_reuse_guard_test).
-include_lib("eunit/include/eunit.hrl").

-define(OBSERVATION_MILLISECONDS, 8000).
-define(CLEANUP_MILLISECONDS, 500).

reuse_success_is_published_after_checker_down_test() ->
    Deadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    Observation = case http_client_ffi:call_http3_reuse_before(
        fun() -> {ok, self()} end, Deadline
    ) of
        {ok, {ok, Worker}} when is_pid(Worker) -> worker_state(Worker);
        _ -> unexpected_result
    end,
    ?assertEqual(worker_down, Observation).

reuse_checker_exception_is_a_redacted_service_failure_test() ->
    Deadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    Outcome = http_client_ffi:call_http3_reuse_before(
        fun() -> erlang:error(private_fixture_reason) end, Deadline
    ),
    ?assertEqual({error, 1}, Outcome).

expired_reuse_deadline_never_starts_a_checker_test() ->
    Observer = self(),
    Started = make_ref(),
    Deadline = erlang:monotonic_time(millisecond),
    Outcome = http_client_ffi:call_http3_reuse_before(
        fun() ->
            Observer ! {Started, checker_started},
            {ok, true}
        end,
        Deadline
    ),
    StartedState = receive
        {Started, checker_started} -> checker_started
    after 0 ->
        checker_not_started
    end,
    ?assertEqual({{error, 0}, checker_not_started}, {Outcome, StartedState}).

reuse_timeout_reaps_checker_without_caller_mailbox_residue_test() ->
    Observer = self(),
    Started = make_ref(),
    Returned = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Caller, CallerMonitor} = erlang:spawn_monitor(fun() ->
        Deadline = erlang:monotonic_time(millisecond) + 1000,
        Outcome = http_client_ffi:call_http3_reuse_before(
            fun() ->
                Observer ! {Started, self()},
                receive checker_stays_blocked -> {ok, unexpected} end
            end,
            Deadline
        ),
        QueueState = case process_info(self(), message_queue_len) of
            {message_queue_len, 0} -> queue_empty;
            {message_queue_len, _} -> queue_not_empty
        end,
        Observer ! {Returned, public_outcome(Outcome), QueueState}
    end),
    Observation = case await_started_until(Started, ObservationDeadline) of
        {started, Worker} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            case linked_supervisor(Worker) of
                {ok, Supervisor} ->
                    SupervisorMonitor = erlang:monitor(process, Supervisor),
                    ReturnedState = receive
                        {Returned, OutcomeState, QueueState} ->
                            {OutcomeState, QueueState}
                    after remaining(ObservationDeadline) ->
                        {caller_not_returned, queue_unknown}
                    end,
                    ImmediateCleanup = {
                        process_state(
                            Supervisor, supervisor_down, supervisor_alive
                        ),
                        worker_state(Worker)
                    },
                    CallerState = named_down_state_until(
                        Caller, CallerMonitor, caller_down, caller_not_down,
                        ObservationDeadline
                    ),
                    SupervisorState = named_down_state_until(
                        Supervisor, SupervisorMonitor,
                        supervisor_down, supervisor_not_down,
                        ObservationDeadline
                    ),
                    WorkerState = named_down_state_until(
                        Worker, WorkerMonitor, worker_down, worker_not_down,
                        ObservationDeadline
                    ),
                    {
                        ReturnedState, ImmediateCleanup, CallerState,
                        SupervisorState, WorkerState
                    };
                error ->
                    exit(Caller, kill),
                    exit(Worker, kill),
                    supervisor_not_linked
            end;
        checker_not_started ->
            exit(Caller, kill),
            _ = named_down_state_until(
                Caller, CallerMonitor, caller_down, caller_not_down,
                erlang:monotonic_time(millisecond) + ?CLEANUP_MILLISECONDS
            ),
            checker_not_started
    end,
    ?assertEqual(
        {
            {deadline, queue_empty}, {supervisor_down, worker_down},
            caller_down, supervisor_down, worker_down
        },
        Observation
    ).

reuse_caller_death_reaps_a_trapping_blocked_checker_test() ->
    Observer = self(),
    Started = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Caller, CallerMonitor} = erlang:spawn_monitor(fun() ->
        Deadline = erlang:monotonic_time(millisecond) + 5000,
        _ = http_client_ffi:call_http3_reuse_before(
            fun() ->
                process_flag(trap_exit, true),
                Observer ! {Started, self()},
                receive checker_stays_blocked -> {ok, unexpected} end
            end,
            Deadline
        )
    end),
    Observation = case await_started_until(Started, ObservationDeadline) of
        {started, Worker} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            case linked_supervisor(Worker) of
                {ok, Supervisor} ->
                    SupervisorMonitor = erlang:monitor(process, Supervisor),
                    exit(Caller, kill),
                    CallerState = named_down_state_until(
                        Caller, CallerMonitor, caller_down, caller_not_down,
                        ObservationDeadline
                    ),
                    SupervisorState = named_down_state_until(
                        Supervisor, SupervisorMonitor,
                        supervisor_down, supervisor_not_down,
                        ObservationDeadline
                    ),
                    ImmediateWorkerState = worker_state(Worker),
                    WorkerState = case named_down_state_until(
                        Worker, WorkerMonitor, worker_down, worker_not_down,
                        ObservationDeadline
                    ) of
                        worker_down -> worker_down;
                        worker_not_down ->
                            exit(Worker, kill),
                            _ = named_down_state_until(
                                Worker, WorkerMonitor,
                                worker_down, worker_not_down,
                                erlang:monotonic_time(millisecond)
                                    + ?CLEANUP_MILLISECONDS
                            ),
                            worker_not_down
                    end,
                    {
                        CallerState, SupervisorState, ImmediateWorkerState,
                        WorkerState
                    };
                error ->
                    exit(Caller, kill),
                    exit(Worker, kill),
                    supervisor_not_linked
            end;
        checker_not_started ->
            exit(Caller, kill),
            _ = named_down_state_until(
                Caller, CallerMonitor, caller_down, caller_not_down,
                erlang:monotonic_time(millisecond) + ?CLEANUP_MILLISECONDS
            ),
            checker_not_started
    end,
    ?assertEqual(
        {caller_down, supervisor_down, worker_down, worker_down}, Observation
    ).

reuse_supervisor_death_is_recovered_by_the_registered_caller_test() ->
    Observer = self(),
    Started = make_ref(),
    Returned = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Caller, CallerMonitor} = erlang:spawn_monitor(fun() ->
        Deadline = erlang:monotonic_time(millisecond) + 5000,
        Outcome = http_client_ffi:call_http3_reuse_before(
            fun() ->
                %% A propagated linked exit is intentionally survivable. The
                %% registered caller must issue its own untrappable kill.
                process_flag(trap_exit, true),
                Observer ! {Started, self()},
                receive checker_stays_blocked -> {ok, unexpected} end
            end,
            Deadline
        ),
        QueueState = case process_info(self(), message_queue_len) of
            {message_queue_len, 0} -> queue_empty;
            {message_queue_len, _} -> queue_not_empty
        end,
        Observer ! {Returned, public_outcome(Outcome), QueueState}
    end),
    Observation = case await_started_until(Started, ObservationDeadline) of
        {started, Worker} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            case linked_supervisor(Worker) of
                {ok, Supervisor} ->
                    SupervisorMonitor = erlang:monitor(process, Supervisor),
                    exit(Supervisor, kill),
                    ReturnedState = receive
                        {Returned, OutcomeState, QueueState} ->
                            {OutcomeState, QueueState}
                    after remaining(ObservationDeadline) ->
                        {caller_not_returned, queue_unknown}
                    end,
                    ImmediateCleanup = {
                        process_state(
                            Supervisor, supervisor_down, supervisor_alive
                        ),
                        worker_state(Worker)
                    },
                    CallerState = named_down_state_until(
                        Caller, CallerMonitor, caller_down, caller_not_down,
                        ObservationDeadline
                    ),
                    SupervisorState = named_down_state_until(
                        Supervisor, SupervisorMonitor,
                        supervisor_down, supervisor_not_down,
                        ObservationDeadline
                    ),
                    WorkerState = named_down_state_until(
                        Worker, WorkerMonitor, worker_down, worker_not_down,
                        ObservationDeadline
                    ),
                    {
                        ReturnedState, ImmediateCleanup, CallerState,
                        SupervisorState, WorkerState
                    };
                error ->
                    exit(Caller, kill),
                    exit(Worker, kill),
                    supervisor_not_linked
            end;
        checker_not_started ->
            exit(Caller, kill),
            _ = named_down_state_until(
                Caller, CallerMonitor, caller_down, caller_not_down,
                erlang:monotonic_time(millisecond) + ?CLEANUP_MILLISECONDS
            ),
            checker_not_started
    end,
    ?assertEqual(
        {
            {service, queue_empty}, {supervisor_down, worker_down},
            caller_down, supervisor_down, worker_down
        },
        Observation
    ).

public_outcome({error, 0}) -> deadline;
public_outcome({error, 1}) -> service;
public_outcome(_) -> unexpected_result.

worker_state(Worker) ->
    process_state(Worker, worker_down, worker_alive).

process_state(Process, Down, Alive) ->
    case erlang:is_process_alive(Process) of
        true -> Alive;
        false -> Down
    end.

linked_supervisor(Worker) ->
    case process_info(Worker, links) of
        {links, [Supervisor]} when is_pid(Supervisor) -> {ok, Supervisor};
        _ -> error
    end.

await_started_until(Started, Deadline) ->
    receive
        {Started, Worker} when is_pid(Worker) -> {started, Worker}
    after remaining(Deadline) ->
        checker_not_started
    end.

named_down_state_until(Process, Monitor, Down, TimedOut, Deadline) ->
    receive
        {'DOWN', Monitor, process, Process, _Reason} -> Down
    after remaining(Deadline) ->
        TimedOut
    end.

remaining(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).
