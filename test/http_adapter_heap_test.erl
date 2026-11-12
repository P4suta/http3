%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_adapter_heap_test).
-include_lib("eunit/include/eunit.hrl").

-define(OBSERVATION_MILLISECONDS, 2000).
-define(CLEANUP_MILLISECONDS, 500).

bounded_adapter_counts_retained_reference_binaries_test() ->
    Outcome = without_global_binary_accounting(fun() ->
        http_server_ffi:call_bounded_adapter(fun retained_binary/0, 1000, 131072)
    end),
    ?assertEqual({error, bounded_adapter_failed}, Outcome).

bounded_adapter_counts_reference_binaries_captured_by_gated_worker_test() ->
    Captured = binary:copy(<<"s">>, 2097152),
    Outcome = without_global_binary_accounting(fun() ->
        http_server_ffi:call_bounded_adapter(
            fun() -> {ok, byte_size(Captured)} end,
            1000,
            131072
        )
    end),
    ?assertEqual({error, bounded_adapter_failed}, Outcome).

traced_adapter_counts_retained_reference_binaries_test() ->
    {Outcome, Began, QueueTime, ExecutionTime, TimedOut} =
        without_global_binary_accounting(fun() ->
            http_server_ffi:call_bounded_adapter_traced(fun retained_binary/0, 1000, 131072)
        end),
    ?assertEqual({error, bounded_adapter_failed}, Outcome),
    ?assertEqual(true, Began),
    ?assertEqual(false, TimedOut),
    ?assert(QueueTime >= 0 andalso ExecutionTime >= 0).

traced_adapter_counts_reference_binaries_captured_by_gated_worker_test() ->
    Captured = binary:copy(<<"s">>, 2097152),
    {Outcome, _Began, _QueueTime, _ExecutionTime, _TimedOut} =
        without_global_binary_accounting(fun() ->
            http_server_ffi:call_bounded_adapter_traced(
                fun() -> {ok, byte_size(Captured)} end,
                1000,
                131072
            )
        end),
    ?assertEqual({error, bounded_adapter_failed}, Outcome).

bounded_adapter_supervisor_enforces_the_worker_heap_contract_test() ->
    Outcome = http_server_ffi:call_bounded_adapter(
        fun() ->
            case process_info(self(), links) of
                {links, [Supervisor | _]} when is_pid(Supervisor) ->
                    {ok, bounded_heap_contract(Supervisor, 131072)};
                _ ->
                    {ok, false}
            end
        end,
        1000,
        131072
    ),
    ?assertEqual({ok, {ok, true}}, Outcome).

bounded_adapter_accepts_a_binary_inside_its_budget_test() ->
    Outcome = http_server_ffi:call_bounded_adapter(fun() -> retain(65536) end, 1000, 131072),
    ?assertEqual({ok, {ok, 65536}}, Outcome).

bounded_adapter_success_joins_its_worker_before_return_test() ->
    Observation = case http_server_ffi:call_bounded_adapter(
        fun() -> {ok, self()} end, 1000, 131072
    ) of
        {ok, {ok, Worker}} -> worker_state(Worker);
        _ -> unexpected_result
    end,
    ?assertEqual(worker_down, Observation).

bounded_adapter_installs_caller_monitor_before_callback_starts_test() ->
    Caller = self(),
    Outcome = http_server_ffi:call_bounded_adapter(
        fun() ->
            MonitorInstalled = case process_info(Caller, monitors) of
                {monitors, Monitors} ->
                    lists:member({process, self()}, Monitors);
                _ -> false
            end,
            {ok, MonitorInstalled}
        end,
        1000,
        131072
    ),
    ?assertEqual({ok, {ok, true}}, Outcome).

bounded_adapter_pre_registration_supervisor_exit_reaps_both_test() ->
    Observation = pre_registration_supervisor_exit_observation(),
    ?assertEqual(
        {adapter_failed, worker_down, supervisor_down, owner_down,
         callback_not_started},
        Observation
    ).

traced_adapter_success_joins_its_worker_before_return_test() ->
    Observation = case http_server_ffi:call_bounded_adapter_traced(
            fun() -> {ok, self()} end, 1000, 131072
        ) of
        {{ok, {ok, Worker}}, true, _Queue, _Callback, false} ->
            worker_state(Worker);
        _ -> unexpected_result
    end,
    ?assertEqual(worker_down, Observation).

bounded_adapter_success_joins_worker_and_supervisor_before_return_test() ->
    Observation = case http_server_ffi:call_bounded_adapter(
            fun() ->
                case process_info(self(), links) of
                    {links, [Supervisor | _]} when is_pid(Supervisor) ->
                        {ok, {self(), Supervisor}};
                    _ ->
                        {error, no_supervisor}
                end
            end,
            1000,
            131072
        ) of
        {ok, {ok, {Worker, Supervisor}}} ->
            {worker_state(Worker), worker_state(Supervisor)};
        _ -> unexpected_result
    end,
    ?assertEqual({worker_down, worker_down}, Observation).

bounded_adapter_owner_exit_reaps_callback_test() ->
    Observation = owner_exit_observation(fun(Run) ->
        http_server_ffi:call_bounded_adapter(Run, 60000, 131072)
    end),
    ?assertEqual({owner_down, worker_down}, Observation).

traced_adapter_owner_exit_reaps_callback_test() ->
    Observation = owner_exit_observation(fun(Run) ->
        http_server_ffi:call_bounded_adapter_traced(Run, 60000, 131072)
    end),
    ?assertEqual({owner_down, worker_down}, Observation).

bounded_adapter_supervisor_exit_reaps_callback_test() ->
    Observation = supervisor_exit_observation(fun(Run) ->
        http_server_ffi:call_bounded_adapter(Run, 60000, 131072)
    end),
    ?assertEqual({adapter_failed, owner_down, worker_down}, Observation).

traced_adapter_supervisor_exit_reaps_callback_test() ->
    Observation = supervisor_exit_observation(fun(Run) ->
        http_server_ffi:call_bounded_adapter_traced(Run, 60000, 131072)
    end),
    ?assertEqual({adapter_failed, owner_down, worker_down}, Observation).

bounded_adapter_timeout_confirms_worker_exit_before_return_test() ->
    Parent = self(),
    Started = make_ref(),
    ?assertEqual(
        {error, bounded_adapter_timed_out},
        http_server_ffi:call_bounded_adapter(
            fun() ->
                Parent ! {Started, self()},
                receive stop_never_arrives -> {ok, unexpected} end
            end,
            1000,
            131072
        )
    ),
    Observation = case await_started_callback(Started) of
        {started, Worker} -> worker_state(Worker);
        callback_not_started -> callback_not_started
    end,
    ?assertEqual(worker_down, Observation).

traced_adapter_timeout_confirms_worker_exit_before_return_test() ->
    Parent = self(),
    Started = make_ref(),
    {{error, bounded_adapter_timed_out}, true, _Queue, _Callback, true} =
        http_server_ffi:call_bounded_adapter_traced(
            fun() ->
                Parent ! {Started, self()},
                receive stop_never_arrives -> {ok, unexpected} end
            end,
            1000,
            131072
        ),
    Observation = case await_started_callback(Started) of
        {started, Worker} -> worker_state(Worker);
        callback_not_started -> callback_not_started
    end,
    ?assertEqual(worker_down, Observation).

bounded_adapter_timeout_leaves_no_protocol_messages_test() ->
    Observer = self(),
    Finished = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Owner, OwnerMonitor} = erlang:spawn_monitor(fun() ->
        Result = http_server_ffi:call_bounded_adapter(
            fun() ->
                receive callback_stays_blocked -> {ok, unexpected} end
            end,
            100,
            131072
        ),
        {message_queue_len, QueueLength} = process_info(
            self(), message_queue_len
        ),
        Observer ! {
            Finished,
            adapter_result_class(Result),
            case QueueLength of 0 -> mailbox_empty; _ -> mailbox_not_empty end
        }
    end),
    ResultState = receive
        {Finished, Classification, MailboxState} ->
            {Classification, MailboxState}
    after ?OBSERVATION_MILLISECONDS ->
        result_not_observed
    end,
    OwnerState = named_down_state_until(
        Owner, OwnerMonitor, owner_down, owner_not_down, ObservationDeadline
    ),
    ?assertEqual(
        {{adapter_timed_out, mailbox_empty}, owner_down},
        {ResultState, OwnerState}
    ).

retained_binary() -> retain(2097152).

without_global_binary_accounting(Run) ->
    %% Ordinary embedding VMs do not enable referenced-binary accounting.
    %% Qualification's stronger global setting must not hide a library gap.
    Previous = erlang:system_info(max_heap_size),
    erlang:system_flag(max_heap_size, Previous#{include_shared_binaries => false}),
    try Run() after erlang:system_flag(max_heap_size, Previous) end.

retain(Bytes) ->
    %% The dictionary keeps the reference live through an explicit GC; only
    %% its scalar size can reach the assertion or the adapter's result.
    put(adapter_heap_fixture, binary:copy(<<"x">>, Bytes)),
    erlang:garbage_collect(),
    {ok, byte_size(erase(adapter_heap_fixture))}.

worker_state(Worker) ->
    case erlang:is_process_alive(Worker) of
        true -> worker_alive;
        false -> worker_down
    end.

bounded_heap_contract(Process, MaximumHeapWords) ->
    case process_info(Process, max_heap_size) of
        {max_heap_size, Options} when is_map(Options) ->
            maps:get(size, Options, 0) =:= MaximumHeapWords
                andalso maps:get(kill, Options, false) =:= true
                andalso maps:get(error_logger, Options, true) =:= false
                andalso maps:get(
                    include_shared_binaries, Options, false
                ) =:= true;
        _ -> false
    end.

owner_exit_observation(Call) ->
    Observer = self(),
    Started = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Owner, OwnerMonitor} = erlang:spawn_monitor(fun() ->
        _ = Call(fun() ->
            %% Owner shutdown must remain authoritative even if a callback
            %% elects to trap ordinary linked-exit signals.
            process_flag(trap_exit, true),
            Observer ! {Started, self()},
            receive callback_stays_blocked -> {ok, unexpected} end
        end)
    end),
    case await_started_callback_until(Started, ObservationDeadline) of
        {started, Worker} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            exit(Owner, kill),
            OwnerState = named_down_state_until(
                Owner, OwnerMonitor, owner_down, owner_not_down,
                ObservationDeadline
            ),
            WorkerState = case named_down_state_until(
                Worker, WorkerMonitor, worker_down, worker_not_down,
                ObservationDeadline
            ) of
                worker_down -> worker_down;
                worker_not_down ->
                    %% A deliberately broken implementation must not leak its
                    %% fixture after the scalar failure has been observed.
                    exit(Worker, kill),
                    _ = named_down_state_until(
                        Worker, WorkerMonitor, worker_down, worker_not_down,
                        erlang:monotonic_time(millisecond)
                            + ?CLEANUP_MILLISECONDS
                    ),
                    worker_not_down
            end,
            {OwnerState, WorkerState};
        callback_not_started ->
            exit(Owner, kill),
            _ = named_down_state_until(
                Owner, OwnerMonitor, owner_down, owner_not_down,
                erlang:monotonic_time(millisecond)
                    + ?CLEANUP_MILLISECONDS
            ),
            callback_not_started
    end.

supervisor_exit_observation(Call) ->
    Observer = self(),
    Started = make_ref(),
    Finished = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Owner, OwnerMonitor} = erlang:spawn_monitor(fun() ->
        Result = Call(fun() ->
            %% This makes a link-only cleanup deliberately ineffective. The
            %% caller's independent monitor must still kill and join us when
            %% the supervisor disappears.
            process_flag(trap_exit, true),
            case process_info(self(), links) of
                {links, [Supervisor | _]} when is_pid(Supervisor) ->
                    Observer ! {Started, self(), Supervisor};
                _ ->
                    Observer ! {Started, self(), no_supervisor}
            end,
            receive callback_stays_blocked -> {ok, unexpected} end
        end),
        Observer ! {Finished, adapter_result_class(Result)}
    end),
    case await_supervised_callback_until(Started, ObservationDeadline) of
        {started, Worker, Supervisor} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            exit(Supervisor, kill),
            ResultState = await_adapter_result_until(
                Finished, ObservationDeadline
            ),
            OwnerState = named_down_state_until(
                Owner, OwnerMonitor, owner_down, owner_not_down,
                ObservationDeadline
            ),
            WorkerState = case named_down_state_until(
                Worker, WorkerMonitor, worker_down, worker_not_down,
                ObservationDeadline
            ) of
                worker_down -> worker_down;
                worker_not_down ->
                    exit(Worker, kill),
                    _ = named_down_state_until(
                        Worker, WorkerMonitor, worker_down, worker_not_down,
                        erlang:monotonic_time(millisecond)
                            + ?CLEANUP_MILLISECONDS
                    ),
                    worker_not_down
            end,
            {ResultState, OwnerState, WorkerState};
        callback_not_started ->
            exit(Owner, kill),
            _ = named_down_state_until(
                Owner, OwnerMonitor, owner_down, owner_not_down,
                erlang:monotonic_time(millisecond)
                    + ?CLEANUP_MILLISECONDS
            ),
            callback_not_started
    end.

pre_registration_supervisor_exit_observation() ->
    Observer = self(),
    Finished = make_ref(),
    CallbackStarted = make_ref(),
    ObservationDeadline = erlang:monotonic_time(millisecond)
        + ?OBSERVATION_MILLISECONDS,
    {Owner, OwnerMonitor} = erlang:spawn_monitor(fun() ->
        Result = http_server_ffi:call_bounded_adapter_registration_probe(
            fun() ->
                Observer ! {CallbackStarted, callback_started},
                {ok, unexpected}
            end,
            60000,
            131072,
            Observer
        ),
        Observer ! {Finished, adapter_result_class(Result)}
    end),
    receive
        {bounded_adapter_pre_registration, _ProbeReference,
         Supervisor, Worker}
                when is_pid(Supervisor), is_pid(Worker) ->
            SupervisorMonitor = erlang:monitor(process, Supervisor),
            WorkerMonitor = erlang:monitor(process, Worker),
            exit(Supervisor, kill),
            ResultState = await_adapter_result_until(
                Finished, ObservationDeadline
            ),
            WorkerState = named_down_state_until(
                Worker, WorkerMonitor, worker_down, worker_not_down,
                ObservationDeadline
            ),
            SupervisorState = named_down_state_until(
                Supervisor, SupervisorMonitor,
                supervisor_down, supervisor_not_down,
                ObservationDeadline
            ),
            OwnerState = named_down_state_until(
                Owner, OwnerMonitor, owner_down, owner_not_down,
                ObservationDeadline
            ),
            CallbackState = receive
                {CallbackStarted, callback_started} -> callback_started
            after 0 ->
                callback_not_started
            end,
            {ResultState, WorkerState, SupervisorState, OwnerState,
             CallbackState}
    after ?OBSERVATION_MILLISECONDS ->
        exit(Owner, kill),
        _ = named_down_state_until(
            Owner, OwnerMonitor, owner_down, owner_not_down,
            erlang:monotonic_time(millisecond) + ?CLEANUP_MILLISECONDS
        ),
        pre_registration_not_observed
    end.

adapter_result_class({error, bounded_adapter_failed}) -> adapter_failed;
adapter_result_class({error, bounded_adapter_timed_out}) -> adapter_timed_out;
adapter_result_class({{error, bounded_adapter_failed}, _, _, _, _}) ->
    adapter_failed;
adapter_result_class(_) -> unexpected_result.

await_supervised_callback_until(Started, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {Started, Worker, Supervisor}
                when is_pid(Worker), is_pid(Supervisor) ->
            {started, Worker, Supervisor};
        {Started, _Worker, no_supervisor} ->
            callback_not_started
    after Remaining ->
        callback_not_started
    end.

await_adapter_result_until(Finished, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {Finished, ResultState} -> ResultState
    after Remaining ->
        result_not_observed
    end.

await_started_callback(Started) ->
    await_started_callback_until(
        Started,
        erlang:monotonic_time(millisecond) + ?OBSERVATION_MILLISECONDS
    ).

await_started_callback_until(Started, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {Started, Worker} when is_pid(Worker) -> {started, Worker}
    after Remaining ->
        callback_not_started
    end.

named_down_state_until(Process, Monitor, Down, TimedOut, Deadline) ->
    Remaining = erlang:max(
        0, Deadline - erlang:monotonic_time(millisecond)
    ),
    receive
        {'DOWN', Monitor, process, Process, _Reason} -> Down
    after Remaining ->
        TimedOut
    end.
