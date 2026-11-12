%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_body_cancel_test_ffi).
-export([callback_outcomes/0, timeout_joins_callback/0,
         timeout_cause_survives_pending_registry_confirmation/0,
         success_requires_registry_confirmation/0,
         normal_guardian_exit_waits_for_delegated_result/0,
         owner_death_joins_callback/0, concurrent_cancel_once/0,
         concurrent_cancel_preserves_cleanup_result/0,
         owner_death_publishes_cleanup_result/0,
         pending_and_completed_timeout_are_distinct/0,
         success_joins_guardian_and_worker/0,
         guardian_death_joins_trapping_callback/0,
         guardian_death_stabilizes_shared_result/0,
         guardian_death_during_release_observer_is_reaped/0,
         detached_observer_owner_death_is_reaped/0,
         prearmed_recovery_survives_pre_callback_primary_death/0,
         completion_and_owner_down_observe_release_once/0,
         await_release_joins_recovery_controller/0,
         orphaned_recovery_registration_is_removed_after_controller_down/0,
         recovery_registry_restart_is_fail_closed_and_private/0,
         scheduler_stall_keeps_the_original_deadline/0,
         expired_registration_never_starts_callback/0,
         release_observer_is_bounded_and_once/0]).

callback_outcomes() ->
    Success = http_body_ffi:run_cancel_callback(fun() -> nil end, 1000),
    Failed = http_body_ffi:run_cancel_callback(
        fun() -> error({credential, <<"must-not-appear">>}) end, 1000),
    Invalid = http_body_ffi:run_cancel_callback(fun() -> nil end, 0),
    Success =:= {ok, nil} andalso Failed =:= {error, 1}
        andalso Invalid =:= {error, 1}.

success_joins_guardian_and_worker() ->
    Root = self(), Tag = make_ref(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Owner = self(),
        Result = http_body_ffi:run_cancel_callback(fun() ->
            case process_info(self(), links) of
                {links, [Guardian]} ->
                    Owner ! {Tag, identities, self(), Guardian};
                _ ->
                    Owner ! {Tag, identities_unavailable}
            end,
            nil
        end, 1000),
        Observation = receive
                {Tag, identities, Worker, Guardian} ->
                    {result_class(Result),
                 stopped(Worker), stopped(Guardian), mailbox_empty()};
            {Tag, identities_unavailable} ->
                {identity_failed, worker_unknown,
                 guardian_unknown, mailbox_empty()}
        after 100 ->
            {identity_missing, worker_unknown,
             guardian_unknown, mailbox_empty()}
        end,
        Root ! {Tag, success_observation, Observation}
    end),
    Observation = receive
        {Tag, success_observation, Safe} -> Safe
    after 2000 -> missing
    end,
    CallerDown = down(CallerMonitor),
    stopped(Caller) =:= down andalso CallerDown andalso
        Observation =:= {success, down, down, queue_empty}.

timeout_joins_callback() ->
    Root = self(),
    Tag = make_ref(),
    Result = http_body_ffi:run_cancel_callback(fun() ->
        Root ! {Tag, self()},
        receive stop -> nil end
    end, 100),
    ChildStopped = receive {Tag, Child} -> not is_process_alive(Child)
                   after 1000 -> false end,
    Result =:= {error, 2} andalso ChildStopped.

owner_death_joins_callback() ->
    Root = self(),
    Tag = make_ref(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        http_body_ffi:run_cancel_callback(fun() ->
            {links, Links} = process_info(self(), links),
            Root ! {Tag, self(), Links},
            receive stop -> nil end
        end, 5000)
    end),
    receive
        {Tag, Child, [Guardian]} ->
            ChildMonitor = monitor(process, Child),
            GuardianMonitor = monitor(process, Guardian),
            exit(Caller, kill),
            CallerDown = down(CallerMonitor),
            ChildDown = down(ChildMonitor),
            GuardianDown = down(GuardianMonitor),
            CallerDown andalso ChildDown andalso GuardianDown
    after 1000 -> exit(Caller, kill), down(CallerMonitor), false
    end.

guardian_death_joins_trapping_callback() ->
    Root = self(), Tag = make_ref(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:run_cancel_callback(fun() ->
            _ = process_flag(trap_exit, true),
            case process_info(self(), links) of
                {links, [Guardian]} ->
                    Root ! {Tag, callback_started, self(), Guardian};
                _ ->
                    Root ! {Tag, callback_identity_failed}
            end,
            receive continue -> nil end
        end, 5000),
        Root ! {Tag, caller_result, result_class(Result), mailbox_empty()}
    end),
    case receive
        {Tag, callback_started, Worker, Guardian} ->
            WorkerMonitor = monitor(process, Worker),
            GuardianMonitor = monitor(process, Guardian),
            exit(Guardian, kill),
            Result = receive
                {Tag, caller_result, SafeResult, QueueState} ->
                    {SafeResult, QueueState}
            after 2000 -> missing
            end,
            WorkerDown = down(WorkerMonitor),
            GuardianDown = down(GuardianMonitor),
            CallerDown = down(CallerMonitor),
            {Result, WorkerDown, GuardianDown, CallerDown,
             stopped(Worker), stopped(Guardian), stopped(Caller)};
        {Tag, callback_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            identity_failed
    after 1000 ->
        exit(Caller, kill),
        down(CallerMonitor),
        start_missing
    end of
        {{service, queue_empty}, true, true, true,
         down, down, down} -> true;
        _ -> false
    end.

scheduler_stall_keeps_the_original_deadline() ->
    Root = self(), Tag = make_ref(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:run_cancel_callback(fun() ->
            _ = process_flag(trap_exit, true),
            case process_info(self(), links) of
                {links, [Guardian]} ->
                    Root ! {Tag, stalled_callback, self(), Guardian};
                _ ->
                    Root ! {Tag, stalled_identity_failed}
            end,
            receive continue -> nil end
        end, 100),
        Root ! {Tag, stalled_result, result_class(Result), mailbox_empty()}
    end),
    case receive
        {Tag, stalled_callback, Worker, Guardian} ->
            WorkerMonitor = monitor(process, Worker),
            GuardianMonitor = monitor(process, Guardian),
            Suspended = suspend(Guardian),
            Result = receive
                {Tag, stalled_result, SafeResult, QueueState} ->
                    {SafeResult, QueueState}
            after 1500 -> missing
            end,
            WorkerDown = down(WorkerMonitor),
            GuardianDown = down(GuardianMonitor),
            CallerDown = down(CallerMonitor),
            {Suspended, Result, WorkerDown, GuardianDown, CallerDown,
             stopped(Worker), stopped(Guardian), stopped(Caller)};
        {Tag, stalled_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            identity_failed
    after 1000 ->
        exit(Caller, kill),
        down(CallerMonitor),
        start_missing
    end of
        {true, {timeout, queue_empty}, true, true, true,
         down, down, down} -> true;
        _ -> false
    end.

-spec stop_process_trace(pid()) -> ok.
stop_process_trace(Pid) ->
    try erlang:trace(Pid, false, [all]) of
        _ -> ok
    catch error:badarg ->
        case is_process_alive(Pid) of
            false -> ok;
            true -> erlang:error(trace_disable_failed)
        end
    end.

expired_registration_never_starts_callback() ->
    Root = self(), Tag = make_ref(),
    Started = atomics:new(1, []),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        _ = process_flag(priority, low),
        receive begin_cancel -> ok end,
        Result = http_body_ffi:run_cancel_callback(fun() ->
            atomics:add(Started, 1, 1),
            receive never -> nil end
        end, 100),
        Root ! {Tag, expired_result, result_class(Result), mailbox_empty()}
    end),
    TraceEnabled = erlang:trace(
        Caller, true, [procs, set_on_spawn, {tracer, Root}]
    ) =:= 1,
    Caller ! begin_cancel,
    Guardian = receive
        {trace, Caller, spawn, SpawnedGuardian, _Mfa} -> SpawnedGuardian
    after 500 -> missing
    end,
    case is_pid(Guardian) of
        false ->
            _ = stop_process_trace(Caller),
            exit(Caller, kill),
            down(CallerMonitor),
            drain_process_trace(Caller, missing, missing),
            false;
        true ->
            Suspended = suspend(Caller),
            Worker = receive
                {trace, Guardian, spawn, SpawnedWorker, _WorkerMfa} ->
                    SpawnedWorker
            after 500 -> missing
            end,
            GuardianMonitor = monitor(process, Guardian),
            WorkerMonitor = case is_pid(Worker) of
                true -> monitor(process, Worker);
                false -> missing
            end,
            GuardianDown = down(GuardianMonitor),
            WorkerDown = case WorkerMonitor of
                missing -> false;
                _ -> down(WorkerMonitor)
            end,
            _ = resume(Caller),
            Result = receive
                {Tag, expired_result, SafeResult, QueueState} ->
                    {SafeResult, QueueState}
            after 1000 -> missing
            end,
            CallerDown = down(CallerMonitor),
            _ = stop_process_trace(Caller),
            drain_process_trace(Caller, Guardian, Worker),
            TraceEnabled andalso Suspended
                andalso GuardianDown andalso WorkerDown andalso CallerDown
                andalso atomics:get(Started, 1) =:= 0
                andalso Result =:= {timeout, queue_empty}
                andalso stopped(Caller) =:= down
                andalso stopped(Guardian) =:= down
                andalso stopped(Worker) =:= down
    end.

drain_process_trace(Caller, Guardian, Worker) ->
    receive
        {trace, Caller, _Event, _Detail} ->
            drain_process_trace(Caller, Guardian, Worker);
        {trace, Guardian, _Event, _Detail} ->
            drain_process_trace(Caller, Guardian, Worker);
        {trace, Worker, _Event, _Detail} ->
            drain_process_trace(Caller, Guardian, Worker);
        {trace, Caller, _Event, _Detail, _Extra} ->
            drain_process_trace(Caller, Guardian, Worker);
        {trace, Guardian, _Event, _Detail, _Extra} ->
            drain_process_trace(Caller, Guardian, Worker);
        {trace, Worker, _Event, _Detail, _Extra} ->
            drain_process_trace(Caller, Guardian, Worker)
    after 0 ->
        ok
    end.

concurrent_cancel_once() ->
    Counter = atomics:new(1, []),
    {ok, Body} = http@body:from_pull(
        http@body:pull(fun(_) -> {ok, {pull_end, []}} end),
        none, none, fun() -> atomics:add(Counter, 1, 1), nil end),
    Monitors = [begin
        {_, Monitor} = spawn_monitor(fun() -> http@body:cancel(Body) end),
        Monitor
    end || _ <- lists:seq(1, 250)],
    Joined = lists:all(fun down/1, Monitors),
    Joined andalso atomics:get(Counter, 1) =:= 1.

down(Monitor) ->
    receive {'DOWN', Monitor, process, _, _} -> true
    after 1500 -> demonitor(Monitor, [flush]), false
    end.

down_within(Monitor, Timeout) ->
    receive {'DOWN', Monitor, process, _, _} -> true
    after Timeout -> demonitor(Monitor, [flush]), false
    end.

timeout_cause_survives_pending_registry_confirmation() ->
    pending_registry_confirmation(timeout).

success_requires_registry_confirmation() ->
    pending_registry_confirmation(success).

normal_guardian_exit_waits_for_delegated_result() ->
    Root = self(), Tag = make_ref(),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:cancel_once(
            Handle, {some, fun() -> nil end},
            {some, fun(_) ->
                {links, [Guardian]} = process_info(self(), links),
                Recovery = guardian_recovery(Guardian, self()),
                Root ! {Tag, observer, Guardian, Recovery},
                receive never -> nil end
            end}, 100),
        Root ! {Tag, result, Result}
    end),
    {Guardian, Recovery} = receive
        {Tag, observer, G, R} when is_pid(G), is_pid(R) -> {G, R}
    after 1000 -> error(observer_start_timeout)
    end,
    GuardianMonitor = monitor(process, Guardian),
    RecoveryMonitor = monitor(process, Recovery),
    Registry = whereis(http_body_cancel_recovery_registry),
    true = erlang:suspend_process(Caller),
    true = erlang:suspend_process(Registry),
    Checks = try
        GuardianDown = down_within(GuardianMonitor, 1000),
        RecoveryDown = down_within(RecoveryMonitor, 1000),
        true = erlang:resume_process(Caller),
        Premature = receive {Tag, result, Early} -> {returned, Early}
            after 50 -> pending end,
        true = erlang:resume_process(Registry),
        Result = case Premature of
            {returned, EarlyResult} -> EarlyResult;
            pending -> receive {Tag, result, Final} -> Final
                after 1000 -> missing end
        end,
        {GuardianDown, RecoveryDown, Premature, raw_result_class(Result),
         down(CallerMonitor), release_class(http_body_ffi:await_release(Handle, 1000))}
    after
        resume(Caller),
        resume(Registry),
        exit(Caller, kill),
        demonitor(CallerMonitor, [flush]),
        demonitor(GuardianMonitor, [flush]),
        demonitor(RecoveryMonitor, [flush])
    end,
    case Checks of
        {true, true, pending, success, true, success} -> true;
        _ -> io:format("delegated_result_checks=~p~n", [Checks]), false
    end.

pending_registry_confirmation(Kind) ->
    Root = self(), Tag = make_ref(),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:cancel_once(Handle, {some, fun() ->
            Root ! {Tag, callback_started, self()},
            receive complete -> nil end
        end}, none, 500),
        Root ! {Tag, result, Result}
    end),
    Worker = receive {Tag, callback_started, Pid} -> Pid
        after 1000 -> error(callback_start_timeout) end,
    Registry = whereis(http_body_cancel_recovery_registry),
    true = erlang:suspend_process(Registry),
    {Result, Pending} = try
        case Kind of success -> Worker ! complete; timeout -> ok end,
        Outcome = receive {Tag, result, Value} -> Value
            after 2500 -> missing end,
        {Outcome, http_body_ffi:await_release(Handle, 0)}
    after
        true = erlang:resume_process(Registry)
    end,
    Joined = down(CallerMonitor),
    Released = http_body_ffi:await_release(Handle, 1000),
    exit(Caller, kill),
    Checks = {raw_result_class(Result), Pending, Released, Joined},
    Expected = case Kind of
        timeout -> {timeout, none, {some, {error, 2}}, true};
        success -> {service, none, {some, {ok, nil}}, true}
    end,
    case Checks of
        Expected -> true;
        _ -> io:format("pending_registry_checks=~p~n", [Checks]), false
    end.

concurrent_cancel_preserves_cleanup_result() ->
    Root = self(), Tag = make_ref(),
    {ok, Body} = http@body:from_pull(
        http@body:pull(fun(_) -> {ok, {pull_end, []}} end), none, none,
        fun() -> Root ! {Tag, entered}, receive finish -> nil end end),
    {_, FirstMonitor} = spawn_monitor(fun() ->
        Root ! {Tag, first, http@body:cancel_within(Body, 100)}
    end),
    Entered = receive {Tag, entered} -> true after 1000 -> false end,
    Second = http@body:cancel_within(Body, 1000),
    First = receive {Tag, first, Result} -> Result after 1500 -> missing end,
    Joined = down(FirstMonitor),
    %% Only a stable typed classification crosses the assertion boundary.
    Checks = {Entered, Joined, cancellation_class(First), cancellation_class(Second)},
    case Checks of
        {true, true, timeout, timeout} -> true;
        _ -> io:format("concurrent_cancel_checks=~p~n", [Checks]), false
    end.

cancellation_class({error, Failure}) ->
    case http@error:kind(Failure) of
        {timeout, operation} -> timeout;
        service -> service;
        cancelled -> cancelled;
        _ -> other_failure
    end;
cancellation_class({ok, nil}) -> success;
cancellation_class(_) -> missing.

is_timeout({error, Failure}) ->
    http@error:kind(Failure) =:= {timeout, operation};
is_timeout(_) -> false.

owner_death_publishes_cleanup_result() ->
    Root = self(), Tag = make_ref(),
    Counter = atomics:new(1, []),
    {ok, Source} = http@body:from_pull(
        http@body:pull(fun(_) -> {ok, {pull_end, []}} end), none, none,
        fun() ->
            atomics:add(Counter, 1, 1),
            Root ! {Tag, entered, self()},
            receive finish -> nil end
        end),
    Body = http@body:observe_release(Source, fun(Result) ->
        Root ! {Tag, released, is_cancelled(Result)}, nil
    end),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        http@body:cancel_within(Body, 5000)
    end),
    receive
        {Tag, entered, Callback} ->
            CallbackMonitor = monitor(process, Callback),
            exit(Caller, kill),
            CallerDown = down(CallerMonitor),
            CallbackDown = down(CallbackMonitor),
            Released = receive {Tag, released, SafeOutcome} -> SafeOutcome
                       after 1000 -> false end,
            Repeated = http@body:cancel_within(Body, 100),
            Duplicate = receive {Tag, released, _} -> true after 0 -> false end,
            io:format(
                "owner_death caller_down=~p callback_down=~p "
                "released=~p repeated_cancelled=~p repeated_timeout=~p "
                "exactly_once=~p~n",
                [CallerDown, CallbackDown, Released, is_cancelled(Repeated),
                 is_timeout(Repeated), atomics:get(Counter, 1) =:= 1]),
            CallerDown andalso CallbackDown andalso Released
                andalso is_cancelled(Repeated) andalso not Duplicate
                andalso atomics:get(Counter, 1) =:= 1
    after 1000 -> exit(Caller, kill), down(CallerMonitor), false
    end.

guardian_death_stabilizes_shared_result() ->
    Root = self(), Tag = make_ref(),
    Released = atomics:new(1, []),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                _ = process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {Tag, shared_callback, self(), Guardian};
                    _ ->
                        Root ! {Tag, shared_identity_failed}
                end,
                receive continue -> nil end
            end},
            {some, fun(Outcome) ->
                atomics:add(Released, 1, 1),
                Root ! {Tag, shared_released, raw_result_class(Outcome)},
                nil
            end},
            5000
        ),
        Root ! {Tag, shared_result, raw_result_class(Result), mailbox_empty()}
    end),
    case receive
        {Tag, shared_callback, Worker, Guardian} ->
            WorkerMonitor = monitor(process, Worker),
            GuardianMonitor = monitor(process, Guardian),
            exit(Guardian, kill),
            ReleasedResult = receive
                {Tag, shared_released, SafeReleased} -> SafeReleased
            after 1500 -> missing
            end,
            FirstResult = receive
                {Tag, shared_result, SafeResult, QueueState} ->
                    {SafeResult, QueueState}
            after 1500 -> missing
            end,
            WorkerDown = down(WorkerMonitor),
            GuardianDown = down(GuardianMonitor),
            CallerDown = down(CallerMonitor),
            Repeated = http_body_ffi:cancel_once(
                Handle, none, none, 100
            ),
            Duplicate = receive
                {Tag, shared_released, _} -> duplicate
            after 0 -> once
            end,
            {ReleasedResult, FirstResult, raw_result_class(Repeated),
             atomics:get(Released, 1), Duplicate,
             WorkerDown, GuardianDown, CallerDown,
             stopped(Worker), stopped(Guardian), stopped(Caller)};
        {Tag, shared_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            identity_failed
    after 1000 ->
        exit(Caller, kill),
        down(CallerMonitor),
        start_missing
    end of
        {service, {service, queue_empty}, service, 1, once,
         true, true, true, down, down, down} -> true;
        _ -> false
    end.

guardian_death_during_release_observer_is_reaped() ->
    Root = self(), Tag = make_ref(),
    Released = atomics:new(1, []),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        _ = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                _ = process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {Tag, original_callback, self(), Guardian};
                    _ ->
                        Root ! {Tag, original_identity_failed}
                end,
                receive continue -> nil end
            end},
            {some, fun(_Outcome) ->
                atomics:add(Released, 1, 1),
                _ = process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {Tag, release_observer, self(), Guardian};
                    _ ->
                        Root ! {Tag, observer_identity_failed}
                end,
                receive finish -> nil end
            end},
            500
        )
    end),
    receive
        {Tag, original_callback, CallbackWorker, OriginalGuardian} ->
            CallbackMonitor = monitor(process, CallbackWorker),
            OriginalGuardianMonitor = monitor(process, OriginalGuardian),
            exit(Caller, kill),
            CallerDown = down(CallerMonitor),
            CallbackDown = down(CallbackMonitor),
            receive
                {Tag, release_observer, ObserverWorker, ObserverGuardian} ->
                    ObserverOwner = observer_owner(
                        ObserverGuardian, ObserverWorker
                    ),
                    ObserverWorkerMonitor = monitor(process, ObserverWorker),
                    ObserverGuardianMonitor = monitor(
                        process, ObserverGuardian
                    ),
                    ObserverOwnerMonitor = case is_pid(ObserverOwner) of
                        true -> monitor(process, ObserverOwner);
                        false -> missing
                    end,
                    exit(OriginalGuardian, kill),
                    ObserverWorker ! finish,
                    OriginalGuardianDown = down(OriginalGuardianMonitor),
                    ObserverWorkerDown = down(ObserverWorkerMonitor),
                    ObserverGuardianDown = down(ObserverGuardianMonitor),
                    ObserverOwnerDown = case ObserverOwnerMonitor of
                        missing -> false;
                        _ -> down(ObserverOwnerMonitor)
                    end,
                    Repeated = http_body_ffi:cancel_once(
                        Handle, none, none, 500
                    ),
                    Duplicate = receive
                        {Tag, release_observer, _Worker, _Guardian} -> duplicate
                    after 0 -> once
                    end,
                    CallerDown andalso CallbackDown
                        andalso OriginalGuardianDown
                        andalso ObserverWorkerDown
                        andalso ObserverGuardianDown
                        andalso ObserverOwnerDown
                        andalso stopped(Caller) =:= down
                        andalso stopped(CallbackWorker) =:= down
                        andalso stopped(OriginalGuardian) =:= down
                        andalso stopped(ObserverWorker) =:= down
                        andalso stopped(ObserverGuardian) =:= down
                        andalso stopped(ObserverOwner) =:= down
                        andalso atomics:get(Released, 1) =:= 1
                        andalso raw_result_class(Repeated) =:= service
                        andalso Duplicate =:= once;
                {Tag, observer_identity_failed} ->
                    exit(OriginalGuardian, kill),
                    down(OriginalGuardianMonitor),
                    false
            after 1500 ->
                exit(OriginalGuardian, kill),
                down(OriginalGuardianMonitor),
                false
            end;
        {Tag, original_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            false
    after 1000 ->
        exit(Caller, kill),
        down(CallerMonitor),
        false
    end.

prearmed_recovery_survives_pre_callback_primary_death() ->
    Root = self(), Tag = make_ref(),
    RegistryReady = raw_result_class(http_body_ffi:cancel_once(
        http_body_ffi:new_cancel_handle(),
        {some, fun() -> nil end},
        none,
        1000
    )) =:= success,
    Started = atomics:new(1, []),
    Released = atomics:new(1, []),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        receive begin_cancel -> ok end,
        Result = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                atomics:add(Started, 1, 1),
                receive never -> nil end
            end},
            {some, fun(Outcome) ->
                atomics:add(Released, 1, 1),
                Root ! {Tag, prearmed_released, raw_result_class(Outcome)},
                nil
            end},
            1000
        ),
        Root ! {Tag, prearmed_result, raw_result_class(Result)}
    end),
    TraceEnabled = erlang:trace(
        Caller, true, [procs, set_on_spawn, {tracer, Root}]
    ) =:= 1,
    Caller ! begin_cancel,
    Guardian = receive
        {trace, Caller, spawn, SpawnedGuardian, _Mfa} -> SpawnedGuardian
    after 500 -> missing
    end,
    case is_pid(Guardian) of
        false ->
            exit(Caller, kill),
            down(CallerMonitor),
            false;
        true ->
            Suspended = suspend(Caller),
            Children = traced_children(Guardian, 2, 1000, []),
            case Children of
                [Recovery, Worker] ->
                    GuardianMonitor = monitor(process, Guardian),
                    RecoveryMonitor = monitor(process, Recovery),
                    WorkerMonitor = monitor(process, Worker),
                    exit(Caller, kill),
                    exit(Guardian, kill),
                    CallerDown = down(CallerMonitor),
                    GuardianDown = down_within(GuardianMonitor, 3000),
                    WorkerDown = down_within(WorkerMonitor, 3000),
                    RecoveryDown = down_within(RecoveryMonitor, 3000),
                    ReleasedClass = receive
                        {Tag, prearmed_released, SafeClass} -> SafeClass
                    after 3000 -> missing
                    end,
                    Repeated = http_body_ffi:cancel_once(
                        Handle, none, none, 100
                    ),
                    UnexpectedResult = receive
                        {Tag, prearmed_result, _} -> true
                    after 0 -> false
                    end,
                    _ = stop_process_trace(Caller),
                    drain_process_trace(Caller, Guardian, Worker),
                    RegistryReady andalso TraceEnabled andalso Suspended
                        andalso CallerDown andalso GuardianDown
                        andalso WorkerDown andalso RecoveryDown
                        andalso stopped(Caller) =:= down
                        andalso stopped(Guardian) =:= down
                        andalso stopped(Worker) =:= down
                        andalso stopped(Recovery) =:= down
                        andalso atomics:get(Started, 1) =:= 0
                        andalso atomics:get(Released, 1) =:= 1
                        andalso ReleasedClass =:= service
                        andalso raw_result_class(Repeated) =:= service
                        andalso not UnexpectedResult;
                _ ->
                    _ = resume(Caller),
                    exit(Caller, kill),
                    down(CallerMonitor),
                    _ = stop_process_trace(Caller),
                    drain_process_trace(Caller, Guardian, missing),
                    false
            end
    end.

completion_and_owner_down_observe_release_once() ->
    Root = self(), Tag = make_ref(),
    Released = atomics:new(1, []),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Owner = self(),
        _ = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {Tag, completion_race, self(), Guardian};
                    _ ->
                        Root ! {Tag, completion_race_identity_failed}
                end,
                receive {Tag, continue_completion_race} -> ok end,
                exit(Owner, kill),
                nil
            end},
            {some, fun(Outcome) ->
                atomics:add(Released, 1, 1),
                Root ! {
                    Tag, completion_race_released,
                    raw_result_class(Outcome)
                },
                nil
            end},
            1000
        )
    end),
    case receive
        {Tag, completion_race, Worker, Guardian} ->
            Recovery = guardian_recovery(Guardian, Worker),
            WorkerMonitor = monitor(process, Worker),
            GuardianMonitor = monitor(process, Guardian),
            RecoveryMonitor = case is_pid(Recovery) of
                true -> monitor(process, Recovery);
                false -> missing
            end,
            Worker ! {Tag, continue_completion_race},
            CallerDown = down_within(CallerMonitor, 3000),
            WorkerDown = down_within(WorkerMonitor, 3000),
            GuardianDown = down_within(GuardianMonitor, 3000),
            RecoveryDown = case RecoveryMonitor of
                missing -> false;
                _ -> down_within(RecoveryMonitor, 3000)
            end,
            ReleasedClass = receive
                {Tag, completion_race_released, SafeClass} -> SafeClass
            after 3000 -> missing
            end,
            Repeated = raw_result_class(http_body_ffi:cancel_once(
                Handle, none, none, 100
            )),
            Duplicate = receive
                {Tag, completion_race_released, _} -> duplicate
            after 0 -> once
            end,
            {CallerDown, WorkerDown, GuardianDown, RecoveryDown,
             ReleasedClass, Repeated, atomics:get(Released, 1), Duplicate,
             stopped(Worker), stopped(Guardian), stopped(Recovery)};
        {Tag, completion_race_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            identity_failed
    after 1500 ->
        exit(Caller, kill),
        down(CallerMonitor),
        missing
    end of
        {true, true, true, true, Class, Class, 1, once,
         down, down, down}
                when Class =:= success; Class =:= cancelled -> true;
        _ -> false
    end.

await_release_joins_recovery_controller() ->
    Root = self(), Tag = make_ref(),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:cancel_once(
            Handle,
            {some, fun() -> nil end},
            {some, fun(_Outcome) ->
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Recovery = guardian_recovery(Guardian, self()),
                        Root ! {
                            Tag, release_barrier_entered,
                            self(), Guardian, Recovery
                        };
                    _ ->
                        Root ! {Tag, release_barrier_identity_failed}
                end,
                receive finish -> nil end
            end},
            5000
        ),
        Root ! {
            Tag, release_barrier_cancelled,
            raw_result_class(Result), mailbox_empty()
        }
    end),
    case receive
        {Tag, release_barrier_entered, Worker, Guardian, Recovery}
                when is_pid(Recovery) ->
            WorkerMonitor = monitor(process, Worker),
            GuardianMonitor = monitor(process, Guardian),
            RecoveryMonitor = monitor(process, Recovery),
            Suspended = suspend(Recovery),
            {Waiter, WaiterMonitor} = spawn_monitor(fun() ->
                Observed = http_body_ffi:await_release(Handle, 100),
                Root ! {Tag, release_barrier_waiter, release_class(Observed)}
            end),
            Worker ! finish,
            WorkerDown = down_within(WorkerMonitor, 1000),
            Pending = receive
                {Tag, release_barrier_waiter, pending} -> true;
                {Tag, release_barrier_waiter, _Premature} -> false
            after 1000 -> false
            end,
            WaiterDown = down_within(WaiterMonitor, 1000),
            _ = resume(Recovery),
            Cancelled = receive
                {Tag, release_barrier_cancelled, SafeResult, QueueState} ->
                    {SafeResult, QueueState}
            after 3000 -> missing
            end,
            GuardianDown = down_within(GuardianMonitor, 3000),
            RecoveryDown = down_within(RecoveryMonitor, 3000),
            CallerDown = down_within(CallerMonitor, 3000),
            Released = release_class(http_body_ffi:await_release(Handle, 1000)),
            {Suspended, WorkerDown, Pending, WaiterDown,
             Cancelled, GuardianDown, RecoveryDown, CallerDown, Released,
             stopped(Waiter), stopped(Worker), stopped(Guardian),
             stopped(Recovery), stopped(Caller)};
        {Tag, release_barrier_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            identity_failed
    after 1500 ->
        exit(Caller, kill),
        down(CallerMonitor),
        missing
    end of
        {true, true, true, true, {success, queue_empty},
         true, true, true, success,
         down, down, down, down, down} -> true;
        _ -> false
    end.

orphaned_recovery_registration_is_removed_after_controller_down() ->
    Root = self(), Tag = make_ref(),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        _ = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                _ = process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {
                            Tag, orphan_callback, self(), Guardian
                        };
                    _ ->
                        Root ! {Tag, orphan_identity_failed}
                end,
                receive never -> nil end
            end},
            none,
            5000
        )
    end),
    receive
        {Tag, orphan_callback, Worker, Guardian} ->
            Recovery = guardian_recovery(Guardian, Worker),
            Registry = whereis(http_body_cancel_recovery_registry),
            case is_pid(Recovery) andalso is_pid(Registry) of
                true ->
                    WorkerMonitor = monitor(process, Worker),
                    GuardianMonitor = monitor(process, Guardian),
                    RecoveryMonitor = monitor(process, Recovery),
                    ActiveCount = registry_monitor_count(Registry),
                    TrackedBefore = registry_tracks_all(
                        Registry, [Guardian, Recovery]
                    ),
                    Registry ! {
                        'DOWN', make_ref(), process, Recovery, forged
                    },
                    Synced = registry_sync(Registry, 1000),
                    ForgedDownRejected = registry_tracks_all(
                        Registry, [Guardian, Recovery]
                    ),
                    PublicLedgerRejected = public_recovery_ledger_rejects_write(
                        Handle, Recovery
                    ),
                    exit(Caller, kill),
                    CallerDown = down_within(CallerMonitor, 3000),
                    WorkerDown = down_within(WorkerMonitor, 3000),
                    GuardianDown = down_within(GuardianMonitor, 3000),
                    RecoveryDown = down_within(RecoveryMonitor, 3000),
                    RegistryConverged = await_registry_absent(
                        Registry, [Guardian, Recovery], 3000
                    ),
                    FinalCount = registry_monitor_count(Registry),
                    Released = release_class(
                        http_body_ffi:await_release(Handle, 1000)
                    ),
                    ActiveCountValid = is_integer(ActiveCount)
                        andalso ActiveCount >= 2,
                    CountConverged = ActiveCountValid
                        andalso is_integer(FinalCount)
                        andalso FinalCount =< ActiveCount - 2,
                    TrackedBefore andalso Synced
                        andalso ForgedDownRejected
                        andalso PublicLedgerRejected
                        andalso CallerDown andalso WorkerDown
                        andalso GuardianDown andalso RecoveryDown
                        andalso RegistryConverged andalso CountConverged
                        andalso Released =:= cancelled
                        andalso stopped(Caller) =:= down
                        andalso stopped(Worker) =:= down
                        andalso stopped(Guardian) =:= down
                        andalso stopped(Recovery) =:= down;
                false ->
                    exit(Caller, kill),
                    down(CallerMonitor),
                    false
            end;
        {Tag, orphan_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            false
    after 1500 ->
        exit(Caller, kill),
        down(CallerMonitor),
        false
    end.

recovery_registry_restart_is_fail_closed_and_private() ->
    Root = self(), Tag = make_ref(),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {
                            Tag, registry_restart_callback, self(), Guardian
                        };
                    _ ->
                        Root ! {Tag, registry_restart_identity_failed}
                end,
                receive finish -> nil end
            end},
            none,
            5000
        ),
        Root ! {Tag, registry_restart_result, raw_result_class(Result)}
    end),
    receive
        {Tag, registry_restart_callback, Worker, Guardian} ->
            Recovery = guardian_recovery(Guardian, Worker),
            Registry = whereis(http_body_cancel_recovery_registry),
            case is_pid(Recovery) andalso is_pid(Registry) of
                true ->
                    RegistryMonitor = monitor(process, Registry),
                    WorkerMonitor = monitor(process, Worker),
                    GuardianMonitor = monitor(process, Guardian),
                    RecoveryMonitor = monitor(process, Recovery),
                    exit(Registry, kill),
                    RegistryDown = down_within(RegistryMonitor, 3000),
                    Worker ! finish,
                    WorkerDown = down_within(WorkerMonitor, 3000),
                    GuardianDown = down_within(GuardianMonitor, 3000),
                    RecoveryDown = down_within(RecoveryMonitor, 3000),
                    CallerDown = down_within(CallerMonitor, 3000),
                    CallerResult = receive
                        {Tag, registry_restart_result, SafeClass} -> SafeClass
                    after 3000 -> missing
                    end,
                    OldRelease = release_class(
                        http_body_ffi:await_release(Handle, 50)
                    ),
                    OldBarrier = recovery_barrier_word_class(Handle),
                    NewHandle = http_body_ffi:new_cancel_handle(),
                    NewResult = raw_result_class(http_body_ffi:cancel_once(
                        NewHandle, {some, fun() -> nil end}, none, 1000
                    )),
                    NewRegistry = whereis(
                        http_body_cancel_recovery_registry
                    ),
                    NewRelease = release_class(
                        http_body_ffi:await_release(NewHandle, 1000)
                    ),
                    PublicLedgerRejected = public_recovery_ledger_rejects_write(
                        Handle, Recovery
                    ),
                    RegistryDown andalso WorkerDown
                        andalso GuardianDown andalso RecoveryDown
                        andalso CallerDown
                        andalso CallerResult =:= service
                        andalso OldRelease =:= pending
                        andalso OldBarrier =:= active
                        andalso NewResult =:= success
                        andalso NewRelease =:= success
                        andalso is_pid(NewRegistry)
                        andalso NewRegistry =/= Registry
                        andalso PublicLedgerRejected
                        andalso stopped(Caller) =:= down
                        andalso stopped(Worker) =:= down
                        andalso stopped(Guardian) =:= down
                        andalso stopped(Recovery) =:= down;
                false ->
                    exit(Caller, kill),
                    down(CallerMonitor),
                    false
            end;
        {Tag, registry_restart_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            false
    after 1500 ->
        exit(Caller, kill),
        down(CallerMonitor),
        false
    end.

registry_monitor_count(Registry) ->
    case process_info(Registry, monitors) of
        {monitors, Monitors} when is_list(Monitors) -> length(Monitors);
        _ -> missing
    end.

registry_tracks_all(Registry, Controllers) ->
    case process_info(Registry, monitors) of
        {monitors, Monitors} when is_list(Monitors) ->
            lists:all(fun(Controller) ->
                lists:member({process, Controller}, Monitors)
            end, Controllers);
        _ ->
            false
    end.

await_registry_absent(Registry, Controllers, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    await_registry_absent_until(Registry, Controllers, Deadline).

await_registry_absent_until(Registry, Controllers, Deadline) ->
    case registry_tracks_any(Registry, Controllers) of
        false ->
            true;
        true ->
            Remaining = erlang:max(
                0, Deadline - erlang:monotonic_time(millisecond)
            ),
            case Remaining of
                0 -> false;
                _ ->
                    receive
                    after erlang:min(1, Remaining) ->
                        await_registry_absent_until(
                            Registry, Controllers, Deadline
                        )
                    end
            end
    end.

registry_tracks_any(Registry, Controllers) ->
    case process_info(Registry, monitors) of
        {monitors, Monitors} when is_list(Monitors) ->
            lists:any(fun(Controller) ->
                lists:member({process, Controller}, Monitors)
            end, Controllers);
        _ ->
            false
    end.

registry_sync(Registry, Timeout) ->
    ReplyAlias = erlang:alias(), Reference = make_ref(),
    Registry ! {
        cancel_recovery_registry, identity, ReplyAlias, Reference
    },
    Result = receive
        {Reference, cancel_recovery_registry_identity, Registry, Generation}
                when is_integer(Generation), Generation > 0 -> true
    after Timeout -> false
    end,
    _ = erlang:unalias(ReplyAlias),
    Result.

public_recovery_ledger_rejects_write(Handle, Recovery) ->
    Missing = ets:whereis(http_body_cancel_recovery_ledger) =:= undefined,
    Rejected = try ets:insert(
        http_body_cancel_recovery_ledger, {Handle, Recovery}
    ) of
        _ -> false
    catch
        error:badarg -> true;
        _:_ -> false
    end,
    Missing andalso Rejected.

recovery_barrier_word_class(Handle) ->
    try atomics:get(Handle, 3) of
        0 -> fresh;
        Value when is_integer(Value), Value > 0,
                   (Value band 1) =:= 0 -> clear;
        Value when is_integer(Value), Value > 1 -> active;
        _ -> invalid
    catch
        _:_ -> invalid
    end.

traced_children(_Parent, 0, _Timeout, Children) ->
    lists:reverse(Children);
traced_children(Parent, Count, Timeout, Children) ->
    receive
        {trace, Parent, spawn, Child, _Mfa} ->
            traced_children(Parent, Count - 1, Timeout, [Child | Children])
    after Timeout ->
        lists:reverse(Children)
    end.

guardian_recovery(Guardian, Excluded) ->
    case process_info(Guardian, links) of
        {links, Links} ->
            Candidates = [Process || Process <- Links,
                                      Process =/= Excluded,
                                      is_pid(Process)],
            case Candidates of
                [Recovery] -> Recovery;
                _ -> missing
            end;
        _ ->
            missing
    end.

release_class(none) -> pending;
release_class({some, Result}) -> raw_result_class(Result);
release_class(_) -> invalid.

detached_observer_owner_death_is_reaped() ->
    Root = self(), Tag = make_ref(),
    Released = atomics:new(1, []),
    Handle = http_body_ffi:new_cancel_handle(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        _ = http_body_ffi:cancel_once(
            Handle,
            {some, fun() ->
                _ = process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {Tag, owner_test_callback, self(), Guardian};
                    _ ->
                        Root ! {Tag, owner_test_identity_failed}
                end,
                receive continue -> nil end
            end},
            {some, fun(_Outcome) ->
                atomics:add(Released, 1, 1),
                _ = process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Guardian]} ->
                        Root ! {Tag, owner_test_observer, self(), Guardian};
                    _ ->
                        Root ! {Tag, owner_test_observer_identity_failed}
                end,
                receive finish -> nil end
            end},
            500
        )
    end),
    receive
        {Tag, owner_test_callback, CallbackWorker, OriginalGuardian} ->
            CallbackMonitor = monitor(process, CallbackWorker),
            OriginalGuardianMonitor = monitor(process, OriginalGuardian),
            exit(Caller, kill),
            CallerDown = down(CallerMonitor),
            CallbackDown = down(CallbackMonitor),
            receive
                {Tag, owner_test_observer, ObserverWorker, ObserverGuardian} ->
                    ObserverOwner = observer_owner(
                        ObserverGuardian, ObserverWorker
                    ),
                    ObserverWorkerMonitor = monitor(process, ObserverWorker),
                    ObserverGuardianMonitor = monitor(
                        process, ObserverGuardian
                    ),
                    ObserverOwnerMonitor = case is_pid(ObserverOwner) of
                        true -> monitor(process, ObserverOwner);
                        false -> missing
                    end,
                    exit(ObserverOwner, kill),
                    ObserverOwnerDown = case ObserverOwnerMonitor of
                        missing -> false;
                        _ -> down(ObserverOwnerMonitor)
                    end,
                    ObserverWorkerDown = down(ObserverWorkerMonitor),
                    ObserverGuardianDown = down(ObserverGuardianMonitor),
                    OriginalGuardianDown = down(OriginalGuardianMonitor),
                    Repeated = http_body_ffi:cancel_once(
                        Handle, none, none, 500
                    ),
                    Duplicate = receive
                        {Tag, owner_test_observer, _Worker, _Guardian} -> duplicate
                    after 0 -> once
                    end,
                    CallerDown andalso CallbackDown
                        andalso ObserverOwnerDown
                        andalso ObserverWorkerDown
                        andalso ObserverGuardianDown
                        andalso OriginalGuardianDown
                        andalso stopped(Caller) =:= down
                        andalso stopped(CallbackWorker) =:= down
                        andalso stopped(ObserverOwner) =:= down
                        andalso stopped(ObserverWorker) =:= down
                        andalso stopped(ObserverGuardian) =:= down
                        andalso stopped(OriginalGuardian) =:= down
                        andalso atomics:get(Released, 1) =:= 1
                        andalso raw_result_class(Repeated) =:= service
                        andalso Duplicate =:= once;
                {Tag, owner_test_observer_identity_failed} ->
                    exit(OriginalGuardian, kill),
                    down(OriginalGuardianMonitor),
                    false
            after 1500 ->
                exit(OriginalGuardian, kill),
                down(OriginalGuardianMonitor),
                false
            end;
        {Tag, owner_test_identity_failed} ->
            exit(Caller, kill),
            down(CallerMonitor),
            false
    after 1000 ->
        exit(Caller, kill),
        down(CallerMonitor),
        false
    end.

observer_owner(ObserverGuardian, ObserverWorker) ->
    case process_info(ObserverGuardian, monitors) of
        {monitors, Monitors} ->
            Candidates = [Process || {process, Process} <- Monitors,
                                      Process =/= ObserverWorker],
            case Candidates of
                [Owner] -> Owner;
                _ -> missing
            end;
        _ ->
            missing
    end.

release_observer_is_bounded_and_once() ->
    Root = self(), Tag = make_ref(),
    Released = atomics:new(1, []),
    Handle = http_body_ffi:new_cancel_handle(),
    Result = http_body_ffi:cancel_once(
        Handle,
        {some, fun() -> nil end},
        {some, fun(_Outcome) ->
            atomics:add(Released, 1, 1),
            _ = process_flag(trap_exit, true),
            case process_info(self(), links) of
                {links, [Guardian]} ->
                    Root ! {Tag, observer_started, self(), Guardian};
                _ ->
                    Root ! {Tag, observer_identity_failed}
            end,
            receive continue -> nil end
        end},
        100
    ),
    Observation = receive
        {Tag, observer_started, Worker, Guardian} ->
            {raw_result_class(Result),
             stopped(Worker), stopped(Guardian)};
        {Tag, observer_identity_failed} -> identity_failed
    after 0 -> missing
    end,
    Repeated = http_body_ffi:cancel_once(Handle, none, none, 100),
    Duplicate = receive
        {Tag, observer_started, _Worker, _Guardian} -> duplicate
    after 0 -> once
    end,
    Checks = {Observation, raw_result_class(Repeated), atomics:get(Released, 1), Duplicate},
    case Checks of
        {{success, down, down}, success, 1, once} -> true;
        _ -> io:format("release_observer_checks=~p~n", [Checks]), false
    end.

is_cancelled({error, Failure}) -> http@error:kind(Failure) =:= cancelled;
is_cancelled(_) -> false.

result_class({ok, nil}) -> success;
result_class({error, 1}) -> service;
result_class({error, 2}) -> timeout;
result_class(_) -> invalid.

raw_result_class({ok, nil}) -> success;
raw_result_class({error, 1}) -> service;
raw_result_class({error, 2}) -> timeout;
raw_result_class({error, 3}) -> cancelled;
raw_result_class(_) -> invalid.

stopped(Process) when is_pid(Process) ->
    case {is_process_alive(Process), process_info(Process)} of
        {false, undefined} -> down;
        _ -> running
    end;
stopped(_) -> unknown.

suspend(Process) ->
    try erlang:suspend_process(Process) of
        true -> true;
        _ -> false
    catch
        _:_ -> false
    end.

resume(Process) ->
    try erlang:resume_process(Process) of
        _ -> ok
    catch
        _:_ -> ok
    end.

mailbox_empty() ->
    case process_info(self(), message_queue_len) of
        {message_queue_len, 0} -> queue_empty;
        _ -> queue_not_empty
    end.

pending_and_completed_timeout_are_distinct() ->
    Root = self(), Tag = make_ref(),
    {ok, Body} = http@body:from_pull(
        http@body:pull(fun(_) -> {ok, {pull_end, []}} end), none, none,
        fun() -> Root ! {Tag, entered, self()}, receive finish -> nil end end),
    Unstarted = http@body:await_release(Body, 0) =:= release_pending,
    {Caller, Monitor} = spawn_monitor(fun() -> http@body:cancel_within(Body, 5000) end),
    Pending = receive {Tag, entered, Worker} ->
        Observed = http@body:await_release(Body, 10) =:= release_pending,
        Worker ! finish,
        Observed
    after 1000 -> exit(Caller, kill), false end,
    Joined = down(Monitor),
    Success = http@body:await_release(Body, 0) =:= {released, {ok, nil}},
    {ok, Stalled} = http@body:from_pull(
        http@body:pull(fun(_) -> {ok, {pull_end, []}} end), none, none,
        fun() -> receive never -> nil end end),
    TimedOut = is_timeout(http@body:cancel_within(Stalled, 50)),
    CompletedTimeout = case http@body:await_release(Stalled, 0) of
        {released, Result} -> is_timeout(Result);
        _ -> false
    end,
    Unstarted andalso Pending andalso Joined andalso Success
        andalso TimedOut andalso CompletedTimeout.
