%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_body_ffi).

-define(MAX_TIMEOUT_MILLISECONDS, 2147482647).
-define(CALLBACK_JOIN_MILLISECONDS, 500).
-define(RELEASE_OBSERVER_MAX_MILLISECONDS, 1000).
-define(CALLBACK_MAX_HEAP_WORDS, 8388608).
-define(CONTROLLER_MAX_HEAP_WORDS, 1048576).
-define(REGISTRY_MAX_HEAP_WORDS, 8388608).
-define(RECOVERY_REGISTRY, http_body_cancel_recovery_registry).

-type cancel_callback() :: fun(() -> term()) |
    {infallible_cleanup, fun(() -> term())} |
    {fallible_cleanup, fun(() -> {ok, nil} | {error, 1 | 2 | 3})}.

-export([
    file_size/1,
    cancel_once/4,
    is_cancelled/1,
    mark_cancelled/1,
    await_release/2,
    new_cancel_handle/0,
    new_cleanup_result/0,
    complete_cleanup_result/2,
    read_cleanup_result/1,
    read_file_chunk/3,
    run_cancel_callback/2
]).

%% One actor-free terminal result outlives a protocol coordinator without
%% retaining its process, callback, payload, or native failure term.
-spec new_cleanup_result() -> atomics:atomics_ref().
new_cleanup_result() -> atomics:new(1, [{signed, false}]).

-spec complete_cleanup_result(
    atomics:atomics_ref(), {ok, nil} | {error, 1 | 2 | 3}
) -> nil.
complete_cleanup_result(Cell, {ok, nil}) ->
    _ = atomics:compare_exchange(Cell, 1, 0, 1),
    nil;
complete_cleanup_result(Cell, {error, Code})
        when is_integer(Code), Code >= 1, Code =< 3 ->
    _ = atomics:compare_exchange(Cell, 1, 0, Code + 1),
    nil.

-spec read_cleanup_result(atomics:atomics_ref()) ->
    none | {some, {ok, nil} | {error, 1 | 2 | 3}}.
read_cleanup_result(Cell) ->
    case atomics:get(Cell, 1) of
        0 -> none;
        1 -> {some, {ok, nil}};
        Code when Code >= 2, Code =< 4 -> {some, {error, Code - 1}}
    end.

-spec new_cancel_handle() -> atomics:atomics_ref().
new_cancel_handle() ->
    %% Word one is the public cancellation state. Word two is an internal
    %% once-claim for the release observer: zero is pending, one is running,
    %% two is joined, and three is terminal with an unconfirmed join. Recovery
    %% after a guardian exit therefore cannot invoke application observation
    %% twice. In word one, zero is unclaimed, one is the simple mark_cancelled
    %% claim, two through five are stable public outcomes, and values from six
    %% upward identify exactly one live cancel_once attempt without retaining
    %% its PID or callback data. Word three encodes the generation of the
    %% private recovery registry: odd means registered controllers remain and
    %% the following even value means that registry observed all of their DOWN
    %% signals. Zero means this handle never needed a recovery controller.
    atomics:new(3, [{signed, false}]).

%% A private registry acknowledges both controllers before the recovery owner
%% can claim cancellation. There is therefore no claimed-but-unowned interval
%% if the API caller or primary guardian exits. The recovery owner publishes the
%% stable outcome only after joining callback and observer work; the registry
%% exposes release only after observing both controllers DOWN.
-spec cancel_once(atomics:atomics_ref(), none | {some, cancel_callback()},
                  none | {some, fun((term()) -> term())}, integer()) ->
    {ok, nil} | {error, 1 | 2 | 3}.
cancel_once(Handle, none, none, Timeout)
        when is_integer(Timeout), Timeout > 0,
             Timeout =< ?MAX_TIMEOUT_MILLISECONDS ->
    Started = monotonic_millisecond(),
    Deadline = Started + Timeout,
    case cancel_recovery_generation(Handle) of
        clear ->
            try atomics:compare_exchange(Handle, 1, 0, 2) of
                ok ->
                    case await_cancel_recovery_barrier(
                        Handle, Deadline
                    ) of
                        confirmed -> {ok, nil};
                        unconfirmed -> {error, 1}
                    end;
                _ ->
                    await_cancel_until(Handle, Deadline)
            catch
                _:_ -> {error, 1}
            end;
        {active, _Generation} ->
            await_cancel_until(Handle, Deadline);
        invalid ->
            {error, 1}
    end;
cancel_once(Handle, Callback, Released, Timeout)
        when is_integer(Timeout), Timeout > 0,
             Timeout =< ?MAX_TIMEOUT_MILLISECONDS ->
    Started = monotonic_millisecond(),
    case cancellation_callbacks(Callback, Released) of
        {ok, Run, Observer} ->
            Deadlines = cancel_deadlines(Started, Timeout, Observer),
            run_cancel_once(Handle, Run, Observer, Deadlines);
        error ->
            {error, 1}
    end;
cancel_once(_, _, _, _) -> {error, 1}.

%% The guardian owns the callback worker and watches the cancelling caller.
%% Neither an exception nor a stalled cleanup callback can escape into a
%% connection actor. Success is reported only after the worker has exited.
-spec run_cancel_callback(fun(() -> term()), pos_integer()) ->
    {ok, nil} | {error, 1 | 2}.
run_cancel_callback(Callback, Timeout)
        when is_function(Callback, 0), is_integer(Timeout),
             Timeout > 0, Timeout =< ?MAX_TIMEOUT_MILLISECONDS ->
    Started = monotonic_millisecond(),
    Deadline = Started + Timeout,
    CleanupDeadline = Deadline + ?CALLBACK_JOIN_MILLISECONDS,
    run_cancel_callback_before(Callback, Deadline, CleanupDeadline);
run_cancel_callback(_, _) -> {error, 1}.

-spec cancellation_callbacks(
    none | {some, cancel_callback()},
    none | {some, fun((term()) -> term())}
) -> {ok, fun(() -> term()), none | {some, fun((term()) -> term())}} | error.
cancellation_callbacks(none, none) ->
    {ok, fun() -> nil end, none};
cancellation_callbacks(none, {some, Observer})
        when is_function(Observer, 1) ->
    {ok, fun() -> nil end, {some, Observer}};
cancellation_callbacks({some, {infallible_cleanup, Callback}}, Observer)
        when is_function(Callback, 0) ->
    cancellation_callbacks({some, Callback}, Observer);
cancellation_callbacks({some, {fallible_cleanup, Callback}}, Observer)
        when is_function(Callback, 0) ->
    cancellation_callbacks({some, fun() ->
        {http_body_cleanup_result, Callback()}
    end}, Observer);
cancellation_callbacks({some, Callback}, none)
        when is_function(Callback, 0) ->
    {ok, Callback, none};
cancellation_callbacks({some, Callback}, {some, Observer})
        when is_function(Callback, 0), is_function(Observer, 1) ->
    {ok, Callback, {some, Observer}};
cancellation_callbacks(_, _) ->
    error.

%% Every deadline in a cancellation attempt is derived from the API entry
%% timestamp. A delayed callback, observer, or monitor receipt therefore
%% consumes the existing budget instead of receiving a fresh duration.
-spec cancel_deadlines(
    integer(), pos_integer(), none | {some, fun((term()) -> term())}
) -> map().
cancel_deadlines(Started, Timeout, Observer) ->
    CallbackDeadline = Started + Timeout,
    CallbackCleanupDeadline =
        CallbackDeadline + ?CALLBACK_JOIN_MILLISECONDS,
    {ObserverDeadline, ObserverCleanupDeadline, CompletionDeadline} =
        case Observer of
            none ->
                {CallbackCleanupDeadline, CallbackCleanupDeadline,
                 CallbackCleanupDeadline};
            {some, _} ->
                ObserverBudget = erlang:min(
                    Timeout, ?RELEASE_OBSERVER_MAX_MILLISECONDS
                ),
                ObserverLimit = CallbackCleanupDeadline + ObserverBudget,
                ObserverCleanup =
                    ObserverLimit + ?CALLBACK_JOIN_MILLISECONDS,
                {ObserverLimit, ObserverCleanup, ObserverCleanup}
        end,
    #{
        request_deadline => CallbackDeadline,
        callback_deadline => CallbackDeadline,
        callback_cleanup_deadline => CallbackCleanupDeadline,
        observer_deadline => ObserverDeadline,
        observer_cleanup_deadline => ObserverCleanupDeadline,
        observer_owner_recovery_deadline =>
            ObserverCleanupDeadline + (?CALLBACK_JOIN_MILLISECONDS div 2),
        completion_deadline => CompletionDeadline,
        termination_deadline =>
            CompletionDeadline + ?CALLBACK_JOIN_MILLISECONDS
    }.

-spec run_cancel_once(
    atomics:atomics_ref(), fun(() -> term()),
    none | {some, fun((term()) -> term())}, map()
) -> {ok, nil} | {error, 1 | 2 | 3}.
run_cancel_once(Handle, Callback, Observer, Deadlines) ->
    case safe_alias() of
        error ->
            {error, 1};
        {ok, Alias} ->
            run_cancel_once_with_alias(
                Handle, Callback, Observer, Deadlines, Alias
            )
    end.

-spec run_cancel_once_with_alias(
    atomics:atomics_ref(), fun(() -> term()),
    none | {some, fun((term()) -> term())}, map(), reference()
) -> {ok, nil} | {error, 1 | 2 | 3}.
run_cancel_once_with_alias(Handle, Callback, Observer, Deadlines, Alias) ->
    Caller = self(),
    Tag = make_ref(),
    ClaimToken = erlang:unique_integer([positive]) + 5,
    Spawned = safe_spawn(fun() ->
        cancel_once_guardian(
            Caller, Alias, Tag, Handle, ClaimToken,
            Callback, Observer, Deadlines
        )
    end, cancel_controller_spawn_options(false)),
    Outcome = case Spawned of
        {ok, Guardian, GuardianMonitor} ->
            try
                await_cancel_guardian(
                    Tag,
                    Guardian,
                    GuardianMonitor,
                    maps:get(completion_deadline, Deadlines),
                    maps:get(request_deadline, Deadlines),
                    maps:get(termination_deadline, Deadlines)
                )
            after
                _ = safe_unalias(Alias)
            end;
        error ->
            _ = safe_unalias(Alias),
            spawn_failed
    end,
    drain_cancel_protocol(Tag),
    case Outcome of
        spawn_failed -> {error, 1};
        {completed, Result} ->
            case await_cancel_recovery_barrier(
                Handle, maps:get(termination_deadline, Deadlines)
            ) of
                confirmed -> Result;
                unconfirmed ->
                    case Result of
                        {error, _} -> Result;
                        {ok, nil} -> {error, 1}
                    end
            end;
        already_claimed ->
            await_cancel_until(
                Handle, maps:get(request_deadline, Deadlines)
            );
        {already_claimed_timeout, _Confirmation} ->
            await_cancel_until(
                Handle, maps:get(request_deadline, Deadlines)
            );
        {timed_out, confirmed} ->
            recover_cancel_once(
                Handle, ClaimToken, Observer, {error, 2},
                Deadlines, confirmed
            );
        {timed_out, unconfirmed} ->
            recover_cancel_once(
                Handle, ClaimToken, Observer, {error, 1},
                Deadlines, unconfirmed
            );
        {failed, Confirmation} ->
            recover_cancel_once(
                Handle, ClaimToken, Observer, {error, 1},
                Deadlines, Confirmation
            )
    end.

-spec run_cancel_callback_before(fun(() -> term()), integer(), integer()) ->
    {ok, nil} | {error, 1 | 2}.
run_cancel_callback_before(Callback, Deadline, CleanupDeadline) ->
    cancel_guardian_outcome_result(
        run_cancel_callback_before_outcome(
            Callback, Deadline, CleanupDeadline
        )
    ).

-spec run_cancel_callback_before_outcome(
    fun(() -> term()), integer(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    already_claimed |
    {already_claimed_timeout, confirmed | unconfirmed} |
    {timed_out, confirmed | unconfirmed} |
    {failed, confirmed | unconfirmed}.
run_cancel_callback_before_outcome(Callback, Deadline, CleanupDeadline) ->
    case safe_alias() of
        error ->
            {failed, confirmed};
        {ok, Alias} ->
            Caller = self(),
            Tag = make_ref(),
            Spawned = safe_spawn(fun() ->
                plain_cancel_guardian(
                    Caller, Alias, Tag, Callback, Deadline, CleanupDeadline
                )
            end, cancel_controller_spawn_options(false)),
            Outcome = case Spawned of
                {ok, Guardian, GuardianMonitor} ->
                    try
                        await_cancel_guardian(
                            Tag,
                            Guardian,
                            GuardianMonitor,
                            Deadline,
                            Deadline,
                            CleanupDeadline
                        )
                    after
                        _ = safe_unalias(Alias)
                    end;
                error ->
                    _ = safe_unalias(Alias),
                    {failed, confirmed}
            end,
            drain_cancel_protocol(Tag),
            Outcome
    end.

-spec cancel_guardian_outcome_result(
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    already_claimed |
    {already_claimed_timeout, confirmed | unconfirmed} |
    {timed_out, confirmed | unconfirmed} |
    {failed, confirmed | unconfirmed}
) -> {ok, nil} | {error, 1 | 2 | 3}.
cancel_guardian_outcome_result({completed, Result}) -> Result;
cancel_guardian_outcome_result({timed_out, confirmed}) -> {error, 2};
cancel_guardian_outcome_result({timed_out, unconfirmed}) -> {error, 1};
cancel_guardian_outcome_result({failed, _Confirmation}) -> {error, 1};
cancel_guardian_outcome_result(
    {already_claimed_timeout, _Confirmation}
) -> {error, 1};
cancel_guardian_outcome_result(already_claimed) -> {error, 1}.

-spec plain_cancel_guardian(
    pid(), reference(), reference(), fun(() -> term()), integer(), integer()
) -> ok.
plain_cancel_guardian(
    Owner, ReplyAlias, Tag, Callback, Deadline, CleanupDeadline
) ->
    ok = proc_lib:set_label(<<"http.body_guardian">>),
    _ = process_flag(trap_exit, true),
    case safe_monitor(Owner, []) of
        error ->
            ReplyAlias ! {Tag, {cancel_result, {error, 1}}};
        {ok, OwnerMonitor} ->
            Phase = run_cancel_callback_phase(
                Owner,
                OwnerMonitor,
                ReplyAlias,
                Tag,
                Callback,
                Deadline,
                CleanupDeadline
            ),
            _ = safe_demonitor(OwnerMonitor),
            case cancel_phase_result(Phase) of
                owner_down -> ok;
                Result -> ReplyAlias ! {Tag, {cancel_result, Result}}
            end
    end,
    ok.

-spec cancel_once_guardian(
    pid(), reference(), reference(), atomics:atomics_ref(), integer(),
    fun(() -> term()), none | {some, fun((term()) -> term())}, map()
) -> ok.
cancel_once_guardian(
    Owner,
    ReplyAlias,
    Tag,
    Handle,
    ClaimToken,
    Callback,
    Observer,
    Deadlines
) ->
    ok = proc_lib:set_label(<<"http.body_guardian">>),
    _ = process_flag(trap_exit, true),
    case safe_monitor(Owner, []) of
        error ->
            ReplyAlias ! {Tag, {cancel_result, {error, 1}}};
        {ok, OwnerMonitor} ->
            RecoveryStart = start_cancel_recovery_owner(
                Owner, OwnerMonitor, ReplyAlias, Tag, Handle, ClaimToken,
                Observer, Deadlines
            ),
            case RecoveryStart of
                error ->
                    _ = safe_demonitor(OwnerMonitor),
                    ReplyAlias ! {Tag, {cancel_result, {error, 1}}};
                {ok, Recovery, RecoveryMonitor, OwnerStateAtArm} ->
                    finish_cancel_once_guardian(
                        Owner,
                        OwnerMonitor,
                        ReplyAlias,
                        Tag,
                        Handle,
                        ClaimToken,
                        Callback,
                        Observer,
                        Deadlines,
                        Recovery,
                        RecoveryMonitor,
                        OwnerStateAtArm
                    )
            end
    end,
    ok.

-spec finish_cancel_once_guardian(
    pid(), reference(), reference(), reference(), atomics:atomics_ref(),
    integer(), fun(() -> term()), none | {some, fun((term()) -> term())},
    map(), pid(), reference(), alive | dead
) -> ok.
finish_cancel_once_guardian(
    Owner,
    OwnerMonitor,
    ReplyAlias,
    Tag,
    Handle,
    ClaimToken,
    Callback,
    Observer,
    Deadlines,
    Recovery,
    RecoveryMonitor,
    OwnerStateAtArm
) ->
    case claim_cancel_through_recovery(
        Tag,
        Recovery,
        RecoveryMonitor,
        maps:get(request_deadline, Deadlines)
    ) of
                already_claimed ->
                    release_unclaimed_recovery(
                        Handle, Tag, Recovery, RecoveryMonitor,
                        maps:get(termination_deadline, Deadlines)
                    ),
                    _ = safe_demonitor(OwnerMonitor),
                    ReplyAlias ! {Tag, already_claimed};
                deferred ->
                    %% The claim request was already sent to the pre-registered
                    %% recovery owner. Do not turn scheduler delay into a second
                    %% controller failure by killing that owner here. Primary
                    %% exit is its durable handoff signal; registry release stays
                    %% closed until both controllers are observed DOWN.
                    _ = safe_demonitor(OwnerMonitor),
                    ReplyAlias ! {Tag, {cancel_result, {error, 1}}};
                failed ->
                    _ = safe_demonitor(OwnerMonitor),
                    case cancel_claim_state(Handle, ClaimToken) of
                        owned ->
                            _ = recover_release_observer_owned(
                                Handle,
                                Observer,
                                {error, 1},
                                Deadlines,
                                []
                            ),
                            finish_owned_cancel(
                                Handle, ClaimToken, {error, 1}
                            );
                        _ ->
                            ok
                    end,
                    ReplyAlias ! {
                        Tag, {cancel_result, stable_cancel_result(Handle)}
                    };
                claimed ->
                    CallbackPhase = case OwnerStateAtArm of
                        dead ->
                            owner_down;
                        alive ->
                            run_cancel_callback_phase_reaped(
                                Owner,
                                OwnerMonitor,
                                ReplyAlias,
                                Tag,
                                Callback,
                                maps:get(callback_deadline, Deadlines),
                                maps:get(callback_cleanup_deadline, Deadlines),
                                {some, Recovery, RecoveryMonitor, callback, none}
                            )
                    end,
                    {InitialResult, _OwnerState} =
                        cancel_phase_outcome(CallbackPhase),
                    {Result, RecoveryState} = run_release_observer(
                        Recovery,
                        RecoveryMonitor,
                        ReplyAlias,
                        Tag,
                        Handle,
                        Observer,
                        InitialResult,
                        Deadlines
                    ),
                    _ = safe_demonitor(OwnerMonitor),
                    Seal = case RecoveryState of
                        dead -> failed;
                        alive -> arm_cancel_recovery_seal(
                            Tag,
                            Recovery,
                            RecoveryMonitor,
                            Result,
                            maps:get(termination_deadline, Deadlines)
                        )
                    end,
                    case Seal of
                        armed ->
                            %% The recovery owner has durably recorded Result.
                            %% It waits for this guardian's DOWN and every
                            %% callback DOWN before publishing the public state.
                            ok;
                        failed ->
                            fail_release_observer_conservatively(
                                Handle, Observer
                            ),
                            finish_owned_cancel(
                                Handle, ClaimToken, {error, 1}
                            ),
                            ReplyAlias ! {
                                Tag, {cancel_result, stable_cancel_result(Handle)}
                             }
                    end
    end,
    ok.

-spec run_release_observer(
    pid(), reference(), reference(), reference(), atomics:atomics_ref(),
    none | {some, fun((term()) -> term())},
    {ok, nil} | {error, 1 | 2 | 3}, map()
) -> {{ok, nil} | {error, 1 | 2 | 3}, alive | dead}.
run_release_observer(
    _Recovery, _RecoveryMonitor, _ReplyAlias, _Tag, _Handle,
    none, Result, _Deadlines
) ->
    {Result, alive};
run_release_observer(
    Recovery,
    RecoveryMonitor,
    ReplyAlias,
    Tag,
    Handle,
    {some, Observer},
    Result,
    Deadlines
) ->
    case claim_release_observer(Handle) of
        false ->
            {Result, alive};
        true ->
            ObserverCallback = fun() -> Observer(Result) end,
            %% Recovery, rather than the API caller, owns this phase. A queued
            %% caller DOWN can therefore never suppress release observation
            %% after the main callback has already completed.
            Phase = run_cancel_callback_phase_reaped(
                Recovery,
                RecoveryMonitor,
                Recovery,
                Tag,
                ObserverCallback,
                maps:get(observer_deadline, Deadlines),
                maps:get(observer_cleanup_deadline, Deadlines),
                {some, Recovery, RecoveryMonitor, observer,
                 {some, ReplyAlias}}
            ),
            finish_release_observer_phase(Handle, Phase),
            case Phase of
                owner_down -> {{error, 1}, dead};
                owner_cleanup_failed -> {{error, 1}, dead};
                cleanup_failed -> {{error, 1}, alive};
                _ -> {Result, alive}
            end
    end.

-spec finish_release_observer_phase(
    atomics:atomics_ref(),
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed
) -> ok.
finish_release_observer_phase(Handle, cleanup_failed) ->
    fail_release_observer(Handle);
finish_release_observer_phase(Handle, owner_cleanup_failed) ->
    fail_release_observer(Handle);
finish_release_observer_phase(Handle, owner_down) ->
    fail_release_observer(Handle);
finish_release_observer_phase(Handle, _Phase) ->
    finish_release_observer(Handle).

%% A finite recovery owner is armed before word one can be claimed. The private
%% registry independently monitors both it and the primary; the recovery owner
%% also monitors every worker before that worker receives its start token. The
%% primary only exits after the recovery owner acknowledges a sealed result.
%% Recovery then observes the primary DOWN, joins all workers against the
%% original termination deadline, closes the observer claim, publishes the
%% stable result, and exits. Registry-confirmed public release follows both
%% controller DOWN signals.
-spec start_cancel_recovery_owner(
    pid(), reference(), reference(), reference(), atomics:atomics_ref(),
    integer(), none | {some, fun((term()) -> term())}, map()
) -> {ok, pid(), reference(), alive | dead} | error.
start_cancel_recovery_owner(
    Owner, OwnerMonitor, ReplyAlias, Tag, Handle, ClaimToken,
    Observer, Deadlines
) ->
    Guardian = self(),
    Spawned = safe_spawn(fun() ->
        cancel_recovery_owner(
            Guardian, ReplyAlias, Tag, Handle, ClaimToken,
            Observer, Deadlines
        )
    end, cancel_controller_spawn_options(true)),
    case Spawned of
        {ok, Recovery, RecoveryMonitor} ->
            case register_cancel_recovery(
                Handle,
                Recovery,
                maps:get(request_deadline, Deadlines)
            ) of
                error ->
                    exit(Recovery, kill),
                    _ = await_process_down(
                        Recovery,
                        RecoveryMonitor,
                        maps:get(termination_deadline, Deadlines)
                    ),
                    _ = safe_demonitor(RecoveryMonitor),
                    error;
                ok ->
                    case await_cancel_recovery_arm(
                        Owner,
                        OwnerMonitor,
                        Tag,
                        Recovery,
                        RecoveryMonitor,
                        false,
                        alive,
                        maps:get(request_deadline, Deadlines)
                    ) of
                        {ready, OwnerState} ->
                            {ok, Recovery, RecoveryMonitor, OwnerState};
                        failed ->
                            exit(Recovery, kill),
                            _ = await_process_down(
                                Recovery,
                                RecoveryMonitor,
                                maps:get(termination_deadline, Deadlines)
                            ),
                            _ = safe_demonitor(RecoveryMonitor),
                            error
                    end
            end;
        error ->
            error
    end.

-spec await_cancel_recovery_arm(
    pid(), reference(), reference(), pid(), reference(),
    boolean(), alive | dead, integer()
) -> {ready, alive | dead} | failed.
await_cancel_recovery_arm(
    Owner,
    OwnerMonitor,
    Tag,
    Recovery,
    RecoveryMonitor,
    RecoveryArmed,
    OwnerState,
    Deadline
) ->
    case RecoveryArmed of
        true ->
            {ready, take_cancel_owner_state(
                Owner, OwnerMonitor, OwnerState
            )};
        false ->
            Remaining = remaining_milliseconds(Deadline),
            receive
                {Tag, {cancel_recovery_armed, Recovery}} ->
                    await_cancel_recovery_arm(
                        Owner, OwnerMonitor, Tag, Recovery, RecoveryMonitor,
                        true, OwnerState, Deadline
                    );
                {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
                    await_cancel_recovery_arm(
                        Owner, OwnerMonitor, Tag, Recovery, RecoveryMonitor,
                        RecoveryArmed, dead, Deadline
                    );
                {'DOWN', RecoveryMonitor, process, Recovery, _Reason} ->
                    failed;
                {'EXIT', Recovery, _Reason} ->
                    await_cancel_recovery_arm(
                        Owner, OwnerMonitor, Tag, Recovery, RecoveryMonitor,
                        RecoveryArmed, OwnerState, Deadline
                    )
            after Remaining ->
                failed
            end
    end.

-spec take_cancel_owner_state(pid(), reference(), alive | dead) ->
    alive | dead.
take_cancel_owner_state(_Owner, _OwnerMonitor, dead) ->
    dead;
take_cancel_owner_state(Owner, OwnerMonitor, alive) ->
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} -> dead
    after 0 ->
        alive
    end.

-spec cancel_recovery_owner(
    pid(), reference(), reference(), atomics:atomics_ref(), integer(),
    none | {some, fun((term()) -> term())}, map()
) -> ok.
cancel_recovery_owner(
    Guardian, ReplyAlias, Tag, Handle, ClaimToken, Observer, Deadlines
) ->
    ok = proc_lib:set_label(<<"http.body_recovery">>),
    _ = process_flag(trap_exit, true),
    case safe_monitor(Guardian, []) of
        error ->
            ok;
        {ok, GuardianMonitor} ->
            Guardian ! {Tag, {cancel_recovery_armed, self()}},
            cancel_recovery_loop(
                Guardian,
                GuardianMonitor,
                ReplyAlias,
                Tag,
                Handle,
                ClaimToken,
                Observer,
                Deadlines,
                [],
                none
            )
    end.

-spec cancel_recovery_loop(
    pid(), reference(), reference(), reference(), atomics:atomics_ref(),
    integer(), none | {some, fun((term()) -> term())}, map(), list(),
    none | {some, {ok, nil} | {error, 1 | 2 | 3}}
) -> ok.
cancel_recovery_loop(
    Guardian,
    GuardianMonitor,
    ReplyAlias,
    Tag,
    Handle,
    ClaimToken,
    Observer,
    Deadlines,
    Workers,
    Sealed
) ->
    Remaining = remaining_milliseconds(
        maps:get(termination_deadline, Deadlines)
    ),
    receive
        {Tag,
         {cancel_recovery_worker_registered,
          Guardian, Kind, WorkerReference, Worker, RegistrationReference}}
                when (Kind =:= callback orelse Kind =:= observer),
                     is_reference(WorkerReference), is_pid(Worker),
                     is_reference(RegistrationReference) ->
            case ensure_recovery_worker(
                Kind, WorkerReference, Worker, Workers
            ) of
                {ok, NextWorkers} ->
                    Guardian ! {
                        Tag,
                        {cancel_recovery_worker_monitored,
                         WorkerReference, RegistrationReference, self()}
                    },
                    cancel_recovery_loop(
                        Guardian, GuardianMonitor, ReplyAlias, Tag,
                        Handle, ClaimToken, Observer, Deadlines,
                        NextWorkers, Sealed
                    );
                error ->
                    Guardian ! {
                        Tag,
                        {cancel_recovery_worker_rejected,
                         WorkerReference, RegistrationReference, self()}
                    },
                    cancel_recovery_loop(
                        Guardian, GuardianMonitor, ReplyAlias, Tag,
                        Handle, ClaimToken, Observer, Deadlines,
                        Workers, Sealed
                    )
            end;
        {Tag,
         {cancel_worker_registered,
          WorkerReference, Worker, RegistrationReference}}
                when is_reference(WorkerReference), is_pid(Worker),
                     is_reference(RegistrationReference) ->
            %% The observer phase uses this recovery process as its logical
            %% caller. The preceding recovery registration already supplied
            %% the phase kind; this duplicate only acknowledges the ordinary
            %% callback protocol.
            case ensure_recovery_worker(
                observer, WorkerReference, Worker, Workers
            ) of
                {ok, NextWorkers} ->
                    Guardian ! {
                        Tag,
                        {cancel_worker_monitored,
                         WorkerReference, RegistrationReference, self()}
                    },
                    cancel_recovery_loop(
                        Guardian, GuardianMonitor, ReplyAlias, Tag,
                        Handle, ClaimToken, Observer, Deadlines,
                        NextWorkers, Sealed
                    );
                error ->
                    Guardian ! {
                        Tag,
                        {cancel_worker_rejected,
                         WorkerReference, RegistrationReference, self()}
                    },
                    cancel_recovery_loop(
                        Guardian, GuardianMonitor, ReplyAlias, Tag,
                        Handle, ClaimToken, Observer, Deadlines,
                        Workers, Sealed
                    )
            end;
        {Tag,
         {cancel_recovery_worker_completed,
          WorkerReference, Outcome, Started, Finished}}
                when is_reference(WorkerReference), is_integer(Started),
                     is_integer(Finished) ->
            NextWorkers = mark_recovery_worker_completed(
                WorkerReference, Outcome, Started, Finished, Workers
            ),
            cancel_recovery_loop(
                Guardian, GuardianMonitor, ReplyAlias, Tag,
                Handle, ClaimToken, Observer, Deadlines,
                NextWorkers, Sealed
            );
        {Tag, {cancel_recovery_seal, Guardian, SealReference, Result}}
                when is_reference(SealReference),
                     (Result =:= {ok, nil} orelse
                      Result =:= {error, 1} orelse
                      Result =:= {error, 2} orelse
                      Result =:= {error, 3}) ->
            Guardian ! {
                Tag, {cancel_recovery_sealed, SealReference, self()}
            },
            cancel_recovery_loop(
                Guardian, GuardianMonitor, ReplyAlias, Tag,
                Handle, ClaimToken, Observer, Deadlines,
                Workers, {some, Result}
            );
        {Tag, {cancel_recovery_claim, Guardian, ClaimReference}}
                when is_reference(ClaimReference) ->
            Claimed = case claim_cancel(Handle, ClaimToken) of
                true -> claimed;
                false -> already_claimed
            end,
            Guardian ! {
                Tag, {cancel_recovery_claimed, ClaimReference, self(), Claimed}
            },
            cancel_recovery_loop(
                Guardian, GuardianMonitor, ReplyAlias, Tag,
                Handle, ClaimToken, Observer, Deadlines,
                Workers, Sealed
            );
        {Tag, {cancel_recovery_release_unclaimed, Guardian}} ->
            _ = safe_demonitor(GuardianMonitor),
            ok;
        {'DOWN', GuardianMonitor, process, Guardian, _Reason} ->
            cancel_recovery_finalize(
                ReplyAlias, Tag, Handle, ClaimToken, Observer,
                Deadlines, Workers, Sealed
            );
        {'DOWN', WorkerMonitor, process, Worker, Reason} ->
            NextWorkers = mark_recovery_worker_down(
                Worker, WorkerMonitor, Reason, Workers
            ),
            cancel_recovery_loop(
                Guardian, GuardianMonitor, ReplyAlias, Tag,
                Handle, ClaimToken, Observer, Deadlines,
                NextWorkers, Sealed
            );
        {'EXIT', _Linked, _Reason} ->
            cancel_recovery_loop(
                Guardian, GuardianMonitor, ReplyAlias, Tag,
                Handle, ClaimToken, Observer, Deadlines,
                Workers, Sealed
            )
    after Remaining ->
        exit(Guardian, kill),
        _ = await_process_down(
            Guardian,
            GuardianMonitor,
            maps:get(termination_deadline, Deadlines)
        ),
        cancel_recovery_finalize(
            ReplyAlias, Tag, Handle, ClaimToken, Observer,
            Deadlines, Workers, Sealed
        )
    end.

-spec ensure_recovery_worker(atom(), reference(), pid(), list()) ->
    {ok, list()} | error.
ensure_recovery_worker(Kind, Reference, Worker, Workers) ->
    case lists:keyfind(Reference, 2, Workers) of
        false ->
            case safe_monitor(Worker, []) of
                {ok, Monitor} ->
                    {ok,
                     [{Kind, Reference, Worker, Monitor, up, none}
                      | Workers]};
                error ->
                    error
            end;
        {ExistingKind, Reference, Worker, _Monitor, _State, _Completion}
                when ExistingKind =:= Kind; ExistingKind =:= observer ->
            {ok, Workers};
        _Mismatch ->
            error
    end.

-spec mark_recovery_worker_completed(
    reference(), term(), integer(), integer(), list()
) -> list().
mark_recovery_worker_completed(Reference, Outcome, Started, Finished, Workers) ->
    lists:map(fun
        ({Kind, EntryReference, Worker, Monitor, State, none})
                when EntryReference =:= Reference ->
            {Kind, Reference, Worker, Monitor, State,
             {some, Outcome, Started, Finished}};
        (Entry) -> Entry
    end, Workers).

-spec mark_recovery_worker_down(pid(), reference(), term(), list()) -> list().
mark_recovery_worker_down(Worker, Monitor, Reason, Workers) ->
    lists:map(fun
        ({Kind, Reference, EntryWorker, EntryMonitor, up, Completion})
                when EntryWorker =:= Worker, EntryMonitor =:= Monitor ->
            {Kind, Reference, Worker, Monitor, {down, Reason}, Completion};
        (Entry) -> Entry
    end, Workers).

-spec cancel_recovery_finalize(
    reference(), reference(), atomics:atomics_ref(), integer(),
    none | {some, fun((term()) -> term())}, map(), list(),
    none | {some, {ok, nil} | {error, 1 | 2 | 3}}
) -> ok.
cancel_recovery_finalize(
    ReplyAlias, Tag, Handle, ClaimToken, Observer,
    Deadlines, Workers, Sealed
) ->
    lists:foreach(fun
        ({_Kind, _Reference, Worker, _Monitor, up, _Completion}) ->
            exit(Worker, kill);
        (_) ->
            ok
    end, Workers),
    {WorkersConfirmation, JoinedWorkers} = join_recovery_workers(
        Workers, maps:get(termination_deadline, Deadlines)
    ),
    lists:foreach(fun
        ({_Kind, _Reference, _Worker, Monitor, _State, _Completion}) ->
            _ = safe_demonitor(Monitor)
    end, JoinedWorkers),
    case cancel_claim_state(Handle, ClaimToken) of
        owned ->
            Suggested = case Sealed of
                {some, Result} -> Result;
                none -> {error, 1}
            end,
            ObserverConfirmation = recover_release_observer_owned(
                Handle, Observer, {error, 1}, Deadlines, JoinedWorkers
            ),
            StableSuggestion = case {
                WorkersConfirmation, ObserverConfirmation, Sealed
            } of
                {confirmed, confirmed, {some, _}} -> Suggested;
                _ -> {error, 1}
            end,
            finish_owned_cancel(Handle, ClaimToken, StableSuggestion),
            ReplyAlias ! {
                Tag, {cancel_result, stable_cancel_result(Handle)}
            };
        {completed, Existing} ->
            ReplyAlias ! {Tag, {cancel_result, Existing}};
        other_pending ->
            ReplyAlias ! {Tag, already_claimed};
        unclaimed ->
            ReplyAlias ! {Tag, {cancel_result, {error, 1}}};
        invalid ->
            ReplyAlias ! {Tag, {cancel_result, {error, 1}}}
    end,
    ok.

-spec join_recovery_workers(list(), integer()) ->
    {confirmed | unconfirmed, list()}.
join_recovery_workers(Workers, Deadline) ->
    case all_recovery_workers_down(Workers) of
        true ->
            {confirmed, Workers};
        false ->
            Remaining = remaining_milliseconds(Deadline),
            receive
                {'DOWN', Monitor, process, Worker, Reason} ->
                    join_recovery_workers(
                        mark_recovery_worker_down(
                            Worker, Monitor, Reason, Workers
                        ),
                        Deadline
                    );
                {_Tag,
                 {cancel_recovery_worker_completed,
                  Reference, Outcome, Started, Finished}}
                        when is_reference(Reference), is_integer(Started),
                             is_integer(Finished) ->
                    join_recovery_workers(
                        mark_recovery_worker_completed(
                            Reference, Outcome, Started, Finished, Workers
                        ),
                        Deadline
                    )
            after Remaining ->
                {unconfirmed, Workers}
            end
    end.

-spec all_recovery_workers_down(list()) -> boolean().
all_recovery_workers_down(Workers) ->
    lists:all(fun
        ({_Kind, _Reference, _Worker, _Monitor,
          {down, _Reason}, _Completion}) -> true;
        (_) -> false
    end, Workers).

-spec recover_release_observer_owned(
    atomics:atomics_ref(), none | {some, fun((term()) -> term())},
    {error, 1}, map(), list()
) -> confirmed | failed.
recover_release_observer_owned(_Handle, none, _Result, _Deadlines, _Workers) ->
    confirmed;
recover_release_observer_owned(
    Handle, {some, Observer}, Result, Deadlines, Workers
) ->
    case release_observer_state(Handle) of
        complete ->
            confirmed;
        failed ->
            failed;
        running ->
            case completed_recovery_observer(Workers) of
                true ->
                    finish_release_observer(Handle),
                    confirmed;
                false ->
                    fail_release_observer(Handle),
                    failed
            end;
        pending ->
            case claim_release_observer(Handle) of
                true ->
                    Outcome = run_cancel_callback_before_outcome(
                        fun() -> Observer(Result) end,
                        maps:get(observer_deadline, Deadlines),
                        maps:get(observer_cleanup_deadline, Deadlines)
                    ),
                    case Outcome of
                        {completed, _} ->
                            finish_release_observer(Handle),
                            confirmed;
                        _ ->
                            fail_release_observer(Handle),
                            failed
                    end;
                false ->
                    case release_observer_state(Handle) of
                        complete -> confirmed;
                        _ -> failed
                    end
            end
    end.

-spec completed_recovery_observer(list()) -> boolean().
completed_recovery_observer(Workers) ->
    lists:any(fun
        ({observer, _Reference, _Worker, _Monitor,
          {down, normal}, {some, _Outcome, _Started, _Finished}}) -> true;
        (_) -> false
    end, Workers).

-spec release_unclaimed_recovery(
    atomics:atomics_ref(), reference(), pid(), reference(), integer()
) -> ok.
release_unclaimed_recovery(
    _Handle, Tag, Recovery, RecoveryMonitor, Deadline
) ->
    Recovery ! {Tag, {cancel_recovery_release_unclaimed, self()}},
    case await_process_down(Recovery, RecoveryMonitor, Deadline) of
        down ->
            ok;
        deadline ->
            exit(Recovery, kill),
            _ = await_process_down(Recovery, RecoveryMonitor, Deadline),
            ok
    end,
    _ = safe_demonitor(RecoveryMonitor),
    ok.

-spec claim_cancel_through_recovery(
    reference(), pid(), reference(), integer()
) -> claimed | already_claimed | deferred | failed.
claim_cancel_through_recovery(Tag, Recovery, RecoveryMonitor, Deadline) ->
    ClaimReference = make_ref(),
    Recovery ! {
        Tag, {cancel_recovery_claim, self(), ClaimReference}
    },
    Remaining = remaining_milliseconds(Deadline),
    receive
        {Tag,
         {cancel_recovery_claimed,
          ClaimReference, Recovery, claimed}} ->
            claimed;
        {Tag,
         {cancel_recovery_claimed,
          ClaimReference, Recovery, already_claimed}} ->
            already_claimed;
        {'DOWN', RecoveryMonitor, process, Recovery, _Reason} ->
            failed;
        {'EXIT', Recovery, _Reason} ->
            claim_cancel_through_recovery(
                Tag, Recovery, RecoveryMonitor, Deadline
            )
    after Remaining ->
        %% The claim signal precedes this guardian's eventual DOWN signal from
        %% the same sender. Recovery will therefore process the claim before it
        %% handles primary death, even if it was not scheduled within the API
        %% caller's request budget.
        deferred
    end.

-spec arm_cancel_recovery_seal(
    reference(), pid(), reference(),
    {ok, nil} | {error, 1 | 2 | 3}, integer()
) -> armed | failed.
arm_cancel_recovery_seal(
    Tag, Recovery, RecoveryMonitor, Result, TerminationDeadline
) ->
    SealReference = make_ref(),
    Recovery ! {
        Tag, {cancel_recovery_seal, self(), SealReference, Result}
    },
    Remaining = remaining_milliseconds(TerminationDeadline),
    receive
        {Tag, {cancel_recovery_sealed, SealReference, Recovery}} ->
            armed;
        {'DOWN', RecoveryMonitor, process, Recovery, _Reason} ->
            failed;
        {'EXIT', Recovery, _Reason} ->
            arm_cancel_recovery_seal(
                Tag, Recovery, RecoveryMonitor, Result,
                TerminationDeadline
            )
    after Remaining ->
        exit(Recovery, kill),
        _ = await_process_down(
            Recovery, RecoveryMonitor, TerminationDeadline
        ),
        failed
    end.

-spec fail_release_observer_conservatively(
    atomics:atomics_ref(), none | {some, fun((term()) -> term())}
) -> ok.
fail_release_observer_conservatively(_Handle, none) ->
    ok;
fail_release_observer_conservatively(Handle, {some, _Observer}) ->
    case release_observer_state(Handle) of
        running ->
            fail_release_observer(Handle);
        pending ->
            case claim_release_observer(Handle) of
                true -> fail_release_observer(Handle);
                false -> ok
            end;
        _ ->
            ok
    end.

-spec stable_cancel_result(atomics:atomics_ref()) ->
    {ok, nil} | {error, 1 | 2 | 3}.
stable_cancel_result(Handle) ->
    case cancel_result(Handle) of
        {some, Result} -> Result;
        none -> {error, 1}
    end.

-spec await_process_down(pid(), reference(), integer()) -> down | deadline.
await_process_down(Process, Monitor, Deadline) ->
    Remaining = remaining_milliseconds(Deadline),
    receive
        {'DOWN', Monitor, process, Process, _Reason} -> down
    after Remaining ->
        deadline
    end.

-spec recover_cancel_once(
    atomics:atomics_ref(), integer(),
    none | {some, fun((term()) -> term())},
    {error, 1 | 2}, map(), confirmed | unconfirmed
) -> {ok, nil} | {error, 1 | 2 | 3}.
recover_cancel_once(
    Handle, ClaimToken, Observer, Suggested, Deadlines, Confirmation
) ->
    case cancel_recovery_barrier_status(
        Handle, maps:get(request_deadline, Deadlines)
    ) of
        clear ->
            recover_cancel_once_without_owner(
                Handle, ClaimToken, Observer, Suggested,
                Deadlines, Confirmation
            );
        pending ->
            %% The caller which supplied ClaimToken owns this recovery attempt.
            %% It may use the already-computed termination budget to observe the
            %% pre-armed controllers' DOWN barrier. A competing caller never
            %% receives that extra budget and remains bounded by its original
            %% request deadline.
            case cancel_claim_state(Handle, ClaimToken) of
                owned ->
                    await_cancel_until(
                        Handle, maps:get(termination_deadline, Deadlines)
                    );
                _ ->
                    await_cancel_until(
                        Handle, maps:get(request_deadline, Deadlines)
                    )
            end;
        unavailable ->
            known_cancel_failure(Handle, {error, 1})
    end.

-spec recover_cancel_once_without_owner(
    atomics:atomics_ref(), integer(),
    none | {some, fun((term()) -> term())},
    {error, 1 | 2}, map(), confirmed | unconfirmed
) -> {ok, nil} | {error, 1 | 2 | 3}.
recover_cancel_once_without_owner(
    Handle, ClaimToken, Observer, Suggested, Deadlines, Confirmation
) ->
    case cancel_claim_state(Handle, ClaimToken) of
        {completed, Existing} ->
            Existing;
        owned ->
            recover_owned_cancel(
                Handle,
                ClaimToken,
                Observer,
                Suggested,
                Deadlines,
                Confirmation
            );
        unclaimed ->
            %% No independent owner remains. Leaving zero retryable is safer
            %% than creating a claimed state owned only by this fallible caller.
            {error, 1};
        other_pending ->
            await_cancel_until(
                Handle, maps:get(request_deadline, Deadlines)
            );
        invalid ->
            {error, 1}
    end.

-spec recover_owned_cancel(
    atomics:atomics_ref(), integer(),
    none | {some, fun((term()) -> term())},
    {error, 1 | 2}, map(), confirmed | unconfirmed
) -> {ok, nil} | {error, 1 | 2 | 3}.
recover_owned_cancel(
    Handle, ClaimToken, Observer, Suggested, Deadlines, Confirmation
) ->
    case Confirmation of
        confirmed ->
            recover_release_observer(
                Handle, Observer, Suggested, Deadlines
            );
        unconfirmed ->
            ok
    end,
    finish_owned_cancel(Handle, ClaimToken, Suggested),
    case cancel_result(Handle) of
        {some, Stable} -> Stable;
        none -> {error, 1}
    end.

-spec recover_release_observer(
    atomics:atomics_ref(), none | {some, fun((term()) -> term())},
    {error, 1 | 2}, map()
) -> ok.
recover_release_observer(_Handle, none, _Result, _Deadlines) ->
    ok;
recover_release_observer(Handle, {some, Observer}, Result, Deadlines) ->
    case release_observer_state(Handle) of
        complete ->
            ok;
        failed ->
            ok;
        running ->
            %% The guardian and every registered worker have already been
            %% joined by the recovery path, but no completion record survived.
            %% Do not report an observer invocation that cannot be proved.
            fail_release_observer(Handle);
        pending ->
            case claim_release_observer(Handle) of
                true ->
                    Outcome = run_cancel_callback_before_outcome(
                        fun() -> Observer(Result) end,
                        maps:get(observer_deadline, Deadlines),
                        maps:get(observer_cleanup_deadline, Deadlines)
                    ),
                    case Outcome of
                        {completed, _} -> finish_release_observer(Handle);
                        _ -> fail_release_observer(Handle)
                    end;
                false ->
                    ok
            end
    end.

%% A callback is gated until its guardian has a monitor from spawn_opt and the
%% API caller acknowledges its own independently tagged monitor. The worker
%% checks the original deadline again after it receives the start token, so a
%% scheduler stall cannot start application code after expiry.
-spec run_cancel_callback_phase(
    pid(), reference(), pid() | reference(), reference(), fun(() -> term()),
    integer(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed.
run_cancel_callback_phase(
    Owner,
    OwnerMonitor,
    ReplyAlias,
    Tag,
    Callback,
    Deadline,
    CleanupDeadline
) ->
    run_cancel_callback_phase_reaped(
        Owner, OwnerMonitor, ReplyAlias, Tag, Callback,
        Deadline, CleanupDeadline, none
    ).

-spec run_cancel_callback_phase_reaped(
    pid(), reference(), pid() | reference(), reference(), fun(() -> term()),
    integer(), integer(),
    none |
    {some, pid(), reference(), callback | observer,
     none | {some, pid() | reference()}}
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed.
run_cancel_callback_phase_reaped(
    Owner,
    OwnerMonitor,
    ReplyAlias,
    Tag,
    Callback,
    Deadline,
    CleanupDeadline,
    Reaper
) ->
    Guardian = self(),
    WorkerReference = make_ref(),
    RegistrationReference = make_ref(),
    Spawned = safe_spawn(fun() ->
        cancel_callback_worker(
            Guardian, Tag, WorkerReference, Callback, Deadline, Reaper
        )
    end, cancel_spawn_options()),
    case Spawned of
        error ->
            cleanup_failed;
        {ok, Worker, WorkerMonitor} ->
            RecoveryRegistration = register_cancel_recovery_worker(
                Reaper,
                Tag,
                WorkerReference,
                Worker,
                RegistrationReference,
                Deadline
            ),
            case RecoveryRegistration of
                confirmed ->
                    notify_cancel_worker_tracker(
                        Reaper,
                        Tag,
                        WorkerReference,
                        Worker,
                        RegistrationReference
                    ),
                    ReplyAlias ! {
                        Tag,
                        {cancel_worker_registered,
                         WorkerReference, Worker, RegistrationReference}
                    },
                    try
                        await_cancel_callback_registration(
                            Owner,
                            OwnerMonitor,
                            Tag,
                            Worker,
                            WorkerMonitor,
                            WorkerReference,
                            RegistrationReference,
                            Deadline,
                            CleanupDeadline
                        )
                    after
                        _ = safe_demonitor(WorkerMonitor)
                    end;
                failed ->
                    Result = stop_cancel_worker(
                        Worker, WorkerMonitor, CleanupDeadline
                    ),
                    _ = safe_demonitor(WorkerMonitor),
                    case Result of
                        confirmed -> cleanup_failed;
                        unconfirmed -> owner_cleanup_failed
                    end
            end
    end.

-spec register_cancel_recovery_worker(
    none |
    {some, pid(), reference(), callback | observer,
     none | {some, pid() | reference()}},
    reference(), reference(), pid(), reference(), integer()
) -> confirmed | failed.
register_cancel_recovery_worker(
    none, _Tag, _WorkerReference, _Worker, _RegistrationReference, _Deadline
) ->
    confirmed;
register_cancel_recovery_worker(
    {some, Recovery, RecoveryMonitor, Kind, _Tracker},
    Tag,
    WorkerReference,
    Worker,
    RegistrationReference,
    Deadline
) ->
    Recovery ! {
        Tag,
        {cancel_recovery_worker_registered,
         self(), Kind, WorkerReference, Worker, RegistrationReference}
    },
    Remaining = remaining_milliseconds(Deadline),
    receive
        {Tag,
         {cancel_recovery_worker_monitored,
          WorkerReference, RegistrationReference, Recovery}} ->
            confirmed;
        {Tag,
         {cancel_recovery_worker_rejected,
          WorkerReference, RegistrationReference, Recovery}} ->
            failed;
        {'DOWN', RecoveryMonitor, process, Recovery, _Reason} ->
            failed
    after Remaining ->
        failed
    end.

-spec notify_cancel_worker_tracker(
    none |
    {some, pid(), reference(), callback | observer,
     none | {some, pid() | reference()}},
    reference(), reference(), pid(), reference()
) -> ok.
notify_cancel_worker_tracker(
    {some, _Recovery, _RecoveryMonitor, _Kind, {some, Tracker}},
    Tag, WorkerReference, Worker, RegistrationReference
) ->
    Tracker ! {
        Tag,
        {cancel_worker_registered,
         WorkerReference, Worker, RegistrationReference}
    },
    ok;
notify_cancel_worker_tracker(
    _Recovery, _Tag, _WorkerReference, _Worker, _RegistrationReference
) ->
    ok.

-spec cancel_callback_worker(
    pid(), reference(), reference(), fun(() -> term()), integer(),
    none |
    {some, pid(), reference(), callback | observer,
     none | {some, pid() | reference()}}
) -> ok.
cancel_callback_worker(
    Guardian, Tag, WorkerReference, Callback, Deadline, Recovery
) ->
    ok = proc_lib:set_label(<<"http.body_callback">>),
    receive
        {WorkerReference, start} ->
            Started = monotonic_millisecond(),
            Outcome = case Started < Deadline of
                true ->
                    invoke_cancel_callback(Callback);
                false ->
                    not_started
            end,
            Finished = monotonic_millisecond(),
            Guardian ! {
                WorkerReference,
                {cancel_callback_completed, Outcome, Started, Finished}
            },
            case Recovery of
                {some, RecoveryPid, _RecoveryMonitor, _Kind, _Tracker} ->
                    RecoveryPid ! {
                        Tag,
                        {cancel_recovery_worker_completed,
                         WorkerReference, Outcome, Started, Finished}
                    };
                none ->
                    ok
            end,
            ok
    end.

-spec cancel_spawn_options() -> [term()].
cancel_spawn_options() ->
    [link,
        monitor,
        {max_heap_size, #{
            size => ?CALLBACK_MAX_HEAP_WORDS,
            kill => true,
            error_logger => false,
            include_shared_binaries => true
        }}
    ].

-spec cancel_controller_spawn_options(boolean()) -> [term()].
cancel_controller_spawn_options(Linked) ->
    Links = case Linked of
        true -> [link];
        false -> []
    end,
    Links ++ [
        monitor,
        {max_heap_size, #{
            size => ?CONTROLLER_MAX_HEAP_WORDS,
            kill => true,
            error_logger => false,
            include_shared_binaries => false
        }}
    ].

-spec cancel_registry_spawn_options() -> [term()].
cancel_registry_spawn_options() ->
    [
        monitor,
        {max_heap_size, #{
            size => ?REGISTRY_MAX_HEAP_WORDS,
            kill => true,
            error_logger => false,
            include_shared_binaries => false
        }}
    ].

-spec safe_spawn(fun(() -> term()), [term()]) ->
    {ok, pid(), reference()} | error.
safe_spawn(Fun, Options) ->
    try spawn_opt(Fun, Options) of
        {Process, Monitor}
                when is_pid(Process), is_reference(Monitor) ->
            {ok, Process, Monitor};
        _ ->
            error
    catch
        _:_ -> error
    end.

-spec safe_alias() -> {ok, reference()} | error.
safe_alias() ->
    try erlang:alias() of
        Alias -> {ok, Alias}
    catch
        _:_ -> error
    end.

-spec safe_unalias(reference()) -> ok.
safe_unalias(Alias) ->
    try erlang:unalias(Alias) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec safe_monitor(pid(), [term()]) -> {ok, reference()} | error.
safe_monitor(Process, Options) ->
    try erlang:monitor(process, Process, Options) of
        Monitor -> {ok, Monitor}
    catch
        _:_ -> error
    end.

-spec safe_demonitor(reference()) -> ok.
safe_demonitor(Monitor) ->
    try erlang:demonitor(Monitor, [flush]) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec safe_send(pid() | reference(), term()) -> ok | error.
safe_send(Destination, Message) ->
    try Destination ! Message of
        _ -> ok
    catch
        _:_ -> error
    end.

%% Recovery membership is private process state. The registry installs its
%% monitor before acknowledging registration, and removes the handle only
%% after receiving that exact monitor's DOWN. Word three mirrors this fact:
%% an odd token is active and the following even token is Registry-confirmed
%% clear. Thus a zero-time await can prove the join without trusting a public
%% ETS table, while a missing or restarted registry fails closed.
-spec register_cancel_recovery(
    atomics:atomics_ref(), pid(), integer()
) -> ok | error.
register_cancel_recovery(Handle, Recovery, Deadline) ->
    case ensure_cancel_recovery_registry(Deadline) of
        {ok, Registry, Generation} ->
            cancel_recovery_registry_register(
                Registry,
                Generation,
                Handle,
                [self(), Recovery],
                Deadline
            );
        error ->
            error
    end.

-spec ensure_cancel_recovery_registry(integer()) ->
    {ok, pid(), pos_integer()} | error.
ensure_cancel_recovery_registry(Deadline) ->
    case safe_registered_process(?RECOVERY_REGISTRY) of
        {ok, Registry} ->
            cancel_recovery_registry_identity(Registry, Deadline);
        missing ->
            start_cancel_recovery_registry(Deadline);
        error ->
            error
    end.

-spec safe_registered_process(atom()) -> {ok, pid()} | missing | error.
safe_registered_process(Name) ->
    try erlang:whereis(Name) of
        undefined -> missing;
        Process when is_pid(Process) -> {ok, Process};
        _ -> error
    catch
        _:_ -> error
    end.

-spec start_cancel_recovery_registry(integer()) ->
    {ok, pid(), pos_integer()} | error.
start_cancel_recovery_registry(Deadline) ->
    case remaining_milliseconds(Deadline) of
        0 ->
            error;
        _ ->
            case safe_alias() of
                error ->
                    error;
                {ok, ReplyAlias} ->
                    Reference = make_ref(),
                    Spawned = safe_spawn(fun() ->
                        cancel_recovery_registry_candidate(
                            ReplyAlias, Reference
                        )
                    end, cancel_registry_spawn_options()),
                    CandidateResult = case Spawned of
                        {ok, Candidate, CandidateMonitor} ->
                            Remaining = remaining_milliseconds(Deadline),
                            Result = receive
                                {Reference,
                                 {cancel_recovery_registry_started,
                                  Candidate, CandidateGeneration}}
                                        when is_integer(CandidateGeneration),
                                             CandidateGeneration > 0 ->
                                    {started, Candidate, CandidateGeneration};
                                {Reference,
                                 {cancel_recovery_registry_contended,
                                  Candidate}} ->
                                    contended;
                                {'DOWN', CandidateMonitor, process,
                                 Candidate, _Reason} ->
                                    failed
                            after Remaining ->
                                failed
                            end,
                            _ = safe_demonitor(CandidateMonitor),
                            Result;
                        error ->
                            failed
                    end,
                    _ = safe_unalias(ReplyAlias),
                    drain_cancel_recovery_registry_protocol(Reference),
                    case CandidateResult of
                        {started, Registry, Generation} ->
                            case safe_registered_process(?RECOVERY_REGISTRY) of
                                {ok, Registry} ->
                                    {ok, Registry, Generation};
                                _ ->
                                    error
                            end;
                        contended ->
                            ensure_cancel_recovery_registry(Deadline);
                        failed ->
                            error
                    end
            end
    end.

-spec cancel_recovery_registry_candidate(reference(), reference()) -> ok.
cancel_recovery_registry_candidate(ReplyAlias, Reference) ->
    ok = proc_lib:set_label(<<"http.body_recovery_registry">>),
    case claim_cancel_recovery_registry_name() of
        ok ->
            Generation = erlang:unique_integer([positive, monotonic]),
            _ = safe_send(ReplyAlias, {
                Reference,
                {cancel_recovery_registry_started, self(), Generation}
            }),
            cancel_recovery_registry_loop(Generation, #{}, #{});
        contended ->
            _ = safe_send(ReplyAlias, {
                Reference, {cancel_recovery_registry_contended, self()}
            }),
            ok;
        error ->
            ok
    end.

-spec claim_cancel_recovery_registry_name() -> ok | contended | error.
claim_cancel_recovery_registry_name() ->
    try erlang:register(?RECOVERY_REGISTRY, self()) of
        true -> ok
    catch
        error:badarg -> contended;
        _:_ -> error
    end.

-spec cancel_recovery_registry_identity(pid(), integer()) ->
    {ok, pid(), pos_integer()} | error.
cancel_recovery_registry_identity(Registry, Deadline) ->
    case safe_alias() of
        error ->
            error;
        {ok, ReplyAlias} ->
            case safe_monitor(Registry, []) of
                error ->
                    _ = safe_unalias(ReplyAlias),
                    error;
                {ok, RegistryMonitor} ->
                    Reference = make_ref(),
                    Registry ! {
                        cancel_recovery_registry,
                        identity,
                        ReplyAlias,
                        Reference
                    },
                    Remaining = remaining_milliseconds(Deadline),
                    Result = receive
                        {Reference,
                         cancel_recovery_registry_identity,
                         Registry,
                         Generation}
                                when is_integer(Generation), Generation > 0 ->
                            {ok, Registry, Generation};
                        {'DOWN', RegistryMonitor, process, Registry, _Reason} ->
                            error
                    after Remaining ->
                        error
                    end,
                    _ = safe_unalias(ReplyAlias),
                    _ = safe_demonitor(RegistryMonitor),
                    drain_cancel_recovery_registry_protocol(Reference),
                    Result
            end
    end.

-spec cancel_recovery_registry_register(
    pid(), pos_integer(), atomics:atomics_ref(), [pid()], integer()
) -> ok | error.
cancel_recovery_registry_register(
    Registry, Generation, Handle, Controllers, Deadline
) ->
    case safe_alias() of
        error ->
            error;
        {ok, ReplyAlias} ->
            case safe_monitor(Registry, []) of
                error ->
                    _ = safe_unalias(ReplyAlias),
                    error;
                {ok, RegistryMonitor} ->
                    Reference = make_ref(),
                    Registry ! {
                        cancel_recovery_registry,
                        register,
                        ReplyAlias,
                        Reference,
                        Generation,
                        Handle,
                        Controllers
                    },
                    Remaining = remaining_milliseconds(Deadline),
                    Result = receive
                        {Reference,
                         cancel_recovery_registry_registered,
                         Registry,
                         Generation} ->
                            ok;
                        {Reference,
                         cancel_recovery_registry_rejected,
                         Registry} ->
                            error;
                        {'DOWN', RegistryMonitor, process, Registry, _Reason} ->
                            error
                    after Remaining ->
                        error
                    end,
                    _ = safe_unalias(ReplyAlias),
                    _ = safe_demonitor(RegistryMonitor),
                    drain_cancel_recovery_registry_protocol(Reference),
                    Result
            end
    end.

-spec cancel_recovery_registry_loop(pos_integer(), map(), map()) -> no_return().
cancel_recovery_registry_loop(Generation, ByRecovery, ByHandle) ->
    receive
        {cancel_recovery_registry, identity, ReplyAlias, Reference}
                when is_reference(ReplyAlias), is_reference(Reference) ->
            _ = safe_send(ReplyAlias, {
                Reference,
                cancel_recovery_registry_identity,
                self(),
                Generation
            }),
            cancel_recovery_registry_loop(Generation, ByRecovery, ByHandle);
        {cancel_recovery_registry, register, ReplyAlias, Reference,
         Generation, Handle, Controllers}
                when is_reference(ReplyAlias), is_reference(Reference),
                     is_list(Controllers) ->
            case add_cancel_recovery_registrations(
                Generation, Handle, Controllers, ByRecovery, ByHandle
            ) of
                {ok, NextByRecovery, NextByHandle} ->
                    _ = safe_send(ReplyAlias, {
                        Reference,
                        cancel_recovery_registry_registered,
                        self(),
                        Generation
                    }),
                    cancel_recovery_registry_loop(
                        Generation, NextByRecovery, NextByHandle
                    );
                error ->
                    _ = safe_send(ReplyAlias, {
                        Reference,
                        cancel_recovery_registry_rejected,
                        self()
                    }),
                    cancel_recovery_registry_loop(
                        Generation, ByRecovery, ByHandle
                    )
            end;
        {cancel_recovery_registry, register, ReplyAlias, Reference,
         _OtherGeneration, _Handle, _Recovery}
                when is_reference(ReplyAlias), is_reference(Reference) ->
            _ = safe_send(ReplyAlias, {
                Reference, cancel_recovery_registry_rejected, self()
            }),
            cancel_recovery_registry_loop(Generation, ByRecovery, ByHandle);
        {cancel_recovery_registry, barrier, ReplyAlias, Reference,
         Generation, Handle}
                when is_reference(ReplyAlias), is_reference(Reference) ->
            Barrier = case maps:get(Handle, ByHandle, 0) of
                Count when is_integer(Count), Count > 0 ->
                    pending;
                _ ->
                    case complete_cancel_recovery_generation(
                        Handle, Generation
                    ) of
                        ok -> clear;
                        error -> stale
                    end
            end,
            _ = safe_send(ReplyAlias, {
                Reference,
                cancel_recovery_registry_barrier,
                self(),
                Generation,
                Barrier
            }),
            cancel_recovery_registry_loop(Generation, ByRecovery, ByHandle);
        {cancel_recovery_registry, barrier, ReplyAlias, Reference,
         OtherGeneration, _Handle}
                when is_reference(ReplyAlias), is_reference(Reference),
                     is_integer(OtherGeneration) ->
            _ = safe_send(ReplyAlias, {
                Reference,
                cancel_recovery_registry_barrier,
                self(),
                Generation,
                stale
            }),
            cancel_recovery_registry_loop(Generation, ByRecovery, ByHandle);
        {'DOWN', Monitor, process, Recovery, _Reason} ->
            {NextByRecovery, NextByHandle} =
                remove_cancel_recovery_registration(
                    Generation,
                    Monitor,
                    Recovery,
                    ByRecovery,
                    ByHandle
                ),
            cancel_recovery_registry_loop(
                Generation, NextByRecovery, NextByHandle
            );
        _Ignored ->
            cancel_recovery_registry_loop(Generation, ByRecovery, ByHandle)
    end.

-spec add_cancel_recovery_registrations(
    pos_integer(), atomics:atomics_ref(), [pid()], map(), map()
) -> {ok, map(), map()} | error.
add_cancel_recovery_registrations(
    Generation,
    Handle,
    [Guardian, Recovery] = Controllers,
    ByRecovery,
    ByHandle
) when is_pid(Guardian), is_pid(Recovery), Guardian =/= Recovery ->
    States = lists:map(fun(Controller) ->
        case maps:find(Controller, ByRecovery) of
            {ok, {_Monitor, Handle}} -> same;
            {ok, _OtherHandle} -> conflict;
            error -> fresh
        end
    end, Controllers),
    case States of
        [same, same] ->
            {ok, ByRecovery, ByHandle};
        [fresh, fresh] ->
            case monitor_cancel_recovery_controllers(Controllers, []) of
                error ->
                    error;
                {ok, Monitored} ->
                    case activate_cancel_recovery_generation(
                        Handle, Generation
                    ) of
                        ok ->
                            Count = maps:get(Handle, ByHandle, 0),
                            NextByRecovery = lists:foldl(fun(
                                {Controller, Monitor}, Acc
                            ) ->
                                maps:put(
                                    Controller, {Monitor, Handle}, Acc
                                )
                            end, ByRecovery, Monitored),
                            {ok,
                             NextByRecovery,
                             maps:put(
                                 Handle, Count + length(Monitored), ByHandle
                             )};
                        error ->
                            demonitor_cancel_recovery_controllers(Monitored),
                            error
                    end
            end;
        _ ->
            error
    end;
add_cancel_recovery_registrations(
    _Generation, _Handle, _Controllers, _ByRecovery, _ByHandle
) ->
    error.

-spec monitor_cancel_recovery_controllers([pid()], list()) ->
    {ok, list()} | error.
monitor_cancel_recovery_controllers([], Monitored) ->
    {ok, Monitored};
monitor_cancel_recovery_controllers([Controller | Rest], Monitored) ->
    case safe_monitor(Controller, []) of
        {ok, Monitor} ->
            monitor_cancel_recovery_controllers(
                Rest, [{Controller, Monitor} | Monitored]
            );
        error ->
            demonitor_cancel_recovery_controllers(Monitored),
            error
    end.

-spec demonitor_cancel_recovery_controllers(list()) -> ok.
demonitor_cancel_recovery_controllers(Monitored) ->
    lists:foreach(fun({_Controller, Monitor}) ->
        _ = safe_demonitor(Monitor)
    end, Monitored),
    ok.

-spec remove_cancel_recovery_registration(
    pos_integer(), reference(), pid(), map(), map()
) -> {map(), map()}.
remove_cancel_recovery_registration(
    Generation, Monitor, Recovery, ByRecovery, ByHandle
) ->
    case maps:find(Recovery, ByRecovery) of
        {ok, {Monitor, Handle}} ->
            NextByRecovery = maps:remove(Recovery, ByRecovery),
            case maps:get(Handle, ByHandle, 0) of
                Count when is_integer(Count), Count > 1 ->
                    {NextByRecovery, maps:put(Handle, Count - 1, ByHandle)};
                _ ->
                    _ = complete_cancel_recovery_generation(
                        Handle, Generation
                    ),
                    {NextByRecovery, maps:remove(Handle, ByHandle)}
            end;
        _ ->
            {ByRecovery, ByHandle}
    end.

-spec activate_cancel_recovery_generation(
    atomics:atomics_ref(), pos_integer()
) -> ok | error.
activate_cancel_recovery_generation(Handle, Generation) ->
    Active = (Generation bsl 1) bor 1,
    Clear = Generation bsl 1,
    try atomics:get(Handle, 3) of
        Active ->
            ok;
        0 ->
            case atomics:compare_exchange(Handle, 3, 0, Active) of
                ok -> ok;
                Active -> ok;
                _ -> error
            end;
        Clear ->
            case atomics:compare_exchange(Handle, 3, Clear, Active) of
                ok -> ok;
                Active -> ok;
                _ -> error
            end;
        _ ->
            error
    catch
        _:_ -> error
    end.

-spec complete_cancel_recovery_generation(
    atomics:atomics_ref(), pos_integer()
) -> ok | error.
complete_cancel_recovery_generation(Handle, Generation) ->
    Active = (Generation bsl 1) bor 1,
    Clear = Generation bsl 1,
    try atomics:get(Handle, 3) of
        Clear ->
            ok;
        Active ->
            case atomics:compare_exchange(Handle, 3, Active, Clear) of
                ok -> ok;
                Clear -> ok;
                _ -> error
            end;
        _ ->
            error
    catch
        _:_ -> error
    end.

-spec cancel_recovery_generation(atomics:atomics_ref()) ->
    clear | {active, pos_integer()} | invalid.
cancel_recovery_generation(Handle) ->
    try atomics:get(Handle, 3) of
        0 ->
            clear;
        Value when is_integer(Value), Value > 0,
                   (Value band 1) =:= 0 ->
            clear;
        Value when is_integer(Value), Value > 1 ->
            {active, Value bsr 1};
        _ ->
            invalid
    catch
        _:_ -> invalid
    end.

-spec await_cancel_recovery_barrier(
    atomics:atomics_ref(), integer()
) -> confirmed | unconfirmed.
await_cancel_recovery_barrier(Handle, Deadline) ->
    case cancel_recovery_barrier_status(Handle, Deadline) of
        clear ->
            confirmed;
        unavailable ->
            unconfirmed;
        pending ->
            Remaining = remaining_milliseconds(Deadline),
            case Remaining of
                0 ->
                    unconfirmed;
                _ ->
                    receive
                    after erlang:min(1, Remaining) ->
                        await_cancel_recovery_barrier(Handle, Deadline)
                    end
            end
    end.

-spec cancel_recovery_barrier_status(
    atomics:atomics_ref(), integer()
) -> clear | pending | unavailable.
cancel_recovery_barrier_status(Handle, Deadline) ->
    case cancel_recovery_generation(Handle) of
        clear ->
            clear;
        invalid ->
            unavailable;
        {active, Generation} ->
            case safe_registered_process(?RECOVERY_REGISTRY) of
                {ok, Registry} ->
                    cancel_recovery_registry_barrier(
                        Registry, Generation, Handle, Deadline
                    );
                _ ->
                    unavailable
            end
    end.

-spec cancel_recovery_registry_barrier(
    pid(), pos_integer(), atomics:atomics_ref(), integer()
) -> clear | pending | unavailable.
cancel_recovery_registry_barrier(
    Registry, Generation, Handle, Deadline
) ->
    case safe_alias() of
        error ->
            unavailable;
        {ok, ReplyAlias} ->
            case safe_monitor(Registry, []) of
                error ->
                    _ = safe_unalias(ReplyAlias),
                    unavailable;
                {ok, RegistryMonitor} ->
                    Reference = make_ref(),
                    Registry ! {
                        cancel_recovery_registry,
                        barrier,
                        ReplyAlias,
                        Reference,
                        Generation,
                        Handle
                    },
                    Remaining = remaining_milliseconds(Deadline),
                    Result = receive
                        {Reference,
                         cancel_recovery_registry_barrier,
                         Registry,
                         Generation,
                         clear} ->
                            clear;
                        {Reference,
                         cancel_recovery_registry_barrier,
                         Registry,
                         Generation,
                         pending} ->
                            pending;
                        {Reference,
                         cancel_recovery_registry_barrier,
                         Registry,
                         _RegistryGeneration,
                         stale} ->
                            unavailable;
                        {'DOWN', RegistryMonitor, process, Registry, _Reason} ->
                            unavailable
                    after Remaining ->
                        unavailable
                    end,
                    _ = safe_unalias(ReplyAlias),
                    _ = safe_demonitor(RegistryMonitor),
                    drain_cancel_recovery_registry_protocol(Reference),
                    Result
            end
    end.

-spec drain_cancel_recovery_registry_protocol(reference()) -> ok.
drain_cancel_recovery_registry_protocol(Reference) ->
    receive
        {Reference, cancel_recovery_registry_identity, _Registry,
         _Generation} ->
            drain_cancel_recovery_registry_protocol(Reference);
        {Reference, cancel_recovery_registry_registered, _Registry,
         _Generation} ->
            drain_cancel_recovery_registry_protocol(Reference);
        {Reference, cancel_recovery_registry_rejected, _Registry} ->
            drain_cancel_recovery_registry_protocol(Reference);
        {Reference, cancel_recovery_registry_barrier, _Registry,
         _Generation, _Barrier} ->
            drain_cancel_recovery_registry_protocol(Reference);
        {Reference, {cancel_recovery_registry_started, _Registry,
                     _Generation}} ->
            drain_cancel_recovery_registry_protocol(Reference);
        {Reference, {cancel_recovery_registry_contended, _Candidate}} ->
            drain_cancel_recovery_registry_protocol(Reference)
    after 0 ->
        ok
    end.

-spec await_cancel_callback_registration(
    pid(), reference(), reference(), pid(), reference(), reference(),
    reference(), integer(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed.
await_cancel_callback_registration(
    Owner,
    OwnerMonitor,
    Tag,
    Worker,
    WorkerMonitor,
    WorkerReference,
    RegistrationReference,
    Deadline,
    CleanupDeadline
) ->
    Remaining = remaining_milliseconds(Deadline),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            owner_stop_result(
                stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline)
            );
        {Tag,
         {cancel_worker_monitored,
          WorkerReference, RegistrationReference, Owner}} ->
            case monotonic_millisecond() < Deadline of
                true ->
                    Worker ! {WorkerReference, start},
                    await_cancel_callback_outcome(
                        Owner,
                        OwnerMonitor,
                        Worker,
                        WorkerMonitor,
                        WorkerReference,
                        Deadline,
                        CleanupDeadline
                    );
                false ->
                    timeout_stop_result(
                        stop_cancel_worker(
                            Worker, WorkerMonitor, CleanupDeadline
                        )
                    )
            end;
        {Tag,
         {cancel_worker_rejected,
          WorkerReference, RegistrationReference, Owner}} ->
            owner_stop_result(
                stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline)
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            callback_terminal_result(Deadline, cleanup_failed);
        {'EXIT', Worker, _Reason} ->
            await_cancel_callback_registration(
                Owner,
                OwnerMonitor,
                Tag,
                Worker,
                WorkerMonitor,
                WorkerReference,
                RegistrationReference,
                Deadline,
                CleanupDeadline
            )
    after Remaining ->
        timeout_stop_result(
            stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline)
        )
    end.

-spec await_cancel_callback_outcome(
    pid(), reference(), pid(), reference(), reference(), integer(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed.
await_cancel_callback_outcome(
    Owner,
    OwnerMonitor,
    Worker,
    WorkerMonitor,
    WorkerReference,
    Deadline,
    CleanupDeadline
) ->
    Remaining = remaining_milliseconds(Deadline),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            owner_stop_result(
                stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline)
            );
        {WorkerReference,
         {cancel_callback_completed, Outcome, Started, Finished}} ->
            Timely = Started < Deadline andalso Finished < Deadline,
            await_cancel_callback_down(
                Owner,
                OwnerMonitor,
                Worker,
                WorkerMonitor,
                Outcome,
                Timely,
                CleanupDeadline
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            callback_terminal_result(Deadline, cleanup_failed);
        {'EXIT', Worker, _Reason} ->
            await_cancel_callback_outcome(
                Owner,
                OwnerMonitor,
                Worker,
                WorkerMonitor,
                WorkerReference,
                Deadline,
                CleanupDeadline
            )
    after Remaining ->
        timeout_stop_result(
            stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline)
        )
    end.

-spec await_cancel_callback_down(
    pid(), reference(), pid(), reference(),
    not_started | {ok, nil} | {error, 1 | 2 | 3}, boolean(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed.
await_cancel_callback_down(
    Owner,
    OwnerMonitor,
    Worker,
    WorkerMonitor,
    Outcome,
    Timely,
    CleanupDeadline
) ->
    Remaining = remaining_milliseconds(CleanupDeadline),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            owner_stop_result(
                stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline)
            );
        {'DOWN', WorkerMonitor, process, Worker, normal} ->
            completed_callback_result(Outcome, Timely);
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            cleanup_failed;
        {'EXIT', Worker, _Reason} ->
            await_cancel_callback_down(
                Owner,
                OwnerMonitor,
                Worker,
                WorkerMonitor,
                Outcome,
                Timely,
                CleanupDeadline
            )
    after Remaining ->
        _ = stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline),
        cleanup_failed
    end.

-spec invoke_cancel_callback(fun(() -> term())) ->
    {ok, nil} | {error, 1 | 2 | 3}.
invoke_cancel_callback(Callback) ->
    try Callback() of
        {http_body_cleanup_result, {ok, nil}} -> {ok, nil};
        {http_body_cleanup_result, {error, Code}}
                when is_integer(Code), Code >= 1, Code =< 3 -> {error, Code};
        {http_body_cleanup_result, _Invalid} -> {error, 1};
        _OrdinaryCallbackResult -> {ok, nil}
    catch
        _:_ -> {error, 1}
    end.

-spec completed_callback_result(
    not_started | {ok, nil} | {error, 1 | 2 | 3}, boolean()
) -> {completed, {ok, nil} | {error, 1 | 2 | 3}} | timed_out.
completed_callback_result(not_started, _Timely) -> timed_out;
completed_callback_result(_Outcome, false) -> timed_out;
completed_callback_result({ok, nil} = Outcome, true) -> {completed, Outcome};
completed_callback_result({error, Code} = Outcome, true)
        when is_integer(Code), Code >= 1, Code =< 3 -> {completed, Outcome}.

-spec callback_terminal_result(integer(), cleanup_failed) ->
    timed_out | cleanup_failed.
callback_terminal_result(Deadline, BeforeDeadline) ->
    case monotonic_millisecond() < Deadline of
        true -> BeforeDeadline;
        false -> timed_out
    end.

-spec timeout_stop_result(confirmed | unconfirmed) ->
    timed_out | cleanup_failed.
timeout_stop_result(confirmed) -> timed_out;
timeout_stop_result(unconfirmed) -> cleanup_failed.

-spec owner_stop_result(confirmed | unconfirmed) ->
    owner_down | owner_cleanup_failed.
owner_stop_result(confirmed) -> owner_down;
owner_stop_result(unconfirmed) -> owner_cleanup_failed.

-spec stop_cancel_worker(pid(), reference(), integer()) ->
    confirmed | unconfirmed.
stop_cancel_worker(Worker, WorkerMonitor, CleanupDeadline) ->
    exit(Worker, kill),
    Remaining = remaining_milliseconds(CleanupDeadline),
    receive
        {'DOWN', WorkerMonitor, process, Worker, _Reason} -> confirmed
    after Remaining ->
        unconfirmed
    end.

-spec cancel_phase_result(
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed
) -> {ok, nil} | {error, 1 | 2} | owner_down.
cancel_phase_result({completed, Result}) -> Result;
cancel_phase_result(timed_out) -> {error, 2};
cancel_phase_result(cleanup_failed) -> {error, 1};
cancel_phase_result(owner_down) -> owner_down;
cancel_phase_result(owner_cleanup_failed) -> owner_down.

-spec cancel_phase_outcome(
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    timed_out | cleanup_failed | owner_down | owner_cleanup_failed
) -> {{ok, nil} | {error, 1 | 2 | 3}, alive | dead}.
cancel_phase_outcome({completed, Result}) -> {Result, alive};
cancel_phase_outcome(timed_out) -> {{error, 2}, alive};
cancel_phase_outcome(cleanup_failed) -> {{error, 1}, alive};
cancel_phase_outcome(owner_down) -> {{error, 3}, dead};
cancel_phase_outcome(owner_cleanup_failed) -> {{error, 1}, dead}.

%% The API caller accepts a result only after consuming its original monitor
%% DOWN for the guardian and every registered callback worker. Its worker
%% monitors carry a private tag, so this receive loop cannot steal an
%% unrelated monitor signal from application code.
-spec await_cancel_guardian(
    reference(), pid(), reference(), integer(), integer(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    already_claimed |
    {already_claimed_timeout, confirmed | unconfirmed} |
    {timed_out, confirmed | unconfirmed} |
    {failed, confirmed | unconfirmed}.
await_cancel_guardian(
    Tag,
    Guardian,
    GuardianMonitor,
    WaitDeadline,
    LoserDeadline,
    TerminationDeadline
) ->
    await_cancel_guardian_loop(
        Tag,
        Guardian,
        GuardianMonitor,
        up,
        [],
        pending,
        WaitDeadline,
        LoserDeadline,
        TerminationDeadline
    ).

-spec await_cancel_guardian_loop(
    reference(), pid(), reference(), up | {down, term()}, list(),
    pending | already_claimed | {result, {ok, nil} | {error, 1 | 2 | 3}},
    integer(), integer(), integer()
) ->
    {completed, {ok, nil} | {error, 1 | 2 | 3}} |
    already_claimed |
    {already_claimed_timeout, confirmed | unconfirmed} |
    {timed_out, confirmed | unconfirmed} |
    {failed, confirmed | unconfirmed}.
await_cancel_guardian_loop(
    Tag,
    Guardian,
    GuardianMonitor,
    GuardianState,
    Workers,
    ResultState,
    WaitDeadline,
    LoserDeadline,
    TerminationDeadline
) ->
    case completed_cancel_guardian_result(
        GuardianState, Workers, ResultState
    ) of
        {done, Result} ->
            Result;
        guardian_failed ->
            Confirmation = stop_cancel_tree(
                Tag,
                Guardian,
                GuardianMonitor,
                GuardianState,
                Workers,
                TerminationDeadline
            ),
            {failed, Confirmation};
        waiting ->
            ActiveDeadline = cancel_wait_deadline(
                ResultState,
                WaitDeadline,
                LoserDeadline,
                TerminationDeadline
            ),
            Remaining = remaining_milliseconds(ActiveDeadline),
            receive
                {Tag,
                 {cancel_worker_registered,
                  WorkerReference, Worker, RegistrationReference}}
                        when is_reference(WorkerReference), is_pid(Worker),
                             is_reference(RegistrationReference) ->
                    case lists:keyfind(WorkerReference, 1, Workers) of
                        false ->
                            case safe_monitor(
                                Worker,
                                [{tag, {Tag, cancel_worker_down}}]
                            ) of
                                {ok, WorkerMonitor} ->
                                    Guardian ! {
                                        Tag,
                                        {cancel_worker_monitored,
                                         WorkerReference,
                                         RegistrationReference,
                                         self()}
                                    },
                                    await_cancel_guardian_loop(
                                        Tag,
                                        Guardian,
                                        GuardianMonitor,
                                        GuardianState,
                                        [{WorkerReference, Worker,
                                          WorkerMonitor, up} | Workers],
                                        ResultState,
                                        WaitDeadline,
                                        LoserDeadline,
                                        TerminationDeadline
                                    );
                                error ->
                                    exit(Worker, kill),
                                    _ = stop_cancel_tree(
                                        Tag,
                                        Guardian,
                                        GuardianMonitor,
                                        GuardianState,
                                        Workers,
                                        TerminationDeadline
                                    ),
                                    {failed, unconfirmed}
                            end;
                        _Duplicate ->
                            Confirmation = stop_cancel_tree(
                                Tag,
                                Guardian,
                                GuardianMonitor,
                                GuardianState,
                                Workers,
                                TerminationDeadline
                            ),
                            {failed, Confirmation}
                    end;
                {Tag, {cancel_result, Result}}
                        when Result =:= {ok, nil};
                             Result =:= {error, 1};
                             Result =:= {error, 2};
                             Result =:= {error, 3} ->
                    case ResultState of
                        pending ->
                            await_cancel_guardian_loop(
                                Tag,
                                Guardian,
                                GuardianMonitor,
                                GuardianState,
                                Workers,
                                {result, Result},
                                WaitDeadline,
                                LoserDeadline,
                                TerminationDeadline
                            );
                        _ ->
                            Confirmation = stop_cancel_tree(
                                Tag,
                                Guardian,
                                GuardianMonitor,
                                GuardianState,
                                Workers,
                                TerminationDeadline
                            ),
                            {failed, Confirmation}
                    end;
                {Tag, already_claimed} ->
                    case ResultState of
                        pending ->
                            await_cancel_guardian_loop(
                                Tag,
                                Guardian,
                                GuardianMonitor,
                                GuardianState,
                                Workers,
                                already_claimed,
                                WaitDeadline,
                                LoserDeadline,
                                TerminationDeadline
                            );
                        _ ->
                            Confirmation = stop_cancel_tree(
                                Tag,
                                Guardian,
                                GuardianMonitor,
                                GuardianState,
                                Workers,
                                TerminationDeadline
                            ),
                            {failed, Confirmation}
                    end;
                {'DOWN', GuardianMonitor, process, Guardian, Reason} ->
                    await_cancel_guardian_loop(
                        Tag,
                        Guardian,
                        GuardianMonitor,
                        {down, Reason},
                        Workers,
                        ResultState,
                        WaitDeadline,
                        LoserDeadline,
                        TerminationDeadline
                    );
                {{Tag, cancel_worker_down}, WorkerMonitor,
                 process, Worker, Reason} ->
                    NextWorkers = mark_cancel_worker_down(
                        Worker, WorkerMonitor, Reason, Workers
                    ),
                    await_cancel_guardian_loop(
                        Tag,
                        Guardian,
                        GuardianMonitor,
                        GuardianState,
                        NextWorkers,
                        ResultState,
                        WaitDeadline,
                        LoserDeadline,
                        TerminationDeadline
                    )
            after Remaining ->
                Confirmation = stop_cancel_tree(
                    Tag,
                    Guardian,
                    GuardianMonitor,
                    GuardianState,
                    Workers,
                    TerminationDeadline
                ),
                case ResultState of
                    pending -> {timed_out, Confirmation};
                    already_claimed ->
                        {already_claimed_timeout, Confirmation};
                    {result, _} -> {failed, Confirmation}
                end
            end
    end.

-spec completed_cancel_guardian_result(
    up | {down, term()}, list(),
    pending | already_claimed | {result, {ok, nil} | {error, 1 | 2 | 3}}
) ->
    waiting | guardian_failed | {done, already_claimed} |
    {done, {completed, {ok, nil} | {error, 1 | 2 | 3}}}.
completed_cancel_guardian_result(
    {down, _Reason}, Workers, {result, Result}
) ->
    case all_cancel_workers_down(Workers) of
        true -> {done, {completed, Result}};
        false -> waiting
    end;
completed_cancel_guardian_result(
    {down, normal}, Workers, already_claimed
) ->
    case all_cancel_workers_down(Workers) of
        true -> {done, already_claimed};
        false -> waiting
    end;
completed_cancel_guardian_result({down, normal}, _Workers, pending) ->
    waiting;
completed_cancel_guardian_result({down, _Reason}, _Workers, pending) ->
    guardian_failed;
completed_cancel_guardian_result({down, _Reason}, _Workers, already_claimed) ->
    guardian_failed;
completed_cancel_guardian_result(up, _Workers, _Result) ->
    waiting.

-spec cancel_wait_deadline(
    pending | already_claimed | {result, term()}, integer(), integer(), integer()
) -> integer().
cancel_wait_deadline(pending, WaitDeadline, _LoserDeadline, _Termination) ->
    WaitDeadline;
cancel_wait_deadline(already_claimed, _WaitDeadline, LoserDeadline, _Termination) ->
    LoserDeadline;
cancel_wait_deadline({result, _}, _WaitDeadline, _LoserDeadline, Termination) ->
    Termination.

-spec mark_cancel_worker_down(pid(), reference(), term(), list()) -> list().
mark_cancel_worker_down(Worker, Monitor, Reason, Workers) ->
    lists:map(fun
        ({Reference, EntryWorker, EntryMonitor, up})
                when EntryWorker =:= Worker, EntryMonitor =:= Monitor ->
            {Reference, Worker, Monitor, {down, Reason}};
        (State) -> State
    end, Workers).

-spec all_cancel_workers_down(list()) -> boolean().
all_cancel_workers_down(Workers) ->
    lists:all(fun
        ({_Reference, _Worker, _Monitor, {down, _Reason}}) -> true;
        (_) -> false
    end, Workers).

%% Stops are broadcast before either process is joined. Every original monitor
%% is then consumed against the same absolute termination deadline. Once the
%% guardian DOWN is observed, same-sender ordering lets us collect any final
%% registration which was already sent but not selected by the wait loop.
-spec stop_cancel_tree(
    reference(), pid(), reference(), up | {down, term()}, list(), integer()
) -> confirmed | unconfirmed.
stop_cancel_tree(
    Tag,
    Guardian,
    GuardianMonitor,
    GuardianState,
    Workers,
    TerminationDeadline
) ->
    case GuardianState of
        up -> exit(Guardian, kill);
        {down, _} -> ok
    end,
    lists:foreach(fun
        ({_Reference, Worker, _Monitor, up}) -> exit(Worker, kill);
        (_) -> ok
    end, Workers),
    {WorkersConfirmed, JoinedWorkers} = join_cancel_workers(
        Tag, Workers, TerminationDeadline, true, []
    ),
    GuardianConfirmed = join_cancel_guardian(
        Guardian,
        GuardianMonitor,
        GuardianState,
        TerminationDeadline
    ),
    {LateWorkers, LateMonitorsConfirmed} = collect_late_cancel_workers(
        Tag, Guardian, [], true
    ),
    lists:foreach(fun
        ({_Reference, Worker, _Monitor, up}) -> exit(Worker, kill)
    end, LateWorkers),
    {LateConfirmed, JoinedLateWorkers} = join_cancel_workers(
        Tag, LateWorkers, TerminationDeadline, true, []
    ),
    clear_cancel_monitors(JoinedWorkers ++ JoinedLateWorkers),
    _ = safe_demonitor(GuardianMonitor),
    drain_cancel_protocol(Tag),
    case {
        WorkersConfirmed,
        GuardianConfirmed,
        LateConfirmed andalso LateMonitorsConfirmed
    } of
        {true, true, true} -> confirmed;
        _ -> unconfirmed
    end.

-spec join_cancel_workers(
    reference(), list(), integer(), boolean(), list()
) -> {boolean(), list()}.
join_cancel_workers(_Tag, [], _Deadline, Confirmed, Joined) ->
    {Confirmed, Joined};
join_cancel_workers(
    Tag,
    [{Reference, Worker, Monitor, up} = State | Rest],
    Deadline,
    Confirmed,
    Joined
) ->
    Remaining = remaining_milliseconds(Deadline),
    receive
        {{Tag, cancel_worker_down}, Monitor, process, Worker, Reason} ->
            join_cancel_workers(
                Tag,
                Rest,
                Deadline,
                Confirmed,
                [{Reference, Worker, Monitor, {down, Reason}} | Joined]
            )
    after Remaining ->
        join_cancel_workers(
            Tag, Rest, Deadline, false,
            [State | Joined]
        )
    end;
join_cancel_workers(
    Tag, [State | Rest], Deadline, Confirmed, Joined
) ->
    join_cancel_workers(
        Tag, Rest, Deadline, Confirmed, [State | Joined]
    ).

-spec join_cancel_guardian(
    pid(), reference(), up | {down, term()}, integer()
) -> boolean().
join_cancel_guardian(_Guardian, _Monitor, {down, _Reason}, _Deadline) ->
    true;
join_cancel_guardian(Guardian, Monitor, up, Deadline) ->
    Remaining = remaining_milliseconds(Deadline),
    receive
        {'DOWN', Monitor, process, Guardian, _Reason} -> true
    after Remaining ->
        false
    end.

-spec collect_late_cancel_workers(reference(), pid(), list(), boolean()) ->
    {list(), boolean()}.
collect_late_cancel_workers(Tag, Guardian, Workers, Confirmed) ->
    receive
        {Tag,
         {cancel_worker_registered,
          WorkerReference, Worker, _RegistrationReference}}
                when is_reference(WorkerReference), is_pid(Worker) ->
            case safe_monitor(
                Worker, [{tag, {Tag, cancel_worker_down}}]
            ) of
                {ok, WorkerMonitor} ->
                    collect_late_cancel_workers(
                        Tag,
                        Guardian,
                        [{WorkerReference, Worker, WorkerMonitor, up}
                         | Workers],
                        Confirmed
                    );
                error ->
                    exit(Worker, kill),
                    collect_late_cancel_workers(
                        Tag, Guardian, Workers, false
                    )
            end;
        {Tag, {cancel_result, _Result}} ->
            collect_late_cancel_workers(
                Tag, Guardian, Workers, Confirmed
            );
        {Tag, {cancel_worker_rejected, _Reference, _Registration,
               _Owner}} ->
            collect_late_cancel_workers(
                Tag, Guardian, Workers, Confirmed
            );
        {Tag, already_claimed} ->
            collect_late_cancel_workers(
                Tag, Guardian, Workers, Confirmed
            )
    after 0 ->
        {Workers, Confirmed}
    end.

-spec clear_cancel_monitors(list()) -> ok.
clear_cancel_monitors(Workers) ->
    lists:foreach(fun
        ({_Reference, _Worker, Monitor, _State}) ->
            _ = safe_demonitor(Monitor),
            ok
    end, Workers),
    ok.

-spec drain_cancel_protocol(reference()) -> ok.
drain_cancel_protocol(Tag) ->
    receive
        {Tag, {cancel_worker_registered, _Reference, Worker, _Ack}}
                when is_pid(Worker) ->
            exit(Worker, kill),
            drain_cancel_protocol(Tag);
        {Tag, {cancel_result, _Result}} ->
            drain_cancel_protocol(Tag);
        {Tag, {cancel_worker_rejected, _Reference, _Registration,
               _Owner}} ->
            drain_cancel_protocol(Tag);
        {Tag, {cancel_recovery_worker_rejected, _Reference,
               _Registration, _Recovery}} ->
            drain_cancel_protocol(Tag);
        {Tag, already_claimed} ->
            drain_cancel_protocol(Tag);
        {{Tag, cancel_worker_down}, _Monitor, process, _Worker, _Reason} ->
            drain_cancel_protocol(Tag)
    after 0 ->
        ok
    end.

-spec remaining_milliseconds(integer()) -> non_neg_integer().
remaining_milliseconds(Deadline) ->
    erlang:min(
        ?MAX_TIMEOUT_MILLISECONDS,
        erlang:max(0, Deadline - monotonic_millisecond())
    ).

-spec monotonic_millisecond() -> integer().
monotonic_millisecond() ->
    erlang:monotonic_time(millisecond).

-spec mark_cancelled(atomics:atomics_ref()) -> boolean().
mark_cancelled(Handle) ->
    try atomics:compare_exchange(Handle, 1, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec claim_cancel(atomics:atomics_ref(), integer()) -> boolean().
claim_cancel(Handle, ClaimToken)
        when is_integer(ClaimToken), ClaimToken >= 6 ->
    try atomics:compare_exchange(Handle, 1, 0, ClaimToken) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec finish_owned_cancel(
    atomics:atomics_ref(), integer(), {ok, nil} | {error, 1 | 2 | 3}
) -> ok.
finish_owned_cancel(Handle, ClaimToken, Result) ->
    Value = cancel_result_value(Result),
    try atomics:compare_exchange(Handle, 1, ClaimToken, Value) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec cancel_result_value({ok, nil} | {error, integer()}) -> 2 | 3 | 4 | 5.
cancel_result_value({ok, nil}) -> 2;
cancel_result_value({error, 2}) -> 4;
cancel_result_value({error, 3}) -> 5;
cancel_result_value(_) -> 3.

-spec cancel_result(atomics:atomics_ref()) ->
    none | {some, {ok, nil} | {error, 1 | 2 | 3}}.
cancel_result(Handle) ->
    try atomics:get(Handle, 1) of
        2 -> {some, {ok, nil}};
        3 -> {some, {error, 1}};
        4 -> {some, {error, 2}};
        5 -> {some, {error, 3}};
        _ -> none
    catch
        _:_ -> {some, {error, 1}}
    end.

-spec cancel_claim_state(atomics:atomics_ref(), integer()) ->
    unclaimed | owned | other_pending | invalid |
    {completed, {ok, nil} | {error, 1 | 2 | 3}}.
cancel_claim_state(Handle, ClaimToken) ->
    try atomics:get(Handle, 1) of
        0 -> unclaimed;
        ClaimToken -> owned;
        2 -> {completed, {ok, nil}};
        3 -> {completed, {error, 1}};
        4 -> {completed, {error, 2}};
        5 -> {completed, {error, 3}};
        _ -> other_pending
    catch
        _:_ -> invalid
    end.

-spec claim_release_observer(atomics:atomics_ref()) -> boolean().
claim_release_observer(Handle) ->
    try atomics:compare_exchange(Handle, 2, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec finish_release_observer(atomics:atomics_ref()) -> ok.
finish_release_observer(Handle) ->
    try atomics:compare_exchange(Handle, 2, 1, 2) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec fail_release_observer(atomics:atomics_ref()) -> ok.
fail_release_observer(Handle) ->
    try atomics:compare_exchange(Handle, 2, 1, 3) of
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec release_observer_state(atomics:atomics_ref()) ->
    pending | running | complete | failed.
release_observer_state(Handle) ->
    try atomics:get(Handle, 2) of
        0 -> pending;
        1 -> running;
        2 -> complete;
        _ -> failed
    catch
        _:_ -> failed
    end.

-spec await_cancel_until(atomics:atomics_ref(), integer()) ->
    {ok, nil} | {error, 1 | 2 | 3}.
await_cancel_until(Handle, Deadline) ->
    case await_release_until(Handle, Deadline) of
        {some, Result} -> Result;
        none -> known_cancel_failure(Handle, {error, 2})
    end.

-spec known_cancel_failure(atomics:atomics_ref(), {error, 1 | 2}) ->
    {error, 1 | 2 | 3}.
known_cancel_failure(Handle, Fallback) ->
    case cancel_result(Handle) of
        {some, {error, _} = Failure} -> Failure;
        _ -> Fallback
    end.

-spec await_release(atomics:atomics_ref(), integer()) ->
    none | {some, {ok, nil} | {error, 1 | 2 | 3}}.
await_release(Handle, Timeout)
        when is_integer(Timeout), Timeout >= 0,
             Timeout =< ?MAX_TIMEOUT_MILLISECONDS ->
    Deadline = monotonic_millisecond() + Timeout,
    await_release_until(Handle, Deadline);
await_release(_, _) -> none.

-spec await_release_until(atomics:atomics_ref(), integer()) ->
    none | {some, {ok, nil} | {error, 1 | 2 | 3}}.
await_release_until(Handle, Deadline) ->
    case cancel_result(Handle) of
        {some, _Result} = Completed ->
            case await_cancel_recovery_barrier(Handle, Deadline) of
                confirmed -> Completed;
                unconfirmed -> none
            end;
        none ->
            Remaining = remaining_milliseconds(Deadline),
            case Remaining of
                0 -> none;
                _ ->
                    receive
                    after erlang:min(1, Remaining) ->
                        await_release_until(Handle, Deadline)
                    end
            end
    end.

-spec is_cancelled(atomics:atomics_ref()) -> boolean().
is_cancelled(Handle) ->
    try atomics:get(Handle, 1) of
        0 -> false;
        _ -> true
    catch
        _:_ -> true
    end.

-spec file_size(binary()) -> {ok, non_neg_integer()} | {error, nil}.
file_size(Path) when is_binary(Path) ->
    with_file(Path, fun(File) ->
        case file:position(File, eof) of
            {ok, Size} when is_integer(Size), Size >= 0 -> {ok, Size};
            _ -> {error, nil}
        end
    end);
file_size(_) ->
    {error, nil}.

-spec read_file_chunk(binary(), non_neg_integer(), pos_integer()) ->
    {ok, binary()} | {error, nil}.
read_file_chunk(Path, Offset, Maximum)
    when is_binary(Path), is_integer(Offset), Offset >= 0,
         is_integer(Maximum), Maximum > 0 ->
    with_file(Path, fun(File) ->
        case file:pread(File, Offset, Maximum) of
            eof -> {ok, <<>>};
            {ok, Bytes} when is_binary(Bytes) -> {ok, Bytes};
            _ -> {error, nil}
        end
    end);
read_file_chunk(_, _, _) ->
    {error, nil}.

-spec with_file(binary(), fun((file:io_device()) -> term())) -> term().
with_file(Path, Fun) ->
    try file:open(Path, [read, binary, raw]) of
        {ok, File} ->
            try Fun(File)
            after
                _ = file:close(File)
            end;
        {error, _Reason} ->
            {error, nil}
    catch
        _:_ -> {error, nil}
    end.
