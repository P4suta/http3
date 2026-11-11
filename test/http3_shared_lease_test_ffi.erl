%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_shared_lease_test_ffi).

-include_lib("eunit/include/eunit.hrl").


-define(SCENARIO_TIMEOUT, 20000).
-define(CLEANUP_TIMEOUT, 12000).

concurrent_candidates_deduplicate_and_join_loser_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(2, 2, 2000),
    First = new_candidate(Lifecycle, candidate_a, connection_a, Deadline),
    Second = new_candidate(Lifecycle, candidate_b, connection_b, Deadline),
    FirstActivation = start_activation(activation_a, First, true, Deadline),
    SecondActivation = start_activation(activation_b, Second, true, Deadline),
    try
        release_activation_start(FirstActivation),
        release_activation_start(SecondActivation),
        {FirstConnection, FirstLease} = activation_result(
            FirstActivation, Deadline
        ),
        {SecondConnection, SecondLease} = activation_result(
            SecondActivation, Deadline
        ),
        require(FirstConnection =:= SecondConnection, deduplication_failed),
        expect_ok(http_client_ffi:adopt_http3_lease_within(
            FirstLease, self(), remaining(Deadline)
        ), first_lease_adoption_failed),
        expect_ok(http_client_ffi:adopt_http3_lease_within(
            SecondLease, self(), remaining(Deadline)
        ), second_lease_adoption_failed),
        finish_activation(FirstActivation, Deadline),
        finish_activation(SecondActivation, Deadline),
        {Winner, Loser} = case FirstConnection of
            connection_a -> {First, Second};
            connection_b -> {Second, First};
            _ -> fail(unexpected_connection_identity)
        end,
        require(candidate_alive(Winner), winner_closed_early),
        await_candidate_close(Loser, Deadline),
        expect_ok(http_client_ffi:release_http3_lease_within(
            FirstLease, true, remaining(Deadline)
        ), first_lease_release_failed),
        expect_ok(http_client_ffi:release_http3_lease_within(
            SecondLease, true, remaining(Deadline)
        ), second_lease_release_failed),
        require(
            await_shared_snapshot(
                Lifecycle, {1, 1, 0, 0, 0, 1}, Deadline
            ),
            shared_idle_snapshot_failed
        ),
        expect_ok(
            http_client_ffi:close_before(Lifecycle, Deadline, true),
            deduplication_close_failed
        ),
        await_candidate_close(Winner, Deadline)
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_activation(FirstActivation, CleanupDeadline),
        cleanup_activation(SecondActivation, CleanupDeadline),
        cleanup_candidates([First, Second], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

logical_full_scales_to_a_new_physical_candidate_test() ->
    Deadline = scenario_deadline(),
    RequestResources = http_server_ffi:new_resource_controller(200, 1),
    try
        RequestAdmissions = acquire_request_admissions(
            RequestResources, 101, [], Deadline
        ),
        try
            exercise_logical_scale_out(
                RequestResources, Deadline
            )
        after
            release_request_admissions(
                RequestResources, RequestAdmissions
            ),
            require(
                http_server_ffi:resource_snapshot(RequestResources)
                    =:= {0, 0},
                aggregate_request_admission_not_released
            )
        end
    after
        nil = http_server_ffi:resource_stop(RequestResources)
    end.

exercise_logical_scale_out(RequestResources, Deadline) ->
    Lifecycle = http_client_ffi:new_lifecycle(2, 2, 2000),
    try
        First = new_candidate(
            Lifecycle, scale_a, scale_connection_a, Deadline
        ),
        try
            Second = new_candidate(
                Lifecycle, scale_b, scale_connection_b, Deadline
            ),
            try
                {scale_connection_a, FirstLease} = activate(
                    First, true, Deadline
                ),
                AdditionalLeases = checkout_many(
                    Lifecycle, 99, [], Deadline
                ),
                require(
                    http_client_ffi:checkout_http3_shared_within(
                        Lifecycle, pool_key(), remaining(Deadline)
                    ) =:= {error, 0},
                    logical_full_did_not_request_scale_out
                ),
                {scale_connection_b, SecondLease} = activate(
                    Second, true, Deadline
                ),
                require(
                    http_server_ffi:resource_snapshot(RequestResources)
                        =:= {101, 0},
                    aggregate_request_admission_not_held
                ),
                require(
                    http_client_ffi:http3_shared_snapshot(Lifecycle)
                        =:= {2, 2, 0, 0, 101, 0},
                    scale_out_snapshot_failed
                ),
                release_many([FirstLease | AdditionalLeases], Deadline),
                expect_ok(http_client_ffi:release_http3_lease_within(
                    SecondLease, true, remaining(Deadline)
                ), scale_out_release_failed),
                require(
                    await_shared_snapshot(
                        Lifecycle, {2, 2, 0, 0, 0, 2}, Deadline
                    ),
                    scale_out_idle_snapshot_failed
                ),
                expect_ok(
                    http_client_ffi:close_before(Lifecycle, Deadline, true),
                    scale_out_close_failed
                ),
                await_candidate_close(First, Deadline),
                await_candidate_close(Second, Deadline)
            after
                cleanup_candidates([First, Second], cleanup_deadline())
            end
        after
            cleanup_candidates([First], cleanup_deadline())
        end
    after
        close_lifecycle(Lifecycle, cleanup_deadline())
    end.

without_pooling_never_shares_physical_candidates_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(2, 2, 2000),
    First = new_candidate(Lifecycle, unpooled_a, unpooled_connection_a, Deadline),
    Second = new_candidate(
        Lifecycle, unpooled_b, unpooled_connection_b, Deadline
    ),
    try
        {FirstConnection, FirstLease} = activate(First, false, Deadline),
        {SecondConnection, SecondLease} = activate(Second, false, Deadline),
        require(
            FirstConnection =:= unpooled_connection_a
                andalso SecondConnection =:= unpooled_connection_b,
            unpooled_candidate_was_shared
        ),
        require(
            http_client_ffi:http3_shared_snapshot(Lifecycle)
                =:= {2, 2, 0, 0, 2, 0},
            unpooled_active_snapshot_failed
        ),
        expect_ok(http_client_ffi:release_http3_lease_within(
            FirstLease, false, remaining(Deadline)
        ), first_unpooled_release_failed),
        expect_ok(http_client_ffi:release_http3_lease_within(
            SecondLease, false, remaining(Deadline)
        ), second_unpooled_release_failed),
        await_candidate_close(First, Deadline),
        await_candidate_close(Second, Deadline),
        require(
            await_shared_snapshot(
                Lifecycle, {0, 0, 0, 0, 0, 0}, Deadline
            ),
            unpooled_cleanup_snapshot_failed
        )
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([First, Second], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

close_deadline_is_bounded_and_never_extended_test() ->
    Now = 100000,
    LongRequestDeadline = Now + 3600000,
    First = http_client_ffi:http3_close_deadline_probe(
        accepting, none, LongRequestDeadline, Now
    ),
    RepeatedDrain = http_client_ffi:http3_close_deadline_probe(
        closing, First, LongRequestDeadline, Now + 500
    ),
    RepeatedUnregister = http_client_ffi:http3_close_deadline_probe(
        closing, RepeatedDrain, LongRequestDeadline, Now + 5000
    ),
    require(First =:= Now + 10000, close_deadline_not_bounded),
    require(RepeatedDrain =:= First, repeated_drain_extended_deadline),
    require(
        RepeatedUnregister =:= First,
        repeated_unregister_extended_deadline
    ).

deduplicated_nonresponsive_candidate_is_forced_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(2, 2, 60000),
    Winner = new_stubborn_candidate(
        Lifecycle, stubborn_dedupe_winner, stubborn_connection, Deadline
    ),
    Loser = new_stubborn_candidate(
        Lifecycle, stubborn_dedupe_loser, discarded_connection, Deadline
    ),
    try
        {stubborn_connection, FirstLease} = activate(Winner, true, Deadline),
        Started = erlang:monotonic_time(millisecond),
        {stubborn_connection, SecondLease} = activate(Loser, true, Deadline),
        CloseDeadline = await_close_ignored(
            stubborn_dedupe_loser, Deadline
        ),
        CloseObservedAt = erlang:monotonic_time(millisecond),
        require(
            CloseDeadline > Started
                andalso CloseDeadline =< CloseObservedAt + 10000
                andalso CloseDeadline < Deadline,
            dedupe_loser_close_deadline_not_bounded
        ),
        {LoserRegistration, _, _, _, _} = Loser,
        expect_ok(
            http_client_ffi:retire_http3_candidate_within(
                LoserRegistration, remaining(Deadline)
            ),
            repeated_loser_retirement_failed
        ),
        await_forced_candidate_down(Loser, Deadline),
        require(
            await_registered_count(Lifecycle, 1, Deadline),
            dedupe_loser_capacity_not_released
        ),
        expect_ok(http_client_ffi:release_http3_lease_within(
            FirstLease, true, remaining(Deadline)
        ), stubborn_first_lease_release_failed),
        expect_ok(http_client_ffi:release_http3_lease_within(
            SecondLease, true, remaining(Deadline)
        ), stubborn_second_lease_release_failed),
        {_WinnerRegistration, WinnerOwner, WinnerMonitor, _WinnerLabel,
            _WinnerConnection} = Winner,
        cleanup_process(WinnerOwner, WinnerMonitor, Deadline),
        require(
            await_registered_count(Lifecycle, 0, Deadline),
            stubborn_dedupe_cleanup_not_converged
        ),
        require(
            await_shared_snapshot(
                Lifecycle, {0, 0, 0, 0, 0, 0}, Deadline
            ),
            stubborn_dedupe_shared_state_not_released
        )
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([Winner, Loser], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

nonreusable_nonresponsive_shared_owner_is_forced_test() ->
    exercise_nonresponsive_shared_close(nonreusable_last_release).

idle_nonresponsive_shared_owner_is_forced_test() ->
    exercise_nonresponsive_shared_close(idle_eviction).

repeated_unregister_nonresponsive_shared_owner_is_forced_test() ->
    exercise_nonresponsive_shared_close(live_unregister).

one_bad_lease_drains_only_after_its_sibling_finishes_test() ->
    exercise_sibling_drain(holder_down),
    exercise_sibling_drain(nonreusable_release).

expired_adoption_keeps_original_holder_and_drops_late_reply_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    Candidate = new_candidate(
        Lifecycle, adoption, adoption_connection, Deadline
    ),
    Holder = spawn(fun idle/0),
    HolderMonitor = monitor(process, Holder),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    try
        {adoption_connection, Lease} = activate(Candidate, true, Deadline),
        true = erlang:suspend_process(LifecycleOwner),
        Probe = start_adoption_timeout_probe(
            Lease, Holder, Lifecycle, Deadline
        ),
        require(
            adoption_timeout_result(Probe, Deadline),
            adoption_timeout_not_observed
        ),
        true = erlang:resume_process(LifecycleOwner),
        require(
            adoption_probe_synchronized(Probe, Deadline),
            adoption_commit_not_observed
        ),
        require(
            adoption_probe_mailbox_empty(Probe, Deadline),
            stale_adoption_reply
        ),
        finish_adoption_probe(Probe, Deadline),
        exit(Holder, kill),
        await_down(Holder, HolderMonitor, Deadline),
        require(candidate_alive(Candidate), expired_adoption_changed_holder),
        expect_ok(http_client_ffi:release_http3_lease_within(
            Lease, false, remaining(Deadline)
        ), original_holder_release_failed),
        await_candidate_close(Candidate, Deadline),
        require(
            await_shared_snapshot(
                Lifecycle, {0, 0, 0, 0, 0, 0}, Deadline
            ),
            adopted_holder_cleanup_failed
        )
    after
        ensure_resumed(LifecycleOwner),
        CleanupDeadline = cleanup_deadline(),
        cleanup_process(Holder, HolderMonitor, CleanupDeadline),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

retire_timeout_drops_late_reply_without_crashing_lifecycle_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    Candidate = new_candidate(
        Lifecycle, retire_timeout, retire_timeout_connection, Deadline
    ),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    {Registration, PhysicalOwner, PhysicalMonitor, _Label, _Connection} =
        Candidate,
    try
        true = erlang:suspend_process(LifecycleOwner),
        retire_timeout_while_lifecycle_suspended(
            Lifecycle, LifecycleOwner, Registration, Deadline
        ),
        require(is_process_alive(LifecycleOwner), lifecycle_crashed_on_late_reply),
        await_down(PhysicalOwner, PhysicalMonitor, Deadline),
        flush_physical_observation(retire_timeout),
        require(
            await_registered_count(Lifecycle, 0, Deadline),
            retired_candidate_capacity_not_released
        )
    after
        ensure_resumed(LifecycleOwner),
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

retire_timeout_while_lifecycle_suspended(
    Lifecycle, LifecycleOwner, Registration, Deadline
) ->
    Parent = self(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = http_client_ffi:retire_http3_candidate_within(Registration, 0),
        Parent ! {retire_timeout_result, Result},
        receive continue_after_retire_timeout -> ok
        after remaining(Deadline) -> fail(retire_probe_continue_timeout)
        end,
        Snapshot = http_client_ffi:lifecycle_snapshot(Lifecycle),
        {messages, Messages} = process_info(self(), messages),
        Parent ! {retire_timeout_synchronized, Snapshot, Messages =:= []}
    end),
    try
        receive
            {retire_timeout_result, {error, 1}} -> ok;
            {retire_timeout_result, _} -> fail(retire_timeout_not_observed)
        after remaining(Deadline) -> fail(retire_timeout_result_timeout)
        end,
        true = erlang:resume_process(LifecycleOwner),
        Caller ! continue_after_retire_timeout,
        receive
            {retire_timeout_synchronized, _SafeSnapshot, true} -> ok;
            {retire_timeout_synchronized, _SafeSnapshot, false} ->
                fail(stale_retire_reply)
        after remaining(Deadline) -> fail(retire_timeout_sync_timeout)
        end,
        await_down(Caller, CallerMonitor, Deadline)
    after
        ensure_resumed(LifecycleOwner),
        cleanup_process(Caller, CallerMonitor, cleanup_deadline())
    end.

late_activated_candidate_is_joined_instead_of_becoming_idle_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    Candidate = new_candidate(
        Lifecycle, late_activation, late_connection, Deadline
    ),
    try
        {Registration, _Owner, _Monitor, _Label, _Connection} = Candidate,
        {http_client_registration, LifecycleOwner, Token} = Registration,
        LeaseReference = make_ref(),
        LifecycleOwner ! {activate_http3_candidate, self(), self(),
            LeaseReference, Token, pool_key(), late_connection, true,
            Deadline},
        receive
            {LeaseReference, {ok, {late_connection, _Lease}}} -> ok;
            {LeaseReference, _SafeFailure} -> fail(late_activation_failed)
        after remaining(Deadline) ->
            fail(late_activation_timeout)
        end,
        LifecycleOwner ! {abandon_http3_lease, self(), LeaseReference},
        LifecycleOwner ! {retire_http3_candidate, Token, Deadline},
        await_candidate_close(Candidate, Deadline),
        require(
            await_shared_snapshot(
                Lifecycle, {0, 0, 0, 0, 0, 0}, Deadline
            ),
            late_activation_not_reclaimed
        )
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

terminal_close_owns_every_lease_guard_and_joins_once_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    Candidate = new_candidate(
        Lifecycle, terminal_close, terminal_connection, Deadline
    ),
    try
        {terminal_connection, FirstLease} = activate(Candidate, true, Deadline),
        {terminal_connection, SecondLease} = expect_checkout(
            http_client_ffi:checkout_http3_shared_within(
                Lifecycle, pool_key(), remaining(Deadline)
            )
        ),
        expect_ok(
            http_client_ffi:close_before(Lifecycle, Deadline, true),
            terminal_close_failed
        ),
        await_candidate_close(Candidate, Deadline),
        expect_ok(http_client_ffi:release_http3_lease_within(
            FirstLease, true, remaining(Deadline)
        ), first_terminal_guard_failed),
        expect_ok(http_client_ffi:release_http3_lease_within(
            SecondLease, true, remaining(Deadline)
        ), second_terminal_guard_failed),
        require(no_duplicate_close(terminal_close), duplicate_physical_close)
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

capability_calls_reject_non_result_replies_test() ->
    Deadline = scenario_deadline(),
    Parent = self(),
    AdoptOwner = spawn(fun() -> invalid_adopt_reply_owner(Deadline) end),
    ReleaseOwner = spawn(fun() -> invalid_release_reply_owner(Deadline) end),
    AdoptCodeOwner = spawn(fun() ->
        invalid_reply_owner(
            {error, 0}, Parent, invalid_adopt_code, Deadline
        )
    end),
    ReleaseCodeOwner = spawn(fun() ->
        invalid_reply_owner(
            {error, 2147483647}, Parent, invalid_release_code, Deadline
        )
    end),
    ActivateCodeOwner = spawn(fun() ->
        invalid_reply_owner(
            {error, -1}, Parent, invalid_activation_code, Deadline
        )
    end),
    CheckoutCodeOwner = spawn(fun() ->
        invalid_reply_owner(
            {error, 2147483647}, Parent, invalid_checkout_code, Deadline
        )
    end),
    AdoptMonitor = monitor(process, AdoptOwner),
    ReleaseMonitor = monitor(process, ReleaseOwner),
    AdoptCodeMonitor = monitor(process, AdoptCodeOwner),
    ReleaseCodeMonitor = monitor(process, ReleaseCodeOwner),
    ActivateCodeMonitor = monitor(process, ActivateCodeOwner),
    CheckoutCodeMonitor = monitor(process, CheckoutCodeOwner),
    AdoptLease = standalone_lease(AdoptOwner),
    ReleaseLease = standalone_lease(ReleaseOwner),
    AdoptCodeLease = standalone_lease(AdoptCodeOwner),
    ReleaseCodeLease = standalone_lease(ReleaseCodeOwner),
    CheckoutState = atomics:new(1, [{signed, false}]),
    atomics:put(CheckoutState, 1, 0),
    InvalidLifecycle = #{state => CheckoutState, owner => CheckoutCodeOwner},
    try
        require(
            http_client_ffi:adopt_http3_lease_within(
                AdoptLease, self(), remaining(Deadline)
            ) =:= {error, 1},
            invalid_adopt_reply_was_accepted
        ),
        require(
            http_client_ffi:release_http3_lease_within(
                ReleaseLease, true, remaining(Deadline)
            ) =:= {error, 1},
            invalid_release_reply_was_accepted
        ),
        require(
            http_client_ffi:adopt_http3_lease_within(
                AdoptCodeLease, self(), remaining(Deadline)
            ) =:= {error, 1},
            invalid_adopt_error_code_was_accepted
        ),
        await_invalid_reply_emitted(invalid_adopt_code, Deadline),
        require(
            http_client_ffi:release_http3_lease_within(
                ReleaseCodeLease, true, remaining(Deadline)
            ) =:= {error, 1},
            invalid_release_error_code_was_accepted
        ),
        await_invalid_reply_emitted(invalid_release_code, Deadline),
        require(
            http_client_ffi:activate_http3_candidate_within(
                {http_client_registration, ActivateCodeOwner, make_ref()},
                pool_key(), invalid_connection, true, remaining(Deadline)
            ) =:= {error, 1},
            invalid_activation_error_code_was_accepted
        ),
        await_invalid_reply_emitted(invalid_activation_code, Deadline),
        require(
            http_client_ffi:checkout_http3_shared_within(
                InvalidLifecycle, pool_key(), remaining(Deadline)
            ) =:= {error, 1},
            invalid_checkout_error_code_was_accepted
        ),
        await_invalid_reply_emitted(invalid_checkout_code, Deadline),
        AdoptCodeOwner ! stop,
        ReleaseCodeOwner ! stop,
        ActivateCodeOwner ! stop,
        CheckoutCodeOwner ! stop,
        await_down(AdoptOwner, AdoptMonitor, Deadline),
        await_down(ReleaseOwner, ReleaseMonitor, Deadline),
        await_down(AdoptCodeOwner, AdoptCodeMonitor, Deadline),
        await_down(ReleaseCodeOwner, ReleaseCodeMonitor, Deadline),
        await_down(ActivateCodeOwner, ActivateCodeMonitor, Deadline),
        await_down(CheckoutCodeOwner, CheckoutCodeMonitor, Deadline)
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_processes([
            {AdoptOwner, AdoptMonitor},
            {ReleaseOwner, ReleaseMonitor},
            {AdoptCodeOwner, AdoptCodeMonitor},
            {ReleaseCodeOwner, ReleaseCodeMonitor},
            {ActivateCodeOwner, ActivateCodeMonitor},
            {CheckoutCodeOwner, CheckoutCodeMonitor}
        ], CleanupDeadline)
    end.

unregistering_a_live_shared_owner_starts_and_joins_shutdown_test() ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    Candidate = new_candidate(
        Lifecycle, unregister_shared, unregister_connection, Deadline
    ),
    try
        {unregister_connection, Lease} = activate(Candidate, true, Deadline),
        {Registration, _Owner, _Monitor, _Label, _Connection} = Candidate,
        nil = http_client_ffi:unregister_socket(Registration),
        await_candidate_close(Candidate, Deadline),
        expect_ok(http_client_ffi:release_http3_lease_within(
            Lease, true, remaining(Deadline)
        ), unregister_terminal_guard_failed),
        require(
            await_shared_snapshot(
                Lifecycle, {0, 0, 0, 0, 0, 0}, Deadline
            ),
            unregister_shared_cleanup_failed
        )
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

exercise_nonresponsive_shared_close(Cause) ->
    Deadline = scenario_deadline(),
    IdleMilliseconds = case Cause of
        idle_eviction -> 1;
        _ -> 60000
    end,
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, IdleMilliseconds),
    Label = case Cause of
        nonreusable_last_release -> stubborn_nonreusable;
        idle_eviction -> stubborn_idle;
        live_unregister -> stubborn_unregister
    end,
    Candidate = new_stubborn_candidate(
        Lifecycle, Label, stubborn_shared_connection, Deadline
    ),
    try
        {stubborn_shared_connection, Lease} = activate(
            Candidate, true, Deadline
        ),
        {Registration, _, _, _, _} = Candidate,
        CloseStarted = erlang:monotonic_time(millisecond),
        case Cause of
            nonreusable_last_release ->
                expect_ok(http_client_ffi:release_http3_lease_within(
                    Lease, false, remaining(Deadline)
                ), stubborn_nonreusable_release_failed);
            idle_eviction ->
                expect_ok(http_client_ffi:release_http3_lease_within(
                    Lease, true, remaining(Deadline)
                ), stubborn_idle_release_failed);
            live_unregister ->
                nil = http_client_ffi:unregister_socket(Registration)
        end,
        CloseDeadline = await_close_ignored(Label, Deadline),
        CloseObservedAt = erlang:monotonic_time(millisecond),
        require(
            CloseDeadline > CloseStarted
                andalso CloseDeadline =< CloseObservedAt + 10000
                andalso CloseDeadline < Deadline,
            stubborn_close_deadline_not_bounded
        ),
        nil = http_client_ffi:unregister_socket(Registration),
        RepeatedUnregister = await_close_ignored(Label, Deadline),
        require(
            RepeatedUnregister =:= CloseDeadline,
            stubborn_unregister_extended_deadline
        ),
        _ = http_client_ffi:drain(Lifecycle),
        RepeatedDrain = await_close_ignored(Label, Deadline),
        require(
            RepeatedDrain =:= CloseDeadline,
            stubborn_drain_extended_deadline
        ),
        require(
            http_client_ffi:lifecycle_snapshot(Lifecycle)
                =:= {1, 0, 0, 1},
            stubborn_capacity_released_before_owner_down
        ),
        await_forced_candidate_down(Candidate, Deadline),
        case Cause of
            live_unregister ->
                expect_ok(http_client_ffi:release_http3_lease_within(
                    Lease, true, remaining(Deadline)
                ), stubborn_terminal_guard_failed);
            _ -> ok
        end,
        require(
            await_registered_count(Lifecycle, 0, Deadline),
            stubborn_capacity_not_released_after_owner_down
        ),
        require(
            await_shared_snapshot(
                Lifecycle, {0, 0, 0, 0, 0, 0}, Deadline
            ),
            stubborn_shared_state_not_released
        ),
        require(
            is_process_alive(http_client_ffi:lifecycle_owner(Lifecycle)),
            stubborn_close_crashed_lifecycle
        )
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

exercise_sibling_drain(Cause) ->
    Deadline = scenario_deadline(),
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    Label = case Cause of
        holder_down -> sibling_holder_down;
        nonreusable_release -> sibling_nonreusable
    end,
    Candidate = new_candidate(
        Lifecycle, Label, sibling_connection, Deadline
    ),
    Holder = spawn(fun idle/0),
    HolderMonitor = monitor(process, Holder),
    try
        {sibling_connection, FirstLease} = activate(Candidate, true, Deadline),
        {sibling_connection, SecondLease} = expect_checkout(
            http_client_ffi:checkout_http3_shared_within(
                Lifecycle, pool_key(), remaining(Deadline)
            )
        ),
        case Cause of
            holder_down ->
                expect_ok(http_client_ffi:adopt_http3_lease_within(
                    FirstLease, Holder, remaining(Deadline)
                ), sibling_adoption_failed),
                exit(Holder, kill),
                await_down(Holder, HolderMonitor, Deadline);
            nonreusable_release ->
                expect_ok(http_client_ffi:release_http3_lease_within(
                    FirstLease, false, remaining(Deadline)
                ), nonreusable_sibling_release_failed)
        end,
        require(
            await_shared_snapshot(
                Lifecycle, {1, 0, 1, 0, 1, 0}, Deadline
            ),
            sibling_drain_snapshot_failed
        ),
        require(candidate_alive(Candidate), sibling_interrupted),
        require(no_close_observed(Label), sibling_closed_early),
        expect_ok(http_client_ffi:release_http3_lease_within(
            SecondLease, true, remaining(Deadline)
        ), last_sibling_release_failed),
        await_candidate_close(Candidate, Deadline)
    after
        CleanupDeadline = cleanup_deadline(),
        cleanup_process(Holder, HolderMonitor, CleanupDeadline),
        cleanup_candidates([Candidate], CleanupDeadline),
        close_lifecycle(Lifecycle, CleanupDeadline)
    end.

new_candidate(Lifecycle, Label, Connection, Deadline) ->
    new_candidate_with_owner(
        Lifecycle, Label, Connection, responsive, Deadline
    ).

new_stubborn_candidate(Lifecycle, Label, Connection, Deadline) ->
    new_candidate_with_owner(
        Lifecycle, Label, Connection, nonresponsive, Deadline
    ).

new_candidate_with_owner(Lifecycle, Label, Connection, Behaviour, Deadline) ->
    Registration = case http_client_ffi:reserve_resource_within(
        Lifecycle, physical_origin(), remaining(Deadline)
    ) of
        {ok, Value} -> Value;
        _ -> fail(candidate_reservation_failed)
    end,
    Parent = self(),
    Tag = make_ref(),
    Owner = case Behaviour of
        responsive ->
            spawn(fun() -> physical_owner(Parent, Tag, Label, Deadline) end);
        nonresponsive ->
            spawn(fun() ->
                nonresponsive_physical_owner(Parent, Tag, Label, Deadline)
            end)
    end,
    Monitor = monitor(process, Owner),
    Handle = {http3_close_handle, Owner, Tag},
    case http_client_ffi:attach_http3_resource(
        Registration, Owner, Handle
    ) of
        {ok, nil} ->
            {Registration, Owner, Monitor, Label, Connection};
        _ ->
            exit(Owner, kill),
            await_down(Owner, Monitor, Deadline),
            fail(candidate_adoption_failed)
    end.

activate(
    {Registration, _Owner, _Monitor, _Label, Connection},
    AllowShare,
    Deadline
) ->
    case http_client_ffi:activate_http3_candidate_within(
        Registration, pool_key(), Connection, AllowShare, remaining(Deadline)
    ) of
        {ok, {SharedConnection, Lease}} -> {SharedConnection, Lease};
        _ -> fail(candidate_activation_failed)
    end.

start_activation(Id, Candidate, AllowShare, Deadline) ->
    Parent = self(),
    {Registration, _Owner, _OwnerMonitor, _Label, Connection} = Candidate,
    {Pid, Monitor} = spawn_monitor(fun() ->
        Parent ! {activation_ready, Id, self()},
        receive
            {activation_start, Id} -> ok
        after remaining(Deadline) ->
            fail(activation_start_timeout)
        end,
        Result = http_client_ffi:activate_http3_candidate_within(
            Registration, pool_key(), Connection, AllowShare,
            remaining(Deadline)
        ),
        Parent ! {activation_result, Id, Result},
        receive
            {activation_finish, Id} -> ok
        after remaining(Deadline) ->
            fail(activation_finish_timeout)
        end
    end),
    receive
        {activation_ready, Id, Pid} -> ok
    after remaining(Deadline) ->
        fail(activation_readiness_timeout)
    end,
    {Id, Pid, Monitor}.

release_activation_start({Id, Pid, _Monitor}) ->
    Pid ! {activation_start, Id}.

activation_result({Id, _Pid, _Monitor}, Deadline) ->
    receive
        {activation_result, Id, {ok, {Connection, Lease}}} ->
            {Connection, Lease};
        {activation_result, Id, _SafeFailure} ->
            fail(activation_result_failed)
    after remaining(Deadline) ->
        fail(activation_result_timeout)
    end.

finish_activation({Id, Pid, Monitor}, Deadline) ->
    Pid ! {activation_finish, Id},
    await_down(Pid, Monitor, Deadline).

cleanup_activation({_Id, Pid, Monitor}, Deadline) ->
    cleanup_process(Pid, Monitor, Deadline).

checkout_many(_Lifecycle, 0, Leases, _Deadline) -> Leases;
checkout_many(Lifecycle, Remaining, Leases, Deadline) ->
    {_Connection, Lease} = expect_checkout(
        http_client_ffi:checkout_http3_shared_within(
            Lifecycle, pool_key(), remaining(Deadline)
        )
    ),
    checkout_many(Lifecycle, Remaining - 1, [Lease | Leases], Deadline).

acquire_request_admissions(_Controller, 0, Leases, _Deadline) ->
    Leases;
acquire_request_admissions(Controller, Remaining, Leases, Deadline) ->
    require(remaining(Deadline) > 0, aggregate_admission_deadline),
    case http_server_ffi:resource_acquire(Controller, 0) of
        {ok, Lease} ->
            acquire_request_admissions(
                Controller, Remaining - 1, [Lease | Leases], Deadline
            );
        _ ->
            release_request_admissions(Controller, Leases),
            fail(aggregate_request_admission_failed)
    end.

release_request_admissions(Controller, Leases) ->
    lists:foreach(fun(Lease) ->
        nil = http_server_ffi:resource_release(Controller, Lease)
    end, Leases).

expect_checkout({ok, {Connection, Lease}}) -> {Connection, Lease};
expect_checkout(_) -> fail(shared_checkout_failed).

release_many(Leases, Deadline) ->
    lists:foreach(fun(Lease) ->
        expect_ok(http_client_ffi:release_http3_lease_within(
            Lease, true, remaining(Deadline)
        ), shared_release_failed)
    end, Leases).

start_adoption_timeout_probe(Lease, Holder, Lifecycle, Deadline) ->
    Parent = self(),
    Id = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Result = http_client_ffi:adopt_http3_lease_within(Lease, Holder, 0),
        Parent ! {Id, adoption_timeout_result, Result =:= {error, 1}},
        receive
            {Id, synchronize} ->
                Snapshot = http_client_ffi:http3_shared_snapshot(Lifecycle),
                Parent ! {Id, adoption_synchronized,
                    Snapshot =:= {1, 1, 0, 0, 1, 0}}
        after remaining(Deadline) ->
            fail(adoption_synchronization_timeout)
        end,
        receive
            {Id, inspect_mailbox} ->
                {messages, Messages} = process_info(self(), messages),
                Parent ! {Id, adoption_mailbox_empty, Messages =:= []}
        after remaining(Deadline) ->
            fail(adoption_inspection_timeout)
        end,
        receive
            {Id, finish} -> ok
        after remaining(Deadline) ->
            fail(adoption_probe_finish_timeout)
        end
    end),
    {Id, Pid, Monitor}.

standalone_lease(Owner) ->
    Guard = atomics:new(1, [{signed, false}]),
    atomics:put(Guard, 1, 0),
    {http3_stream_lease, Owner, make_ref(), make_ref(), make_ref(), Guard}.

invalid_adopt_reply_owner(Deadline) ->
    receive
        {adopt_http3_lease, ReplyTo, Reference, _Lease, _Holder, _Deadline} ->
            ReplyTo ! {Reference, invalid},
            exit(normal)
    after remaining(Deadline) ->
        exit(invalid_adopt_reply_timeout)
    end.

invalid_release_reply_owner(Deadline) ->
    receive
        {release_http3_lease, ReplyTo, Reference, _Lease, _Reusable,
                _Deadline} ->
            ReplyTo ! {Reference, {ok, unexpected}},
            exit(normal)
    after remaining(Deadline) ->
        exit(invalid_release_reply_timeout)
    end.

invalid_reply_owner(Reply, Parent, Label, Deadline) ->
    receive
        {adopt_http3_lease, ReplyTo, Reference, _Lease, _Holder, _Deadline} ->
            ReplyTo ! {Reference, Reply},
            Parent ! {invalid_reply_emitted, Label},
            idle();
        {release_http3_lease, ReplyTo, Reference, _Lease, _Reusable,
                _Deadline} ->
            ReplyTo ! {Reference, Reply},
            Parent ! {invalid_reply_emitted, Label},
            idle();
        {activate_http3_candidate, _Sender, ReplyTo, Reference, _Token, _Key,
                _Connection, _AllowShare, _Deadline} ->
            ReplyTo ! {Reference, Reply},
            Parent ! {invalid_reply_emitted, Label},
            idle();
        {checkout_http3_shared, _Sender, ReplyTo, Reference, _Key,
                _Deadline} ->
            ReplyTo ! {Reference, Reply},
            Parent ! {invalid_reply_emitted, Label},
            idle()
    after remaining(Deadline) ->
        exit(invalid_reply_owner_timeout)
    end.

await_invalid_reply_emitted(Label, Deadline) ->
    receive
        {invalid_reply_emitted, Label} -> ok
    after remaining(Deadline) ->
        fail(invalid_reply_not_emitted)
    end.

adoption_timeout_result({Id, _Pid, _Monitor}, Deadline) ->
    receive
        {Id, adoption_timeout_result, Result} -> Result
    after remaining(Deadline) ->
        fail(adoption_result_timeout)
    end.

adoption_probe_synchronized({Id, Pid, _Monitor}, Deadline) ->
    Pid ! {Id, synchronize},
    receive
        {Id, adoption_synchronized, Synchronized} -> Synchronized
    after remaining(Deadline) ->
        fail(adoption_synchronization_timeout)
    end.

adoption_probe_mailbox_empty({Id, Pid, _Monitor}, Deadline) ->
    Pid ! {Id, inspect_mailbox},
    receive
        {Id, adoption_mailbox_empty, Empty} -> Empty
    after remaining(Deadline) ->
        fail(adoption_mailbox_timeout)
    end.

finish_adoption_probe({Id, Pid, Monitor}, Deadline) ->
    Pid ! {Id, finish},
    await_down(Pid, Monitor, Deadline).

physical_owner(Parent, Tag, Label, Deadline) ->
    receive
        {Tag, {close, _Deadline}} ->
            Parent ! {physical_close, Label},
            exit(normal);
        stop -> exit(normal)
    after remaining(Deadline) ->
        Parent ! {physical_timeout, Label},
        exit(physical_timeout)
    end.

nonresponsive_physical_owner(Parent, Tag, Label, Deadline) ->
    receive
        {Tag, {close, CloseDeadline}} ->
            Parent ! {physical_close_ignored, Label, CloseDeadline},
            nonresponsive_physical_owner(Parent, Tag, Label, Deadline);
        stop -> exit(normal)
    after remaining(Deadline) ->
        Parent ! {physical_timeout, Label},
        exit(physical_timeout)
    end.

await_close_ignored(Label, Deadline) ->
    receive
        {physical_close_ignored, Label, CloseDeadline}
          when is_integer(CloseDeadline) -> CloseDeadline;
        {physical_timeout, Label} -> fail(nonresponsive_owner_timed_out)
    after remaining(Deadline) ->
        fail(nonresponsive_close_not_observed)
    end.

await_forced_candidate_down(
    {_Registration, Owner, Monitor, Label, _Connection}, Deadline
) ->
    receive
        {'DOWN', Monitor, process, Owner, killed} ->
            flush_physical_observation(Label),
            ok;
        {'DOWN', Monitor, process, Owner, _OtherReason} ->
            fail(nonresponsive_owner_not_forced)
    after remaining(Deadline) ->
        fail(nonresponsive_owner_force_timeout)
    end.

await_candidate_close(
    {_Registration, Owner, Monitor, Label, _Connection}, Deadline
) ->
    receive
        {physical_close, Label} -> ok;
        {physical_timeout, Label} -> fail(physical_owner_timeout)
    after remaining(Deadline) ->
        fail(physical_close_timeout)
    end,
    await_down(Owner, Monitor, Deadline).

candidate_alive({_Registration, Owner, _Monitor, _Label, _Connection}) ->
    is_process_alive(Owner).

no_close_observed(Label) ->
    receive
        {physical_close, Label} -> false;
        {physical_timeout, Label} -> false
    after 0 -> true
    end.

no_duplicate_close(Label) -> no_close_observed(Label).

cleanup_candidates(Candidates, Deadline) ->
    cleanup_processes(
        [{Owner, Monitor} ||
            {_Registration, Owner, Monitor, _Label, _Connection} <- Candidates],
        Deadline
    ).

cleanup_process(Pid, Monitor, Deadline) ->
    cleanup_processes([{Pid, Monitor}], Deadline).

cleanup_processes(ProcessMonitors, Deadline) ->
    lists:foreach(fun({Pid, _Monitor}) ->
        case is_process_alive(Pid) of
            true -> exit(Pid, kill);
            false -> ok
        end
    end, ProcessMonitors),
    lists:foreach(fun({Pid, Monitor}) ->
        confirm_process_down(Pid, Monitor, Deadline)
    end, ProcessMonitors).

confirm_process_down(Pid, Monitor, Deadline) ->
    case is_process_alive(Pid) of
        false ->
            demonitor(Monitor, [flush]),
            ok;
        true ->
            receive
                {'DOWN', Monitor, process, Pid, _Reason} -> ok
            after remaining(Deadline) ->
                fail(cleanup_process_join_timeout)
            end
    end.

close_lifecycle(Lifecycle, Deadline) ->
    expect_ok(
        http_client_ffi:close_before(Lifecycle, Deadline, true),
        cleanup_lifecycle_close_unconfirmed
    ).

await_shared_snapshot(Lifecycle, Expected, Deadline) ->
    Remaining0 = Deadline - erlang:monotonic_time(millisecond),
    ObservationTimeout = erlang:max(0, erlang:min(50, Remaining0)),
    case http_client_ffi:http3_shared_snapshot(
        Lifecycle, ObservationTimeout
    ) of
        Expected -> true;
        _ ->
            Remaining = Deadline - erlang:monotonic_time(millisecond),
            case Remaining > 0 of
                true ->
                    receive after erlang:min(10, Remaining) -> ok end,
                    await_shared_snapshot(Lifecycle, Expected, Deadline);
                false -> false
            end
    end.

await_registered_count(Lifecycle, Expected, Deadline) ->
    case http_client_ffi:lifecycle_snapshot(Lifecycle) of
        {Expected, _Pooled, _CallerOwned, _Monitored} -> true;
        _ ->
            Remaining = Deadline - erlang:monotonic_time(millisecond),
            case Remaining > 0 of
                true ->
                    receive after erlang:min(10, Remaining) -> ok end,
                    await_registered_count(Lifecycle, Expected, Deadline);
                false -> false
            end
    end.

flush_physical_observation(Label) ->
    receive
        {physical_close, Label} -> flush_physical_observation(Label);
        {physical_close_ignored, Label, _CloseDeadline} ->
            flush_physical_observation(Label);
        {physical_timeout, Label} -> flush_physical_observation(Label)
    after 0 -> ok
    end.

await_down(Pid, Monitor, Deadline) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> true
    after remaining(Deadline) ->
        fail(process_join_timeout)
    end.

ensure_resumed(Pid) ->
    case process_info(Pid, status) of
        {status, suspended} -> erlang:resume_process(Pid);
        _ -> true
    end.

expect_ok({ok, nil}, _Phase) -> ok;
expect_ok(_, Phase) -> fail(Phase).

require(true, _Phase) -> ok;
require(false, Phase) -> fail(Phase).

fail(Phase) -> erlang:error({http3_shared_lease_phase, Phase}).

scenario_deadline() ->
    erlang:monotonic_time(millisecond) + ?SCENARIO_TIMEOUT.

cleanup_deadline() ->
    erlang:monotonic_time(millisecond) + ?CLEANUP_TIMEOUT.

remaining(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

pool_key() -> <<"h3-shared-test-key">>.

physical_origin() -> <<"https://shared.test:443">>.

idle() ->
    receive stop -> ok after ?SCENARIO_TIMEOUT -> ok end.
