%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_client_resource_test).
-include_lib("eunit/include/eunit.hrl").
-export([
    race_guard_processes/0,
    race_attempt_processes/0,
    linked_processes/0
]).

linked_processes() ->
    {links, Links} = process_info(self(), links),
    [Pid || Pid <- Links, is_pid(Pid)].

%% Test-only process inventory: discover the private guard blocked in receive,
%% without exposing runtime identities through the library's public values.
race_guard_processes() ->
    [Pid || Pid <- processes(), is_race_guard(Pid)].

is_race_guard(Pid) ->
    proc_lib:get_label(Pid) =:= <<"http.client_race_guardian">>.

race_attempt_processes() ->
    [Pid || Pid <- processes(), is_race_attempt(Pid)].

is_race_attempt(Pid) ->
    proc_lib:get_label(Pid) =:= <<"http.client_connection_candidate">>.

reservation_precedes_connection_actor_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    try
        {ok, Lease} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        ?assertEqual({error, 2}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>)),
        nil = http_client_ffi:unregister_socket(Lease),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>))
    after http_client_ffi:close(Lifecycle) end.

candidate_retirement_acknowledges_cleanup_before_waiting_for_owner_exit_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {ok, Registration} = http_client_ffi:reserve_resource(
        Lifecycle, <<"origin">>
    ),
    Parent = self(),
    Tag = make_ref(),
    ResourceOwner = spawn(fun() ->
        receive
            {Tag, {close, Deadline}} ->
                Released = http_client_ffi:unregister_socket_before(
                    Registration, Deadline
                ),
                Parent ! {Tag, Released}
        end
    end),
    Monitor = monitor(process, ResourceOwner),
    CloseHandle = http_client_ffi:new_http3_close_handle(
        {subject, ResourceOwner, Tag}
    ),
    try
        {ok, nil} = http_client_ffi:attach_http3_resource(
            Registration, ResourceOwner, CloseHandle
        ),
        Retired = http_client_ffi:retire_http3_candidate_confirmed_within(
            Registration, 1000
        ),
        Cleanup = receive {Tag, Result} -> Result after 1000 -> missing end,
        Joined = receive
            {'DOWN', Monitor, process, ResourceOwner, _} -> true
        after 1000 -> false end,
        ?assertEqual({ok, nil}, Retired),
        ?assertEqual(true, Cleanup),
        ?assert(Joined),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(
            Lifecycle, <<"replacement">>
        ))
    after
        exit(ResourceOwner, kill),
        demonitor(Monitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

deadline_aware_resource_cancel_never_uses_the_global_owner_wait_test() ->
    Owner = spawn(fun idle/0),
    Registration = {http_client_registration, Owner, make_ref()},
    Started = erlang:monotonic_time(millisecond),
    try
        ?assertNot(http_client_ffi:cancel_resource_within(Registration, 20)),
        ?assert(erlang:monotonic_time(millisecond) - Started < 500)
    after
        Owner ! stop
    end.

deadline_aware_resource_checkin_never_uses_the_global_owner_wait_test() ->
    Owner = spawn(fun idle/0),
    Registration = {http_client_registration, Owner, make_ref()},
    Started = erlang:monotonic_time(millisecond),
    try
        ?assertNot(http_client_ffi:checkin_resource_within(
            Registration, <<"h3|bounded">>, marker, 20
        )),
        ?assert(erlang:monotonic_time(millisecond) - Started < 500)
    after
        Owner ! stop
    end.

deadline_aware_resource_checkout_preserves_a_late_pool_entry_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    ResourceOwner = spawn(fun idle/0),
    ResourceMonitor = monitor(process, ResourceOwner),
    Parent = self(),
    Tag = make_ref(),
    try
        {ok, Registration} =
            http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        {ok, nil} = http_client_ffi:attach_resource(
            Registration, ResourceOwner
        ),
        ?assert(http_client_ffi:checkin_resource(
            Registration, <<"h3|bounded">>, marker
        )),
        true = erlang:suspend_process(LifecycleOwner),
        {Worker, WorkerMonitor} = spawn_monitor(fun() ->
            Started = erlang:monotonic_time(millisecond),
            Kind = case http_client_ffi:checkout_resource_within(
                Lifecycle, <<"h3|bounded">>, 20
            ) of
                {error, 1} -> expired;
                {ok, _Value} -> unexpected_success;
                {error, _Code} -> unexpected_error
            end,
            Elapsed = erlang:monotonic_time(millisecond) - Started,
            Barrier = make_ref(),
            %% This message and the checkout request have the same sender.
            %% Once the owner replies to the barrier it has necessarily
            %% rejected the earlier, now-expired checkout first.
            LifecycleOwner ! {lifecycle_snapshot, Parent, Barrier},
            Parent ! {Tag, checkout_finished, Kind, Elapsed, Barrier},
            receive
                {Tag, inspect_mailbox} ->
                    {message_queue_len, MailboxCount} =
                        process_info(self(), message_queue_len),
                    Parent ! {Tag, mailbox_count, MailboxCount}
            after 1000 ->
                exit(inspect_instruction_timeout)
            end
        end),
        receive
            {Tag, checkout_finished, Kind, Elapsed, Barrier} ->
                ?assertEqual(expired, Kind),
                ?assert(Elapsed < 500),
                true = erlang:resume_process(LifecycleOwner),
                receive
                    {Barrier, {ok, Snapshot}} ->
                        ?assertEqual({1, 1, 0, 1}, Snapshot),
                        Worker ! {Tag, inspect_mailbox},
                        receive
                            {Tag, mailbox_count, MailboxCount} ->
                                ?assertEqual(0, MailboxCount)
                        after 1000 ->
                            ?assert(false)
                        end
                after 1000 ->
                    ?assert(false)
                end
        after 1000 ->
            ?assert(false)
        end,
        receive
            {'DOWN', WorkerMonitor, process, Worker, _WorkerReason} -> ok
        after 1000 ->
            ?assert(false)
        end,
        ?assertEqual(
            {ok, marker},
            http_client_ffi:checkout_resource_within(
                Lifecycle, <<"h3|bounded">>, 100
            )
        ),
        ?assert(http_client_ffi:cancel_resource_within(Registration, 100)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        receive
            {'DOWN', ResourceMonitor, process, ResourceOwner,
                _ResourceReason} -> ok
        after 1000 ->
            ?assert(false)
        end
    after
        _ = try erlang:resume_process(LifecycleOwner) of
            _ -> ok
        catch
            _:_ -> ok
        end,
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

offered_resource_checkout_abandon_restores_pool_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    {Registration, ResourceOwner, ResourceMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|offered-abandon">>),
    Parent = self(),
    Tag = make_ref(),
    {Worker, WorkerMonitor} = spawn_monitor(fun() ->
        Reference = make_ref(),
        ReplyAlias = erlang:alias(),
        Deadline = erlang:monotonic_time(millisecond) + 1000,
        LifecycleOwner ! {checkout_resource_before, self(), ReplyAlias,
            Reference, <<"h3|offered-abandon">>, Deadline},
        case receive
            {Reference, {offer, {marker, 1}}} -> offered;
            {Reference, {error, _Code}} -> refused
        after 500 -> no_offer
        end of
            offered ->
                Parent ! {Tag, offered},
                receive
                    {Tag, abandon} ->
                        LifecycleOwner ! {abandon_resource_checkout,
                            self(), Reference},
                        Barrier = make_ref(),
                        LifecycleOwner ! {lifecycle_snapshot, Parent, Barrier},
                        Parent ! {Tag, barrier, Barrier}
                after 1000 ->
                    Parent ! {Tag, worker_timeout}
                end;
            Failure -> Parent ! {Tag, Failure}
        end,
        _ = erlang:unalias(ReplyAlias)
    end),
    try
        Offer = receive
            {Tag, offered} -> offered;
            {Tag, Failure} when is_atom(Failure) -> Failure
        after 1000 -> no_offer
        end,
        ?assertEqual(offered, Offer),
        ?assertEqual(1, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        Worker ! {Tag, abandon},
        Barrier = receive
            {Tag, barrier, BarrierValue} -> BarrierValue
        after 1000 -> no_barrier
        end,
        Snapshot = receive
            {Barrier, {ok, SnapshotValue}} -> SnapshotValue
        after 1000 -> no_snapshot
        end,
        ?assertEqual({1, 1, 0, 1}, Snapshot),
        ?assert(await_worker_down(Worker, WorkerMonitor, 1000)),
        ?assertEqual(0, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        ?assert(http_client_ffi:cancel_resource_within(Registration, 100)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        ?assert(await_process_down(ResourceOwner, ResourceMonitor, 1000))
    after
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

offered_resource_checkout_expiry_restores_pool_and_rejects_waiter_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    {Registration, ResourceOwner, ResourceMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|offered-expiry">>),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    Parent = self(),
    Tag = make_ref(),
    {Worker, WorkerMonitor} = spawn_monitor(fun() ->
        Reference = make_ref(),
        ReplyAlias = erlang:alias(),
        Deadline = erlang:monotonic_time(millisecond) + 100,
        LifecycleOwner ! {checkout_resource_before, self(), ReplyAlias,
            Reference, <<"h3|offered-expiry">>, Deadline},
        Offer = receive
            {Reference, {offer, {marker, 1}}} -> offered;
            {Reference, {error, _Code}} -> refused
        after 500 -> no_offer
        end,
        Parent ! {Tag, offer, Offer},
        Settlement = receive
            {Reference, rejected} -> rejected
        after 500 -> settlement_timeout
        end,
        Parent ! {Tag, settlement, Settlement},
        _ = erlang:unalias(ReplyAlias)
    end),
    try
        Offer = receive
            {Tag, offer, OfferKind} -> OfferKind
        after 1000 -> no_offer
        end,
        ?assertEqual(offered, Offer),
        ?assertEqual(1, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        Settlement = receive
            {Tag, settlement, SettlementKind} -> SettlementKind
        after 1000 -> settlement_timeout
        end,
        ?assertEqual(rejected, Settlement),
        ?assert(await_worker_down(Worker, WorkerMonitor, 1000)),
        ?assert(await_pending_count(Lifecycle, 0, 100)),
        ?assert(await_snapshot(Lifecycle, {1, 1, 0, 1}, 100)),
        ?assert(http_client_ffi:cancel_resource_within(Registration, 100)),
        ?assert(await_process_down(ResourceOwner, ResourceMonitor, 1000)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100))
    after
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

confirmed_resource_checkout_is_rejected_when_caller_resumes_late_test() ->
    Parent = self(),
    Tag = make_ref(),
    State = atomics:new(1, [{signed, false}]),
    ok = atomics:put(State, 1, 0),
    {FakeOwner, OwnerMonitor} = spawn_monitor(fun() ->
        delayed_checkout_confirmation_owner(Parent, Tag)
    end),
    Lifecycle = #{state => State, owner => FakeOwner},
    {Worker, WorkerMonitor} = spawn_monitor(fun() ->
        Kind = case http_client_ffi:checkout_resource_within(
            Lifecycle, <<"h3|caller-late">>, 300
        ) of
            {error, 1} -> expired;
            {ok, _Value} -> late_success;
            {error, _Code} -> unexpected_error
        end,
        {message_queue_len, MailboxCount} =
            process_info(self(), message_queue_len),
        Parent ! {Tag, checkout_result, Kind, MailboxCount}
    end),
    try
        Deadline = receive
            {Tag, confirmation_waiting, Value} -> Value
        after 1000 -> missing_confirmation_sync
        end,
        ?assert(is_integer(Deadline)),
        true = erlang:suspend_process(Worker),
        FakeOwner ! {Tag, release_confirmation},
        receive
            {Tag, confirmation_sent} -> ok
        after 1000 ->
            ?assert(false)
        end,
        wait_until(Deadline),
        true = erlang:resume_process(Worker),
        receive
            {Tag, checkout_result, Kind, MailboxCount} ->
                ?assertEqual(expired, Kind),
                ?assertEqual(0, MailboxCount)
        after 1000 ->
            ?assert(false)
        end,
        receive
            {Tag, abandoned} -> ok
        after 1000 ->
            ?assert(false)
        end,
        ?assert(await_worker_down(Worker, WorkerMonitor, 1000)),
        FakeOwner ! {Tag, stop},
        ?assert(await_worker_down(FakeOwner, OwnerMonitor, 1000))
    after
        _ = try erlang:resume_process(Worker) of
            _ -> ok
        catch
            _:_ -> ok
        end,
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(FakeOwner, kill),
        demonitor(OwnerMonitor, [flush])
    end.

late_resource_checkout_confirm_is_rejected_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    {Registration, ResourceOwner, ResourceMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|late-confirm">>),
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + 200,
    try
        LifecycleOwner ! {checkout_resource_before, self(), ReplyAlias,
            Reference, <<"h3|late-confirm">>, Deadline},
        Offer = receive
            {Reference, {offer, {marker, 1}}} -> offered;
            {Reference, {error, _Code}} -> refused
        after 1000 -> no_offer
        end,
        ?assertEqual(offered, Offer),
        ?assertEqual(1, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        true = erlang:suspend_process(LifecycleOwner),
        wait_until(Deadline),
        LifecycleOwner ! {confirm_resource_checkout, self(), ReplyAlias,
            Reference},
        Barrier = make_ref(),
        LifecycleOwner ! {lifecycle_snapshot, self(), Barrier},
        true = erlang:resume_process(LifecycleOwner),
        Confirmation = receive
            {Reference, confirmed} -> confirmed;
            {Reference, rejected} -> rejected
        after 1000 -> no_confirmation
        end,
        Snapshot = receive
            {Barrier, {ok, Value}} -> Value
        after 1000 -> no_snapshot
        end,
        ?assertEqual(rejected, Confirmation),
        ?assertEqual({1, 1, 0, 1}, Snapshot),
        ?assertEqual(0, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        ?assert(http_client_ffi:cancel_resource_within(Registration, 100)),
        ?assert(await_process_down(ResourceOwner, ResourceMonitor, 1000)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100))
    after
        _ = erlang:unalias(ReplyAlias),
        _ = try erlang:resume_process(LifecycleOwner) of
            _ -> ok
        catch
            _:_ -> ok
        end,
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

pending_resource_checkout_returns_to_pool_when_caller_dies_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    {Registration, ResourceOwner, ResourceMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|caller-down">>),
    {Worker, WorkerMonitor, Offered} = start_checkout_holder(
        Lifecycle, <<"h3|caller-down">>, 1000
    ),
    try
        ?assertEqual(offered, Offered),
        ?assertEqual(1, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        exit(Worker, kill),
        ?assert(await_worker_down(Worker, WorkerMonitor, 1000)),
        ?assert(await_pending_count(Lifecycle, 0, 100)),
        ?assert(await_snapshot(Lifecycle, {1, 1, 0, 1}, 100)),
        ?assert(is_process_alive(ResourceOwner)),
        ?assert(http_client_ffi:cancel_resource_within(Registration, 100)),
        ?assert(await_process_down(ResourceOwner, ResourceMonitor, 1000)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100))
    after
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

pending_resource_checkout_is_reclaimed_by_drain_and_close_test() ->
    pending_resource_checkout_is_reclaimed_by_drain(),
    pending_resource_checkout_is_reclaimed_by_close().

pending_resource_checkout_never_exceeds_connection_limit_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(2, 2, 2000),
    {FirstRegistration, FirstOwner, FirstMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|pending-limit">>),
    {SecondRegistration, SecondOwner, SecondMonitor} =
        pooled_marker(Lifecycle, 2, <<"h3|pending-limit">>),
    {FirstWorker, FirstWorkerMonitor, FirstOffer} = start_checkout_holder(
        Lifecycle, <<"h3|pending-limit">>, 1000
    ),
    {SecondWorker, SecondWorkerMonitor, SecondOffer} = start_checkout_holder(
        Lifecycle, <<"h3|pending-limit">>, 1000
    ),
    try
        ?assertEqual({offered, offered}, {FirstOffer, SecondOffer}),
        ?assertEqual(2, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        ?assertEqual(
            {error, 2},
            http_client_ffi:checkout_resource_within(
                Lifecycle, <<"h3|pending-limit">>, 100
            )
        ),
        ?assertEqual(2, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        exit(FirstWorker, kill),
        exit(SecondWorker, kill),
        ?assert(await_worker_down(
            FirstWorker, FirstWorkerMonitor, 1000
        )),
        ?assert(await_worker_down(
            SecondWorker, SecondWorkerMonitor, 1000
        )),
        ?assert(await_pending_count(Lifecycle, 0, 100)),
        ?assert(await_snapshot(Lifecycle, {2, 2, 0, 2}, 100)),
        ?assert(http_client_ffi:cancel_resource_within(
            FirstRegistration, 100
        )),
        ?assert(http_client_ffi:cancel_resource_within(
            SecondRegistration, 100
        )),
        ?assert(await_process_down(FirstOwner, FirstMonitor, 1000)),
        ?assert(await_process_down(SecondOwner, SecondMonitor, 1000)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100))
    after
        exit(FirstWorker, kill),
        exit(SecondWorker, kill),
        demonitor(FirstWorkerMonitor, [flush]),
        demonitor(SecondWorkerMonitor, [flush]),
        exit(FirstOwner, kill),
        exit(SecondOwner, kill),
        demonitor(FirstMonitor, [flush]),
        demonitor(SecondMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

deadline_aware_resource_reservation_never_uses_the_global_owner_wait_test() ->
    Owner = spawn(fun idle/0),
    State = atomics:new(1, []),
    atomics:put(State, 1, 0),
    Lifecycle = #{state => State, owner => Owner},
    Started = erlang:monotonic_time(millisecond),
    try
        ?assertEqual(
            {error, 1},
            http_client_ffi:reserve_resource_within(
                Lifecycle, <<"bounded-origin">>, 20
            )
        ),
        ?assert(erlang:monotonic_time(millisecond) - Started < 500)
    after
        Owner ! stop
    end.

expired_resource_reservation_message_never_consumes_capacity_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Owner = http_client_ffi:lifecycle_owner(Lifecycle),
    Token = make_ref(),
    Owner ! {reserve_resource_before, self(), self(), Token, <<"origin">>,
        erlang:monotonic_time(millisecond) - 1},
    try
        receive
            {Token, Result} -> ?assertEqual({error, 1}, Result)
        after 1000 ->
            ?assert(false)
        end,
        ?assertEqual(
            {0, 0, 0, 0}, http_client_ffi:lifecycle_snapshot(Lifecycle)
        )
    after
        http_client_ffi:close(Lifecycle)
    end.

expired_resource_checkin_message_never_publishes_the_value_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    ResourceOwner = spawn(fun idle/0),
    try
        {ok, Registration = {http_client_registration, Owner, Token}} =
            http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        {ok, nil} = http_client_ffi:attach_resource(
            Registration, ResourceOwner
        ),
        Reference = make_ref(),
        Owner ! {checkin_resource_before, self(), Reference, Token,
            <<"h3|origin">>, marker,
            erlang:monotonic_time(millisecond) - 1},
        receive
            {Reference, Result} -> ?assertEqual({error, 1}, Result)
        after 1000 ->
            ?assert(false)
        end,
        ?assertEqual(
            {1, 0, 0, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)
        )
    after
        exit(ResourceOwner, kill),
        http_client_ffi:close(Lifecycle)
    end.

resource_and_tcp_share_the_connection_budget_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    try
        {ok, Lease} = http_client_ffi:register_socket(Lifecycle, <<"origin">>, #{}),
        ?assertEqual({error, 2}, http_client_ffi:reserve_resource(Lifecycle, <<"origin">>)),
        nil = http_client_ffi:unregister_socket(Lease),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(Lifecycle, <<"origin">>))
    after http_client_ffi:close(Lifecycle) end.

close_terminates_an_adopted_resource_owner_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Owner = spawn(fun idle/0),
    Monitor = monitor(process, Owner),
    try
        {ok, Lease} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        ?assertEqual({ok, nil}, http_client_ffi:attach_resource(Lease, Owner)),
        nil = http_client_ffi:close(Lifecycle),
        receive {'DOWN', Monitor, process, Owner, _} -> ok after 1000 -> ?assert(false) end
    after exit(Owner, kill), demonitor(Monitor, [flush]), http_client_ffi:close(Lifecycle) end.

late_adoption_after_close_reclaims_the_resource_owner_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {ok, Lease} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
    nil = http_client_ffi:close(Lifecycle),
    Owner = spawn(fun idle/0),
    Monitor = monitor(process, Owner),
    try
        ?assertEqual({error, 1}, http_client_ffi:attach_resource(Lease, Owner)),
        receive {'DOWN', Monitor, process, Owner, _} -> ok after 1000 -> ?assert(false) end
    after exit(Owner, kill), demonitor(Monitor, [flush]) end.

idle_resource_pool_preserves_value_and_closes_on_drain_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Owner = spawn(fun idle/0),
    Monitor = monitor(process, Owner),
    try
        {ok, Lease} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        {ok, nil} = http_client_ffi:attach_resource(Lease, Owner),
        ?assert(http_client_ffi:checkin_resource(Lease, <<"h3|origin|443">>, marker)),
        ?assertEqual({ok, marker}, http_client_ffi:checkout_resource(Lifecycle, <<"h3|origin|443">>)),
        ?assertEqual({error, 0}, http_client_ffi:checkout_resource(Lifecycle, <<"h3|origin|443">>)),
        ?assert(http_client_ffi:checkin_resource(Lease, <<"h3|origin|443">>, marker)),
        ?assertEqual(1, http_client_ffi:drain(Lifecycle)),
        receive {'DOWN', Monitor, process, Owner, _} -> ok after 1000 -> ?assert(false) end,
        ?assertEqual({error, 1}, http_client_ffi:checkout_resource(Lifecycle, <<"h3|origin|443">>))
    after exit(Owner, kill), demonitor(Monitor, [flush]), http_client_ffi:close(Lifecycle) end.

abandoned_reservation_releases_capacity_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Parent = self(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Parent ! {reserved, http_client_ffi:reserve_resource(Lifecycle, <<"origin">>)}
    end),
    try
        receive {reserved, Result} -> ?assertMatch({ok, _}, Result) after 1000 -> ?assert(false) end,
        receive {'DOWN', Monitor, process, Pid, _} -> ok after 1000 -> ?assert(false) end,
        ?assertMatch({ok, _}, await_capacity(Lifecycle, 100))
    after exit(Pid, kill), demonitor(Monitor, [flush]), http_client_ffi:close(Lifecycle) end.

socket_owner_handoff_releases_capacity_on_new_owner_down_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    Owner = spawn(fun idle/0),
    OwnerMonitor = monitor(process, Owner),
    try
        {ok, _Registration} =
            http_client_ffi:register_socket(Lifecycle, <<"origin">>, Socket),
        ?assertEqual({1, 0, 1, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        ?assertEqual(
            {ok, nil},
            http_client_ffi:transfer_and_adopt_socket_owner(
                Lifecycle, Socket, Owner
            )
        ),
        ?assertEqual({1, 0, 0, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        exit(Owner, kill),
        receive
            {'DOWN', OwnerMonitor, process, Owner, _} -> ok
        after 1000 -> ?assert(false)
        end,
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        ?assert(peer_closed(Peer)),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(
            Lifecycle, <<"replacement">>
        ))
    after
        exit(Owner, kill),
        demonitor(OwnerMonitor, [flush]),
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer)
    end.

reserved_socket_adoption_installs_owner_monitor_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    try
        {ok, Reservation} =
            http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        ?assertEqual(
            {ok, nil},
            http_client_ffi:attach_reserved_socket(Reservation, Socket)
        ),
        ?assertEqual({1, 0, 1, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        nil = http_client_ffi:unregister_socket(Reservation),
        ?assertEqual({0, 0, 0, 0}, http_client_ffi:lifecycle_snapshot(Lifecycle))
    after
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer)
    end.

tls_replacement_refreshes_the_owned_socket_monitor_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Raw, RawPeer} = socket_pair(),
    {Secured, SecuredPeer} = socket_pair(),
    try
        {ok, RawRegistration} =
            http_client_ffi:register_socket(Lifecycle, <<"origin">>, Raw),
        ?assertEqual(
            {ok, nil},
            http_client_ffi:replace_socket(Lifecycle, Raw, Secured)
        ),
        nil = http_client_ffi:unregister_socket(RawRegistration),
        ?assertEqual({1, 0, 1, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        ?assertEqual(
            {ok, {0, 0, 0, 0}},
            refresh_and_release_socket(Lifecycle, Secured, 500)
        )
    after
        http_client_ffi:close(Lifecycle),
        close_pair(Raw, RawPeer),
        close_pair(Secured, SecuredPeer)
    end.

http1_pool_updates_owner_on_checkin_and_checkout_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    Parent = self(),
    Borrower = spawn(fun() ->
        receive begin_checkout ->
            Outcome = case http_client_ffi:checkout_socket(
                Lifecycle, <<"origin">>
            ) of
                {ok, _BorrowedSocket} -> borrowed;
                _ -> refused
            end,
            Parent ! {http1_checkout, Outcome},
            idle()
        end
    end),
    BorrowerMonitor = monitor(process, Borrower),
    try
        {ok, _Registration} =
            http_client_ffi:register_socket(Lifecycle, <<"origin">>, Socket),
        ?assert(http_client_ffi:checkin_socket(Lifecycle, <<"origin">>, Socket)),
        ?assertEqual({1, 1, 0, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        Borrower ! begin_checkout,
        receive
            {http1_checkout, Outcome} -> ?assertEqual(borrowed, Outcome)
        after 1000 -> ?assert(false)
        end,
        ?assertEqual({1, 0, 0, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        exit(Borrower, kill),
        receive
            {'DOWN', BorrowerMonitor, process, Borrower, _} -> ok
        after 1000 -> ?assert(false)
        end,
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        ?assert(peer_closed(Peer))
    after
        exit(Borrower, kill),
        demonitor(BorrowerMonitor, [flush]),
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer)
    end.

http2_pool_updates_lifecycle_owner_on_checkin_and_checkout_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Pool = http_client_ffi:new_http2_pool(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    Parent = self(),
    Borrower = spawn(fun() ->
        receive begin_checkout ->
            Outcome = case http_client_ffi:checkout_http2(
                Pool, Lifecycle, <<"origin">>
            ) of
                {ok, {_BorrowedSocket, wire_state, _Cleanup}} -> borrowed;
                _ -> refused
            end,
            Parent ! {http2_checkout, Outcome},
            idle()
        end
    end),
    BorrowerMonitor = monitor(process, Borrower),
    try
        {ok, Registration} =
            http_client_ffi:register_socket(Lifecycle, <<"origin">>, Socket),
        Cleanup = fun() -> http_client_ffi:unregister_socket(Registration) end,
        ?assert(http_client_ffi:checkin_http2(
            Pool, Lifecycle, <<"origin">>, Socket, wire_state, Cleanup
        )),
        ?assertEqual({1, 0, 0, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        Borrower ! begin_checkout,
        receive
            {http2_checkout, Outcome} -> ?assertEqual(borrowed, Outcome)
        after 1000 -> ?assert(false)
        end,
        ?assertEqual({1, 0, 0, 1}, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        exit(Borrower, kill),
        receive
            {'DOWN', BorrowerMonitor, process, Borrower, _} -> ok
        after 1000 -> ?assert(false)
        end,
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        ?assert(peer_closed(Peer))
    after
        exit(Borrower, kill),
        demonitor(BorrowerMonitor, [flush]),
        http_client_ffi:close_http2_pool(Pool),
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer)
    end.

http1_checkin_previous_owner_death_after_transfer_test() ->
    checkin_handoff_death_contract(http1, previous).

http1_checkin_next_owner_death_after_transfer_test() ->
    checkin_handoff_death_contract(http1, next).

http2_checkin_previous_owner_death_after_transfer_test() ->
    checkin_handoff_death_contract(http2, previous).

http2_checkin_next_owner_death_after_transfer_test() ->
    checkin_handoff_death_contract(http2, next).

http1_checkout_previous_owner_death_after_transfer_test() ->
    checkout_handoff_death_contract(http1, previous).

http1_checkout_next_owner_death_after_transfer_test() ->
    checkout_handoff_death_contract(http1, next).

http2_checkout_previous_owner_death_after_transfer_test() ->
    checkout_handoff_death_contract(http2, previous).

http2_checkout_next_owner_death_after_transfer_test() ->
    checkout_handoff_death_contract(http2, next).

combined_adoption_previous_owner_death_after_transfer_test() ->
    combined_adoption_death_contract(previous).

combined_adoption_next_owner_death_after_transfer_test() ->
    combined_adoption_death_contract(next).

socket_handoff_monitor_system_limit_is_fail_closed_test() ->
    socket_handoff_monitor_fault_contract(system_limit).

socket_handoff_monitor_badarg_is_fail_closed_test() ->
    socket_handoff_monitor_fault_contract(badarg).

http2_socket_handoff_monitor_system_limit_is_fail_closed_test() ->
    http2_socket_handoff_monitor_fault_contract(system_limit).

socket_handoff_untrusted_owner_tuple_is_rejected_test_() ->
    {spawn, fun socket_handoff_untrusted_owner_mailbox_contract/0}.

socket_handoff_untrusted_owner_mailbox_contract() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Owner = http_client_ffi:lifecycle_owner(Lifecycle),
    OwnerMonitor = monitor(process, Owner),
    ReplyAlias = erlang:alias(),
    Reference = make_ref(),
    OwnerReference = make_ref(),
    try
        Owner ! {begin_socket_handoff, self(), ReplyAlias, Reference,
            make_ref(), opaque_transport, not_a_pid, self(),
            erlang:monotonic_time(millisecond) + 1000},
        Outcome = receive
            {Reference, Result} -> Result
        after 1000 ->
            timeout
        end,
        ?assertEqual({error, 1}, Outcome),
        Owner ! {begin_socket_handoff, self(), ReplyAlias, OwnerReference,
            make_ref(), opaque_transport, self(), not_a_pid,
            erlang:monotonic_time(millisecond) + 1000},
        OwnerOutcome = receive
            {OwnerReference, Result2} -> Result2
        after 1000 ->
            timeout
        end,
        ?assertEqual({error, 1}, OwnerOutcome),
        ?assert(is_process_alive(Owner)),
        ?assertEqual({0, 0, 0, 0},
                     http_client_ffi:lifecycle_snapshot(Lifecycle)),
        nil = http_client_ffi:close(Lifecycle),
        ?assert(await_process_down(Owner, OwnerMonitor, 1000)),
        ?assertEqual(0, safe_mailbox_length())
    after
        _ = erlang:unalias(ReplyAlias),
        exit(Owner, kill),
        demonitor(OwnerMonitor, [flush]),
        http_client_ffi:close(Lifecycle),
        flush_reference_messages(Reference),
        flush_reference_messages(OwnerReference)
    end.

socket_handoff_monitor_fault_contract(Fault) ->
    Factory = fun(_Owner) -> erlang:error(Fault) end,
    Lifecycle = http_client_ffi:new_lifecycle_with_handoff_probe(
        1, 1, 1000, self(), Factory
    ),
    Owner = http_client_ffi:lifecycle_owner(Lifecycle),
    OwnerMonitor = monitor(process, Owner),
    {Socket, Peer} = socket_pair(),
    try
        {ok, Registration} = http_client_ffi:register_socket(
            Lifecycle, <<"monitor-fault">>, Socket
        ),
        Before = http_client_ffi:lifecycle_snapshot(Lifecycle),
        ?assertEqual({1, 0, 1, 1}, Before),
        ?assertEqual(false, http_client_ffi:checkin_socket(
            Lifecycle, <<"monitor-fault">>, Socket
        )),
        %% The throwing monitor primitive did not replace or demonitor the
        %% old owner entry. The request path closed the still-owned socket.
        ?assertEqual(Before, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        ?assert(is_process_alive(Owner)),
        ?assert(peer_closed(Peer)),
        nil = http_client_ffi:unregister_socket(Registration),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        nil = http_client_ffi:close(Lifecycle),
        ?assert(await_process_down(Owner, OwnerMonitor, 1000)),
        ?assert(no_handoff_residue(Lifecycle, make_ref()))
    after
        exit(Owner, kill),
        demonitor(OwnerMonitor, [flush]),
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer),
        flush_test_messages(make_ref(), maps:get(handoff_probe, Lifecycle))
    end.

http2_socket_handoff_monitor_fault_contract(Fault) ->
    Factory = fun(_Owner) -> erlang:error(Fault) end,
    Lifecycle = http_client_ffi:new_lifecycle_with_handoff_probe(
        1, 1, 1000, self(), Factory
    ),
    Pool = http_client_ffi:new_http2_pool(1, 1, 1000),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    LifecycleMonitor = monitor(process, LifecycleOwner),
    PoolOwner = maps:get(owner, Pool),
    PoolMonitor = monitor(process, PoolOwner),
    {Socket, Peer} = socket_pair(),
    try
        {ok, Registration} = http_client_ffi:register_socket(
            Lifecycle, <<"http2-monitor-fault">>, Socket
        ),
        Before = http_client_ffi:lifecycle_snapshot(Lifecycle),
        ?assertEqual({1, 0, 1, 1}, Before),
        ?assertEqual(false, http_client_ffi:checkin_http2(
            Pool, Lifecycle, <<"http2-monitor-fault">>, Socket,
            wire_state, fun() -> nil end
        )),
        ?assertEqual(Before, http_client_ffi:lifecycle_snapshot(Lifecycle)),
        ?assert(is_process_alive(LifecycleOwner)),
        ?assert(is_process_alive(PoolOwner)),
        ?assert(peer_closed(Peer)),
        nil = http_client_ffi:unregister_socket(Registration),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        nil = http_client_ffi:close_http2_pool(Pool),
        ?assert(await_process_down(PoolOwner, PoolMonitor, 1000)),
        nil = http_client_ffi:close(Lifecycle),
        ?assert(await_process_down(
            LifecycleOwner, LifecycleMonitor, 1000
        )),
        ?assert(no_handoff_residue(Lifecycle, make_ref()))
    after
        exit(PoolOwner, kill),
        demonitor(PoolMonitor, [flush]),
        exit(LifecycleOwner, kill),
        demonitor(LifecycleMonitor, [flush]),
        http_client_ffi:close_http2_pool(Pool),
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer),
        flush_test_messages(make_ref(), maps:get(handoff_probe, Lifecycle))
    end.

%% Each pool implementation is transport-opaque: the same finite handoff
%% state machine invokes http_transport_ffi:transfer_owner/2 for TCP and TLS.
%% These real-loopback cases kill both ledger participants at the private
%% after-transfer synchronization point. Only typed outcomes, finite counts,
%% phase atoms, and mailbox lengths cross the assertion boundary.
combined_adoption_death_contract(DeadSide) ->
    Lifecycle = http_client_ffi:new_lifecycle_with_handoff_probe(
        1, 1, 1000, self()
    ),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    LifecycleMonitor = monitor(process, LifecycleOwner),
    {Socket, Peer} = socket_pair(),
    Parent = self(),
    Tag = make_ref(),
    {Transferer, TransfererMonitor} = spawn_monitor(fun() ->
        receive
            {Tag, transfer_to, Target} ->
                {ok, _Registration} = http_client_ffi:register_socket(
                    Lifecycle, <<"combined-adoption">>, Socket
                ),
                Outcome = http_client_ffi:transfer_and_adopt_socket_owner(
                    Lifecycle, Socket, Target
                ),
                Parent ! {Tag, adoption_outcome, Outcome,
                    safe_mailbox_length()}
        after 1000 ->
            exit(adoption_start_timeout)
        end
    end),
    {Target, TargetMonitor} = spawn_monitor(fun() ->
        receive
            {Tag, watch_transferer} ->
                Monitor = monitor(process, Transferer),
                receive
                    {Tag, target_stop} -> ok;
                    {'DOWN', Monitor, process, Transferer, _Reason} ->
                        CloseOutcome = case http_transport_ffi:close(Socket) of
                            {ok, nil} -> closed;
                            {error, _Code} -> close_failed
                        end,
                        Parent ! {Tag, target_close, CloseOutcome,
                            safe_mailbox_length()}
                after 1000 ->
                    exit(transferer_down_timeout)
                end,
                demonitor(Monitor, [flush])
        after 1000 ->
            exit(target_start_timeout)
        end
    end),
    try
        transfer_fixture_socket(Socket, Transferer),
        Target ! {Tag, watch_transferer},
        Transferer ! {Tag, transfer_to, Target},
        PausedTransferer = await_socket_handoff_phase(
            Lifecycle, contender_owner_after_transfer
        ),
        require_expected_actor(PausedTransferer, Transferer),
        case DeadSide of
            previous ->
                exit(Transferer, kill),
                ?assert(await_process_down(
                    Transferer, TransfererMonitor, 1000
                )),
                ?assertEqual(
                    {closed, 0}, await_target_close(Tag, 1000)
                ),
                ?assert(await_process_down(Target, TargetMonitor, 1000));
            next ->
                exit(Target, kill),
                ?assert(await_process_down(Target, TargetMonitor, 1000)),
                continue_socket_handoff(Lifecycle, PausedTransferer),
                ?assertEqual(
                    {{error, 1}, 0}, await_adoption_outcome(Tag, 1000)
                ),
                ?assert(await_process_down(
                    Transferer, TransfererMonitor, 1000
                ))
        end,
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        ?assert(peer_closed(Peer)),
        nil = http_client_ffi:close(Lifecycle),
        ?assert(await_process_down(
            LifecycleOwner, LifecycleMonitor, 1000
        )),
        ?assert(no_handoff_residue(Lifecycle, Tag))
    after
        exit(Transferer, kill),
        demonitor(TransfererMonitor, [flush]),
        exit(Target, kill),
        demonitor(TargetMonitor, [flush]),
        exit(LifecycleOwner, kill),
        demonitor(LifecycleMonitor, [flush]),
        http_client_ffi:close(Lifecycle),
        close_pair(Socket, Peer),
        flush_test_messages(Tag, maps:get(handoff_probe, Lifecycle))
    end.

await_target_close(Tag, Timeout) ->
    receive
        {Tag, target_close, Outcome, MailboxLength} ->
            {Outcome, MailboxLength}
    after Timeout ->
        timeout
    end.

await_adoption_outcome(Tag, Timeout) ->
    receive
        {Tag, adoption_outcome, Outcome, MailboxLength} ->
            {Outcome, MailboxLength}
    after Timeout ->
        timeout
    end.

checkin_handoff_death_contract(Kind, DeadSide) ->
    {Lifecycle, Pool, ProbeHandle} = new_socket_handoff_fixture(Kind),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    Actor = maps:get(owner, ProbeHandle),
    ActorMonitor = monitor(process, Actor),
    LifecycleMonitor = case Kind of
        http1 -> none;
        http2 -> monitor(process, LifecycleOwner)
    end,
    {Socket, Peer} = socket_pair(),
    Parent = self(),
    Tag = make_ref(),
    {Worker, WorkerMonitor} = spawn_monitor(fun() ->
        receive
            {Tag, begin_checkin} ->
                {ok, _Registration} = http_client_ffi:register_socket(
                    Lifecycle, <<"handoff-checkin">>, Socket
                ),
                Outcome = socket_checkin_outcome(
                    Kind, Lifecycle, Pool, Socket
                ),
                Parent ! {Tag, checkin_outcome, Outcome,
                    safe_mailbox_length()}
        after 1000 ->
            exit(checkin_start_timeout)
        end
    end),
    try
        transfer_fixture_socket(Socket, Worker),
        Worker ! {Tag, begin_checkin},
        PausedActor = await_socket_handoff_phase(
            ProbeHandle, checkin_handoff_phase(Kind)
        ),
        require_expected_actor(PausedActor, Actor),
        case DeadSide of
            previous ->
                exit(Worker, kill),
                ?assert(await_process_down(Worker, WorkerMonitor, 1000)),
                continue_socket_handoff(ProbeHandle, PausedActor),
                ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
                ?assert(peer_closed(Peer)),
                ?assert(await_mailbox_empty(Actor, 100));
            next ->
                exit(PausedActor, kill),
                ?assert(await_process_down(
                    PausedActor, ActorMonitor, 1000
                )),
                ?assertEqual(
                    {false, 0}, await_checkin_outcome(Tag, 1000)
                ),
                ?assert(await_process_down(Worker, WorkerMonitor, 1000)),
                maybe_assert_lifecycle_converged(Kind, Lifecycle),
                ?assert(peer_closed(Peer))
        end,
        close_handoff_fixture(
            Kind, checkin_actor_state(DeadSide), Lifecycle, Pool, Actor,
            ActorMonitor,
            LifecycleOwner, LifecycleMonitor
        ),
        ?assert(no_handoff_residue(ProbeHandle, Tag))
    after
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(Actor, kill),
        demonitor(ActorMonitor, [flush]),
        case LifecycleMonitor of
            none -> ok;
            _ ->
                exit(LifecycleOwner, kill),
                demonitor(LifecycleMonitor, [flush])
        end,
        close_handoff_fixture_quietly(Kind, Lifecycle, Pool),
        close_pair(Socket, Peer),
        flush_test_messages(Tag, maps:get(handoff_probe, ProbeHandle))
    end.

checkout_handoff_death_contract(Kind, DeadSide) ->
    {Lifecycle, Pool, ProbeHandle} = new_socket_handoff_fixture(Kind),
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    Actor = maps:get(owner, ProbeHandle),
    ActorMonitor = monitor(process, Actor),
    LifecycleMonitor = case Kind of
        http1 -> none;
        http2 -> monitor(process, LifecycleOwner)
    end,
    {Socket, Peer} = socket_pair(),
    Parent = self(),
    Tag = make_ref(),
    try
        seed_socket_pool(Kind, Lifecycle, Pool, ProbeHandle, Socket),
        {Borrower, BorrowerMonitor} = spawn_monitor(fun() ->
            Outcome = socket_checkout_outcome(Kind, Lifecycle, Pool),
            Parent ! {Tag, checkout_outcome, Outcome,
                safe_mailbox_length()}
        end),
        PausedActor = await_socket_handoff_phase(
            ProbeHandle, checkout_handoff_phase(Kind)
        ),
        require_expected_actor(PausedActor, Actor),
        case DeadSide of
            previous ->
                exit(PausedActor, kill),
                ?assert(await_process_down(
                    PausedActor, ActorMonitor, 1000
                )),
                ?assertEqual(
                    {{error, 1}, 0}, await_checkout_outcome(Tag, 1000)
                ),
                ?assert(await_process_down(
                    Borrower, BorrowerMonitor, 1000
                )),
                maybe_assert_lifecycle_converged(Kind, Lifecycle),
                ?assert(peer_closed(Peer));
            next ->
                exit(Borrower, kill),
                ?assert(await_process_down(
                    Borrower, BorrowerMonitor, 1000
                )),
                continue_socket_handoff(ProbeHandle, PausedActor),
                ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
                ?assert(peer_closed(Peer)),
                ?assert(await_mailbox_empty(Actor, 100))
        end,
        demonitor(BorrowerMonitor, [flush]),
        close_handoff_fixture(
            Kind, checkout_actor_state(DeadSide), Lifecycle, Pool, Actor,
            ActorMonitor,
            LifecycleOwner, LifecycleMonitor
        ),
        ?assert(no_handoff_residue(ProbeHandle, Tag))
    after
        exit(Actor, kill),
        demonitor(ActorMonitor, [flush]),
        case LifecycleMonitor of
            none -> ok;
            _ ->
                exit(LifecycleOwner, kill),
                demonitor(LifecycleMonitor, [flush])
        end,
        close_handoff_fixture_quietly(Kind, Lifecycle, Pool),
        close_pair(Socket, Peer),
        flush_test_messages(Tag, maps:get(handoff_probe, ProbeHandle))
    end.

new_socket_handoff_fixture(http1) ->
    Lifecycle = http_client_ffi:new_lifecycle_with_handoff_probe(
        1, 1, 1000, self()
    ),
    {Lifecycle, none, Lifecycle};
new_socket_handoff_fixture(http2) ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    Pool = http_client_ffi:new_http2_pool_with_handoff_probe(
        1, 1, 1000, self()
    ),
    {Lifecycle, Pool, Pool}.

socket_checkin_outcome(http1, Lifecycle, _Pool, Socket) ->
    http_client_ffi:checkin_socket(
        Lifecycle, <<"handoff-checkin">>, Socket
    );
socket_checkin_outcome(http2, Lifecycle, Pool, Socket) ->
    http_client_ffi:checkin_http2(
        Pool,
        Lifecycle,
        <<"handoff-checkin">>,
        Socket,
        handoff_wire_state,
        fun() -> nil end
    ).

socket_checkout_outcome(http1, Lifecycle, _Pool) ->
    case http_client_ffi:checkout_socket(
        Lifecycle, <<"handoff-checkout">>
    ) of
        {error, Code} -> {error, Code};
        {ok, _Socket} -> unexpected_success
    end;
socket_checkout_outcome(http2, Lifecycle, Pool) ->
    case http_client_ffi:checkout_http2(
        Pool, Lifecycle, <<"handoff-checkout">>
    ) of
        {error, Code} -> {error, Code};
        {ok, {_Socket, _WireState, _Cleanup}} -> unexpected_success
    end.

seed_socket_pool(Kind, Lifecycle, Pool, ProbeHandle, Socket) ->
    Parent = self(),
    Tag = make_ref(),
    {Seeder, SeederMonitor} = spawn_monitor(fun() ->
        receive
            {Tag, seed} ->
                {ok, _Registration} = http_client_ffi:register_socket(
                    Lifecycle, <<"handoff-checkout">>, Socket
                ),
                Outcome = case Kind of
                    http1 -> http_client_ffi:checkin_socket(
                        Lifecycle, <<"handoff-checkout">>, Socket
                    );
                    http2 -> http_client_ffi:checkin_http2(
                        Pool,
                        Lifecycle,
                        <<"handoff-checkout">>,
                        Socket,
                        handoff_wire_state,
                        fun() -> nil end
                    )
                end,
                Parent ! {Tag, seed_outcome, Outcome,
                    safe_mailbox_length()}
        after 1000 ->
            exit(seed_start_timeout)
        end
    end),
    transfer_fixture_socket(Socket, Seeder),
    Seeder ! {Tag, seed},
    Actor = await_socket_handoff_phase(
        ProbeHandle, checkin_handoff_phase(Kind)
    ),
    require_expected_actor(Actor, maps:get(owner, ProbeHandle)),
    continue_socket_handoff(ProbeHandle, Actor),
    Seeded = receive
        {Tag, seed_outcome, Outcome, MailboxLength} ->
            {Outcome, MailboxLength}
    after 1000 ->
        erlang:error(seed_result_timeout)
    end,
    case Seeded of
        {true, 0} -> ok;
        _ -> erlang:error(seed_handoff_failed)
    end,
    case await_process_down(Seeder, SeederMonitor, 1000) of
        true -> ok;
        false -> erlang:error(seed_join_timeout)
    end.

checkin_handoff_phase(http1) -> http1_checkin_after_transfer;
checkin_handoff_phase(http2) -> http2_checkin_after_transfer.

checkout_handoff_phase(http1) -> http1_checkout_after_transfer;
checkout_handoff_phase(http2) -> http2_checkout_after_transfer.

await_socket_handoff_phase(ProbeHandle, Phase) ->
    ProbeReference = maps:get(handoff_probe, ProbeHandle),
    receive
        {http_client_socket_handoff, ProbeReference, Phase, Actor}
                when is_pid(Actor) ->
            Actor
    after 1000 ->
        erlang:error(socket_handoff_probe_timeout)
    end.

continue_socket_handoff(ProbeHandle, Actor) ->
    ProbeReference = maps:get(handoff_probe, ProbeHandle),
    Actor ! {http_client_socket_handoff_continue, ProbeReference},
    ok.

require_expected_actor(Actual, Expected) ->
    case Actual =:= Expected of
        true -> ok;
        false -> erlang:error(unexpected_socket_handoff_actor)
    end.

transfer_fixture_socket(Socket, Owner) ->
    case http_transport_ffi:transfer_owner(Socket, Owner) of
        {ok, nil} -> ok;
        {error, _Code} -> erlang:error(socket_fixture_transfer_failed)
    end.

await_checkin_outcome(Tag, Timeout) ->
    receive
        {Tag, checkin_outcome, Outcome, MailboxLength} ->
            {Outcome, MailboxLength}
    after Timeout ->
        timeout
    end.

await_checkout_outcome(Tag, Timeout) ->
    receive
        {Tag, checkout_outcome, Outcome, MailboxLength} ->
            {Outcome, MailboxLength}
    after Timeout ->
        timeout
    end.

safe_mailbox_length() ->
    case process_info(self(), message_queue_len) of
        {message_queue_len, Length} when is_integer(Length), Length >= 0 ->
            Length;
        _ -> -1
    end.

await_mailbox_empty(Pid, Remaining) when Remaining > 0 ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, 0} -> true;
        {message_queue_len, _Length} ->
            receive after 1 -> await_mailbox_empty(Pid, Remaining - 1) end;
        undefined -> false
    end;
await_mailbox_empty(Pid, 0) ->
    process_info(Pid, message_queue_len) =:= {message_queue_len, 0}.

maybe_assert_lifecycle_converged(http1, _Lifecycle) -> ok;
maybe_assert_lifecycle_converged(http2, Lifecycle) ->
    ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)).

checkin_actor_state(previous) -> actor_alive;
checkin_actor_state(next) -> actor_dead.

checkout_actor_state(previous) -> actor_dead;
checkout_actor_state(next) -> actor_alive.

close_handoff_fixture(
    http1, actor_alive, Lifecycle, _Pool, _Actor, ActorMonitor,
    _LifecycleOwner, _LifecycleMonitor
) ->
    nil = http_client_ffi:close(Lifecycle),
    ?assert(await_process_down(
        http_client_ffi:lifecycle_owner(Lifecycle), ActorMonitor, 1000
    ));
close_handoff_fixture(
    http1, actor_dead, _Lifecycle, _Pool, _Actor, _ActorMonitor,
    _LifecycleOwner, _LifecycleMonitor
) ->
    ok;
close_handoff_fixture(
    http2, actor_alive, Lifecycle, Pool, Actor, ActorMonitor,
    LifecycleOwner, LifecycleMonitor
) ->
    nil = http_client_ffi:close_http2_pool(Pool),
    ?assert(await_process_down(Actor, ActorMonitor, 1000)),
    nil = http_client_ffi:close(Lifecycle),
    ?assert(await_process_down(LifecycleOwner, LifecycleMonitor, 1000));
close_handoff_fixture(
    http2, actor_dead, Lifecycle, Pool, _Actor, _ActorMonitor,
    LifecycleOwner, LifecycleMonitor
) ->
    nil = http_client_ffi:close_http2_pool(Pool),
    nil = http_client_ffi:close(Lifecycle),
    ?assert(await_process_down(LifecycleOwner, LifecycleMonitor, 1000)).

close_handoff_fixture_quietly(http1, Lifecycle, _Pool) ->
    http_client_ffi:close(Lifecycle);
close_handoff_fixture_quietly(http2, Lifecycle, Pool) ->
    http_client_ffi:close_http2_pool(Pool),
    http_client_ffi:close(Lifecycle).

no_handoff_residue(ProbeHandle, Tag) ->
    ProbeReference = maps:get(handoff_probe, ProbeHandle),
    receive
        {http_client_socket_handoff, ProbeReference, _Phase, _Actor} -> false;
        {Tag, _Kind, _Outcome, _MailboxLength} -> false
    after 0 ->
        true
    end.

flush_test_messages(Tag, ProbeReference) ->
    receive
        {http_client_socket_handoff, ProbeReference, _Phase, _Actor} ->
            flush_test_messages(Tag, ProbeReference);
        {Tag, _Kind, _Outcome, _MailboxLength} ->
            flush_test_messages(Tag, ProbeReference)
    after 0 ->
        ok
    end.

flush_reference_messages(Reference) ->
    receive
        {Reference, _Result} -> flush_reference_messages(Reference)
    after 0 ->
        ok
    end.

expired_policy_items_are_evicted_without_a_store_request_test() ->
    Store = http_client_ffi:new_policy_store(8, 1024),
    Partition = <<"hsts-partition">>,
    Key = <<"expired.example">>,
    ExpiresAt = erlang:monotonic_time(millisecond) + 50,
    try
        ?assert(http_client_ffi:policy_store_put(
            Store, Partition, Key, marker, ExpiresAt, 32)),
        ?assertEqual([marker], http_client_ffi:policy_store_list(Store, Partition)),
        receive after 150 -> ok end,
        ?assertEqual([], http_client_ffi:policy_store_list(Store, Partition))
    after
        http_client_ffi:close_policy_store(Store)
    end.

pending_resource_checkout_is_reclaimed_by_drain() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    {_Registration, ResourceOwner, ResourceMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|pending-drain">>),
    {Worker, WorkerMonitor, Offered} = start_checkout_holder(
        Lifecycle, <<"h3|pending-drain">>, 2000
    ),
    try
        ?assertEqual(offered, Offered),
        ?assertEqual(1, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        ?assertEqual(1, http_client_ffi:drain(Lifecycle)),
        ?assert(await_snapshot(Lifecycle, {0, 0, 0, 0}, 100)),
        ?assert(await_process_down(ResourceOwner, ResourceMonitor, 1000)),
        ?assertEqual(0, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        ?assert(await_worker_down(Worker, WorkerMonitor, 1000))
    after
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

pending_resource_checkout_is_reclaimed_by_close() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 2000),
    {_Registration, ResourceOwner, ResourceMonitor} =
        pooled_marker(Lifecycle, 1, <<"h3|pending-close">>),
    {Worker, WorkerMonitor, Offered} = start_checkout_holder(
        Lifecycle, <<"h3|pending-close">>, 2000
    ),
    try
        ?assertEqual(offered, Offered),
        ?assertEqual(1, http_client_ffi:lifecycle_pending_count(Lifecycle)),
        ?assertEqual(nil, http_client_ffi:close(Lifecycle)),
        ?assert(await_process_down(ResourceOwner, ResourceMonitor, 1000)),
        ?assertEqual(2, http_client_ffi:state(Lifecycle)),
        ?assert(await_worker_down(Worker, WorkerMonitor, 1000))
    after
        exit(Worker, kill),
        demonitor(WorkerMonitor, [flush]),
        exit(ResourceOwner, kill),
        demonitor(ResourceMonitor, [flush]),
        http_client_ffi:close(Lifecycle)
    end.

pooled_marker(Lifecycle, Identifier, Key) ->
    ResourceOwner = spawn(fun idle/0),
    ResourceMonitor = monitor(process, ResourceOwner),
    Origin = <<"origin-", (integer_to_binary(Identifier))/binary>>,
    {ok, Registration} = http_client_ffi:reserve_resource(
        Lifecycle, Origin
    ),
    {ok, nil} = http_client_ffi:attach_resource(
        Registration, ResourceOwner
    ),
    true = http_client_ffi:checkin_resource(
        Registration, Key, {marker, Identifier}
    ),
    {Registration, ResourceOwner, ResourceMonitor}.

start_checkout_holder(Lifecycle, Key, Timeout) ->
    LifecycleOwner = http_client_ffi:lifecycle_owner(Lifecycle),
    Parent = self(),
    Tag = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Reference = make_ref(),
        ReplyAlias = erlang:alias(),
        Deadline = erlang:monotonic_time(millisecond) + Timeout,
        LifecycleOwner ! {checkout_resource_before, self(), ReplyAlias,
            Reference, Key, Deadline},
        Kind = receive
            {Reference, {offer, _Value}} -> offered;
            {Reference, {error, _Code}} -> refused
        after Timeout -> no_offer
        end,
        Parent ! {Tag, Kind},
        case Kind of
            offered ->
                receive
                    {Tag, stop} -> ok;
                    {Reference, rejected} -> ok
                after Timeout -> ok
                end;
            _ -> ok
        end,
        _ = erlang:unalias(ReplyAlias)
    end),
    Kind = receive
        {Tag, Value} when is_atom(Value) -> Value
    after Timeout -> no_offer
    end,
    {Worker, Monitor, Kind}.

await_pending_count(Lifecycle, Expected, Remaining) ->
    case http_client_ffi:lifecycle_pending_count(Lifecycle) of
        Expected -> true;
        _Actual when Remaining > 0 ->
            receive after 1 -> await_pending_count(
                Lifecycle, Expected, Remaining - 1
            ) end;
        _Actual -> false
    end.

await_process_down(Pid, Monitor, Timeout) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> true
    after Timeout -> false
    end.

await_worker_down(Pid, Monitor, Timeout) ->
    await_process_down(Pid, Monitor, Timeout).

wait_until(Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining > 0 of
        true -> receive after Remaining -> ok end;
        false -> ok
    end.

delayed_checkout_confirmation_owner(Parent, Tag) ->
    receive
        {checkout_resource_before, Caller, ReplyAlias, Reference, _Key,
                Deadline} ->
            ReplyAlias ! {Reference, {offer, marker}},
            receive
                {confirm_resource_checkout, Caller, ReplyAlias, Reference} ->
                    Parent ! {Tag, confirmation_waiting, Deadline},
                    receive
                        {Tag, release_confirmation} ->
                            ReplyAlias ! {Reference, confirmed},
                            Parent ! {Tag, confirmation_sent},
                            delayed_checkout_confirmation_owner_wait(
                                Parent, Tag, Caller, Reference
                            )
                    after 1000 ->
                        exit(release_confirmation_timeout)
                    end
            after 1000 ->
                exit(confirm_checkout_timeout)
            end
    after 1000 ->
        exit(checkout_offer_timeout)
    end.

delayed_checkout_confirmation_owner_wait(Parent, Tag, Caller, Reference) ->
    receive
        {abandon_resource_checkout, Caller, Reference} ->
            Parent ! {Tag, abandoned},
            receive
                {Tag, stop} -> ok
            after 1000 ->
                exit(stop_instruction_timeout)
            end
    after 1000 ->
        exit(abandon_checkout_timeout)
    end.

await_capacity(Lifecycle, Remaining) ->
    case http_client_ffi:reserve_resource(Lifecycle, <<"origin">>) of
        {error, 2} when Remaining > 0 ->
            receive after 1 -> await_capacity(Lifecycle, Remaining - 1) end;
        Result -> Result
    end.

await_snapshot(Lifecycle, Expected, Remaining) ->
    case http_client_ffi:lifecycle_snapshot(Lifecycle) of
        Expected -> true;
        _Actual when Remaining > 0 ->
            receive after 1 -> await_snapshot(
                Lifecycle, Expected, Remaining - 1
            ) end;
        _Actual -> false
    end.

peer_closed(Peer) ->
    gen_tcp:recv(Peer, 0, 1000) =:= {error, closed}.

refresh_and_release_socket(Lifecycle, Socket, Timeout) ->
    Parent = self(),
    Tag = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        case http_client_ffi:register_socket(Lifecycle, <<"origin">>, Socket) of
            {ok, Registration} ->
                Parent ! {Tag, registered},
                receive
                    {Tag, unregister} ->
                        nil = http_client_ffi:unregister_socket(Registration),
                        Parent ! {Tag, released},
                        receive
                            {Tag, finish} -> ok
                        after Timeout -> exit(finish_instruction_timeout)
                        end
                after Timeout ->
                    nil = http_client_ffi:unregister_socket(Registration),
                    exit(release_instruction_timeout)
                end;
            {error, _Code} ->
                Parent ! {Tag, registration_error}
        end
    end),
    receive
        {Tag, registered} ->
            Worker ! {Tag, unregister},
            receive
                {Tag, released} ->
                    Snapshot = http_client_ffi:lifecycle_snapshot(Lifecycle),
                    Worker ! {Tag, finish},
                    case await_registration_worker(Worker, Monitor, Timeout) of
                        ok -> {ok, Snapshot};
                        join_timeout -> join_timeout
                    end;
                {'DOWN', Monitor, process, Worker, _Reason} ->
                    registration_worker_down
            after Timeout ->
                stop_registration_worker(Worker, Monitor, Timeout),
                release_reply_timeout
            end;
        {Tag, registration_error} ->
            stop_registration_worker(Worker, Monitor, Timeout),
            registration_error;
        {'DOWN', Monitor, process, Worker, _Reason} ->
            registration_worker_down
    after Timeout ->
        stop_registration_worker(Worker, Monitor, Timeout),
        registration_reply_timeout
    end.

stop_registration_worker(Worker, Monitor, Timeout) ->
    exit(Worker, kill),
    await_registration_worker(Worker, Monitor, Timeout).

await_registration_worker(Worker, Monitor, Timeout) ->
    receive
        {'DOWN', Monitor, process, Worker, _Reason} -> ok
    after Timeout ->
        demonitor(Monitor, [flush]),
        join_timeout
    end.

socket_pair() ->
    {ok, Listener} = gen_tcp:listen(
        0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]
    ),
    try
        {ok, {_, Port}} = inet:sockname(Listener),
        {ok, Socket} = gen_tcp:connect(
            {127, 0, 0, 1}, Port, [binary, {active, false}], 1000
        ),
        {ok, Peer} = gen_tcp:accept(Listener, 1000),
        {#{kind => tcp, socket => Socket, buffered => <<>>}, Peer}
    after
        gen_tcp:close(Listener)
    end.

close_pair(Socket, Peer) ->
    _ = http_transport_ffi:close(Socket),
    gen_tcp:close(Peer).

idle() -> receive stop -> ok end.
