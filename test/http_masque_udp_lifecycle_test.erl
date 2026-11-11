%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_masque_udp_lifecycle_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

-define(PROBE, http_masque_udp_lifecycle_probe).

contracts() ->
    {setup, fun load_probe/0, fun unload_probe/1, [
        fun one_absolute_deadline_contains_the_cleanup_tail/0,
        fun timeout_confirmation_preserves_credit_without_admitting_late_data/0,
        fun close_reply_is_provisional_until_owner_down/0,
        fun expired_close_starts_no_command_and_reaps_trap_exit_owner/0,
        fun expired_setup_gate_starts_no_socket_work/0,
        fun adoption_publishes_open_before_success_reply/0,
        fun stale_adoption_closes_socket_before_typed_timeout/0,
        fun deadline_first_setup_expiry_remains_typed_timeout/0,
        fun setup_caller_death_reaps_the_pre_start_owner/0
    ]}.

one_absolute_deadline_contains_the_cleanup_tail() ->
    ?assertEqual({119, 125}, ?PROBE:call_deadlines_at(100, 25)),
    ?assertEqual(122, ?PROBE:force_join_at(119, 125)),
    ?assertEqual(true, ?PROBE:operation_reply_is_timely(118, 119)),
    ?assertEqual(false, ?PROBE:operation_reply_is_timely(119, 119)),
    ?assertEqual(false, ?PROBE:operation_reply_is_timely(120, 119)).

timeout_confirmation_preserves_credit_without_admitting_late_data() ->
    ?assertEqual({receive_udp, 113}, ?PROBE:waiter_command_deadline(
        {receive_udp, 25}, 119, 125
    )),
    ?assertEqual({receive_event, 113}, ?PROBE:waiter_command_deadline(
        {receive_event, 25}, 119, 125
    )),
    ?assert(?PROBE:operation_result_is_timely(118, 119, 125, true, {ok, payload})),
    ?assert(?PROBE:operation_result_is_timely(119, 119, 125, true, {error, 2})),
    ?assert(?PROBE:operation_result_is_timely(121, 119, 125, true, {error, 2})),
    ?assertNot(?PROBE:operation_result_is_timely(122, 119, 125, true, {error, 2})),
    ?assertNot(?PROBE:operation_result_is_timely(119, 119, 125, true, {ok, payload})),
    ?assertNot(?PROBE:operation_result_is_timely(119, 119, 125, false, {error, 2})).

close_reply_is_provisional_until_owner_down() ->
    Parent = self(),
    SocketReference = make_ref(),
    Counters = atomics:new(28, [{signed, true}]),
    {Owner, OwnerMonitor} = spawn_monitor(fun() ->
        receive
            {http_masque_udp_call, SocketReference, CallReference, Caller,
             close} ->
                Parent ! {close_received, self()},
                Caller ! {
                    http_masque_udp_reply, CallReference, {ok, nil}
                },
                receive finish_close -> exit(normal) end
        end
    end),
    Handle = #{
        pid => Owner,
        reference => SocketReference,
        counters => Counters,
        packet_too_big => undefined
    },
    Now = erlang:monotonic_time(millisecond),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Result = ?PROBE:close_call(Handle, {Now + 1000, Now + 2000}),
        Parent ! {close_result, Result},
        Residue = receive _Unexpected -> residue after 0 -> clean end,
        Parent ! {close_mailbox, Residue}
    end),
    receive {close_received, Owner} -> ok
    after 1000 -> error(close_was_not_received)
    end,
    receive {close_result, _} -> error(close_succeeded_before_owner_down)
    after 0 -> ok
    end,
    Owner ! finish_close,
    ?assertEqual({ok, nil}, receive
        {close_result, Result} -> Result
    after 1000 -> missing_close_result
    end),
    ?assertEqual(clean, receive
        {close_mailbox, Mailbox} -> Mailbox
    after 1000 -> missing_mailbox_observation
    end),
    await_down(Owner, OwnerMonitor),
    await_down(Caller, CallerMonitor).

expired_close_starts_no_command_and_reaps_trap_exit_owner() ->
    Parent = self(),
    SocketReference = make_ref(),
    Counters = atomics:new(28, [{signed, true}]),
    {Owner, OwnerMonitor} = spawn_monitor(fun() ->
        process_flag(trap_exit, true),
        Parent ! {trap_exit_owner_ready, self()},
        receive
            {http_masque_udp_call, SocketReference, _CallReference, _Caller,
             close} -> Parent ! close_started_after_expiry
        end
    end),
    receive {trap_exit_owner_ready, Owner} -> ok
    after 1000 -> error(owner_not_ready)
    end,
    Handle = #{
        pid => Owner,
        reference => SocketReference,
        counters => Counters,
        packet_too_big => undefined
    },
    Now = erlang:monotonic_time(millisecond),
    ?assertEqual(
        {error, 8},
        ?PROBE:close_call(Handle, {Now - 1, Now + 100})
    ),
    await_down(Owner, OwnerMonitor),
    receive close_started_after_expiry -> error(expired_close_was_sent)
    after 0 -> ok
    end,
    ?assertEqual(false, is_process_alive(Owner)).

expired_setup_gate_starts_no_socket_work() ->
    Parent = self(),
    StartReference = make_ref(),
    {Owner, OwnerMonitor} = spawn_monitor(fun() ->
        ?PROBE:owner_start_gate(
            Parent,
            StartReference,
            make_ref(),
            atomics:new(28, [{signed, true}]),
            {127, 0, 0, 1},
            4,
            443,
            Parent,
            undefined,
            erlang:monotonic_time(millisecond) - 1
        )
    end),
    receive {StartReference, owner_ready, Owner} -> ok
    after 1000 -> error(setup_gate_not_observed)
    end,
    Owner ! {StartReference, start_owner, Parent},
    await_down(Owner, OwnerMonitor),
    receive
        {StartReference, {error, timeout}} -> ok;
        {StartReference, {ok, _, _, _, _}} -> error(socket_work_started);
        {StartReference, {error, _}} -> error(socket_work_started)
    after 0 -> error(missing_expired_setup_outcome)
    end.

adoption_publishes_open_before_success_reply() ->
    Parent = self(),
    CallReference = make_ref(),
    Counters = atomics:new(28, [{signed, true}]),
    {Publisher, PublisherMonitor} = spawn_monitor(fun() ->
        ?PROBE:publish_adoption(
            Counters,
            Parent,
            CallReference,
            fun() ->
                Parent ! {adoption_state_published, self()},
                receive release_adoption_reply -> ok end
            end
        )
    end),
    try
        receive {adoption_state_published, Publisher} -> ok
        after 1000 -> error(adoption_state_not_published)
        end,
        ?assertEqual(ok, ?PROBE:reserve_command(#{counters => Counters})),
        ?PROBE:release_command(Counters),
        receive
            {http_masque_udp_reply, CallReference, _} ->
                error(adoption_reply_preceded_publication_barrier)
        after 0 -> ok
        end,
        Publisher ! release_adoption_reply,
        ?assertEqual({ok, nil}, receive
            {http_masque_udp_reply, CallReference, Result} -> Result
        after 1000 -> missing_adoption_reply
        end),
        await_down(Publisher, PublisherMonitor),
        ?assertEqual(1, atomics:get(Counters, 1)),
        ?assertEqual(0, atomics:get(Counters, 2))
    after
        Publisher ! release_adoption_reply,
        exit(Publisher, kill),
        cleanup_owner(Publisher),
        erlang:demonitor(PublisherMonitor, [flush]),
        ?PROBE:drain_call_reply(CallReference)
    end.

stale_adoption_closes_socket_before_typed_timeout() ->
    Parent = self(),
    CallReference = make_ref(),
    Counters = atomics:new(28, [{signed, true}]),
    Diagnostics = http_masque_packet_too_big_ffi:diagnostics_new(65527, 4),
    PacketTooBig = {4, 65527, Diagnostics, 1000},
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}, inet]),
    {SetupOwner, SetupMonitor} = spawn_monitor(fun() ->
        receive begin_stale_adoption ->
            StableOwnerMonitor = monitor(process, Parent),
            ?PROBE:reject_expired_adoption(
                Socket,
                StableOwnerMonitor,
                Counters,
                PacketTooBig,
                Parent,
                CallReference,
                fun() ->
                    Parent ! {stale_socket_closed, self()},
                    receive release_stale_timeout -> ok end
                end
            )
        end
    end),
    try
        ok = gen_udp:controlling_process(Socket, SetupOwner),
        SetupOwner ! begin_stale_adoption,
        receive {stale_socket_closed, SetupOwner} -> ok
        after 1000 -> error(stale_close_not_observed)
        end,
        ?assert(is_process_alive(SetupOwner)),
        ?assert(socket_is_closed(Socket)),
        ?assertEqual(3, atomics:get(Counters, 1)),
        receive
            {http_masque_udp_reply, CallReference, _} ->
                error(timeout_preceded_socket_close_barrier)
        after 0 -> ok
        end,
        SetupOwner ! release_stale_timeout,
        ?assertEqual({error, 2}, receive
            {http_masque_udp_reply, CallReference, Result} -> Result
        after 1000 -> missing_stale_timeout
        end),
        await_down(SetupOwner, SetupMonitor),
        receive {stale_socket_closed, SetupOwner} ->
            error(stale_socket_closed_twice)
        after 0 -> ok
        end,
        receive {http_masque_udp_reply, CallReference, _} ->
            error(stale_timeout_replied_twice)
        after 0 -> ok
        end
    after
        SetupOwner ! release_stale_timeout,
        exit(SetupOwner, kill),
        cleanup_owner(SetupOwner),
        case socket_is_closed(Socket) of
            true -> ok;
            false -> try gen_udp:close(Socket) catch _:_ -> ok end
        end,
        erlang:demonitor(SetupMonitor, [flush])
    end.

deadline_first_setup_expiry_remains_typed_timeout() ->
    Parent = self(),
    SocketReference = make_ref(),
    Counters = atomics:new(28, [{signed, true}]),
    Diagnostics = http_masque_packet_too_big_ffi:diagnostics_new(65527, 4),
    PacketTooBig = {4, 65527, Diagnostics, 1000},
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}, inet]),
    {SetupOwner, SetupMonitor} = spawn_monitor(fun() ->
        receive begin_expired_setup ->
            StableOwnerMonitor = monitor(process, Parent),
            ?PROBE:setup_loop(
                Socket,
                {127, 0, 0, 1},
                443,
                Parent,
                StableOwnerMonitor,
                SocketReference,
                Counters,
                PacketTooBig,
                erlang:monotonic_time(millisecond) - 1,
                none
            )
        end
    end),
    try
        ok = gen_udp:controlling_process(Socket, SetupOwner),
        SetupOwner ! begin_expired_setup,
        await_down(SetupOwner, SetupMonitor),
        ?assert(socket_is_closed(Socket)),
        ?assertEqual(2, atomics:get(Counters, 28)),
        Handle = #{
            pid => SetupOwner,
            reference => SocketReference,
            counters => Counters,
            packet_too_big => Diagnostics
        },
        ?assertEqual(
            {error, 2},
            ?PROBE:direct_call(Handle, {adopt, Parent}, 100)
        ),
        receive
            {http_masque_udp_reply, _Reference, _Result} ->
                error(expired_setup_reply_residue)
        after 0 -> ok
        end
    after
        exit(SetupOwner, kill),
        cleanup_owner(SetupOwner),
        case socket_is_closed(Socket) of
            true -> ok;
            false -> try gen_udp:close(Socket) catch _:_ -> ok end
        end,
        erlang:demonitor(SetupMonitor, [flush])
    end.

setup_caller_death_reaps_the_pre_start_owner() ->
    Parent = self(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        SetupCaller = self(),
        StartReference = make_ref(),
        Owner = spawn(fun() ->
            ?PROBE:owner_start_gate(
                SetupCaller,
                StartReference,
                make_ref(),
                atomics:new(28, [{signed, true}]),
                {127, 0, 0, 1},
                4,
                443,
                SetupCaller,
                undefined,
                erlang:monotonic_time(millisecond) + 1000
            )
        end),
        receive
            {StartReference, owner_ready, Owner} ->
                Parent ! {pre_start_owner, Owner},
                receive continue -> ok end
        after 1000 ->
            error(pre_start_owner_not_ready)
        end
    end),
    Owner = receive {pre_start_owner, OwnerPid} -> OwnerPid
    after 1000 -> error(pre_start_owner_not_observed)
    end,
    OwnerMonitor = monitor(process, Owner),
    exit(Caller, kill),
    await_down(Caller, CallerMonitor),
    await_down(Owner, OwnerMonitor),
    ?assertEqual(false, is_process_alive(Owner)).

await_down(Pid, Monitor) ->
    receive {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after 1000 -> error(process_not_joined)
    end.

cleanup_owner(Pid) ->
    Monitor = monitor(process, Pid),
    receive {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after 1000 -> demonitor(Monitor, [flush]), ok
    end.

socket_is_closed(Socket) ->
    try inet:sockname(Socket) of
        {ok, _Endpoint} -> false;
        {error, _Category} -> true
    catch
        _:_ -> true
    end.

load_probe() ->
    {ok, Forms} = epp:parse_file("src/http_masque_udp_ffi.erl", [], []),
    Modified = [rewrite(Form) || Form <- Forms],
    {ok, ?PROBE, Beam, _Warnings} = compile:forms(
        Modified, [binary, export_all, return_errors, return_warnings]
    ),
    {module, ?PROBE} = code:load_binary(
        ?PROBE, "masque-udp-lifecycle-test-only", Beam
    ),
    ok.

rewrite({attribute, Line, module, http_masque_udp_ffi}) ->
    {attribute, Line, module, ?PROBE};
rewrite(Value) -> Value.

unload_probe(_) ->
    code:purge(?PROBE),
    code:delete(?PROBE),
    ok.
