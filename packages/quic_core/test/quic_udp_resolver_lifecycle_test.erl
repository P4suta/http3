%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_udp_resolver_lifecycle_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

-define(PROBE, quic_udp_resolver_lifecycle_probe).
-define(MAXIMUM_MILLISECONDS, 9223372036854775807).

contracts() ->
    {setup, fun load_probe/0, fun unload_probe/1, [
        fun deadline_is_fixed_once_and_rejects_expired_start/0,
        fun supervisor_death_before_ready_joins_preowned_resolver/0,
        fun resolver_death_during_callback_joins_supervisor/0,
        fun success_follows_original_resolver_and_supervisor_down/0,
        fun caller_death_reaps_a_trap_exit_resolver/0
    ]}.

deadline_is_fixed_once_and_rejects_expired_start() ->
    ?assertEqual({1600, 1620}, ?PROBE:group_deadlines_at(100, 1500)),
    ?assertEqual({ok, 119, 125}, ?PROBE:resolver_deadlines(100, 25)),
    ?assertEqual(
        error,
        ?PROBE:resolver_deadlines(?MAXIMUM_MILLISECONDS - 10, 25)
    ),
    ?assertEqual(true, ?PROBE:resolver_may_start(99, 100, 120)),
    ?assertEqual(false, ?PROBE:resolver_may_start(100, 100, 120)),
    ?assertEqual(true, ?PROBE:resolver_result_is_timely(99, 100)),
    ?assertEqual(false, ?PROBE:resolver_result_is_timely(100, 100)),
    ?assertEqual(false, ?PROBE:resolver_result_is_timely(101, 100)),
    Parent = self(),
    Started = make_ref(),
    ?assertEqual(
        {error, 2},
        ?PROBE:resolve_operation_with_deadline(
            fun() -> Parent ! Started, {ok, []} end,
            0,
            20
        )
    ),
    receive Started -> error(expired_resolver_was_started)
    after 0 -> ok
    end.

supervisor_death_before_ready_joins_preowned_resolver() ->
    Parent = self(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Now = ?PROBE:monotonic_millisecond(),
        Result = ?PROBE:resolve_operation_with_supervisor_hook(
            fun() ->
                Parent ! resolver_started_before_supervisor_ready,
                {ok, []}
            end,
            fun() -> ok end,
            fun() ->
                Parent ! {resolver_supervisor_pre_ready, self()},
                receive release_supervisor -> ok end
            end,
            Now + 1000,
            Now + 1020
        ),
        Parent ! {pre_ready_resolution_result, Result},
        Residue = receive _Unexpected -> residue after 0 -> clean end,
        Parent ! {pre_ready_resolution_mailbox, Residue}
    end),
    Supervisor = receive
        {resolver_supervisor_pre_ready, SupervisorPid} -> SupervisorPid
    after 1000 ->
        error(supervisor_pre_ready_hook_not_reached)
    end,
    {links, Links} = process_info(Supervisor, links),
    Resolver = only_process(Links),
    SupervisorMonitor = monitor(process, Supervisor),
    ResolverMonitor = monitor(process, Resolver),
    exit(Supervisor, kill),
    ?assertEqual({error, 8}, receive
        {pre_ready_resolution_result, Result} -> Result
    after 1000 -> missing_pre_ready_result
    end),
    await_down(Supervisor, SupervisorMonitor),
    await_down(Resolver, ResolverMonitor),
    await_down(Caller, CallerMonitor),
    ?assertEqual(false, is_process_alive(Supervisor)),
    ?assertEqual(false, is_process_alive(Resolver)),
    receive resolver_started_before_supervisor_ready ->
        error(gated_resolver_started)
    after 0 -> ok
    end,
    ?assertEqual(clean, receive
        {pre_ready_resolution_mailbox, Mailbox} -> Mailbox
    after 1000 -> missing_pre_ready_mailbox_observation
    end).

resolver_death_during_callback_joins_supervisor() ->
    Parent = self(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Now = ?PROBE:monotonic_millisecond(),
        Result = ?PROBE:resolve_operation_with_deadline(
            fun() ->
                {links, Links} = process_info(self(), links),
                Parent ! {resolver_callback_blocked, self(), Links},
                receive continue_resolution -> {ok, []} end
            end,
            Now + 1000,
            Now + 1020
        ),
        Parent ! {resolver_death_result, Result},
        Residue = receive _Unexpected -> residue after 0 -> clean end,
        Parent ! {resolver_death_mailbox, Residue}
    end),
    {Resolver, Supervisor} = receive
        {resolver_callback_blocked, ResolverPid, Links} ->
            {ResolverPid, only_process(Links)}
    after 1000 ->
        error(resolver_callback_not_reached)
    end,
    ResolverMonitor = monitor(process, Resolver),
    SupervisorMonitor = monitor(process, Supervisor),
    exit(Resolver, kill),
    ?assertEqual({error, 8}, receive
        {resolver_death_result, Result} -> Result
    after 1000 -> missing_resolver_death_result
    end),
    await_down(Resolver, ResolverMonitor),
    await_down(Supervisor, SupervisorMonitor),
    await_down(Caller, CallerMonitor),
    ?assertEqual(clean, receive
        {resolver_death_mailbox, Mailbox} -> Mailbox
    after 1000 -> missing_resolver_death_mailbox
    end).

success_follows_original_resolver_and_supervisor_down() ->
    Parent = self(),
    Gate = make_ref(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Now = ?PROBE:monotonic_millisecond(),
        Result = ?PROBE:resolve_operation_with_hooks(
            fun() ->
                {links, Links} = process_info(self(), links),
                Parent ! {resolver_started, self(), Links},
                {ok, [<<127, 0, 0, 1>>]}
            end,
            fun() ->
                Parent ! {resolver_result_sent, self()},
                receive Gate -> ok end
            end,
            Now + 1000,
            Now + 1020
        ),
        Parent ! {resolver_caller_result, Result},
        Residue = receive _Unexpected -> residue after 0 -> clean end,
        Parent ! {resolver_caller_mailbox, Residue}
    end),
    {Resolver, Supervisor} = receive
        {resolver_started, ResolverPid, Links} ->
            {ResolverPid, only_process(Links)}
    after 1000 ->
        error(resolver_did_not_start)
    end,
    ResolverMonitor = monitor(process, Resolver),
    SupervisorMonitor = monitor(process, Supervisor),
    receive {resolver_result_sent, Resolver} -> ok
    after 1000 -> error(provisional_result_not_observed)
    end,
    receive {resolver_caller_result, _} -> error(result_preceded_release)
    after 0 -> ok
    end,
    Resolver ! Gate,
    receive
        {resolver_caller_result, Result} ->
            ?assertEqual({ok, [<<127, 0, 0, 1>>]}, Result),
            ?assertEqual(false, is_process_alive(Resolver)),
            ?assertEqual(false, is_process_alive(Supervisor))
    after 1000 ->
        error(result_did_not_complete)
    end,
    ?assertEqual(clean, receive
        {resolver_caller_mailbox, Mailbox} -> Mailbox
    after 1000 -> missing_mailbox_observation
    end),
    await_down(Resolver, ResolverMonitor),
    await_down(Supervisor, SupervisorMonitor),
    await_down(Caller, CallerMonitor).

caller_death_reaps_a_trap_exit_resolver() ->
    Parent = self(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Now = ?PROBE:monotonic_millisecond(),
        _ = ?PROBE:resolve_operation_with_hooks(
            fun() ->
                process_flag(trap_exit, true),
                {links, Links} = process_info(self(), links),
                Parent ! {trap_exit_resolver, self(), Links},
                {ok, []}
            end,
            fun() ->
                Parent ! {trap_exit_result_sent, self()},
                receive continue -> ok end
            end,
            Now + 1000,
            Now + 1020
        )
    end),
    {Resolver, Supervisor} = receive
        {trap_exit_resolver, ResolverPid, Links} ->
            {ResolverPid, only_process(Links)}
    after 1000 ->
        error(trap_exit_resolver_did_not_start)
    end,
    ResolverMonitor = monitor(process, Resolver),
    SupervisorMonitor = monitor(process, Supervisor),
    receive {trap_exit_result_sent, Resolver} -> ok
    after 1000 -> error(provisional_result_not_sent)
    end,
    exit(Caller, kill),
    await_down(Caller, CallerMonitor),
    await_down(Resolver, ResolverMonitor),
    await_down(Supervisor, SupervisorMonitor),
    ?assertEqual(false, is_process_alive(Resolver)),
    ?assertEqual(false, is_process_alive(Supervisor)).

only_process([Pid]) when is_pid(Pid) -> Pid;
only_process(Links) -> error({unexpected_resolver_links, length(Links)}).

await_down(Pid, Monitor) ->
    receive {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after 1000 -> error(process_not_joined)
    end.

load_probe() ->
    {ok, Forms} = epp:parse_file("src/quic_core_udp_ffi.erl", [], []),
    Modified = [rewrite(Form) || Form <- Forms],
    {ok, ?PROBE, Beam, _Warnings} = compile:forms(
        Modified, [binary, export_all, return_errors, return_warnings]
    ),
    {module, ?PROBE} = code:load_binary(
        ?PROBE, "resolver-lifecycle-test-only", Beam
    ),
    ok.

rewrite({attribute, Line, module, quic_core_udp_ffi}) ->
    {attribute, Line, module, ?PROBE};
rewrite(Value) -> Value.

unload_probe(_) ->
    code:purge(?PROBE),
    code:delete(?PROBE),
    ok.
