-module(http_transport_fault_ffi).

-export([
    delayed_ipv6_does_not_starve_ipv4_case/0,
    delayed_dns_family_does_not_block_a_usable_answer_case/0,
    address_cap_preserves_both_families_case/0,
    duplicate_answers_do_not_consume_candidate_capacity_case/0,
    all_candidates_share_the_connect_deadline_case/0,
    total_deadline_remains_distinct_from_connect_case/0,
    dns_deadline_remains_distinct_from_connect_case/0,
    failed_dials_leave_no_workers_or_messages_case/0,
    caller_exit_stops_pending_dials_case/0,
    simultaneous_success_closes_every_losing_socket_case/0,
    late_connected_success_closes_the_losing_socket_case/0,
    worker_registry_rejects_unsealed_and_live_processes_case/0,
    malformed_dial_results_are_redacted_case/0,
    trace_is_bounded_and_contains_only_scalar_metadata_case/0
]).

-define(COORDINATOR_KIND, 0).
-define(RESOLVER_KIND, 1).
-define(CANDIDATE_KIND, 2).
-define(TEST_DEADLINE_MILLISECONDS, 3000).
-define(JOIN_DEADLINE_MILLISECONDS, 1500).

delayed_ipv6_does_not_starve_ipv4_case() ->
    with_worker_registry(fun(Registry) ->
        with_listener(fun(Port) ->
            Runtime = runtime(Registry,
                fun(_Host, Family) -> addresses(Family) end,
                fun(Address, TargetPort, Options, Timeout) ->
                    case lists:member(inet6, Options) of
                        true -> receive after Timeout -> {error, timeout} end;
                        false -> gen_tcp:connect(Address, TargetPort, Options, Timeout)
                    end
                end),
            Trace = http_transport_ffi:diagnostics_new(),
            Result = dial(Port, 1000, 1000, 1500, Runtime, Trace),
            require_success_and_close(Result),
            {true, 0, Events} = http_transport_ffi:diagnostics_snapshot(Trace),
            require(has_event(Events, 3, 6), ipv6_attempt_was_not_observed),
            require(has_event(Events, 3, 4), ipv4_attempt_was_not_observed),
            require_kind_count_at_least(Registry, ?CANDIDATE_KIND, 2,
                ipv4_candidate_was_not_created),
            require_runtime_stopped(Registry),
            require_no_dial_messages_after_seal()
        end)
    end).

delayed_dns_family_does_not_block_a_usable_answer_case() ->
    with_worker_registry(fun(Registry) ->
        with_listener(fun(Port) ->
            Runtime = runtime(Registry, fun(_Host, Family) ->
                case Family of
                    inet6 -> receive after 5000 -> {error, timeout} end;
                    inet -> addresses(inet)
                end
            end, fun gen_tcp:connect/4),
            Trace = http_transport_ffi:diagnostics_new(),
            Result = dial(Port, 150, 750, 1000, Runtime, Trace),
            require_success_and_close(Result),
            require_kind_count_at_least(Registry, ?RESOLVER_KIND, 2,
                both_dns_workers_were_not_created),
            require_runtime_stopped(Registry)
        end)
    end).

address_cap_preserves_both_families_case() ->
    with_worker_registry(fun(Registry) ->
        with_listener(fun(Port) ->
            Runtime = runtime(Registry, fun(_Host, Family) ->
                case Family of
                    inet6 ->
                        {ok, [{0, 0, 0, 0, 0, 0, 0, N}
                            || N <- lists:seq(1, 24)]};
                    inet -> addresses(inet)
                end
            end, fun(Address, TargetPort, Options, Timeout) ->
                case lists:member(inet6, Options) of
                    true -> {error, econnrefused};
                    false -> gen_tcp:connect(Address, TargetPort, Options, Timeout)
                end
            end),
            Trace = http_transport_ffi:diagnostics_new(),
            Result = dial(Port, 1000, 1000, 1500, Runtime, Trace),
            require_success_and_close(Result),
            {true, 0, Events} = http_transport_ffi:diagnostics_snapshot(Trace),
            Attempts = [Family || {3, Family, _Index, _At, _Outcome} <- Events],
            require(length(Attempts) =< 16, address_limit_exceeded),
            require(lists:member(4, Attempts), ipv4_was_removed_by_address_cap),
            require_runtime_stopped(Registry)
        end)
    end).

duplicate_answers_do_not_consume_candidate_capacity_case() ->
    with_worker_registry(fun(Registry) ->
        with_listener(fun(Port) ->
            Runtime = runtime(Registry, fun(_Host, Family) ->
                case Family of
                    inet6 -> {ok, []};
                    inet -> {ok, lists:duplicate(16, {192, 0, 2, 1}) ++
                        [{127, 0, 0, 1}]}
                end
            end, fun(Address, TargetPort, Options, Timeout) ->
                case Address of
                    {192, 0, 2, 1} -> {error, econnrefused};
                    _ -> gen_tcp:connect(Address, TargetPort, Options, Timeout)
                end
            end),
            Trace = http_transport_ffi:diagnostics_new(),
            Result = dial(Port, 1000, 1000, 1500, Runtime, Trace),
            require_success_and_close(Result),
            {true, 0, Events} = http_transport_ffi:diagnostics_snapshot(Trace),
            Attempts = [{Family, Index}
                || {3, Family, Index, _, _} <- Events],
            require(Attempts =:= [{4, 1}, {4, 2}],
                duplicate_answer_consumed_capacity),
            require_runtime_stopped(Registry),
            require_no_dial_messages_after_seal()
        end)
    end).

all_candidates_share_the_connect_deadline_case() ->
    with_worker_registry(fun(Registry) ->
        Runtime = stalled_runtime(Registry),
        Trace = http_transport_ffi:diagnostics_new(),
        Result = dial(9, 1000, 80, 1000, Runtime, Trace),
        require(Result =:= {error, 2}, connect_deadline_was_not_preserved),
        require_kind_count_at_least(Registry, ?CANDIDATE_KIND, 1,
            timed_candidate_was_not_created),
        require_runtime_stopped(Registry),
        require_no_dial_messages_after_seal()
    end).

total_deadline_remains_distinct_from_connect_case() ->
    with_worker_registry(fun(Registry) ->
        Runtime = stalled_runtime(Registry),
        Trace = http_transport_ffi:diagnostics_new(),
        Result = dial(9, 1000, 1000, 80, Runtime, Trace),
        require(Result =:= {error, 17}, total_deadline_was_not_preserved),
        require_kind_count_at_least(Registry, ?CANDIDATE_KIND, 1,
            total_deadline_candidate_was_not_created),
        require_runtime_stopped(Registry)
    end).

dns_deadline_remains_distinct_from_connect_case() ->
    with_worker_registry(fun(Registry) ->
        Runtime = runtime(Registry, fun(_Host, _Family) ->
            receive after 5000 -> {error, timeout} end
        end, fun gen_tcp:connect/4),
        Trace = http_transport_ffi:diagnostics_new(),
        Result = dial(9, 50, 1000, 1000, Runtime, Trace),
        require(Result =:= {error, 16}, dns_deadline_was_not_preserved),
        require_kind_count_at_least(Registry, ?RESOLVER_KIND, 2,
            dns_workers_were_not_created),
        require_runtime_stopped(Registry),
        require_no_dial_messages_after_seal()
    end).

failed_dials_leave_no_workers_or_messages_case() ->
    with_worker_registry(fun(Registry) ->
        Runtime = runtime(Registry,
            fun(_Host, Family) -> addresses(Family) end,
            fun(_Address, _Port, _Options, _Timeout) ->
                {error, econnrefused}
            end),
        Trace = http_transport_ffi:diagnostics_new(),
        require(dial(9, 1000, 1000, 1500, Runtime, Trace) =:= {error, 5},
            failed_dial_was_not_typed),
        require_kind_count_at_least(Registry, ?CANDIDATE_KIND, 2,
            failed_candidates_were_not_all_created),
        require_runtime_stopped(Registry),
        require_no_dial_messages_after_seal()
    end).

caller_exit_stops_pending_dials_case() ->
    with_worker_registry(fun(Registry) ->
        Runtime = runtime(Registry,
            fun(_Host, Family) -> addresses(Family) end,
            fun(_Address, _Port, _Options, Timeout) ->
                receive after Timeout -> {error, timeout} end
            end),
        {Caller, CallerMonitor} = spawn_monitor(fun() ->
            dial(9, 1000, 4000, 5000, Runtime,
                http_transport_ffi:diagnostics_new())
        end),
        Deadline = deadline_after(?TEST_DEADLINE_MILLISECONDS),
        _ = await_kind_count(Registry, ?CANDIDATE_KIND, 1, Deadline,
            dial_never_started),
        exit(Caller, kill),
        await_down(CallerMonitor, Caller, Deadline, caller_did_not_stop),
        require_runtime_stopped_within(Registry,
            deadline_after(?JOIN_DEADLINE_MILLISECONDS))
    end).

simultaneous_success_closes_every_losing_socket_case() ->
    successful_candidate_race_case(simultaneous).

late_connected_success_closes_the_losing_socket_case() ->
    successful_candidate_race_case(late).

worker_registry_rejects_unsealed_and_live_processes_case() ->
    with_worker_registry(fun(Registry) ->
        Block = make_ref(),
        Candidate = spawn(fun() -> receive Block -> ok end end),
        register_test_process(Registry, ?CANDIDATE_KIND, Candidate),
        require(runtime_stop_status_now(Registry) =:=
            {seal_missing, 1}, registry_accepted_missing_seal),
        Coordinator = spawn(fun() -> receive Block -> ok end end),
        register_test_process(Registry, ?COORDINATOR_KIND, Coordinator),
        {processes_alive, Alive} = runtime_stop_status_now(Registry),
        require(Alive =:= 2, registry_accepted_live_processes),
        Duplicate = spawn(fun() -> receive Block -> ok end end),
        register_test_process(Registry, ?COORDINATOR_KIND, Duplicate),
        require(runtime_stop_status_now(Registry) =:= {seal_duplicated, 2},
            registry_accepted_duplicate_seal),
        force_stop_and_join([Coordinator, Duplicate, Candidate])
    end).

trace_is_bounded_and_contains_only_scalar_metadata_case() ->
    Trace = http_transport_ffi:diagnostics_new(),
    lists:foreach(fun(_) ->
        with_worker_registry(fun(Registry) ->
            Runtime = runtime(Registry,
                fun(_Host, _Family) -> {error, nxdomain} end,
                fun gen_tcp:connect/4),
            require(dial(9, 50, 50, 100, Runtime, Trace) =:= {error, 4},
                dns_failure_was_not_typed),
            require_runtime_stopped(Registry)
        end)
    end, lists:seq(1, 32)),
    {Consistent, Dropped, Events} =
        http_transport_ffi:diagnostics_snapshot(Trace),
    require(Consistent, completed_trace_was_inconsistent),
    require(length(Events) =< 64, trace_was_unbounded),
    require(Dropped > 0, trace_overflow_was_not_observed),
    require(lists:all(fun(Event) ->
        tuple_size(Event) =:= 5 andalso
            lists:all(fun(Value) ->
                is_integer(Value) andalso Value >= 0
            end, tuple_to_list(Event))
    end, Events), trace_contains_non_scalar_values).

malformed_dial_results_are_redacted_case() ->
    Trace = http_transport_ffi:diagnostics_new(),
    with_worker_registry(fun(Registry) ->
        MalformedRuntime = runtime(Registry,
            fun(_Host, Family) -> addresses(Family) end,
            fun(_Address, _Port, _Options, _Timeout) ->
                {unexpected_backend_value, <<"must-not-enter-diagnostics">>}
            end),
        require(dial(9, 1000, 1000, 1500, MalformedRuntime, Trace) =:=
            {error, 5},
            malformed_runtime_result_was_not_redacted),
        require_runtime_stopped(Registry)
    end),
    with_worker_registry(fun(Registry) ->
        ExceptionRuntime = runtime(Registry,
            fun(_Host, Family) -> addresses(Family) end,
            fun(_Address, _Port, _Options, _Timeout) ->
                erlang:error({private_backend_failure,
                    <<"must-not-enter-diagnostics">>})
            end),
        require(dial(9, 1000, 1000, 1500, ExceptionRuntime, Trace) =:=
            {error, 5}, dial_exception_was_not_typed),
        require_runtime_stopped(Registry)
    end),
    {true, 0, Events} = http_transport_ffi:diagnostics_snapshot(Trace),
    require(lists:all(fun(Event) ->
        lists:all(fun is_integer/1, tuple_to_list(Event))
    end, Events), backend_value_entered_diagnostics).

successful_candidate_race_case(ReleaseMode) ->
    with_worker_registry(fun(Registry) ->
        {ok, Listener} = gen_tcp:listen(0,
            [binary, inet, {active, false}, {ip, {127, 0, 0, 1}}]),
        try
            {ok, {_, Port}} = inet:sockname(Listener),
            Parent = self(),
            Gate = make_ref(),
            Runtime = runtime(Registry,
                fun(_Host, Family) -> addresses(Family) end,
                fun(_Address, TargetPort, _Options, Timeout) ->
                    Result = gen_tcp:connect({127, 0, 0, 1}, TargetPort,
                        [binary, inet, {active, false}], Timeout),
                    case Result of
                        {ok, _} -> record_test_stage(Registry, connected, self());
                        _ -> ok
                    end,
                    receive {publish_candidate, Gate} -> Result
                    %% Deliberately outlast the audit deadline. If production
                    %% cleanup is weakened, the late connected worker remains
                    %% observable and this test fails before fixture cleanup.
                    after ?TEST_DEADLINE_MILLISECONDS * 2 -> Result
                    end
                end),
            ResultReference = make_ref(),
            {Caller, CallerMonitor} = spawn_monitor(fun() ->
                Result = dial(Port, 1000, 1500, 2500, Runtime,
                    http_transport_ffi:diagnostics_new()),
                case Result of
                    {ok, Stream = #{socket := Socket}} ->
                        try gen_tcp:controlling_process(Socket, Parent) of
                            ok ->
                                Parent ! {candidate_race_result,
                                    ResultReference, Stream};
                            {error, _} ->
                                http_transport_ffi:close(Stream),
                                Parent ! {candidate_race_error,
                                    ResultReference, 11}
                        catch
                            _:_ ->
                                http_transport_ffi:close(Stream),
                                Parent ! {candidate_race_error,
                                    ResultReference, 11}
                        end;
                    {error, Code} ->
                        Parent ! {candidate_race_error, ResultReference, Code}
                end
            end),
            try
                Deadline = deadline_after(?TEST_DEADLINE_MILLISECONDS),
                Candidates = await_stage_count(Registry, connected, 2,
                    Deadline, both_candidates_did_not_connect),
                Peer1 = accept_until(Listener, Deadline),
                Peer2 = accept_until(Listener, Deadline),
                try
                    release_candidates(Candidates, ReleaseMode, Gate),
                    Winner = receive_race_winner(ResultReference, Deadline),
                    try
                        await_down(CallerMonitor, Caller, Deadline,
                            caller_did_not_converge),
                        require_runtime_stopped(Registry),
                        require_one_winner_and_one_closed_peer(
                            Winner, Peer1, Peer2, Deadline)
                    after
                        http_transport_ffi:close(Winner)
                    end
                after
                    gen_tcp:close(Peer1),
                    gen_tcp:close(Peer2)
                end
            after
                exit(Caller, kill),
                erlang:demonitor(CallerMonitor, [flush])
            end
        after
            gen_tcp:close(Listener)
        end
    end).

release_candidates(Candidates, simultaneous, Gate) ->
    lists:foreach(fun(Pid) -> Pid ! {publish_candidate, Gate} end, Candidates);
release_candidates([First | _], late, Gate) ->
    First ! {publish_candidate, Gate}.

receive_race_winner(Reference, Deadline) ->
    receive
        {candidate_race_result, Reference, Stream} -> Stream;
        {candidate_race_error, Reference, _Code} ->
            erlang:error(candidate_race_connect_failed)
    after remaining_milliseconds(Deadline) ->
        erlang:error(winner_was_not_delivered)
    end.

require_one_winner_and_one_closed_peer(Winner, Peer1, Peer2, Deadline) ->
    arm_peer(Peer1),
    arm_peer(Peer2),
    {ok, nil} = http_transport_ffi:send(Winner, <<1>>),
    await_peer_outcomes([Peer1, Peer2], none, none, Deadline).

arm_peer(Peer) ->
    try inet:setopts(Peer, [{active, once}]) of
        ok -> ok;
        {error, closed} -> mark_peer_closed(Peer);
        {error, einval} -> mark_peer_closed(Peer);
        {error, badarg} -> mark_peer_closed(Peer);
        {error, econnreset} -> mark_peer_closed(Peer);
        {error, enotconn} -> mark_peer_closed(Peer);
        {error, _} -> erlang:error(candidate_peer_could_not_be_observed)
    catch
        error:badarg -> mark_peer_closed(Peer);
        _:_ -> erlang:error(candidate_peer_could_not_be_observed)
    end.

mark_peer_closed(Peer) ->
    self() ! {tcp_closed, Peer},
    ok.

await_peer_outcomes(_Peers, WinnerPeer, ClosedPeer, _Deadline)
    when WinnerPeer =/= none, ClosedPeer =/= none ->
    require(WinnerPeer =/= ClosedPeer, winner_socket_was_closed);
await_peer_outcomes(Peers, WinnerPeer, ClosedPeer, Deadline) ->
    receive
        {tcp, Peer, <<1>>} ->
            require(lists:member(Peer, Peers), unexpected_peer_data),
            require(WinnerPeer =:= none, duplicate_winner_data),
            await_peer_outcomes(Peers, Peer, ClosedPeer, Deadline);
        {tcp_closed, Peer} ->
            require(lists:member(Peer, Peers), unexpected_peer_close),
            require(ClosedPeer =:= none, both_candidate_sockets_closed),
            await_peer_outcomes(Peers, WinnerPeer, Peer, Deadline);
        {tcp_error, Peer, Reason}
            when Reason =:= closed; Reason =:= econnreset;
                 Reason =:= enotconn ->
            require(lists:member(Peer, Peers), unexpected_peer_error),
            require(ClosedPeer =:= none, both_candidate_sockets_closed),
            await_peer_outcomes(Peers, WinnerPeer, Peer, Deadline);
        {tcp_error, Peer, _Reason} ->
            require(lists:member(Peer, Peers), unexpected_peer_error),
            erlang:error(candidate_peer_socket_error)
    after remaining_milliseconds(Deadline) ->
        erlang:error(losing_socket_was_not_closed)
    end.

runtime(Registry, Resolve, Connect) ->
    #{resolve => Resolve, connect => Connect,
        lifecycle_observer => observer_capability(Registry)}.

observer_capability(#{table := Table, owner := Owner, reference := Reference}) ->
    {http_transport_lifecycle_observer, Table, Owner, Reference}.

addresses(inet6) -> {ok, [{0, 0, 0, 0, 0, 0, 0, 1}]};
addresses(inet) -> {ok, [{127, 0, 0, 1}]}.

stalled_runtime(Registry) ->
    runtime(Registry, fun(_Host, Family) -> addresses(Family) end,
        fun(_Address, _Port, _Options, Timeout) ->
            receive after Timeout -> {error, timeout} end
        end).

dial(Port, Dns, Connect, Total, Runtime, Trace) ->
    http_transport_ffi:connect_with_runtime(
        <<"redacted-fixture.invalid">>, Port, Dns, Connect, Total, 1000,
        Runtime, Trace).

with_listener(Fun) ->
    {ok, Listener} = http_transport_ffi:listen(<<127, 0, 0, 1>>, 0, 8, 1000),
    try
        {ok, {_, Port}} = http_transport_ffi:local_endpoint(Listener),
        Fun(Port)
    after
        http_transport_ffi:stop(Listener)
    end.

require_success_and_close({ok, Socket}) ->
    http_transport_ffi:close(Socket),
    ok;
require_success_and_close({error, Code}) ->
    erlang:error({expected_connected_socket, Code}).

has_event(Events, Kind, Family) ->
    lists:any(fun({K, F, _, _, _}) ->
        K =:= Kind andalso F =:= Family
    end, Events).

with_worker_registry(Fun) ->
    Table = ets:new(?MODULE, [set, public,
        {read_concurrency, true}, {write_concurrency, true}]),
    Registry = #{table => Table, owner => self(), reference => make_ref()},
    try Fun(Registry)
    after
        cleanup_registered_processes(Registry),
        flush_registry_notifications(Registry),
        ets:delete(Table)
    end.

register_test_process(Registry = #{table := Table}, Kind, Pid) ->
    true = ets:insert(Table, {{http_transport_worker, Pid}, Kind}),
    notify_registry_change(Registry).

record_test_stage(Registry = #{table := Table}, Stage, Pid) ->
    true = ets:insert(Table, {{http_transport_stage, Stage, Pid}, 1}),
    notify_registry_change(Registry).

notify_registry_change(#{owner := Owner, reference := Reference}) ->
    Owner ! {http_transport_worker_observed, Reference},
    ok.

registered_processes(#{table := Table}) ->
    lists:usort([Pid || {{http_transport_worker, Pid}, _Kind}
        <- ets:tab2list(Table)]).

registered_processes(#{table := Table}, Kind) ->
    lists:usort([Pid || {{http_transport_worker, Pid}, ObservedKind}
        <- ets:tab2list(Table), ObservedKind =:= Kind]).

registered_stages(#{table := Table}, Stage) ->
    lists:usort([Pid || {{http_transport_stage, ObservedStage, Pid}, 1}
        <- ets:tab2list(Table), ObservedStage =:= Stage]).

await_kind_count(Registry, Kind, Count, Deadline, Reason) ->
    await_registry_count(fun() -> registered_processes(Registry, Kind) end,
        Registry, Count, Deadline, Reason).

await_stage_count(Registry, Stage, Count, Deadline, Reason) ->
    await_registry_count(fun() -> registered_stages(Registry, Stage) end,
        Registry, Count, Deadline, Reason).

await_registry_count(Read, Registry, Count, Deadline, Reason) ->
    Values = Read(),
    case length(Values) >= Count of
        true -> Values;
        false ->
            Reference = maps:get(reference, Registry),
            receive
                {http_transport_worker_observed, Reference} ->
                    await_registry_count(Read, Registry, Count, Deadline, Reason)
            after remaining_milliseconds(Deadline) ->
                erlang:error(Reason)
            end
    end.

require_kind_count_at_least(Registry, Kind, Count, Reason) ->
    require(length(registered_processes(Registry, Kind)) >= Count, Reason).

require_runtime_stopped(Registry) ->
    case runtime_stop_status_now(Registry) of
        {ok, Count} ->
            require(Count > 0, empty_runtime_registry),
            Pending = await_processes_down(registered_processes(Registry),
                deadline_after(?JOIN_DEADLINE_MILLISECONDS)),
            require(map_size(Pending) =:= 0, runtime_down_was_not_confirmed);
        {Failure, Count} ->
            force_stop_and_join(registered_processes(Registry)),
            erlang:error({Failure, Count})
    end.

require_runtime_stopped_within(Registry, Deadline) ->
    case runtime_stop_status(Registry, Deadline) of
        {ok, _Count} -> require_runtime_stopped(Registry);
        {Failure, Count} ->
            force_stop_and_join(registered_processes(Registry)),
            erlang:error({Failure, Count})
    end.

runtime_stop_status_now(Registry) ->
    Processes = registered_processes(Registry),
    case registered_processes(Registry, ?COORDINATOR_KIND) of
        [] -> {seal_missing, length(Processes)};
        [_Coordinator] ->
            Alive = [Pid || Pid <- Processes, erlang:is_process_alive(Pid)],
            case Alive of
                [] -> {ok, length(Processes)};
                _ -> {processes_alive, length(Alive)}
            end;
        Coordinators -> {seal_duplicated, length(Coordinators)}
    end.

runtime_stop_status(Registry, Deadline) ->
    Coordinators = registered_processes(Registry, ?COORDINATOR_KIND),
    case Coordinators of
        [] -> {seal_missing, length(registered_processes(Registry))};
        [_Coordinator] ->
            case await_processes_down(Coordinators, Deadline) of
                Pending when map_size(Pending) > 0 ->
                    {processes_alive, map_size(Pending)};
                _ ->
                    Processes = registered_processes(Registry),
                    case await_processes_down(Processes, Deadline) of
                        Remaining when map_size(Remaining) > 0 ->
                            {processes_alive, map_size(Remaining)};
                        _ -> {ok, length(Processes)}
                    end
            end;
        _ -> {seal_duplicated, length(Coordinators)}
    end.

await_processes_down(Processes, Deadline) ->
    Monitors = maps:from_list([
        {erlang:monitor(process, Pid), Pid} || Pid <- lists:usort(Processes)
    ]),
    await_monitors(Monitors, Deadline).

await_monitors(Monitors, _Deadline) when map_size(Monitors) =:= 0 -> #{};
await_monitors(Monitors, Deadline) ->
    receive
        {'DOWN', Monitor, process, _Pid, _Reason}
            when is_map_key(Monitor, Monitors) ->
            await_monitors(maps:remove(Monitor, Monitors), Deadline)
    after remaining_milliseconds(Deadline) ->
        maps:foreach(fun(Monitor, _Pid) ->
            erlang:demonitor(Monitor, [flush])
        end, Monitors),
        Monitors
    end.

force_stop_and_join(Processes) ->
    Unique = lists:usort(Processes),
    Monitors = maps:from_list([
        {erlang:monitor(process, Pid), Pid} || Pid <- Unique
    ]),
    lists:foreach(fun(Pid) -> exit(Pid, kill) end, Unique),
    Deadline = deadline_after(?JOIN_DEADLINE_MILLISECONDS),
    case await_monitors(Monitors, Deadline) of
        Pending when map_size(Pending) =:= 0 -> ok;
        Pending -> erlang:error({forced_process_join_failed, map_size(Pending)})
    end.

cleanup_registered_processes(Registry) ->
    force_stop_and_join(registered_processes(Registry)).

flush_registry_notifications(#{reference := Reference}) ->
    receive
        {http_transport_worker_observed, Reference} ->
            flush_registry_notifications(#{reference => Reference})
    after 0 -> ok
    end.

await_down(Monitor, Pid, Deadline, Reason) ->
    receive
        {'DOWN', Monitor, process, Pid, _} -> ok
    after remaining_milliseconds(Deadline) ->
        erlang:demonitor(Monitor, [flush]),
        erlang:error(Reason)
    end.

accept_until(Listener, Deadline) ->
    case remaining_milliseconds(Deadline) of
        0 -> erlang:error(candidate_peer_was_not_accepted);
        Remaining ->
            case gen_tcp:accept(Listener, Remaining) of
                {ok, Peer} -> Peer;
                {error, _} -> erlang:error(candidate_peer_was_not_accepted)
            end
    end.

deadline_after(Milliseconds) ->
    erlang:monotonic_time(millisecond) + Milliseconds.

remaining_milliseconds(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

%% Every contributing coordinator is DOWN before this zero-time scan. Since
%% it is the only sender of dial results, no cross-sender registration race is
%% hidden here and no later matching message can be created.
require_no_dial_messages_after_seal() ->
    receive
        {http_transport_dial, _, _} -> erlang:error(late_dial_result_leaked)
    after 0 -> ok
    end.

require(true, _Reason) -> ok;
require(false, Reason) -> erlang:error(Reason).
