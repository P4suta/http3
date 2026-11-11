%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_protocol_observer_test).
-export([contracts/0, isolated_contracts/0]).
-include_lib("eunit/include/eunit.hrl").

isolated_contracts() -> {timeout,45,fun controls_are_isolated_from_unrelated_parent_resources/0}.

controls_are_isolated_from_unrelated_parent_resources() ->
    Fixture=fixture_start(),
    try
        {ok,protocol_observer_controls,Beam,[]}=compile:file(
            "scripts/protocol_observer_controls.erl",
            [binary,return_errors,return_warnings,{i,"scripts"}]),
        {module,protocol_observer_controls}=code:load_binary(protocol_observer_controls,
            "scripts/protocol_observer_controls.erl",Beam),
        ?assert(protocol_observer_controls:run())
    after
        Monitor=monitor(process,Fixture),Fixture!stop,
        receive {'DOWN',Monitor,process,Fixture,_}->ok
        after 1000->exit(Fixture,kill),error(fixture_stop_failed) end
    end.

contracts() -> [
    fun missing_cleanup_cannot_claim_runtime_convergence/0,
    fun original_work_and_cleanup_failure_are_both_retained/0,
    fun actual_workload_is_sampled_before_cleanup/0,
    fun blocked_work_has_an_absolute_deadline_and_cleanup/0,
    fun invalid_sampler_payload_never_enters_the_report/0,
    fun blocked_sampler_is_killed_and_cleanup_runs/0,
    fun sampling_saturation_stops_work_and_joins_children/0,
    fun a_stalled_injected_clock_cannot_extend_real_deadline/0,
    fun owner_exit_joins_work_and_invokes_cleanup_once/0,
    fun report_schema_rejects_unknown_and_secret_fields/0,
    fun guardian_death_independently_reaps_trapping_work/0,
    fun backward_clock_is_reported_without_extending_work/0,
    fun cleanup_timeout_retains_the_original_failure/0,
    fun thrown_callback_payload_never_enters_the_report/0,
    fun every_project_role_prefix_rejects_an_unclean_baseline/0,
    fun invalid_options_do_not_start_callbacks/0,
    fun normal_publication_has_already_joined_every_observer_helper/0,
    fun non_scalar_nested_samples_are_rejected/0,
    fun completion_published_after_deadline_cannot_override_timeout/0,
    fun successful_report_requires_every_lifecycle_barrier/0,
    fun late_cleanup_completion_cannot_override_its_deadline/0,
    fun convergence_trace_classifies_transient_process_drift/0,
    fun blocked_convergence_sample_has_an_absolute_deadline/0,
    fun convergence_trace_is_bounded_and_retains_its_tail/0,
    fun injected_convergence_cannot_claim_qualification/0
].

options() -> #{deadline_ms => erlang:monotonic_time(millisecond)+1000,
    sample_interval_ms => 5, convergence_timeout_ms => 50}.

missing_cleanup_cannot_claim_runtime_convergence() ->
    Ledger = ets:new(observer_fixture, [public, set]),
    try
        Report = http_protocol_observer:measure(fun() ->
            Pid = fixture_start(),
            ets:insert(Ledger, {worker, Pid}),
            ok
        end, fun() -> ok end, options()),
        ?assertEqual(false, maps:get(converged, Report)),
        ?assertEqual(<<"failed">>, maps:get(status, Report))
    after stop_fixture(Ledger), ets:delete(Ledger)
    end.

original_work_and_cleanup_failure_are_both_retained() ->
    Report = http_protocol_observer:measure(fun() -> {error, 23} end,
        fun() -> {error, 42} end, options()),
    ?assertEqual(23, maps:get(work_code, Report)),
    ?assertEqual(42, maps:get(cleanup_code, Report)),
    ?assertEqual(<<"failed">>, maps:get(status, Report)).

actual_workload_is_sampled_before_cleanup() ->
    Ledger = ets:new(observer_fixture, [public, set]),
    try
        Report = http_protocol_observer:measure(fun() ->
            Pid = fixture_start(),
            ets:insert(Ledger, {worker, Pid}),
            receive after 40 -> ok end
        end, fun() -> stop_fixture(Ledger) end, options()),
        ok = write_diagnostic_if_requested(Report),
        Peak = maps:get(peak, Report),
        ?assert(maps:get(project_processes, Peak) >= 1),
        ?assert(maps:get(udp_ports, Peak)+maps:get(sockets, Peak) >= 1),
        ?assert(maps:get(tcp_ports, Peak)+maps:get(sockets, Peak) >= 1),
        ?assert(maps:get(converged, Report)),
        ?assertEqual(2,maps:get(convergence_quiet_samples,Report)),
        ?assertEqual(<<"restored">>,maps:get(blocker,lists:last(
            maps:get(convergence_trace,Report)))),
        ?assert(maps:get(children_down, Report)),
        ?assert(http_protocol_observer:valid_report(Report))
    after stop_fixture(Ledger), ets:delete(Ledger)
    end.

blocked_work_has_an_absolute_deadline_and_cleanup() ->
    Ledger = ets:new(observer_fixture,[public,set]),
    try
        Started = erlang:monotonic_time(millisecond),
        Report = http_protocol_observer:measure(fun() ->
            ets:insert(Ledger,{callback,self()}), blocked()
        end, fun() -> ets:insert(Ledger,{cleaned,true}), ok end,
            (options())#{deadline_ms => Started+100}),
        [{callback,Pid}] = ets:lookup(Ledger,callback),
        ?assertNot(is_process_alive(Pid)),
        ?assertEqual(<<"timeout">>,maps:get(work_outcome,Report)),
        ?assertEqual([{cleaned,true}],ets:lookup(Ledger,cleaned)),
        ?assert(erlang:monotonic_time(millisecond)-Started < 2000),
        ?assert(http_protocol_observer:valid_report(Report))
    after ets:delete(Ledger) end.

invalid_sampler_payload_never_enters_the_report() ->
    Secret = <<"private-observer-value-4f9e">>,
    Sampler = fun() -> #{private_endpoint => Secret} end,
    Report = http_protocol_observer:measure(fun blocked/0,fun() -> ok end,
        (options())#{sampler => Sampler}),
    ?assertEqual(<<"invalid_sample">>,maps:get(observer_outcome,Report)),
    ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(Report)),Secret)),
    ?assert(maps:get(children_down,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

blocked_sampler_is_killed_and_cleanup_runs() ->
    Ledger = ets:new(observer_fixture,[public,set]),
    try
        Report = http_protocol_observer:measure(fun blocked/0,
            fun() -> ets:insert(Ledger,{cleaned,true}), ok end,
            (options())#{sampler => fun() -> ets:insert(Ledger,{sampler,self()}), blocked() end}),
        [{sampler,Pid}] = ets:lookup(Ledger,sampler),
        ?assertNot(is_process_alive(Pid)),
        ?assertEqual(<<"sampler_timeout">>,maps:get(observer_outcome,Report)),
        ?assertEqual([{cleaned,true}],ets:lookup(Ledger,cleaned)),
        ?assert(maps:get(children_down,Report)),
        ?assert(http_protocol_observer:valid_report(Report))
    after ets:delete(Ledger) end.

sampling_saturation_stops_work_and_joins_children() ->
    Report = http_protocol_observer:measure(fun blocked/0,fun() -> ok end,
        (options())#{max_samples => 2}),
    ?assertEqual(<<"saturated">>,maps:get(observer_outcome,Report)),
    ?assertEqual(2,maps:get(sample_attempts,Report)),
    ?assert(maps:get(saturated,Report)),
    ?assert(maps:get(children_down,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

a_stalled_injected_clock_cannot_extend_real_deadline() ->
    Started = erlang:monotonic_time(millisecond),
    Report = http_protocol_observer:measure(fun blocked/0,fun() -> ok end,
        (options())#{deadline_ms => Started+100,clock => fun() -> 0 end}),
    ?assertEqual(<<"timeout">>,maps:get(work_outcome,Report)),
    ?assert(erlang:monotonic_time(millisecond)-Started < 2000),
    ?assert(http_protocol_observer:valid_report(Report)).

owner_exit_joins_work_and_invokes_cleanup_once() ->
    Parent = self(),
    Cleaned = atomics:new(1,[]),
    Owner = spawn(fun() ->
        http_protocol_observer:measure(fun() ->
            {links,Links} = process_info(self(),links),
            [Guardian] = [Pid || Pid <- Links,is_pid(Pid)],
            Parent ! {work,self(),Guardian},blocked()
        end,fun() -> atomics:add(Cleaned,1,1),Parent ! {cleaned,self()},ok end,options())
    end),
    {Worker,Guardian} = receive {work,Pid,Group} -> {Pid,Group} after 1500 -> error(missing_work) end,
    Monitor = monitor(process,Worker),
    GuardianMonitor = monitor(process,Guardian),
    exit(Owner,kill),
    Down = receive {'DOWN',Monitor,process,Worker,_} -> true after 1500 -> false end,
    Cleaner = receive {cleaned,CleanerPid} -> CleanerPid after 1500 -> error(missing_cleanup) end,
    CleanerMonitor = monitor(process,Cleaner),
    CleanupDown = receive {'DOWN',CleanerMonitor,process,Cleaner,_} -> true after 1500 -> false end,
    GuardianDown = receive {'DOWN',GuardianMonitor,process,Guardian,_} -> true after 1500 -> false end,
    ?assert(Down), ?assert(CleanupDown), ?assert(GuardianDown), ?assertEqual(1,atomics:get(Cleaned,1)).

report_schema_rejects_unknown_and_secret_fields() ->
    Report = http_protocol_observer:measure(fun() -> receive after 20 -> ok end end,
        fun() -> ok end,options()),
    ?assert(http_protocol_observer:valid_report(Report)),
    ?assert(http_protocol_observer:valid_report(json:decode(iolist_to_binary(json:encode(Report))))),
    ?assertNot(http_protocol_observer:valid_report(Report#{private_value => <<"private">>})),
    ?assertNot(http_protocol_observer:valid_report(Report#{work_code := <<"private">>})),
    ?assertNot(http_protocol_observer:valid_report(Report#{sample_count := 900000})),
    [First|Rest] = maps:get(convergence_trace,Report),
    ?assertNot(http_protocol_observer:valid_report(Report#{convergence_trace :=
        [First#{blocker := <<"private">>}|Rest]})),
    ?assertNot(http_protocol_observer:valid_report(Report#{convergence_trace_dropped := 1})).

blocked() -> receive release -> ok after 5000 -> ok end.

guardian_death_independently_reaps_trapping_work() ->
    Parent = self(), Cleaned = atomics:new(1,[]),
    Owner = spawn(fun() ->
        Report = http_protocol_observer:measure(fun() ->
            process_flag(trap_exit,true),
            {links,Links} = process_info(self(),links),
            [Guardian] = [Pid || Pid <- Links,is_pid(Pid)],
            Parent ! {owned,self(),Guardian}, blocked()
        end,fun() -> atomics:add(Cleaned,1,1),ok end,options()),
        Parent ! {completed,Report}
    end),
    try
        {Worker,Guardian} = receive {owned,Pid,Group} -> {Pid,Group}
            after 1000 -> error(missing_work) end,
        exit(Guardian,kill),
        Report = receive {completed,Value} -> Value after 2000 -> error(missing_report) end,
        ?assertNot(is_process_alive(Worker)),
        ?assertNot(is_process_alive(Guardian)),
        ?assertEqual(1,atomics:get(Cleaned,1)),
        ?assertEqual(<<"observer_exited">>,maps:get(observer_outcome,Report)),
        ?assert(maps:get(converged,Report)),
        ?assert(http_protocol_observer:valid_report(Report))
    after exit(Owner,kill) end.

backward_clock_is_reported_without_extending_work() ->
    Counter = atomics:new(1,[]),
    Clock = fun() -> 100-atomics:add_get(Counter,1,1) end,
    Report = http_protocol_observer:measure(fun blocked/0,fun() -> ok end,
        (options())#{clock => Clock}),
    ?assertEqual(<<"clock_reversed">>,maps:get(observer_outcome,Report)),
    ?assert(maps:get(children_down,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

cleanup_timeout_retains_the_original_failure() ->
    Report = http_protocol_observer:measure(fun() -> {error,71} end,fun blocked/0,
        (options())#{cleanup_timeout_ms => 30}),
    ?assertEqual(71,maps:get(work_code,Report)),
    ?assertEqual(<<"failed">>,maps:get(work_outcome,Report)),
    ?assertEqual(<<"incomplete">>,maps:get(cleanup_outcome,Report)),
    ?assert(maps:get(cleanup_started,Report)),
    ?assertNot(maps:get(cleanup_finished,Report)),
    ?assert(maps:get(children_down,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

thrown_callback_payload_never_enters_the_report() ->
    Secret = <<"private-callback-value-92bd">>,
    Report = http_protocol_observer:measure(fun() -> throw(Secret) end,
        fun() -> error(Secret) end,options()),
    ?assertEqual(<<"throw">>,maps:get(work_outcome,Report)),
    ?assertEqual(<<"error">>,maps:get(cleanup_outcome,Report)),
    ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(Report)),Secret)),
    ?assert(http_protocol_observer:valid_report(Report)).

every_project_role_prefix_rejects_an_unclean_baseline() ->
    lists:foreach(fun(Label) ->
        Parent = self(), Ref = make_ref(),
        {Pid,Monitor} = spawn_monitor(fun() ->
            proc_lib:set_label(Label), Parent ! {Ref,ready},blocked()
        end),
        try
            receive {Ref,ready} -> ok after 500 -> error(missing_ready) end,
            Report = http_protocol_observer:measure(fun() -> ok end,fun() -> ok end,options()),
            ?assertEqual(<<"unclean_baseline">>,maps:get(observer_outcome,Report)),
            ?assertNot(maps:get(work_started,Report)),
            ?assert(http_protocol_observer:valid_report(Report))
        after
            exit(Pid,kill),
            receive {'DOWN',Monitor,process,Pid,_} -> ok after 500 -> ok end
        end
    end,[<<"http.fixture">>,<<"http3.fixture">>,<<"quic_core.fixture">>]).

invalid_options_do_not_start_callbacks() ->
    Counter = atomics:new(1,[]),
    Work = fun() -> atomics:add(Counter,1,1),ok end,
    Report = http_protocol_observer:measure(Work,Work,#{secret_option => <<"private">>}),
    ?assertEqual(0,atomics:get(Counter,1)),
    ?assertEqual(<<"invalid_options">>,maps:get(observer_outcome,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

normal_publication_has_already_joined_every_observer_helper() ->
    Report = http_protocol_observer:measure(fun() -> receive after 30 -> ok end end,
        fun() -> ok end,options()),
    Remaining = [Pid || Pid <- processes(),
        {label,Label} <- [process_info(Pid,label)],is_binary(Label),
        byte_size(Label) =< 80,
        case Label of <<"measurement.protocol.",_/binary>> -> true; _ -> false end],
    ?assertEqual(0,length(Remaining)),
    ?assert(maps:get(observer_ready,Report)),
    ?assert(maps:get(children_down,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

non_scalar_nested_samples_are_rejected() ->
    Valid = http_protocol_observer:runtime_sample(),
    Secret = <<"private-nested-counter-value">>,
    Report = http_protocol_observer:measure(fun blocked/0,fun() -> ok end,
        (options())#{sampler => fun() -> Valid#{memory_bytes := #{secret => Secret}} end}),
    ?assertEqual(<<"invalid_sample">>,maps:get(observer_outcome,Report)),
    ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(Report)),Secret)),
    ?assert(http_protocol_observer:valid_report(Report)).

completion_published_after_deadline_cannot_override_timeout() ->
    Parent=self(), Ref=make_ref(), Deadline=erlang:monotonic_time(millisecond)+200,
    {Owner,OwnerMonitor}=spawn_monitor(fun() ->
        Report=http_protocol_observer:measure(fun() ->
            {links,[Guardian]}=process_info(self(),links),
            Parent!{Ref,self(),Guardian},
            receive finish -> ok after 2000 -> {error,1} end
        end,fun()->ok end,(options())#{deadline_ms=>Deadline}),
        Parent!{Ref,Report}
    end),
    {Worker,Guardian}=receive {Ref,W,G}->{W,G} after 1000 -> error(missing_ready) end,
    WorkerMonitor=monitor(process,Worker),
    try
        true=erlang:suspend_process(Guardian),
        receive after max(0,Deadline-erlang:monotonic_time(millisecond)+20)->ok end,
        Worker!finish,
        receive {'DOWN',WorkerMonitor,process,Worker,_}->ok after 1000->error(missing_down) end,
        true=erlang:resume_process(Guardian),
        Report=receive {Ref,R}->R after 2000->error(missing_report) end,
        ?assertEqual(<<"timeout">>,maps:get(work_outcome,Report)),
        ?assert(maps:get(work_finished,Report)),
        ?assert(http_protocol_observer:valid_report(Report))
    after
        try erlang:resume_process(Guardian) catch _:_ -> ok end,
        exit(Worker,kill),exit(Guardian,kill),exit(Owner,kill),
        receive {'DOWN',OwnerMonitor,process,Owner,_}->ok after 1000->ok end,
        demonitor(WorkerMonitor,[flush])
    end.

successful_report_requires_every_lifecycle_barrier() ->
    Report=http_protocol_observer:measure(fun()->receive after 50->ok end end,
        fun()->ok end,options()),
    ?assertEqual(<<"ok">>,maps:get(status,Report)),
    lists:foreach(fun(Key)->
        ?assertNot(http_protocol_observer:valid_report(Report#{Key:=false}))
    end,[work_started,work_finished,cleanup_started,cleanup_finished,observer_ready]).

late_cleanup_completion_cannot_override_its_deadline()->
    Parent=self(),Ref=make_ref(),
    {Owner,OwnerMonitor}=spawn_monitor(fun()->
        Report=http_protocol_observer:measure(fun()->receive after 40->ok end end,
            fun()->
                {links,[Guardian]}=process_info(self(),links),Parent!{Ref,self(),Guardian},
                receive finish->ok after 2000->{error,1} end
            end,(options())#{cleanup_timeout_ms=>100}),
        Parent!{Ref,Report}
    end),
    {Cleaner,Guardian}=receive {Ref,C,G}->{C,G} after 1000->error(missing_ready) end,
    CleanerMonitor=monitor(process,Cleaner),
    try
        true=erlang:suspend_process(Guardian),
        receive after 150->ok end,
        Cleaner!finish,
        receive {'DOWN',CleanerMonitor,process,Cleaner,_}->ok after 1000->error(missing_down) end,
        true=erlang:resume_process(Guardian),
        Report=receive {Ref,R}->R after 2000->error(missing_report) end,
        ?assertEqual(<<"timeout">>,maps:get(cleanup_outcome,Report)),
        ?assert(maps:get(cleanup_finished,Report)),
        ?assert(http_protocol_observer:valid_report(Report))
    after
        try erlang:resume_process(Guardian) catch _:_ ->ok end,
        exit(Cleaner,kill),exit(Guardian,kill),exit(Owner,kill),
        receive {'DOWN',OwnerMonitor,process,Owner,_}->ok after 1000->ok end,
        demonitor(CleanerMonitor,[flush])
    end.

convergence_trace_classifies_transient_process_drift() ->
    Counter=atomics:new(1,[]),
    Sampler=fun()->
        case atomics:add_get(Counter,1,1) of
            1->(zero_sample())#{processes:=8192};
            _->zero_sample()
        end
    end,
    Report=http_protocol_observer:measure(fun()->receive after 30->ok end end,
        fun()->ok end,(options())#{convergence_timeout_ms=>200,
            convergence_sampler=>Sampler}),
    Trace=maps:get(convergence_trace,Report),
    [First,Second,Third]=Trace,
    ?assertEqual({false,<<"processes">>},
        {maps:get(restored,First),maps:get(blocker,First)}),
    ?assert(maps:get(excess,First)>0),
    ?assertEqual({true,<<"restored">>,0},
        {maps:get(restored,Second),maps:get(blocker,Second),maps:get(excess,Second)}),
    ?assertEqual({true,<<"restored">>,0},
        {maps:get(restored,Third),maps:get(blocker,Third),maps:get(excess,Third)}),
    ?assert(maps:get(converged,Report)),
    ?assertEqual(2,maps:get(convergence_quiet_samples,Report)),
    ?assertEqual(<<"injected">>,maps:get(convergence_sampler_mode,Report)),
    ?assertEqual(<<"failed">>,maps:get(status,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

blocked_convergence_sample_has_an_absolute_deadline() ->
    Parent=self(),Ref=make_ref(),
    Sampler=fun()->Parent!{Ref,convergence_sample_entered,self()},blocked() end,
    {Owner,OwnerMonitor}=spawn_monitor(fun()->
        Report=http_protocol_observer:measure(fun()->receive after 30->ok end end,
            fun()->ok end,(options())#{convergence_timeout_ms=>40,
                convergence_sampler=>Sampler}),
        Parent!{Ref,convergence_report,Report}
    end),
    SamplerPid=receive {Ref,convergence_sample_entered,Pid}->Pid
        after 1000->error(missing_convergence_sync) end,
    Report=receive {Ref,convergence_report,Value}->Value
        after 1000->error(missing_convergence_report) end,
    receive {'DOWN',OwnerMonitor,process,Owner,_}->ok
        after 1000->error(convergence_owner_not_joined) end,
    ?assertNot(is_process_alive(SamplerPid)),
    ?assertEqual(<<"sampler_timeout">>,maps:get(convergence_outcome,Report)),
    ?assertEqual(0,maps:get(convergence_samples,Report)),
    ?assertEqual([],maps:get(convergence_trace,Report)),
    ?assertNot(maps:get(converged,Report)),
    ?assert(maps:get(children_down,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

convergence_trace_is_bounded_and_retains_its_tail() ->
    Report=http_protocol_observer:measure(fun()->receive after 30->ok end end,
        fun()->ok end,(options())#{convergence_timeout_ms=>1000,
            convergence_sampler=>fun()->(zero_sample())#{processes:=8192} end}),
    Samples=maps:get(convergence_samples,Report),
    Trace=maps:get(convergence_trace,Report),
    Dropped=maps:get(convergence_trace_dropped,Report),
    ?assert(Samples>16),
    ?assertEqual(16,length(Trace)),
    ?assertEqual(Samples-16,Dropped),
    ?assertEqual(Dropped+1,maps:get(ordinal,hd(Trace))),
    ?assertEqual(Samples,maps:get(ordinal,lists:last(Trace))),
    ?assert(lists:all(fun(Entry)->maps:get(blocker,Entry)=:=<<"processes">> end,Trace)),
    ?assertEqual(<<"timeout">>,maps:get(convergence_outcome,Report)),
    ?assert(http_protocol_observer:valid_report(Report)).

injected_convergence_cannot_claim_qualification() ->
    Report=http_protocol_observer:measure(fun()->receive after 30->ok end end,
        fun()->ok end,(options())#{convergence_sampler=>fun zero_sample/0,
            convergence_timeout_ms=>1000}),
    ?assert(maps:get(converged,Report)),
    ?assertEqual(<<"failed">>,maps:get(status,Report)),
    ?assertNot(http_protocol_observer:valid_report(
        Report#{convergence_sampler_mode:=<<"runtime">>})),
    ?assert(http_protocol_observer:valid_report(Report)).

zero_sample() ->
    #{processes=>0,project_processes=>0,queued_messages=>0,
      project_queued_messages=>0,largest_mailbox=>0,project_largest_mailbox=>0,
      memory_bytes=>0,ports=>0,tcp_ports=>0,udp_ports=>0,sockets=>0}.

write_diagnostic_if_requested(Report) ->
    case application:get_env(http,protocol_observer_diagnostic_path) of
        undefined->ok;
        {ok,Path} when is_list(Path),length(Path)>0,length(Path)=<4096->
            true=http_protocol_observer:valid_report(Report),
            file:write_file(Path,[json:encode(#{schema=>1,
                diagnostic_case=><<"actual_workload_cleanup_convergence">>,
                report=>Report}),$\n],[exclusive]);
        _->error(invalid_diagnostic_path)
    end.

fixture_start() ->
    Parent = self(),
    Ref = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        ok = proc_lib:set_label(<<"http.protocol_observer.fixture">>),
        {ok, Socket} = gen_udp:open(0, [binary, {active, false}, {ip, {127,0,0,1}}]),
        {ok, Listener} = gen_tcp:listen(0,[binary,{active,false},{ip,{127,0,0,1}}]),
        Parent ! {Ref, self()},
        receive stop -> ok after 3000 -> ok end,
        gen_tcp:close(Listener),gen_udp:close(Socket)
    end),
    receive {Ref, Pid} -> demonitor(Monitor, [flush]), Pid
    after 500 -> exit(Pid, kill), error(fixture_start_failed)
    end.

stop_fixture(Ledger) ->
    case ets:lookup(Ledger, worker) of
        [{worker, Pid}] ->
            Monitor = monitor(process, Pid),
            Pid ! stop,
            receive {'DOWN',Monitor,process,Pid,_} -> ok
            after 1000 -> exit(Pid, kill), error(fixture_stop_failed)
            end;
        [] -> ok
    end.
