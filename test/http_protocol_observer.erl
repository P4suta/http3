%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Internal benchmark measurement. Reports contain fixed scalar fields only.
%%
%% measure/3 executes Work in an owned worker, then executes Cleanup once. Both
%% callbacks return ok or {error, 0..255}; their values/exception terms are never
%% report data. deadline_ms is an absolute erlang:monotonic_time(millisecond)
%% deadline (default now+60s, at most 300s). Cleanup is capped at 5s; actual VM
%% convergence is capped at 10s. An injected clock cannot extend either bound.
%%
%% The caller warms protocol/runtime caches before measure/3. Baseline requires
%% zero http./http3./quic_core. actors and TCP/UDP/socket handles. Final sampling
%% requires those resources to be zero again, with global processes, ports and
%% mailbox counts restored. No prior leaked project actor becomes a baseline.
%%
%% Peaks retain only samples wholly inside the native microsecond Work scope.
%% They are sampled peaks, never exact peaks. sample_wall_time_us measures
%% completed sampler wall time (including scheduling), not time to subtract
%% from Work. Controller/sampler memory and their finite heap limit are explicit.
%% clock/sampler options exist for controls; their reports say "injected" and
%% must not be presented as native performance qualification by a caller. A
%% convergence_sampler can delay or synthesize only the final sampling phase;
%% such a report is always diagnostic and cannot acquire status "ok".
-module(http_protocol_observer).
-export([measure/3, runtime_sample/0, valid_report/1]).

%% Work/Cleanup return ok or {error, 0..255}. Exceptions and other values are
%% converted here, before they can enter an observer mailbox or report.
measure(Work, Cleanup, Options) ->
    case configuration(Work, Cleanup, Options) of
        error -> (empty_report())#{observer_outcome := <<"invalid_options">>};
        {ok, Config} -> measure_owned(Work, Cleanup, Config)
    end.

configuration(Work, Cleanup, Options) ->
    try
        true = is_function(Work, 0) andalso is_function(Cleanup, 0),
        true = is_map(Options),
        Allowed = [deadline_ms, sample_interval_ms, convergence_timeout_ms,
            cleanup_timeout_ms, max_samples, clock, sampler, convergence_sampler],
        true = lists:all(fun(Key) -> lists:member(Key, Allowed) end, maps:keys(Options)),
        Now = now_ms(),
        Defaults = #{deadline_ms => Now+60000, sample_interval_ms => 10,
            convergence_timeout_ms => 10000, cleanup_timeout_ms => 1000,
            max_samples => 4096, clock => fun now_ms/0,
            sampler => fun runtime_sample/0,
            convergence_sampler => fun runtime_sample/0},
        Config = maps:merge(Defaults, Options),
        true = bounded_integer(maps:get(deadline_ms, Config)-Now, 1, 300000),
        true = bounded_integer(maps:get(sample_interval_ms, Config), 1, 1000),
        true = bounded_integer(maps:get(convergence_timeout_ms, Config), 1, 10000),
        true = bounded_integer(maps:get(cleanup_timeout_ms, Config), 1, 5000),
        true = bounded_integer(maps:get(max_samples, Config), 1, 4096),
        true = is_function(maps:get(clock, Config), 0),
        true = is_function(maps:get(sampler, Config), 0),
        true = is_function(maps:get(convergence_sampler, Config), 0),
        {ok, Config#{clock_mode => mode(clock, Options),
            sampler_mode => mode(sampler, Options),
            convergence_sampler_mode => mode(convergence_sampler, Options)}}
    catch _:_ -> error end.

mode(Key, Options) -> case maps:is_key(Key, Options) of true -> <<"injected">>; false -> <<"runtime">> end.
bounded_integer(Value, Min, Max) -> is_integer(Value) andalso Value >= Min andalso Value =< Max.
now_ms() -> erlang:monotonic_time(millisecond).
now_us() -> erlang:monotonic_time(microsecond).

measure_owned(Work, Cleanup, Config) ->
    Owner = self(), Ref = make_ref(),
    Ledger = ets:new(protocol_observer, [set, public]),
    Cells = atomics:new(12, [{signed, true}]),
    atomics:put(Cells,11,maps:get(deadline_ms,Config)*1000),
    Trap = process_flag(trap_exit, true),
    {Guardian, Monitor} = spawn_opt(fun() ->
        process_flag(trap_exit, true),
        ok = proc_lib:set_label(<<"measurement.protocol.controller">>),
        OwnerMonitor = monitor(process, Owner),
        Report = try supervise(Work, Cleanup, Config, Ledger, Cells, OwnerMonitor)
            catch _:_ -> fallback(Cleanup, Config, Ledger, Cells, <<"observer_failed">>) end,
        Owner ! {Ref, Report}
    end, [link, monitor, heap_limit()]),
    try
        Limit = maps:get(deadline_ms, Config)+maps:get(cleanup_timeout_ms, Config)
            +maps:get(convergence_timeout_ms, Config)+4000,
        Report = receive
            {Ref, Result} -> Result;
            {'DOWN',Monitor,process,Guardian,_} ->
                join(Guardian,Monitor),
                fallback(Cleanup, Config, Ledger, Cells, <<"observer_exited">>)
        after max(0, Limit-now_ms()) ->
            exit(Guardian, kill),
            join(Guardian, Monitor),
            fallback(Cleanup, Config, Ledger, Cells, <<"observer_timeout">>)
        end,
        GuardianDown = join(Guardian, Monitor),
        AllDown = reap(Ledger),
        finish_report(Report#{children_down := GuardianDown andalso AllDown})
    after
        exit(Guardian, kill),
        join(Guardian, Monitor),
        reap(Ledger),
        ets:delete(Ledger),
        unlink(Guardian),
        flush_exit(Guardian),
        process_flag(trap_exit, Trap)
    end.

heap_limit() -> {max_heap_size, #{size => 4194304,
    include_shared_binaries => true, kill => true, error_logger => false}}.

supervise(Work, Cleanup, Config, Ledger, Cells, OwnerMonitor) ->
    Sampler = spawn_owned(Ledger, <<"measurement.protocol.sampler">>,
        fun() -> sample_loop(Config) end),
    Report = configured_report(Config),
    %% Prime lazy VM socket/diagnostic services before taking the baseline.
    Prime = sample(Sampler, runtime, now_ms()+500, OwnerMonitor),
    Baseline = case Prime of
        {ok, _, _, _, _, _} -> sample(Sampler, runtime, now_ms()+500, OwnerMonitor);
        Error -> Error
    end,
    {Observed, WorkPid} = case Baseline of
        {ok, Base, _, Overhead, _, _} ->
            try ets:insert(Ledger,{baseline,Base}) catch error:badarg -> ok end,
            Initial = Report#{baseline := Base,
                baseline_valid := clean_baseline(Base), observer_ready := true,
                observer_memory_bytes := Overhead},
            case clean_baseline(Base) of
                false -> {Initial#{observer_outcome := <<"unclean_baseline">>}, none};
                true ->
                    Worker = spawn_owned(Ledger, <<"measurement.protocol.work">>,
                        fun() -> callback(Work, Cells, 1) end),
                    {work_loop(Worker, Sampler, Initial, Config, Cells, OwnerMonitor, none), Worker}
            end;
        {error, Cause} -> {Report#{observer_outcome := Cause}, none}
    end,
    stop(WorkPid),
    AfterWork = from_cells(Observed, Cells),
    AfterCleanup = perform_cleanup(Cleanup, Config, Ledger, Cells, AfterWork),
    stop(Sampler),
    %% Final convergence always uses real VM observations, including when a
    %% hostile injected sampler stopped or produced invalid scalar data.
    settle(Config, Ledger, OwnerMonitor, AfterCleanup).

spawn_owned(Ledger, Label, Function) ->
    Parent = self(), Ref = make_ref(),
    {Pid, Monitor} = spawn_opt(fun() ->
        try
            ok = proc_lib:set_label(Label),
            try ets:insert(Ledger, {self()}) catch error:badarg -> ok end,
            Parent ! {Ref, ready},
            receive {Ref, start} -> Function() after 1000 -> ok end
        catch _:_ -> ok end
    end, [link, monitor, heap_limit()]),
    receive
        {Ref, ready} -> Pid ! {Ref, start}, {Pid, Monitor};
        {'DOWN',Monitor,process,Pid,_} -> {Pid, Monitor}
    after 1000 -> exit(Pid, kill), join(Pid, Monitor), {Pid, Monitor}
    end.

callback(Function, Cells, Base) ->
    case Base =:= 5 andalso atomics:compare_exchange(Cells, 9, 0, 1) =/= ok of
        true -> ok;
        false ->
            atomics:put(Cells, Base+2, now_us()),
            case Base of 1 -> atomics:put(Cells,10,1); 5 -> ok end,
            {Outcome, Code} = invoke(Function),
            atomics:put(Cells, Base+1, Code),
            atomics:put(Cells, Base+3, now_us()),
            atomics:put(Cells, Base, Outcome)
    end.

invoke(Function) ->
    try Function() of
        ok -> {1, 0};
        {error, Code} when is_integer(Code), Code >= 0, Code =< 255 -> {2, Code};
        _ -> {6, 0}
    catch error:_ -> {3, 0}; exit:_ -> {4, 0}; throw:_ -> {5, 0}
    end.

sample_loop(Config) ->
    receive
        {sample, Parent, Ref, Kind} ->
            Result = try
                Clock = case Kind of
                    configured -> maps:get(clock, Config);
                    runtime -> fun now_ms/0;
                    convergence -> fun now_ms/0
                end,
                Reader = case Kind of
                    runtime -> fun runtime_sample/0;
                    configured -> maps:get(sampler, Config);
                    convergence -> maps:get(convergence_sampler, Config)
                end,
                At = Clock(),
                true = is_integer(At) andalso abs(At) =< 9007199254740991,
                From = now_us(),
                Value = Reader(),
                case valid_sample(Value) of
                    true -> {ok, Value, At, own_memory(Parent)+own_memory(self()), From, now_us()};
                    false -> {error, <<"invalid_sample">>}
                end
            catch _:_ -> {error, <<"sampler_failed">>} end,
            Parent ! {Ref, Result},
            sample_loop(Config);
        stop -> ok
    end.

sample({Pid, Monitor}, Kind, Deadline, OwnerMonitor) ->
    Ref = make_ref(),
    Pid ! {sample, self(), Ref, Kind},
    receive
        {Ref, Result} ->
            case now_ms() < Deadline of true -> Result; false -> {error, <<"sampler_timeout">>} end;
        {'DOWN',Monitor,process,Pid,_} -> {error, <<"sampler_exited">>};
        {'DOWN',OwnerMonitor,process,_,_} -> {error, <<"owner_exited">>}
    after max(0, min(250, Deadline-now_ms())) -> {error, <<"sampler_timeout">>}
    end.

own_memory(Pid) -> case process_info(Pid, memory) of {memory, Bytes} -> Bytes; _ -> 0 end.

work_loop(Worker = {Pid, Monitor}, Sampler, Report, Config, Cells, OwnerMonitor, LastClock) ->
    Deadline = maps:get(deadline_ms, Config),
    case {atomics:get(Cells, 1), now_ms() >= Deadline,
          maps:get(sample_attempts, Report) >= maps:get(max_samples, Config)} of
        {Done, _, _} when Done =/= 0 ->
            case atomics:get(Cells,4) >= atomics:get(Cells,11) of
                true -> Report#{work_outcome := <<"timeout">>};
                false -> Report
            end;
        {_, true, _} -> Report#{work_outcome := <<"timeout">>};
        {_, _, true} -> Report#{observer_outcome := <<"saturated">>, saturated := true};
        _ ->
            case sample(Sampler, configured, Deadline, OwnerMonitor) of
                {error, Cause} ->
                    Timed = case now_ms() >= Deadline of true -> <<"timeout">>; false -> maps:get(work_outcome,Report) end,
                    Report#{observer_outcome := Cause,work_outcome := Timed};
                {ok, Value, At, Overhead, From, To} ->
                    case LastClock =/= none andalso At < LastClock of
                        true -> Report#{observer_outcome := <<"clock_reversed">>};
                        false ->
                            Next = retain_sample(Report,Value,Overhead,From,To,Cells),
                            receive
                                {'DOWN',Monitor,process,Pid,_} -> Next#{work_outcome := <<"worker_exited">>};
                                {'DOWN',OwnerMonitor,process,_,_} -> Next#{observer_outcome := <<"owner_exited">>}
                            after max(0,min(maps:get(sample_interval_ms,Config),Deadline-now_ms())) ->
                                work_loop(Worker,Sampler,Next,Config,Cells,OwnerMonitor,At)
                            end
                    end
            end
    end.

retain_sample(Report, Value, Overhead, From, To, Cells) ->
    Start = atomics:get(Cells,3), Finish = atomics:get(Cells,4),
    Inside = atomics:get(Cells,10) =:= 1 andalso From >= Start andalso
        (atomics:get(Cells,1) =:= 0 orelse To =< Finish),
    Next = Report#{sample_attempts := maps:get(sample_attempts,Report)+1,
        sample_wall_time_us := maps:get(sample_wall_time_us,Report)+max(0,To-From),
        max_sample_wall_time_us := max(maps:get(max_sample_wall_time_us,Report),max(0,To-From)),
        observer_memory_bytes := max(Overhead,maps:get(observer_memory_bytes,Report))},
    case Inside of
        true -> Next#{peak := peaks(maps:get(peak,Report),Value),
            sample_count := maps:get(sample_count,Report)+1};
        false -> Next#{samples_outside_work := maps:get(samples_outside_work,Report)+1}
    end.

perform_cleanup(Cleanup, Config, Ledger, Cells, Report) ->
    Started = now_ms(),
    case atomics:get(Cells, 9) of
        0 ->
            atomics:put(Cells,12,now_us()+maps:get(cleanup_timeout_ms,Config)*1000),
            Cleaner = spawn_owned(Ledger, <<"measurement.protocol.cleanup">>,
                fun() -> callback(Cleanup, Cells, 5) end),
            await_callback(Cleaner,max(0,(atomics:get(Cells,12)-now_us()) div 1000)),
            stop(Cleaner);
        _ -> ok
    end,
    from_cells(Report#{cleanup_elapsed_ms := max(0,now_ms()-Started)}, Cells).

await_callback({Pid, Monitor}, Timeout) ->
    receive {'DOWN',Monitor,process,Pid,_} -> ok after Timeout -> ok end.

from_cells(Report, Cells) ->
    Work = atomics:get(Cells, 1), Cleanup = atomics:get(Cells, 5),
    Elapsed = elapsed_work(Cells),
    %% The callback publishes its native completion time before its outcome.
    %% A suspended controller must not turn a late callback into success when
    %% both the result and deadline are already pending on its next turn.
    WorkOutcome = case {maps:get(work_outcome,Report),Work} of
        {<<"timeout">>,_} -> <<"timeout">>;
        {Previous,0} -> Previous;
        _ -> case atomics:get(Cells,4) >= atomics:get(Cells,11) of
            true -> <<"timeout">>;
            false -> outcome(Work)
        end
    end,
    CleanupOutcome=case Cleanup=/=0 andalso atomics:get(Cells,8)>=atomics:get(Cells,12) of
        true-><<"timeout">>;false->outcome(Cleanup) end,
    Report#{work_outcome := WorkOutcome, work_code := atomics:get(Cells,2),
        cleanup_outcome := CleanupOutcome, cleanup_code := atomics:get(Cells,6),
        work_started := atomics:get(Cells,10) =:= 1,
        work_finished := Work =/= 0,
        cleanup_started := atomics:get(Cells,7) =/= 0,cleanup_finished := Cleanup =/= 0,
        work_elapsed_us := Elapsed,work_elapsed_ms := Elapsed div 1000}.

elapsed_work(Cells) ->
    Start = atomics:get(Cells,3),
    case {atomics:get(Cells,10),atomics:get(Cells,1)} of
        {0,_} -> 0;
        {_,0} -> max(0,now_us()-Start);
        {_,_} -> max(0,atomics:get(Cells,4)-Start)
    end.

outcome(0) -> <<"incomplete">>;
outcome(1) -> <<"ok">>;
outcome(2) -> <<"failed">>;
outcome(3) -> <<"error">>;
outcome(4) -> <<"exit">>;
outcome(5) -> <<"throw">>;
outcome(6) -> <<"invalid_result">>.

settle(Config, Ledger, OwnerMonitor, Report) ->
    Sampler = spawn_owned(Ledger, <<"measurement.protocol.sampler">>,
        fun() -> sample_loop(Config) end),
    Started = now_ms(),
    Final = settle_loop(Sampler, OwnerMonitor, Report,
        Started+maps:get(convergence_timeout_ms,Config), Started, 0),
    stop(Sampler),
    Final.

settle_loop(Sampler, OwnerMonitor, Report, Deadline, Started, Quiet) ->
    case now_ms() >= Deadline of
        true -> Report#{convergence_elapsed_ms := max(0,now_ms()-Started),
            convergence_outcome := <<"timeout">>};
        false -> settle_before_deadline(Sampler,OwnerMonitor,Report,Deadline,Started,Quiet)
    end.

settle_before_deadline(Sampler, OwnerMonitor, Report, Deadline, Started, Quiet) ->
    case sample(Sampler,convergence,Deadline,OwnerMonitor) of
        {ok, Value, _, Overhead, From, To} ->
            Now = now_ms(),
            {Restored, Blocker, Excess} = restoration(maps:get(baseline,Report),Value),
            NextQuiet = case Restored of true -> Quiet+1; false -> 0 end,
            Ordinal = maps:get(convergence_samples,Report)+1,
            Wall = max(0,To-From),
            Entry = #{ordinal => Ordinal, offset_ms => max(0,Now-Started),
                restored => Restored, blocker => Blocker, excess => Excess,
                sample_wall_time_us => Wall},
            {Trace, Dropped} = retain_convergence_trace(
                maps:get(convergence_trace,Report),
                maps:get(convergence_trace_dropped,Report), Entry),
            Next = Report#{final := Value, convergence_elapsed_ms := max(0,Now-Started),
                convergence_samples := Ordinal, convergence_quiet_samples := NextQuiet,
                convergence_trace := Trace, convergence_trace_dropped := Dropped,
                convergence_sample_wall_time_us :=
                    maps:get(convergence_sample_wall_time_us,Report)+Wall,
                convergence_max_sample_wall_time_us :=
                    max(Wall,maps:get(convergence_max_sample_wall_time_us,Report)),
                observer_memory_bytes := max(Overhead,maps:get(observer_memory_bytes,Report))},
            case {NextQuiet >= 2 andalso Now < Deadline, Now+5 >= Deadline} of
                {true,_} -> Next#{converged := true,convergence_outcome := <<"ok">>};
                {_,true} -> Next#{convergence_outcome := <<"timeout">>};
                _ -> receive after 5 -> settle_loop(Sampler,OwnerMonitor,Next,Deadline,Started,NextQuiet) end
            end;
        {error,Cause} -> Report#{convergence_elapsed_ms := max(0,now_ms()-Started),
            convergence_outcome := Cause}
    end.

retain_convergence_trace(Trace, Dropped, Entry) ->
    case length(Trace) < 16 of
        true -> {Trace++[Entry],Dropped};
        false -> {tl(Trace)++[Entry],Dropped+1}
    end.

restored(Baseline, Final) ->
    element(1,restoration(Baseline,Final)).

restoration(null, _) -> {false,<<"baseline_missing">>,0};
restoration(Baseline, Final) ->
    Checks = [
        {<<"project_processes">>,maps:get(project_processes,Final)},
        {<<"tcp_ports">>,maps:get(tcp_ports,Final)},
        {<<"udp_ports">>,maps:get(udp_ports,Final)},
        {<<"sockets">>,maps:get(sockets,Final)},
        {<<"processes">>,max(0,maps:get(processes,Final)-maps:get(processes,Baseline))},
        {<<"queued_messages">>,max(0,maps:get(queued_messages,Final)-maps:get(queued_messages,Baseline))},
        {<<"ports">>,max(0,maps:get(ports,Final)-maps:get(ports,Baseline))}
    ],
    case lists:dropwhile(fun({_,Value}) -> Value =:= 0 end,Checks) of
        [] -> {true,<<"restored">>,0};
        [{Blocker,Excess}|_] -> {false,Blocker,Excess}
    end.

clean_baseline(Value) -> lists:all(fun(Key) -> maps:get(Key,Value) =:= 0 end,
    [project_processes,tcp_ports,udp_ports,sockets]).

peaks(null, Incoming) -> Incoming;
peaks(Previous, Incoming) -> maps:map(fun(Key,Value) -> max(Value,maps:get(Key,Incoming)) end,Previous).

fallback(Cleanup, Config, Ledger, Cells, Cause) ->
    reap(Ledger),
    Baseline = try ets:lookup(Ledger,baseline) of [{baseline,Value}] -> Value; [] -> null
        catch error:badarg -> null end,
    Report = (configured_report(Config))#{baseline := Baseline,
        baseline_valid := Baseline =/= null andalso clean_baseline(Baseline)},
    Cleaned = from_cells(perform_cleanup(Cleanup,Config,Ledger,Cells,
        Report#{observer_outcome := Cause}),Cells),
    settle(Config,Ledger,make_ref(),Cleaned).

stop(none) -> true;
stop({Pid,Monitor}) ->
    exit(Pid,kill), join(Pid,Monitor).

join(Pid, OldMonitor) ->
    Monitor = monitor(process,Pid),
    Result = receive {'DOWN',Monitor,process,Pid,_} -> true after 1000 -> false end,
    demonitor(Monitor,[flush]), demonitor(OldMonitor,[flush]), flush_exit(Pid), Result.

flush_exit(Pid) -> receive {'EXIT',Pid,_} -> ok after 0 -> ok end.

reap(Ledger) ->
    try ets:select(Ledger,[{{'$1'},[],['$1']}],8) of
        '$end_of_table' -> true;
        {Pids,_} ->
            lists:foreach(fun(Pid) -> exit(Pid,kill) end,Pids),
            lists:all(fun(Pid) -> join(Pid,monitor(process,Pid)) end,Pids)
    catch error:badarg -> true end.

configured_report(Config) ->
    (empty_report())#{max_samples := maps:get(max_samples,Config),
        sample_interval_ms := maps:get(sample_interval_ms,Config),
        clock_mode := maps:get(clock_mode,Config),sampler_mode := maps:get(sampler_mode,Config),
        convergence_sampler_mode := maps:get(convergence_sampler_mode,Config)}.

empty_report() ->
    #{schema => 1,status => <<"failed">>,work_outcome => <<"incomplete">>,work_code => 0,
      cleanup_outcome => <<"incomplete">>,cleanup_code => 0,observer_outcome => <<"ok">>,
      work_started => false,work_finished => false,cleanup_started => false,cleanup_finished => false,
      observer_ready => false,work_elapsed_ms => 0,work_elapsed_us => 0,cleanup_elapsed_ms => 0,
      baseline => null,peak => null,final => null,baseline_valid => false,converged => false,
      children_down => false,sample_count => 0,sample_attempts => 0,samples_outside_work => 0,
      sample_wall_time_us => 0,max_sample_wall_time_us => 0,
      max_samples => 4096,sample_interval_ms => 10,
      convergence_elapsed_ms => 0,convergence_samples => 0,convergence_outcome => <<"incomplete">>,saturated => false,
      convergence_quiet_samples => 0,convergence_sample_wall_time_us => 0,
      convergence_max_sample_wall_time_us => 0,convergence_trace => [],
      convergence_trace_dropped => 0,convergence_trace_limit => 16,
      peak_kind => <<"sampled">>,observer_processes => 2,observer_memory_bytes => 0,
      observer_heap_limit_words => 4194304,
      clock_mode => <<"runtime">>,sampler_mode => <<"runtime">>,
      convergence_sampler_mode => <<"runtime">>}.

finish_report(Report) ->
    Ready = maps:get(work_outcome,Report) =:= <<"ok">> andalso
        maps:get(cleanup_outcome,Report) =:= <<"ok">> andalso
        maps:get(observer_outcome,Report) =:= <<"ok">> andalso
        lists:all(fun(Key)->maps:get(Key,Report) end,
            [work_started,work_finished,cleanup_started,cleanup_finished,observer_ready]) andalso
        maps:get(baseline_valid,Report) andalso maps:get(converged,Report) andalso
        maps:get(children_down,Report) andalso maps:get(sample_count,Report) > 0,
    Native = maps:get(convergence_sampler_mode,Report) =:= <<"runtime">>,
    Report#{status := case Ready andalso Native of true -> <<"ok">>; false -> <<"failed">> end}.

runtime_sample() ->
    ProcessCount = erlang:system_info(process_count),
    PortCount = erlang:system_info(port_count),
    true = ProcessCount =< 8192 andalso PortCount =< 8192,
    Processes = processes(),
    Ports = erlang:ports(),
    true = length(Processes) =< 8192 andalso length(Ports) =< 8192,
    Initial = #{processes => length(Processes), project_processes => 0,
        queued_messages => 0, project_queued_messages => 0,
        largest_mailbox => 0, project_largest_mailbox => 0,
        memory_bytes => erlang:memory(total), ports => length(Ports),
        tcp_ports => 0, udp_ports => 0, sockets => 0},
    Queues = lists:foldl(fun count_process/2, Initial, Processes),
    Network = lists:foldl(fun count_port/2, Queues, Ports),
    Sockets = socket:which_sockets(),
    true = length(Sockets) =< 8192,
    Network#{sockets := length(Sockets)}.

count_process(Pid, Counts) ->
    case process_info(Pid, [label, message_queue_len]) of
        [{label, Label}, {message_queue_len, Size}] ->
            Next = Counts#{queued_messages := maps:get(queued_messages, Counts)+Size,
                largest_mailbox := max(Size, maps:get(largest_mailbox, Counts))},
            case project_label(Label) of
                true -> Next#{project_processes := maps:get(project_processes, Counts)+1,
                    project_queued_messages := maps:get(project_queued_messages, Counts)+Size,
                    project_largest_mailbox := max(Size, maps:get(project_largest_mailbox, Counts))};
                false -> Next
            end;
        undefined -> Counts
    end.

project_label(Label) when is_binary(Label), byte_size(Label) =< 80 ->
    case Label of
        <<"http.", _/binary>> -> true;
        <<"http3.", _/binary>> -> true;
        <<"quic_core.", _/binary>> -> true;
        _ -> false
    end;
project_label(_) -> false.

count_port(Port, Counts) ->
    case erlang:port_info(Port, name) of
        {name, "tcp_inet"} -> Counts#{tcp_ports := maps:get(tcp_ports, Counts)+1};
        {name, "udp_inet"} -> Counts#{udp_ports := maps:get(udp_ports, Counts)+1};
        _ -> Counts
    end.

sample_keys() -> [processes,project_processes,queued_messages,project_queued_messages,
    largest_mailbox,project_largest_mailbox,memory_bytes,ports,tcp_ports,udp_ports,sockets].

valid_sample(Value) when is_map(Value) ->
    lists:sort(maps:keys(Value)) =:= lists:sort(sample_keys()) andalso
        lists:all(fun(Number) -> bounded_integer(Number,0,9007199254740991) end,maps:values(Value)) andalso
        lists:all(fun(Key) -> maps:get(Key,Value) =< 8192 end,
            [processes,project_processes,ports,tcp_ports,udp_ports,sockets]) andalso
        maps:get(project_processes,Value) =< maps:get(processes,Value) andalso
        maps:get(project_queued_messages,Value) =< maps:get(queued_messages,Value) andalso
        maps:get(project_largest_mailbox,Value) =< maps:get(project_queued_messages,Value) andalso
        maps:get(largest_mailbox,Value) =< maps:get(queued_messages,Value) andalso
        maps:get(tcp_ports,Value)+maps:get(udp_ports,Value) =< maps:get(ports,Value);
valid_sample(_) -> false.

valid_report(External) ->
    try
        Report = normalize_report(External),
        true = is_map(Report),
        true = lists:sort(maps:keys(Report)) =:= lists:sort(maps:keys(empty_report())),
        1 = maps:get(schema,Report),
        <<"sampled">> = maps:get(peak_kind,Report),
        true = lists:all(fun(Key) -> is_boolean(maps:get(Key,Report)) end,
            [work_started,work_finished,cleanup_started,cleanup_finished,observer_ready,
             baseline_valid,converged,children_down,saturated]),
        true = not maps:get(work_finished,Report) orelse maps:get(work_started,Report),
        true = not maps:get(cleanup_finished,Report) orelse maps:get(cleanup_started,Report),
        true = maps:get(work_outcome,Report) =/= <<"ok">> orelse
            (maps:get(work_started,Report) andalso maps:get(work_finished,Report)),
        true = maps:get(cleanup_outcome,Report) =/= <<"ok">> orelse
            (maps:get(cleanup_started,Report) andalso maps:get(cleanup_finished,Report)),
        true = lists:all(fun(Key) -> bounded_integer(maps:get(Key,Report),0,255) end,
            [work_code,cleanup_code]),
        true = lists:all(fun(Key) -> bounded_integer(maps:get(Key,Report),0,9007199254740991) end,
            [work_elapsed_ms,work_elapsed_us,cleanup_elapsed_ms,observer_memory_bytes,
             sample_wall_time_us,max_sample_wall_time_us,convergence_sample_wall_time_us,
             convergence_max_sample_wall_time_us]),
        true = maps:get(max_sample_wall_time_us,Report) =< maps:get(sample_wall_time_us,Report),
        true = maps:get(convergence_max_sample_wall_time_us,Report)
            =< maps:get(convergence_sample_wall_time_us,Report),
        true = maps:get(work_elapsed_ms,Report) =:= maps:get(work_elapsed_us,Report) div 1000,
        true = bounded_integer(maps:get(observer_processes,Report),0,2),
        4194304 = maps:get(observer_heap_limit_words,Report),
        true = bounded_integer(maps:get(max_samples,Report),1,4096),
        true = bounded_integer(maps:get(sample_count,Report),0,maps:get(max_samples,Report)),
        true = bounded_integer(maps:get(sample_attempts,Report),0,maps:get(max_samples,Report)),
        true = bounded_integer(maps:get(samples_outside_work,Report),0,maps:get(sample_attempts,Report)),
        true = maps:get(sample_attempts,Report) =:= maps:get(sample_count,Report)+maps:get(samples_outside_work,Report),
        true = bounded_integer(maps:get(sample_interval_ms,Report),1,1000),
        true = bounded_integer(maps:get(convergence_elapsed_ms,Report),0,11000),
        true = bounded_integer(maps:get(convergence_samples,Report),0,2001),
        true = bounded_integer(maps:get(convergence_quiet_samples,Report),0,2),
        true = bounded_integer(maps:get(convergence_trace_dropped,Report),0,2001),
        16 = maps:get(convergence_trace_limit,Report),
        true = valid_convergence_trace(Report),
        true = lists:all(fun(Key) -> lists:member(maps:get(Key,Report),[<<"runtime">>,<<"injected">>]) end,
            [clock_mode,sampler_mode,convergence_sampler_mode]),
        Outcomes = [<<"ok">>,<<"failed">>,<<"error">>,<<"exit">>,<<"throw">>,
            <<"invalid_result">>,<<"incomplete">>,<<"timeout">>,<<"worker_exited">>],
        true = lists:all(fun(Key) -> lists:member(maps:get(Key,Report),Outcomes) end,
            [work_outcome,cleanup_outcome]),
        true = lists:member(maps:get(observer_outcome,Report),[<<"ok">>,<<"invalid_options">>,
            <<"unclean_baseline">>,<<"invalid_sample">>,<<"sampler_failed">>,<<"sampler_timeout">>,
            <<"sampler_exited">>,<<"owner_exited">>,<<"saturated">>,<<"clock_reversed">>,
            <<"observer_failed">>,<<"observer_exited">>,<<"observer_timeout">>]),
        true = lists:member(maps:get(convergence_outcome,Report),[<<"ok">>,<<"incomplete">>,<<"timeout">>,
            <<"invalid_sample">>,<<"sampler_failed">>,<<"sampler_timeout">>,<<"sampler_exited">>,<<"owner_exited">>]),
        true = lists:all(fun(Key) ->
            Value = maps:get(Key,Report), Value =:= null orelse valid_sample(Value)
        end,[baseline,peak,final]),
        true = maps:get(baseline_valid,Report) =:=
            (maps:get(baseline,Report) =/= null andalso clean_baseline(maps:get(baseline,Report))),
        true = not maps:get(converged,Report) orelse
            (maps:get(final,Report) =/= null andalso maps:get(convergence_elapsed_ms,Report) =< 10000
             andalso maps:get(convergence_samples,Report) >= 2
             andalso maps:get(convergence_quiet_samples,Report) >= 2
             andalso maps:get(convergence_outcome,Report) =:= <<"ok">>
             andalso restored(maps:get(baseline,Report),maps:get(final,Report))),
        true = maps:get(sample_count,Report) =:= 0 orelse valid_sample(maps:get(peak,Report)),
        true = not maps:get(saturated,Report) orelse
            maps:get(sample_attempts,Report) =:= maps:get(max_samples,Report),
        true = maps:get(status,Report) =:= maps:get(status,finish_report(Report)),
        true
    catch _:_ -> false end.

normalize_report(Report = #{schema := _}) -> Report;
normalize_report(Report = #{<<"schema">> := _}) ->
    Keys = maps:keys(empty_report()),
    true = maps:size(Report) =:= length(Keys),
    Normal = maps:from_list([{Key,maps:get(atom_to_binary(Key),Report)} || Key <- Keys]),
    Samples = lists:foldl(fun(Key, Acc) ->
        case maps:get(Key,Acc) of
            null -> Acc;
            Value when is_map(Value) ->
                Fields = sample_keys(),
                true = maps:size(Value) =:= length(Fields),
                Acc#{Key := maps:from_list([{Field,maps:get(atom_to_binary(Field),Value)} || Field <- Fields])}
        end
    end,Normal,[baseline,peak,final]),
    Trace = maps:get(convergence_trace,Samples),
    true = is_list(Trace) andalso length(Trace) =< 16,
    Samples#{convergence_trace := [normalize_trace_entry(Entry) || Entry <- Trace]}.

normalize_trace_entry(Entry = #{ordinal := _}) -> Entry;
normalize_trace_entry(Entry = #{<<"ordinal">> := _}) ->
    Keys = [ordinal,offset_ms,restored,blocker,excess,sample_wall_time_us],
    true = maps:size(Entry) =:= length(Keys),
    maps:from_list([{Key,maps:get(atom_to_binary(Key),Entry)} || Key <- Keys]).

valid_convergence_trace(Report) ->
    Trace = maps:get(convergence_trace,Report),
    Dropped = maps:get(convergence_trace_dropped,Report),
    Samples = maps:get(convergence_samples,Report),
    is_list(Trace) andalso length(Trace) =< maps:get(convergence_trace_limit,Report)
        andalso Dropped+length(Trace) =:= Samples
        andalso [maps:get(ordinal,Entry) || Entry <- Trace]
            =:= lists:seq(Dropped+1,Samples)
        andalso lists:all(fun(Entry) -> valid_convergence_entry(Entry,Report) end,Trace)
        andalso trace_offsets_monotonic(Trace,-1)
        andalso lists:sum([maps:get(sample_wall_time_us,Entry) || Entry <- Trace])
            =< maps:get(convergence_sample_wall_time_us,Report)
        andalso lists:all(fun(Entry) -> maps:get(sample_wall_time_us,Entry)
            =< maps:get(convergence_max_sample_wall_time_us,Report) end,Trace)
        andalso maps:get(convergence_quiet_samples,Report) =:= trailing_restored(Trace,0)
        andalso trace_matches_final(Trace,maps:get(baseline,Report),maps:get(final,Report)).

valid_convergence_entry(Entry, Report) when is_map(Entry) ->
    Keys = [ordinal,offset_ms,restored,blocker,excess,sample_wall_time_us],
    lists:sort(maps:keys(Entry)) =:= lists:sort(Keys)
        andalso bounded_integer(maps:get(ordinal,Entry),1,2001)
        andalso bounded_integer(maps:get(offset_ms,Entry),0,
            maps:get(convergence_elapsed_ms,Report))
        andalso is_boolean(maps:get(restored,Entry))
        andalso lists:member(maps:get(blocker,Entry),[<<"restored">>,<<"baseline_missing">>,
            <<"project_processes">>,<<"tcp_ports">>,<<"udp_ports">>,<<"sockets">>,
            <<"processes">>,<<"queued_messages">>,<<"ports">>])
        andalso bounded_integer(maps:get(excess,Entry),0,9007199254740991)
        andalso bounded_integer(maps:get(sample_wall_time_us,Entry),0,9007199254740991)
        andalso case {maps:get(restored,Entry),maps:get(blocker,Entry),maps:get(excess,Entry)} of
            {true,<<"restored">>,0} -> true;
            {false,<<"baseline_missing">>,0} -> true;
            {false,<<"restored">>,_} -> false;
            {false,_,Value} -> Value > 0;
            _ -> false
        end;
valid_convergence_entry(_,_) -> false.

trace_offsets_monotonic([],_) -> true;
trace_offsets_monotonic([Entry|Rest],Previous) ->
    Offset = maps:get(offset_ms,Entry),
    Offset >= Previous andalso trace_offsets_monotonic(Rest,Offset).

trailing_restored([],Count) -> min(2,Count);
trailing_restored(Trace,_) ->
    trailing_restored_reverse(lists:reverse(Trace),0).

trailing_restored_reverse([#{restored := true}|Rest],Count) ->
    trailing_restored_reverse(Rest,Count+1);
trailing_restored_reverse(_,Count) -> min(2,Count).

trace_matches_final([],_,Final) -> Final =:= null;
trace_matches_final(Trace,Baseline,Final) when Final =/= null ->
    Last = lists:last(Trace),
    {Restored,Blocker,Excess} = restoration(Baseline,Final),
    {maps:get(restored,Last),maps:get(blocker,Last),maps:get(excess,Last)}
        =:= {Restored,Blocker,Excess};
trace_matches_final(_,_,_) -> false.
