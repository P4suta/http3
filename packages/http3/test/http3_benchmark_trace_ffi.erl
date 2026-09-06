-module(http3_benchmark_trace_ffi).

-export([
    progress_distribution/2,
    progress_summary/4,
    start_progress_trace/5,
    stop_progress_trace/1,
    trace_client_progress/4,
    trace_server_progress/2
]).

-define(TRACE_DIRECTORY_ENVIRONMENT, "HTTP3_BENCHMARK_TRACE_DIR").
-define(START_TIMEOUT_MILLISECONDS, 10000).
-define(STOP_TIMEOUT_MILLISECONDS, 10000).
-define(SAMPLE_INTERVAL_MILLISECONDS, 1000).
-define(VM_CENSUS_INTERVAL_MILLISECONDS, 5000).
-define(STALL_MILLISECONDS, 5000).
-define(SNAPSHOT_INTERVAL_MILLISECONDS, 30000).
-define(MAXIMUM_SNAPSHOT_PROCESSES, 64).
-define(MAXIMUM_SNAPSHOT_PORTS, 64).
-define(MAXIMUM_STACK_FRAMES, 16).

-define(CSV_HEADER,
        <<"schema,mode,iteration,warmup,workers,requests_per_worker,elapsed_ms,"
          "server_completed,client_completed,client_min_completed,"
          "client_p10_completed,client_p50_completed,client_p90_completed,"
          "client_max_completed,client_completion_spread,active_clients,"
          "client_phase_connect_open_or_send,"
          "client_phase_awaiting_response,client_phase_response,"
          "client_phase_completed,stalled_clients,server_minus_client_completed,"
          "server_completed_since_previous,client_completed_since_previous,"
          "beam_processes,beam_memory_bytes,mailbox_messages,vm_census_age_ms,"
          "vm_census_collection_microseconds,run_queue,"
          "runtime_ms_since_previous,reductions_since_previous,"
          "progress_collection_microseconds,sample_collection_microseconds\n">>).

-spec start_progress_trace(binary(), pos_integer(), boolean(), pos_integer(),
                           pos_integer()) ->
    disabled | tuple().
start_progress_trace(Mode, Iteration, Warmup, Workers, RequestsPerWorker)
        when is_binary(Mode), is_integer(Iteration), Iteration > 0,
             is_boolean(Warmup), is_integer(Workers), Workers > 0,
             is_integer(RequestsPerWorker), RequestsPerWorker > 0 ->
    case os:getenv(?TRACE_DIRECTORY_ENVIRONMENT) of
        false ->
            disabled;
        [] ->
            disabled;
        Directory ->
            start_enabled_trace(Directory, Mode, Iteration, Warmup, Workers,
                                RequestsPerWorker)
    end.

-spec trace_client_progress(disabled | tuple(), non_neg_integer(), pos_integer(),
                            1..4) -> nil.
trace_client_progress(disabled, _Worker, _Request, _Phase) ->
    nil;
trace_client_progress({http3_benchmark_progress_trace, _Writer, _Monitor, Table},
                      Worker, Request, Phase)
        when is_integer(Worker), Worker >= 0, is_integer(Request), Request > 0,
             is_integer(Phase), Phase >= 1, Phase =< 4 ->
    safe_trace_insert(Table,
                      {{client, Worker}, Request, Phase,
                       erlang:monotonic_time(millisecond)}),
    nil.

-spec trace_server_progress(disabled | tuple(), non_neg_integer()) -> nil.
trace_server_progress(disabled, _Completed) ->
    nil;
trace_server_progress({http3_benchmark_progress_trace, _Writer, _Monitor, Table},
                      Completed)
        when is_integer(Completed), Completed >= 0 ->
    safe_trace_insert(Table,
                      {server, Completed, erlang:monotonic_time(millisecond)}),
    nil.

-spec stop_progress_trace(disabled | tuple()) -> nil.
stop_progress_trace(disabled) ->
    nil;
stop_progress_trace({http3_benchmark_progress_trace, Writer, Monitor, _Table}) ->
    StopReference = make_ref(),
    Writer ! {stop_progress_trace, self(), StopReference},
    receive
        {StopReference, progress_trace_stopped} ->
            await_writer_down(Writer, Monitor);
        {'DOWN', Monitor, process, Writer, Reason} ->
            erlang:error({benchmark_progress_writer_failed, Reason})
    after ?STOP_TIMEOUT_MILLISECONDS ->
        exit(Writer, kill),
        await_writer_down_after_timeout(Writer, Monitor)
    end,
    nil.

-spec progress_summary([{integer(), integer(), integer()}], integer(),
                       non_neg_integer(), non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
progress_summary(Workers, NowMilliseconds, StallMilliseconds, RequestsPerWorker)
        when is_list(Workers), is_integer(NowMilliseconds),
             is_integer(StallMilliseconds), StallMilliseconds >= 0,
             is_integer(RequestsPerWorker), RequestsPerWorker >= 0 ->
    {Total, Minimum, Maximum, PhaseOne, PhaseTwo, PhaseThree, PhaseFour, Stalled} =
        lists:foldl(
          fun progress_entry/2,
          {0, undefined, 0, 0, 0, 0, 0, 0},
          [{Entry, NowMilliseconds, StallMilliseconds, RequestsPerWorker}
           || Entry <- Workers]),
    {Total, minimum_or_zero(Minimum), Maximum, PhaseOne, PhaseTwo, PhaseThree,
     PhaseFour, Stalled}.

-spec progress_distribution([{integer(), integer(), integer()}],
                            non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
     non_neg_integer(), non_neg_integer()}.
progress_distribution(Workers, RequestsPerWorker)
        when is_list(Workers), is_integer(RequestsPerWorker),
             RequestsPerWorker >= 0 ->
    Completed = lists:sort([
        validated_completed_requests(Entry)
     || Entry <- Workers
    ]),
    case Completed of
        [] ->
            {0, 0, 0, 0, 0};
        _ ->
            Minimum = hd(Completed),
            Maximum = lists:last(Completed),
            Active = length([
                Value
             || Value <- Completed, Value < RequestsPerWorker
            ]),
            {nearest_rank(Completed, 10), nearest_rank(Completed, 50),
             nearest_rank(Completed, 90), Maximum - Minimum, Active}
    end.

start_enabled_trace(Directory, Mode, Iteration, Warmup, Workers,
                    RequestsPerWorker) ->
    Owner = self(),
    StartReference = make_ref(),
    {Writer, Monitor} = spawn_monitor(fun() ->
        progress_writer_start(Owner, StartReference, Directory, Mode, Iteration,
                              Warmup, Workers, RequestsPerWorker)
    end),
    receive
        {StartReference, progress_trace_ready, Table} ->
            {http3_benchmark_progress_trace, Writer, Monitor, Table};
        {'DOWN', Monitor, process, Writer, Reason} ->
            erlang:error({benchmark_progress_writer_start_failed, Reason})
    after ?START_TIMEOUT_MILLISECONDS ->
        exit(Writer, kill),
        receive
            {'DOWN', Monitor, process, Writer, _Reason} -> ok
        after ?STOP_TIMEOUT_MILLISECONDS -> ok
        end,
        erlang:error(benchmark_progress_writer_start_timeout)
    end.

progress_writer_start(Owner, StartReference, Directory, Mode, Iteration,
                      Warmup, Workers, RequestsPerWorker) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    Table = ets:new(http3_benchmark_progress,
                    [set, public, {read_concurrency, true},
                     {write_concurrency, true}]),
    StartedMilliseconds = erlang:monotonic_time(millisecond),
    initialize_workers(Table, Workers, StartedMilliseconds),
    true = ets:insert(Table, {server, 0, StartedMilliseconds}),
    CsvPath = trace_csv_path(Directory, Mode, Iteration, Warmup),
    ok = filelib:ensure_dir(CsvPath),
    {ok, File} = file:open(CsvPath, [write, raw, binary]),
    ok = file:write(File, ?CSV_HEADER),
    {RuntimeMilliseconds, Reductions} = diagnostic_counters(),
    CensusStartedMicroseconds = erlang:monotonic_time(microsecond),
    {Processes, MemoryBytes, MailboxMessages} = vm_census(),
    CensusMicroseconds =
        nonnegative_delta(CensusStartedMicroseconds,
                          erlang:monotonic_time(microsecond)),
    Owner ! {StartReference, progress_trace_ready, Table},
    Timer = erlang:send_after(?SAMPLE_INTERVAL_MILLISECONDS, self(),
                              sample_progress),
    progress_writer_loop(
      #{owner => Owner, owner_monitor => OwnerMonitor, table => Table,
        file => File, csv_path => CsvPath, mode => Mode, iteration => Iteration,
        warmup => Warmup, workers => Workers,
        requests_per_worker => RequestsPerWorker,
        started_milliseconds => StartedMilliseconds,
        previous_runtime_milliseconds => RuntimeMilliseconds,
        previous_reductions => Reductions, previous_server_completed => 0,
        previous_client_completed => 0, beam_processes => Processes,
        beam_memory_bytes => MemoryBytes, mailbox_messages => MailboxMessages,
        last_census_milliseconds => StartedMilliseconds,
        initial_census_microseconds => CensusMicroseconds, timer => Timer,
        last_snapshot_milliseconds => undefined, snapshot_sequence => 0}).

progress_writer_loop(State) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    receive
        sample_progress ->
            SampledState = write_progress_sample(State),
            Timer = erlang:send_after(?SAMPLE_INTERVAL_MILLISECONDS, self(),
                                      sample_progress),
            progress_writer_loop(SampledState#{timer => Timer});
        {stop_progress_trace, Owner, StopReference} ->
            cancel_sample_timer(State),
            FinalState = write_progress_sample(State),
            ok = file:sync(maps:get(file, FinalState)),
            ok = file:close(maps:get(file, FinalState)),
            Owner ! {StopReference, progress_trace_stopped},
            ok;
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            cancel_sample_timer(State),
            ok = ignore_failure(fun() -> write_progress_sample(State) end),
            ok = ignore_failure(fun() -> file:sync(maps:get(file, State)) end),
            ok = ignore_failure(fun() -> file:close(maps:get(file, State)) end),
            ok
    end.

write_progress_sample(State) ->
    SampleStartedMicroseconds = erlang:monotonic_time(microsecond),
    NowMilliseconds = erlang:monotonic_time(millisecond),
    Table = maps:get(table, State),
    ProgressStartedMicroseconds = erlang:monotonic_time(microsecond),
    ClientRecords =
        [{Worker, Request, Phase, UpdatedMilliseconds}
         || {{client, Worker}, Request, Phase, UpdatedMilliseconds}
                <- ets:tab2list(Table)],
    ClientEntries =
        [{Request, Phase, UpdatedMilliseconds}
         || {_Worker, Request, Phase, UpdatedMilliseconds} <- ClientRecords],
    {ClientCompleted, MinimumCompleted, MaximumCompleted, PhaseOne, PhaseTwo,
     PhaseThree, PhaseFour, StalledClients} =
        progress_summary(ClientEntries, NowMilliseconds, ?STALL_MILLISECONDS,
                         maps:get(requests_per_worker, State)),
    {PercentileTen, PercentileFifty, PercentileNinety, CompletionSpread,
     ActiveClients} =
        progress_distribution(ClientEntries,
                              maps:get(requests_per_worker, State)),
    ServerCompleted = server_completed(Table),
    ProgressCollectionMicroseconds =
        nonnegative_delta(ProgressStartedMicroseconds,
                          erlang:monotonic_time(microsecond)),
    {CensusState, CensusAgeMilliseconds, CensusCollectionMicroseconds} =
        maybe_refresh_vm_census(State, NowMilliseconds),
    RunQueue = erlang:statistics(run_queue),
    {RuntimeMilliseconds, Reductions} = diagnostic_counters(),
    RuntimeDelta = nonnegative_delta(
                     maps:get(previous_runtime_milliseconds, State),
                     RuntimeMilliseconds),
    ReductionsDelta = nonnegative_delta(maps:get(previous_reductions, State),
                                        Reductions),
    ElapsedMilliseconds =
        nonnegative_delta(maps:get(started_milliseconds, State),
                          NowMilliseconds),
    ServerDelta = nonnegative_delta(
                    maps:get(previous_server_completed, CensusState),
                    ServerCompleted),
    ClientDelta = nonnegative_delta(
                    maps:get(previous_client_completed, CensusState),
                    ClientCompleted),
    SampleCollectionMicroseconds =
        nonnegative_delta(SampleStartedMicroseconds,
                          erlang:monotonic_time(microsecond)),
    Sample =
        #{elapsed_ms => ElapsedMilliseconds,
          server_completed => ServerCompleted,
          client_completed => ClientCompleted,
          client_min_completed => MinimumCompleted,
          client_p10_completed => PercentileTen,
          client_p50_completed => PercentileFifty,
          client_p90_completed => PercentileNinety,
          client_max_completed => MaximumCompleted,
          client_completion_spread => CompletionSpread,
          active_clients => ActiveClients,
          client_phase_connect_open_or_send => PhaseOne,
          client_phase_awaiting_response => PhaseTwo,
          client_phase_response => PhaseThree,
          client_phase_completed => PhaseFour,
          stalled_clients => StalledClients,
          server_minus_client_completed => ServerCompleted - ClientCompleted,
          server_completed_since_previous => ServerDelta,
          client_completed_since_previous => ClientDelta,
          beam_processes => maps:get(beam_processes, CensusState),
          beam_memory_bytes => maps:get(beam_memory_bytes, CensusState),
          mailbox_messages => maps:get(mailbox_messages, CensusState),
          vm_census_age_ms => CensusAgeMilliseconds,
          vm_census_collection_microseconds => CensusCollectionMicroseconds,
          run_queue => RunQueue,
          runtime_ms_since_previous => RuntimeDelta,
          reductions_since_previous => ReductionsDelta,
          progress_collection_microseconds => ProgressCollectionMicroseconds,
          sample_collection_microseconds => SampleCollectionMicroseconds},
    ok = write_csv_sample(maps:get(file, CensusState), CensusState, Sample),
    maybe_write_stall_snapshot(
      CensusState#{previous_runtime_milliseconds => RuntimeMilliseconds,
                   previous_reductions => Reductions,
                   previous_server_completed => ServerCompleted,
                   previous_client_completed => ClientCompleted},
      Sample, ClientRecords, NowMilliseconds).

write_csv_sample(File, State, Sample) ->
    Fields =
        ["1", safe_component(maps:get(mode, State)),
         integer_to_list(maps:get(iteration, State)),
         boolean_text(maps:get(warmup, State)),
         integer_to_list(maps:get(workers, State)),
         integer_to_list(maps:get(requests_per_worker, State)),
         integer_to_list(maps:get(elapsed_ms, Sample)),
         integer_to_list(maps:get(server_completed, Sample)),
         integer_to_list(maps:get(client_completed, Sample)),
         integer_to_list(maps:get(client_min_completed, Sample)),
         integer_to_list(maps:get(client_p10_completed, Sample)),
         integer_to_list(maps:get(client_p50_completed, Sample)),
         integer_to_list(maps:get(client_p90_completed, Sample)),
         integer_to_list(maps:get(client_max_completed, Sample)),
         integer_to_list(maps:get(client_completion_spread, Sample)),
         integer_to_list(maps:get(active_clients, Sample)),
         integer_to_list(maps:get(client_phase_connect_open_or_send, Sample)),
         integer_to_list(maps:get(client_phase_awaiting_response, Sample)),
         integer_to_list(maps:get(client_phase_response, Sample)),
         integer_to_list(maps:get(client_phase_completed, Sample)),
         integer_to_list(maps:get(stalled_clients, Sample)),
         integer_to_list(maps:get(server_minus_client_completed, Sample)),
         integer_to_list(maps:get(server_completed_since_previous, Sample)),
         integer_to_list(maps:get(client_completed_since_previous, Sample)),
         integer_to_list(maps:get(beam_processes, Sample)),
         integer_to_list(maps:get(beam_memory_bytes, Sample)),
         integer_to_list(maps:get(mailbox_messages, Sample)),
         integer_to_list(maps:get(vm_census_age_ms, Sample)),
         integer_to_list(maps:get(vm_census_collection_microseconds, Sample)),
         integer_to_list(maps:get(run_queue, Sample)),
         integer_to_list(maps:get(runtime_ms_since_previous, Sample)),
         integer_to_list(maps:get(reductions_since_previous, Sample)),
         integer_to_list(maps:get(progress_collection_microseconds, Sample)),
         integer_to_list(maps:get(sample_collection_microseconds, Sample))],
    file:write(File, [lists:join($,, Fields), $\n]).

maybe_write_stall_snapshot(State, #{stalled_clients := 0}, _ClientRecords,
                           _NowMilliseconds) ->
    State;
maybe_write_stall_snapshot(State, Sample, ClientRecords, NowMilliseconds) ->
    LastSnapshot = maps:get(last_snapshot_milliseconds, State),
    case snapshot_due(LastSnapshot, NowMilliseconds) of
        false ->
            State;
        true ->
            Sequence = maps:get(snapshot_sequence, State) + 1,
            SnapshotPath = stall_snapshot_path(maps:get(csv_path, State), Sequence),
            ProcessSnapshots = top_process_snapshots(),
            PortSnapshots = bounded_port_snapshots(),
            Snapshot =
                #{schema => 1, shareable => false, payload_free => true,
                  capture => <<"bounded-beam-stall">>, mode => maps:get(mode, State),
                  iteration => maps:get(iteration, State),
                  warmup => maps:get(warmup, State),
                  workers => maps:get(workers, State),
                  requests_per_worker => maps:get(requests_per_worker, State),
                  captured_unix_milliseconds => erlang:system_time(millisecond),
                  sample => Sample,
                  observed_process_count => erlang:system_info(process_count),
                  captured_process_count => length(ProcessSnapshots),
                  processes => ProcessSnapshots,
                  worker_progress =>
                      worker_progress_snapshots(
                        ClientRecords, NowMilliseconds,
                        maps:get(requests_per_worker, State)),
                  observed_port_count => length(erlang:ports()),
                  captured_port_count => length(PortSnapshots),
                  ports => PortSnapshots,
                  redaction =>
                      #{message_payloads => <<"omitted">>,
                        process_dictionaries => <<"omitted">>,
                        function_arguments => <<"omitted">>,
                        socket_endpoints => <<"omitted">>}},
            ok = file:write_file(SnapshotPath, [json:encode(Snapshot), <<"\n">>]),
            State#{last_snapshot_milliseconds => NowMilliseconds,
                   snapshot_sequence => Sequence}
    end.

snapshot_due(undefined, _NowMilliseconds) ->
    true;
snapshot_due(LastSnapshotMilliseconds, NowMilliseconds) ->
    NowMilliseconds - LastSnapshotMilliseconds >= ?SNAPSHOT_INTERVAL_MILLISECONDS.

progress_entry({{Request, Phase, UpdatedMilliseconds}, NowMilliseconds,
                StallMilliseconds, RequestsPerWorker},
               {Total, Minimum, Maximum, PhaseOne, PhaseTwo, PhaseThree,
                PhaseFour, Stalled})
        when is_integer(Request), Request >= 0, is_integer(Phase), Phase >= 1,
             Phase =< 4, is_integer(UpdatedMilliseconds) ->
    Completed = completed_requests(Request, Phase),
    {NextPhaseOne, NextPhaseTwo, NextPhaseThree, NextPhaseFour} =
        increment_phase(Phase, PhaseOne, PhaseTwo, PhaseThree, PhaseFour),
    IsStalled = Completed < RequestsPerWorker
                andalso NowMilliseconds - UpdatedMilliseconds >= StallMilliseconds,
    {Total + Completed, minimum(Minimum, Completed), max(Maximum, Completed),
     NextPhaseOne, NextPhaseTwo, NextPhaseThree, NextPhaseFour,
     Stalled + boolean_integer(IsStalled)};
progress_entry({Entry, _NowMilliseconds, _StallMilliseconds, _RequestsPerWorker},
               _Accumulator) ->
    erlang:error({invalid_benchmark_progress_entry, Entry}).

validated_completed_requests({Request, Phase, _UpdatedMilliseconds})
        when is_integer(Request), Request >= 0, is_integer(Phase), Phase >= 1,
             Phase =< 4 ->
    completed_requests(Request, Phase);
validated_completed_requests(Entry) ->
    erlang:error({invalid_benchmark_progress_entry, Entry}).

completed_requests(Request, 4) -> Request;
completed_requests(Request, _Phase) -> max(0, Request - 1).

increment_phase(1, PhaseOne, PhaseTwo, PhaseThree, PhaseFour) ->
    {PhaseOne + 1, PhaseTwo, PhaseThree, PhaseFour};
increment_phase(2, PhaseOne, PhaseTwo, PhaseThree, PhaseFour) ->
    {PhaseOne, PhaseTwo + 1, PhaseThree, PhaseFour};
increment_phase(3, PhaseOne, PhaseTwo, PhaseThree, PhaseFour) ->
    {PhaseOne, PhaseTwo, PhaseThree + 1, PhaseFour};
increment_phase(4, PhaseOne, PhaseTwo, PhaseThree, PhaseFour) ->
    {PhaseOne, PhaseTwo, PhaseThree, PhaseFour + 1}.

initialize_workers(Table, Workers, StartedMilliseconds) ->
    lists:foreach(
      fun(Worker) ->
          true = ets:insert(Table,
                            {{client, Worker}, 0, 1, StartedMilliseconds})
      end,
      lists:seq(0, Workers - 1)).

server_completed(Table) ->
    case ets:lookup(Table, server) of
        [{server, Completed, _UpdatedMilliseconds}] -> Completed;
        [] -> 0
    end.

safe_trace_insert(Table, Entry) ->
    try ets:insert(Table, Entry) of
        true -> ok
    catch
        error:badarg -> ok
    end.

diagnostic_counters() ->
    {RuntimeMilliseconds, _RuntimeSinceLastCall} = erlang:statistics(runtime),
    {Reductions, _ReductionsSinceLastCall} = erlang:statistics(reductions),
    {RuntimeMilliseconds, Reductions}.

vm_census() ->
    {erlang:system_info(process_count), erlang:memory(total), mailbox_messages()}.

maybe_refresh_vm_census(State, NowMilliseconds) ->
    Age = nonnegative_delta(maps:get(last_census_milliseconds, State),
                            NowMilliseconds),
    case Age >= ?VM_CENSUS_INTERVAL_MILLISECONDS of
        false ->
            {State, Age, 0};
        true ->
            StartedMicroseconds = erlang:monotonic_time(microsecond),
            {Processes, MemoryBytes, MailboxMessages} = vm_census(),
            CollectionMicroseconds =
                nonnegative_delta(StartedMicroseconds,
                                  erlang:monotonic_time(microsecond)),
            {State#{beam_processes => Processes,
                    beam_memory_bytes => MemoryBytes,
                    mailbox_messages => MailboxMessages,
                    last_census_milliseconds => NowMilliseconds},
             0, CollectionMicroseconds}
    end.

mailbox_messages() ->
    lists:sum([
        Length
     || Process <- processes(),
        {message_queue_len, Length} <- [process_info(Process, message_queue_len)]
    ]).

top_process_snapshots() ->
    Snapshots = [Snapshot || Process <- processes(),
                             Snapshot <- process_snapshot(Process)],
    Sorted = lists:sort(fun higher_process_cost/2, Snapshots),
    lists:sublist(Sorted, ?MAXIMUM_SNAPSHOT_PROCESSES).

process_snapshot(Process) ->
    case process_info(Process,
                      [status, current_function, initial_call, message_queue_len,
                       memory, reductions, current_stacktrace]) of
        undefined ->
            [];
        Information ->
            [#{pid => list_to_binary(pid_to_list(Process)),
               status => atom_binary(proplists:get_value(status, Information)),
               current_mfa =>
                   sanitize_mfa(proplists:get_value(current_function,
                                                    Information)),
               initial_mfa =>
                   sanitize_mfa(proplists:get_value(initial_call, Information)),
               message_queue_len =>
                   proplists:get_value(message_queue_len, Information, 0),
               memory_bytes => proplists:get_value(memory, Information, 0),
               reductions => proplists:get_value(reductions, Information, 0),
               stack_mfas =>
                   sanitize_stack(proplists:get_value(current_stacktrace,
                                                      Information, []))}]
    end.

worker_progress_snapshots(ClientRecords, NowMilliseconds, RequestsPerWorker) ->
    lists:sort(
      fun(Left, Right) -> maps:get(worker, Left) < maps:get(worker, Right) end,
      [worker_progress_snapshot(Worker, Request, Phase, UpdatedMilliseconds,
                                NowMilliseconds, RequestsPerWorker)
       || {Worker, Request, Phase, UpdatedMilliseconds} <- ClientRecords]).

worker_progress_snapshot(Worker, Request, Phase, UpdatedMilliseconds,
                         NowMilliseconds, RequestsPerWorker) ->
    Completed = completed_requests(Request, Phase),
    Age = nonnegative_delta(UpdatedMilliseconds, NowMilliseconds),
    #{worker => Worker, request => Request, completed => Completed,
      phase => Phase, phase_name => phase_name(Phase), updated_age_ms => Age,
      stalled => Completed < RequestsPerWorker
                 andalso Age >= ?STALL_MILLISECONDS}.

phase_name(1) -> <<"connect-open-send">>;
phase_name(2) -> <<"awaiting-response">>;
phase_name(3) -> <<"receiving-response">>;
phase_name(4) -> <<"request-completed">>.

higher_process_cost(Left, Right) ->
    {maps:get(message_queue_len, Left), maps:get(memory_bytes, Left),
     maps:get(reductions, Left), maps:get(pid, Left)}
    > {maps:get(message_queue_len, Right), maps:get(memory_bytes, Right),
       maps:get(reductions, Right), maps:get(pid, Right)}.

sanitize_stack(Stack) when is_list(Stack) ->
    [sanitize_stack_frame(Frame)
     || Frame <- lists:sublist(Stack, ?MAXIMUM_STACK_FRAMES)].

sanitize_stack_frame({Module, Function, ArityOrArguments, _Location}) ->
    sanitize_mfa({Module, Function, sanitized_arity(ArityOrArguments)});
sanitize_stack_frame({Module, Function, ArityOrArguments}) ->
    sanitize_mfa({Module, Function, sanitized_arity(ArityOrArguments)});
sanitize_stack_frame(_Other) ->
    null.

sanitize_mfa({Module, Function, ArityOrArguments})
        when is_atom(Module), is_atom(Function) ->
    #{module => atom_to_binary(Module), function => atom_to_binary(Function),
      arity => sanitized_arity(ArityOrArguments)};
sanitize_mfa(_Other) ->
    null.

sanitized_arity(Arity) when is_integer(Arity), Arity >= 0 -> Arity;
sanitized_arity(Arguments) when is_list(Arguments) -> length(Arguments);
sanitized_arity(_Other) -> 0.

bounded_port_snapshots() ->
    lists:sublist([Snapshot || Port <- erlang:ports(),
                               Snapshot <- port_snapshot(Port)],
                  ?MAXIMUM_SNAPSHOT_PORTS).

port_snapshot(Port) ->
    case erlang:port_info(Port) of
        undefined ->
            [];
        Information ->
            [#{id => list_to_binary(erlang:port_to_list(Port)),
               name => text_binary(proplists:get_value(name, Information)),
               connected => connected_binary(
                              proplists:get_value(connected, Information)),
               queue_size => proplists:get_value(queue_size, Information, 0),
               memory_bytes => proplists:get_value(memory, Information, 0),
               input_bytes => proplists:get_value(input, Information, 0),
               output_bytes => proplists:get_value(output, Information, 0)}]
    end.

connected_binary(Process) when is_pid(Process) ->
    list_to_binary(pid_to_list(Process));
connected_binary(_Other) ->
    <<"unknown">>.

text_binary(Value) when is_binary(Value) -> Value;
text_binary(Value) when is_list(Value) -> unicode:characters_to_binary(Value);
text_binary(Value) when is_atom(Value) -> atom_to_binary(Value);
text_binary(_Other) -> <<"unknown">>.

atom_binary(Value) when is_atom(Value) -> atom_to_binary(Value);
atom_binary(_Other) -> <<"unknown">>.

trace_csv_path(Directory, Mode, Iteration, Warmup) ->
    Filename =
        lists:flatten(
          io_lib:format("~s-~s-~B.csv",
                        [safe_component(Mode), warmup_label(Warmup), Iteration])),
    filename:join(filename:absname(Directory), Filename).

stall_snapshot_path(CsvPath, Sequence) ->
    lists:flatten(
      io_lib:format("~s-stall-~6..0B.json",
                    [filename:rootname(CsvPath, ".csv"), Sequence])).

safe_component(Value) when is_binary(Value) ->
    [safe_component_character(Character) || Character <- binary_to_list(Value)].

safe_component_character(Character)
        when Character >= $a, Character =< $z -> Character;
safe_component_character(Character)
        when Character >= $A, Character =< $Z -> Character;
safe_component_character(Character)
        when Character >= $0, Character =< $9 -> Character;
safe_component_character($-) -> $-;
safe_component_character($_) -> $_;
safe_component_character(_Other) -> $_.

warmup_label(true) -> "warmup";
warmup_label(false) -> "measured".

boolean_text(true) -> "true";
boolean_text(false) -> "false".

cancel_sample_timer(State) ->
    _ = erlang:cancel_timer(maps:get(timer, State)),
    ok.

await_writer_down(Writer, Monitor) ->
    receive
        {'DOWN', Monitor, process, Writer, normal} -> ok;
        {'DOWN', Monitor, process, Writer, Reason} ->
            erlang:error({benchmark_progress_writer_failed, Reason})
    after ?STOP_TIMEOUT_MILLISECONDS ->
        exit(Writer, kill),
        await_writer_down_after_timeout(Writer, Monitor)
    end.

await_writer_down_after_timeout(Writer, Monitor) ->
    receive
        {'DOWN', Monitor, process, Writer, _Reason} -> ok
    after ?STOP_TIMEOUT_MILLISECONDS -> ok
    end,
    erlang:error(benchmark_progress_writer_stop_timeout).

minimum(undefined, Value) -> Value;
minimum(Current, Value) -> min(Current, Value).

minimum_or_zero(undefined) -> 0;
minimum_or_zero(Value) -> Value.

nonnegative_delta(Before, After) when After >= Before -> After - Before;
nonnegative_delta(_Before, _After) -> 0.

nearest_rank(Values, Percent) ->
    Rank = max(1, (Percent * length(Values) + 99) div 100),
    lists:nth(Rank, Values).

boolean_integer(true) -> 1;
boolean_integer(false) -> 0.

ignore_failure(Function) ->
    try Function() of
        _Result -> ok
    catch
        _Class:_Reason -> ok
    end.
