#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("diagnostic_failure.hrl").
-include("json_evidence.hrl").
-include("evidence_identity.hrl").
-include("performance_execution.hrl").

-define(PROFILE, "standards/performance-profile.json").
-define(OUTPUT, "build/performance/current").
-include("performance_csv.hrl").
-define(HEADER, ?PERFORMANCE_CSV_HEADER).
-define(LOG_TAIL_BYTES, 16384).

main(["--self-test"]) ->
    guarded_self_test();
main([Mode, ExitStatus, LogPath, StartHostPath, EndHostPath])
        when Mode =:= "benchmark"; Mode =:= "load"; Mode =:= "soak" ->
    guarded_run(Mode, ExitStatus, LogPath, StartHostPath, EndHostPath);
main(_) ->
    erlang:error(
      {usage,
       "--self-test | benchmark|load|soak EXIT_STATUS LOG START_HOST END_HOST"}).

guarded_self_test() ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "performance report self-test failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end.

guarded_run(Mode, ExitStatusText, LogPath, StartHostPath, EndHostPath) ->
    try run(Mode, ExitStatusText, LogPath, StartHostPath, EndHostPath) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            _ = try write_emergency_report(
                      Mode, LogPath, StartHostPath, EndHostPath,
                      Class, Reason, Stacktrace) of
                ok -> ok
            catch
                _:_ -> emergency_report_unavailable
            end,
            io:format(standard_error, "~s performance report failed: ~p~n",
                      [Mode, diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end.

run(ModeText, ExitStatusText, LogPath, StartHostPath, EndHostPath) ->
    Mode = list_to_binary(ModeText),
    ExitStatus = parse_nonnegative(<<"exit_status">>,
                                   list_to_binary(ExitStatusText)),
    Log = maps:get(csv, performance_filter_csv(read(LogPath))),
    ProfileBytes = read(?PROFILE),
    Profile = evidence_json_decode(ProfileBytes),
    EvidenceProfile = validate_evidence_profile(Profile),
    Configuration = workload_configuration(Mode, Profile),
    Rows = parse_rows(Log, Mode),
    Execution = performance_verify_execution(Mode, Log),
    HostEvidence = host_evidence(StartHostPath, EndHostPath),
    Child = maps:get(<<"child">>, Execution),
    true = maps:get(snapshot, maps:get(start, HostEvidence)) =:= maps:get(<<"host_start">>, Child),
    true = maps:get(snapshot, maps:get('end', HostEvidence)) =:= maps:get(<<"host_end">>, Child),
    Stem = "build/performance/current/" ++ ModeText,
    true = LogPath =:= Stem ++ ".log",
    true = StartHostPath =:= Stem ++ "-host-start.json",
    true = EndHostPath =:= Stem ++ "-host-end.json",
    HostViolations = validate_host_evidence(HostEvidence),
    Violations = validate_run(ExitStatus, Rows, Configuration)
                 ++ HostViolations,
    Status = case Violations of [] -> <<"Ready">>; _ -> <<"Failed">> end,
    Report = #{schema => maps:get(<<"report_schema">>, EvidenceProfile),
               status => Status, mode => Mode,
               baseline_date => maps:get(<<"baseline_date">>, Profile),
               source_sha256 => source_digest(Profile),
               profile_sha256 => hex(crypto:hash(sha256, ProfileBytes)),
               otp_release => list_to_binary(erlang:system_info(otp_release)),
               system_architecture => list_to_binary(
                                        erlang:system_info(system_architecture)),
               logical_processors => erlang:system_info(logical_processors),
               exit_status => ExitStatus,
               log => bounded_log_evidence(Log, LogPath),
               host => HostEvidence,
               configuration => Configuration,
               measured_median_requests_per_second => measured_median(Rows),
               rows => Rows, violations => Violations, execution => Execution},
    write_report(ModeText, evidence_complete(Report, maps:get(<<"evidence_identity">>, Execution)), Rows),
    case Violations of
        [] ->
            io:format("~s performance evidence: ~B rows, median ~B req/s~n",
                      [ModeText, length(Rows), measured_median(Rows)]),
            ok;
        _ ->
            io:format(standard_error,
                      "~s performance evidence failed: ~p~n",
                      [ModeText, Violations]),
            halt(1)
    end.

validate_evidence_profile(Profile) ->
    Evidence = maps:get(<<"performance_evidence">>, Profile),
    ensure(maps:get(<<"report_schema">>, Evidence) =:= 4,
           unsupported_performance_report_schema),
    ensure(maps:get(<<"host_snapshot_schema">>, Evidence) =:= 1,
           unsupported_host_snapshot_schema),
    ensure(maps:get(<<"log_tail_bytes">>, Evidence) =:= ?LOG_TAIL_BYTES,
           performance_log_tail_limit_drift),
    Modes = maps:get(<<"fixed_http3_modes">>, Evidence),
    ensure(Modes =:= [<<"benchmark">>, <<"load">>, <<"soak">>],
           invalid_fixed_http3_evidence_modes),
    SourceFiles = maps:get(<<"source_files">>, Evidence),
    ensure(SourceFiles =/= []
           andalso length(SourceFiles) =:= length(lists:usort(SourceFiles)),
           invalid_performance_source_files),
    SourceRoots = maps:get(<<"production_source_roots">>, Evidence),
    ensure(SourceRoots =/= []
           andalso length(SourceRoots) =:= length(lists:usort(SourceRoots)),
           invalid_performance_source_roots),
    Evidence.

host_evidence(StartPath, EndPath) ->
    Start = host_file_evidence(StartPath),
    End = host_file_evidence(EndPath),
    StartSnapshot = maps:get(snapshot, Start),
    EndSnapshot = maps:get(snapshot, End),
    #{shareable => false, start => Start, 'end' => End,
      deltas => host_deltas(StartSnapshot, EndSnapshot)}.

host_file_evidence(Path) ->
    Bytes = read(Path),
    Snapshot = evidence_json_decode(Bytes),
    true = performance_host_valid(Snapshot, maps:get(<<"label">>, Snapshot)),
    Canonical = iolist_to_binary([json:encode(Snapshot), $\n]),
    #{path => list_to_binary(Path), bytes => byte_size(Bytes),
      sha256 => hex(crypto:hash(sha256, Canonical)), snapshot => Snapshot}.

validate_host_evidence(Evidence) ->
    Start = maps:get(snapshot, maps:get(start, Evidence)),
    End = maps:get(snapshot, maps:get('end', Evidence)),
    StartTime = snapshot_integer(Start,
                                 <<"captured_system_time_milliseconds">>, 0),
    EndTime = snapshot_integer(End,
                               <<"captured_system_time_milliseconds">>, 0),
    lists:append([
        validate_host_snapshot(Start, <<"start">>),
        validate_host_snapshot(End, <<"end">>),
        violation(EndTime < StartTime,
                  #{id => <<"host-snapshot-time-order">>, start => StartTime,
                    'end' => EndTime}),
        violation(maps:get(<<"runtime">>, Start, undefined)
                  =/= maps:get(<<"runtime">>, End, undefined),
                  #{id => <<"host-runtime-drift">>}),
        host_counter_violations(Start, End)
    ]).

validate_host_snapshot(Snapshot, ExpectedLabel) when is_map(Snapshot) ->
    Probes = maps:get(<<"probes">>, Snapshot, #{}),
    lists:append([
        violation(maps:get(<<"schema">>, Snapshot, undefined) =/= 1,
                  #{id => <<"host-snapshot-schema">>, label => ExpectedLabel}),
        violation(maps:get(<<"status">>, Snapshot, undefined)
                  =/= <<"Captured">>,
                  #{id => <<"host-snapshot-status">>, label => ExpectedLabel}),
        violation(maps:get(<<"label">>, Snapshot, undefined)
                  =/= ExpectedLabel,
                  #{id => <<"host-snapshot-label">>, label => ExpectedLabel}),
        violation(maps:get(<<"shareable">>, Snapshot, undefined) =/= false,
                  #{id => <<"host-snapshot-shareability">>,
                    label => ExpectedLabel}),
        violation(not is_map(maps:get(<<"runtime">>, Snapshot, undefined)),
                  #{id => <<"host-snapshot-runtime">>, label => ExpectedLabel}),
        violation(not is_integer(maps:get(
                      <<"captured_system_time_milliseconds">>, Snapshot,
                      undefined)),
                  #{id => <<"host-snapshot-time">>, label => ExpectedLabel}),
        validate_host_probes(Probes, ExpectedLabel)
    ]);
validate_host_snapshot(_Snapshot, ExpectedLabel) ->
    [#{id => <<"host-snapshot-shape">>, label => ExpectedLabel}].

validate_host_probes(Probes, Label) when is_map(Probes) ->
    lists:append([validate_host_probe(Name, maps:find(Name, Probes), Label)
                  || Name <- expected_host_probes()]);
validate_host_probes(_Probes, Label) ->
    [#{id => <<"host-probes-shape">>, label => Label}].

validate_host_probe(Name, error, Label) ->
    [#{id => <<"host-probe-missing">>, label => Label, probe => Name}];
validate_host_probe(Name, {ok, Probe}, Label) when is_map(Probe) ->
    Status = maps:get(<<"status">>, Probe, undefined),
    case lists:member(Status, [<<"Available">>, <<"Partial">>,
                               <<"Unavailable">>]) of
        true -> [];
        false ->
            [#{id => <<"host-probe-invalid">>, label => Label,
               probe => Name, status => <<"Invalid">>, reason => <<"invalid_probe">>}]
    end;
validate_host_probe(Name, {ok, _Probe}, Label) ->
    [#{id => <<"host-probe-shape">>, label => Label, probe => Name}].

expected_host_probes() ->
    [<<"load_average">>, <<"cpu_pressure">>, <<"memory_pressure">>,
     <<"io_pressure">>, <<"cpu_accounting">>, <<"memory">>,
     <<"cgroup_cpu_accounting">>, <<"cgroup_cpu_limit">>,
     <<"cgroup_memory_current">>, <<"cgroup_memory_peak">>,
     <<"cgroup_memory_limit">>, <<"cgroup_memory_events">>,
     <<"cpu_frequency">>, <<"thermal">>].

host_counter_violations(Start, End) ->
    Paths =
        [[<<"cpu_accounting">>, <<"total_ticks">>],
         [<<"cpu_accounting">>, <<"busy_ticks">>],
         [<<"cpu_accounting">>, <<"context_switches">>],
         [<<"cpu_accounting">>, <<"processes_created">>],
         [<<"cpu_pressure">>, <<"some">>, <<"total_microseconds">>],
         [<<"cpu_pressure">>, <<"full">>, <<"total_microseconds">>],
         [<<"memory_pressure">>, <<"some">>, <<"total_microseconds">>],
         [<<"memory_pressure">>, <<"full">>, <<"total_microseconds">>],
         [<<"io_pressure">>, <<"some">>, <<"total_microseconds">>],
         [<<"io_pressure">>, <<"full">>, <<"total_microseconds">>],
         [<<"cgroup_cpu_accounting">>, <<"counters">>, <<"usage_usec">>],
         [<<"cgroup_cpu_accounting">>, <<"counters">>,
          <<"nr_throttled">>],
         [<<"cgroup_cpu_accounting">>, <<"counters">>,
          <<"throttled_usec">>]],
    lists:append([counter_path_violation(Start, End, Path) || Path <- Paths]).

counter_path_violation(Start, End, Path) ->
    Before = host_probe_value(Start, Path),
    After = host_probe_value(End, Path),
    case {Before, After} of
        {Value, Later}
                when is_integer(Value), is_integer(Later), Later < Value ->
            [#{id => <<"host-counter-regression">>,
               path => join_path(Path), before => Value, 'after' => Later}];
        {_, _} -> []
    end.

workload_configuration(Mode, Profile) ->
    Workloads = maps:get(<<"fixed_http3_workloads">>, Profile),
    case [Workload || Workload <- Workloads,
                      maps:get(<<"mode">>, Workload) =:= Mode] of
        [Workload] ->
            #{mode => Mode,
              warmup_runs => maps:get(<<"warmup_runs">>, Workload),
              measured_trials => maps:get(<<"measured_trials">>, Workload),
              concurrency => maps:get(<<"concurrency">>, Workload),
              requests_per_connection =>
                  maps:get(<<"requests_per_connection">>, Workload),
              payload_bytes => maps:get(<<"payload_bytes">>, Workload),
              minimum_requests_per_second =>
                  maps:get(<<"minimum_requests_per_second">>, Workload)};
        [] -> erlang:error({missing_fixed_http3_workload, Mode});
        Duplicate -> erlang:error({duplicate_fixed_http3_workload,
                                   Mode, Duplicate})
    end.

parse_rows(Log, Mode) ->
    Lines = binary:split(Log, <<"\n">>, [global]),
    HeaderCount = length([Line || Line <- Lines, Line =:= ?HEADER]),
    ensure(HeaderCount =:= 1, {invalid_performance_header_count, HeaderCount}),
    Prefix = <<Mode/binary, ",">>,
    [parse_row(Line) || Line <- Lines,
                        binary:match(Line, Prefix) =:= {0, byte_size(Prefix)}].

parse_row(Line) ->
    case binary:split(Line, <<",">>, [global]) of
        [Mode, Iteration, Warmup, Concurrency, Requests, TotalRequests,
         Payload, Elapsed, RequestsPerSecond, ProcessesBefore, ProcessesAfter,
         MemoryBefore, MemoryAfter, MessagesBefore, MessagesAfter,
         PortsBefore, PortsAfter, NetworkPortsBefore, NetworkPortsAfter,
         SocketsBefore, SocketsAfter,
         RuntimeMilliseconds, Reductions, ContextSwitches, GarbageCollections,
         GarbageCollectedWords, InputBytes, OutputBytes, RunQueueBefore,
         RunQueueAfter, InitialRttMinimum, InitialRttAverage, InitialRttMaximum,
         FinalRttMinimum, FinalRttAverage, FinalRttMaximum,
         InitialWindowMinimum, InitialWindowAverage, InitialWindowMaximum,
         FinalWindowMinimum, FinalWindowAverage, FinalWindowMaximum,
         Retransmissions, MaximumRetransmissions, PacketsReceived, PacketsSent,
         BatchFlushes, PacketsCoalesced, ConnectionsInRecovery,
         ConnectionsCongested] ->
            ElapsedMicroseconds =
                parse_positive(<<"elapsed_microseconds">>, Elapsed),
            Total = parse_positive(<<"total_requests">>, TotalRequests),
            Runtime = parse_nonnegative(<<"runtime_milliseconds">>,
                                        RuntimeMilliseconds),
            ReductionCount = parse_nonnegative(<<"reductions">>, Reductions),
            #{mode => Mode,
              iteration => parse_positive(<<"iteration">>, Iteration),
              warmup => parse_boolean(Warmup),
              concurrency => parse_positive(<<"concurrency">>, Concurrency),
              requests_per_connection =>
                  parse_positive(<<"requests_per_connection">>, Requests),
              total_requests => Total,
              payload_bytes => parse_positive(<<"payload_bytes">>, Payload),
              elapsed_microseconds => ElapsedMicroseconds,
              requests_per_second =>
                  parse_positive(<<"requests_per_second">>, RequestsPerSecond),
              processes_before =>
                  parse_positive(<<"processes_before">>, ProcessesBefore),
              processes_after =>
                  parse_positive(<<"processes_after">>, ProcessesAfter),
              memory_before_bytes =>
                  parse_positive(<<"memory_before_bytes">>, MemoryBefore),
              memory_after_bytes =>
                  parse_positive(<<"memory_after_bytes">>, MemoryAfter),
              mailbox_messages_before =>
                  parse_nonnegative(<<"mailbox_messages_before">>,
                                    MessagesBefore),
              mailbox_messages_after =>
                  parse_nonnegative(<<"mailbox_messages_after">>,
                                    MessagesAfter),
              ports_before =>
                  parse_nonnegative(<<"ports_before">>, PortsBefore),
              ports_after =>
                  parse_nonnegative(<<"ports_after">>, PortsAfter),
              network_ports_before =>
                  parse_nonnegative(<<"network_ports_before">>,
                                    NetworkPortsBefore),
              network_ports_after =>
                  parse_nonnegative(<<"network_ports_after">>,
                                    NetworkPortsAfter),
              sockets_before =>
                  parse_nonnegative(<<"sockets_before">>, SocketsBefore),
              sockets_after =>
                  parse_nonnegative(<<"sockets_after">>, SocketsAfter),
              runtime_milliseconds => Runtime,
              beam_runtime_basis_points =>
                  Runtime * 10000000 div ElapsedMicroseconds,
              reductions => ReductionCount,
              reductions_per_request => ReductionCount div Total,
              context_switches =>
                  parse_nonnegative(<<"context_switches">>, ContextSwitches),
              garbage_collections =>
                  parse_nonnegative(<<"garbage_collections">>,
                                    GarbageCollections),
              garbage_collected_words =>
                  parse_nonnegative(<<"garbage_collected_words">>,
                                    GarbageCollectedWords),
              io_input_bytes =>
                  parse_nonnegative(<<"io_input_bytes">>, InputBytes),
              io_output_bytes =>
                  parse_nonnegative(<<"io_output_bytes">>, OutputBytes),
              run_queue_before =>
                  parse_nonnegative(<<"run_queue_before">>, RunQueueBefore),
              run_queue_after =>
                  parse_nonnegative(<<"run_queue_after">>, RunQueueAfter),
              client_initial_smoothed_rtt_min_us =>
                  parse_nonnegative(<<"client_initial_smoothed_rtt_min_us">>,
                                    InitialRttMinimum),
              client_initial_smoothed_rtt_avg_us =>
                  parse_nonnegative(<<"client_initial_smoothed_rtt_avg_us">>,
                                    InitialRttAverage),
              client_initial_smoothed_rtt_max_us =>
                  parse_nonnegative(<<"client_initial_smoothed_rtt_max_us">>,
                                    InitialRttMaximum),
              client_final_smoothed_rtt_min_us =>
                  parse_nonnegative(<<"client_final_smoothed_rtt_min_us">>,
                                    FinalRttMinimum),
              client_final_smoothed_rtt_avg_us =>
                  parse_nonnegative(<<"client_final_smoothed_rtt_avg_us">>,
                                    FinalRttAverage),
              client_final_smoothed_rtt_max_us =>
                  parse_nonnegative(<<"client_final_smoothed_rtt_max_us">>,
                                    FinalRttMaximum),
              client_initial_cwnd_min =>
                  parse_nonnegative(<<"client_initial_cwnd_min">>,
                                    InitialWindowMinimum),
              client_initial_cwnd_avg =>
                  parse_nonnegative(<<"client_initial_cwnd_avg">>,
                                    InitialWindowAverage),
              client_initial_cwnd_max =>
                  parse_nonnegative(<<"client_initial_cwnd_max">>,
                                    InitialWindowMaximum),
              client_final_cwnd_min =>
                  parse_nonnegative(<<"client_final_cwnd_min">>,
                                    FinalWindowMinimum),
              client_final_cwnd_avg =>
                  parse_nonnegative(<<"client_final_cwnd_avg">>,
                                    FinalWindowAverage),
              client_final_cwnd_max =>
                  parse_nonnegative(<<"client_final_cwnd_max">>,
                                    FinalWindowMaximum),
              client_retransmissions_total =>
                  parse_nonnegative(<<"client_retransmissions_total">>,
                                    Retransmissions),
              client_retransmissions_max =>
                  parse_nonnegative(<<"client_retransmissions_max">>,
                                    MaximumRetransmissions),
              client_packets_received_total =>
                  parse_nonnegative(<<"client_packets_received_total">>,
                                    PacketsReceived),
              client_packets_sent_total =>
                  parse_nonnegative(<<"client_packets_sent_total">>,
                                    PacketsSent),
              client_batch_flushes_total =>
                  parse_nonnegative(<<"client_batch_flushes_total">>,
                                    BatchFlushes),
              client_packets_coalesced_total =>
                  parse_nonnegative(<<"client_packets_coalesced_total">>,
                                    PacketsCoalesced),
              client_connections_in_recovery =>
                  parse_nonnegative(<<"client_connections_in_recovery">>,
                                    ConnectionsInRecovery),
              client_connections_congested =>
                  parse_nonnegative(<<"client_connections_congested">>,
                                    ConnectionsCongested)};
        Fields -> erlang:error({invalid_performance_row, length(Fields), Line})
    end.

validate_run(ExitStatus, Rows, Configuration) ->
    ExpectedRows = maps:get(warmup_runs, Configuration)
                   + maps:get(measured_trials, Configuration),
    ExpectedSequence =
        [{1, true}]
        ++ [{Iteration, false}
            || Iteration <- lists:seq(1,
                                      maps:get(measured_trials,
                                               Configuration))],
    Sequence = [{maps:get(iteration, Row), maps:get(warmup, Row)} || Row <- Rows],
    ExitViolations = violation(ExitStatus =/= 0,
                               #{id => <<"workload-exit">>,
                                 observed => ExitStatus, expected => 0}),
    CountViolations = violation(length(Rows) =/= ExpectedRows,
                                #{id => <<"row-count">>,
                                  observed => length(Rows),
                                  expected => ExpectedRows}),
    SequenceViolations = violation(Sequence =/= ExpectedSequence,
                                   #{id => <<"row-sequence">>,
                                     observed => format_term(Sequence),
                                     expected => format_term(ExpectedSequence)}),
    RowViolations = lists:append([validate_row(Row, Configuration)
                                  || Row <- Rows]),
    Median = measured_median(Rows),
    Minimum = maps:get(minimum_requests_per_second, Configuration),
    ThresholdViolations = violation(
                            Median < Minimum,
                            #{id => <<"throughput-threshold">>,
                              observed => Median, expected_minimum => Minimum}),
    ExitViolations ++ CountViolations ++ SequenceViolations
    ++ RowViolations ++ ThresholdViolations.

validate_row(Row, Configuration) ->
    ExpectedTotal = maps:get(concurrency, Configuration)
                    * maps:get(requests_per_connection, Configuration),
    Label = #{iteration => maps:get(iteration, Row),
              warmup => maps:get(warmup, Row)},
    lists:append([
        violation(maps:get(mode, Row) =/= maps:get(mode, Configuration),
                  maps:merge(Label, #{id => <<"mode">>})),
        violation(maps:get(concurrency, Row)
                  =/= maps:get(concurrency, Configuration),
                  maps:merge(Label, #{id => <<"concurrency">>})),
        violation(maps:get(requests_per_connection, Row)
                  =/= maps:get(requests_per_connection, Configuration),
                  maps:merge(Label, #{id => <<"requests-per-connection">>})),
        violation(maps:get(total_requests, Row) =/= ExpectedTotal,
                  maps:merge(Label, #{id => <<"total-requests">>})),
        violation(maps:get(payload_bytes, Row)
                  =/= maps:get(payload_bytes, Configuration),
                  maps:merge(Label, #{id => <<"payload-bytes">>})),
        violation(maps:get(processes_after, Row)
                  > maps:get(processes_before, Row),
                  maps:merge(Label, #{id => <<"process-convergence">>,
                                      before => maps:get(processes_before, Row),
                                      processes_after =>
                                          maps:get(processes_after, Row)})),
        violation(maps:get(mailbox_messages_after, Row) =/= 0,
                  maps:merge(Label, #{id => <<"final-mailbox-zero">>,
                                      observed =>
                                          maps:get(mailbox_messages_after,
                                                   Row)})),
        violation(maps:get(ports_after, Row) > maps:get(ports_before, Row),
                  maps:merge(Label, #{id => <<"port-convergence">>,
                                      before => maps:get(ports_before, Row),
                                      ports_after => maps:get(ports_after, Row)})),
        violation(maps:get(network_ports_after, Row)
                  > maps:get(network_ports_before, Row),
                  maps:merge(
                    Label,
                    #{id => <<"network-port-convergence">>,
                      before => maps:get(network_ports_before, Row),
                      network_ports_after =>
                          maps:get(network_ports_after, Row)})),
        violation(maps:get(sockets_after, Row) > maps:get(sockets_before, Row),
                  maps:merge(Label, #{id => <<"socket-convergence">>,
                                      before => maps:get(sockets_before, Row),
                                      sockets_after =>
                                          maps:get(sockets_after, Row)})),
        diagnostic_order_violation(
          Row, Label, <<"initial-rtt-summary-order">>,
          client_initial_smoothed_rtt_min_us,
          client_initial_smoothed_rtt_avg_us,
          client_initial_smoothed_rtt_max_us),
        diagnostic_order_violation(
          Row, Label, <<"final-rtt-summary-order">>,
          client_final_smoothed_rtt_min_us,
          client_final_smoothed_rtt_avg_us,
          client_final_smoothed_rtt_max_us),
        diagnostic_order_violation(
          Row, Label, <<"initial-cwnd-summary-order">>,
          client_initial_cwnd_min, client_initial_cwnd_avg,
          client_initial_cwnd_max),
        diagnostic_order_violation(
          Row, Label, <<"final-cwnd-summary-order">>,
          client_final_cwnd_min, client_final_cwnd_avg,
          client_final_cwnd_max),
        violation(maps:get(client_retransmissions_max, Row)
                  > maps:get(client_retransmissions_total, Row),
                  maps:merge(Label,
                             #{id => <<"retransmission-summary-order">>})),
        violation(maps:get(client_connections_in_recovery, Row)
                  > maps:get(concurrency, Row),
                  maps:merge(Label,
                             #{id => <<"recovery-connection-bound">>})),
        violation(maps:get(client_connections_congested, Row)
                  > maps:get(concurrency, Row),
                  maps:merge(Label,
                             #{id => <<"congested-connection-bound">>}))
    ]).

diagnostic_order_violation(Row, Label, Id, MinimumKey, AverageKey, MaximumKey) ->
    Minimum = maps:get(MinimumKey, Row),
    Average = maps:get(AverageKey, Row),
    Maximum = maps:get(MaximumKey, Row),
    violation(not (Minimum =< Average andalso Average =< Maximum),
              maps:merge(Label,
                         #{id => Id, minimum => Minimum, average => Average,
                           maximum => Maximum})).

measured_median(Rows) ->
    Values = lists:sort([maps:get(requests_per_second, Row) || Row <- Rows,
                        maps:get(warmup, Row) =:= false]),
    case Values of
        [] -> 0;
        _ -> lists:nth((length(Values) div 2) + 1, Values)
    end.

violation(true, Evidence) -> [Evidence];
violation(false, _Evidence) -> [].

write_report(Mode, Report, Rows) ->
    JsonPath = filename:join(?OUTPUT, Mode ++ ".json"),
    CsvPath = filename:join(?OUTPUT, Mode ++ ".csv"),
    ok = filelib:ensure_dir(JsonPath),
    ok = file:write_file(JsonPath, [json:encode(Report), <<"\n">>]),
    CsvRows = [canonical_csv_row(Row) || Row <- Rows],
    ok = file:write_file(CsvPath, [?HEADER, <<"\n">>, CsvRows]).

canonical_csv_row(Row) ->
    Fields =
        [maps:get(mode, Row), integer_binary(maps:get(iteration, Row)),
         boolean_text(maps:get(warmup, Row)),
         integer_binary(maps:get(concurrency, Row)),
         integer_binary(maps:get(requests_per_connection, Row)),
         integer_binary(maps:get(total_requests, Row)),
         integer_binary(maps:get(payload_bytes, Row)),
         integer_binary(maps:get(elapsed_microseconds, Row)),
         integer_binary(maps:get(requests_per_second, Row)),
         integer_binary(maps:get(processes_before, Row)),
         integer_binary(maps:get(processes_after, Row)),
         integer_binary(maps:get(memory_before_bytes, Row)),
         integer_binary(maps:get(memory_after_bytes, Row)),
         integer_binary(maps:get(mailbox_messages_before, Row)),
         integer_binary(maps:get(mailbox_messages_after, Row)),
         integer_binary(maps:get(ports_before, Row)),
         integer_binary(maps:get(ports_after, Row)),
         integer_binary(maps:get(network_ports_before, Row)),
         integer_binary(maps:get(network_ports_after, Row)),
         integer_binary(maps:get(sockets_before, Row)),
         integer_binary(maps:get(sockets_after, Row)),
         integer_binary(maps:get(runtime_milliseconds, Row)),
         integer_binary(maps:get(reductions, Row)),
         integer_binary(maps:get(context_switches, Row)),
         integer_binary(maps:get(garbage_collections, Row)),
         integer_binary(maps:get(garbage_collected_words, Row)),
         integer_binary(maps:get(io_input_bytes, Row)),
         integer_binary(maps:get(io_output_bytes, Row)),
         integer_binary(maps:get(run_queue_before, Row)),
         integer_binary(maps:get(run_queue_after, Row)),
         integer_binary(maps:get(client_initial_smoothed_rtt_min_us, Row)),
         integer_binary(maps:get(client_initial_smoothed_rtt_avg_us, Row)),
         integer_binary(maps:get(client_initial_smoothed_rtt_max_us, Row)),
         integer_binary(maps:get(client_final_smoothed_rtt_min_us, Row)),
         integer_binary(maps:get(client_final_smoothed_rtt_avg_us, Row)),
         integer_binary(maps:get(client_final_smoothed_rtt_max_us, Row)),
         integer_binary(maps:get(client_initial_cwnd_min, Row)),
         integer_binary(maps:get(client_initial_cwnd_avg, Row)),
         integer_binary(maps:get(client_initial_cwnd_max, Row)),
         integer_binary(maps:get(client_final_cwnd_min, Row)),
         integer_binary(maps:get(client_final_cwnd_avg, Row)),
         integer_binary(maps:get(client_final_cwnd_max, Row)),
         integer_binary(maps:get(client_retransmissions_total, Row)),
         integer_binary(maps:get(client_retransmissions_max, Row)),
         integer_binary(maps:get(client_packets_received_total, Row)),
         integer_binary(maps:get(client_packets_sent_total, Row)),
         integer_binary(maps:get(client_batch_flushes_total, Row)),
         integer_binary(maps:get(client_packets_coalesced_total, Row)),
         integer_binary(maps:get(client_connections_in_recovery, Row)),
         integer_binary(maps:get(client_connections_congested, Row))],
    [lists:join($,, Fields), $\n].

source_digest(Profile) ->
    Evidence = maps:get(<<"performance_evidence">>, Profile),
    Roots = [binary_to_list(Path)
             || Path <- maps:get(<<"source_files">>, Evidence)],
    ProductionRoots = [binary_to_list(Path)
                       || Path <- maps:get(<<"production_source_roots">>,
                                           Evidence)],
    SourcePaths = lists:sort(lists:append([
        filelib:fold_files(Directory, ".*\\.(gleam|erl|hrl)$", true,
                           fun(Path, Paths) -> [Path | Paths] end, [])
        || Directory <- ProductionRoots
    ])),
    Paths = lists:usort(Roots ++ SourcePaths),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

write_emergency_report(
  Mode, _LogPath, _StartHostPath, _EndHostPath, Class, Reason, Stacktrace
) ->
    Path = filename:join(?OUTPUT, Mode ++ ".json"),
    Stem = "build/performance/current/" ++ Mode,
    ok = filelib:ensure_dir(Path),
    Report = #{schema => 4, status => <<"Failed">>,
               mode => list_to_binary(Mode),
               log => emergency_log_evidence(Stem ++ ".log"),
               host =>
                   #{shareable => false,
                     start => emergency_host_evidence(Stem ++ "-host-start.json"),
                     'end' => emergency_host_evidence(Stem ++ "-host-end.json")},
               runner_error => diagnostic_failure_details(Class, Reason, Stacktrace)},
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]).

emergency_log_evidence(Path) ->
    try bounded_log_evidence(read(Path), Path)
    catch _:_ -> #{shareable => true, status => <<"Unavailable">>, reason => <<"invalid_or_missing_log">>} end.

emergency_host_evidence(Path) ->
    try host_file_evidence(Path) of Host -> Host#{status => <<"Captured">>}
    catch _:_ -> #{status => <<"Unavailable">>, reason => <<"invalid_or_missing_snapshot">>} end.

self_test() ->
    Configuration = #{mode => <<"benchmark">>, warmup_runs => 1,
                      measured_trials => 1, concurrency => 2,
                      requests_per_connection => 5, payload_bytes => 256,
                      minimum_requests_per_second => 10},
    Header = <<?HEADER/binary, "\n">>,
    Warmup = fixture_row(true, 1, 2, 5, 256, 30, 0),
    Measured = fixture_row(false, 1, 2, 5, 256, 20, 0),
    Log = <<"compiler noise\n", Header/binary, Warmup/binary, "\n",
            Measured/binary, "\n">>,
    Rows = parse_rows(Log, <<"benchmark">>),
    ensure(runtime_matrix_json(Rows) =:= performance_csv_rows(maps:get(csv, performance_filter_csv(Log)), <<"benchmark">>),
           self_test_independent_csv_projection),
    [] = validate_run(0, Rows, Configuration),
    ensure(measured_median(Rows) =:= 20, self_test_median),
    BadMailbox = fixture_row(false, 1, 2, 5, 256, 20, 1),
    BadLog = <<"noise\n", Header/binary, Warmup/binary, "\n",
               BadMailbox/binary, "\n">>,
    BadRows = parse_rows(BadLog, <<"benchmark">>),
    BadViolations = validate_run(0, BadRows, Configuration),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"final-mailbox-zero">>
    end, BadViolations), self_test_mailbox_violation),
    [WarmupRow | _] = Rows,
    BadResourceRows =
        [WarmupRow#{ports_after => 4, network_ports_after => 1,
                    sockets_after => 2} | tl(Rows)],
    ResourceViolations = validate_run(0, BadResourceRows, Configuration),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"port-convergence">>
    end, ResourceViolations), self_test_port_convergence_violation),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"socket-convergence">>
    end, ResourceViolations), self_test_socket_convergence_violation),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"network-port-convergence">>
    end, ResourceViolations), self_test_network_port_convergence_violation),
    ExitViolations = validate_run(9, Rows, Configuration),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"workload-exit">>
    end, ExitViolations), self_test_exit_violation),
    BadDiagnosticRows =
        [WarmupRow#{client_initial_smoothed_rtt_avg_us => 40} | tl(Rows)],
    DiagnosticViolations = validate_run(0, BadDiagnosticRows, Configuration),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"initial-rtt-summary-order">>
    end, DiagnosticViolations), self_test_diagnostic_order_violation),
    HostStart = fixture_host_snapshot(<<"start">>, 1000, 1000, 400, 10000),
    HostEnd = fixture_host_snapshot(<<"end">>, 2000, 1200, 500, 10250),
    HostEvidence =
        #{shareable => false,
          start => #{snapshot => HostStart},
          'end' => #{snapshot => HostEnd},
          deltas => host_deltas(HostStart, HostEnd)},
    [] = validate_host_evidence(HostEvidence),
    HostDeltas = maps:get(deltas, HostEvidence),
    ensure(maps:get(cpu_total_ticks, HostDeltas) =:= 200,
           self_test_host_total_ticks),
    ensure(maps:get(cpu_busy_ticks, HostDeltas) =:= 100,
           self_test_host_busy_ticks),
    ensure(maps:get(cpu_busy_basis_points, HostDeltas) =:= 5000,
           self_test_host_cpu_utilization),
    ensure(maps:get(cpu_pressure_some_microseconds, HostDeltas) =:= 250,
           self_test_host_pressure_delta),
    StartProbes = maps:get(<<"probes">>, HostStart),
    InvalidStart = HostStart#{<<"probes">> => maps:put(
        <<"load_average">>,
        #{<<"status">> => <<"Invalid">>, <<"reason">> => <<"fixture">>},
        StartProbes)},
    InvalidEvidence = HostEvidence#{start => #{snapshot => InvalidStart}},
    InvalidViolations = validate_host_evidence(InvalidEvidence),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"host-probe-invalid">>
    end, InvalidViolations), self_test_invalid_host_probe),
    RegressedEnd = fixture_host_snapshot(<<"end">>, 2000, 900, 300, 9000),
    RegressedEvidence = HostEvidence#{'end' => #{snapshot => RegressedEnd}},
    RegressedViolations = validate_host_evidence(RegressedEvidence),
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= <<"host-counter-regression">>
    end, RegressedViolations), self_test_host_counter_regression),
    LogEvidence = bounded_log_evidence(<<"fixture log">>, "fixture.log"),
    PrivateLog = <<"private-endpoint-credential-body">>,
    PrivateEvidence = bounded_log_evidence(PrivateLog, "fixture.log"),
    ensure(binary:match(base64:decode(maps:get(tail_base64, PrivateEvidence)), PrivateLog) =:= nomatch,
           self_test_log_private_bytes),
    ensure(maps:get(sha256, PrivateEvidence) =/= hex(crypto:hash(sha256, PrivateLog)),
           self_test_log_private_digest),
    ensure(maps:get(shareable, LogEvidence) =:= true,
           self_test_log_numeric_summary_shareable),
    SafeRow = fixture_row(true, 1, 4, 100, 1024, 600, 0),
    Mixed = <<PrivateLog/binary, "\n", ?HEADER/binary, "\n", SafeRow/binary, "\n", PrivateLog/binary>>,
    #{csv := Sanitized} = performance_filter_csv(Mixed),
    ensure(Sanitized =:= <<?HEADER/binary, "\n", SafeRow/binary, "\n">>,
           self_test_numeric_row_preserved),
    ensure(byte_size(maps:get(sha256, LogEvidence)) =:= 64,
           self_test_log_digest),
    MissingLog = emergency_log_evidence(
      "/definitely-not-a-real-http3-performance-log"),
    ensure(maps:get(status, MissingLog) =:= <<"Unavailable">>,
           self_test_missing_emergency_log),
    MissingHost = emergency_host_evidence(
      "/definitely-not-a-real-http3-performance-host-snapshot"),
    ensure(maps:get(status, MissingHost) =:= <<"Unavailable">>,
           self_test_missing_emergency_host),
    io:put_chars(
      "performance report self-test: parsing, host evidence, and failure gates ok\n"),
    ok.

fixture_host_snapshot(Label, Time, TotalTicks, BusyTicks, PressureTotal) ->
    Unavailable = #{<<"status">> => <<"Unavailable">>,
                    <<"reason">> => <<"fixture">>},
    BaseProbes = maps:from_list(
      [{Name, Unavailable} || Name <- expected_host_probes()]),
    Probes = maps:merge(
      BaseProbes,
      #{<<"load_average">> =>
            #{<<"status">> => <<"Available">>,
              <<"load_1m_milli">> => 1000},
        <<"cpu_pressure">> =>
            #{<<"status">> => <<"Available">>,
              <<"some">> => #{<<"total_microseconds">> => PressureTotal},
              <<"full">> => #{<<"total_microseconds">> => 0}},
        <<"cpu_accounting">> =>
            #{<<"status">> => <<"Available">>,
              <<"total_ticks">> => TotalTicks, <<"busy_ticks">> => BusyTicks,
              <<"context_switches">> => TotalTicks * 2,
              <<"processes_created">> => TotalTicks div 10},
        <<"memory">> =>
            #{<<"status">> => <<"Available">>,
              <<"available_bytes">> => 1000000 - TotalTicks},
        <<"cgroup_cpu_accounting">> =>
            #{<<"status">> => <<"Available">>,
              <<"counters">> =>
                  #{<<"usage_usec">> => TotalTicks * 10,
                    <<"nr_throttled">> => TotalTicks div 100,
                    <<"throttled_usec">> => TotalTicks}},
        <<"cpu_frequency">> =>
            #{<<"status">> => <<"Available">>, <<"average">> => 4000000},
        <<"thermal">> =>
            #{<<"status">> => <<"Available">>, <<"maximum">> => 60000}}),
    #{<<"schema">> => 1, <<"status">> => <<"Captured">>,
      <<"label">> => Label, <<"shareable">> => false,
      <<"captured_system_time_milliseconds">> => Time,
      <<"runtime">> => #{<<"otp_release">> => <<"fixture">>},
      <<"probes">> => Probes}.

fixture_row(Warmup, Iteration, Concurrency, Requests, Payload, Rate, Mailbox) ->
    Total = Concurrency * Requests,
    iolist_to_binary(
      io_lib:format("benchmark,~B,~s,~B,~B,~B,~B,1000,~B,50,49,100000,100100,0,~B",
                    [Iteration, boolean_text(Warmup), Concurrency, Requests,
                     Total, Payload, Rate, Mailbox])
      ++ <<",3,2,0,0,1,0,10,1000,20,30,4000,50,60,0,1,"
           "10,20,30,5,10,15,1000,2000,3000,1500,2500,3500,"
           "2,1,100,120,10,5,0,0">>).

parse_boolean(<<"True">>) -> true;
parse_boolean(<<"False">>) -> false;
parse_boolean(Value) -> erlang:error({invalid_boolean, Value}).

boolean_text(true) -> <<"True">>;
boolean_text(false) -> <<"False">>.

integer_binary(Value) -> integer_to_binary(Value).

parse_positive(Name, Value) ->
    Parsed = parse_nonnegative(Name, Value),
    ensure(Parsed > 0, {not_positive, Name, Value}),
    Parsed.

parse_nonnegative(Name, Value) ->
    try binary_to_integer(Value) of
        Parsed when Parsed >= 0 -> Parsed;
        Parsed -> erlang:error({negative_integer, Name, Parsed})
    catch
        error:badarg -> erlang:error({invalid_integer, Name, Value})
    end.

format_term(Term) ->
    Bytes = unicode:characters_to_binary(io_lib:format("~0P", [Term, 20])),
    case byte_size(Bytes) =< 8192 of
        true -> Bytes;
        false -> <<(binary:part(Bytes, 0, 8192))/binary, "...[truncated]">>
    end.

read(Path) ->
    {ok, File} = file:open(Path, [read, binary, raw]),
    Result = file:read(File, 1048577), ok = file:close(File),
    case Result of {ok, Bytes} when byte_size(Bytes) =< 1048576 -> Bytes;
        eof -> <<>>; _ -> erlang:error(performance_input_limit) end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
