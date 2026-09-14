#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(PROFILE_PATH, "standards/performance-profile.json").
-define(OUTPUT_PATH, "build/performance/report.json").
-define(HOT_PATH_REPORT, "build/performance/hot-path-profile.json").
-define(IDLE_WAKEUP_REPORT, "build/performance/current/idle-wakeup.json").
-define(IDLE_WAKEUP_RAW, "build/performance/current/idle-wakeup.raw.json").
-define(IDLE_WAKEUP_LOG, "build/performance/current/idle-wakeup.log").
-define(MAXIMUM_REPORT_BYTES, 33554432).

main(["--self-test"]) ->
    guarded_self_test();
main([]) ->
    guarded_run();
main(_) ->
    erlang:error({usage, "[--self-test]"}).

guarded_self_test() ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "performance audit self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

guarded_run() ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "performance audit failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run() ->
    ProfileBytes = read(?PROFILE_PATH),
    Profile = json:decode(ProfileBytes),
    Evidence = maps:get(<<"performance_evidence">>, Profile),
    validate_profile(Profile, Evidence),
    ProfileDigest = hex(crypto:hash(sha256, ProfileBytes)),
    SourceDigest = source_digest(Evidence),
    Modes = maps:get(<<"fixed_http3_modes">>, Evidence),
    FixedReports = [audit_fixed_report(Mode, Profile, Evidence,
                                       ProfileDigest, SourceDigest)
                    || Mode <- Modes],
    HotPath = audit_hot_path(ProfileDigest),
    IdleWakeup = audit_idle_wakeup(Profile, Evidence,
                                   ProfileDigest, SourceDigest),
    FixedViolations =
        lists:append([maps:get(violations, Report) || Report <- FixedReports])
        ++ maps:get(violations, HotPath),
    IdleViolations = maps:get(violations, IdleWakeup),
    CurrentViolations = FixedViolations ++ IdleViolations,
    FixedReady = FixedViolations =:= [],
    IdleReady = IdleViolations =:= [],
    Satisfied = maps:get(<<"fixed_http3_satisfies">>, Evidence),
    ObservedRoles = case FixedReady of
        true -> maps:get(<<"roles">>, Satisfied);
        false -> []
    end,
    FixedResources = case FixedReady of
        true -> maps:get(<<"resource_assertions">>, Satisfied);
        false -> []
    end,
    IdleResources = case IdleReady of
        true -> maps:get(<<"satisfies">>,
                         maps:get(<<"idle_wakeup">>, Evidence));
        false -> []
    end,
    ObservedResources = lists:usort(FixedResources ++ IdleResources),
    RequiredRoles = maps:get(<<"required_protocol_roles">>, Profile),
    RequiredResources = maps:get(<<"required_resource_assertions">>, Profile),
    MissingRoles = missing(RequiredRoles, ObservedRoles),
    MissingResources = missing(RequiredResources, ObservedResources),
    Status = case CurrentViolations =:= []
                  andalso MissingRoles =:= []
                  andalso MissingResources =:= [] of
        true -> <<"Ready">>;
        false -> <<"Blocked">>
    end,
    LegacyCsv = filelib:wildcard("packages/http3/benchmarks/results/*.csv"),
    Report =
        #{schema => 3, status => Status,
          baseline_date => maps:get(<<"baseline_date">>, Profile),
          profile_sha256 => ProfileDigest, source_sha256 => SourceDigest,
          fixed_http3_reports => FixedReports, hot_path_profile => HotPath,
          idle_wakeup => IdleWakeup,
          observed_protocol_roles => ObservedRoles,
          missing_protocol_roles => MissingRoles,
          observed_resource_assertions => ObservedResources,
          missing_resource_assertions => MissingResources,
          current_evidence_violations => CurrentViolations,
          legacy_csv_files => length(LegacyCsv),
          legacy_csv_acceptance => false},
    write_report(Report),
    case Status of
        <<"Ready">> ->
            io:format("performance audit: ~B fixed reports and all roles ready~n",
                      [length(FixedReports)]),
            ok;
        <<"Blocked">> ->
            erlang:error(
              {performance_matrix_incomplete,
               #{current_evidence => length(CurrentViolations),
                 roles => MissingRoles, resources => MissingResources}})
    end.

validate_profile(Profile, Evidence) ->
    ensure(maps:get(<<"report_schema">>, Evidence) =:= 3,
           unsupported_performance_report_schema),
    ensure(maps:get(<<"host_snapshot_schema">>, Evidence) =:= 1,
           unsupported_host_snapshot_schema),
    ensure(maps:get(<<"log_tail_bytes">>, Evidence) =:= 16384,
           unexpected_log_tail_limit),
    Modes = maps:get(<<"fixed_http3_modes">>, Evidence),
    ensure(Modes =:= [<<"benchmark">>, <<"load">>, <<"soak">>],
           invalid_fixed_modes),
    ensure(unique(Modes), duplicate_fixed_modes),
    WorkloadModes = [maps:get(<<"mode">>, Workload)
                     || Workload <- maps:get(<<"fixed_http3_workloads">>,
                                             Profile)],
    ensure(lists:sort(Modes) =:= lists:sort(WorkloadModes),
           fixed_workload_mode_drift),
    Satisfied = maps:get(<<"fixed_http3_satisfies">>, Evidence),
    SatisfiedRoles = maps:get(<<"roles">>, Satisfied),
    SatisfiedResources = maps:get(<<"resource_assertions">>, Satisfied),
    ensure(unique(SatisfiedRoles), duplicate_satisfied_roles),
    ensure(unique(SatisfiedResources), duplicate_satisfied_resources),
    ensure(missing(SatisfiedRoles,
                   maps:get(<<"required_protocol_roles">>, Profile)) =:= [],
           unknown_satisfied_role),
    ensure(missing(SatisfiedResources,
                   maps:get(<<"required_resource_assertions">>, Profile))
           =:= [], unknown_satisfied_resource),
    validate_idle_profile(Profile, Evidence),
    SourceFiles = maps:get(<<"source_files">>, Evidence),
    SourceRoots = maps:get(<<"production_source_roots">>, Evidence),
    ensure(SourceFiles =/= [] andalso unique(SourceFiles),
           invalid_performance_source_files),
    ensure(SourceRoots =/= [] andalso unique(SourceRoots),
           invalid_performance_source_roots),
    ok.

validate_idle_profile(Profile, Evidence) ->
    Idle = maps:get(<<"idle_wakeup">>, Evidence),
    ensure(is_map(Idle), invalid_idle_wakeup_profile),
    ensure(maps:get(<<"fixture_schema">>, Idle) =:= 2,
           unsupported_idle_wakeup_fixture_schema),
    ensure(maps:get(<<"artifact">>, Idle) =:= <<?IDLE_WAKEUP_REPORT>>,
           unexpected_idle_wakeup_artifact),
    ensure(maps:get(<<"raw_artifact">>, Idle) =:= <<?IDLE_WAKEUP_RAW>>,
           unexpected_idle_wakeup_raw_artifact),
    ensure(maps:get(<<"log_artifact">>, Idle) =:= <<?IDLE_WAKEUP_LOG>>,
           unexpected_idle_wakeup_log_artifact),
    ensure(maps:get(<<"minimum_observation_milliseconds">>, Idle) =:= 2500,
           weakened_idle_observation),
    ensure(maps:get(<<"expected_actor_count">>, Idle) =:= 8,
           idle_actor_count_drift),
    ensure(maps:get(<<"quiescence_required_stable_samples">>, Idle) =:= 5,
           weakened_idle_quiescence_samples),
    ensure(maps:get(<<"quiescence_poll_milliseconds">>, Idle) =:= 100,
           idle_quiescence_poll_drift),
    ensure(maps:get(<<"quiescence_maximum_attempts">>, Idle) =:= 80,
           weakened_idle_quiescence_attempts),
    ensure(maps:get(<<"maximum_quiescence_milliseconds">>, Idle) =:= 8000,
           weakened_idle_quiescence_bound),
    ensure(maps:get(<<"maximum_quiescence_milliseconds">>, Idle)
           =:= maps:get(<<"quiescence_poll_milliseconds">>, Idle)
               * maps:get(<<"quiescence_maximum_attempts">>, Idle),
           inconsistent_idle_quiescence_bound),
    ensure(maps:get(<<"trace_primitive">>, Idle)
           =:= <<"gleam_erlang_ffi:select/1,2">>,
           idle_trace_primitive_drift),
    Roles = maps:get(<<"required_roles">>, Idle),
    ensure(Roles =:= idle_expected_roles(), idle_role_topology_drift),
    ensure(unique(Roles), duplicate_idle_roles),
    LivenessRoles = maps:get(<<"required_liveness_roles">>, Idle),
    ensure(LivenessRoles =:= idle_liveness_roles(),
           idle_liveness_role_drift),
    ensure(unique(LivenessRoles), duplicate_idle_liveness_roles),
    ensure(missing(LivenessRoles, Roles) =:= [],
           unknown_idle_liveness_role),
    Satisfies = maps:get(<<"satisfies">>, Idle),
    ensure(Satisfies =:= [<<"idle-periodic-wakeup-zero">>],
           idle_satisfaction_drift),
    ensure(unique(Satisfies), duplicate_idle_satisfaction),
    ensure(missing(Satisfies,
                   maps:get(<<"required_resource_assertions">>, Profile))
           =:= [], unknown_idle_satisfaction),
    ok.

audit_fixed_report(Mode, Profile, Evidence, ProfileDigest, SourceDigest) ->
    Path = filename:join("build/performance/current",
                         binary_to_list(Mode) ++ ".json"),
    case read_json(Path) of
        {error, Reason} ->
            #{mode => Mode, path => list_to_binary(Path), status => <<"Missing">>,
              violations => [violation(Mode, <<"report-unavailable">>,
                                       #{reason => atom_to_binary(Reason)})]};
        {ok, Report} ->
            Workload = workload(Mode, Profile),
            Violations = validate_fixed_report(
                           Mode, Report, Workload, Evidence,
                           ProfileDigest, SourceDigest),
            Status = case Violations of [] -> <<"Ready">>; _ -> <<"Failed">> end,
            #{mode => Mode, path => list_to_binary(Path), status => Status,
              report_sha256 => file_digest(Path), violations => Violations}
    end.

validate_fixed_report(
  Mode, Report, Workload, Evidence, ProfileDigest, SourceDigest
) when is_map(Report) ->
    Rows = maps:get(<<"rows">>, Report, []),
    ExpectedRows = maps:get(<<"warmup_runs">>, Workload)
                   + maps:get(<<"measured_trials">>, Workload),
    Configuration = expected_configuration(Workload),
    lists:append([
        problem(maps:get(<<"schema">>, Report, undefined)
                =/= maps:get(<<"report_schema">>, Evidence),
                Mode, <<"report-schema">>, #{}),
        problem(maps:get(<<"status">>, Report, undefined) =/= <<"Ready">>,
                Mode, <<"report-status">>,
                #{observed => maps:get(<<"status">>, Report, undefined)}),
        problem(maps:get(<<"mode">>, Report, undefined) =/= Mode,
                Mode, <<"report-mode">>, #{}),
        problem(maps:get(<<"profile_sha256">>, Report, undefined)
                =/= ProfileDigest, Mode, <<"stale-profile">>, #{}),
        problem(maps:get(<<"source_sha256">>, Report, undefined)
                =/= SourceDigest, Mode, <<"stale-source">>, #{}),
        problem(maps:get(<<"configuration">>, Report, undefined)
                =/= Configuration, Mode, <<"configuration">>, #{}),
        problem(not is_list(Rows) orelse length(Rows) =/= ExpectedRows,
                Mode, <<"row-count">>,
                #{observed => safe_length(Rows), expected => ExpectedRows}),
        validate_rows(Mode, Rows, ExpectedRows),
        validate_log(Mode, maps:get(<<"log">>, Report, undefined), Evidence),
        validate_host(Mode, maps:get(<<"host">>, Report, undefined), Evidence)
    ]);
validate_fixed_report(Mode, _Report, _Workload, _Evidence,
                      _ProfileDigest, _SourceDigest) ->
    [violation(Mode, <<"report-shape">>, #{})].

validate_rows(Mode, Rows, ExpectedRows) when is_list(Rows) ->
    Selected = lists:sublist(Rows, ExpectedRows + 1),
    lists:append([validate_row(Mode, Row) || Row <- Selected]);
validate_rows(Mode, _Rows, _ExpectedRows) ->
    [violation(Mode, <<"rows-shape">>, #{})].

validate_row(Mode, Row) when is_map(Row) ->
    RequiredIntegers =
        [<<"ports_before">>, <<"ports_after">>,
         <<"network_ports_before">>, <<"network_ports_after">>,
         <<"sockets_before">>, <<"sockets_after">>,
         <<"client_initial_smoothed_rtt_min_us">>,
         <<"client_initial_smoothed_rtt_avg_us">>,
         <<"client_initial_smoothed_rtt_max_us">>,
         <<"client_final_smoothed_rtt_min_us">>,
         <<"client_final_smoothed_rtt_avg_us">>,
         <<"client_final_smoothed_rtt_max_us">>,
         <<"client_initial_cwnd_min">>, <<"client_initial_cwnd_avg">>,
         <<"client_initial_cwnd_max">>, <<"client_final_cwnd_min">>,
         <<"client_final_cwnd_avg">>, <<"client_final_cwnd_max">>,
         <<"client_retransmissions_total">>,
         <<"client_retransmissions_max">>,
         <<"client_packets_received_total">>,
         <<"client_packets_sent_total">>,
         <<"client_batch_flushes_total">>,
         <<"client_packets_coalesced_total">>,
         <<"client_connections_in_recovery">>,
         <<"client_connections_congested">>],
    MissingIntegers = [Key || Key <- RequiredIntegers,
                              not nonnegative_map_integer(Row, Key)],
    lists:append([
        problem(MissingIntegers =/= [], Mode, <<"transport-diagnostics">>,
                #{missing_or_invalid => MissingIntegers}),
        convergence_problem(Mode, Row, <<"port-convergence">>,
                            <<"ports_before">>, <<"ports_after">>),
        convergence_problem(Mode, Row, <<"network-port-convergence">>,
                            <<"network_ports_before">>,
                            <<"network_ports_after">>),
        convergence_problem(Mode, Row, <<"socket-convergence">>,
                            <<"sockets_before">>, <<"sockets_after">>),
        ordered_metric_problem(
          Mode, Row, <<"initial-rtt-order">>,
          <<"client_initial_smoothed_rtt_min_us">>,
          <<"client_initial_smoothed_rtt_avg_us">>,
          <<"client_initial_smoothed_rtt_max_us">>),
        ordered_metric_problem(
          Mode, Row, <<"final-rtt-order">>,
          <<"client_final_smoothed_rtt_min_us">>,
          <<"client_final_smoothed_rtt_avg_us">>,
          <<"client_final_smoothed_rtt_max_us">>),
        ordered_metric_problem(
          Mode, Row, <<"initial-cwnd-order">>,
          <<"client_initial_cwnd_min">>, <<"client_initial_cwnd_avg">>,
          <<"client_initial_cwnd_max">>),
        ordered_metric_problem(
          Mode, Row, <<"final-cwnd-order">>,
          <<"client_final_cwnd_min">>, <<"client_final_cwnd_avg">>,
          <<"client_final_cwnd_max">>)
    ]);
validate_row(Mode, _Row) ->
    [violation(Mode, <<"row-shape">>, #{})].

convergence_problem(Mode, Row, Id, BeforeKey, AfterKey) ->
    case {maps:get(BeforeKey, Row, undefined),
          maps:get(AfterKey, Row, undefined)} of
        {Before, After}
                when is_integer(Before), is_integer(After), After =< Before ->
            [];
        _ -> [violation(Mode, Id, #{})]
    end.

ordered_metric_problem(Mode, Row, Id, MinimumKey, AverageKey, MaximumKey) ->
    case {maps:get(MinimumKey, Row, undefined),
          maps:get(AverageKey, Row, undefined),
          maps:get(MaximumKey, Row, undefined)} of
        {Minimum, Average, Maximum}
                when is_integer(Minimum), is_integer(Average),
                     is_integer(Maximum), Minimum =< Average,
                     Average =< Maximum -> [];
        _ -> [violation(Mode, Id, #{})]
    end.

validate_log(Mode, Log, Evidence) when is_map(Log) ->
    TailLimit = maps:get(<<"log_tail_bytes">>, Evidence),
    TailBytes = maps:get(<<"tail_bytes">>, Log, -1),
    lists:append([
        problem(maps:get(<<"shareable">>, Log, undefined) =/= false,
                Mode, <<"log-shareability">>, #{}),
        problem(not valid_digest(maps:get(<<"sha256">>, Log, undefined)),
                Mode, <<"log-digest">>, #{}),
        problem(not is_integer(TailBytes) orelse TailBytes < 0
                orelse TailBytes > TailLimit,
                Mode, <<"log-tail-bound">>, #{observed => TailBytes})
    ]);
validate_log(Mode, _Log, _Evidence) ->
    [violation(Mode, <<"log-shape">>, #{})].

validate_host(Mode, Host, Evidence) when is_map(Host) ->
    Start = nested(Host, [<<"start">>, <<"snapshot">>]),
    End = nested(Host, [<<"end">>, <<"snapshot">>]),
    Deltas = maps:get(<<"deltas">>, Host, #{}),
    Busy = maps:get(<<"cpu_busy_basis_points">>, Deltas, undefined),
    lists:append([
        problem(maps:get(<<"shareable">>, Host, undefined) =/= false,
                Mode, <<"host-shareability">>, #{}),
        validate_host_snapshot(Mode, Start, <<"start">>, Evidence),
        validate_host_snapshot(Mode, End, <<"end">>, Evidence),
        problem(not is_map(Deltas), Mode, <<"host-deltas-shape">>, #{}),
        problem(not (Busy =:= null orelse
                     (is_integer(Busy) andalso Busy >= 0 andalso Busy =< 10000)),
                Mode, <<"host-cpu-busy-bound">>, #{observed => Busy})
    ]);
validate_host(Mode, _Host, _Evidence) ->
    [violation(Mode, <<"host-shape">>, #{})].

validate_host_snapshot(Mode, Snapshot, Label, Evidence) when is_map(Snapshot) ->
    Probes = maps:get(<<"probes">>, Snapshot, #{}),
    Invalid = invalid_probe_names(Probes),
    lists:append([
        problem(maps:get(<<"schema">>, Snapshot, undefined)
                =/= maps:get(<<"host_snapshot_schema">>, Evidence),
                Mode, <<"host-snapshot-schema">>, #{label => Label}),
        problem(maps:get(<<"status">>, Snapshot, undefined)
                =/= <<"Captured">>,
                Mode, <<"host-snapshot-status">>, #{label => Label}),
        problem(maps:get(<<"label">>, Snapshot, undefined) =/= Label,
                Mode, <<"host-snapshot-label">>, #{label => Label}),
        problem(maps:get(<<"shareable">>, Snapshot, undefined) =/= false,
                Mode, <<"host-snapshot-shareability">>, #{label => Label}),
        problem(Invalid =/= [], Mode, <<"host-probe-invalid">>,
                #{label => Label, probes => Invalid})
    ]);
validate_host_snapshot(Mode, _Snapshot, Label, _Evidence) ->
    [violation(Mode, <<"host-snapshot-shape">>, #{label => Label})].

invalid_probe_names(Probes) when is_map(Probes) ->
    [Name || {Name, Probe} <- maps:to_list(Probes),
             not valid_probe(Probe)];
invalid_probe_names(_Probes) -> [<<"probes">>].

valid_probe(Probe) when is_map(Probe) ->
    lists:member(maps:get(<<"status">>, Probe, undefined),
                 [<<"Available">>, <<"Partial">>, <<"Unavailable">>]);
valid_probe(_Probe) -> false.

audit_hot_path(ProfileDigest) ->
    case read_json(?HOT_PATH_REPORT) of
        {error, Reason} ->
            #{path => <<?HOT_PATH_REPORT>>, status => <<"Missing">>,
              violations =>
                  [violation(<<"hot-path">>, <<"report-unavailable">>,
                             #{reason => atom_to_binary(Reason)})]};
        {ok, Report} ->
            Violations = lists:append([
                problem(maps:get(<<"schema">>, Report, undefined) =/= 1,
                        <<"hot-path">>, <<"report-schema">>, #{}),
                problem(maps:get(<<"status">>, Report, undefined)
                        =/= <<"Ready">>,
                        <<"hot-path">>, <<"report-status">>, #{}),
                problem(maps:get(<<"profile_sha256">>, Report, undefined)
                        =/= ProfileDigest,
                        <<"hot-path">>, <<"stale-profile">>, #{})
            ]),
            Status = case Violations of [] -> <<"Ready">>;
                        _ -> <<"Failed">> end,
            #{path => <<?HOT_PATH_REPORT>>, status => Status,
              report_sha256 => file_digest(?HOT_PATH_REPORT),
              violations => Violations}
    end.

audit_idle_wakeup(Profile, Evidence, ProfileDigest, SourceDigest) ->
    case read_json(?IDLE_WAKEUP_REPORT) of
        {error, Reason} ->
            #{path => <<?IDLE_WAKEUP_REPORT>>, status => <<"Missing">>,
              violations =>
                  [violation(<<"idle-wakeup">>, <<"report-unavailable">>,
                             #{reason => atom_to_binary(Reason)})]};
        {ok, Report} ->
            Violations = validate_idle_report(
                           Report, Profile, Evidence,
                           ProfileDigest, SourceDigest),
            Status = case Violations of [] -> <<"Ready">>;
                        _ -> <<"Failed">> end,
            #{path => <<?IDLE_WAKEUP_REPORT>>, status => Status,
              report_sha256 => file_digest(?IDLE_WAKEUP_REPORT),
              violations => Violations}
    end.

validate_idle_report(
  Report, Profile, Evidence, ProfileDigest, SourceDigest
) when is_map(Report) ->
    Idle = maps:get(<<"idle_wakeup">>, Evidence),
    RawMetadata = maps:get(<<"raw_fixture">>, Report, invalid),
    LogMetadata = maps:get(<<"log">>, Report, invalid),
    RawEvidence = maps:get(<<"evidence">>, Report, invalid),
    lists:append([
        idle_equal_problem(
          Report, <<"schema">>, maps:get(<<"report_schema">>, Evidence),
          <<"report-schema">>),
        idle_equal_problem(Report, <<"status">>, <<"Ready">>,
                           <<"report-status">>),
        idle_equal_problem(Report, <<"kind">>, <<"idle-wakeup">>,
                           <<"report-kind">>),
        idle_equal_problem(Report, <<"shareable">>, true,
                           <<"report-shareability">>),
        idle_equal_problem(Report, <<"redacted">>, true,
                           <<"report-redaction">>),
        idle_equal_problem(
          Report, <<"baseline_date">>, maps:get(<<"baseline_date">>, Profile),
          <<"baseline-date">>),
        idle_equal_problem(Report, <<"profile_sha256">>, ProfileDigest,
                           <<"stale-profile">>),
        idle_equal_problem(Report, <<"source_sha256">>, SourceDigest,
                           <<"stale-source">>),
        idle_equal_problem(Report, <<"exit_status">>, 0,
                           <<"workload-exit-status">>),
        idle_equal_problem(Report, <<"configuration">>, Idle,
                           <<"configuration">>),
        idle_equal_problem(Report, <<"satisfies">>,
                           maps:get(<<"satisfies">>, Idle),
                           <<"satisfaction">>),
        idle_equal_problem(Report, <<"violations">>, [],
                           <<"reported-violations">>),
        idle_runtime_problem(Report, <<"otp_release">>,
                             <<"otp-release">>),
        idle_runtime_problem(Report, <<"system_architecture">>,
                             <<"system-architecture">>),
        validate_idle_evidence(RawEvidence, Idle),
        validate_idle_raw_artifact(RawMetadata, RawEvidence),
        validate_idle_log_artifact(LogMetadata)
    ]);
validate_idle_report(_Report, _Profile, _Evidence,
                     _ProfileDigest, _SourceDigest) ->
    [violation(<<"idle-wakeup">>, <<"report-shape">>, #{})].

validate_idle_raw_artifact(Metadata, EmbeddedEvidence) ->
    case read_json_bytes(?IDLE_WAKEUP_RAW) of
        {error, Reason} ->
            [violation(<<"idle-wakeup">>, <<"raw-artifact-unavailable">>,
                       #{reason => atom_to_binary(Reason)})];
        {ok, DiskEvidence, Bytes} ->
            Digest = hex(crypto:hash(sha256, Bytes)),
            Size = byte_size(Bytes),
            MetadataProblems = case is_map(Metadata) of
                true -> lists:append([
                    idle_equal_problem(Metadata, <<"path">>,
                                       <<?IDLE_WAKEUP_RAW>>,
                                       <<"raw-artifact-path">>),
                    idle_equal_problem(Metadata, <<"bytes">>, Size,
                                       <<"raw-artifact-size">>),
                    idle_equal_problem(Metadata, <<"sha256">>, Digest,
                                       <<"raw-artifact-digest">>),
                    idle_equal_problem(Metadata, <<"content_included">>, true,
                                       <<"raw-content-inclusion">>),
                    idle_equal_problem(Metadata, <<"shareable">>, true,
                                       <<"raw-shareability">>)
                ]);
                false ->
                    [violation(<<"idle-wakeup">>,
                               <<"raw-metadata-shape">>, #{})]
            end,
            MetadataProblems
            ++ idle_problem(DiskEvidence =/= EmbeddedEvidence,
                            <<"raw-embedded-mismatch">>, #{})
    end.

validate_idle_log_artifact(Metadata) when is_map(Metadata) ->
    case read_bytes(?IDLE_WAKEUP_LOG) of
        {error, Reason} ->
            [violation(<<"idle-wakeup">>, <<"log-artifact-unavailable">>,
                       #{reason => atom_to_binary(Reason)})];
        {ok, Bytes} ->
            Digest = hex(crypto:hash(sha256, Bytes)),
            lists:append([
                idle_equal_problem(Metadata, <<"path">>,
                                   <<?IDLE_WAKEUP_LOG>>,
                                   <<"log-artifact-path">>),
                idle_equal_problem(Metadata, <<"bytes">>, byte_size(Bytes),
                                   <<"log-artifact-size">>),
                idle_equal_problem(Metadata, <<"sha256">>, Digest,
                                   <<"log-artifact-digest">>),
                idle_equal_problem(Metadata, <<"content_included">>, false,
                                   <<"log-content-inclusion">>),
                idle_equal_problem(Metadata, <<"shareable">>, false,
                                   <<"log-shareability">>),
                idle_problem(maps:is_key(<<"tail_base64">>, Metadata),
                             <<"log-tail-embedded">>, #{}),
                idle_problem(maps:is_key(<<"content">>, Metadata),
                             <<"log-content-embedded">>, #{})
            ])
    end;
validate_idle_log_artifact(_Metadata) ->
    [violation(<<"idle-wakeup">>, <<"log-metadata-shape">>, #{})].

validate_idle_evidence(Raw, Idle) when is_map(Raw) ->
    Roles = maps:get(<<"roles">>, Raw, invalid),
    lists:append([
        idle_equal_problem(
          Raw, <<"schema">>, maps:get(<<"fixture_schema">>, Idle),
          <<"fixture-schema">>),
        idle_equal_problem(Raw, <<"status">>, <<"Ready">>,
                           <<"fixture-status">>),
        idle_equal_problem(Raw, <<"shareable">>, true,
                           <<"fixture-shareability">>),
        idle_equal_problem(Raw, <<"redacted">>, true,
                           <<"fixture-redaction">>),
        idle_equal_problem(Raw, <<"quiescence_confirmed">>, true,
                           <<"quiescence-not-confirmed">>),
        idle_equal_problem(
          Raw, <<"quiescence_required_stable_samples">>,
          maps:get(<<"quiescence_required_stable_samples">>, Idle),
          <<"quiescence-sample-configuration">>),
        idle_equal_problem(
          Raw, <<"quiescence_poll_milliseconds">>,
          maps:get(<<"quiescence_poll_milliseconds">>, Idle),
          <<"quiescence-poll-configuration">>),
        idle_equal_problem(
          Raw, <<"quiescence_maximum_attempts">>,
          maps:get(<<"quiescence_maximum_attempts">>, Idle),
          <<"quiescence-attempt-configuration">>),
        idle_bounded_integer_problem(
          Raw, <<"quiescence_milliseconds">>, 0,
          maps:get(<<"maximum_quiescence_milliseconds">>, Idle),
          <<"quiescence-duration">>),
        idle_equal_problem(
          Raw, <<"minimum_observation_milliseconds">>,
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
          <<"observation-configuration">>),
        idle_minimum_integer_problem(
          Raw, <<"observation_milliseconds">>,
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
          <<"observation-duration">>),
        idle_equal_problem(Raw, <<"actor_set_stable">>, true,
                           <<"actor-set-stability">>),
        idle_equal_problem(Raw, <<"expected_actor_count">>,
                           maps:get(<<"expected_actor_count">>, Idle),
                           <<"actor-count">>),
        idle_equal_problem(Raw, <<"deadline_timeout_returns">>, 0,
                           <<"deadline-timeout-returns">>),
        idle_equal_problem(Raw, <<"unexpected_actor_exits">>, 0,
                           <<"unexpected-actor-exits">>),
        idle_equal_problem(Raw, <<"required_actor_liveness">>, true,
                           <<"required-actor-liveness">>),
        idle_equal_problem(Raw, <<"trace_synchronized">>, true,
                           <<"trace-synchronization">>),
        idle_equal_problem(Raw, <<"trace_primitive">>,
                           maps:get(<<"trace_primitive">>, Idle),
                           <<"trace-primitive">>),
        validate_idle_roles(Roles, Idle),
        idle_global_timeout_problem(Raw, Roles)
    ]);
validate_idle_evidence(_Raw, _Idle) ->
    [violation(<<"idle-wakeup">>, <<"fixture-shape">>, #{})].

validate_idle_roles(Roles, Idle) when is_list(Roles) ->
    Labels = [maps:get(<<"label">>, Role, invalid)
              || Role <- Roles, is_map(Role)],
    ShapeProblems =
        idle_problem(length(Labels) =/= length(Roles),
                     <<"role-shape">>, #{})
        ++ idle_problem(Labels =/= maps:get(<<"required_roles">>, Idle),
                        <<"role-topology">>,
                        #{expected => maps:get(<<"required_roles">>, Idle),
                          observed => Labels})
        ++ idle_problem(not unique(Labels), <<"duplicate-role">>, #{}),
    ShapeProblems
    ++ lists:append([validate_idle_role(Role, Idle)
                     || Role <- Roles, is_map(Role)]);
validate_idle_roles(_Roles, _Idle) ->
    [violation(<<"idle-wakeup">>, <<"roles-shape">>, #{})].

validate_idle_role(Role, Idle) ->
    Label = maps:get(<<"label">>, Role, <<"unknown">>),
    NumericKeys = idle_role_numeric_keys(),
    InvalidNumbers = [Key || Key <- NumericKeys,
                             not nonnegative_map_integer(Role, Key)],
    TimedCalls = idle_integer_or_negative(Role, <<"timed_wait_calls">>),
    WaitClasses = idle_sum_keys(
      Role,
      [<<"wait_zero_calls">>, <<"wait_short_calls">>,
       <<"wait_second_calls">>, <<"wait_long_calls">>]),
    TimeoutReturns = idle_integer_or_negative(
                       Role, <<"deadline_timeout_returns">>),
    TimeoutClasses = idle_sum_keys(
      Role,
      [<<"timeout_zero_returns">>, <<"timeout_short_returns">>,
       <<"timeout_second_returns">>, <<"timeout_long_returns">>,
       <<"timeout_unclassified_returns">>]),
    LivenessRequired = lists:member(
                         Label, maps:get(<<"required_liveness_roles">>, Idle)),
    MessageReturns = idle_integer_or_negative(
                       Role, <<"timed_message_returns">>)
                     + idle_integer_or_negative(
                         Role, <<"unbounded_message_returns">>),
    lists:append([
        idle_problem(InvalidNumbers =/= [], <<"role-counter-shape">>,
                     #{role => Label, invalid => InvalidNumbers}),
        idle_role_equal_problem(Role, Label, <<"expected_actors">>, 1,
                                <<"role-expected-count">>),
        idle_role_equal_problem(Role, Label, <<"actors_start">>, 1,
                                <<"role-start-count">>),
        idle_role_equal_problem(Role, Label, <<"actors_end">>, 1,
                                <<"role-end-count">>),
        idle_role_equal_problem(Role, Label,
                                <<"deadline_timeout_returns">>, 0,
                                <<"role-deadline-timeout">>),
        idle_problem(TimedCalls =/= WaitClasses,
                     <<"timed-wait-class-sum">>,
                     #{role => Label, calls => TimedCalls,
                       class_sum => WaitClasses}),
        idle_problem(TimeoutReturns =/= TimeoutClasses,
                     <<"timeout-class-sum">>,
                     #{role => Label, returns => TimeoutReturns,
                       class_sum => TimeoutClasses}),
        idle_problem(
          idle_integer_or_negative(
            Role, <<"timed_boundary_message_returns">>)
          > idle_integer_or_negative(Role, <<"expected_actors">>),
          <<"timed-boundary-return-bound">>, #{role => Label}),
        idle_problem(
          idle_integer_or_negative(Role, <<"timed_message_returns">>)
          > TimedCalls
              + idle_integer_or_negative(
                  Role, <<"timed_boundary_message_returns">>),
          <<"timed-return-without-call">>, #{role => Label}),
        idle_problem(
          idle_integer_or_negative(
            Role, <<"unbounded_boundary_message_returns">>)
          > idle_integer_or_negative(Role, <<"expected_actors">>),
          <<"unbounded-boundary-return-bound">>, #{role => Label}),
        idle_problem(
          idle_integer_or_negative(Role, <<"unbounded_message_returns">>)
          > idle_integer_or_negative(Role, <<"unbounded_wait_calls">>)
              + idle_integer_or_negative(
                  Role, <<"unbounded_boundary_message_returns">>),
          <<"unbounded-return-without-call">>, #{role => Label}),
        idle_problem(LivenessRequired andalso MessageReturns =< 0,
                     <<"role-liveness">>, #{role => Label})
    ]).

idle_global_timeout_problem(Raw, Roles) when is_list(Roles) ->
    ValidRoles = [Role || Role <- Roles, is_map(Role)],
    RowTotal = lists:sum([
        erlang:max(0, idle_integer_or_negative(
                        Role, <<"deadline_timeout_returns">>))
        || Role <- ValidRoles
    ]),
    Global = maps:get(<<"deadline_timeout_returns">>, Raw, invalid),
    idle_problem(not is_integer(Global) orelse Global =/= RowTotal,
                 <<"global-timeout-sum">>,
                 #{observed => idle_json_value(Global),
                   row_sum => RowTotal});
idle_global_timeout_problem(_Raw, _Roles) -> [].

idle_role_numeric_keys() ->
    [<<"expected_actors">>, <<"actors_start">>, <<"actors_end">>,
     <<"timed_wait_calls">>, <<"timed_message_returns">>,
     <<"timed_boundary_message_returns">>,
     <<"deadline_timeout_returns">>, <<"wait_zero_calls">>,
     <<"wait_short_calls">>, <<"wait_second_calls">>,
     <<"wait_long_calls">>, <<"timeout_zero_returns">>,
     <<"timeout_short_returns">>, <<"timeout_second_returns">>,
     <<"timeout_long_returns">>, <<"timeout_unclassified_returns">>,
     <<"unbounded_wait_calls">>, <<"unbounded_message_returns">>,
     <<"unbounded_boundary_message_returns">>].

idle_equal_problem(Map, Key, Expected, Id) ->
    Observed = maps:get(Key, Map, invalid),
    idle_problem(Observed =/= Expected, Id,
                 #{expected => Expected,
                   observed => idle_json_value(Observed)}).

idle_role_equal_problem(Role, Label, Key, Expected, Id) ->
    Observed = maps:get(Key, Role, invalid),
    idle_problem(Observed =/= Expected, Id,
                 #{role => Label, expected => Expected,
                   observed => idle_json_value(Observed)}).

idle_bounded_integer_problem(Map, Key, Minimum, Maximum, Id) ->
    Value = maps:get(Key, Map, invalid),
    idle_problem(not is_integer(Value) orelse Value < Minimum
                 orelse Value > Maximum,
                 Id, #{minimum => Minimum, maximum => Maximum,
                       observed => idle_json_value(Value)}).

idle_minimum_integer_problem(Map, Key, Minimum, Id) ->
    Value = maps:get(Key, Map, invalid),
    idle_problem(not is_integer(Value) orelse Value < Minimum,
                 Id, #{minimum => Minimum,
                       observed => idle_json_value(Value)}).

idle_runtime_problem(Map, Key, Id) ->
    Value = maps:get(Key, Map, invalid),
    idle_problem(not is_binary(Value) orelse byte_size(Value) =:= 0,
                 Id, #{observed => idle_json_value(Value)}).

idle_sum_keys(Map, Keys) ->
    lists:sum([erlang:max(0, idle_integer_or_negative(Map, Key))
               || Key <- Keys]).

idle_integer_or_negative(Map, Key) ->
    case maps:get(Key, Map, invalid) of
        Value when is_integer(Value), Value >= 0 -> Value;
        _ -> -1
    end.

idle_problem(true, Id, Evidence) ->
    [violation(<<"idle-wakeup">>, Id, Evidence)];
idle_problem(false, _Id, _Evidence) -> [].

idle_json_value(invalid) -> null;
idle_json_value(Value) -> Value.

idle_expected_roles() ->
    [<<"http3.client">>, <<"http3.listener">>, <<"http3.acceptor">>,
     <<"http3.connection">>, <<"quic_core.client">>,
     <<"quic_core.listener">>, <<"quic_core.connection">>,
     <<"quic_core.udp_relay">>].

idle_liveness_roles() ->
    [<<"http3.client">>, <<"http3.connection">>,
     <<"quic_core.client">>, <<"quic_core.connection">>].

expected_configuration(Workload) ->
    #{<<"mode">> => maps:get(<<"mode">>, Workload),
      <<"warmup_runs">> => maps:get(<<"warmup_runs">>, Workload),
      <<"measured_trials">> => maps:get(<<"measured_trials">>, Workload),
      <<"concurrency">> => maps:get(<<"concurrency">>, Workload),
      <<"requests_per_connection">> =>
          maps:get(<<"requests_per_connection">>, Workload),
      <<"payload_bytes">> => maps:get(<<"payload_bytes">>, Workload),
      <<"minimum_requests_per_second">> =>
          maps:get(<<"minimum_requests_per_second">>, Workload)}.

workload(Mode, Profile) ->
    case [Entry || Entry <- maps:get(<<"fixed_http3_workloads">>, Profile),
                   maps:get(<<"mode">>, Entry) =:= Mode] of
        [Entry] -> Entry;
        [] -> erlang:error({missing_workload, Mode});
        _ -> erlang:error({duplicate_workload, Mode})
    end.

source_digest(Evidence) ->
    Explicit = [binary_to_list(Path)
                || Path <- maps:get(<<"source_files">>, Evidence)],
    Roots = [binary_to_list(Path)
             || Path <- maps:get(<<"production_source_roots">>, Evidence)],
    Production = lists:append([
        filelib:fold_files(Root, ".*\\.(gleam|erl|hrl)$", true,
                           fun(Path, Paths) -> [Path | Paths] end, [])
        || Root <- Roots
    ]),
    Paths = lists:usort(Explicit ++ Production),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

problem(true, Mode, Id, Evidence) -> [violation(Mode, Id, Evidence)];
problem(false, _Mode, _Id, _Evidence) -> [].

violation(Mode, Id, Evidence) ->
    maps:merge(#{mode => Mode, id => Id}, Evidence).

missing(Required, Observed) ->
    [Value || Value <- Required, not lists:member(Value, Observed)].

unique(Values) -> length(Values) =:= length(lists:usort(Values)).

safe_length(Value) when is_list(Value) -> length(Value);
safe_length(_Value) -> -1.

nonnegative_map_integer(Map, Key) ->
    case maps:get(Key, Map, undefined) of
        Value when is_integer(Value), Value >= 0 -> true;
        _ -> false
    end.

nested(Value, []) -> Value;
nested(Map, [Key | Rest]) when is_map(Map) ->
    case maps:find(Key, Map) of
        {ok, Value} -> nested(Value, Rest);
        error -> undefined
    end;
nested(_Value, _Path) -> undefined.

valid_digest(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    lists:all(fun(Character) ->
        (Character >= $0 andalso Character =< $9)
        orelse (Character >= $a andalso Character =< $f)
        orelse (Character >= $A andalso Character =< $F)
    end, binary_to_list(Value));
valid_digest(_Value) -> false.

read_json(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} when byte_size(Bytes) =< ?MAXIMUM_REPORT_BYTES ->
            try json:decode(Bytes) of
                Value -> {ok, Value}
            catch
                _:_ -> {error, invalid_json}
            end;
        {ok, _Bytes} -> {error, report_too_large};
        {error, Reason} -> {error, Reason}
    end.

read_json_bytes(Path) ->
    case read_bytes(Path) of
        {ok, Bytes} ->
            try json:decode(Bytes) of
                Value when is_map(Value) -> {ok, Value, Bytes};
                _ -> {error, invalid_json_shape}
            catch
                _:_ -> {error, invalid_json}
            end;
        {error, Reason} -> {error, Reason}
    end.

read_bytes(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} when byte_size(Bytes) =< ?MAXIMUM_REPORT_BYTES ->
            {ok, Bytes};
        {ok, _Bytes} -> {error, report_too_large};
        {error, Reason} -> {error, Reason}
    end.

file_digest(Path) -> hex(crypto:hash(sha256, read(Path))).

write_report(Report) ->
    ok = filelib:ensure_dir(?OUTPUT_PATH),
    ok = file:write_file(?OUTPUT_PATH, [json:encode(Report), <<"\n">>]).

self_test() ->
    ensure(valid_digest(binary:copy(<<"a">>, 64)), digest_accepts_hex),
    ensure(valid_digest(binary:copy(<<"F">>, 64)), digest_accepts_upper_hex),
    ensure(not valid_digest(binary:copy(<<"g">>, 64)), digest_rejects_nonhex),
    ensure(not valid_digest(<<"short">>), digest_rejects_length),
    GoodRow = maps:from_list(
      [{Key, 0} || Key <-
          [<<"ports_before">>, <<"ports_after">>,
           <<"network_ports_before">>, <<"network_ports_after">>,
           <<"sockets_before">>, <<"sockets_after">>,
           <<"client_initial_smoothed_rtt_min_us">>,
           <<"client_initial_smoothed_rtt_avg_us">>,
           <<"client_initial_smoothed_rtt_max_us">>,
           <<"client_final_smoothed_rtt_min_us">>,
           <<"client_final_smoothed_rtt_avg_us">>,
           <<"client_final_smoothed_rtt_max_us">>,
           <<"client_initial_cwnd_min">>, <<"client_initial_cwnd_avg">>,
           <<"client_initial_cwnd_max">>, <<"client_final_cwnd_min">>,
           <<"client_final_cwnd_avg">>, <<"client_final_cwnd_max">>,
           <<"client_retransmissions_total">>,
           <<"client_retransmissions_max">>,
           <<"client_packets_received_total">>,
           <<"client_packets_sent_total">>,
           <<"client_batch_flushes_total">>,
           <<"client_packets_coalesced_total">>,
           <<"client_connections_in_recovery">>,
           <<"client_connections_congested">>]]),
    [] = validate_row(<<"fixture">>, GoodRow),
    BadRow = GoodRow#{<<"client_initial_smoothed_rtt_avg_us">> => 2,
                     <<"client_initial_smoothed_rtt_max_us">> => 1},
    BadRowViolations = validate_row(<<"fixture">>, BadRow),
    ensure(lists:any(fun(V) -> maps:get(id, V) =:= <<"initial-rtt-order">> end,
                     BadRowViolations), row_order_violation),
    GoodProbes = #{<<"cpu">> => #{<<"status">> => <<"Available">>},
                   <<"missing">> =>
                       #{<<"status">> => <<"Unavailable">>}},
    [] = invalid_probe_names(GoodProbes),
    [<<"cpu">>] = invalid_probe_names(
      GoodProbes#{<<"cpu">> => #{<<"status">> => <<"Invalid">>}}),
    ensure(missing([<<"a">>, <<"b">>], [<<"b">>]) =:= [<<"a">>],
           missing_values),
    Profile = json:decode(read(?PROFILE_PATH)),
    Evidence = maps:get(<<"performance_evidence">>, Profile),
    ok = validate_profile(Profile, Evidence),
    Idle = maps:get(<<"idle_wakeup">>, Evidence),
    GoodIdle = idle_fixture_evidence(Idle),
    [] = validate_idle_evidence(GoodIdle, Idle),
    expect_idle_violation(
      validate_idle_evidence(
        GoodIdle#{<<"deadline_timeout_returns">> := 1}, Idle),
      <<"deadline-timeout-returns">>),
    IdleRoles = maps:get(<<"roles">>, GoodIdle),
    expect_idle_violation(
      validate_idle_evidence(
        GoodIdle#{<<"roles">> := lists:droplast(IdleRoles)}, Idle),
      <<"role-topology">>),
    expect_idle_violation(
      validate_idle_evidence(
        GoodIdle#{<<"quiescence_required_stable_samples">> := 4}, Idle),
      <<"quiescence-sample-configuration">>),
    expect_idle_violation(
      validate_idle_evidence(
        GoodIdle#{<<"quiescence_milliseconds">> := 8001}, Idle),
      <<"quiescence-duration">>),
    [FirstIdleRole | RemainingIdleRoles] = IdleRoles,
    BadIdleRole = FirstIdleRole#{<<"deadline_timeout_returns">> := 1,
                                 <<"timeout_second_returns">> := 1},
    expect_idle_violation(
      validate_idle_evidence(
        GoodIdle#{<<"roles">> :=
                      [BadIdleRole | RemainingIdleRoles]}, Idle),
      <<"role-deadline-timeout">>),
    ensure(byte_size(source_digest(Evidence)) =:= 64, source_digest_shape),
    io:put_chars(
      "performance audit self-test: source, report, transport, host, and "
      "idle-wakeup gates ok\n"),
    ok.

idle_fixture_evidence(Idle) ->
    Liveness = maps:get(<<"required_liveness_roles">>, Idle),
    Roles = [idle_fixture_role(Label, lists:member(Label, Liveness))
             || Label <- maps:get(<<"required_roles">>, Idle)],
    #{<<"schema">> => maps:get(<<"fixture_schema">>, Idle),
      <<"status">> => <<"Ready">>,
      <<"shareable">> => true,
      <<"redacted">> => true,
      <<"quiescence_confirmed">> => true,
      <<"quiescence_maximum_attempts">> =>
          maps:get(<<"quiescence_maximum_attempts">>, Idle),
      <<"quiescence_milliseconds">> => 600,
      <<"quiescence_poll_milliseconds">> =>
          maps:get(<<"quiescence_poll_milliseconds">>, Idle),
      <<"quiescence_required_stable_samples">> =>
          maps:get(<<"quiescence_required_stable_samples">>, Idle),
      <<"observation_milliseconds">> =>
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
      <<"minimum_observation_milliseconds">> =>
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
      <<"actor_set_stable">> => true,
      <<"expected_actor_count">> =>
          maps:get(<<"expected_actor_count">>, Idle),
      <<"deadline_timeout_returns">> => 0,
      <<"unexpected_actor_exits">> => 0,
      <<"required_actor_liveness">> => true,
      <<"trace_synchronized">> => true,
      <<"trace_primitive">> => maps:get(<<"trace_primitive">>, Idle),
      <<"roles">> => Roles}.

idle_fixture_role(Label, LivenessRequired) ->
    Unbounded = case LivenessRequired of true -> 1; false -> 0 end,
    #{<<"label">> => Label,
      <<"expected_actors">> => 1,
      <<"actors_start">> => 1,
      <<"actors_end">> => 1,
      <<"timed_wait_calls">> => 0,
      <<"timed_message_returns">> => 0,
      <<"timed_boundary_message_returns">> => 0,
      <<"deadline_timeout_returns">> => 0,
      <<"wait_zero_calls">> => 0,
      <<"wait_short_calls">> => 0,
      <<"wait_second_calls">> => 0,
      <<"wait_long_calls">> => 0,
      <<"timeout_zero_returns">> => 0,
      <<"timeout_short_returns">> => 0,
      <<"timeout_second_returns">> => 0,
      <<"timeout_long_returns">> => 0,
      <<"timeout_unclassified_returns">> => 0,
      <<"unbounded_wait_calls">> => Unbounded,
      <<"unbounded_message_returns">> => Unbounded,
      <<"unbounded_boundary_message_returns">> => 0}.

expect_idle_violation(Violations, Id) ->
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= Id
    end, Violations), {missing_idle_self_test_violation, Id}).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
