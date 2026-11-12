#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1 +hmax 134217728 +hmaxib true +hmaxk true +hmaxel false
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% This gate is deliberately static. It binds the configured workload
%% deadlines, preflight invalidation, safe failure projection, task ordering,
%% and CI collection paths without launching a benchmark or opening a socket.

-define(OUTPUT, "build/performance/contract-audit.json").
-define(SELF_TEST_OUTPUT, "build/performance/contract-audit-self-test.json").
-define(MAXIMUM_SOURCE_BYTES, 2097152).
-define(MAXIMUM_TOTAL_BYTES, 16777216).
-define(MAXIMUM_REPORT_BYTES, 4194304).
-define(SUPERVISOR_MAXIMUM_MS, 5400000).

-include("execution_identity.hrl").
-include("file_identity.hrl").
-include("diagnostic_failure.hrl").
-include("json_evidence.hrl").

main([]) -> guarded(audit, ?OUTPUT, fun audit/0);
main(["--self-test"]) -> guarded(self_test, ?SELF_TEST_OUTPUT, fun self_test/0);
main(_) -> halt(2).

guarded(Kind, Output, Function) ->
    try
        invalidate_prior_reports(Kind, Output),
        Function()
    of
        ok -> ok
    catch
      throw:performance_contract_violation_reported:_ ->
        io:put_chars(standard_error,
            "performance contract audit failed: performance_contract_violation\n"),
        halt(1);
      throw:{performance_contract_self_test_violation_reported, FailedCount}:_ ->
        _ = try write_report(?OUTPUT, reported_self_test_failure(FailedCount))
            catch _:_ -> unavailable end,
        io:put_chars(standard_error,
            "performance contract self-test failed: adversarial_control_not_rejected\n"),
        halt(1);
      Class:Reason:Stack ->
        FailureReport = maps:merge(failure_context(),
          #{schema => 1, status => <<"Failed">>,
            kind => atom_to_binary(Kind), shareable => true, redacted => true,
            failure_classification => <<"performance_contract_audit_internal_failure">>,
            failure => diagnostic_failure_details(Class, Reason, Stack),
            completed_controls => 0, failure_count => 1,
            rerun_command => rerun_command(Kind)}),
        _ = try write_report(Output, FailureReport) catch _:_ -> unavailable end,
        %% The task stops after a failed self-test. Leave an explicit failed
        %% audit record too, so CI never mistakes an absent main report for a
        %% collector problem or reuses one from an earlier invocation.
        _ = case Kind of
            self_test -> try write_report(?OUTPUT, FailureReport#{
                kind => <<"audit">>, rerun_command => rerun_command(audit)})
                catch _:_ -> unavailable end;
            audit -> ok
        end,
        io:format(standard_error, "performance contract audit failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

invalidate_prior_reports(self_test, Output) ->
    invalidate(?OUTPUT),
    invalidate(Output);
invalidate_prior_reports(audit, Output) -> invalidate(Output).

failure_context() ->
    try
        Runtime = safe_execution_runtime(),
        Available = [{Path, Bytes} || Path <- source_paths(),
            {ok, Bytes} <- [try_bounded_read(Path)]],
        Sources = maps:from_list(Available),
        Complete = length(Available) =:= length(source_paths()),
        #{source_set_sha256 => case Complete of
              true -> source_digest(Sources);
              false -> <<"unavailable">>
          end,
          source_set_status => case Complete of
              true -> <<"complete">>;
              false -> <<"incomplete">>
          end,
          source_files => length(source_paths()),
          completed_source_files => length(Available),
          execution_environment => Runtime,
          tool => #{name => <<"OTP escript">>,
              otp_version => maps:get(<<"otp_version">>, Runtime, <<"unknown">>),
              erts_version => maps:get(<<"erts_version">>, Runtime, <<"unknown">>)}}
    catch _:_ ->
        FallbackRuntime = safe_execution_runtime(),
        #{source_set_sha256 => <<"unavailable">>,
          source_set_status => <<"incomplete">>, source_files => length(source_paths()),
          completed_source_files => 0, execution_environment => FallbackRuntime,
          tool => #{name => <<"OTP escript">>,
              otp_version => maps:get(<<"otp_version">>, FallbackRuntime, <<"unknown">>),
              erts_version => maps:get(<<"erts_version">>, FallbackRuntime, <<"unknown">>)}}
    end.

safe_execution_runtime() ->
    try execution_runtime()
    catch _:_ -> #{<<"otp_version">> => <<"unknown">>,
        <<"erts_version">> => <<"unknown">>, <<"system_architecture">> => <<"unknown">>,
        <<"os_family">> => <<"unknown">>, <<"os_name">> => <<"unknown">>,
        <<"word_size">> => 0}
    end.

try_bounded_read(Path) ->
    try {ok, bounded_read(Path)} catch _:_ -> unavailable end.

reported_self_test_failure(FailedCount) ->
    maps:merge(failure_context(),
        #{schema => 1, status => <<"Failed">>, kind => <<"audit">>,
          shareable => true, redacted => true,
          failure_classification => <<"performance_contract_self_test_violation">>,
          configured_controls => length(adversarial_cases()),
          completed_controls => length(adversarial_cases()),
          failure_count => FailedCount,
          rerun_command => rerun_command(self_test)}).

audit() ->
    Sources = read_sources(),
    Controls = contract_controls(Sources),
    Failures = [maps:remove(passed, Row) || Row <- Controls,
        maps:get(passed, Row) =:= false],
    Report0 = base_report(audit, Sources, Controls, Failures),
    %% A mixed-revision report cannot qualify. Re-read every input after all
    %% parsing and compare the framed file-set digest before publication.
    maps:get(source_set_sha256, Report0) =:= source_digest(read_sources())
        orelse erlang:error(source_changed_during_performance_contract_audit),
    write_report(?OUTPUT, Report0),
    io:format("performance contract audit: ~B controls, ~B failures, maximum ~B ms~n",
        [length(Controls), length(Failures), ?SUPERVISOR_MAXIMUM_MS]),
    case Failures of
        [] -> ok;
        _ -> throw(performance_contract_violation_reported)
    end.

self_test() ->
    Sources = read_sources(),
    Baseline = contract_controls(Sources),
    [] = [maps:get(id, Row) || Row <- Baseline, maps:get(passed, Row) =:= false],
    Cases = adversarial_cases(),
    Rows = [adversarial_case(Sources, Case) || Case <- Cases],
    EncodedRows = iolist_to_binary(json:encode(Rows)),
    nomatch = binary:match(EncodedRows, <<"private-performance-contract-marker">>),
    Controls = [#{id => maps:get(id, Row), path => maps:get(path, Row),
        rule => <<"adversarial mutation rejected">>, passed => maps:get(passed, Row)}
        || Row <- Rows],
    Failures = [maps:remove(passed, Row) || Row <- Rows,
        maps:get(passed, Row) =:= false],
    Report0 = base_report(self_test, Sources, Controls, Failures),
    maps:get(source_set_sha256, Report0) =:= source_digest(read_sources())
        orelse erlang:error(source_changed_during_performance_contract_self_test),
    write_report(?SELF_TEST_OUTPUT, Report0),
    case Failures of
        [] -> ok;
        _ -> throw({performance_contract_self_test_violation_reported, length(Failures)})
    end,
    io:format("performance contract self-test: ~B adversarial mutations rejected~n",
        [length(Rows)]),
    ok.

base_report(Kind, Sources, Controls, Failures) ->
    Runtime = execution_runtime(),
    FailureClassification = case Failures of
        [] -> <<"none">>;
        _ -> <<"performance_contract_violation">>
    end,
    #{schema => 1, status => case Failures of [] -> <<"Ready">>; _ -> <<"Failed">> end,
      kind => atom_to_binary(Kind), shareable => true, redacted => true,
      failure_classification => FailureClassification,
      scope => <<"performance deadlines, preflight invalidation, safe failure evidence, task wiring, and artifact collection">>,
      supervisor_maximum_milliseconds => ?SUPERVISOR_MAXIMUM_MS,
      source_set_sha256 => source_digest(Sources),
      source_files => length(source_paths()),
      completed_source_files => maps:size(Sources),
      source_identity => [source_identity(Path, maps:get(Path, Sources))
          || Path <- source_paths()],
      execution_environment => Runtime,
      tool => #{name => <<"OTP escript">>,
          otp_version => maps:get(<<"otp_version">>, Runtime),
          erts_version => maps:get(<<"erts_version">>, Runtime)},
      configured_modes => [<<"benchmark">>, <<"load">>, <<"soak">>,
          <<"idle-wakeup">>, <<"hot-path">>, <<"protocol-performance">>],
      controls => Controls, configured_controls => length(Controls),
      completed_controls => length(Controls), failure_count => length(Failures),
      failures => Failures, rerun_command => rerun_command(Kind)}.

contract_controls(Sources) ->
    Process = erlang_active(source(Sources, "scripts/process_runner.hrl")),
    FixedExecution = erlang_active(source(Sources, "scripts/performance_execution.hrl")),
    IdleExecution = erlang_active(source(Sources, "scripts/performance_idle_execution.hrl")),
    HotEvidence = erlang_active(source(Sources, "scripts/hot_path_evidence.hrl")),
    HotRunner = erlang_active(source(Sources, "scripts/hot_path_profile.erl")),
    HotInvalidator = between(HotRunner, <<"invalidate_outputs(JsonPath, CsvPath) ->">>,
        <<"\n\nhpp_csv_header() ->">>),
    ProtocolExecution = erlang_active(source(Sources, "scripts/protocol_performance_execution.hrl")),
    Profile = performance_profile(source(Sources, "standards/performance-profile.json")),
    FixedDeadlines = fixed_deadlines(FixedExecution),
    IdleDeadline = scalar_deadline(IdleExecution, <<"idw_deadline\\(\\)\\s*->\\s*([0-9]+)">>),
    ProtocolDeadline = scalar_deadline(ProtocolExecution, <<"ppr_deadline\\(\\)\\s*->\\s*([0-9]+)">>),
    HotProfileDeadline = maps:get(<<"timeout_milliseconds">>,
        maps:get(<<"hot_path_call_profile">>, Profile), -1),
    HotRunnerDeadlines = capture_integers(HotRunner,
        <<"execute_child\\(HotPath,\\s*Compiled,\\s*Nonce,\\s*([0-9]+)\\)">>),
    HotEvidenceDeadlines = capture_integers(HotEvidence,
        <<"([0-9]+)\\s*=\\s*maps:get\\(<<\"deadline_ms\">>">>),
    SupervisorInput = capture_integers(Process,
        <<"Milliseconds\\s*=<\\s*([0-9]+)">>),
    SupervisorForward = capture_integers(Process,
        <<"erlang:min\\(\\s*([0-9]+)\\s*,\\s*Deadline">>),
    Mise = configuration_active(source(Sources, ".mise.toml")),
    FixedRun = shell_active(source(Sources, "scripts/performance_run.sh")),
    FixedRunner = erlang_active(source(Sources, "scripts/performance_runner.escript")),
    FixedExecute = between(FixedRunner, <<"execute(Mode) ->">>,
        <<"\n\nperformance_run_child(Mode, Compiled, Deadline) ->">>),
    FixedInvalidator = between(FixedRunner, <<"invalidate(Stem, Mode) ->">>, <<"\n\nself_test() ->">>),
    FixedReporter = erlang_active(source(Sources, "scripts/performance_run_report.escript")),
    IdleRunner = erlang_active(source(Sources, "scripts/performance_idle_runner.escript")),
    IdleExecute = between(IdleRunner, <<"execute() ->">>, <<"\n\nrun_idle_child(Compiled, Deadline) ->">>),
    IdleInvalidator = between(IdleRunner, <<"invalidate(Stem) ->">>, <<"\n\nself_test() ->">>),
    IdleShell = shell_active(source(Sources, "scripts/performance_idle_wakeup.sh")),
    IdleReporter = erlang_active(source(Sources, "scripts/performance_idle_wakeup_report.escript")),
    ProtocolRunner = erlang_active(source(Sources, "scripts/protocol_performance_runner.escript")),
    ProtocolExecute = between(ProtocolRunner, <<"execute() ->">>,
        <<"\n\nppr_run_child(Protocol,Compiled,Deadline) ->">>),
    ProtocolInvalidator = between(ProtocolRunner, <<"ppr_invalidate(Path,Proof) ->">>,
        <<"\n\nppr_invalidation_self_test() ->">>),
    PerformanceAudit = erlang_active(source(Sources, "scripts/performance_audit.erl")),
    AggregateGuard = between(PerformanceAudit, <<"guarded_self_test() ->">>,
        <<"\n\nrun() ->">>),
    AggregateRun = between(PerformanceAudit, <<"run() ->">>,
        <<"\n\nverify_report(Report) ->">>),
    AggregateInvalidator = between(PerformanceAudit, <<"invalidate_report() ->">>,
        <<"\n\nwrite_report(Report) ->">>),
    AggregateWriter = between(PerformanceAudit, <<"atomic_write_report(Path, Report) ->">>,
        <<"\n\nself_test() ->">>),
    AggregateSelfTest = between(PerformanceAudit, <<"self_test() ->">>,
        <<"\n\nidle_fixture_evidence(Idle) ->">>),
    ContractAudit = erlang_active(source(Sources, "scripts/performance_contract_audit.escript")),
    ContractPreamble = between(ContractAudit, <<"-define(OUTPUT">>, <<"\n\nmain([])">>),
    ContractEntry = between(ContractAudit, <<"main([])">>,
        <<"\n\nguarded(Kind, Output, Function) ->">>),
    ContractGuard = between(ContractAudit, <<"guarded(Kind, Output, Function) ->">>,
        <<"\n\naudit() ->">>),
    ContractBaseReport = between(ContractAudit, <<"base_report(Kind, Sources, Controls, Failures) ->">>,
        <<"\n\ncontract_controls(Sources) ->">>),
    HotRun = between(HotRunner, <<"run([]) ->">>, <<"\nrun(_) ->">>),
    Nightly = configuration_active(source(Sources, ".github/workflows/nightly.yml")),
    Ci = configuration_active(source(Sources, ".github/workflows/ci.yml")),
    ProtocolJob = yaml_job(Nightly, <<"protocol-performance">>),
    SoakJob = yaml_job(Nightly, <<"soak">>),
    QualityJob = yaml_job(Ci, <<"quality">>),
    RequiredReportsStep = yaml_step(QualityJob, <<"Require both performance contract reports">>),
    PreserveReportsStep = yaml_step(QualityJob, <<"Preserve performance contract audit on success and failure">>),
    ProtocolUploadStep = yaml_step(ProtocolJob, <<"Upload bounded execution evidence">>),
    SoakUploadStep = yaml_step(SoakJob, <<"Upload soak evidence">>),
    AggregateTask = task_section(Mise, <<"performance-audit">>),
    ProtocolTimeout = yaml_timeout(ProtocolJob),
    SoakTimeout = yaml_timeout(SoakJob),
    [
      control(<<"supervisor-input-maximum">>, "scripts/process_runner.hrl",
        <<"child deadline maximum is exactly 5,400,000 ms">>,
        SupervisorInput =:= [?SUPERVISOR_MAXIMUM_MS]),
      control(<<"supervisor-forwarded-maximum">>, "scripts/process_runner.hrl",
        <<"forwarded supervisor deadline is clamped to the same maximum">>,
        SupervisorForward =:= [?SUPERVISOR_MAXIMUM_MS]),
      control(<<"fixed-deadline-set">>, "scripts/performance_execution.hrl",
        <<"benchmark/load/soak deadlines are complete, unique, and pinned">>,
        FixedDeadlines =:= [{<<"benchmark">>,5400000},{<<"load">>,3600000},{<<"soak">>,1800000}]),
      control(<<"fixed-deadline-upper-bound">>, "scripts/performance_execution.hrl",
        <<"every fixed workload deadline fits the common supervisor">>,
        deadline_values_valid([Value || {_,Value} <- FixedDeadlines])),
      control(<<"idle-deadline">>, "scripts/performance_idle_execution.hrl",
        <<"idle deadline is pinned and fits the common supervisor">>,
        IdleDeadline =:= 60000 andalso deadline_values_valid([IdleDeadline])),
      control(<<"hot-path-deadline">>, "standards/performance-profile.json",
        <<"profile, runner, and verifier agree on a bounded hot-path deadline">>,
        HotProfileDeadline =:= 120000 andalso HotRunnerDeadlines =:= [120000]
            andalso HotEvidenceDeadlines =:= [120000]
            andalso deadline_values_valid([HotProfileDeadline])),
      control(<<"protocol-deadline">>, "scripts/protocol_performance_execution.hrl",
        <<"per-protocol deadline is pinned and fits the common supervisor">>,
        ProtocolDeadline =:= 300000 andalso deadline_values_valid([ProtocolDeadline])),
      control(<<"protocol-ci-envelope">>, ".github/workflows/nightly.yml",
        <<"nightly job exceeds all three protocol child deadlines">>,
        ProtocolTimeout * 60000 > 3 * ProtocolDeadline),
      control(<<"soak-ci-envelope">>, ".github/workflows/nightly.yml",
        <<"nightly job exceeds the supervised soak deadline">>,
        SoakTimeout * 60000 > deadline_for(<<"soak">>, FixedDeadlines)),
      control(<<"fixed-task-order">>, "scripts/performance_run.sh",
        <<"fixed artifacts are invalidated before controls, build, workload, and reporter">>,
        ordered(FixedRun, [<<"performance_runner.escript --invalidate">>,
            <<"performance_runner.escript --self-test">>, <<"fresh_build.sh http3">>,
            <<"performance_runner.escript \"$mode\"">>,
            <<"performance_run_report.escript \"$mode\"">>])),
      control(<<"hot-path-task-order">>, ".mise.toml",
        <<"hot-path invalidation precedes controls, build, run, and verification">>,
        ordered(task_section(Mise, <<"hot-path-profile">>),
            [<<"hot_path_profile.escript --invalidate">>, <<"hot_path_profile.escript --self-test">>,
             <<"fresh_build.sh http3">>, <<"hot_path_profile.escript\"">>,
             <<"hot_path_profile.escript --verify">>])),
      control(<<"idle-task-order">>, ".mise.toml",
        <<"idle invalidation precedes build and the supervised workflow">>,
        ordered(task_section(Mise, <<"idle-wakeup">>),
            [<<"performance_idle_runner.escript --invalidate">>,
             <<"fresh_build.sh http3">>, <<"performance_idle_wakeup.sh">>])),
      control(<<"protocol-task-order">>, ".mise.toml",
        <<"protocol invalidation precedes build, controls, run, and verification">>,
        ordered(task_section(Mise, <<"protocol-performance">>),
            [<<"protocol_performance_runner.escript --invalidate">>, <<"fresh_build.sh http">>,
              <<"protocol_performance_test.escript">>, <<"protocol_performance_runner.escript --self-test">>,
              <<"protocol_performance_runner.escript\"">>, <<"protocol_performance_runner.escript --verify">>])),
      control(<<"aggregate-task-order">>, ".mise.toml",
        <<"aggregate invalidation precedes self-test, collection, and verification">>,
        ordered(AggregateTask,
            [<<"performance_audit.escript --invalidate">>,
             <<"performance_audit.escript --self-test">>,
             <<"performance_audit.escript\"">>,
             <<"performance_audit.escript --verify">>])),
      control(<<"source-candidate-performance-set">>, ".mise.toml",
        <<"source candidate runs every performance producer before its aggregate">>,
        ordered(task_section(Mise, <<"source-candidate">>),
            [<<"mise run hot-path-profile">>, <<"mise run idle-wakeup">>,
             <<"mise run benchmark">>, <<"mise run load">>, <<"mise run soak">>,
             <<"mise run protocol-performance">>, <<"mise run performance-audit">>])),
      control(<<"check-contract-wiring">>, ".mise.toml",
        <<"the static contract and its adversarial controls are required by check">>,
        contains(task_section(Mise, <<"check">>), <<"mise run performance-contract-audit">>)
            andalso contains_all(task_section(Mise, <<"performance-contract-audit">>),
                [<<"performance_contract_audit.escript --self-test">>,
                 <<"performance_contract_audit.escript\"">>])),
      control(<<"ci-contract-wiring">>, ".github/workflows/ci.yml",
        <<"PR quality executes check, requires both reports, and always retains exactly both">>,
        contains(QualityJob, <<"run: mise run check">>)
            andalso contains_all(RequiredReportsStep, [<<"if: always()">>, <<"shell: bash">>,
                <<"test -f build/performance/contract-audit.json">>,
                <<"test -f build/performance/contract-audit-self-test.json">>])
            andalso contains_all(PreserveReportsStep, [<<"if: always()">>,
                <<"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a">>,
                <<"if-no-files-found: error">>])
            andalso yaml_performance_paths(PreserveReportsStep) =:= contract_artifacts()),
      control(<<"contract-report-invalidation">>, "scripts/performance_contract_audit.escript",
        <<"the audit invalidates main and self-test reports before evaluating controls">>,
        contains_all(ContractEntry, [<<"main([]) -> guarded(audit, ?OUTPUT">>,
            <<"main([\"--self-test\"]) -> guarded(self_test, ?SELF_TEST_OUTPUT">>])
            andalso contains_all(ContractGuard, [<<"invalidate_prior_reports(Kind, Output)">>,
                <<"invalidate_prior_reports(self_test, Output) ->\n    invalidate(?OUTPUT),\n    invalidate(Output)">>,
                <<"invalidate_prior_reports(audit, Output) -> invalidate(Output)">>])
            andalso contains(ContractGuard, <<"self_test -> try write_report(?OUTPUT">>)),
      control(<<"contract-safe-failure-evidence">>, "scripts/performance_contract_audit.escript",
        <<"internal failure has fixed bounded classification and best-effort source/runtime identity">>,
        contains(ContractPreamble, <<"MAXIMUM_REPORT_BYTES, 4194304">>)
            andalso contains_all(ContractGuard,
                [<<"failure_classification => <<\"performance_contract_audit_internal_failure\">>">>,
                 <<"diagnostic_failure_details(Class, Reason, Stack)">>,
                 <<"source_set_sha256">>, <<"completed_source_files">>,
                 <<"execution_environment">>, <<"tool =>">>])
            andalso contains(ContractBaseReport,
                <<"_ -> <<\"performance_contract_violation\">>">>)),
      control(<<"fixed-failure-invalidation">>, "scripts/performance_runner.escript",
        <<"direct and task runs make every collected fixed artifact harmless before preflight">>,
        ordered(FixedExecute, [<<"execute(Mode) ->">>,
            <<"Stem = \"build/performance/current/\" ++ binary_to_list(Mode)">>,
            <<"ok = invalidate(Stem, Mode)">>, <<"Path = Stem ++ \"-execution.json\"">>,
            <<"Identity = evidence_identity()">>])
            andalso not contains(FixedExecute, <<"evidence_begin(">>)
            andalso contains_all(FixedInvalidator, [<<"Stem ++ \".json\"">>, <<"Stem ++ \".csv\"">>,
            <<"Stem ++ \".log\"">>, <<"Stem ++ \"-execution.json\"">>,
            <<"Stem ++ \"-execution-proof.tar\"">>, <<"Stem ++ \"-host-start.json\"">>,
            <<"Stem ++ \"-host-end.json\"">>, <<"execution_not_completed">>])),
      control(<<"fixed-safe-failure-evidence">>, "scripts/performance_runner.escript",
        <<"child output is bounded, private fields are removed, and reporter runs after failure">>,
        contains_all(FixedRunner, [<<"maps:without([tail, output_sha256], Output)">>,
            <<"write(ChildPath,Safe)">>, <<"diagnostic_failure_details">>])
            andalso contains_all(FixedReporter, [<<"write_emergency_report">>,
                <<"diagnostic_failure_details">>])
            andalso contains_all(FixedRun, [<<"workload_status=$?">>,
                <<"report_status=$?">>, <<"if ((workload_status))">>])),
      control(<<"idle-failure-invalidation">>, "scripts/performance_idle_runner.escript",
        <<"idle primary, typed fixture, log, and execution are invalidated">>,
        contains(IdleRunner, <<"main([\"--invalidate\"])">>)
            andalso ordered(IdleExecute, [<<"execute() ->">>, <<"ok = invalidate(Stem)">>,
                <<"Path = Stem ++ \"-execution.json\"">>, <<"Identity = evidence_identity()">>])
            andalso not contains(IdleExecute, <<"evidence_begin(">>)
            andalso ordered(IdleShell,
                [<<"performance_idle_runner.escript --invalidate">>,
                 <<"performance_idle_wakeup_report.escript --self-test">>,
                 <<"performance_idle_runner.escript --self-test">>,
                 <<"escript scripts/performance_idle_runner.escript\n">>])
            andalso contains_all(IdleInvalidator, [<<"Stem ++ \".json\"">>,
            <<"Stem ++ \".raw.json\"">>, <<"Stem ++ \".log\"">>,
            <<"Stem ++ \"-execution.json\"">>, <<"execution_not_completed">>])),
      control(<<"idle-safe-failure-evidence">>, "scripts/performance_idle_runner.escript",
        <<"idle child and reporter publish only typed bounded failure evidence">>,
        contains_all(IdleRunner, [<<"maps:without([tail, output_sha256], Output)">>,
            <<"write(ChildPath, Safe)">>, <<"diagnostic_failure_details">>])
            andalso contains_all(IdleReporter, [<<"write_emergency_report">>,
                <<"diagnostic_failure_details">>])
            andalso contains_all(IdleShell, [<<"workload_status=$?">>,
                <<"report_status=$?">>, <<"if ((workload_status))">>])),
      control(<<"hot-path-failure-invalidation">>, "scripts/hot_path_profile.erl",
        <<"hot-path JSON and scalar CSV are invalidated before preflight">>,
        contains_all(HotRunner, [<<"run([\"--invalidate\"])">>, <<"invalidate_outputs">>])
            andalso ordered(HotRun, [<<"run([]) ->">>,
                <<"invalidate_outputs(?JSON_REPORT, ?CSV_REPORT)">>,
                <<"Identity = evidence_identity()">>,
                <<"write_reports(#{schema => 2, status => <<\"Failed\">>">>,
                <<"fresh_with_verified_build(\"http3\"">>])
            andalso not contains(HotRun, <<"evidence_begin(">>)
            andalso contains_all(HotInvalidator, [<<"execution_not_completed">>,
                <<"file:write_file(JsonPath">>, <<"file:write_file(CsvPath, hpp_csv_header())">>])),
      control(<<"hot-path-safe-failure-evidence">>, "scripts/hot_path_profile.erl",
        <<"hot-path child output is projected and unexpected failure is preserved safely">>,
        contains_all(HotRunner, [<<"maps:without([tail,output_sha256],Output)">>,
            <<"json:encode(Safe)">>, <<"preserve_execution_failure(Class, Reason, Stacktrace)">>,
            <<"diagnostic_failure_details">>])),
      control(<<"protocol-failure-invalidation">>, "scripts/protocol_performance_runner.escript",
        <<"protocol report is Failed and proof is removed before preflight">>,
        contains_all(ProtocolRunner, [<<"command([\"--invalidate\"])">>,
            <<"ppr_invalidate()">>])
            andalso ordered(ProtocolExecute, [<<"execute() ->">>, <<"ok=ppr_invalidate()">>,
                <<"Identity=evidence_identity()">>])
            andalso not contains(ProtocolExecute, <<"evidence_begin(">>)
            andalso contains_all(ProtocolInvalidator, [<<"execution_not_completed">>,
                <<"file:delete(Proof)">>])),
      control(<<"protocol-safe-failure-evidence">>, "scripts/protocol_performance_runner.escript",
        <<"protocol child output is projected to typed bounded evidence">>,
        contains_all(ProtocolRunner, [<<"maps:without([tail,output_sha256],Output)">>,
            <<"ppr_write(ChildPath,Safe)">>, <<"diagnostic_failure_details">>])),
      control(<<"aggregate-failure-invalidation">>, "scripts/performance_audit.erl",
        <<"aggregate self-test and collection replace prior Ready evidence before work">>,
        contains(PerformanceAudit, <<"main([\"--invalidate\"]) ->">>)
            andalso ordered(AggregateGuard,
                [<<"guarded_self_test() ->">>, <<"invalidate_report()">>, <<"self_test()">>])
            andalso ordered(AggregateRun,
                [<<"run() ->">>, <<"invalidate_report()">>, <<"Identity = evidence_identity()">>,
                 <<"collect_report()">>, <<"write_report(Report)">>])
            andalso not contains_any(AggregateRun, [<<"evidence_begin(">>, <<"case false">>])
            andalso contains_all(AggregateInvalidator,
                [<<"execution_not_completed">>, <<"failure_classification">>,
                 <<"atomic_write_report(Path">>, <<"source_identity_status">>])
            andalso contains_all(AggregateSelfTest,
                [<<"self_test() ->\n    invalidation_self_test(),">>,
                 <<"private-stale-performance-audit-marker">>,
                 <<"filelib:wildcard(Path ++ \".tmp-*\")">>])),
      control(<<"aggregate-safe-failure-evidence">>, "scripts/performance_audit.erl",
        <<"aggregate unexpected failures are typed, bounded, and atomically published">>,
        contains_all(AggregateGuard,
            [<<"preserve_audit_failure(<<\"self_test_failed\">>">>,
             <<"preserve_audit_failure(<<\"collection_failed\">>">>,
             <<"preserve_audit_failure(<<\"verification_failed\">>">>,
             <<"diagnostic_failure_details">>, <<"performance_matrix_incomplete">>])
            andalso contains_all(AggregateWriter,
                [<<"byte_size(Bytes) =< ?MAXIMUM_REPORT_BYTES">>, <<"ok = file:sync(Handle)">>,
                 <<"file:delete(Path)">>, <<"file:rename(Temporary, Path)">>])),
      control(<<"fixed-artifact-contract">>, "scripts/performance_audit.erl",
        <<"fixed producer and aggregate agree on report, CSV/log, hosts, execution, and proof">>,
        fixed_artifact_contract(FixedRunner, FixedReporter, PerformanceAudit)),
      control(<<"idle-artifact-contract">>, "scripts/performance_audit.erl",
        <<"idle producer, reporter, and aggregate use the same four paths">>,
        idle_artifact_contract(IdleRunner, IdleReporter, PerformanceAudit)),
      control(<<"hot-path-artifact-contract">>, "scripts/performance_audit.erl",
        <<"hot-path producer and aggregate use the same JSON and CSV">>,
        hot_artifact_contract(HotRunner, PerformanceAudit)),
      control(<<"protocol-artifact-contract">>, "scripts/performance_audit.erl",
        <<"protocol producer and aggregate use the same report and selected proof">>,
        protocol_artifact_contract(ProtocolExecution, ProtocolRunner, PerformanceAudit)),
      control(<<"nightly-soak-collection">>, ".github/workflows/nightly.yml",
        <<"nightly soak always collects exactly its seven safe public artifacts">>,
        yaml_performance_paths(SoakUploadStep) =:= soak_artifacts()
            andalso contains(SoakUploadStep, <<"if: always()">>)
            andalso contains(SoakUploadStep, <<"if-no-files-found: error">>)),
      control(<<"nightly-protocol-collection">>, ".github/workflows/nightly.yml",
        <<"nightly protocol always collects exactly its report and selected proof">>,
        yaml_performance_paths(ProtocolUploadStep) =:= protocol_artifacts()
            andalso contains(ProtocolUploadStep, <<"if: always()">>)
            andalso contains(ProtocolUploadStep, <<"if-no-files-found: error">>)),
      control(<<"nightly-private-artifact-exclusion">>, ".github/workflows/nightly.yml",
        <<"CI never uploads raw retained runner trees or diagnostic fixtures">>,
        not contains_any(<<SoakUploadStep/binary, ProtocolUploadStep/binary>>,
            [<<"build/performance/runner/">>,
            <<"build/performance/idle-runner/">>, <<"build/performance/hot-path-runner/">>,
            <<"build/performance/protocol-runner/">>, <<"build/diagnostics/">>]))
    ].

fixed_artifact_contract(Runner, Reporter, Audit) ->
    contains_all(Runner, [<<"build/performance/current/">>, <<"-execution.json">>,
        <<"-execution-proof.tar">>, <<"-host-start.json">>, <<"-host-end.json">>,
        <<".log">>])
    andalso contains_all(Reporter, [<<"filename:join(?OUTPUT, Mode ++ \".json\")">>,
        <<"filename:join(?OUTPUT, Mode ++ \".csv\")">>])
    andalso contains_all(Audit, [<<"-execution.json">>, <<"-host-start.json">>,
        <<"-host-end.json">>, <<".log">>, <<"performance_execution_paths">>]).

idle_artifact_contract(Runner, Reporter, Audit) ->
    contains_all(Runner, [<<"build/performance/current/idle-wakeup">>,
        <<".raw.json">>, <<".log">>, <<"-execution.json">>])
    andalso contains_all(Reporter, [<<"build/performance/current/idle-wakeup.json">>,
        <<"build/performance/current/idle-wakeup.raw.json">>,
        <<"build/performance/current/idle-wakeup.log">>])
    andalso contains_all(Audit, [<<"build/performance/current/idle-wakeup.json">>,
        <<"build/performance/current/idle-wakeup.raw.json">>,
        <<"build/performance/current/idle-wakeup.log">>, <<"idw_execution_paths">>]).

hot_artifact_contract(Runner, Audit) ->
    contains_all(Runner, [<<"build/performance/hot-path-profile.json">>,
        <<"build/performance/hot-path-profile.csv">>])
    andalso contains_all(Audit, [<<"build/performance/hot-path-profile.json">>,
        <<"hpp_load_auditor">>]).

protocol_artifact_contract(Execution, Runner, Audit) ->
    contains(Execution, <<"build/performance/current/protocols.json">>)
    andalso contains(Runner, <<"build/performance/current/protocols-execution-proof.tar">>)
    andalso contains_all(Audit, [<<"ppr_verify()">>, <<"ppr_bundle_paths()">>]).

adversarial_cases() ->
    [
      {<<"reject-supervisor-expansion">>, <<"supervisor-input-maximum">>,
       "scripts/process_runner.hrl", <<"Milliseconds =< 5400000">>, <<"Milliseconds =< 5400001">>},
      {<<"reject-fixed-expansion">>, <<"fixed-deadline-set">>,
       "scripts/performance_execution.hrl", <<"performance_deadline(<<\"benchmark\">>) -> 5400000">>,
       <<"performance_deadline(<<\"benchmark\">>) -> 5400001">>},
      {<<"reject-missing-fixed-mode">>, <<"fixed-deadline-set">>,
       "scripts/performance_execution.hrl", <<"performance_deadline(<<\"soak\">>)">>,
       <<"performance_deadline(<<\"other\">>)">>},
      {<<"reject-idle-expansion">>, <<"idle-deadline">>,
       "scripts/performance_idle_execution.hrl", <<"idw_deadline() -> 60000">>, <<"idw_deadline() -> 5400001">>},
      {<<"reject-hot-profile-drift">>, <<"hot-path-deadline">>,
       "standards/performance-profile.json", <<"\"timeout_milliseconds\": 120000">>,
       <<"\"timeout_milliseconds\": 120001">>},
      {<<"reject-protocol-expansion">>, <<"protocol-deadline">>,
       "scripts/protocol_performance_execution.hrl", <<"ppr_deadline() -> 300000">>, <<"ppr_deadline() -> 5400001">>},
      {<<"reject-fixed-direct-invalidation-comment">>, <<"fixed-failure-invalidation">>,
       "scripts/performance_runner.escript", <<"    ok = invalidate(Stem, Mode),">>,
       <<"    % ok = invalidate(Stem, Mode),">>},
      {<<"reject-idle-direct-invalidation-comment">>, <<"idle-failure-invalidation">>,
       "scripts/performance_idle_runner.escript",
       <<"execute() ->\n    Stem = \"build/performance/current/idle-wakeup\",\n    ok = invalidate(Stem),">>,
       <<"execute() ->\n    Stem = \"build/performance/current/idle-wakeup\",\n    % ok = invalidate(Stem),">>},
      {<<"reject-idle-shell-invalidation-comment">>, <<"idle-failure-invalidation">>,
       "scripts/performance_idle_wakeup.sh",
       <<"escript scripts/performance_idle_runner.escript --invalidate">>,
       <<"# escript scripts/performance_idle_runner.escript --invalidate">>},
      {<<"reject-hot-direct-invalidation-loss">>, <<"hot-path-failure-invalidation">>,
       "scripts/hot_path_profile.erl",
       <<"run([]) ->\n    ok = invalidate_outputs(?JSON_REPORT, ?CSV_REPORT),">>,
       <<"run([]) ->\n    ok = discard_outputs(?JSON_REPORT, ?CSV_REPORT),">>},
      {<<"reject-protocol-direct-invalidation-comment">>, <<"protocol-failure-invalidation">>,
       "scripts/protocol_performance_runner.escript",
       <<"execute() ->\n    ok=ppr_invalidate(),">>,
       <<"execute() ->\n    % ok=ppr_invalidate(),">>},
      {<<"reject-fixed-identity-deletes-failure">>, <<"fixed-failure-invalidation">>,
       "scripts/performance_runner.escript", <<"    Identity = evidence_identity(),">>,
       <<"    Identity = evidence_begin(Path),">>},
      {<<"reject-idle-identity-deletes-failure">>, <<"idle-failure-invalidation">>,
       "scripts/performance_idle_runner.escript", <<"Identity = evidence_identity(),">>,
       <<"Identity = evidence_begin(Path),">>},
      {<<"reject-hot-identity-deletes-failure">>, <<"hot-path-failure-invalidation">>,
       "scripts/hot_path_profile.erl", <<"    Identity = evidence_identity(),">>,
       <<"    Identity = evidence_begin(?JSON_REPORT),">>},
      {<<"reject-protocol-identity-deletes-failure">>, <<"protocol-failure-invalidation">>,
       "scripts/protocol_performance_runner.escript", <<"Identity=evidence_identity(),">>,
       <<"Identity=evidence_begin(Path),">>},
      {<<"reject-aggregate-invalidation-comment">>, <<"aggregate-failure-invalidation">>,
       "scripts/performance_audit.erl",
       <<"run() ->\n    ok = invalidate_report(),">>,
       <<"run() ->\n    % ok = invalidate_report(),">>},
      {<<"reject-aggregate-invalidation-dead-code">>, <<"aggregate-failure-invalidation">>,
       "scripts/performance_audit.erl",
       <<"run() ->\n    ok = invalidate_report(),">>,
       <<"run() ->\n    case false of true -> ok = invalidate_report(); false -> ok end,">>},
      {<<"reject-aggregate-self-test-invalidation-loss">>, <<"aggregate-failure-invalidation">>,
       "scripts/performance_audit.erl",
       <<"self_test() ->\n    invalidation_self_test(),">>,
       <<"self_test() ->\n    skipped_invalidation_self_test(),">>},
      {<<"reject-aggregate-safe-failure-comment">>, <<"aggregate-safe-failure-evidence">>,
       "scripts/performance_audit.erl",
       <<"            _ = preserve_audit_failure(<<\"collection_failed\">>">>,
       <<"            % _ = preserve_audit_failure(<<\"collection_failed\">>">>},
      {<<"reject-aggregate-atomic-sync-loss">>, <<"aggregate-safe-failure-evidence">>,
       "scripts/performance_audit.erl", <<"            ok = file:sync(Handle)">>,
       <<"            skipped = file:sync(Handle)">>},
      {<<"reject-fixed-stale-csv">>, <<"fixed-failure-invalidation">>,
       "scripts/performance_runner.escript",
       <<"lists:foreach(fun(Path) -> ok = file:write_file(Path, <<>>) end,\n        [Stem ++ \".csv\"">>,
       <<"lists:foreach(fun(Path) -> ok = file:write_file(Path, <<>>) end,\n        [Stem ++ \".stale-csv\"">>},
      {<<"reject-fixed-stale-host">>, <<"fixed-failure-invalidation">>,
       "scripts/performance_runner.escript",
       <<"Stem ++ \".log\", Stem ++ \"-host-start.json\",\n         Stem ++ \"-host-end.json\"]),\n    case file:delete">>,
       <<"Stem ++ \".log\", Stem ++ \"-stale-host.json\",\n         Stem ++ \"-host-end.json\"]),\n    case file:delete">>},
      {<<"reject-fixed-order-drift">>, <<"fixed-task-order">>,
       "scripts/performance_run.sh",
       <<"escript scripts/performance_runner.escript --invalidate \"$mode\"\nescript scripts/performance_runner.escript --self-test">>,
       <<"escript scripts/performance_runner.escript --self-test\nescript scripts/performance_runner.escript --invalidate \"$mode\"">>},
      {<<"reject-hot-order-drift">>, <<"hot-path-task-order">>,
       ".mise.toml",
       <<"  \"escript scripts/hot_path_profile.escript --invalidate\",\n  \"escript scripts/hot_path_profile.escript --self-test\",">>,
       <<"  \"escript scripts/hot_path_profile.escript --self-test\",\n  \"escript scripts/hot_path_profile.escript --invalidate\",">>},
      {<<"reject-idle-order-drift">>, <<"idle-task-order">>,
       ".mise.toml",
       <<"  \"escript scripts/performance_idle_runner.escript --invalidate\",\n  \"bash scripts/fresh_build.sh http3\",">>,
       <<"  \"bash scripts/fresh_build.sh http3\",\n  \"escript scripts/performance_idle_runner.escript --invalidate\",">>},
      {<<"reject-protocol-order-drift">>, <<"protocol-task-order">>,
       ".mise.toml",
       <<"  \"escript scripts/protocol_performance_runner.escript --invalidate\",\n  \"bash scripts/fresh_build.sh http\",">>,
       <<"  \"bash scripts/fresh_build.sh http\",\n  \"escript scripts/protocol_performance_runner.escript --invalidate\",">>},
      {<<"reject-aggregate-order-drift">>, <<"aggregate-task-order">>,
       ".mise.toml",
       <<"  \"escript scripts/performance_audit.escript --invalidate\",\n  \"escript scripts/performance_audit.escript --self-test\",">>,
       <<"  \"escript scripts/performance_audit.escript --self-test\",\n  \"escript scripts/performance_audit.escript --invalidate\",">>},
      {<<"reject-fixed-private-tail">>, <<"fixed-safe-failure-evidence">>,
       "scripts/performance_runner.escript", <<"maps:without([tail, output_sha256], Output)">>,
       <<"maps:without([output_sha256], Output)">>},
      {<<"reject-idle-private-tail">>, <<"idle-safe-failure-evidence">>,
       "scripts/performance_idle_runner.escript", <<"maps:without([tail, output_sha256], Output)">>,
       <<"maps:without([output_sha256], Output)">>},
      {<<"reject-hot-private-tail">>, <<"hot-path-safe-failure-evidence">>,
       "scripts/hot_path_profile.erl", <<"maps:without([tail,output_sha256],Output)">>,
       <<"maps:without([output_sha256],Output)">>},
      {<<"reject-protocol-private-tail">>, <<"protocol-safe-failure-evidence">>,
       "scripts/protocol_performance_runner.escript", <<"maps:without([tail,output_sha256],Output)">>,
       <<"maps:without([output_sha256],Output)">>},
      {<<"reject-missing-check-gate">>, <<"check-contract-wiring">>,
       ".mise.toml", <<"  \"mise run performance-contract-audit\",">>, <<"  \"mise run removed-contract-audit\",">>},
      {<<"reject-missing-source-mode">>, <<"source-candidate-performance-set">>,
       ".mise.toml", <<"  \"mise run load\",">>, <<"  \"mise run removed-load\",">>},
      {<<"reject-source-aggregate-reorder">>, <<"source-candidate-performance-set">>,
       ".mise.toml",
       <<"  \"mise run protocol-performance\",\n  \"mise run performance-audit\",">>,
       <<"  \"mise run performance-audit\",\n  \"mise run protocol-performance\",">>},
      {<<"reject-ci-bypass">>, <<"ci-contract-wiring">>,
       ".github/workflows/ci.yml", <<"run: mise run check">>, <<"run: mise run unchecked">>},
      {<<"reject-ci-missing-self-test-report">>, <<"ci-contract-wiring">>,
       ".github/workflows/ci.yml",
       <<"test -f build/performance/contract-audit-self-test.json">>,
       <<"test -f build/performance/missing-contract-audit-self-test.json">>},
      {<<"reject-ci-require-step-skip">>, <<"ci-contract-wiring">>,
       ".github/workflows/ci.yml",
       <<"      - name: Require both performance contract reports\n        if: always()">>,
       <<"      - name: Require both performance contract reports\n        if: success()">>},
      {<<"reject-ci-upload-step-skip">>, <<"ci-contract-wiring">>,
       ".github/workflows/ci.yml",
       <<"      - name: Preserve performance contract audit on success and failure\n        if: always()">>,
       <<"      - name: Preserve performance contract audit on success and failure\n        if: success()">>},
      {<<"reject-ci-upload-missing-self-test">>, <<"ci-contract-wiring">>,
       ".github/workflows/ci.yml",
       <<"            build/performance/contract-audit-self-test.json">>,
       <<"            build/performance/missing-contract-audit-self-test.json">>},
      {<<"reject-soak-collection-drift">>, <<"nightly-soak-collection">>,
       ".github/workflows/nightly.yml", <<"build/performance/current/soak.csv">>,
       <<"build/performance/current/private-performance-contract-marker">>},
      {<<"reject-protocol-collection-drift">>, <<"nightly-protocol-collection">>,
       ".github/workflows/nightly.yml", <<"build/performance/current/protocols-execution-proof.tar">>,
       <<"build/performance/current/protocols-proof-wrong.tar">>},
      {<<"reject-protocol-upload-skip">>, <<"nightly-protocol-collection">>,
       ".github/workflows/nightly.yml",
       <<"      - name: Upload bounded execution evidence\n        if: always()">>,
       <<"      - name: Upload bounded execution evidence\n        if: success()">>},
      {<<"reject-soak-upload-skip">>, <<"nightly-soak-collection">>,
       ".github/workflows/nightly.yml",
       <<"      - name: Upload soak evidence\n        if: always()">>,
       <<"      - name: Upload soak evidence\n        if: success()">>},
      {<<"reject-protocol-short-job">>, <<"protocol-ci-envelope">>,
       ".github/workflows/nightly.yml",
       <<"  protocol-performance:\n    name: Public H1/H2/H3 workload (informational timing)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30">>,
       <<"  protocol-performance:\n    name: Public H1/H2/H3 workload (informational timing)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10">>},
      {<<"reject-private-runner-upload">>, <<"nightly-private-artifact-exclusion">>,
       ".github/workflows/nightly.yml", <<"            build/performance/current/soak.json">>,
       <<"            build/performance/current/soak.json\n            build/performance/runner/">>},
      {<<"reject-hot-failure-loss">>, <<"hot-path-safe-failure-evidence">>,
       "scripts/hot_path_profile.erl", <<"preserve_execution_failure(Class, Reason, Stacktrace)">>,
       <<"discard_execution_failure(Class, Reason, Stacktrace)">>},
      {<<"reject-idle-reporter-skip">>, <<"idle-safe-failure-evidence">>,
       "scripts/performance_idle_wakeup.sh", <<"report_status=$?">>, <<"report_was_skipped=1">>},
      {<<"reject-erlang-comment-only-evidence">>, <<"fixed-safe-failure-evidence">>,
       "scripts/performance_runner.escript",
       <<"        process => maps:without([tail, output_sha256], Output)}, Csv}.">>,
       <<"        % process => maps:without([tail, output_sha256], Output)}, Csv}.">>},
      {<<"reject-shell-comment-only-evidence">>, <<"idle-safe-failure-evidence">>,
       "scripts/performance_idle_wakeup.sh", <<"report_status=$?">>, <<"# report_status=$?">>},
      {<<"reject-contract-invalidation-bypass">>, <<"contract-report-invalidation">>,
       "scripts/performance_contract_audit.escript",
       contract_invalidation_before(), contract_invalidation_after()},
      {<<"reject-contract-classification-drift">>, <<"contract-safe-failure-evidence">>,
       "scripts/performance_contract_audit.escript",
       contract_classification_before(), contract_classification_after()},
      {<<"reject-contract-violation-classification-drift">>, <<"contract-safe-failure-evidence">>,
       "scripts/performance_contract_audit.escript",
       contract_violation_before(), contract_violation_after()},
      {<<"reject-contract-report-expansion">>, <<"contract-safe-failure-evidence">>,
       "scripts/performance_contract_audit.escript",
       contract_report_limit_before(), contract_report_limit_after()}
    ].

%% Self-mutation fixtures are assembled from fragments. Keeping the complete
%% production sequence out of this fixture section makes uniqueness meaningful.
contract_invalidation_before() -> iolist_to_binary([
    <<"    try\n        invalidate_prior_reports">>, <<"(Kind, Output),\n        Function()">>]).
contract_invalidation_after() -> iolist_to_binary([
    <<"    try\n        % invalidate_prior_reports">>, <<"(Kind, Output),\n        Function()">>]).

contract_classification_before() -> iolist_to_binary([
    <<"            failure_classification => <<\"performance_contract_">>,
    <<"audit_internal_failure\">>,\n            failure => diagnostic_failure_details">>]).
contract_classification_after() -> iolist_to_binary([
    <<"            failure_classification => <<\"unclassified\">>,\n">>,
    <<"            failure => diagnostic_failure_details">>]).

contract_violation_before() -> iolist_to_binary([
    <<"        _ -> <<\"performance_contract_">>, <<"violation\">>\n    end,">>]).
contract_violation_after() -> iolist_to_binary([
    <<"        _ -> <<\"unclassified\">>\n">>, <<"    end,">>]).

contract_report_limit_before() -> iolist_to_binary([
    <<"-define(MAXIMUM_REPORT_BYTES, ">>, <<"4194304).\n-define(SUPERVISOR_MAXIMUM_MS">>]).
contract_report_limit_after() -> iolist_to_binary([
    <<"-define(MAXIMUM_REPORT_BYTES, ">>, <<"4194305).\n-define(SUPERVISOR_MAXIMUM_MS">>]).

adversarial_case(Sources, {Id, ExpectedControl, Path, Before, After}) ->
    Mutated = mutate_source(Sources, Path, Before, After),
    Controls = contract_controls(Mutated),
    Passed = case [maps:get(passed, Row) || Row <- Controls,
        maps:get(id, Row) =:= ExpectedControl] of [false] -> true; _ -> false end,
    #{id => Id, path => list_to_binary(Path), expected_control => ExpectedControl,
      passed => Passed}.

mutate_source(Sources, Path, Before, After) ->
    Original = source(Sources, Path),
    case binary:matches(Original, Before) of
        [_] -> maps:put(Path, binary:replace(Original, Before, After), Sources);
        _ -> erlang:error(adversarial_fixture_drift)
    end.

fixed_deadlines(Source) ->
    case re:run(Source,
        <<"performance_deadline\\(<<\"([^\"]+)\">>\\)\\s*->\\s*([0-9]+)">>,
        [global, {capture, [1,2], binary}]) of
        {match, Captures} -> [{Mode, binary_to_integer(Value)} || [Mode,Value] <- Captures];
        nomatch -> []
    end.

scalar_deadline(Source, Pattern) ->
    case capture_integers(Source, Pattern) of [Value] -> Value; _ -> -1 end.

capture_integers(Source, Pattern) ->
    case re:run(Source, Pattern, [global, {capture, [1], binary}]) of
        {match, Captures} -> [binary_to_integer(Value) || [Value] <- Captures];
        nomatch -> []
    end.

deadline_values_valid(Values) ->
    Values =/= [] andalso lists:all(fun(Value) -> is_integer(Value) andalso
        Value > 0 andalso Value =< ?SUPERVISOR_MAXIMUM_MS end, Values).

deadline_for(Mode, Pairs) ->
    case [Value || {Candidate,Value} <- Pairs, Candidate =:= Mode] of
        [Value] -> Value;
        _ -> ?SUPERVISOR_MAXIMUM_MS + 1
    end.

performance_profile(Bytes) ->
    try evidence_json_decode(Bytes) of Value when is_map(Value) -> Value
    catch _:_ -> #{} end.

task_section(Source, Name) ->
    section(Source, <<"[tasks.", Name/binary, "]">>, <<"\n[">>).

yaml_job(Source, Name) ->
    Header = <<"\n  ", Name/binary, ":\n">>,
    case binary:match(Source, Header) of
        {Start, Length} ->
            Offset = Start + Length,
            Rest = binary:part(Source, Offset, byte_size(Source) - Offset),
            case re:run(Rest, <<"\\n  [A-Za-z0-9][A-Za-z0-9_-]*:\\n">>,
                    [{capture, first, index}]) of
                {match, [{Finish, _}]} -> binary:part(Rest, 0, Finish);
                nomatch -> Rest
            end;
        nomatch -> <<>>
    end.

yaml_step(Source, Name) ->
    Header = <<"\n      - name: ", Name/binary, "\n">>,
    case binary:match(Source, Header) of
        {Start, Length} ->
            Offset = Start + Length,
            Rest = binary:part(Source, Offset, byte_size(Source) - Offset),
            case re:run(Rest, <<"\n      - name: [^\n]+\n">>,
                    [{capture, first, index}]) of
                {match, [{Finish, _}]} -> binary:part(Rest, 0, Finish);
                nomatch -> Rest
            end;
        nomatch -> <<>>
    end.

section(Source, Header, NextPrefix) ->
    case binary:match(Source, Header) of
        {Start, Length} ->
            Offset = Start + Length,
            Rest = binary:part(Source, Offset, byte_size(Source) - Offset),
            case binary:match(Rest, NextPrefix) of
                {Finish, _} -> binary:part(Rest, 0, Finish);
                nomatch -> Rest
            end;
        nomatch -> <<>>
    end.

between(Source, StartNeedle, EndNeedle) ->
    case binary:match(Source, StartNeedle) of
        {Start, _} ->
            Rest = binary:part(Source, Start, byte_size(Source) - Start),
            case binary:match(Rest, EndNeedle) of
                {Finish, _} -> binary:part(Rest, 0, Finish);
                nomatch -> <<>>
            end;
        nomatch -> <<>>
    end.

yaml_timeout(Job) ->
    scalar_deadline(Job, <<"timeout-minutes:\\s*([0-9]+)">>).

yaml_performance_paths(Job) ->
    Lines = binary:split(Job, <<"\n">>, [global]),
    [Trimmed || Line <- Lines,
        Trimmed <- [unicode:characters_to_binary(string:trim(binary_to_list(Line)))],
        binary:match(Trimmed, <<"build/performance/">>) =:= {0,18}].

erlang_active(Source) -> strip_inline_comments(Source, <<"%">>).
shell_active(Source) -> strip_inline_comments(Source, <<"#">>).

strip_inline_comments(Source, Marker) ->
    Lines = binary:split(Source, <<"\n">>, [global]),
    iolist_to_binary(lists:join(<<"\n">>,
        [strip_inline_comment(Line, Marker) || Line <- Lines])).

strip_inline_comment(Line, Marker) ->
    case binary:match(Line, Marker) of
        {Position, _} -> binary:part(Line, 0, Position);
        nomatch -> Line
    end.

configuration_active(Source) ->
    Lines = binary:split(Source, <<"\n">>, [global]),
    iolist_to_binary(lists:join(<<"\n">>,
        [configuration_line(Line) || Line <- Lines])).

configuration_line(Line) ->
    Trimmed = unicode:characters_to_binary(string:trim(binary_to_list(Line), leading)),
    case Trimmed of <<"#", _/binary>> -> <<>>; _ -> Line end.

contract_artifacts() ->
    [<<"build/performance/contract-audit.json">>,
     <<"build/performance/contract-audit-self-test.json">>].

soak_artifacts() ->
    [<<"build/performance/current/soak.json">>,
     <<"build/performance/current/soak.csv">>,
     <<"build/performance/current/soak.log">>,
     <<"build/performance/current/soak-execution.json">>,
     <<"build/performance/current/soak-execution-proof.tar">>,
     <<"build/performance/current/soak-host-start.json">>,
     <<"build/performance/current/soak-host-end.json">>].

protocol_artifacts() ->
    [<<"build/performance/current/protocols.json">>,
     <<"build/performance/current/protocols-execution-proof.tar">>].

ordered(Source, Needles) -> ordered(Source, Needles, -1).
ordered(_Source, [], _Previous) -> true;
ordered(Source, [Needle|Rest], Previous) ->
    Offset = Previous + 1,
    Search = binary:part(Source, Offset, byte_size(Source) - Offset),
    case binary:match(Search, Needle) of
        {Relative, _} -> ordered(Source, Rest, Offset + Relative);
        _ -> false
    end.

contains(Source, Needle) -> binary:match(Source, Needle) =/= nomatch.
contains_all(Source, Needles) -> lists:all(fun(Needle) -> contains(Source, Needle) end, Needles).
contains_any(Source, Needles) -> lists:any(fun(Needle) -> contains(Source, Needle) end, Needles).

control(Id, Path, Rule, Passed) ->
    #{id => Id, path => list_to_binary(Path), rule => Rule, passed => Passed}.

source(Sources, Path) -> maps:get(Path, Sources, <<>>).

source_paths() ->
    [".mise.toml", ".github/workflows/ci.yml", ".github/workflows/nightly.yml",
     "standards/performance-profile.json", "scripts/process_runner.hrl",
     "scripts/performance_contract_audit.escript",
     "scripts/performance_execution.hrl", "scripts/performance_runner.escript",
     "scripts/performance_run.sh", "scripts/performance_run_report.escript",
     "scripts/performance_idle_execution.hrl", "scripts/performance_idle_runner.escript",
     "scripts/performance_idle_wakeup.sh", "scripts/performance_idle_wakeup_report.escript",
     "scripts/hot_path_evidence.hrl", "scripts/hot_path_profile.erl",
     "scripts/protocol_performance_execution.hrl", "scripts/protocol_performance_runner.escript",
     "scripts/performance_audit.erl", "docs/TESTING.md", "docs/PROTOCOL_PERFORMANCE.md"].

read_sources() ->
    Pairs = [{Path, bounded_read(Path)} || Path <- source_paths()],
    Total = lists:sum([byte_size(Bytes) || {_,Bytes} <- Pairs]),
    true = Total =< ?MAXIMUM_TOTAL_BYTES,
    maps:from_list(Pairs).

bounded_read(Path) ->
    case file:open(Path, [read,binary,raw]) of
        {ok, Handle} ->
            try
                Bytes = case file:read(Handle, ?MAXIMUM_SOURCE_BYTES + 1) of
                    {ok, Value} -> Value; eof -> <<>>
                end,
                true = byte_size(Bytes) =< ?MAXIMUM_SOURCE_BYTES,
                eof = file:read(Handle, 1), Bytes
            after file:close(Handle) end;
        _ -> erlang:error(required_performance_contract_source_unavailable)
    end.

source_digest(Sources) ->
    file_identity_digest(source_paths(), fun(Path) -> maps:get(Path, Sources) end, lowercase).

source_identity(Path, Bytes) ->
    #{path => list_to_binary(Path), bytes => byte_size(Bytes),
      sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase)}.

rerun_command(audit) -> <<"escript scripts/performance_contract_audit.escript">>;
rerun_command(self_test) -> <<"escript scripts/performance_contract_audit.escript --self-test">>.

invalidate(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        _ -> erlang:error(cannot_invalidate_prior_performance_contract_report)
    end.

write_report(Path, Report) ->
    ok = filelib:ensure_dir(Path),
    Bytes = iolist_to_binary([json:encode(Report), $\n]),
    true = byte_size(Bytes) =< ?MAXIMUM_REPORT_BYTES,
    Temporary = Path ++ ".tmp-" ++ binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    try
        ok = file:write_file(Temporary, Bytes, [exclusive]),
        ok = file:rename(Temporary, Path)
    after
        case file:delete(Temporary) of ok -> ok; {error,enoent} -> ok; _ -> ok end
    end.
