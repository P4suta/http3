#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("interop_evidence.hrl").
-include("campaign_evidence.hrl").
-include("campaign_audit_tests.hrl").
-include("examples_evidence.hrl").
-include("runtime_matrix_evidence.hrl").
-include("credential_evidence.hrl").
-include("http_model_evidence.hrl").
-include("fault_evidence.hrl").
-include("performance_verifier.hrl").
-include("hot_path_verifier.hrl").
-include("release_evidence.hrl").
-include("bundle_capture.hrl").
-include("bundle_capture_tests.hrl").
-include("coverage_report_evidence_tests.hrl").
-compile({nowarn_unused_function, [{interop_native_build, 1},
                                  {release_safe_compile_child, 3}, {release_safe_compile_child, 4}]}).

-define(OUTPUT, "build/audit-bundle").
-define(COVERAGE_POLICY, "coverage-policy.json").
-define(COVERAGE_EVIDENCE, "coverage-evidence.json").
-define(QPACK_DIRECTORY, "build/qpack-differential").
-define(QPACK_MAX_BYTES, 2097152).
-define(QPACK_LOCK_SUFFIX, ".qpack-lock").

main([]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "audit bundle failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end;
main(["--self-test"]) ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "audit bundle self-test failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end;
main(["--verify-report", Path]) ->
    try verify_report(Path) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "qualification report verification failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end;
main(["--qpack-self-test"]) ->
    try qpack_audit_self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "QPACK audit self-test failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end;
main(_) -> erlang:error(audit_bundle_usage).

run() ->
    Identity = evidence_begin(filename:join(?OUTPUT, "manifest.json")),
    invalidate_archive_report(),
    Directory = filename:join(?OUTPUT, "run-" ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16)))),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    try run_capture(Directory, Identity)
    catch Class:Reason:Stack ->
        Failure = #{schema => 2, status => <<"Failed">>,
                    failure => diagnostic_failure_details(Class, Reason, Stack)},
        write_json(filename:join(Directory, "failure.json"), Failure),
        write_json(filename:join(?OUTPUT, "manifest.json"), Failure),
        erlang:raise(Class, Reason, Stack)
    end.

run_capture(Directory, Identity) ->
    %% Discovery is provisional. Every gate and the selected path set are
    %% validated again against the captured mirror before publishing anything.
    Files = validated_evidence_files(),
    Captured = bundle_capture(lists:usort(Files ++ bundle_context_paths())),
    Mirror = filename:join(Directory, "captured"),
    ok = bundle_materialize(Mirror, Captured),
    ok = bundle_validate_capture(Mirror, Captured, fun() ->
        evidence_require_identity(#{<<"evidence_identity">> => Identity}, evidence_identity()),
        ensure(validated_evidence_files() =:= Files, changed_evidence_selection)
    end),
    ok = qpack_audit_validate_captured_inputs(Captured),
    Selected = [{Path, Bytes} || {Path, Bytes} <- Captured, lists:member(Path, Files)],
    ok = require_shareable_bundle_artifacts(Selected),
    Manifest = evidence_complete(#{schema => 2, status => <<"Ready">>,
                 qualification_date => audit_execution_date(),
                 source_sha256 => maps:get(<<"source_sha256">>, Identity),
                 capture => #{limits => bundle_limits(), context_files => length(Captured),
                              validated_captured_bytes => true},
                 files => bundle_entries(Selected),
                 external_conditions => #{independent_audit => false, signed_commit => false}}, Identity),
    ManifestBytes = iolist_to_binary([json:encode(Manifest), <<"\n">>]),
    BundleFiles = lists:keysort(1, [{"audit-manifest.json", ManifestBytes} | Selected]),
    Archive = filename:join(Directory, "audit-bundle.tar"),
    ArchiveBytes = bundle_archive(Archive, BundleFiles),
    %% Source edits during archive construction also invalidate this run.
    _ = evidence_complete(#{}, Identity),
    ok = qpack_audit_validate_captured_inputs(Captured),
    ArchiveReport = #{schema => 2, status => <<"Ready">>,
        sha256 => hex(crypto:hash(sha256, ArchiveBytes)), bytes => byte_size(ArchiveBytes),
        files => length(BundleFiles), manifest_sha256 => hex(crypto:hash(sha256, ManifestBytes)),
        evidence_identity => Identity},
    ok = file:write_file(filename:join(Directory, "manifest.json"), ManifestBytes, [exclusive]),
    write_json(filename:join(Directory, "archive.json"), ArchiveReport),
    %% Stable entrypoints are published last; failed runs retain their own
    %% inputs and never destroy the preceding nonce directory.
    ok = file:write_file(filename:join(?OUTPUT, "audit-bundle.tar"), ArchiveBytes),
    write_json(filename:join(?OUTPUT, "archive.json"), ArchiveReport),
    ok = file:write_file(filename:join(?OUTPUT, "manifest.json"), ManifestBytes),
    io:format("audit bundle: ~B evidence files, sha256 ~s~n",
              [length(BundleFiles), maps:get(sha256, ArchiveReport)]),
    ok.

validated_evidence_files() ->
    Static = static_evidence(),
    ReadyReports = ready_reports(),
    TestMatrixSource = test_matrix_source_digest(),
    lists:foreach(
      fun(Path) -> require_ready_report(Path, TestMatrixSource) end,
      ReadyReports),
    Families = family_evidence(),
    audit_model_family(proplists:get_value(model, Families, [])),
    lists:foreach(fun({Label, Paths}) ->
        ensure(Paths =/= [], {missing_evidence_family, Label})
    end, Families),
    Files = lists:usort(Static ++ ReadyReports ++
                        lists:append([Paths || {_Label, Paths} <- Families])),
    lists:foreach(fun(Path) ->
        ensure(filelib:is_regular(Path), {missing_audit_evidence, Path})
    end, Files),
    Files.

bundle_context_paths() ->
    lists:usort(evidence_source_paths() ++ examples_markdown_files() ++
        [examples_normalise(Path) || Target <- ["core", "http3", "http"],
            Path <- [fresh_manifest_path(Target) | fresh_artifact_paths(Target, fresh_packages(Target))]] ++
        lists:append([bundle_tree(filename:join("build/dev/erlang", Name)) ||
            Name <- ["gleam_stdlib", "gleam_erlang", "gleam_http"]])).

static_evidence() ->
    coverage_report_process_files(<<"full">>) ++ coverage_report_process_files(<<"changed">>) ++
    ["qualification.json", ?COVERAGE_POLICY, ?COVERAGE_EVIDENCE,
     "docs/V1.md", "docs/CONFORMANCE.md",
     "docs/SECURITY_REVIEW.md", "docs/ARCHITECTURE.md", "docs/TESTING.md",
     "SECURITY.md", "api/http.snapshot", "api/http3.snapshot",
     "api/quic_core.snapshot", "api/boundary.allow",
     "standards/requirements.json", "standards/qlog-profile.json",
     "standards/structured-fields-oracle.json",
     "build/http-package-interface.json",
     "packages/http3/build/http3-package-interface.json",
     "packages/quic_core/build/quic-core-package-interface.json",
     "build/security/http.cdx.json"].

ready_reports() ->
    ["build/coverage/changed.json", "build/coverage/full.json",
     "build/campaign/property.json", "build/campaign/fuzz.json",
     "build/http-model/result.json",
     "build/campaign/aggregates/property.json",
     "build/campaign/aggregates/fuzz.json",
     "build/campaign/aggregates/model.json",
     "build/fault/hostile-peer.json",
     "build/fault/stability.json",
     "build/credential-matrix/report.json",
     "build/runtime-matrix/report.json",
     "build/requirements/report.json", "build/qlog/report.json",
     "build/structured-fields-oracle/report.json",
     "build/qpack-differential/report.json",
     "build/examples/report.json", "build/release-sim/report.json",
     "build/interop/report.json", "build/performance/report.json",
     "build/performance/hot-path-profile.json"].

family_evidence() ->
    [
        {model, filelib:wildcard("build/model/shard-*.json")},
        {documented_examples, examples_bundle_paths()},
        {runtime_matrix, lists:append([
            tuple_to_list(runtime_matrix_paths(Row)) || Row <- runtime_matrix_expected()])},
        {million_case_campaigns,
         filelib:wildcard("build/campaign/property/shard-*.json") ++
         filelib:wildcard("build/campaign/fuzz/shard-*.json")},
        {release_execution, release_bundle_paths()},
        {performance,
         lists:append([["build/performance/current/" ++ Mode ++ Suffix
                        || Suffix <- [".json", ".csv", ".log", "-execution.json",
                                      "-host-start.json", "-host-end.json"]]
                       || Mode <- ["benchmark", "load", "soak"]]) ++
         ["build/performance/current/idle-wakeup.json",
          "build/performance/current/protocols.json",
          "build/performance/current/idle-wakeup-execution.json",
          "build/performance/current/idle-wakeup.raw.json",
          "build/performance/current/idle-wakeup.log",
          "build/performance/hot-path-profile.csv"] ++ performance_child_artifacts()},
        {coverage_captures,
         filelib:wildcard("build/coverage/*.capture.json") ++
         filelib:wildcard("build/coverage/*.cover")},
        {qpack_differential, qpack_evidence_paths()},
        {interoperability,
         filelib:wildcard("build/interop/*.json") ++
         filelib:wildcard("build/interop/peers/*.json") ++
         filelib:wildcard("build/interop/manifests/*.json") ++ interop_retained_files()}
    ].

%% Fixed paths are required even when an omitted artifact would disappear from
%% a wildcard. Retained Go binaries let the reader independently inspect their
%% embedded build information and bind it to the build receipt and source.
interop_retained_files() ->
    ["build/interop/go-build/" ++ Peer ++ Suffix ||
        Peer <- ["quic-go-h3", "ohttp-go", "masque-independent"],
        Suffix <- [".json", "-attempt.json"]] ++
    ["build/interop/bin/" ++ Name || Name <- ["quic-go", "ohttp-go", "masque-go"]] ++
    ["build/interop/native/masque-independent/" ++ Role ++ ".json" ||
        Role <- ["client", "proxy"]] ++ interop_browser_retained_files().

performance_child_artifacts() ->
    performance_load_auditor(), hpp_load_auditor(),
    performance_audit:bundle_paths() ++ hot_path_profile:bundle_paths().

require_ready_report(Path, TestMatrixSource) ->
    ensure(filelib:is_regular(Path), {missing_ready_report, Path}),
    Report = evidence_json_decode(read(Path)),
    evidence_require_identity(Report, evidence_identity()),
    audit_ready_report(Path, Report, TestMatrixSource),
    case Path of
        "build/fault/hostile-peer.json" -> fault_verify_report(hostile, Report);
        "build/fault/stability.json" -> fault_verify_report(stability, Report);
        _ -> ok
    end.

audit_ready_report(Path, Report, TestMatrixSource) ->
    ensure(maps:get(<<"status">>, Report, undefined) =:= <<"Ready">>,
           {gate_not_ready, Path, maps:get(<<"status">>, Report, undefined)}),
    case test_matrix_report(Path) of
        true ->
            ensure(maps:get(<<"source_sha256">>, Report, undefined)
                   =:= TestMatrixSource,
                   {stale_test_matrix_report, Path,
                    TestMatrixSource,
                    maps:get(<<"source_sha256">>, Report, undefined)});
        false -> ok
    end,
    case coverage_report(Path) of
        true -> audit_current_coverage_report(Path, Report);
        false -> ok
    end,
    case Path of
        "build/fault/hostile-peer.json" -> audit_hostile_report(Report);
        "build/fault/stability.json" -> audit_stability_report(Report);
        "build/campaign/property.json" -> audit_campaign_report(Report, <<"property">>);
        "build/campaign/fuzz.json" -> audit_campaign_report(Report, <<"fuzz">>);
        "build/interop/report.json" -> interop_verify_report();
        "build/performance/report.json" ->
            performance_load_auditor(), performance_audit:verify_report(Report);
        "build/performance/hot-path-profile.json" ->
            hpp_load_auditor(), hot_path_profile:verify_report(Report);
        "build/runtime-matrix/report.json" -> runtime_matrix_verify(Report);
        "build/credential-matrix/report.json" -> credential_matrix_verify(Report);
        "build/http-model/result.json" -> audit_http_model_report(Report);
        "build/qpack-differential/report.json" ->
            audit_qpack_differential_report(Report);
        "build/examples/report.json" -> audit_examples(Report);
        "build/release-sim/report.json" -> audit_release(Report);
        "build/campaign/aggregates/property.json" -> campaign_verify_aggregate("property", Report);
        "build/campaign/aggregates/fuzz.json" -> campaign_verify_aggregate("fuzz", Report);
        "build/campaign/aggregates/model.json" -> campaign_verify_aggregate("model", Report);
        _ -> ok
    end.

qpack_evidence_paths() ->
    [filename:join(?QPACK_DIRECTORY, Name) ||
        Name <- ["oracle.json", "implementation.json",
                 "implementation.json.identity.json", "oracle-report.json"]].

audit_qpack_differential_report(Report) ->
    qpack_audit_ensure_no_locks(),
    fresh_with_verified_build("http3", fun(Snapshot) ->
        ManifestPath = fresh_manifest_path("http3"),
        ManifestBytes = qpack_audit_read(ManifestPath),
        ManifestDigest = qpack_audit_digest(ManifestBytes),
        ensure(ManifestDigest =:= maps:get(sha256, Snapshot),
               qpack_fresh_manifest_digest_drift),
        [OraclePath, ImplementationPath, IdentityPath, OracleReportPath] =
            qpack_evidence_paths(),
        Inputs =
            #{oracle => qpack_audit_input(OraclePath),
              implementation => qpack_audit_input(ImplementationPath),
              implementation_identity => qpack_audit_input(IdentityPath),
              oracle_report => qpack_audit_input(OracleReportPath)},
        LockBytes = qpack_audit_read(
            "packages/http3/test/interop/requirements.lock"),
        DriverBytes = qpack_audit_read(
            "packages/http3/test/interop/qpack_oracle.py"),
        Context =
            #{inputs => Inputs,
              source_sha256 => qpack_audit_source_digest(),
              build_identity => maps:get(report, Snapshot),
              build_manifest_sha256 => ManifestDigest,
              evidence_identity => evidence_identity(),
              execution_environment => execution_runtime(),
              oracle_lock_bytes => LockBytes,
              oracle_lock_sha256 => qpack_audit_digest(LockBytes),
              oracle_driver_sha256 => qpack_audit_digest(DriverBytes),
              locks => qpack_audit_locks()},
        qpack_audit_validate(Report, Context)
    end).

qpack_audit_validate(Report, Context) ->
    ensure(suite_exact_keys(Report,
        [schema, status, family, shareable, replay_command, oracle,
         oracle_run_id, directions, oracle_execution, oracle_corpus_bytes,
         oracle_corpus_sha256, implementation_corpus_bytes,
         implementation_corpus_sha256, implementation_identity_bytes,
         implementation_identity_sha256, oracle_report_bytes,
         oracle_report_sha256, source_sha256, build_identity,
         build_manifest_sha256, evidence_identity, execution_environment]),
        invalid_qpack_report_fields),
    ensure(maps:get(locks, Context) =:= [], qpack_lock_present),
    ensure(maps:get(<<"schema">>, Report) =:= 2,
           invalid_qpack_report_schema),
    ensure(maps:get(<<"status">>, Report) =:= <<"Ready">>,
           qpack_report_not_ready),
    ensure(maps:get(<<"family">>, Report) =:=
               <<"qpack-rfc9204-differential">>,
           invalid_qpack_report_family),
    ensure(maps:get(<<"shareable">>, Report) =:= true,
           qpack_report_not_shareable),
    ensure(maps:get(<<"replay_command">>, Report) =:=
               <<"mise run qpack-differential">>,
           invalid_qpack_replay_command),
    ensure(maps:get(<<"source_sha256">>, Report) =:=
               maps:get(source_sha256, Context),
           stale_qpack_source),
    ensure(maps:get(<<"build_identity">>, Report) =:=
               maps:get(build_identity, Context),
           stale_qpack_build_identity),
    ensure(maps:get(<<"build_manifest_sha256">>, Report) =:=
               maps:get(build_manifest_sha256, Context),
           stale_qpack_build_manifest),
    ensure(maps:get(<<"evidence_identity">>, Report) =:=
               maps:get(evidence_identity, Context),
           stale_qpack_evidence_identity),
    Runtime = maps:get(<<"execution_environment">>, Report),
    ensure(Runtime =:= maps:get(execution_environment, Context),
           stale_qpack_execution_environment),
    ensure(lists:any(fun(Row) ->
        try runtime_matrix_environment_valid(Runtime, Row)
        catch _:_ -> false end
    end, runtime_matrix_expected()), invalid_qpack_execution_environment),
    Oracle = maps:get(<<"oracle">>, Report),
    ok = qpack_audit_oracle_identity(Oracle, Context),
    RunId = maps:get(<<"oracle_run_id">>, Report),
    ensure(qpack_audit_digest_value(RunId), invalid_qpack_oracle_run_id),
    Inputs = maps:get(inputs, Context),
    OracleInput = maps:get(oracle, Inputs),
    ImplementationInput = maps:get(implementation, Inputs),
    IdentityInput = maps:get(implementation_identity, Inputs),
    OracleReportInput = maps:get(oracle_report, Inputs),
    qpack_audit_report_input(
        Report, OracleInput, <<"oracle_corpus_bytes">>,
        <<"oracle_corpus_sha256">>),
    qpack_audit_report_input(
        Report, ImplementationInput, <<"implementation_corpus_bytes">>,
        <<"implementation_corpus_sha256">>),
    qpack_audit_report_input(
        Report, IdentityInput, <<"implementation_identity_bytes">>,
        <<"implementation_identity_sha256">>),
    qpack_audit_report_input(
        Report, OracleReportInput, <<"oracle_report_bytes">>,
        <<"oracle_report_sha256">>),
    OracleSummary = qpack_audit_transcript(
        maps:get(document, OracleInput), <<"pylsqpack-to-http3">>,
        Oracle, RunId, Context),
    ImplementationSummary = qpack_audit_transcript(
        maps:get(document, ImplementationInput), <<"http3-to-pylsqpack">>,
        Oracle, RunId, Context),
    qpack_audit_directions(
        maps:get(<<"directions">>, Report),
        OracleSummary, ImplementationSummary),
    OracleExecution = maps:get(<<"oracle_execution">>, Report),
    ok = qpack_audit_oracle_execution(OracleExecution, OracleSummary),
    ok = qpack_audit_implementation_identity(
        maps:get(document, IdentityInput), Report, OracleExecution,
        Oracle, RunId, OracleInput, ImplementationInput, Context),
    ok = qpack_audit_oracle_report(
        maps:get(document, OracleReportInput), Oracle, RunId,
        ImplementationSummary, ImplementationInput),
    ok.

qpack_audit_report_input(Report, Input, SizeKey, DigestKey) ->
    ensure(maps:get(SizeKey, Report) =:= maps:get(bytes, Input),
           {qpack_input_size_drift, SizeKey}),
    ensure(maps:get(DigestKey, Report) =:= maps:get(sha256, Input),
           {qpack_input_digest_drift, DigestKey}),
    ok.

qpack_audit_implementation_identity(
  Identity, Report, OracleExecution, Oracle, RunId, OracleInput,
  ImplementationInput, Context) ->
    ensure(suite_exact_keys(Identity,
        [artifact_sha256, artifact_bytes, oracle_corpus_sha256,
         oracle_corpus_bytes, oracle_run_id, oracle_identity,
         oracle_execution, build_identity, build_manifest_sha256,
         evidence_identity, execution_environment]),
        invalid_qpack_implementation_identity_fields),
    ensure(maps:get(<<"artifact_sha256">>, Identity) =:=
               maps:get(sha256, ImplementationInput),
           stale_qpack_implementation_capture),
    ensure(maps:get(<<"artifact_bytes">>, Identity) =:=
               maps:get(bytes, ImplementationInput),
           stale_qpack_implementation_capture_size),
    ensure(maps:get(<<"oracle_corpus_sha256">>, Identity) =:=
               maps:get(sha256, OracleInput),
           stale_qpack_oracle_capture),
    ensure(maps:get(<<"oracle_corpus_bytes">>, Identity) =:=
               maps:get(bytes, OracleInput),
           stale_qpack_oracle_capture_size),
    ensure(maps:get(<<"oracle_run_id">>, Identity) =:= RunId,
           stale_qpack_capture_run),
    ensure(maps:get(<<"oracle_identity">>, Identity) =:= Oracle,
           stale_qpack_capture_oracle),
    ensure(maps:get(<<"oracle_execution">>, Identity) =:= OracleExecution,
           stale_qpack_capture_execution),
    ensure(maps:get(<<"build_identity">>, Identity) =:=
               maps:get(build_identity, Context),
           stale_qpack_capture_build),
    ensure(maps:get(<<"build_manifest_sha256">>, Identity) =:=
               maps:get(build_manifest_sha256, Context),
           stale_qpack_capture_manifest),
    ensure(maps:get(<<"evidence_identity">>, Identity) =:=
               maps:get(<<"evidence_identity">>, Report),
           stale_qpack_capture_evidence_identity),
    ensure(maps:get(<<"execution_environment">>, Identity) =:=
               maps:get(<<"execution_environment">>, Report),
           stale_qpack_capture_runtime),
    ok.

qpack_audit_oracle_report(
  OracleReport, Oracle, RunId, Summary, ImplementationInput) ->
    ensure(suite_exact_keys(OracleReport,
        [schema, status, direction, oracle, oracle_run_id, cases, fields,
         blocked_cases, decoder_control_bytes, implementation_bytes,
         implementation_sha256]), invalid_qpack_oracle_report_fields),
    ensure(maps:get(<<"schema">>, OracleReport) =:= 2 andalso
           maps:get(<<"status">>, OracleReport) =:= <<"Ready">> andalso
           maps:get(<<"direction">>, OracleReport) =:=
               <<"http3-to-pylsqpack">>,
           invalid_qpack_oracle_report_scope),
    ensure(maps:get(<<"oracle">>, OracleReport) =:= Oracle andalso
           maps:get(<<"oracle_run_id">>, OracleReport) =:= RunId,
           stale_qpack_oracle_report_peer),
    ensure(maps:get(<<"cases">>, OracleReport) =:= maps:get(cases, Summary)
           andalso maps:get(<<"fields">>, OracleReport) =:=
                       maps:get(fields, Summary)
           andalso maps:get(<<"blocked_cases">>, OracleReport) =:=
                       maps:get(blocked_cases, Summary),
           stale_qpack_oracle_report_summary),
    ensure(qpack_audit_integer(
        maps:get(<<"decoder_control_bytes">>, OracleReport), 0,
        ?QPACK_MAX_BYTES), invalid_qpack_decoder_control_bytes),
    ensure(maps:get(<<"implementation_bytes">>, OracleReport) =:=
               maps:get(bytes, ImplementationInput) andalso
           maps:get(<<"implementation_sha256">>, OracleReport) =:=
               maps:get(sha256, ImplementationInput),
           stale_qpack_oracle_report_implementation),
    ok.

qpack_audit_directions(Directions, OracleSummary, ImplementationSummary) ->
    ensure(is_list(Directions) andalso length(Directions) =:= 2,
           invalid_qpack_directions),
    lists:foreach(fun(Direction) ->
        ensure(suite_exact_keys(Direction,
            [direction, cases, fields, blocked_cases, encoded_bytes]),
            invalid_qpack_direction_fields),
        ensure(qpack_audit_integer(maps:get(<<"cases">>, Direction), 1, 1024)
               andalso qpack_audit_integer(
                   maps:get(<<"fields">>, Direction), 1, 65536)
               andalso qpack_audit_integer(
                   maps:get(<<"blocked_cases">>, Direction), 0, 1024)
               andalso qpack_audit_integer(
                   maps:get(<<"encoded_bytes">>, Direction), 0,
                   ?QPACK_MAX_BYTES),
               invalid_qpack_direction_counts)
    end, Directions),
    Names = [maps:get(<<"direction">>, Direction) || Direction <- Directions],
    ensure(lists:sort(Names) =:=
               [<<"http3-to-pylsqpack">>, <<"pylsqpack-to-http3">>],
           missing_or_duplicate_qpack_direction),
    Expected =
        [qpack_audit_summary(<<"pylsqpack-to-http3">>, OracleSummary),
         qpack_audit_summary(<<"http3-to-pylsqpack">>,
                             ImplementationSummary)],
    ensure(lists:sort(Directions) =:= lists:sort(Expected),
           stale_qpack_direction_summary),
    ok.

qpack_audit_summary(Direction, Summary) ->
    #{<<"direction">> => Direction,
      <<"cases">> => maps:get(cases, Summary),
      <<"fields">> => maps:get(fields, Summary),
      <<"blocked_cases">> => maps:get(blocked_cases, Summary),
      <<"encoded_bytes">> => maps:get(encoded_bytes, Summary)}.

qpack_audit_oracle_execution(Execution, Summary) ->
    ensure(suite_exact_keys(Execution,
        [cases, fields, blocked_cases, encoder_instructions,
         feedback_instructions, feedback_bytes, feedback_actions_verified]),
        invalid_qpack_oracle_execution_fields),
    ensure(qpack_audit_integer(maps:get(<<"cases">>, Execution), 1, 1024)
           andalso qpack_audit_integer(
               maps:get(<<"fields">>, Execution), 1, 65536)
           andalso qpack_audit_integer(
               maps:get(<<"blocked_cases">>, Execution), 0, 1024)
           andalso qpack_audit_integer(
               maps:get(<<"encoder_instructions">>, Execution), 0, 65536)
           andalso qpack_audit_integer(
               maps:get(<<"feedback_instructions">>, Execution), 0, 65536)
           andalso qpack_audit_integer(
               maps:get(<<"feedback_bytes">>, Execution), 0,
               ?QPACK_MAX_BYTES), invalid_qpack_oracle_execution_counts),
    ensure(maps:get(<<"feedback_actions_verified">>, Execution) =:= true,
           qpack_feedback_actions_not_verified),
    ensure(maps:get(<<"cases">>, Execution) =:= maps:get(cases, Summary)
           andalso maps:get(<<"fields">>, Execution) =:=
                       maps:get(fields, Summary)
           andalso maps:get(<<"blocked_cases">>, Execution) =:=
                       maps:get(blocked_cases, Summary),
           stale_qpack_oracle_execution_summary),
    ok.

qpack_audit_oracle_identity(Oracle, Context) ->
    ensure(suite_exact_keys(Oracle,
        [name, version, requirements_lock, requirements_lock_sha256,
         driver_sha256, python_runtime, module_files]),
        invalid_qpack_oracle_fields),
    ensure(maps:get(<<"name">>, Oracle) =:= <<"pylsqpack">> andalso
           maps:get(<<"version">>, Oracle) =:= <<"0.3.24">> andalso
           maps:get(<<"requirements_lock">>, Oracle) =:=
               <<"packages/http3/test/interop/requirements.lock">>,
           invalid_qpack_oracle_peer),
    ensure(binary:match(maps:get(oracle_lock_bytes, Context),
                        <<"pylsqpack==0.3.24">>) =/= nomatch,
           unpinned_qpack_oracle),
    ensure(maps:get(<<"requirements_lock_sha256">>, Oracle) =:=
               maps:get(oracle_lock_sha256, Context) andalso
           maps:get(<<"driver_sha256">>, Oracle) =:=
               maps:get(oracle_driver_sha256, Context),
           stale_qpack_oracle_source_identity),
    Runtime = maps:get(<<"python_runtime">>, Oracle),
    ensure(suite_exact_keys(Runtime, [implementation, version, cache_tag]),
           invalid_qpack_python_runtime_fields),
    Version = maps:get(<<"version">>, Runtime),
    CacheTag = maps:get(<<"cache_tag">>, Runtime),
    ensure(maps:get(<<"implementation">>, Runtime) =:= <<"cpython">>
           andalso is_binary(Version)
           andalso re:run(Version,
               <<"^[0-9]{1,8}(?:\\.[0-9]{1,8}){2}$">>,
               [{capture, none}]) =:= match
           andalso is_binary(CacheTag)
           andalso byte_size(CacheTag) > 0
           andalso byte_size(CacheTag) =< 64
           andalso re:run(CacheTag, <<"^[a-z0-9_-]+$">>,
                          [{capture, none}]) =:= match,
           invalid_qpack_python_runtime),
    Modules = maps:get(<<"module_files">>, Oracle),
    ensure(is_list(Modules) andalso length(Modules) >= 1 andalso
           length(Modules) =< 2, invalid_qpack_oracle_modules),
    Roles = [qpack_audit_oracle_module(Module) || Module <- Modules],
    ensure(length(Roles) =:= length(lists:usort(Roles)) andalso
           lists:member(<<"package">>, Roles) andalso
           lists:all(fun(Role) ->
               lists:member(Role, [<<"package">>, <<"binding">>])
           end, Roles), invalid_qpack_oracle_module_roles),
    ok.

qpack_audit_oracle_module(Module) ->
    ensure(suite_exact_keys(Module, [role, sha256, bytes]),
           invalid_qpack_oracle_module_fields),
    Role = maps:get(<<"role">>, Module),
    ensure(is_binary(Role) andalso byte_size(Role) > 0 andalso
           byte_size(Role) =< 32 andalso
           re:run(Role, <<"^[a-z_-]+$">>, [{capture, none}]) =:= match,
           invalid_qpack_oracle_module_role),
    ensure(qpack_audit_digest_value(maps:get(<<"sha256">>, Module)),
           invalid_qpack_oracle_module_digest),
    ensure(qpack_audit_integer(maps:get(<<"bytes">>, Module), 1,
                               ?QPACK_MAX_BYTES),
           invalid_qpack_oracle_module_size),
    Role.

qpack_audit_transcript(Document, Direction, Oracle, RunId, Context) ->
    Keys = case Direction of
        <<"pylsqpack-to-http3">> ->
            [schema, direction, oracle, oracle_run_id, configuration,
             encoder_stream_prefix, steps];
        <<"http3-to-pylsqpack">> ->
            [schema, direction, oracle, oracle_run_id, configuration, steps]
    end,
    ensure(suite_exact_keys(Document, Keys), invalid_qpack_transcript_fields),
    ensure(maps:get(<<"schema">>, Document) =:= 2 andalso
           maps:get(<<"direction">>, Document) =:= Direction,
           invalid_qpack_transcript_scope),
    ensure(maps:get(<<"oracle">>, Document) =:= Oracle andalso
           maps:get(<<"oracle_run_id">>, Document) =:= RunId,
           stale_qpack_transcript_peer),
    ok = qpack_audit_oracle_identity(maps:get(<<"oracle">>, Document),
                                     Context),
    Configuration = maps:get(<<"configuration">>, Document),
    ensure(suite_exact_keys(Configuration,
        [maximum_table_capacity, maximum_blocked_streams]) andalso
        maps:get(<<"maximum_table_capacity">>, Configuration) =:= 512 andalso
        maps:get(<<"maximum_blocked_streams">>, Configuration) =:= 8,
        invalid_qpack_configuration),
    PrefixBytes = case Direction of
        <<"pylsqpack-to-http3">> ->
            byte_size(qpack_audit_decode_hex(
                maps:get(<<"encoder_stream_prefix">>, Document), 1048576,
                true));
        <<"http3-to-pylsqpack">> -> 0
    end,
    Steps = maps:get(<<"steps">>, Document),
    ensure(is_list(Steps) andalso length(Steps) > 0 andalso
           length(Steps) =< 1024, invalid_qpack_steps),
    Summary = lists:foldl(fun(Step, Acc) ->
        qpack_audit_step(Step, Direction, Acc)
    end, #{streams => #{}, cases => 0, fields => 0,
           blocked_cases => 0, encoded_bytes => PrefixBytes}, Steps),
    maps:remove(streams, Summary).

qpack_audit_step(Step, Direction, Summary) ->
    Keys = case Direction of
        <<"pylsqpack-to-http3">> ->
            [id, stream_id, delivery, encoder_stream, field_section,
             decoder_stream, headers];
        <<"http3-to-pylsqpack">> ->
            [id, stream_id, delivery, encoder_stream, field_section, headers]
    end,
    ensure(suite_exact_keys(Step, Keys), invalid_qpack_step_fields),
    Id = maps:get(<<"id">>, Step),
    StreamId = maps:get(<<"stream_id">>, Step),
    ensure(is_binary(Id) andalso byte_size(Id) > 0 andalso
           byte_size(Id) =< 128 andalso
           qpack_audit_integer(StreamId, 0, 4611686018427387903),
           invalid_qpack_step_identity),
    Streams = maps:get(streams, Summary),
    ensure(not maps:is_key(StreamId, Streams), duplicate_qpack_stream_id),
    Delivery = maps:get(<<"delivery">>, Step),
    Allowed = case Direction of
        <<"pylsqpack-to-http3">> ->
            [<<"encoder_first">>, <<"header_first">>,
             <<"header_before_encoder_unblocked">>];
        <<"http3-to-pylsqpack">> ->
            [<<"encoder_first">>, <<"header_first">>]
    end,
    ensure(lists:member(Delivery, Allowed), invalid_qpack_delivery),
    Encoder = qpack_audit_decode_hex(
        maps:get(<<"encoder_stream">>, Step), 1048576, true),
    Section = qpack_audit_decode_hex(
        maps:get(<<"field_section">>, Step), 1048576, false),
    Decoder = case Direction of
        <<"pylsqpack-to-http3">> -> qpack_audit_decode_hex(
            maps:get(<<"decoder_stream">>, Step), 1048576, true);
        <<"http3-to-pylsqpack">> -> <<>>
    end,
    Headers = maps:get(<<"headers">>, Step),
    ensure(is_list(Headers) andalso length(Headers) > 0 andalso
           length(Headers) =< 64, invalid_qpack_headers),
    HeaderBytes = lists:sum([qpack_audit_header(Header) || Header <- Headers]),
    EncodedBytes = byte_size(Encoder) + byte_size(Section) +
                   byte_size(Decoder),
    ensure(EncodedBytes =< 1048576, qpack_step_too_large),
    Fields = maps:get(fields, Summary) + length(Headers),
    TotalBytes = maps:get(encoded_bytes, Summary) + EncodedBytes + HeaderBytes,
    ensure(Fields =< 65536 andalso TotalBytes =< ?QPACK_MAX_BYTES,
           qpack_transcript_limit),
    Summary#{streams := Streams#{StreamId => true},
             cases := maps:get(cases, Summary) + 1,
             fields := Fields,
             blocked_cases := maps:get(blocked_cases, Summary) +
                 case Delivery of <<"header_first">> -> 1; _ -> 0 end,
             encoded_bytes := TotalBytes}.

qpack_audit_header(Header) ->
    ensure(suite_exact_keys(Header, [name, value]),
           invalid_qpack_header_fields),
    Name = qpack_audit_decode_hex(maps:get(<<"name">>, Header), 65536, false),
    Value = qpack_audit_decode_hex(
        maps:get(<<"value">>, Header), 1048576, true),
    byte_size(Name) + byte_size(Value).

qpack_audit_decode_hex(Value, MaximumBytes, AllowEmpty)
  when is_binary(Value), is_integer(MaximumBytes), MaximumBytes >= 0,
       is_boolean(AllowEmpty), byte_size(Value) rem 2 =:= 0,
       byte_size(Value) =< MaximumBytes * 2 ->
    ensure(AllowEmpty orelse byte_size(Value) > 0, invalid_qpack_hex),
    ensure(re:run(Value, <<"^[0-9a-f]*$">>, [{capture, none}]) =:= match,
           invalid_qpack_hex_digit),
    try binary:decode_hex(Value)
    catch _:_ -> erlang:error(invalid_qpack_hex) end;
qpack_audit_decode_hex(_Value, _MaximumBytes, _AllowEmpty) ->
    erlang:error(invalid_qpack_hex).

qpack_audit_integer(Value, Minimum, Maximum) ->
    is_integer(Value) andalso Value >= Minimum andalso Value =< Maximum.

qpack_audit_digest_value(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 64 andalso
    re:run(Value, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match.

qpack_audit_input(Path) ->
    Bytes = qpack_audit_read(Path),
    Document = evidence_json_decode(Bytes),
    ensure(is_map(Document), {invalid_qpack_json_document, Path}),
    #{path => Path, bytes => byte_size(Bytes),
      sha256 => qpack_audit_digest(Bytes), document => Document}.

qpack_audit_read(Path) ->
    Info = bundle_regular(Path),
    ensure(Info#file_info.links =:= 1,
           {qpack_hardlinked_evidence_rejected, Path}),
    Bytes = read(Path),
    ensure(is_binary(Bytes) andalso byte_size(Bytes) > 0 andalso
           byte_size(Bytes) =< ?QPACK_MAX_BYTES,
           {invalid_qpack_evidence_size, Path}),
    Bytes.

qpack_audit_source_digest() ->
    Paths = ["scripts/qpack_differential.escript",
             "packages/http3/test/interop/qpack_oracle.py",
             "packages/http3/test/interop/qpack_oracle_contract_test.py",
             "packages/http3/test/interop/requirements.lock",
             "packages/http3/src/http3/internal/qpack/decoder.gleam",
             "packages/http3/src/http3/internal/qpack/encoder.gleam",
             "packages/http3/src/http3/internal/qpack/field_section.gleam",
             "packages/http3/src/http3/internal/qpack/instruction.gleam",
             "packages/http3/src/http3/internal/qpack/instruction_stream.gleam"],
    Frames = [begin
        Name = unicode:characters_to_binary(Path),
        Bytes = qpack_audit_read(Path),
        <<(byte_size(Name)):64/unsigned-big, Name/binary,
          (byte_size(Bytes)):64/unsigned-big,
          (crypto:hash(sha256, Bytes))/binary>>
    end || Path <- Paths],
    qpack_audit_digest(iolist_to_binary(
        [<<"http3-qpack-source-v2", 0,
           (length(Paths)):64/unsigned-big>> | Frames])).

qpack_audit_digest(Bytes) ->
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

qpack_audit_ensure_no_locks() ->
    ensure(qpack_audit_locks() =:= [], qpack_lock_present).

qpack_audit_validate_captured_inputs(Captured) ->
    qpack_audit_ensure_no_locks(),
    Paths = ["build/qpack-differential/report.json" |
             qpack_evidence_paths()],
    lists:foreach(fun(Path) ->
        case lists:keyfind(Path, 1, Captured) of
            {Path, Bytes} ->
                ensure(qpack_audit_read(Path) =:= Bytes,
                       {qpack_input_changed_after_capture, Path});
            false -> erlang:error({qpack_input_missing_from_capture, Path})
        end
    end, Paths),
    qpack_audit_ensure_no_locks(),
    ok.

qpack_audit_locks() ->
    case file:list_dir(?QPACK_DIRECTORY) of
        {ok, Names} -> [filename:join(?QPACK_DIRECTORY, Name) ||
                        Name <- qpack_audit_lock_entries(Names)];
        {error, enoent} -> [];
        {error, Reason} -> erlang:error({qpack_directory_unreadable, Reason})
    end.

qpack_audit_lock_entries(Names) ->
    lists:sort([Name || Name <- Names,
                       lists:suffix(?QPACK_LOCK_SUFFIX, Name)]).

audit_http_model_report(Report) ->
    Sources = fresh_source_paths(fresh_packages("http")),
    Catalog = #{source_sha256 => fresh_digest(Sources), source_files => length(Sources)},
    audit_http_model_report(Report, evidence_identity(), Catalog).

audit_http_model_report(Report, Identity, Catalog) ->
    ensure(suite_exact_keys(Report, [schema, family, status, mode, seed, requested_cases_or_steps,
        execution_environment, shareable, build_identity, runner_sha256, replay_command,
        model, runner_exit, runner_output, evidence_identity]), unsafe_http_model_report),
    ensure(maps:get(<<"schema">>, Report) =:= 1 andalso
           maps:get(<<"family">>, Report) =:= <<"http-state-models">> andalso
           maps:get(<<"status">>, Report) =:= <<"Ready">> andalso
           maps:get(<<"mode">>, Report) =:= <<"campaign">>, wrong_http_model_scope),
    evidence_require_identity(Report, Identity),
    ensure(maps:get(<<"shareable">>, Report) =:= true, unsafe_http_model_evidence),
    ensure(maps:get(<<"seed">>, Report) =:= 982451653 andalso
           maps:get(<<"requested_cases_or_steps">>, Report) =:= 10000,
           incomplete_http_model_cases),
    ensure(maps:get(<<"replay_command">>, Report) =:=
        <<"escript scripts/http_models.escript --seed 982451653 --cases 10000">>, wrong_model_replay),
    Model = maps:get(<<"model">>, Report),
    Nonce = maps:get(<<"nonce">>, Model),
    ensure(is_binary(Nonce) andalso byte_size(Nonce) =:= 32 andalso
        re:run(Nonce, <<"^[0-9A-Fa-f]{32}$">>, [{capture, none}]) =:= match, invalid_model_nonce),
    ensure(http_model_valid_child(Model, campaign,
        [<<"http1">>, <<"http2">>, <<"hpack">>, <<"pool">>, <<"cancellation">>, <<"drain">>],
        982451653, 10000, Nonce), invalid_http_model_results),
    ensure(maps:get(<<"status">>, Model) =:= <<"Passed">> andalso
        maps:get(<<"runner_exit">>, Report) =:= 0 andalso
        runtime_matrix_process_valid(maps:get(<<"runner_output">>, Report)), incomplete_http_model_process),
    Runtime = maps:get(<<"execution_environment">>, Report),
    ensure(lists:any(fun(Row) ->
        try runtime_matrix_environment_valid(Runtime, Row) catch _:_ -> false end
    end, runtime_matrix_expected()), invalid_http_model_runtime),
    ensure(runtime_matrix_build_valid(maps:get(<<"build_identity">>, Report), <<"http">>, Catalog, Runtime),
           stale_http_model_build),
    ensure(runtime_matrix_hex(maps:get(<<"runner_sha256">>, Report)), missing_model_runner_identity).

audit_campaign_report(Report, Mode) ->
    campaign_audit_report(binary_to_list(Mode), 0, 1, Report, evidence_identity(), campaign_context()).

audit_model_family(Paths) ->
    ensure(Paths =/= [], missing_model_evidence),
    Reports = [evidence_json_decode(read(Path)) || Path <- Paths],
    [First | _] = Reports,
    Shards = maps:get(<<"shards">>, First),
    ensure(Shards =:= 1 orelse Shards =:= 8, invalid_model_shard_count),
    Ids = lists:sort([maps:get(<<"shard">>, R) || R <- Reports]),
    ensure(Ids =:= lists:seq(0, Shards - 1), missing_or_duplicate_model_shard),
    Context = campaign_context(), Identity = evidence_identity(),
    lists:foreach(fun(Report) -> campaign_audit_report("model", maps:get(<<"shard">>, Report),
        Shards, Report, Identity, Context) end, Reports),
    Nonces = [maps:get(<<"nonce">>, E) || Report <- Reports, E <- maps:get(<<"executions">>, Report)],
    ensure(length(Nonces) =:= length(lists:usort(Nonces)), replayed_model_nonce).

audit_examples(Report) ->
    Build = fresh_verified_report("http"),
    {_, Examples} = examples_sources(),
    ensure(examples_validate_report(Report, evidence_identity(), Build, Examples) =:= ok,
           invalid_documented_example_evidence).

audit_release(Report) ->
    Targets = ["core", "http3", "http"],
    Snapshots = fresh_with_verified_builds(Targets,
        fun(Verified) -> Verified end),
    Builds = maps:from_list([{list_to_binary(maps:get(target, Snapshot)),
        maps:get(report, Snapshot)} || Snapshot <- Snapshots]),
    ensure(release_validate_report(Report, evidence_identity(), Builds, release_expected()) =:= ok,
           invalid_release_execution_evidence).

release_bundle_paths() ->
    Report = evidence_json_decode(read("build/release-sim/report.json")),
    audit_release(Report),
    release_selected_paths(Report).

release_selected_paths(Report) ->
    Nonce = maps:get(<<"run_nonce">>, Report),
    ensure(examples_nonce_valid(Nonce), invalid_release_bundle_nonce),
    Directory = release_directory(Nonce),
    Packages = ["quic_core", "http3", "http"],
    Fixed = [filename:join(Directory, File) || File <- ["release-sim.cdx.json", "provenance.json"]] ++
        [filename:join([Directory, "runner", Name ++ ".beam"]) ||
            Name <- ["examples_child", "qualification_eunit_listener", "release_child"]] ++
        [filename:join([Directory, Pass, Name ++ "-0.1.0.tar"]) ||
            Pass <- ["pass-a", "pass-b"], Name <- Packages],
    Registries = lists:append([bundle_tree(filename:join([Directory, "registry", Name, "0.1.0"])) ||
        Name <- Packages]),
    Dependencies = lists:append([bundle_tree(filename:join([Directory, "lib", Name])) ||
        Name <- ["gleam_stdlib", "gleam_erlang", "gleam_http"]]),
    Compilers = lists:append([release_compiler_bundle_paths(C,
        filename:join([Directory, "lib", binary_to_list(maps:get(<<"name">>, C))])) ||
        C <- maps:get(<<"package_compilers">>, Report)]),
    Consumers = lists:append([begin
        Name = binary_to_list(maps:get(<<"name">>, C)),
        Consumer = filename:join([Directory, "consumers", Name]),
        Out = filename:join(Consumer, "out"),
        [filename:join(Consumer, "gleam.toml"), filename:join([Consumer, "src", Name ++ "_main.gleam"]),
         filename:join(Out, "execution.json") |
         release_compiler_bundle_paths(maps:get(<<"compiler">>, C), Out)]
    end || C <- maps:get(<<"consumers">>, Report)]),
    Paths = lists:usort(Fixed ++ Registries ++ Dependencies ++ Compilers ++ Consumers),
    ensure(lists:all(fun(P) -> lists:prefix(Directory ++ "/", bundle_path(P)) end, Paths),
           release_bundle_path_escape),
    Paths.

release_compiler_bundle_paths(Compiler, Out) ->
    [filename:join(Out, "beam-compiler.json") |
     [binary_to_list(maps:get(<<"path">>, F)) ||
        F <- maps:get(<<"generated">>, Compiler) ++ maps:get(<<"generated_support">>, Compiler)]] ++
    [filename:join([Out, "ebin", binary_to_list(maps:get(<<"module">>, F)) ++ ".beam"]) ||
        F <- maps:get(<<"generated">>, Compiler)].

examples_bundle_paths() ->
    Report = evidence_json_decode(read("build/examples/report.json")),
    audit_examples(Report),
    Directory = examples_run_directory(maps:get(<<"run_nonce">>, Report)),
    {_, Examples} = examples_sources(),
    [filename:join([Directory, "runner", Name ++ ".beam"])
        || Name <- ["examples_child", "qualification_eunit_listener"]] ++
    lists:append([[examples_project_path(Directory, maps:get(module, E)),
                   examples_generated_path(Directory, maps:get(module, E)),
                   examples_beam_path(Directory, maps:get(module, E))] || E <- Examples]).
test_matrix_report(Path) ->
    lists:member(Path, ["build/fault/hostile-peer.json",
                        "build/fault/stability.json"]).

coverage_report(Path) ->
    lists:member(Path, ["build/coverage/changed.json",
                        "build/coverage/full.json"]).

verify_report("build/release-sim/report.json" = Path) ->
    Identity = evidence_identity(),
    require_ready_report(Path, test_matrix_source_digest()),
    Files = lists:usort([Path | release_bundle_paths()]),
    Inputs = lists:usort(Files ++ bundle_context_paths()),
    io:format("release capture: ~B selected files, ~B total validation inputs~n", [length(Files), length(Inputs)]),
    Captured = bundle_capture(Inputs),
    Directory = filename:join(?OUTPUT, "verify-" ++
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16)))),
    ok = bundle_materialize(Directory, Captured),
    io:put_chars("release capture: validating materialized bytes\n"),
    ok = bundle_validate_capture(Directory, Captured, fun() ->
        require_ready_report(Path, test_matrix_source_digest()),
        ensure(lists:usort([Path | release_bundle_paths()]) =:= Files, changed_release_selection)
    end),
    _ = evidence_complete(#{}, Identity),
    io:format("current-source release qualification verified from captured bytes: ~B files~n", [length(Files)]),
    ok;
verify_report(Path) ->
    ensure(lists:member(Path, ready_reports()),
           {unsupported_ready_report, Path}),
    require_ready_report(Path, test_matrix_source_digest()),
    io:format("current-source qualification report ok: ~s~n", [Path]),
    ok.

audit_current_coverage_report(Path, Report) ->
    Policy = evidence_json_decode(read(?COVERAGE_POLICY)),
    Methodology = audit_coverage_policy_contract(Policy),
    audit_coverage_document_contract(Path, Report, Methodology),
    SourcePaths = coverage_source_paths(Policy),
    Source = coverage_source_digest(SourcePaths),
    PolicyDigest = coverage_file_digest(?COVERAGE_POLICY),
    audit_coverage_identity(
        Path, Report, Source, PolicyDigest, length(SourcePaths)
    ),
    ensure(filelib:is_regular(?COVERAGE_EVIDENCE),
           missing_coverage_evidence),
    Evidence = evidence_json_decode(read(?COVERAGE_EVIDENCE)),
    evidence_require_identity(Evidence, evidence_identity()),
    audit_coverage_document_contract(
        ?COVERAGE_EVIDENCE, Evidence, Methodology
    ),
    audit_coverage_identity(
        ?COVERAGE_EVIDENCE, Evidence, Source, PolicyDigest,
        length(SourcePaths)
    ),
    Mode = case Path of
        "build/coverage/full.json" -> <<"full">>;
        "build/coverage/changed.json" -> <<"changed">>
    end,
    ensure(coverage_report_process_audit(Mode, read(Path), read(?COVERAGE_EVIDENCE), evidence_identity()),
           coverage_report_process_mismatch),
    ensure(maps:get(<<"mode">>, Report, undefined) =:= Mode,
           {coverage_report_mode_mismatch, Path}),
    EvidenceStatuses = maps:get(<<"statuses">>, Evidence),
    ensure(maps:get(Mode, EvidenceStatuses, undefined) =:= <<"Ready">>,
           {coverage_evidence_not_ready, Mode}),
    ensure(coverage_report_thresholds_match(Mode, Report, Evidence),
           coverage_selected_thresholds_mismatch),
    lists:foreach(fun(Key) ->
        ensure(maps:get(Key, Report, undefined) =:=
                   maps:get(Key, Evidence, undefined),
               {coverage_evidence_mismatch, Path, Key})
    end, [<<"coordinate_methodology">>,
          <<"full">>, <<"changed">>,
          <<"capture_policy">>, <<"capture_repetitions">>, <<"captures">>]),
    ensure(maps:get(<<"capture_policy">>, Report) =:=
               maps:get(<<"capture">>, Policy),
           {coverage_policy_mismatch, Path}),
    audit_coverage_capture_files(
        maps:get(<<"captures">>, Report), Source, PolicyDigest,
        length(SourcePaths), Methodology
    ),
    ok.

audit_coverage_policy_contract(Policy) ->
    ensure(maps:get(<<"schema">>, Policy, undefined) =:= 2,
           invalid_coverage_policy_schema),
    Methodology = maps:get(
        <<"coordinate_methodology">>, Policy, undefined
    ),
    Expected = expected_coverage_coordinate_methodology(),
    ensure(Methodology =:= Expected,
           {invalid_coverage_coordinate_methodology, Methodology}),
    Methodology.

audit_coverage_document_contract(Path, Document, Methodology) ->
    ensure(maps:get(<<"schema">>, Document, undefined) =:= 2,
           {invalid_coverage_document_schema, Path}),
    ensure(maps:get(<<"coordinate_methodology">>, Document, undefined) =:=
               Methodology,
           {coverage_coordinate_methodology_mismatch, Path}),
    ok.

expected_coverage_coordinate_methodology() ->
    #{<<"schema">> => 1,
      <<"metric_coordinates">> => <<"generated_erlang_physical_lines">>,
      <<"line_universe">> => <<"otp_cover_executable_lines">>,
      <<"clause_alternative_universe">> =>
          <<"beam_debug_abstract_multi_clause_alternatives">>,
      <<"clause_alternative_coverage">> =>
          <<"any_sibling_exclusive_otp_cover_artifact_line">>,
      <<"gleam_source_attribution">> =>
          <<"glance_name_arity_function_span_including_attached_attributes">>,
      <<"erlang_source_attribution">> =>
          <<"byte_identical_source_artifact_lines">>,
      <<"changed_selection">> =>
          <<"source_span_overlap_with_whole_module_fallback">>,
      <<"generated_clause_exclusion">> => <<"none">>,
      <<"unclaimed_control_flow">> =>
          <<"short_circuit_guard_timeout_and_exception_outcomes">>}.

audit_coverage_identity(Path, Report, Source, PolicyDigest, SourceFiles) ->
    ensure(maps:get(<<"source_sha256">>, Report, undefined) =:= Source,
           {stale_coverage_source, Path}),
    ensure(maps:get(<<"policy_sha256">>, Report, undefined) =:= PolicyDigest,
           {stale_coverage_policy, Path}),
    ensure(maps:get(<<"source_files">>, Report, undefined) =:= SourceFiles,
           {coverage_source_set_changed, Path}),
    ok.

audit_coverage_capture_files(Captures, Source, PolicyDigest, SourceFiles,
                             Methodology) ->
    ExpectedPackages = [<<"http">>, <<"http3">>, <<"quic_core">>],
    Packages = lists:sort([
        maps:get(<<"package">>, Capture) || Capture <- Captures
    ]),
    ensure(Packages =:= ExpectedPackages,
           {coverage_capture_packages, ExpectedPackages, Packages}),
    lists:foreach(fun(Capture) ->
        Package = maps:get(<<"package">>, Capture),
        audit_coverage_document_contract(
            {coverage_capture_summary, Package}, Capture, Methodology
        ),
        PackageText = binary_to_list(Package),
        MetadataPath = binary_to_list(maps:get(<<"metadata">>, Capture)),
        ExpectedMetadata = filename:join(
            "build/coverage", PackageText ++ ".capture.json"
        ),
        ensure(MetadataPath =:= ExpectedMetadata,
               {unexpected_coverage_metadata_path, Package, MetadataPath}),
        ensure(filelib:is_regular(MetadataPath),
               {missing_coverage_metadata, MetadataPath}),
        ensure(coverage_file_digest(MetadataPath) =:=
                   maps:get(<<"metadata_sha256">>, Capture),
               {modified_coverage_metadata, MetadataPath}),
        Metadata = evidence_json_decode(read(MetadataPath)),
        evidence_require_identity(Metadata, evidence_identity()),
        audit_coverage_document_contract(
            MetadataPath, Metadata, Methodology
        ),
        audit_coverage_identity(
            MetadataPath, Metadata, Source, PolicyDigest, SourceFiles
        ),
        ensure(maps:get(<<"status">>, Metadata, undefined) =:= <<"Ready">>,
               {coverage_capture_not_ready, Package}),
        ensure(maps:get(<<"package">>, Metadata, undefined) =:= Package,
               {coverage_capture_package_mismatch, Package}),
        ensure(maps:get(<<"paths_saturated">>, Metadata, false),
               {coverage_capture_not_saturated, Package}),
        ensure(maps:get(<<"repetition_count">>, Metadata, undefined) =:=
                   maps:get(<<"repetition_count">>, Capture, undefined),
               {coverage_repetition_mismatch, Package}),
        Growth = maps:get(<<"growth">>, Metadata),
        ensure(maps:get(<<"paths_saturated">>, Growth, false),
               {coverage_growth_not_saturated, Package}),
        Runtime = maps:get(<<"runtime_convergence">>, Metadata),
        ensure(maps:get(<<"final_resource_counts_converged">>, Runtime, false),
               {coverage_runtime_not_converged, Package}),
        CoverPath = filename:join(
            "build/coverage", PackageText ++ ".cover"
        ),
        ensure(filelib:is_regular(CoverPath),
               {missing_raw_coverage_capture, CoverPath}),
        CoverDigest = coverage_file_digest(CoverPath),
        ensure(CoverDigest =:= maps:get(<<"cover_sha256">>, Capture) andalso
               CoverDigest =:= maps:get(<<"cover_sha256">>, Metadata),
               {modified_raw_coverage_capture, CoverPath})
    end, Captures),
    ok.

coverage_source_paths(Policy) ->
    Files = [coverage_policy_path(Path)
             || Path <- maps:get(<<"source_files">>, Policy)],
    Trees = [coverage_policy_path(Path)
             || Path <- maps:get(<<"source_trees">>, Policy)],
    lists:foreach(fun(Tree) ->
        ensure(filelib:is_dir(Tree), {missing_coverage_source_tree, Tree})
    end, Trees),
    TreePaths = lists:append([
        filelib:fold_files(Tree, ".*", true,
                           fun(Path, Acc) -> [Path | Acc] end, [])
        || Tree <- Trees
    ]),
    Paths = lists:usort(Files ++ TreePaths),
    lists:foreach(fun(Path) ->
        ensure(filelib:is_regular(Path), {missing_coverage_source, Path})
    end, Paths),
    Paths.

coverage_policy_path(Value) when is_binary(Value), byte_size(Value) > 0 ->
    Path = binary_to_list(Value),
    Parts = filename:split(Path),
    ensure(filename:pathtype(Path) =:= relative andalso
           not lists:member("..", Parts),
           {unsafe_coverage_policy_path, Value}),
    Path;
coverage_policy_path(Value) ->
    erlang:error({invalid_coverage_policy_path, Value}).

coverage_source_digest(Paths) ->
    Material = [[unicode:characters_to_binary(coverage_relative(Path)),
                 0, read(Path), 0]
                || Path <- lists:sort(Paths)],
    coverage_hex(crypto:hash(sha256, Material)).

coverage_relative(Path) ->
    RootParts = filename:split(filename:absname(".")),
    PathParts = filename:split(filename:absname(Path)),
    case coverage_drop_prefix(RootParts, PathParts) of
        [] -> ".";
        Parts -> filename:join(Parts)
    end.

coverage_drop_prefix([Part | Root], [Part | Path]) ->
    coverage_drop_prefix(Root, Path);
coverage_drop_prefix([], Path) -> Path;
coverage_drop_prefix(_, Path) -> Path.

coverage_file_digest(Path) -> coverage_hex(crypto:hash(sha256, read(Path))).

coverage_hex(Bytes) -> binary:encode_hex(Bytes, lowercase).

audit_hostile_report(Report) ->
    ensure(maps:get(<<"schema">>, Report, undefined) =:= 1,
           invalid_hostile_report_schema),
    Families = maps:get(<<"families">>, Report, []),
    Runs = maps:get(<<"package_runs">>, Report, []),
    ConfiguredPackages = maps:get(<<"configured_packages">>, Report, 0),
    ConfiguredTests = maps:get(<<"configured_tests">>, Report, 0),
    CompletedTests = maps:get(<<"completed_tests">>, Report, -1),
    ensure(Families =/= [], empty_hostile_report_families),
    ensure(ConfiguredPackages > 0 andalso length(Runs) =:= ConfiguredPackages,
           {invalid_hostile_report_packages, ConfiguredPackages, length(Runs)}),
    ensure(ConfiguredTests > 0 andalso CompletedTests =:= ConfiguredTests,
           {incomplete_hostile_report, ConfiguredTests, CompletedTests}),
    lists:foreach(fun(Run) ->
        ConfiguredModules = maps:get(<<"configured_modules">>, Run, 0),
        Modules = maps:get(<<"modules">>, Run, []),
        Tests = maps:get(<<"tests">>, Run, 0),
        ensure(maps:get(<<"status">>, Run, undefined) =:= <<"Ready">>,
               {hostile_package_not_ready,
                maps:get(<<"package">>, Run, undefined)}),
        ensure(ConfiguredModules > 0 andalso
               maps:get(<<"completed_modules">>, Run, -1)
               =:= ConfiguredModules andalso
               length(Modules) =:= ConfiguredModules,
               {incomplete_hostile_modules,
                maps:get(<<"package">>, Run, undefined)}),
        ensure(Tests > 0 andalso
               maps:get(<<"completed_tests">>, Run, -1) =:= Tests,
               {incomplete_hostile_tests,
                maps:get(<<"package">>, Run, undefined)})
    end, Runs),
    ensure(lists:sum([maps:get(<<"tests">>, Run) || Run <- Runs])
           =:= ConfiguredTests,
           hostile_report_test_total).

audit_stability_report(Report) ->
    ensure(maps:get(<<"schema">>, Report, undefined) =:= 1,
           invalid_stability_report_schema),
    Targets = maps:get(<<"target_runs">>, Report, []),
    ConfiguredTargets = maps:get(<<"configured_targets">>, Report, 0),
    Configured = maps:get(<<"configured_repetitions">>, Report, 0),
    Completed = maps:get(<<"completed_repetitions">>, Report, -1),
    ensure(ConfiguredTargets > 0 andalso length(Targets) =:= ConfiguredTargets,
           {invalid_stability_report_targets, ConfiguredTargets,
            length(Targets)}),
    ensure(Configured > 0 andalso Completed =:= Configured,
           {incomplete_stability_report, Configured, Completed}),
    lists:foreach(fun(Target) ->
        TargetConfigured = maps:get(<<"configured_repetitions">>, Target, 0),
        ensure(maps:get(<<"status">>, Target, undefined) =:= <<"Ready">>,
               {stability_target_not_ready,
                maps:get(<<"name">>, Target, undefined)}),
        ensure(TargetConfigured > 0 andalso
               maps:get(<<"completed_repetitions">>, Target, -1)
               =:= TargetConfigured,
               {incomplete_stability_target,
                maps:get(<<"name">>, Target, undefined)})
    end, Targets),
    ensure(lists:sum([
        maps:get(<<"configured_repetitions">>, Target) || Target <- Targets
    ]) =:= Configured,
           stability_report_repetition_total).

test_matrix_source_digest() ->
    Roots = [".mise.toml", "qualification.json", "gleam.toml",
             "packages/http3/gleam.toml",
             "packages/quic_core/gleam.toml", "scripts/test_matrix.escript"],
    SourcePaths = lists:sort(lists:append([
        filelib:fold_files(Root, ".*\\.(gleam|erl|pem)$", true,
                           fun(Path, Acc) -> [Path | Acc] end, [])
        || Root <- ["src", "test", "packages/http3/src",
                    "packages/http3/test", "packages/quic_core/src",
                    "packages/quic_core/test"]
    ])),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Roots ++ SourcePaths])).

invalidate_archive_report() ->
    case file:delete(filename:join(?OUTPUT, "archive.json")) of
        ok -> ok;
        {error, enoent} -> ok;
        _ -> error(cannot_invalidate_bundle_archive)
    end.

qpack_audit_self_test() ->
    {Report, Context} = qpack_audit_fixture(),
    ok = qpack_audit_validate(Report, Context),
    expect_error(qpack_missing_report_key, fun() ->
        qpack_audit_validate(maps:remove(<<"oracle">>, Report), Context)
    end),
    expect_error(qpack_extra_report_key, fun() ->
        qpack_audit_validate(Report#{<<"unexpected">> => true}, Context)
    end),
    [OracleDirection, ImplementationDirection] =
        maps:get(<<"directions">>, Report),
    expect_error(qpack_missing_direction, fun() ->
        qpack_audit_validate(
            Report#{<<"directions">> => [OracleDirection]}, Context)
    end),
    expect_error(qpack_duplicate_direction, fun() ->
        qpack_audit_validate(
            Report#{<<"directions">> =>
                [OracleDirection, OracleDirection]}, Context)
    end),
    expect_error(qpack_wrong_direction, fun() ->
        qpack_audit_validate(
            Report#{<<"directions">> =>
                [OracleDirection,
                 ImplementationDirection#{<<"direction">> =>
                     <<"unverified">>}]}, Context)
    end),
    expect_error(qpack_oversized_direction_count, fun() ->
        qpack_audit_directions(
            [OracleDirection#{<<"cases">> => 1025},
             ImplementationDirection],
            #{cases => 1025, fields => 1, blocked_cases => 0,
              encoded_bytes => 2},
            #{cases => 1, fields => 1, blocked_cases => 0,
              encoded_bytes => 2})
    end),
    OracleExecution = maps:get(<<"oracle_execution">>, Report),
    expect_error(qpack_feedback_not_verified, fun() ->
        qpack_audit_oracle_execution(
            OracleExecution#{<<"feedback_actions_verified">> => false},
            #{cases => 1, fields => 1, blocked_cases => 0,
              encoded_bytes => 2})
    end),
    expect_error(qpack_feedback_byte_limit, fun() ->
        qpack_audit_oracle_execution(
            OracleExecution#{<<"feedback_bytes">> =>
                ?QPACK_MAX_BYTES + 1},
            #{cases => 1, fields => 1, blocked_cases => 0,
              encoded_bytes => 2})
    end),
    expect_error(qpack_stale_input_digest, fun() ->
        qpack_audit_validate(
            Report#{<<"oracle_corpus_sha256">> =>
                binary:copy(<<"0">>, 64)}, Context)
    end),
    expect_error(qpack_stale_input_size, fun() ->
        qpack_audit_validate(
            Report#{<<"implementation_corpus_bytes">> => 0}, Context)
    end),
    expect_error(qpack_stale_source, fun() ->
        qpack_audit_validate(
            Report#{<<"source_sha256">> => binary:copy(<<"1">>, 64)},
            Context)
    end),
    expect_error(qpack_stale_build, fun() ->
        qpack_audit_validate(
            Report#{<<"build_identity">> => #{}}, Context)
    end),
    expect_error(qpack_stale_manifest, fun() ->
        qpack_audit_validate(
            Report#{<<"build_manifest_sha256">> =>
                binary:copy(<<"2">>, 64)}, Context)
    end),
    Oracle = maps:get(<<"oracle">>, Report),
    expect_error(qpack_wrong_oracle_peer, fun() ->
        qpack_audit_oracle_identity(
            Oracle#{<<"name">> => <<"lookalike">>}, Context)
    end),
    expect_error(qpack_stale_oracle_driver, fun() ->
        qpack_audit_oracle_identity(
            Oracle#{<<"driver_sha256">> => binary:copy(<<"3">>, 64)},
            Context)
    end),
    expect_error(qpack_lock_present, fun() ->
        qpack_audit_validate(
            Report,
            Context#{locks =>
                ["build/qpack-differential/report.json.qpack-lock"]})
    end),
    ensure(qpack_audit_lock_entries(
        ["report.json.qpack-lock", "implementation.json.qpack-lock",
         "ordinary.json"]) =:=
        ["implementation.json.qpack-lock", "report.json.qpack-lock"],
        qpack_lock_discovery_self_test_failed),
    io:put_chars("QPACK audit: exact peer, transcripts, directions, inputs, "
                 "fresh build, current source, feedback and lock state "
                 "verified\n"),
    ok.

qpack_audit_fixture() ->
    Hash = binary:copy(<<"a">>, 64),
    RunId = binary:copy(<<"b">>, 64),
    LockBytes = <<"pylsqpack==0.3.24 --hash=sha256:fixture\n">>,
    DriverBytes = <<"fixture qpack oracle driver\n">>,
    Runtime = execution_runtime(),
    Build = #{<<"fixture">> => <<"http3-build">>},
    Evidence = #{<<"source_sha256">> => Hash},
    Context0 =
        #{source_sha256 => Hash,
          build_identity => Build,
          build_manifest_sha256 => Hash,
          evidence_identity => Evidence,
          execution_environment => Runtime,
          oracle_lock_bytes => LockBytes,
          oracle_lock_sha256 => qpack_audit_digest(LockBytes),
          oracle_driver_sha256 => qpack_audit_digest(DriverBytes),
          locks => []},
    Oracle =
        #{<<"name">> => <<"pylsqpack">>,
          <<"version">> => <<"0.3.24">>,
          <<"requirements_lock">> =>
              <<"packages/http3/test/interop/requirements.lock">>,
          <<"requirements_lock_sha256">> =>
              maps:get(oracle_lock_sha256, Context0),
          <<"driver_sha256">> =>
              maps:get(oracle_driver_sha256, Context0),
          <<"python_runtime">> =>
              #{<<"implementation">> => <<"cpython">>,
                <<"version">> => <<"3.12.0">>,
                <<"cache_tag">> => <<"cpython-312">>},
          <<"module_files">> =>
              [#{<<"role">> => <<"package">>,
                 <<"sha256">> => Hash,
                 <<"bytes">> => 1}]},
    Configuration =
        #{<<"maximum_table_capacity">> => 512,
          <<"maximum_blocked_streams">> => 8},
    Header = #{<<"name">> => <<"78">>, <<"value">> => <<>>},
    CommonStep =
        #{<<"id">> => <<"fixture">>, <<"stream_id">> => 0,
          <<"delivery">> => <<"encoder_first">>,
          <<"encoder_stream">> => <<>>, <<"field_section">> => <<"00">>,
          <<"headers">> => [Header]},
    OracleDocument =
        #{<<"schema">> => 2,
          <<"direction">> => <<"pylsqpack-to-http3">>,
          <<"oracle">> => Oracle, <<"oracle_run_id">> => RunId,
          <<"configuration">> => Configuration,
          <<"encoder_stream_prefix">> => <<>>,
          <<"steps">> => [CommonStep#{<<"decoder_stream">> => <<>>}]},
    ImplementationDocument =
        #{<<"schema">> => 2,
          <<"direction">> => <<"http3-to-pylsqpack">>,
          <<"oracle">> => Oracle, <<"oracle_run_id">> => RunId,
          <<"configuration">> => Configuration,
          <<"steps">> => [CommonStep]},
    OracleInput = qpack_audit_fixture_input(OracleDocument),
    ImplementationInput = qpack_audit_fixture_input(ImplementationDocument),
    OracleSummary =
        #{cases => 1, fields => 1, blocked_cases => 0, encoded_bytes => 2},
    ImplementationSummary = OracleSummary,
    OracleExecution =
        #{<<"cases">> => 1, <<"fields">> => 1,
          <<"blocked_cases">> => 0, <<"encoder_instructions">> => 0,
          <<"feedback_instructions">> => 0, <<"feedback_bytes">> => 0,
          <<"feedback_actions_verified">> => true},
    IdentityDocument =
        #{<<"artifact_sha256">> => maps:get(sha256, ImplementationInput),
          <<"artifact_bytes">> => maps:get(bytes, ImplementationInput),
          <<"oracle_corpus_sha256">> => maps:get(sha256, OracleInput),
          <<"oracle_corpus_bytes">> => maps:get(bytes, OracleInput),
          <<"oracle_run_id">> => RunId, <<"oracle_identity">> => Oracle,
          <<"oracle_execution">> => OracleExecution,
          <<"build_identity">> => Build,
          <<"build_manifest_sha256">> => Hash,
          <<"evidence_identity">> => Evidence,
          <<"execution_environment">> => Runtime},
    IdentityInput = qpack_audit_fixture_input(IdentityDocument),
    OracleReportDocument =
        #{<<"schema">> => 2, <<"status">> => <<"Ready">>,
          <<"direction">> => <<"http3-to-pylsqpack">>,
          <<"oracle">> => Oracle, <<"oracle_run_id">> => RunId,
          <<"cases">> => 1, <<"fields">> => 1,
          <<"blocked_cases">> => 0, <<"decoder_control_bytes">> => 0,
          <<"implementation_bytes">> =>
              maps:get(bytes, ImplementationInput),
          <<"implementation_sha256">> =>
              maps:get(sha256, ImplementationInput)},
    OracleReportInput = qpack_audit_fixture_input(OracleReportDocument),
    Inputs =
        #{oracle => OracleInput, implementation => ImplementationInput,
          implementation_identity => IdentityInput,
          oracle_report => OracleReportInput},
    Report =
        #{<<"schema">> => 2, <<"status">> => <<"Ready">>,
          <<"family">> => <<"qpack-rfc9204-differential">>,
          <<"shareable">> => true,
          <<"replay_command">> => <<"mise run qpack-differential">>,
          <<"oracle">> => Oracle, <<"oracle_run_id">> => RunId,
          <<"directions">> =>
              [qpack_audit_summary(
                   <<"pylsqpack-to-http3">>, OracleSummary),
               qpack_audit_summary(
                   <<"http3-to-pylsqpack">>, ImplementationSummary)],
          <<"oracle_execution">> => OracleExecution,
          <<"oracle_corpus_bytes">> => maps:get(bytes, OracleInput),
          <<"oracle_corpus_sha256">> => maps:get(sha256, OracleInput),
          <<"implementation_corpus_bytes">> =>
              maps:get(bytes, ImplementationInput),
          <<"implementation_corpus_sha256">> =>
              maps:get(sha256, ImplementationInput),
          <<"implementation_identity_bytes">> => maps:get(bytes, IdentityInput),
          <<"implementation_identity_sha256">> =>
              maps:get(sha256, IdentityInput),
          <<"oracle_report_bytes">> => maps:get(bytes, OracleReportInput),
          <<"oracle_report_sha256">> => maps:get(sha256, OracleReportInput),
          <<"source_sha256">> => Hash,
          <<"build_identity">> => Build,
          <<"build_manifest_sha256">> => Hash,
          <<"evidence_identity">> => Evidence,
          <<"execution_environment">> => Runtime},
    {Report, Context0#{inputs => Inputs}}.

qpack_audit_fixture_input(Document) ->
    Bytes = iolist_to_binary([json:encode(Document), <<"\n">>]),
    #{path => "fixture", bytes => byte_size(Bytes),
      sha256 => qpack_audit_digest(Bytes), document => Document}.

self_test() ->
    shareable_bundle_self_test(),
    ok = coverage_report_process_self_test(),
    bundle_capture_self_test(),
    fault_evidence_self_test(),
    credential_matrix_self_test(),
    self_test_http_models(),
    self_test_campaign_and_model(),
    qpack_audit_self_test(),
    Source = <<"CURRENT-SOURCE">>,
    Target = #{<<"name">> => <<"http2-graceful-drain">>,
               <<"status">> => <<"Ready">>,
               <<"configured_repetitions">> => 30,
               <<"completed_repetitions">> => 30},
    Report = #{<<"schema">> => 1,
               <<"status">> => <<"Ready">>,
               <<"source_sha256">> => Source,
               <<"configured_targets">> => 1,
               <<"configured_repetitions">> => 30,
               <<"completed_repetitions">> => 30,
               <<"target_runs">> => [Target]},
    ok = audit_ready_report("build/fault/stability.json", Report, Source),
    expect_error(stale_source, fun() ->
        audit_ready_report(
            "build/fault/stability.json",
            Report#{<<"source_sha256">> => <<"STALE">>},
            Source)
    end),
    expect_error(partial_report, fun() ->
        audit_ready_report(
            "build/fault/stability.json",
            Report#{<<"completed_repetitions">> => 29},
            Source)
    end),
    expect_error(partial_target, fun() ->
        audit_ready_report(
            "build/fault/stability.json",
            Report#{<<"target_runs">> => [
                Target#{<<"completed_repetitions">> => 29}
            ]},
            Source)
    end),
    expect_error(non_ready_report, fun() ->
        audit_ready_report(
            "build/fault/stability.json",
            Report#{<<"status">> => <<"Failed">>},
            Source)
    end),
    HostileRun = #{<<"package">> => <<"http">>,
                   <<"status">> => <<"Ready">>,
                   <<"tests">> => 12,
                   <<"configured_modules">> => 1,
                   <<"completed_modules">> => 1,
                   <<"completed_tests">> => 12,
                   <<"modules">> => [<<"http2_server_test">>]},
    HostileReport = #{<<"schema">> => 1,
                      <<"status">> => <<"Ready">>,
                      <<"source_sha256">> => Source,
                      <<"families">> => [<<"stalled-peer-isolation">>],
                      <<"configured_packages">> => 1,
                      <<"configured_tests">> => 12,
                      <<"completed_tests">> => 12,
                      <<"package_runs">> => [HostileRun]},
    ok = audit_ready_report(
        "build/fault/hostile-peer.json", HostileReport, Source),
    expect_error(partial_hostile_report, fun() ->
        audit_ready_report(
            "build/fault/hostile-peer.json",
            HostileReport#{<<"completed_tests">> => 11},
            Source)
    end),
    ok = audit_ready_report(
        "build/qlog/report.json",
        #{<<"status">> => <<"Ready">>},
        Source),
    CoverageMethodology = expected_coverage_coordinate_methodology(),
    CoveragePolicy = #{<<"schema">> => 2,
                       <<"coordinate_methodology">> =>
                           CoverageMethodology},
    CoverageMethodology = audit_coverage_policy_contract(CoveragePolicy),
    expect_error(coverage_policy_schema, fun() ->
        audit_coverage_policy_contract(CoveragePolicy#{<<"schema">> => 1})
    end),
    expect_error(coverage_policy_methodology, fun() ->
        audit_coverage_policy_contract(
            CoveragePolicy#{<<"coordinate_methodology">> =>
                CoverageMethodology#{<<"line_universe">> => <<"stale">>}}
        )
    end),
    CoverageIdentity = #{<<"schema">> => 2,
                         <<"coordinate_methodology">> => CoverageMethodology,
                         <<"source_sha256">> => Source,
                         <<"policy_sha256">> => <<"CURRENT-POLICY">>,
                         <<"source_files">> => 478},
    CoverageDocuments = [
        "build/coverage/full.json",
        ?COVERAGE_EVIDENCE,
        {coverage_capture_summary, <<"http">>},
        "build/coverage/http.capture.json"
    ],
    lists:foreach(fun(Path) ->
        ok = audit_coverage_document_contract(
            Path, CoverageIdentity, CoverageMethodology
        ),
        expect_error({coverage_document_schema, Path}, fun() ->
            audit_coverage_document_contract(
                Path, CoverageIdentity#{<<"schema">> => 1},
                CoverageMethodology
            )
        end),
        expect_error({coverage_document_methodology, Path}, fun() ->
            audit_coverage_document_contract(
                Path,
                CoverageIdentity#{<<"coordinate_methodology">> =>
                    maps:remove(<<"unclaimed_control_flow">>,
                                CoverageMethodology)},
                CoverageMethodology
            )
        end)
    end, CoverageDocuments),
    ok = audit_coverage_identity(
        "build/coverage/full.json", CoverageIdentity,
        Source, <<"CURRENT-POLICY">>, 478
    ),
    expect_error(stale_coverage_source, fun() ->
        audit_coverage_identity(
            "build/coverage/full.json",
            CoverageIdentity#{<<"source_sha256">> => <<"STALE">>},
            Source, <<"CURRENT-POLICY">>, 478
        )
    end),
    expect_error(stale_coverage_policy, fun() ->
        audit_coverage_identity(
            "build/coverage/full.json",
            CoverageIdentity#{<<"policy_sha256">> => <<"STALE">>},
            Source, <<"CURRENT-POLICY">>, 478
        )
    end),
    ensure(byte_size(test_matrix_source_digest()) =:= 64,
           invalid_test_matrix_source_digest),
    io:format("audit bundle self-test ok (stale coverage/test-matrix source, "
              "schema/methodology drift, stale coverage policy, partial "
              "stability or hostile execution, and non-Ready reports "
              "rejected)~n"),
    ok.

require_shareable_bundle_artifacts(Artifacts) ->
    Findings = lists:append([shareable_bundle_findings(Path, Bytes)
                             || {Path, Bytes} <- Artifacts]),
    ensure(Findings =:= [], unsafe_shareable_bundle_artifact),
    ok.

shareable_bundle_findings(Path, Bytes) ->
    Normal = string:lowercase(bundle_path(Path)),
    RawDiagnostic = lists:prefix("build/rfc6455-evidence/", Normal) orelse
        lists:suffix(".tail.log", Normal),
    ValuePatterns = [
        {otp_error_report, <<"=ERROR REPORT====">>},
        {beam_process_identifier, <<"<[0-9]+\\.[0-9]+\\.[0-9]+>">>},
        {beam_runtime_handle, <<"(?i)#(?:Pid|Port|Ref)<">>},
        {user_home_path,
         <<"(?i)(?:[A-Z]:[\\\\/]Users[\\\\/][^\\s]+|"
           "/home/[^/\\s]+|/Users/[^/\\s]+)">>},
        {raw_exception_report, <<"(?i)(?:\\*\\* exception (?:error|exit|throw)|"
                                 "exception (?:error|exit|throw):)">>},
        {http_credential_header,
         <<"(?im)^(?:authorization|proxy-authorization|cookie|set-cookie)[ \\t]*:">>},
        {credential_value,
         <<"(?i)\\b(?:bearer|basic)\\s+[A-Za-z0-9._~+/=-]{4,}">>},
        {private_key_material,
         <<"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----">>},
        {connection_port_record, <<"(?im)^PORT=[0-9]{1,5}\\r?$">>},
        {url_userinfo,
         <<"(?i)[a-z][a-z0-9+.-]*://[^/?#\\s@]+@">>}
    ],
    FieldPatterns = [
        {raw_runtime_or_content_field,
         <<"(?i)\"(?:socket|socket_handle|os_pid|pid|reference|"
           "process_reference|tail|output_tail|stdout|stderr|raw_output|body|"
           "raw_body|payload|raw_payload|stack|stacktrace)\"\\s*:">>},
        {credential_field,
         <<"(?i)\"(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie|"
           "password|passwd|credential|credentials|secret|access[-_]token|"
           "refresh[-_]token)\"\\s*:">>},
        {connection_identity_field,
         <<"(?i)\"(?:endpoint|destination|authority|sni|peer[-_]address|"
           "local[-_]address|remote[-_]address)\"\\s*:">>}
    ],
    Patterns = ValuePatterns ++ case shareable_schema_artifact(Normal) of
        true -> [];
        false -> FieldPatterns
    end,
    Prefix = case RawDiagnostic of true -> [raw_diagnostic_tail]; false -> [] end,
    Rules = Prefix ++ [Rule || {Rule, Pattern} <- Patterns,
        re:run(Bytes, Pattern, [{capture, none}]) =:= match],
    [#{path => unicode:characters_to_binary(bundle_path(Path)), line => 1,
       rule => atom_to_binary(Rule)} || Rule <- lists:usort(Rules)].

shareable_schema_artifact(Normal) ->
    lists:prefix("api/", Normal) orelse
        lists:suffix("-package-interface.json", Normal) orelse
        Normal =:= "standards/requirements.json".

shareable_bundle_self_test() ->
    Safe = <<"{\"schema\":1,\"status\":\"Ready\","
             "\"classification\":\"validation_failed\","
             "\"completed\":12,\"source_sha256\":\"fixed\"}">>,
    [] = shareable_bundle_findings("build/safe/report.json", Safe),
    [] = shareable_bundle_findings("build/safe/report.json",
        <<"{\"authorization_result\":\"redacted\",\"cookie_count\":0,"
          "\"endpoint_classification\":\"loopback\","
          "\"authority_sha256\":\"fixed\","
          "\"url\":\"https://example.test/path\"}">>),
    [] = shareable_bundle_findings("build/http-package-interface.json",
        <<"{\"modules\":{\"endpoint\":{\"documentation\":\"safe\"},"
          "\"body\":{\"documentation\":\"safe\"}}}">>),
    [] = shareable_bundle_findings("standards/requirements.json",
        <<"{\"reason\":\"normative explanation\"}">>),
    [] = shareable_bundle_findings("build/safe/artifact.bin", <<0, 255, 1>>),
    Mutants = [
        {raw_tail, "build/rfc6455-evidence/run.stdout.tail.log", Safe},
        {otp_error, "build/report.json", <<"=ERROR REPORT==== fixed">>},
        {windows_path, "build/report.json", <<"C:/Users/private/run.beam">>},
        {beam_pid, "build/report.json", <<"<0.99.0>">>},
        {beam_port, "build/report.json", <<"#Port<0.4>">>},
        {raw_exception, "build/report.json", <<"** exception error: fixed">>},
        {raw_socket, "build/report.json", <<"{\"socket\":17}">>},
        {authorization, "build/report.json",
            <<"{\"authorization\":\"Bearer private-canary\"}">>},
        {authorization_header, "build/report.log",
            <<"Authorization: Bearer private-canary\n">>},
        {cookie, "build/report.json",
            <<"{\"cookie\":\"session=private-canary\"}">>},
        {set_cookie_header, "build/report.log",
            <<"Set-Cookie: session=private-canary\n">>},
        {credential, "build/report.json",
            <<"{\"password\":\"private-canary\"}">>},
        {credential_value, "build/report.json",
            <<"{\"note\":\"Bearer private-canary\"}">>},
        {access_token, "build/report.json",
            <<"{\"access_token\":\"private-canary\"}">>},
        {private_key, "build/report.json",
            <<"-----BEGIN PRIVATE KEY-----\nprivate-canary">>},
        {connection_endpoint, "build/report.json",
            <<"{\"endpoint\":\"198.51.100.7:443\"}">>},
        {connection_destination, "build/report.json",
            <<"{\"destination\":\"198.51.100.7:443\"}">>},
        {connection_authority, "build/report.json",
            <<"{\"authority\":\"private.example:443\"}">>},
        {connection_remote_address, "build/report.json",
            <<"{\"remote_address\":\"198.51.100.7\"}">>},
        {connection_port_record, "build/report.log", <<"PORT=49152\n">>},
        {url_userinfo, "build/report.json",
            <<"{\"note\":\"https://private:canary@example.test/\"}">>},
        {url_user_only, "build/report.json",
            <<"{\"note\":\"https://private@example.test/\"}">>},
        {unix_home, "build/report.json", <<"/home/private/trace.log">>},
        {raw_stack, "build/report.json",
            <<"{\"stacktrace\":[\"private frame\"]}">>}
    ],
    lists:foreach(fun({Id, Path, Bytes}) ->
        ensure(shareable_bundle_findings(Path, Bytes) =/= [],
               {unsafe_bundle_mutant_accepted, Id})
    end, Mutants),
    ok.

self_test_http_models() ->
    Hash = binary:copy(<<"A">>, 64),
    Identity = #{<<"schema">> => 2, <<"source_sha256">> => Hash, <<"files">> => 3},
    Runtime = execution_runtime(),
    Catalog = #{source_sha256 => Hash, source_files => 2},
    Tool = fun(V) -> #{declared_version => V, executable_sha256 => Hash} end,
    Rows = [#{domain => Name, seed => 982451653, cases => 10000, transitions => Count,
              sha256 => binary:copy(<<"a">>, 64), status => <<"Passed">>}
            || {Name, Count} <- [{<<"http1">>, 30000}, {<<"http2">>, 640000},
                {<<"hpack">>, 320000}, {<<"pool">>, 350000}, {<<"cancellation">>, 330000}, {<<"drain">>, 50000}]],
    Report = runtime_matrix_json(#{schema => 1, family => <<"http-state-models">>, status => <<"Ready">>,
        mode => <<"campaign">>, seed => 982451653, requested_cases_or_steps => 10000,
        execution_environment => Runtime, shareable => true, evidence_identity => Identity,
        replay_command => <<"escript scripts/http_models.escript --seed 982451653 --cases 10000">>,
        build_identity => #{schema => 3, package => <<"http">>, source_sha256 => Hash, source_files => 2,
            artifact_sha256 => Hash, artifact_files => 3,
            build_nonce => binary:copy(<<"1">>, 32),
            prebuild_profile_state => <<"absent">>,
            toolchain => #{runtime => Runtime, gleam => Tool(<<"1.18.1">>), rebar3 => Tool(<<"3.27.0">>)}},
        runner_sha256 => Hash, runner_exit => 0,
        model => #{schema => 1, nonce => binary:copy(<<"A">>, 32), mode => <<"campaign">>, status => <<"Passed">>, domains => Rows},
        runner_output => runtime_matrix_process_fixture(#{output_bytes => 0, output_hashed_bytes => 0, output_limit_bytes => 8388608,
            output_limit_exceeded => false, output_digest_complete => true, timed_out => false, child_exit_observed => true,
            vm_process_heap_words => 33554432, vm_heap_includes_shared_binaries => true, crash_dumps_disabled => true})}),
    ok = audit_http_model_report(Report, Identity, Catalog),
    Model = maps:get(<<"model">>, Report),
    lists:foreach(fun(Bad) -> expect_error(incomplete_http_models,
        fun() -> audit_http_model_report(Bad, Identity, Catalog) end) end,
        [Report#{<<"requested_cases_or_steps">> => 1000}, Report#{<<"mode">> => <<"replay">>},
         Report#{<<"evidence_identity">> => #{}}, Report#{<<"build_identity">> => #{}},
         Report#{<<"runner_exit">> => 1}, Report#{<<"payload">> => <<"fixture-private-marker">>},
         Report#{<<"model">> => Model#{<<"domains">> => tl(maps:get(<<"domains">>, Model))}}]),
    io:put_chars("HTTP model audit: exact six-domain campaign, source/build and process evidence verified\n").

self_test_campaign_and_model() -> campaign_adversarial_self_test().

audit_execution_date() ->
    {{Year, Month, Day}, _} = calendar:universal_time(),
    iolist_to_binary(io_lib:format("~4..0B-~2..0B-~2..0B", [Year, Month, Day])).

expect_error(Label, Function) ->
    Outcome = try Function() of
        _ -> unexpected_success
    catch
        error:_ -> expected_error
    end,
    ensure(Outcome =:= expected_error,
           {self_test_expected_error, Label}).

write_json(Path, Value) ->
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Value), <<"\n">>]).

read(Path) ->
    bundle_read(Path, maps:get(file_bytes, bundle_limits())).

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
