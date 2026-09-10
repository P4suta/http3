#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(OUTPUT, "build/audit-bundle").
-define(COVERAGE_POLICY, "coverage-policy.json").
-define(COVERAGE_EVIDENCE, "coverage-evidence.json").

main([]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "audit bundle failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(["--self-test"]) ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "audit bundle self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(["--verify-report", Path]) ->
    try verify_report(Path) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "qualification report verification failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(_) -> erlang:error(audit_bundle_usage).

run() ->
    reset_output(),
    Static = static_evidence(),
    ReadyReports = ready_reports(),
    TestMatrixSource = test_matrix_source_digest(),
    lists:foreach(
      fun(Path) -> require_ready_report(Path, TestMatrixSource) end,
      ReadyReports),
    Families = family_evidence(),
    lists:foreach(fun({Label, Paths}) ->
        ensure(Paths =/= [], {missing_evidence_family, Label})
    end, Families),
    Files = lists:usort(Static ++ ReadyReports ++
                        lists:append([Paths || {_Label, Paths} <- Families])),
    lists:foreach(fun(Path) ->
        ensure(filelib:is_regular(Path), {missing_audit_evidence, Path})
    end, Files),
    Entries = [#{path => unicode:characters_to_binary(Path),
                 bytes => byte_size(read(Path)),
                 sha256 => hex(crypto:hash(sha256, read(Path)))}
               || Path <- Files],
    Manifest = #{schema => 1, status => <<"Ready">>,
                 qualification_date => <<"2026-08-30">>,
                 source_sha256 => source_digest(),
                 files => Entries,
                 external_conditions => #{independent_audit => false,
                                           signed_commit => false}},
    ManifestPath = filename:join(?OUTPUT, "manifest.json"),
    write_json(ManifestPath, Manifest),
    BundleFiles = [{Path, read(Path)} || Path <- Files] ++
                  [{"audit-manifest.json", read(ManifestPath)}],
    Archive = filename:join(?OUTPUT, "audit-bundle.tar"),
    ok = erl_tar:create(Archive, lists:keysort(1, BundleFiles),
                        [{mtime, 0}, {atime, 0}, {ctime, 0},
                         {uid, 0}, {gid, 0}, {mode, 8#600}]),
    Digest = hex(crypto:hash(sha256, read(Archive))),
    write_json(filename:join(?OUTPUT, "archive.json"),
               #{status => <<"Ready">>, sha256 => Digest,
                 files => length(BundleFiles)}),
    io:format("audit bundle: ~B evidence files, sha256 ~s~n",
              [length(BundleFiles), Digest]),
    ok.

static_evidence() ->
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
     "build/security/http.cdx.json",
     "build/release-sim/release-sim.cdx.json",
     "build/release-sim/provenance.json"].

ready_reports() ->
    ["build/coverage/changed.json", "build/coverage/full.json",
     "build/campaign/property.json", "build/campaign/fuzz.json",
     "build/fault/hostile-peer.json",
     "build/fault/stability.json",
     "build/credential-matrix/report.json",
     "build/requirements/report.json", "build/qlog/report.json",
     "build/structured-fields-oracle/report.json",
     "build/qpack-differential/report.json",
     "build/examples/report.json", "build/release-sim/report.json",
     "build/interop/report.json", "build/performance/report.json",
     "build/performance/hot-path-profile.json"].

family_evidence() ->
    [
        {model, filelib:wildcard("build/model/shard-*.json")},
        {release_archives,
         filelib:wildcard("build/release-sim/pass-b/*.tar")},
        {performance,
         filelib:wildcard("packages/http3/benchmarks/results/*.csv")},
        {coverage_captures,
         filelib:wildcard("build/coverage/*.capture.json") ++
         filelib:wildcard("build/coverage/*.cover")},
        {interoperability,
         filelib:wildcard("build/interop/*.json")}
    ].

require_ready_report(Path, TestMatrixSource) ->
    ensure(filelib:is_regular(Path), {missing_ready_report, Path}),
    Report = json:decode(read(Path)),
    audit_ready_report(Path, Report, TestMatrixSource).

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
        _ -> ok
    end.

test_matrix_report(Path) ->
    lists:member(Path, ["build/fault/hostile-peer.json",
                        "build/fault/stability.json",
                        "build/credential-matrix/report.json"]).

coverage_report(Path) ->
    lists:member(Path, ["build/coverage/changed.json",
                        "build/coverage/full.json"]).

verify_report(Path) ->
    ensure(test_matrix_report(Path) orelse coverage_report(Path),
           {unsupported_ready_report, Path}),
    require_ready_report(Path, test_matrix_source_digest()),
    io:format("current-source qualification report ok: ~s~n", [Path]),
    ok.

audit_current_coverage_report(Path, Report) ->
    Policy = json:decode(read(?COVERAGE_POLICY)),
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
    Evidence = json:decode(read(?COVERAGE_EVIDENCE)),
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
    ensure(maps:get(<<"mode">>, Report, undefined) =:= Mode,
           {coverage_report_mode_mismatch, Path}),
    EvidenceStatuses = maps:get(<<"statuses">>, Evidence),
    ensure(maps:get(Mode, EvidenceStatuses, undefined) =:= <<"Ready">>,
           {coverage_evidence_not_ready, Mode}),
    lists:foreach(fun(Key) ->
        ensure(maps:get(Key, Report, undefined) =:=
                   maps:get(Key, Evidence, undefined),
               {coverage_evidence_mismatch, Path, Key})
    end, [<<"coordinate_methodology">>,
          <<"thresholds_basis_points">>, <<"full">>, <<"changed">>,
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
        Metadata = json:decode(read(MetadataPath)),
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

source_digest() ->
    Paths = source_paths(),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

source_paths() ->
    {ok, Entries} = file:list_dir("."),
    lists:sort(lists:append([collect_source_path(Entry) || Entry <- Entries])).

collect_source_path(Path) ->
    case filelib:is_dir(Path) of
        true ->
            case excluded_source_directory(filename:basename(Path)) of
                true -> [];
                false ->
                    {ok, Entries} = file:list_dir(Path),
                    lists:append([
                        collect_source_path(filename:join(Path, Entry))
                        || Entry <- Entries
                    ])
            end;
        false ->
            case filelib:is_regular(Path) of
                true -> [Path];
                false -> []
            end
    end.

excluded_source_directory(Name) ->
    lists:member(Name, [".agents", ".claude", ".codex", ".git", ".idea",
                        ".vscode", "_build", "audit", "build", "deps"]).

reset_output() ->
    Expected = filename:join(filename:absname("build"), "audit-bundle"),
    case filename:absname(?OUTPUT) of
        Expected ->
            _ = file:del_dir_r(Expected),
            ok = filelib:ensure_dir(filename:join(Expected, "placeholder"));
        Unsafe -> erlang:error({unsafe_audit_bundle_output, Unsafe})
    end.

self_test() ->
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
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
