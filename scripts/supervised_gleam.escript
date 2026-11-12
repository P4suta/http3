#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("diagnostic_failure.hrl").
-include("command_capture.hrl").
-include("file_identity.hrl").
-include("json_evidence.hrl").
-include("suite_evidence.hrl").
-include("suite_discovery.hrl").
-include("canonical_etf_wire.hrl").
-include("execution_beam_identity.hrl").
-include_lib("kernel/include/file.hrl").

main(["--self-test"] = Arguments) ->
    supervised_gleam_with_owner_observer(
        fun() -> supervised_gleam_inner_main(Arguments) end);
main(Arguments) ->
    case {supervised_gleam_arguments_valid(Arguments),
          os:getenv("HTTP_SUPERVISED_GLEAM_INNER")} of
        {false, _} -> halt(2);
        {true, "1"} -> supervised_gleam_with_owner_observer(
            fun() -> supervised_gleam_inner_main(Arguments) end);
        {true, _} -> supervised_gleam_with_owner_observer(
            fun() -> supervised_gleam_outer(Arguments) end)
    end.

supervised_gleam_with_owner_observer(Operation) ->
    execution_beam_with_owned_platform_observer(
        fun supervised_gleam_owner_identity_capture/4, Operation).

supervised_gleam_owner_identity_capture(Executable, Arguments,
                                        Timeout, Limit) ->
    try command_capture(Executable, Arguments, filename:absname("."),
                        Timeout, Limit, []) of
        {ok, Output, Proof} when is_binary(Output) ->
            case command_success_verified(Proof) of
                true -> {ok, Output};
                false -> {error, owner_identity_capture_unverified}
            end;
        _ -> {error, owner_identity_capture_failed}
    catch _:_ -> {error, owner_identity_capture_failed}
    end.

supervised_gleam_inner_main([Mode | Paths])
  when Mode =:= "--check"; Mode =:= "--write" ->
    try supervised_gleam(Mode, Paths) of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
supervised_gleam_inner_main([Mode])
  when Mode =:= "--http3-check"; Mode =:= "--http3-test";
                  Mode =:= "--http-check"; Mode =:= "--http-test";
                  Mode =:= "--quic-check"; Mode =:= "--quic-test" ->
    try supervised_package(Mode) of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
supervised_gleam_inner_main([Mode])
  when Mode =:= "--http-diagnostic-check";
       Mode =:= "--http3-diagnostic-check";
       Mode =:= "--quic-diagnostic-check" ->
    try supervised_diagnostic_check(Mode) of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
supervised_gleam_inner_main(["--http-exact-test"]) ->
    try supervised_http_exact_test() of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
supervised_gleam_inner_main(["--http-server-exact-test"]) ->
    try supervised_http_server_exact_test() of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
supervised_gleam_inner_main(["--http-ohttp-exact-test"]) ->
    try supervised_http_ohttp_exact_test() of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
supervised_gleam_inner_main(["--self-test"]) ->
    try supervised_gleam_self_test() of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "supervised Gleam failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end.

supervised_gleam_arguments_valid([Mode | Paths])
  when Mode =:= "--check"; Mode =:= "--write" ->
    Paths =/= [] andalso length(Paths) =< 256;
supervised_gleam_arguments_valid([Mode]) ->
    lists:member(Mode, ["--http3-check", "--http3-test", "--http-check",
                        "--http-test", "--quic-check", "--quic-test",
                        "--http-diagnostic-check",
                        "--http3-diagnostic-check",
                        "--quic-diagnostic-check",
                        "--http-exact-test", "--http-server-exact-test",
                        "--http-ohttp-exact-test",
                        "--self-test"]);
supervised_gleam_arguments_valid(_) -> false.

%% The outer VM performs no workload. It places the inner escript and every
%% native descendant under the same pinned Job/process-group supervisor before
%% any Gleam command can start. The caller still launches this one fixed VM
%% with Start-Process -WindowStyle Hidden on Windows.
supervised_gleam_outer(Arguments) ->
    Root = filename:absname("."),
    EscriptName = case os:type() of {win32, _} -> "escript.exe"; _ -> "escript" end,
    Escript = filename:join([code:root_dir(), "bin", EscriptName]),
    true = filelib:is_regular(Escript),
    Script = filename:absname(escript:script_name()),
    Timeout = supervised_gleam_outer_timeout(Arguments),
    PackageAttempt = supervised_gleam_outer_package_attempt_begin(
        Arguments, Root, Script),
    Environment = supervised_gleam_inner_environment(PackageAttempt),
    Result = case supervised_gleam_projected_arguments(Arguments) of
        true ->
            Project = case supervised_gleam_test_arguments(Arguments) of
                true -> fun(Bytes) ->
                    gleam_outer_test_failure_projection(
                        Bytes, maps:get(nonce, PackageAttempt),
                        maps:get(source_before_sha256, PackageAttempt),
                        maps:get(runner_before_sha256, PackageAttempt),
                        maps:get(mode, PackageAttempt))
                end;
                false -> fun gleam_test_failure_projection/1
            end,
            command_capture_projected(
                Escript, [Script | Arguments], Root, Timeout, 2097152,
                Environment, Project,
                fun gleam_test_failure_projection_valid/1);
        false -> command_capture(Escript, [Script | Arguments], Root, Timeout,
                                 2097152, Environment)
    end,
    case PackageAttempt of
        none -> supervised_gleam_outer_nonpackage_result(Arguments, Result);
        Attempt -> supervised_gleam_outer_package_result(Attempt, Result)
    end.

supervised_gleam_inner_environment(none) ->
    [{"HTTP_SUPERVISED_GLEAM_INNER", "1"}];
supervised_gleam_inner_environment(Attempt) when is_map(Attempt) ->
    Nonce = maps:get(nonce, Attempt),
    SourceSha = maps:get(source_before_sha256, Attempt),
    RunnerSha = maps:get(runner_before_sha256, Attempt),
    Mode = maps:get(mode, Attempt),
    true = execution_beam_digest(Nonce, 32),
    true = exact_sha256_valid(SourceSha),
    true = exact_sha256_valid(RunnerSha),
    true = supervised_gleam_test_arguments([Mode]),
    [{"HTTP_SUPERVISED_GLEAM_INNER", "1"},
     {"HTTP_SUPERVISED_GLEAM_PROJECTION_NONCE", binary_to_list(Nonce)},
     {"HTTP_SUPERVISED_GLEAM_PROJECTION_SOURCE_SHA256",
      binary_to_list(SourceSha)},
     {"HTTP_SUPERVISED_GLEAM_PROJECTION_RUNNER_SHA256",
      binary_to_list(RunnerSha)},
     {"HTTP_SUPERVISED_GLEAM_PROJECTION_MODE", Mode}].

supervised_gleam_outer_nonpackage_result(Arguments, Result) ->
    case Result of
        {ok, Output, Proof} ->
            true = command_success_verified(Proof),
            Outcome = supervised_gleam_inner_outcome(Arguments, Output),
            supervised_gleam_emit_outer_success(Outcome),
            case Outcome of
                failed -> halt(1);
                _ -> ok
            end;
        {error, Projection, Proof} when is_map(Projection) ->
            io:format(standard_error,
                      "supervised Gleam outer test failed: "
                      "projection=~p process=~p~n",
                      [Projection, supervised_package_process_proof(Proof)]),
            halt(1);
        {error, Proof} ->
            Safe = maps:with([outcome, exit_status, child_exit_observed,
                process_supervisor_protocol_valid,
                process_supervisor_failure_code,
                process_supervisor_attestation_failure,
                native_tree_empty, native_console_isolated,
                native_descendant_outlived,
                native_termination_requested], Proof),
            io:format(standard_error,
                      "supervised Gleam outer process rejected: ~p~n", [Safe]),
            halt(1);
        {error, ProjectionFailure, Proof} ->
            ProjectionCategory = case ProjectionFailure of
                no_failure_projection -> no_failure_projection;
                invalid_failure_projection -> invalid_failure_projection;
                _ -> unknown_failure_projection
            end,
            io:format(standard_error,
                      "supervised Gleam outer test projection rejected: "
                      "category=~p process=~p~n",
                      [ProjectionCategory,
                       supervised_package_process_proof(Proof)]),
            halt(1)
    end.

supervised_gleam_outer_package_attempt_begin([Mode], Root, Script)
  when Mode =:= "--http-test";
       Mode =:= "--http3-test";
       Mode =:= "--quic-test" ->
    {Package, Directory, SourcePaths} =
        supervised_gleam_package_test_scope(Mode, Root),
    true = SourcePaths =/= [] andalso length(SourcePaths) =< 20000,
    RunnerPaths = ["scripts/supervised_gleam.escript",
                   "scripts/diagnostic_failure.hrl",
                   "scripts/command_capture.hrl",
                   "scripts/process_runner.hrl",
                   "scripts/file_identity.hrl",
                   "scripts/json_evidence.hrl",
                   "scripts/suite_evidence.hrl",
                   "scripts/suite_discovery.hrl",
                   "scripts/execution_beam_identity.hrl",
                   "scripts/evidence_publication.hrl",
                   "scripts/canonical_etf_wire.hrl"],
    ExpectedScript = filename:absname(filename:join(
        Root, "scripts/supervised_gleam.escript")),
    true = exact_normalized_absolute(ExpectedScript) =:=
        exact_normalized_absolute(Script),
    Gleam = gleam_executable(),
    #{root => Root, directory => Directory,
      mode => Mode, package => list_to_binary(Package),
      source_paths_before => SourcePaths,
      source_before_sha256 => root_relative_digest(Root, SourcePaths),
      source_files_before => length(SourcePaths),
      runner_paths => RunnerPaths,
      runner_before_sha256 => root_relative_digest(Root, RunnerPaths),
      toolchain => supervised_toolchain(Gleam),
      nonce => binary:encode_hex(crypto:strong_rand_bytes(16), lowercase)};
supervised_gleam_outer_package_attempt_begin(_, _, _) -> none.

supervised_gleam_package_test_scope(Mode, Root) ->
    Http3Directory = filename:join(Root, "packages/http3"),
    QuicDirectory = filename:join(Root, "packages/quic_core"),
    RootToolConfig = case filelib:is_regular(filename:join(Root, ".mise.toml")) of
        true -> [".mise.toml"];
        false -> []
    end,
    case Mode of
        "--http-test" ->
            {"http", Root, http_check_source_paths(Root)};
        "--http3-test" ->
            Paths = RootToolConfig
                ++ supervised_gleam_prefixed_package_paths(
                    "packages/http3", Http3Directory)
                ++ supervised_gleam_prefixed_package_paths(
                    "packages/quic_core", QuicDirectory),
            {"http3", Http3Directory, lists:usort(Paths)};
        "--quic-test" ->
            Paths = RootToolConfig
                ++ supervised_gleam_prefixed_package_paths(
                    "packages/quic_core", QuicDirectory),
            {"quic_core", QuicDirectory, lists:usort(Paths)}
    end.

supervised_gleam_prefixed_package_paths(Prefix, Directory) ->
    [exact_normalized_relative(filename:join(Prefix, Path))
     || Path <- package_check_source_paths(Directory)].

supervised_gleam_outer_package_result(Attempt0, Result) ->
    {Outcome0, Proof} = supervised_gleam_outer_package_command_outcome(
        maps:get(mode, Attempt0), Result),
    Attempt = supervised_gleam_outer_package_attempt_finish(Attempt0),
    Outcome = supervised_gleam_outer_package_bind_outcome(Outcome0, Attempt),
    Report = supervised_gleam_outer_package_report(Attempt, Outcome, Proof),
    case supervised_gleam_outer_package_report_valid(Report) of
        false ->
            io:format(standard_error,
                      "supervised_gleam report_publication_failed=true~n", []),
            halt(1);
        true ->
            case supervised_gleam_publish_package_report(Attempt, Report) of
                {ok, ReportPath} ->
                    Line = supervised_gleam_outer_package_report_line(
                        Report, ReportPath),
                    case maps:get(status, Report) of
                        <<"Ready">> ->
                            io:put_chars([Line, $\n]),
                            ok;
                        <<"Failed">> ->
                            io:put_chars(standard_error, [Line, $\n]),
                            halt(1)
                    end;
                error ->
                    io:format(standard_error,
                              "supervised_gleam "
                              "report_publication_failed=true~n", []),
                    halt(1)
            end
    end.

supervised_gleam_outer_package_command_outcome(Mode, {ok, Output, Proof}) ->
    case command_success_verified(Proof) of
        false ->
            {supervised_gleam_package_failed_outcome(
                 <<"inner_process">>,
                 <<"inner_process_attestation_rejected">>), Proof};
        true ->
            case supervised_gleam_inner_outcome([Mode], Output) of
                {passed, Evidence} ->
                    {#{status => ready, evidence => Evidence,
                       failure_phase => <<"none">>,
                       failure_classification => <<"none">>}, Proof};
                {failed, Classification} ->
                    {supervised_gleam_package_failed_outcome(
                         <<"inner_evidence">>, Classification), Proof}
            end
    end;
supervised_gleam_outer_package_command_outcome(
  _Mode, {error, Projection, Proof}) when is_map(Projection) ->
    case gleam_test_failure_projection_valid(Projection) of
        true ->
            {(supervised_gleam_package_failed_outcome(
                 <<"inner_test">>, <<"inner_test_failed">>))#{
                    failure_projection => Projection}, Proof};
        false ->
            {supervised_gleam_package_failed_outcome(
                 <<"failure_projection">>,
                 <<"inner_failure_projection_rejected">>), Proof}
    end;
supervised_gleam_outer_package_command_outcome(_Mode, {error, Proof}) ->
    {Phase, Classification} = supervised_gleam_package_process_failure(Proof),
    {supervised_gleam_package_failed_outcome(Phase, Classification), Proof};
supervised_gleam_outer_package_command_outcome(
  _Mode, {error, _ProjectionFailure, Proof}) ->
    {supervised_gleam_package_failed_outcome(
         <<"failure_projection">>,
         <<"inner_failure_projection_rejected">>), Proof}.

supervised_gleam_package_failed_outcome(Phase, Classification) ->
    #{status => failed, evidence => none, failure_phase => Phase,
      failure_classification => Classification, failure_projection => none}.

supervised_gleam_package_process_failure(Proof) when is_map(Proof) ->
    case maps:get(outcome, Proof, invalid) of
        start_failed ->
            {<<"inner_process">>, <<"inner_process_start_failed">>};
        deadline ->
            {<<"inner_process">>, <<"inner_process_deadline">>};
        output_limit ->
            {<<"inner_process">>, <<"inner_process_output_limit">>};
        protocol_failure ->
            {<<"inner_process">>, <<"inner_process_protocol_rejected">>};
        collector_failure ->
            {<<"inner_process">>, <<"inner_process_protocol_rejected">>};
        supervisor_unconfirmed ->
            {<<"inner_process">>,
             <<"inner_process_attestation_rejected">>};
        reap_failed ->
            {<<"inner_process">>,
             <<"inner_process_attestation_rejected">>};
        ok ->
            {<<"inner_process">>,
             <<"inner_process_attestation_rejected">>};
        exit_failure ->
            {<<"inner_process">>,
             <<"inner_process_attestation_rejected">>};
        _ ->
            {<<"inner_process">>,
             <<"inner_process_attestation_rejected">>}
    end;
supervised_gleam_package_process_failure(_) ->
    {<<"inner_process">>, <<"inner_process_attestation_rejected">>}.

supervised_gleam_outer_package_attempt_finish(Attempt) ->
    Root = maps:get(root, Attempt),
    Mode = maps:get(mode, Attempt),
    SourceAfter = try
        {Package, Directory, Paths} = supervised_gleam_package_test_scope(
            Mode, Root),
        true = list_to_binary(Package) =:= maps:get(package, Attempt),
        true = exact_normalized_absolute(Directory) =:=
            exact_normalized_absolute(maps:get(directory, Attempt)),
        true = Paths =/= [] andalso length(Paths) =< 20000,
        #{source_paths_after => Paths,
          source_after_sha256 => root_relative_digest(Root, Paths),
          source_files_after => length(Paths),
          source_after_state => verified}
    catch _:_ ->
        #{source_paths_after => [], source_after_sha256 => null,
          source_files_after => 0, source_after_state => unavailable}
    end,
    RunnerAfter = try
        RunnerPaths = maps:get(runner_paths, Attempt),
        #{runner_after_sha256 => root_relative_digest(Root, RunnerPaths),
          runner_after_state => verified}
    catch _:_ ->
        #{runner_after_sha256 => null,
          runner_after_state => unavailable}
    end,
    Finished0 = maps:merge(maps:merge(Attempt, SourceAfter), RunnerAfter),
    SourceStable = maps:get(source_after_state, Finished0) =:= verified
        andalso maps:get(source_paths_before, Finished0) =:=
            maps:get(source_paths_after, Finished0)
        andalso maps:get(source_before_sha256, Finished0) =:=
            maps:get(source_after_sha256, Finished0),
    RunnerStable = maps:get(runner_after_state, Finished0) =:= verified
        andalso maps:get(runner_before_sha256, Finished0) =:=
            maps:get(runner_after_sha256, Finished0),
    Finished0#{source_stable => SourceStable,
               runner_stable => RunnerStable}.

supervised_gleam_outer_package_bind_outcome(Outcome, Attempt) ->
    case supervised_gleam_outer_package_binding_failure(Attempt) of
        none -> Outcome;
        {Phase, Classification} ->
            Outcome#{status => failed, failure_phase => Phase,
                     failure_classification => Classification}
    end.

supervised_gleam_outer_package_binding_failure(Attempt) ->
    case {maps:get(source_after_state, Attempt),
          maps:get(source_stable, Attempt),
          maps:get(runner_after_state, Attempt),
          maps:get(runner_stable, Attempt)} of
        {unavailable, _, _, _} ->
            {<<"source_verification">>, <<"source_capture_failed">>};
        {verified, false, _, _} ->
            {<<"source_verification">>,
             <<"source_changed_during_test">>};
        {verified, true, unavailable, _} ->
            {<<"runner_identity">>, <<"runner_identity_unavailable">>};
        {verified, true, verified, false} ->
            {<<"runner_identity">>, <<"runner_changed_during_test">>};
        {verified, true, verified, true} -> none
    end.

supervised_gleam_outer_package_report(Attempt, Outcome, Proof0) ->
    Evidence = maps:get(evidence, Outcome, none),
    {CountsState, Modules, Units, InventorySha} = case Evidence of
        EvidenceValue when is_map(EvidenceValue) ->
            {<<"verified">>, maps:get(modules, EvidenceValue),
             maps:get(configured_units, EvidenceValue),
             maps:get(inventory_sha256, EvidenceValue)};
        none -> {<<"unavailable">>, null, null, null}
    end,
    Projection0 = maps:get(failure_projection, Outcome, none),
    Projection = case gleam_test_failure_projection_valid(Projection0) of
        true -> Projection0;
        false -> null
    end,
    {CompletionState, Completed, ObservedFailures} = case Evidence of
        CompletionEvidence when is_map(CompletionEvidence) ->
            {<<"verified">>, maps:get(completed_tests, CompletionEvidence), 0};
        none -> supervised_gleam_projected_completion(Projection)
    end,
    {SkippedState, Skipped} = case Evidence of
        SkippedEvidence when is_map(SkippedEvidence) ->
            {<<"verified">>, 0};
        none ->
            {<<"unavailable">>, null}
    end,
    Process = case is_map(Proof0) of
        true -> exact_safe_process(Proof0);
        false -> #{}
    end,
    Status = case maps:get(status, Outcome) of
        ready -> <<"Ready">>;
        failed -> <<"Failed">>
    end,
    Mode = list_to_binary(maps:get(mode, Attempt)),
    SourceAfter = maps:get(source_after_sha256, Attempt),
    {CurrentSource, CurrentSourceFiles} = case SourceAfter of
        SourceDigestValue when is_binary(SourceDigestValue) ->
            {SourceDigestValue, maps:get(source_files_after, Attempt)};
        null ->
            {maps:get(source_before_sha256, Attempt),
             maps:get(source_files_before, Attempt)}
    end,
    RunnerAfter = maps:get(runner_after_sha256, Attempt),
    CurrentRunner = case RunnerAfter of
        RunnerDigestValue when is_binary(RunnerDigestValue) ->
            RunnerDigestValue;
        null -> maps:get(runner_before_sha256, Attempt)
    end,
    ProjectionBound = is_map(Projection)
        andalso maps:get(source_stable, Attempt)
        andalso maps:get(runner_stable, Attempt),
    FailureCount = case {Status, CompletionState} of
        {<<"Ready">>, _} -> 0;
        {<<"Failed">>, <<"projected">>} -> ObservedFailures;
        {<<"Failed">>, _} -> 1
    end,
    #{schema => 2, report_kind => <<"supervised_package_test">>,
      shareable => true, status => Status,
      mode => Mode, package => maps:get(package, Attempt),
      source_sha256 => CurrentSource, source_files => CurrentSourceFiles,
      source_before_sha256 => maps:get(source_before_sha256, Attempt),
      source_after_sha256 => maps:get(source_after_sha256, Attempt),
      source_files_before => maps:get(source_files_before, Attempt),
      source_files_after => maps:get(source_files_after, Attempt),
      source_stable => maps:get(source_stable, Attempt),
      runner_sha256 => CurrentRunner,
      runner_before_sha256 => maps:get(runner_before_sha256, Attempt),
      runner_after_sha256 => maps:get(runner_after_sha256, Attempt),
      runner_stable => maps:get(runner_stable, Attempt),
      toolchain => maps:get(toolchain, Attempt),
      configured_modules => Modules, configured_units => Units,
      suite_inventory_sha256 => InventorySha,
      completed_tests => Completed, skipped_tests => Skipped,
      skipped_tests_state => SkippedState,
      failure_count => FailureCount,
      observed_test_failures => ObservedFailures,
      counts_state => CountsState, completion_state => CompletionState,
      failure_projection => Projection,
      failure_projection_bound_to_current_source => ProjectionBound,
      inner_process_verified => process_completion_verified(Process),
      outer_process => Process,
      failure_phase => maps:get(failure_phase, Outcome),
      failure_classification => maps:get(failure_classification, Outcome),
      rerun_command => <<"escript scripts/supervised_gleam.escript ",
                         Mode/binary>>}.

supervised_gleam_projected_completion(Projection) when is_map(Projection) ->
    case maps:get(summary_state, Projection, <<"unavailable">>) of
        <<"projected">> ->
            {<<"projected">>, maps:get(completed_tests, Projection),
             maps:get(observed_test_failures, Projection)};
        _ -> {<<"unavailable">>, null, null}
    end;
supervised_gleam_projected_completion(_) ->
    {<<"unavailable">>, null, null}.

supervised_gleam_outer_package_report_valid(Report) when is_map(Report) ->
    try
        true = lists:sort(maps:keys(Report)) =:= lists:sort([
            schema, report_kind, shareable, status, mode, package,
            source_sha256, source_files,
            source_before_sha256, source_after_sha256,
            source_files_before, source_files_after, source_stable,
            runner_sha256,
            runner_before_sha256, runner_after_sha256, runner_stable,
            toolchain, configured_modules, configured_units,
            suite_inventory_sha256, completed_tests, skipped_tests,
            skipped_tests_state, failure_count,
            observed_test_failures, counts_state, completion_state,
            failure_projection,
            failure_projection_bound_to_current_source,
            inner_process_verified, outer_process, failure_phase,
            failure_classification, rerun_command]),
        2 = maps:get(schema, Report),
        <<"supervised_package_test">> = maps:get(report_kind, Report),
        true = maps:get(shareable, Report),
        Mode = maps:get(mode, Report),
        Package = maps:get(package, Report),
        true = supervised_gleam_package_mode_package_valid(Mode, Package),
        true = exact_sha256_valid(maps:get(source_before_sha256, Report)),
        true = exact_positive_count(maps:get(source_files_before, Report),
                                    20000),
        SourceAfter = maps:get(source_after_sha256, Report),
        SourceFilesAfter = maps:get(source_files_after, Report),
        true = (SourceAfter =:= null andalso SourceFilesAfter =:= 0) orelse
            (exact_sha256_valid(SourceAfter) andalso
             exact_positive_count(SourceFilesAfter, 20000)),
        ExpectedSource = case SourceAfter of
            SourceDigestValue when is_binary(SourceDigestValue) ->
                {SourceDigestValue, SourceFilesAfter};
            null ->
                {maps:get(source_before_sha256, Report),
                 maps:get(source_files_before, Report)}
        end,
        ExpectedSource = {maps:get(source_sha256, Report),
                          maps:get(source_files, Report)},
        SourceStable = maps:get(source_stable, Report),
        true = is_boolean(SourceStable),
        SourceStableExpected = SourceAfter =/= null
            andalso maps:get(source_before_sha256, Report) =:= SourceAfter
            andalso maps:get(source_files_before, Report) =:= SourceFilesAfter,
        SourceStableExpected = SourceStable,
        true = exact_sha256_valid(maps:get(runner_before_sha256, Report)),
        RunnerAfter = maps:get(runner_after_sha256, Report),
        true = RunnerAfter =:= null orelse exact_sha256_valid(RunnerAfter),
        ExpectedRunner = case RunnerAfter of
            RunnerDigestValue when is_binary(RunnerDigestValue) ->
                RunnerDigestValue;
            null -> maps:get(runner_before_sha256, Report)
        end,
        ExpectedRunner = maps:get(runner_sha256, Report),
        RunnerStable = maps:get(runner_stable, Report),
        true = is_boolean(RunnerStable),
        RunnerStableExpected = RunnerAfter =/= null andalso
            maps:get(runner_before_sha256, Report) =:= RunnerAfter,
        RunnerStableExpected = RunnerStable,
        true = supervised_toolchain_valid(maps:get(toolchain, Report)),
        Process = maps:get(outer_process, Report),
        true = exact_public_process_valid(Process),
        true = supervised_gleam_package_process_bounds_valid(Mode, Process),
        InnerProcessVerified = maps:get(inner_process_verified, Report),
        true = is_boolean(InnerProcessVerified),
        InnerProcessVerified = process_completion_verified(Process),
        CountsState = maps:get(counts_state, Report),
        CompletionState = maps:get(completion_state, Report),
        Modules = maps:get(configured_modules, Report),
        Units = maps:get(configured_units, Report),
        InventorySha = maps:get(suite_inventory_sha256, Report),
        Completed = maps:get(completed_tests, Report),
        ObservedFailures = maps:get(observed_test_failures, Report),
        FailureCount = maps:get(failure_count, Report),
        Projection = maps:get(failure_projection, Report),
        ProjectionBound = maps:get(
            failure_projection_bound_to_current_source, Report),
        true = is_boolean(ProjectionBound),
        true = ProjectionBound =:= (is_map(Projection)
            andalso SourceStable andalso RunnerStable),
        true = case {CountsState, CompletionState} of
            {<<"verified">>, <<"verified">>} ->
                exact_positive_count(Modules, 10000)
                    andalso exact_positive_count(Units, 10000)
                    andalso exact_sha256_valid(InventorySha)
                    andalso exact_positive_count(Completed, 999999999)
                    andalso ObservedFailures =:= 0
                    andalso Projection =:= null;
            {<<"unavailable">>, <<"projected">>} ->
                Modules =:= null andalso Units =:= null
                    andalso InventorySha =:= null
                    andalso exact_positive_count(Completed, 999999999)
                    andalso exact_positive_count(
                        ObservedFailures, 999999999)
                    andalso ObservedFailures =< Completed
                    andalso is_map(Projection)
                    andalso gleam_test_failure_projection_valid(Projection)
                    andalso maps:get(summary_state, Projection) =:=
                        <<"projected">>
                    andalso maps:get(completed_tests, Projection) =:= Completed
                    andalso maps:get(observed_test_failures, Projection) =:=
                        ObservedFailures;
            {<<"unavailable">>, <<"unavailable">>} ->
                Modules =:= null andalso Units =:= null
                    andalso InventorySha =:= null
                    andalso Completed =:= null
                    andalso ObservedFailures =:= null
                    andalso (Projection =:= null orelse
                        (is_map(Projection)
                         andalso gleam_test_failure_projection_valid(Projection)
                         andalso maps:get(summary_state, Projection) =/=
                            <<"projected">>));
            _ -> false
        end,
        true = case {maps:get(status, Report), CompletionState} of
            {<<"Ready">>, <<"verified">>} -> FailureCount =:= 0;
            {<<"Failed">>, <<"projected">>} ->
                FailureCount =:= ObservedFailures;
            {<<"Failed">>, <<"verified">>} -> FailureCount =:= 1;
            {<<"Failed">>, <<"unavailable">>} -> FailureCount =:= 1;
            _ -> false
        end,
        SkippedState = maps:get(skipped_tests_state, Report),
        Skipped = maps:get(skipped_tests, Report),
        true = case SkippedState of
            <<"verified">> ->
                CountsState =:= <<"verified">> andalso Skipped =:= 0;
            <<"unavailable">> ->
                CountsState =:= <<"unavailable">> andalso Skipped =:= null;
            _ -> false
        end,
        Rerun = <<"escript scripts/supervised_gleam.escript ", Mode/binary>>,
        Rerun = maps:get(rerun_command, Report),
        true = supervised_gleam_outer_package_status_valid(Report),
        true
    catch _:_ -> false end;
supervised_gleam_outer_package_report_valid(_) -> false.

supervised_gleam_package_process_bounds_valid(Mode, Process) ->
    Required = [outcome, exit_status, deadline_ms, elapsed_ms, output_bytes,
        output_limit_bytes, output_limit_exceeded, timed_out,
        terminal_control_bytes_removed, child_exit_observed],
    lists:all(fun(Key) -> maps:is_key(Key, Process) end, Required)
        andalso maps:get(deadline_ms, Process, -1) =:=
            supervised_gleam_outer_timeout([binary_to_list(Mode)])
        andalso maps:get(output_limit_bytes, Process, -1) =:= 2097152
        andalso exact_nonnegative_count(
            maps:get(elapsed_ms, Process, -1),
            maps:get(deadline_ms, Process, 0) + 15000)
        andalso exact_nonnegative_count(
            maps:get(output_bytes, Process, -1), 9223372036854775807)
        andalso exact_nonnegative_count(
            maps:get(terminal_control_bytes_removed, Process, -1),
            9223372036854775807).

supervised_gleam_package_mode_package_valid(<<"--http-test">>, <<"http">>) ->
    true;
supervised_gleam_package_mode_package_valid(
  <<"--http3-test">>, <<"http3">>) -> true;
supervised_gleam_package_mode_package_valid(
  <<"--quic-test">>, <<"quic_core">>) -> true;
supervised_gleam_package_mode_package_valid(_, _) -> false.

supervised_gleam_outer_package_status_valid(Report) ->
    case maps:get(status, Report) of
        <<"Ready">> ->
            maps:get(source_stable, Report)
                andalso maps:get(runner_stable, Report)
                andalso maps:get(counts_state, Report) =:= <<"verified">>
                andalso maps:get(completion_state, Report) =:= <<"verified">>
                andalso maps:get(inner_process_verified, Report)
                andalso command_success_verified(
                    maps:get(outer_process, Report))
                andalso maps:get(failure_count, Report) =:= 0
                andalso maps:get(observed_test_failures, Report) =:= 0
                andalso maps:get(failure_projection, Report) =:= null
                andalso maps:get(failure_phase, Report) =:= <<"none">>
                andalso maps:get(failure_classification, Report) =:=
                    <<"none">>;
        <<"Failed">> ->
            maps:get(failure_count, Report) > 0
                andalso supervised_gleam_package_failure_pair_valid(
                    maps:get(failure_phase, Report),
                    maps:get(failure_classification, Report))
                andalso supervised_gleam_package_failure_evidence_valid(
                    Report);
        _ -> false
    end.

supervised_gleam_package_failure_evidence_valid(Report) ->
    Phase = maps:get(failure_phase, Report),
    Classification = maps:get(failure_classification, Report),
    Process = maps:get(outer_process, Report),
    Stable = maps:get(source_stable, Report)
        andalso maps:get(runner_stable, Report),
    CountsUnavailable = maps:get(counts_state, Report) =:= <<"unavailable">>,
    CompletionUnavailable = maps:get(completion_state, Report) =:=
        <<"unavailable">>,
    NoFailureProjection = maps:get(failure_projection, Report) =:= null,
    case {Phase, Classification} of
        {<<"inner_evidence">>, _} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso command_success_verified(Process);
        {<<"inner_test">>, <<"inner_test_failed">>} ->
            Stable andalso CountsUnavailable
                andalso supervised_gleam_package_natural_failure_valid(
                    Process)
                andalso supervised_gleam_projected_failure_valid(Report);
        {<<"failure_projection">>,
         <<"inner_failure_projection_rejected">>} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso supervised_gleam_package_natural_failure_valid(
                    Process);
        {<<"inner_process">>, <<"inner_process_start_failed">>} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso maps:get(outcome, Process, invalid) =:= start_failed
                andalso maps:get(exit_status, Process, invalid) =:= null
                andalso not maps:get(child_exit_observed, Process, true);
        {<<"inner_process">>, <<"inner_process_deadline">>} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso maps:get(outcome, Process, invalid) =:= deadline
                andalso process_deadline_verified(
                    maps:get(exit_status, Process, invalid), Process);
        {<<"inner_process">>, <<"inner_process_output_limit">>} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso maps:get(outcome, Process, invalid) =:= output_limit
                andalso process_output_limit_verified(
                    maps:get(exit_status, Process, invalid), Process);
        {<<"inner_process">>, <<"inner_process_protocol_rejected">>} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso lists:member(maps:get(outcome, Process, invalid),
                                     [protocol_failure, collector_failure]);
        {<<"inner_process">>,
         <<"inner_process_attestation_rejected">>} ->
            Stable andalso CountsUnavailable andalso CompletionUnavailable
                andalso NoFailureProjection
                andalso not process_completion_verified(Process)
                andalso lists:member(maps:get(outcome, Process, invalid),
                    [ok, exit_failure, supervisor_unconfirmed, reap_failed]);
        {<<"source_verification">>, <<"source_capture_failed">>} ->
            maps:get(source_after_sha256, Report) =:= null
                andalso maps:get(source_files_after, Report) =:= 0
                andalso not maps:get(source_stable, Report);
        {<<"source_verification">>,
         <<"source_changed_during_test">>} ->
            is_binary(maps:get(source_after_sha256, Report))
                andalso not maps:get(source_stable, Report);
        {<<"runner_identity">>, <<"runner_identity_unavailable">>} ->
            maps:get(source_stable, Report)
                andalso maps:get(runner_after_sha256, Report) =:= null
                andalso not maps:get(runner_stable, Report);
        {<<"runner_identity">>, <<"runner_changed_during_test">>} ->
            maps:get(source_stable, Report)
                andalso is_binary(maps:get(runner_after_sha256, Report))
                andalso not maps:get(runner_stable, Report);
        _ -> false
    end.

supervised_gleam_package_natural_failure_valid(Process) ->
    command_natural_exit_verified(Process)
        andalso maps:get(outcome, Process, invalid) =:= exit_failure
        andalso maps:get(exit_status, Process, 0) > 0.

supervised_gleam_projected_failure_valid(Report) ->
    Projection = maps:get(failure_projection, Report),
    case {maps:get(completion_state, Report), Projection} of
        {<<"projected">>, Value} when is_map(Value) ->
            gleam_test_failure_projection_valid(Value)
                andalso maps:get(summary_state, Value) =:= <<"projected">>
                andalso maps:get(failure_count, Report) =:=
                    maps:get(observed_test_failures, Report)
                andalso maps:get(observed_test_failures, Report) > 0;
        {<<"unavailable">>, Value} when is_map(Value) ->
            gleam_test_failure_projection_valid(Value)
                andalso maps:get(summary_state, Value) =/= <<"projected">>
                andalso maps:get(failure_count, Report) =:= 1
                andalso maps:get(observed_test_failures, Report) =:= null;
        _ -> false
    end.

supervised_gleam_package_failure_pair_valid(Phase, Classification) ->
    lists:member({Phase, Classification}, [
        {<<"inner_evidence">>, <<"inner_result_missing">>},
        {<<"inner_evidence">>, <<"inner_result_ambiguous">>},
        {<<"inner_evidence">>, <<"inner_result_schema_rejected">>},
        {<<"inner_evidence">>, <<"inner_result_context_mismatch">>},
        {<<"inner_process">>, <<"inner_process_start_failed">>},
        {<<"inner_process">>, <<"inner_process_deadline">>},
        {<<"inner_process">>, <<"inner_process_output_limit">>},
        {<<"inner_process">>, <<"inner_process_protocol_rejected">>},
        {<<"inner_process">>, <<"inner_process_attestation_rejected">>},
        {<<"inner_test">>, <<"inner_test_failed">>},
        {<<"failure_projection">>,
         <<"inner_failure_projection_rejected">>},
        {<<"source_verification">>, <<"source_capture_failed">>},
        {<<"source_verification">>,
         <<"source_changed_during_test">>},
        {<<"runner_identity">>, <<"runner_identity_unavailable">>},
        {<<"runner_identity">>, <<"runner_changed_during_test">>}]).

supervised_gleam_publish_package_report(Attempt, Report) ->
    try
        Root = maps:get(root, Attempt),
        Package = maps:get(package, Attempt),
        true = lists:member(Package, [<<"http">>, <<"http3">>,
                                      <<"quic_core">>]),
        Digest = case maps:get(source_after_sha256, Report) of
            Value when is_binary(Value) -> Value;
            null -> maps:get(source_before_sha256, Report)
        end,
        true = exact_sha256_valid(Digest),
        Nonce = maps:get(nonce, Attempt),
        true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32,
        match = re:run(Nonce, <<"^[0-9a-f]{32}$">>, [{capture, none}]),
        DirectoryRelative = "build/supervised-gleam/"
            ++ binary_to_list(Package) ++ "-test-reports",
        Directory = filename:join(Root, DirectoryRelative),
        Name = binary_to_list(Digest) ++ "-" ++ binary_to_list(Nonce)
            ++ ".json",
        Final = filename:join(Directory, Name),
        Temporary = Final ++ ".tmp",
        Bytes = iolist_to_binary([json:encode(Report), $\n]),
        true = byte_size(Bytes) > 0 andalso byte_size(Bytes) =< 65536,
        ok = filelib:ensure_dir(Temporary),
        try
            ok = file:write_file(Temporary, Bytes, [binary, exclusive]),
            ok = file:rename(Temporary, Final),
            case file:read_file(Final) of
                {ok, Bytes} -> ok;
                {ok, _Changed} ->
                    _ = file:delete(Final),
                    erlang:error(package_report_readback_mismatch);
                {error, _ReadFailure} ->
                    _ = file:delete(Final),
                    erlang:error(package_report_readback_failed)
            end
        after
            case file:delete(Temporary) of
                ok -> ok;
                {error, enoent} -> ok;
                {error, _} -> ok
            end
        end,
        Relative = exact_normalized_relative(filename:join(
            DirectoryRelative, Name)),
        true = supervised_gleam_package_report_path_valid(Relative),
        {ok, Relative}
    catch _:_ -> error end.

supervised_gleam_package_report_path_valid(Path) when is_list(Path) ->
    re:run(list_to_binary(Path),
        <<"^build/supervised-gleam/(?:http|http3|quic_core)-test-reports/"
          "[0-9a-f]{64}-[0-9a-f]{32}\\.json$">>,
        [{capture, none}]) =:= match;
supervised_gleam_package_report_path_valid(_) -> false.

supervised_gleam_outer_package_report_line(Report, ReportPath) ->
    true = supervised_gleam_package_report_path_valid(ReportPath),
    case maps:get(status, Report) of
        <<"Ready">> ->
            io_lib:format(
              "supervised_gleam outer_tree_verified=true "
              "inner_outcome=ready mode=~s package=~s modules=~B "
              "configured_units=~B inventory_sha256=~s "
              "completed_tests=~B skipped=0 "
              "failures=0 report_published=true report=~s",
              [maps:get(mode, Report), maps:get(package, Report),
               maps:get(configured_modules, Report),
               maps:get(configured_units, Report),
               maps:get(suite_inventory_sha256, Report),
               maps:get(completed_tests, Report), ReportPath]);
        <<"Failed">> ->
            io_lib:format(
              "supervised_gleam inner_outcome=failed mode=~s package=~s "
              "counts_state=~s completion_state=~s completed_tests=~p "
              "skipped_state=~s skipped=~p failures=~B phase=~s "
              "classification=~s report_published=true report=~s",
              [maps:get(mode, Report), maps:get(package, Report),
               maps:get(counts_state, Report),
               maps:get(completion_state, Report),
               maps:get(completed_tests, Report),
               maps:get(skipped_tests_state, Report),
               maps:get(skipped_tests, Report),
               maps:get(failure_count, Report),
               maps:get(failure_phase, Report),
               maps:get(failure_classification, Report), ReportPath])
    end.

supervised_gleam_test_arguments([Mode]) ->
    lists:member(Mode, ["--http-test", "--http3-test", "--quic-test"]);
supervised_gleam_test_arguments(_) -> false.

supervised_gleam_projected_arguments(Arguments) ->
    supervised_gleam_test_arguments(Arguments) orelse
    case Arguments of
        [Mode] -> lists:member(Mode, [
            "--http-diagnostic-check", "--http3-diagnostic-check",
            "--quic-diagnostic-check", "--http-exact-test",
            "--http-server-exact-test", "--http-ohttp-exact-test"]);
        _ -> false
    end.

supervised_gleam_outer_timeout(["--http-exact-test"]) ->
    http_exact_build_timeout() + http_exact_evaluation_timeout(all) + 30000;
supervised_gleam_outer_timeout(["--http-server-exact-test"]) ->
    http_exact_build_timeout()
        + http_exact_evaluation_timeout(http3_server_lifecycle) + 30000;
supervised_gleam_outer_timeout(["--http-ohttp-exact-test"]) ->
    http_exact_build_timeout() + http_exact_evaluation_timeout(ohttp) + 30000;
supervised_gleam_outer_timeout([Mode])
  when Mode =:= "--http-test";
       Mode =:= "--http3-test";
       Mode =:= "--quic-test" ->
    supervised_package_timeout(Mode) + 30000;
supervised_gleam_outer_timeout([Mode])
  when Mode =:= "--http-diagnostic-check";
       Mode =:= "--http3-diagnostic-check";
       Mode =:= "--quic-diagnostic-check" -> 120000;
supervised_gleam_outer_timeout(_) -> 75000.

supervised_gleam_inner_outcome(["--http-exact-test"], Output) ->
    Ready = binary:matches(Output, <<"report_status_candidate=ready">>),
    Failed = binary:matches(Output, <<"report_status_candidate=failed">>),
    case {length(Ready), length(Failed)} of
        {1, 0} -> ready;
        {0, 1} -> failed;
        _ -> erlang:error(invalid_http_exact_inner_outcome)
    end;
supervised_gleam_inner_outcome(["--http-server-exact-test"], Output) ->
    supervised_gleam_inner_outcome(["--http-exact-test"], Output);
supervised_gleam_inner_outcome(["--http-ohttp-exact-test"], Output) ->
    supervised_gleam_inner_outcome(["--http-exact-test"], Output);
supervised_gleam_inner_outcome([Mode], Output)
  when Mode =:= "--http-test";
       Mode =:= "--http3-test";
       Mode =:= "--quic-test" ->
    case supervised_gleam_package_inner_evidence(Mode, Output) of
        {ok, Evidence} -> {passed, Evidence};
        {error, Classification} -> {failed, Classification}
    end;
supervised_gleam_inner_outcome([Mode], Output)
  when Mode =:= "--http-diagnostic-check";
       Mode =:= "--http3-diagnostic-check";
       Mode =:= "--quic-diagnostic-check" ->
    Ready = binary:matches(Output, <<"diagnostic_outcome=ready">>),
    Failed = binary:matches(Output, <<"diagnostic_outcome=failed">>),
    case {length(Ready), length(Failed)} of
        {1, 0} -> ready;
        {0, 1} -> failed;
        _ -> erlang:error(invalid_http_diagnostic_inner_outcome)
    end;
supervised_gleam_inner_outcome(_, _) -> passed.

supervised_gleam_emit_outer_success(Outcome) ->
    io:put_chars([supervised_gleam_outer_success_line(Outcome), $\n]).

supervised_gleam_outer_success_line({passed, Evidence}) ->
    io_lib:format(
      "supervised_gleam outer_tree_verified=true inner_outcome=passed "
      "mode=~s package=~s modules=~B configured_units=~B "
      "inventory_sha256=~s completed_tests=~B skipped=0 failures=0",
      [maps:get(mode, Evidence), maps:get(package, Evidence),
       maps:get(modules, Evidence), maps:get(configured_units, Evidence),
       maps:get(inventory_sha256, Evidence),
       maps:get(completed_tests, Evidence)]);
supervised_gleam_outer_success_line(Outcome) when is_atom(Outcome) ->
    io_lib:format("supervised_gleam outer_tree_verified=true "
                  "inner_outcome=~s", [atom_to_list(Outcome)]).

supervised_gleam_package_inner_evidence(Mode, Bytes)
  when is_list(Mode), is_binary(Bytes), byte_size(Bytes) =< 2097152 ->
    Lines = binary:split(gleam_strip_ansi(Bytes), <<"\n">>, [global]),
    case length(Lines) =< 100000 of
        false -> {error, <<"inner_result_schema_rejected">>};
        true ->
            Candidates = lists:filter(
                fun supervised_gleam_package_inner_evidence_candidate/1,
                Lines),
            case Candidates of
                [] -> {error, <<"inner_result_missing">>};
                [Candidate] ->
                    case supervised_gleam_package_inner_evidence_line(
                           Candidate) of
                        {true, Value} ->
                            case supervised_gleam_package_inner_evidence_schema_valid(
                                   Value) of
                                false ->
                                    {error,
                                     <<"inner_result_schema_rejected">>};
                                true ->
                                    case supervised_gleam_package_inner_evidence_context_valid(
                                           Mode, Value) of
                                        true -> {ok, Value};
                                        false -> {error,
                                            <<"inner_result_context_mismatch">>}
                                    end
                            end;
                        false ->
                            {error, <<"inner_result_schema_rejected">>}
                    end;
                _ -> {error, <<"inner_result_ambiguous">>}
            end
    end;
supervised_gleam_package_inner_evidence(_, _) ->
    {error, <<"inner_result_schema_rejected">>}.

supervised_gleam_package_inner_evidence_candidate(Line0) ->
    Line = string:trim(Line0, both, " \t\r"),
    case binary:match(Line, <<"supervised_gleam mode=">>) of
        {0, _} -> true;
        _ -> false
    end.

supervised_gleam_package_inner_evidence_line(Line0) ->
    Line = string:trim(Line0, both, " \t\r"),
    Pattern =
        <<"^supervised_gleam mode=(--(?:http|http3|quic)-test) "
          "package=(http|http3|quic_core) modules=([0-9]{1,5}) "
          "configured_units=([0-9]{1,5}) "
          "inventory_sha256=([0-9a-f]{64}) "
          "completed_tests=([0-9]{1,9}) "
          "skipped=0 failures=0 passed=true$">>,
    case re:run(Line, Pattern, [{capture, [1, 2, 3, 4, 5, 6], binary}]) of
        {match, [Mode, Package, Modules, Units, InventorySha, Completed]} ->
            {true, #{mode => Mode, package => Package,
                     modules => binary_to_integer(Modules),
                     configured_units => binary_to_integer(Units),
                     inventory_sha256 => InventorySha,
                     completed_tests => binary_to_integer(Completed)}};
        nomatch -> false
    end.

supervised_gleam_package_inner_evidence_schema_valid(Evidence) ->
    is_map(Evidence) andalso
    lists:sort(maps:keys(Evidence)) =:= lists:sort([
        mode, package, modules, configured_units, inventory_sha256,
        completed_tests])
        andalso supervised_runtime_label_valid(maps:get(mode, Evidence, <<>>))
        andalso supervised_runtime_label_valid(
            maps:get(package, Evidence, <<>>))
        andalso exact_positive_count(maps:get(modules, Evidence, 0), 10000)
        andalso exact_positive_count(
            maps:get(configured_units, Evidence, 0), 10000)
        andalso exact_sha256_valid(
            maps:get(inventory_sha256, Evidence, <<>>))
        andalso exact_positive_count(
            maps:get(completed_tests, Evidence, 0), 999999999).

supervised_gleam_package_inner_evidence_context_valid(Mode, Evidence) ->
    ModeBinary = list_to_binary(Mode),
    Package = case Mode of
        "--http-test" -> <<"http">>;
        "--http3-test" -> <<"http3">>;
        "--quic-test" -> <<"quic_core">>;
        _ -> <<>>
    end,
    maps:get(mode, Evidence, <<>>) =:= ModeBinary
        andalso maps:get(package, Evidence, <<>>) =:= Package.

supervised_gleam(Mode, Paths) ->
    true = length(Paths) >= 1 andalso length(Paths) =< 256,
    Root = filename:absname("."),
    Checked = [validated_gleam_path(Root, Path) || Path <- Paths],
    Gleam = gleam_executable(),
    ok = verify_gleam(Gleam, Root, []),
    Arguments = case Mode of
        "--check" -> ["format", "--check" | Checked];
        "--write" -> ["format" | Checked]
    end,
    case command_capture(Gleam, Arguments, Root, 60000, 2097152, []) of
        {ok, _Output, Proof} ->
            true = command_success_verified(Proof),
            io:format("supervised_gleam mode=~s files=~B passed=true~n",
                      [Mode, length(Checked)]),
            ok;
        {error, Proof} ->
            Safe = maps:with([outcome, exit_status, child_exit_observed,
                process_supervisor_protocol_valid,
                process_supervisor_failure_code,
                process_supervisor_attestation_failure,
                native_tree_empty, native_console_isolated,
                native_descendant_outlived,
                native_termination_requested], Proof),
            io:format(standard_error,
                      "supervised Gleam process rejected: ~p~n", [Safe]),
            erlang:error(gleam_command_failed)
    end.

supervised_package(Mode) ->
    Root = filename:absname("."),
    {Package, Directory} = case Mode of
        "--http3-check" -> {"http3", filename:join(Root, "packages/http3")};
        "--http3-test" -> {"http3", filename:join(Root, "packages/http3")};
        "--http-check" -> {"http", Root};
        "--http-test" -> {"http", Root};
        "--quic-check" -> {"quic_core", filename:join(Root,
                                                        "packages/quic_core")};
        "--quic-test" -> {"quic_core", filename:join(Root,
                                                       "packages/quic_core")}
    end,
    true = filelib:is_regular(filename:join(Directory, "gleam.toml")),
    true = lists:member(erlang:system_info(otp_release), ["28", "29"]),
    Environment = otp_environment(),
    Gleam = gleam_executable(),
    ok = verify_gleam(Gleam, Root, Environment),
    Arguments = case Mode of
        "--http3-check" -> ["check"];
        "--http3-test" -> ["test"];
        "--http-check" -> ["check"];
        "--http-test" -> ["test"];
        "--quic-check" -> ["check"];
        "--quic-test" -> ["test"]
    end,
    Timeout = supervised_package_timeout(Mode),
    Result = case lists:suffix("-test", Mode) of
        true -> command_capture_projected(
            Gleam, Arguments, Directory, Timeout, 8388608, Environment,
            fun gleam_test_failure_projection/1,
            fun gleam_test_failure_projection_valid/1);
        false -> command_capture(
            Gleam, Arguments, Directory, Timeout, 8388608, Environment)
    end,
    case Result of
        {ok, Output, Proof} ->
            true = command_success_verified(Proof),
            supervised_package_success(Mode, Package, Directory, Output),
            ok;
        {error, Projection, Proof} when is_map(Projection) ->
            Safe = supervised_package_process_proof(Proof),
            {ProjectionNonce, ProjectionSourceSha, ProjectionRunnerSha,
             ProjectionMode} = supervised_gleam_projection_binding(Mode),
            Envelope = gleam_test_failure_projection_envelope(
                Projection, ProjectionNonce, ProjectionSourceSha,
                ProjectionRunnerSha, ProjectionMode),
            io:put_chars(standard_error, [Envelope, $\n]),
            io:format(standard_error,
                      "supervised Gleam test failed: "
                      "projection_available=true process=~p~n",
                      [Safe]),
            erlang:error(gleam_test_failed);
        {error, Proof} ->
            Safe = supervised_package_process_proof(Proof),
            io:format(standard_error,
                      "supervised Gleam process rejected: ~p~n", [Safe]),
            erlang:error(gleam_command_failed);
        {error, ProjectionFailure, Proof} ->
            Safe = supervised_package_process_proof(Proof),
            ProjectionCategory = case ProjectionFailure of
                no_failure_projection -> no_failure_projection;
                invalid_failure_projection -> invalid_failure_projection;
                _ -> unknown_failure_projection
            end,
            io:format(standard_error,
                      "supervised Gleam test projection rejected: "
                      "category=~p process=~p~n",
                      [ProjectionCategory, Safe]),
            erlang:error(gleam_test_projection_failed)
    end.

supervised_gleam_projection_binding(Mode) ->
    Nonce = supervised_gleam_projection_environment(
        "HTTP_SUPERVISED_GLEAM_PROJECTION_NONCE"),
    SourceSha = supervised_gleam_projection_environment(
        "HTTP_SUPERVISED_GLEAM_PROJECTION_SOURCE_SHA256"),
    RunnerSha = supervised_gleam_projection_environment(
        "HTTP_SUPERVISED_GLEAM_PROJECTION_RUNNER_SHA256"),
    Mode = binary_to_list(supervised_gleam_projection_environment(
        "HTTP_SUPERVISED_GLEAM_PROJECTION_MODE")),
    true = execution_beam_digest(Nonce, 32),
    true = exact_sha256_valid(SourceSha),
    true = exact_sha256_valid(RunnerSha),
    {Nonce, SourceSha, RunnerSha, Mode}.

supervised_gleam_projection_environment(Name) ->
    case os:getenv(Name) of
        Value when is_list(Value), Value =/= [], length(Value) =< 128 ->
            unicode:characters_to_binary(Value);
        _ -> erlang:error(missing_projection_binding)
    end.

%% A successful gleeunit process is not enough evidence for a complete suite:
%% retain the compiler-discovered unit inventory and require exactly one final
%% success summary with no skipped leaf. This also prevents a changed or empty
%% test entry point from being reported as a passing package run.
supervised_package_success(Mode, Package, Directory, Output) ->
    case lists:suffix("-test", Mode) of
        false ->
            io:format("supervised_gleam mode=~s package=~s "
                      "configured_commands=1 completed_commands=1 "
                      "failures=0 passed=true~n", [Mode, Package]);
        true ->
            Summary = gleam_test_success_summary(Output),
            0 = maps:get(skipped, Summary),
            Ebin = filename:join([Directory, "build/dev/erlang", Package,
                                  "ebin"]),
            Inventory = suite_inventory(
                filename:join(Directory, "test"), Ebin),
            Modules = suite_inventory_modules(Inventory),
            Units = suite_inventory_units(Inventory),
            true = Modules =/= [] andalso length(Modules) =< 10000,
            true = Units =/= [] andalso length(Units) =< 10000,
            Completed = maps:get(passed, Summary),
            true = Completed >= length(Units),
            io:format("supervised_gleam mode=~s package=~s modules=~B "
                      "configured_units=~B inventory_sha256=~s "
                      "completed_tests=~B skipped=0 "
                      "failures=0 passed=true~n",
                      [Mode, Package, length(Modules), length(Units),
                       maps:get(inventory_sha256, Inventory), Completed])
    end.

gleam_test_success_summary(Bytes)
  when is_binary(Bytes), byte_size(Bytes) =< 8388608 ->
    Lines = binary:split(gleam_strip_ansi(Bytes), <<"\n">>, [global]),
    Summaries = lists:filtermap(fun gleam_test_success_summary_line/1, Lines),
    case Summaries of
        [Summary] -> Summary;
        _ -> erlang:error(invalid_or_ambiguous_gleeunit_success_summary)
    end.

gleam_test_success_summary_line(Line0) ->
    Line = string:trim(Line0, both, " \t\r"),
    case re:run(Line, <<"^([0-9]{1,9}) passed, no failures$">>,
                [{capture, [1], binary}]) of
        {match, [Passed]} ->
            {true, #{passed => binary_to_integer(Passed), skipped => 0}};
        nomatch ->
            case re:run(Line,
                        <<"^([0-9]{1,9}) passed, 0 failures, "
                          "([0-9]{1,9}) skipped$">>,
                        [{capture, [1, 2], binary}]) of
                {match, [Passed, Skipped]} ->
                    {true, #{passed => binary_to_integer(Passed),
                             skipped => binary_to_integer(Skipped)}};
                nomatch -> false
            end
    end.

supervised_package_process_proof(Proof) ->
    maps:with([outcome, exit_status, child_exit_observed,
        process_supervisor_protocol_valid,
        process_supervisor_failure_code,
        process_supervisor_attestation_failure,
        native_tree_empty, native_console_isolated,
        native_descendant_outlived, native_termination_requested,
        output_bytes, output_limit_bytes, output_limit_exceeded,
        timed_out, elapsed_ms, terminal_control_bytes_removed], Proof).

%% The complete root suite intentionally exercises several bounded native
%% teardown intervals. The previous five-minute envelope was reached by a
%% healthy aggregate run, so it classified progress as a test failure. Every
%% inner deadline remains fixed and the outer supervisor receives exactly one
%% additional thirty-second attestation interval.
supervised_package_timeout("--http-test") -> 600000;
supervised_package_timeout("--http3-test") -> 300000;
supervised_package_timeout("--quic-test") -> 300000;
supervised_package_timeout(_) -> 60000.

http_exact_build_timeout() -> 300000.

http_exact_evaluation_timeout(all) -> 600000;
http_exact_evaluation_timeout(http3_server_lifecycle) -> 180000;
http_exact_evaluation_timeout(ohttp) -> 120000.

http_exact_unit_timeout(all) -> 30;
http_exact_unit_timeout(http3_server_lifecycle) -> 30;
http_exact_unit_timeout(ohttp) -> 10.

supervised_diagnostic_check(Mode) ->
    Root = filename:absname("."),
    {Package, Directory, SourcePaths} = diagnostic_check_scope(Mode, Root),
    exact_progress(diagnostic_runtime),
    true = lists:member(erlang:system_info(otp_release), ["28", "29"]),
    Gleam = gleam_executable(),
    Environment = otp_environment(),
    ok = verify_gleam(Gleam, Root, Environment),
    Toolchain = supervised_toolchain(Gleam),
    exact_progress(diagnostic_source_capture),
    true = SourcePaths =/= [] andalso length(SourcePaths) =< 10000,
    SourceDigest = root_relative_digest(Directory, SourcePaths),
    Result = command_capture_projected(Gleam, ["check"], Directory, 60000,
        2097152, Environment, fun(Bytes) ->
            gleam_diagnostic_projection(Directory, SourcePaths, Bytes)
        end,
        fun gleam_diagnostic_projection_valid/1),
    exact_progress(diagnostic_process_complete),
    {Outcome, Diagnostics, Proof0} = case Result of
        {ok, _Output, SuccessProof} ->
            true = command_success_verified(SuccessProof),
            {ready, gleam_empty_diagnostic_projection(), SuccessProof};
        {error, Projection, FailureProof} ->
            true = maps:get(outcome, FailureProof, invalid) =:= exit_failure,
            true = process_completion_verified(FailureProof),
            true = gleam_diagnostic_projection_valid(Projection),
            {failed, Projection, FailureProof}
    end,
    SourcePaths = diagnostic_check_source_paths(Mode, Root, Directory),
    SourceDigest = root_relative_digest(Directory, SourcePaths),
    exact_progress(diagnostic_source_verified),
    Report = #{schema => 1, shareable => true,
        package => list_to_binary(Package),
        status => case Outcome of ready -> <<"Ready">>; failed -> <<"Failed">> end,
        configured_commands => 1, completed_commands => 1,
        source_sha256 => SourceDigest, source_files => length(SourcePaths),
        diagnostics => maps:get(diagnostics, Diagnostics),
        diagnostic_count => maps:get(diagnostic_count, Diagnostics),
        diagnostics_dropped => maps:get(diagnostics_dropped, Diagnostics),
        parser_status => maps:get(parser_status, Diagnostics),
        toolchain => Toolchain,
        rerun_command => list_to_binary(
            "escript scripts/supervised_gleam.escript " ++ Mode),
        process => exact_safe_process(Proof0)},
    _ = publish_gleam_diagnostic_report(Root, Package, SourceDigest, Report),
    exact_progress(diagnostic_report_published),
    io:format("supervised_gleam mode=~s package=~s diagnostics=~B "
              "report_published=true diagnostic_outcome=~s~n",
              [Mode, Package, maps:get(diagnostic_count, Diagnostics),
               atom_to_list(Outcome)]),
    ok.

diagnostic_check_scope(Mode, Root) ->
    {Package, Directory} = case Mode of
        "--http-diagnostic-check" -> {"http", Root};
        "--http3-diagnostic-check" ->
            {"http3", filename:join(Root, "packages/http3")};
        "--quic-diagnostic-check" ->
            {"quic_core", filename:join(Root, "packages/quic_core")}
    end,
    true = filelib:is_regular(filename:join(Directory, "gleam.toml")),
    {Package, Directory,
     diagnostic_check_source_paths(Mode, Root, Directory)}.

diagnostic_check_source_paths("--http-diagnostic-check", Root, Root) ->
    http_check_source_paths(Root);
diagnostic_check_source_paths(Mode, _Root, Directory)
  when Mode =:= "--http3-diagnostic-check";
       Mode =:= "--quic-diagnostic-check" ->
    package_check_source_paths(Directory).

package_check_source_paths(Directory) ->
    Configs = [Path || Path <- ["gleam.toml", "manifest.toml", "mix.exs",
                                "mix.lock"],
                       filelib:is_regular(filename:join(Directory, Path))],
    Trees = ["src", "test"],
    lists:usort(Configs ++ lists:append([
        exact_tree_files(Directory, Tree, 10000, 268435456)
        || Tree <- Trees])).

http_check_source_paths(Root) ->
    Configs = [Path || Path <- [".mise.toml", "gleam.toml", "manifest.toml",
                                "mix.exs", "mix.lock"],
                       filelib:is_regular(filename:join(Root, Path))],
    Trees = ["src", "test", "packages/http3/src", "packages/http3/test",
             "packages/quic_core/src", "packages/quic_core/test"],
    PackageConfigs = [filename:join(Package, Name)
        || Package <- ["packages/http3", "packages/quic_core"],
           Name <- ["gleam.toml", "manifest.toml", "mix.exs", "mix.lock"],
           filelib:is_regular(filename:join(Root, filename:join(Package, Name)))],
    lists:usort(Configs ++ PackageConfigs ++ lists:append([
        exact_tree_files(Root, Tree, 10000, 268435456) || Tree <- Trees])).

gleam_empty_diagnostic_projection() ->
    #{schema => 1, parser_status => complete, diagnostic_count => 0,
      diagnostics_dropped => 0, diagnostics => []}.

gleam_diagnostic_projection(Bytes)
  when is_binary(Bytes), byte_size(Bytes) =< 2097152 ->
    gleam_diagnostic_projection(filename:absname("."), [], Bytes).

gleam_diagnostic_projection(Root, SourcePaths, Bytes)
  when is_binary(Bytes), byte_size(Bytes) =< 2097152 ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    true = length(Lines) =< 100000,
    {Rows0, Count, _Unlocated, _Pending} = gleam_diagnostic_lines(
        Root, Lines, none, [], 0, 0),
    ParsedRows = lists:reverse(Rows0),
    FallbackRows0 = case ParsedRows of
        [] -> gleam_known_source_diagnostics(SourcePaths, Bytes);
        _ -> []
    end,
    FallbackRows1 = case FallbackRows0 of
        [] -> gleam_generated_source_diagnostics(SourcePaths, Bytes);
        _ -> FallbackRows0
    end,
    FallbackRows = case FallbackRows1 of
        [] -> gleam_package_level_diagnostics(SourcePaths, Bytes);
        _ -> FallbackRows1
    end,
    Rows = lists:sublist(ParsedRows ++ FallbackRows, 64),
    FallbackCount = length(FallbackRows),
    TotalCount = case Count of 0 -> FallbackCount; _ -> Count end,
    Dropped = erlang:max(0, TotalCount - length(Rows)),
    #{schema => 1,
      parser_status => case TotalCount of 0 -> unparsed; _ -> complete end,
      diagnostic_count => TotalCount, diagnostics_dropped => Dropped,
      diagnostics => Rows}.

gleam_known_source_diagnostics(SourcePaths, Bytes) ->
    Normalized = unicode:characters_to_binary([
        case Character of $\\ -> $/; _ -> Character end
        || Character <- unicode:characters_to_list(gleam_strip_ansi(Bytes))]),
    Candidates = [unicode:characters_to_binary(exact_normalized_relative(Path))
        || Path <- SourcePaths,
           lists:member(filename:extension(Path), [".gleam", ".erl"])],
    lists:usort(lists:filtermap(fun(Path) ->
        case gleam_known_source_location(Normalized, Path) of
            {ok, Line, Column} ->
                {true, #{path => Path, line => Line, column => Column,
                         location_synthetic => false,
                         category => <<"compiler_error">>,
                         title => <<"Compiler error">>}};
            none -> false
        end
    end, Candidates)).

%% Erlang compiler errors can name Gleam's private copied artefact instead of
%% the authored foreign source. Map that basename back only when it is unique
%% in the source-bound inventory. Ambiguous names fall through to a package
%% diagnostic rather than inventing a location.
gleam_generated_source_diagnostics(SourcePaths, Bytes) ->
    Normalized = unicode:characters_to_binary([
        case Character of $\\ -> $/; _ -> Character end
        || Character <- unicode:characters_to_list(gleam_strip_ansi(Bytes))]),
    ErlangPaths = [unicode:characters_to_binary(
                       exact_normalized_relative(Path))
                   || Path <- SourcePaths,
                      filename:extension(Path) =:= ".erl"],
    Index = lists:foldl(fun(Path, Acc) ->
        Basename = unicode:characters_to_binary(
            filename:basename(binary_to_list(Path))),
        case maps:get(Basename, Acc, none) of
            none -> Acc#{Basename => Path};
            _ -> Acc#{Basename => duplicate}
        end
    end, #{}, ErlangPaths),
    Unique = lists:sort([{Basename, Path}
                         || {Basename, Path} <- maps:to_list(Index),
                            Path =/= duplicate]),
    lists:filtermap(fun({Basename, Path}) ->
        Needle = <<"/_gleam_artefacts/", Basename/binary>>,
        case gleam_known_source_location(Normalized, Needle) of
            {ok, Line, Column} ->
                {true, #{path => Path, line => Line, column => Column,
                         location_synthetic => false,
                         category => <<"erlang_compiler_error">>,
                         title => <<"Shell command failure">>}};
            none -> false
        end
    end, Unique).

gleam_package_level_diagnostics(SourcePaths, Bytes) ->
    case lists:member("gleam.toml", SourcePaths) of
        false -> [];
        true ->
            Lines = [string:trim(gleam_strip_ansi(Line), both, " \t\r")
                     || Line <- binary:split(Bytes, <<"\n">>, [global])],
            Known = lists:usort(lists:filtermap(fun(Line) ->
                case Line of
                    <<"error: Shell program failed">> ->
                        {true, {<<"Shell program failed">>,
                                <<"erlang_compiler_error">>}};
                    <<"error: Shell command failure">> ->
                        {true, {<<"Shell command failure">>,
                                <<"erlang_compiler_error">>}};
                    <<"error: Compiler error">> ->
                        {true, {<<"Compiler error">>, <<"compiler_error">>}};
                    _ -> false
                end
            end, Lines)),
            [#{path => <<"gleam.toml">>, line => 1, column => 1,
               location_synthetic => true, title => Title,
               category => Category}
             || {Title, Category} <- lists:sublist(Known, 1)]
    end.

gleam_known_source_location(Bytes, Path) ->
    Locations = binary:matches(Bytes, Path),
    gleam_known_source_location(Bytes, byte_size(Path), Locations).

gleam_known_source_location(_Bytes, _Length, []) -> none;
gleam_known_source_location(Bytes, Length, [{Offset, Length} | Rest]) ->
    Start = Offset + Length,
    Available = erlang:min(64, byte_size(Bytes) - Start),
    Tail = binary:part(Bytes, Start, Available),
    case re:run(Tail, <<"^:([0-9]{1,10}):([0-9]{1,10})">>,
                [{capture, [1, 2], binary}]) of
        {match, [LineBytes, ColumnBytes]} ->
            Line = binary_to_integer(LineBytes),
            Column = binary_to_integer(ColumnBytes),
            case Line > 0 andalso Line =< 2147483647 andalso
                 Column > 0 andalso Column =< 2147483647 of
                true -> {ok, Line, Column};
                false -> none
            end;
        nomatch -> gleam_known_source_location(Bytes, Length, Rest)
    end.

gleam_diagnostic_lines(_Root, [], Pending, Rows, Count, Dropped) ->
    {Rows, Count, Dropped, Pending};
gleam_diagnostic_lines(Root, [Line0 | Rest], Pending0, Rows, Count, Dropped) ->
    true = byte_size(Line0) =< 16384,
    Line = string:trim(gleam_strip_ansi(Line0), both, " \t\r"),
    case gleam_diagnostic_title(Line) of
        {ok, Title, Category} ->
            PendingDropped = case Pending0 of none -> Dropped; _ -> Dropped + 1 end,
            gleam_diagnostic_lines(Root, Rest, {Title, Category, 64}, Rows,
                                   Count, PendingDropped);
        none ->
            gleam_diagnostic_pending_line(Root, Rest, Line, Pending0, Rows,
                                          Count, Dropped)
    end.

gleam_diagnostic_pending_line(Root, Rest, Line, none, Rows, Count, Dropped) ->
    case gleam_diagnostic_location(Root, Line) of
        {ok, Path, LineNumber, Column} ->
            Row = #{path => Path, line => LineNumber, column => Column,
                    location_synthetic => false,
                    category => <<"compiler_error">>,
                    title => <<"Compiler error">>},
            case length(Rows) < 64 of
                true -> gleam_diagnostic_lines(Root, Rest, none,
                                               [Row | Rows], Count + 1, Dropped);
                false -> gleam_diagnostic_lines(Root, Rest, none, Rows,
                                                Count + 1, Dropped + 1)
            end;
        none -> gleam_diagnostic_lines(Root, Rest, none, Rows, Count, Dropped)
    end;
gleam_diagnostic_pending_line(Root, Rest, Line, {Title, Category, Remaining},
                              Rows, Count, Dropped) ->
    case gleam_diagnostic_location(Root, Line) of
        {ok, Path, LineNumber, Column} ->
            Row = #{path => Path, line => LineNumber, column => Column,
                    location_synthetic => false,
                    category => Category, title => Title},
            case length(Rows) < 64 of
                true -> gleam_diagnostic_lines(Root, Rest, none, [Row | Rows],
                                               Count + 1, Dropped);
                false -> gleam_diagnostic_lines(Root, Rest, none, Rows, Count + 1,
                                                Dropped + 1)
            end;
        none when Remaining > 1 ->
            gleam_diagnostic_lines(Root, Rest,
                                   {Title, Category, Remaining - 1},
                                   Rows, Count, Dropped);
        none -> gleam_diagnostic_lines(Root, Rest, none, Rows,
                                       Count, Dropped + 1)
    end.

gleam_strip_ansi(Line) ->
    re:replace(Line, <<"\\x1B\\[[0-9;]{1,16}m">>, <<>>,
               [global, {return, binary}]).

gleam_diagnostic_title(<<"error: ", Raw/binary>>) ->
    case gleam_diagnostic_known_title(Raw) of
        {Title, Category} -> {ok, Title, Category};
        unknown -> {ok, <<"Compiler error">>, <<"compiler_error">>}
    end;
gleam_diagnostic_title(<<"warning: ", Raw/binary>>) ->
    case gleam_diagnostic_known_title(Raw) of
        {Title, Category} -> {ok, Title, Category};
        unknown -> {ok, <<"Compiler warning">>, <<"compiler_warning">>}
    end;
gleam_diagnostic_title(_) -> none.

gleam_diagnostic_known_title(<<"Syntax error">>) ->
    {<<"Syntax error">>, <<"syntax_error">>};
gleam_diagnostic_known_title(<<"Type mismatch">>) ->
    {<<"Type mismatch">>, <<"type_mismatch">>};
gleam_diagnostic_known_title(<<"Unknown variable">>) ->
    {<<"Unknown variable">>, <<"unknown_variable">>};
gleam_diagnostic_known_title(<<"Unknown module">>) ->
    {<<"Unknown module">>, <<"unknown_module">>};
gleam_diagnostic_known_title(<<"Unknown type">>) ->
    {<<"Unknown type">>, <<"unknown_type">>};
gleam_diagnostic_known_title(<<"Unknown function">>) ->
    {<<"Unknown function">>, <<"unknown_function">>};
gleam_diagnostic_known_title(<<"Unknown record field">>) ->
    {<<"Unknown record field">>, <<"unknown_record_field">>};
gleam_diagnostic_known_title(<<"Incorrect arity">>) ->
    {<<"Incorrect arity">>, <<"incorrect_arity">>};
gleam_diagnostic_known_title(<<"Duplicate definition">>) ->
    {<<"Duplicate definition">>, <<"duplicate_definition">>};
gleam_diagnostic_known_title(<<"Invalid import">>) ->
    {<<"Invalid import">>, <<"invalid_import">>};
gleam_diagnostic_known_title(<<"Private function">>) ->
    {<<"Private function">>, <<"private_function">>};
gleam_diagnostic_known_title(<<"Private type">>) ->
    {<<"Private type">>, <<"private_type">>};
gleam_diagnostic_known_title(<<"Recursive type">>) ->
    {<<"Recursive type">>, <<"recursive_type">>};
gleam_diagnostic_known_title(<<"Shell program failed">>) ->
    {<<"Shell program failed">>, <<"erlang_compiler_error">>};
gleam_diagnostic_known_title(<<"Shell command failure">>) ->
    {<<"Shell command failure">>, <<"erlang_compiler_error">>};
gleam_diagnostic_known_title(<<"Compiler error">>) ->
    {<<"Compiler error">>, <<"compiler_error">>};
gleam_diagnostic_known_title(<<"Unused value">>) ->
    {<<"Unused value">>, <<"unused_value_warning">>};
gleam_diagnostic_known_title(<<"Unused function argument">>) ->
    {<<"Unused function argument">>, <<"unused_argument_warning">>};
gleam_diagnostic_known_title(<<"Compiler warning">>) ->
    {<<"Compiler warning">>, <<"compiler_warning">>};
gleam_diagnostic_known_title(_) -> unknown.

gleam_diagnostic_location(Root, Line0) ->
    Normalized = unicode:characters_to_binary([
        case Character of $\\ -> $/; _ -> Character end
        || Character <- unicode:characters_to_list(Line0)]),
    Pattern = <<"((?:[A-Za-z]:/[A-Za-z0-9_ .()@/-]{1,1024}|"
                "(?:src|test|packages/(?:http3|quic_core)/(?:src|test))/"
                "[A-Za-z0-9_./@-]{1,480})\\.(?:gleam|erl)):"
                "([0-9]{1,10}):([0-9]{1,10})"
                "(?:-[0-9]{1,10}(?::[0-9]{1,10})?)?">>,
    case re:run(Normalized, Pattern,
                [{capture, [1, 2, 3], binary}, unicode]) of
        {match, [Candidate, LineBytes, ColumnBytes]} ->
            LineNumber = binary_to_integer(LineBytes),
            Column = binary_to_integer(ColumnBytes),
            case {gleam_diagnostic_relative_path(Root, Candidate),
                  LineNumber > 0 andalso LineNumber =< 2147483647,
                  Column > 0 andalso Column =< 2147483647} of
                {{ok, Path}, true, true} -> {ok, Path, LineNumber, Column};
                _ -> none
            end;
        nomatch -> none
    end.

gleam_diagnostic_relative_path(Root, Candidate) ->
    RootBytes = unicode:characters_to_binary(
        string:trim(exact_normalized_absolute(Root), trailing, "/")),
    Prefix = <<RootBytes/binary, "/">>,
    Relative = case Candidate of
        <<Prefix:(byte_size(Prefix))/binary, Rest/binary>> -> Rest;
        _ -> Candidate
    end,
    case gleam_diagnostic_path_valid(Relative) of
        true -> {ok, Relative};
        false -> none
    end.

gleam_diagnostic_projection_valid(Value) ->
    try
        true = is_map(Value),
        true = lists:sort(maps:keys(Value)) =:= lists:sort(
            [schema, parser_status, diagnostic_count,
             diagnostics_dropped, diagnostics]),
        1 = maps:get(schema, Value),
        true = lists:member(maps:get(parser_status, Value), [complete, unparsed]),
        Count = maps:get(diagnostic_count, Value),
        Dropped = maps:get(diagnostics_dropped, Value),
        Rows = maps:get(diagnostics, Value),
        true = is_integer(Count) andalso Count >= 0 andalso Count =< 100000,
        true = is_integer(Dropped) andalso Dropped >= 0 andalso Dropped =< 100000,
        true = is_list(Rows) andalso length(Rows) =< 64,
        true = Count =:= length(Rows) + Dropped,
        true = lists:all(fun gleam_diagnostic_row_valid/1, Rows),
        true
    catch _:_ -> false end.

gleam_diagnostic_row_valid(Row) ->
    true = lists:sort(maps:keys(Row)) =:=
           lists:sort([path, line, column, location_synthetic,
                       category, title]),
    true = gleam_diagnostic_path_valid(maps:get(path, Row)),
    Line = maps:get(line, Row), Column = maps:get(column, Row),
    true = is_integer(Line) andalso Line > 0 andalso Line =< 2147483647,
    true = is_integer(Column) andalso Column > 0 andalso Column =< 2147483647,
    Expected = gleam_diagnostic_known_title(maps:get(title, Row)),
    Expected = {maps:get(title, Row), maps:get(category, Row)},
    Synthetic = maps:get(location_synthetic, Row),
    true = is_boolean(Synthetic),
    true = case Synthetic of
        true ->
            maps:get(path, Row) =:= <<"gleam.toml">> andalso Line =:= 1
                andalso Column =:= 1 andalso
                lists:member(maps:get(title, Row),
                    [<<"Shell program failed">>, <<"Shell command failure">>,
                     <<"Compiler error">>]);
        false -> maps:get(path, Row) =/= <<"gleam.toml">>
    end,
    true.

gleam_diagnostic_path_valid(Path) ->
    is_binary(Path) andalso byte_size(Path) =< 512 andalso
    (Path =:= <<"gleam.toml">> orelse
     re:run(Path, <<"^(?:src|test|packages/(?:http3|quic_core)/(?:src|test))/"
                    "[A-Za-z0-9_./@-]+\\.(?:gleam|erl)$">>,
           [{capture, none}]) =:= match andalso
    binary:match(Path, <<"..">>) =:= nomatch) andalso
    binary:match(Path, <<":">>) =:= nomatch.

%% Project ordinary test-run failures into a small, shareable diagnosis. Raw
%% assertion values and stack frames never leave command_capture; only bounded
%% source-shaped identifiers, fixed categories, and finite summary counts do.
gleam_test_failure_projection(Bytes)
  when is_binary(Bytes), byte_size(Bytes) =< 8388608 ->
    {Sample0, ParserStatus} = gleam_test_failure_sample(Bytes),
    Sample = gleam_strip_ansi(Sample0),
    {Tests, TestsTruncated} = gleam_test_failure_identifiers(
        Sample,
        <<"(?:^|[^A-Za-z0-9_])([a-z][a-z0-9_]{1,119}_test)"
          "(?:[^A-Za-z0-9_]|$)">>,
        64),
    {Modules, ModulesTruncated} = gleam_test_failure_identifiers(
        Sample,
        <<"(?:^|[/\\\\])([a-z][a-z0-9_]{1,119}_tests?\\.erl)"
          "(?:[^A-Za-z0-9_.]|$)">>,
        64),
    Lower = gleam_test_ascii_lower(Sample),
    Categories = lists:sort([Category || {Category, Needle} <-
        gleam_test_failure_category_needles(),
        binary:match(Lower, Needle) =/= nomatch]),
    {Summaries, SummariesTruncated, SummariesInvalid} =
        gleam_test_failure_summaries(Lower),
    {SummaryState, Completed, ObservedFailures} = case ParserStatus of
        <<"complete">> ->
            gleam_test_failure_summary_state(
                Summaries, SummariesTruncated, SummariesInvalid);
        <<"sampled">> -> {<<"ambiguous">>, 0, 0}
    end,
    #{schema => 2, parser_status => ParserStatus,
      test_identifiers => Tests,
      test_identifiers_truncated => TestsTruncated,
      module_identifiers => Modules,
      module_identifiers_truncated => ModulesTruncated,
      categories => Categories,
      summaries => Summaries,
      summaries_truncated => SummariesTruncated,
      summaries_invalid => SummariesInvalid,
      summary_state => SummaryState,
      completed_tests => Completed,
      observed_test_failures => ObservedFailures}.

gleam_test_failure_sample(Bytes) when byte_size(Bytes) =< 2097152 ->
    {Bytes, <<"complete">>};
gleam_test_failure_sample(Bytes) ->
    PrefixBytes = 524288,
    TailBytes = 1572864,
    Prefix = binary:part(Bytes, 0, PrefixBytes),
    Tail = binary:part(Bytes, byte_size(Bytes) - TailBytes, TailBytes),
    {<<Prefix/binary, $\n, Tail/binary>>, <<"sampled">>}.

gleam_test_failure_identifiers(Bytes, Pattern, Limit) ->
    {ok, Compiled} = re:compile(Pattern, [unicode]),
    gleam_test_failure_identifiers(Bytes, Compiled, Limit, 0, #{}, 0).

gleam_test_failure_identifiers(_Bytes, _Pattern, _Limit, _Offset, Seen, 4096) ->
    {lists:sort(maps:keys(Seen)), true};
gleam_test_failure_identifiers(Bytes, Pattern, Limit, Offset, Seen, Attempts) ->
    case re:run(Bytes, Pattern,
                [{offset, Offset}, {capture, [1], index}]) of
        nomatch -> {lists:sort(maps:keys(Seen)), false};
        {match, [{Start, Length}]} when Length > 0 ->
            Value = binary:part(Bytes, Start, Length),
            Next = Start + Length,
            case maps:is_key(Value, Seen) of
                true -> gleam_test_failure_identifiers(
                    Bytes, Pattern, Limit, Next, Seen, Attempts + 1);
                false when map_size(Seen) >= Limit ->
                    {lists:sort(maps:keys(Seen)), true};
                false -> gleam_test_failure_identifiers(
                    Bytes, Pattern, Limit, Next, Seen#{Value => true},
                    Attempts + 1)
            end
    end.

gleam_test_failure_category_needles() ->
    [{<<"assertion">>, <<"assert">>}, {<<"badmatch">>, <<"badmatch">>},
     {<<"timeout">>, <<"timeout">>}, {<<"deadline">>, <<"deadline">>},
     {<<"function_clause">>, <<"function_clause">>},
     {<<"undef">>, <<"undef">>}, {<<"badarg">>, <<"badarg">>},
     {<<"noproc">>, <<"noproc">>}, {<<"killed">>, <<"killed">>},
     {<<"shutdown">>, <<"shutdown">>},
     {<<"resource">>, <<"resource">>}, {<<"compile">>, <<"compil">>},
     {<<"failure">>, <<"fail">>}, {<<"exception">>, <<"exception">>}].

gleam_test_failure_summaries(Bytes) ->
    Patterns = [
        {<<"tests_failures">>,
         <<"(?m)^[ \\t]*([0-9]{1,9}) tests?, "
           "([0-9]{1,9}) failures?[ \\t\\r]*$">>},
        {<<"passed_failed">>,
         <<"(?m)^[ \\t]*([0-9]{1,9}) passed, "
           "([0-9]{1,9}) failures?[ \\t\\r]*$">>}
    ],
    {Rows, Truncated, Invalid} = lists:foldl(
        fun({Kind, Pattern}, {Rows0, Truncated0, Invalid0}) ->
            {NextRows, NextTruncated, NextInvalid} =
                gleam_test_failure_summary_matches(Bytes, Pattern, Kind),
            {NextRows ++ Rows0, Truncated0 orelse NextTruncated,
             Invalid0 orelse NextInvalid}
        end,
        {[], false, false},
        Patterns
    ),
    {lists:usort(Rows), Truncated, Invalid}.

gleam_test_failure_summary_matches(Bytes, Pattern, Kind) ->
    {ok, Compiled} = re:compile(Pattern),
    gleam_test_failure_summary_matches(
        Bytes, Compiled, Kind, 0, 0, [], false).

gleam_test_failure_summary_matches(
  _Bytes, _Pattern, _Kind, _Offset, 64, Rows, Invalid) ->
    {Rows, true, Invalid};
gleam_test_failure_summary_matches(
  Bytes, Pattern, Kind, Offset, Attempts, Rows, Invalid) ->
    case re:run(Bytes, Pattern,
                [{offset, Offset}, {capture, [0, 1, 2], index}]) of
        nomatch -> {Rows, false, Invalid};
        {match, [{Start, Length}, {FirstStart, FirstLength},
                 {SecondStart, SecondLength}]} ->
            First = binary_to_integer(binary:part(
                Bytes, FirstStart, FirstLength)),
            Second = binary_to_integer(binary:part(
                Bytes, SecondStart, SecondLength)),
            Next = Start + erlang:max(1, Length),
            case gleam_test_failure_summary(Kind, First, Second) of
                {ok, Summary} ->
                    gleam_test_failure_summary_matches(
                        Bytes, Pattern, Kind, Next, Attempts + 1,
                        [Summary | Rows], Invalid);
                error ->
                    gleam_test_failure_summary_matches(
                        Bytes, Pattern, Kind, Next, Attempts + 1,
                        Rows, true)
            end
    end.

gleam_test_failure_summary(<<"tests_failures">>, Completed, Failed)
  when Completed =< 999999999, Failed > 0, Failed =< Completed ->
    {ok, #{kind => <<"tests_failures">>, completed => Completed,
           failed => Failed}};
gleam_test_failure_summary(<<"passed_failed">>, Passed, Failed)
  when Passed =< 999999999, Failed > 0, Failed =< 999999999,
       Passed + Failed =< 999999999 ->
    {ok, #{kind => <<"passed_failed">>, completed => Passed + Failed,
           failed => Failed}};
gleam_test_failure_summary(_Kind, _First, _Second) -> error.

gleam_test_failure_summary_state(Summaries, Truncated, Invalid) ->
    Counts = lists:usort([
        {maps:get(completed, Summary), maps:get(failed, Summary)}
        || Summary <- Summaries
    ]),
    case {Truncated orelse Invalid, Counts} of
        {true, _} -> {<<"ambiguous">>, 0, 0};
        {false, []} -> {<<"unavailable">>, 0, 0};
        {false, [{Completed, Failed}]} ->
            {<<"projected">>, Completed, Failed};
        {false, _} -> {<<"ambiguous">>, 0, 0}
    end.

gleam_test_ascii_lower(Bytes) ->
    << <<(gleam_test_ascii_lower_byte(Byte))>> || <<Byte>> <= Bytes >>.

gleam_test_ascii_lower_byte(Byte) when Byte >= $A, Byte =< $Z -> Byte + 32;
gleam_test_ascii_lower_byte(Byte) -> Byte.

gleam_test_failure_projection_valid(Value) ->
    try
        true = is_map(Value),
        true = lists:sort(maps:keys(Value)) =:= lists:sort([
            schema, parser_status, test_identifiers,
            test_identifiers_truncated, module_identifiers,
            module_identifiers_truncated, categories, summaries,
            summaries_truncated, summaries_invalid, summary_state,
            completed_tests, observed_test_failures]),
        2 = maps:get(schema, Value),
        true = lists:member(maps:get(parser_status, Value),
                            [<<"complete">>, <<"sampled">>]),
        Tests = maps:get(test_identifiers, Value),
        Modules = maps:get(module_identifiers, Value),
        true = is_list(Tests) andalso length(Tests) =< 64,
        true = is_list(Modules) andalso length(Modules) =< 64,
        true = Tests =:= lists:usort(Tests),
        true = Modules =:= lists:usort(Modules),
        true = lists:all(fun gleam_test_failure_identifier_valid/1, Tests),
        true = lists:all(fun gleam_test_failure_module_valid/1, Modules),
        true = is_boolean(maps:get(test_identifiers_truncated, Value)),
        true = is_boolean(maps:get(module_identifiers_truncated, Value)),
        Categories = maps:get(categories, Value),
        AllowedCategories = [Category || {Category, _} <-
            gleam_test_failure_category_needles()],
        true = is_list(Categories) andalso length(Categories) =<
            length(AllowedCategories),
        true = Categories =:= lists:usort(Categories),
        true = lists:all(fun(Category) ->
            lists:member(Category, AllowedCategories)
        end, Categories),
        Summaries = maps:get(summaries, Value),
        true = is_list(Summaries) andalso length(Summaries) =< 128,
        true = Summaries =:= lists:usort(Summaries),
        true = lists:all(fun gleam_test_failure_summary_valid/1, Summaries),
        SummariesTruncated = maps:get(summaries_truncated, Value),
        SummariesInvalid = maps:get(summaries_invalid, Value),
        true = is_boolean(SummariesTruncated),
        true = is_boolean(SummariesInvalid),
        SummaryState = maps:get(summary_state, Value),
        Completed = maps:get(completed_tests, Value),
        ObservedFailures = maps:get(observed_test_failures, Value),
        Counts = lists:usort([
            {maps:get(completed, Summary), maps:get(failed, Summary)}
            || Summary <- Summaries
        ]),
        true = case SummaryState of
            <<"projected">> ->
                not SummariesTruncated andalso not SummariesInvalid
                    andalso Counts =:= [{Completed, ObservedFailures}]
                    andalso exact_positive_count(Completed, 999999999)
                    andalso exact_positive_count(
                        ObservedFailures, 999999999)
                    andalso ObservedFailures =< Completed;
            <<"unavailable">> ->
                not SummariesTruncated andalso not SummariesInvalid
                    andalso Counts =:= [] andalso Completed =:= 0
                    andalso ObservedFailures =:= 0;
            <<"ambiguous">> ->
                (maps:get(parser_status, Value) =:= <<"sampled">>
                 orelse SummariesTruncated orelse SummariesInvalid
                 orelse length(Counts) > 1)
                    andalso Completed =:= 0
                    andalso ObservedFailures =:= 0;
            _ -> false
        end,
        true
    catch _:_ -> false end.

gleam_test_failure_identifier_valid(Value)
  when is_binary(Value), byte_size(Value) =< 128 ->
    re:run(Value, <<"^[a-z][a-z0-9_]{1,119}_test$">>,
           [{capture, none}, unicode]) =:= match;
gleam_test_failure_identifier_valid(_) -> false.

gleam_test_failure_module_valid(Value)
  when is_binary(Value), byte_size(Value) =< 132 ->
    re:run(Value, <<"^[a-z][a-z0-9_]{1,119}_tests?\\.erl$">>,
           [{capture, none}, unicode]) =:= match;
gleam_test_failure_module_valid(_) -> false.

gleam_test_failure_summary_valid(#{kind := Kind, completed := Completed,
                                   failed := Failed} = Summary) ->
    lists:sort(maps:keys(Summary)) =:= [completed, failed, kind] andalso
    lists:member(Kind, [<<"tests_failures">>, <<"passed_failed">>]) andalso
    is_integer(Completed) andalso Completed > 0 andalso
    Completed =< 999999999 andalso is_integer(Failed) andalso Failed > 0
    andalso Failed =< Completed;
gleam_test_failure_summary_valid(_) -> false.

%% The inner VM has already reduced raw test output to a strictly validated,
%% finite map.  Carry only that map across the outer process boundary.  The
%% outer VM never reparses assertion text or an Erlang pretty-printed map.
gleam_test_failure_projection_envelope(
  Projection, Nonce, SourceSha, RunnerSha, Mode) ->
    true = gleam_test_failure_projection_valid(Projection),
    InvocationSha = gleam_test_failure_projection_invocation_sha(
        Nonce, SourceSha, RunnerSha, Mode),
    Payload = term_to_binary(
        {supervised_gleam_failure_projection_v2, Nonce, SourceSha,
         RunnerSha, InvocationSha, list_to_binary(Mode), Projection},
        [{minor_version, 2}]),
    true = byte_size(Payload) =< 49152,
    Encoded = base64:encode(Payload),
    true = byte_size(Encoded) =< 65536,
    <<"supervised_gleam_failure_projection_v2 payload=", Encoded/binary>>.

gleam_outer_test_failure_projection(
  Bytes, Nonce, SourceSha, RunnerSha, Mode)
  when is_binary(Bytes), byte_size(Bytes) =< 8388608 ->
    case gleam_test_failure_projection_envelopes(gleam_strip_ansi(Bytes)) of
        [{valid, Encoded}] ->
            gleam_test_failure_projection_decode(
                Encoded, Nonce, SourceSha, RunnerSha, Mode);
        _ -> invalid_failure_projection
    end;
gleam_outer_test_failure_projection(_, _, _, _, _) ->
    invalid_failure_projection.

gleam_test_failure_projection_envelopes(Bytes) ->
    lists:filtermap(fun gleam_test_failure_projection_envelope_line/1,
        binary:split(Bytes, <<"\n">>, [global])).

gleam_test_failure_projection_envelope_line(Line0) ->
    Line = string:trim(Line0, trailing, "\r"),
    Prefix = <<"supervised_gleam_failure_projection_v2 payload=">>,
    case binary:match(Line, Prefix) of
        {0, PrefixBytes} ->
            Encoded = binary:part(
                Line, PrefixBytes, byte_size(Line) - PrefixBytes),
            Valid = byte_size(Encoded) > 0
                andalso byte_size(Encoded) =< 65536
                andalso re:run(
                    Encoded, <<"^[A-Za-z0-9+/]+={0,2}$">>,
                    [{capture, none}]) =:= match,
            {true, case Valid of true -> {valid, Encoded}; false -> invalid end};
        _ -> false
    end.

gleam_test_failure_projection_decode(
  Encoded, Nonce, SourceSha, RunnerSha, Mode) ->
    try
        true = execution_beam_digest(Nonce, 32),
        true = exact_sha256_valid(SourceSha),
        true = exact_sha256_valid(RunnerSha),
        true = supervised_gleam_test_arguments([Mode]),
        InvocationSha = gleam_test_failure_projection_invocation_sha(
            Nonce, SourceSha, RunnerSha, Mode),
        Payload = base64:decode(Encoded),
        true = byte_size(Payload) =< 49152,
        {ok, Envelope} = canonical_etf_decode(Payload, 49152, 32, 8192),
        {supervised_gleam_failure_projection_v2,
         Nonce, SourceSha, RunnerSha, InvocationSha, ModeBinary,
         Projection} = Envelope,
        ModeBinary = list_to_binary(Mode),
        true = gleam_test_failure_projection_valid(Projection),
        Projection
    catch _:_ -> invalid_failure_projection end.

gleam_test_failure_projection_invocation_sha(
  Nonce, SourceSha, RunnerSha, Mode) ->
    true = execution_beam_digest(Nonce, 32),
    true = exact_sha256_valid(SourceSha),
    true = exact_sha256_valid(RunnerSha),
    true = supervised_gleam_test_arguments([Mode]),
    Bytes = term_to_binary(
        {supervised_gleam_projection_invocation_v2, Nonce, SourceSha,
         RunnerSha, list_to_binary(Mode)},
        [{minor_version, 2}]),
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

publish_gleam_diagnostic_report(Root, Package, SourceDigest, Report) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Name = binary_to_list(SourceDigest) ++ "-" ++ binary_to_list(Nonce) ++ ".json",
    Path = filename:join(Root,
        filename:join("build/supervised-gleam/" ++ Package ++
                      "-diagnostic-reports", Name)),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), $\n], [exclusive]),
    ok.

%% Build the root test closure in a private tree that starts without generated
%% artifacts, then enumerate every exported EUnit unit from that exact build.
%% Its isolated entry point is replaced with a no-op for this compilation only,
%% so one aggregate gleeunit run cannot hide the remaining unit inventory.
supervised_http_exact_test() -> supervised_http_exact_test(all).

supervised_http_server_exact_test() ->
    supervised_http_exact_test(http3_server_lifecycle).

supervised_http_ohttp_exact_test() -> supervised_http_exact_test(ohttp).

supervised_http_exact_test(Selection) ->
    Root = filename:absname("."),
    exact_progress(runtime),
    true = lists:member(erlang:system_info(otp_release), ["28", "29"]),
    Gleam = gleam_executable(),
    Environment = otp_environment(),
    ok = verify_gleam(Gleam, Root, Environment),
    Toolchain = supervised_toolchain(Gleam),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(
        filename:join(Root, "build/supervised-gleam/http-exact-attempts"),
        Nonce),
    put(http_exact_attempt_lease, Lease),
    try supervised_http_exact_reserved(
        Root, Gleam, Environment, Toolchain, Selection, Nonce, Lease)
    after exact_release_attempt_if_active() end.

supervised_http_exact_reserved(Root, Gleam, Environment, Toolchain, Selection,
                               Nonce, Lease) ->
    exact_progress(source_capture),
    {Stage, SourcePaths, SourceDigest, SourceCount, DependencyDigest} =
        stage_http_sources(Root, Lease),
    CompileDriver = install_http_compile_driver(Stage),
    exact_progress(test_beam_build),
    BuildResult = try command_capture_projected(
        Gleam, ["test"], Stage, http_exact_build_timeout(), 2097152,
        Environment,
        fun(Bytes) -> gleam_diagnostic_projection(Stage, SourcePaths, Bytes) end,
        fun gleam_diagnostic_projection_valid/1)
                  after restore_http_compile_driver(CompileDriver) end,
    ok = exact_require_successful_build(
        Root, Stage, SourcePaths, SourceDigest, SourceCount, DependencyDigest,
        Toolchain, CompileDriver, Selection, Nonce, BuildResult),
    Context = #{root => Root, stage => Stage, source_paths => SourcePaths,
        source_sha256 => SourceDigest, source_files => SourceCount,
        dependency_cache_sha256 => DependencyDigest, toolchain => Toolchain,
        compile_driver => CompileDriver, selection => Selection, nonce => Nonce,
        phase => post_build_start, configured_modules => null,
        configured_units => null, counts_state => <<"unavailable">>,
        completed_tests => null,
        skipped_tests => null, skipped_tests_state => <<"unavailable">>,
        observed_test_failures => null, failures => [], child_exit_status => -1,
        process => #{}, artifact_sha256 => null, artifact_files => 0,
        artifact_paths => [], runner_sha256 => null,
        execution_beam_inventory_sha256 => null,
        loaded_beam_sha256 => null, loaded_beam_count => null,
        lease => Lease,
        suite_inventory_sha256 => null,
        suite_inventory_state => <<"unavailable">>,
        report_published => false},
    put(http_exact_attempt_context, Context),
    try supervised_http_exact_post_build(Context)
    catch Class:Reason:Stack ->
        Current = case get(http_exact_attempt_context) of
            Value when is_map(Value) -> Value;
            _ -> Context
        end,
        case maps:get(report_published, Current, false) of
            true -> ok;
            false -> ok = exact_publish_post_build_failure(Current, Reason)
        end,
        erlang:raise(Class, Reason, Stack)
    after
        erase(http_exact_attempt_context)
    end.

supervised_http_exact_post_build(Context) ->
    Root = maps:get(root, Context),
    Stage = maps:get(stage, Context),
    SourcePaths = maps:get(source_paths, Context),
    SourceDigest = maps:get(source_sha256, Context),
    SourceCount = maps:get(source_files, Context),
    DependencyDigest = maps:get(dependency_cache_sha256, Context),
    Toolchain = maps:get(toolchain, Context),
    CompileDriver = maps:get(compile_driver, Context),
    Selection = maps:get(selection, Context),
    Nonce = maps:get(nonce, Context),
    exact_attempt_progress(source_verification),
    ok = verify_http_stage_inputs(Root, Stage, SourcePaths, SourceDigest),
    exact_progress(source_verified),
    exact_attempt_progress(module_inventory),
    TestRoot = filename:join(Stage, "test"),
    Ebin = filename:join([Stage, "build/dev/erlang/http/ebin"]),
    Inventory = suite_inventory(TestRoot, Ebin),
    Modules = suite_inventory_modules(Inventory),
    true = Modules =/= [] andalso length(Modules) =< 10000,
    exact_attempt_update(#{configured_modules => length(Modules),
        suite_inventory_sha256 => maps:get(inventory_sha256, Inventory),
        suite_inventory_state => <<"verified">>}),
    exact_attempt_progress(unit_inventory),
    AllUnits = suite_inventory_units(Inventory),
    Units = exact_selected_units(Selection, AllUnits),
    true = Units =/= [] andalso length(Units) =< 10000,
    exact_attempt_update(#{configured_units => length(Units)}),
    exact_attempt_progress(artifact_inventory),
    ArtifactPaths = http_exact_artifact_paths(Stage),
    fresh_ensure(exact_stage_artifacts_exist(Stage, ArtifactPaths),
                 missing_fresh_http_test_artifact),
    ArtifactDigest = stage_relative_digest(Stage, ArtifactPaths),
    exact_attempt_update(#{artifact_paths => ArtifactPaths,
        artifact_sha256 => ArtifactDigest, artifact_files => length(ArtifactPaths)}),
    exact_attempt_progress(runner_compilation),
    RunnerInfo = compile_http_exact_runner(Stage, maps:get(lease, Context)),
    Runner = maps:get(directory, RunnerInfo),
    RunnerSha = maps:get(sha256, RunnerInfo),
    CodePaths0 = http_exact_code_paths(Stage),
    BuildRoot = filename:join(Stage, "build/dev"),
    BeamInventory = execution_beam_inventory(CodePaths0, BuildRoot,
        fun(Path) -> execution_beam_read(Path, 67108864) end),
    BeamInventorySha = maps:get(sha256, BeamInventory),
    exact_attempt_update(#{runner_sha256 => RunnerSha,
        execution_beam_inventory_sha256 => BeamInventorySha}),
    ChildPath = filename:join(maps:get(root, maps:get(lease, Context)),
                              "child.json"),
    CodePaths = [Runner | CodePaths0],
    UnitTimeoutSeconds = http_exact_unit_timeout(Selection),
    Evaluation = execution_beam_bootstrap_evaluation(
        maps:get(lease, Context), run_units_attested,
        [Units, ChildPath, Nonce, UnitTimeoutSeconds, RunnerSha,
         BuildRoot, BeamInventory], RunnerSha, SourceDigest, 126),
    exact_attempt_progress(exact_unit_execution),
    {Status, Process0} = run_child_evaluation(
        Stage, CodePaths, Evaluation, http_exact_evaluation_timeout(Selection)),
    Process = exact_safe_unit_process(Process0),
    exact_attempt_update(#{child_exit_status => Status, process => Process}),
    exact_attempt_progress(unit_process_verification),
    true = process_status_verified(Status, Status, Process0),
    true = Status =:= 0 orelse Status =:= 1,
    exact_attempt_progress(child_evidence),
    Child = try exact_read_child(ChildPath)
            after exact_remove_file(ChildPath) end,
    true = suite_attested_child_schema_valid(
        Child, Units, Nonce, RunnerSha, BeamInventorySha),
    ChildBeamIdentity = maps:get(<<"execution_beam_identity">>, Child),
    LoadedBeamSha = maps:get(<<"loaded_beam_sha256">>, ChildBeamIdentity),
    LoadedBeamCount = maps:get(<<"loaded_beam_count">>, ChildBeamIdentity),
    exact_attempt_update(#{loaded_beam_sha256 => LoadedBeamSha,
        loaded_beam_count => LoadedBeamCount}),
    CompletedTests = suite_completed_tests(Child),
    FailureCount = maps:get(<<"failure_count">>, Child),
    FailureRows = exact_failure_rows(Child, Units),
    Counts = suite_attested_test_counts(
        Child, Units, Nonce, RunnerSha, BeamInventorySha),
    exact_attempt_update(#{completed_tests => CompletedTests,
        counts_state => maps:get(state, Counts),
        skipped_tests => maps:get(skipped, Counts),
        skipped_tests_state => maps:get(state, Counts),
        observed_test_failures => FailureCount, failures => FailureRows}),
    exact_attempt_progress(post_execution_source_verification),
    ok = verify_http_stage_inputs(Root, Stage, SourcePaths, SourceDigest),
    exact_attempt_progress(artifact_verification),
    true = ArtifactDigest =:= stage_relative_digest(Stage, ArtifactPaths),
    ok = suite_require_inventory_unchanged(Inventory, TestRoot, Ebin),
    Complete = Status =:= 0 andalso suite_attested_child_valid(
        Child, Units, Nonce, RunnerSha, BeamInventorySha),
    Report = #{schema => 3, shareable => true,
        status => case Complete of true -> <<"Ready">>; false -> <<"Failed">> end,
        run_nonce => Nonce, child => Child,
        prebuild_profile_state => <<"absent">>,
        source_sha256 => SourceDigest, source_files => SourceCount,
        dependency_cache_sha256 => DependencyDigest,
        toolchain => Toolchain,
        compile_driver => safe_http_compile_driver(CompileDriver),
        artifact_sha256 => ArtifactDigest, artifact_files => length(ArtifactPaths),
        selection => atom_to_binary(Selection),
        unit_timeout_seconds => UnitTimeoutSeconds,
        configured_modules => length(lists:usort(
            [maps:get(module, Unit) || Unit <- Units])),
        configured_units => length(Units),
        suite_inventory_sha256 => maps:get(inventory_sha256, Inventory),
        suite_inventory_state => <<"verified">>,
        counts_state => maps:get(state, Counts),
        completed_tests => CompletedTests,
        skipped_tests => maps:get(skipped, Counts),
        skipped_tests_state => maps:get(state, Counts),
        failure_count => FailureCount,
        failures => FailureRows,
        child_exit_status => Status, process => Process,
        rerun_command => list_to_binary(
            "escript scripts/supervised_gleam.escript " ++
            http_exact_mode(Selection)),
        runner_sha256 => RunnerSha,
        execution_beam_inventory_sha256 => BeamInventorySha,
        loaded_beam_sha256 => LoadedBeamSha,
        loaded_beam_count => LoadedBeamCount},
    true = exact_unit_report_valid(Report),
    %% Successful publication is also the cleanup receipt for the private
    %% runner and child evidence.  Never expose a Ready report before that
    %% finite attempt directory has been removed.
    exact_attempt_progress(attempt_cleanup),
    ok = exact_release_attempt_active(),
    exact_attempt_progress(report_publication),
    ModeName = http_exact_mode(Selection),
    io:format("supervised_gleam mode=~s fresh_test_beams=true "
              "modules=~B units=~B inventory_sha256=~s "
              "completed=~B skipped=~B failures=~B "
              "report_publication=pending report_status_candidate=~s~n",
              [ModeName, length(lists:usort(
                   [maps:get(module, Unit) || Unit <- Units])),
               length(Units), maps:get(inventory_sha256, Inventory),
               CompletedTests, maps:get(skipped, Counts), FailureCount,
               case Complete of true -> "ready"; false -> "failed" end]),
    _ = exact_publish_report(Root, SourceDigest, Nonce, Report),
    ok.

exact_release_attempt_active() ->
    case get(http_exact_attempt_lease) of
        Lease when is_map(Lease) ->
            ok = execution_beam_release_attempt(Lease),
            put(http_exact_attempt_lease, released),
            ok;
        released -> ok;
        _ -> erlang:error(http_exact_attempt_lease_missing)
    end.

exact_release_attempt_if_active() ->
    case erase(http_exact_attempt_lease) of
        Lease when is_map(Lease) -> execution_beam_release_attempt(Lease);
        released -> ok;
        undefined -> ok;
        _ -> erlang:error(http_exact_attempt_lease_invalid)
    end.

exact_selected_units(all, Units) -> Units;
exact_selected_units(http3_server_lifecycle, Units) ->
    Selected = [Unit || Unit <- Units,
                        maps:get(module, Unit, <<>>) =:=
                            <<"http3_server_lifecycle_test">>],
    true = Selected =/= [] andalso length(Selected) =< 256,
    Selected;
exact_selected_units(ohttp, Units) ->
    Selected = [Unit || Unit <- Units,
        lists:member(maps:get(module, Unit, <<>>),
                     [<<"ohttp_test">>, <<"http_ohttp_guard_tests">>])],
    true = Selected =/= [] andalso length(Selected) =< 256,
    Selected.

http_exact_mode(all) -> "--http-exact-test";
http_exact_mode(http3_server_lifecycle) -> "--http-server-exact-test";
http_exact_mode(ohttp) -> "--http-ohttp-exact-test".

exact_progress(Stage) ->
    io:format("supervised_gleam progress=~s~n", [atom_to_list(Stage)]).

exact_attempt_progress(Stage) ->
    exact_attempt_update(#{phase => Stage}),
    exact_progress(Stage).

exact_attempt_update(Changes) when is_map(Changes) ->
    case get(http_exact_attempt_context) of
        Context when is_map(Context) ->
            put(http_exact_attempt_context, maps:merge(Context, Changes)),
            ok;
        _ -> erlang:error(http_exact_attempt_context_missing)
    end.

exact_publish_post_build_failure(Context) ->
    exact_publish_post_build_failure(Context, post_build_invariant_rejected).

exact_publish_post_build_failure(Context, Reason) ->
    Root = maps:get(root, Context),
    Stage = maps:get(stage, Context),
    SourcePaths = maps:get(source_paths, Context),
    SourceDigest = maps:get(source_sha256, Context),
    Nonce = maps:get(nonce, Context),
    Phase = maps:get(phase, Context, post_build_start),
    Classification = exact_post_build_failure_classification(Phase, Reason),
    SourceStable = exact_http_stage_inputs_stable(
        Root, Stage, SourcePaths, SourceDigest),
    ArtifactState = exact_attempt_artifact_state(Context),
    Report = #{schema => 3, report_kind => <<"http_exact_attempt">>,
        shareable => true, status => <<"Failed">>,
        prebuild_profile_state => <<"absent">>,
        source_sha256 => SourceDigest,
        source_files => maps:get(source_files, Context),
        dependency_cache_sha256 => maps:get(dependency_cache_sha256, Context),
        toolchain => maps:get(toolchain, Context),
        compile_driver => safe_http_compile_driver(
            maps:get(compile_driver, Context)),
        artifact_sha256 => maps:get(artifact_sha256, Context, null),
        artifact_files => maps:get(artifact_files, Context, 0),
        artifact_state => ArtifactState,
        runner_sha256 => maps:get(runner_sha256, Context, null),
        execution_beam_inventory_sha256 => maps:get(
            execution_beam_inventory_sha256, Context, null),
        loaded_beam_sha256 => maps:get(loaded_beam_sha256, Context, null),
        loaded_beam_count => maps:get(loaded_beam_count, Context, null),
        suite_inventory_sha256 => maps:get(
            suite_inventory_sha256, Context, null),
        suite_inventory_state => maps:get(
            suite_inventory_state, Context, <<"unavailable">>),
        selection => atom_to_binary(maps:get(selection, Context)),
        unit_timeout_seconds => http_exact_unit_timeout(
            maps:get(selection, Context)),
        configured_modules => maps:get(configured_modules, Context, null),
        configured_units => maps:get(configured_units, Context, null),
        counts_state => maps:get(counts_state, Context, <<"unavailable">>),
        completed_tests => maps:get(completed_tests, Context, null),
        skipped_tests => maps:get(skipped_tests, Context, null),
        skipped_tests_state => maps:get(
            skipped_tests_state, Context, <<"unavailable">>),
        observed_test_failures => maps:get(
            observed_test_failures, Context, null),
        failures => maps:get(failures, Context, []),
        child_exit_status => maps:get(child_exit_status, Context, -1),
        process => maps:get(process, Context, #{}),
        rerun_command => list_to_binary(
            "escript scripts/supervised_gleam.escript " ++
            http_exact_mode(maps:get(selection, Context))),
        failure_phase => atom_to_binary(Phase),
        failure_classification => Classification,
        source_stable => SourceStable},
    true = exact_post_build_failure_report_valid(Report),
    %% Ordinary failure evidence is published only after the private attempt
    %% has been removed.  A cleanup failure is itself evidence: retain the
    %% contaminated attempt for inspection and publish only a Failed report.
    case Phase of
        attempt_cleanup -> ok;
        _ -> ok = exact_release_attempt_active()
    end,
    ReportPath = exact_publish_report(Root, SourceDigest, Nonce, Report),
    io:format(standard_error,
              "supervised_gleam mode=~s phase=~s completed=~p failures=1 "
              "classification=~s report=~s exact_outcome=failed~n",
              [http_exact_mode(maps:get(selection, Context)), atom_to_list(Phase),
               maps:get(completed_tests, Context, null), Classification,
               ReportPath]),
    ok.

exact_attempt_artifact_state(#{artifact_sha256 := Digest,
                               artifact_paths := Paths,
                               stage := Stage})
  when is_binary(Digest), is_list(Paths), Paths =/= [] ->
    try Digest =:= stage_relative_digest(Stage, Paths) of
        true -> <<"verified">>;
        false -> <<"changed">>
    catch _:_ -> <<"unavailable">> end;
exact_attempt_artifact_state(_) -> <<"unavailable">>.

exact_post_build_failure_classification(
  Phase, {suite_inventory_rejected, Reason}) ->
    case exact_suite_inventory_failure(Reason) of
        true -> atom_to_binary(Reason);
        false -> exact_post_build_failure_classification(Phase)
    end;
exact_post_build_failure_classification(Phase, _) ->
    exact_post_build_failure_classification(Phase).

exact_suite_inventory_failure(Reason) ->
    lists:member(Reason, [
        no_test_sources, source_limit_exceeded, duplicate_source_module,
        unsupported_source_extension, erlang_declared_module_mismatch,
        erlang_module_declaration_missing,
        erlang_module_declaration_ambiguous, unsafe_module_name,
        source_outside_test_root, unsafe_source_path, source_size_rejected,
        source_tree_depth_limit, source_tree_entry_limit,
        source_tree_read_failed, source_tree_link_rejected,
        source_tree_special_file_rejected, source_tree_changed_while_reading,
        source_tree_inspection_failed, source_tree_missing,
        source_changed_while_reading, source_read_failed,
        source_link_rejected, source_hardlink_rejected,
        source_special_file_rejected, source_missing,
        source_inspection_failed, beam_size_rejected,
        beam_changed_while_reading, beam_read_failed, beam_link_rejected,
        beam_hardlink_rejected,
        beam_special_file_rejected, beam_missing, beam_inspection_failed,
        malformed_beam, unreadable_beam_metadata, unsafe_beam_module,
        beam_module_mismatch, beam_export_limit_exceeded,
        unsafe_eunit_export, unit_limit_exceeded,
        internally_invalid_inventory, stale_suite_inventory]).

exact_post_build_failure_classification(source_verification) ->
    <<"source_verification_failed">>;
exact_post_build_failure_classification(module_inventory) ->
    <<"module_inventory_rejected">>;
exact_post_build_failure_classification(unit_inventory) ->
    <<"unit_inventory_rejected">>;
exact_post_build_failure_classification(artifact_inventory) ->
    <<"artifact_inventory_rejected">>;
exact_post_build_failure_classification(runner_compilation) ->
    <<"runner_compilation_failed">>;
exact_post_build_failure_classification(exact_unit_execution) ->
    <<"unit_process_failed">>;
exact_post_build_failure_classification(unit_process_verification) ->
    <<"unit_process_attestation_rejected">>;
exact_post_build_failure_classification(child_evidence) ->
    <<"child_evidence_rejected">>;
exact_post_build_failure_classification(post_execution_source_verification) ->
    <<"source_changed_during_units">>;
exact_post_build_failure_classification(artifact_verification) ->
    <<"artifact_changed_during_units">>;
exact_post_build_failure_classification(attempt_cleanup) ->
    <<"attempt_cleanup_failed">>;
exact_post_build_failure_classification(report_publication) ->
    <<"unit_report_rejected">>;
exact_post_build_failure_classification(_) ->
    <<"post_build_invariant_rejected">>.

supervised_gleam_self_test() ->
    Identity = #{source_sha256 => process_supervisor_sha256(),
                  python_executable_sha256 => binary:copy(<<"0">>, 64),
                  python_implementation => <<"CPython">>,
                  python_version => <<"3.12.13">>,
                  console_isolation => process_supervisor_isolation()},
    Natural = #{outcome => exit_failure, exit_status => 1,
        deadline_ms => 330000, elapsed_ms => 123,
        output_bytes => 512, output_limit_bytes => 2097152,
        output_limit_exceeded => false, timed_out => false,
        terminal_control_bytes_removed => 0,
        child_exit_observed => true, process_supervisor_protocol_valid => true,
        native_tree_empty => true, native_console_isolated => true,
        process_supervisor_failure_code => none,
        process_supervisor_attestation_failure => none,
        process_supervisor_reported_status => 1,
        process_supervisor_observed_status => 1,
        native_descendant_outlived => false,
        native_termination_requested => false,
        process_supervisor => Identity},
    true = command_natural_exit_verified(Natural),
    false = command_natural_exit_verified(Natural#{native_tree_empty => false}),
    false = command_natural_exit_verified(
        Natural#{native_console_isolated => false}),
    false = command_natural_exit_verified(
        Natural#{process_supervisor_protocol_valid => false}),
    false = command_natural_exit_verified(
        Natural#{native_descendant_outlived => true}),
    false = command_natural_exit_verified(
        Natural#{native_termination_requested => true}),
    false = command_natural_exit_verified(Natural#{outcome => deadline}),
    false = command_natural_exit_verified(Natural#{exit_status => 256,
        process_supervisor_reported_status => 256,
        process_supervisor_observed_status => 256}),
    ProjectionState = (new_command_state(0, 1000, 1024, undefined))#{
        chunks => [<<"private-cookie-marker">>],
        failure_projection => {fun(_) -> #{safe => true} end,
                               fun(Value) -> Value =:= #{safe => true} end}},
    FailureProof = #{outcome => exit_failure},
    {error, #{safe := true}, ProjectedProof} = command_failure_result(
        ProjectionState, FailureProof),
    0 = maps:get(terminal_control_bytes_removed, ProjectedProof),
    InvalidState = ProjectionState#{failure_projection => {
        fun(Bytes) -> Bytes end, fun(_) -> false end}},
    {error, invalid_failure_projection, InvalidProof} = command_failure_result(
        InvalidState, FailureProof),
    0 = maps:get(terminal_control_bytes_removed, InvalidProof),
    {error, no_failure_projection,
     #{outcome := deadline, terminal_control_bytes_removed := 0}} =
        command_failure_result(ProjectionState, #{outcome => deadline}),
    VerifiedSuccess = Natural#{outcome => ok, exit_status => 0,
        process_supervisor_reported_status => 0,
        process_supervisor_observed_status => 0},
    {ok, <<"safe">>, VerifiedSuccess} = command_capture_success_result(
        ProjectionState, <<"safe">>, VerifiedSuccess),
    {error, RejectedSuccess} = command_capture_success_result(
        ProjectionState, <<"private-cookie-marker">>,
        VerifiedSuccess#{native_termination_requested => true}),
    true = maps:get(native_termination_requested, RejectedSuccess),
    <<"compile_success_attestation_rejected">> =
        exact_build_process_failure_classification(VerifiedSuccess#{
            native_termination_requested => true}),
    <<"compile_deadline">> = exact_build_process_failure_classification(
        VerifiedSuccess#{outcome => deadline}),
    <<"compile_output_limit">> = exact_build_process_failure_classification(
        VerifiedSuccess#{outcome => output_limit}),
    <<"compiler_rejected">> = exact_build_process_failure_classification(
        VerifiedSuccess#{outcome => exit_failure}),
    true = supervised_gleam_arguments_valid(["--http-exact-test"]),
    true = supervised_gleam_arguments_valid(["--http-server-exact-test"]),
    true = supervised_gleam_arguments_valid(["--http-ohttp-exact-test"]),
    true = supervised_gleam_arguments_valid(["--quic-check"]),
    true = supervised_gleam_arguments_valid(["--quic-test"]),
    true = supervised_gleam_test_arguments(["--http-test"]),
    true = supervised_gleam_test_arguments(["--http3-test"]),
    true = supervised_gleam_test_arguments(["--quic-test"]),
    false = supervised_gleam_test_arguments(["--quic-check"]),
    true = supervised_gleam_projected_arguments(["--quic-diagnostic-check"]),
    true = supervised_gleam_projected_arguments(["--http-ohttp-exact-test"]),
    630000 = supervised_gleam_outer_timeout(["--http-test"]),
    330000 = supervised_gleam_outer_timeout(["--http3-test"]),
    330000 = supervised_gleam_outer_timeout(["--quic-test"]),
    930000 = supervised_gleam_outer_timeout(["--http-exact-test"]),
    510000 = supervised_gleam_outer_timeout(["--http-server-exact-test"]),
    450000 = supervised_gleam_outer_timeout(["--http-ohttp-exact-test"]),
    30 = http_exact_unit_timeout(all),
    30 = http_exact_unit_timeout(http3_server_lifecycle),
    10 = http_exact_unit_timeout(ohttp),
    ToolchainFixture = #{gleam_version => <<"1.18.1">>,
        gleam_sha256 => binary:copy(<<"a">>, 64), otp_release => <<"29">>,
        erts_version => <<"17.0.5">>, os_family => <<"win32">>,
        os_name => <<"nt">>},
    true = supervised_toolchain_valid(ToolchainFixture),
    false = supervised_toolchain_valid(
        ToolchainFixture#{gleam_sha256 => binary:copy(<<"A">>, 64)}),
    gleam_test_success_summary_self_test(),
    exact_build_failure_report_self_test(Natural, ToolchainFixture),
    600000 = supervised_package_timeout("--http-test"),
    300000 = supervised_package_timeout("--http3-test"),
    300000 = supervised_package_timeout("--quic-test"),
    true = supervised_gleam_arguments_valid(["--http-diagnostic-check"]),
    true = supervised_gleam_arguments_valid(["--http3-diagnostic-check"]),
    true = supervised_gleam_arguments_valid(["--quic-diagnostic-check"]),
    false = supervised_gleam_arguments_valid(["--http-exact-test", "extra"]),
    false = supervised_gleam_arguments_valid(
        ["--http-server-exact-test", "extra"]),
    false = supervised_gleam_arguments_valid(
        ["--http-ohttp-exact-test", "extra"]),
    false = supervised_gleam_arguments_valid(["--unknown"]),
    ready = supervised_gleam_inner_outcome(["--http-exact-test"],
                                            <<"report_status_candidate=ready">>),
    failed = supervised_gleam_inner_outcome(["--http-exact-test"],
                                              <<"report_status_candidate=failed">>),
    ready = supervised_gleam_inner_outcome(["--http3-diagnostic-check"],
                                            <<"diagnostic_outcome=ready">>),
    failed = supervised_gleam_inner_outcome(["--quic-diagnostic-check"],
                                             <<"diagnostic_outcome=failed">>),
    ready = supervised_gleam_inner_outcome(["--http-server-exact-test"],
                                            <<"report_status_candidate=ready">>),
    ready = supervised_gleam_inner_outcome(["--http-ohttp-exact-test"],
                                            <<"report_status_candidate=ready">>),
    PackageInventoryDigest = binary:copy(<<"f">>, 64),
    PackageEvidenceLine = iolist_to_binary([
        "supervised_gleam mode=--quic-test package=quic_core modules=107 "
        "configured_units=718 inventory_sha256=", PackageInventoryDigest,
        " completed_tests=746 skipped=0 failures=0 passed=true\n"]),
    {passed, #{mode := <<"--quic-test">>, package := <<"quic_core">>,
               modules := 107, configured_units := 718,
               inventory_sha256 := PackageInventoryDigest,
               completed_tests := 746}} =
        supervised_gleam_inner_outcome(["--quic-test"], PackageEvidenceLine),
    PackageEvidence = #{mode => <<"--quic-test">>,
        package => <<"quic_core">>, modules => 107,
        configured_units => 718, inventory_sha256 => PackageInventoryDigest,
        completed_tests => 746},
    ExpectedOuterPackageLine = iolist_to_binary([
        "supervised_gleam outer_tree_verified=true inner_outcome=passed "
        "mode=--quic-test package=quic_core modules=107 "
        "configured_units=718 inventory_sha256=", PackageInventoryDigest,
        " completed_tests=746 skipped=0 failures=0"]),
    ExpectedOuterPackageLine = iolist_to_binary(
        supervised_gleam_outer_success_line({passed, PackageEvidence})),
    {passed, PackageEvidence} = supervised_gleam_inner_outcome(
        ["--quic-test"],
        <<PackageEvidenceLine/binary, "fixture-private-marker\n">>),
    nomatch = binary:match(ExpectedOuterPackageLine,
                           <<"fixture-private-marker">>),
    PackageSourceDigest = binary:copy(<<"b">>, 64),
    PackageRunnerDigest = binary:copy(<<"c">>, 64),
    PackageAttempt = #{mode => "--quic-test", package => <<"quic_core">>,
        source_before_sha256 => PackageSourceDigest,
        source_after_sha256 => PackageSourceDigest,
        source_files_before => 81, source_files_after => 81,
        source_after_state => verified, source_stable => true,
        runner_before_sha256 => PackageRunnerDigest,
        runner_after_sha256 => PackageRunnerDigest,
        runner_after_state => verified, runner_stable => true,
        toolchain => ToolchainFixture},
    PackageReadyOutcome = #{status => ready, evidence => PackageEvidence,
        failure_phase => <<"none">>, failure_classification => <<"none">>},
    PackageReadyReport = supervised_gleam_outer_package_report(
        PackageAttempt, PackageReadyOutcome, VerifiedSuccess),
    true = supervised_gleam_outer_package_report_valid(PackageReadyReport),
    <<"Ready">> = maps:get(status, PackageReadyReport),
    true = maps:get(source_stable, PackageReadyReport),
    true = maps:get(runner_stable, PackageReadyReport),
    true = maps:get(inner_process_verified, PackageReadyReport),
    PackageReportPath = "build/supervised-gleam/quic_core-test-reports/"
        ++ binary_to_list(PackageSourceDigest) ++ "-"
        ++ lists:duplicate(32, $d) ++ ".json",
    true = supervised_gleam_package_report_path_valid(PackageReportPath),
    false = supervised_gleam_package_report_path_valid(
        "build/supervised-gleam/quic_core-test-reports/../private.json"),
    ExpectedBoundOuterPackageLine = iolist_to_binary([
        "supervised_gleam outer_tree_verified=true inner_outcome=ready "
        "mode=--quic-test package=quic_core modules=107 "
        "configured_units=718 inventory_sha256=", PackageInventoryDigest,
        " completed_tests=746 skipped=0 failures=0 "
        "report_published=true report=", PackageReportPath]),
    ExpectedBoundOuterPackageLine = iolist_to_binary(
        supervised_gleam_outer_package_report_line(
            PackageReadyReport, PackageReportPath)),
    nomatch = binary:match(ExpectedBoundOuterPackageLine,
                           <<"fixture-private-marker">>),
    nomatch = binary:match(iolist_to_binary(json:encode(PackageReadyReport)),
                           <<"fixture-private-marker">>),
    {failed, <<"inner_result_missing">>} = supervised_gleam_inner_outcome(
        ["--quic-test"],
        <<"746 passed, no failures\nfixture-private-marker\n">>),
    PackageMissingOutcome = supervised_gleam_package_failed_outcome(
        <<"inner_evidence">>, <<"inner_result_missing">>),
    PackageMissingReport = supervised_gleam_outer_package_report(
        PackageAttempt, PackageMissingOutcome, VerifiedSuccess),
    true = supervised_gleam_outer_package_report_valid(PackageMissingReport),
    <<"Failed">> = maps:get(status, PackageMissingReport),
    <<"unavailable">> = maps:get(counts_state, PackageMissingReport),
    <<"inner_result_missing">> = maps:get(
        failure_classification, PackageMissingReport),
    MissingLine = iolist_to_binary(supervised_gleam_outer_package_report_line(
        PackageMissingReport, PackageReportPath)),
    nomatch = binary:match(MissingLine, <<"fixture-private-marker">>),
    {failed, <<"inner_result_ambiguous">>} =
        supervised_gleam_inner_outcome(
            ["--quic-test"], <<PackageEvidenceLine/binary,
                               PackageEvidenceLine/binary>>),
    {failed, <<"inner_result_ambiguous">>} =
        supervised_gleam_inner_outcome(
            ["--quic-test"], <<PackageEvidenceLine/binary,
                               "supervised_gleam mode=truncated\n">>),
    {failed, <<"inner_result_context_mismatch">>} =
        supervised_gleam_inner_outcome(
            ["--http3-test"], PackageEvidenceLine),
    {failed, <<"inner_result_schema_rejected">>} =
        supervised_gleam_inner_outcome(
            ["--quic-test"], <<"supervised_gleam mode=truncated\n">>),
    PackageMalformedOutcome = supervised_gleam_package_failed_outcome(
        <<"inner_evidence">>, <<"inner_result_schema_rejected">>),
    PackageMalformedReport = supervised_gleam_outer_package_report(
        PackageAttempt, PackageMalformedOutcome, VerifiedSuccess),
    true = supervised_gleam_outer_package_report_valid(
        PackageMalformedReport),
    {failed, <<"inner_result_schema_rejected">>} =
        supervised_gleam_inner_outcome(
        ["--quic-test"],
        iolist_to_binary([
          "supervised_gleam mode=--quic-test package=quic_core modules=0 "
          "configured_units=718 inventory_sha256=", PackageInventoryDigest,
          " completed_tests=746 skipped=0 failures=0 passed=true\n"])),
    {failed, <<"inner_result_context_mismatch">>} =
        supervised_gleam_inner_outcome(
        ["--quic-test"],
        iolist_to_binary([
          "supervised_gleam mode=--quic-test package=http modules=107 "
          "configured_units=718 inventory_sha256=", PackageInventoryDigest,
          " completed_tests=746 skipped=0 failures=0 passed=true\n"])),
    {failed, <<"inner_result_schema_rejected">>} =
        supervised_gleam_inner_outcome(
        ["--quic-test"],
        iolist_to_binary([
          "supervised_gleam mode=--quic-test package=quic_core modules=107 "
          "configured_units=0 inventory_sha256=", PackageInventoryDigest,
          " completed_tests=746 skipped=0 failures=0 passed=true\n"])),
    {failed, <<"inner_result_schema_rejected">>} =
        supervised_gleam_inner_outcome(
        ["--quic-test"],
        iolist_to_binary([
          "supervised_gleam mode=--quic-test package=quic_core modules=107 "
          "configured_units=718 inventory_sha256=", PackageInventoryDigest,
          " completed_tests=0 skipped=0 failures=0 passed=true\n"])),
    {failed, <<"inner_result_schema_rejected">>} =
        supervised_gleam_inner_outcome(
        ["--quic-test"],
        iolist_to_binary([
          "supervised_gleam mode=--quic-test package=quic_core modules=107 "
          "configured_units=718 inventory_sha256=", PackageInventoryDigest,
          " completed_tests=1000000000 skipped=0 failures=0 passed=true\n"])),
    ExcessivePackageLines = <<(binary:copy(<<"\n">>, 100000))/binary,
                              PackageEvidenceLine/binary>>,
    {failed, <<"inner_result_schema_rejected">>} =
        supervised_gleam_inner_outcome(
            ["--quic-test"], ExcessivePackageLines),
    ChangedSourceAttempt = PackageAttempt#{
        source_after_sha256 => binary:copy(<<"d">>, 64),
        source_stable => false},
    #{status := failed,
      failure_classification := <<"source_changed_during_test">>} =
        ChangedSourceOutcome = supervised_gleam_outer_package_bind_outcome(
            PackageReadyOutcome, ChangedSourceAttempt),
    true = supervised_gleam_outer_package_report_valid(
        supervised_gleam_outer_package_report(
            ChangedSourceAttempt, ChangedSourceOutcome, VerifiedSuccess)),
    ChangedRunnerAttempt = PackageAttempt#{
        runner_after_sha256 => binary:copy(<<"e">>, 64),
        runner_stable => false},
    #{status := failed,
      failure_classification := <<"runner_changed_during_test">>} =
        ChangedRunnerOutcome = supervised_gleam_outer_package_bind_outcome(
            PackageReadyOutcome, ChangedRunnerAttempt),
    true = supervised_gleam_outer_package_report_valid(
        supervised_gleam_outer_package_report(
            ChangedRunnerAttempt, ChangedRunnerOutcome, VerifiedSuccess)),
    UnavailableSourceAttempt = PackageAttempt#{
        source_after_sha256 => null, source_files_after => 0,
        source_after_state => unavailable, source_stable => false},
    #{status := failed,
      failure_classification := <<"source_capture_failed">>} =
        UnavailableSourceOutcome = supervised_gleam_outer_package_bind_outcome(
            PackageReadyOutcome, UnavailableSourceAttempt),
    true = supervised_gleam_outer_package_report_valid(
        supervised_gleam_outer_package_report(UnavailableSourceAttempt,
            UnavailableSourceOutcome, VerifiedSuccess)),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{private => <<"fixture-private-marker">>}),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{source_before_sha256 => binary:copy(<<"A">>, 64)}),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{source_stable => false}),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{runner_stable => false}),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{outer_process =>
            (maps:get(outer_process, PackageReadyReport))#{
                tail => <<"fixture-private-marker">>}}),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{outer_process => maps:remove(
            deadline_ms, maps:get(outer_process, PackageReadyReport))}),
    false = supervised_gleam_outer_package_report_valid(
        PackageMissingReport#{configured_modules => 1}),
    false = supervised_gleam_outer_package_report_valid(
        PackageMissingReport#{failure_classification =>
            <<"fixture-private-marker">>}),
    false = supervised_gleam_outer_package_report_valid(
        PackageReadyReport#{failure_count => 1}),
    {<<"inner_process">>, <<"inner_process_start_failed">>} =
        supervised_gleam_package_process_failure(#{outcome => start_failed}),
    {<<"inner_process">>, <<"inner_process_deadline">>} =
        supervised_gleam_package_process_failure(#{outcome => deadline}),
    {<<"inner_process">>, <<"inner_process_output_limit">>} =
        supervised_gleam_package_process_failure(#{outcome => output_limit}),
    {<<"inner_process">>, <<"inner_process_protocol_rejected">>} =
        supervised_gleam_package_process_failure(#{outcome => protocol_failure}),
    {<<"inner_process">>, <<"inner_process_attestation_rejected">>} =
        supervised_gleam_package_process_failure(
            #{outcome => supervisor_unconfirmed}),
    UngroundedProof = #{outcome => invalid},
    {#{failure_classification :=
           <<"inner_process_attestation_rejected">>} = UngroundedProofOutcome,
     UngroundedProof} = supervised_gleam_outer_package_command_outcome(
        "--quic-test", {error, UngroundedProof}),
    false = supervised_gleam_outer_package_report_valid(
        supervised_gleam_outer_package_report(
            PackageAttempt, UngroundedProofOutcome, UngroundedProof)),
    {#{failure_classification :=
           <<"inner_process_attestation_rejected">>} = NonMapProofOutcome,
     invalid_success_proof} = supervised_gleam_outer_package_command_outcome(
        "--quic-test", {ok, <<"fixture-private-marker">>,
                         invalid_success_proof}),
    false = supervised_gleam_outer_package_report_valid(
        supervised_gleam_outer_package_report(
            PackageAttempt, NonMapProofOutcome, invalid_success_proof)),
    NaturalProjection = gleam_test_failure_projection(
        <<"safe_projection_test failed\n900 passed, 96 failures\n"
          "Authorization: Bearer report-private-bearer\n"
          "Cookie: report-private-cookie\n"
          "-----BEGIN PRIVATE KEY----- report-private-key\n">>),
    true = gleam_test_failure_projection_valid(NaturalProjection),
    {NaturalFailedOutcome, Natural} =
        supervised_gleam_outer_package_command_outcome(
            "--quic-test", {error, NaturalProjection, Natural}),
    <<"inner_test_failed">> = maps:get(
        failure_classification, NaturalFailedOutcome),
    NaturalProjection = maps:get(
        failure_projection, NaturalFailedOutcome),
    NaturalFailedReport = supervised_gleam_outer_package_report(
        PackageAttempt, NaturalFailedOutcome, Natural),
    true = supervised_gleam_outer_package_report_valid(NaturalFailedReport),
    2 = maps:get(schema, NaturalFailedReport),
    <<"projected">> = maps:get(completion_state, NaturalFailedReport),
    996 = maps:get(completed_tests, NaturalFailedReport),
    96 = maps:get(observed_test_failures, NaturalFailedReport),
    96 = maps:get(failure_count, NaturalFailedReport),
    NaturalProjection = maps:get(failure_projection, NaturalFailedReport),
    true = maps:get(
        failure_projection_bound_to_current_source, NaturalFailedReport),
    NaturalFailedJson = iolist_to_binary(json:encode(NaturalFailedReport)),
    true = lists:all(fun(Marker) ->
        binary:match(NaturalFailedJson, Marker) =:= nomatch
    end, [<<"report-private-bearer">>, <<"report-private-cookie">>,
          <<"report-private-key">>]),
    false = supervised_gleam_outer_package_report_valid(
        NaturalFailedReport#{failure_projection => null,
            failure_projection_bound_to_current_source => false}),
    false = supervised_gleam_outer_package_report_valid(
        NaturalFailedReport#{failure_count => 1}),
    false = supervised_gleam_outer_package_report_valid(
        NaturalFailedReport#{failure_phase => <<"inner_evidence">>,
            failure_classification => <<"inner_result_missing">>}),
    {RejectedProjectionOutcome, Natural} =
        supervised_gleam_outer_package_command_outcome(
            "--quic-test", {error, #{schema => 1}, Natural}),
    <<"inner_failure_projection_rejected">> = maps:get(
        failure_classification, RejectedProjectionOutcome),
    RejectedProjectionReport = supervised_gleam_outer_package_report(
        PackageAttempt, RejectedProjectionOutcome, Natural),
    true = supervised_gleam_outer_package_report_valid(
        RejectedProjectionReport),
    <<"unavailable">> = maps:get(
        completion_state, RejectedProjectionReport),
    null = maps:get(completed_tests, RejectedProjectionReport),
    <<"unavailable">> = maps:get(
        skipped_tests_state, RejectedProjectionReport),
    null = maps:get(skipped_tests, RejectedProjectionReport),
    ProjectedSourceDriftAttempt = PackageAttempt#{
        source_after_sha256 => binary:copy(<<"d">>, 64),
        source_sha256 => binary:copy(<<"d">>, 64), source_stable => false},
    ProjectedSourceDriftOutcome = supervised_gleam_outer_package_bind_outcome(
        NaturalFailedOutcome, ProjectedSourceDriftAttempt),
    ProjectedSourceDriftReport = supervised_gleam_outer_package_report(
        ProjectedSourceDriftAttempt, ProjectedSourceDriftOutcome, Natural),
    true = supervised_gleam_outer_package_report_valid(
        ProjectedSourceDriftReport),
    false = maps:get(failure_projection_bound_to_current_source,
        ProjectedSourceDriftReport),
    996 = maps:get(completed_tests, ProjectedSourceDriftReport),
    ProjectedRunnerDriftAttempt = PackageAttempt#{
        runner_after_sha256 => binary:copy(<<"e">>, 64),
        runner_sha256 => binary:copy(<<"e">>, 64), runner_stable => false},
    ProjectedRunnerDriftOutcome = supervised_gleam_outer_package_bind_outcome(
        NaturalFailedOutcome, ProjectedRunnerDriftAttempt),
    ProjectedRunnerDriftReport = supervised_gleam_outer_package_report(
        ProjectedRunnerDriftAttempt, ProjectedRunnerDriftOutcome, Natural),
    true = supervised_gleam_outer_package_report_valid(
        ProjectedRunnerDriftReport),
    false = maps:get(failure_projection_bound_to_current_source,
        ProjectedRunnerDriftReport),
    996 = maps:get(completed_tests, ProjectedRunnerDriftReport),
    false = supervised_gleam_outer_package_report_valid(
        PackageMissingReport#{failure_phase => <<"inner_test">>,
            failure_classification => <<"inner_test_failed">>}),
    MissingWithSourceDrift = PackageMissingReport#{
        source_after_sha256 => binary:copy(<<"d">>, 64),
        source_sha256 => binary:copy(<<"d">>, 64), source_stable => false},
    false = supervised_gleam_outer_package_report_valid(
        MissingWithSourceDrift),
    MissingWithRunnerDrift = PackageMissingReport#{
        runner_after_sha256 => binary:copy(<<"e">>, 64),
        runner_sha256 => binary:copy(<<"e">>, 64), runner_stable => false},
    false = supervised_gleam_outer_package_report_valid(
        MissingWithRunnerDrift),
    false = supervised_gleam_outer_package_report_valid(
        PackageMissingReport#{failure_phase => <<"source_verification">>,
            failure_classification => <<"source_changed_during_test">>}),
    false = supervised_gleam_outer_package_report_valid(
        PackageMissingReport#{failure_phase => <<"runner_identity">>,
            failure_classification => <<"runner_changed_during_test">>}),
    MissingTreeProcess = (maps:get(outer_process, PackageMissingReport))#{
        native_tree_empty => false},
    false = supervised_gleam_outer_package_report_valid(
        PackageMissingReport#{outer_process => MissingTreeProcess,
            inner_process_verified => false}),
    DeadlineProof = VerifiedSuccess#{outcome => deadline,
        exit_status => 124, timed_out => true,
        process_supervisor_failure_code => <<"supervisor_deadline">>,
        process_supervisor_reported_status => 124,
        process_supervisor_observed_status => 124,
        native_termination_requested => true},
    true = process_deadline_verified(124, DeadlineProof),
    DeadlineOutcome = supervised_gleam_package_failed_outcome(
        <<"inner_process">>, <<"inner_process_deadline">>),
    DeadlineReport = supervised_gleam_outer_package_report(
        PackageAttempt, DeadlineOutcome, DeadlineProof),
    true = supervised_gleam_outer_package_report_valid(DeadlineReport),
    false = supervised_gleam_outer_package_report_valid(
        DeadlineReport#{failure_phase => <<"inner_test">>,
            failure_classification => <<"inner_test_failed">>}),
    false = supervised_gleam_outer_package_report_valid(
        DeadlineReport#{outer_process =>
            (maps:get(outer_process, DeadlineReport))#{timed_out => false}}),
    OutputLimitProof = VerifiedSuccess#{outcome => output_limit,
        exit_status => 125, output_bytes => 2097153,
        output_limit_exceeded => true,
        process_supervisor_failure_code => <<"supervisor_output_limit">>,
        process_supervisor_reported_status => 125,
        process_supervisor_observed_status => 125,
        native_termination_requested => true},
    true = process_output_limit_verified(125, OutputLimitProof),
    OutputLimitOutcome = supervised_gleam_package_failed_outcome(
        <<"inner_process">>, <<"inner_process_output_limit">>),
    OutputLimitReport = supervised_gleam_outer_package_report(
        PackageAttempt, OutputLimitOutcome, OutputLimitProof),
    true = supervised_gleam_outer_package_report_valid(OutputLimitReport),
    2097153 = maps:get(output_bytes,
        maps:get(outer_process, OutputLimitReport)),
    false = supervised_gleam_outer_package_report_valid(
        OutputLimitReport#{failure_classification =>
            <<"inner_process_deadline">>}),
    StartProof = #{outcome => start_failed, exit_status => null,
        deadline_ms => 330000, elapsed_ms => 1, output_bytes => 0,
        output_limit_bytes => 2097152, output_limit_exceeded => false,
        timed_out => false, terminal_control_bytes_removed => 0,
        child_exit_observed => false},
    StartOutcome = supervised_gleam_package_failed_outcome(
        <<"inner_process">>, <<"inner_process_start_failed">>),
    StartReport = supervised_gleam_outer_package_report(
        PackageAttempt, StartOutcome, StartProof),
    true = supervised_gleam_outer_package_report_valid(StartReport),
    AttestationProof = VerifiedSuccess#{native_tree_empty => false},
    AttestationOutcome = supervised_gleam_package_failed_outcome(
        <<"inner_process">>, <<"inner_process_attestation_rejected">>),
    AttestationReport = supervised_gleam_outer_package_report(
        PackageAttempt, AttestationOutcome, AttestationProof),
    true = supervised_gleam_outer_package_report_valid(AttestationReport),
    false = supervised_gleam_outer_package_report_valid(
        AttestationReport#{failure_phase => <<"inner_evidence">>,
            failure_classification => <<"inner_result_missing">>}),
    supervised_gleam_package_report_publication_self_test(
        PackageAttempt, PackageReadyReport),
    true = try supervised_gleam_inner_outcome(["--http-exact-test"],
        <<"report_status_candidate=ready report_status_candidate=failed">>),
        false
        catch error:invalid_http_exact_inner_outcome -> true end,
    gleam_diagnostic_projection_self_test(),
    gleam_test_failure_projection_self_test(),
    command_terminal_projection_self_test(),
    exact_digest_self_test(),
    exact_failure_projection_self_test(),
    http_compile_driver_self_test(),
    exact_post_build_publication_self_test(ToolchainFixture),
    http_exact_execution_beam_identity_self_test(),
    io:format("supervised_gleam self_test controls=246 passed=true~n"),
    ok.

supervised_gleam_package_report_publication_self_test(Attempt0, Report) ->
    Token = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    FixtureRoot = filename:join([filename:absname("."), "build",
        "supervised-gleam", "package-report-self-test-"
            ++ binary_to_list(Token)]),
    Attempt = Attempt0#{root => FixtureRoot, nonce => Token},
    {ok, Relative} = supervised_gleam_publish_package_report(Attempt, Report),
    Path = filename:join(FixtureRoot, Relative),
    try
        {ok, Published} = file:read_file(Path),
        Expected = iolist_to_binary([json:encode(Report), $\n]),
        Expected = Published,
        true = byte_size(Published) > 0 andalso byte_size(Published) =< 65536,
        nomatch = binary:match(Published, <<"fixture-private-marker">>)
    after
        ok = file:delete(Path),
        ok = file:del_dir(filename:dirname(Path)),
        ok = file:del_dir(filename:join(
            [FixtureRoot, "build", "supervised-gleam"])),
        ok = file:del_dir(filename:join(FixtureRoot, "build")),
        ok = file:del_dir(FixtureRoot)
    end,
    ok.

gleam_test_success_summary_self_test() ->
    #{passed := 485, skipped := 0} = gleam_test_success_summary(
        <<"running tests\n485 passed, no failures\n">>),
    #{passed := 7, skipped := 2} = gleam_test_success_summary(
        <<"7 passed, 0 failures, 2 skipped\r\n">>),
    true = try gleam_test_success_summary(
        <<"1 passed, no failures\n2 passed, no failures\n">>), false
        catch error:invalid_or_ambiguous_gleeunit_success_summary -> true end,
    true = try gleam_test_success_summary(
        <<"7 passed, 1 failures\n">>), false
        catch error:invalid_or_ambiguous_gleeunit_success_summary -> true end,
    ok.

exact_build_failure_report_self_test(Natural, Toolchain) ->
    UnitProcess = exact_safe_unit_process(Natural#{
        output_hashed_bytes => 512, output_limit_bytes => 8388608,
        output_digest_complete => true, vm_process_heap_words => 33554432,
        vm_heap_includes_shared_binaries => true,
        crash_dumps_disabled => true}),
    Digest = binary:copy(<<"a">>, 64),
    Driver = #{relative_path => <<"test/http_test.gleam">>,
        original_sha256 => Digest, driver_sha256 => binary:copy(<<"b">>, 64),
        replacement_count => 1},
    Report = exact_build_failure_report(
        Digest, 10, binary:copy(<<"c">>, 64), Toolchain, Driver, ohttp,
        Natural, <<"compiler_rejected">>, true,
        gleam_empty_diagnostic_projection()),
    true = exact_build_failure_report_valid(Report),
    false = exact_build_failure_report_valid(
        Report#{source_sha256 => binary:copy(<<"A">>, 64)}),
    false = exact_build_failure_report_valid(
        Report#{source_files => 0}),
    false = exact_build_failure_report_valid(
        Report#{failure_classification => <<"private-reason">>}),
    false = exact_build_failure_report_valid(
        Report#{process => (maps:get(process, Report))#{tail => <<"private">>}}),
    false = exact_build_failure_report_valid(
        Report#{build_diagnostics => #{private => <<"private">>}}),
    true = exact_build_failure_report_valid(exact_build_failure_report(
        Digest, 10, binary:copy(<<"c">>, 64), Toolchain, Driver, ohttp,
        Natural#{outcome => start_failed, exit_status => null,
            child_exit_observed => false},
        <<"compile_process_failure">>, true,
        gleam_empty_diagnostic_projection())),
    FailureRow = #{unit => 1, module => <<"safe_module">>,
        function => <<"safe_test">>, kind => <<"test">>,
        classification => <<"assertion_failed">>, stack => []},
    UnitNonce = binary:copy(<<"0">>, 32),
    UnitRunner = binary:copy(<<"e">>, 64),
    UnitBeamInventory = binary:copy(<<"1">>, 64),
    UnitLoaded = binary:copy(<<"2">>, 64),
    UnitChild0 = #{schema => 2, run_nonce => UnitNonce,
        listener_completed => true, eunit_completed => false,
        unexpected_events => 0, failure_count => 1,
        failures => [#{unit => 1, classification => <<"assertion_failed">>,
                       stack => []}], failures_dropped => 0,
        execution_beam_identity => #{runner_sha256 => UnitRunner,
            expected_inventory_sha256 => UnitBeamInventory,
            loaded_beam_sha256 => UnitLoaded, loaded_beam_count => 1,
            loaded_beams_verified => true},
        units => [#{ordinal => 1, module => <<"safe_module">>,
            function => <<"safe_test">>, kind => <<"test">>,
            counts => #{started => 1, completed => 1, passed => 0,
                failed => 1, skipped => 0, cancelled => 0}}]},
    UnitChild = evidence_json_decode(iolist_to_binary(json:encode(UnitChild0))),
    UnitReport = #{schema => 3, shareable => true, status => <<"Failed">>,
        run_nonce => UnitNonce, child => UnitChild,
        prebuild_profile_state => <<"absent">>,
        source_sha256 => Digest, source_files => 10,
        dependency_cache_sha256 => binary:copy(<<"c">>, 64),
        toolchain => Toolchain, compile_driver => Driver,
        artifact_sha256 => binary:copy(<<"d">>, 64), artifact_files => 4,
        selection => <<"ohttp">>, unit_timeout_seconds => 10,
        configured_modules => 1, configured_units => 1,
        suite_inventory_sha256 => binary:copy(<<"f">>, 64),
        suite_inventory_state => <<"verified">>,
        counts_state => <<"verified">>, completed_tests => 1,
        skipped_tests => 0, skipped_tests_state => <<"verified">>,
        failure_count => 1, failures => [FailureRow],
        child_exit_status => 1, process => UnitProcess,
        rerun_command =>
            <<"escript scripts/supervised_gleam.escript --http-ohttp-exact-test">>,
        runner_sha256 => UnitRunner,
        execution_beam_inventory_sha256 => UnitBeamInventory,
        loaded_beam_sha256 => UnitLoaded,
        loaded_beam_count => 1},
    true = exact_unit_report_valid(UnitReport),
    false = exact_unit_report_valid(UnitReport#{status => <<"Ready">>}),
    false = exact_unit_report_valid(UnitReport#{failures => [
        FailureRow#{module => <<"private/path">>}]}),
    false = exact_unit_report_valid(UnitReport#{process =>
        UnitProcess#{tail => <<"private-cookie-marker">>}}),
    false = exact_unit_report_valid(UnitReport#{process =>
        maps:remove(output_digest_complete, UnitProcess)}),
    false = exact_unit_report_valid(UnitReport#{process =>
        UnitProcess#{timed_out => true}}),
    false = exact_unit_report_valid(UnitReport#{runner_sha256 =>
        binary:copy(<<"E">>, 64)}),
    false = exact_unit_report_valid(UnitReport#{child_exit_status => 0}),
    AttemptReport = #{schema => 3,
        report_kind => <<"http_exact_attempt">>, shareable => true,
        status => <<"Failed">>, prebuild_profile_state => <<"absent">>,
        source_sha256 => Digest, source_files => 10,
        dependency_cache_sha256 => binary:copy(<<"c">>, 64),
        toolchain => Toolchain, compile_driver => Driver,
        artifact_sha256 => null, artifact_files => 0,
        artifact_state => <<"unavailable">>, runner_sha256 => null,
        execution_beam_inventory_sha256 => null,
        loaded_beam_sha256 => null, loaded_beam_count => null,
        selection => <<"ohttp">>, unit_timeout_seconds => 10,
        configured_modules => null, configured_units => null,
        suite_inventory_sha256 => null,
        suite_inventory_state => <<"unavailable">>,
        counts_state => <<"unavailable">>, completed_tests => null,
        skipped_tests => null, skipped_tests_state => <<"unavailable">>,
        observed_test_failures => null, failures => [],
        child_exit_status => -1, process => #{},
        rerun_command =>
            <<"escript scripts/supervised_gleam.escript --http-ohttp-exact-test">>,
        failure_phase => <<"source_verification">>,
        failure_classification => <<"source_verification_failed">>,
        source_stable => false},
    true = exact_post_build_failure_report_valid(AttemptReport),
    false = exact_post_build_failure_report_valid(AttemptReport#{
        failure_classification => <<"private-reason">>}),
    false = exact_post_build_failure_report_valid(AttemptReport#{
        artifact_state => <<"verified">>}),
    false = exact_post_build_failure_report_valid(AttemptReport#{
        failures => [FailureRow]}),
    false = exact_post_build_failure_report_valid(AttemptReport#{
        process => #{tail => <<"private-cookie-marker">>}}),
    CleanupReport = AttemptReport#{
        artifact_sha256 => binary:copy(<<"d">>, 64), artifact_files => 4,
        artifact_state => <<"verified">>, runner_sha256 => UnitRunner,
        execution_beam_inventory_sha256 => UnitBeamInventory,
        loaded_beam_sha256 => UnitLoaded, loaded_beam_count => 1,
        configured_modules => 1, configured_units => 1,
        suite_inventory_sha256 => binary:copy(<<"f">>, 64),
        suite_inventory_state => <<"verified">>,
        counts_state => <<"verified">>, completed_tests => 1,
        skipped_tests => 0, skipped_tests_state => <<"verified">>,
        observed_test_failures => 1, failures => [FailureRow],
        child_exit_status => 1, process => UnitProcess,
        failure_phase => <<"attempt_cleanup">>,
        failure_classification => <<"attempt_cleanup_failed">>,
        source_stable => true},
    true = exact_post_build_failure_report_valid(CleanupReport),
    false = exact_post_build_failure_report_valid(CleanupReport#{
        failure_classification => <<"unit_report_rejected">>}),
    nomatch = binary:match(iolist_to_binary(json:encode(Report)),
                           <<"private-cookie-marker">>),
    exact_build_failure_publication_self_test(Natural, Toolchain),
    ok.

exact_build_failure_publication_self_test(Natural, Toolchain) ->
    Root = filename:absname(filename:join("build/supervised-gleam",
        "build-failure-report-self-test-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    Config = filename:join(Root, "gleam.toml"),
    Source = filename:join(Root, "src/safe.gleam"),
    ok = filelib:ensure_dir(Config),
    ok = file:write_file(Config, <<"name = \"safe\"\n">>, [exclusive]),
    ok = filelib:ensure_dir(Source),
    ok = file:write_file(Source, <<"pub fn safe() { Nil }\n">>, [exclusive]),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(filename:join(Root,
        "build/supervised-gleam/http-exact-attempts"), Nonce),
    put(http_exact_attempt_lease, Lease),
    Stage = filename:join(maps:get(root, Lease), "stage"),
    ok = file:make_dir(Stage),
    Paths = http_exact_source_paths(Root),
    true = length(Paths) =:= 2,
    lists:foreach(fun(Relative) -> ok = exact_copy_file(
        filename:join(Root, Relative), filename:join(Stage, Relative)) end,
        Paths),
    Digest = root_relative_digest(Root, Paths),
    DriverDigest = binary:copy(<<"a">>, 64),
    Driver = #{relative_path => <<"test/http_test.gleam">>,
        original_sha256 => DriverDigest,
        driver_sha256 => binary:copy(<<"b">>, 64), replacement_count => 1},
    true = try exact_publish_build_failure(
        Root, Stage, Paths, Digest, length(Paths), binary:copy(<<"c">>, 64),
        Toolchain, Driver, ohttp, Nonce, Natural, <<"compiler_rejected">>,
        gleam_empty_diagnostic_projection()), false
    catch error:http_exact_test_beam_build_failed -> true end,
    true = execution_beam_path_absent(maps:get(root, Lease)),
    released = get(http_exact_attempt_lease),
    ok = exact_release_attempt_if_active(),
    Pattern = filename:join(Root,
        "build/supervised-gleam/http-exact-reports/*.json"),
    [ReportPath] = filelib:wildcard(Pattern),
    Published = evidence_json_decode(element(2, file:read_file(ReportPath))),
    <<"Failed">> = maps:get(<<"status">>, Published),
    true = maps:get(<<"source_stable">>, Published),
    <<"compiler_rejected">> =
        maps:get(<<"failure_classification">>, Published),
    _ = exact_remove_tree(Root, 0),
    ok.

http_compile_driver_self_test() ->
    Original = <<"import gleeunit\n"
                 "pub fn main() -> Nil { gleeunit.main() }\n"
                 "pub fn retained_test() -> Nil { Nil }\n">>,
    {ok, Driver} = http_compile_driver(Original),
    nomatch = binary:match(Driver, <<"gleeunit.main()">>),
    {_, _} = binary:match(Driver, <<"retained_test">>),
    error = http_compile_driver(<<"pub fn main() -> Nil { Nil }\n">>),
    error = http_compile_driver(
        <<"gleeunit.main()\ngleeunit.main()\n">>),
    ok.

exact_post_build_publication_self_test(Toolchain) ->
    Root = filename:absname(filename:join("build/supervised-gleam",
        "post-build-report-self-test-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    Config = filename:join(Root, "gleam.toml"),
    Source = filename:join(Root, "src/safe.gleam"),
    ok = filelib:ensure_dir(Config),
    ok = file:write_file(Config, <<"name = \"safe\"\n">>, [exclusive]),
    ok = filelib:ensure_dir(Source),
    ok = file:write_file(Source, <<"pub fn safe() { Nil }\n">>, [exclusive]),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(filename:join(Root,
        "build/supervised-gleam/http-exact-attempts"), Nonce),
    put(http_exact_attempt_lease, Lease),
    Stage = filename:join(maps:get(root, Lease), "stage"),
    ok = file:make_dir(Stage),
    Paths = http_exact_source_paths(Root),
    true = length(Paths) =:= 2,
    lists:foreach(fun(Relative) -> ok = exact_copy_file(
        filename:join(Root, Relative), filename:join(Stage, Relative)) end,
        Paths),
    Digest = root_relative_digest(Root, Paths),
    ArtifactPath = "build/dev/erlang/http/ebin/safe.beam",
    ok = filelib:ensure_dir(filename:join(Stage, ArtifactPath)),
    ok = file:write_file(filename:join(Stage, ArtifactPath), <<"safe-beam">>,
                         [exclusive]),
    true = exact_stage_artifacts_exist(Stage, [ArtifactPath]),
    false = exact_stage_artifacts_exist(Stage, ["missing.beam"]),
    ArtifactDigest = stage_relative_digest(Stage, [ArtifactPath]),
    DriverDigest = binary:copy(<<"a">>, 64),
    Context = #{root => Root, stage => Stage, source_paths => Paths,
        source_sha256 => Digest, source_files => length(Paths),
        dependency_cache_sha256 => binary:copy(<<"b">>, 64),
        toolchain => Toolchain,
        compile_driver => #{relative_path => <<"test/http_test.gleam">>,
            original_sha256 => DriverDigest,
            driver_sha256 => binary:copy(<<"c">>, 64),
            replacement_count => 1},
        selection => ohttp, nonce => Nonce,
        phase => post_execution_source_verification,
        configured_modules => 1, configured_units => 1,
        suite_inventory_sha256 => binary:copy(<<"e">>, 64),
        suite_inventory_state => <<"verified">>,
        counts_state => <<"verified">>, completed_tests => 1,
        skipped_tests => 0, skipped_tests_state => <<"verified">>,
        observed_test_failures => 0, failures => [],
        child_exit_status => 0, process => #{},
        artifact_sha256 => ArtifactDigest, artifact_files => 1,
        artifact_paths => [ArtifactPath],
        runner_sha256 => binary:copy(<<"6">>, 64),
        execution_beam_inventory_sha256 => binary:copy(<<"7">>, 64),
        loaded_beam_sha256 => binary:copy(<<"8">>, 64),
        loaded_beam_count => 1},
    ok = file:write_file(Source, <<"pub fn changed() { Nil }\n">>),
    ok = exact_publish_post_build_failure(Context),
    true = execution_beam_path_absent(maps:get(root, Lease)),
    released = get(http_exact_attempt_lease),
    ok = exact_release_attempt_if_active(),
    Pattern = filename:join(Root,
        "build/supervised-gleam/http-exact-reports/*.json"),
    [ReportPath] = filelib:wildcard(Pattern),
    Report = evidence_json_decode(element(2, file:read_file(ReportPath))),
    <<"Failed">> = maps:get(<<"status">>, Report),
    false = maps:get(<<"source_stable">>, Report),
    <<"source_changed_during_units">> =
        maps:get(<<"failure_classification">>, Report),
    1 = maps:get(<<"completed_tests">>, Report),
    <<"verified">> = maps:get(<<"artifact_state">>, Report),
    _ = exact_remove_tree(Root, 0),
    ok.

http_exact_execution_beam_identity_self_test() ->
    Root = filename:absname("."),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(filename:join(Root,
        "build/supervised-gleam/http-exact-self-test-attempts"), Nonce),
    true = try
        _ = execution_beam_reserve_attempt(filename:join(Root,
            "build/supervised-gleam/http-exact-self-test-attempts"), Nonce),
        false
    catch error:execution_beam_attempt_conflict -> true end,
    Stage = filename:join(maps:get(root, Lease), "stage"),
    ok = file:make_dir(Stage),
    BuildRoot = filename:join(Stage, "build/dev"),
    Ebin = filename:join(BuildRoot, "erlang/http_exact_fixture/ebin"),
    Source = filename:join(Ebin, "http_exact_identity_fixture.erl"),
    ok = filelib:ensure_dir(Source),
    SourceBytes = <<"-module(http_exact_identity_fixture).\n"
                    "-export([identity_test/0]).\n"
                    "identity_test()->ok.\n">>,
    ok = execution_beam_publish_new(Source, SourceBytes, 1048576),
    {ok, Module, Original, []} = compile:file(
        Source, [binary, return_errors, return_warnings]),
    BeamPath = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    ok = execution_beam_publish_new(BeamPath, Original, 4194304),
    RunnerInfo = compile_http_exact_runner(Root, Lease),
    Runner = maps:get(directory, RunnerInfo),
    RunnerSha = maps:get(sha256, RunnerInfo),
    Inventory = execution_beam_inventory([Ebin], BuildRoot,
        fun(Path) -> execution_beam_read(Path, 4194304) end),
    InventorySha = maps:get(sha256, Inventory),
    Units = [#{module => <<"http_exact_identity_fixture">>,
               function => <<"identity_test">>, kind => <<"test">>}],
    SuccessPath = filename:join(maps:get(root, Lease), "identity-success.json"),
    SuccessEval = execution_beam_bootstrap_evaluation(
        Lease, run_units_attested,
        [Units, SuccessPath, <<"http-exact-identity-success">>, 5,
         RunnerSha, BuildRoot, Inventory], RunnerSha, InventorySha, 126),
    {0, SuccessProcess} = run_child_evaluation(Stage, [Runner, Ebin],
        SuccessEval, 15000),
    true = process_status_verified(0, 0, SuccessProcess),
    Success = exact_read_child(SuccessPath),
    true = suite_attested_child_valid(Success, Units,
        <<"http-exact-identity-success">>, RunnerSha, InventorySha),
    MutantSource = filename:join(Ebin, "http_exact_identity_mutant.erl"),
    OriginalCopyPath = BeamPath ++ ".original",
    ok = execution_beam_publish_new(OriginalCopyPath, Original, 4194304),
    HardlinkPath = filename:join(maps:get(root, Lease),
        "identity-hardlink.json"),
    try
        ok = file:delete(BeamPath),
        ok = file:make_link(OriginalCopyPath, BeamPath),
        HardlinkEval = execution_beam_bootstrap_evaluation(
            Lease, run_units_attested,
            [Units, HardlinkPath, <<"http-exact-identity-hardlink">>, 5,
             RunnerSha, BuildRoot, Inventory], RunnerSha, InventorySha, 126),
        {1, HardlinkProcess} = run_child_evaluation(Stage, [Runner, Ebin],
            HardlinkEval, 15000),
        true = process_status_verified(1, 1, HardlinkProcess)
    after
        ok = exact_remove_file(BeamPath),
        ok = file:write_file(BeamPath, Original, [binary, exclusive])
    end,
    HardlinkChild = exact_read_child(HardlinkPath),
    true = suite_attested_child_schema_valid(HardlinkChild, Units,
        <<"http-exact-identity-hardlink">>, RunnerSha, InventorySha),
    false = suite_attested_child_valid(HardlinkChild, Units,
        <<"http-exact-identity-hardlink">>, RunnerSha, InventorySha),
    false = maps:get(<<"loaded_beams_verified">>,
        maps:get(<<"execution_beam_identity">>, HardlinkChild)),
    ok = execution_beam_publish_new(MutantSource,
        <<"-module(http_exact_identity_fixture).\n"
          "-export([identity_test/0]).\n"
          "identity_test()->P=code:which(?MODULE),"
          "{ok,B}=file:read_file(P++\".original\"),"
          "ok=file:write_file(P,B),ok.\n">>, 1048576),
    {ok, Module, Mutant, []} = compile:file(
        MutantSource, [binary, return_errors, return_warnings]),
    true = crypto:hash(sha256, Original) =/= crypto:hash(sha256, Mutant),
    MutantPath = filename:join(maps:get(root, Lease), "identity-mutant.json"),
    try
        ok = file:write_file(BeamPath, Mutant),
        MutantEval = execution_beam_bootstrap_evaluation(
            Lease, run_units_attested,
            [Units, MutantPath, <<"http-exact-identity-mutant">>, 5,
             RunnerSha, BuildRoot, Inventory], RunnerSha, InventorySha, 126),
        {1, MutantProcess} = run_child_evaluation(Stage, [Runner, Ebin],
            MutantEval, 15000),
        true = process_status_verified(1, 1, MutantProcess),
        Original = execution_beam_read(BeamPath, 4194304)
    after ok = file:write_file(BeamPath, Original) end,
    MutantChild = exact_read_child(MutantPath),
    true = suite_attested_child_schema_valid(MutantChild, Units,
        <<"http-exact-identity-mutant">>, RunnerSha, InventorySha),
    false = suite_attested_child_valid(MutantChild, Units,
        <<"http-exact-identity-mutant">>, RunnerSha, InventorySha),
    false = maps:get(<<"loaded_beams_verified">>,
        maps:get(<<"execution_beam_identity">>, MutantChild)),
    RunnerPath = maps:get(beam_path, RunnerInfo),
    RunnerBinary = maps:get(binary, RunnerInfo),
    RunnerMutantPath = filename:join(maps:get(root, Lease),
        "runner-mutant.json"),
    try
        ok = file:write_file(RunnerPath, <<"not-a-beam">>),
        RunnerMutantEval = execution_beam_bootstrap_evaluation(
            Lease, run_units_attested,
            [Units, RunnerMutantPath, <<"http-exact-runner-mutant">>, 5,
             RunnerSha, BuildRoot, Inventory], RunnerSha, InventorySha, 126),
        {126, RunnerMutantProcess} = run_child_evaluation(Stage, [Runner, Ebin],
            RunnerMutantEval, 15000),
        true = process_status_verified(126, 126, RunnerMutantProcess)
    after ok = file:write_file(RunnerPath, RunnerBinary) end,
    false = filelib:is_regular(RunnerMutantPath),
    Restored = execution_beam_inventory([Ebin], BuildRoot,
        fun(Path) -> execution_beam_read(Path, 4194304) end),
    InventorySha = maps:get(sha256, Restored),
    ok = execution_beam_release_attempt(Lease),
    io:format("supervised_gleam execution_beam_identity=verified "
              "unique_lease=verified hardlink_swap=rejected "
              "inventory_swap_restore=rejected "
              "runner_hash_swap=rejected~n"),
    ok.

gleam_test_failure_projection_self_test() ->
    io:format("supervised_gleam self_test_stage=test_failure_projection~n"),
    Input = <<"packages/http3/test/http3_qlog_admission_tests.erl: "
              "stable_failed_owner_keeps_the_shared_slot_test failed\n"
              "18 tests, 2 failures\n"
              "Authorization: Bearer private-bearer-marker\n"
              "Cookie: private-cookie-marker\n"
              "-----BEGIN PRIVATE KEY-----\n"
              "pid=<0.123.0> ref=#Ref<0.1.2.3> socket=#Port<0.4>\n"
              "**error:{assertion_failed,private-assertion-marker}">>,
    Projection = gleam_test_failure_projection(Input),
    true = gleam_test_failure_projection_valid(Projection),
    [<<"stable_failed_owner_keeps_the_shared_slot_test">>] =
        maps:get(test_identifiers, Projection),
    [<<"http3_qlog_admission_tests.erl">>] =
        maps:get(module_identifiers, Projection),
    false = maps:get(test_identifiers_truncated, Projection),
    false = maps:get(module_identifiers_truncated, Projection),
    [<<"assertion">>, <<"failure">>] = maps:get(categories, Projection),
    [#{kind := <<"tests_failures">>, completed := 18, failed := 2}] =
        maps:get(summaries, Projection),
    <<"projected">> = maps:get(summary_state, Projection),
    18 = maps:get(completed_tests, Projection),
    2 = maps:get(observed_test_failures, Projection),
    ProjectionJson = iolist_to_binary(json:encode(Projection)),
    lists:foreach(fun(Marker) ->
        nomatch = binary:match(ProjectionJson, Marker)
    end, [<<"private-bearer-marker">>, <<"private-cookie-marker">>,
          <<"BEGIN PRIVATE KEY">>, <<"<0.123.0>">>, <<"#Ref<">>,
          <<"#Port<">>, <<"private-assertion-marker">>]),
    Plural = gleam_test_failure_projection(
        <<"900 passed, 96 failures\n">>),
    true = gleam_test_failure_projection_valid(Plural),
    <<"projected">> = maps:get(summary_state, Plural),
    996 = maps:get(completed_tests, Plural),
    96 = maps:get(observed_test_failures, Plural),
    [#{kind := <<"passed_failed">>, completed := 996, failed := 96}] =
        maps:get(summaries, Plural),
    Equivalent = gleam_test_failure_projection(
        <<"18 tests, 2 failures\n16 passed, 2 failures\n">>),
    <<"projected">> = maps:get(summary_state, Equivalent),
    18 = maps:get(completed_tests, Equivalent),
    2 = maps:get(observed_test_failures, Equivalent),
    Conflicting = gleam_test_failure_projection(
        <<"18 tests, 2 failures\n15 passed, 2 failures\n">>),
    true = gleam_test_failure_projection_valid(Conflicting),
    <<"ambiguous">> = maps:get(summary_state, Conflicting),
    0 = maps:get(completed_tests, Conflicting),
    0 = maps:get(observed_test_failures, Conflicting),
    Spoof = gleam_test_failure_projection(
        <<"18 tests reported that 2 tests failed\n">>),
    true = gleam_test_failure_projection_valid(Spoof),
    <<"unavailable">> = maps:get(summary_state, Spoof),
    [] = maps:get(summaries, Spoof),
    Sampled = gleam_test_failure_projection(iolist_to_binary([
        binary:copy(<<"x">>, 2097153), <<"\n900 passed, 96 failures\n">>
    ])),
    true = gleam_test_failure_projection_valid(Sampled),
    <<"sampled">> = maps:get(parser_status, Sampled),
    <<"ambiguous">> = maps:get(summary_state, Sampled),
    0 = maps:get(completed_tests, Sampled),
    0 = maps:get(observed_test_failures, Sampled),
    ProjectionNonce = binary:copy(<<"1">>, 32),
    ProjectionSourceSha = binary:copy(<<"2">>, 64),
    ProjectionRunnerSha = binary:copy(<<"3">>, 64),
    ProjectionMode = "--http-test",
    Envelope = gleam_test_failure_projection_envelope(
        Plural, ProjectionNonce, ProjectionSourceSha,
        ProjectionRunnerSha, ProjectionMode),
    Plural = gleam_outer_test_failure_projection(
        <<"compiler-safe-prefix\n", Envelope/binary, "\r\n">>,
        ProjectionNonce, ProjectionSourceSha, ProjectionRunnerSha,
        ProjectionMode),
    invalid_failure_projection = gleam_outer_test_failure_projection(
        <<Envelope/binary, "\n", Envelope/binary, "\n">>,
        ProjectionNonce, ProjectionSourceSha, ProjectionRunnerSha,
        ProjectionMode),
    invalid_failure_projection = gleam_outer_test_failure_projection(
        <<"supervised_gleam_failure_projection_v2 payload=not+base64!\n">>,
        ProjectionNonce, ProjectionSourceSha, ProjectionRunnerSha,
        ProjectionMode),
    invalid_failure_projection = gleam_outer_test_failure_projection(
        <<Envelope/binary, "\n">>, binary:copy(<<"4">>, 32),
        ProjectionSourceSha, ProjectionRunnerSha, ProjectionMode),
    invalid_failure_projection = gleam_outer_test_failure_projection(
        <<Envelope/binary, "\n">>, ProjectionNonce,
        binary:copy(<<"5">>, 64), ProjectionRunnerSha, ProjectionMode),
    invalid_failure_projection = gleam_outer_test_failure_projection(
        <<Envelope/binary, "\n">>, ProjectionNonce, ProjectionSourceSha,
        binary:copy(<<"6">>, 64), ProjectionMode),
    invalid_failure_projection = gleam_outer_test_failure_projection(
        <<Envelope/binary, "\n">>, ProjectionNonce, ProjectionSourceSha,
        ProjectionRunnerSha, "--quic-test"),
    Many = iolist_to_binary([
        io_lib:format("candidate_~2..0B_projection_test failed~n", [Index])
        || Index <- lists:seq(1, 65)
    ]),
    Bounded = gleam_test_failure_projection(Many),
    true = gleam_test_failure_projection_valid(Bounded),
    64 = length(maps:get(test_identifiers, Bounded)),
    true = maps:get(test_identifiers_truncated, Bounded),
    false = gleam_test_failure_projection_valid(
        Projection#{categories => [<<"private_category">>]}),
    false = gleam_test_failure_projection_valid(
        Projection#{test_identifiers => [<<"unsafe/path_test">>]}),
    false = gleam_test_failure_projection_valid(
        Projection#{completed_tests => 17}),
    false = gleam_test_failure_projection_valid(
        Projection#{summary_state => <<"unavailable">>}),
    ok.

command_terminal_projection_self_test() ->
    io:format("supervised_gleam self_test_stage=terminal_semantic_output~n"),
    Marker = <<"private-cookie-marker">>,
    Decorated = iolist_to_binary([
        27, "[?9001h", 27, "[?1004h", 27, "[?25l", 27, "[2J",
        27, "[m", 27, "[H", "gleam 1.18.1\r\n", 27, "]0;", Marker,
        7, 27, "[?25h", 27, "[?9001l", 27, "[?1004l"
    ]),
    {<<"gleam 1.18.1\r\n">>, Removed} = command_semantic_output(Decorated),
    true = Removed =:= byte_size(Decorated) - byte_size(<<"gleam 1.18.1\r\n">>),
    {<<"plain\r\n">>, 0} = command_semantic_output(<<"plain\r\n">>),
    {<<"prefix">>, IncompleteRemoved} = command_semantic_output(
        iolist_to_binary(["prefix", 27, "]0;", Marker])),
    true = IncompleteRemoved > byte_size(Marker),
    nomatch = binary:match(element(1, command_semantic_output(Decorated)), Marker),
    ok.

gleam_diagnostic_projection_self_test() ->
    io:format("supervised_gleam self_test_stage=diagnostic_safe~n"),
    Marker = <<"private-cookie-marker">>,
    SafeInput = <<"error: Type mismatch\n  src/http/client.gleam:12:3\n  ",
                  Marker/binary, "\n">>,
    Safe = gleam_diagnostic_projection(SafeInput),
    true = gleam_diagnostic_projection_valid(Safe),
    1 = maps:get(diagnostic_count, Safe),
    [SafeRow] = maps:get(diagnostics, Safe),
    <<"src/http/client.gleam">> = maps:get(path, SafeRow),
    <<"type_mismatch">> = maps:get(category, SafeRow),
    nomatch = binary:match(iolist_to_binary(json:encode(Safe)), Marker),
    io:format("supervised_gleam self_test_stage=diagnostic_unknown~n"),
    Unknown = gleam_diagnostic_projection(
        <<"error: private-cookie-marker\n  test/client_test.gleam:4:2\n">>),
    [UnknownRow] = maps:get(diagnostics, Unknown),
    <<"Compiler error">> = maps:get(title, UnknownRow),
    nomatch = binary:match(iolist_to_binary(json:encode(Unknown)), Marker),
    Warning = gleam_diagnostic_projection(
        <<"warning: Unused value\n  src/http/body.gleam:373:7\n">>),
    true = gleam_diagnostic_projection_valid(Warning),
    [WarningRow] = maps:get(diagnostics, Warning),
    <<"Unused value">> = maps:get(title, WarningRow),
    <<"unused_value_warning">> = maps:get(category, WarningRow),
    Surrounded = gleam_diagnostic_projection(
        <<"error: Type mismatch\ncompiler-prefix [test/client_test.gleam:9:4] ",
          Marker/binary, "\n">>),
    true = gleam_diagnostic_projection_valid(Surrounded),
    [SurroundedRow] = maps:get(diagnostics, Surrounded),
    <<"test/client_test.gleam">> = maps:get(path, SurroundedRow),
    9 = maps:get(line, SurroundedRow),
    4 = maps:get(column, SurroundedRow),
    nomatch = binary:match(iolist_to_binary(json:encode(Surrounded)), Marker),
    PackageFailure = gleam_diagnostic_projection(filename:absname("."),
        ["gleam.toml"],
        <<"error: Shell program failed\nprivate-cookie-marker\n">>),
    true = gleam_diagnostic_projection_valid(PackageFailure),
    [PackageRow] = maps:get(diagnostics, PackageFailure),
    <<"gleam.toml">> = maps:get(path, PackageRow),
    true = maps:get(location_synthetic, PackageRow),
    <<"erlang_compiler_error">> = maps:get(category, PackageRow),
    nomatch = binary:match(iolist_to_binary(json:encode(PackageFailure)), Marker),
    GeneratedFailure = gleam_diagnostic_projection(filename:absname("."),
        ["gleam.toml", "packages/quic_core/test/qlog_budget_tests.erl"],
        <<"c:/private/build/dev/erlang/quic_core/_gleam_artefacts/"
          "qlog_budget_tests.erl:1132:20: illegal guard expression\n"
          "error: Shell command failure\n", Marker/binary, "\n">>),
    true = gleam_diagnostic_projection_valid(GeneratedFailure),
    [GeneratedRow] = maps:get(diagnostics, GeneratedFailure),
    <<"packages/quic_core/test/qlog_budget_tests.erl">> =
        maps:get(path, GeneratedRow),
    1132 = maps:get(line, GeneratedRow),
    20 = maps:get(column, GeneratedRow),
    <<"erlang_compiler_error">> = maps:get(category, GeneratedRow),
    nomatch = binary:match(
        iolist_to_binary(json:encode(GeneratedFailure)), Marker),
    AmbiguousGenerated = gleam_diagnostic_projection(filename:absname("."),
        ["gleam.toml", "test/duplicate.erl",
         "packages/http3/test/duplicate.erl"],
        <<"c:/private/build/dev/erlang/http/_gleam_artefacts/"
          "duplicate.erl:4:2: private-cookie-marker\n"
          "error: Shell command failure\n">>),
    true = gleam_diagnostic_projection_valid(AmbiguousGenerated),
    [AmbiguousRow] = maps:get(diagnostics, AmbiguousGenerated),
    <<"gleam.toml">> = maps:get(path, AmbiguousRow),
    true = maps:get(location_synthetic, AmbiguousRow),
    UntrustedNoLocation = gleam_diagnostic_projection(filename:absname("."),
        ["gleam.toml"], <<"error: private-cookie-marker\n">>),
    [] = maps:get(diagnostics, UntrustedNoLocation),
    unparsed = maps:get(parser_status, UntrustedNoLocation),
    io:format("supervised_gleam self_test_stage=diagnostic_paths~n"),
    Absolute = gleam_diagnostic_projection(
        <<"error: Type mismatch\n  C:/private/src/http/client.gleam:2:1\n">>),
    [] = maps:get(diagnostics, Absolute),
    Traversal = gleam_diagnostic_projection(
        <<"error: Type mismatch\n  src/../private.gleam:2:1\n">>),
    [] = maps:get(diagnostics, Traversal),
    Otp = gleam_diagnostic_projection(
        <<"=ERROR REPORT====\n<0.99.0> private-cookie-marker\n">>),
    [] = maps:get(diagnostics, Otp),
    io:format("supervised_gleam self_test_stage=diagnostic_bounds~n"),
    Many = gleam_diagnostic_projection(binary:copy(SafeInput, 65)),
    65 = maps:get(diagnostic_count, Many),
    64 = length(maps:get(diagnostics, Many)),
    1 = maps:get(diagnostics_dropped, Many),
    false = gleam_diagnostic_projection_valid(
        Safe#{body => <<"private-cookie-marker">>}),
    false = gleam_diagnostic_projection_valid(Safe#{diagnostics => [
        SafeRow#{category => <<"syntax_error">>}]}),
    false = gleam_diagnostic_projection_valid(Safe#{diagnostics => [
        SafeRow#{location_synthetic => true}]}),
    io:format("supervised_gleam self_test_stage=diagnostic_complete~n"),
    ok.

exact_digest_self_test() ->
    Root = filename:absname(filename:join("build/supervised-gleam",
        "self-test-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    Stage = filename:join(Root, "stage"),
    Source = filename:join(Root, "source"),
    A = filename:join(Source, "a.txt"),
    B = filename:join(Source, "b.txt"),
    StageA = filename:join(Stage, "source/a.txt"),
    ok = filelib:ensure_dir(A), ok = file:write_file(A, <<"safe">>, [exclusive]),
    ok = exact_copy_file(A, StageA),
    Paths = ["source/a.txt"],
    Digest = root_relative_digest(Root, Paths),
    Digest = stage_relative_digest(Stage, Paths),
    ok = file:write_file(StageA, <<"mutated">>),
    false = Digest =:= stage_relative_digest(Stage, Paths),
    ok = file:write_file(StageA, <<"safe">>),
    ok = file:write_file(B, <<"added">>, [exclusive]),
    false = Digest =:= root_relative_digest(Root,
                                            ["source/a.txt", "source/b.txt"]),
    _ = exact_remove_tree(Root, 0),
    ok.

exact_failure_projection_self_test() ->
    Units = [#{module => <<"safe_module">>, function => <<"safe_test">>,
               kind => <<"test">>}],
    Child = #{<<"failures">> => [#{<<"unit">> => 1,
        <<"classification">> => <<"assertion_failed">>, <<"stack">> => []}]},
    [Row] = exact_failure_rows(Child, Units),
    true = maps:get(module, Row) =:= <<"safe_module">>,
    true = maps:get(function, Row) =:= <<"safe_test">>,
    true = maps:get(classification, Row) =:= <<"assertion_failed">>,
    false = maps:is_key(reason, Row),
    ok.

exact_require_successful_build(_Root, _Stage, _SourcePaths, _SourceDigest,
                               _SourceCount, _DependencyDigest, _Toolchain,
                               _CompileDriver, _Selection, _Nonce,
                               {ok, _Output, Proof}) ->
    case command_success_verified(Proof) of
        true -> ok;
        false -> erlang:error(unreachable_unverified_command_success)
    end;
exact_require_successful_build(Root, Stage, SourcePaths, SourceDigest,
                               SourceCount, DependencyDigest, Toolchain,
                               CompileDriver, Selection, Nonce,
                               {error, Diagnostics, Proof})
  when is_map(Diagnostics) ->
    true = gleam_diagnostic_projection_valid(Diagnostics),
    exact_publish_build_failure(
        Root, Stage, SourcePaths, SourceDigest, SourceCount, DependencyDigest,
        Toolchain, CompileDriver, Selection, Nonce, Proof,
        <<"compiler_rejected">>, Diagnostics);
exact_require_successful_build(Root, Stage, SourcePaths, SourceDigest,
                               SourceCount, DependencyDigest, Toolchain,
                               CompileDriver, Selection, Nonce,
                               {error, Proof})
  when is_map(Proof) ->
    exact_publish_build_failure(
        Root, Stage, SourcePaths, SourceDigest, SourceCount, DependencyDigest,
        Toolchain, CompileDriver, Selection, Nonce, Proof,
        exact_build_process_failure_classification(Proof),
        gleam_empty_diagnostic_projection());
exact_require_successful_build(Root, Stage, SourcePaths, SourceDigest,
                               SourceCount, DependencyDigest, Toolchain,
                               CompileDriver, Selection, Nonce,
                               {error, ProjectionFailure, Proof})
  when is_map(Proof) ->
    Classification = case ProjectionFailure of
        no_failure_projection ->
            exact_build_process_failure_classification(Proof);
        invalid_failure_projection -> <<"diagnostic_projection_invalid">>;
        _ -> <<"diagnostic_projection_rejected">>
    end,
    exact_publish_build_failure(
        Root, Stage, SourcePaths, SourceDigest, SourceCount, DependencyDigest,
        Toolchain, CompileDriver, Selection, Nonce, Proof, Classification,
        gleam_empty_diagnostic_projection()).

exact_build_process_failure_classification(Proof) ->
    case maps:get(outcome, Proof, invalid) of
        ok -> <<"compile_success_attestation_rejected">>;
        deadline -> <<"compile_deadline">>;
        output_limit -> <<"compile_output_limit">>;
        protocol_failure -> <<"compile_supervisor_protocol_failure">>;
        exit_failure -> <<"compiler_rejected">>;
        _ -> <<"compile_process_failure">>
    end.

exact_publish_build_failure(Root, Stage, SourcePaths, SourceDigest,
                            SourceCount, DependencyDigest, Toolchain,
                            CompileDriver, Selection, Nonce, Proof,
                            Classification0, Diagnostics) ->
    SourceStable = exact_http_stage_inputs_stable(
        Root, Stage, SourcePaths, SourceDigest),
    Classification = case SourceStable of
        true -> Classification0;
        false -> <<"source_changed_during_build">>
    end,
    Report = exact_build_failure_report(
        SourceDigest, SourceCount, DependencyDigest, Toolchain, CompileDriver,
        Selection, Proof, Classification, SourceStable, Diagnostics),
    true = exact_build_failure_report_valid(Report),
    ok = exact_release_attempt_active(),
    ReportPath = exact_publish_report(Root, SourceDigest, Nonce, Report),
    io:format(standard_error,
              "supervised_gleam mode=~s phase=test_beam_build completed=0 "
              "failures=1 classification=~s report=~s diagnostics=~p "
              "exact_outcome=failed~n",
              [http_exact_mode(Selection), Classification, ReportPath,
               Diagnostics]),
    erlang:error(http_exact_test_beam_build_failed).

exact_build_failure_report(SourceDigest, SourceCount, DependencyDigest,
                           Toolchain, CompileDriver, Selection, Proof,
                           Classification, SourceStable, Diagnostics) ->
    #{schema => 2, shareable => true, status => <<"Failed">>,
        prebuild_profile_state => <<"absent">>,
        source_sha256 => SourceDigest, source_files => SourceCount,
        dependency_cache_sha256 => DependencyDigest,
        toolchain => Toolchain,
        compile_driver => safe_http_compile_driver(CompileDriver),
        selection => atom_to_binary(Selection),
        unit_timeout_seconds => http_exact_unit_timeout(Selection),
        configured_modules => null, configured_units => null,
        suite_inventory_sha256 => null,
        suite_inventory_state => <<"unavailable">>,
        counts_state => <<"unavailable">>, completed_tests => null,
        skipped_tests => null, skipped_tests_state => <<"unavailable">>,
        failure_count => 1, failures => [],
        child_exit_status => exact_child_exit_status(Proof),
        process => exact_safe_process(Proof),
        rerun_command => list_to_binary(
            "escript scripts/supervised_gleam.escript " ++
            http_exact_mode(Selection)),
        failure_phase => <<"test_beam_build">>,
        failure_classification => Classification,
        source_stable => SourceStable,
        build_diagnostics => Diagnostics}.

exact_child_exit_status(Proof) ->
    case maps:get(exit_status, Proof, -1) of
        Status when is_integer(Status), Status >= 0, Status =< 255 -> Status;
        _ -> -1
    end.

exact_http_stage_inputs_stable(Root, Stage, SourcePaths, SourceDigest) ->
    try verify_http_stage_inputs(Root, Stage, SourcePaths, SourceDigest) of
        ok -> true
    catch _:_ -> false end.

exact_build_failure_report_valid(Report) ->
    try
        true = lists:sort(maps:keys(Report)) =:= lists:sort([
            schema, shareable, status, prebuild_profile_state,
            source_sha256, source_files,
            dependency_cache_sha256, toolchain, compile_driver, selection,
            unit_timeout_seconds, configured_modules, configured_units,
            suite_inventory_sha256, suite_inventory_state, counts_state,
            completed_tests, skipped_tests, skipped_tests_state,
            failure_count, failures, child_exit_status,
            process, rerun_command, failure_phase, failure_classification,
            source_stable, build_diagnostics]),
        2 = maps:get(schema, Report),
        true = maps:get(shareable, Report),
        <<"Failed">> = maps:get(status, Report),
        <<"absent">> = maps:get(prebuild_profile_state, Report),
        true = exact_sha256_valid(maps:get(source_sha256, Report)),
        true = exact_sha256_valid(maps:get(dependency_cache_sha256, Report)),
        SourceFiles = maps:get(source_files, Report),
        true = is_integer(SourceFiles) andalso SourceFiles > 0
            andalso SourceFiles =< 20000,
        true = supervised_toolchain_valid(maps:get(toolchain, Report)),
        Driver = maps:get(compile_driver, Report),
        true = lists:sort(maps:keys(Driver)) =:= lists:sort([
            relative_path, original_sha256, driver_sha256,
            replacement_count]),
        <<"test/http_test.gleam">> = maps:get(relative_path, Driver),
        true = exact_sha256_valid(maps:get(original_sha256, Driver)),
        true = exact_sha256_valid(maps:get(driver_sha256, Driver)),
        1 = maps:get(replacement_count, Driver),
        true = lists:member(maps:get(selection, Report),
            [<<"all">>, <<"http3_server_lifecycle">>, <<"ohttp">>]),
        UnitTimeout = maps:get(unit_timeout_seconds, Report),
        true = is_integer(UnitTimeout) andalso UnitTimeout >= 5
            andalso UnitTimeout =< 3600,
        null = maps:get(configured_modules, Report),
        null = maps:get(configured_units, Report),
        null = maps:get(suite_inventory_sha256, Report),
        <<"unavailable">> = maps:get(suite_inventory_state, Report),
        <<"unavailable">> = maps:get(counts_state, Report),
        null = maps:get(completed_tests, Report),
        null = maps:get(skipped_tests, Report),
        <<"unavailable">> = maps:get(skipped_tests_state, Report),
        1 = maps:get(failure_count, Report),
        [] = maps:get(failures, Report),
        ChildStatus = maps:get(child_exit_status, Report),
        true = is_integer(ChildStatus) andalso ChildStatus >= -1
            andalso ChildStatus =< 255,
        Process = maps:get(process, Report),
        true = exact_public_process_valid(Process),
        <<"test_beam_build">> = maps:get(failure_phase, Report),
        true = lists:member(maps:get(failure_classification, Report), [
            <<"compiler_rejected">>, <<"compile_deadline">>,
            <<"compile_output_limit">>,
            <<"compile_supervisor_protocol_failure">>,
            <<"compile_process_failure">>,
            <<"compile_success_attestation_rejected">>,
            <<"diagnostic_projection_missing">>,
            <<"diagnostic_projection_invalid">>,
            <<"diagnostic_projection_rejected">>,
            <<"source_changed_during_build">>]),
        true = is_boolean(maps:get(source_stable, Report)),
        true = gleam_diagnostic_projection_valid(
            maps:get(build_diagnostics, Report)),
        Rerun = maps:get(rerun_command, Report),
        true = is_binary(Rerun) andalso byte_size(Rerun) =< 256,
        true
    catch _:_ -> false end.

exact_unit_report_valid(Report) ->
    try
        true = lists:sort(maps:keys(Report)) =:= lists:sort([
            schema, shareable, status, run_nonce, child,
            prebuild_profile_state,
            source_sha256, source_files,
            dependency_cache_sha256, toolchain, compile_driver,
            artifact_sha256, artifact_files, selection,
            unit_timeout_seconds, configured_modules, configured_units,
            suite_inventory_sha256, suite_inventory_state, counts_state,
            completed_tests, skipped_tests, skipped_tests_state,
            failure_count, failures, child_exit_status,
            process, rerun_command, runner_sha256,
            execution_beam_inventory_sha256,
            loaded_beam_sha256, loaded_beam_count]),
        3 = maps:get(schema, Report),
        true = maps:get(shareable, Report),
        <<"absent">> = maps:get(prebuild_profile_state, Report),
        Status = maps:get(status, Report),
        true = lists:member(Status, [<<"Ready">>, <<"Failed">>]),
        Nonce = maps:get(run_nonce, Report),
        true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32,
        match = re:run(Nonce, <<"^[0-9a-f]{32}$">>, [{capture, none}]),
        true = exact_sha256_valid(maps:get(source_sha256, Report)),
        true = exact_sha256_valid(maps:get(dependency_cache_sha256, Report)),
        true = exact_sha256_valid(maps:get(artifact_sha256, Report)),
        true = exact_sha256_valid(maps:get(runner_sha256, Report)),
        true = exact_sha256_valid(maps:get(
            execution_beam_inventory_sha256, Report)),
        true = exact_sha256_valid(maps:get(loaded_beam_sha256, Report)),
        true = exact_positive_count(maps:get(loaded_beam_count, Report), 20000),
        true = exact_positive_count(maps:get(source_files, Report), 20000),
        true = exact_positive_count(maps:get(artifact_files, Report), 20000),
        true = supervised_toolchain_valid(maps:get(toolchain, Report)),
        true = exact_compile_driver_valid(maps:get(compile_driver, Report)),
        Selection = maps:get(selection, Report),
        true = lists:member(Selection,
            [<<"all">>, <<"http3_server_lifecycle">>, <<"ohttp">>]),
        true = exact_positive_count(maps:get(unit_timeout_seconds, Report), 3600),
        true = exact_positive_count(maps:get(configured_modules, Report), 10000),
        Configured = maps:get(configured_units, Report),
        true = exact_positive_count(Configured, 10000),
        Child = maps:get(child, Report),
        Units = exact_units_from_child(Child),
        Configured = length(Units),
        true = maps:get(configured_modules, Report) =:= length(lists:usort(
            [maps:get(module, Unit) || Unit <- Units])),
        true = exact_sha256_valid(maps:get(
            suite_inventory_sha256, Report)),
        <<"verified">> = maps:get(suite_inventory_state, Report),
        <<"verified">> = maps:get(counts_state, Report),
        Completed = maps:get(completed_tests, Report),
        true = exact_nonnegative_count(Completed, 999999999),
        Skipped = maps:get(skipped_tests, Report),
        true = exact_nonnegative_count(Skipped, 999999999),
        <<"verified">> = maps:get(skipped_tests_state, Report),
        FailureCount = maps:get(failure_count, Report),
        true = exact_nonnegative_count(FailureCount, 999999999),
        Failures = maps:get(failures, Report),
        true = exact_failure_rows_valid(Failures, Configured),
        true = FailureCount >= length(Failures),
        RunnerSha = maps:get(runner_sha256, Report),
        BeamInventorySha = maps:get(execution_beam_inventory_sha256, Report),
        true = suite_attested_child_schema_valid(
            Child, Units, Nonce, RunnerSha, BeamInventorySha),
        ChildCounts = suite_attested_test_counts(
            Child, Units, Nonce, RunnerSha, BeamInventorySha),
        <<"verified">> = maps:get(state, ChildCounts),
        Completed = maps:get(completed, ChildCounts),
        Skipped = maps:get(skipped, ChildCounts),
        FailureCount = maps:get(<<"failure_count">>, Child),
        Failures = exact_failure_rows(Child, Units),
        ChildBeamIdentity = maps:get(<<"execution_beam_identity">>, Child),
        true = maps:get(loaded_beam_sha256, Report) =:=
            maps:get(<<"loaded_beam_sha256">>, ChildBeamIdentity),
        true = maps:get(loaded_beam_count, Report) =:=
            maps:get(<<"loaded_beam_count">>, ChildBeamIdentity),
        ChildStatus = maps:get(child_exit_status, Report),
        true = is_integer(ChildStatus) andalso ChildStatus >= 0
            andalso ChildStatus =< 1,
        Process = maps:get(process, Report),
        true = exact_unit_process_valid(Process),
        ChildStatus = maps:get(process_supervisor_reported_status, Process),
        Rerun = maps:get(rerun_command, Report),
        true = is_binary(Rerun) andalso byte_size(Rerun) =< 256,
        case Status of
            <<"Ready">> ->
                0 = ChildStatus,
                0 = FailureCount,
                0 = Skipped,
                [] = Failures,
                true = Completed >= Configured,
                true = suite_attested_child_valid(
                    Child, Units, Nonce, RunnerSha, BeamInventorySha);
            <<"Failed">> ->
                false = suite_attested_child_valid(
                    Child, Units, Nonce, RunnerSha, BeamInventorySha)
        end,
        true
    catch _:_ -> false end.

exact_post_build_failure_report_valid(Report) ->
    try
        true = lists:sort(maps:keys(Report)) =:= lists:sort([
            schema, report_kind, shareable, status,
            prebuild_profile_state, source_sha256,
            source_files, dependency_cache_sha256, toolchain,
            compile_driver, artifact_sha256, artifact_files,
            artifact_state, runner_sha256, execution_beam_inventory_sha256,
            loaded_beam_sha256, loaded_beam_count, suite_inventory_sha256,
            suite_inventory_state, selection, unit_timeout_seconds,
            configured_modules, configured_units, counts_state,
            completed_tests, skipped_tests, skipped_tests_state,
            observed_test_failures, failures, child_exit_status, process,
            rerun_command, failure_phase, failure_classification,
            source_stable]),
        3 = maps:get(schema, Report),
        <<"http_exact_attempt">> = maps:get(report_kind, Report),
        true = maps:get(shareable, Report),
        <<"Failed">> = maps:get(status, Report),
        <<"absent">> = maps:get(prebuild_profile_state, Report),
        true = exact_sha256_valid(maps:get(source_sha256, Report)),
        true = exact_sha256_valid(maps:get(dependency_cache_sha256, Report)),
        true = exact_positive_count(maps:get(source_files, Report), 20000),
        true = supervised_toolchain_valid(maps:get(toolchain, Report)),
        true = exact_compile_driver_valid(maps:get(compile_driver, Report)),
        Selection = maps:get(selection, Report),
        true = lists:member(Selection,
            [<<"all">>, <<"http3_server_lifecycle">>, <<"ohttp">>]),
        true = exact_positive_count(maps:get(unit_timeout_seconds, Report), 3600),
        ConfiguredModules = maps:get(configured_modules, Report),
        ConfiguredUnits = maps:get(configured_units, Report),
        InventoryState = maps:get(suite_inventory_state, Report),
        InventorySha = maps:get(suite_inventory_sha256, Report),
        true = case InventoryState of
            <<"unavailable">> ->
                InventorySha =:= null andalso ConfiguredModules =:= null
                    andalso ConfiguredUnits =:= null;
            <<"verified">> ->
                exact_sha256_valid(InventorySha)
                    andalso exact_positive_count(ConfiguredModules, 10000)
                    andalso (ConfiguredUnits =:= null orelse
                        exact_positive_count(ConfiguredUnits, 10000));
            _ -> false
        end,
        CountsState = maps:get(counts_state, Report),
        Completed = maps:get(completed_tests, Report),
        Skipped = maps:get(skipped_tests, Report),
        SkippedState = maps:get(skipped_tests_state, Report),
        ObservedFailures = maps:get(observed_test_failures, Report),
        Failures = maps:get(failures, Report),
        true = case CountsState of
            <<"unavailable">> ->
                Completed =:= null andalso Skipped =:= null
                    andalso SkippedState =:= <<"unavailable">>
                    andalso ObservedFailures =:= null
                    andalso Failures =:= [];
            <<"verified">> ->
                ConfiguredUnits =/= null
                    andalso exact_nonnegative_count(Completed, 999999999)
                    andalso exact_nonnegative_count(Skipped, 999999999)
                    andalso SkippedState =:= <<"verified">>
                    andalso exact_nonnegative_count(
                        ObservedFailures, 999999999)
                    andalso exact_failure_rows_valid(
                        Failures, ConfiguredUnits);
            _ -> false
        end,
        ChildStatus = maps:get(child_exit_status, Report),
        true = is_integer(ChildStatus) andalso ChildStatus >= -1
            andalso ChildStatus =< 255,
        true = exact_public_process_valid(maps:get(process, Report)),
        ArtifactDigest = maps:get(artifact_sha256, Report),
        ArtifactFiles = maps:get(artifact_files, Report),
        ArtifactState = maps:get(artifact_state, Report),
        true = exact_nonnegative_count(ArtifactFiles, 20000),
        true = lists:member(ArtifactState,
            [<<"verified">>, <<"changed">>, <<"unavailable">>]),
        true = (ArtifactDigest =:= null andalso ArtifactFiles =:= 0
                andalso ArtifactState =:= <<"unavailable">>) orelse
            (exact_sha256_valid(ArtifactDigest) andalso ArtifactFiles > 0),
        RunnerDigest = maps:get(runner_sha256, Report),
        true = RunnerDigest =:= null orelse exact_sha256_valid(RunnerDigest),
        BeamInventoryDigest = maps:get(execution_beam_inventory_sha256, Report),
        LoadedBeamDigest = maps:get(loaded_beam_sha256, Report),
        LoadedBeamCount = maps:get(loaded_beam_count, Report),
        true = BeamInventoryDigest =:= null orelse
            exact_sha256_valid(BeamInventoryDigest),
        true = LoadedBeamDigest =:= null orelse
            exact_sha256_valid(LoadedBeamDigest),
        true = (LoadedBeamDigest =:= null andalso LoadedBeamCount =:= null) orelse
            (exact_sha256_valid(LoadedBeamDigest) andalso
             exact_nonnegative_count(LoadedBeamCount, 20000)),
        Phase = maps:get(failure_phase, Report),
        Classification = maps:get(failure_classification, Report),
        true = exact_post_build_failure_pair_valid(Phase, Classification),
        true = exact_post_build_evidence_state_valid(Report),
        true = is_boolean(maps:get(source_stable, Report)),
        Rerun = maps:get(rerun_command, Report),
        true = is_binary(Rerun) andalso byte_size(Rerun) =< 256,
        true
    catch _:_ -> false end.

exact_units_from_child(Child) when is_map(Child) ->
    Rows = maps:get(<<"units">>, Child),
    true = is_list(Rows),
    true = Rows =/= [] andalso length(Rows) =< 10000,
    [#{module => maps:get(<<"module">>, Row),
       function => maps:get(<<"function">>, Row),
       kind => maps:get(<<"kind">>, Row)}
     || Row <- Rows];
exact_units_from_child(_) ->
    erlang:error(invalid_child_units).

exact_post_build_failure_pair_valid(Phase, Classification) ->
    lists:member({Phase, Classification}, [
        {<<"source_verification">>, <<"source_verification_failed">>},
        {<<"module_inventory">>, <<"module_inventory_rejected">>},
        {<<"unit_inventory">>, <<"unit_inventory_rejected">>},
        {<<"artifact_inventory">>, <<"artifact_inventory_rejected">>},
        {<<"runner_compilation">>, <<"runner_compilation_failed">>},
        {<<"exact_unit_execution">>, <<"unit_process_failed">>},
        {<<"unit_process_verification">>,
         <<"unit_process_attestation_rejected">>},
        {<<"child_evidence">>, <<"child_evidence_rejected">>},
        {<<"post_execution_source_verification">>,
         <<"source_changed_during_units">>},
        {<<"artifact_verification">>, <<"artifact_changed_during_units">>},
        {<<"attempt_cleanup">>, <<"attempt_cleanup_failed">>},
        {<<"report_publication">>, <<"unit_report_rejected">>},
        {<<"post_build_start">>, <<"post_build_invariant_rejected">>},
        {<<"source_verified">>, <<"post_build_invariant_rejected">>}])
    orelse (Phase =:= <<"module_inventory">>
        andalso exact_suite_inventory_classification(Classification))
    orelse (Phase =:= <<"artifact_verification">>
        andalso Classification =:= <<"stale_suite_inventory">>).

exact_suite_inventory_classification(Classification) ->
    lists:member(Classification,
        [atom_to_binary(Reason) || Reason <- [
            no_test_sources, source_limit_exceeded, duplicate_source_module,
            unsupported_source_extension, erlang_declared_module_mismatch,
            erlang_module_declaration_missing,
            erlang_module_declaration_ambiguous, unsafe_module_name,
            source_outside_test_root, unsafe_source_path,
            source_tree_depth_limit, source_tree_entry_limit,
            source_tree_read_failed, source_tree_link_rejected,
            source_tree_special_file_rejected,
            source_tree_changed_while_reading,
            source_tree_inspection_failed, source_tree_missing,
            source_size_rejected, source_changed_while_reading,
            source_read_failed, source_link_rejected,
            source_hardlink_rejected,
            source_special_file_rejected, source_missing,
            source_inspection_failed, beam_size_rejected,
            beam_changed_while_reading, beam_read_failed,
            beam_link_rejected, beam_hardlink_rejected,
            beam_special_file_rejected, beam_missing,
            beam_inspection_failed, malformed_beam,
            unreadable_beam_metadata, unsafe_beam_module,
            beam_module_mismatch, beam_export_limit_exceeded,
            unsafe_eunit_export,
            unit_limit_exceeded, internally_invalid_inventory]]).

exact_post_build_evidence_state_valid(Report) ->
    Phase = maps:get(failure_phase, Report),
    Inventory = maps:get(suite_inventory_state, Report),
    Counts = maps:get(counts_state, Report),
    ConfiguredUnits = maps:get(configured_units, Report),
    RunnerBound = exact_sha256_valid(maps:get(runner_sha256, Report))
        andalso exact_sha256_valid(maps:get(
            execution_beam_inventory_sha256, Report)),
    LoadedCount = maps:get(loaded_beam_count, Report),
    LoadedBound = exact_sha256_valid(maps:get(loaded_beam_sha256, Report))
        andalso exact_nonnegative_count(LoadedCount, 20000),
    case Phase of
        <<"post_build_start">> ->
            Inventory =:= <<"unavailable">>
                andalso Counts =:= <<"unavailable">>;
        <<"source_verified">> ->
            Inventory =:= <<"unavailable">>
                andalso Counts =:= <<"unavailable">>;
        <<"source_verification">> ->
            Inventory =:= <<"unavailable">>
                andalso Counts =:= <<"unavailable">>;
        <<"module_inventory">> ->
            Inventory =:= <<"unavailable">>
                andalso Counts =:= <<"unavailable">>;
        <<"unit_inventory">> ->
            Inventory =:= <<"verified">> andalso ConfiguredUnits =:= null
                andalso Counts =:= <<"unavailable">>;
        <<"artifact_inventory">> ->
            Inventory =:= <<"verified">>
                andalso exact_positive_count(ConfiguredUnits, 10000)
                andalso Counts =:= <<"unavailable">>;
        <<"runner_compilation">> ->
            Inventory =:= <<"verified">>
                andalso exact_positive_count(ConfiguredUnits, 10000)
                andalso Counts =:= <<"unavailable">>;
        <<"exact_unit_execution">> ->
            Inventory =:= <<"verified">>
                andalso exact_positive_count(ConfiguredUnits, 10000)
                andalso Counts =:= <<"unavailable">> andalso RunnerBound
                andalso not LoadedBound;
        <<"unit_process_verification">> ->
            Inventory =:= <<"verified">>
                andalso exact_positive_count(ConfiguredUnits, 10000)
                andalso Counts =:= <<"unavailable">> andalso RunnerBound
                andalso not LoadedBound;
        <<"child_evidence">> ->
            Inventory =:= <<"verified">>
                andalso exact_positive_count(ConfiguredUnits, 10000)
                andalso Counts =:= <<"unavailable">> andalso RunnerBound
                andalso not LoadedBound;
        <<"post_execution_source_verification">> ->
            Inventory =:= <<"verified">> andalso Counts =:= <<"verified">>
                andalso RunnerBound andalso LoadedBound;
        <<"artifact_verification">> ->
            Inventory =:= <<"verified">> andalso Counts =:= <<"verified">>
                andalso RunnerBound andalso LoadedBound;
        <<"attempt_cleanup">> ->
            Inventory =:= <<"verified">> andalso Counts =:= <<"verified">>
                andalso RunnerBound andalso LoadedBound;
        <<"report_publication">> ->
            Inventory =:= <<"verified">> andalso Counts =:= <<"verified">>
                andalso RunnerBound andalso LoadedBound;
        _ -> false
    end.

exact_compile_driver_valid(Driver) ->
    try
        true = lists:sort(maps:keys(Driver)) =:= lists:sort([
            relative_path, original_sha256, driver_sha256,
            replacement_count]),
        <<"test/http_test.gleam">> = maps:get(relative_path, Driver),
        true = exact_sha256_valid(maps:get(original_sha256, Driver)),
        true = exact_sha256_valid(maps:get(driver_sha256, Driver)),
        1 = maps:get(replacement_count, Driver),
        true
    catch _:_ -> false end.

exact_failure_rows_valid(Rows, UnitCount)
  when is_list(Rows), length(Rows) =< 64,
       is_integer(UnitCount), UnitCount >= 0 ->
    lists:all(fun(Row) -> exact_failure_row_valid(Row, UnitCount) end, Rows);
exact_failure_rows_valid(_, _) -> false.

exact_failure_row_valid(Row, UnitCount) ->
    try
        true = lists:sort(maps:keys(Row)) =:= lists:sort([
            unit, module, function, kind, classification, stack]),
        Unit = maps:get(unit, Row),
        true = is_integer(Unit) andalso Unit >= 0 andalso Unit =< UnitCount,
        true = suite_safe_identifier(maps:get(module, Row)),
        true = suite_safe_identifier(maps:get(function, Row)),
        true = lists:member(maps:get(kind, Row),
                            [<<"test">>, <<"generator">>]),
        true = lists:member(maps:get(classification, Row),
            [<<"skipped">>, <<"cancelled">>, <<"invalid_test_status">>,
             <<"worker_killed">>, <<"worker_exit">>,
             <<"dependency_cancelled">>, <<"execution_aborted">>,
             <<"startup_failed">>, <<"pattern_mismatch">>,
             <<"unexpected_variant">>, <<"assertion_failed">>,
             <<"callback_failed">>, <<"invalid_argument">>,
             <<"resource_limit">>, <<"deadline_exceeded">>,
             <<"stale_source">>, <<"stale_build">>, <<"modified_build">>,
             <<"validation_failed">>]),
        Stack = maps:get(stack, Row),
        true = is_list(Stack) andalso length(Stack) =< 16,
        true = lists:all(fun suite_frame_schema/1, Stack),
        true
    catch _:_ -> false end.

exact_public_process_valid(Process) when is_map(Process) ->
    try
        false = maps:is_key(tail, Process),
        false = maps:is_key(output_sha256, Process),
        true = lists:all(fun(Key) -> lists:member(Key, [
            outcome, exit_status, deadline_ms, elapsed_ms, output_bytes,
            output_hashed_bytes, output_limit_bytes, output_digest_complete,
            output_limit_exceeded, vm_process_heap_words,
            vm_heap_includes_shared_binaries, crash_dumps_disabled, timed_out,
            terminal_control_bytes_removed, child_exit_observed,
            process_supervisor_protocol_valid,
            process_supervisor_failure_code,
            process_supervisor_attestation_failure,
            process_supervisor_reported_status,
            process_supervisor_observed_status, native_tree_empty,
            native_console_isolated, native_descendant_outlived,
            native_termination_requested, process_supervisor])
        end, maps:keys(Process)),
        true = exact_optional_process_outcome(Process),
        true = exact_optional_process_status(Process, exit_status, true),
        true = lists:all(fun(Key) -> exact_optional_process_count(Process, Key) end,
            [deadline_ms, elapsed_ms, output_bytes, output_hashed_bytes,
             output_limit_bytes, vm_process_heap_words,
             terminal_control_bytes_removed]),
        true = lists:all(fun(Key) -> exact_optional_process_boolean(Process, Key) end,
            [output_digest_complete, output_limit_exceeded,
             vm_heap_includes_shared_binaries, crash_dumps_disabled,
             timed_out, child_exit_observed,
             process_supervisor_protocol_valid, native_tree_empty,
             native_console_isolated, native_descendant_outlived,
             native_termination_requested]),
        true = exact_optional_process_status(
            Process, process_supervisor_reported_status, false),
        true = exact_optional_process_status(
            Process, process_supervisor_observed_status, false),
        true = exact_optional_supervisor_failure_code(Process),
        true = exact_optional_attestation_failure(Process),
        true = exact_optional_supervisor_identity(Process),
        true
    catch _:_ -> false end;
exact_public_process_valid(_) -> false.

exact_unit_process_keys() ->
    [output_bytes, output_hashed_bytes, output_limit_bytes,
     output_digest_complete, output_limit_exceeded, vm_process_heap_words,
     vm_heap_includes_shared_binaries, crash_dumps_disabled, timed_out,
     child_exit_observed, process_supervisor,
     process_supervisor_protocol_valid, process_supervisor_failure_code,
     process_supervisor_attestation_failure, process_supervisor_reported_status,
     process_supervisor_observed_status, native_tree_empty,
     native_console_isolated, native_descendant_outlived,
     native_termination_requested].

exact_unit_process_valid(Process) when is_map(Process) ->
    try
        true = lists:sort(maps:keys(Process)) =:=
            lists:sort(exact_unit_process_keys()),
        true = process_completion_verified(Process),
        8388608 = maps:get(output_limit_bytes, Process),
        33554432 = maps:get(vm_process_heap_words, Process),
        true = maps:get(vm_heap_includes_shared_binaries, Process),
        true = maps:get(crash_dumps_disabled, Process),
        true = maps:get(output_digest_complete, Process),
        false = maps:get(output_limit_exceeded, Process),
        false = maps:get(timed_out, Process),
        Bytes = maps:get(output_bytes, Process),
        Bytes = maps:get(output_hashed_bytes, Process),
        true = is_integer(Bytes) andalso Bytes >= 0 andalso Bytes =< 8388608,
        none = maps:get(process_supervisor_failure_code, Process),
        none = maps:get(process_supervisor_attestation_failure, Process),
        true = maps:get(native_tree_empty, Process),
        true = maps:get(native_console_isolated, Process),
        false = maps:get(native_descendant_outlived, Process),
        false = maps:get(native_termination_requested, Process),
        true
    catch _:_ -> false end;
exact_unit_process_valid(_) -> false.

exact_optional_process_outcome(Process) ->
    case maps:find(outcome, Process) of
        error -> true;
        {ok, Outcome} -> lists:member(Outcome, [ok, exit_failure,
            start_failed, deadline, output_limit, protocol_failure,
            supervisor_unconfirmed, reap_failed, collector_failure])
    end.

exact_optional_process_status(Process, Key, AllowNull) ->
    case maps:find(Key, Process) of
        error -> true;
        {ok, null} -> AllowNull;
        {ok, Status} -> is_integer(Status) andalso Status >= -1
            andalso Status =< 255
    end.

exact_optional_process_count(Process, Key) ->
    case maps:find(Key, Process) of
        error -> true;
        {ok, Count} -> exact_nonnegative_count(Count, 9223372036854775807)
    end.

exact_optional_process_boolean(Process, Key) ->
    case maps:find(Key, Process) of
        error -> true;
        {ok, Value} -> is_boolean(Value)
    end.

exact_optional_supervisor_failure_code(Process) ->
    case maps:find(process_supervisor_failure_code, Process) of
        error -> true;
        {ok, none} -> true;
        {ok, Code} when is_binary(Code) ->
            lists:member(Code, supervisor_failure_codes());
        _ -> false
    end.

exact_optional_attestation_failure(Process) ->
    case maps:find(process_supervisor_attestation_failure, Process) of
        error -> true;
        {ok, Value} -> lists:member(Value, [none, protocol_invalid,
            identity_mismatch, final_missing, status_mismatch,
            tree_not_empty, console_isolation_unconfirmed])
    end.

exact_optional_supervisor_identity(Process) ->
    case maps:find(process_supervisor, Process) of
        error -> true;
        {ok, Identity} -> exact_supervisor_identity_valid(Identity)
    end.

exact_supervisor_identity_valid(Identity) ->
    try
        true = lists:sort(maps:keys(Identity)) =:= lists:sort([
            python_implementation, python_version, console_isolation,
            source_sha256, python_executable_sha256]),
        <<"CPython">> = maps:get(python_implementation, Identity),
        true = re:run(maps:get(python_version, Identity),
            <<"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$">>,
            [{capture, none}]) =:= match,
        true = maps:get(console_isolation, Identity) =:=
            process_supervisor_isolation(),
        true = exact_sha256_valid(maps:get(source_sha256, Identity)),
        true = exact_sha256_valid(
            maps:get(python_executable_sha256, Identity)),
        true
    catch _:_ -> false end.

exact_positive_count(Value, Maximum) ->
    is_integer(Value) andalso Value > 0 andalso Value =< Maximum.

exact_nonnegative_count(Value, Maximum) ->
    is_integer(Value) andalso Value >= 0 andalso Value =< Maximum.

exact_sha256_valid(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    re:run(Value, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
exact_sha256_valid(_) -> false.

command_natural_exit_verified(Proof) ->
    process_completion_verified(Proof)
        andalso lists:member(maps:get(outcome, Proof, invalid), [ok, exit_failure])
        andalso is_integer(maps:get(exit_status, Proof, invalid))
        andalso maps:get(exit_status, Proof) >= 0
        andalso maps:get(exit_status, Proof) =< 255
        andalso not maps:get(native_descendant_outlived, Proof, true)
        andalso not maps:get(native_termination_requested, Proof, true).

stage_http_sources(Root, Lease) ->
    Stage = filename:join(maps:get(root, Lease), "stage"),
    ok = file:make_dir(Stage),
    exact_progress(stage_ready),
    SourcePaths = http_exact_source_paths(Root),
    true = SourcePaths =/= [] andalso length(SourcePaths) =< 20000,
    SourceDigest = root_relative_digest(Root, SourcePaths),
    lists:foreach(fun(Relative) -> exact_copy_file(
        filename:join(Root, Relative), filename:join(Stage, Relative)) end,
        SourcePaths),
    DependencyPaths = exact_tree_files(Root, "build/packages",
                                       5000, 268435456),
    lists:foreach(fun(Relative) -> exact_copy_file(
        filename:join(Root, Relative), filename:join(Stage, Relative)) end,
        DependencyPaths),
    DependencyDigest = root_relative_digest(Root, DependencyPaths),
    SourceDigest = stage_relative_digest(Stage, SourcePaths),
    DependencyDigest = stage_relative_digest(Stage, DependencyPaths),
    false = filelib:is_dir(filename:join(Stage, "build/dev")),
    {Stage, SourcePaths, SourceDigest, length(SourcePaths), DependencyDigest}.

%% `gleam test` is the only public command that emits every test beam, but its
%% normal entry point also runs the complete suite. In the isolated stage only,
%% replace that one call with Nil, build all beams once, then restore the exact
%% source bytes before any source or artifact evidence is accepted.
install_http_compile_driver(Stage) ->
    Relative = "test/http_test.gleam",
    Path = filename:join(Stage, Relative),
    {ok, Original} = file:read_file(Path),
    true = byte_size(Original) > 0 andalso byte_size(Original) =< 1048576,
    {ok, Driver} = http_compile_driver(Original),
    OriginalSha = binary:encode_hex(crypto:hash(sha256, Original), lowercase),
    DriverSha = binary:encode_hex(crypto:hash(sha256, Driver), lowercase),
    true = OriginalSha =/= DriverSha,
    ok = file:write_file(Path, Driver),
    #{path => Path, relative_path => unicode:characters_to_binary(Relative),
      original => Original, original_sha256 => OriginalSha,
      driver_sha256 => DriverSha, replacement_count => 1}.

restore_http_compile_driver(#{path := Path, original := Original,
                              driver_sha256 := DriverSha}) ->
    {ok, Current} = file:read_file(Path),
    CurrentSha = binary:encode_hex(crypto:hash(sha256, Current), lowercase),
    Restored = file:write_file(Path, Original),
    ok = Restored,
    true = CurrentSha =:= DriverSha,
    ok.

safe_http_compile_driver(State) ->
    maps:with([relative_path, original_sha256, driver_sha256,
               replacement_count], State).

http_compile_driver(Bytes)
  when is_binary(Bytes), byte_size(Bytes) > 0, byte_size(Bytes) =< 1048576 ->
    Pattern = <<"gleeunit.main()">>,
    case binary:matches(Bytes, Pattern) of
        [{_, _}] -> {ok, binary:replace(Bytes, Pattern, <<"Nil">>)};
        _ -> error
    end;
http_compile_driver(_) -> error.

http_exact_source_paths(Root) ->
    Configs = [Path || Path <- [".mise.toml", "gleam.toml", "manifest.toml",
                                "mix.exs", "mix.lock"],
                       filelib:is_regular(filename:join(Root, Path))],
    Trees = ["src", "test", "scripts", "standards",
             "packages/http3/src", "packages/http3/test",
             "packages/quic_core/src", "packages/quic_core/test"],
    PackageConfigs = [filename:join(Package, Name)
        || Package <- ["packages/http3", "packages/quic_core"],
           Name <- ["gleam.toml", "manifest.toml", "mix.exs", "mix.lock"],
           filelib:is_regular(filename:join(Root, filename:join(Package, Name)))],
    lists:usort(Configs ++ PackageConfigs ++ lists:append([
        exact_source_tree_files(Root, Tree) || Tree <- Trees])).

exact_source_tree_files(Root, Tree) ->
    io:format("supervised_gleam source_tree=~s state=scanning~n", [Tree]),
    Paths = exact_tree_files(Root, Tree, 20000, 536870912),
    io:format("supervised_gleam source_tree=~s state=captured~n", [Tree]),
    Paths.

exact_tree_files(Root, Tree, MaxFiles, MaxBytes) ->
    relative = filename:pathtype(Tree),
    false = lists:member("..", filename:split(Tree)),
    Relative = exact_normalized_relative(Tree),
    {Paths, Count, Bytes} = exact_tree_files(
        filename:join(Root, Tree), Relative, [], 0, 0, MaxFiles, MaxBytes),
    true = Count =< MaxFiles andalso Bytes =< MaxBytes,
    lists:sort(Paths).

exact_tree_files(Path, Relative, Paths, Count, Bytes, MaxFiles, MaxBytes) ->
    true = Count =< MaxFiles andalso Bytes =< MaxBytes,
    case file:read_link_info(Path) of
        {ok, #file_info{type = regular, size = Size}}
          when is_integer(Size), Size >= 0, Size =< 67108864 ->
            NextCount = Count + 1,
            NextBytes = Bytes + Size,
            true = NextCount =< MaxFiles andalso NextBytes =< MaxBytes,
            {[Relative | Paths], NextCount, NextBytes};
        {ok, #file_info{type = directory}} ->
            {ok, Names} = file:list_dir(Path),
            lists:foldl(fun(Name, {AccPaths, AccCount, AccBytes}) ->
                exact_tree_files(filename:join(Path, Name),
                                 exact_normalized_relative(
                                     filename:join(Relative, Name)), AccPaths,
                                 AccCount, AccBytes, MaxFiles, MaxBytes)
            end, {Paths, Count, Bytes}, lists:sort(Names));
        {ok, #file_info{type = symlink}} -> erlang:error(staged_source_link_rejected);
        {ok, _} -> erlang:error(staged_source_special_file_rejected);
        {error, enoent} -> {Paths, Count, Bytes};
        {error, _} -> erlang:error(staged_source_scan_failed)
    end.

exact_copy_file(Source, Destination) ->
    ok = filelib:ensure_dir(Destination),
    {ok, Bytes} = file:read_file(Source),
    true = byte_size(Bytes) =< 67108864,
    ok = file:write_file(Destination, Bytes, [exclusive]),
    ok.

verify_http_stage_inputs(Root, Stage, SourcePaths, Digest) ->
    Digest = root_relative_digest(Root, http_exact_source_paths(Root)),
    Digest = root_relative_digest(Root, SourcePaths),
    Digest = stage_relative_digest(Stage, SourcePaths),
    ok.

root_relative_digest(Root, Paths) ->
    file_identity_digest(Paths, fun(Relative) ->
        {ok, Bytes} = file:read_file(filename:join(Root, Relative)), Bytes
    end, lowercase).

stage_relative_digest(Stage, Paths) ->
    RelativePaths = [exact_normalized_relative(Path) || Path <- Paths],
    file_identity_digest(RelativePaths,
        fun(Relative) ->
            {ok, Bytes} = file:read_file(filename:join(Stage, Relative)), Bytes
        end, lowercase).

http_exact_artifact_paths(Stage) ->
    [Path || Path <- exact_tree_files(Stage, "build/dev/erlang",
                                      20000, 536870912),
             lists:member(filename:extension(Path), [".beam", ".app", ".erl"])].

exact_stage_artifacts_exist(Stage, Paths)
  when is_list(Paths), Paths =/= [] ->
    lists:all(fun(Path) ->
        filename:pathtype(Path) =:= relative andalso
        not lists:member("..", filename:split(Path)) andalso
        filelib:is_regular(filename:join(Stage, Path))
    end, Paths);
exact_stage_artifacts_exist(_, _) -> false.

http_exact_code_paths(Stage) ->
    lists:sort([filename:absname(Path) || Path <- filelib:wildcard(
        filename:join(Stage, "build/dev/erlang/*/ebin"))]).

compile_http_exact_runner(SourceRoot, Lease) ->
    Directory = filename:join(maps:get(root, Lease), "runner"),
    ok = file:make_dir(Directory),
    SourceDirectory = filename:join(maps:get(root, Lease), "runner-source"),
    ok = file:make_dir(SourceDirectory),
    SourceNames = http_exact_runner_source_names(),
    CapturedSources = [{Name, execution_beam_read(
        filename:join([SourceRoot, "scripts", Name]), 4194304)}
        || Name <- SourceNames],
    lists:foreach(fun({Name, Bytes}) ->
        ok = execution_beam_publish_new(
            filename:join(SourceDirectory, Name), Bytes, 4194304)
    end, CapturedSources),
    {ok, Module, Binary, []} = compile:file(
        filename:join(SourceDirectory, "qualification_eunit_listener.erl"),
        [binary, return_errors, return_warnings,
         {i, SourceDirectory}]),
    lists:foreach(fun({Name, Bytes}) ->
        Bytes = execution_beam_read(filename:join(SourceDirectory, Name),
                                    4194304),
        Bytes = execution_beam_read(
            filename:join([SourceRoot, "scripts", Name]), 4194304)
    end, CapturedSources),
    Sha256 = binary:encode_hex(crypto:hash(sha256, Binary), lowercase),
    BeamPath = filename:join(Directory, atom_to_list(Module) ++ ".beam"),
    ok = execution_beam_publish_new(BeamPath, Binary, 4194304),
    Binary = execution_beam_read(BeamPath, 4194304),
    #{directory => Directory, beam_path => BeamPath,
      binary => Binary, module => Module, sha256 => Sha256}.

http_exact_runner_source_names() ->
    ["qualification_eunit_listener.erl", "diagnostic_failure.hrl",
     "suite_evidence.hrl", "json_evidence.hrl",
     "execution_beam_identity.hrl", "evidence_publication.hrl",
     "canonical_etf_wire.hrl"].

exact_read_child(Path) ->
    evidence_json_decode(execution_beam_read(Path, 16777216)).

exact_safe_process(Process) ->
    maps:with([outcome, exit_status, deadline_ms, elapsed_ms, output_bytes,
        output_limit_bytes, output_limit_exceeded, timed_out,
        terminal_control_bytes_removed,
        child_exit_observed, process_supervisor_protocol_valid,
        process_supervisor_failure_code, process_supervisor_attestation_failure,
        process_supervisor_reported_status, process_supervisor_observed_status,
        native_tree_empty, native_console_isolated,
        native_descendant_outlived,
        native_termination_requested, process_supervisor], Process).

exact_safe_unit_process(Process) ->
    maps:with(exact_unit_process_keys(), Process).

exact_failure_rows(Child, Units) ->
    [exact_failure_row(Row, Units) || Row <- maps:get(<<"failures">>, Child)].

exact_failure_row(Row, Units) ->
    Ordinal = maps:get(<<"unit">>, Row),
    Unit = case Ordinal > 0 andalso Ordinal =< length(Units) of
        true -> lists:nth(Ordinal, Units);
        false -> #{module => <<"unknown">>, function => <<"unknown">>,
                   kind => <<"test">>}
    end,
    #{unit => Ordinal, module => maps:get(module, Unit),
      function => maps:get(function, Unit), kind => maps:get(kind, Unit),
      classification => maps:get(<<"classification">>, Row),
      stack => maps:get(<<"stack">>, Row)}.

exact_publish_report(Root, SourceDigest, Nonce, Report) ->
    Directory = filename:join(Root, "build/supervised-gleam/http-exact-reports"),
    Name = binary_to_list(SourceDigest) ++ "-" ++ binary_to_list(Nonce) ++ ".json",
    Path = filename:join(Directory, Name),
    Bytes = iolist_to_binary([json:encode(Report), $\n]),
    ok = evidence_publish_new(Path, Bytes, 33554432),
    exact_normalized_relative(filename:join(
        "build/supervised-gleam/http-exact-reports", Name)).

exact_remove_tree(Path, Count) when Count =< 100000 ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = directory}} ->
            {ok, Names} = file:list_dir(Path),
            Final = lists:foldl(fun(Name, Acc) ->
                exact_remove_tree(filename:join(Path, Name), Acc)
            end, Count + 1, lists:sort(Names)),
            ok = file:del_dir(Path), Final;
        {ok, _} -> ok = file:delete(Path), Count + 1;
        {error, enoent} -> Count;
        {error, _} -> erlang:error(http_exact_stage_cleanup_failed)
    end;
exact_remove_tree(_, _) -> erlang:error(http_exact_stage_cleanup_limit).

exact_remove_file(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(http_exact_child_cleanup_failed)
    end.

exact_normalized_absolute(Path) ->
    [case Character of $\\ -> $/; _ -> Character end
     || Character <- filename:absname(Path)].

exact_normalized_relative(Path) ->
    [case Character of $\\ -> $/; _ -> Character end || Character <- Path].

fresh_ensure(true, _) -> ok;
fresh_ensure(false, Reason) -> erlang:error(Reason).

verify_gleam(Gleam, Root, Environment) ->
    Digest = bounded_file_sha256(Gleam, 134217728),
    true = lists:member(Digest, [
        <<"480d513f2e618a9435c654d073d1e1b18693d7442244b921796110117cca7875">>,
        <<"2d48c70edb9da6181224b82050179da9112bc42d7e374360475dc18109762a0e">>
    ]),
    io:format("supervised_gleam runtime_identity=verified~n"),
    case command_capture(
            Gleam, ["--version"], Root, 10000, 1024, Environment) of
        {ok, Version, VersionProof} ->
            true = command_success_verified(VersionProof),
            true = string:trim(binary_to_list(Version)) =:= "gleam 1.18.1",
            io:format("supervised_gleam runtime_version=verified~n"),
            ok;
        {error, VersionProof} when is_map(VersionProof) ->
            io:format(standard_error,
                "supervised_gleam runtime_probe=rejected process=~p~n",
                [supervised_package_process_proof(VersionProof)]),
            erlang:error(gleam_runtime_probe_failed);
        {error, _, VersionProof} when is_map(VersionProof) ->
            io:format(standard_error,
                "supervised_gleam runtime_probe=rejected process=~p~n",
                [supervised_package_process_proof(VersionProof)]),
            erlang:error(gleam_runtime_probe_failed)
    end.

supervised_toolchain(Gleam) ->
    {OsFamily, OsName} = os:type(),
    Value = #{gleam_version => <<"1.18.1">>,
        gleam_sha256 => bounded_file_sha256(Gleam, 134217728),
        otp_release => list_to_binary(erlang:system_info(otp_release)),
        erts_version => list_to_binary(erlang:system_info(version)),
        os_family => atom_to_binary(OsFamily), os_name => atom_to_binary(OsName)},
    true = supervised_toolchain_valid(Value),
    Value.

supervised_toolchain_valid(Value) ->
    try
        true = lists:sort(maps:keys(Value)) =:= lists:sort([
            gleam_version, gleam_sha256, otp_release, erts_version,
            os_family, os_name]),
        <<"1.18.1">> = maps:get(gleam_version, Value),
        Digest = maps:get(gleam_sha256, Value),
        true = is_binary(Digest) andalso byte_size(Digest) =:= 64,
        match = re:run(Digest, <<"^[0-9a-f]{64}$">>, [{capture, none}]),
        true = lists:member(maps:get(otp_release, Value), [<<"28">>, <<"29">>]),
        true = lists:all(fun supervised_runtime_label_valid/1, [
            maps:get(erts_version, Value), maps:get(os_family, Value),
            maps:get(os_name, Value)]),
        true
    catch _:_ -> false end.

supervised_runtime_label_valid(Value)
  when is_binary(Value), byte_size(Value) > 0, byte_size(Value) =< 64 ->
    re:run(Value, <<"^[A-Za-z0-9._-]+$">>, [{capture, none}]) =:= match;
supervised_runtime_label_valid(_) -> false.

otp_environment() ->
    Separator = case os:type() of {win32, _} -> ";"; _ -> ":" end,
    OtpBin = filename:join(code:root_dir(), "bin"),
    Existing = case os:getenv("PATH") of false -> ""; Value -> Value end,
    [{"PATH", OtpBin ++ Separator ++ Existing},
     {"ERL_AFLAGS", false}, {"ERL_FLAGS", false}, {"ERL_ZFLAGS", false}].

validated_gleam_path(Root, Path) ->
    true = is_list(Path) andalso length(Path) >= 1 andalso length(Path) =< 512,
    true = hd(Path) =/= $-,
    true = filename:extension(Path) =:= ".gleam",
    Safe = filelib:safe_relative_path(Path, Root),
    true = Safe =/= unsafe,
    Absolute = filename:absname(Safe, Root),
    true = filelib:is_regular(Absolute),
    Safe.

gleam_executable() ->
    case os:getenv("HTTP_GLEAM_EXECUTABLE") of
        Path when is_list(Path), Path =/= [] ->
            Absolute = filename:absname(Path),
            true = filelib:is_regular(Absolute),
            Absolute;
        _ ->
            case os:find_executable("gleam") of
                Found when is_list(Found) -> Found;
                false -> erlang:error(gleam_runtime_missing)
            end
    end.
