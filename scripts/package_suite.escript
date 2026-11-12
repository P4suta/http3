#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile({nowarn_unused_function, [
    {command_capture_projected, 8},
    {bounded_file_sha256, 2}
]}).
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("command_capture.hrl").
-include("suite_evidence.hrl").
-include("suite_discovery.hrl").
-include("execution_beam_identity.hrl").

main(Arguments) ->
    ok = file:set_cwd(filename:dirname(filename:dirname(filename:absname(escript:script_name())))),
    execution_beam_with_owned_platform_observer(
        fun package_owner_identity_capture/4,
        fun() -> package_main(Arguments) end).

package_main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch Class:Reason:Stack ->
        io:format(standard_error, "package suite failed: ~s~n",
                  [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

package_owner_identity_capture(Executable, Arguments, Timeout, Limit) ->
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

run(["--self-test"]) -> self_test();
run(["--recover-stale-attempt", Base, Nonce0, Snapshot]) ->
    true = length(Base) > 0 andalso length(Base) =< 4096,
    true = length(Nonce0) =:= 32,
    true = length(Snapshot) > 0 andalso length(Snapshot) =< 4096,
    Nonce = unicode:characters_to_binary(Nonce0),
    true = execution_beam_digest(Nonce, 32),
    #{status := recovered, attempt_sha256 := Attempt,
      snapshot_sha256 := SnapshotSha, death_proof := Proof} =
        execution_beam_recover_stale_attempt(Base, Nonce, Snapshot),
    io:format("stale_attempt=~s recovery=recovered snapshot=~s proof=~s~n",
              [binary:part(Attempt, 0, 16),
               binary:part(SnapshotSha, 0, 16),
               atom_to_binary(Proof, utf8)]),
    ok;
run([Target]) when Target =:= "http"; Target =:= "http3"; Target =:= "core" ->
    package(Target);
run(_) -> erlang:error(invalid_package_suite_arguments).

package(Target) ->
    Path = "build/package-suite/" ++ Target ++ ".json",
    Identity = evidence_begin(Path),
    ok = filelib:ensure_dir(Path),
    try package_run(Target, Path, Identity)
    catch Class:Reason:Stack ->
        case filelib:is_regular(Path) of
            true -> ok;
            false ->
                Failure = #{schema => 3, report_kind => <<"package_suite">>,
                            package => list_to_binary(Target),
                            status => <<"Failed">>, shareable => true,
                            scope => <<"all source-discovered EUnit tests and generators">>,
                            evidence_identity => Identity,
                            execution_environment => execution_runtime(),
                            suite_inventory => null,
                            configured_modules => null,
                            configured_units => null,
                            counts_state => <<"unavailable">>,
                            completed_tests => null, skipped_tests => null,
                            failure_classification =>
                                package_failure_classification(Reason),
                            failure => diagnostic_failure_details(
                                Class, Reason, Stack),
                            replay => list_to_binary(
                                "bash scripts/fresh_build.sh " ++ Target ++
                                " && escript scripts/package_suite.escript " ++
                                Target)},
                ensure(package_suite_minimal_failure_valid(
                    Failure, Target, Identity),
                    invalid_minimal_package_failure),
                ok = package_publish_report(Path, Failure)
        end,
        erlang:raise(Class, Reason, Stack)
    end.

package_run(Target, Path, Identity) ->
    fresh_with_verified_build(Target, fun(Snapshot) ->
        package_run_verified(Target, Path, Identity, Snapshot)
    end).

package_run_verified(Target, Path, Identity, InitialSnapshot) ->
    BuildIdentity = maps:get(report, InitialSnapshot),
    Directory = fresh_target_directory(Target),
    {Name, _} = lists:last(fresh_packages(Target)),
    Ebin = filename:join([Directory, "build/dev/erlang", Name, "ebin"]),
    TestRoot = filename:join(Directory, "test"),
    Inventory = suite_inventory(TestRoot, Ebin),
    Modules = suite_inventory_modules(Inventory),
    Units = suite_inventory_units(Inventory),
    ensure(Units =/= [] andalso length(Units) =< 10000, invalid_suite_unit_count),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(
        "build/package-suite/attempts", Nonce),
    put(package_suite_attempt_lease, Lease),
    try package_run_verified_leased(
        Target, Path, Identity, InitialSnapshot, BuildIdentity, Directory, Ebin,
        TestRoot, Inventory, Modules, Units, Nonce, Lease)
    after package_release_attempt_if_active() end.

package_run_verified_leased(Target, Path, Identity, InitialSnapshot,
                            BuildIdentity, Directory, Ebin, TestRoot, Inventory,
                            Modules, Units, Nonce, Lease) ->
    Runner = compile_runner(Lease),
    RunnerDirectory = maps:get(directory, Runner),
    RunnerSha = maps:get(sha256, Runner),
    ChildPath = filename:join(maps:get(root, Lease), "child.json"),
    Paths = [RunnerDirectory, filename:absname(Ebin) |
             [filename:absname(P) || P <- filelib:wildcard(
                 filename:join(Directory, "build/dev/erlang/*/ebin")),
                 filename:absname(P) =/= filename:absname(Ebin)]],
    BuildRoot = filename:absname(filename:join(Directory, "build/dev")),
    BeamInventory = execution_beam_inventory(
        lists:delete(RunnerDirectory, Paths), BuildRoot, fun fresh_read/1),
    BeamInventorySha = maps:get(sha256, BeamInventory),
    SourceSha = maps:get(<<"source_sha256">>, BuildIdentity),
    Evaluation = execution_beam_bootstrap_evaluation(Lease, run_attested,
        [Units, ChildPath, Nonce, RunnerSha, BuildRoot, BeamInventory],
        RunnerSha, SourceSha, 126),
    {Status, Output} = run_child_evaluation(filename:absname(Directory), Paths,
                                           Evaluation, 1200000),
    Child = suite_safe_attested_child(read_child(ChildPath), Units, Nonce,
        RunnerSha, BeamInventorySha),
    Valid = suite_attested_child_valid(Child, Units, Nonce,
        RunnerSha, BeamInventorySha),
    Counts = suite_attested_test_counts(Child, Units, Nonce,
        RunnerSha, BeamInventorySha),
    ChildBeamIdentity = maps:get(<<"execution_beam_identity">>, Child, #{}),
    Complete = process_status_verified(Status, 0, Output) andalso Valid,
    Report0 = #{schema => 3, report_kind => <<"package_suite">>,
                package => list_to_binary(Target), shareable => true,
                scope => <<"all source-discovered EUnit tests and generators">>,
                configured_modules => Modules, configured_units => length(Units),
                suite_inventory => Inventory,
                build_identity => BuildIdentity,
                runner_sha256 => RunnerSha,
                execution_beam_inventory_sha256 => BeamInventorySha,
                loaded_beam_sha256 => maps:get(
                    <<"loaded_beam_sha256">>, ChildBeamIdentity, null),
                loaded_beam_count => maps:get(
                    <<"loaded_beam_count">>, ChildBeamIdentity, null),
                counts_state => maps:get(state, Counts),
                completed_tests => maps:get(completed, Counts),
                skipped_tests => maps:get(skipped, Counts),
                status => case Complete of true -> <<"Ready">>; false -> <<"Failed">> end,
                child_exit_status => Status, child => Child,
                process => package_safe_process(Output),
                replay => list_to_binary("bash scripts/fresh_build.sh " ++ Target ++
                                          " && escript scripts/package_suite.escript " ++ Target)},
    %% Verification runs again after execution: source and loaded dependency
    %% artifacts must still describe the same full suite.
    Report = try
        ok = suite_require_inventory_unchanged(Inventory, TestRoot, Ebin),
        FinalSnapshot = fresh_verify_locked(Target),
        InitialSnapshotSha = maps:get(sha256, InitialSnapshot),
        InitialSnapshotSha = maps:get(sha256, FinalSnapshot),
        InitialSnapshotBytes = maps:get(bytes, InitialSnapshot),
        InitialSnapshotBytes = maps:get(bytes, FinalSnapshot),
        evidence_complete(Report0, Identity)
    catch FinalClass:FinalReason:FinalStack ->
        Report0#{status => <<"Failed">>, evidence_identity => Identity,
                 execution_environment => execution_runtime(),
                 failure => diagnostic_failure_details(FinalClass, FinalReason, FinalStack)}
    end,
    ensure(package_suite_report_valid(
        Report, Target, Identity, Inventory, Units, Nonce),
        invalid_package_suite_report),
    %% A published Ready report implies that the private runner, child report,
    %% and staged attempt have already been removed.  Cleanup failure must not
    %% leave an otherwise valid success artifact for a later audit to accept.
    ok = package_release_attempt_active(),
    io:format("package ~s: ~s, completed=~p configured=~B counts=~s~n",
              [Target, maps:get(status, Report),
               maps:get(completed_tests, Report), length(Units),
               maps:get(counts_state, Report)]),
    case Complete andalso maps:get(status, Report) =:= <<"Ready">> of
        true -> package_publish_report(Path, Report);
        false ->
            ok = package_publish_report(Path, Report),
            erlang:error(package_suite_incomplete)
    end.

package_release_attempt_active() ->
    case get(package_suite_attempt_lease) of
        Lease when is_map(Lease) ->
            ok = execution_beam_release_attempt(Lease),
            put(package_suite_attempt_lease, released),
            ok;
        released -> ok;
        _ -> erlang:error(package_suite_attempt_lease_missing)
    end.

package_release_attempt_if_active() ->
    case erase(package_suite_attempt_lease) of
        Lease when is_map(Lease) -> execution_beam_release_attempt(Lease);
        released -> ok;
        undefined -> ok;
        _ -> erlang:error(package_suite_attempt_lease_invalid)
    end.

package_failure_classification({suite_inventory_rejected, Reason})
  when is_atom(Reason) ->
    atom_to_binary(Reason);
package_failure_classification({fresh_input_rejected, Reason})
  when is_atom(Reason) ->
    atom_to_binary(Reason);
package_failure_classification({stale_build_sources, _}) ->
    <<"stale_build_sources">>;
package_failure_classification({modified_build_artifacts, _}) ->
    <<"modified_build_artifacts">>;
package_failure_classification({missing_artifact, _}) ->
    <<"missing_artifact">>;
package_failure_classification(_) ->
    <<"package_suite_failed">>.

package_suite_report_valid(Report, Target, Identity, Inventory, Units, Nonce) ->
    try
        BaseKeys = [schema, report_kind, package, status, shareable, scope,
            configured_modules, configured_units, suite_inventory,
            build_identity, runner_sha256, execution_beam_inventory_sha256,
            loaded_beam_sha256, loaded_beam_count,
            counts_state, completed_tests,
            skipped_tests, child_exit_status, child, process, replay,
            evidence_identity, execution_environment],
        Keys = lists:sort(maps:keys(Report)),
        true = Keys =:= lists:sort(BaseKeys) orelse
            Keys =:= lists:sort([failure | BaseKeys]),
        3 = maps:get(schema, Report),
        <<"package_suite">> = maps:get(report_kind, Report),
        TargetBinary = list_to_binary(Target),
        TargetBinary = maps:get(package, Report),
        true = maps:get(shareable, Report),
        <<"all source-discovered EUnit tests and generators">> =
            maps:get(scope, Report),
        Identity = maps:get(evidence_identity, Report),
        CurrentRuntime = execution_runtime(),
        CurrentRuntime = maps:get(execution_environment, Report),
        Inventory = maps:get(suite_inventory, Report),
        true = suite_inventory_schema_valid(Inventory),
        Modules = suite_inventory_modules(Inventory),
        Modules = maps:get(configured_modules, Report),
        UnitCount = length(Units),
        UnitCount = maps:get(configured_units, Report),
        RunnerSha = maps:get(runner_sha256, Report),
        true = package_digest(RunnerSha),
        BeamInventorySha = maps:get(execution_beam_inventory_sha256, Report),
        true = package_digest(BeamInventorySha),
        Child = maps:get(child, Report),
        Counts = suite_attested_test_counts(
            Child, Units, Nonce, RunnerSha, BeamInventorySha),
        true = suite_test_counts_valid(Counts),
        CountsState = maps:get(state, Counts),
        CountsState = maps:get(counts_state, Report),
        Completed = maps:get(completed, Counts),
        Completed = maps:get(completed_tests, Report),
        Skipped = maps:get(skipped, Counts),
        Skipped = maps:get(skipped_tests, Report),
        true = package_build_identity_valid(
            maps:get(build_identity, Report), Target),
        BeamIdentity = maps:get(<<"execution_beam_identity">>, Child),
        LoadedSha = maps:get(<<"loaded_beam_sha256">>, BeamIdentity),
        LoadedSha = maps:get(loaded_beam_sha256, Report),
        true = package_digest(LoadedSha),
        LoadedCount = maps:get(<<"loaded_beam_count">>, BeamIdentity),
        LoadedCount = maps:get(loaded_beam_count, Report),
        true = is_integer(LoadedCount) andalso LoadedCount > 0
            andalso LoadedCount =< 20000,
        ChildExitStatus = maps:get(child_exit_status, Report),
        true = is_integer(ChildExitStatus),
        Process = maps:get(process, Report),
        true = package_process_valid(Process),
        ChildExitStatus = maps:get(
            process_supervisor_reported_status, Process),
        Replay = list_to_binary("bash scripts/fresh_build.sh " ++ Target ++
            " && escript scripts/package_suite.escript " ++ Target),
        Replay = maps:get(replay, Report),
        true = case maps:get(status, Report) of
            <<"Ready">> ->
                false = maps:is_key(failure, Report),
                0 = maps:get(child_exit_status, Report),
                0 = maps:get(skipped_tests, Report),
                suite_attested_child_valid(
                    Child, Units, Nonce, RunnerSha, BeamInventorySha);
            <<"Failed">> ->
                case maps:find(failure, Report) of
                    {ok, Failure} -> package_failure_document_valid(Failure);
                    error -> true
                end;
            _ -> false
        end,
        true
    catch _:_ -> false end.

package_suite_minimal_failure_valid(Report, Target, Identity) ->
    try
        true = lists:sort(maps:keys(Report)) =:= lists:sort([
            schema, report_kind, package, status, shareable, scope,
            evidence_identity, execution_environment, suite_inventory,
            configured_modules, configured_units, counts_state,
            completed_tests, skipped_tests, failure_classification,
            failure, replay]),
        3 = maps:get(schema, Report),
        <<"package_suite">> = maps:get(report_kind, Report),
        TargetBinary = list_to_binary(Target),
        TargetBinary = maps:get(package, Report),
        <<"Failed">> = maps:get(status, Report),
        true = maps:get(shareable, Report),
        <<"all source-discovered EUnit tests and generators">> =
            maps:get(scope, Report),
        Identity = maps:get(evidence_identity, Report),
        CurrentRuntime = execution_runtime(),
        CurrentRuntime = maps:get(execution_environment, Report),
        null = maps:get(suite_inventory, Report),
        null = maps:get(configured_modules, Report),
        null = maps:get(configured_units, Report),
        <<"unavailable">> = maps:get(counts_state, Report),
        null = maps:get(completed_tests, Report),
        null = maps:get(skipped_tests, Report),
        true = package_failure_classification_valid(
            maps:get(failure_classification, Report)),
        true = package_failure_document_valid(maps:get(failure, Report)),
        Replay = list_to_binary("bash scripts/fresh_build.sh " ++ Target ++
            " && escript scripts/package_suite.escript " ++ Target),
        Replay = maps:get(replay, Report),
        true
    catch _:_ -> false end.

package_failure_classification_valid(Value) ->
    lists:member(Value, [<<"package_suite_failed">>, <<"stale_build_sources">>,
        <<"modified_build_artifacts">>, <<"missing_artifact">>])
    orelse lists:member(Value, [atom_to_binary(Reason) || Reason <- [
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
        internally_invalid_inventory, stale_suite_inventory]])
    orelse lists:member(Value, [atom_to_binary(Reason) || Reason <- [
        tree_depth_limit, tree_entry_limit, tree_read_failed,
        tree_link_rejected, tree_special_file_rejected,
        tree_changed_while_reading, tree_inspection_failed, tree_missing,
        unsafe_path, file_link_rejected, file_hardlink_rejected,
        file_special_file_rejected, file_parent_rejected, file_missing,
        file_inspection_failed, file_size_rejected,
        file_changed_while_reading, file_read_failed,
        duplicate_path, case_colliding_path]]).

package_failure_document_valid(Failure) ->
    try
        true = lists:sort(maps:keys(Failure)) =:= lists:sort([
            exception_class, exception_reason, stacktrace]),
        true = lists:member(maps:get(exception_class, Failure),
            [<<"error">>, <<"exit">>, <<"throw">>, <<"unknown">>]),
        true = lists:member(maps:get(exception_reason, Failure),
            [<<"pattern_mismatch">>, <<"unexpected_variant">>,
             <<"assertion_failed">>, <<"callback_failed">>,
             <<"invalid_argument">>, <<"resource_limit">>,
             <<"startup_failed">>, <<"deadline_exceeded">>,
             <<"stale_source">>, <<"stale_build">>,
             <<"modified_build">>, <<"validation_failed">>]),
        StackBytes = maps:get(stacktrace, Failure),
        true = is_binary(StackBytes) andalso byte_size(StackBytes) =< 32768,
        Stack = evidence_json_decode(StackBytes),
        true = is_list(Stack) andalso length(Stack) =< 16,
        true = lists:all(fun suite_frame_schema/1, Stack),
        true
    catch _:_ -> false end.

package_digest(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 64 andalso
        re:run(Value, <<"^[0-9A-Fa-f]{64}$">>,
               [{capture, none}]) =:= match.

package_build_identity_valid(Build, Target) ->
    try
        true = lists:sort(maps:keys(Build)) =:= lists:sort([
            <<"schema">>, <<"package">>, <<"source_sha256">>,
            <<"source_files">>, <<"artifact_sha256">>, <<"artifact_files">>,
            <<"toolchain">>, <<"build_nonce">>,
            <<"prebuild_profile_state">>]),
        3 = maps:get(<<"schema">>, Build),
        TargetBinary = list_to_binary(Target),
        TargetBinary = maps:get(<<"package">>, Build),
        true = package_digest(maps:get(<<"source_sha256">>, Build)),
        true = package_digest(maps:get(<<"artifact_sha256">>, Build)),
        SourceFiles = maps:get(<<"source_files">>, Build),
        ArtifactFiles = maps:get(<<"artifact_files">>, Build),
        true = is_integer(SourceFiles) andalso SourceFiles > 0
            andalso SourceFiles =< 1000000,
        true = is_integer(ArtifactFiles) andalso ArtifactFiles > 0
            andalso ArtifactFiles =< 1000000,
        CurrentTools = execution_build_tools(),
        CurrentTools = maps:get(<<"toolchain">>, Build),
        true = fresh_build_nonce_valid(maps:get(<<"build_nonce">>, Build)),
        <<"absent">> = maps:get(<<"prebuild_profile_state">>, Build),
        true
    catch _:_ -> false end.

compile_runner(Lease) ->
    Directory = filename:join(maps:get(root, Lease), "runner"),
    ok = file:make_dir(Directory),
    SourceDirectory = filename:join(maps:get(root, Lease), "runner-source"),
    ok = file:make_dir(SourceDirectory),
    SourceNames = package_runner_source_names(),
    CapturedSources = [{Name, fresh_read(filename:join("scripts", Name))}
                       || Name <- SourceNames],
    lists:foreach(fun({Name, Bytes}) ->
        ok = execution_beam_publish_new(
            filename:join(SourceDirectory, Name), Bytes, 4194304)
    end, CapturedSources),
    {Module, Binary} = case compile:file(
        filename:join(SourceDirectory, "qualification_eunit_listener.erl"),
        [binary, return_errors, return_warnings, {i, SourceDirectory}]) of
        {ok, CompiledModule, CompiledBinary, []} ->
            {CompiledModule, CompiledBinary};
        {ok, _, _, Warnings} when is_list(Warnings) ->
            erlang:error(listener_compiler_warning);
        {error, _, _} ->
            erlang:error(listener_compilation_failed);
        _ ->
            erlang:error(listener_compilation_result_invalid)
    end,
    lists:foreach(fun({Name, Bytes}) ->
        Bytes = execution_beam_read(filename:join(SourceDirectory, Name),
                                    4194304),
        Bytes = fresh_read(filename:join("scripts", Name))
    end, CapturedSources),
    Sha256 = binary:encode_hex(crypto:hash(sha256, Binary), lowercase),
    BeamPath = filename:join(Directory, atom_to_list(Module) ++ ".beam"),
    ok = execution_beam_publish_new(BeamPath, Binary, 4194304),
    Binary = execution_beam_read(BeamPath, 4194304),
    #{directory => Directory, beam_path => BeamPath,
      module => Module, binary => Binary, sha256 => Sha256, lease => Lease}.

package_runner_source_names() ->
    ["qualification_eunit_listener.erl", "diagnostic_failure.hrl",
     "suite_evidence.hrl", "json_evidence.hrl",
     "execution_beam_identity.hrl", "evidence_publication.hrl",
     "canonical_etf_wire.hrl"].

package_publish_report(Path, Report) ->
    Bytes = iolist_to_binary([json:encode(Report), $\n]),
    execution_beam_publish_new(Path, Bytes, 33554432).

package_safe_process(Process) -> maps:with(package_process_keys(), Process).

package_process_keys() ->
    [output_bytes, output_hashed_bytes, output_limit_bytes,
     output_digest_complete, output_limit_exceeded, vm_process_heap_words,
     vm_heap_includes_shared_binaries, crash_dumps_disabled, timed_out,
     child_exit_observed, process_supervisor,
     process_supervisor_protocol_valid, process_supervisor_failure_code,
     process_supervisor_attestation_failure, process_supervisor_reported_status,
     process_supervisor_observed_status, native_tree_empty,
     native_console_isolated, native_descendant_outlived,
     native_termination_requested].

package_process_valid(Process) when is_map(Process) ->
    try
        true = lists:sort(maps:keys(Process)) =:=
            lists:sort(package_process_keys()),
        true = process_completion_verified(Process),
        8388608 = maps:get(output_limit_bytes, Process),
        33554432 = maps:get(vm_process_heap_words, Process),
        true = maps:get(vm_heap_includes_shared_binaries, Process),
        true = maps:get(crash_dumps_disabled, Process),
        false = maps:get(output_limit_exceeded, Process),
        false = maps:get(timed_out, Process),
        true = maps:get(output_digest_complete, Process),
        Bytes = maps:get(output_bytes, Process),
        Bytes = maps:get(output_hashed_bytes, Process),
        true = is_integer(Bytes) andalso Bytes >= 0 andalso Bytes =< 8388608,
        true = package_process_supervisor_valid(Process),
        true
    catch _:_ -> false end;
package_process_valid(_) -> false.

package_process_supervisor_valid(Process) ->
    Supervisor = maps:get(process_supervisor, Process),
    true = is_map(Supervisor),
    true = lists:sort(maps:keys(Supervisor)) =:= lists:sort([
        source_sha256, python_executable_sha256, python_implementation,
        python_version, console_isolation]),
    ExpectedSupervisorSha = process_supervisor_sha256(),
    ExpectedSupervisorSha = maps:get(source_sha256, Supervisor),
    PythonSha = maps:get(python_executable_sha256, Supervisor),
    true = package_digest(PythonSha),
    <<"CPython">> = maps:get(python_implementation, Supervisor),
    Version = maps:get(python_version, Supervisor),
    match = re:run(Version, <<"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$">>,
                   [{capture, none}]),
    ExpectedIsolation = process_supervisor_isolation(),
    ExpectedIsolation = maps:get(console_isolation, Supervisor),
    true = maps:get(process_supervisor_protocol_valid, Process),
    none = maps:get(process_supervisor_failure_code, Process),
    none = maps:get(process_supervisor_attestation_failure, Process),
    Reported = maps:get(process_supervisor_reported_status, Process),
    Reported = maps:get(process_supervisor_observed_status, Process),
    true = is_integer(Reported) andalso Reported >= 0 andalso Reported =< 255,
    true = maps:get(native_tree_empty, Process),
    true = maps:get(native_console_isolated, Process),
    false = maps:get(native_descendant_outlived, Process),
    false = maps:get(native_termination_requested, Process),
    true.

read_child(Path) ->
    try evidence_json_decode(execution_beam_read(Path, 16777216))
    catch _:_ -> #{invalid => true} end.

remove_report(Path) ->
    case file:delete(Path) of ok -> ok; {error, enoent} -> ok; _ -> erlang:error(stale_report_not_removed) end.

self_test() ->
    package_attempt_lifecycle_self_test(),
    AttemptNonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(
        "build/package-suite/self-test-attempts", AttemptNonce),
    RunnerInfo = compile_runner(Lease),
    Runner = maps:get(directory, RunnerInfo),
    BuildRoot = filename:join(maps:get(root, Lease), "build/dev"),
    FixtureEbin = filename:join(BuildRoot, "erlang/fixture/ebin"),
    ok = filelib:ensure_dir(filename:join(FixtureEbin, "placeholder")),
    compile_fixture(FixtureEbin),
    put(package_self_test_root, maps:get(root, Lease)),
    put(package_self_test_code_paths, [Runner, FixtureEbin]),
    try self_test_with_attempt(RunnerInfo, FixtureEbin, BuildRoot)
    after
        erase(package_self_test_code_paths),
        erase(package_self_test_root),
        ok = execution_beam_release_attempt(Lease)
    end.

package_attempt_lifecycle_self_test() ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(
        "build/package-suite/lifecycle-self-test-attempts", Nonce),
    put(package_suite_attempt_lease, Lease),
    Marker = filename:join(maps:get(root, Lease), "owned-marker"),
    ok = execution_beam_publish_new(Marker, <<"owned">>, 32),
    ok = package_release_attempt_active(),
    true = execution_beam_path_absent(maps:get(root, Lease)),
    released = get(package_suite_attempt_lease),
    ok = package_release_attempt_if_active(),
    undefined = get(package_suite_attempt_lease),
    ok.

self_test_with_attempt(RunnerInfo, FixtureEbin, BuildRoot) ->
    evidence_publication_self_test(),
    Runner = maps:get(directory, RunnerInfo),
    Nonce = <<"self-test-current-run">>,
    Unit = #{module => <<"erlang">>, function => <<"yield">>, kind => <<"test">>},
    Path = package_self_test_path("self-test-child.json"),
    Evaluation = lists:flatten(io_lib:format(
        "qualification_eunit_listener:run(~0tp,~0tp,~0tp).", [[Unit], Path, Nonce])),
    {0, Output} = run_child_evaluation(filename:absname("."),
        package_self_test_code_paths(Runner), Evaluation, 5000),
    Child = read_child(Path),
    ensure(suite_child_valid(Child, [Unit], Nonce), listener_unit_accounting),
    self_test_json_boundary(Child, [Unit], Nonce),
    empty_child_transcript_self_test(),
    Tail = output_tail(Output),
    case empty_child_transcript(Tail) of
        true -> ok;
        false ->
            io:format("empty child transcript rejected: ~p~n",
                      [console_transcript_shape(Tail)]),
            erlang:error(no_unsolicited_output)
    end,
    ensure(not suite_child_valid(Child, [Unit], <<"stale-run">>), stale_run_rejected),
    ensure(not suite_child_valid(Child#{<<"units">> => []}, [Unit], Nonce), missing_unit_rejected),
    UnknownRejected = not suite_child_valid(Child#{<<"payload">> => <<"fixture-private-marker">>}, [Unit], Nonce),
    io:format("unknown_fields_rejected=~p~n", [UnknownRejected]),
    ensure(UnknownRejected,
           unknown_secret_field_rejected),
    [Row] = maps:get(<<"units">>, Child),
    Counts = maps:get(<<"counts">>, Row),
    ZeroRow = Row#{<<"counts">> => Counts#{<<"started">> => 0, <<"completed">> => 0,
                                           <<"passed">> => 0}},
    ensure(not suite_child_valid(Child#{<<"units">> => [ZeroRow]}, [Unit], Nonce), unexecuted_unit_rejected),
    ensure(not suite_child_valid(Child#{<<"units">> => [Row, Row]}, [Unit, Unit], Nonce), duplicate_unit_rejected),
    ensure(not suite_child_valid(Child#{<<"units">> => [Row#{<<"counts">> =>
        Counts#{<<"started">> => 2, <<"completed">> => 2, <<"passed">> => 2}}]}, [Unit], Nonce),
        repeated_ordinary_test_rejected),
    {GeneratedStatus, Generated, _} = fixture_run(Runner, [fixture_unit("pass_test", test),
                                            fixture_unit("pair_test_", generator)], Nonce),
    GeneratedValid = GeneratedStatus =:= 0 andalso suite_child_valid(Generated, [fixture_unit("pass_test", test),
                                            fixture_unit("pair_test_", generator)], Nonce),
    io:format("generated_unit_counts_valid=~p~n", [GeneratedValid]),
    ensure(GeneratedValid, generator_accounting),
    ensure(suite_completed_tests(Generated) =:= 3, generator_completed_leaf_count),
    {1, Failure, FailureOutput} = fixture_run(Runner, [fixture_unit("failure_test", test)], Nonce),
    ensure(suite_child_schema_valid(Failure, [fixture_unit("failure_test", test)], Nonce), safe_failure_schema),
    ensure(not suite_child_valid(Failure, [fixture_unit("failure_test", test)], Nonce), failure_rejected),
    ensure(binary:match(output_tail(FailureOutput), <<"fixture-private-marker">>) =/= nomatch,
           stderr_secret_positive_control),
    ensure(binary:match(iolist_to_binary(json:encode(Failure)), <<"fixture-private-marker">>) =:= nomatch,
           failure_payload_not_reported),
    lists:foreach(fun(Function) ->
        Units = [fixture_unit(Function, test)],
        {1, Assertion, AssertionOutput} = fixture_run(Runner, Units, Nonce),
        ensure(suite_child_schema_valid(Assertion, Units, Nonce), assertion_failure_schema),
        ensure(binary:match(output_tail(AssertionOutput), <<"fixture-private-marker">>) =/= nomatch,
               assertion_secret_positive_control),
        ensure(binary:match(iolist_to_binary(json:encode(Assertion)), <<"fixture-private-marker">>) =:= nomatch,
               assertion_payload_not_reported),
        [RetainedFailure] = maps:get(<<"failures">>, Assertion),
        ensure(maps:get(<<"classification">>, RetainedFailure) =:= <<"assertion_failed">>,
               erlang_assertion_category_missing)
    end, ["assert_equal_test", "assert_match_test"]),
    {1, Forged, _} = fixture_run(Runner, [fixture_unit("forged_test", test)], Nonce),
    ensure(suite_child_schema_valid(Forged, [fixture_unit("forged_test", test)], Nonce),
           forged_stack_failure_accounted),
    ensure(binary:match(iolist_to_binary(json:encode(Forged)), <<"fixture_private_marker">>) =:= nomatch,
           forged_stack_payload_not_reported),
    {1, Many, _} = fixture_run(Runner, [fixture_unit("many_test_", generator)], Nonce),
    ensure(suite_child_schema_valid(Many, [fixture_unit("many_test_", generator)], Nonce), bounded_failures_schema),
    ensure(maps:get(<<"failure_count">>, Many) =:= 65 andalso
           length(maps:get(<<"failures">>, Many)) =:= 64 andalso
           maps:get(<<"failures_dropped">>, Many) =:= 1, bounded_failure_retention),
    {1, Empty, _} = fixture_run(Runner, [fixture_unit("empty_test_", generator)], Nonce),
    ensure(not suite_child_valid(Empty, [fixture_unit("empty_test_", generator)], Nonce), empty_generator_rejected),
    execution_beam_identity_self_test(RunnerInfo, FixtureEbin, BuildRoot),
    io:format("secrecy_positive_control=true sanitized_failure=true generated_leaf_counts=true failures_bounded=true~n"),
    io:format("package suite self-test ok~n").

evidence_publication_self_test() ->
    Directory = package_self_test_path("publication"),
    ok = file:make_dir(Directory),
    Target = filename:join(Directory, "concurrent.json"),
    Parent = self(),
    Start = make_ref(),
    Worker = fun(Bytes) ->
        receive Start -> ok end,
        Result = try evidence_publish_new(Target, Bytes, 1024) of
            ok -> published
        catch _:_ -> rejected end,
        Parent ! {publication_result, self(), Result}
    end,
    {First, FirstMonitor} = spawn_monitor(fun() -> Worker(<<"first">>) end),
    {Second, SecondMonitor} = spawn_monitor(fun() -> Worker(<<"second">>) end),
    First ! Start,
    Second ! Start,
    Results = [publication_self_test_result(), publication_self_test_result()],
    [published, rejected] = lists:sort(Results),
    publication_self_test_down(FirstMonitor),
    publication_self_test_down(SecondMonitor),
    Published = evidence_publication_read(Target, 1024),
    true = lists:member(Published, [<<"first">>, <<"second">>]),
    {ok, Names} = file:list_dir(Directory),
    false = lists:any(fun(Name) ->
        string:find(Name, ".pending-") =/= nomatch
    end, Names),
    Source = filename:join(Directory, "hardlink-source.json"),
    Link = filename:join(Directory, "hardlink-alias.json"),
    ok = evidence_publish_new(Source, <<"link-safe">>, 1024),
    ok = file:make_link(Source, Link),
    true = try evidence_publication_read(Source, 1024), false
           catch _:_ -> true end,
    ok = file:delete(Link),
    <<"link-safe">> = evidence_publication_read(Source, 1024),
    Replace = filename:join(Directory, "replace.json"),
    ok = evidence_publish_new(Replace, <<"old">>, 1024),
    true = try evidence_replace_locked(Replace, <<"wrong">>, <<"new">>, 1024),
               false
           catch _:_ -> true end,
    <<"old">> = evidence_publication_read(Replace, 1024),
    ok = evidence_replace_locked(Replace, <<"old">>, <<"new">>, 1024),
    <<"new">> = evidence_publication_read(Replace, 1024),
    io:format("atomic_no_replace=verified hardlink_rejected=true "
              "locked_replace=verified~n"),
    ok.

publication_self_test_result() ->
    receive
        {publication_result, _, Result} -> Result
    after 2000 -> erlang:error(publication_worker_timeout)
    end.

publication_self_test_down(Monitor) ->
    receive
        {'DOWN', Monitor, process, _, normal} -> ok;
        {'DOWN', Monitor, process, _, _} ->
            erlang:error(publication_worker_failed)
    after 2000 -> erlang:error(publication_worker_exit_unconfirmed)
    end.

empty_child_transcript_self_test() ->
    Prefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
        27, "[?9001l", 27, "[?1004l", 27, "[2J", 27, "[m", 27, "[H">>,
    Suffix = <<27, "[?25h">>,
    Valid = <<Prefix/binary, 27, "]0;fixed-tool.exe", 7, Suffix/binary>>,
    ensure(empty_child_transcript(<<>>), empty_transcript_rejected),
    ensure(empty_child_transcript(Valid), console_envelope_rejected),
    ensure(not empty_child_transcript(
        <<Prefix/binary, "output", 27, "]0;fixed-tool.exe", 7,
          Suffix/binary>>), unsolicited_text_accepted),
    ensure(not empty_child_transcript(
        <<Prefix/binary, 27, "]0;bad", 10, "title", 7, Suffix/binary>>),
        control_title_accepted),
    ensure(not empty_child_transcript(
        <<Prefix/binary, 27, "]0;fixed-tool.exe", 7>>),
        missing_console_suffix_accepted),
    io:format("empty_console_envelope_controls=5 passed=true~n").

self_test_json_boundary(Child, Units, Nonce) ->
    Path = package_self_test_path("hostile-child.json"),
    <<${, Rest/binary>> = iolist_to_binary(json:encode(Child)),
    Size = byte_size(Rest),
    <<WithoutEnd:(Size-1)/binary, $}>> = Rest,
    Variants = [
        <<"{\"run_nonce\":\"stale-run\",", Rest/binary>>,
        <<"{\"run_\\u006eonce\":\"stale-run\",", Rest/binary>>,
        <<${, WithoutEnd/binary, ",\"run_nonce\":\"stale-run\"}">>,
        <<${, WithoutEnd/binary, ",\"run_\\u006eonce\":\"stale-run\"}">>,
        binary:replace(<<${, Rest/binary>>, <<"\"passed\":1">>,
                       <<"\"passed\":0,\"passed\":1">>),
        binary:replace(<<${, Rest/binary>>, <<"\"passed\":1">>,
                       <<"\"passed\":1,\"passed\":0">>)
    ],
    Rejected = [begin
        ok = file:write_file(Path, Bytes),
        not suite_child_valid(read_child(Path), Units, Nonce)
    end || Bytes <- Variants],
    remove_report(Path),
    io:format("duplicate_json_keys_rejected=~p~n", [lists:all(fun(V) -> V end, Rejected)]),
    ensure(lists:all(fun(V) -> V end, Rejected), duplicate_json_keys_rejected).

fixture_unit(Function, Kind) ->
    #{module => <<"qualification_eunit_fixture">>, function => list_to_binary(Function),
      kind => atom_to_binary(Kind)}.

fixture_run(Runner, Units, Nonce) ->
    Path = package_self_test_path("fixture-child.json"),
    remove_report(Path),
    Evaluation = lists:flatten(io_lib:format(
        "qualification_eunit_listener:run(~0tp,~0tp,~0tp).", [Units, Path, Nonce])),
    {Status, Output} = run_child_evaluation(filename:absname("."),
        package_self_test_code_paths(Runner), Evaluation, 10000),
    {Status, read_child(Path), Output}.

compile_fixture(Runner) ->
    Path = filename:join(Runner, "qualification_eunit_fixture.erl"),
    Source = iolist_to_binary(
        "-module(qualification_eunit_fixture).\n"
        "-include_lib(\"stdlib/include/assert.hrl\").\n"
        "-export([pass_test/0,failure_test/0,forged_test/0,pair_test_/0,many_test_/0,empty_test_/0,"
        "assert_equal_test/0,assert_match_test/0]).\n"
        "pass_test()->ok.\n"
        "failure_test()->Marker = <<\"fixture-private-marker\">>,"
        "io:put_chars(Marker),io:format(standard_error,\"~s~n\",[Marker]),"
        "erlang:error({badmatch,{Marker,self(),make_ref()}}).\n"
        "assert_equal_test()->Marker = <<\"fixture-private-marker\">>,"
        "io:format(standard_error,\"~s~n\",[Marker]),"
        "?assertEqual(expected,private_value()).\n"
        "assert_match_test()->Marker = <<\"fixture-private-marker\">>,"
        "io:format(standard_error,\"~s~n\",[Marker]),"
        "?assertMatch({expected,_},private_value()).\n"
        "private_value()->{<<\"fixture-private-marker\">>,self(),make_ref()}.\n"
        "forged_test()->erlang:raise(error,<<\"fixture_private_marker\">>,"
        "[{fixture_private_marker,main,0,[]},{erlang,fixture_private_marker,0,[]}]).\n"
        "pair_test_()->[{test,?MODULE,pass_test},{test,?MODULE,pass_test}].\n"
        "many_test_()->lists:duplicate(65,{test,?MODULE,failure_test}).\n"
        "empty_test_()->[].\n"),
    ok = execution_beam_publish_new(Path, Source, 1048576),
    {ok, Module, Binary, []} = compile:file(Path, [binary, return_errors, return_warnings]),
    ok = execution_beam_publish_new(
        filename:join(Runner, atom_to_list(Module) ++ ".beam"), Binary, 4194304).

package_self_test_path(Name) ->
    filename:join(get(package_self_test_root), Name).

package_self_test_code_paths(Runner) ->
    case get(package_self_test_code_paths) of
        Paths when is_list(Paths), Paths =/= [] -> Paths;
        _ -> [Runner]
    end.

execution_beam_identity_self_test(RunnerInfo, FixtureEbin, BuildRoot) ->
    Runner = maps:get(directory, RunnerInfo),
    RunnerSha = maps:get(sha256, RunnerInfo),
    Read = fun(Path) -> execution_beam_read(Path, 4194304) end,
    Inventory = execution_beam_inventory([FixtureEbin], BuildRoot, Read),
    InventorySha = maps:get(sha256, Inventory),
    Units = [fixture_unit("pass_test", test)],
    SuccessPath = package_self_test_path("attested-success.json"),
    Lease = maps:get(lease, RunnerInfo),
    SuccessEval = execution_beam_bootstrap_evaluation(Lease, run_attested,
        [Units, SuccessPath, <<"attested-success">>, RunnerSha,
         BuildRoot, Inventory], RunnerSha, InventorySha, 126),
    {0, SuccessProcess} = run_child_evaluation(filename:absname("."),
        [Runner, FixtureEbin], SuccessEval, 10000),
    ensure(process_status_verified(0, 0, SuccessProcess),
           attested_child_process_unverified),
    Success = read_child(SuccessPath),
    ensure(suite_attested_child_valid(Success, Units, <<"attested-success">>,
        RunnerSha, InventorySha), loaded_beam_identity_missing),
    BeamPath = filename:join(FixtureEbin, "qualification_eunit_fixture.beam"),
    Original = execution_beam_read(BeamPath, 4194304),
    OriginalCopyPath = BeamPath ++ ".original",
    ok = execution_beam_publish_new(OriginalCopyPath, Original, 4194304),
    HardlinkPath = package_self_test_path("attested-hardlink-mutant.json"),
    try
        ok = file:delete(BeamPath),
        ok = file:make_link(OriginalCopyPath, BeamPath),
        HardlinkEval = execution_beam_bootstrap_evaluation(Lease, run_attested,
            [Units, HardlinkPath, <<"attested-hardlink">>, RunnerSha,
             BuildRoot, Inventory], RunnerSha, InventorySha, 126),
        {1, HardlinkProcess} = run_child_evaluation(filename:absname("."),
            [Runner, FixtureEbin], HardlinkEval, 10000),
        ensure(process_status_verified(1, 1, HardlinkProcess),
               hardlink_child_process_unverified)
    after
        ok = delete_if_present(BeamPath),
        ok = file:write_file(BeamPath, Original, [binary, exclusive])
    end,
    HardlinkChild = read_child(HardlinkPath),
    ensure(suite_attested_child_schema_valid(HardlinkChild, Units,
        <<"attested-hardlink">>, RunnerSha, InventorySha),
        hardlink_child_schema_missing),
    ensure(not suite_attested_child_valid(HardlinkChild, Units,
        <<"attested-hardlink">>, RunnerSha, InventorySha),
        hardlink_execution_false_green),
    false = maps:get(<<"loaded_beams_verified">>, maps:get(
        <<"execution_beam_identity">>, HardlinkChild)),
    MutantSource = filename:join(FixtureEbin, "inventory_swap_mutant.erl"),
    ok = execution_beam_publish_new(MutantSource,
        <<"-module(qualification_eunit_fixture).\n"
          "-export([pass_test/0]).\n"
          "pass_test()->P=code:which(?MODULE),"
          "{ok,B}=file:read_file(P++\".original\"),"
          "ok=file:write_file(P,B),ok.\n">>, 1048576),
    {ok, qualification_eunit_fixture, Mutant, []} = compile:file(
        MutantSource, [binary, return_errors, return_warnings]),
    true = crypto:hash(sha256, Original) =/= crypto:hash(sha256, Mutant),
    MutantPath = package_self_test_path("attested-inventory-mutant.json"),
    try
        ok = file:write_file(BeamPath, Mutant),
        MutantEval = execution_beam_bootstrap_evaluation(Lease, run_attested,
            [Units, MutantPath, <<"attested-mutant">>, RunnerSha,
             BuildRoot, Inventory], RunnerSha, InventorySha, 126),
        {1, MutantProcess} = run_child_evaluation(filename:absname("."),
            [Runner, FixtureEbin], MutantEval, 10000),
        ensure(process_status_verified(1, 1, MutantProcess),
               mutant_child_process_unverified),
        Original = execution_beam_read(BeamPath, 4194304)
    after ok = file:write_file(BeamPath, Original) end,
    MutantChild = read_child(MutantPath),
    ensure(suite_attested_child_schema_valid(MutantChild, Units,
        <<"attested-mutant">>, RunnerSha, InventorySha),
        mutant_child_schema_missing),
    ensure(not suite_attested_child_valid(MutantChild, Units,
        <<"attested-mutant">>, RunnerSha, InventorySha),
        inventory_swap_restore_false_green),
    MutantAttestation = maps:get(<<"execution_beam_identity">>, MutantChild),
    false = maps:get(<<"loaded_beams_verified">>, MutantAttestation),
    RunnerBeamPath = maps:get(beam_path, RunnerInfo),
    RunnerBinary = maps:get(binary, RunnerInfo),
    RunnerMutantPath = package_self_test_path("attested-runner-mutant.json"),
    try
        ok = file:write_file(RunnerBeamPath, <<"not-a-beam">>),
        RunnerMutantEval = execution_beam_bootstrap_evaluation(Lease, run_attested,
            [Units, RunnerMutantPath, <<"runner-mutant">>, RunnerSha,
             BuildRoot, Inventory], RunnerSha, InventorySha, 126),
        {126, RunnerMutantProcess} = run_child_evaluation(filename:absname("."),
            [Runner, FixtureEbin], RunnerMutantEval, 10000),
        ensure(process_status_verified(126, 126, RunnerMutantProcess),
               runner_mutant_process_unverified)
    after ok = file:write_file(RunnerBeamPath, RunnerBinary) end,
    ensure(not filelib:is_regular(RunnerMutantPath),
           runner_swap_reached_listener),
    Restored = execution_beam_inventory([FixtureEbin], BuildRoot, Read),
    InventorySha = maps:get(sha256, Restored),
    io:format("execution_beam_identity=verified hardlink_swap=rejected "
              "inventory_swap_restore=rejected runner_hash_swap=rejected "
              "loaded_count=~B~n",
              [maps:get(<<"loaded_beam_count">>, maps:get(
                  <<"execution_beam_identity">>, Success))]),
    ok.

delete_if_present(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(self_test_cleanup_failed)
    end.

empty_child_transcript(<<>>) -> true;
empty_child_transcript(Bytes) when byte_size(Bytes) =< 8192 ->
    WindowsPrefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
        27, "[?9001l", 27, "[?1004l", 27, "[2J", 27, "[m", 27, "[H">>,
    WindowsSuffix = <<27, "[?25h">>,
    LegacyPrefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
        27, "[2J", 27, "[m", 27, "[H">>,
    LegacySuffix = <<27, "[?25h", 27, "[?9001l", 27, "[?1004l">>,
    title_only_console_envelope(Bytes, WindowsPrefix, WindowsSuffix) orelse
        title_only_console_envelope(Bytes, LegacyPrefix, LegacySuffix);
empty_child_transcript(_) -> false.

title_only_console_envelope(Bytes, Prefix, Suffix) ->
    PrefixSize = byte_size(Prefix),
    SuffixSize = byte_size(Suffix),
    case Bytes of
        <<Prefix:PrefixSize/binary, 27, "]0;", Rest/binary>> ->
            case binary:match(Rest, <<7>>) of
                {TitleSize, 1} when TitleSize > 0, TitleSize =< 4096 ->
                    RemainingSize = byte_size(Rest) - TitleSize - 1,
                    Title = binary:part(Rest, 0, TitleSize),
                    Remaining = binary:part(Rest, TitleSize + 1,
                                            RemainingSize),
                    RemainingSize =:= SuffixSize andalso
                        Remaining =:= Suffix andalso safe_console_title(Title);
                _ -> false
            end;
        _ -> false
    end.

safe_console_title(Title) ->
    lists:all(fun(Byte) -> Byte >= 32 andalso Byte =/= 127 end,
              binary_to_list(Title)).

console_transcript_shape(Bytes) ->
    Prefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
               27, "[2J", 27, "[m", 27, "[H">>,
    Suffix = <<27, "[?25h", 27, "[?9001l", 27, "[?1004l">>,
    #{bytes => byte_size(Bytes),
      sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase),
      escapes => length(binary:matches(Bytes, <<27>>)),
      carriage_returns => length(binary:matches(Bytes, <<13>>)),
      line_feeds => length(binary:matches(Bytes, <<10>>)),
      bells => length(binary:matches(Bytes, <<7>>)),
      known_prefix => binary:match(Bytes, Prefix) =:= {0, byte_size(Prefix)},
      control_segments => console_control_segments(Bytes, 0),
      known_suffix => case byte_size(Bytes) >= byte_size(Suffix) of
          true -> binary:part(Bytes, byte_size(Bytes) - byte_size(Suffix),
                              byte_size(Suffix)) =:= Suffix;
          false -> false
      end}.

console_control_segments(<<>>, _) -> [];
console_control_segments(Bytes, Count) when Count >= 32 ->
    [#{kind => segment_limit, bytes => byte_size(Bytes)}];
console_control_segments(<<27, "[?9001h", Rest/binary>>, Count) ->
    [mode_9001_on | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[?1004h", Rest/binary>>, Count) ->
    [mode_1004_on | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[?25l", Rest/binary>>, Count) ->
    [cursor_hidden | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[2J", Rest/binary>>, Count) ->
    [screen_cleared | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[m", Rest/binary>>, Count) ->
    [attributes_reset | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[H", Rest/binary>>, Count) ->
    [cursor_home | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[?25h", Rest/binary>>, Count) ->
    [cursor_visible | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[?9001l", Rest/binary>>, Count) ->
    [mode_9001_off | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "[?1004l", Rest/binary>>, Count) ->
    [mode_1004_off | console_control_segments(Rest, Count + 1)];
console_control_segments(<<27, "]0;", Rest/binary>>, Count) ->
    case binary:match(Rest, <<7>>) of
        {TitleBytes, 1} ->
            Following = binary:part(Rest, TitleBytes + 1,
                                    byte_size(Rest) - TitleBytes - 1),
            [#{kind => title, bytes => TitleBytes}
             | console_control_segments(Following, Count + 1)];
        nomatch -> [#{kind => unterminated_title, bytes => byte_size(Rest)}]
    end;
console_control_segments(Bytes, _) ->
    [#{kind => unknown, bytes => byte_size(Bytes),
       sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase)}].

ensure(true, _) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
