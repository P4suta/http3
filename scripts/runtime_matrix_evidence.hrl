%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_RUNTIME_MATRIX_EVIDENCE_HRL).
-define(HTTP_RUNTIME_MATRIX_EVIDENCE_HRL, true).
-compile({nowarn_unused_function, [
    {runtime_matrix_directory, 2},
    {runtime_matrix_verify, 1},
    {runtime_matrix_read, 2}
]}).
-include("suite_evidence.hrl").
-include("suite_discovery.hrl").
-include("fresh_build_identity.hrl").
-include("json_evidence.hrl").
-include_lib("kernel/include/file.hrl").

runtime_matrix_package_valid(Report, Manifest, Row, Catalog, Identity) ->
    try
        true = suite_exact_keys(Report, [schema, status, package, shareable, scope,
            report_kind, configured_modules, configured_units, suite_inventory,
            counts_state, completed_tests, skipped_tests, build_identity,
            runner_sha256, execution_beam_inventory_sha256,
            loaded_beam_sha256, loaded_beam_count,
            child_exit_status, child, process, replay,
            evidence_identity, execution_environment]),
        3 = maps:get(<<"schema">>, Report),
        <<"package_suite">> = maps:get(<<"report_kind">>, Report),
        <<"Ready">> = maps:get(<<"status">>, Report),
        true = maps:get(<<"shareable">>, Report),
        <<"all source-discovered EUnit tests and generators">> = maps:get(<<"scope">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Target = maps:get(target, Row),
        Target = maps:get(<<"package">>, Report),
        0 = maps:get(<<"child_exit_status">>, Report),
        Replay = runtime_matrix_replay(Target),
        Replay = maps:get(<<"replay">>, Report),
        Inventory = maps:get(inventory, Catalog),
        Inventory = maps:get(<<"suite_inventory">>, Report),
        true = suite_inventory_document_valid(Inventory),
        Modules = suite_inventory_document_modules(Inventory),
        Modules = maps:get(<<"configured_modules">>, Report),
        Units = suite_inventory_document_units(Inventory),
        true = length(Units) > 0 andalso length(Units) =< 10000,
        true = length(Units) =:= maps:get(<<"configured_units">>, Report),
        Child = maps:get(<<"child">>, Report),
        Nonce = maps:get(<<"run_nonce">>, Child),
        true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32 andalso
               re:run(Nonce, <<"^[0-9A-Fa-f]{32}$">>, [{capture, none}]) =:= match,
        RunnerSha = maps:get(<<"runner_sha256">>, Report),
        BeamInventorySha = maps:get(
            <<"execution_beam_inventory_sha256">>, Report),
        true = suite_attested_child_valid(
            Child, Units, Nonce, RunnerSha, BeamInventorySha),
        Counts = suite_attested_test_counts(
            Child, Units, Nonce, RunnerSha, BeamInventorySha),
        <<"verified">> = maps:get(<<"counts_state">>, Report),
        Completed = maps:get(completed, Counts),
        Completed = maps:get(<<"completed_tests">>, Report),
        Skipped = maps:get(skipped, Counts),
        Skipped = maps:get(<<"skipped_tests">>, Report),
        0 = maps:get(<<"skipped_tests">>, Report),
        true = runtime_matrix_lower_hex(RunnerSha),
        true = runtime_matrix_lower_hex(BeamInventorySha),
        BeamIdentity = maps:get(<<"execution_beam_identity">>, Child),
        LoadedSha = maps:get(<<"loaded_beam_sha256">>, BeamIdentity),
        LoadedSha = maps:get(<<"loaded_beam_sha256">>, Report),
        true = runtime_matrix_lower_hex(LoadedSha),
        LoadedCount = maps:get(<<"loaded_beam_count">>, BeamIdentity),
        LoadedCount = maps:get(<<"loaded_beam_count">>, Report),
        true = is_integer(LoadedCount) andalso LoadedCount > 0
            andalso LoadedCount =< 20000,
        Process = maps:get(<<"process">>, Report),
        true = runtime_matrix_process_valid(Process),
        0 = maps:get(<<"process_supervisor_reported_status">>, Process),
        Runtime = maps:get(<<"execution_environment">>, Report),
        true = runtime_matrix_environment_valid(Runtime, Row),
        Manifest = maps:get(<<"build_identity">>, Report),
        runtime_matrix_build_valid(Manifest, Target, Catalog, Runtime)
    catch _:_ -> false end.

runtime_matrix_process_valid(Process) ->
    true = suite_exact_keys(Process, runtime_matrix_process_keys()),
    true = runtime_matrix_process_supervisor_valid(Process),
    true = maps:get(<<"child_exit_observed">>, Process),
    true = maps:get(<<"crash_dumps_disabled">>, Process),
    true = maps:get(<<"vm_heap_includes_shared_binaries">>, Process),
    false = maps:get(<<"output_limit_exceeded">>, Process),
    false = maps:get(<<"timed_out">>, Process),
    33554432 = maps:get(<<"vm_process_heap_words">>, Process),
    8388608 = maps:get(<<"output_limit_bytes">>, Process),
    true = maps:get(<<"output_digest_complete">>, Process),
    Bytes = maps:get(<<"output_bytes">>, Process),
    Bytes = maps:get(<<"output_hashed_bytes">>, Process),
    is_integer(Bytes) andalso Bytes >= 0 andalso Bytes =< 8388608.

runtime_matrix_process_document_safe(Process) ->
    try
        true = suite_exact_keys(Process, runtime_matrix_process_keys()),
        true = runtime_matrix_process_supervisor_document_safe(Process),
        8388608 = maps:get(<<"output_limit_bytes">>, Process),
        33554432 = maps:get(<<"vm_process_heap_words">>, Process),
        DigestComplete = maps:get(<<"output_digest_complete">>, Process),
        LimitExceeded = maps:get(<<"output_limit_exceeded">>, Process),
        true = is_boolean(DigestComplete),
        true = is_boolean(LimitExceeded),
        true = maps:get(<<"vm_heap_includes_shared_binaries">>, Process),
        true = maps:get(<<"crash_dumps_disabled">>, Process),
        true = is_boolean(maps:get(<<"timed_out">>, Process)),
        true = is_boolean(maps:get(<<"child_exit_observed">>, Process)),
        Bytes = maps:get(<<"output_bytes">>, Process),
        Hashed = maps:get(<<"output_hashed_bytes">>, Process),
        true = is_integer(Bytes) andalso Bytes >= 0 andalso Bytes =< 16777216,
        true = is_integer(Hashed) andalso Hashed >= 0 andalso Hashed =< 8388608,
        true = Hashed =< Bytes,
        true = case LimitExceeded of
            true -> not DigestComplete andalso Hashed =:= 8388608 andalso Bytes > Hashed;
            false -> DigestComplete andalso Hashed =:= Bytes
        end,
        true
    catch _:_ -> false end.

runtime_matrix_process_keys() ->
    [output_bytes, output_hashed_bytes, output_limit_bytes,
     output_digest_complete, output_limit_exceeded, vm_process_heap_words,
     vm_heap_includes_shared_binaries, crash_dumps_disabled, timed_out,
     child_exit_observed, process_supervisor,
     process_supervisor_protocol_valid, process_supervisor_failure_code,
     process_supervisor_attestation_failure, process_supervisor_reported_status,
     process_supervisor_observed_status, native_tree_empty,
     native_console_isolated,
     native_descendant_outlived, native_termination_requested].

runtime_matrix_process_supervisor_sha256() ->
    binary:encode_hex(crypto:hash(
        sha256, fresh_read("scripts/process_supervisor.py")), lowercase).

runtime_matrix_process_supervisor_valid(Process) ->
    true = runtime_matrix_process_supervisor_document_safe(Process),
    true = maps:get(<<"process_supervisor_protocol_valid">>, Process),
    <<"none">> = maps:get(<<"process_supervisor_failure_code">>, Process),
    <<"none">> = maps:get(<<"process_supervisor_attestation_failure">>, Process),
    true = maps:get(<<"native_tree_empty">>, Process),
    true = maps:get(<<"native_console_isolated">>, Process),
    false = maps:get(<<"native_descendant_outlived">>, Process),
    false = maps:get(<<"native_termination_requested">>, Process),
    true.

runtime_matrix_process_supervisor_document_safe(Process) ->
    Identity = maps:get(<<"process_supervisor">>, Process),
    true = suite_exact_keys(Identity, [source_sha256, python_executable_sha256,
        python_implementation, python_version, console_isolation]),
    ExpectedSource = runtime_matrix_process_supervisor_sha256(),
    ExpectedSource = maps:get(<<"source_sha256">>, Identity),
    true = runtime_matrix_hex(maps:get(<<"python_executable_sha256">>, Identity)),
    <<"CPython">> = maps:get(<<"python_implementation">>, Identity),
    true = lists:member(maps:get(<<"console_isolation">>, Identity),
                        [<<"conpty-v1">>, <<"session-v1">>]),
    Version = maps:get(<<"python_version">>, Identity),
    match = re:run(Version, <<"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$">>,
                   [{capture, none}]),
    true = is_boolean(maps:get(<<"process_supervisor_protocol_valid">>, Process)),
    true = lists:member(maps:get(<<"process_supervisor_failure_code">>, Process),
                        [<<"none">>, <<"child_start_failed">>,
                         <<"child_wait_failed">>, <<"group_query_failed">>,
                         <<"group_termination_failed">>, <<"job_assign_failed">>,
                         <<"job_create_failed">>, <<"job_query_failed">>,
                         <<"job_resume_failed">>, <<"job_set_limits_failed">>,
                          <<"job_termination_failed">>,
                          <<"console_attribute_failed">>,
                          <<"console_child_start_failed">>,
      <<"console_create_failed">>,
      <<"console_output_join_failed">>,
      <<"console_output_setup_failed">>,
      <<"console_pipe_failed">>,
      <<"console_prestart_cleanup_failed">>,
      <<"console_prestart_setup_failed">>,
      <<"console_isolation_unconfirmed">>,
      <<"prestart_reap_unconfirmed">>,
      <<"group_reap_unconfirmed">>,
                          <<"protocol_failure">>,
                          <<"source_identity_failed">>, <<"supervisor_deadline">>,
                          <<"supervisor_output_limit">>, <<"supervisor_failure">>]),
    true = lists:member(
        maps:get(<<"process_supervisor_attestation_failure">>, Process),
        [<<"none">>, <<"protocol_invalid">>, <<"identity_mismatch">>,
         <<"final_missing">>, <<"status_mismatch">>, <<"tree_not_empty">>,
         <<"console_isolation_unconfirmed">>]),
    Reported = maps:get(<<"process_supervisor_reported_status">>, Process),
    Observed = maps:get(<<"process_supervisor_observed_status">>, Process),
    true = is_integer(Reported) andalso Reported >= -1 andalso Reported =< 255,
    true = is_integer(Observed) andalso Observed >= -1 andalso Observed =< 255,
    true = Reported =:= Observed,
    true = is_boolean(maps:get(<<"native_tree_empty">>, Process)),
    true = is_boolean(maps:get(<<"native_console_isolated">>, Process)),
    true = is_boolean(maps:get(<<"native_descendant_outlived">>, Process)),
    true = is_boolean(maps:get(<<"native_termination_requested">>, Process)),
    true.

runtime_matrix_process_fixture(Process) ->
    Process#{process_supervisor => #{
        source_sha256 => runtime_matrix_process_supervisor_sha256(),
        python_executable_sha256 => binary:copy(<<"a">>, 64),
        python_implementation => <<"CPython">>, python_version => <<"3.13.7">>,
        console_isolation => case os:type() of
            {win32, _} -> <<"conpty-v1">>;
            _ -> <<"session-v1">>
        end},
      process_supervisor_protocol_valid => true,
      process_supervisor_failure_code => none,
      process_supervisor_attestation_failure => none,
      process_supervisor_reported_status => 0,
      process_supervisor_observed_status => 0,
      native_tree_empty => true, native_console_isolated => true,
      native_descendant_outlived => false,
      native_termination_requested => false}.

runtime_matrix_environment_valid(Runtime, Row) ->
    true = suite_exact_keys(Runtime, [otp_version, erts_version, os_family, os_name,
                                    system_architecture, word_size]),
    {Family, Name} = case maps:get(os, Row) of
        <<"ubuntu-24.04">> -> {<<"unix">>, <<"linux">>};
        <<"macos-15">> -> {<<"unix">>, <<"darwin">>};
        <<"windows-2025">> -> {<<"win32">>, <<"nt">>}
    end,
    Family = maps:get(<<"os_family">>, Runtime),
    Name = maps:get(<<"os_name">>, Runtime),
    true = lists:member(maps:get(<<"word_size">>, Runtime), [4, 8]),
    Version = maps:get(<<"otp_version">>, Runtime),
    true = runtime_matrix_version(Version),
    ExpectedVersion = case maps:get(otp, Row) of
        28 -> <<"28.5.0.6">>;
        29 -> <<"29.0.5">>
    end,
    ExpectedVersion = Version,
    true = runtime_matrix_version(maps:get(<<"erts_version">>, Runtime)),
    Architecture = maps:get(<<"system_architecture">>, Runtime),
    Pattern = case Name of
        <<"linux">> -> <<"^(x86_64|aarch64|i[3-6]86)-(pc|unknown)-linux-(gnu|musl)$">>;
        <<"darwin">> -> <<"^(x86_64|aarch64|arm64)-apple-darwin[0-9.]*$">>;
        <<"nt">> -> <<"^(win32|x86_64-pc-windows)$">>
    end,
    is_binary(Architecture) andalso byte_size(Architecture) =< 128 andalso
    re:run(Architecture, Pattern, [{capture, none}]) =:= match.

runtime_matrix_version(Version) ->
    is_binary(Version) andalso byte_size(Version) =< 64 andalso
    re:run(Version, <<"^[0-9]+(?:\\.[0-9]+)*$">>, [{capture, none}]) =:= match.

runtime_matrix_build_valid(Build, Target, Catalog, Runtime) ->
    true = suite_exact_keys(Build, [schema, package, source_sha256, source_files,
        artifact_sha256, artifact_files, toolchain, build_nonce,
        prebuild_profile_state]),
    3 = maps:get(<<"schema">>, Build),
    Target = maps:get(<<"package">>, Build),
    true = maps:get(<<"source_sha256">>, Build) =:= maps:get(source_sha256, Catalog),
    true = maps:get(<<"source_files">>, Build) =:= maps:get(source_files, Catalog),
    true = runtime_matrix_hex(maps:get(<<"artifact_sha256">>, Build)),
    Files = maps:get(<<"artifact_files">>, Build),
    true = is_integer(Files) andalso Files > 0 andalso Files =< 1000000,
    true = runtime_matrix_build_nonce(
        maps:get(<<"build_nonce">>, Build)),
    <<"absent">> = maps:get(<<"prebuild_profile_state">>, Build),
    Tools = maps:get(<<"toolchain">>, Build),
    true = suite_exact_keys(Tools, [runtime, gleam, rebar3]),
    Runtime = maps:get(<<"runtime">>, Tools),
    lists:all(fun({Name, Version}) ->
        Tool = maps:get(Name, Tools),
        suite_exact_keys(Tool, [declared_version, executable_sha256]) andalso
        maps:get(<<"declared_version">>, Tool) =:= Version andalso
        runtime_matrix_hex(maps:get(<<"executable_sha256">>, Tool))
    end, [{<<"gleam">>, <<"1.18.1">>}, {<<"rebar3">>, <<"3.27.0">>}]).

runtime_matrix_build_document_safe(Build, Target, Runtime) ->
    try
        true = suite_exact_keys(Build, [schema, package, source_sha256, source_files,
            artifact_sha256, artifact_files, toolchain, build_nonce,
            prebuild_profile_state]),
        3 = maps:get(<<"schema">>, Build),
        Target = maps:get(<<"package">>, Build),
        true = runtime_matrix_hex(maps:get(<<"source_sha256">>, Build)),
        true = runtime_matrix_hex(maps:get(<<"artifact_sha256">>, Build)),
        SourceFiles = maps:get(<<"source_files">>, Build),
        ArtifactFiles = maps:get(<<"artifact_files">>, Build),
        true = is_integer(SourceFiles) andalso SourceFiles > 0 andalso
               SourceFiles =< 1000000,
        true = is_integer(ArtifactFiles) andalso ArtifactFiles > 0 andalso
               ArtifactFiles =< 1000000,
        true = runtime_matrix_build_nonce(
            maps:get(<<"build_nonce">>, Build)),
        <<"absent">> = maps:get(<<"prebuild_profile_state">>, Build),
        Tools = maps:get(<<"toolchain">>, Build),
        true = suite_exact_keys(Tools, [runtime, gleam, rebar3]),
        Runtime = maps:get(<<"runtime">>, Tools),
        true = lists:all(fun({Name, Version}) ->
            Tool = maps:get(Name, Tools),
            suite_exact_keys(Tool, [declared_version, executable_sha256]) andalso
            maps:get(<<"declared_version">>, Tool) =:= Version andalso
            runtime_matrix_hex(maps:get(<<"executable_sha256">>, Tool))
        end, [{<<"gleam">>, <<"1.18.1">>}, {<<"rebar3">>, <<"3.27.0">>}]),
        true
    catch _:_ -> false end.

runtime_matrix_build_nonce(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 32 andalso
        re:run(Value, <<"^[0-9a-f]{32}$">>, [{capture, none}]) =:= match.

runtime_matrix_failed_report_safe(Report, Row, Identity) ->
    try
        3 = maps:get(<<"schema">>, Report),
        <<"package_suite">> = maps:get(<<"report_kind">>, Report),
        <<"Failed">> = maps:get(<<"status">>, Report),
        true = maps:get(<<"shareable">>, Report),
        ExpectedTarget = maps:get(target, Row),
        ExpectedTarget = maps:get(<<"package">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Runtime = maps:get(<<"execution_environment">>, Report),
        true = runtime_matrix_environment_valid(Runtime, Row),
        Keys = lists:sort(maps:keys(Report)),
        Minimal = lists:sort([<<"schema">>, <<"report_kind">>, <<"package">>,
            <<"status">>, <<"shareable">>, <<"scope">>,
            <<"evidence_identity">>, <<"execution_environment">>,
            <<"suite_inventory">>, <<"configured_modules">>,
            <<"configured_units">>, <<"counts_state">>,
            <<"completed_tests">>, <<"skipped_tests">>,
            <<"failure_classification">>, <<"failure">>, <<"replay">>]),
        Full = lists:sort([<<"schema">>, <<"report_kind">>, <<"status">>,
            <<"package">>, <<"shareable">>, <<"scope">>,
            <<"configured_modules">>, <<"configured_units">>,
            <<"suite_inventory">>, <<"counts_state">>,
            <<"completed_tests">>, <<"skipped_tests">>,
            <<"build_identity">>, <<"runner_sha256">>,
            <<"execution_beam_inventory_sha256">>,
            <<"loaded_beam_sha256">>, <<"loaded_beam_count">>,
            <<"child_exit_status">>, <<"child">>, <<"process">>, <<"replay">>,
            <<"evidence_identity">>, <<"execution_environment">>]),
        FullWithFailure = lists:sort([<<"failure">> | Full]),
        case Keys of
            Minimal -> runtime_matrix_failed_minimal_safe(Report);
            Full -> runtime_matrix_failed_full_safe(Report, Row, Runtime, false);
            FullWithFailure -> runtime_matrix_failed_full_safe(Report, Row, Runtime, true);
            _ -> false
        end
    catch _:_ -> false end.

runtime_matrix_failed_minimal_safe(Report) ->
    <<"all source-discovered EUnit tests and generators">> =
        maps:get(<<"scope">>, Report),
    null = maps:get(<<"suite_inventory">>, Report),
    null = maps:get(<<"configured_modules">>, Report),
    null = maps:get(<<"configured_units">>, Report),
    <<"unavailable">> = maps:get(<<"counts_state">>, Report),
    null = maps:get(<<"completed_tests">>, Report),
    null = maps:get(<<"skipped_tests">>, Report),
    true = runtime_matrix_package_failure_classification(
        maps:get(<<"failure_classification">>, Report)),
    true = runtime_matrix_diagnostic_safe(maps:get(<<"failure">>, Report)),
    Replay = runtime_matrix_replay(maps:get(<<"package">>, Report)),
    Replay = maps:get(<<"replay">>, Report),
    true.

runtime_matrix_failed_report_bound(Report, Manifest, Row, Catalog, Identity) ->
    try
        true = runtime_matrix_failed_report_safe(Report, Row, Identity),
        Manifest = maps:get(<<"build_identity">>, Report),
        Runtime = maps:get(<<"execution_environment">>, Report),
        true = runtime_matrix_build_valid(Manifest, maps:get(target, Row), Catalog, Runtime),
        Inventory = maps:get(inventory, Catalog),
        Inventory = maps:get(<<"suite_inventory">>, Report),
        true = suite_inventory_document_valid(Inventory),
        Modules = suite_inventory_document_modules(Inventory),
        Modules = maps:get(<<"configured_modules">>, Report),
        Units = suite_inventory_document_units(Inventory),
        UnitCount = length(Units),
        UnitCount = maps:get(<<"configured_units">>, Report),
        true
    catch _:_ -> false end.

runtime_matrix_failed_full_safe(Report, Row, Runtime, HasFailure) ->
    <<"all source-discovered EUnit tests and generators">> = maps:get(<<"scope">>, Report),
    Target = maps:get(target, Row),
    Target = maps:get(<<"package">>, Report),
    Replay = runtime_matrix_replay(Target),
    Replay = maps:get(<<"replay">>, Report),
    RunnerSha = maps:get(<<"runner_sha256">>, Report),
    BeamInventorySha = maps:get(
        <<"execution_beam_inventory_sha256">>, Report),
    true = runtime_matrix_lower_hex(RunnerSha),
    true = runtime_matrix_lower_hex(BeamInventorySha),
    Exit = maps:get(<<"child_exit_status">>, Report),
    true = is_integer(Exit) andalso Exit >= 0 andalso Exit =< 255,
    Process = maps:get(<<"process">>, Report),
    true = runtime_matrix_process_document_safe(Process),
    Exit = maps:get(<<"process_supervisor_reported_status">>, Process),
    Exit = maps:get(<<"process_supervisor_observed_status">>, Process),
    true = runtime_matrix_build_document_safe(maps:get(<<"build_identity">>, Report),
                                              Target, Runtime),
    Inventory = maps:get(<<"suite_inventory">>, Report),
    true = suite_inventory_document_valid(Inventory),
    Modules = maps:get(<<"configured_modules">>, Report),
    Modules = suite_inventory_document_modules(Inventory),
    true = length(Modules) > 0 andalso length(Modules) =< 10000,
    Units = suite_inventory_document_units(Inventory),
    true = maps:get(<<"configured_units">>, Report) =:= length(Units),
    true = length(Units) > 0 andalso length(Units) =< 10000,
    Child = maps:get(<<"child">>, Report),
    LoadedSha = maps:get(<<"loaded_beam_sha256">>, Report),
    LoadedCount = maps:get(<<"loaded_beam_count">>, Report),
    CountsState = maps:get(<<"counts_state">>, Report),
    true = runtime_matrix_failed_counts_safe(
        CountsState, Report, Child, Units, RunnerSha, BeamInventorySha),
    true = case CountsState of
        <<"verified">> ->
            Attestation = maps:get(<<"execution_beam_identity">>, Child),
            LoadedSha =:= maps:get(<<"loaded_beam_sha256">>, Attestation)
                andalso LoadedCount =:= maps:get(
                    <<"loaded_beam_count">>, Attestation)
                andalso runtime_matrix_lower_hex(LoadedSha)
                andalso is_integer(LoadedCount) andalso LoadedCount >= 0
                andalso LoadedCount =< 20000;
        <<"unavailable">> -> LoadedSha =:= null andalso LoadedCount =:= null
    end,
    ChildFailureObserved = case CountsState of
        <<"verified">> ->
            maps:get(<<"failure_count">>, Child) > 0 orelse
            maps:get(<<"unexpected_events">>, Child) > 0 orelse
            not maps:get(<<"eunit_completed">>, Child);
        <<"unavailable">> -> true
    end,
    FailureObserved = Exit =/= 0 orelse
        maps:get(<<"timed_out">>, Process) orelse
        maps:get(<<"output_limit_exceeded">>, Process) orelse
        not maps:get(<<"child_exit_observed">>, Process) orelse
        ChildFailureObserved orelse HasFailure,
    true = FailureObserved,
    case HasFailure of
        true -> true = runtime_matrix_diagnostic_safe(maps:get(<<"failure">>, Report));
        false -> ok
    end,
    true.

runtime_matrix_failed_counts_safe(<<"verified">>, Report, Child, Units,
                                  RunnerSha, BeamInventorySha) ->
    Nonce = maps:get(<<"run_nonce">>, Child),
    true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32 andalso
           re:run(Nonce, <<"^[0-9A-Fa-f]{32}$">>,
                  [{capture, none}]) =:= match,
    true = suite_attested_child_schema_valid(
        Child, Units, Nonce, RunnerSha, BeamInventorySha),
    Counts = suite_attested_test_counts(
        Child, Units, Nonce, RunnerSha, BeamInventorySha),
    maps:get(<<"completed_tests">>, Report) =:= maps:get(completed, Counts)
        andalso maps:get(<<"skipped_tests">>, Report) =:=
            maps:get(skipped, Counts);
runtime_matrix_failed_counts_safe(
  <<"unavailable">>, Report, #{<<"invalid">> := true} = Child, _Units,
  _RunnerSha, _BeamInventorySha) ->
    true = suite_exact_keys(Child, [invalid]),
    maps:get(<<"completed_tests">>, Report) =:= null
        andalso maps:get(<<"skipped_tests">>, Report) =:= null;
runtime_matrix_failed_counts_safe(_, _, _, _, _, _) ->
    false.

runtime_matrix_lower_hex(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    re:run(Value, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
runtime_matrix_lower_hex(_) -> false.

runtime_matrix_package_failure_classification(Value) ->
    lists:member(Value, [
        <<"package_suite_failed">>, <<"stale_build_sources">>,
        <<"modified_build_artifacts">>, <<"missing_artifact">>,
        <<"no_test_sources">>, <<"source_limit_exceeded">>,
        <<"duplicate_source_module">>, <<"unsupported_source_extension">>,
        <<"erlang_declared_module_mismatch">>,
        <<"erlang_module_declaration_missing">>,
        <<"erlang_module_declaration_ambiguous">>, <<"unsafe_module_name">>,
        <<"source_outside_test_root">>, <<"unsafe_source_path">>,
        <<"source_tree_depth_limit">>, <<"source_tree_entry_limit">>,
        <<"source_tree_read_failed">>, <<"source_tree_link_rejected">>,
        <<"source_tree_special_file_rejected">>,
        <<"source_tree_changed_while_reading">>,
        <<"source_tree_inspection_failed">>, <<"source_tree_missing">>,
        <<"source_size_rejected">>, <<"source_changed_while_reading">>,
        <<"source_read_failed">>, <<"source_link_rejected">>,
        <<"source_hardlink_rejected">>,
        <<"source_special_file_rejected">>, <<"source_missing">>,
        <<"source_inspection_failed">>, <<"beam_size_rejected">>,
        <<"beam_changed_while_reading">>, <<"beam_read_failed">>,
        <<"beam_link_rejected">>, <<"beam_hardlink_rejected">>,
        <<"beam_special_file_rejected">>,
        <<"beam_missing">>, <<"beam_inspection_failed">>,
        <<"malformed_beam">>, <<"unreadable_beam_metadata">>,
        <<"unsafe_beam_module">>, <<"beam_module_mismatch">>,
        <<"beam_export_limit_exceeded">>,
        <<"unsafe_eunit_export">>, <<"unit_limit_exceeded">>,
        <<"internally_invalid_inventory">>, <<"stale_suite_inventory">>,
        <<"tree_depth_limit">>, <<"tree_entry_limit">>,
        <<"tree_read_failed">>, <<"tree_link_rejected">>,
        <<"tree_special_file_rejected">>,
        <<"tree_changed_while_reading">>, <<"tree_inspection_failed">>,
        <<"tree_missing">>, <<"unsafe_path">>, <<"file_link_rejected">>,
        <<"file_hardlink_rejected">>, <<"file_special_file_rejected">>,
        <<"file_parent_rejected">>, <<"file_missing">>,
        <<"file_inspection_failed">>, <<"file_size_rejected">>,
        <<"file_changed_while_reading">>, <<"file_read_failed">>,
        <<"duplicate_path">>, <<"case_colliding_path">>]).

runtime_matrix_diagnostic_safe(Failure) ->
    try
        true = suite_exact_keys(Failure, [exception_class, exception_reason, stacktrace]),
        true = lists:member(maps:get(<<"exception_class">>, Failure),
                            [<<"error">>, <<"exit">>, <<"throw">>, <<"unknown">>]),
        true = lists:member(maps:get(<<"exception_reason">>, Failure),
            [<<"pattern_mismatch">>, <<"unexpected_variant">>, <<"assertion_failed">>,
             <<"callback_failed">>, <<"invalid_argument">>, <<"resource_limit">>,
             <<"startup_failed">>, <<"deadline_exceeded">>, <<"stale_source">>,
             <<"stale_build">>, <<"modified_build">>, <<"validation_failed">>]),
        StackBytes = maps:get(<<"stacktrace">>, Failure),
        true = is_binary(StackBytes) andalso byte_size(StackBytes) =< 32768,
        Stack = evidence_json_decode(StackBytes),
        true = is_list(Stack) andalso length(Stack) =< 16,
        true = lists:all(fun suite_frame_schema/1, Stack),
        true
    catch _:_ -> false end.

runtime_matrix_replay(Target) ->
    <<"bash scripts/fresh_build.sh ", Target/binary,
      " && escript scripts/package_suite.escript ", Target/binary>>.

runtime_matrix_catalog() ->
    maps:from_list([{list_to_binary(Target), runtime_matrix_catalog(Target)}
                   || Target <- ["http", "http3", "core"]]).

runtime_matrix_catalog(Target) ->
    fresh_verify(Target),
    Directory = fresh_target_directory(Target),
    {Name, _} = lists:last(fresh_packages(Target)),
    Ebin = filename:join([Directory, "build/dev/erlang", Name, "ebin"]),
    Inventory = suite_inventory(filename:join(Directory, "test"), Ebin),
    Sources = fresh_source_paths(fresh_packages(Target)),
    #{inventory => runtime_matrix_json(Inventory),
      modules => suite_inventory_modules(Inventory),
      units => suite_inventory_units(Inventory),
      source_sha256 => fresh_digest(Sources), source_files => length(Sources)}.

runtime_matrix_artifact(Row) ->
    Package = maps:get(package, Row), Os = maps:get(os, Row),
    Otp = integer_to_binary(maps:get(otp, Row)),
    <<"suite-", Package/binary, "-", Os/binary, "-otp", Otp/binary>>.

runtime_matrix_directory(Family, Row) ->
    runtime_matrix_directory_at("build/runtime-matrix", Family, Row).

runtime_matrix_directory_at(Root, Family, Row) ->
    filename:join([Root, Family, binary_to_list(runtime_matrix_artifact(Row))]).

runtime_matrix_paths(Row) ->
    runtime_matrix_paths("verified", Row).

runtime_matrix_paths(Family, Row) ->
    runtime_matrix_paths_at("build/runtime-matrix", Family, Row).

runtime_matrix_paths_at(Root, Family, Row) ->
    Directory = runtime_matrix_directory_at(Root, Family, Row),
    {filename:join(Directory, "package-suite.json"),
     filename:join(Directory, "fresh-build.json")}.

runtime_matrix_stage_row(Target0, Os0, Otp0) ->
    try
        Target = unicode:characters_to_binary(Target0),
        Os = unicode:characters_to_binary(Os0),
        Otp = list_to_integer(Otp0),
        Otp0 = integer_to_list(Otp),
        [Row] = [Candidate || Candidate <- runtime_matrix_expected(),
            maps:get(target, Candidate) =:= Target,
            maps:get(os, Candidate) =:= Os,
            maps:get(otp, Candidate) =:= Otp],
        Row
    catch _:_ -> erlang:error(invalid_runtime_stage_arguments) end.

runtime_matrix_read_regular(Path, Maximum) ->
    runtime_matrix_ensure(is_integer(Maximum) andalso Maximum >= 0 andalso
                          Maximum =< 16777216,
                          invalid_runtime_report_size),
    Initial = runtime_matrix_regular_info(Path),
    Size = element(2, Initial),
    runtime_matrix_ensure(is_integer(Size) andalso Size >= 0 andalso
                          Size =< Maximum,
                          invalid_runtime_report_size),
    runtime_matrix_ensure(element(9, Initial) =:= 1,
                          runtime_artifact_hardlink_rejected),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> erlang:error(unreadable_runtime_artifact_source)
    end,
    {Bytes, Finished} = try
        Opened = runtime_matrix_handle_info(File),
        runtime_matrix_ensure(element(3, Opened) =:= regular andalso
                              element(9, Opened) =:= 1 andalso
                              runtime_matrix_file_identity(Initial) =:=
                                  runtime_matrix_file_identity(Opened),
                              runtime_artifact_changed_while_reading),
        Captured = runtime_matrix_read_bounded(File, Size, []),
        FinalHandle = runtime_matrix_handle_info(File),
        runtime_matrix_ensure(
            runtime_matrix_file_identity(Opened) =:=
                runtime_matrix_file_identity(FinalHandle) andalso
            byte_size(Captured) =:= Size,
            runtime_artifact_changed_while_reading),
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = runtime_matrix_regular_info(Path),
    runtime_matrix_ensure(
        runtime_matrix_file_identity(Finished) =:=
            runtime_matrix_file_identity(FinalPath),
        runtime_artifact_changed_while_reading),
    Bytes.

runtime_matrix_optional_regular(Path, Maximum) ->
    try {ok, runtime_matrix_read_regular(Path, Maximum)}
    catch error:missing_runtime_artifact_source -> none end.

runtime_matrix_regular_info(Path) ->
    runtime_matrix_regular_components(
        filename:split(filename:absname(Path)), "").

runtime_matrix_regular_components([Name], Parent) ->
    Current = runtime_matrix_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, #file_info{type = regular} = Info} -> Info;
        {ok, #file_info{type = symlink}} ->
            erlang:error(runtime_artifact_link_rejected);
        {ok, _} -> erlang:error(runtime_artifact_special_file_rejected);
        {error, enoent} -> erlang:error(missing_runtime_artifact_source);
        {error, _} -> erlang:error(unreadable_runtime_artifact_source)
    end;
runtime_matrix_regular_components([Name | Rest], Parent) ->
    Current = runtime_matrix_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, #file_info{type = directory}} ->
            runtime_matrix_regular_components(Rest, Current);
        {ok, #file_info{type = symlink}} ->
            erlang:error(runtime_artifact_parent_link_rejected);
        {ok, _} -> erlang:error(runtime_artifact_parent_rejected);
        {error, enoent} -> erlang:error(missing_runtime_artifact_source);
        {error, _} -> erlang:error(unreadable_runtime_artifact_source)
    end;
runtime_matrix_regular_components([], _Parent) ->
    erlang:error(unsafe_runtime_artifact_path).

runtime_matrix_join_component("", Name) -> Name;
runtime_matrix_join_component(Parent, Name) -> filename:join(Parent, Name).

runtime_matrix_handle_info(File) ->
    case file:read_file_info(File) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(unreadable_runtime_artifact_source)
    end.

runtime_matrix_read_bounded(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            runtime_matrix_read_bounded(
                File, Remaining - byte_size(Chunk), [Chunk | Acc]);
        {ok, _} -> erlang:error(runtime_artifact_changed_while_reading);
        {error, _} -> erlang:error(unreadable_runtime_artifact_source)
    end.

runtime_matrix_file_identity(Info) ->
    %% atime is excluded because verification itself may update it.
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

%% Compatibility entry point used by the other retained-evidence readers.
%% It now inherits the same fail-closed path and handle validation.
runtime_matrix_read(Path, Maximum) ->
    runtime_matrix_read_regular(Path, Maximum).

runtime_matrix_stage_write(Root, Row, ReportBytes, BuildBytes) ->
    runtime_matrix_stage_write_at(Root, "staging", Row, ReportBytes, BuildBytes).

runtime_matrix_stage_write_at(Root, Family, Row, ReportBytes, BuildBytes) ->
    Directory = runtime_matrix_directory_at(Root, Family, Row),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    {ok, #file_info{type = directory}} = file:read_link_info(Directory),
    Entries = runtime_matrix_directory_entries(Directory),
    runtime_matrix_ensure(lists:all(fun(Name) ->
        lists:member(Name, ["package-suite.json", "fresh-build.json"])
    end, Entries), unexpected_runtime_stage_entry),
    lists:foreach(fun(Name) ->
        case file:delete(filename:join(Directory, Name)) of
            ok -> ok;
            {error, enoent} -> ok;
            {error, _} -> erlang:error(cannot_invalidate_runtime_stage)
        end
    end, ["package-suite.json", "fresh-build.json"]),
    [] = runtime_matrix_directory_entries(Directory),
    {ReportPath, BuildPath} = runtime_matrix_paths_at(Root, Family, Row),
    ok = file:write_file(ReportPath, ReportBytes, [exclusive]),
    case BuildBytes of
        none -> ok;
        Bytes when is_binary(Bytes) -> ok = file:write_file(BuildPath, Bytes, [exclusive])
    end,
    Expected = case BuildBytes of
        none -> ["package-suite.json"];
        _ -> ["fresh-build.json", "package-suite.json"]
    end,
    runtime_matrix_ensure(runtime_matrix_directory_entries(Directory) =:= Expected,
                          incomplete_runtime_stage),
    true = lists:all(fun(Path) ->
        case file:read_link_info(Path) of
            {ok, #file_info{type = regular}} -> true;
            _ -> false
        end
    end, case BuildBytes of
        none -> [ReportPath];
        _ -> [ReportPath, BuildPath]
    end),
    ok.

runtime_matrix_directory_entries(Directory) ->
    case file:list_dir(Directory) of
        {ok, Entries} -> lists:sort(Entries);
        {error, enoent} -> [];
        {error, _} -> erlang:error(unreadable_runtime_artifact_directory)
    end.

runtime_matrix_rows(Family, Catalogs, Identity) ->
    [runtime_matrix_read_row(Family, Row, maps:get(maps:get(target, Row), Catalogs), Identity)
     || Row <- runtime_matrix_expected()].

runtime_matrix_read_row(Family, Row, Catalog, Identity) ->
    {Path, BuildPath} = runtime_matrix_paths(Family, Row),
    Base = Row#{artifact => runtime_matrix_artifact(Row), replay => runtime_matrix_replay(maps:get(target, Row))},
    try
        Bytes = runtime_matrix_read_regular(Path, 16777216),
        Report = evidence_json_decode(Bytes),
        evidence_require_identity(Report, Identity),
        case maps:get(<<"status">>, Report, undefined) of
            <<"Ready">> -> runtime_matrix_read_ready(Family, Row, Catalog, Identity,
                                                       Base, Bytes, Report, BuildPath);
            <<"Failed">> -> runtime_matrix_read_failed(Row, Catalog, Identity,
                                                         Base, Bytes, Report, BuildPath);
            _ -> erlang:error(invalid_runtime_package_status)
        end
    catch
        error:missing_runtime_artifact_source ->
            Base#{status => <<"Blocked">>, failure => <<"missing_package_run">>};
        error:stale_or_missing_evidence_identity -> Base#{status => <<"Blocked">>, failure => <<"stale_source">>};
        _:_ -> Base#{status => <<"Blocked">>, failure => <<"invalid_or_incomplete_package_run">>}
    end.

runtime_matrix_read_ready(Family, Row, Catalog, Identity, Base, Bytes, Report, BuildPath) ->
    BuildBytes = runtime_matrix_read_regular(BuildPath, 1048576),
    Build = evidence_json_decode(BuildBytes),
    runtime_matrix_ensure(runtime_matrix_package_valid(Report, Build, Row, Catalog, Identity),
                          invalid_runtime_package),
    case Family of
        "inputs" ->
            %% Only fully validated documents enter shareable artifacts.
            {SafePath, SafeBuildPath} = runtime_matrix_paths("verified", Row),
            ok = filelib:ensure_dir(SafePath), ok = filelib:ensure_dir(SafeBuildPath),
            ok = file:write_file(SafePath, Bytes), ok = file:write_file(SafeBuildPath, BuildBytes);
        "verified" -> ok
    end,
    Base#{status => <<"Ready">>, report_sha256 => runtime_matrix_sha256(Bytes),
        manifest_sha256 => runtime_matrix_sha256(BuildBytes),
        configured_units => maps:get(<<"configured_units">>, Report),
        completed_tests => maps:get(<<"completed_tests">>, Report),
        run_nonce => maps:get(<<"run_nonce">>, maps:get(<<"child">>, Report)),
        execution_environment => maps:get(<<"execution_environment">>, Report)}.

runtime_matrix_read_failed(Row, Catalog, Identity, Base, Bytes, Report, BuildPath) ->
    runtime_matrix_ensure(runtime_matrix_failed_report_safe(Report, Row, Identity),
                          unsafe_failed_runtime_package),
    ManifestFields = case maps:is_key(<<"build_identity">>, Report) of
        true ->
            BuildBytes = runtime_matrix_read_regular(BuildPath, 1048576),
            Build = evidence_json_decode(BuildBytes),
            runtime_matrix_ensure(runtime_matrix_failed_report_bound(
                Report, Build, Row, Catalog, Identity), unbound_failed_runtime_package),
            #{manifest_sha256 => runtime_matrix_sha256(BuildBytes)};
        false -> #{}
    end,
    maps:merge(Base#{status => <<"Blocked">>, failure => <<"failed_package_run">>,
        report_sha256 => runtime_matrix_sha256(Bytes),
        completed_tests => maps:get(<<"completed_tests">>, Report),
        execution_environment => maps:get(<<"execution_environment">>, Report)},
        ManifestFields).

runtime_matrix_sha256(Bytes) -> binary:encode_hex(crypto:hash(sha256, Bytes)).

runtime_matrix_rows_valid(Rows) ->
    try
        18 = length(Rows),
        true = [maps:with([package, target, os, otp], Row) || Row <- Rows] =:= runtime_matrix_expected(),
        true = lists:all(fun(Row) -> maps:get(status, Row) =:= <<"Ready">> end, Rows),
        18 = length(lists:usort([maps:get(run_nonce, Row) || Row <- Rows])),
        true
    catch _:_ -> false end.

runtime_matrix_inventory_valid(Family) ->
    runtime_matrix_inventory_valid_at("build/runtime-matrix", Family).

runtime_matrix_inventory_valid_at(Root, Family) ->
    Expected = lists:sort([runtime_matrix_directory_at(Root, Family, Row)
                           || Row <- runtime_matrix_expected()]),
    Actual = lists:sort(filelib:wildcard(filename:join([Root, Family, "*"]))),
    Actual =:= Expected andalso lists:all(fun(Row) ->
        Directory = runtime_matrix_directory_at(Root, Family, Row),
        runtime_matrix_directory_entries(Directory) =:=
            ["fresh-build.json", "package-suite.json"] andalso
        lists:all(fun(Path) ->
            case file:read_link_info(Path) of
                {ok, #file_info{type = regular}} -> true;
                _ -> false
            end
        end, tuple_to_list(runtime_matrix_paths_at(Root, Family, Row)))
    end, runtime_matrix_expected()).

runtime_matrix_summary(Rows, InventoryValid, Identity) ->
    Ready = InventoryValid andalso runtime_matrix_rows_valid(Rows),
    #{schema => 1, status => case Ready of true -> <<"Ready">>; false -> <<"Blocked">> end,
      evidence_identity => Identity, expected_runs => 18,
      verified_runs => length([ok || #{status := <<"Ready">>} <- Rows]),
      artifact_inventory_valid => InventoryValid, runs => Rows}.

runtime_matrix_verify(Report) ->
    Identity = evidence_identity(),
    Rows = runtime_matrix_rows("verified", runtime_matrix_catalog(), Identity),
    runtime_matrix_ensure(runtime_matrix_rows_valid(Rows) andalso runtime_matrix_inventory_valid("verified"),
                          incomplete_runtime_matrix),
    runtime_matrix_ensure(Report =:= runtime_matrix_json(runtime_matrix_summary(Rows, true, Identity)),
                          stale_or_invalid_runtime_matrix).

runtime_matrix_expected() ->
    [#{package => Package, target => Target, os => Os, otp => Otp}
     || {Package, Target} <- [{<<"http">>, <<"http">>}, {<<"http3">>, <<"http3">>},
                              {<<"quic_core">>, <<"core">>}],
        Os <- [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>],
        Otp <- [28, 29]].

runtime_matrix_ensure(true, _) -> ok;
runtime_matrix_ensure(false, Reason) -> erlang:error(Reason).

runtime_matrix_json(Value) -> json:decode(iolist_to_binary(json:encode(Value))).

runtime_matrix_hex(Value) -> is_binary(Value) andalso byte_size(Value) =:= 64 andalso
    re:run(Value, <<"^[0-9A-Fa-f]{64}$">>, [{capture, none}]) =:= match.
-endif.
