#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("runtime_matrix_evidence.hrl").
-include("reader_boundary_fixture.hrl").

main(Arguments) ->
    ok = file:set_cwd(filename:dirname(filename:dirname(filename:absname(escript:script_name())))),
    try run(Arguments) catch Class:Reason:Stack ->
        io:format(standard_error, "runtime matrix failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["stage", Target, Os, Otp]) -> stage(Target, Os, Otp);
run([]) -> aggregate();
run(_) -> erlang:error(invalid_runtime_matrix_arguments).

stage(Target0, Os0, Otp0) ->
    Row = runtime_matrix_stage_row(Target0, Os0, Otp0),
    Runtime = execution_runtime(),
    runtime_matrix_ensure(runtime_matrix_environment_valid(Runtime, Row),
                          staging_environment_mismatch),
    Identity = evidence_identity(),
    Target = binary_to_list(maps:get(target, Row)),
    ReportPath = filename:join(["build", "package-suite", Target ++ ".json"]),
    ReportBytes = runtime_matrix_read_regular(ReportPath, 16777216),
    Report = evidence_json_decode(ReportBytes),
    BuildPath = fresh_manifest_path(Target),
    {BuildBytes, Build} = runtime_matrix_stage_build(Report, BuildPath, Runtime),
    case maps:get(<<"status">>, Report, undefined) of
        <<"Ready">> ->
            Catalog = runtime_matrix_catalog(Target),
            runtime_matrix_ensure(BuildBytes =/= none andalso
                runtime_matrix_package_valid(Report, Build, Row, Catalog, Identity),
                invalid_ready_package_stage);
        <<"Failed">> ->
            runtime_matrix_ensure(
                runtime_matrix_failed_report_safe(Report, Row, Identity),
                unsafe_failed_package_stage),
            case maps:is_key(<<"build_identity">>, Report) of
                true ->
                    Catalog = runtime_matrix_catalog(Target),
                    runtime_matrix_ensure(BuildBytes =/= none andalso
                        runtime_matrix_failed_report_bound(Report, Build, Row,
                                                           Catalog, Identity),
                        unbound_failed_package_stage);
                false -> ok
            end;
        _ -> erlang:error(invalid_package_stage_status)
    end,
    ok = runtime_matrix_stage_write("build/runtime-matrix", Row, ReportBytes, BuildBytes),
    evidence_require_identity(#{<<"evidence_identity">> => Identity}, evidence_identity()),
    Directory = runtime_matrix_directory_at("build/runtime-matrix", "staging", Row),
    io:format("runtime artifact staged: ~s (~B files)~n",
              [runtime_matrix_artifact(Row), length(runtime_matrix_directory_entries(Directory))]).

runtime_matrix_stage_build(Report, Path, Runtime) ->
    case maps:find(<<"build_identity">>, Report) of
        {ok, Embedded} ->
            case runtime_matrix_optional_regular(Path, 1048576) of
                {ok, Bytes} ->
                    try evidence_json_decode(Bytes) of
                        Embedded ->
                            case runtime_matrix_build_document_safe(Embedded,
                                    maps:get(<<"package">>, Report), Runtime) of
                                true -> {Bytes, Embedded};
                                false -> runtime_matrix_stage_build_failure(Report)
                            end;
                        _ -> runtime_matrix_stage_build_failure(Report)
                    catch _:_ -> runtime_matrix_stage_build_failure(Report) end;
                none -> runtime_matrix_stage_build_failure(Report)
            end;
        error -> {none, none}
    end.

runtime_matrix_stage_build_failure(#{<<"status">> := <<"Failed">>}) -> {none, none};
runtime_matrix_stage_build_failure(_) -> erlang:error(invalid_package_stage_build).

aggregate() ->
    Path = "build/runtime-matrix/report.json",
    Identity = evidence_begin(Path),
    ok = filelib:ensure_dir(Path),
    Report = try
        %% Invalidate each known prior output before considering new evidence.
        lists:foreach(fun(Row) ->
            lists:foreach(fun(SafePath) ->
                case file:delete(SafePath) of ok -> ok; {error, enoent} -> ok; _ -> erlang:error(stale_verified_output) end
            end, tuple_to_list(runtime_matrix_paths(Row)))
        end, runtime_matrix_expected()),
        Rows = runtime_matrix_rows("inputs", runtime_matrix_catalog(), Identity),
        Summary = runtime_matrix_summary(Rows, runtime_matrix_inventory_valid("inputs"), Identity),
        evidence_require_identity(#{<<"evidence_identity">> => Identity}, evidence_identity()),
        Summary
    catch Class:Reason:Stack ->
        #{schema => 1, status => <<"Blocked">>, evidence_identity => Identity,
          expected_runs => 18, verified_runs => 0,
          failure => diagnostic_failure_details(Class, Reason, Stack)}
    end,
    ok = file:write_file(Path, [json:encode(Report), $\n]),
    io:format("runtime matrix: ~s, ~B of 18 package runs verified~n",
              [maps:get(status, Report), maps:get(verified_runs, Report)]),
    runtime_matrix_ensure(maps:get(status, Report) =:= <<"Ready">>, incomplete_runtime_matrix).

self_test() ->
    Identity = #{<<"schema">> => 2, <<"source_sha256">> => hash(), <<"files">> => 17},
    {Report, Manifest, Catalog} = fixture(hd(runtime_matrix_expected()), Identity),
    Row = hd(runtime_matrix_expected()),
    runtime_matrix_ensure(runtime_matrix_package_valid(Report, Manifest, Row, Catalog, Identity),
                          complete_package_rejected),
    StaleRejected = not runtime_matrix_package_valid(
        Report#{<<"evidence_identity">> => #{}}, Manifest, Row, Catalog, Identity),
    io:format("stale_package_rejected=~p~n", [StaleRejected]),
    runtime_matrix_ensure(StaleRejected, stale_package_accepted),
    Child = maps:get(<<"child">>, Report),
    Process = maps:get(<<"process">>, Report),
    Runtime = maps:get(<<"execution_environment">>, Report),
    InventoryDocument = maps:get(<<"suite_inventory">>, Report),
    [InventoryRelation] = maps:get(<<"relations">>, InventoryDocument),
    BadReports = [Report#{<<"payload">> => <<"fixture-private-marker">>},
        Report#{<<"completed_tests">> => 0}, Report#{<<"configured_modules">> => []},
        Report#{<<"configured_units">> => 0}, Report#{<<"runner_sha256">> => <<>>},
        Report#{<<"execution_beam_inventory_sha256">> => <<>>},
        Report#{<<"loaded_beam_sha256">> => <<>>},
        Report#{<<"loaded_beam_count">> => 0},
        Report#{<<"process">> => Process#{
            <<"process_supervisor_reported_status">> => 1,
            <<"process_supervisor_observed_status">> => 1}},
        Report#{<<"counts_state">> => <<"unavailable">>},
        Report#{<<"skipped_tests">> => null},
        Report#{<<"suite_inventory">> => #{}},
        Report#{<<"suite_inventory">> => InventoryDocument#{
            <<"relations">> => [InventoryRelation#{
                <<"source_sha256">> => binary:copy(<<"c">>, 64)}]}},
        Report#{<<"suite_inventory">> => InventoryDocument#{
            <<"private">> => <<"fixture-private-marker">>}},
        Report#{<<"build_identity">> => #{}},
        Report#{<<"build_identity">> => Manifest#{
            <<"prebuild_profile_state">> => <<"present">>}},
        Report#{<<"build_identity">> => Manifest#{
            <<"build_nonce">> => <<"unverified">>}},
        Report#{<<"child_exit_status">> => 1},
        Report#{<<"child">> => Child#{<<"units">> => []}},
        Report#{<<"child">> => Child#{<<"run_nonce">> => <<"not-a-nonce">>}},
        Report#{<<"process">> => Process#{<<"child_exit_observed">> => false}},
        Report#{<<"process">> => Process#{<<"output_limit_exceeded">> => true}},
        Report#{<<"process">> => Process#{<<"timed_out">> => true}},
        Report#{<<"process">> => Process#{<<"output_bytes">> => 8388609}},
        Report#{<<"process">> => Process#{<<"crash_dumps_disabled">> => false}},
        Report#{<<"process">> => Process#{<<"vm_process_heap_words">> => 0}},
        Report#{<<"process">> => Process#{<<"tail">> => <<"fixture-private-marker">>}},
        Report#{<<"execution_environment">> => Runtime#{<<"otp_version">> => <<"27.3">>}},
        Report#{<<"execution_environment">> => Runtime#{<<"otp_version">> => <<"28.0.0">>}},
        Report#{<<"execution_environment">> => Runtime#{<<"os_name">> => <<"darwin">>}},
        Report#{<<"execution_environment">> => Runtime#{<<"system_architecture">> => <<"fixture-private-marker">>}}],
    lists:foreach(fun(Bad) -> runtime_matrix_ensure(
        not runtime_matrix_package_valid(Bad, Manifest, Row, Catalog, Identity),
        invalid_package_accepted) end, BadReports),
    runtime_matrix_stage_contract_self_test(Report, Manifest, Row, Identity),
    lists:foreach(fun(Expected) ->
        {Good, Build, Inputs} = fixture(Expected, Identity),
        runtime_matrix_ensure(runtime_matrix_package_valid(Good, Build, Expected, Inputs, Identity),
                              platform_fixture_rejected)
    end, runtime_matrix_expected()),
    Rows = [Expected#{status => <<"Ready">>, run_nonce => integer_to_binary(Id)}
            || {Id, Expected} <- lists:zip(lists:seq(1, 18), runtime_matrix_expected())],
    runtime_matrix_ensure(runtime_matrix_rows_valid(Rows), complete_matrix_rejected),
    [First, Second | Rest] = Rows,
    lists:foreach(fun(BadRows) -> runtime_matrix_ensure(not runtime_matrix_rows_valid(BadRows),
                                                     incomplete_matrix_accepted) end,
        [tl(Rows), Rows ++ [First], [First, First | Rest],
         [First, Second#{run_nonce => maps:get(run_nonce, First)} | Rest],
         [First#{status => <<"Blocked">>} | tl(Rows)]]),
    #{status := <<"Blocked">>} = runtime_matrix_summary(Rows, false, Identity),
    runtime_matrix_workflow_layout_self_test(),
    runtime_matrix_upload_layout_self_test(),
    runtime_matrix_reader_boundary_self_test(),
    io:put_chars("missing_duplicate_replayed_runs_rejected=true extra_artifacts_rejected=true\n"),
    io:put_chars("runtime matrix adversarial tests passed\n").

runtime_matrix_reader_boundary_self_test() ->
    Nonce = binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    Root = filename:absname(filename:join(
        "build", "runtime-reader-self-test-" ++ Nonce)),
    Original = filename:join(Root, "original.json"),
    Alias = filename:join(Root, "hardlink-alias.json"),
    ParentTarget = filename:join(Root, "parent-target"),
    ParentContainer = filename:join(Root, "parent-container"),
    ParentLink = filename:join(ParentContainer, "linked-parent"),
    ParentFile = filename:join(ParentTarget, "input.json"),
    ok = filelib:ensure_dir(Original),
    ok = filelib:ensure_dir(filename:join(ParentTarget, "placeholder")),
    ok = filelib:ensure_dir(filename:join(ParentContainer, "placeholder")),
    try
        ok = file:write_file(Original, <<"current">>, [exclusive]),
        <<"current">> = runtime_matrix_read_regular(Original, 7),
        none = runtime_matrix_optional_regular(
            filename:join(Root, "missing.json"), 16),
        runtime_matrix_reader_expect(fun() ->
            runtime_matrix_read_regular(Original, 6)
        end, invalid_runtime_report_size),
        {ok, Info} = file:read_link_info(Original),
        StableIdentity = runtime_matrix_file_identity(Info),
        StableIdentity = runtime_matrix_file_identity(
            setelement(5, Info, changed_atime)),
        false = StableIdentity =:= runtime_matrix_file_identity(
            setelement(6, Info, changed_mtime)),
        HardlinkState = case file:make_link(Original, Alias) of
            ok ->
                try
                    runtime_matrix_reader_expect(fun() ->
                        runtime_matrix_read_regular(Original, 7)
                    end, runtime_artifact_hardlink_rejected)
                after
                    ok = file:delete(Alias)
                end,
                <<"verified">>;
            {error, _} -> <<"unavailable">>
        end,
        {ParentKind, ParentState} = case
            reader_boundary_supplied_parent_path()
        of
            {ok, Supplied} ->
                runtime_matrix_reader_expect(fun() ->
                    runtime_matrix_read_regular(Supplied, 1048576)
                end, runtime_artifact_parent_link_rejected),
                {<<"junction">>, <<"verified">>};
            none ->
                ok = file:write_file(ParentFile, <<"parent">>, [exclusive]),
                {Kind, State} = reader_boundary_make_parent_link(
                    ParentTarget, ParentLink),
                case State of
                    <<"verified">> ->
                        try
                            runtime_matrix_reader_expect(fun() ->
                                runtime_matrix_read_regular(filename:join(
                                    ParentLink, "input.json"), 6)
                            end, runtime_artifact_parent_link_rejected)
                        after
                            ok = reader_boundary_remove_parent_link(ParentLink)
                        end;
                    <<"unavailable">> -> ok
                end,
                {Kind, State}
        end,
        io:format("runtime reader hardlink=~s parent_component_kind=~s "
                  "parent_component_link=~s bounded_read=verified "
                  "identity_before_after=verified atime_stable=verified~n",
                  [HardlinkState, ParentKind, ParentState])
    after
        ok = file:del_dir_r(Root)
    end.

runtime_matrix_reader_expect(Function, Expected) ->
    Result = try Function(), accepted
             catch error:Reason -> {rejected, Reason} end,
    runtime_matrix_ensure(Result =:= {rejected, Expected},
                          runtime_reader_mutant_accepted).

runtime_matrix_workflow_layout_self_test() ->
    Workflow = runtime_matrix_read_regular(".github/workflows/ci.yml", 1048576),
    runtime_matrix_ensure(runtime_matrix_workflow_layout_valid(Workflow),
                          invalid_runtime_workflow_layout),
    Mutants = [
        binary:replace(Workflow,
            <<"path: build/runtime-matrix/staging/suite-${{ matrix.package }}-${{ matrix.os }}-otp${{ matrix.otp }}/">>,
            <<"path: build/package-suite/${{ matrix.target }}.json">>),
        binary:replace(Workflow, <<"merge-multiple: false">>, <<"merge-multiple: true">>),
        binary:replace(Workflow,
            <<"if: ${{ always() && steps.stage.outcome == 'success' }}">>,
            <<"if: always()">>)],
    runtime_matrix_ensure(lists:all(fun(Mutant) ->
        not runtime_matrix_workflow_layout_valid(Mutant)
    end, Mutants), runtime_workflow_mutant_survived),
    io:format("runtime workflow layout: canonical_stage=true non_merged_download=true "
              "mutants_rejected=~B~n", [length(Mutants)]).

runtime_matrix_workflow_layout_valid(Workflow) ->
    Required = [
        <<"id: stage">>,
        <<"run: escript scripts/runtime_matrix.escript stage \"${{ matrix.target }}\" \"${{ matrix.os }}\" \"${{ matrix.otp }}\"">>,
        <<"if: ${{ always() && steps.stage.outcome == 'success' }}">>,
        <<"name: suite-${{ matrix.package }}-${{ matrix.os }}-otp${{ matrix.otp }}">>,
        <<"path: build/runtime-matrix/staging/suite-${{ matrix.package }}-${{ matrix.os }}-otp${{ matrix.otp }}/">>,
        <<"pattern: suite-*">>,
        <<"path: build/runtime-matrix/inputs">>,
        <<"merge-multiple: false">>],
    Lines = [string:trim(Line) || Line <- binary:split(Workflow, <<"\n">>, [global])],
    RequiredOnce = lists:all(fun(Line) ->
        length([ok || Candidate <- Lines, Candidate =:= Line]) =:= 1
    end, Required),
    Forbidden = [<<"build/package-suite/${{ matrix.target }}.json">>,
                 <<"${{ matrix.directory }}/build/dev/fresh-build.json">>,
                 <<"${{ matrix.directory }}/build/fresh-build-inputs.json">>],
    RequiredOnce andalso lists:all(fun(Value) ->
        binary:match(Workflow, Value) =:= nomatch
    end, Forbidden).

runtime_matrix_stage_contract_self_test(Report, Manifest, Row, Identity) ->
    Runtime = maps:get(<<"execution_environment">>, Report),
    runtime_matrix_ensure(runtime_matrix_build_document_safe(Manifest,
        maps:get(target, Row), Runtime), safe_build_document_rejected),
    ReadyProcess = maps:get(<<"process">>, Report),
    FailedProcess = ReadyProcess#{
        <<"process_supervisor_reported_status">> => 1,
        <<"process_supervisor_observed_status">> => 1},
    Failed = Report#{<<"status">> => <<"Failed">>,
        <<"child_exit_status">> => 1, <<"process">> => FailedProcess},
    runtime_matrix_ensure(runtime_matrix_failed_report_safe(Failed, Row, Identity),
                          safe_failed_report_rejected),
    runtime_matrix_ensure(runtime_matrix_failed_report_bound(
        Failed, Manifest, Row, fixture_catalog(Report), Identity),
        bound_failed_report_rejected),
    runtime_matrix_ensure(not runtime_matrix_failed_report_safe(
        Failed#{<<"payload">> => <<"fixture-private-marker">>}, Row, Identity),
        private_failed_report_accepted),
    Process = maps:get(<<"process">>, Failed),
    runtime_matrix_ensure(not runtime_matrix_failed_report_safe(
        Failed#{<<"process">> => Process#{<<"tail">> => <<"fixture-private-marker">>}},
        Row, Identity), private_process_output_accepted),
    runtime_matrix_ensure(not runtime_matrix_failed_report_safe(
        Failed#{<<"child_exit_status">> => 0}, Row, Identity),
        failed_child_exit_mismatch_accepted),
    Diagnostic = #{<<"exception_class">> => <<"error">>,
        <<"exception_reason">> => <<"validation_failed">>, <<"stacktrace">> => <<"[]">>},
    Minimal = #{<<"schema">> => 3, <<"report_kind">> => <<"package_suite">>,
        <<"package">> => maps:get(target, Row),
        <<"status">> => <<"Failed">>, <<"shareable">> => true,
        <<"scope">> => <<"all source-discovered EUnit tests and generators">>,
        <<"evidence_identity">> => Identity, <<"execution_environment">> => Runtime,
        <<"suite_inventory">> => null, <<"configured_modules">> => null,
        <<"configured_units">> => null, <<"counts_state">> => <<"unavailable">>,
        <<"completed_tests">> => null, <<"skipped_tests">> => null,
        <<"failure_classification">> => <<"package_suite_failed">>,
        <<"failure">> => Diagnostic,
        <<"replay">> => runtime_matrix_replay(maps:get(target, Row))},
    runtime_matrix_ensure(runtime_matrix_failed_report_safe(Minimal, Row, Identity),
                          safe_minimal_failure_rejected),
    FailedRow = runtime_matrix_read_failed(Row, fixture_catalog(Report), Identity,
        Row, iolist_to_binary(json:encode(Minimal)), Minimal, "unused-for-minimal-failure"),
    <<"Blocked">> = maps:get(status, FailedRow),
    <<"failed_package_run">> = maps:get(failure, FailedRow),
    runtime_matrix_ensure(not runtime_matrix_failed_report_safe(Minimal#{<<"failure">> =>
        Diagnostic#{<<"exception_reason">> => <<"fixture-private-marker">>}}, Row, Identity),
        private_failure_reason_accepted),
    Target = binary_to_list(maps:get(target, Row)),
    Os = binary_to_list(maps:get(os, Row)),
    Otp = integer_to_list(maps:get(otp, Row)),
    Row = runtime_matrix_stage_row(Target, Os, Otp),
    InvalidArgumentsRejected = lists:all(fun(Arguments) ->
        try apply(fun runtime_matrix_stage_row/3, Arguments), false
        catch error:invalid_runtime_stage_arguments -> true end
    end, [["../http", Os, Otp], [Target, "windows-latest", Otp],
          [Target, Os, "29.0.5"], ["quic_core", Os, Otp]]),
    runtime_matrix_ensure(InvalidArgumentsRejected, unsafe_stage_arguments_accepted),
    io:format("runtime stage safety controls: failed_report=true minimal_failure=true "
              "private_fields_rejected=true arguments_rejected=~p~n",
              [InvalidArgumentsRejected]).

fixture_catalog(Report) ->
    Child = maps:get(<<"child">>, Report),
    Units = [#{module => maps:get(<<"module">>, Unit),
               function => maps:get(<<"function">>, Unit),
               kind => maps:get(<<"kind">>, Unit)}
             || Unit <- maps:get(<<"units">>, Child)],
    #{inventory => maps:get(<<"suite_inventory">>, Report),
      modules => maps:get(<<"configured_modules">>, Report), units => Units,
      source_sha256 => maps:get(<<"source_sha256">>, maps:get(<<"build_identity">>, Report)),
      source_files => maps:get(<<"source_files">>, maps:get(<<"build_identity">>, Report))}.

runtime_matrix_upload_layout_self_test() ->
    Root = "build/runtime-matrix-layout-controls",
    runtime_matrix_reset_control_root(Root),
    try
        lists:foreach(fun(Row) ->
            Marker = runtime_matrix_artifact(Row),
            Report = <<"report:", Marker/binary>>,
            Build = <<"build:", Marker/binary>>,
            ok = runtime_matrix_stage_write(Root, Row, Report, Build),
            ok = runtime_matrix_emulate_artifact_download(Root, Row)
        end, runtime_matrix_expected()),
        runtime_matrix_ensure(runtime_matrix_inventory_valid_at(Root, "inputs"),
                              canonical_download_layout_rejected),
        Uniform = lists:all(fun(Row) ->
            {ReportPath, BuildPath} = runtime_matrix_paths_at(Root, "inputs", Row),
            filename:basename(ReportPath) =:= "package-suite.json" andalso
            filename:basename(BuildPath) =:= "fresh-build.json"
        end, runtime_matrix_expected()),
        runtime_matrix_ensure(Uniform, package_layout_not_uniform),
        [Http | _] = runtime_matrix_expected(),
        {HttpReport, HttpBuild} = runtime_matrix_paths_at(Root, "inputs", Http),
        {ok, HttpReportBytes} = file:read_file(HttpReport),
        {ok, HttpBuildBytes} = file:read_file(HttpBuild),
        ok = file:delete(HttpReport), ok = file:delete(HttpBuild),
        HttpDirectory = runtime_matrix_directory_at(Root, "inputs", Http),
        LegacyReport = filename:join([HttpDirectory, "build", "package-suite", "http.json"]),
        LegacyBuild = filename:join([HttpDirectory, "build", "dev", "fresh-build.json"]),
        ok = filelib:ensure_dir(LegacyReport), ok = filelib:ensure_dir(LegacyBuild),
        ok = file:write_file(LegacyReport, HttpReportBytes),
        ok = file:write_file(LegacyBuild, HttpBuildBytes),
        LegacyRejected = not runtime_matrix_inventory_valid_at(Root, "inputs"),
        runtime_matrix_ensure(LegacyRejected, legacy_http_upload_root_accepted),
        ok = file:del_dir_r(filename:join(HttpDirectory, "build")),
        ok = runtime_matrix_stage_write_at(Root, "inputs", Http,
                                           HttpReportBytes, HttpBuildBytes),
        Merged = filename:join([Root, "inputs", "package-suite.json"]),
        ok = file:write_file(Merged, <<"merged-artifacts-collide">>),
        MergedRejected = not runtime_matrix_inventory_valid_at(Root, "inputs"),
        runtime_matrix_ensure(MergedRejected, merged_artifact_download_accepted),
        ok = file:delete(Merged),
        Extra = filename:join(HttpDirectory, "private-output.txt"),
        ok = file:write_file(Extra, <<"must-not-be-uploaded">>),
        ExtraRejected = not runtime_matrix_inventory_valid_at(Root, "inputs"),
        runtime_matrix_ensure(ExtraRejected, extra_downloaded_file_accepted),
        ok = file:delete(Extra),
        StageDirectory = runtime_matrix_directory_at(Root, "staging", Http),
        StageExtra = filename:join(StageDirectory, "unexpected.txt"),
        ok = file:write_file(StageExtra, <<"stale">>),
        StaleStageRejected = try
            runtime_matrix_stage_write(Root, Http, HttpReportBytes, HttpBuildBytes), false
        catch error:unexpected_runtime_stage_entry -> true end,
        runtime_matrix_ensure(StaleStageRejected, stale_stage_entry_accepted),
        ok = file:delete(StageExtra),
        ok = runtime_matrix_stage_write(Root, Http, HttpReportBytes, HttpBuildBytes),
        runtime_matrix_ensure(runtime_matrix_inventory_valid_at(Root, "inputs"),
                              restored_download_layout_rejected),
        io:format("runtime artifact layout controls: packages=~B files=~B "
                  "legacy_rejected=~p merged_rejected=~p extra_rejected=~p "
                  "stale_stage_rejected=~p~n",
                  [length(runtime_matrix_expected()), 2 * length(runtime_matrix_expected()),
                   LegacyRejected, MergedRejected, ExtraRejected, StaleStageRejected])
    after
        runtime_matrix_reset_control_root(Root)
    end.

runtime_matrix_emulate_artifact_download(Root, Row) ->
    %% upload-artifact receives one directory. Its directory name is omitted
    %% from the archive; download-artifact's default non-merged mode restores
    %% those relative entries below a directory named for the artifact.
    Stage = runtime_matrix_directory_at(Root, "staging", Row),
    Inputs = runtime_matrix_directory_at(Root, "inputs", Row),
    Names = runtime_matrix_directory_entries(Stage),
    runtime_matrix_ensure(Names =:= ["fresh-build.json", "package-suite.json"],
                          invalid_staged_upload_inventory),
    lists:foreach(fun(Name) ->
        {ok, Bytes} = file:read_file(filename:join(Stage, Name)),
        Destination = filename:join(Inputs, Name),
        ok = filelib:ensure_dir(Destination),
        ok = file:write_file(Destination, Bytes, [exclusive])
    end, Names),
    ok.

runtime_matrix_reset_control_root(Root) ->
    Absolute = filename:absname(Root),
    runtime_matrix_ensure(Absolute =:= filename:absname(
        "build/runtime-matrix-layout-controls"), unsafe_control_root),
    case file:del_dir_r(Root) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_reset_layout_controls)
    end.

fixture(Row, Identity) ->
    {Family, Name, Architecture} = case maps:get(os, Row) of
        <<"ubuntu-24.04">> -> {<<"unix">>, <<"linux">>, <<"x86_64-pc-linux-gnu">>};
        <<"macos-15">> -> {<<"unix">>, <<"darwin">>, <<"aarch64-apple-darwin">>};
        <<"windows-2025">> -> {<<"win32">>, <<"nt">>, <<"x86_64-pc-windows">>}
    end,
    OtpVersion = case maps:get(otp, Row) of
        28 -> <<"28.5.0.6">>;
        29 -> <<"29.0.5">>
    end,
    Runtime = #{otp_version => OtpVersion, erts_version => <<"17.0.5">>,
        os_family => Family, os_name => Name, system_architecture => Architecture, word_size => 8},
    Target = maps:get(target, Row),
    Tool = fun(Version) -> #{declared_version => Version, executable_sha256 => hash()} end,
    Build = runtime_matrix_json(#{schema => 3, package => Target,
        source_sha256 => hash(), source_files => 12, artifact_sha256 => hash(), artifact_files => 99,
        build_nonce => binary:copy(<<"0">>, 32),
        prebuild_profile_state => <<"absent">>,
        toolchain => #{runtime => Runtime, gleam => Tool(<<"1.18.1">>), rebar3 => Tool(<<"3.27.0">>)}}),
    Unit = #{module => <<"fixture_test">>, function => <<"case_test">>, kind => <<"test">>},
    Relation = #{source => <<"fixture_test.gleam">>, language => <<"gleam">>,
        module => <<"fixture_test">>,
        source_sha256 => binary:copy(<<"a">>, 64), source_bytes => 32,
        beam => <<"fixture_test.beam">>,
        beam_sha256 => binary:copy(<<"b">>, 64), beam_bytes => 128,
        unit_count => 1},
    Inventory0 = #{schema => 1, source_files => 1, modules => 1,
        beam_files => 1, configured_units => 1, relations => [Relation],
        units => [Unit],
        inventory_sha256 => suite_inventory_digest([Relation], [Unit])},
    true = suite_inventory_schema_valid(Inventory0),
    Inventory = runtime_matrix_json(Inventory0),
    ExecutionDigest = binary:copy(<<"a">>, 64),
    LoadedDigest = binary:copy(<<"b">>, 64),
    Child = #{schema => 2, run_nonce => <<"0123456789abcdef0123456789abcdef">>,
        listener_completed => true, eunit_completed => true, unexpected_events => 0,
        failure_count => 0, failures => [], failures_dropped => 0,
        execution_beam_identity => #{runner_sha256 => ExecutionDigest,
            expected_inventory_sha256 => ExecutionDigest,
            loaded_beam_sha256 => LoadedDigest, loaded_beam_count => 1,
            loaded_beams_verified => true},
        units => [Unit#{ordinal => 1, counts => #{started => 1, completed => 1,
            passed => 1, failed => 0, skipped => 0, cancelled => 0}}]},
    Report = runtime_matrix_json(#{schema => 3,
        report_kind => <<"package_suite">>, status => <<"Ready">>, package => Target,
        shareable => true, scope => <<"all source-discovered EUnit tests and generators">>,
        configured_modules => [<<"fixture_test">>], configured_units => 1,
        suite_inventory => Inventory, counts_state => <<"verified">>,
        completed_tests => 1, skipped_tests => 0,
        build_identity => Build, runner_sha256 => ExecutionDigest,
        execution_beam_inventory_sha256 => ExecutionDigest,
        loaded_beam_sha256 => LoadedDigest, loaded_beam_count => 1,
        child => Child,
        child_exit_status => 0, process => runtime_matrix_process_fixture(#{output_bytes => 0, output_hashed_bytes => 0,
            output_limit_bytes => 8388608, output_digest_complete => true,
            output_limit_exceeded => false, vm_process_heap_words => 33554432,
            vm_heap_includes_shared_binaries => true, crash_dumps_disabled => true,
            timed_out => false, child_exit_observed => true}),
        evidence_identity => Identity, execution_environment => Runtime,
        replay => <<"bash scripts/fresh_build.sh ", Target/binary,
                    " && escript scripts/package_suite.escript ", Target/binary>>}),
    Catalog = #{inventory => Inventory, modules => [<<"fixture_test">>],
                units => [Unit],
                source_sha256 => hash(), source_files => 12},
    {Report, Build, Catalog}.

hash() -> binary:copy(<<"A">>, 64).
