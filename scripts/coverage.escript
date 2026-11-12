#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("command_capture.hrl").
-include("suite_evidence.hrl").
-include("suite_discovery.hrl").
-include("json_evidence.hrl").
-include("coverage_report_evidence_tests.hrl").
-compile({nowarn_unused_function, [{output_tail, 1}]}).

-define(OUTPUT, "build/coverage").
-define(POLICY, "coverage-policy.json").
-define(EVIDENCE, "coverage-evidence.json").

main(Arguments) ->
    try dispatch(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            Details = coverage_failure_details(Class, Reason, Stacktrace),
            case get(coverage_failure_path) of
                undefined -> ok;
                FailurePath -> _ = file:write_file(FailurePath, [json:encode(Details), $\n])
            end,
            io:format(standard_error, "qualification failed: ~p~n", [Details]),
            halt(1)
    end.

dispatch([Command | _] = Arguments)
  when Command =:= "capture"; Command =:= "diagnose" ->
    case get(coverage_bounded_worker) of
        true -> run(Arguments);
        _ -> run_bounded_coverage(Arguments)
    end;
dispatch(["report", Mode] = Arguments) when Mode =:= "full"; Mode =:= "changed" ->
    case get(coverage_bounded_worker) of
        true -> run(Arguments);
        _ -> run_bounded_report(Mode, Arguments)
    end;
dispatch(Arguments) -> run(Arguments).

coverage_report_deadline() -> 300000.

run_bounded_report(Mode, Arguments) ->
    Path = filename:join(?OUTPUT, "report-" ++ Mode ++ ".process.json"),
    Attempt = filename:join(?OUTPUT, "report-" ++ Mode ++ ".attempt.json"),
    Nonce = hex(crypto:strong_rand_bytes(16)),
    ok = filelib:ensure_dir(Attempt),
    ok = file:write_file(Attempt, json:encode(#{schema => 1,
        mode => list_to_binary(Mode), nonce => Nonce})),
    FinalReport = filename:join(?OUTPUT, Mode ++ ".json"),
    %% Invalidate before compilation or child startup: failure before entry
    %% cannot make an earlier Ready document describe this attempt.
    delete_if_present(FinalReport),
    delete_if_present(?EVIDENCE),
    Identity = evidence_begin(Path),
    Runner = filename:absname(filename:join([?OUTPUT, "runner", binary_to_list(Nonce)])),
    ok = filelib:ensure_dir(filename:join(Runner, "placeholder")),
    {ok, Sections} = escript:extract(escript:script_name(), [compile_source]),
    {ok, RunnerSource} = file:read_file(escript:script_name()),
    Binary = proplists:get_value(source, Sections),
    {ok, {Module, [{exports, Exports}]}} = beam_lib:chunks(Binary, [exports]),
    true = lists:member({main, 1}, Exports),
    BeamPath = filename:join(Runner, atom_to_list(Module) ++ ".beam"),
    FailurePath = filename:join(Runner, "failure.json"),
    Staging = #{nonce => Nonce, mode => list_to_binary(Mode),
        report => filename:join(Runner, "report.json"),
        evidence => filename:join(Runner, "evidence.json"),
        receipt => filename:join(Runner, "completion.json")},
    ok = file:write_file(BeamPath, Binary, [exclusive]),
    Evaluation = lists:flatten(io_lib:format(
        "put(coverage_bounded_worker,true),put(coverage_failure_path,~0tp),"
        "put(coverage_report_staging,~0tp),~p:main(~0tp),halt(0).",
        [FailurePath, Staging, Module, Arguments])),
    Deadline = coverage_report_deadline(),
    try
        {Status, Output} = run_child_evaluation(filename:absname("."), [Runner], Evaluation, Deadline),
        Documents = coverage_completed_report(Staging, Identity, Status, Output),
        Complete = Status =:= 0 andalso Documents =/= error,
        Base = #{schema => 1, scope => <<"CoverageProcess">>, shareable => true,
            status => case Complete of true -> <<"Ready">>; false -> <<"Failed">> end,
            command => <<"report">>, package => list_to_binary(Mode),
            run_nonce => Nonce, runner_source_sha256 => hex(crypto:hash(sha256, RunnerSource)),
            completion => case Documents of
                {ok, _, _, Receipt} -> Receipt;
                error -> null
            end,
            deadline_milliseconds => Deadline, child_exit_status => Status,
            process => maps:without([tail, output_sha256], Output)},
        WithFailure = case Complete of
            true -> Base;
            false -> Base#{failure => safe_coverage_failure(read_coverage_unit_report(FailurePath))}
        end,
        {Report, Current} = try
            {evidence_complete(WithFailure, Identity), true}
        catch Class:Reason:Stack ->
            {WithFailure#{status => <<"Failed">>, evidence_identity => Identity,
                execution_environment => execution_runtime(),
                failure => coverage_failure_details(Class, Reason, Stack)}, false}
        end,
        %% A completed threshold failure still has useful Blocked documents.
        %% Timeout, output exhaustion, absent/stale receipt or stale source
        %% never publishes either authoritative document.
        case {Documents, Current} of
            {{ok, ReportBytes, EvidenceBytes, _}, true} ->
                coverage_publish_report(FinalReport, ReportBytes, EvidenceBytes);
            _ -> ok
        end,
        ok = file:write_file(Path, [json:encode(Report), $\n]),
        io:format("coverage report ~s: ~s; bounded process report ~s~n",
            [Mode, maps:get(status, Report), Path]),
        ensure(Complete andalso Current, coverage_child_incomplete)
    after
        lists:foreach(fun delete_if_present/1,
            [BeamPath, FailurePath, maps:get(report, Staging),
             maps:get(evidence, Staging), maps:get(receipt, Staging)]),
        _ = file:del_dir(Runner)
    end.

coverage_completed_report(Staging, Identity, Status, Output) ->
    try
        true = Status =:= 0 orelse Status =:= 1,
        true = process_completion_verified(Output),
        false = maps:get(timed_out, Output),
        false = maps:get(output_limit_exceeded, Output),
        {ok, ReceiptBytes} = coverage_report_bytes(maps:get(receipt, Staging), 4096),
        Receipt = coverage_decode_json(ReceiptBytes),
        true = suite_exact_keys(Receipt, [schema, nonce, mode, child_exit_status,
                                         report_sha256, evidence_sha256]),
        1 = maps:get(<<"schema">>, Receipt),
        Status = maps:get(<<"child_exit_status">>, Receipt),
        Nonce = maps:get(nonce, Staging), Nonce = maps:get(<<"nonce">>, Receipt),
        Mode = maps:get(mode, Staging), Mode = maps:get(<<"mode">>, Receipt),
        {ok, ReportBytes} = coverage_report_bytes(maps:get(report, Staging), 16777216),
        {ok, EvidenceBytes} = coverage_report_bytes(maps:get(evidence, Staging), 16777216),
        ReportHash = hex(crypto:hash(sha256, ReportBytes)),
        EvidenceHash = hex(crypto:hash(sha256, EvidenceBytes)),
        ReportHash = maps:get(<<"report_sha256">>, Receipt),
        EvidenceHash = maps:get(<<"evidence_sha256">>, Receipt),
        Report = coverage_decode_json(ReportBytes), Evidence = coverage_decode_json(EvidenceBytes),
        2 = maps:get(<<"schema">>, Report), 2 = maps:get(<<"schema">>, Evidence),
        Mode = maps:get(<<"mode">>, Report),
        Expected = case Status of 0 -> <<"Ready">>; 1 -> <<"Blocked">> end,
        Expected = maps:get(<<"status">>, Report),
        Expected = maps:get(Mode, maps:get(<<"statuses">>, Evidence)),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Evidence),
        {ok, ReportBytes, EvidenceBytes, Receipt}
    catch _:_ -> error end.

coverage_publish_report(Path, Report, Evidence) ->
    try
        ok = file:write_file(Path, Report, [exclusive]),
        ok = file:write_file(?EVIDENCE, Evidence, [exclusive])
    catch Class:Reason:Stack ->
        delete_if_present(Path), delete_if_present(?EVIDENCE),
        erlang:raise(Class, Reason, Stack)
    end.

coverage_report_path(Mode) ->
    case get(coverage_report_staging) of
        #{report := Path} -> Path;
        _ -> filename:join(?OUTPUT, Mode ++ ".json")
    end.

coverage_evidence_path() ->
    case get(coverage_report_staging) of
        #{evidence := Path} -> Path;
        _ -> ?EVIDENCE
    end.

coverage_report_completion(Mode, Result) ->
    #{nonce := Nonce, receipt := Receipt, report := Report, evidence := Evidence} = get(coverage_report_staging),
    {ok, ReportBytes} = coverage_report_bytes(Report, 16777216),
    {ok, EvidenceBytes} = coverage_report_bytes(Evidence, 16777216),
    Exit = case Result of ok -> 0; {blocked, _} -> 1 end,
    Record = #{schema => 1, nonce => Nonce, mode => list_to_binary(Mode),
        child_exit_status => Exit, report_sha256 => hex(crypto:hash(sha256, ReportBytes)),
        evidence_sha256 => hex(crypto:hash(sha256, EvidenceBytes))},
    ok = file:write_file(Receipt, json:encode(Record), [exclusive]).

run_bounded_coverage([Command, Name | _] = Arguments) ->
    ensure(valid_diagnostic_name(Name), invalid_coverage_name),
    Directory = filename:absname("."),
    Path = filename:join(?OUTPUT, Command ++ "-" ++ Name ++ ".process.json"),
    Identity = evidence_begin(Path),
    delete_if_present(Path),
    Nonce = binary_to_list(hex(crypto:strong_rand_bytes(16))),
    Runner = filename:absname(filename:join([?OUTPUT, "runner", Nonce])),
    ok = filelib:ensure_dir(filename:join(Runner, "placeholder")),
    {ok, Sections} = escript:extract(escript:script_name(), [compile_source]),
    Binary = proplists:get_value(source, Sections),
    {ok, {Module, [{exports, Exports}]}} = beam_lib:chunks(Binary, [exports]),
    true = lists:member({main, 1}, Exports),
    BeamPath = filename:join(Runner, atom_to_list(Module) ++ ".beam"),
    FailurePath = filename:join(Runner, "failure.json"),
    ok = file:write_file(BeamPath, Binary),
    Evaluation = lists:flatten(io_lib:format(
        "put(coverage_bounded_worker,true),put(coverage_failure_path,~0tp),~p:main(~0tp),halt(0).",
        [FailurePath, Module, Arguments])),
    %% This bounds the complete repetition history, including instrumentation,
    %% cleanup and export. Per-test ceilings remain independent and finite.
    Deadline = 7200000,
    try
        {Status, Output} = run_child_evaluation(Directory, [Runner], Evaluation, Deadline),
        Complete = process_status_verified(Status, 0, Output),
        BaseReport = #{schema => 1, scope => <<"CoverageProcess">>, shareable => true,
                   status => case Complete of true -> <<"Ready">>; false -> <<"Failed">> end,
                   command => list_to_binary(Command), package => list_to_binary(Name),
                   deadline_milliseconds => Deadline, child_exit_status => Status,
                   process => maps:without([tail, output_sha256], Output)},
        Report = case Complete of
            true -> BaseReport;
            false -> BaseReport#{failure => safe_coverage_failure(
                read_coverage_unit_report(FailurePath))}
        end,
        CompletedReport = try evidence_complete(Report, Identity)
        catch Class:Reason:Stack ->
            Report#{status => <<"Failed">>, evidence_identity => Identity,
                    execution_environment => execution_runtime(),
                    failure => coverage_failure_details(Class, Reason, Stack)}
        end,
        ok = file:write_file(Path, [json:encode(CompletedReport), $\n]),
        io:format("coverage ~s ~s: ~s; bounded process report ~s~n",
                  [Command, Name, maps:get(status, CompletedReport), Path]),
        ensure(Complete andalso maps:get(status, CompletedReport) =:= <<"Ready">>,
               coverage_child_incomplete)
    after
        delete_if_present(BeamPath),
        delete_if_present(FailurePath),
        _ = file:del_dir(Runner)
    end.

safe_coverage_failure(Value) ->
    try
        Keys = [exception_class, exception_reason, stacktrace],
        Coordinate = maps:get(<<"coordinate">>, Value, undefined),
        true = suite_exact_keys(Value, case Coordinate of undefined -> Keys; _ -> [coordinate | Keys] end),
        true = Coordinate =:= undefined orelse coverage_coordinate_valid(Coordinate),
        true = lists:member(maps:get(<<"exception_class">>, Value),
                            [<<"error">>, <<"exit">>, <<"throw">>, <<"unknown">>]),
        Stack = maps:get(<<"stacktrace">>, Value),
        true = is_binary(Stack) andalso byte_size(Stack) =< 16384,
        true = suite_failure_schema(#{<<"unit">> => 0,
            <<"classification">> => maps:get(<<"exception_reason">>, Value),
            <<"stack">> => coverage_decode_json(Stack)}, 0),
        Value
    catch _:_ -> diagnostic_failure_details(error, coverage_child_incomplete, []) end.

coverage_failure_details(Class, Reason, Stack) ->
    Base = diagnostic_failure_details(Class, Reason, Stack),
    case coverage_coordinate_detail(Reason) of
        undefined -> Base;
        Coordinate -> Base#{coordinate => Coordinate}
    end.

coverage_coordinate_detail({Kind, Module, Index, #{branch := Branch, observed := Observed,
                                                 siblings := Siblings}})
  when Kind =:= unobservable_branch_coordinates; Kind =:= indistinguishable_branch_coordinates ->
    try
        Result = #{<<"kind">> => atom_to_binary(Kind), <<"module">> => atom_to_binary(Module),
            <<"function">> => atom_to_binary(maps:get(function, Branch)),
            <<"arity">> => maps:get(arity, Branch), <<"index">> => Index,
            <<"source_first_line">> => maps:get(source_first_line, Branch),
            <<"source_last_line">> => maps:get(source_last_line, Branch),
            <<"artifact_lines">> => lists:sublist(maps:get(artifact_lines, Branch), 64),
            <<"observed_lines">> => lists:sublist(Observed, 64),
            <<"sibling_lines">> => lists:sublist(Siblings, 64)},
        true = coverage_coordinate_valid(Result),
        Result
    catch _:_ -> undefined end;
coverage_coordinate_detail(_) -> undefined.

coverage_coordinate_valid(Value) ->
    try
        true = suite_exact_keys(Value, [kind, module, function, arity, index,
            source_first_line, source_last_line, artifact_lines, observed_lines, sibling_lines]),
        true = lists:member(maps:get(<<"kind">>, Value),
            [<<"unobservable_branch_coordinates">>, <<"indistinguishable_branch_coordinates">>]),
        true = suite_safe_identifier(maps:get(<<"module">>, Value)),
        true = suite_safe_identifier(maps:get(<<"function">>, Value)),
        true = lists:all(fun suite_count_value/1,
            [maps:get(Key, Value) || Key <- [<<"arity">>, <<"index">>,
                <<"source_first_line">>, <<"source_last_line">>]]),
        true = maps:get(<<"arity">>, Value) =< 255,
        lists:all(fun(Key) ->
            Lines = maps:get(Key, Value),
            is_list(Lines) andalso length(Lines) =< 64 andalso lists:all(fun suite_count_value/1, Lines)
        end, [<<"artifact_lines">>, <<"observed_lines">>, <<"sibling_lines">>])
    catch _:_ -> false end.

run(["reset"]) -> reset_output();
run(["--self-test"]) -> self_test();
run(["--self-test-selection"]) -> selection_json_self_test();
run(["--self-test-report-runner"]) -> coverage_report_runner_self_test();
run(["capture", Name, SourceRoot, Ebin, Export]) ->
    capture(Name, SourceRoot, Ebin, Export);
run(["diagnose", Name, SourceRoot, Ebin, Module, Test, Repetitions]) ->
    diagnose(Name, SourceRoot, Ebin, Module, Test, Repetitions);
run(["audit-coordinates", Name, SourceRoot, Ebin]) ->
    audit_coordinates(Name, SourceRoot, Ebin);
run(["report", Mode]) when Mode =:= "changed"; Mode =:= "full" ->
    report(Mode);
run(_) ->
    erlang:error({usage,
                  "reset | capture NAME SOURCE_ROOT EBIN EXPORT | "
                  "diagnose NAME SOURCE_ROOT EBIN MODULE TEST REPETITIONS | "
                  "audit-coordinates NAME SOURCE_ROOT EBIN | "
                  "report changed|full"}).

reset_output() ->
    Expected = filename:join(filename:absname("build"), "coverage"),
    case filename:absname(?OUTPUT) of
        Expected ->
            _ = file:del_dir_r(Expected),
            ok = filelib:ensure_dir(filename:join(Expected, "placeholder")),
            delete_if_present(?EVIDENCE);
        Unsafe -> erlang:error({unsafe_coverage_output, Unsafe})
    end.

capture(Name, SourceRoot, Ebin0, Export0) ->
    put(coverage_instrumentation_path,
        filename:absname(filename:join(?OUTPUT, "instrumentation-" ++ Name ++ ".json"))),
    Identity = evidence_begin(capture_metadata_path(filename:absname(Export0))),
    put(coverage_capture_identity, Identity),
    delete_if_present(coverage_progress_path(Name)),
    delete_if_present(package_gaps_path(Name)),
    fresh_verify_many([case Name of "quic_core" -> "core"; _ -> Name end]),
    add_package_code_paths(Ebin0),
    Ebin = filename:absname(Ebin0),
    Export = filename:absname(Export0),
    delete_capture_artifacts(Export),
    true = code:add_patha(Ebin),
    Sources = production_sources(SourceRoot),
    Modules = [{module_for_source(Path), Path} || Path <- Sources],
    ensure(length(Modules) =:= length(lists:usort([M || {M, _} <- Modules])),
           {duplicate_production_module, Name}),
    CoverageMap = maps:from_list([
        {Module, coverage_model(
                     Module, Path, beam_path(Ebin, Module)
                 )} || {Module, Path} <- Modules
    ]),
    {ok, _} = cover:start(),
    try capture_started(Name, SourceRoot, Ebin, Export, Modules, CoverageMap, Identity)
    after
        cover:stop()
    end.

capture_started(Name, SourceRoot, Ebin, Export, Modules, CoverageMap, Identity) ->
    ok = cover_compile_modules(Modules, Ebin),
    ok = load_coverage_listener(),
    TestModules = test_modules(Ebin, SourceRoot),
    ensure(TestModules =/= [], {no_eunit_modules, Name}),
    Units = lists:append([suite_beam_units(Ebin, atom_to_binary(Module)) || Module <- TestModules]),
    TestEntrypoints = length(Units),
    ensure(TestEntrypoints > 0, {no_eunit_test_entrypoints, Name}),
    InitialCoverage = coverage_snapshot(Modules, CoverageMap),
    CoordinateModelDigest = coverage_coordinate_digest(
        CoverageMap, InitialCoverage
    ),
    RuntimeBefore = runtime_snapshot(),
    {RepetitionReports, _FinalCoverage, StopReason} = run_coverage_repetitions(
        1,
        Name,
        filename:absname(SourceRoot),
        Units,
        Modules,
        CoverageMap,
        InitialCoverage,
        RuntimeBefore,
        0,
        []
    ),
    ok = filelib:ensure_dir(Export),
    ok = cover:export(Export),
    SourcePaths = coverage_source_paths(),
    CompiledBeamPaths = lists:sort(filelib:wildcard(
        filename:join(Ebin, "*.beam")
    )),
    ensure(CompiledBeamPaths =/= [], {no_compiled_coverage_beams, Name}),
    Growth = capture_growth_summary(RepetitionReports),
    RuntimeConvergence = capture_runtime_summary(
        RuntimeBefore, RepetitionReports),
    CapturePolicy = current_capture_policy(),
    PathsSaturated = StopReason =:= saturated,
    Metadata = #{schema => 2,
                 coordinate_methodology => current_coordinate_methodology(),
                 coordinate_model_sha256 => CoordinateModelDigest,
                 status => case PathsSaturated andalso
                                    maps:get(final_resource_counts_converged,
                                             RuntimeConvergence) of
                               true -> <<"Ready">>;
                               false -> <<"Blocked">>
                           end,
                 package => unicode:characters_to_binary(Name),
                 source_root => unicode:characters_to_binary(
                     relative(filename:absname(SourceRoot))),
                 source_sha256 => digest_paths(SourcePaths),
                 source_files => length(SourcePaths),
                 policy_sha256 => file_digest(?POLICY),
                 artifact_sha256 => digest_paths(CompiledBeamPaths),
                 compiled_beams => length(CompiledBeamPaths),
                 compiled_beam_names =>
                     [unicode:characters_to_binary(filename:basename(Path))
                      || Path <- CompiledBeamPaths],
                 cover_sha256 => file_digest(Export),
                 otp_release => unicode:characters_to_binary(
                     erlang:system_info(otp_release)),
                 erts_version => unicode:characters_to_binary(
                     erlang:system_info(version)),
                 instrumented_modules => length(Modules),
                 instrumented_module_names =>
                     [atom_to_binary(Module) || {Module, _Path} <- Modules],
                 test_modules => length(TestModules),
                 test_module_names =>
                     [atom_to_binary(Module) || Module <- TestModules],
                 test_entrypoints => TestEntrypoints,
                 configured_units => Units,
                 instrumentation => get(coverage_instrumentation_evidence),
                 minimum_repetitions =>
                     maps:get(minimum_repetitions, CapturePolicy),
                 maximum_repetitions =>
                     maps:get(maximum_repetitions, CapturePolicy),
                 required_quiescent_repetitions =>
                     maps:get(required_quiescent_repetitions, CapturePolicy),
                 runtime_settle_max_milliseconds =>
                     maps:get(runtime_settle_max_milliseconds, CapturePolicy),
                 runtime_settle_interval_milliseconds =>
                     maps:get(runtime_settle_interval_milliseconds,
                              CapturePolicy),
                 runtime_settle_quiet_samples =>
                     maps:get(runtime_settle_quiet_samples, CapturePolicy),
                 repetition_count => length(RepetitionReports),
                 paths_saturated => PathsSaturated,
                 stop_reason => atom_to_binary(StopReason),
                 initial_coverage => snapshot_metrics(InitialCoverage),
                 runtime_before => RuntimeBefore,
                 repetitions => RepetitionReports,
                 growth => Growth,
                 runtime_convergence => RuntimeConvergence},
    MetadataPath = capture_metadata_path(Export),
    CompletedMetadata = evidence_complete(Metadata, Identity),
    ok = file:write_file(MetadataPath,
        [json:encode(CompletedMetadata), <<"\n">>]),
    ok = write_package_gaps(Name, Modules, CoverageMap, CompletedMetadata, MetadataPath),
    io:format(
        "captured ~s coverage: ~B modules, ~B test modules/~B entrypoints, "
        "~B repetitions; "
        "later growth +~B lines/+~B branches; paths saturated: ~p; "
        "runtime resources converged: ~p~n",
        [Name, length(Modules), length(TestModules), TestEntrypoints,
         length(RepetitionReports),
         maps:get(lines, maps:get(later_growth, Growth)),
         maps:get(branches, maps:get(later_growth, Growth)),
         PathsSaturated,
         maps:get(final_resource_counts_converged, RuntimeConvergence)]
    ),
    ensure(maps:get(final_resource_counts_converged, RuntimeConvergence),
           {coverage_runtime_did_not_converge, Name,
            capture_metadata_path(Export), RuntimeConvergence}),
    ensure(PathsSaturated,
           {coverage_paths_not_saturated, Name,
            maps:get(maximum_repetitions, CapturePolicy), Growth}),
    ok.

audit_coordinates(Name, SourceRoot, Ebin0) ->
    add_package_code_paths(Ebin0),
    Ebin = filename:absname(Ebin0),
    true = code:add_patha(Ebin),
    Sources = production_sources(SourceRoot),
    Modules = [{module_for_source(Path), Path} || Path <- Sources],
    ensure(length(Modules) =:= length(lists:usort([M || {M, _} <- Modules])),
           {duplicate_production_module, Name}),
    CoverageMap = maps:from_list([
        {Module, coverage_model(
                     Module, Path, beam_path(Ebin, Module)
                 )} || {Module, Path} <- Modules
    ]),
    {ok, _} = cover:start(),
    try
        ok = cover_compile_modules(Modules, Ebin),
        Snapshot = coverage_snapshot(Modules, CoverageMap),
        Metrics = snapshot_metrics(Snapshot),
        CoordinateDigest = coverage_coordinate_digest(CoverageMap, Snapshot),
        io:format(
            "coverage coordinate audit ~s: ~B modules, ~B executable lines, "
            "~B observable clause alternatives; model ~s~n",
            [Name, length(Modules),
             maps:get(total, maps:get(lines, Metrics)),
             maps:get(total, maps:get(branches, Metrics)),
             CoordinateDigest]
        ),
        ok
    after
        cover:stop()
    end.

cover_compile_modules(Modules, Ebin) ->
    Watcher = spawn(fun() -> instrumentation_watch(
        #{gc_samples => 0, peak_gc_heap_block_words => 0,
          peak_gc_live_heap_words => 0, attempted_modules => 0,
          compiled_modules => 0}) end),
    Monitor = monitor(process, Watcher),
    PreviousMonitor = erlang:system_monitor(Watcher, [{large_heap, 1000000}]),
    PreviousHeap = erlang:system_flag(max_heap_size,
        #{size => 134217728, kill => true, error_logger => false, include_shared_binaries => true}),
    Outcome = try
        lists:foreach(fun({Module, Path}) ->
            Watcher ! {attempt, Module},
        Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
        ensure(filelib:is_regular(Beam), {missing_production_beam, Path, Beam}),
        case cover:compile_beam(Beam) of
            {ok, Module} -> Watcher ! compiled;
            Error -> erlang:error({cannot_instrument, Path, Error})
        end
        end, Modules),
        ok
    catch Class:Reason:Stack -> {error, Class, Reason, Stack}
    after
        %% Compiler allocations cannot enlarge the budget inherited by test
        %% callbacks, protocol actors, EUnit capture or cleanup descendants.
        erlang:system_flag(max_heap_size, PreviousHeap),
        restore_instrumentation_monitor(PreviousMonitor)
    end,
    Reference = make_ref(),
    Watcher ! {finish, self(), Reference},
    Sample = receive {Reference, Value} -> Value after 1000 ->
        exit(Watcher, kill), erlang:error(instrumentation_observer_timeout)
    end,
    receive {'DOWN', Monitor, process, Watcher, normal} -> ok after 1000 ->
        exit(Watcher, kill), erlang:error(instrumentation_observer_did_not_stop)
    end,
    Evidence = Sample#{schema => 1, observation => <<"sampled_gc">>,
        status => case Outcome of ok -> <<"Ready">>; _ -> <<"Failed">> end,
        compiler_heap_words => 134217728,
        restored_heap_words => maps:get(size, erlang:system_info(max_heap_size)),
        heap_configuration_restored => PreviousHeap =:= erlang:system_info(max_heap_size)},
    put(coverage_instrumentation_evidence, Evidence),
    case get(coverage_instrumentation_path) of
        undefined -> ok;
        EvidencePath ->
            ok = filelib:ensure_dir(EvidencePath),
            ok = file:write_file(EvidencePath, [json:encode(Evidence), $\n])
    end,
    case Outcome of ok -> ok; {error, C, R, S} -> erlang:raise(C, R, S) end.

restore_instrumentation_monitor(undefined) -> erlang:system_monitor(undefined);
restore_instrumentation_monitor({Pid, Options}) -> erlang:system_monitor(Pid, Options).

instrumentation_watch(State) ->
    receive
        {monitor, _, large_heap, Info} ->
            Blocks = proplists:get_value(heap_block_size, Info, 0) +
                     proplists:get_value(old_heap_block_size, Info, 0) +
                     proplists:get_value(mbuf_size, Info, 0),
            Live = proplists:get_value(heap_size, Info, 0) +
                   proplists:get_value(old_heap_size, Info, 0),
            instrumentation_watch(State#{
                gc_samples => erlang:min(2147483647, maps:get(gc_samples, State) + 1),
                peak_gc_heap_block_words => erlang:max(Blocks, maps:get(peak_gc_heap_block_words, State)),
                peak_gc_live_heap_words => erlang:max(Live, maps:get(peak_gc_live_heap_words, State))});
        {attempt, Module} -> instrumentation_watch(State#{
            attempted_modules => maps:get(attempted_modules, State) + 1,
            last_module => atom_to_binary(Module)});
        compiled -> instrumentation_watch(State#{compiled_modules => maps:get(compiled_modules, State) + 1});
        {finish, Owner, Reference} -> Owner ! {Reference, State}
    end.

run_coverage_repetitions(Index, Name, Directory, Units, Modules,
                         CoverageMap, Previous, RuntimeBefore,
                         QuiescentRepetitions, Acc) ->
    Started = erlang:monotonic_time(millisecond),
    TestEvidence = case eunit_in_directory(Directory, Units) of
        {ok, Evidence} -> Evidence;
        {error, FailedTests} = Error ->
            Partial = preserve_failed_coverage(Name, Index, FailedTests,
                Modules, CoverageMap, RuntimeBefore, Acc),
            write_capture_progress(Name, #{phase => <<"Tests">>, status => <<"Failed">>,
                repetition => Index, tests => FailedTests, partial_coverage => Partial}),
            CapturePolicy = current_capture_policy(),
            erlang:error({coverage_test_failure, Name, Index,
                          maps:get(maximum_repetitions, CapturePolicy), Error})
    end,
    Duration = erlang:monotonic_time(millisecond) - Started,
    RuntimeImmediate = runtime_snapshot(),
    WarmReference = case Acc of
        [] -> undefined;
        _ -> maps:get(runtime, lists:last(Acc))
    end,
    Settlement = settle_runtime(RuntimeBefore, WarmReference),
    RuntimeAfter = settlement_final_runtime(Settlement),
    Current = coverage_snapshot(Modules, CoverageMap),
    BaseReport = summarize_coverage_repetition(
        Index, Previous, Current, Duration
    ),
    PreviousRuntime = case Acc of
        [] -> RuntimeBefore;
        [PreviousReport | _] -> maps:get(runtime, PreviousReport)
    end,
    Report = BaseReport#{test_duration_ms => Duration,
                         tests => TestEvidence,
                         settle_duration_ms =>
                             maps:get(elapsed_milliseconds, Settlement),
                         runtime_immediate => RuntimeImmediate,
                         runtime => RuntimeAfter,
                         settlement => Settlement,
                         runtime_delta_from_start =>
                             runtime_delta(RuntimeBefore, RuntimeAfter),
                         runtime_delta_from_previous =>
                             runtime_delta(PreviousRuntime, RuntimeAfter)},
    print_repetition_summary(Name, Report),
    NextQuiescent = case repetition_grew(Report) of
        true -> 0;
        false -> QuiescentRepetitions + 1
    end,
    write_capture_progress(Name, #{phase => <<"RepetitionCompleted">>, status => <<"Running">>,
        repetition => Index, quiescent_repetitions => NextQuiescent,
        measurement => maps:with([duration_ms, tests, settle_duration_ms,
            cumulative, added, runtime, settlement], Report)}),
    case maps:get(converged, Settlement) of
        false ->
            {lists:reverse([Report | Acc]), Current, runtime_not_converged};
        true ->
            case capture_stop_decision(Index, NextQuiescent) of
                continue ->
                    run_coverage_repetitions(
                        Index + 1, Name, Directory, Units, Modules,
                        CoverageMap, Current, RuntimeBefore, NextQuiescent,
                        [Report | Acc]
                    );
                StopReason ->
                    {lists:reverse([Report | Acc]), Current, StopReason}
            end
    end.

preserve_failed_coverage(Name, Index, Tests, Modules, Models, RuntimeBefore, Previous) ->
    %% Failure must never discard counters from earlier successful repetitions.
    %% This export is deliberately outside the qualified capture glob, and its
    %% explicit non-gating scope cannot satisfy the final capture auditor.
    try
        Settlement = settle_runtime(RuntimeBefore, undefined),
        SourceMap = maps:from_list([{M, relative(P)} || {M, P} <- Modules]),
        Reports = [module_report(M, SourceMap, #{}, maps:get(M, Models))
                   || {M, _} <- Modules],
        Export = filename:join([?OUTPUT, "diagnostic", Name ++ ".cover"]),
        Path = filename:join([?OUTPUT, "diagnostic", Name ++ ".json"]),
        ok = filelib:ensure_dir(Export),
        ok = cover:export(Export),
        Report = #{schema => 1, scope => <<"PartialCoverageAfterTestFailure">>,
            satisfies_coverage_gate => false, lower_bound => true,
            status => <<"MeasuredWithTestFailures">>, package => list_to_binary(Name),
            initial_source_identity => get(coverage_capture_identity),
            failed_repetition => Index, completed_repetitions => length(Previous),
            tests => Tests, settlement => Settlement, runtime_before => RuntimeBefore,
            instrumentation => get(coverage_instrumentation_evidence),
            metrics => metric_json(#{lines => sum_metric(Reports, full_lines),
                branches => sum_metric(Reports, full_branches)}),
            modules => Reports, cover_sha256 => file_digest(Export)},
        ok = file:write_file(Path, [json:encode(Report), $\n]),
        #{status => <<"Retained">>, report => list_to_binary(Path)}
    catch _:_ ->
        %% A secondary diagnostic failure cannot replace the original test
        %% failure or publish an arbitrary exception payload.
        #{status => <<"Unavailable">>}
    end.

coverage_progress_path(Name) ->
    filename:join(?OUTPUT, "capture-progress-" ++ Name ++ ".json").

package_gaps_path(Name) ->
    filename:join([?OUTPUT, "diagnostic", Name ++ ".gaps.json"]).

write_package_gaps(Name, Modules, Models, Metadata, CapturePath) ->
    %% This reads this package's actual counters while its instrumented VM is
    %% still alive. It is deliberately outside the capture glob: diagnostics
    %% cannot replace the three-package, current-source qualification audit.
    SourceMap = maps:from_list([{M, relative(P)} || {M, P} <- Modules]),
    Reports = [module_report(M, SourceMap, #{}, maps:get(M, Models))
               || {M, _} <- Modules],
    Report = #{schema => 1, scope => <<"PackageCoverageGaps">>,
        status => <<"Measured">>, satisfies_coverage_gate => false,
        package => list_to_binary(Name),
        capture_status => maps:get(status, Metadata),
        capture_sha256 => file_digest(CapturePath),
        source_sha256 => maps:get(source_sha256, Metadata),
        coordinate_model_sha256 => maps:get(coordinate_model_sha256, Metadata),
        cover_sha256 => maps:get(cover_sha256, Metadata),
        completed_repetitions => maps:get(repetition_count, Metadata),
        stop_reason => maps:get(stop_reason, Metadata),
        evidence_identity => maps:get(evidence_identity, Metadata),
        execution_environment => maps:get(execution_environment, Metadata),
        metrics => metric_json(#{lines => sum_metric(Reports, full_lines),
            branches => sum_metric(Reports, full_branches)}),
        modules => [maps:without([changed_selection, changed_lines, changed_branches,
            changed_uncovered_lines, changed_uncovered_branches], R) || R <- Reports]},
    Path = package_gaps_path(Name),
    ok = filelib:ensure_dir(Path),
    file:write_file(Path, [json:encode(Report), $\n]).

write_capture_progress(Name, Record) ->
    %% The bounded child never forwards untrusted stdout. This independently
    %% readable, typed checkpoint preserves live phase evidence and the last
    %% successful measurement even before the final capture can be qualified.
    Report = Record#{schema => 1, scope => <<"CoverageProgress">>,
        satisfies_coverage_gate => false, package => list_to_binary(Name),
        initial_source_identity => get(coverage_capture_identity)},
    Path = coverage_progress_path(Name),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), $\n]).

print_repetition_summary(Name, Report) ->
    Cumulative = maps:get(cumulative, Report),
    Lines = maps:get(lines, Cumulative),
    Branches = maps:get(branches, Cumulative),
    Added = maps:get(added, Report),
    Index = maps:get(repetition, Report),
    CapturePolicy = current_capture_policy(),
    io:format(
        "~s coverage repetition ~B (minimum ~B, maximum ~B): "
        "lines ~B/~B (+~B), "
        "observable clause alternatives ~B/~B (+~B), test ~B ms, "
        "settle ~B ms, project processes ~B, network ports ~B, "
        "sockets ~B~n",
        [Name, Index,
         maps:get(minimum_repetitions, CapturePolicy),
         maps:get(maximum_repetitions, CapturePolicy),
         maps:get(covered, Lines), maps:get(total, Lines),
         maps:get(lines, Added),
         maps:get(covered, Branches), maps:get(total, Branches),
         maps:get(branches, Added), maps:get(test_duration_ms, Report),
         maps:get(settle_duration_ms, Report),
         maps:get(project_processes, maps:get(runtime, Report)),
         maps:get(network_ports, maps:get(runtime, Report)),
         maps:get(sockets, maps:get(runtime, Report))]
    ),
    case Index > 1 andalso
         (maps:get(lines, Added) > 0 orelse maps:get(branches, Added) > 0) of
        true -> print_repetition_growth(Report);
        false -> ok
    end.

print_repetition_growth(Report) ->
    Lines = lists:sublist(maps:get(newly_covered_lines, Report), 12),
    Branches = lists:sublist(maps:get(newly_covered_branches, Report), 12),
    io:format("  newly reached line coordinates: ~s~n",
              [coordinate_text(Lines)]),
    io:format("  newly reached branch coordinates: ~s~n",
              [coordinate_text(Branches)]).

coordinate_text(Coordinates) -> json:encode(Coordinates).

delete_capture_artifacts(Export) ->
    lists:foreach(fun delete_if_present/1,
                  [Export, capture_metadata_path(Export),
                   filename:rootname(Export, ".cover") ++ ".modules"]).

delete_if_present(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> erlang:error({cannot_delete_stale_capture, Path, Reason})
    end.

%% Repeat one exported test under the same OTP cover instrumentation as the
%% aggregate package capture. This is deliberately a non-gating diagnostic:
%% it isolates failures which need both instrumentation and same-VM history
%% without allowing a selected test to stand in for complete suite evidence.
diagnose(Name, SourceRoot, Ebin0, ModuleText, TestText, RepetitionsText) ->
    ensure(valid_diagnostic_name(Name), {invalid_diagnostic_name, Name}),
    put(coverage_instrumentation_path,
        filename:absname(filename:join(?OUTPUT, "instrumentation-" ++ Name ++ ".json"))),
    Repetitions = diagnostic_repetitions(RepetitionsText),
    add_package_code_paths(Ebin0),
    Ebin = filename:absname(Ebin0),
    true = code:add_patha(Ebin),
    Sources = production_sources(SourceRoot),
    Modules = [{module_for_source(Path), Path} || Path <- Sources],
    TestModules = test_modules(Ebin, SourceRoot),
    Module = select_named_atom(ModuleText, TestModules,
                               diagnostic_test_module_not_found),
    Test = select_named_atom(
        TestText,
        [ExportName || {ExportName, 0} <- eunit_test_exports(Ebin, Module)],
        diagnostic_test_not_found),
    Path = filename:join(?OUTPUT, "diagnostic-" ++ Name ++ ".json"),
    delete_if_present(Path),
    ok = load_coverage_listener(),
    {ok, _} = cover:start(),
    try
        ok = cover_compile_modules(Modules, Ebin),
        run_coverage_diagnostic(
            Name, SourceRoot, Ebin, Modules, Module, Test, Repetitions, Path)
    after
        cover:stop()
    end.

run_coverage_diagnostic(
    Name, SourceRoot, Ebin, Modules, Module, Test, Repetitions, Path
) ->
    SourcePaths = coverage_source_paths(),
    ProductionBeams = [filename:join(
        Ebin, atom_to_list(ProductionModule) ++ ".beam")
        || {ProductionModule, _} <- Modules],
    TestBeam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    RuntimeBefore = runtime_snapshot(),
    Directory = filename:absname(SourceRoot),
    Outcome = run_coverage_diagnostic_repetitions(
        1, Repetitions, Directory, Module, Test,
        [#{runtime => RuntimeBefore}]),
    {Status, Completed, Samples, Failure} = case Outcome of
        {ok, Count, RuntimeSamples} ->
            {<<"Ready">>, Count, RuntimeSamples, undefined};
        {error, Count, RuntimeSamples, ErrorEvidence} ->
            {<<"Failed">>, Count, RuntimeSamples, ErrorEvidence}
    end,
    OrderedSamples = lists:reverse(Samples),
    RepetitionEvidence = [Sample || Sample <- OrderedSamples,
                                     maps:is_key(iteration, Sample)],
    RuntimeSummary = capture_runtime_summary(
        RuntimeBefore, RepetitionEvidence),
    BaseReport = #{schema => 2,
                   scope => <<"InstrumentedTargetDiagnostic">>,
                   shareable => false,
                   satisfies_coverage_gate => false,
                   status => Status,
                   package => unicode:characters_to_binary(Name),
                   module => atom_to_binary(Module),
                   test => atom_to_binary(Test),
                   configured_repetitions => Repetitions,
                   attempted_repetitions => length(RepetitionEvidence),
                   completed_repetitions => Completed,
                   source_sha256 => digest_paths(SourcePaths),
                   artifact_sha256 => digest_paths(
                       ProductionBeams ++ [TestBeam]),
                   policy_sha256 => file_digest(?POLICY),
                   instrumentation => get(coverage_instrumentation_evidence),
                   otp_release => unicode:characters_to_binary(
                       erlang:system_info(otp_release)),
                   erts_version => unicode:characters_to_binary(
                       erlang:system_info(version)),
                   repetitions => RepetitionEvidence,
                   timing => diagnostic_timing_evidence(RepetitionEvidence),
                   runtime_convergence => RuntimeSummary},
    Report = case Failure of
        undefined -> BaseReport;
        ReportEvidence -> BaseReport#{first_failure => ReportEvidence}
    end,
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    case Failure of
        undefined ->
            io:format(
                "coverage diagnostic ~s: ~B/~B instrumented same-VM "
                "executions passed; non-gating report ~s~n",
                [Name, Completed, Repetitions, Path]),
            ok;
        OutputEvidence ->
            io:format("coverage diagnostic failed: ~s~n",
                      [json:encode(OutputEvidence)]),
            erlang:error({coverage_diagnostic_test_failure, Name,
                          Completed + 1, Path})
    end.

run_coverage_diagnostic_repetitions(
    Index, Repetitions, _Directory, _Module, _Test, Samples
) when Index > Repetitions ->
    {ok, Repetitions, Samples};
run_coverage_diagnostic_repetitions(
    Index, Repetitions, Directory, Module, Test, Samples
) ->
    io:format("coverage diagnostic ~p: instrumented same VM ~B/~B~n",
              [Test, Index, Repetitions]),
    Started = erlang:monotonic_time(millisecond),
    [Kind] = suite_test_kind(atom_to_binary(Test)),
    Unit = #{module => atom_to_binary(Module), function => atom_to_binary(Test), kind => Kind},
    Outcome = eunit_in_directory(Directory, [Unit], 240),
    Duration = erlang:monotonic_time(millisecond) - Started,
    RuntimeImmediate = runtime_snapshot(),
    RuntimeBefore = maps:get(runtime, lists:last(Samples)),
    RepetitionSamples = [Sample || Sample <- Samples,
                                   maps:is_key(iteration, Sample)],
    WarmReference = case RepetitionSamples of
        [] -> undefined;
        _ -> maps:get(runtime, lists:last(RepetitionSamples))
    end,
    Settlement = settle_runtime(RuntimeBefore, WarmReference),
    Runtime = settlement_final_runtime(Settlement),
    Previous = maps:get(runtime, hd(Samples)),
    Delta = runtime_delta(Previous, Runtime),
    io:format(
        "  test ~B ms; settle ~B ms; process ~s, port ~s, ETS ~s, "
        "messages ~s; project processes ~B, network ports ~B, sockets ~B~n",
        [Duration, maps:get(elapsed_milliseconds, Settlement),
         signed_integer_text(maps:get(processes, Delta)),
         signed_integer_text(maps:get(ports, Delta)),
         signed_integer_text(maps:get(ets_tables, Delta)),
         signed_integer_text(maps:get(queued_messages, Delta)),
         maps:get(project_processes, Runtime),
         maps:get(network_ports, Runtime), maps:get(sockets, Runtime)]),
    Result = case {Outcome, maps:get(converged, Settlement)} of
        {{ok, _}, true} -> <<"Passed">>;
        {{error, _}, _} -> <<"Failed">>;
        {{ok, _}, false} -> <<"ResourceFailed">>
    end,
    Evidence = #{iteration => Index,
                 outcome => Result,
                 tests => case Outcome of {ok, Proof} -> Proof; {error, Proof} -> Proof end,
                 duration_ms => Duration,
                 test_duration_ms => Duration,
                 settle_duration_ms =>
                     maps:get(elapsed_milliseconds, Settlement),
                 runtime_immediate => RuntimeImmediate,
                 runtime => Runtime,
                 settlement => Settlement,
                 runtime_delta_from_start =>
                     runtime_delta(RuntimeBefore, Runtime),
                 runtime_delta_from_previous => Delta},
    UpdatedSamples = [Evidence | Samples],
    case {Outcome, maps:get(converged, Settlement)} of
        {{ok, _}, true} ->
            run_coverage_diagnostic_repetitions(
                Index + 1, Repetitions, Directory, Module, Test,
                UpdatedSamples);
        {{error, Failure}, _} ->
            {error, Index - 1, UpdatedSamples,
             diagnostic_failure_evidence(Index, Failure, 16384)};
        {{ok, _}, false} ->
            {error, Index - 1, UpdatedSamples,
             diagnostic_failure_evidence(
                 Index, {runtime_did_not_converge, Settlement}, 16384)}
    end.

run_in_directory(Directory, Fun, TimeoutMilliseconds) ->
    run_in_directory_with_completion(Directory, Fun, TimeoutMilliseconds,
                                     fun() -> ok end).

run_in_directory_with_completion(Directory, Fun, TimeoutMilliseconds, AfterPublish) ->
    ensure(is_integer(TimeoutMilliseconds) andalso TimeoutMilliseconds > 0,
           {invalid_diagnostic_timeout, TimeoutMilliseconds}),
    {ok, Previous} = file:get_cwd(),
    ok = file:set_cwd(Directory),
    Parent = self(),
    Reference = make_ref(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    {Pid, Monitor} = spawn_monitor(fun() ->
        Outcome = try Fun() of
            Value -> {ok, Value}
        catch
            Class:Reason:Stacktrace ->
                {error, {Class, Reason, lists:sublist(Stacktrace, 16)}}
        end,
        Parent ! {Reference, Outcome},
        AfterPublish()
    end),
    try
        await_diagnostic_result(Pid, Monitor, Reference, Deadline)
    after
        ok = file:set_cwd(Previous)
    end.

await_diagnostic_result(Pid, Monitor, Reference, Deadline) ->
    Remaining = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {Reference, Outcome} -> await_diagnostic_exit(Pid, Monitor, Deadline, Outcome);
        {'DOWN', Monitor, process, Pid, Reason} ->
            {error, {test_process_stopped, Reason}}
    after Remaining -> stop_diagnostic_process(Pid, Monitor)
    end.

await_diagnostic_exit(Pid, Monitor, Deadline, Outcome) ->
    Remaining = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {'DOWN', Monitor, process, Pid, normal} -> Outcome;
        {'DOWN', Monitor, process, Pid, Reason} ->
            {error, {test_process_stopped, Reason}}
    after Remaining -> stop_diagnostic_process(Pid, Monitor)
    end.

stop_diagnostic_process(Pid, Monitor) ->
    exit(Pid, kill),
    receive
        {'DOWN', Monitor, process, Pid, _} -> {error, test_timeout}
    after 1000 ->
        demonitor(Monitor, [flush]),
        {error, diagnostic_process_did_not_stop}
    end.

diagnostic_failure_evidence(Iteration, Failure, _LegacyLimit) ->
    %% Redaction precedes serialization and allocation. A bounded raw tail or
    %% its hash would still retain certificate, endpoint, and exception data.
    #{iteration => Iteration, failure => diagnostic_failure_summary(Failure)}.

diagnostic_failure_summary({Class, Reason, Stack})
  when Class =:= error; Class =:= exit; Class =:= throw ->
    diagnostic_failure_details(Class, Reason, Stack);
diagnostic_failure_summary(test_timeout) ->
    diagnostic_failure_details(error, timeout, []);
diagnostic_failure_summary({test_process_stopped, _Reason}) ->
    diagnostic_failure_details(exit, test_process_stopped, []);
diagnostic_failure_summary({runtime_did_not_converge, _Snapshot}) ->
    (diagnostic_failure_details(error, runtime_did_not_converge, []))#{
        exception_reason => <<"resources_not_restored">>};
diagnostic_failure_summary(_Failure) ->
    diagnostic_failure_details(error, diagnostic_failure, []).

diagnostic_repetitions(Text) ->
    try list_to_integer(Text) of
        Value when Value >= 1, Value =< 1000 -> Value;
        _ -> erlang:error({invalid_diagnostic_repetitions, Text})
    catch
        error:badarg ->
            erlang:error({invalid_diagnostic_repetitions, Text})
    end.

diagnostic_timing_evidence(Reports) ->
    AllAttempts = diagnostic_timing_summary(Reports),
    case Reports of
        [_Warmup] ->
            #{all_attempts => AllAttempts,
              post_warmup_attempts => null,
              excluded_warmup_attempts => 1};
        [_Warmup | PostWarmup] ->
            #{all_attempts => AllAttempts,
              post_warmup_attempts =>
                  diagnostic_timing_summary(PostWarmup),
              excluded_warmup_attempts => 1}
    end.

diagnostic_timing_summary(Reports) ->
    ensure(Reports =/= [], no_diagnostic_timing_samples),
    Durations = lists:sort([
        begin
            Duration = maps:get(duration_ms, Report),
            ensure(is_integer(Duration) andalso Duration >= 0,
                   {invalid_diagnostic_duration, Duration}),
            Duration
        end
        || Report <- Reports
    ]),
    Slowest = lists:foldl(fun(Report, Current) ->
        case maps:get(duration_ms, Report) > maps:get(duration_ms, Current) of
            true -> Report;
            false -> Current
        end
    end, hd(Reports), tl(Reports)),
    Count = length(Durations),
    #{count => Count,
      total_ms => lists:sum(Durations),
      minimum_ms => hd(Durations),
      p50_ms => nearest_rank(Durations, 50),
      p95_ms => nearest_rank(Durations, 95),
      p99_ms => nearest_rank(Durations, 99),
      maximum_ms => lists:last(Durations),
      slowest_repetition =>
          #{iteration => maps:get(iteration, Slowest),
            duration_ms => maps:get(duration_ms, Slowest)}}.

nearest_rank(SortedValues, Percent) ->
    Rank = max(1, (Percent * length(SortedValues) + 99) div 100),
    lists:nth(Rank, SortedValues).

valid_diagnostic_name(Name) ->
    re:run(Name, "^[a-z][a-z0-9_-]{0,63}$", [{capture, none}]) =:= match.

select_named_atom(Text, [Candidate | Rest], Error) ->
    case atom_to_list(Candidate) of
        Text -> Candidate;
        _ -> select_named_atom(Text, Rest, Error)
    end;
select_named_atom(Text, [], Error) ->
    erlang:error({Error, Text}).

signed_integer_text(Value) when is_integer(Value), Value >= 0 ->
    [$+ | integer_to_list(Value)];
signed_integer_text(Value) when is_integer(Value) ->
    integer_to_list(Value).

capture_metadata_path(Export) ->
    filename:rootname(Export, ".cover") ++ ".capture.json".

validate_capture_identity(Captures, CurrentSource) ->
    ExpectedPolicy = current_capture_policy(),
    Packages = lists:sort([capture_field(Capture, package)
                           || Capture <- Captures]),
    ExpectedPackages = [<<"http">>, <<"http3">>, <<"quic_core">>],
    ensure(Packages =:= ExpectedPackages,
           {coverage_capture_packages, ExpectedPackages, Packages}),
    lists:foreach(fun(Capture) ->
        Package = capture_field(Capture, package),
        ensure(capture_field(Capture, schema) =:= 2,
               {coverage_capture_schema, Package}),
        ensure(capture_field(Capture, coordinate_methodology) =:=
                   current_coordinate_methodology(),
               {coverage_capture_coordinate_methodology, Package}),
        ensure(valid_digest(capture_field(Capture, coordinate_model_sha256)),
               {invalid_coverage_coordinate_model_digest, Package}),
        ensure(capture_field(Capture, otp_release) =:=
                   unicode:characters_to_binary(erlang:system_info(otp_release)),
               {coverage_capture_otp_mismatch, Package}),
        ensure(capture_field(Capture, erts_version) =:=
                   unicode:characters_to_binary(erlang:system_info(version)),
               {coverage_capture_erts_mismatch, Package}),
        ActualSource = capture_field(Capture, source_sha256),
        case ActualSource =:= CurrentSource of
            true -> ok;
            false -> erlang:error(
                {stale_coverage_capture, Package, CurrentSource, ActualSource}
            )
        end,
        ensure(capture_field(Capture, policy_sha256) =:= file_digest(?POLICY),
               {stale_coverage_policy, Package}),
        Repetitions = capture_field(Capture, repetition_count),
        Minimum = capture_field(Capture, minimum_repetitions),
        Maximum = capture_field(Capture, maximum_repetitions),
        Quiescent = capture_field(Capture, required_quiescent_repetitions),
        SettleMaximum = capture_field(
            Capture, runtime_settle_max_milliseconds),
        SettleInterval = capture_field(
            Capture, runtime_settle_interval_milliseconds),
        SettleQuiet = capture_field(Capture, runtime_settle_quiet_samples),
        ensure(Minimum =:= maps:get(minimum_repetitions, ExpectedPolicy)
               andalso Maximum =:= maps:get(maximum_repetitions, ExpectedPolicy)
               andalso Quiescent =:= maps:get(
                   required_quiescent_repetitions, ExpectedPolicy
               )
               andalso SettleMaximum =:= maps:get(
                   runtime_settle_max_milliseconds, ExpectedPolicy)
               andalso SettleInterval =:= maps:get(
                   runtime_settle_interval_milliseconds, ExpectedPolicy)
               andalso SettleQuiet =:= maps:get(
                   runtime_settle_quiet_samples, ExpectedPolicy),
               {coverage_capture_policy, Package, Minimum, Maximum, Quiescent,
                SettleMaximum, SettleInterval, SettleQuiet}),
        ensure(Repetitions >= Minimum andalso Repetitions =< Maximum,
               {coverage_capture_repetitions, Package, Minimum,
                Maximum, Repetitions}),
        ensure(capture_field(Capture, paths_saturated) =:= true,
               {unsaturated_coverage_capture, Package, Repetitions}),
        ensure(capture_field(Capture, status) =:= <<"Ready">>,
               {coverage_capture_not_ready, Package})
    end, Captures),
    ok.

audit_capture_metadata(Path, Capture, SourceFiles) ->
    audit_capture_shape(Capture),
    Package = capture_field(Capture, package),
    Stem = filename:basename(Path, ".capture.json"),
    ensure(Package =:= unicode:characters_to_binary(Stem),
           {coverage_capture_path_mismatch, Path, Package}),
    ensure(capture_field(Capture, schema) =:= 2,
           {coverage_capture_schema, Path}),
    ensure(capture_field(Capture, coordinate_methodology) =:=
               current_coordinate_methodology(),
           {coverage_capture_coordinate_methodology, Path}),
    ensure(valid_digest(capture_field(Capture, coordinate_model_sha256)),
           {invalid_coverage_coordinate_model_digest, Path}),
    ensure(capture_field(Capture, source_files) =:= SourceFiles,
           {coverage_capture_source_set_changed, Path}),
    ensure(valid_digest(capture_field(Capture, source_sha256)),
           {invalid_coverage_source_digest, Path}),
    ensure(capture_field(Capture, policy_sha256) =:= file_digest(?POLICY),
           {invalid_coverage_policy_digest, Path}),
    ensure(valid_digest(capture_field(Capture, artifact_sha256)),
           {invalid_coverage_artifact_digest, Path}),
    audit_current_capture_artifacts(Path, Capture),
    audit_capture_process(Capture),
    CoverDigest = capture_field(Capture, cover_sha256),
    ensure(valid_digest(CoverDigest), {invalid_cover_digest, Path}),
    CoverPath = filename:join(filename:dirname(Path), Stem ++ ".cover"),
    ensure(filelib:is_regular(CoverPath), {missing_coverage_capture, CoverPath}),
    ensure(file_digest(CoverPath) =:= CoverDigest,
           {modified_coverage_capture, CoverPath}),
    ModuleCount = capture_field(Capture, instrumented_modules),
    ModuleNames = capture_field(Capture, instrumented_module_names),
    TestCount = capture_field(Capture, test_modules),
    TestNames = capture_field(Capture, test_module_names),
    TestEntrypoints = capture_field(Capture, test_entrypoints),
    ensure(ModuleCount > 0 andalso length(ModuleNames) =:= ModuleCount,
           {invalid_instrumented_modules, Path}),
    ensure(TestCount > 0 andalso length(TestNames) =:= TestCount,
           {invalid_coverage_test_modules, Path}),
    ensure(is_integer(TestEntrypoints) andalso TestEntrypoints > 0,
           {invalid_coverage_test_entrypoints, Path, TestEntrypoints}),
    ensure(length(lists:usort(ModuleNames)) =:= ModuleCount,
           {duplicate_instrumented_modules, Path}),
    ensure(length(lists:usort(TestNames)) =:= TestCount,
           {duplicate_coverage_test_modules, Path}),
    ensure(nonempty_binary(capture_field(Capture, otp_release)),
           {invalid_capture_otp_release, Path}),
    ensure(nonempty_binary(capture_field(Capture, erts_version)),
           {invalid_capture_erts_version, Path}),
    audit_runtime_snapshot(Path, runtime_before,
                           capture_field(Capture, runtime_before), false),
    Repetitions = capture_field(Capture, repetitions),
    RepetitionCount = capture_field(Capture, repetition_count),
    ensure(length(Repetitions) =:= RepetitionCount,
           {incomplete_coverage_repetitions, Path,
            RepetitionCount, length(Repetitions)}),
    Initial = capture_field(Capture, initial_coverage),
    {InitialLines, LineTotal} = capture_metric_values(
        capture_field(Initial, lines), Path, initial_lines
    ),
    {InitialBranches, BranchTotal} = capture_metric_values(
        capture_field(Initial, branches), Path, initial_branches
    ),
    audit_capture_repetitions(
        Repetitions, 1, InitialLines, InitialBranches,
        LineTotal, BranchTotal,
        normalize_runtime(capture_field(Capture, runtime_before)), Path
    ),
    audit_capture_growth(Path, Repetitions, capture_field(Capture, growth)),
    audit_capture_runtime_summary(
        Path, normalize_runtime(capture_field(Capture, runtime_before)),
        Repetitions, capture_field(Capture, runtime_convergence)
    ),
    ok.

%% Imported capture files can contain arbitrary JSON. Reject extension fields
%% before publishing either their summaries or a digest of their bytes.
audit_capture_shape(Capture) ->
    coverage_keys(Capture, [schema, coordinate_methodology, coordinate_model_sha256,
        status, package, source_root, source_sha256, source_files, policy_sha256,
        artifact_sha256, compiled_beams, compiled_beam_names, cover_sha256,
        otp_release, erts_version, instrumented_modules, instrumented_module_names,
        test_modules, test_module_names, test_entrypoints, configured_units,
        instrumentation, minimum_repetitions, maximum_repetitions,
        required_quiescent_repetitions, runtime_settle_max_milliseconds,
        runtime_settle_interval_milliseconds, runtime_settle_quiet_samples,
        repetition_count, paths_saturated, stop_reason, initial_coverage,
        runtime_before, repetitions, growth, runtime_convergence,
        evidence_identity, execution_environment]),
    ensure(capture_field(Capture, execution_environment) =:= execution_runtime(),
           coverage_execution_runtime_changed),
    ensure(capture_field(Capture, stop_reason) =:= <<"saturated">>,
           coverage_capture_not_saturated),
    lists:foreach(fun(Unit) -> coverage_keys(Unit, [module, function, kind]) end,
                  capture_field(Capture, configured_units)),
    coverage_metric_keys(capture_field(Capture, initial_coverage)),
    coverage_keys(capture_field(Capture, runtime_before), runtime_keys()),
    lists:foreach(fun coverage_repetition_keys/1, capture_field(Capture, repetitions)),
    Growth = capture_field(Capture, growth),
    coverage_keys(Growth, [repetitions, later_growth, last_growth_repetition,
        final_repetition_grew, quiescent_tail_repetitions, paths_saturated]),
    coverage_keys(capture_field(Growth, later_growth), [lines, branches]),
    Convergence = capture_field(Capture, runtime_convergence),
    coverage_keys(Convergence, [final_resource_counts_converged,
        all_repetitions_settled, warm_resource_counts_restored, owned_resource_counts_restored,
        final_delta_from_previous, final_delta_from_start, final_delta_from_warm_reference,
        warm_runtime_reference, maximum_settle_milliseconds, peaks, observed_peaks]),
    lists:foreach(fun(Key) -> coverage_keys(capture_field(Convergence, Key), runtime_keys()) end,
        [final_delta_from_previous, final_delta_from_start, final_delta_from_warm_reference,
         warm_runtime_reference, peaks, observed_peaks]),
    Instrumentation = capture_field(Capture, instrumentation),
    coverage_keys(Instrumentation, [schema, observation, status, compiler_heap_words,
        restored_heap_words, heap_configuration_restored, gc_samples, peak_gc_heap_block_words,
        peak_gc_live_heap_words, attempted_modules, compiled_modules, last_module]),
    ensure(capture_field(Instrumentation, schema) =:= 1 andalso
               capture_field(Instrumentation, observation) =:= <<"sampled_gc">> andalso
               lists:member(capture_field(Instrumentation, last_module),
                            capture_field(Capture, instrumented_module_names)),
           invalid_coverage_instrumentation_observation),
    lists:foreach(fun(Key) -> coverage_scalar(capture_field(Instrumentation, Key)) end,
        [gc_samples, peak_gc_heap_block_words, peak_gc_live_heap_words,
         attempted_modules, compiled_modules]),
    ok.

coverage_repetition_keys(Report) ->
    coverage_keys(Report, [repetition, duration_ms, cumulative, added, newly_covered_lines,
        newly_covered_branches, test_duration_ms, settle_duration_ms, runtime_immediate,
        runtime, runtime_delta_from_start, runtime_delta_from_previous, settlement, tests]),
    coverage_metric_keys(capture_field(Report, cumulative)),
    coverage_keys(capture_field(Report, added), [lines, branches]),
    lists:foreach(fun(Key) -> coverage_keys(capture_field(Report, Key), runtime_keys()) end,
        [runtime_immediate, runtime, runtime_delta_from_start, runtime_delta_from_previous]),
    coverage_keys(capture_field(Report, tests), [valid, configured_units, completed_tests,
        report, report_sha256, failures, failures_dropped]),
    Settlement = capture_field(Report, settlement),
    coverage_keys(Settlement, [converged, timed_out, elapsed_milliseconds, maximum_milliseconds,
        interval_milliseconds, required_quiet_samples, final_quiet_samples, sample_count, samples]),
    lists:foreach(fun(Sample) ->
        coverage_keys(Sample, [sample, offset_milliseconds, restored, stable, runtime]),
        coverage_keys(capture_field(Sample, runtime), runtime_keys())
    end, capture_field(Settlement, samples)),
    lists:foreach(fun(Row) ->
        coverage_keys(Row, [module, artifact_line, source_first_line, source_last_line]),
        coverage_coordinate_fields(Row, [module])
    end, capture_field(Report, newly_covered_lines)),
    lists:foreach(fun(Row) ->
        coverage_keys(Row, [module, function, arity, index, function_alternative_index,
            function_decision_index, decision_alternative_index, artifact_anchor_line,
            artifact_lines, source_first_line, source_last_line]),
        coverage_coordinate_fields(Row, [module, function])
    end, capture_field(Report, newly_covered_branches)).

coverage_coordinate_fields(Row, Names) ->
    lists:foreach(fun({Key, Value}) ->
        case lists:member(Key, Names) orelse lists:member(Key, [atom_to_binary(K) || K <- Names]) of
            true -> ensure(suite_safe_identifier(Value), invalid_coverage_coordinate_name);
            false when Key =:= artifact_lines; Key =:= <<"artifact_lines">> ->
                lists:foreach(fun coverage_scalar/1, Value);
            false -> coverage_scalar(Value)
        end
    end, maps:to_list(Row)).

coverage_metric_keys(Metrics) ->
    coverage_keys(Metrics, [lines, branches]),
    lists:foreach(fun(Key) -> coverage_keys(capture_field(Metrics, Key), [covered, total]) end,
                  [lines, branches]).

coverage_keys(Map, Keys) ->
    Normalized = maps:from_list([{case Key of K when is_atom(K) -> atom_to_binary(K); K -> K end,
                                 Value} || {Key, Value} <- maps:to_list(Map)]),
    ensure(map_size(Map) =:= map_size(Normalized) andalso suite_exact_keys(Normalized, Keys),
           invalid_coverage_report_schema).

coverage_scalar(Value) ->
    ensure(is_integer(Value) andalso Value >= 0 andalso Value =< 9223372036854775807,
           invalid_coverage_scalar).

audit_current_capture_artifacts(Path, Capture) ->
    Package = capture_field(Capture, package),
    SourceRoot = capture_field(Capture, source_root),
    ExpectedRoot = case Package of
        <<"http">> -> <<".">>;
        <<"http3">> -> <<"packages/http3">>;
        <<"quic_core">> -> <<"packages/quic_core">>
    end,
    ensure(SourceRoot =:= ExpectedRoot,
           {coverage_capture_source_root, Path, ExpectedRoot, SourceRoot}),
    Ebin = filename:join([
        binary_to_list(SourceRoot), "build", "dev", "erlang",
        binary_to_list(Package), "ebin"
    ]),
    BeamPaths = lists:sort(filelib:wildcard(filename:join(Ebin, "*.beam"))),
    BeamNames = [unicode:characters_to_binary(filename:basename(BeamPath))
                 || BeamPath <- BeamPaths],
    ensure(length(BeamPaths) =:= capture_field(Capture, compiled_beams),
           {coverage_capture_compiled_beam_count, Path,
            length(BeamPaths), capture_field(Capture, compiled_beams)}),
    ensure(BeamNames =:= capture_field(Capture, compiled_beam_names),
           {coverage_capture_compiled_beam_set, Path}),
    ensure(digest_paths(BeamPaths) =:= capture_field(Capture, artifact_sha256),
           {modified_coverage_compiled_artifacts, Path}),
    TestModules = test_modules(Ebin, binary_to_list(SourceRoot)),
    Units = lists:append([suite_beam_units(Ebin, atom_to_binary(Module)) || Module <- TestModules]),
    ensure([atom_to_binary(Module) || Module <- TestModules] =:=
               capture_field(Capture, test_module_names), coverage_test_inventory_changed),
    StoredUnits = capture_field(Capture, configured_units),
    ensure(is_list(StoredUnits) andalso length(StoredUnits) =< 10000,
           invalid_coverage_unit_inventory),
    Normalized = [#{module => capture_field(Unit, module),
                    function => capture_field(Unit, function),
                    kind => capture_field(Unit, kind)} || Unit <- StoredUnits],
    ensure(Normalized =:= Units andalso length(Units) =:= capture_field(Capture, test_entrypoints),
           coverage_unit_inventory_changed),
    lists:foreach(fun(Repetition) ->
        audit_coverage_unit_evidence(Units, capture_field(Repetition, tests))
    end, capture_field(Capture, repetitions)),
    Instrumentation = capture_field(Capture, instrumentation),
    ensure(capture_field(Instrumentation, status) =:= <<"Ready">> andalso
               capture_field(Instrumentation, compiler_heap_words) =:= 134217728 andalso
               capture_field(Instrumentation, restored_heap_words) =:= 33554432 andalso
               capture_field(Instrumentation, heap_configuration_restored) =:= true andalso
               capture_field(Instrumentation, compiled_modules) =:= capture_field(Capture, instrumented_modules),
           invalid_coverage_instrumentation_bound),
    ok.

audit_capture_process(Capture) ->
    Name = binary_to_list(capture_field(Capture, package)),
    Path = filename:join(?OUTPUT, "capture-" ++ Name ++ ".process.json"),
    ProcessReport = read_coverage_unit_report(Path),
    coverage_keys(ProcessReport, [schema, scope, shareable, status, command, package,
        deadline_milliseconds, child_exit_status, process, evidence_identity, execution_environment]),
    ensure(capture_field(ProcessReport, status) =:= <<"Ready">> andalso
               capture_field(ProcessReport, scope) =:= <<"CoverageProcess">> andalso
               capture_field(ProcessReport, command) =:= <<"capture">> andalso
               capture_field(ProcessReport, package) =:= capture_field(Capture, package) andalso
               capture_field(ProcessReport, child_exit_status) =:= 0 andalso
               capture_field(ProcessReport, evidence_identity) =:= capture_field(Capture, evidence_identity),
           invalid_coverage_process_evidence),
    Process = capture_field(ProcessReport, process),
    coverage_keys(Process, runtime_matrix_process_keys()),
    ensure(runtime_matrix_process_valid(Process) andalso
               capture_field(Process, child_exit_observed) =:= true andalso
               capture_field(Process, timed_out) =:= false andalso
               capture_field(Process, output_limit_exceeded) =:= false andalso
               capture_field(Process, vm_process_heap_words) =:= 33554432 andalso
               capture_field(Process, vm_heap_includes_shared_binaries) =:= true andalso
               capture_field(Process, crash_dumps_disabled) =:= true andalso
               capture_field(Process, output_limit_bytes) =:= 8388608 andalso
               capture_field(Process, output_digest_complete) =:= true andalso
               capture_field(Process, output_bytes) =:= capture_field(Process, output_hashed_bytes),
           coverage_process_not_bounded),
    ensure(capture_field(ProcessReport, schema) =:= 1 andalso
               capture_field(ProcessReport, shareable) =:= true andalso
               capture_field(ProcessReport, deadline_milliseconds) =:= 7200000 andalso
               capture_field(ProcessReport, execution_environment) =:= execution_runtime(),
           invalid_coverage_process_configuration),
    ok.

audit_coverage_unit_evidence(Units, Evidence) ->
    Path = capture_field(Evidence, report),
    ensure(is_binary(Path) andalso byte_size(Path) =< 128 andalso
               re:run(Path, <<"^build/coverage/units-[a-f0-9]{32}\\.json$">>, [{capture, none}]) =:= match,
           invalid_coverage_unit_report_path),
    Nonce = binary:part(Path, byte_size(<<"build/coverage/units-">>), 32),
    {ok, Bytes} = coverage_unit_report_bytes(binary_to_list(Path)),
    ensure(hex(crypto:hash(sha256, Bytes)) =:= capture_field(Evidence, report_sha256),
           modified_coverage_unit_report),
    Child = coverage_decode_json(Bytes),
    ensure(suite_child_valid(Child, Units, Nonce), incomplete_coverage_unit_report),
    ensure(capture_field(Evidence, valid) =:= true andalso
               capture_field(Evidence, configured_units) =:= length(Units) andalso
               capture_field(Evidence, completed_tests) =:= suite_completed_tests(Child) andalso
               capture_field(Evidence, failures) =:= [] andalso
               capture_field(Evidence, failures_dropped) =:= 0,
           invalid_coverage_unit_summary),
    ok.

audit_capture_repetitions([], _Expected, _PreviousLines, _PreviousBranches,
                          _LineTotal, _BranchTotal, _PreviousRuntime, _Path) ->
    ok;
audit_capture_repetitions([Report | Rest], Expected, PreviousLines,
                          PreviousBranches, LineTotal, BranchTotal,
                          PreviousRuntime, Path) ->
    ensure(capture_field(Report, repetition) =:= Expected,
           {coverage_repetition_order, Path, Expected}),
    Duration = capture_field(Report, duration_ms),
    ensure(is_integer(Duration) andalso Duration >= 0,
           {invalid_coverage_repetition_duration, Path, Expected, Duration}),
    ensure(capture_field(Report, test_duration_ms) =:= Duration,
           {invalid_coverage_test_duration, Path, Expected}),
    SettleDuration = capture_field(Report, settle_duration_ms),
    ensure(is_integer(SettleDuration) andalso SettleDuration >= 0,
           {invalid_coverage_settle_duration, Path, Expected}),
    Cumulative = capture_field(Report, cumulative),
    {CurrentLines, LineTotal} = capture_metric_values(
        capture_field(Cumulative, lines), Path, {lines, Expected}
    ),
    {CurrentBranches, BranchTotal} = capture_metric_values(
        capture_field(Cumulative, branches), Path, {branches, Expected}
    ),
    Added = capture_field(Report, added),
    AddedLines = capture_field(Added, lines),
    AddedBranches = capture_field(Added, branches),
    ensure(CurrentLines >= PreviousLines andalso
           AddedLines =:= CurrentLines - PreviousLines,
           {invalid_coverage_line_growth, Path, Expected}),
    ensure(CurrentBranches >= PreviousBranches andalso
           AddedBranches =:= CurrentBranches - PreviousBranches,
           {invalid_coverage_branch_growth, Path, Expected}),
    ensure(length(capture_field(Report, newly_covered_lines)) =:= AddedLines,
           {incomplete_new_line_locations, Path, Expected}),
    ensure(length(capture_field(Report, newly_covered_branches)) =:=
               AddedBranches,
           {incomplete_new_branch_locations, Path, Expected}),
    RuntimeImmediate = normalize_runtime(
        capture_field(Report, runtime_immediate)),
    audit_runtime_snapshot(
        Path, {runtime_immediate, Expected}, RuntimeImmediate, false),
    Runtime = normalize_runtime(capture_field(Report, runtime)),
    audit_runtime_snapshot(Path, {runtime, Expected}, Runtime, false),
    Settlement = capture_field(Report, settlement),
    ensure(capture_field(Settlement, elapsed_milliseconds) =:= SettleDuration,
           {coverage_settle_duration_mismatch, Path, Expected}),
    SettlementFinal = normalize_runtime(capture_field(
        lists:last(capture_field(Settlement, samples)), runtime)),
    ensure(SettlementFinal =:= Runtime,
           {coverage_settle_final_mismatch, Path, Expected}),
    audit_runtime_snapshot(Path, {runtime_delta, Expected},
                           capture_field(Report, runtime_delta_from_start), true),
    PreviousDelta = normalize_runtime(
        capture_field(Report, runtime_delta_from_previous)
    ),
    audit_runtime_snapshot(Path, {runtime_previous_delta, Expected},
                           PreviousDelta, true),
    ensure(PreviousDelta =:= runtime_delta(PreviousRuntime, Runtime),
           {invalid_runtime_previous_delta, Path, Expected}),
    audit_capture_repetitions(
        Rest, Expected + 1, CurrentLines, CurrentBranches,
        LineTotal, BranchTotal, Runtime, Path
    );

audit_capture_repetitions(Reports, Expected, _PreviousLines, _PreviousBranches,
                          _LineTotal, _BranchTotal, _PreviousRuntime, Path) ->
    erlang:error({invalid_coverage_repetition_count, Path, Expected,
                  length(Reports)}).

capture_metric_values(Metric, Path, Label) ->
    Covered = capture_field(Metric, covered),
    Total = capture_field(Metric, total),
    ensure(is_integer(Covered) andalso is_integer(Total) andalso
           Covered >= 0 andalso Total >= Covered,
           {invalid_capture_metric, Path, Label, Covered, Total}),
    {Covered, Total}.

audit_runtime_snapshot(Path, Label, Snapshot, Signed) ->
    lists:foreach(fun(Key) ->
        Value = capture_field(Snapshot, Key),
        Valid = is_integer(Value) andalso (Signed orelse Value >= 0),
        ensure(Valid, {invalid_coverage_runtime_metric, Path, Label, Key, Value})
    end, runtime_keys()),
    ProjectTotal = lists:sum([
        capture_field(Snapshot, Key) || Key <- project_process_label_keys()
    ]),
    ensure(capture_field(Snapshot, project_processes) =:= ProjectTotal,
           {invalid_project_process_total, Path, Label}),
    case Signed of
        true -> ok;
        false ->
            ensure(capture_field(Snapshot, network_ports) =<
                       capture_field(Snapshot, ports),
                   {invalid_network_port_total, Path, Label})
    end.

audit_capture_growth(Path, Reports, Growth) ->
    Later = tl(Reports),
    LaterLines = lists:sum([repetition_added(Report, lines) || Report <- Later]),
    LaterBranches = lists:sum([
        repetition_added(Report, branches) || Report <- Later
    ]),
    LastGrowth = lists:foldl(fun(Report, Previous) ->
        case decoded_repetition_grew(Report) of
            true -> capture_field(Report, repetition);
            false -> Previous
        end
    end, 0, Reports),
    FinalGrew = decoded_repetition_grew(lists:last(Reports)),
    ensure(capture_field(Growth, repetitions) =:= length(Reports),
           {invalid_coverage_growth_repetitions, Path}),
    LaterGrowth = capture_field(Growth, later_growth),
    ensure(capture_field(LaterGrowth, lines) =:= LaterLines andalso
           capture_field(LaterGrowth, branches) =:= LaterBranches,
           {invalid_later_coverage_growth, Path}),
    ensure(capture_field(Growth, last_growth_repetition) =:= LastGrowth,
           {invalid_last_coverage_growth, Path}),
    ensure(capture_field(Growth, final_repetition_grew) =:= FinalGrew,
           {invalid_final_coverage_growth, Path}),
    QuiescentTail = quiescent_tail_repetitions_decoded(
        lists:reverse(Reports), 0
    ),
    ensure(capture_field(Growth, quiescent_tail_repetitions) =:= QuiescentTail,
           {invalid_quiescent_coverage_tail, Path}),
    RequiredQuiescent = maps:get(
        required_quiescent_repetitions, current_capture_policy()
    ),
    Saturated = QuiescentTail >= RequiredQuiescent,
    ensure(capture_field(Growth, paths_saturated) =:= Saturated,
           {invalid_coverage_saturation, Path}),
    ensure(Saturated, {unsaturated_coverage_capture, Path, QuiescentTail}).

quiescent_tail_repetitions_decoded([], Count) -> Count;
quiescent_tail_repetitions_decoded([Report | Rest], Count) ->
    case decoded_repetition_grew(Report) of
        true -> Count;
        false -> quiescent_tail_repetitions_decoded(Rest, Count + 1)
    end.

audit_capture_runtime_summary(Path, RuntimeBefore, Reports, Actual) ->
    lists:foreach(fun({Report, Index}) ->
        audit_runtime_settlement(
            Path, Index, RuntimeBefore,
            case Index of
                1 -> undefined;
                _ -> normalize_runtime(capture_field(hd(Reports), runtime))
            end,
            capture_field(Report, settlement)
        )
    end, lists:zip(Reports, lists:seq(1, length(Reports)))),
    Expected = capture_runtime_summary(RuntimeBefore, Reports),
    ActualDelta = normalize_runtime(
        capture_field(Actual, final_delta_from_previous)
    ),
    ActualStartDelta = normalize_runtime(
        capture_field(Actual, final_delta_from_start)
    ),
    ActualWarmDelta = normalize_runtime(
        capture_field(Actual, final_delta_from_warm_reference)
    ),
    ActualPeaks = normalize_runtime(capture_field(Actual, peaks)),
    ActualObservedPeaks = normalize_runtime(
        capture_field(Actual, observed_peaks)),
    ActualWarmReference = normalize_runtime(
        capture_field(Actual, warm_runtime_reference)),
    ensure(capture_field(Actual, final_resource_counts_converged) =:=
               maps:get(final_resource_counts_converged, Expected),
           {invalid_runtime_convergence, Path}),
    ensure(capture_field(Actual, all_repetitions_settled) =:=
               maps:get(all_repetitions_settled, Expected),
           {invalid_runtime_settlement_summary, Path}),
    ensure(capture_field(Actual, warm_resource_counts_restored) =:=
               maps:get(warm_resource_counts_restored, Expected),
           {invalid_warm_runtime_convergence, Path}),
    ensure(capture_field(Actual, owned_resource_counts_restored) =:=
               maps:get(owned_resource_counts_restored, Expected),
           {invalid_owned_runtime_convergence, Path}),
    ensure(ActualDelta =:= maps:get(final_delta_from_previous, Expected),
           {invalid_runtime_final_delta, Path}),
    ensure(ActualStartDelta =:= maps:get(final_delta_from_start, Expected),
           {invalid_runtime_start_delta, Path}),
    ensure(ActualWarmDelta =:=
               maps:get(final_delta_from_warm_reference, Expected),
           {invalid_runtime_warm_delta, Path}),
    ensure(ActualWarmReference =:= maps:get(warm_runtime_reference, Expected),
           {invalid_runtime_warm_reference, Path}),
    ensure(ActualPeaks =:= maps:get(peaks, Expected),
           {invalid_runtime_peaks, Path}),
    ensure(ActualObservedPeaks =:= maps:get(observed_peaks, Expected),
           {invalid_runtime_observed_peaks, Path}),
    ensure(capture_field(Actual, maximum_settle_milliseconds) =:=
               maps:get(maximum_settle_milliseconds, Expected),
           {invalid_runtime_maximum_settle, Path}),
    ensure(maps:get(final_resource_counts_converged, Expected),
           {coverage_runtime_did_not_converge, Path, ActualDelta}).

audit_runtime_settlement(Path, Index, RuntimeBefore, WarmReference,
                         Settlement) ->
    Policy = current_capture_policy(),
    Samples = capture_field(Settlement, samples),
    ensure(Samples =/= [], {empty_runtime_settlement, Path, Index}),
    ensure(capture_field(Settlement, sample_count) =:= length(Samples),
           {invalid_runtime_settlement_sample_count, Path, Index}),
    ensure(capture_field(Settlement, maximum_milliseconds) =:=
               maps:get(runtime_settle_max_milliseconds, Policy),
           {invalid_runtime_settlement_maximum, Path, Index}),
    ensure(capture_field(Settlement, interval_milliseconds) =:=
               maps:get(runtime_settle_interval_milliseconds, Policy),
           {invalid_runtime_settlement_interval, Path, Index}),
    ensure(capture_field(Settlement, required_quiet_samples) =:=
               maps:get(runtime_settle_quiet_samples, Policy),
           {invalid_runtime_settlement_quiet_policy, Path, Index}),
    audit_runtime_settlement_samples(
        Path, Index, Samples, 1, -1, RuntimeBefore, WarmReference,
        undefined),
    Quiet = runtime_settlement_quiet_tail(
        RuntimeBefore, WarmReference, Samples),
    Converged = Quiet >= maps:get(runtime_settle_quiet_samples, Policy),
    ensure(capture_field(Settlement, final_quiet_samples) =:= Quiet,
           {invalid_runtime_settlement_quiet_tail, Path, Index}),
    ensure(capture_field(Settlement, converged) =:= Converged,
           {invalid_runtime_settlement_outcome, Path, Index}),
    ensure(capture_field(Settlement, timed_out) =:= not Converged,
           {invalid_runtime_settlement_timeout, Path, Index}),
    Elapsed = capture_field(Settlement, elapsed_milliseconds),
    ensure(is_integer(Elapsed) andalso Elapsed >= 0 andalso
               Elapsed =< maps:get(runtime_settle_max_milliseconds, Policy) +
                          maps:get(runtime_settle_interval_milliseconds, Policy),
           {invalid_runtime_settlement_elapsed, Path, Index, Elapsed}),
    ensure(capture_field(lists:last(Samples), offset_milliseconds) =:= Elapsed,
           {runtime_settlement_elapsed_mismatch, Path, Index}),
    ensure(Converged, {runtime_settlement_did_not_converge, Path, Index}).

audit_runtime_settlement_samples(_Path, _Repetition, [], _Expected,
                                 _PreviousOffset, _RuntimeBefore,
                                 _WarmReference, _PreviousRuntime) -> ok;
audit_runtime_settlement_samples(Path, Repetition, [Sample | Rest], Expected,
                                 PreviousOffset, RuntimeBefore,
                                 WarmReference, PreviousRuntime) ->
    ensure(capture_field(Sample, sample) =:= Expected,
           {runtime_settlement_sample_order, Path, Repetition, Expected}),
    Offset = capture_field(Sample, offset_milliseconds),
    ensure(is_integer(Offset) andalso Offset >= PreviousOffset,
           {runtime_settlement_offset_order, Path, Repetition, Expected}),
    Runtime = normalize_runtime(capture_field(Sample, runtime)),
    audit_runtime_snapshot(
        Path, {runtime_settlement, Repetition, Expected}, Runtime, false),
    Stable = case PreviousRuntime of
        undefined -> false;
        Value -> runtime_not_growing(Value, Runtime)
    end,
    Restored = runtime_owned_resources_restored(RuntimeBefore, Runtime)
               andalso runtime_warm_resources_restored(
                   WarmReference, Runtime),
    ensure(capture_field(Sample, stable) =:= Stable,
           {invalid_runtime_settlement_stability, Path, Repetition, Expected}),
    ensure(capture_field(Sample, restored) =:= Restored,
           {invalid_runtime_settlement_restoration, Path, Repetition, Expected}),
    audit_runtime_settlement_samples(
        Path, Repetition, Rest, Expected + 1, Offset, RuntimeBefore,
        WarmReference, Runtime).

repetition_added(Report, Metric) ->
    capture_field(capture_field(Report, added), Metric).

decoded_repetition_grew(Report) ->
    repetition_added(Report, lines) > 0 orelse
        repetition_added(Report, branches) > 0.

capture_report_summary(Path, Capture, MetadataDigest) ->
    #{schema => capture_field(Capture, schema),
      package => capture_field(Capture, package),
      metadata => unicode:characters_to_binary(relative(filename:absname(Path))),
      metadata_sha256 => MetadataDigest,
      coordinate_methodology =>
          capture_field(Capture, coordinate_methodology),
      coordinate_model_sha256 =>
          capture_field(Capture, coordinate_model_sha256),
      cover_sha256 => capture_field(Capture, cover_sha256),
      artifact_sha256 => capture_field(Capture, artifact_sha256),
      compiled_beams => capture_field(Capture, compiled_beams),
      repetition_count => capture_field(Capture, repetition_count),
      paths_saturated => capture_field(Capture, paths_saturated),
      growth => capture_field(Capture, growth),
      runtime_convergence => capture_field(Capture, runtime_convergence)}.

validate_current_coordinate_models(Captures, CoverageMap, SourceMap) ->
    ByName = maps:from_list([
        {atom_to_binary(Module), Module} || Module <- maps:keys(CoverageMap)
    ]),
    lists:foreach(fun(Capture) ->
        Package = capture_field(Capture, package),
        DeclaredNames = lists:sort(
            capture_field(Capture, instrumented_module_names)
        ),
        ExpectedNames = lists:sort([
            atom_to_binary(Module)
            || {Module, SourcePath} <- maps:to_list(SourceMap),
               source_belongs_to_package(Package, SourcePath)
        ]),
        ensure(DeclaredNames =:= ExpectedNames,
               {coverage_capture_module_ownership, Package,
                #{expected_count => length(ExpectedNames),
                  declared_count => length(DeclaredNames),
                  expected_only => lists:sublist(
                      ExpectedNames -- DeclaredNames, 16
                  ),
                  declared_only => lists:sublist(
                      DeclaredNames -- ExpectedNames, 16
                  )}}),
        PackageModules = [maps:get(Name, ByName) || Name <- DeclaredNames],
        PackageMap = maps:with(PackageModules, CoverageMap),
        Snapshot = coverage_snapshot(
            [{Module, maps:get(Module, SourceMap)}
             || Module <- PackageModules],
            PackageMap
        ),
        ActualDigest = coverage_coordinate_digest(PackageMap, Snapshot),
        ExpectedDigest = capture_field(Capture, coordinate_model_sha256),
        ensure(ActualDigest =:= ExpectedDigest,
               {coverage_coordinate_model_changed, Package,
                ExpectedDigest, ActualDigest}),
        SnapshotMetrics = snapshot_metrics(Snapshot),
        FinalRepetition = lists:last(capture_field(Capture, repetitions)),
        FinalCumulative = capture_field(FinalRepetition, cumulative),
        lists:foreach(fun(Metric) ->
            SnapshotMetric = maps:get(Metric, SnapshotMetrics),
            {CapturedCovered, CapturedTotal} = capture_metric_values(
                capture_field(FinalCumulative, Metric),
                Package, {final_imported_coverage, Metric}
            ),
            ensure({CapturedCovered, CapturedTotal} =:=
                       {maps:get(covered, SnapshotMetric),
                        maps:get(total, SnapshotMetric)},
                   {coverage_capture_final_import_mismatch, Package, Metric,
                    #{captured => {CapturedCovered, CapturedTotal},
                      imported => {maps:get(covered, SnapshotMetric),
                                   maps:get(total, SnapshotMetric)}}})
        end, [lines, branches])
    end, Captures),
    ok.

source_belongs_to_package(<<"http">>, SourcePath) ->
    case filename:split(SourcePath) of
        ["src" | _] -> true;
        _ -> false
    end;
source_belongs_to_package(<<"http3">>, SourcePath) ->
    case filename:split(SourcePath) of
        ["packages", "http3", "src" | _] -> true;
        _ -> false
    end;
source_belongs_to_package(<<"quic_core">>, SourcePath) ->
    case filename:split(SourcePath) of
        ["packages", "quic_core", "src" | _] -> true;
        _ -> false
    end.

capture_field(Map, Key) when is_atom(Key) ->
    case maps:find(Key, Map) of
        {ok, Value} -> Value;
        error -> maps:get(atom_to_binary(Key), Map)
    end.

caught_error(Fun) ->
    try Fun() of
        Value -> {unexpected_success, Value}
    catch
        error:Reason -> Reason
    end.

valid_digest(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    case re:run(Value, "^[0-9a-f]{64}$", [{capture, none}]) of
        match -> true;
        nomatch -> false
    end;
valid_digest(_) -> false.

nonempty_binary(Value) -> is_binary(Value) andalso byte_size(Value) > 0.

load_coverage_listener() ->
    {ok, qualification_eunit_listener, Binary, []} = compile:file(
        "scripts/qualification_eunit_listener.erl",
        [binary, return_errors, return_warnings, {i, "scripts"}]),
    {module, qualification_eunit_listener} = code:load_binary(
        qualification_eunit_listener, "qualification_eunit_listener.erl", Binary),
    ok.

eunit_in_directory(Directory, Units) ->
    eunit_in_directory(Directory, Units, 120).

eunit_in_directory(Directory, Units, TimeoutSeconds) ->
    ensure(Units =/= [] andalso length(Units) =< 10000, invalid_coverage_unit_count),
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Path = filename:absname(filename:join(?OUTPUT,
        "units-" ++ binary_to_list(Nonce) ++ ".json")),
    ok = filelib:ensure_dir(Path),
    {ok, Previous} = file:get_cwd(),
    ok = file:set_cwd(Directory),
    Result = try qualification_eunit_listener:run_same_vm_units(
        Units, Path, Nonce, TimeoutSeconds)
    after
        ok = file:set_cwd(Previous)
    end,
    Child = suite_safe_child(read_coverage_unit_report(Path), Units, Nonce),
    %% Only a schema-checked record is retained. In particular, a malformed
    %% imported file cannot leak through its bytes or a published raw digest.
    Encoded = iolist_to_binary([json:encode(Child), $\n]),
    ok = file:write_file(Path, Encoded),
    Valid = Result =:= ok andalso suite_child_valid(Child, Units, Nonce),
    Evidence = #{valid => Valid, configured_units => length(Units),
                 completed_tests => suite_completed_tests(Child),
                 report => list_to_binary(relative(Path)),
                 report_sha256 => hex(crypto:hash(sha256, Encoded)),
                 failures => maps:get(<<"failures">>, Child, []),
                 failures_dropped => maps:get(<<"failures_dropped">>, Child, 0)},
    case Valid of true -> {ok, Evidence}; false -> {error, Evidence} end.

read_coverage_unit_report(Path) ->
    case coverage_unit_report_bytes(Path) of
        {ok, Bytes} -> try coverage_decode_json(Bytes) catch _:_ -> #{invalid => true} end;
        error -> #{invalid => true}
    end.

coverage_unit_report_bytes(Path) ->
    coverage_report_bytes(Path, 8388608).

coverage_report_bytes(Path, Limit) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, Handle} ->
            try
                {ok, Bytes} = file:read(Handle, Limit + 1),
                true = byte_size(Bytes) =< Limit,
                eof = file:read(Handle, 1),
                {ok, Bytes}
            catch _:_ -> error
            after file:close(Handle) end;
        _ -> error
    end.

coverage_decode_json(Bytes) ->
    evidence_json_decode(Bytes).

report(Mode) ->
    add_all_code_paths(),
    {ok, CoverPid} = cover:start(),
    QuietIo = start_quiet_io(CoverPid),
    Result = try report_started(Mode)
    after
        cover:stop(),
        _ = stop_quiet_io(QuietIo)
    end,
    coverage_report_completion(Mode, Result),
    case Result of ok -> ok; {blocked, Reason} -> erlang:error(Reason) end.

report_started(Mode) ->
    Identity = evidence_begin(coverage_report_path(Mode)),
    MetadataPaths = lists:sort(
        filelib:wildcard(filename:join(?OUTPUT, "*.capture.json"))
    ),
    ensure(length(MetadataPaths) =:= 3,
           {missing_coverage_capture_metadata, MetadataPaths}),
    MetadataBytes = [begin
        {ok, Bytes} = coverage_report_bytes(Path, 16777216), Bytes
    end || Path <- MetadataPaths],
    Captures = [coverage_decode_json(Bytes) || Bytes <- MetadataBytes],
    lists:foreach(fun(Capture) -> evidence_require_identity(Capture, Identity) end,
                  Captures),
    SourcePaths = coverage_source_paths(),
    SourceDigest = digest_paths(SourcePaths),
    ok = validate_capture_identity(Captures, SourceDigest),
    lists:foreach(fun({Path, Capture}) ->
        audit_capture_metadata(Path, Capture, length(SourcePaths))
    end, lists:zip(MetadataPaths, Captures)),
    Exports = lists:sort(filelib:wildcard(filename:join(?OUTPUT, "*.cover"))),
    ensure(length(Exports) =:= 3, {missing_coverage_captures, Exports}),
    lists:foreach(fun(Path) -> ok = cover:import(Path) end, Exports),
    SourceMap = source_map(),
    Modules = lists:usort(cover:modules() ++ cover:imported_modules()),
    ensure(Modules =:= lists:sort(maps:keys(SourceMap)),
           {coverage_module_set_mismatch,
            lists:sort(maps:keys(SourceMap)), Modules}),
    CoverageMap = maps:from_list([
        {Module, coverage_model(
                     Module, maps:get(Module, SourceMap),
                     production_beam_path(Module, maps:get(Module, SourceMap))
                 )}
        || Module <- Modules
    ]),
    ok = validate_current_coordinate_models(
        Captures, CoverageMap, SourceMap
    ),
    Changed = changed_lines(),
    ModuleReports = [module_report(
                         Module, SourceMap, Changed,
                         maps:get(Module, CoverageMap)
                     ) || Module <- Modules],
    FullLines = sum_metric(ModuleReports, full_lines),
    FullBranches = sum_metric(ModuleReports, full_branches),
    ChangedLines = sum_metric(ModuleReports, changed_lines),
    ChangedBranches = sum_metric(ModuleReports, changed_branches),
    Selected = case Mode of
                   "full" -> #{lines => FullLines, branches => FullBranches};
                   "changed" -> #{lines => ChangedLines,
                                  branches => ChangedBranches}
               end,
    AllThresholds = #{full => coverage_thresholds("full"),
                      changed => coverage_thresholds("changed")},
    Thresholds = maps:get(list_to_atom(Mode), AllThresholds),
    LineThreshold = maps:get(lines, Thresholds),
    BranchThreshold = maps:get(branches, Thresholds),
    CapturePolicy = current_capture_policy(),
    LineBasisPoints = basis_points(maps:get(lines, Selected)),
    BranchBasisPoints = basis_points(maps:get(branches, Selected)),
    Statuses = #{full => coverage_status(FullLines, FullBranches,
                                         maps:get(full, AllThresholds)),
                 changed => coverage_status(
                     ChangedLines, ChangedBranches,
                     maps:get(changed, AllThresholds)
                 )},
    Passed = maps:get(list_to_atom(Mode), Statuses) =:= <<"Ready">>,
    Report = #{schema => 2,
               coordinate_methodology => current_coordinate_methodology(),
               status => case Passed of true -> <<"Ready">>;
                                           false -> <<"Blocked">> end,
               mode => list_to_binary(Mode),
               source_sha256 => SourceDigest,
               source_files => length(SourcePaths),
               policy_sha256 => file_digest(?POLICY),
               capture_policy => CapturePolicy,
               capture_repetitions =>
                   [#{package => capture_field(Capture, package),
                      repetitions => capture_field(Capture, repetition_count)}
                    || Capture <- Captures],
               captures => [capture_report_summary(Path, Capture, hex(crypto:hash(sha256, Bytes)))
                            || {Path, Capture, Bytes} <-
                                   lists:zip3(MetadataPaths, Captures, MetadataBytes)],
               thresholds_basis_points =>
                   #{lines => LineThreshold, branches => BranchThreshold},
               selected => metric_json(Selected),
               full => metric_json(#{lines => FullLines,
                                     branches => FullBranches}),
               changed => metric_json(#{lines => ChangedLines,
                                        branches => ChangedBranches}),
               modules => ModuleReports},
    Path = coverage_report_path(Mode),
    ok = file:write_file(Path,
        [json:encode(evidence_complete(Report, Identity)), <<"\n">>]),
    Evidence = #{schema => 2,
                 coordinate_methodology => current_coordinate_methodology(),
                 source_sha256 => SourceDigest,
                 source_files => length(SourcePaths),
                 policy_sha256 => file_digest(?POLICY),
                 thresholds_basis_points => AllThresholds,
                 statuses => Statuses,
                 full => metric_json(#{lines => FullLines,
                                       branches => FullBranches}),
                 changed => metric_json(#{lines => ChangedLines,
                                          branches => ChangedBranches}),
                 capture_policy => CapturePolicy,
                 capture_repetitions => maps:get(capture_repetitions, Report),
                 captures => maps:get(captures, Report)},
    ok = file:write_file(coverage_evidence_path(),
        [json:encode(evidence_complete(Evidence, Identity)), <<"\n">>]),
    io:format("~s coverage: generated-artifact lines ~s, "
              "observable compiled clause alternatives ~s~n",
              [Mode, percentage(maps:get(lines, Selected)),
               percentage(maps:get(branches, Selected))]),
    print_gap_summary(Mode, ModuleReports),
    case Passed of
        true -> ok;
        false -> {blocked, {coverage_threshold_not_met, Mode,
                           LineBasisPoints, BranchBasisPoints}}
    end.

start_quiet_io(CoverPid) ->
    QuietIo = spawn(fun() -> quiet_io_loop(0) end),
    true = erlang:group_leader(QuietIo, CoverPid),
    QuietIo.

quiet_io_loop(Requests) ->
    receive
        {io_request, From, ReplyAs, _Request} ->
            From ! {io_reply, ReplyAs, ok},
            quiet_io_loop(Requests + 1);
        {stop, From} ->
            From ! {quiet_io_stopped, self(), Requests}
    end.

stop_quiet_io(QuietIo) ->
    QuietIo ! {stop, self()},
    receive
        {quiet_io_stopped, QuietIo, Requests} -> Requests
    after 1000 ->
        erlang:error({quiet_io_stop_timeout, QuietIo})
    end.

print_gap_summary(Mode, Reports) ->
    {LineKey, BranchKey} = case Mode of
        "full" -> {full_lines, full_branches};
        "changed" -> {changed_lines, changed_branches}
    end,
    Ranked = rank_gaps(Reports, LineKey, BranchKey),
    case Ranked of
        [] -> ok;
        _ ->
            io:format("largest coverage gaps (up to 10 modules):~n"),
            lists:foreach(fun(Report) ->
                Lines = maps:get(LineKey, Report),
                Branches = maps:get(BranchKey, Report),
                io:format("  ~ts: lines ~B/~B (~s, ~B missing), "
                          "clause alternatives ~B/~B (~s, ~B missing)~n",
                          [maps:get(source, Report),
                           maps:get(covered, Lines), maps:get(total, Lines),
                           percentage(metric_tuple(Lines)), uncovered(Lines),
                           maps:get(covered, Branches), maps:get(total, Branches),
                           percentage(metric_tuple(Branches)),
                           uncovered(Branches)]),
                print_gap_anchors(Mode, Report)
            end, lists:sublist(Ranked, 10))
    end.

print_gap_anchors(Mode, Report) ->
    {LineKey, BranchKey} = case Mode of
        "full" -> {full_uncovered_lines, full_uncovered_branches};
        "changed" -> {changed_uncovered_lines, changed_uncovered_branches}
    end,
    Lines = maps:get(LineKey, Report),
    Branches = maps:get(BranchKey, Report),
    io:format(
        "    first uncovered artifact/source regions ~s; "
        "branch artifact/source regions ~s~n",
        [coordinate_text(lists:sublist(Lines, 12)),
         coordinate_text(lists:sublist(Branches, 12))]
    ).

line_number_text(Lines) -> io_lib:format("~w", [Lines]).

rank_gaps(Reports, LineKey, BranchKey) ->
    WithGaps = [Report || Report <- Reports,
        gap_score(Report, LineKey, BranchKey) > 0],
    lists:sort(fun(Left, Right) ->
        LeftScore = gap_score(Left, LineKey, BranchKey),
        RightScore = gap_score(Right, LineKey, BranchKey),
        case LeftScore =:= RightScore of
            true -> maps:get(source, Left) < maps:get(source, Right);
            false -> LeftScore > RightScore
        end
    end, WithGaps).

gap_score(Report, LineKey, BranchKey) ->
    uncovered(maps:get(LineKey, Report)) +
        uncovered(maps:get(BranchKey, Report)).

uncovered(Metric) -> maps:get(total, Metric) - maps:get(covered, Metric).

metric_tuple(Metric) -> {maps:get(covered, Metric), maps:get(total, Metric)}.

synthetic_branch(Index, ArtifactLines, SourceFirst, SourceLast) ->
    #{index => Index,
      function => sample,
      arity => 0,
      function_alternative_index => Index,
      function_decision_index => 1,
      decision_alternative_index => Index,
      artifact_lines => ArtifactLines,
      source_first_line => SourceFirst,
      source_last_line => SourceLast}.

coverage_report_runner_self_test() ->
    Directory = filename:absname(filename:join("build/coverage-report-tests/runner",
        binary_to_list(hex(crypto:strong_rand_bytes(16))))),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    {ok, Sections} = escript:extract("scripts/coverage_report_test.escript", [compile_source]),
    Binary = proplists:get_value(source, Sections),
    {ok, {Module, _}} = beam_lib:chunks(Binary, [exports]),
    Path = filename:join(Directory, atom_to_list(Module) ++ ".beam"),
    ok = file:write_file(Path, Binary, [exclusive]),
    Evaluation = lists:flatten(io_lib:format("~p:main([]),halt(0).", [Module])),
    try
        {Status, Output} = run_child_evaluation(filename:absname("."), [Directory], Evaluation, 300000),
        Process = maps:without([tail, output_sha256], Output),
        ok = file:write_file(filename:join(Directory, "process.json"),
            json:encode(#{schema => 1, child_exit_status => Status, process => Process})),
        ensure(process_status_verified(Status, 0, Output),
            coverage_report_runner_controls_failed),
        io:format("coverage report lifecycle controls passed in joined bounded VM~n")
    after delete_if_present(Path) end.

self_test() ->
    ok = coverage_report_process_self_test(),
    ok = coverage_report_runner_self_test(),
    ok = selection_json_self_test(),
    [{1, "src\\sample.gleam", 2}] = generated_file_directives_from_binary(
        <<"-file(\"src\\\\sample.gleam\", 2).\r\n">>),
    invalid_evidence_json = caught_error(fun() ->
        coverage_decode_json(<<"{\"value\":\"private\",\"value\":1}">>)
    end),
    invalid_evidence_json = caught_error(fun() ->
        coverage_decode_json(<<"[{\"key\":1,\"ke\\u0079\":2}]">>)
    end),
    OriginalLeader = erlang:group_leader(),
    QuietIo = spawn(fun() -> quiet_io_loop(0) end),
    true = erlang:group_leader(QuietIo, self()),
    ok = io:format("this self-test line must be suppressed~n"),
    true = erlang:group_leader(OriginalLeader, self()),
    ensure(stop_quiet_io(QuietIo) > 0, quiet_io_did_not_receive_output),
    Sparse = #{source => <<"sparse.gleam">>,
               full_lines => metric_map({1, 10}),
               full_branches => metric_map({0, 5})},
    Dense = #{source => <<"dense.gleam">>,
              full_lines => metric_map({9, 10}),
              full_branches => metric_map({4, 5})},
    [Sparse, Dense] = rank_gaps([Dense, Sparse], full_lines, full_branches),
    LineCoverage = [{10, 1, 0}, {20, 0, 1}, {30, 0, 1}],
    [20, 30] = uncovered_line_numbers(LineCoverage),
    CoverageByLine = #{10 => true, 11 => false, 20 => false,
                       21 => false, 30 => false},
    [#{artifact_anchor_line := 20, artifact_lines := [20, 21],
       source_first_line := 7, source_last_line := 9},
     #{artifact_anchor_line := 30, artifact_lines := [30],
       source_first_line := 12, source_last_line := 14}] =
        uncovered_branch_details([
            synthetic_branch(1, [10, 11], 2, 4),
            synthetic_branch(2, [20, 21], 7, 9),
            synthetic_branch(3, [30], 12, 14)
        ], CoverageByLine),
    "[201,202]" = lists:flatten(line_number_text([201, 202])),
    CoordinateText = lists:flatten(coordinate_text(
        [#{module => <<"sample">>, lines => [115, 116]}]
    )),
    ensure(string:find(CoordinateText, "[115,116]") =/= nomatch,
           coordinate_lines_rendered_as_charlist),
    [{10, 1, 0}, {20, 0, 1}] = normalize_cover_lines(sample, [
        {{sample, 20}, {0, 1}}, {{sample, 10}, {1, 0}}
    ]),
    {foreign_cover_line_module, sample, other, 10} = caught_error(fun() ->
        normalize_cover_lines(sample, [{{other, 10}, {0, 1}}])
    end),
    {duplicate_cover_line_rows, sample, 2, 1} = caught_error(fun() ->
        normalize_cover_lines(sample, [
            {{sample, 10}, {0, 1}}, {{sample, 10}, {1, 0}}
        ])
    end),
    true = source_span_changed(10, 20, all),
    true = source_span_changed(10, 20, [{1, 10}]),
    true = source_span_changed(10, 20, [{20, 30}]),
    true = source_span_changed(10, 20, [{15, 15}]),
    false = source_span_changed(10, 20, [{1, 9}, {21, 30}]),
    %% A size unit in a bit-syntax element is a type specifier, not a node, so
    %% its integer is never read as a line number.
    [400, 401] = lists:usort(syntax_lines(
        {bin_element, erl_anno:new(400), {integer, erl_anno:new(400), 0},
         {var, erl_anno:new(401), 'Zeros'}, [{unit, 8}, integer]}
    )),
    SingleRegion = #{artifact_first_line => 10,
                     artifact_last_line => 20,
                     source_first_line => 2,
                     source_last_line => 7},
    SingleRegionModel = #{regions => [SingleRegion],
                          coordinate_method =>
                              generated_erlang_line_with_glance_function_span},
    SingleRegion = source_region_for_artifact_line(
        sample, 10, SingleRegionModel
    ),
    {unmapped_coverage_artifact_line, sample, 9, _} = caught_error(fun() ->
        source_region_for_artifact_line(sample, 9, SingleRegionModel)
    end),
    OverlapModel = SingleRegionModel#{regions => [
        SingleRegion, SingleRegion#{artifact_first_line => 15,
                                    artifact_last_line => 25}
    ]},
    {unmapped_coverage_artifact_line, sample, 15, _} = caught_error(fun() ->
        source_region_for_artifact_line(sample, 15, OverlapModel)
    end),
    #{source_first_line := 17, source_last_line := 17} =
        source_span_for_artifact_line(
            sample, 17,
            SingleRegionModel#{coordinate_method => exact_erlang_source_line}
        ),
    #{source_first_line := 17, source_last_line := 17} =
        source_span_for_artifact_line(
            sample, 17,
            SingleRegionModel#{coordinate_method =>
                exact_erlang_source_line_from_verified_build_copy}
        ),
    #{source_first_line := 2, source_last_line := 7} =
        source_span_for_artifact_line(sample, 17, SingleRegionModel),
    {[{3, 4}], #{effective_scope := source_spans,
                 unattributed_ranges := []}} =
        changed_selection(SingleRegionModel, [{3, 4}]),
    {all, #{effective_scope := whole_module,
            unattributed_ranges := [#{first_line := 1, last_line := 1}]}} =
        changed_selection(SingleRegionModel, [{1, 4}]),
    [{1, 1}, {8, 9}] = unattributed_ranges(
        [{1, 9}], [{2, 7}]
    ),
    <<"src/sample.gleam">> = repository_path("src\\sample.gleam"),
    #{<<"src/sample.gleam">> := [{12, 12}]} = parse_diff([
        "+++ b/src/sample.gleam",
        "@@ -12,3 +12,0 @@",
        "+++ /dev/null",
        "@@ -30,2 +30,0 @@"
    ], undefined, #{}),
    [{2, "src/sample.gleam", 3},
     {4, "src/sample.gleam", 17}] =
        generated_file_directives_from_binary(
            <<"-module(sample).\n"
              "-file(\"src/sample.gleam\", 3).\n"
              "first() -> ok.\n"
              "-file(\"src/sample.gleam\",17).\n"
              "second() -> ok.\n">>
        ),
    [{2, "src/sample.gleam", 3},
     {5, "src/sample.gleam", 17}] = expected_abstract_directives([
        {2, "src/sample.gleam", 3},
        {4, "src/sample.gleam", 17}
    ]),
    false = has_function_forms([{attribute, 1, module, types_only}]),
    [] = refine_gleam_source_regions(types_only, [], [], #{}),
    {gleam_coverage_function_set_mismatch, types_only, _} =
        caught_error(fun() ->
            refine_gleam_source_regions(
                types_only, [], [],
                #{{ghost, 0} => #{compiled => true}}
            )
        end),
    #{source_first_line := 1, source_last_line := 1} =
        glance_source_span(sample, {span, 0, 1}, [0], 1),
    {invalid_gleam_source_span, sample, 1, 1, 1} = caught_error(fun() ->
        glance_source_span(sample, {span, 1, 1}, [0], 1)
    end),
    AttributeSource = <<"@internal\n@external(erlang, \"m\", \"f\")\n"
                        "pub fn sample() { Nil }\n">>,
    {FunctionOffset, _} = binary:match(AttributeSource, <<"pub fn">>),
    0 = attached_attribute_start(
        sample,
        [{attribute, <<"internal">>, []},
         {attribute, <<"external">>, []}],
        FunctionOffset,
        AttributeSource
    ),
    AttributeSpan = gleam_definition_span(
        sample,
        [{attribute, <<"internal">>, []},
         {attribute, <<"external">>, []}],
        private,
        {span, FunctionOffset, byte_size(AttributeSource)},
        AttributeSource,
        source_line_starts(AttributeSource)
    ),
    #{source_first_line := 1, declaration_first_line := 3,
      external := true, compiled := false} = AttributeSpan,
    GoodBranches = [
        synthetic_branch(1, [10, 11], 2, 4),
        synthetic_branch(2, [20, 21], 7, 9)
    ],
    [#{artifact_witness_lines := [10, 11]},
     #{artifact_witness_lines := [20, 21]}] =
        observable_branches(
            sample, GoodBranches,
            #{10 => true, 11 => false, 20 => false, 21 => true}
        ),
    ok = validate_branch_observability(
        sample, GoodBranches,
        #{10 => true, 11 => false, 20 => false, 21 => true}
    ),
    {unobservable_branch_coordinates, sample, 1, _} = caught_error(fun() ->
        validate_branch_observability(
            sample,
            [synthetic_branch(1, [41, 42], 2, 4),
             synthetic_branch(2, [10], 7, 9)],
            #{10 => false}
        )
    end),
    {indistinguishable_branch_coordinates, sample, 1, _} =
        caught_error(fun() ->
            validate_branch_observability(
                sample,
                [synthetic_branch(1, [10], 2, 4),
                 synthetic_branch(2, [10], 7, 9)],
                #{10 => false}
            )
        end),
    CoordinateFixtureDigest =
        <<"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef">>,
    CoordinateModel = #{source => "src/sample.gleam",
                        source_sha256 => CoordinateFixtureDigest,
                        artifact => "build/sample.erl",
                        artifact_sha256 => CoordinateFixtureDigest,
                        compiled_beam => "build/sample.beam",
                        compiled_beam_sha256 => CoordinateFixtureDigest,
                        coordinate_method =>
                            generated_erlang_line_with_glance_function_span,
                        regions => [SingleRegion], functions => [],
                        branches => GoodBranches},
    CoordinateUniverse = #{all_lines => [{sample, 10, 2, 7}],
                           all_branches => [],
                           covered_lines => [], covered_branches => []},
    CoordinateDigest = coverage_coordinate_digest(
        #{sample => CoordinateModel}, CoordinateUniverse
    ),
    true = valid_digest(CoordinateDigest),
    false = CoordinateDigest =:= coverage_coordinate_digest(
        #{sample => CoordinateModel#{source_sha256 =>
            <<"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff">>}},
        CoordinateUniverse
    ),
    BranchOne = {alpha, sample, 0, 1, 1, 1, 1,
                 10, [10, 11], 2, 4},
    BranchTwo = {alpha, sample, 0, 2, 2, 1, 2,
                 20, [20, 21], 7, 9},
    Universe = #{all_lines => ordsets:from_list(
                     [{alpha, 10, 2, 4}, {alpha, 11, 2, 4},
                      {beta, 2, 1, 3}]),
                 all_branches => ordsets:from_list([BranchOne, BranchTwo])},
    Previous = Universe#{covered_lines => ordsets:from_list(
                             [{alpha, 10, 2, 4}]),
                         covered_branches => ordsets:from_list([BranchOne])},
    Current = Universe#{covered_lines => ordsets:from_list(
                            [{alpha, 10, 2, 4}, {alpha, 11, 2, 4}]),
                        covered_branches => ordsets:from_list(
                            [BranchOne, BranchTwo])},
    #{repetition := 2,
      duration_ms := 17,
      cumulative := #{lines := #{covered := 2, total := 3},
                      branches := #{covered := 2, total := 2}},
      added := #{lines := 1, branches := 1},
      newly_covered_lines :=
          [#{module := <<"alpha">>, artifact_line := 11,
             source_first_line := 2, source_last_line := 4}],
      newly_covered_branches :=
          [#{module := <<"alpha">>, function := <<"sample">>, arity := 0,
             index := 2, function_alternative_index := 2,
             function_decision_index := 1,
             decision_alternative_index := 2,
             artifact_anchor_line := 20, artifact_lines := [20, 21],
             source_first_line := 7, source_last_line := 9}]} =
        summarize_coverage_repetition(2, Previous, Current, 17),
    CapturePolicy = current_capture_policy(),
    MinimumRepetitions = maps:get(minimum_repetitions, CapturePolicy),
    MaximumRepetitions = maps:get(maximum_repetitions, CapturePolicy),
    RequiredQuiescent = maps:get(
        required_quiescent_repetitions, CapturePolicy
    ),
    GrowthReports = [
        #{repetition => 1, added => #{lines => 1, branches => 1}},
        #{repetition => 2, added => #{lines => 1, branches => 1}}
        | [#{repetition => Index, added => #{lines => 0, branches => 0}}
           || Index <- lists:seq(3, RequiredQuiescent + 2)]
    ],
    GrowthRepetitions = length(GrowthReports),
    #{repetitions := GrowthRepetitions,
      later_growth := #{lines := 1, branches := 1},
      last_growth_repetition := 2,
      final_repetition_grew := false,
      quiescent_tail_repetitions := RequiredQuiescent,
      paths_saturated := true} = capture_growth_summary(GrowthReports),
    continue = capture_stop_decision(
        MinimumRepetitions - 1, RequiredQuiescent
    ),
    continue = capture_stop_decision(
        MinimumRepetitions, RequiredQuiescent - 1
    ),
    saturated = capture_stop_decision(
        MinimumRepetitions, RequiredQuiescent
    ),
    maximum_without_saturation = capture_stop_decision(
        MaximumRepetitions, RequiredQuiescent - 1
    ),
    Digest = <<"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef">>,
    CaptureIdentity = fun(Package, Source) ->
        #{schema => 2,
          coordinate_methodology => current_coordinate_methodology(),
          coordinate_model_sha256 => Digest,
          package => Package, source_sha256 => Source,
          policy_sha256 => file_digest(?POLICY),
          otp_release => unicode:characters_to_binary(
              erlang:system_info(otp_release)),
          erts_version => unicode:characters_to_binary(
              erlang:system_info(version)),
          minimum_repetitions => maps:get(minimum_repetitions, CapturePolicy),
          maximum_repetitions => maps:get(maximum_repetitions, CapturePolicy),
          required_quiescent_repetitions => maps:get(
              required_quiescent_repetitions, CapturePolicy
          ),
          runtime_settle_max_milliseconds => maps:get(
              runtime_settle_max_milliseconds, CapturePolicy
          ),
          runtime_settle_interval_milliseconds => maps:get(
              runtime_settle_interval_milliseconds, CapturePolicy
          ),
          runtime_settle_quiet_samples => maps:get(
              runtime_settle_quiet_samples, CapturePolicy
          ),
          repetition_count => MinimumRepetitions, paths_saturated => true,
          status => <<"Ready">>}
    end,
    CaptureIdentities = [
        CaptureIdentity(<<"http">>, Digest),
        CaptureIdentity(<<"http3">>, Digest),
        CaptureIdentity(<<"quic_core">>, Digest)
    ],
    ok = validate_capture_identity(CaptureIdentities, Digest),
    {stale_coverage_capture, <<"http3">>, Digest, <<"stale">>} =
        caught_error(fun() -> validate_capture_identity([
            CaptureIdentity(<<"http">>, Digest),
            CaptureIdentity(<<"http3">>, <<"stale">>),
            CaptureIdentity(<<"quic_core">>, Digest)
        ], Digest) end),
    RuntimeZero = maps:from_list([{Key, 0} || Key <- runtime_keys()]),
    RuntimeOne = RuntimeZero#{processes => 10, ports => 2, ets_tables => 5,
                              queued_messages => 1, largest_mailbox => 1,
                              memory_bytes => 100, run_queue => 0},
    RuntimeTwo = RuntimeOne#{processes => 11, queued_messages => 0,
                            largest_mailbox => 0, memory_bytes => 120},
    RuntimeThree = RuntimeTwo#{memory_bytes => 115},
    RuntimeSample = fun(Index, Runtime, Restored, Stable) ->
        #{sample => Index, offset_milliseconds => (Index - 1) * 100,
          restored => Restored, stable => Stable, runtime => Runtime}
    end,
    FirstSettlement = runtime_settlement(
        RuntimeOne, undefined, 300,
        [RuntimeSample(1, RuntimeTwo, true, false),
         RuntimeSample(2, RuntimeTwo, true, true),
         RuntimeSample(3, RuntimeTwo, true, true),
         RuntimeSample(4, RuntimeTwo, true, true)]
    ),
    SecondSettlement = runtime_settlement(
        RuntimeOne, RuntimeTwo, 300,
        [RuntimeSample(1, RuntimeThree, true, false),
         RuntimeSample(2, RuntimeThree, true, true),
         RuntimeSample(3, RuntimeThree, true, true),
         RuntimeSample(4, RuntimeThree, true, true)]
    ),
    #{final_resource_counts_converged := true,
      final_delta_from_previous :=
          #{processes := 0, ports := 0, ets_tables := 0,
            queued_messages := 0, largest_mailbox := 0,
            memory_bytes := -5, run_queue := 0},
      peaks := #{processes := 11, ports := 2, ets_tables := 5,
                 queued_messages := 1, largest_mailbox := 1,
                 memory_bytes := 120, run_queue := 0}} =
        capture_runtime_summary(RuntimeOne, [
            #{runtime_immediate => RuntimeTwo, runtime => RuntimeTwo,
              settlement => FirstSettlement},
            #{runtime_immediate => RuntimeTwo, runtime => RuntimeThree,
              settlement => SecondSettlement}
        ]),
    RuntimeLeaked = RuntimeOne#{processes => 15, ports => 7,
                                network_ports => 5, sockets => 5,
                                project_processes => 5,
                                quic_core_client_processes => 5},
    LeakedSettlement = runtime_settlement(
        RuntimeOne, undefined, 300,
        [RuntimeSample(1, RuntimeLeaked, false, false),
         RuntimeSample(2, RuntimeLeaked, false, true),
         RuntimeSample(3, RuntimeLeaked, false, true),
         RuntimeSample(4, RuntimeLeaked, false, true)]
    ),
    #{final_resource_counts_converged := false} =
        capture_runtime_summary(RuntimeOne, [
            #{runtime_immediate => RuntimeLeaked, runtime => RuntimeLeaked,
              settlement => LeakedSettlement}
        ]),
    CensusBefore = project_process_label_counts(),
    ok = common_worker_census_test(),
    CensusParent = self(),
    CensusReference = make_ref(),
    {CensusOwner, CensusOwnerMonitor} = spawn_monitor(fun() ->
        Child = spawn(fun() ->
            ok = proc_lib:set_label(<<"quic_core.client">>),
            CensusParent ! {CensusReference, self()},
            receive {CensusReference, stop} -> ok end
        end),
        CensusParent ! {CensusReference, owner, Child}
    end),
    CensusChild = receive
        {CensusReference, ChildPid} when is_pid(ChildPid) -> ChildPid
    after 1000 -> erlang:error(census_child_start_timeout)
    end,
    receive
        {CensusReference, owner, CensusChild} -> ok
    after 1000 -> erlang:error(census_owner_message_timeout)
    end,
    receive
        {'DOWN', CensusOwnerMonitor, process, CensusOwner, normal} -> ok
    after 1000 -> erlang:error(census_owner_exit_timeout)
    end,
    CensusDuring = project_process_label_counts(),
    ensure(maps:get(quic_core_client_processes, CensusDuring) =:=
               maps:get(quic_core_client_processes, CensusBefore) + 1,
           detached_child_missing_from_global_census),
    CensusChildMonitor = monitor(process, CensusChild),
    CensusChild ! {CensusReference, stop},
    receive
        {'DOWN', CensusChildMonitor, process, CensusChild, normal} -> ok
    after 1000 -> erlang:error(census_child_exit_timeout)
    end,
    CensusBefore = project_process_label_counts(),
    <<"Ready">> = coverage_status({95, 100}, {90, 100},
                                   #{lines => 9500, branches => 9000}),
    <<"Blocked">> = coverage_status({94, 100}, {90, 100},
                                     #{lines => 9500, branches => 9000}),
    true = has_eunit_test_export([{self_test, 0}, {ordinary, 0}]),
    true = has_eunit_test_export([{generated_test_, 0}]),
    false = has_eunit_test_export([
        {wrong_arity_test, 1}, {ordinary, 0}
    ]),
    true = valid_diagnostic_name("server-push"),
    true = valid_diagnostic_name("quic_core"),
    false = valid_diagnostic_name("../server-push"),
    1 = diagnostic_repetitions("1"),
    1000 = diagnostic_repetitions("1000"),
    {invalid_diagnostic_repetitions, "0"} = caught_error(fun() ->
        diagnostic_repetitions("0")
    end),
    #{count := 5, total_ms := 150, minimum_ms := 10,
      p50_ms := 30, p95_ms := 50, p99_ms := 50, maximum_ms := 50,
      slowest_repetition := #{iteration := 5, duration_ms := 50}} =
        diagnostic_timing_summary([
            #{iteration => 1, duration_ms => 10},
            #{iteration => 2, duration_ms => 20},
            #{iteration => 3, duration_ms => 30},
            #{iteration => 4, duration_ms => 40},
            #{iteration => 5, duration_ms => 50}
        ]),
    #{all_attempts := #{count := 1, p99_ms := 7},
      post_warmup_attempts := null,
      excluded_warmup_attempts := 1} = diagnostic_timing_evidence([
        #{iteration => 1, duration_ms => 7}
    ]),
    no_diagnostic_timing_samples = caught_error(fun() ->
        diagnostic_timing_summary([])
    end),
    {invalid_diagnostic_duration, -1} = caught_error(fun() ->
        diagnostic_timing_summary([#{iteration => 1, duration_ms => -1}])
    end),
    diagnostic_test = select_named_atom(
        "diagnostic_test", [other_test, diagnostic_test], missing_diagnostic),
    {missing_diagnostic, "absent_test"} = caught_error(fun() ->
        select_named_atom("absent_test", [diagnostic_test], missing_diagnostic)
    end),
    DiagnosticDirectory = filename:absname("."),
    {ok, diagnostic_ok} = run_in_directory(
        DiagnosticDirectory, fun() -> diagnostic_ok end, 1000),
    {error, {error, diagnostic_marker, _}} = run_in_directory(
        DiagnosticDirectory, fun() -> erlang:error(diagnostic_marker) end,
        1000),
    {error, test_timeout} = run_in_directory(
        DiagnosticDirectory, fun() -> receive after 50 -> diagnostic_late end end,
        1),
    ok = diagnostic_publication_lifetime_test(DiagnosticDirectory),
    DiagnosticEvidence = diagnostic_failure_evidence(
        3, {diagnostic_marker, binary:copy(<<"x">>, 20000)}, 64),
    3 = maps:get(iteration, DiagnosticEvidence),
    false = maps:is_key(reason_tail_base64, DiagnosticEvidence),
    ensure(byte_size(iolist_to_binary(json:encode(DiagnosticEvidence))) < 512,
           unbounded_diagnostic_failure_evidence),
    Sensitive = #{endpoint => <<"coverage-private-endpoint.example">>,
                  owner => self(), reference => make_ref(),
                  certificate => binary:copy(<<"private-certificate">>, 64)},
    SensitiveStack = [{http_transport_ffi, connect, [Sensitive],
                       [{file, "C:/private/workspace/secret.erl"}, {line, 42}]}],
    SanitizedEvidence = diagnostic_failure_evidence(
        4, {error, {badmatch, Sensitive}, SensitiveStack}, 16384),
    ensure(maps:get(failure, SanitizedEvidence, undefined) =:=
               diagnostic_failure_details(error, {badmatch, Sensitive},
                                          SensitiveStack),
           coverage_diagnostic_retains_raw_failure_payload),
    CoordinateBranch = #{function => fixture, arity => 0, artifact_lines => [10, 11],
                         source_first_line => 4, source_last_line => 6,
                         private => Sensitive},
    CoordinateReason = {unobservable_branch_coordinates, sample, 2,
        #{branch => CoordinateBranch, observed => [], siblings => [9]}},
    CoordinateFailure = coverage_failure_details(error, CoordinateReason, []),
    true = coverage_coordinate_valid(maps:get(coordinate, CoordinateFailure)),
    CoordinateEncoded = iolist_to_binary(json:encode(CoordinateFailure)),
    nomatch = binary:match(CoordinateEncoded, <<"coverage-private-endpoint.example">>),
    CoordinateDecoded = json:decode(CoordinateEncoded),
    CoordinateDecoded = safe_coverage_failure(CoordinateDecoded),
    HostileCoordinate = (maps:get(<<"coordinate">>, CoordinateDecoded))#{<<"module">> => <<"../private">>},
    false = maps:is_key(<<"coordinate">>, safe_coverage_failure(
        CoordinateDecoded#{<<"coordinate">> => HostileCoordinate})),
    undefined = coverage_coordinate_detail({unobservable_branch_coordinates, sample, 2,
        #{branch => CoordinateBranch#{arity => Sensitive}, observed => [], siblings => [9]}}),
    "+0" = signed_integer_text(0),
    "+17" = signed_integer_text(17),
    "-3" = signed_integer_text(-3),
    'native@sample_test' = module_for_tree_source(
        "fixture/test/native/sample_test.gleam", "test"
    ),
    ok = same_vm_listener_test(),
    ok = listener_cancellation_test(),
    io:format("coverage self-test ok (quiet cover output, policy-driven "
              "saturation, ranked gaps, bounded instrumented-target "
              "failures, and separated artifact/source diagnostics)~n"),
    ok.

listener_cancellation_test() ->
    Unit = #{module => <<"coverage_same_vm_fixture">>, function => <<"accepted_test">>, kind => <<"test">>},
    State = qualification_eunit_listener:init([{units, [Unit]}]),
    Private = #{endpoint => <<"coverage-private-endpoint.example">>, owner => self(), reference => make_ref()},
    Cases = [{timeout, <<"deadline_exceeded">>},
             {{timeout, #{stacktrace => [{coverage_same_vm_fixture, accepted_test, [Private], [{line, 2}]}]}}, <<"deadline_exceeded">>},
             {{exit, killed}, <<"worker_killed">>},
             {{exit, Private}, <<"worker_exit">>},
             {{blame, Private}, <<"dependency_cancelled">>},
             {{abort, Private}, <<"execution_aborted">>},
             {{startup, Private}, <<"startup_failed">>}],
    lists:foreach(fun({Reason, Expected}) ->
        Result = qualification_eunit_listener:handle_cancel(test, [{id, [1]}, {reason, Reason}], State),
        [#{classification := Actual}] = maps:get(failures, Result),
        ensure(Expected =:= Actual, cancellation_lost_its_typed_cause),
        Bytes = iolist_to_binary(json:encode(maps:get(failures, Result))),
        ensure(binary:match(Bytes, <<"coverage-private-endpoint.example">>) =:= nomatch,
               cancellation_exposed_private_payload)
    end, Cases),
    ok.

common_worker_census_test() ->
    {ok, http_server_ffi, Binary, []} = compile:file("src/http_server_ffi.erl",
        [binary, return_errors, return_warnings]),
    {module, http_server_ffi} = code:load_binary(http_server_ffi, "http_server_ffi.erl", Binary),
    Before = runtime_snapshot(),
    Owner = self(), Ref = make_ref(),
    {Worker, Monitor} = http_server_ffi:spawn_monitor(fun() ->
        Owner ! {Ref, ready},
        receive {Ref, stop} -> ok end
    end),
    receive {Ref, ready} -> ok after 1000 -> erlang:error(common_worker_fixture_start_failed) end,
    During = runtime_snapshot(),
    Observed = maps:get(http_worker_processes, During) =:= maps:get(http_worker_processes, Before) + 1,
    Worker ! {Ref, stop},
    receive {'DOWN', Monitor, process, Worker, normal} -> ok after 1000 ->
        erlang:error(common_worker_fixture_stop_failed)
    end,
    ensure(Observed, common_http_worker_missing_from_census),
    ensure(not runtime_owned_resources_restored(Before, During), common_worker_leak_became_warm_baseline),
    ok.

diagnostic_publication_lifetime_test(Directory) ->
    Parent = self(),
    Gate = make_ref(),
    Completed = make_ref(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Outcome = run_in_directory_with_completion(
            Directory, fun() -> diagnostic_ok end, 1000,
            fun() ->
                Parent ! {Gate, self()},
                receive {Gate, finish} -> ok end
            end),
        Parent ! {Completed, Outcome}
    end),
    Worker = receive {Gate, Pid} -> Pid after 1000 ->
        erlang:error(diagnostic_publication_fixture_timeout)
    end,
    WorkerMonitor = monitor(process, Worker),
    Premature = receive {Completed, _} -> true after 100 -> false end,
    Worker ! {Gate, finish},
    receive {'DOWN', WorkerMonitor, process, Worker, _} -> ok after 1000 ->
        erlang:error(diagnostic_worker_did_not_stop)
    end,
    receive {'DOWN', CallerMonitor, process, Caller, _} -> ok after 1000 ->
        erlang:error(diagnostic_caller_did_not_stop)
    end,
    receive {Completed, _} -> ok after 0 -> ok end,
    ensure(not Premature, diagnostic_result_preceded_worker_exit),
    ok.

same_vm_listener_test() ->
    {ok, qualification_eunit_listener, ListenerBeam} = compile:file(
        "scripts/qualification_eunit_listener.erl", [binary, {i, "scripts"}]),
    {module, qualification_eunit_listener} = code:load_binary(
        qualification_eunit_listener, "qualification_eunit_listener.erl", ListenerBeam),
    ensure(erlang:function_exported(qualification_eunit_listener, run_same_vm, 3),
           missing_nonhalting_coverage_listener),
    Directory = filename:join("build", "coverage-listener-self-test"),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    SourcePath = filename:join(Directory, "coverage_same_vm_fixture.erl"),
    BeamPath = filename:join(Directory, "coverage_same_vm_fixture.beam"),
    ok = file:write_file(SourcePath, <<
        "-module(coverage_same_vm_fixture).\n",
        "-export([accepted_test/0, secret_failure_test/0, empty_test_/0, two_test_/0]).\n",
        "accepted_test() -> ok.\n",
        "secret_failure_test() -> erlang:error({badmatch, #{",
        "endpoint => <<\"coverage-private-endpoint.example\">>,",
        "owner => self(), reference => make_ref()}}).\n",
        "empty_test_() -> [].\n",
        "two_test_() -> [fun accepted_test/0, fun accepted_test/0].\n"
    >>),
    {ok, coverage_same_vm_fixture} = compile:file(SourcePath,
        [debug_info, {outdir, Directory}]),
    {ok, _} = cover:start(),
    try
        ok = instrumentation_heap_test(Directory, SourcePath),
        ok = same_vm_listener_case(Directory, <<"accepted_test">>, <<"test">>, ok, 1),
        ok = same_vm_listener_case(Directory, <<"secret_failure_test">>, <<"test">>, error, 1),
        ok = same_vm_listener_case(Directory, <<"empty_test_">>, <<"generator">>, error, 0),
        ok = same_vm_listener_case(Directory, <<"two_test_">>, <<"generator">>, ok, 2),
        Unit = #{module => <<"coverage_same_vm_fixture">>, function => <<"accepted_test">>, kind => <<"test">>},
        {ok, #{valid := true, configured_units := 1, completed_tests := 1} = Proof} =
            eunit_in_directory(filename:absname(Directory), [Unit]),
        ok = coverage_unit_evidence_test(Unit, Proof),
        {error, #{valid := false, configured_units := 1, completed_tests := 1,
                  failures := [#{<<"classification">> := <<"pattern_mismatch">>}]}} =
            eunit_in_directory(filename:absname(Directory),
                [Unit#{function => <<"secret_failure_test">>}]),
        {ok, Calls} = cover:analyse(coverage_same_vm_fixture, calls, function),
        {{coverage_same_vm_fixture, accepted_test, 0}, 5} =
            lists:keyfind({coverage_same_vm_fixture, accepted_test, 0}, 1, Calls),
        ok = failed_repetition_retains_coverage_test(Directory, SourcePath, BeamPath),
        ok = package_gap_diagnostic_test(SourcePath, BeamPath),
        ok
    after
        cover:stop(),
        code:purge(coverage_same_vm_fixture),
        code:delete(coverage_same_vm_fixture),
        file:delete(SourcePath),
        file:delete(BeamPath)
    end.

failed_repetition_retains_coverage_test(Directory, SourcePath, BeamPath) ->
    Name = "failure-fixture",
    Partial = filename:join([?OUTPUT, "diagnostic", Name ++ ".json"]),
    Export = filename:join([?OUTPUT, "diagnostic", Name ++ ".cover"]),
    delete_if_present(Partial),
    delete_if_present(Export),
    Modules = [{coverage_same_vm_fixture, SourcePath}],
    Models = #{coverage_same_vm_fixture => coverage_model(
        coverage_same_vm_fixture, SourcePath, BeamPath)},
    Unit = #{module => <<"coverage_same_vm_fixture">>,
        function => <<"secret_failure_test">>, kind => <<"test">>},
    {coverage_test_failure, Name, 1, _, _} = caught_error(fun() ->
        run_coverage_repetitions(1, Name, filename:absname(Directory), [Unit],
            Modules, Models, coverage_snapshot(Modules, Models), runtime_snapshot(), 0, [])
    end),
    {ok, Bytes} = file:read_file(Partial),
    #{<<"scope">> := <<"PartialCoverageAfterTestFailure">>,
      <<"satisfies_coverage_gate">> := false,
      <<"tests">> := #{<<"valid">> := false, <<"completed_tests">> := 1},
      <<"cover_sha256">> := Digest} = coverage_decode_json(Bytes),
    Digest = file_digest(Export),
    ensure(binary:match(Bytes, <<"coverage-private-endpoint.example">>) =:= nomatch,
        partial_coverage_exposed_failure_payload),
    ok = file:delete(Partial),
    ok = file:delete(Export),
    delete_if_present(coverage_progress_path(Name)),
    ok.

package_gap_diagnostic_test(SourcePath, BeamPath) ->
    %% A successful package still needs actionable gaps if another package
    %% cannot capture. Exercise actual cover counters without inventing the
    %% missing packages or accepting this diagnostic as qualification.
    Name = "package-gap-fixture-" ++ binary_to_list(hex(crypto:strong_rand_bytes(8))),
    Path = filename:join([?OUTPUT, "diagnostic", Name ++ ".gaps.json"]),
    CapturePath = filename:join([?OUTPUT, "diagnostic", Name ++ ".capture-fixture.json"]),
    ok = filelib:ensure_dir(Path),
    Modules = [{coverage_same_vm_fixture, SourcePath}],
    Models = #{coverage_same_vm_fixture => coverage_model(
        coverage_same_vm_fixture, SourcePath, BeamPath)},
    Before = lists:sort(filelib:wildcard(filename:join(?OUTPUT, "*.capture.json"))),
    Metadata = #{status => <<"Ready">>, source_sha256 => <<"source-fixture">>,
        coordinate_model_sha256 => <<"coordinates-fixture">>, cover_sha256 => <<"cover-fixture">>,
        repetition_count => 10, stop_reason => <<"saturated">>,
        evidence_identity => #{scope => <<"Synthetic fixture only">>},
        execution_environment => execution_runtime()},
    ok = file:write_file(CapturePath, json:encode(Metadata)),
    try
        ok = cover:reset(coverage_same_vm_fixture),
        ok = coverage_same_vm_fixture:accepted_test(),
        ok = write_package_gaps(Name, Modules, Models, Metadata, CapturePath),
        {ok, Bytes} = file:read_file(Path),
        Report = coverage_decode_json(Bytes),
        false = capture_field(Report, satisfies_coverage_gate),
        <<"Measured">> = capture_field(Report, status),
        <<"PackageCoverageGaps">> = capture_field(Report, scope),
        true = capture_field(Report, capture_sha256) =:= file_digest(CapturePath),
        [Module] = capture_field(Report, modules),
        Missing = capture_field(Module, full_uncovered_lines),
        ensure(Missing =/= [], missing_actual_package_gap),
        Metric = capture_field(Module, full_lines),
        ensure(capture_field(Metric, covered) > 0 andalso
            capture_field(Metric, covered) < capture_field(Metric, total),
            missing_executed_and_unexecuted_package_paths),
        ensure(binary:match(Bytes, <<"coverage-private-endpoint.example">>) =:= nomatch,
            package_gap_exposed_test_payload),
        ensure(not maps:is_key(<<"changed">>, Report), package_gap_claimed_changed_scope),
        Before = lists:sort(filelib:wildcard(filename:join(?OUTPUT, "*.capture.json"))),
        ok
    after
        file:delete(Path),
        file:delete(CapturePath)
    end.

coverage_unit_evidence_test(Unit, Proof) ->
    ok = coverage_repetition_schema_test(Proof),
    ok = audit_coverage_unit_evidence([Unit], Proof),
    invalid_coverage_unit_summary = caught_error(fun() ->
        audit_coverage_unit_evidence([Unit], Proof#{completed_tests => 2})
    end),
    invalid_coverage_unit_report_path = caught_error(fun() ->
        audit_coverage_unit_evidence([Unit], Proof#{report => <<"../private.json">>})
    end),
    incomplete_coverage_unit_report = caught_error(fun() ->
        audit_coverage_unit_evidence([Unit#{function => <<"substituted_test">>}], Proof)
    end),
    Path = binary_to_list(maps:get(report, Proof)),
    {ok, Original} = coverage_unit_report_bytes(Path),
    try
        Child = json:decode(Original),
        [Row] = maps:get(<<"units">>, Child),
        Counts = maps:get(<<"counts">>, Row),
        Doubled = Counts#{<<"started">> => 2, <<"completed">> => 2, <<"passed">> => 2},
        Forged = Child#{<<"units">> => [Row#{<<"counts">> => Doubled}]},
        ForgedBytes = iolist_to_binary([json:encode(Forged), $\n]),
        ok = file:write_file(Path, ForgedBytes),
        modified_coverage_unit_report = caught_error(fun() ->
            audit_coverage_unit_evidence([Unit], Proof)
        end),
        ForgedProof = Proof#{report_sha256 => hex(crypto:hash(sha256, ForgedBytes)),
                             completed_tests => 2},
        incomplete_coverage_unit_report = caught_error(fun() ->
            audit_coverage_unit_evidence([Unit], ForgedProof)
        end),
        ok = file:write_file(Path, <<0:67108872>>),
        error = coverage_unit_report_bytes(Path),
        ok = file:delete(Path),
        error = coverage_unit_report_bytes(Path)
    after
        ok = file:write_file(Path, Original)
    end,
    ok = audit_coverage_unit_evidence([Unit], Proof),
    ok.

coverage_repetition_schema_test(Proof) ->
    Runtime = maps:from_list([{Key, 0} || Key <- runtime_keys()]),
    Universe = #{all_lines => [], all_branches => [], covered_lines => [], covered_branches => []},
    Base = summarize_coverage_repetition(1, Universe, Universe, 0),
    Sample = #{sample => 1, offset_milliseconds => 0, restored => true, stable => false,
               runtime => Runtime},
    Settlement = runtime_settlement(Runtime, undefined, 0, [Sample]),
    Report = Base#{test_duration_ms => 0, settle_duration_ms => 0, tests => Proof,
        runtime_immediate => Runtime, runtime => Runtime, settlement => Settlement,
        runtime_delta_from_start => Runtime, runtime_delta_from_previous => Runtime},
    ok = coverage_repetition_keys(Report),
    Secret = <<"private-capture.example">>,
    Hostile = [Report#{private => Secret},
        Report#{runtime => Runtime#{private => Secret}},
        Report#{tests => Proof#{private => Secret}},
        Report#{settlement => Settlement#{samples => [Sample#{runtime => Runtime#{private => Secret}}]}}],
    lists:foreach(fun(Value) ->
        invalid_coverage_report_schema = caught_error(fun() -> coverage_repetition_keys(Value) end)
    end, Hostile),
    ok = coverage_repetition_keys(json:decode(iolist_to_binary(json:encode(Report)))),
    ok.

instrumentation_heap_test(Directory, SourcePath) ->
    Bound = #{size => 33554432, kill => true, error_logger => false, include_shared_binaries => true},
    Previous = erlang:system_flag(max_heap_size, Bound),
    try
        ok = cover_compile_modules([{coverage_same_vm_fixture, SourcePath}], Directory),
        #{status := <<"Ready">>, compiled_modules := 1,
          restored_heap_words := 33554432, heap_configuration_restored := true} =
            get(coverage_instrumentation_evidence),
        Missing = caught_error(fun() ->
            cover_compile_modules([{coverage_missing_fixture, SourcePath}], Directory)
        end),
        ensure(element(1, Missing) =:= missing_production_beam,
               wrong_instrumentation_fixture_failure),
        #{status := <<"Failed">>, compiled_modules := 0,
          restored_heap_words := 33554432, heap_configuration_restored := true} =
            get(coverage_instrumentation_evidence),
        Owner = self(),
        Ref = make_ref(),
        {Worker, Monitor} = spawn_monitor(fun() ->
            Owner ! {Ref, process_info(self(), max_heap_size)}
        end),
        receive {Ref, {max_heap_size, Bound}} -> ok after 1000 ->
            erlang:error(test_actor_inherited_compiler_heap)
        end,
        receive {'DOWN', Monitor, process, Worker, normal} -> ok after 1000 ->
            erlang:error(heap_fixture_did_not_stop)
        end
    after erlang:system_flag(max_heap_size, Previous) end.

same_vm_listener_case(Directory, Function, Kind, Expected, Leaves) ->
    Path = filename:join(Directory, binary_to_list(Function) ++ ".json"),
    delete_if_present(Path),
    Nonce = <<"coverage-listener-self-test">>,
    Units = [#{module => <<"coverage_same_vm_fixture">>, function => Function, kind => Kind}],
    Expected = qualification_eunit_listener:run_same_vm(Units, Path, Nonce),
    {ok, Bytes} = file:read_file(Path),
    ensure(binary:match(Bytes, <<"coverage-private-endpoint.example">>) =:= nomatch,
           same_vm_listener_exposed_failure_payload),
    Report = json:decode(Bytes),
    [#{<<"counts">> := #{<<"started">> := Leaves, <<"completed">> := Leaves}}] =
        maps:get(<<"units">>, Report),
    case Function of
        <<"accepted_test">> ->
            %% An exclusive write failure returns locally and cannot reuse a
            %% stale completion, even when the same nonce is supplied.
            error = qualification_eunit_listener:run_same_vm(Units, Path, Nonce);
        _ -> ok
    end,
    ok = file:delete(Path),
    ok.

coverage_snapshot(Modules, CoverageMap) ->
    Parts = [module_coverage_snapshot(Module, maps:get(Module, CoverageMap))
             || {Module, _Path} <- Modules],
    lists:foldl(fun merge_coverage_snapshot/2,
                #{all_lines => [], covered_lines => [],
                  all_branches => [], covered_branches => []}, Parts).

snapshot_metrics(Snapshot) ->
    #{lines => coverage_metric(maps:get(covered_lines, Snapshot),
                               maps:get(all_lines, Snapshot)),
      branches => coverage_metric(maps:get(covered_branches, Snapshot),
                                  maps:get(all_branches, Snapshot))}.

coverage_coordinate_digest(CoverageMap, Snapshot) ->
    Models = lists:sort([
        {Module, coordinate_model_material(Model)}
        || {Module, Model} <- maps:to_list(CoverageMap)
    ]),
    Universe = #{all_lines => maps:get(all_lines, Snapshot),
                 all_branches => maps:get(all_branches, Snapshot)},
    Material = {expected_coordinate_methodology(), Models, Universe},
    hex(crypto:hash(sha256, term_to_binary(Material, [deterministic]))).

coordinate_model_material(Model) ->
    maps:with(
        [source, source_sha256, artifact, artifact_sha256,
         compiled_beam, compiled_beam_sha256, coordinate_method,
         regions, functions, branches],
        Model
    ).

module_coverage_snapshot(Module, Model) ->
    {ok, LineCoverage} = cover:analyse(Module, coverage, line),
    NormalizedLines = normalize_cover_lines(Module, LineCoverage),
    Lines = [{Line, Covered}
             || {Line, Covered, _Missed} <- NormalizedLines],
    CoverageByLine = maps:from_list([
        {Line, Covered > 0} || {Line, Covered} <- Lines
    ]),
    Branches0 = maps:get(branches, Model),
    ok = validate_line_observability(Module, Lines, Model),
    Branches = observable_branches(Module, Branches0, CoverageByLine),
    AllLines = ordsets:from_list([
        line_identity(Module, Line, Model) || {Line, _} <- Lines
    ]),
    CoveredLines = ordsets:from_list([
        line_identity(Module, Line, Model)
        || {Line, Covered} <- Lines, Covered > 0
    ]),
    AllBranches = ordsets:from_list([
        branch_identity(Module, Branch, CoverageByLine) || Branch <- Branches
    ]),
    CoveredBranches = ordsets:from_list([
        branch_identity(Module, Branch, CoverageByLine)
        || Branch <- Branches, branch_covered(Branch, CoverageByLine)
    ]),
    #{all_lines => AllLines, covered_lines => CoveredLines,
      all_branches => AllBranches, covered_branches => CoveredBranches}.

normalize_cover_lines(Module, Rows) ->
    Normalized = [normalize_cover_line(Module, Row) || Row <- Rows],
    LineNumbers = [Line || {Line, _Covered, _Missed} <- Normalized],
    ensure(length(LineNumbers) =:= length(lists:usort(LineNumbers)),
           {duplicate_cover_line_rows, Module,
            length(LineNumbers), length(lists:usort(LineNumbers))}),
    lists:sort(Normalized).

normalize_cover_line(Module,
                     {{CoveredModule, Line}, {Covered, Missed}} = Row) ->
    ensure(CoveredModule =:= Module,
           {foreign_cover_line_module, Module, CoveredModule, Line}),
    ensure(is_integer(Line) andalso Line > 0 andalso
           is_integer(Covered) andalso Covered >= 0 andalso
           is_integer(Missed) andalso Missed >= 0,
           {invalid_cover_line_row, Module, Row}),
    {Line, Covered, Missed};
normalize_cover_line(Module, Row) ->
    erlang:error({invalid_cover_line_row, Module, Row}).

validate_line_observability(Module, Lines, Model) ->
    lists:foreach(fun({ArtifactLine, _Covered}) ->
        _ = source_region_for_artifact_line(Module, ArtifactLine, Model)
    end, Lines),
    ObservableLines = ordsets:from_list([Line || {Line, _Covered} <- Lines]),
    lists:foreach(fun(Function) ->
        FunctionLines = ordsets:from_list(maps:get(artifact_lines, Function)),
        Witnesses = ordsets:intersection(FunctionLines, ObservableLines),
        ensure(Witnesses =/= [],
               {unobservable_compiled_function, Module,
                maps:get(function, Function), maps:get(arity, Function),
                #{function_lines => line_number_binary(FunctionLines),
                  observable_line_count => length(ObservableLines)}})
    end, maps:get(functions, Model)),
    ok.

validate_branch_observability(Module, Branches, CoverageByLine) ->
    _ = observable_branches(Module, Branches, CoverageByLine),
    ok.

observable_branches(Module, Branches, CoverageByLine) ->
    ObservableLines = ordsets:from_list(maps:keys(CoverageByLine)),
    DecisionAlternatives = [
        {branch_decision_key(Branch),
         maps:get(decision_alternative_index, Branch)}
        || Branch <- Branches
    ],
    ensure(length(DecisionAlternatives) =:=
               length(lists:usort(DecisionAlternatives)),
           {duplicate_compiled_branch_alternative, Module}),
    lists:map(fun(Branch) ->
        Index = maps:get(index, Branch),
        DecisionKey = branch_decision_key(Branch),
        BranchLines = ordsets:from_list(maps:get(artifact_lines, Branch)),
        Observable = ordsets:intersection(BranchLines, ObservableLines),
        Siblings = [Sibling || Sibling <- Branches,
                              branch_decision_key(Sibling) =:= DecisionKey,
                              maps:get(index, Sibling) =/= Index],
        ensure(Siblings =/= [],
               {compiled_branch_decision_without_sibling, Module,
                DecisionKey, Index}),
        SiblingLines = ordsets:from_list(lists:append([
            maps:get(artifact_lines, Sibling) || Sibling <- Siblings
        ])),
        Exclusive = ordsets:subtract(Observable, SiblingLines),
        ensure(Observable =/= [],
               {unobservable_branch_coordinates, Module, Index,
                #{branch => Branch, observed => Observable, siblings => SiblingLines}}),
        ensure(Exclusive =/= [],
               {indistinguishable_branch_coordinates, Module, Index,
                #{branch => Branch, observed => Observable, siblings => SiblingLines}}),
        Branch#{artifact_witness_lines => Exclusive}
    end, Branches).

branch_decision_key(Branch) ->
    {maps:get(function, Branch), maps:get(arity, Branch),
     maps:get(function_decision_index, Branch)}.

line_identity(Module, ArtifactLine, Model) ->
    Region = source_span_for_artifact_line(Module, ArtifactLine, Model),
    {Module, ArtifactLine,
     maps:get(source_first_line, Region),
     maps:get(source_last_line, Region)}.

branch_identity(Module, Branch, CoverageByLine) ->
    ArtifactLines = branch_witness_lines(Branch, CoverageByLine),
    {Module, maps:get(function, Branch), maps:get(arity, Branch),
     maps:get(index, Branch), maps:get(function_alternative_index, Branch),
     maps:get(function_decision_index, Branch),
     maps:get(decision_alternative_index, Branch),
     lists:min(ArtifactLines), ArtifactLines,
     maps:get(source_first_line, Branch),
     maps:get(source_last_line, Branch)}.

branch_witness_lines(Branch, CoverageByLine) ->
    case maps:find(artifact_witness_lines, Branch) of
        {ok, Lines} -> Lines;
        error ->
            lists:usort([
                Line || Line <- maps:get(artifact_lines, Branch),
                        maps:is_key(Line, CoverageByLine)
            ])
    end.

line_number_binary(Lines) ->
    unicode:characters_to_binary(line_number_text(lists:usort(Lines))).

bounded_term(Value, Limit) ->
    Bytes = unicode:characters_to_binary(io_lib:format("~0P", [Value, 12])),
    case byte_size(Bytes) =< Limit of
        true -> Bytes;
        false -> <<(binary:part(Bytes, 0, Limit))/binary, "...">>
    end.

merge_coverage_snapshot(Part, Acc) ->
    maps:map(fun(Key, Values) ->
        ordsets:union(Values, maps:get(Key, Part))
    end, Acc).

summarize_coverage_repetition(Index, Previous, Current, Duration) ->
    ensure(Index > 0, {invalid_coverage_repetition, Index}),
    ensure(Duration >= 0, {invalid_coverage_duration, Duration}),
    ensure(maps:get(all_lines, Previous) =:= maps:get(all_lines, Current),
           {coverage_line_universe_changed, Index}),
    ensure(maps:get(all_branches, Previous) =:= maps:get(all_branches, Current),
           {coverage_branch_universe_changed, Index}),
    PreviousLines = maps:get(covered_lines, Previous),
    CurrentLines = maps:get(covered_lines, Current),
    PreviousBranches = maps:get(covered_branches, Previous),
    CurrentBranches = maps:get(covered_branches, Current),
    ensure(ordsets:is_subset(PreviousLines, CurrentLines),
           {coverage_lines_regressed, Index}),
    ensure(ordsets:is_subset(PreviousBranches, CurrentBranches),
           {coverage_branches_regressed, Index}),
    AddedLines = ordsets:subtract(CurrentLines, PreviousLines),
    AddedBranches = ordsets:subtract(CurrentBranches, PreviousBranches),
    #{repetition => Index,
      duration_ms => Duration,
      cumulative =>
          #{lines => coverage_metric(CurrentLines, maps:get(all_lines, Current)),
            branches => coverage_metric(
                CurrentBranches, maps:get(all_branches, Current))},
      added => #{lines => length(AddedLines), branches => length(AddedBranches)},
      newly_covered_lines => [line_location(Line) || Line <- AddedLines],
      newly_covered_branches =>
          [branch_location(Branch) || Branch <- AddedBranches]}.

coverage_metric(Covered, All) ->
    #{covered => length(Covered), total => length(All)}.

line_location({Module, ArtifactLine, SourceFirst, SourceLast}) ->
    #{module => atom_to_binary(Module),
      artifact_line => ArtifactLine,
      source_first_line => SourceFirst,
      source_last_line => SourceLast}.

branch_location({Module, Function, Arity, Index, FunctionIndex,
                 DecisionIndex, AlternativeIndex, Anchor, Lines,
                 SourceFirst, SourceLast}) ->
    #{module => atom_to_binary(Module),
      function => atom_to_binary(Function),
      arity => Arity,
      index => Index,
      function_alternative_index => FunctionIndex,
      function_decision_index => DecisionIndex,
      decision_alternative_index => AlternativeIndex,
      artifact_anchor_line => Anchor,
      artifact_lines => Lines,
      source_first_line => SourceFirst,
      source_last_line => SourceLast}.

capture_growth_summary(Reports) ->
    ensure(Reports =/= [], empty_coverage_repetitions),
    Later = tl(Reports),
    LaterLines = lists:sum([
        maps:get(lines, maps:get(added, Report)) || Report <- Later
    ]),
    LaterBranches = lists:sum([
        maps:get(branches, maps:get(added, Report)) || Report <- Later
    ]),
    LastGrowth = lists:foldl(fun(Report, Previous) ->
        case repetition_grew(Report) of
            true -> maps:get(repetition, Report);
            false -> Previous
        end
    end, 0, Reports),
    Final = lists:last(Reports),
    QuiescentTail = quiescent_tail_repetitions(lists:reverse(Reports), 0),
    RequiredQuiescent = maps:get(
        required_quiescent_repetitions, current_capture_policy()
    ),
    #{repetitions => length(Reports),
      later_growth => #{lines => LaterLines, branches => LaterBranches},
      last_growth_repetition => LastGrowth,
      final_repetition_grew => repetition_grew(Final),
      quiescent_tail_repetitions => QuiescentTail,
      paths_saturated => QuiescentTail >= RequiredQuiescent}.

quiescent_tail_repetitions([], Count) -> Count;
quiescent_tail_repetitions([Report | Rest], Count) ->
    case repetition_grew(Report) of
        true -> Count;
        false -> quiescent_tail_repetitions(Rest, Count + 1)
    end.

capture_stop_decision(Executed, Quiescent) ->
    Policy = current_capture_policy(),
    Minimum = maps:get(minimum_repetitions, Policy),
    Maximum = maps:get(maximum_repetitions, Policy),
    RequiredQuiescent = maps:get(required_quiescent_repetitions, Policy),
    case {Executed < Minimum,
          Quiescent >= RequiredQuiescent,
          Executed >= Maximum} of
        {true, _, _} -> continue;
        {false, true, _} -> saturated;
        {false, false, true} -> maximum_without_saturation;
        {false, false, false} -> continue
    end.

repetition_grew(Report) ->
    Added = maps:get(added, Report),
    maps:get(lines, Added) > 0 orelse maps:get(branches, Added) > 0.

runtime_snapshot() ->
    Queues = [Length
              || Process <- processes(),
                 {message_queue_len, Length} <-
                     [process_info(Process, message_queue_len)]],
    LabelCounts = project_process_label_counts(),
    maps:merge(
        LabelCounts,
        #{processes => erlang:system_info(process_count),
          ports => length(erlang:ports()),
          network_ports => network_port_count(),
          sockets => socket_count(),
          project_processes => lists:sum(maps:values(LabelCounts)),
          ets_tables => length(ets:all()),
          queued_messages => lists:sum(Queues),
          largest_mailbox => case Queues of [] -> 0; _ -> lists:max(Queues) end,
          memory_bytes => erlang:memory(total),
          run_queue => statistics(run_queue)}
    ).

project_process_label_counts() ->
    Initial = maps:from_list([{Key, 0} || {Key, _} <- project_process_labels()]),
    ByLabel = maps:from_list([{Label, Key}
                              || {Key, Label} <- project_process_labels()]),
    lists:foldl(fun(Process, Counts) ->
        case process_info(Process, label) of
            {label, Label} when is_binary(Label) ->
                case maps:find(Label, ByLabel) of
                    {ok, Key} -> maps:update_with(Key, fun(Value) -> Value + 1 end,
                                                  Counts);
                    error -> Counts
                end;
            _ -> Counts
        end
    end, Initial, processes()).

project_process_labels() ->
    [{http_worker_processes, <<"http.worker">>},
     {http_reaper_processes, <<"http.reaper">>},
     {http_guardian_processes, <<"http.guardian">>},
     {http_cancel_broker_processes, <<"http.cancel_broker">>},
     {http_adapter_callback_processes, <<"http.adapter_callback">>},
     {http_body_guardian_processes, <<"http.body_guardian">>},
     {http_body_callback_processes, <<"http.body_callback">>},
     {http_connect_coordinator_processes, <<"http.connect_coordinator">>},
     {http_dns_resolver_processes, <<"http.dns_resolver">>},
     {http_connect_candidate_processes, <<"http.connect_candidate">>},
     {http_policy_callback_processes, <<"http.policy_callback">>},
     {http_https_resolver_processes, <<"http.https_resolver">>},
     {http_policy_store_processes, <<"http.policy_store">>},
     {http_http2_pool_processes, <<"http.http2_pool">>},
     {http_client_lifecycle_processes, <<"http.client_lifecycle">>},
     {http_server_executor_processes, <<"http.server_executor">>},
     {http_request_handler_processes, <<"http.request_handler">>},
     {http_upload_reader_processes, <<"http.upload_reader">>},
     {http_diagnostic_guardian_processes, <<"http.diagnostic_guardian">>},
     {http_diagnostic_sink_processes, <<"http.diagnostic_sink">>},
     {http_http3_connection_owner_processes, <<"http.http3_connection_owner">>},
     {http_http3_request_reaper_processes, <<"http.http3_request_reaper">>},
     {http_http3_request_worker_processes, <<"http.http3_request_worker">>},
     {http_http3_io_worker_processes, <<"http.http3_io_worker">>},
     {http_client_race_guardian_processes, <<"http.client_race_guardian">>},
     {http_client_connection_candidate_processes, <<"http.client_connection_candidate">>},
     {quic_core_client_processes, <<"quic_core.client">>},
     {quic_core_listener_processes, <<"quic_core.listener">>},
     {quic_core_connection_processes, <<"quic_core.connection">>},
     {quic_core_connect_candidate_processes,
      <<"quic_core.connect_candidate">>},
     {quic_core_dns_resolver_processes, <<"quic_core.dns_resolver">>},
     {quic_core_udp_relay_processes, <<"quic_core.udp_relay">>},
     {quic_core_replay_guard_processes, <<"quic_core.replay_guard">>},
     {quic_core_qlog_writer_processes, <<"quic_core.qlog_writer">>},
     {http3_client_processes, <<"http3.client">>},
     {http3_listener_processes, <<"http3.listener">>},
     {http3_acceptor_processes, <<"http3.acceptor">>},
     {http3_connection_processes, <<"http3.connection">>},
     {http3_connect_candidate_processes, <<"http3.connect_candidate">>}].

network_port_count() ->
    length([Port
            || Port <- erlang:ports(),
               {name, Name} <- [erlang:port_info(Port, name)],
               lists:member(Name, ["udp_inet", "tcp_inet", "sctp_inet"])]).

socket_count() ->
    case code:ensure_loaded(socket) of
        {module, socket} ->
            ensure(erlang:function_exported(socket, which_sockets, 0),
                   socket_inventory_unavailable),
            length(socket:which_sockets());
        {error, Reason} -> erlang:error({socket_inventory_unavailable, Reason})
    end.

settle_runtime(RuntimeBefore0, WarmReference0) ->
    RuntimeBefore = normalize_runtime(RuntimeBefore0),
    WarmReference = case WarmReference0 of
        undefined -> undefined;
        ReferenceValue -> normalize_runtime(ReferenceValue)
    end,
    Policy = current_capture_policy(),
    Maximum = maps:get(runtime_settle_max_milliseconds, Policy),
    Interval = maps:get(runtime_settle_interval_milliseconds, Policy),
    Required = maps:get(runtime_settle_quiet_samples, Policy),
    ensure(Maximum > 0 andalso Interval > 0 andalso Required > 0,
           invalid_runtime_settle_policy),
    Started = erlang:monotonic_time(millisecond),
    settle_runtime_loop(
        RuntimeBefore, WarmReference, Started, Maximum, Interval, Required,
        undefined, 0, [], 1
    ).

settle_runtime_loop(RuntimeBefore, WarmReference, Started, Maximum, Interval,
                    Required, Previous, Quiet, Acc, Index) ->
    Runtime = runtime_snapshot(),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    Stable = case Previous of
        undefined -> false;
        Value -> runtime_not_growing(Value, Runtime)
    end,
    Restored = runtime_owned_resources_restored(RuntimeBefore, Runtime)
               andalso runtime_warm_resources_restored(
                   WarmReference, Runtime),
    NextQuiet = case Stable andalso Restored of
        true -> Quiet + 1;
        false -> 0
    end,
    Sample = #{sample => Index,
               offset_milliseconds => Elapsed,
               restored => Restored,
               stable => Stable,
               runtime => Runtime},
    Samples = [Sample | Acc],
    case NextQuiet >= Required of
        true -> runtime_settlement(
                    RuntimeBefore, WarmReference, Elapsed,
                    lists:reverse(Samples));
        false when Elapsed >= Maximum ->
            runtime_settlement(
                RuntimeBefore, WarmReference, Elapsed,
                lists:reverse(Samples));
        false ->
            timer:sleep(erlang:min(Interval, Maximum - Elapsed)),
            settle_runtime_loop(
                RuntimeBefore, WarmReference, Started, Maximum, Interval,
                Required, Runtime, NextQuiet, Samples, Index + 1
            )
    end.

runtime_settlement(RuntimeBefore, WarmReference, Elapsed, Samples) ->
    Policy = current_capture_policy(),
    Quiet = runtime_settlement_quiet_tail(
        RuntimeBefore, WarmReference, Samples),
    Required = maps:get(runtime_settle_quiet_samples, Policy),
    Converged = Quiet >= Required,
    #{converged => Converged,
      timed_out => not Converged,
      elapsed_milliseconds => Elapsed,
      maximum_milliseconds =>
          maps:get(runtime_settle_max_milliseconds, Policy),
      interval_milliseconds =>
          maps:get(runtime_settle_interval_milliseconds, Policy),
      required_quiet_samples =>
          maps:get(runtime_settle_quiet_samples, Policy),
      final_quiet_samples => Quiet,
      sample_count => length(Samples),
      samples => Samples}.

runtime_settlement_quiet_tail(RuntimeBefore0, WarmReference0, Samples) ->
    RuntimeBefore = normalize_runtime(RuntimeBefore0),
    WarmReference = case WarmReference0 of
        undefined -> undefined;
        Value -> normalize_runtime(Value)
    end,
    {_Previous, Quiet} = lists:foldl(fun(Sample, {Previous, Count}) ->
        Runtime = normalize_runtime(capture_field(Sample, runtime)),
        Stable = case Previous of
            undefined -> false;
            PreviousValue -> runtime_not_growing(PreviousValue, Runtime)
        end,
        Restored = runtime_owned_resources_restored(RuntimeBefore, Runtime)
                   andalso runtime_warm_resources_restored(
                       WarmReference, Runtime),
        {Runtime, case Stable andalso Restored of
            true -> Count + 1;
            false -> 0
        end}
    end, {undefined, 0}, Samples),
    Quiet.

settlement_final_runtime(Settlement) ->
    Samples = maps:get(samples, Settlement),
    normalize_runtime(capture_field(lists:last(Samples), runtime)).

runtime_not_growing(Previous, Current) ->
    lists:all(fun(Key) ->
        maps:get(Key, Current) =< maps:get(Key, Previous)
    end, runtime_settle_resource_keys()).

runtime_owned_resources_restored(Before, Current) ->
    lists:all(fun(Key) ->
        maps:get(Key, Current) =< maps:get(Key, Before)
    end, [network_ports, sockets | project_process_label_keys()]).

runtime_warm_resources_restored(undefined, _Current) -> true;
runtime_warm_resources_restored(Reference, Current) ->
    lists:all(fun(Key) ->
        maps:get(Key, Current) =< maps:get(Key, Reference)
    end, [processes, ports, ets_tables]).

runtime_settle_resource_keys() ->
    [processes, ports, network_ports, sockets, project_processes, ets_tables
     | project_process_label_keys()].

runtime_delta(Before, After) ->
    maps:from_list([{Key, maps:get(Key, After) - maps:get(Key, Before)}
                    || Key <- runtime_keys()]).

capture_runtime_summary(RuntimeBefore0, Reports) ->
    ensure(Reports =/= [], insufficient_runtime_repetitions),
    RuntimeBefore = normalize_runtime(RuntimeBefore0),
    Runtimes = [normalize_runtime(capture_field(Report, runtime))
                || Report <- Reports],
    ImmediateRuntimes = [normalize_runtime(
                             capture_field(Report, runtime_immediate))
                         || Report <- Reports],
    SettlementRuntimes = lists:append([
        [normalize_runtime(capture_field(Sample, runtime))
         || Sample <- capture_field(
                            capture_field(Report, settlement), samples)]
        || Report <- Reports
    ]),
    WarmReference = hd(Runtimes),
    Previous = case Runtimes of
        [_] -> RuntimeBefore;
        _ -> lists:nth(length(Runtimes) - 1, Runtimes)
    end,
    Final = lists:last(Runtimes),
    FinalDelta = runtime_delta(Previous, Final),
    FinalStartDelta = runtime_delta(RuntimeBefore, Final),
    FinalWarmDelta = runtime_delta(WarmReference, Final),
    RestoredKeys = [processes, ports, ets_tables],
    OwnedKeys = [network_ports, sockets | project_process_label_keys()],
    AllSettled = lists:all(fun(Report) ->
        capture_field(capture_field(Report, settlement), converged) =:= true
    end, Reports),
    WarmRestored = lists:all(fun(Key) ->
        maps:get(Key, Final) =< maps:get(Key, WarmReference)
    end, RestoredKeys),
    OwnedRestored = lists:all(fun(Key) ->
        maps:get(Key, Final) =< maps:get(Key, RuntimeBefore)
    end, OwnedKeys),
    Converged = AllSettled andalso WarmRestored andalso OwnedRestored,
    ObservedRuntimes = [RuntimeBefore | ImmediateRuntimes ++
                        SettlementRuntimes],
    #{final_resource_counts_converged => Converged,
      all_repetitions_settled => AllSettled,
      warm_resource_counts_restored => WarmRestored,
      owned_resource_counts_restored => OwnedRestored,
      final_delta_from_previous => FinalDelta,
      final_delta_from_start => FinalStartDelta,
      final_delta_from_warm_reference => FinalWarmDelta,
      warm_runtime_reference => WarmReference,
      maximum_settle_milliseconds => lists:max([
          capture_field(capture_field(Report, settlement), elapsed_milliseconds)
          || Report <- Reports
      ]),
      peaks => maps:from_list([
          {Key, lists:max([maps:get(Key, Runtime)
                           || Runtime <- ObservedRuntimes])}
          || Key <- runtime_keys()
      ]),
      observed_peaks => maps:from_list([
          {Key, lists:max([maps:get(Key, Runtime)
                           || Runtime <- ObservedRuntimes])}
          || Key <- runtime_keys()
      ])}.

normalize_runtime(Runtime) ->
    maps:from_list([{Key, capture_field(Runtime, Key)} || Key <- runtime_keys()]).

runtime_keys() ->
    [processes, ports, network_ports, sockets, project_processes,
     ets_tables, queued_messages, largest_mailbox, memory_bytes, run_queue
     | project_process_label_keys()].

project_process_label_keys() ->
    [Key || {Key, _Label} <- project_process_labels()].

module_report(Module, SourceMap, Changed, Model) ->
    Path = maps:get(Module, SourceMap),
    {ok, LineCoverage} = cover:analyse(Module, coverage, line),
    Lines = normalize_cover_lines(Module, LineCoverage),
    FullLineMetric = metric_from_lines(Lines),
    Ranges = maps:get(repository_path(Path), Changed, []),
    {EffectiveRanges, ChangedSelection} = changed_selection(Model, Ranges),
    ChangedLines = [
        Entry || Entry = {Line, _, _} <- Lines,
                 artifact_line_changed(Module, Line, Model, EffectiveRanges)
    ],
    ChangedLineMetric = metric_from_lines(ChangedLines),
    CoverageByLine = maps:from_list([
        {Line, Covered > 0} || {Line, Covered, _} <- Lines
    ]),
    Branches0 = maps:get(branches, Model),
    ok = validate_line_observability(
        Module, [{Line, Covered} || {Line, Covered, _} <- Lines], Model
    ),
    Branches = observable_branches(Module, Branches0, CoverageByLine),
    FullBranchMetric = metric_from_branches(Branches, CoverageByLine),
    ChangedBranches = [
        Branch || Branch <- Branches,
                  source_span_changed(
                      maps:get(source_first_line, Branch),
                      maps:get(source_last_line, Branch),
                      EffectiveRanges
                  )
    ],
    ChangedBranchMetric = metric_from_branches(ChangedBranches, CoverageByLine),
    #{module => atom_to_binary(Module),
      source => list_to_binary(Path),
      artifact => list_to_binary(maps:get(artifact, Model)),
      compiled_beam => list_to_binary(maps:get(compiled_beam, Model)),
      compiled_beam_sha256 => maps:get(compiled_beam_sha256, Model),
      coordinate_method => maps:get(coordinate_method, Model),
      source_region_count => length(maps:get(regions, Model)),
      changed_selection => ChangedSelection,
      full_lines => metric_map(FullLineMetric),
      full_branches => metric_map(FullBranchMetric),
      changed_lines => metric_map(ChangedLineMetric),
      changed_branches => metric_map(ChangedBranchMetric),
      full_uncovered_lines => uncovered_line_details(Module, Lines, Model),
      changed_uncovered_lines =>
          uncovered_line_details(Module, ChangedLines, Model),
      full_uncovered_branches =>
          uncovered_branch_details(Branches, CoverageByLine),
      changed_uncovered_branches =>
          uncovered_branch_details(ChangedBranches, CoverageByLine)}.

selection_json_self_test() ->
    Model = #{regions => [#{source_first_line => 2, source_last_line => 7}]},
    Cases = [
        {[], [], [], <<"none">>},
        {all, <<"all">>, [], <<"whole_module">>},
        {[{3, 4}], [#{<<"first_line">> => 3, <<"last_line">> => 4}],
         [], <<"source_spans">>},
        {[{1, 9}], [#{<<"first_line">> => 1, <<"last_line">> => 9}],
         [#{<<"first_line">> => 1, <<"last_line">> => 1},
          #{<<"first_line">> => 8, <<"last_line">> => 9}], <<"whole_module">>}
    ],
    lists:foreach(fun({Input, ExpectedInput, ExpectedUnattributed, ExpectedScope}) ->
        {_, Selection} = changed_selection(Model, Input),
        %% Exercise the real JSON boundary, not just the in-memory tuples.
        Decoded = coverage_decode_json(iolist_to_binary(json:encode(Selection))),
        ensure(maps:get(<<"input_ranges">>, Decoded) =:= ExpectedInput,
               changed_input_ranges_lost),
        ensure(maps:get(<<"unattributed_ranges">>, Decoded) =:= ExpectedUnattributed,
               unattributed_ranges_lost),
        ensure(maps:get(<<"effective_scope">>, Decoded) =:= ExpectedScope,
               changed_selection_scope_lost)
    end, Cases),
    io:put_chars("coverage selection JSON: 4 cases passed\n").

changed_selection(_Model, []) ->
    {[], #{reason => no_changed_source,
           input_ranges => [],
           effective_scope => none,
           unattributed_ranges => []}};
changed_selection(_Model, all) ->
    {all, #{reason => untracked_source_file,
            input_ranges => all,
            effective_scope => whole_module,
            unattributed_ranges => []}};
changed_selection(Model, Ranges) ->
    SourceSpans = [
        {maps:get(source_first_line, Region),
         maps:get(source_last_line, Region)}
        || Region <- maps:get(regions, Model)
    ],
    Unattributed = unattributed_ranges(Ranges, SourceSpans),
    case Unattributed of
        [] ->
            {Ranges, #{reason => attributed_source_span_overlap,
                       input_ranges => range_json(Ranges),
                       effective_scope => source_spans,
                       unattributed_ranges => []}};
        _ ->
            {all, #{reason => conservative_unattributed_source_change,
                    input_ranges => range_json(Ranges),
                    effective_scope => whole_module,
                    unattributed_ranges => range_json(Unattributed)}}
    end.

range_json(Ranges) ->
    [#{first_line => First, last_line => Last} || {First, Last} <- Ranges].

unattributed_ranges(Ranges, SourceSpans) ->
    lists:sort(lists:append([
        lists:foldl(fun subtract_source_span/2, [Range], SourceSpans)
        || Range <- Ranges
    ])).

subtract_source_span({SpanFirst, SpanLast}, Ranges) ->
    lists:append([
        subtract_source_span_from_range(Range, SpanFirst, SpanLast)
        || Range <- Ranges
    ]).

subtract_source_span_from_range({First, Last}, SpanFirst, SpanLast)
  when Last < SpanFirst; First > SpanLast ->
    [{First, Last}];
subtract_source_span_from_range({First, Last}, SpanFirst, SpanLast) ->
    Before = case First < SpanFirst of
        true -> [{First, SpanFirst - 1}];
        false -> []
    end,
    After = case Last > SpanLast of
        true -> [{SpanLast + 1, Last}];
        false -> []
    end,
    Before ++ After.

artifact_line_changed(Module, ArtifactLine, Model, Ranges) ->
    Region = source_span_for_artifact_line(Module, ArtifactLine, Model),
    source_span_changed(
        maps:get(source_first_line, Region),
        maps:get(source_last_line, Region),
        Ranges
    ).

source_span_changed(_First, _Last, all) -> true;
source_span_changed(First, Last, Ranges) ->
    lists:any(fun({ChangedFirst, ChangedLast}) ->
        First =< ChangedLast andalso Last >= ChangedFirst
    end, Ranges).

uncovered_line_numbers(Lines) ->
    lists:usort([Line || {Line, Covered, _Missed} <- Lines, Covered =:= 0]).

uncovered_line_details(Module, Lines, Model) ->
    [begin
         Region = source_span_for_artifact_line(Module, ArtifactLine, Model),
         #{artifact_line => ArtifactLine,
           source_first_line => maps:get(source_first_line, Region),
           source_last_line => maps:get(source_last_line, Region)}
     end || {ArtifactLine, Covered, _Missed} <- Lines, Covered =:= 0].

uncovered_branch_details(Branches, CoverageByLine) ->
    lists:sort([
        #{function => atom_to_binary(maps:get(function, Branch)),
          arity => maps:get(arity, Branch),
          index => maps:get(index, Branch),
          function_alternative_index => maps:get(
              function_alternative_index, Branch
          ),
          function_decision_index => maps:get(
              function_decision_index, Branch
          ),
          decision_alternative_index => maps:get(
              decision_alternative_index, Branch
          ),
          artifact_anchor_line => lists:min(branch_witness_lines(
              Branch, CoverageByLine
          )),
          artifact_lines => branch_witness_lines(Branch, CoverageByLine),
          source_first_line => maps:get(source_first_line, Branch),
          source_last_line => maps:get(source_last_line, Branch)}
        || Branch <- Branches, not branch_covered(Branch, CoverageByLine)
    ]).

branch_covered(Branch, CoverageByLine) ->
    lists:any(fun(Line) -> maps:get(Line, CoverageByLine) end,
              branch_witness_lines(Branch, CoverageByLine)).

metric_from_lines(Lines) ->
    lists:foldl(fun({_Line, Covered, _Missed}, {Hit, Total}) ->
        {Hit + case Covered > 0 of true -> 1; false -> 0 end, Total + 1}
    end, {0, 0}, Lines).

metric_from_branches(Branches, CoverageByLine) ->
    lists:foldl(fun(Branch, {Hit, Total}) ->
        Covered = branch_covered(Branch, CoverageByLine),
        {Hit + case Covered of true -> 1; false -> 0 end, Total + 1}
    end, {0, 0}, Branches).

coverage_model(Module, SourcePath0, BeamPath0) ->
    SourcePath = filename:absname(SourcePath0),
    BeamPath = filename:absname(BeamPath0),
    ensure(filelib:is_regular(BeamPath),
           {missing_coverage_model_beam, Module, relative(BeamPath)}),
    Forms = beam_abstract_forms(Module, BeamPath),
    ArtifactPath = main_artifact_path(Module, Forms),
    CoverForms = epp:interpret_file_attribute(Forms),
    InitialRegions = coverage_source_regions(
        Module, SourcePath, ArtifactPath, Forms
    ),
    SourceFunctions = source_function_spans(Module, SourcePath),
    Regions = refine_source_regions(
        Module, SourcePath, CoverForms, InitialRegions, SourceFunctions
    ),
    Functions = [coverage_function(
                     Module, SourcePath, Form, Regions, SourceFunctions
                 ) || Form = {function, _Anno, _Name, _Arity, _Clauses} <-
                          CoverForms],
    FunctionBranches = lists:append([
        function_branches(Form) || Form <- CoverForms
    ]),
    Indexed = lists:zip(
        lists:seq(1, length(FunctionBranches)), FunctionBranches
    ),
    Branches = [coverage_branch(
                    Module, SourcePath, Index, FunctionBranch,
                    Regions, SourceFunctions
                ) || {Index, FunctionBranch} <- Indexed],
    #{source => relative(SourcePath),
      source_sha256 => file_digest(SourcePath),
      artifact => relative(ArtifactPath),
      artifact_sha256 => file_digest(ArtifactPath),
      compiled_beam => relative(BeamPath),
      compiled_beam_sha256 => file_digest(BeamPath),
      coordinate_method => coverage_coordinate_method(SourcePath, ArtifactPath),
      regions => Regions,
      functions => Functions,
      branches => Branches}.

coverage_function(Module, SourcePath,
                  {function, _Anno, Name, Arity, _Clauses} = Form,
                  Regions, SourceFunctions) ->
    ArtifactLines = lists:usort([
        Line || Line <- syntax_lines(Form), Line > 0
    ]),
    ensure(ArtifactLines =/= [],
           {unlocated_compiled_function, Module, Name, Arity}),
    SourceSpan = case filename:extension(SourcePath) of
        ".erl" ->
            #{source_first_line => lists:min(ArtifactLines),
              source_last_line => lists:max(ArtifactLines)};
        ".gleam" ->
            MatchedRegions = lists:usort([
                source_region_for_artifact_line(
                    Module, Line, #{regions => Regions}
                ) || Line <- ArtifactLines
            ]),
            ensure(length(MatchedRegions) =:= 1,
                   {function_crosses_source_regions, Module, Name, Arity,
                    line_number_binary(ArtifactLines),
                    lists:sublist(MatchedRegions, 4)}),
            [Region] = MatchedRegions,
            ensure(maps:get(function, Region) =:= Name andalso
                   maps:get(arity, Region) =:= Arity,
                   {function_region_mismatch, Module, Name, Arity}),
            maps:get({Name, Arity}, SourceFunctions)
    end,
    #{function => Name,
      arity => Arity,
      artifact_lines => ArtifactLines,
      source_first_line => maps:get(source_first_line, SourceSpan),
      source_last_line => maps:get(source_last_line, SourceSpan)}.

function_branches({function, _Anno, Name, Arity, _Clauses} = Form) ->
    Decisions = branch_decisions(Form),
    Grouped = lists:append([
        [#{function => Name,
           arity => Arity,
           function_decision_index => DecisionIndex,
           decision_alternative_index => AlternativeIndex,
           artifact_lines => BranchLines}
         || {AlternativeIndex, BranchLines} <- lists:zip(
                lists:seq(1, length(Alternatives)), Alternatives
            )]
        || {DecisionIndex, Alternatives} <- lists:zip(
               lists:seq(1, length(Decisions)), Decisions
           )
    ]),
    [Branch#{function_alternative_index => Index}
     || {Index, Branch} <- lists:zip(
            lists:seq(1, length(Grouped)), Grouped
        )];
function_branches(_) -> [].

beam_abstract_forms(Module, BeamPath) ->
    case beam_lib:chunks(BeamPath, [abstract_code]) of
        {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} ->
            Forms;
        Other -> erlang:error(
            {missing_abstract_code, Module, relative(BeamPath), Other}
        )
    end.

main_artifact_path(Module, Forms) ->
    case [Path || {attribute, Anno, file, {Path, _Line}} <- Forms,
                  not erl_anno:generated(Anno)] of
        [Path | _] -> filename:absname(Path);
        [] -> erlang:error({missing_coverage_artifact_path, Module})
    end.

coverage_coordinate_method(SourcePath, ArtifactPath) ->
    case filename:extension(SourcePath) of
        ".erl" ->
            case filename:absname(SourcePath) =:= filename:absname(ArtifactPath) of
                true -> exact_erlang_source_line;
                false -> exact_erlang_source_line_from_verified_build_copy
            end;
        ".gleam" -> generated_erlang_line_with_glance_function_span
    end.

source_function_spans(Module, SourcePath) ->
    case filename:extension(SourcePath) of
        ".erl" -> #{};
        ".gleam" -> gleam_function_spans(Module, SourcePath)
    end.

gleam_function_spans(Module, SourcePath) ->
    case code:ensure_loaded(glance) of
        {module, glance} -> ok;
        Error -> erlang:error({missing_glance_coverage_parser, Module, Error})
    end,
    Source = read_file(SourcePath),
    Parsed = case glance:module(Source) of
        {ok, Value} -> Value;
        {error, Reason} ->
            erlang:error({cannot_parse_gleam_coverage_source, Module,
                          relative(SourcePath), bounded_term(Reason, 512)})
    end,
    {module, _Imports, _CustomTypes, _Aliases, _Constants, Functions} = Parsed,
    LineStarts = source_line_starts(Source),
    Pairs = [begin
        {definition, Attributes,
         {function, Span, Name, Publicity, Parameters, _Return, _Body}} =
            Definition,
        Key = {binary_to_atom(Name), length(Parameters)},
        {Key, gleam_definition_span(
                  Module, Attributes, Publicity, Span, Source, LineStarts
              )}
    end || Definition <- Functions],
    ensure(length(Pairs) =:= length(lists:usort([Key || {Key, _} <- Pairs])),
           {duplicate_gleam_coverage_functions, Module}),
    maps:from_list(Pairs).

source_line_starts(Source) ->
    [0 | [Offset + 1 || {Offset, 1} <- binary:matches(Source, <<"\n">>)]].

gleam_definition_span(Module, Attributes, Publicity,
                      {span, Start, _End} = Span, Source, LineStarts) ->
    Declaration = glance_source_span(
        Module, Span, LineStarts, byte_size(Source)
    ),
    DefinitionStart = attached_attribute_start(
        Module, Attributes, Start, Source
    ),
    External = has_gleam_attribute(<<"external">>, Attributes),
    Declaration#{
      source_first_line => source_line_for_offset(DefinitionStart, LineStarts),
      source_byte_start => DefinitionStart,
      declaration_first_line => maps:get(source_first_line, Declaration),
      declaration_byte_start => Start,
      publicity => Publicity,
      external => External,
      compiled => not External orelse Publicity =:= public}.

glance_source_span(Module, {span, Start, End}, LineStarts, SourceSize) ->
    ensure(is_integer(Start) andalso is_integer(End) andalso
           Start >= 0 andalso Start < End andalso End =< SourceSize,
           {invalid_gleam_source_span, Module, Start, End, SourceSize}),
    LastOffset = End - 1,
    #{source_first_line => source_line_for_offset(Start, LineStarts),
      source_last_line => source_line_for_offset(LastOffset, LineStarts),
      source_byte_start => Start,
      source_byte_end => End}.

attached_attribute_start(_Module, [], FunctionStart, _Source) -> FunctionStart;
attached_attribute_start(Module, Attributes, FunctionStart, Source) ->
    Prefix = binary:part(Source, 0, FunctionStart),
    Matches = case re:run(
        Prefix, <<"(?m)^[\\t ]*@([A-Za-z_][A-Za-z0-9_]*)">>,
        [global, {capture, [0, 1], index}]
    ) of
        {match, Captures} -> [
            {Offset, binary:part(Prefix, NameOffset, NameLength)}
            || [{Offset, _Length}, {NameOffset, NameLength}] <- Captures
        ];
        nomatch -> []
    end,
    AttributeCount = length(Attributes),
    ensure(length(Matches) >= AttributeCount,
           {missing_gleam_attribute_source_span, Module,
            AttributeCount, length(Matches), FunctionStart}),
    Attached = lists:nthtail(length(Matches) - AttributeCount, Matches),
    ExpectedNames = [Name || {attribute, Name, _Arguments} <- Attributes],
    ActualNames = [Name || {_Offset, Name} <- Attached],
    ensure(ActualNames =:= ExpectedNames,
           {gleam_attribute_source_mismatch, Module,
            ExpectedNames, ActualNames, FunctionStart}),
    {DefinitionStart, _Name} = hd(Attached),
    DefinitionStart.

has_gleam_attribute(Name, Attributes) ->
    lists:any(fun
        ({attribute, AttributeName, _Arguments}) -> AttributeName =:= Name;
        (_) -> false
    end, Attributes).

source_line_for_offset(Offset, LineStarts) ->
    ensure(is_integer(Offset) andalso Offset >= 0,
           {invalid_gleam_source_offset, Offset}),
    length(lists:takewhile(fun(Start) -> Start =< Offset end, LineStarts)).

refine_source_regions(Module, SourcePath, CoverForms, Regions,
                      SourceFunctions) ->
    case filename:extension(SourcePath) of
        ".erl" -> Regions;
        ".gleam" -> refine_gleam_source_regions(
            Module, CoverForms, Regions, SourceFunctions
        )
    end.

refine_gleam_source_regions(Module, CoverForms, Regions, SourceFunctions) ->
    Functions = [{Name, Arity, anno_line(Anno)}
                 || {function, Anno, Name, Arity, _Clauses} <- CoverForms],
    FunctionKeys = [{Name, Arity} || {Name, Arity, _Line} <- Functions],
    ensure(length(FunctionKeys) =:= length(lists:usort(FunctionKeys)),
           {duplicate_compiled_gleam_coverage_functions, Module}),
    ExpectedFunctionKeys = lists:sort([
        Key || {Key, Span} <- maps:to_list(SourceFunctions),
               maps:get(compiled, Span)
    ]),
    ensure(lists:sort(FunctionKeys) =:= ExpectedFunctionKeys,
           {gleam_coverage_function_set_mismatch, Module,
            #{source_count => length(ExpectedFunctionKeys),
              compiled_count => length(FunctionKeys),
              source_only => lists:sublist(
                  ExpectedFunctionKeys -- FunctionKeys, 16
              ),
              compiled_only => lists:sublist(
                  FunctionKeys -- ExpectedFunctionKeys, 16
              )}}),
    Refined = [refine_source_region(
                   Module, Region, Functions, SourceFunctions
               ) || Region <- Regions],
    ensure(length(Functions) =:= length(Refined),
           {gleam_coverage_function_region_count, Module,
            length(Functions), length(Refined)}),
    Refined.

refine_source_region(Module, Region, Functions, SourceFunctions) ->
    ArtifactFirst = maps:get(artifact_first_line, Region),
    ArtifactLast = maps:get(artifact_last_line, Region),
    Matches = [{Name, Arity} || {Name, Arity, Line} <- Functions,
                             Line >= ArtifactFirst,
                             Line =< ArtifactLast],
    ensure(length(Matches) =:= 1,
           {gleam_coverage_region_function_count, Module,
            ArtifactFirst, ArtifactLast, lists:sublist(Matches, 8)}),
    [{Name, Arity} = Key] = Matches,
    Span = case maps:find(Key, SourceFunctions) of
        {ok, Value} -> Value;
        error -> erlang:error(
            {missing_gleam_function_span, Module, Name, Arity,
             maps:size(SourceFunctions)}
        )
    end,
    DeclaredSourceFirst = maps:get(source_first_line, Region),
    ensure(DeclaredSourceFirst =:= maps:get(declaration_first_line, Span),
           {gleam_file_directive_span_mismatch, Module, Name, Arity,
            DeclaredSourceFirst, maps:get(declaration_first_line, Span)}),
    maps:merge(
        Region#{function => Name, arity => Arity,
                declared_source_first_line => DeclaredSourceFirst},
        Span
    ).

coverage_source_regions(Module, SourcePath, ArtifactPath, Forms) ->
    SourceLineCount = source_line_count(SourcePath),
    case filename:extension(SourcePath) of
        ".erl" ->
            ArtifactLineCount = source_line_count(ArtifactPath),
            ensure(read_file(SourcePath) =:= read_file(ArtifactPath),
                   {erlang_coverage_artifact_content_mismatch, Module,
                    relative(SourcePath), file_digest(SourcePath),
                    relative(ArtifactPath), file_digest(ArtifactPath)}),
            ensure(SourceLineCount =:= ArtifactLineCount,
                   {erlang_coverage_artifact_line_count_mismatch, Module,
                    SourceLineCount, ArtifactLineCount}),
            [#{artifact_first_line => 1,
               artifact_last_line => ArtifactLineCount,
               source_first_line => 1,
               source_last_line => SourceLineCount}];
        ".gleam" ->
            ArtifactLineCount = source_line_count(ArtifactPath),
            ExpectedSource = generated_source_name(SourcePath),
            AllGleamDirectives = generated_file_directives(ArtifactPath),
            Directives = [#{artifact_first_line => ArtifactLine + 1,
                            source_first_line => SourceLine}
                          || {ArtifactLine, Path, SourceLine} <-
                                 AllGleamDirectives,
                             repository_path(Path) =:= repository_path(ExpectedSource)],
            ExpectedAbstractDirectives = expected_abstract_directives(
                AllGleamDirectives
            ),
            AbstractDirectives = [{anno_line(Anno), Path, Line}
                || {attribute, Anno, file, {Path, Line}} <- Forms,
                   erl_anno:generated(Anno)],
            case {AllGleamDirectives, AbstractDirectives,
                  has_function_forms(Forms)} of
                {[], [], false} ->
                    [];
                _ ->
                    ensure(AllGleamDirectives =/= [] andalso
                           length(AllGleamDirectives) =:=
                               length(Directives) andalso
                           ExpectedAbstractDirectives =:= AbstractDirectives,
                           {unexpected_gleam_coverage_source, Module,
                            ExpectedSource,
                            #{artifact_directives =>
                                  lists:sublist(AllGleamDirectives, 8),
                              abstract_directives =>
                                  lists:sublist(AbstractDirectives, 8)}}),
                    coverage_regions_from_starts(
                        Module, Directives, SourceLineCount,
                        ArtifactLineCount
                    )
            end
    end.

expected_abstract_directives(Directives) ->
    {Expected, _Physical, _Source} = lists:foldl(
        fun({PhysicalLine, Path, SourceLine}, {Acc, PreviousPhysical,
                                              PreviousSource}) ->
            LogicalAnnotation = PhysicalLine + PreviousSource -
                PreviousPhysical,
            {[{LogicalAnnotation, Path, SourceLine} | Acc],
             PhysicalLine, SourceLine}
        end,
        {[], 1, 1},
        Directives
    ),
    lists:reverse(Expected).

has_function_forms(Forms) ->
    lists:any(fun
        ({function, _Anno, _Name, _Arity, _Clauses}) -> true;
        (_) -> false
    end, Forms).

generated_file_directives(ArtifactPath) ->
    generated_file_directives_from_binary(read_file(ArtifactPath)).

generated_file_directives_from_binary(Bytes) ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    lists:reverse(generated_file_directives(Lines, 1, [])).

generated_file_directives([Line | Rest], Number, Acc) ->
    Updated = case Line of
        <<"-file(", _/binary>> ->
            %% The compiler emits an Erlang string literal. Reading its raw
            %% regex capture mistakes Windows' escaped separators for actual
            %% path bytes and breaks comparison with the BEAM abstract form.
            {ok, Tokens, _} = erl_scan:string(binary_to_list(Line)),
            {ok, {attribute, _, file, {Path, SourceLine}}} = erl_parse:parse_form(Tokens),
            ensure(is_list(Path) andalso is_integer(SourceLine) andalso SourceLine > 0,
                invalid_generated_source_directive),
            [{Number, Path, SourceLine} | Acc];
        _ -> Acc
    end,
    generated_file_directives(Rest, Number + 1, Updated);
generated_file_directives([], _Number, Acc) -> Acc.

generated_source_name(SourcePath) ->
    filename:join(["src" | tail_after_tree(filename:split(SourcePath), "src")]).

coverage_regions_from_starts(Module, Starts, SourceLineCount,
                             ArtifactLineCount) ->
    ensure(Starts =/= [], {missing_gleam_coverage_regions, Module}),
    coverage_regions_from_starts(
        Module, Starts, SourceLineCount, ArtifactLineCount, []
    ).

coverage_regions_from_starts(Module, [Current, Next | Rest], SourceLineCount,
                             ArtifactLineCount, Acc) ->
    ArtifactFirst = maps:get(artifact_first_line, Current),
    SourceFirst = maps:get(source_first_line, Current),
    NextArtifactFirst = maps:get(artifact_first_line, Next),
    NextSourceFirst = maps:get(source_first_line, Next),
    ensure(ArtifactFirst > 0 andalso ArtifactFirst < NextArtifactFirst andalso
           SourceFirst > 0 andalso SourceFirst =< SourceLineCount andalso
           NextSourceFirst > 0 andalso NextSourceFirst =< SourceLineCount,
           {non_monotonic_gleam_coverage_regions, Module,
            ArtifactFirst, NextArtifactFirst, SourceFirst, NextSourceFirst}),
    Region = Current#{artifact_last_line => NextArtifactFirst - 1,
                      source_last_line => SourceLineCount},
    coverage_regions_from_starts(
        Module, [Next | Rest], SourceLineCount, ArtifactLineCount,
        [Region | Acc]
    );
coverage_regions_from_starts(Module, [Current], SourceLineCount,
                             ArtifactLineCount, Acc) ->
    ArtifactFirst = maps:get(artifact_first_line, Current),
    SourceFirst = maps:get(source_first_line, Current),
    ensure(ArtifactFirst > 0 andalso ArtifactFirst =< ArtifactLineCount andalso
           SourceFirst > 0 andalso SourceFirst =< SourceLineCount,
           {invalid_final_gleam_coverage_region, Module,
            ArtifactFirst, ArtifactLineCount, SourceFirst, SourceLineCount}),
    lists:reverse([
        Current#{artifact_last_line => ArtifactLineCount,
                 source_last_line => SourceLineCount}
        | Acc
    ]).

coverage_branch(Module, SourcePath, Index, FunctionBranch, Regions,
                SourceFunctions) ->
    Name = maps:get(function, FunctionBranch),
    Arity = maps:get(arity, FunctionBranch),
    ArtifactLines = lists:usort(maps:get(artifact_lines, FunctionBranch)),
    MatchedRegions = lists:usort([
        source_region_for_artifact_line(
            Module, Line, #{regions => Regions}
        ) || Line <- ArtifactLines
    ]),
    ensure(length(MatchedRegions) =:= 1,
           {branch_crosses_source_regions, Module, Index,
            line_number_binary(ArtifactLines),
            lists:sublist(MatchedRegions, 4)}),
    [Region] = MatchedRegions,
    SourceSpan = case filename:extension(SourcePath) of
        ".erl" ->
            #{source_first_line => lists:min(ArtifactLines),
              source_last_line => lists:max(ArtifactLines)};
        ".gleam" ->
            ensure(maps:get(function, Region) =:= Name andalso
                   maps:get(arity, Region) =:= Arity,
                   {branch_function_region_mismatch, Module, Name, Arity,
                    maps:get(function, Region), maps:get(arity, Region)}),
            maps:get({Name, Arity}, SourceFunctions)
    end,
    #{index => Index,
      function => Name,
      arity => Arity,
      function_alternative_index => maps:get(
          function_alternative_index, FunctionBranch
      ),
      function_decision_index => maps:get(
          function_decision_index, FunctionBranch
      ),
      decision_alternative_index => maps:get(
          decision_alternative_index, FunctionBranch
      ),
      artifact_lines => ArtifactLines,
      source_first_line => maps:get(source_first_line, SourceSpan),
      source_last_line => maps:get(source_last_line, SourceSpan)}.

source_region_for_artifact_line(Module, ArtifactLine, Model) ->
    Regions = maps:get(regions, Model),
    Matches = [Region || Region <- Regions,
        ArtifactLine >= maps:get(artifact_first_line, Region),
        ArtifactLine =< maps:get(artifact_last_line, Region)],
    case Matches of
        [Region] -> Region;
        _ -> erlang:error(
            {unmapped_coverage_artifact_line, Module, ArtifactLine,
             lists:sublist(Regions, 8)}
        )
    end.

source_span_for_artifact_line(Module, ArtifactLine, Model) ->
    Region = source_region_for_artifact_line(Module, ArtifactLine, Model),
    case maps:get(coordinate_method, Model) of
        exact_erlang_source_line ->
            Region#{source_first_line => ArtifactLine,
                    source_last_line => ArtifactLine};
        exact_erlang_source_line_from_verified_build_copy ->
            Region#{source_first_line => ArtifactLine,
                    source_last_line => ArtifactLine};
        generated_erlang_line_with_glance_function_span -> Region
    end.

source_line_count(Path) ->
    Bytes = read_file(Path),
    Parts = binary:split(Bytes, <<"\n">>, [global]),
    case Parts of
        [<<>>] -> 1;
        _ ->
            case lists:last(Parts) of
                <<>> -> max(1, length(Parts) - 1);
                _ -> length(Parts)
            end
    end.

branch_decisions({function, _Anno, _Name, _Arity, Clauses}) ->
    own_clause_decision(Clauses) ++ recurse_clause_decisions(Clauses);
branch_decisions({'case', _Anno, Expression, Clauses}) ->
    branch_decisions(Expression) ++ own_clause_decision(Clauses) ++
        recurse_clause_decisions(Clauses);
branch_decisions({'if', _Anno, Clauses}) ->
    own_clause_decision(Clauses) ++ recurse_clause_decisions(Clauses);
branch_decisions({'receive', _Anno, Clauses}) ->
    own_clause_decision(Clauses) ++ recurse_clause_decisions(Clauses);
branch_decisions({'receive', _Anno, Clauses, Timeout, Body}) ->
    own_clause_decision(Clauses) ++ recurse_clause_decisions(Clauses) ++
        branch_decisions(Timeout) ++ branch_decisions(Body);
branch_decisions({'try', _Anno, Expressions, Clauses, CatchClauses, After}) ->
    branch_decisions(Expressions) ++ own_clause_decision(Clauses) ++
        recurse_clause_decisions(Clauses) ++
        own_clause_decision(CatchClauses) ++
        recurse_clause_decisions(CatchClauses) ++ branch_decisions(After);
branch_decisions({'fun', _Anno, {clauses, Clauses}}) ->
    own_clause_decision(Clauses) ++ recurse_clause_decisions(Clauses);
branch_decisions(Value) when is_tuple(Value) ->
    branch_decisions(tuple_to_list(Value));
branch_decisions(Values) when is_list(Values) ->
    lists:append([branch_decisions(Value) || Value <- Values]);
branch_decisions(_) -> [].

own_clause_decision(Clauses) when length(Clauses) > 1 ->
    Alternatives = [clause_lines(Clause) || Clause <- Clauses],
    ensure(lists:all(fun(Lines) -> Lines =/= [] end, Alternatives),
           {unlocated_compiled_clause_alternative,
            length(Clauses), Alternatives}),
    [Alternatives];
own_clause_decision(_Clauses) -> [].

recurse_clause_decisions(Clauses) ->
    lists:append([case Clause of
        {clause, _Anno, Patterns, Guards, Body} ->
            branch_decisions(Patterns) ++ branch_decisions(Guards) ++
                branch_decisions(Body)
    end || Clause <- Clauses]).

clause_lines({clause, Anno, _Patterns, _Guards, Body}) ->
    lists:usort([Line || Line <- [anno_line(Anno) | syntax_lines(Body)],
                         Line > 0]).

%% A bit-syntax element's fifth position holds type specifiers, not code: a
%% size unit is spelled {unit, Integer}, whose shape is indistinguishable from
%% an annotated node and whose integer would otherwise be read as a line number.
%% Only the annotation, the value, and the size carry positions.
syntax_lines({bin_element, Anno, Value, Size, _TypeSpecifiers}) ->
    [anno_line(Anno) | syntax_lines(Value) ++ syntax_lines(Size)];
syntax_lines(Value) when is_tuple(Value) ->
    Own = case tuple_size(Value) >= 2 andalso is_atom(element(1, Value)) of
              true -> [anno_line(element(2, Value))];
              false -> []
          end,
    Own ++ syntax_lines(tuple_to_list(Value));
syntax_lines(Values) when is_list(Values) ->
    lists:append([syntax_lines(Value) || Value <- Values]);
syntax_lines(_) -> [].

anno_line(Anno) ->
    try erl_anno:line(Anno) of Line when is_integer(Line) -> Line;
                               _ -> 0
    catch _:_ -> 0 end.

production_sources(SourceRoot) ->
    Root = filename:join(SourceRoot, "src"),
    lists:sort(filelib:fold_files(
        Root, ".*\\.(gleam|erl)$", true,
        fun(Path, Acc) -> [filename:absname(Path) | Acc] end, [])).

source_map() ->
    Roots = [".", "packages/http3", "packages/quic_core"],
    Sources = lists:append([production_sources(Root) || Root <- Roots]),
    Pairs = [{module_for_source(Path), relative(Path)} || Path <- Sources],
    Modules = [Module || {Module, _Path} <- Pairs],
    ensure(length(Modules) =:= length(lists:usort(Modules)),
           {duplicate_cross_package_production_module,
            duplicate_values(Modules)}),
    maps:from_list(Pairs).

duplicate_values(Values) ->
    lists:usort([Value || Value <- Values,
                         length([Match || Match <- Values,
                                          Match =:= Value]) > 1]).

module_for_source(Path) ->
    case filename:extension(Path) of
        ".gleam" -> module_for_tree_source(Path, "src");
        ".erl" ->
            {ok, Bytes} = file:read_file(Path),
            {match, [Name]} = re:run(Bytes, <<"(?m)^-module\\(([^)]+)\\)\\.">>,
                                     [{capture, [1], binary}]),
            binary_to_atom(Name)
    end.

beam_path(Ebin, Module) ->
    filename:join(filename:absname(Ebin), atom_to_list(Module) ++ ".beam").

production_beam_path(Module, SourcePath) ->
    RelativeSource = filename:split(relative(filename:absname(SourcePath))),
    {PackageRoot, PackageName} = case RelativeSource of
        ["src" | _] -> {".", "http"};
        ["packages", "http3", "src" | _] ->
            {"packages/http3", "http3"};
        ["packages", "quic_core", "src" | _] ->
            {"packages/quic_core", "quic_core"};
        _ -> erlang:error(
            {unknown_coverage_package_source, Module, RelativeSource}
        )
    end,
    beam_path(
        filename:join([PackageRoot, "build", "dev", "erlang",
                       PackageName, "ebin"]),
        Module
    ).

module_for_tree_source(Path, Tree) ->
    Tail = tail_after_tree(filename:split(Path), Tree),
    StemParts = lists:sublist(Tail, length(Tail) - 1) ++
        [filename:rootname(lists:last(Tail))],
    list_to_atom(lists:flatten(lists:join($@, StemParts))).

tail_after_tree([Tree | Rest], Tree) when Rest =/= [] -> Rest;
tail_after_tree([_ | Rest], Tree) -> tail_after_tree(Rest, Tree);
tail_after_tree([], Tree) -> erlang:error({source_outside_tree, Tree}).

test_modules(Ebin, SourceRoot) ->
    %% Missing source-discovered beams invalidate coverage; silently filtering
    %% them would shrink the test inventory into an apparently complete run.
    Names = suite_source_modules(filename:join(SourceRoot, "test")),
    [binary_to_atom(Name) || Name <- Names, suite_beam_units(Ebin, Name) =/= []].

eunit_test_exports(Ebin, Module) ->
    Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    [Export || Export <- beam_exports(Beam, Module), is_eunit_test_export(Export)].

beam_exports(Beam, Module) ->
    case beam_lib:chunks(Beam, [exports]) of
        {ok, {Module, [{exports, Exports}]}} -> Exports;
        Error -> erlang:error({cannot_read_test_exports, Beam, Module, Error})
    end.

has_eunit_test_export(Exports) ->
    lists:any(fun is_eunit_test_export/1, Exports).

is_eunit_test_export({Name, 0}) ->
    Text = atom_to_list(Name),
    lists:suffix("_test", Text) orelse lists:suffix("_test_", Text);
is_eunit_test_export(_) -> false.

add_all_code_paths() ->
    Roots = ["build/dev/erlang", "packages/http3/build/dev/erlang",
             "packages/quic_core/build/dev/erlang"],
    Paths = lists:usort(lists:append([
        filelib:wildcard(filename:join(Root, "*/ebin")) || Root <- Roots
    ])),
    lists:foreach(fun(Path) -> true = code:add_patha(filename:absname(Path)) end,
                  Paths).

add_package_code_paths(Ebin) ->
    %% Use only the selected package's dependency build. Mixing sibling build
    %% trees can execute stale dependency BEAMs despite a fresh target stamp.
    Build = filename:dirname(filename:dirname(filename:absname(Ebin))),
    Paths = lists:sort(filelib:wildcard(filename:join(Build, "*/ebin"))),
    ensure(Paths =/= [], missing_coverage_package_dependencies),
    lists:foreach(fun(Path) -> true = code:add_patha(Path) end, Paths),
    true = code:add_patha(filename:absname(Ebin)),
    ok.

changed_lines() ->
    Diff = unicode:characters_to_list(git_output([
        "-c", "core.quotePath=false", "diff", "HEAD", "--unified=0",
        "--no-color", "--", "*.gleam", "*.erl"
    ])),
    Tracked = parse_diff(string:split(Diff, "\n", all), undefined, #{}),
    OtherBytes = git_output([
        "ls-files", "--others", "--exclude-standard", "-z"
    ]),
    Others = [binary_to_list(Path)
              || Path <- binary:split(OtherBytes, <<0>>, [global]),
                 Path =/= <<>>,
                 filename:extension(binary_to_list(Path)) =:= ".gleam" orelse
                 filename:extension(binary_to_list(Path)) =:= ".erl"],
    lists:foldl(fun(Path, Acc) ->
        maps:put(repository_path(Path), all, Acc)
    end, Tracked, Others).

parse_diff([], _Path, Acc) -> Acc;
parse_diff([Line | Rest], Path, Acc) ->
    case string:prefix(Line, "+++ ") of
        nomatch ->
            case {Path, re:run(Line,
                    "^@@ [^+]*\\+([0-9]+)(?:,([0-9]+))? @@",
                    [{capture, [1, 2], list}])} of
                {undefined, _} -> parse_diff(Rest, Path, Acc);
                {_, nomatch} -> parse_diff(Rest, Path, Acc);
                {Current, {match, [StartText, CountText]}} ->
                    Start = list_to_integer(StartText),
                    Count = case CountText of [] -> 1;
                                              _ -> list_to_integer(CountText) end,
                    Key = repository_path(Current),
                    Ranges = maps:get(Key, Acc, []),
                    Updated = case Count of
                                  0 -> [{max(1, Start), max(1, Start)} | Ranges];
                                  _ -> [{Start, Start + Count - 1} | Ranges]
                              end,
                    parse_diff(Rest, Path, maps:put(Key, Updated, Acc))
            end;
        "/dev/null" ->
            parse_diff(Rest, undefined, Acc);
        Target ->
            case string:prefix(Target, "b/") of
                nomatch -> erlang:error({unexpected_git_diff_target, Target});
                Current -> parse_diff(Rest, Current, Acc)
            end
    end.

repository_path(Path) when is_binary(Path) ->
    repository_path(binary_to_list(Path));
repository_path(Path) when is_list(Path) ->
    unicode:characters_to_binary(string:replace(Path, "\\", "/", all)).

git_output(Arguments) ->
    Executable = case os:find_executable("git") of
        false -> erlang:error(missing_git_for_coverage_diff);
        GitExecutable -> GitExecutable
    end,
    %% These two read-only commands must not invoke configured pagers, external
    %% diff/textconv drivers, or filesystem-monitor helpers. Ambient Git path
    %% overrides must not silently select another repository.
    {Kind, SafeArguments} = case Arguments of
        ["-c", "core.quotePath=false", "diff", "HEAD", "--unified=0",
         "--no-color", "--", "*.gleam", "*.erl"] ->
            {diff, ["-c", "core.quotePath=false", "diff", "--no-ext-diff",
                    "--no-textconv", "HEAD", "--unified=0", "--no-color",
                    "--", "*.gleam", "*.erl"]};
        ["ls-files", "--others", "--exclude-standard", "-z"] ->
            {untracked, Arguments};
        _ -> erlang:error(unsupported_coverage_git_operation)
    end,
    Unset = [{hd(string:split(Entry, "=")), false} || Entry <- os:getenv(),
        lists:prefix("GIT_", Entry),
        not lists:prefix("GIT_CONFIG_NOSYSTEM=", Entry),
        not lists:prefix("GIT_CONFIG_GLOBAL=", Entry),
        not lists:prefix("GIT_TERMINAL_PROMPT=", Entry)],
    Null = case os:type() of {win32, _} -> "NUL"; _ -> "/dev/null" end,
    Environment = Unset ++ [{"GIT_CONFIG_NOSYSTEM", "1"},
        {"GIT_CONFIG_GLOBAL", Null}, {"GIT_TERMINAL_PROMPT", "0"},
        {"LC_ALL", "C"}],
    Prefix = ["--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"],
    Result = command_capture(Executable, Prefix ++ SafeArguments,
                             filename:absname("."), 60000, 16777216, Environment),
    Proof = case Result of {ok, _, P} -> P; {error, P} -> P end,
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Path = filename:join(?OUTPUT, "git-" ++ binary_to_list(Nonce) ++ ".process.json"),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, json:encode(#{schema => 1, nonce => Nonce,
        operation => Kind, process => Proof}), [exclusive]),
    case Result of
        {ok, Bytes, _} -> Bytes;
        {error, _} -> erlang:error({git_coverage_diff_failed, Proof})
    end.

relative(Path) ->
    RootParts = filename:split(filename:absname(".")),
    PathParts = filename:split(filename:absname(Path)),
    case drop_prefix(RootParts, PathParts) of
        [] -> ".";
        RelativeParts -> filename:join(RelativeParts)
    end.

drop_prefix([Part | Root], [Part | Path]) -> drop_prefix(Root, Path);
drop_prefix([], Path) -> Path;
drop_prefix(_, Path) -> Path.

sum_metric(Reports, Key) ->
    lists:foldl(fun(Report, {Hit, Total}) ->
        Metric = maps:get(Key, Report),
        {Hit + maps:get(covered, Metric), Total + maps:get(total, Metric)}
    end, {0, 0}, Reports).

metric_map({Covered, Total}) -> #{covered => Covered, total => Total}.

metric_json(Metrics) ->
    maps:map(fun(_Key, Metric) ->
        Map = metric_map(Metric),
        Map#{basis_points => basis_points(Metric)}
    end, Metrics).

metric_total({_Covered, Total}) -> Total.

basis_points({_Covered, 0}) -> 0;
basis_points({Covered, Total}) -> Covered * 10000 div Total.

coverage_status(Lines, Branches, Thresholds) ->
    Passed = metric_total(Lines) > 0 andalso metric_total(Branches) > 0
        andalso basis_points(Lines) >= maps:get(lines, Thresholds)
        andalso basis_points(Branches) >= maps:get(branches, Thresholds),
    case Passed of true -> <<"Ready">>; false -> <<"Blocked">> end.

percentage(Metric) ->
    BasisPoints = basis_points(Metric),
    lists:flatten(io_lib:format("~B.~2.10.0B%",
                                [BasisPoints div 100, BasisPoints rem 100])).

coverage_source_paths() ->
    Policy = coverage_policy(),
    Configs = [policy_path(Path) || Path <- capture_field(Policy, source_files)],
    Trees = [policy_path(Path) || Path <- capture_field(Policy, source_trees)],
    lists:foreach(fun(Tree) ->
        ensure(filelib:is_dir(Tree), {missing_coverage_source_tree, Tree})
    end, Trees),
    TreePaths = lists:append([
        filelib:fold_files(Tree, ".*", true,
                           fun(Path, Acc) -> [Path | Acc] end, [])
        || Tree <- Trees
    ]),
    Paths = lists:usort(Configs ++ TreePaths),
    ensure(Paths =/= [], missing_coverage_sources),
    Paths.

coverage_policy() ->
    Policy = json:decode(read_file(?POLICY)),
    ensure(capture_field(Policy, schema) =:= 2, invalid_coverage_policy_schema),
    Methodology = capture_field(Policy, coordinate_methodology),
    ensure(Methodology =:= expected_coordinate_methodology(),
           {invalid_coverage_coordinate_methodology, Methodology}),
    Capture = capture_field(Policy, capture),
    Minimum = capture_field(Capture, minimum_repetitions),
    Maximum = capture_field(Capture, maximum_repetitions),
    Quiescent = capture_field(Capture, required_quiescent_repetitions),
    ensure(is_integer(Minimum) andalso is_integer(Maximum) andalso
           is_integer(Quiescent) andalso Minimum >= 2 andalso
           Minimum =< Maximum andalso Maximum =< 100 andalso
           Quiescent >= 1 andalso Quiescent =< Minimum,
           {invalid_coverage_capture_policy, Minimum, Maximum, Quiescent}),
    Thresholds = capture_field(Policy, thresholds_basis_points),
    lists:foreach(fun(Mode) ->
        MetricThresholds = capture_field(Thresholds, Mode),
        lists:foreach(fun(Metric) ->
            Value = capture_field(MetricThresholds, Metric),
            ensure(is_integer(Value) andalso Value >= 0 andalso Value =< 10000,
                   {invalid_coverage_threshold, Mode, Metric, Value})
        end, [lines, branches])
    end, [changed, full]),
    lists:foreach(fun(Key) ->
        Values = capture_field(Policy, Key),
        ensure(Values =/= [] andalso length(Values) =:=
                   length(lists:usort(Values)),
               {invalid_coverage_source_policy, Key}),
        lists:foreach(fun policy_path/1, Values)
    end, [source_files, source_trees]),
    Policy.

current_coordinate_methodology() ->
    capture_field(coverage_policy(), coordinate_methodology).

expected_coordinate_methodology() ->
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

current_capture_policy() ->
    Capture = capture_field(coverage_policy(), capture),
    #{minimum_repetitions => capture_field(Capture, minimum_repetitions),
      maximum_repetitions => capture_field(Capture, maximum_repetitions),
      required_quiescent_repetitions =>
          capture_field(Capture, required_quiescent_repetitions),
      runtime_settle_max_milliseconds =>
          capture_field(Capture, runtime_settle_max_milliseconds),
      runtime_settle_interval_milliseconds =>
          capture_field(Capture, runtime_settle_interval_milliseconds),
      runtime_settle_quiet_samples =>
          capture_field(Capture, runtime_settle_quiet_samples)}.

coverage_thresholds(Mode) ->
    Thresholds = capture_field(
        capture_field(coverage_policy(), thresholds_basis_points),
        list_to_atom(Mode)
    ),
    #{lines => capture_field(Thresholds, lines),
      branches => capture_field(Thresholds, branches)}.

policy_path(Value) when is_binary(Value), byte_size(Value) > 0 ->
    Path = binary_to_list(Value),
    Parts = filename:split(Path),
    ensure(filename:pathtype(Path) =:= relative andalso
           not lists:member("..", Parts),
           {unsafe_coverage_policy_path, Value}),
    Path;
policy_path(Value) -> erlang:error({invalid_coverage_policy_path, Value}).

digest_paths(Paths) ->
    lists:foreach(fun(Path) ->
        ensure(filelib:is_regular(Path), {missing_digest_input, Path})
    end, Paths),
    Material = [[unicode:characters_to_binary(relative(filename:absname(Path))),
                 0, read_file(Path), 0]
                || Path <- lists:sort(Paths)],
    hex(crypto:hash(sha256, Material)).

file_digest(Path) -> hex(crypto:hash(sha256, read_file(Path))).

read_file(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Bytes) -> binary:encode_hex(Bytes, lowercase).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
