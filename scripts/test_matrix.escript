#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("suite_evidence.hrl").
-include("suite_discovery.hrl").
-include("credential_evidence.hrl").
-include("json_reader_tests.hrl").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "qualification failed: ~p~n", [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["hostile"]) -> fault_guard("hostile-peer", fun hostile/0);
run(["stability"]) -> fault_guard("stability", fun stability/0);
run(["stability", Target]) -> stability_diagnostic(Target, undefined);
run(["stability", Target, Repetitions]) ->
    stability_diagnostic(Target, Repetitions);
run(["credential-local"]) -> credential_local();
run(["credential-aggregate"]) -> credential_aggregate();
run(["credential-artifact-aggregate"]) -> credential_artifact_aggregate();
run(_) -> erlang:error({usage,
                        "--self-test | hostile | stability [target [runs]] | "
                        "credential-local | credential-aggregate | credential-artifact-aggregate"}).

hostile() ->
    Matrix = hostile_matrix(),
    Path = "build/fault/hostile-peer.json",
    Identity = evidence_begin(Path),
    fresh_verify_many(["http", "http3", "core"]),
    Builds = matrix_builds(),
    Groups = [hostile_group(Package)
              || Package <- maps:get(<<"packages">>, Matrix)],
    Families = maps:get(<<"families">>, Matrix),
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    Configured = lists:sum([group_test_count(Group) || Group <- Groups]),
    Source = source_digest(),
    case run_hostile_groups(Groups, TailLimit, [], 0) of
        {ok, Results, Completed} ->
            Report = #{schema => 1,
                       status => <<"Ready">>,
                       source_sha256 => Source,
                       families => Families,
                       configured_packages => length(Groups),
                       configured_tests => Configured,
                       completed_tests => Completed,
                       completed_cases => lists:sum([maps:get(completed_cases, R) || R <- Results]),
                       package_runs => Results},
            matrix_complete(Path, Report, Identity, Builds, <<"hostile">>),
            io:format("hostile-peer matrix: ~B families, ~B tests~n",
                      [length(Families), Completed]),
            ok;
        {error, Results, Completed, Failure} ->
            Report = #{schema => 1,
                       status => <<"Failed">>,
                       source_sha256 => Source,
                       families => Families,
                       configured_packages => length(Groups),
                       configured_tests => Configured,
                       completed_tests => Completed,
                       completed_cases => lists:sum([maps:get(completed_cases, R) || R <- Results]),
                       package_runs => Results,
                       first_failure => Failure},
            write_report(Path, matrix_metadata(Report, Identity, Builds, <<"hostile">>)),
            erlang:error({hostile_test_failed,
                          maps:get(package, Failure),
                          maps:get(module, Failure),
                          maps:get(exit_status, Failure),
                          Path})
    end.

hostile_matrix() ->
    Manifest = json:decode(read("qualification.json")),
    Matrix = maps:get(<<"hostile_matrix">>, Manifest),
    ensure(maps:get(<<"schema">>, Matrix) =:= 1,
           invalid_hostile_matrix_schema),
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    ensure(is_integer(TailLimit) andalso TailLimit >= 1024
           andalso TailLimit =< 65536,
           {invalid_hostile_output_tail_bytes, TailLimit}),
    Families = maps:get(<<"families">>, Matrix),
    ensure(is_list(Families) andalso Families =/= [],
           empty_hostile_families),
    ensure(length(Families) =:= length(lists:usort(Families)),
           duplicate_hostile_family),
    Packages = maps:get(<<"packages">>, Matrix),
    ensure(is_list(Packages) andalso Packages =/= [],
           empty_hostile_packages),
    Names = [maps:get(<<"name">>, Package) || Package <- Packages],
    ensure(length(Names) =:= length(lists:usort(Names)),
           duplicate_hostile_package),
    lists:foreach(fun audit_hostile_package/1, Packages),
    Matrix.

audit_hostile_package(Package) ->
    lists:foreach(
      fun(Key) ->
          Value = maps:get(Key, Package),
          ensure(is_binary(Value) andalso byte_size(Value) > 0,
                 {invalid_hostile_package_field, Key})
      end,
      [<<"name">>, <<"directory">>, <<"ebin">>, <<"tests">>]),
    Modules = maps:get(<<"modules">>, Package),
    ensure(is_list(Modules) andalso Modules =/= [],
           {empty_hostile_modules, maps:get(<<"name">>, Package)}),
    ensure(length(Modules) =:= length(lists:usort(Modules)),
           {duplicate_hostile_module, maps:get(<<"name">>, Package)}),
    lists:foreach(
      fun(Module) ->
          ensure(is_binary(Module) andalso byte_size(Module) > 0,
                 {invalid_hostile_module, Module})
      end,
      Modules).

hostile_group(Package) ->
    {maps:get(<<"name">>, Package),
     binary_to_list(maps:get(<<"directory">>, Package)),
     binary_to_list(maps:get(<<"ebin">>, Package)),
     [binary_to_atom(Module) || Module <- maps:get(<<"modules">>, Package)]}.

group_test_count({_Name, _Directory, Ebin0, Modules}) ->
    Ebin = filename:absname(Ebin0),
    lists:foreach(fun(Module) -> ensure_test_beam(Ebin, Module) end, Modules),
    lists:sum([beam_test_count(Ebin, Module) || Module <- Modules]).

run_hostile_groups([], _TailLimit, Results, Completed) ->
    {ok, lists:reverse(Results), Completed};
run_hostile_groups([Group | Rest], TailLimit, Results, Completed0) ->
    case run_hostile_group(Group, TailLimit) of
        {ok, Result} ->
            Completed = Completed0 + maps:get(completed_tests, Result),
            run_hostile_groups(Rest, TailLimit, [Result | Results], Completed);
        {error, Result, Failure} ->
            Completed = Completed0 + maps:get(completed_tests, Result),
            {error, lists:reverse([Result | Results]), Completed, Failure}
    end.

run_hostile_group({Name, Directory0, Ebin0, Modules}, TailLimit) ->
    Directory = filename:absname(Directory0),
    Ebin = filename:absname(Ebin0),
    lists:foreach(fun(Module) -> ensure_test_beam(Ebin, Module) end, Modules),
    TestCount = lists:sum([beam_test_count(Ebin, Module) || Module <- Modules]),
    ensure(TestCount > 0, {no_tests_in_group, Name}),
    run_hostile_modules(
        Name, Directory, Ebin, Modules, Modules, TestCount, TailLimit, 0, 0, []).

run_hostile_modules(
    Name, _Directory, _Ebin, AllModules, [], TestCount, _TailLimit,
    CompletedModules, CompletedTests, Executions
) ->
    {ok, (hostile_group_result(
        Name, AllModules, <<"Ready">>, TestCount,
        CompletedModules, CompletedTests))#{executions => lists:reverse(Executions),
          completed_cases => lists:sum([maps:get(completed_tests, R) || R <- Executions])}};
run_hostile_modules(
    Name, Directory, Ebin, AllModules, [Module | Rest], TestCount, TailLimit,
    CompletedModules, CompletedTests, Executions
) ->
    ModuleTests = beam_test_count(Ebin, Module),
    {Status, Output} = run_eunit_module(Directory, Ebin, Module),
    case Status of
        0 ->
            run_hostile_modules(
                Name, Directory, Ebin, AllModules, Rest, TestCount, TailLimit,
                CompletedModules + 1, CompletedTests + ModuleTests,
                [(bounded_output_evidence(Output, TailLimit))#{module => atom_to_binary(Module)} | Executions]);
        _ ->
            Result = hostile_group_result(
                Name, AllModules, <<"Failed">>, TestCount,
                CompletedModules, CompletedTests),
            Failure = hostile_failure(
                Name, Module, Status, Output, TailLimit),
            Runs = lists:reverse([(bounded_output_evidence(Output, TailLimit))#{module => atom_to_binary(Module)} | Executions]),
            {error, Result#{executions => Runs,
                completed_cases => lists:sum([maps:get(completed_tests, R, 0) || R <- Runs])}, Failure}
    end.

hostile_group_result(
    Name, Modules, Status, TestCount, CompletedModules, CompletedTests
) ->
    #{package => Name,
      status => Status,
      tests => TestCount,
      configured_modules => length(Modules),
      completed_modules => CompletedModules,
      completed_tests => CompletedTests,
      modules => [atom_to_binary(Module) || Module <- Modules]}.

hostile_failure(Name, Module, Status, Output, TailLimit) ->
    maps:merge(
        #{package => Name,
          module => atom_to_binary(Module),
          exit_status => Status,
          shareable => true},
        bounded_output_evidence(Output, TailLimit)).

stability() ->
    Matrix = stability_matrix(),
    Path = "build/fault/stability.json",
    Identity = evidence_begin(Path),
    fresh_verify_many(["http", "http3", "core"]),
    Builds = matrix_builds(),
    Manifest = json:decode(read("qualification.json")),
    Packages = maps:get(<<"packages">>, maps:get(<<"hostile_matrix">>, Manifest)),
    Targets = [stability_target(Target, Packages)
               || Target <- maps:get(<<"targets">>, Matrix)],
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    Source = source_digest(),
    Configured = lists:sum([maps:get(repetitions, Target) || Target <- Targets]),
    case run_stability_targets(Targets, TailLimit, [], 0) of
        {ok, Results, Completed} ->
            Report = #{schema => 1,
                       status => <<"Ready">>,
                       source_sha256 => Source,
                       configured_targets => length(Targets),
                       configured_repetitions => Configured,
                       completed_repetitions => Completed,
                       target_runs => Results},
            matrix_complete(Path, Report, Identity, Builds, <<"stability">>),
            io:format("stability matrix: ~B targets, ~B/~B fresh-BEAM "
                      "executions passed~n",
                      [length(Targets), Completed, Configured]),
            ok;
        {error, Results, Completed, Failure} ->
            Report = #{schema => 1,
                       status => <<"Failed">>,
                       source_sha256 => Source,
                       configured_targets => length(Targets),
                       configured_repetitions => Configured,
                       completed_repetitions => Completed,
                       target_runs => Results,
                       first_failure => Failure},
            write_report(Path, matrix_metadata(Report, Identity, Builds, <<"stability">>)),
            erlang:error({stability_test_failed,
                          maps:get(target, Failure),
                          maps:get(iteration, Failure),
                          maps:get(exit_status, Failure),
                          Path})
    end.

%% Replay one manifest-declared scheduling-sensitive target without replacing
%% aggregate qualification evidence. This is intentionally a diagnostic scope:
%% a successful partial run cannot be consumed as the 29-target stability gate.
stability_diagnostic(TargetText, RepetitionsText) ->
    Matrix = stability_matrix(),
    Manifest = json:decode(read("qualification.json")),
    Packages = maps:get(<<"packages">>, maps:get(<<"hostile_matrix">>, Manifest)),
    TargetName = unicode:characters_to_binary(TargetText),
    Declared = select_stability_target(
        TargetName, maps:get(<<"targets">>, Matrix)),
    DefaultRepetitions = maps:get(<<"repetitions">>, Declared),
    Repetitions = diagnostic_repetitions(
        RepetitionsText, DefaultRepetitions),
    Target = (stability_target(Declared, Packages))#{
        repetitions => Repetitions
    },
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    Source = source_digest(),
    Path = "build/fault/stability-target-" ++
        binary_to_list(sanitize(TargetName)) ++ ".json",
    Identity = evidence_begin(Path),
    TargetPackage = case maps:get(package, Target) of
        <<"quic_core">> -> "core";
        PackageName -> binary_to_list(PackageName)
    end,
    fresh_verify_many([TargetPackage]),
    case run_stability_targets([Target], TailLimit, [], 0) of
        {ok, Results, Completed} ->
            Report = #{schema => 1,
                       scope => <<"DiagnosticTarget">>,
                       shareable => false,
                       status => <<"Ready">>,
                       source_sha256 => Source,
                       configured_targets => 1,
                       configured_repetitions => Repetitions,
                       completed_repetitions => Completed,
                       target_runs => Results},
            write_report(Path, evidence_complete(Report, Identity)),
            io:format("stability diagnostic ~s: ~B/~B fresh-BEAM "
                      "executions passed; report ~s~n",
                      [TargetName, Completed, Repetitions, Path]),
            ok;
        {error, Results, Completed, Failure} ->
            Report = #{schema => 1,
                       scope => <<"DiagnosticTarget">>,
                       shareable => false,
                       status => <<"Failed">>,
                       source_sha256 => Source,
                       configured_targets => 1,
                       configured_repetitions => Repetitions,
                       completed_repetitions => Completed,
                       target_runs => Results,
                       first_failure => Failure},
            write_report(Path, Report#{evidence_identity => Identity}),
            erlang:error({stability_diagnostic_failed,
                          maps:get(target, Failure),
                          maps:get(iteration, Failure),
                          maps:get(exit_status, Failure),
                          Path})
    end.

select_stability_target(Name, [Target | Rest]) ->
    case maps:get(<<"name">>, Target) of
        Name -> Target;
        _ -> select_stability_target(Name, Rest)
    end;
select_stability_target(Name, []) ->
    erlang:error({unknown_stability_target, Name}).

diagnostic_repetitions(undefined, Default) ->
    Default;
diagnostic_repetitions(Text, _Default) ->
    try list_to_integer(Text) of
        Value when Value >= 1, Value =< 1000 -> Value;
        _ -> erlang:error({invalid_stability_repetitions_override, Text})
    catch
        error:badarg ->
            erlang:error({invalid_stability_repetitions_override, Text})
    end.

stability_matrix() ->
    Manifest = json:decode(read("qualification.json")),
    Hostile = maps:get(<<"hostile_matrix">>, Manifest),
    Matrix = maps:get(<<"stability_matrix">>, Manifest),
    audit_stability_matrix(Matrix, maps:get(<<"packages">>, Hostile)),
    Matrix.

audit_stability_matrix(Matrix, Packages) ->
    ensure(maps:get(<<"schema">>, Matrix) =:= 1,
           invalid_stability_matrix_schema),
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    ensure(is_integer(TailLimit) andalso TailLimit >= 1024
           andalso TailLimit =< 65536,
           {invalid_stability_output_tail_bytes, TailLimit}),
    Targets = maps:get(<<"targets">>, Matrix),
    ensure(is_list(Targets) andalso Targets =/= [], empty_stability_targets),
    Names = [maps:get(<<"name">>, Target) || Target <- Targets],
    ensure(length(Names) =:= length(lists:usort(Names)),
           duplicate_stability_target),
    PackageNames = [maps:get(<<"name">>, Package) || Package <- Packages],
    lists:foreach(
      fun(Target) -> audit_stability_target(Target, PackageNames) end,
      Targets),
    ok.

audit_stability_target(Target, PackageNames) ->
    Name = required_binary(Target, <<"name">>),
    Package = required_binary(Target, <<"package">>),
    Module = required_binary(Target, <<"module">>),
    Test = required_binary(Target, <<"test">>),
    Repetitions = maps:get(<<"repetitions">>, Target),
    ensure(valid_identifier(Name, <<"^[a-z][a-z0-9-]*$">>),
           {invalid_stability_target_name, Name}),
    ensure(lists:member(Package, PackageNames),
           {unknown_stability_package, Name, Package}),
    ensure(valid_identifier(Module, <<"^[a-z][a-z0-9_@]*_test$">>),
           {invalid_stability_module, Name, Module}),
    ensure(valid_identifier(Test, <<"^[a-z][a-z0-9_]*_test$">>),
           {invalid_stability_test, Name, Test}),
    ensure(is_integer(Repetitions) andalso Repetitions >= 1
           andalso Repetitions =< 1000,
           {invalid_stability_repetitions, Name, Repetitions}).

required_binary(Map, Key) ->
    Value = maps:get(Key, Map),
    ensure(is_binary(Value) andalso byte_size(Value) > 0,
           {invalid_stability_field, Key, Value}),
    Value.

valid_identifier(Value, Pattern) ->
    re:run(Value, Pattern, [{capture, none}]) =:= match.

stability_target(Target, Packages) ->
    PackageName = maps:get(<<"package">>, Target),
    Package = find_package(PackageName, Packages),
    #{name => maps:get(<<"name">>, Target),
      package => PackageName,
      directory => binary_to_list(maps:get(<<"directory">>, Package)),
      ebin => binary_to_list(maps:get(<<"ebin">>, Package)),
      module => binary_to_atom(maps:get(<<"module">>, Target)),
      test => binary_to_atom(maps:get(<<"test">>, Target)),
      repetitions => maps:get(<<"repetitions">>, Target)}.

find_package(Name, [Package | Rest]) ->
    case maps:get(<<"name">>, Package) of
        Name -> Package;
        _ -> find_package(Name, Rest)
    end;
find_package(Name, []) ->
    erlang:error({unknown_stability_package, Name}).

run_stability_targets([], _TailLimit, Results, Completed) ->
    {ok, lists:reverse(Results), Completed};
run_stability_targets([Target | Rest], TailLimit, Results, Completed0) ->
    case run_stability_target(Target, TailLimit, 1, []) of
        {ok, Result} ->
            Completed = Completed0 + maps:get(completed_repetitions, Result),
            run_stability_targets(Rest, TailLimit, [Result | Results], Completed);
        {error, Result, Failure} ->
            Completed = Completed0 + maps:get(completed_repetitions, Result),
            {error, lists:reverse([Result | Results]), Completed, Failure}
    end.

run_stability_target(Target, TailLimit, Iteration, Executions) ->
    Directory = filename:absname(maps:get(directory, Target)),
    Ebin = filename:absname(maps:get(ebin, Target)),
    Module = maps:get(module, Target),
    Test = maps:get(test, Target),
    Repetitions = maps:get(repetitions, Target),
    ensure_test_function(Ebin, Module, Test),
    case Iteration > Repetitions of
        true ->
            {ok, (stability_target_result(Target, <<"Ready">>, Repetitions))#{executions => lists:reverse(Executions)}};
        false ->
            io:format("stability ~s: fresh BEAM ~B/~B~n",
                      [maps:get(name, Target), Iteration, Repetitions]),
            {Status, Output} = run_eunit_function(
                Directory, Ebin, Module, Test),
            case Status of
                0 -> run_stability_target(Target, TailLimit, Iteration + 1,
                    [(bounded_output_evidence(Output, TailLimit))#{iteration => Iteration} | Executions]);
                _ ->
                    Completed = Iteration - 1,
                    Failure = stability_failure(
                        Target, Iteration, Status, Output, TailLimit),
                    {error,
                     (stability_target_result(Target, <<"Failed">>, Completed))#{executions =>
                         lists:reverse([(bounded_output_evidence(Output, TailLimit))#{iteration => Iteration} | Executions])},
                     Failure}
            end
    end.

stability_target_result(Target, Status, Completed) ->
    #{name => maps:get(name, Target),
      package => maps:get(package, Target),
      module => atom_to_binary(maps:get(module, Target)),
      test => atom_to_binary(maps:get(test, Target)),
      status => Status,
      configured_repetitions => maps:get(repetitions, Target),
      completed_repetitions => Completed}.

stability_failure(Target, Iteration, Status, Output, TailLimit) ->
    maps:merge(
        #{target => maps:get(name, Target),
          package => maps:get(package, Target),
          module => atom_to_binary(maps:get(module, Target)),
          test => atom_to_binary(maps:get(test, Target)),
          iteration => Iteration,
          exit_status => Status,
          shareable => true},
        bounded_output_evidence(Output, TailLimit)).

ensure_test_function(Ebin, Module, Test) ->
    ensure_test_beam(Ebin, Module),
    Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    {ok, {Module, [{exports, Exports}]}} = beam_lib:chunks(Beam, [exports]),
    ensure(lists:member({Test, 0}, Exports),
           {missing_stability_test_export, Module, Test, Beam}).

run_eunit_function(Directory, Ebin, Module, Test) ->
    Unit = #{module => atom_to_binary(Module), function => atom_to_binary(Test), kind => <<"test">>},
    run_eunit_units(Directory, Ebin, [Unit]).

bounded_output_evidence(Captured, _Limit) when is_map(Captured) ->
    %% Output can contain secrets even on successful runs. Neither it nor a
    %% guessable digest belongs in a shared qualification document.
    maps:with([output_bytes, output_hashed_bytes, output_limit_bytes,
        output_limit_exceeded, output_digest_complete, timed_out, child_exit_observed,
        vm_process_heap_words, vm_heap_includes_shared_binaries, crash_dumps_disabled,
        process_supervisor, process_supervisor_protocol_valid,
        process_supervisor_failure_code, process_supervisor_attestation_failure,
        process_supervisor_reported_status, process_supervisor_observed_status,
        native_tree_empty, native_console_isolated,
        native_descendant_outlived,
        native_termination_requested,
        exit_status, configured_units, completed_tests, eunit], Captured);
bounded_output_evidence(Output, _Limit) when is_binary(Output) ->
    #{output_bytes => byte_size(Output)}.

remove_stale_report(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> erlang:error({cannot_remove_stale_report, Path, Reason})
    end.

credential_local() ->
    Platform = qualification_platform(),
    Otp = list_to_binary(erlang:system_info(otp_release)),
    Filename = binary_to_list(sanitize(Platform)) ++ "-otp" ++
               binary_to_list(Otp) ++ ".json",
    Path = filename:join("build/credential-matrix/local", Filename),
    Identity = evidence_begin(Path),
    try
        Catalogs = runtime_matrix_catalog(),
        ensure(credential_contract_valid(Catalogs), missing_credential_test_export),
        Builds = matrix_builds(),
        Requirements = credential_required_units(),
        Targets = [credential_target(Requirement) || Requirement <- Requirements],
        Base = #{schema => 2, scope => <<"LocalCredentialDiagnostic">>, platform => Platform,
            otp => Otp, source_sha256 => source_digest(), configured_targets => length(Targets),
            configured_repetitions => length(Targets), required_roles => Requirements},
        case run_stability_targets(Targets, 4096, [], 0) of
            {ok, Results, Completed} ->
                Report = Base#{status => <<"DiagnosticPassed">>, completed_repetitions => Completed,
                               target_runs => Results},
                matrix_complete(Path, Report, Identity, Builds, <<"credential-local">>),
                io:format("local credential diagnostic: ~B/~B exact test symbols executed; "
                          "six-platform qualification still requires complete package suites~n",
                          [Completed, length(Targets)]);
            {error, Results, Completed, Failure} ->
                Report = Base#{status => <<"Failed">>, completed_repetitions => Completed,
                               target_runs => Results, first_failure => Failure},
                write_report(Path, matrix_metadata(Report, Identity, Builds, <<"credential-local">>)),
                erlang:error(local_credential_test_failed)
        end
    catch Class:Reason:Stack ->
        case filelib:is_regular(Path) of
            true -> ok;
            false -> write_report(Path, #{schema => 2, status => <<"Failed">>, shareable => true,
                scope => <<"LocalCredentialDiagnostic">>, completed_repetitions => 0,
                replay => <<"escript scripts/test_matrix.escript credential-local">>,
                evidence_identity => Identity, execution_environment => execution_runtime(),
                failure => diagnostic_failure_details(Class, Reason, Stack)})
        end,
        erlang:raise(Class, Reason, Stack)
    end.

credential_target(#{role := Role, target := Target, unit := Unit}) ->
    TargetText = binary_to_list(Target),
    {Name, Directory} = lists:last(fresh_packages(TargetText)),
    #{name => Role, package => list_to_binary(Name), directory => Directory,
      ebin => filename:join([Directory, "build/dev/erlang", Name, "ebin"]),
      module => binary_to_atom(maps:get(module, Unit)),
      test => binary_to_atom(maps:get(function, Unit)), repetitions => 1}.

credential_aggregate() ->
    Path = "build/credential-matrix/report.json",
    Identity = evidence_begin(Path),
    Report = try
        Candidate = credential_matrix_capture(Identity),
        true = runtime_matrix_inventory_valid("verified"),
        evidence_require_identity(#{<<"evidence_identity">> => Identity}, evidence_identity()),
        Candidate
    catch Class:Reason:Stack ->
        #{schema => 2, status => <<"Blocked">>, evidence_identity => Identity,
          expected_platforms => 6, completed_platforms => 0,
          failure => diagnostic_failure_details(Class, Reason, Stack)}
    end,
    write_report(Path, Report),
    io:format("credential matrix: ~s, ~B/6 platform runs verified~n",
              [maps:get(status, Report), maps:get(completed_platforms, Report)]),
    ensure(maps:get(status, Report) =:= <<"Ready">>, incomplete_credential_matrix).

credential_artifact_aggregate() ->
    Path = "build/credential-matrix/report.json",
    Identity = evidence_begin(Path),
    Report = try
        Candidate = credential_artifact_capture(Identity),
        evidence_complete(Candidate, Identity)
    catch Class:Reason:Stack ->
        #{schema => 1, status => <<"Blocked">>, evidence_identity => Identity,
          execution_environment => execution_runtime(),
          evidence_source => <<"six isolated live credential artifacts">>,
          expected_platforms => 6, completed_platforms => 0,
          failure => diagnostic_failure_details(Class, Reason, Stack)}
    end,
    write_report(Path, Report),
    io:format("credential artifact matrix: ~s, ~B/6 platform runs verified~n",
              [maps:get(status, Report), maps:get(completed_platforms, Report)]),
    ensure(maps:get(status, Report) =:= <<"Ready">>,
           incomplete_credential_artifact_matrix).

%% Nightly's six live credential diagnostics are a separate evidence source
%% from the 18 package-suite rows consumed by credential_aggregate/0.
credential_artifact_capture(Identity) ->
    Merge = artifact_merge_verify_credential(Identity),
    Catalogs = runtime_matrix_catalog(),
    Platforms = [{Os, Otp} || Os <- [<<"ubuntu-24.04">>, <<"macos-15">>,
                                      <<"windows-2025">>],
                                Otp <- [28, 29]],
    Rows = [credential_artifact_row(Os, Otp, Identity, Catalogs)
            || {Os, Otp} <- Platforms],
    Complete = length([ok || #{status := <<"Ready">>} <- Rows]),
    #{schema => 1,
      status => case credential_artifact_rows_valid(Rows) of
          true -> <<"Ready">>; false -> <<"Blocked">> end,
      evidence_identity => Identity, execution_environment => execution_runtime(),
      evidence_source => <<"six isolated live credential artifacts">>,
      assembly_receipt_sha256 => maps:get(sha256, Merge),
      expected_platforms => 6, completed_platforms => Complete,
      platforms => Rows}.

credential_artifact_rows_valid(Rows) ->
    Expected = [{Os, Otp,
        <<"nightly-credential-", Os/binary, "-otp-", (integer_to_binary(Otp))/binary>>}
        || Os <- [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>],
           Otp <- [28, 29]],
    Actual = [{maps:get(platform, Row), maps:get(otp, Row), maps:get(artifact, Row)}
              || Row <- Rows],
    Nonces = lists:append([maps:get(run_nonces, Row, []) || Row <- Rows]),
    length(Rows) =:= 6 andalso Actual =:= Expected andalso
    lists:all(fun(Row) -> maps:get(status, Row) =:= <<"Ready">> end, Rows) andalso
    credential_artifact_runner_hashes_valid(Rows) andalso
    length(Nonces) =:= 6 * length(credential_required_units()) andalso
    length(Nonces) =:= length(lists:usort(Nonces)).

%% The listener is compiled once from the same current source for each pinned
%% OTP. Its BEAM identity must agree across all three operating systems; a row
%% cannot substitute a different runner while retaining valid local counters.
credential_artifact_runner_hashes_valid(Rows) ->
    try lists:all(fun(Otp) ->
        Hashes = lists:usort([
            maps:get(runner_sha256, Row)
            || Row <- Rows, maps:get(otp, Row) =:= Otp
        ]),
        case Hashes of
            [Hash] -> runtime_matrix_hex(Hash);
            _ -> false
        end
    end, [28, 29])
    catch _:_ -> false end.

credential_artifact_rows_self_test() ->
    Rows = [#{platform => Os, otp => Otp,
        artifact => <<"nightly-credential-", Os/binary, "-otp-",
                      (integer_to_binary(Otp))/binary>>,
        status => <<"Ready">>, runner_sha256 =>
            case Otp of
                28 -> binary:copy(<<"a">>, 64);
                29 -> binary:copy(<<"b">>, 64)
            end,
        run_nonces => [iolist_to_binary(io_lib:format("~32.16.0b", [Base + Id]))
                       || Id <- lists:seq(1, length(credential_required_units()))]}
        || {{Os, Otp}, Base} <- lists:zip(
            [{P, V} || P <- [<<"ubuntu-24.04">>, <<"macos-15">>,
                              <<"windows-2025">>], V <- [28, 29]],
            [0, 100, 200, 300, 400, 500])],
    true = credential_artifact_rows_valid(Rows),
    [First, Second, Third | Rest] = Rows,
    false = credential_artifact_rows_valid(tl(Rows)),
    false = credential_artifact_rows_valid([First, First, Third | Rest]),
    false = credential_artifact_rows_valid([
        First#{artifact => <<"nightly-credential-unexpected">>}, Second,
        Third | Rest]),
    false = credential_artifact_rows_valid([
        First#{run_nonces => maps:get(run_nonces, Second)}, Second,
        Third | Rest]),
    false = credential_artifact_rows_valid([
        First, Second,
        Third#{runner_sha256 => binary:copy(<<"c">>, 64)} | Rest
    ]),
    ok.

credential_artifact_row(Os, Otp, Identity, Catalogs) ->
    OtpText = integer_to_binary(Otp),
    Artifact = <<"nightly-credential-", Os/binary, "-otp-", OtpText/binary>>,
    Relative = <<Os/binary, "-otp", OtpText/binary, ".json">>,
    Path = filename:join(["build", "credential-matrix", "local",
                          binary_to_list(Relative)]),
    Base = #{platform => Os, otp => Otp, artifact => Artifact},
    try
        Bytes = runtime_matrix_read(Path, 16777216),
        Report = evidence_json_decode(Bytes),
        Nonces = credential_artifact_report(Report, Os, Otp, Identity, Catalogs),
        Base#{status => <<"Ready">>,
              report_sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase),
              runner_sha256 => maps:get(<<"runner_sha256">>, Report),
              run_nonces => Nonces}
    catch _:_ -> Base#{status => <<"Blocked">>,
                       failure => <<"invalid_or_incomplete_credential_artifact">>}
    end.

credential_artifact_report(Report, Os, Otp, Identity, Catalogs) ->
    true = suite_exact_keys(Report, [schema, status, scope, platform, otp,
        source_sha256, configured_targets, configured_repetitions,
        required_roles, completed_repetitions, target_runs,
        evidence_identity, execution_environment, build_identities,
        shareable, runner_sha256, replay]),
    2 = maps:get(<<"schema">>, Report),
    <<"DiagnosticPassed">> = maps:get(<<"status">>, Report),
    <<"LocalCredentialDiagnostic">> = maps:get(<<"scope">>, Report),
    true = maps:get(<<"shareable">>, Report),
    Os = maps:get(<<"platform">>, Report),
    OtpText = integer_to_binary(Otp),
    OtpText = maps:get(<<"otp">>, Report),
    Identity = maps:get(<<"evidence_identity">>, Report),
    Source = source_digest(),
    Source = maps:get(<<"source_sha256">>, Report),
    Runtime = maps:get(<<"execution_environment">>, Report),
    true = runtime_matrix_environment_valid(Runtime, #{os => Os, otp => Otp}),
    Roles = runtime_matrix_json(credential_required_units()),
    Roles = maps:get(<<"required_roles">>, Report),
    Count = length(Roles),
    Count = maps:get(<<"configured_targets">>, Report),
    Count = maps:get(<<"configured_repetitions">>, Report),
    Count = maps:get(<<"completed_repetitions">>, Report),
    <<"escript scripts/test_matrix.escript credential-local">> =
        maps:get(<<"replay">>, Report),
    Builds = maps:get(<<"build_identities">>, Report),
    true = suite_exact_keys(Builds, [http, http3, core]),
    true = lists:all(fun(Target) -> runtime_matrix_build_valid(
        maps:get(Target, Builds), Target, maps:get(Target, Catalogs), Runtime)
    end, [<<"http">>, <<"http3">>, <<"core">>]),
    true = runtime_matrix_hex(maps:get(<<"runner_sha256">>, Report)),
    Targets = [credential_artifact_target(Requirement)
               || Requirement <- credential_required_units()],
    Runs = maps:get(<<"target_runs">>, Report),
    Count = length(Runs),
    Executions = lists:append([credential_artifact_target_run(Run, Target, Catalogs)
                               || {Run, Target} <- lists:zip(Runs, Targets)]),
    Nonces = [maps:get(<<"run_nonce">>, maps:get(<<"eunit">>, Execution))
              || Execution <- Executions],
    true = length(Nonces) =:= Count andalso
           length(Nonces) =:= length(lists:usort(Nonces)),
    Nonces.

credential_artifact_target(Requirement) ->
    Target = credential_target(Requirement),
    runtime_matrix_json(maps:without([directory, ebin], Target)).

credential_artifact_target_run(Run, Target, Catalogs) ->
    true = suite_exact_keys(Run, [name, package, module, test, status,
        configured_repetitions, completed_repetitions, executions]),
    true = maps:with([<<"name">>, <<"package">>, <<"module">>, <<"test">>], Run)
        =:= maps:with([<<"name">>, <<"package">>, <<"module">>, <<"test">>], Target),
    <<"Ready">> = maps:get(<<"status">>, Run),
    1 = maps:get(<<"repetitions">>, Target),
    1 = maps:get(<<"configured_repetitions">>, Run),
    1 = maps:get(<<"completed_repetitions">>, Run),
    [Execution] = maps:get(<<"executions">>, Run),
    Unit = #{module => maps:get(<<"module">>, Target),
             function => maps:get(<<"test">>, Target), kind => <<"test">>},
    Package = maps:get(<<"package">>, Target),
    CatalogTarget = case Package of <<"quic_core">> -> <<"core">>; _ -> Package end,
    true = lists:member(Unit, maps:get(units, maps:get(CatalogTarget, Catalogs))),
    true = credential_artifact_execution(Execution, Unit),
    [Execution].

credential_artifact_execution(Execution, Unit) ->
    try
        ProcessKeys = runtime_matrix_process_keys(),
        true = suite_exact_keys(Execution, [iteration, exit_status, eunit,
            configured_units, completed_tests | ProcessKeys]),
        1 = maps:get(<<"iteration">>, Execution),
        0 = maps:get(<<"exit_status">>, Execution),
        1 = maps:get(<<"configured_units">>, Execution),
        Child = maps:get(<<"eunit">>, Execution),
        Nonce = maps:get(<<"run_nonce">>, Child),
        true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32 andalso
               re:run(Nonce, <<"^[0-9A-Fa-f]{32}$">>, [{capture, none}]) =:= match,
        true = suite_child_valid(Child, [Unit], Nonce),
        true = maps:get(<<"completed_tests">>, Execution) =:= suite_completed_tests(Child),
        runtime_matrix_process_valid(maps:with(
            [atom_to_binary(Key) || Key <- ProcessKeys], Execution))
    catch _:_ -> false end.

ensure_test_beam(Ebin, Module) ->
    Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    ensure(filelib:is_regular(Beam), {missing_test_beam, Module, Beam}).

beam_test_count(Ebin, Module) ->
    length(suite_beam_units(Ebin, atom_to_binary(Module))).

run_eunit_module(Directory, Ebin, Module) ->
    run_eunit_units(Directory, Ebin, suite_beam_units(Ebin, atom_to_binary(Module))).

run_eunit_units(Directory, Ebin, Units) ->
    Paths0 = group_code_paths(Ebin),
    Paths = [Ebin | lists:delete(Ebin, Paths0)],
    Descriptors = [{<<"qualification unit">>, {inorder, [{timeout, 240,
        {case maps:get(kind, Unit) of <<"test">> -> test; <<"generator">> -> generator end,
         binary_to_atom(maps:get(module, Unit)), binary_to_atom(maps:get(function, Unit))}}]}}
        || Unit <- Units],
    run_eunit_descriptors(Directory, Paths, Units, lists:flatten(io_lib:format("~0tp", [Descriptors]))).

%% Used only for executable adversarial fixtures in this script's self-test.
run_eunit_with_paths(Directory, Paths, Descriptor) ->
    Unit = #{module => <<"qualification_eunit_fixture">>, function => <<"injected_test">>, kind => <<"test">>},
    run_eunit_descriptors(Directory, Paths, [Unit],
        "[{<<\"qualification unit\">>,{inorder,[" ++ Descriptor ++ "]}}]").

run_eunit_descriptors(Directory, Paths, Units, Descriptors) ->
    ensure(Units =/= [] andalso length(Units) =< 10000, invalid_eunit_unit_count),
    Runner = matrix_runner(),
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Path = filename:absname("build/test-matrix/child.json"),
    remove_stale_report(Path),
    Evaluation = lists:flatten(io_lib:format(
        "qualification_eunit_listener:run_descriptors(~0tp,~s,~0tp,~0tp).",
        [Units, Descriptors, Path, Nonce])),
    {Status, Output} = run_child_evaluation(Directory, [Runner | Paths], Evaluation, 600000),
    Child = suite_safe_child(matrix_read_child(Path), Units, Nonce),
    Valid = suite_child_valid(Child, Units, Nonce) andalso
        process_status_verified(Status, 0, Output),
    EffectiveStatus = case Status =:= 0 andalso not Valid of true -> 1; false -> Status end,
    {EffectiveStatus, Output#{exit_status => Status, eunit => Child, configured_units => length(Units),
                              completed_tests => suite_completed_tests(Child)}}.

fault_guard(Name, Run) ->
    Path = "build/fault/" ++ Name ++ ".json",
    remove_stale_report(Path),
    try Run()
    catch Class:Reason:Stack ->
        case filelib:is_regular(Path) of
            true -> ok;
            false -> write_report(Path, #{schema => 1, status => <<"Failed">>,
                shareable => true, completed_tests => 0,
                evidence_identity => evidence_identity(), execution_environment => execution_runtime(),
                failure => diagnostic_failure_details(Class, Reason, Stack)})
        end,
        erlang:raise(Class, Reason, Stack)
    end.

matrix_builds() ->
    Snapshots = fresh_with_verified_builds(["http", "http3", "core"],
        fun(Verified) -> Verified end),
    maps:from_list([{list_to_binary(maps:get(target, Snapshot)),
        maps:get(report, Snapshot)} || Snapshot <- Snapshots]).

matrix_metadata(Report, Identity, Builds, Mode) ->
    Runner = filename:join(matrix_runner(), "qualification_eunit_listener.beam"),
    Report#{evidence_identity => Identity, execution_environment => execution_runtime(),
            build_identities => Builds, shareable => true,
            runner_sha256 => hex(crypto:hash(sha256, fresh_read(Runner))),
            replay => <<"escript scripts/test_matrix.escript ", Mode/binary>>}.

matrix_complete(Path, Report, Identity, Builds, Mode) ->
    ExpectedStatus = case maps:get(status, Report) of
        <<"Ready">> -> <<"Ready">>;
        <<"DiagnosticPassed">> -> <<"DiagnosticPassed">>
    end,
    WithMetadata = matrix_metadata(Report, Identity, Builds, Mode),
    %% Save completed executions even if final source/artifact verification fails.
    Checked = try
        fresh_verify_many(["http", "http3", "core"]),
        ensure(matrix_builds() =:= Builds, changed_matrix_build),
        evidence_complete(WithMetadata, Identity)
    catch Class:Reason:Stack ->
        WithMetadata#{status => <<"Failed">>,
            failure => diagnostic_failure_details(Class, Reason, Stack)}
    end,
    write_report(Path, Checked),
    ensure(maps:get(status, Checked) =:= ExpectedStatus, final_matrix_verification_failed).

matrix_runner() ->
    case get(qualification_matrix_runner) of
        undefined ->
            Directory = filename:absname("build/test-matrix/runner"),
            ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
            {ok, Module, Binary, []} = compile:file("scripts/qualification_eunit_listener.erl",
                [binary, return_errors, return_warnings, {i, "scripts"}]),
            ok = file:write_file(filename:join(Directory, atom_to_list(Module) ++ ".beam"), Binary),
            put(qualification_matrix_runner, Directory),
            Directory;
        Directory -> Directory
    end.

matrix_read_child(Path) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, File} ->
            Read = file:read(File, 16777217),
            ok = file:close(File),
            case Read of
                {ok, Bytes} when byte_size(Bytes) =< 16777216 ->
                    try evidence_json_decode(Bytes) catch _:_ -> #{invalid => true} end;
                _ -> #{invalid => true}
            end;
        _ -> #{missing => true}
    end.

qualification_platform() ->
    case os:getenv("QUALIFICATION_PLATFORM") of
        false -> inferred_platform();
        Value ->
            Platform = unicode:characters_to_binary(Value),
            Allowed = case os:type() of
                {unix, darwin} -> [<<"macos-15">>, <<"local-macos">>];
                {unix, _} -> [<<"ubuntu-24.04">>, <<"local-linux">>];
                {win32, _} -> [<<"windows-2025">>, <<"local-windows">>]
            end,
            ensure(lists:member(Platform, Allowed), invalid_credential_platform_label),
            Platform
    end.

inferred_platform() ->
    case os:type() of
        {unix, darwin} -> <<"local-macos">>;
        {unix, _} -> <<"local-linux">>;
        {win32, _} -> <<"local-windows">>
    end.

source_digest() ->
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

write_report(Path, Report) ->
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]).

sanitize(Value) ->
    re:replace(Value, <<"[^A-Za-z0-9._-]">>, <<"-">>,
               [global, {return, binary}]).

group_code_paths(Ebin) ->
    %% Each Gleam package build is self-contained.  Mixing all three build
    %% roots makes identically named test modules (notably client_test and
    %% server_test) shadow one another, so a qualification row must load only
    %% the package under test and the dependencies compiled into its build.
    ErlangRoot = filename:dirname(filename:dirname(Ebin)),
    Paths = filelib:wildcard(filename:join(ErlangRoot, "*/ebin")),
    [filename:absname(Path) || Path <- lists:usort(Paths)].

self_test() ->
    json_reader_duplicate_controls("matrix-child", ["child.json"],
        fun() -> not maps:is_key(invalid, matrix_read_child("child.json")) end),
    json_reader_duplicate_controls("matrix-build",
        [fresh_manifest_path(Target) || Target <- ["http", "http3", "core"]],
        fun() -> is_map(matrix_builds()) end),
    lists:foreach(fun(Requirement) ->
        CredentialTarget = credential_target(Requirement),
        ensure(maps:get(name, CredentialTarget) =:= maps:get(role, Requirement)
            andalso maps:get(repetitions, CredentialTarget) =:= 1,
            exact_local_credential_target)
    end, credential_required_units()),
    PrivateEvidence = bounded_output_evidence(<<"fixture-private-marker">>, 4096),
    SafeFailure = not maps:is_key(output_tail_base64, PrivateEvidence) andalso
                  not maps:is_key(output_sha256, PrivateEvidence),
    io:format("failure_payload_omitted=~p~n", [SafeFailure]),
    ensure(SafeFailure, failure_payload_must_not_be_published),
    collector_self_test(),
    credential_matrix_self_test(),
    credential_artifact_rows_self_test(),
    Packages = [#{<<"name">> => <<"http">>,
                  <<"directory">> => <<".">>,
                  <<"ebin">> => <<"build/dev/erlang/http/ebin">>}],
    Target = #{<<"name">> => <<"http2-drain">>,
               <<"package">> => <<"http">>,
               <<"module">> => <<"http2_server_test">>,
               <<"test">> => <<"drain_order_test">>,
               <<"repetitions">> => 30},
    Matrix = #{<<"schema">> => 1,
               <<"output_tail_bytes">> => 4096,
               <<"targets">> => [Target]},
    ok = audit_stability_matrix(Matrix, Packages),
    ensure(select_stability_target(<<"http2-drain">>, [Target]) =:= Target,
           self_test_stability_target_selection),
    expect_error(unknown_stability_target,
                 fun() -> select_stability_target(<<"missing">>, [Target]) end),
    ensure(diagnostic_repetitions(undefined, 30) =:= 30,
           self_test_default_diagnostic_repetitions),
    ensure(diagnostic_repetitions("17", 30) =:= 17,
           self_test_override_diagnostic_repetitions),
    expect_error(invalid_diagnostic_repetitions,
                 fun() -> diagnostic_repetitions("0", 30) end),
    expect_error(excessive_diagnostic_repetitions,
                 fun() -> diagnostic_repetitions("1001", 30) end),
    expect_error(non_numeric_diagnostic_repetitions,
                 fun() -> diagnostic_repetitions("many", 30) end),
    expect_error(bad_schema,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"schema">> => 2}, Packages) end),
    expect_error(bad_tail_limit,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"output_tail_bytes">> => 0}, Packages) end),
    expect_error(empty_targets,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"targets">> => []}, Packages) end),
    expect_error(duplicate_targets,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"targets">> => [Target, Target]}, Packages) end),
    expect_error(unknown_package,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"targets">> => [
                         Target#{<<"package">> => <<"missing">>}
                     ]}, Packages) end),
    expect_error(zero_repetitions,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"targets">> => [
                         Target#{<<"repetitions">> => 0}
                     ]}, Packages) end),
    expect_error(unsafe_module,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"targets">> => [
                         Target#{<<"module">> => <<"http2;halt_test">>}
                     ]}, Packages) end),
    expect_error(non_test_function,
                 fun() -> audit_stability_matrix(
                     Matrix#{<<"targets">> => [
                         Target#{<<"test">> => <<"drain_order">>}
                     ]}, Packages) end),
    Evidence = bounded_output_evidence(<<"0123456789">>, 4),
    ensure(maps:get(output_bytes, Evidence) =:= 10,
           self_test_output_size),
    ensure(maps:keys(Evidence) =:= [output_bytes], self_test_no_raw_output_evidence),
    SyntheticTarget = #{name => <<"http2-drain">>,
                        package => <<"http">>,
                        module => http2_server_test,
                        test => drain_order_test,
                        repetitions => 30},
    Failure = stability_failure(
        SyntheticTarget, 7, 1, <<"0123456789">>, 4),
    ensure(maps:get(iteration, Failure) =:= 7,
           self_test_failure_iteration),
    ensure(maps:get(exit_status, Failure) =:= 1,
           self_test_failure_status),
    ensure(maps:get(shareable, Failure) =:= true,
           self_test_failure_shareability),
    {InjectedStatus, InjectedOutput} = run_eunit_with_paths(
        filename:absname("."), [],
        "{timeout,1,fun() -> io:put_chars(standard_error,<<\"fixture-private-marker\">>),"
        "erlang:error({<<\"fixture-private-marker\">>,self(),make_ref()}) end}"),
    ensure(InjectedStatus =:= 1, self_test_injected_failure_status),
    ensure(binary:match(output_tail(InjectedOutput), <<"fixture-private-marker">>)
           =/= nomatch,
           self_test_injected_failure_output),
    InjectedEvidence = bounded_output_evidence(InjectedOutput, 1024),
    ensure(maps:get(output_bytes, InjectedEvidence) > 0,
           self_test_injected_failure_evidence),
    ensure(binary:match(iolist_to_binary(json:encode(InjectedEvidence)), <<"fixture-private-marker">>)
           =:= nomatch, self_test_injected_failure_redacted),
    ensure(not maps:is_key(output_tail_base64, InjectedEvidence), self_test_no_encoded_secret),
    ensure(maps:get(<<"failure_count">>, maps:get(eunit, InjectedEvidence)) =:= 1,
           self_test_typed_failure_retained),
    HostileFailure = hostile_failure(
        <<"http">>, http2_server_test, InjectedStatus, InjectedOutput, 1024),
    ensure(maps:get(package, HostileFailure) =:= <<"http">>,
           self_test_hostile_failure_package),
    ensure(maps:get(module, HostileFailure) =:= <<"http2_server_test">>,
           self_test_hostile_failure_module),
    ensure(maps:get(shareable, HostileFailure) =:= true,
           self_test_hostile_failure_shareability),
    SelfTestPath = "build/fault/test-matrix-self-test.json",
    write_report(SelfTestPath, #{status => <<"InjectedFailure">>}),
    ensure(filelib:is_regular(SelfTestPath), self_test_report_write),
    remove_stale_report(SelfTestPath),
    ensure(not filelib:is_regular(SelfTestPath), self_test_report_removal),
    remove_stale_report(SelfTestPath),
    io:format("qualification matrix self-test ok (8 adversarial schemas, "
              "6 exact Windows transcript controls, diagnostic target "
              "selection, repetition overrides, isolated child failure, "
              "bounded evidence, and stale-report removal)~n"),
    ok.

%% These tests use real child BEAMs: a flood must neither grow retained output
%% nor postpone the parent's deadline, and a silent child must be reaped too.
collector_self_test() ->
    absolute_collector_self_test(),
    child_transcript_self_test(),
    Chunk = binary:copy(<<"0123456789">>, 10000),
    Collected = append_output(Chunk, append_output(<<"prefix">>, new_output())),
    Finished = finish_output(Collected, false, true),
    Evidence = bounded_output_evidence(Finished, 32),
    ensure(maps:get(output_bytes, Evidence) =:= byte_size(Chunk) + 6,
           self_test_streaming_output_count),
    ensure(maps:get(output_sha256, Finished) =:=
               binary:encode_hex(
                   crypto:hash(sha256, [<<"prefix">>, Chunk]), lowercase),
           self_test_streaming_output_digest),
    ensure(binary:part(output_tail(Finished), 65536 - 32, 32) =:=
               binary:part(Chunk, byte_size(Chunk) - 32, 32),
           self_test_streaming_output_tail),
    ensure(byte_size(maps:get(tail, Collected)) =< 65536,
           self_test_streaming_output_retention),
    {0, Successful} = run_child_evaluation(
        filename:absname("."), [], "io:put_chars(<<\"success\">>),halt(0).", 5000),
    ensure(process_status_verified(0, 0, Successful),
           self_test_success_process_unverified),
    ensure(child_transcript_matches(output_tail(Successful), <<"success">>),
           self_test_child_success),
    {7, Abnormal} = run_child_evaluation(
        filename:absname("."), [], "halt(7).", 5000),
    ensure(process_status_verified(7, 7, Abnormal), self_test_abnormal_reaped),
    lists:foreach(fun(Evaluation) ->
        Started = erlang:monotonic_time(millisecond),
        {124, TimedOut} = run_child_evaluation(
            filename:absname("."), [], Evaluation, 1000),
        Elapsed = erlang:monotonic_time(millisecond) - Started,
        ensure(Elapsed < 12000, {self_test_absolute_deadline, Elapsed}),
        ensure(process_deadline_verified(124, TimedOut),
               self_test_timeout_provenance),
        ensure(byte_size(output_tail(TimedOut)) =< 65536,
               self_test_timeout_retention)
    end, ["receive never -> ok end.",
          "F=fun Loop()->io:put_chars(<<\"x\">>),receive after 10->ok end,Loop() end,F()."]),
    ok.

child_transcript_self_test() ->
    Prefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
        27, "[?9001l", 27, "[?1004l", 27, "[2J", 27, "[m", 27, "[H">>,
    Suffix = <<27, "[?25h">>,
    Envelope = <<Prefix/binary, "success", 27, "]0;fixed-tool.exe", 7,
                 Suffix/binary>>,
    ensure(child_transcript_matches(<<"success">>, <<"success">>),
           raw_child_transcript_rejected),
    ensure(child_transcript_matches(Envelope, <<"success">>),
           console_child_transcript_rejected),
    ensure(not child_transcript_matches(
        <<Prefix/binary, "success-extra", 27, "]0;fixed-tool.exe", 7,
          Suffix/binary>>, <<"success">>), extra_child_output_accepted),
    ensure(not child_transcript_matches(
        <<Prefix/binary, "success", 27, "]0;bad", 10, "title", 7,
          Suffix/binary>>, <<"success">>), control_console_title_accepted),
    ensure(not child_transcript_matches(
        <<Prefix/binary, "success", 27, "]0;fixed-tool.exe", 7>>,
        <<"success">>), missing_console_suffix_accepted),
    ensure(not child_transcript_matches(Envelope, <<"failure">>),
           wrong_child_payload_accepted).

absolute_collector_self_test() ->
    Owner = self(),
    Token = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        lists:foreach(fun(_) ->
            Owner ! {Token, {data, <<"x">>}},
            receive after 10 -> ok end
        end, lists:seq(1, 30)),
        Owner ! {Token, {exit_status, 0}}
    end),
    %% No child watchdog is involved: continued data cannot postpone this
    %% absolute deadline, even though the eventual child status is successful.
    {124, Output} = collect_eunit_with_deadline_stop(
        Token, new_output(), erlang:monotonic_time(millisecond) + 20,
        fun synthetic_deadline_stop/2),
    ensure(maps:get(output_bytes, Output) =:= 30,
           self_test_post_deadline_output_accounting),
    ensure(maps:get(child_exit_observed, Output), self_test_deadline_exit_observed),
    receive {'DOWN', Monitor, process, Pid, normal} -> ok
    after 1000 -> erlang:error(self_test_emitter_cleanup)
    end.

%% A hidden ConPTY can surround an otherwise exact child transcript with a
%% fixed terminal setup/teardown envelope. Keep the payload assertion exact;
%% only the bounded, title-only envelope is platform-specific.
child_transcript_matches(Bytes, Expected) ->
    Bytes =:= Expected orelse
        console_payload_envelope_matches(
            Bytes,
            <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
              27, "[?9001l", 27, "[?1004l", 27, "[2J", 27, "[m", 27, "[H">>,
            <<27, "[?25h">>,
            Expected) orelse
        console_payload_envelope_matches(
            Bytes,
            <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
              27, "[2J", 27, "[m", 27, "[H">>,
            <<27, "[?25h", 27, "[?9001l", 27, "[?1004l">>,
            Expected).

console_payload_envelope_matches(Bytes, Prefix, Suffix, Expected)
  when byte_size(Bytes) =< 8388608, byte_size(Expected) =< 65536 ->
    PrefixSize = byte_size(Prefix),
    ExpectedSize = byte_size(Expected),
    SuffixSize = byte_size(Suffix),
    case Bytes of
        <<Prefix:PrefixSize/binary, Expected:ExpectedSize/binary,
          27, "]0;", Rest/binary>> ->
            case binary:match(Rest, <<7>>) of
                {TitleSize, 1} when TitleSize > 0, TitleSize =< 4096 ->
                    RemainingSize = byte_size(Rest) - TitleSize - 1,
                    Title = binary:part(Rest, 0, TitleSize),
                    Remaining = binary:part(Rest, TitleSize + 1,
                                            RemainingSize),
                    RemainingSize =:= SuffixSize andalso
                        Remaining =:= Suffix andalso
                        test_matrix_safe_console_title(Title);
                _ -> false
            end;
        _ -> false
    end;
console_payload_envelope_matches(_, _, _, _) -> false.

test_matrix_safe_console_title(Title) ->
    lists:all(fun(Byte) -> Byte >= 32 andalso Byte =/= 127 end,
              binary_to_list(Title)).

synthetic_deadline_stop(Token, Output) ->
    receive
        {Token, {data, Bytes}} ->
            synthetic_deadline_stop(Token, append_output(Bytes, Output));
        {Token, {exit_status, _Status}} ->
            {124, finish_output(Output, true, true)}
    after 1000 ->
        erlang:error(self_test_emitter_cleanup)
    end.

expect_error(Label, Function) ->
    Outcome = try Function() of
        _ -> unexpected_success
    catch
        error:_ -> expected_error
    end,
    ensure(Outcome =:= expected_error,
           {self_test_expected_error, Label}).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
