#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "qualification matrix failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["hostile"]) -> hostile();
run(["stability"]) -> stability();
run(["stability", Target]) -> stability_diagnostic(Target, undefined);
run(["stability", Target, Repetitions]) ->
    stability_diagnostic(Target, Repetitions);
run(["credential-local"]) -> credential_local();
run(["credential-aggregate"]) -> credential_aggregate();
run(_) -> erlang:error({usage,
                        "--self-test | hostile | stability [target [runs]] | "
                        "credential-local | credential-aggregate"}).

hostile() ->
    Matrix = hostile_matrix(),
    Path = "build/fault/hostile-peer.json",
    remove_stale_report(Path),
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
                       package_runs => Results},
            write_report(Path, Report),
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
                       package_runs => Results,
                       first_failure => Failure},
            write_report(Path, Report),
            io:put_chars(base64:decode(maps:get(output_tail_base64, Failure))),
            erlang:error({hostile_test_failed,
                          maps:get(package, Failure),
                          maps:get(module, Failure),
                          maps:get(exit_status, Failure),
                          maps:get(output_sha256, Failure),
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
        Name, Directory, Ebin, Modules, Modules, TestCount, TailLimit, 0, 0).

run_hostile_modules(
    Name, _Directory, _Ebin, AllModules, [], TestCount, _TailLimit,
    CompletedModules, CompletedTests
) ->
    {ok, hostile_group_result(
        Name, AllModules, <<"Ready">>, TestCount,
        CompletedModules, CompletedTests)};
run_hostile_modules(
    Name, Directory, Ebin, AllModules, [Module | Rest], TestCount, TailLimit,
    CompletedModules, CompletedTests
) ->
    ModuleTests = beam_test_count(Ebin, Module),
    {Status, Output} = run_eunit_module(Directory, Ebin, Module),
    case Status of
        0 ->
            io:put_chars(Output),
            run_hostile_modules(
                Name, Directory, Ebin, AllModules, Rest, TestCount, TailLimit,
                CompletedModules + 1, CompletedTests + ModuleTests);
        _ ->
            Result = hostile_group_result(
                Name, AllModules, <<"Failed">>, TestCount,
                CompletedModules, CompletedTests),
            Failure = hostile_failure(
                Name, Module, Status, Output, TailLimit),
            {error, Result, Failure}
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
          shareable => false},
        bounded_output_evidence(Output, TailLimit)).

stability() ->
    Matrix = stability_matrix(),
    Path = "build/fault/stability.json",
    remove_stale_report(Path),
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
            write_report(Path, Report),
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
            write_report(Path, Report),
            io:put_chars(base64:decode(maps:get(output_tail_base64, Failure))),
            erlang:error({stability_test_failed,
                          maps:get(target, Failure),
                          maps:get(iteration, Failure),
                          maps:get(exit_status, Failure),
                          maps:get(output_sha256, Failure),
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
    remove_stale_report(Path),
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
            write_report(Path, Report),
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
            write_report(Path, Report),
            io:put_chars(base64:decode(maps:get(output_tail_base64, Failure))),
            erlang:error({stability_diagnostic_failed,
                          maps:get(target, Failure),
                          maps:get(iteration, Failure),
                          maps:get(exit_status, Failure),
                          maps:get(output_sha256, Failure),
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
    case run_stability_target(Target, TailLimit, 1) of
        {ok, Result} ->
            Completed = Completed0 + maps:get(completed_repetitions, Result),
            run_stability_targets(Rest, TailLimit, [Result | Results], Completed);
        {error, Result, Failure} ->
            Completed = Completed0 + maps:get(completed_repetitions, Result),
            {error, lists:reverse([Result | Results]), Completed, Failure}
    end.

run_stability_target(Target, TailLimit, Iteration) ->
    Directory = filename:absname(maps:get(directory, Target)),
    Ebin = filename:absname(maps:get(ebin, Target)),
    Module = maps:get(module, Target),
    Test = maps:get(test, Target),
    Repetitions = maps:get(repetitions, Target),
    ensure_test_function(Ebin, Module, Test),
    case Iteration > Repetitions of
        true ->
            {ok, stability_target_result(Target, <<"Ready">>, Repetitions)};
        false ->
            io:format("stability ~s: fresh BEAM ~B/~B~n",
                      [maps:get(name, Target), Iteration, Repetitions]),
            {Status, Output} = run_eunit_function(
                Directory, Ebin, Module, Test),
            case Status of
                0 -> run_stability_target(Target, TailLimit, Iteration + 1);
                _ ->
                    Completed = Iteration - 1,
                    Failure = stability_failure(
                        Target, Iteration, Status, Output, TailLimit),
                    {error,
                     stability_target_result(Target, <<"Failed">>, Completed),
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
          shareable => false},
        bounded_output_evidence(Output, TailLimit)).

ensure_test_function(Ebin, Module, Test) ->
    ensure_test_beam(Ebin, Module),
    Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    {ok, {Module, [{exports, Exports}]}} = beam_lib:chunks(Beam, [exports]),
    ensure(lists:member({Test, 0}, Exports),
           {missing_stability_test_export, Module, Test, Beam}).

run_eunit_function(Directory, Ebin, Module, Test) ->
    Descriptor = lists:flatten([
        "{timeout,240,fun ", atom_to_list(Module), ":",
        atom_to_list(Test), "/0}"
    ]),
    run_eunit_evaluation(Directory, Ebin, Descriptor).

bounded_output_evidence(Output, Limit) ->
    Size = byte_size(Output),
    TailSize = erlang:min(Size, Limit),
    Start = Size - TailSize,
    Tail = binary:part(Output, Start, TailSize),
    #{output_bytes => Size,
      output_sha256 => hex(crypto:hash(sha256, Output)),
      output_tail_bytes => TailSize,
      output_tail_base64 => base64:encode(Tail),
      output_tail_encoding => <<"base64">>,
      output_truncated => Size > Limit}.

remove_stale_report(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> erlang:error({cannot_remove_stale_report, Path, Reason})
    end.

credential_local() ->
    Groups = [
        {<<"quic_core">>, "packages/quic_core",
         "packages/quic_core/build/dev/erlang/quic_core/ebin",
         [public_loopback_test, tls_authentication_test, tls_engine_test,
          tls_key_exchange_test, tls_replay_guard_test, tls_resumption_test,
          tls_session_ticket_test]},
        {<<"http3">>, "packages/http3",
         "packages/http3/build/dev/erlang/http3/ebin",
         [client_test, server_test, transport_test]},
        {<<"http">>, ".", "build/dev/erlang/http/ebin",
         [tls_transport_test]}
    ],
    Results = [run_group(Group) || Group <- Groups],
    Evidence = credential_evidence(),
    Missing = [Name || {Name, false} <- Evidence],
    Platform = qualification_platform(),
    Otp = list_to_binary(erlang:system_info(otp_release)),
    QualifiedPlatform = lists:member(Platform, required_platforms()),
    Status = case Missing =:= [] andalso QualifiedPlatform of
        true -> <<"Ready">>;
        false -> <<"Blocked">>
    end,
    Report = #{status => Status,
               platform => Platform,
               otp => Otp,
               source_sha256 => source_digest(),
               package_runs => Results,
               evidence => maps:from_list(Evidence),
               missing => Missing,
               qualified_platform_label => QualifiedPlatform},
    Filename = binary_to_list(sanitize(Platform)) ++ "-otp" ++
               binary_to_list(Otp) ++ ".json",
    Path = filename:join("build/credential-matrix/local", Filename),
    write_report(Path, Report),
    io:format("credential local matrix (~s, OTP ~s): ~B tests, ~B gaps~n",
              [Platform, Otp, sum_tests(Results), length(Missing)]),
    case Status of
        <<"Ready">> -> ok;
        _ -> erlang:error({credential_matrix_incomplete,
                           #{missing => Missing,
                             qualified_platform_label => QualifiedPlatform}})
    end.

credential_aggregate() ->
    Required = [{Platform, Otp} || Platform <- required_platforms(),
                                   Otp <- [<<"28">>, <<"29">>]],
    Paths = filelib:wildcard("build/credential-matrix/local/*.json"),
    Reports = [json:decode(read(Path)) || Path <- Paths],
    Source = source_digest(),
    Missing = [#{platform => Platform, otp => Otp}
               || {Platform, Otp} <- Required,
                  not has_ready_report(Reports, Platform, Otp, Source)],
    Status = case Missing of [] -> <<"Ready">>; _ -> <<"Blocked">> end,
    Report = #{status => Status, source_sha256 => Source,
               required => [#{platform => P, otp => O} || {P, O} <- Required],
               supplied_reports => length(Reports), missing => Missing},
    write_report("build/credential-matrix/report.json", Report),
    case Status of
        <<"Ready">> ->
            io:format("credential matrix: all ~B platform/OTP rows ready~n",
                      [length(Required)]),
            ok;
        _ -> erlang:error({credential_platform_matrix_incomplete, Missing})
    end.

run_group({Name, Directory0, Ebin0, Modules}) ->
    Directory = filename:absname(Directory0),
    Ebin = filename:absname(Ebin0),
    lists:foreach(fun(Module) -> ensure_test_beam(Ebin, Module) end, Modules),
    TestCount = lists:sum([beam_test_count(Ebin, Module) || Module <- Modules]),
    ensure(TestCount > 0, {no_tests_in_group, Name}),
    %% A matrix row must not depend on module execution order or state leaked
    %% by an earlier module.  Run every module in a fresh BEAM while retaining
    %% its complete in-module sequence and cleanup assertions.
    lists:foreach(
      fun(Module) -> run_eunit_process(Name, Directory, Ebin, [Module]) end,
      Modules),
    #{package => Name, tests => TestCount,
      modules => [atom_to_binary(Module) || Module <- Modules]}.

ensure_test_beam(Ebin, Module) ->
    Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    ensure(filelib:is_regular(Beam), {missing_test_beam, Module, Beam}).

beam_test_count(Ebin, Module) ->
    Beam = filename:join(Ebin, atom_to_list(Module) ++ ".beam"),
    {ok, {Module, [{exports, Exports}]}} = beam_lib:chunks(Beam, [exports]),
    length([Name || {Name, Arity} <- Exports,
                    Arity =:= 0,
                    lists:suffix("_test", atom_to_list(Name))]).

run_eunit_process(Name, Directory, Ebin, Modules) ->
    ModulesText = lists:flatten(io_lib:format("~0tp", [Modules])),
    Descriptor = lists:flatten(["{timeout,240,", ModulesText, "}"]),
    {Status, Output} = run_eunit_evaluation(Directory, Ebin, Descriptor),
    case Status of
        0 -> io:put_chars(Output);
        _ -> erlang:error({eunit_group_failed, Name, Status, Output})
    end.

run_eunit_module(Directory, Ebin, Module) ->
    ModulesText = lists:flatten(io_lib:format("~0tp", [[Module]])),
    Descriptor = lists:flatten(["{timeout,240,", ModulesText, "}"]),
    run_eunit_evaluation(Directory, Ebin, Descriptor).

run_eunit_evaluation(Directory, Ebin, Descriptor) ->
    Paths0 = group_code_paths(Ebin),
    Paths = [Ebin | lists:delete(Ebin, Paths0)],
    run_eunit_with_paths(Directory, Paths, Descriptor).

run_eunit_with_paths(Directory, Paths, Descriptor) ->
    Erl = case os:find_executable("erl") of
        false -> erlang:error(erl_not_found);
        Path -> Path
    end,
    Evaluation = lists:flatten([
        "Result=eunit:test(", Descriptor, ",[{scale_timeouts,24}]),",
        "halt(case Result of ok->0;error->1 end)."
    ]),
    PathArguments = case Paths of
        [] -> [];
        _ -> ["-pa" | Paths]
    end,
    Arguments = ["-noshell"] ++ PathArguments ++ ["-eval", Evaluation],
    Port = open_port({spawn_executable, Erl},
                     [binary, exit_status, use_stdio, stderr_to_stdout,
                      {args, Arguments}, {cd, Directory}]),
    collect_eunit(Port, []).

collect_eunit(Port, Output) ->
    receive
        {Port, {data, Bytes}} -> collect_eunit(Port, [Bytes | Output]);
        {Port, {exit_status, Status}} ->
            {Status, iolist_to_binary(lists:reverse(Output))}
    after 600000 ->
        port_close(Port),
        {124, iolist_to_binary(lists:reverse(Output))}
    end.

credential_evidence() ->
    Sources = credential_sources(),
    [
        {<<"rsa_pss_certificate_live">>,
         matches(Sources, <<"rsa_pss_certificate.*_test">>)},
        {<<"ecdsa_p256_certificate_live">>,
         matches(Sources, <<"ecdsa_p256_certificate.*_test">>)},
        {<<"ecdsa_p384_certificate_live">>,
         matches(Sources, <<"ecdsa_p384_certificate.*_test">>)},
        {<<"ed25519_certificate_live">>,
         matches(Sources, <<"public_mtls_required_and_optional_round_trip_test">>)},
        {<<"mtls_disabled_optional_required">>,
         matches(Sources, <<"optional_client_certificate_accepts_anonymous_client_test">>)
         andalso matches(Sources, <<"required_client_certificate_rejects_anonymous_client_test">>)
         andalso matches(Sources, <<"completes_authenticated_client_server_handshake_test">>)},
        {<<"direct_and_hrr">>,
         matches(Sources, <<"completes_one_hello_retry_request.*_test">>)
         andalso matches(Sources, <<"completes_authenticated_client_server_handshake_test">>)},
        {<<"certificate_rotation">>,
         matches(Sources, <<"certificate_reload_is_atomic.*_test">>)},
        {<<"resumption_and_zero_rtt_fallback">>,
         matches(Sources, <<"completes_psk_resumption.*_test">>)
         andalso matches(Sources, <<"external_replay_guard_failure_falls_back.*_test">>)},
        {<<"expiry_revocation_mismatch">>,
         matches(Sources, <<"rejects_tampered_expired_or_cross_origin_tickets_test">>)
         andalso matches(Sources, <<"rejects_wrong_hostname_untrusted_chain.*_test">>)}
    ].

credential_sources() ->
    Paths = filelib:fold_files("packages/quic_core/test", ".*\\.gleam$", true,
                               fun(Path, Acc) -> [Path | Acc] end, []),
    Http3 = filelib:fold_files("packages/http3/test", ".*\\.gleam$", true,
                               fun(Path, Acc) -> [Path | Acc] end, Paths),
    Root = filelib:fold_files("test", ".*\\.gleam$", true,
                              fun(Path, Acc) -> [Path | Acc] end, Http3),
    iolist_to_binary([read(Path) || Path <- Root]).

matches(Bytes, Pattern) ->
    case re:run(Bytes, Pattern, [caseless]) of
        {match, _} -> true;
        nomatch -> false
    end.

required_platforms() ->
    [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>].

qualification_platform() ->
    case os:getenv("QUALIFICATION_PLATFORM") of
        false -> inferred_platform();
        Value -> unicode:characters_to_binary(Value)
    end.

inferred_platform() ->
    case os:type() of
        {unix, darwin} -> <<"local-macos">>;
        {unix, _} -> <<"local-linux">>;
        {win32, _} -> <<"local-windows">>
    end.

has_ready_report(Reports, Platform, Otp, Source) ->
    lists:any(fun(Report) ->
        maps:get(<<"status">>, Report, <<>>) =:= <<"Ready">>
        andalso maps:get(<<"platform">>, Report, <<>>) =:= Platform
        andalso maps:get(<<"otp">>, Report, <<>>) =:= Otp
        andalso maps:get(<<"source_sha256">>, Report, <<>>) =:= Source
    end, Reports).

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

sum_tests(Results) ->
    lists:sum([maps:get(tests, Result) || Result <- Results]).

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
    ensure(maps:get(output_tail_bytes, Evidence) =:= 4,
           self_test_tail_size),
    ensure(maps:get(output_tail_base64, Evidence) =:= <<"Njc4OQ==">>,
           self_test_tail_value),
    ensure(maps:get(output_truncated, Evidence) =:= true,
           self_test_tail_truncation),
    ensure(byte_size(maps:get(output_sha256, Evidence)) =:= 64,
           self_test_output_digest),
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
    ensure(maps:get(shareable, Failure) =:= false,
           self_test_failure_shareability),
    {InjectedStatus, InjectedOutput} = run_eunit_with_paths(
        filename:absname("."), [],
        "{timeout,1,fun() -> erlang:error(injected_stability_failure) end}"),
    ensure(InjectedStatus =:= 1, self_test_injected_failure_status),
    ensure(binary:match(InjectedOutput, <<"injected_stability_failure">>)
           =/= nomatch,
           self_test_injected_failure_output),
    InjectedEvidence = bounded_output_evidence(InjectedOutput, 1024),
    ensure(maps:get(output_bytes, InjectedEvidence) > 0,
           self_test_injected_failure_evidence),
    HostileFailure = hostile_failure(
        <<"http">>, http2_server_test, InjectedStatus, InjectedOutput, 1024),
    ensure(maps:get(package, HostileFailure) =:= <<"http">>,
           self_test_hostile_failure_package),
    ensure(maps:get(module, HostileFailure) =:= <<"http2_server_test">>,
           self_test_hostile_failure_module),
    ensure(maps:get(shareable, HostileFailure) =:= false,
           self_test_hostile_failure_shareability),
    SelfTestPath = "build/fault/test-matrix-self-test.json",
    write_report(SelfTestPath, #{status => <<"InjectedFailure">>}),
    ensure(filelib:is_regular(SelfTestPath), self_test_report_write),
    remove_stale_report(SelfTestPath),
    ensure(not filelib:is_regular(SelfTestPath), self_test_report_removal),
    remove_stale_report(SelfTestPath),
    io:format("qualification matrix self-test ok (8 adversarial schemas, "
              "diagnostic target selection, repetition overrides, isolated "
              "child failure, bounded evidence, and stale-report removal)~n"),
    ok.

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
