%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("runtime_matrix_evidence.hrl").

fault_verify_report(Mode, Report) ->
    Config = json:decode(fresh_read("qualification.json")),
    runtime_matrix_ensure(fault_report_valid(Mode, Report, Config,
        runtime_matrix_catalog(), evidence_identity()), invalid_fault_execution_evidence).

fault_report_valid(Mode, Report, Config, Catalogs, Identity) ->
    try
        Common = [schema, status, source_sha256, evidence_identity, execution_environment,
                  build_identities, runner_sha256, replay, shareable],
        Specific = case Mode of
            hostile -> [families, configured_packages, configured_tests, completed_tests,
                        completed_cases, package_runs];
            stability -> [configured_targets, configured_repetitions, completed_repetitions, target_runs]
        end,
        true = suite_exact_keys(Report, Common ++ Specific),
        1 = maps:get(<<"schema">>, Report),
        <<"Ready">> = maps:get(<<"status">>, Report),
        true = maps:get(<<"shareable">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report),
        true = runtime_matrix_hex(maps:get(<<"source_sha256">>, Report)),
        true = runtime_matrix_hex(maps:get(<<"runner_sha256">>, Report)),
        Replay = <<"escript scripts/test_matrix.escript ", (atom_to_binary(Mode))/binary>>,
        Replay = maps:get(<<"replay">>, Report),
        Runtime = maps:get(<<"execution_environment">>, Report),
        true = fault_runtime_valid(Runtime),
        Builds = maps:get(<<"build_identities">>, Report),
        true = suite_exact_keys(Builds, [http, http3, core]),
        true = lists:all(fun(Target) -> runtime_matrix_build_valid(maps:get(Target, Builds),
            Target, maps:get(Target, Catalogs), Runtime) end, [<<"http">>, <<"http3">>, <<"core">>]),
        Executions = case Mode of
            hostile -> fault_hostile_executions(Report, Config, Catalogs);
            stability -> fault_stability_executions(Report, Config, Catalogs)
        end,
        Nonces = [maps:get(<<"run_nonce">>, maps:get(<<"eunit">>, Run)) || Run <- Executions],
        true = Nonces =/= [] andalso length(Nonces) =:= length(lists:usort(Nonces)),
        true
    catch _:_ -> false end.

fault_runtime_valid(Runtime) ->
    Os = case maps:get(<<"os_name">>, Runtime) of
        <<"linux">> -> <<"ubuntu-24.04">>;
        <<"darwin">> -> <<"macos-15">>;
        <<"nt">> -> <<"windows-2025">>
    end,
    [Major | _] = binary:split(maps:get(<<"otp_version">>, Runtime), <<".">>, [global]),
    true = lists:member(Major, [<<"28">>, <<"29">>]),
    runtime_matrix_environment_valid(Runtime, #{os => Os, otp => binary_to_integer(Major)}).

fault_units(Package, Catalogs) ->
    Target = case Package of <<"quic_core">> -> <<"core">>; _ -> Package end,
    maps:get(units, maps:get(Target, Catalogs)).

fault_hostile_executions(Report, Config, Catalogs) ->
    Matrix = maps:get(<<"hostile_matrix">>, Config),
    true = maps:get(<<"families">>, Matrix) =:= maps:get(<<"families">>, Report),
    Packages = maps:get(<<"packages">>, Matrix),
    Runs = maps:get(<<"package_runs">>, Report),
    true = length(Packages) =:= length(Runs) andalso
           length(Packages) =:= maps:get(<<"configured_packages">>, Report),
    true = length(Packages) > 0,
    Executions = lists:append([fault_hostile_run(Run, Package, Catalogs)
                              || {Run, Package} <- lists:zip(Runs, Packages)]),
    Units = lists:sum([maps:get(<<"configured_units">>, Run) || Run <- Executions]),
    Cases = lists:sum([maps:get(<<"completed_tests">>, Run) || Run <- Executions]),
    Units = maps:get(<<"configured_tests">>, Report),
    Units = maps:get(<<"completed_tests">>, Report),
    Cases = maps:get(<<"completed_cases">>, Report),
    Executions.

fault_hostile_run(Run, Package, Catalogs) ->
    true = suite_exact_keys(Run, [package, status, tests, configured_modules,
        completed_modules, completed_tests, completed_cases, modules, executions]),
    Name = maps:get(<<"name">>, Package),
    Name = maps:get(<<"package">>, Run),
    <<"Ready">> = maps:get(<<"status">>, Run),
    Modules = maps:get(<<"modules">>, Package),
    Modules = maps:get(<<"modules">>, Run),
    true = Modules =/= [] andalso length(Modules) =:= length(lists:usort(Modules)),
    Count = length(Modules),
    Count = maps:get(<<"configured_modules">>, Run),
    Count = maps:get(<<"completed_modules">>, Run),
    Executions = maps:get(<<"executions">>, Run),
    Count = length(Executions),
    AllUnits = fault_units(Name, Catalogs),
    true = lists:all(fun({Execution, Module}) ->
        Units = [U || U <- AllUnits, maps:get(module, U) =:= Module],
        fault_execution_valid(Execution, Units, module, Module)
    end, lists:zip(Executions, Modules)),
    UnitsCount = lists:sum([maps:get(<<"configured_units">>, R) || R <- Executions]),
    UnitsCount = maps:get(<<"tests">>, Run),
    UnitsCount = maps:get(<<"completed_tests">>, Run),
    Cases = lists:sum([maps:get(<<"completed_tests">>, R) || R <- Executions]),
    Cases = maps:get(<<"completed_cases">>, Run),
    Executions.

fault_stability_executions(Report, Config, Catalogs) ->
    Targets = maps:get(<<"targets">>, maps:get(<<"stability_matrix">>, Config)),
    Runs = maps:get(<<"target_runs">>, Report),
    true = Targets =/= [] andalso length(Targets) =:= length(Runs) andalso
           length(Targets) =:= maps:get(<<"configured_targets">>, Report),
    Executions = lists:append([fault_stability_run(Run, Target, Catalogs)
                              || {Run, Target} <- lists:zip(Runs, Targets)]),
    Count = length(Executions),
    Count = maps:get(<<"configured_repetitions">>, Report),
    Count = maps:get(<<"completed_repetitions">>, Report),
    Executions.

fault_stability_run(Run, Target, Catalogs) ->
    true = suite_exact_keys(Run, [name, package, module, test, status,
        configured_repetitions, completed_repetitions, executions]),
    true = maps:with([<<"name">>, <<"package">>, <<"module">>, <<"test">>], Target) =:=
           maps:with([<<"name">>, <<"package">>, <<"module">>, <<"test">>], Run),
    <<"Ready">> = maps:get(<<"status">>, Run),
    Count = maps:get(<<"repetitions">>, Target),
    true = is_integer(Count) andalso Count > 0 andalso Count =< 1000,
    Count = maps:get(<<"configured_repetitions">>, Run),
    Count = maps:get(<<"completed_repetitions">>, Run),
    Executions = maps:get(<<"executions">>, Run),
    Count = length(Executions),
    Unit = #{module => maps:get(<<"module">>, Target),
             function => maps:get(<<"test">>, Target), kind => <<"test">>},
    true = lists:member(Unit, fault_units(maps:get(<<"package">>, Target), Catalogs)),
    true = lists:all(fun({Execution, Iteration}) ->
        fault_execution_valid(Execution, [Unit], iteration, Iteration)
    end, lists:zip(Executions, lists:seq(1, Count))),
    Executions.

fault_execution_valid(Execution, Units, Key, Value) ->
    try
        ProcessKeys = runtime_matrix_process_keys(),
        true = suite_exact_keys(Execution, [Key, exit_status, eunit, configured_units,
                                          completed_tests | ProcessKeys]),
        Value = maps:get(atom_to_binary(Key), Execution),
        0 = maps:get(<<"exit_status">>, Execution),
        true = Units =/= [] andalso length(Units) =:= maps:get(<<"configured_units">>, Execution),
        Child = maps:get(<<"eunit">>, Execution),
        Nonce = maps:get(<<"run_nonce">>, Child),
        true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32 andalso
               re:run(Nonce, <<"^[0-9A-Fa-f]{32}$">>, [{capture, none}]) =:= match,
        true = suite_child_valid(Child, Units, Nonce),
        true = maps:get(<<"completed_tests">>, Execution) =:= suite_completed_tests(Child),
        runtime_matrix_process_valid(maps:with([atom_to_binary(K) || K <- ProcessKeys], Execution))
    catch _:_ -> false end.

fault_evidence_self_test() ->
    {Stability, Hostile, Config, Catalogs, Identity} = fault_fixture(),
    Accept = fun(Mode, R) -> fault_report_valid(Mode, R, Config, Catalogs, Identity) end,
    true = Accept(stability, Stability),
    true = Accept(hostile, Hostile),
    [Target] = maps:get(<<"target_runs">>, Stability),
    [First, Second] = maps:get(<<"executions">>, Target),
    BadRuns = [[First], [First, First], [Second, First],
        [First, Second#{<<"exit_status">> => 1}],
        [First, Second#{<<"child_exit_observed">> => false}],
        [First, Second#{<<"completed_tests">> => 0}],
        [First, Second#{<<"output_tail_base64">> => <<"fixture-private-marker">>}],
        [First, Second#{<<"eunit">> => (maps:get(<<"eunit">>, Second))#{<<"failures_dropped">> => 1}}]],
    lists:foreach(fun(Runs) -> false = Accept(stability,
        Stability#{<<"target_runs">> => [Target#{<<"executions">> => Runs}]}) end, BadRuns),
    Replay = Second#{<<"eunit">> => maps:get(<<"eunit">>, First)},
    false = Accept(stability, Stability#{<<"target_runs">> => [Target#{<<"executions">> => [First, Replay]}]}),
    [Package] = maps:get(<<"package_runs">>, Hostile),
    false = Accept(hostile, Hostile#{<<"package_runs">> => [maps:remove(<<"executions">>, Package)]}),
    false = Accept(hostile, Hostile#{<<"package_runs">> => [Package#{<<"modules">> => [<<"never_run">>]}]}),
    false = Accept(hostile, Hostile#{<<"evidence_identity">> => #{}}),
    false = Accept(hostile, Hostile#{<<"raw_exception">> => <<"fixture-private-marker">>}),
    Builds = maps:get(<<"build_identities">>, Hostile),
    BadBuild = (maps:get(<<"http">>, Builds))#{<<"source_sha256">> => binary:copy(<<"B">>, 64)},
    false = Accept(hostile, Hostile#{<<"build_identities">> => Builds#{<<"http">> => BadBuild}}),
    %% Generators require real leaves. Ordinary entrypoints require exactly one.
    Units = maps:get(units, maps:get(<<"http">>, Catalogs)),
    [Unit] = Units,
    true = fault_execution_valid(First, Units, iteration, 1),
    false = fault_execution_valid(First, [Unit#{function => <<"unexecuted_test">>}], iteration, 1),
    io:format("fault evidence self-test ok (actual leaves, per-repetition nonce, compiler inventory, build and process bounds)~n"),
    ok.

fault_fixture() ->
    Hash = binary:copy(<<"A">>, 64),
    Identity = #{schema => 2, source_sha256 => Hash, files => 3},
    Runtime = execution_runtime(),
    Tool = fun(V) -> #{declared_version => V, executable_sha256 => Hash} end,
    Unit = #{module => <<"fixture_test">>, function => <<"case_test">>, kind => <<"test">>},
    Catalog = #{modules => [<<"fixture_test">>], units => [Unit], source_sha256 => Hash, source_files => 2},
    Catalogs = maps:from_list([{T, Catalog} || T <- [<<"http">>, <<"http3">>, <<"core">>]]),
    Builds = maps:from_list([{T, #{schema => 3, package => T, source_sha256 => Hash, source_files => 2,
        artifact_sha256 => Hash, artifact_files => 5,
        build_nonce => binary:copy(<<"1">>, 32),
        prebuild_profile_state => <<"absent">>,
        toolchain => #{runtime => Runtime,
        gleam => Tool(<<"1.18.1">>), rebar3 => Tool(<<"3.27.0">>)}}} || T <- maps:keys(Catalogs)]),
    Execution = fun(I) -> runtime_matrix_process_fixture(#{iteration => I, exit_status => 0, configured_units => 1, completed_tests => 1,
        output_bytes => 0, output_hashed_bytes => 0, output_limit_bytes => 8388608,
        output_digest_complete => true, output_limit_exceeded => false, timed_out => false,
        child_exit_observed => true, vm_process_heap_words => 33554432,
        vm_heap_includes_shared_binaries => true, crash_dumps_disabled => true,
        eunit => #{schema => 1, run_nonce => list_to_binary(io_lib:format("~32.16.0b", [I])),
            listener_completed => true, eunit_completed => true, unexpected_events => 0,
            failure_count => 0, failures => [], failures_dropped => 0,
            units => [Unit#{ordinal => 1, counts => #{started => 1, completed => 1, passed => 1,
                                                    failed => 0, skipped => 0, cancelled => 0}}]}}) end,
    Target = #{name => <<"fixture-stability">>, package => <<"http">>, module => <<"fixture_test">>,
               test => <<"case_test">>, repetitions => 2},
    Common = #{schema => 1, status => <<"Ready">>, source_sha256 => Hash, evidence_identity => Identity,
               execution_environment => Runtime, build_identities => Builds, runner_sha256 => Hash, shareable => true},
    Stability = Common#{replay => <<"escript scripts/test_matrix.escript stability">>,
        configured_targets => 1, configured_repetitions => 2, completed_repetitions => 2,
        target_runs => [(maps:remove(repetitions, Target))#{status => <<"Ready">>,
            configured_repetitions => 2, completed_repetitions => 2, executions => [Execution(1), Execution(2)]}]},
    Families = [<<"fixture">>],
    Hostile = Common#{replay => <<"escript scripts/test_matrix.escript hostile">>, families => Families,
        configured_packages => 1, configured_tests => 1, completed_tests => 1, completed_cases => 1,
        package_runs => [#{package => <<"http">>, status => <<"Ready">>, tests => 1, configured_modules => 1,
            completed_modules => 1, completed_tests => 1, completed_cases => 1, modules => [<<"fixture_test">>],
            executions => [(maps:remove(iteration, Execution(3)))#{module => <<"fixture_test">>}]}]},
    Config = #{hostile_matrix => #{families => Families, packages => [#{name => <<"http">>, modules => [<<"fixture_test">>]}]},
               stability_matrix => #{targets => [Target]}},
    {runtime_matrix_json(Stability), runtime_matrix_json(Hostile), runtime_matrix_json(Config),
     Catalogs, runtime_matrix_json(Identity)}.
