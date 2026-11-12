#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-compile(nowarn_unused_function).
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("command_capture.hrl").
-include("execution_beam_identity.hrl").

-define(CHILD_DEADLINE_MS, 120000).
-define(BUILD_DEADLINE_MS, 180000).
-define(OUTPUT_LIMIT_BYTES, 1048576).
-define(REPORT_LIMIT_BYTES, 33554432).
-define(RECEIPT_LIMIT_BYTES, 1048576).

main(Arguments) ->
    Root = filename:dirname(filename:dirname(
        filename:absname(escript:script_name()))),
    ok = file:set_cwd(Root),
    try run(Arguments) of
        ok -> ok
    catch
        _:_ ->
            io:format(standard_error,
                "HTTP3_MULTIPLEXING_EVIDENCE_CONTRACT_FAILED phase=~s~n",
                [safe_phase(get(http3_multiplexing_evidence_phase))]),
            halt(1)
    end.

run(["self-test"]) ->
    ok = validator_self_test(),
    io:put_chars(<<"HTTP3_MULTIPLEXING_EVIDENCE_SELF_TEST_READY\n">>),
    ok;
run(["runner-self-test"]) ->
    ok = validator_self_test(),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(
        filename:join(["build", "evidence",
                       "http3-multiplexing-attempts"]), Nonce),
    Root = maps:get(root, Lease),
    try
        #{sha256 := RunnerSha, source_sha256 := SourceSha} =
            compile_attested_runner(Lease),
        true = digest(RunnerSha),
        true = digest(SourceSha)
    after
        ok = execution_beam_release_attempt(Lease)
    end,
    true = execution_beam_path_absent(Root),
    io:put_chars(<<"HTTP3_MULTIPLEXING_ATTESTED_RUNNER_READY\n">>),
    ok;
run([Expectation])
  when Expectation =:= "red"; Expectation =:= "green" ->
    run_evidence(Expectation);
run(_) ->
    erlang:error(invalid_arguments).

run_evidence(Expectation) ->
    phase(invalidate_prior_report),
    Path = evidence_path(Expectation),
    InitialIdentity = evidence_begin(Path),
    ok = filelib:ensure_dir(Path),
    phase(validator_self_test),
    ok = validator_self_test(),
    EntrypointPath = filename:join("test", "http_test.gleam"),
    EntrypointBefore = file_sha256(EntrypointPath, 1048576),
    CanonicalEntrypoint = canonical_entrypoint_sha256(),
    CanonicalEntrypoint = EntrypointBefore,
    phase(tool_identity),
    Tools = pinned_tools(),
    phase(bash_identity),
    BashIdentity = bash_identity(Tools),
    phase(fresh_build),
    BuildProof = run_fresh_build(Tools),
    phase(fresh_verified_execution),
    {Verified0, AttemptRoot} =
        fresh_with_verified_build("http", fun(InitialSnapshot) ->
            run_verified(Expectation, InitialSnapshot, Tools)
        end),
    true = execution_beam_path_absent(AttemptRoot),
    EntrypointAfter = file_sha256(EntrypointPath, 1048576),
    EntrypointBefore = EntrypointAfter,
    FinalIdentity = evidence_identity(),
    InitialIdentity = FinalIdentity,
    ChildProof = maps:get(child_proof, Verified0),
    SupervisorIdentity = maps:get(process_supervisor, ChildProof),
    SupervisorSha = process_supervisor_sha256(),
    SupervisorSha = maps:get(source_sha256, SupervisorIdentity),
    SupervisorSha = file_sha256(
        filename:join("scripts", "process_supervisor.py"), 131072),
    PythonSha = file_sha256(maps:get(python, Tools), 134217728),
    PythonSha = maps:get(python_executable_sha256, SupervisorIdentity),
    phase(report_assembly),
    Report0 = report(
        Expectation, Verified0, InitialIdentity, FinalIdentity,
        EntrypointBefore, EntrypointAfter, Tools, BashIdentity,
        BuildProof, SupervisorSha, PythonSha),
    Report = evidence_complete(Report0, InitialIdentity),
    phase(report_validation),
    true = report_valid(Report, Expectation, InitialIdentity),
    false = report_valid(
        Report#{private => <<"fixture-private-marker">>},
        Expectation, InitialIdentity),
    Scenario = maps:get(scenario, Report),
    false = report_valid(
        Report#{scenario =>
            Scenario#{private => <<"fixture-private-marker">>}},
        Expectation, InitialIdentity),
    Bash = maps:get(bash, Report),
    false = report_valid(
        Report#{bash => Bash#{private => <<"fixture-private-marker">>}},
        Expectation, InitialIdentity),
    Toolchain = maps:get(toolchain, Report),
    false = report_valid(
        Report#{toolchain =>
            Toolchain#{<<"private">> => <<"fixture-private-marker">>}},
        Expectation, InitialIdentity),
    Process = maps:get(process, Report),
    false = report_valid(
        Report#{process =>
            Process#{private => <<"fixture-private-marker">>}},
        Expectation, InitialIdentity),
    false = report_valid(
        Report#{rerun_command => <<"Authorization: Bearer private-value">>},
        Expectation, InitialIdentity),
    false = report_valid(
        Report#{invocation_sha256 => binary:copy(<<"0">>, 64)},
        Expectation, InitialIdentity),
    phase(report_publication),
    ReportBytes = iolist_to_binary([json:encode(Report), $\n]),
    ok = execution_beam_publish_new(Path, ReportBytes, ?REPORT_LIMIT_BYTES),
    ReportBytes = execution_beam_read(Path, ?REPORT_LIMIT_BYTES),
    io:format(
        "http3_multiplexing_evidence kind=~s status=~s cases=3 "
        "source=~s otp=~s child_exit=~B tree_empty=true "
        "console_isolated=true~n",
        [maps:get(report_kind, Report), maps:get(status, Report),
         maps:get(<<"source_sha256">>, InitialIdentity),
         maps:get(<<"otp_version">>, maps:get(execution_environment, Report)),
         maps:get(child_exit_status, Report)]),
    ok.

run_verified(Expectation, InitialSnapshot, Tools) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(
        filename:join(["build", "evidence",
                       "http3-multiplexing-attempts"]), Nonce),
    AttemptRoot = maps:get(root, Lease),
    Result = try
        run_verified_leased(
            Expectation, InitialSnapshot, Tools, Nonce, Lease)
    after
        ok = execution_beam_release_attempt(Lease)
    end,
    true = execution_beam_path_absent(AttemptRoot),
    {Result#{attempt_artifacts_removed => true}, AttemptRoot}.

run_verified_leased(Expectation, InitialSnapshot, Tools, Nonce, Lease) ->
    phase(runner_compilation),
    Runner = compile_attested_runner(Lease),
    RunnerDirectory = maps:get(directory, Runner),
    BuildRoot = filename:absname(filename:join("build", "dev")),
    BuildPaths = lists:sort([
        filename:absname(Path)
        || Path <- filelib:wildcard(
            filename:join(["build", "dev", "erlang", "*", "ebin"]))
    ]),
    true = BuildPaths =/= [],
    true = length(BuildPaths) =:= length(lists:usort(BuildPaths)),
    phase(build_inventory),
    InventoryBefore = execution_beam_inventory(
        BuildPaths, BuildRoot, fun fresh_read/1),
    true = inventory_module_names_unique(InventoryBefore),
    InventorySha = maps:get(sha256, InventoryBefore),
    RequiredModules = required_modules(),
    AttemptRoot = maps:get(root, Lease),
    ReceiptPath = filename:join(AttemptRoot, "child-receipt.etf"),
    InvocationPath = filename:join(AttemptRoot, "invocation.etf"),
    RunnerSha = maps:get(sha256, Runner),
    RunnerSourceSha = maps:get(source_sha256, Runner),
    SourceSha = maps:get(
        <<"source_sha256">>, maps:get(report, InitialSnapshot)),
    true = digest(SourceSha),
    true = digest(RunnerSourceSha),
    Invocation = {http3_multiplexing_invocation_v2, ReceiptPath, Nonce,
                  SourceSha, RunnerSha, RunnerSourceSha, BuildRoot,
                  InventoryBefore, RequiredModules},
    InvocationBytes = term_to_binary(Invocation, [{minor_version, 2}]),
    ok = execution_beam_publish_new(
        InvocationPath, InvocationBytes, 16777216),
    InvocationBytes = execution_beam_read(InvocationPath, 16777216),
    InvocationSha = binary:encode_hex(
        crypto:hash(sha256, InvocationBytes), lowercase),
    Evaluation = lists:flatten(io_lib:format(
        "http3_multiplexing_attested_runner:run_from_file("
        "~0tp,~0tp,~0tp,~0tp,~0tp,~0tp).",
        [InvocationPath, InvocationSha, Nonce, SourceSha, RunnerSha,
         RunnerSourceSha])),
    Erl = maps:get(erl, Tools),
    Arguments = ["-noshell", "-noinput"] ++
        lists:append([["-pa", Path]
                      || Path <- [RunnerDirectory | BuildPaths]]) ++
        ["-eval", Evaluation],
    phase(attested_child_execution),
    Capture = command_capture_projected(
        Erl, Arguments, filename:absname("."), ?CHILD_DEADLINE_MS,
        ?OUTPUT_LIMIT_BYTES, tool_environment(Tools),
        fun project_output/1, fun red_projection_valid/1),
    #{status := Status, projection := Projection, proof := ChildProof} =
        validate_capture(Expectation, Capture),
    true = process_status_verified(Status, expected_status(Expectation),
                                   ChildProof),
    true = process_proof_valid(
        ChildProof, expected_status(Expectation), ?CHILD_DEADLINE_MS),
    phase(receipt_decode),
    ReceiptTerm = read_receipt(ReceiptPath),
    ok = validate_receipt_term(
        ReceiptTerm, Nonce, SourceSha, RunnerSourceSha, InvocationSha,
        Status, RunnerSha, InventorySha),
    Receipt = receipt_from_term(ReceiptTerm),
    ok = validate_receipt(
        Receipt, Nonce, SourceSha, RunnerSourceSha, InvocationSha,
        Status, RunnerSha, InventorySha),
    Marker = expected_marker(Expectation),
    Marker = maps:get(marker, Receipt),
    phase(post_execution_inventory),
    InventoryAfter = execution_beam_inventory(
        BuildPaths, BuildRoot, fun fresh_read/1),
    InventoryBefore = InventoryAfter,
    phase(final_fresh_verification),
    FinalSnapshot = fresh_verify_locked("http"),
    InitialSnapshotSha = maps:get(sha256, InitialSnapshot),
    InitialSnapshotSha = maps:get(sha256, FinalSnapshot),
    InitialSnapshotBytes = maps:get(bytes, InitialSnapshot),
    InitialSnapshotBytes = maps:get(bytes, FinalSnapshot),
    Attestation = maps:get(execution_beam_identity, Receipt),
    #{child_status => Status,
      child_projection => Projection,
      child_proof => ChildProof,
      build_identity_before => maps:get(report, InitialSnapshot),
      build_identity_after => maps:get(report, FinalSnapshot),
      build_manifest_sha256 => InitialSnapshotSha,
      execution_beam_inventory_sha256 => InventorySha,
      execution_beam_inventory_count => maps:get(count, InventoryBefore),
      loaded_beam_sha256 => maps:get(loaded_beam_sha256, Attestation),
      loaded_beam_count => maps:get(loaded_beam_count, Attestation),
      runner_sha256 => RunnerSha,
      runner_source_sha256 => RunnerSourceSha,
      invocation_sha256 => InvocationSha,
      receipt_schema => maps:get(schema, Receipt),
      counter_summary => maps:get(counters, Receipt),
      marker => Marker,
      completed => maps:get(completed, Receipt)}.

compile_attested_runner(Lease) ->
    Root = maps:get(root, Lease),
    Directory = filename:join(Root, "runner"),
    SourceDirectory = filename:join(Root, "runner-source"),
    ok = file:make_dir(Directory),
    ok = file:make_dir(SourceDirectory),
    Names = ["http3_multiplexing_attested_runner.erl",
             "execution_beam_identity.hrl",
             "evidence_publication.hrl", "canonical_etf_wire.hrl"],
    Captured = [{Name, fresh_read(filename:join("scripts", Name))}
                || Name <- Names],
    lists:foreach(fun({Name, Bytes}) ->
        ok = execution_beam_publish_new(
            filename:join(SourceDirectory, Name), Bytes, 8388608)
    end, Captured),
    CompileResult = compile:file(
        filename:join(SourceDirectory,
                      "http3_multiplexing_attested_runner.erl"),
        [binary, return_errors, return_warnings, {i, SourceDirectory}]),
    {Module, Binary} = case CompileResult of
        {ok, CompiledModule, CompiledBinary, []} ->
            {CompiledModule, CompiledBinary};
        {ok, _, _, _} -> erlang:error(attested_runner_compiler_warning);
        {error, _, _} -> erlang:error(attested_runner_compilation_failed);
        _ -> erlang:error(attested_runner_compilation_result_invalid)
    end,
    http3_multiplexing_attested_runner = Module,
    lists:foreach(fun({Name, Bytes}) ->
        Bytes = execution_beam_read(
            filename:join(SourceDirectory, Name), 8388608),
        Bytes = fresh_read(filename:join("scripts", Name))
    end, Captured),
    BeamPath = filename:join(Directory, atom_to_list(Module) ++ ".beam"),
    ok = execution_beam_publish_new(BeamPath, Binary, 4194304),
    Binary = execution_beam_read(BeamPath, 4194304),
    SourceContext = lists:foldl(fun({Name, Bytes}, Context) ->
        crypto:hash_update(Context,
            [unicode:characters_to_binary(Name), 0, Bytes, 0])
    end, crypto:hash_init(sha256), Captured),
    #{directory => Directory,
      sha256 => binary:encode_hex(crypto:hash(sha256, Binary), lowercase),
      source_sha256 => binary:encode_hex(
          crypto:hash_final(SourceContext), lowercase)}.

validate_capture("green", {ok, Output, Proof}) ->
    Projection = project_output(Output),
    true = green_projection_valid(Projection),
    #{status => 0, projection => Projection, proof => Proof};
validate_capture("red", {error, Projection, Proof}) when is_map(Projection) ->
    true = red_projection_valid(Projection),
    #{status => 42, projection => Projection, proof => Proof};
validate_capture(_, _) ->
    erlang:error(evidence_capture_contract_failed).

project_output(Bytes)
  when is_binary(Bytes), byte_size(Bytes) =< ?OUTPUT_LIMIT_BYTES ->
    Lines = semantic_lines(Bytes),
    Nonempty = [Line || Line <- Lines, Line =/= <<>>],
    Ready = expected_marker("green"),
    Red = expected_marker("red"),
    Unexpected = <<"HTTP3_MULTIPLEXING_UNEXPECTED_FINITE_PHASE">>,
    Family = [Line || Line <- Nonempty, is_outcome_marker(Line)],
    Recognized = [Line || Line <- Nonempty,
                          Line =:= Ready orelse Line =:= Red orelse
                          Line =:= Unexpected],
    #{schema => 1,
      ready => count_exact(Nonempty, Ready),
      red => count_exact(Nonempty, Red),
      unexpected => count_exact(Nonempty, Unexpected),
      family => length(Family),
      unrecognized => length(Nonempty) - length(Recognized),
      forbidden => length([Line || Line <- Nonempty,
                                   forbidden_output(Line)])}.

green_projection_valid(Projection) ->
    projection_shape_valid(Projection) andalso
        maps:get(ready, Projection) =:= 1 andalso
        maps:get(red, Projection) =:= 0 andalso
        maps:get(unexpected, Projection) =:= 0 andalso
        maps:get(family, Projection) =:= 1 andalso
        maps:get(unrecognized, Projection) =:= 0 andalso
        maps:get(forbidden, Projection) =:= 0.

red_projection_valid(Projection) ->
    projection_shape_valid(Projection) andalso
        maps:get(ready, Projection) =:= 0 andalso
        maps:get(red, Projection) =:= 1 andalso
        maps:get(unexpected, Projection) =:= 0 andalso
        maps:get(family, Projection) =:= 1 andalso
        maps:get(unrecognized, Projection) =:= 0 andalso
        maps:get(forbidden, Projection) =:= 0.

projection_shape_valid(Projection) when is_map(Projection) ->
    try
        [family, forbidden, ready, red, schema, unexpected, unrecognized] =
            lists:sort(maps:keys(Projection)),
        1 = maps:get(schema, Projection),
        true = lists:all(fun(Value) ->
            is_integer(Value) andalso Value >= 0 andalso Value =< 8
        end, [maps:get(ready, Projection), maps:get(red, Projection),
              maps:get(unexpected, Projection), maps:get(family, Projection),
              maps:get(unrecognized, Projection),
              maps:get(forbidden, Projection)]),
        true
    catch _:_ -> false end;
projection_shape_valid(_) -> false.

semantic_lines(Bytes) ->
    Normalized = binary:replace(Bytes, <<"\r\n">>, <<"\n">>, [global]),
    binary:split(Normalized, <<"\n">>, [global]).

count_exact(Lines, Marker) ->
    length([ok || Line <- Lines, Line =:= Marker]).

is_outcome_marker(<<"HTTP3_MULTIPLEXING_", _/binary>>) -> true;
is_outcome_marker(_) -> false.

forbidden_output(Bytes) ->
    re:run(Bytes,
        <<"(?i)(authorization\\s*:|cookie\\s*:|(?:bearer|basic)\\s+"
          "[A-Za-z0-9._~+/=-]{4,}|-----BEGIN (?:RSA |EC |OPENSSH )?"
          "PRIVATE KEY-----|#[Pp][Ii][Dd]<|#[Pp]ort<|#[Rr]ef<|"
          "<[0-9]+\\.[0-9]+\\.[0-9]+>|[A-Za-z]:[/\\\\]Users[/\\\\])">>,
        [{capture, none}, unicode]) =:= match.

read_receipt(Path) ->
    phase(receipt_read),
    Bytes = execution_beam_read(Path, ?RECEIPT_LIMIT_BYTES),
    phase(receipt_safe_decode),
    {ok, ReceiptTerm} = canonical_etf_decode(
        Bytes, ?RECEIPT_LIMIT_BYTES, 32, 8192),
    phase(receipt_canonical),
    ReceiptTerm.

receipt_from_term(
  {http3_multiplexing_receipt_v2,
   Nonce, SourceSha, RunnerSourceSha, InvocationSha,
   Status, Completed, Marker, CountersTerm, AttestationTerm}) ->
    #{schema => 2, nonce => Nonce,
      source_sha256 => SourceSha,
      runner_source_sha256 => RunnerSourceSha,
      invocation_sha256 => InvocationSha,
      status => Status,
      completed => Completed, marker => Marker,
      counters => counters_from_term(CountersTerm),
      execution_beam_identity => attestation_from_term(AttestationTerm)};
receipt_from_term(_) ->
    erlang:error(invalid_receipt_schema).

counters_from_term(
  {http3_multiplexing_counters_v1,
   CounterSchema, Repetitions, Multiplexed, Unavailable, Unexpected,
   {http3_multiplexing_fixture_roles_v1, BaselineRoles, FinalRoles},
   {http3_multiplexing_lifecycle_census_v1,
    Registered, Pooled, CallerOwned, Monitored, Pending,
    LifecycleVerifiedCases},
   {http3_multiplexing_resource_census_v1,
    WorkersBaseline, MemoryBaseline, WorkersFinal, MemoryFinal,
    ResourceVerifiedCases}}) ->
    #{schema => CounterSchema, repetitions => Repetitions,
      multiplexed => Multiplexed, unavailable => Unavailable,
      unexpected => Unexpected,
      fixture_roles => #{baseline => BaselineRoles, final => FinalRoles},
      lifecycle_baseline => #{registered => Registered, pooled => Pooled,
        caller_owned => CallerOwned, monitored => Monitored,
        pending => Pending, verified_cases => LifecycleVerifiedCases},
      resource_census => #{workers_baseline => WorkersBaseline,
        memory_baseline => MemoryBaseline, workers_final => WorkersFinal,
        memory_final => MemoryFinal, verified_cases => ResourceVerifiedCases}};
counters_from_term(_) ->
    erlang:error(invalid_receipt_counters_schema).

attestation_from_term(
  {http3_multiplexing_beam_identity_v1,
   RunnerSha, ExpectedInventorySha, LoadedBeamSha, LoadedBeamCount,
   LoadedBeamsVerified}) ->
    #{runner_sha256 => RunnerSha,
      expected_inventory_sha256 => ExpectedInventorySha,
      loaded_beam_sha256 => LoadedBeamSha,
      loaded_beam_count => LoadedBeamCount,
      loaded_beams_verified => LoadedBeamsVerified};
attestation_from_term(_) ->
    erlang:error(invalid_receipt_attestation_schema).

validate_receipt_term(
  {http3_multiplexing_receipt_v2,
   Nonce, SourceSha, RunnerSourceSha, InvocationSha,
   Status, 3, Marker, CountersTerm, AttestationTerm},
  Nonce, SourceSha, RunnerSourceSha, InvocationSha,
  Status, RunnerSha, InventorySha) ->
    phase(receipt_schema),
    ExpectedMarker = expected_marker_for_status(Status),
    ExpectedMarker = Marker,
    phase(receipt_counters),
    true = counter_summary_valid(Status, counters_from_term(CountersTerm)),
    phase(receipt_attestation),
    true = execution_beam_attestation_valid(
        attestation_from_term(AttestationTerm), RunnerSha, InventorySha),
    ok;
validate_receipt_term(_, _, _, _, _, _, _, _) ->
    phase(receipt_schema),
    erlang:error(invalid_receipt_schema).

receipt_term_valid(Term, Nonce, SourceSha, RunnerSourceSha, InvocationSha,
                   Status, RunnerSha, InventorySha) ->
    try
        ok = validate_receipt_term(
            Term, Nonce, SourceSha, RunnerSourceSha, InvocationSha,
            Status, RunnerSha, InventorySha),
        true
    catch _:_ -> false end.

self_test_receipt_term(Receipt) ->
    Counters = maps:get(counters, Receipt),
    Fixture = maps:get(fixture_roles, Counters),
    Lifecycle = maps:get(lifecycle_baseline, Counters),
    Resource = maps:get(resource_census, Counters),
    Attestation = maps:get(execution_beam_identity, Receipt),
    {http3_multiplexing_receipt_v2,
     maps:get(nonce, Receipt), maps:get(source_sha256, Receipt),
     maps:get(runner_source_sha256, Receipt),
     maps:get(invocation_sha256, Receipt), maps:get(status, Receipt),
     maps:get(completed, Receipt), maps:get(marker, Receipt),
     {http3_multiplexing_counters_v1,
      maps:get(schema, Counters), maps:get(repetitions, Counters),
      maps:get(multiplexed, Counters), maps:get(unavailable, Counters),
      maps:get(unexpected, Counters),
      {http3_multiplexing_fixture_roles_v1,
       maps:get(baseline, Fixture), maps:get(final, Fixture)},
      {http3_multiplexing_lifecycle_census_v1,
       maps:get(registered, Lifecycle), maps:get(pooled, Lifecycle),
       maps:get(caller_owned, Lifecycle), maps:get(monitored, Lifecycle),
       maps:get(pending, Lifecycle), maps:get(verified_cases, Lifecycle)},
      {http3_multiplexing_resource_census_v1,
       maps:get(workers_baseline, Resource),
       maps:get(memory_baseline, Resource),
       maps:get(workers_final, Resource), maps:get(memory_final, Resource),
       maps:get(verified_cases, Resource)}},
     {http3_multiplexing_beam_identity_v1,
      maps:get(runner_sha256, Attestation),
      maps:get(expected_inventory_sha256, Attestation),
      maps:get(loaded_beam_sha256, Attestation),
      maps:get(loaded_beam_count, Attestation),
      maps:get(loaded_beams_verified, Attestation)}}.

receipt_valid(Receipt, Nonce, SourceSha, RunnerSourceSha, InvocationSha,
              Status, RunnerSha, InventorySha) ->
    try
        [completed, counters, execution_beam_identity, invocation_sha256,
         marker, nonce, runner_source_sha256, schema, source_sha256, status] =
            lists:sort(maps:keys(Receipt)),
        2 = maps:get(schema, Receipt),
        Nonce = maps:get(nonce, Receipt),
        SourceSha = maps:get(source_sha256, Receipt),
        RunnerSourceSha = maps:get(runner_source_sha256, Receipt),
        InvocationSha = maps:get(invocation_sha256, Receipt),
        Status = maps:get(status, Receipt),
        3 = maps:get(completed, Receipt),
        true = counter_summary_valid(Status, maps:get(counters, Receipt)),
        ExpectedMarker = expected_marker_for_status(Status),
        ExpectedMarker = maps:get(marker, Receipt),
        true = execution_beam_attestation_valid(
            maps:get(execution_beam_identity, Receipt),
            RunnerSha, InventorySha),
        true
    catch _:_ -> false end.

validate_receipt(Receipt, Nonce, SourceSha, RunnerSourceSha, InvocationSha,
                 Status, RunnerSha, InventorySha) ->
    phase(receipt_schema),
    true = closed_map_keys(Receipt, [
        completed, counters, execution_beam_identity, marker, nonce, schema,
        source_sha256, runner_source_sha256, invocation_sha256, status]),
    2 = maps:get(schema, Receipt),
    Nonce = maps:get(nonce, Receipt),
    SourceSha = maps:get(source_sha256, Receipt),
    RunnerSourceSha = maps:get(runner_source_sha256, Receipt),
    InvocationSha = maps:get(invocation_sha256, Receipt),
    Status = maps:get(status, Receipt),
    3 = maps:get(completed, Receipt),
    ExpectedMarker = expected_marker_for_status(Status),
    ExpectedMarker = maps:get(marker, Receipt),
    phase(receipt_counters),
    true = counter_summary_valid(Status, maps:get(counters, Receipt)),
    phase(receipt_attestation),
    true = execution_beam_attestation_valid(
        maps:get(execution_beam_identity, Receipt), RunnerSha, InventorySha),
    ok.

expected_status("green") -> 0;
expected_status("red") -> 42.

expected_marker("green") -> <<"HTTP3_MULTIPLEXING_READY_COMPLETED_3">>;
expected_marker("red") ->
    <<"HTTP3_MULTIPLEXING_EXPECTED_RED_UNAVAILABLE_3">>.

expected_marker_for_status(0) -> expected_marker("green");
expected_marker_for_status(42) -> expected_marker("red");
expected_marker_for_status(_) ->
    <<"HTTP3_MULTIPLEXING_UNEXPECTED_FINITE_PHASE">>.

expected_counter_summary(Status) ->
    {Multiplexed, Unavailable} = case Status of
        0 -> {3, 0};
        42 -> {0, 3}
    end,
    #{schema => 1, repetitions => 3, multiplexed => Multiplexed,
      unavailable => Unavailable, unexpected => 0,
      fixture_roles => #{baseline => 0, final => 0},
      lifecycle_baseline => #{registered => 0, pooled => 0,
          caller_owned => 0, monitored => 0, pending => 0,
          verified_cases => 3},
      resource_census => #{workers_baseline => 0, memory_baseline => 0,
          workers_final => 0, memory_final => 0, verified_cases => 3}}.

counter_summary_valid(Status, Counters) ->
    try
        true = Status =:= 0 orelse Status =:= 42,
        true = closed_map_keys(Counters, [
            schema, repetitions, multiplexed, unavailable, unexpected,
            fixture_roles, lifecycle_baseline, resource_census]),
        Expected = expected_counter_summary(Status),
        Expected = Counters,
        true = closed_map_keys(
            maps:get(fixture_roles, Counters), [baseline, final]),
        true = closed_map_keys(maps:get(lifecycle_baseline, Counters), [
            registered, pooled, caller_owned, monitored, pending,
            verified_cases]),
        true = closed_map_keys(maps:get(resource_census, Counters), [
            workers_baseline, memory_baseline, workers_final, memory_final,
            verified_cases]),
        true
    catch _:_ -> false end.

required_modules() ->
    [<<"http3_multiplexing_probe">>,
     <<"http3_client_adapter_test">>,
     <<"http3_multiplexing_probe_ffi">>,
     <<"http_client_ffi">>,
     <<"http@client">>,
     <<"http@internal@http3@client">>,
     <<"http3@client">>,
     <<"http3@server">>].

pinned_tools() ->
    Gleam = required_executable("HTTP_GLEAM_EXECUTABLE"),
    Rebar = required_executable("HTTP_REBAR_EXECUTABLE"),
    Python = required_executable("HTTP_PROCESS_SUPERVISOR_PYTHON"),
    Bash = required_executable("HTTP_BASH_EXECUTABLE"),
    Erl = filename:join([code:root_dir(), "bin",
                         case os:type() of
                             {win32, _} -> "erl.exe";
                             _ -> "erl"
                         end]),
    true = filelib:is_regular(Erl),
    GleamSha = file_sha256(Gleam, 134217728),
    RebarSha = file_sha256(Rebar, 134217728),
    GleamSha = file_sha256(execution_tool_path("gleam"), 134217728),
    RebarSha = file_sha256(execution_tool_path("rebar3"), 134217728),
    #{gleam => Gleam, rebar => Rebar, python => Python, bash => Bash,
      erl => Erl, gleam_sha256 => GleamSha, rebar_sha256 => RebarSha,
      python_sha256 => file_sha256(Python, 134217728),
      bash_sha256 => file_sha256(Bash, 134217728),
      erl_sha256 => file_sha256(Erl, 134217728),
      build_tools => execution_build_tools(),
      runtime => execution_runtime()}.

bash_identity(Tools) ->
    Bash = maps:get(bash, Tools),
    {ok, Output, Proof} = command_capture(
        Bash, ["--version"], filename:absname("."), 10000,
        ?OUTPUT_LIMIT_BYTES, tool_environment(Tools)),
    true = process_proof_valid(Proof, 0, 10000),
    {match, [Version]} = re:run(Output,
        <<"^GNU bash, version ([0-9]+(?:\\.[0-9]+){1,3})">>,
        [multiline, {capture, [1], binary}]),
    #{version => Version, executable_sha256 => maps:get(bash_sha256, Tools),
      role => <<"fresh_build_shell">>, process => safe_process(Proof)}.

run_fresh_build(Tools) ->
    Bash = maps:get(bash, Tools),
    {ok, _Output, Proof} = command_capture(
        Bash, ["scripts/fresh_build.sh", "http"], filename:absname("."),
        ?BUILD_DEADLINE_MS, ?OUTPUT_LIMIT_BYTES, tool_environment(Tools)),
    true = process_proof_valid(Proof, 0, ?BUILD_DEADLINE_MS),
    safe_process(Proof).

tool_environment(Tools) ->
    Separator = case os:type() of {win32, _} -> ";"; _ -> ":" end,
    Existing = case os:getenv("PATH") of false -> ""; Value -> Value end,
    Directories = [filename:join(code:root_dir(), "bin"),
                   filename:dirname(maps:get(gleam, Tools)),
                   filename:dirname(maps:get(rebar, Tools)),
                   filename:dirname(maps:get(bash, Tools))],
    Pinned = string:join(Directories, Separator),
    Path = case Existing of
        "" -> Pinned;
        _ -> Pinned ++ Separator ++ Existing
    end,
    [{"PATH", Path}, {"ERL_AFLAGS", false}, {"ERL_FLAGS", false},
     {"ERL_ZFLAGS", false}].

process_proof_valid(Proof, ExpectedStatus, Deadline) ->
    process_map_valid(Proof)
        andalso process_status_verified(
        maps:get(exit_status, Proof, invalid), ExpectedStatus, Proof)
        andalso maps:get(deadline_ms, Proof, invalid) =:= Deadline
        andalso is_integer(maps:get(elapsed_ms, Proof, invalid))
        andalso maps:get(elapsed_ms, Proof) >= 0
        andalso maps:get(elapsed_ms, Proof) =< Deadline
        andalso maps:get(output_limit_bytes, Proof, invalid)
            =:= ?OUTPUT_LIMIT_BYTES
        andalso is_integer(maps:get(output_bytes, Proof, invalid))
        andalso maps:get(output_bytes, Proof) >= 0
        andalso maps:get(output_bytes, Proof) =< ?OUTPUT_LIMIT_BYTES
        andalso maps:get(output_digest_complete, Proof, false)
        andalso not maps:get(output_limit_exceeded, Proof, true)
        andalso not maps:get(timed_out, Proof, true)
        andalso maps:get(child_exit_observed, Proof, false)
        andalso maps:get(process_supervisor_protocol_valid, Proof, false)
        andalso maps:get(native_tree_empty, Proof, false)
        andalso maps:get(native_console_isolated, Proof, false)
        andalso not maps:get(native_descendant_outlived, Proof, true)
        andalso not maps:get(native_termination_requested, Proof, true).

safe_process(Proof) ->
    maps:with([
        schema, outcome, exit_status, deadline_ms, elapsed_ms, output_bytes,
        output_limit_bytes, output_limit_exceeded, output_digest_complete,
        terminal_control_bytes_removed, timed_out, child_exit_observed,
        process_supervisor, process_supervisor_protocol_valid,
        process_supervisor_failure_code,
        process_supervisor_attestation_failure,
        process_supervisor_reported_status,
        process_supervisor_observed_status, native_tree_empty,
        native_console_isolated, native_descendant_outlived,
        native_termination_requested
    ], Proof).

report(Expectation, Verified, InitialIdentity, FinalIdentity,
       EntrypointBefore, EntrypointAfter, Tools, BashIdentity,
       BuildProof, SupervisorSha, PythonSha) ->
    Status = case Expectation of
        "green" -> <<"Ready">>;
        "red" -> <<"ExpectedRed">>
    end,
    Kind = case Expectation of
        "green" -> <<"http3_multiplexing_regression">>;
        "red" -> <<"http3_multiplexing_expected_red">>
    end,
    QualificationEligible = Expectation =:= "green",
    FailureClassification = case Expectation of
        "green" -> <<"none">>;
        "red" -> <<"second_stream_unavailable_while_first_body_open">>
    end,
    Projection = maps:get(child_projection, Verified),
    ChildProof = maps:get(child_proof, Verified),
    #{schema => 3,
      report_kind => Kind,
      status => Status,
      qualification_eligible => QualificationEligible,
      shareable => true,
      expectation => list_to_binary(Expectation),
      scope => <<"one physical HTTP/3 connection, two concurrent streams">>,
      configured_tests => 3,
      completed_tests => maps:get(completed, Verified),
      failed_tests => case Expectation of "green" -> 0; "red" -> 3 end,
      failure_classification => FailureClassification,
      marker => maps:get(marker, Verified),
      marker_count => maps:get(family, Projection),
      secret_forbidden_count => maps:get(forbidden, Projection),
      child_exit_status => maps:get(child_status, Verified),
      deadline_milliseconds => ?CHILD_DEADLINE_MS,
      output_limit_bytes => ?OUTPUT_LIMIT_BYTES,
      scenario => #{
          maximum_physical_connections => 1,
          first_response_body_open => true,
          second_stream_acceptance_synchronized => true,
          exact_resource_rejection_required_for_red => true,
          verification_response_required_for_red => true,
          same_peer_required => true,
          same_connection_actor_required => true,
          server_completion_required => true,
          typed_cleanup_required => true},
      source_identity_before => InitialIdentity,
      source_identity_after => FinalIdentity,
      canonical_entrypoint_sha256_before => EntrypointBefore,
      canonical_entrypoint_sha256_after => EntrypointAfter,
      canonical_entrypoint_unchanged => true,
      build_identity_before => maps:get(build_identity_before, Verified),
      build_identity_after => maps:get(build_identity_after, Verified),
      build_manifest_sha256 => maps:get(build_manifest_sha256, Verified),
      execution_beam_inventory_sha256 =>
          maps:get(execution_beam_inventory_sha256, Verified),
      execution_beam_inventory_count =>
          maps:get(execution_beam_inventory_count, Verified),
      build_beam_modules_unique => true,
      loaded_beam_sha256 => maps:get(loaded_beam_sha256, Verified),
      loaded_beam_count => maps:get(loaded_beam_count, Verified),
      runner_sha256 => maps:get(runner_sha256, Verified),
      runner_source_sha256 => maps:get(runner_source_sha256, Verified),
      invocation_sha256 => maps:get(invocation_sha256, Verified),
      receipt_schema => maps:get(receipt_schema, Verified),
      counter_summary => maps:get(counter_summary, Verified),
      attempt_artifacts_removed =>
          maps:get(attempt_artifacts_removed, Verified),
      toolchain => maps:get(build_tools, Tools),
      erlang_executable_sha256 => maps:get(erl_sha256, Tools),
      bash => BashIdentity,
      process_supervisor_source_sha256 => SupervisorSha,
      python_interpreter_sha256 => PythonSha,
      build_process => BuildProof,
      process => safe_process(ChildProof),
      process_status_verified => true,
      fixture_owned_roles_converged => true,
      replay_platform => <<"windows">>,
      replay_environment => <<"codex_primary_runtime">>,
      rerun_command => rerun_command(Expectation)}.

report_valid(Report, Expectation, Identity) ->
    try
        true = closed_map_keys(Report, report_keys()),
        3 = maps:get(schema, Report),
        ExpectedKind = case Expectation of
            "green" -> <<"http3_multiplexing_regression">>;
            "red" -> <<"http3_multiplexing_expected_red">>
        end,
        ExpectedKind = maps:get(report_kind, Report),
        ExpectedStatus = case Expectation of
            "green" -> <<"Ready">>;
            "red" -> <<"ExpectedRed">>
        end,
        ExpectedStatus = maps:get(status, Report),
        ExpectedQualification = Expectation =:= "green",
        ExpectedQualification = maps:get(qualification_eligible, Report),
        true = maps:get(shareable, Report),
        true = bounded_binary(maps:get(scope, Report), 256),
        ExpectedScope = expected_scope(),
        ExpectedScope = maps:get(scope, Report),
        ExpectedExpectation = list_to_binary(Expectation),
        ExpectedExpectation = maps:get(expectation, Report),
        3 = maps:get(configured_tests, Report),
        3 = maps:get(completed_tests, Report),
        ExpectedFailed = case Expectation of "green" -> 0; "red" -> 3 end,
        ExpectedFailed = maps:get(failed_tests, Report),
        ExpectedFailure = expected_failure_classification(Expectation),
        ExpectedFailure = maps:get(failure_classification, Report),
        ExpectedMarker = expected_marker(Expectation),
        ExpectedMarker = maps:get(marker, Report),
        ExpectedChildStatus = expected_status(Expectation),
        ExpectedChildStatus = maps:get(child_exit_status, Report),
        1 = maps:get(marker_count, Report),
        0 = maps:get(secret_forbidden_count, Report),
        true = maps:get(process_status_verified, Report),
        true = maps:get(attempt_artifacts_removed, Report),
        true = maps:get(fixture_owned_roles_converged, Report),
        2 = maps:get(receipt_schema, Report),
        true = counter_summary_valid(
            ExpectedChildStatus, maps:get(counter_summary, Report)),
        ?CHILD_DEADLINE_MS = maps:get(deadline_milliseconds, Report),
        ?OUTPUT_LIMIT_BYTES = maps:get(output_limit_bytes, Report),
        true = scenario_valid(maps:get(scenario, Report)),
        true = maps:get(canonical_entrypoint_unchanged, Report),
        CanonicalEntrypoint = canonical_entrypoint_sha256(),
        CanonicalEntrypoint =
            maps:get(canonical_entrypoint_sha256_before, Report),
        CanonicalEntrypoint =
            maps:get(canonical_entrypoint_sha256_after, Report),
        Identity = maps:get(source_identity_before, Report),
        Identity = maps:get(source_identity_after, Report),
        Identity = maps:get(evidence_identity, Report),
        Runtime = execution_runtime(),
        Runtime = maps:get(execution_environment, Report),
        true = runtime_valid(Runtime),
        BuildIdentityBefore = maps:get(build_identity_before, Report),
        BuildIdentityBefore = maps:get(build_identity_after, Report),
        true = build_identity_valid(BuildIdentityBefore),
        CurrentTools = execution_build_tools(),
        CurrentTools = maps:get(toolchain, Report),
        true = toolchain_valid(CurrentTools),
        true = digest(maps:get(build_manifest_sha256, Report)),
        true = digest(maps:get(execution_beam_inventory_sha256, Report)),
        true = digest(maps:get(loaded_beam_sha256, Report)),
        true = digest(maps:get(runner_sha256, Report)),
        true = digest(maps:get(runner_source_sha256, Report)),
        true = digest(maps:get(invocation_sha256, Report)),
        true = digest(maps:get(erlang_executable_sha256, Report)),
        true = digest(maps:get(process_supervisor_source_sha256, Report)),
        true = digest(maps:get(python_interpreter_sha256, Report)),
        Count = maps:get(execution_beam_inventory_count, Report),
        true = is_integer(Count) andalso Count > 0 andalso Count =< 20000,
        true = maps:get(build_beam_modules_unique, Report),
        Loaded = maps:get(loaded_beam_count, Report),
        true = is_integer(Loaded) andalso Loaded > 0
            andalso Loaded =< Count,
        true = process_proof_valid(
            maps:get(process, Report), expected_status(Expectation),
            ?CHILD_DEADLINE_MS),
        true = process_proof_valid(
            maps:get(build_process, Report), 0, ?BUILD_DEADLINE_MS),
        true = bash_identity_valid(maps:get(bash, Report)),
        ChildSupervisor = maps:get(
            process_supervisor, maps:get(process, Report)),
        BuildSupervisor = maps:get(
            process_supervisor, maps:get(build_process, Report)),
        BashSupervisor = maps:get(
            process_supervisor,
            maps:get(process, maps:get(bash, Report))),
        ChildSupervisor = BuildSupervisor,
        ChildSupervisor = BashSupervisor,
        true = supervisor_identity_valid(ChildSupervisor),
        SupervisorSha = maps:get(process_supervisor_source_sha256, Report),
        SupervisorSha = maps:get(source_sha256, ChildSupervisor),
        PythonSha = maps:get(python_interpreter_sha256, Report),
        PythonSha = maps:get(python_executable_sha256, ChildSupervisor),
        true = bounded_binary(maps:get(rerun_command, Report), 4096),
        <<"windows">> = maps:get(replay_platform, Report),
        <<"codex_primary_runtime">> = maps:get(replay_environment, Report),
        <<"win32">> = maps:get(<<"os_family">>, Runtime),
        ExpectedReplay = rerun_command(Expectation),
        ExpectedReplay = maps:get(rerun_command, Report),
        true = report_binary_safe(Report),
        true
    catch _:_ -> false end.

report_keys() ->
    [schema, report_kind, status, qualification_eligible, shareable,
     expectation, scope, configured_tests, completed_tests, failed_tests,
     failure_classification, marker, marker_count, secret_forbidden_count,
     child_exit_status, deadline_milliseconds, output_limit_bytes, scenario,
     source_identity_before, source_identity_after,
     canonical_entrypoint_sha256_before,
     canonical_entrypoint_sha256_after, canonical_entrypoint_unchanged,
     build_identity_before, build_identity_after, build_manifest_sha256,
     execution_beam_inventory_sha256, execution_beam_inventory_count,
     build_beam_modules_unique,
     loaded_beam_sha256, loaded_beam_count, runner_sha256,
     runner_source_sha256, invocation_sha256, receipt_schema,
     attempt_artifacts_removed,
     counter_summary,
     toolchain, erlang_executable_sha256, bash,
     process_supervisor_source_sha256, python_interpreter_sha256,
     build_process, process, process_status_verified,
     fixture_owned_roles_converged, rerun_command,
     replay_platform, replay_environment,
     evidence_identity, execution_environment].

expected_scope() ->
    <<"one physical HTTP/3 connection, two concurrent streams">>.

expected_failure_classification("green") -> <<"none">>;
expected_failure_classification("red") ->
    <<"second_stream_unavailable_while_first_body_open">>.

scenario_valid(Scenario) ->
    try
        true = closed_map_keys(Scenario, [
            maximum_physical_connections, first_response_body_open,
            second_stream_acceptance_synchronized,
            exact_resource_rejection_required_for_red,
            verification_response_required_for_red,
            same_peer_required, same_connection_actor_required,
            server_completion_required, typed_cleanup_required]),
        1 = maps:get(maximum_physical_connections, Scenario),
        true = lists:all(fun(Key) -> maps:get(Key, Scenario) =:= true end,
            [first_response_body_open, second_stream_acceptance_synchronized,
             exact_resource_rejection_required_for_red,
             verification_response_required_for_red, same_peer_required,
             same_connection_actor_required, server_completion_required,
             typed_cleanup_required]),
        true
    catch _:_ -> false end.

bash_identity_valid(Bash) ->
    try
        true = closed_map_keys(
            Bash, [version, executable_sha256, role, process]),
        true = bounded_binary(maps:get(version, Bash), 64),
        match = re:run(maps:get(version, Bash),
            <<"^[0-9]+(?:\\.[0-9]+){1,3}$">>, [{capture, none}]),
        true = digest(maps:get(executable_sha256, Bash)),
        <<"fresh_build_shell">> = maps:get(role, Bash),
        true = process_proof_valid(maps:get(process, Bash), 0, 10000),
        true
    catch _:_ -> false end.

runtime_valid(Runtime) ->
    try
        true = closed_map_keys(Runtime, [
            <<"otp_version">>, <<"erts_version">>,
            <<"system_architecture">>, <<"os_family">>, <<"os_name">>,
            <<"word_size">>]),
        true = bounded_binary(maps:get(<<"otp_version">>, Runtime), 64),
        true = bounded_binary(maps:get(<<"erts_version">>, Runtime), 64),
        true = bounded_binary(
            maps:get(<<"system_architecture">>, Runtime), 256),
        true = bounded_binary(maps:get(<<"os_family">>, Runtime), 32),
        true = bounded_binary(maps:get(<<"os_name">>, Runtime), 32),
        WordSize = maps:get(<<"word_size">>, Runtime),
        true = WordSize =:= 4 orelse WordSize =:= 8,
        true
    catch _:_ -> false end.

toolchain_valid(Toolchain) ->
    try
        true = closed_map_keys(
            Toolchain, [<<"runtime">>, <<"gleam">>, <<"rebar3">>]),
        true = runtime_valid(maps:get(<<"runtime">>, Toolchain)),
        true = tool_valid(maps:get(<<"gleam">>, Toolchain)),
        true = tool_valid(maps:get(<<"rebar3">>, Toolchain)),
        true
    catch _:_ -> false end.

tool_valid(Tool) ->
    try
        true = closed_map_keys(
            Tool, [<<"declared_version">>, <<"executable_sha256">>]),
        true = bounded_binary(maps:get(<<"declared_version">>, Tool), 64),
        true = digest(maps:get(<<"executable_sha256">>, Tool)),
        true
    catch _:_ -> false end.

build_identity_valid(Build) ->
    try
        true = closed_map_keys(Build, [
            <<"schema">>, <<"package">>, <<"source_sha256">>,
            <<"source_files">>, <<"artifact_sha256">>,
            <<"artifact_files">>, <<"toolchain">>, <<"build_nonce">>,
            <<"prebuild_profile_state">>]),
        3 = maps:get(<<"schema">>, Build),
        <<"http">> = maps:get(<<"package">>, Build),
        true = digest(maps:get(<<"source_sha256">>, Build)),
        true = digest(maps:get(<<"artifact_sha256">>, Build)),
        true = toolchain_valid(maps:get(<<"toolchain">>, Build)),
        true = bounded_binary(maps:get(<<"build_nonce">>, Build), 128),
        <<"absent">> = maps:get(<<"prebuild_profile_state">>, Build),
        SourceFiles = maps:get(<<"source_files">>, Build),
        ArtifactFiles = maps:get(<<"artifact_files">>, Build),
        true = is_integer(SourceFiles) andalso SourceFiles > 0
            andalso SourceFiles =< 1000000,
        true = is_integer(ArtifactFiles) andalso ArtifactFiles > 0
            andalso ArtifactFiles =< 1000000,
        true
    catch _:_ -> false end.

process_map_valid(Process) ->
    closed_map_keys(Process, [
        schema, outcome, exit_status, deadline_ms, elapsed_ms, output_bytes,
        output_limit_bytes, output_limit_exceeded, output_digest_complete,
        terminal_control_bytes_removed, timed_out, child_exit_observed,
        process_supervisor, process_supervisor_protocol_valid,
        process_supervisor_failure_code,
        process_supervisor_attestation_failure,
        process_supervisor_reported_status,
        process_supervisor_observed_status, native_tree_empty,
        native_console_isolated, native_descendant_outlived,
        native_termination_requested]).

supervisor_identity_valid(Supervisor) ->
    try
        true = closed_map_keys(Supervisor, [
            source_sha256, python_executable_sha256, python_implementation,
            python_version, console_isolation]),
        ExpectedSupervisorSha = process_supervisor_sha256(),
        ExpectedSupervisorSha = maps:get(source_sha256, Supervisor),
        true = digest(maps:get(python_executable_sha256, Supervisor)),
        <<"CPython">> = maps:get(python_implementation, Supervisor),
        match = re:run(maps:get(python_version, Supervisor),
            <<"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$">>,
            [{capture, none}]),
        ExpectedIsolation = process_supervisor_isolation(),
        ExpectedIsolation = maps:get(console_isolation, Supervisor),
        true
    catch _:_ -> false end.

closed_map_keys(Map, Keys) when is_map(Map), is_list(Keys) ->
    lists:sort(maps:keys(Map)) =:= lists:sort(Keys);
closed_map_keys(_, _) -> false.

bounded_binary(Value, Maximum) ->
    is_binary(Value) andalso byte_size(Value) > 0
        andalso byte_size(Value) =< Maximum.

report_binary_safe(Report) ->
    Bytes = iolist_to_binary(json:encode(Report)),
    byte_size(Bytes) > 0 andalso byte_size(Bytes) =< ?REPORT_LIMIT_BYTES
        andalso not forbidden_output(Bytes)
        andalso binary:match(Bytes, <<"fixture-private-marker">>) =:= nomatch.

rerun_command(Expectation) ->
    Version = maps:get(<<"otp_version">>, execution_runtime()),
    iolist_to_binary([
        "powershell -NoProfile -Command \"",
        "$env:HTTP_GLEAM_EXECUTABLE=Join-Path $env:LOCALAPPDATA '",
        "mise\\installs\\gleam\\1.18.1\\gleam.exe'; ",
        "$env:HTTP_REBAR_EXECUTABLE=Join-Path $env:LOCALAPPDATA '",
        "mise\\installs\\rebar\\3.27.0\\rebar3'; ",
        "$env:HTTP_PROCESS_SUPERVISOR_PYTHON=Join-Path $env:USERPROFILE '",
        ".cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\",
        "python\\python.exe'; ",
        "$env:HTTP_BASH_EXECUTABLE=Join-Path $env:ProgramFiles '",
        "Git\\bin\\bash.exe'; ",
        "$env:PATH=(Split-Path $env:HTTP_GLEAM_EXECUTABLE),';',",
        "(Split-Path $env:HTTP_REBAR_EXECUTABLE),';',",
        "(Join-Path $env:LOCALAPPDATA 'mise\\installs\\erlang\\",
        Version, "\\bin'),';',$env:PATH -join ''; ",
        "& (Join-Path $env:LOCALAPPDATA '",
        "mise\\installs\\erlang\\", Version,
        "\\bin\\escript.exe') scripts/http3_multiplexing_evidence.escript ",
        Expectation, "\""]).

validator_self_test() ->
    Ready = <<(expected_marker("green"))/binary, "\n">>,
    Red = <<(expected_marker("red"))/binary, "\n">>,
    Unexpected = <<"HTTP3_MULTIPLEXING_UNEXPECTED_FINITE_PHASE\n">>,
    Mutated = <<"HTTP3_MULTIPLEXING_EXPECTED_RED_UNAVAILABLE_2\n">>,
    Secret = <<"Authorization: Bearer fixture-private-marker\n">>,
    true = green_projection_valid(project_output(Ready)),
    true = red_projection_valid(project_output(Red)),
    false = red_projection_valid(project_output(<<>>)),
    false = red_projection_valid(project_output(<<Red/binary, Red/binary>>)),
    false = red_projection_valid(project_output(Mutated)),
    false = red_projection_valid(project_output(Unexpected)),
    false = red_projection_valid(project_output(<<Red/binary, Secret/binary>>)),
    false = green_projection_valid(project_output(<<Ready/binary, Secret/binary>>)),
    false = red_status_projection_valid(1, project_output(Red)),
    false = red_status_projection_valid(43, project_output(Red)),
    false = red_status_projection_valid(124, project_output(Red)),
    false = red_status_projection_valid(125, project_output(Red)),
    true = red_status_projection_valid(42, project_output(Red)),
    Digest = binary:copy(<<"a">>, 64),
    Nonce = binary:copy(<<"b">>, 32),
    Attestation = #{
        runner_sha256 => Digest,
        expected_inventory_sha256 => Digest,
        loaded_beam_sha256 => Digest,
        loaded_beam_count => 1,
        loaded_beams_verified => true},
    Counters = expected_counter_summary(42),
    Receipt = #{schema => 2, nonce => Nonce,
                source_sha256 => Digest,
                runner_source_sha256 => Digest,
                invocation_sha256 => Digest,
                status => 42, completed => 3,
                counters => Counters,
                marker => expected_marker("red"),
                execution_beam_identity => Attestation},
    ReceiptTerm = self_test_receipt_term(Receipt),
    true = receipt_term_valid(
        ReceiptTerm, Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    Receipt = receipt_from_term(ReceiptTerm),
    ReceiptBytes = term_to_binary(ReceiptTerm, [{minor_version, 2}]),
    {ok, ReceiptTerm} = canonical_etf_decode(
        ReceiptBytes, ?RECEIPT_LIMIT_BYTES, 32, 8192),
    false = receipt_term_valid(
        erlang:append_element(ReceiptTerm, unexpected),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_term_valid(
        list_to_tuple(lists:droplast(tuple_to_list(ReceiptTerm))),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    Reordered0 = setelement(2, ReceiptTerm, element(5, ReceiptTerm)),
    Reordered = setelement(5, Reordered0, element(2, ReceiptTerm)),
    false = receipt_term_valid(
        Reordered, Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_term_valid(
        Receipt, Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_term_valid(
        setelement(1, ReceiptTerm, unknown_receipt_tag),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_term_valid(
        setelement(3, ReceiptTerm, binary:copy(<<"d">>, 64)),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_term_valid(
        setelement(4, ReceiptTerm, binary:copy(<<"e">>, 64)),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_term_valid(
        setelement(5, ReceiptTerm, binary:copy(<<"f">>, 64)),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    CountersTerm = element(9, ReceiptTerm),
    RolesTerm = element(7, CountersTerm),
    MutatedCounters = setelement(
        7, CountersTerm,
        setelement(1, RolesTerm, unknown_fixture_roles_tag)),
    false = receipt_term_valid(
        setelement(9, ReceiptTerm, MutatedCounters),
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    true = receipt_valid(
        Receipt, Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_valid(Receipt#{nonce => binary:copy(<<"c">>, 32)},
                          Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_valid(Receipt#{completed => 2},
                          Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_valid(Receipt#{marker => Mutated},
                          Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_valid(Receipt#{counters =>
        Counters#{unavailable => 2, unexpected => 1}},
        Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    false = receipt_valid(Receipt#{private => <<"fixture-private-marker">>},
                          Nonce, Digest, Digest, Digest, 42, Digest, Digest),
    true = closed_map_keys(#{known => true}, [known]),
    false = closed_map_keys(
        #{known => true, private => <<"fixture-private-marker">>}, [known]),
    true = report_binary_safe(#{known => true}),
    false = report_binary_safe(
        #{known => true, private => <<"fixture-private-marker">>}),
    true = module_names_unique([<<"alpha">>, <<"beta">>]),
    false = module_names_unique([<<"alpha">>, <<"alpha">>]),
    ok.

inventory_module_names_unique(Inventory) ->
    try
        Entries = maps:get(entries, Inventory),
        module_names_unique([maps:get(module, Entry) || Entry <- Entries])
    catch _:_ -> false end.

module_names_unique(Modules) when is_list(Modules) ->
    Modules =/= [] andalso length(Modules) =:= length(lists:usort(Modules));
module_names_unique(_) -> false.

red_status_projection_valid(42, Projection) ->
    red_projection_valid(Projection);
red_status_projection_valid(_, _) -> false.

required_executable(Name) ->
    case os:getenv(Name) of
        Path when is_list(Path), Path =/= [] ->
            Absolute = filename:absname(Path),
            true = filelib:is_regular(Absolute),
            Absolute;
        _ -> erlang:error(missing_pinned_executable)
    end.

file_sha256(Path, Maximum) ->
    Bytes = execution_beam_read(Path, Maximum),
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

digest(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 64 andalso
        re:run(Value, <<"^[0-9a-f]{64}$">>,
               [{capture, none}]) =:= match.

canonical_entrypoint_sha256() ->
    <<"41599d5e8e85f66fee935403ad17f1a5839994bce0fcfb6e3f150c5eaf59d248">>.

evidence_path(Expectation) ->
    filename:join(["build", "evidence",
        "http3-multiplexing-" ++ Expectation ++ "-otp" ++
        erlang:system_info(otp_release) ++ ".json"]).

phase(Name) ->
    put(http3_multiplexing_evidence_phase, Name),
    ok.

safe_phase(invalidate_prior_report) -> <<"invalidate_prior_report">>;
safe_phase(validator_self_test) -> <<"validator_self_test">>;
safe_phase(tool_identity) -> <<"tool_identity">>;
safe_phase(bash_identity) -> <<"bash_identity">>;
safe_phase(fresh_build) -> <<"fresh_build">>;
safe_phase(fresh_verified_execution) -> <<"fresh_verified_execution">>;
safe_phase(runner_compilation) -> <<"runner_compilation">>;
safe_phase(build_inventory) -> <<"build_inventory">>;
safe_phase(attested_child_execution) -> <<"attested_child_execution">>;
safe_phase(receipt_decode) -> <<"receipt_decode">>;
safe_phase(receipt_read) -> <<"receipt_read">>;
safe_phase(receipt_safe_decode) -> <<"receipt_safe_decode">>;
safe_phase(receipt_canonical) -> <<"receipt_canonical">>;
safe_phase(receipt_schema) -> <<"receipt_schema">>;
safe_phase(receipt_counters) -> <<"receipt_counters">>;
safe_phase(receipt_attestation) -> <<"receipt_attestation">>;
safe_phase(post_execution_inventory) -> <<"post_execution_inventory">>;
safe_phase(final_fresh_verification) -> <<"final_fresh_verification">>;
safe_phase(report_assembly) -> <<"report_assembly">>;
safe_phase(report_validation) -> <<"report_validation">>;
safe_phase(report_publication) -> <<"report_publication">>;
safe_phase(_) -> <<"startup">>.
