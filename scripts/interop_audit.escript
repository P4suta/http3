#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-compile({nowarn_unused_function, [
    {artifact_merge_campaign_expected, 1},
    {artifact_merge_campaign_receipt_path, 1},
    {artifact_merge_verify_campaign, 2},
    {artifact_merge_credential_expected, 0},
    {artifact_merge_verify_credential, 1},
    {artifact_merge_verify, 5},
    {artifact_merge_file_path, 1},
    {artifact_merge_output_path, 3}
]}).

-include("evidence_identity.hrl").
-include("evidence_publication.hrl").
-include("artifact_merge_evidence.hrl").
-include("interop_evidence.hrl").
-include("reader_boundary_fixture.hrl").

main(Arguments) ->
    try dispatch(Arguments) of
        ok -> ok
    catch Class:Reason:Stacktrace ->
        io:format(standard_error, "interop audit failed: ~s~n",
                  [json:encode(diagnostic_failure_details(
                      Class, Reason, Stacktrace))]),
        halt(1)
    end.

dispatch(["--self-test"]) -> self_test();
dispatch(["--failure-receipt-runtime-self-test"]) ->
    failure_receipt_runtime_self_test();
dispatch(["--driver-failure-self-test"]) -> driver_failure_self_test();
dispatch(["--verify-failures", Id, RunId]) ->
    verify_failure_evidence(Id, RunId);
dispatch(["--verify-published-failures"]) -> verify_published_failures();
dispatch(["--verify-published-failures-for", Id, Outcome]) ->
    verify_published_failures_for(Id, Outcome);
dispatch(["--driver-failure", Id, RunId, Phase, ExitStatus]) ->
    driver_failure(Id, RunId, Phase, ExitStatus);
dispatch(["--begin", Id, ObservedPin]) -> begin_peer(Id, ObservedPin);
dispatch(["--prepare", Id]) -> prepare_peer(Id);
dispatch(["--record", Id, RunId, Role, Scenario]) ->
    record_peer(Id, RunId, Role, Scenario);
dispatch(["--complete-daemon", Id, RunId, Role, Scenario]) ->
    complete_daemon(Id, RunId, Role, Scenario);
dispatch(["--finish", Id, RunId]) -> finish_peer(Id, RunId);
dispatch(["--fail", Id, RunId]) -> fail_peer(Id, RunId);
dispatch(["--fail", Id]) -> fail_peer_unconditionally(Id);
dispatch(["--verify-report"]) -> interop_verify_report();
dispatch([]) -> run();
dispatch(_) -> erlang:error(interop_audit_usage).

driver_failure(Id, RunId, Phase, ExitStatus) ->
    RunIdBytes = interop_run_id(RunId),
    Report = driver_failure_report(Id, RunIdBytes, Phase, ExitStatus),
    Path = filename:join(["build", "interop", "failures", Id, "driver.json"]),
    with_interop_state_lock(fun() ->
        ok = publish_driver_failure_and_invalidate(Path, "build/interop/report.json",
            interop_peer_path(Id), RunIdBytes, Report),
        verify_failure_evidence_locked(Id, RunIdBytes)
    end).

verify_failure_evidence(Id, RunId0) ->
    RunId = interop_run_id(RunId0),
    with_interop_state_lock(fun() ->
        verify_failure_evidence_locked(Id, RunId)
    end).

verify_failure_evidence_locked(Id, RunId) ->
    Peer = peer(Id),
    Identity = evidence_identity(),
    Source = maps:get(<<"source_sha256">>, Identity),
    Rows = interop_audit_failure_directory(Peer, Source, RunId, Identity),
    Receipt = interop_failure_receipt(Peer, RunId, Identity, Rows),
    Destination = interop_failure_audit_path(Id),
    ok = write_bytes_atomic(Destination,
                            [json:encode(Receipt), <<"\n">>]),
    io:format("interop failure evidence verified: ~s records=~B~n",
              [Id, length(Rows)]),
    ok.

interop_failure_receipt(Peer, RunId, Identity, Rows) ->
    ok = evidence_require_identity(
        #{<<"evidence_identity">> => Identity}, evidence_identity()),
    interop_failure_receipt_with_runtime(
        Peer, RunId, Identity, Rows, execution_runtime()).

interop_failure_receipt_with_runtime(Peer, RunId, Identity, Rows, Runtime) ->
    _ = interop_audit_execution_runtime(Runtime),
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    Source = maps:get(<<"source_sha256">>, Identity),
    Scenarios = [Row || Row <- Rows,
                         maps:get(kind, Row) =:= <<"scenario">>],
    Completed = length([Row || Row <- Scenarios,
        maps:get(completion_observed, Row) =:= true]),
    Receipt0 = #{schema => 1, status => <<"VerifiedFailure">>,
        peer => maps:get(<<"id">>, Peer), pin => maps:get(<<"pin">>, Peer),
        run_id => RunId, source_sha256 => Source,
        profile_sha256 => interop_file_digest("standards/interop-profile.json"),
        scope => #{expected_scenarios => length(interop_expected_scenarios(Peer)),
                   failure_records => length(Rows),
                   scenario_failures => length(Scenarios),
                   driver_failures => length(Rows) - length(Scenarios),
                   completion_records => Completed},
        failures => Rows,
        rerun_command => interop_failure_rerun_command(Id)},
    Receipt0#{evidence_identity => Identity,
              execution_environment => Runtime}.

verify_published_failures() ->
    with_interop_state_lock(fun verify_published_failures_locked/0).

verify_published_failures_for(Id, Outcome) ->
    _ = peer(Id),
    with_interop_state_lock(fun() ->
        Identity = evidence_identity(),
        FailureIds = validate_published_failures_locked(Identity),
        ok = interop_audit_failure_outcome(Id, Outcome, FailureIds),
        io:format("interoperability outcome evidence verified: "
                  "peer=~s outcome=~s failures=~B~n",
                  [Id, Outcome, length(FailureIds)]),
        ok
    end).

interop_audit_failure_outcome(_Id, "success", []) -> ok;
interop_audit_failure_outcome(Id, "failure", [Id]) -> ok;
interop_audit_failure_outcome(_Id, Outcome, _FailureIds)
        when Outcome =:= "success"; Outcome =:= "failure" ->
    erlang:error(missing_or_unexpected_failure_evidence);
interop_audit_failure_outcome(_Id, Outcome, _FailureIds)
        when Outcome =:= "cancelled"; Outcome =:= "skipped" ->
    erlang:error(incomplete_interop_step);
interop_audit_failure_outcome(_Id, _Outcome, _FailureIds) ->
    erlang:error(invalid_interop_step_outcome).

verify_published_failures_locked() ->
    Identity = evidence_identity(),
    FailureIds = validate_published_failures_locked(Identity),
    io:format("published interoperability failures verified: peers=~B~n",
              [length(FailureIds)]),
    ok.

validate_published_failures_locked(Identity) ->
    Peers = maps:get(<<"peers">>, interop_profile()),
    FailureIds = interop_directory_names_or_empty(
        filename:join(["build", "interop", "failures"])),
    ExpectedIds = [binary_to_list(maps:get(<<"id">>, Peer)) || Peer <- Peers],
    interop_ensure(lists:all(fun(Id) -> lists:member(Id, ExpectedIds) end,
                             FailureIds),
                   unknown_failure_peer_directory),
    AuditNames = interop_directory_names_or_empty(
        filename:join(["build", "interop", "failure-audits"])),
    ExpectedAuditNames = lists:sort([Id ++ ".json" || Id <- FailureIds]),
    interop_ensure(lists:sort(AuditNames) =:= ExpectedAuditNames,
                   missing_or_stale_failure_audit),
    lists:foreach(fun(Id) ->
        verify_published_failure_locked(Id, Identity)
    end, FailureIds),
    ok = evidence_require_identity(
        #{<<"evidence_identity">> => Identity}, evidence_identity()),
    FailureIds.

verify_published_failure_locked(Id, Identity) ->
    Peer = peer(Id),
    Receipt = evidence_json_decode(interop_read_bounded(
        interop_failure_audit_path(Id), 1048576)),
    interop_keys(Receipt, [<<"schema">>, <<"status">>, <<"peer">>, <<"pin">>,
        <<"run_id">>, <<"source_sha256">>, <<"profile_sha256">>, <<"scope">>,
        <<"failures">>, <<"rerun_command">>, <<"evidence_identity">>,
        <<"execution_environment">>]),
    RunId = interop_run_id(maps:get(<<"run_id">>, Receipt)),
    Source = maps:get(<<"source_sha256">>, Identity),
    Rows = interop_audit_failure_directory(Peer, Source, RunId, Identity),
    verify_failure_receipt_value(Receipt, Peer, RunId, Identity, Rows).

verify_failure_receipt_value(Receipt, Peer, RunId, Identity, Rows) ->
    Runtime = maps:get(<<"execution_environment">>, Receipt),
    _ = interop_audit_execution_runtime(Runtime),
    Expected = interop_failure_receipt_with_runtime(
        Peer, RunId, Identity, Rows, Runtime),
    interop_ensure(Receipt =:= evidence_json_decode(iolist_to_binary(
        json:encode(Expected))), stale_or_invalid_failure_audit),
    ok.

failure_receipt_runtime_self_test() ->
    _ = interop_audit_execution_runtime(execution_runtime()),
    Identity = evidence_identity(),
    [Peer | _] = maps:get(<<"peers">>, interop_profile()),
    [Scenario | _] = interop_expected_scenarios(Peer),
    RunId = binary:copy(<<"9">>, 64),
    Rows = [#{kind => <<"driver">>, phase => <<"execution">>,
              exit_status => 1, completion_observed => false},
            #{kind => <<"scenario">>,
              role => maps:get(<<"role">>, Scenario),
              scenario => maps:get(<<"scenario">>, Scenario),
              phase => <<"execution">>, result => <<"failed">>,
              exit_status => 1, completion_observed => false}],
    ImportedRuntime = #{<<"otp_version">> => interop_expected_otp_version(<<"29">>),
        <<"erts_version">> => <<"17.0">>, <<"os_family">> => <<"unix">>,
        <<"os_name">> => <<"linux">>,
        <<"system_architecture">> => <<"x86_64-pc-linux-gnu">>,
        <<"word_size">> => 8},
    Imported = evidence_json_decode(iolist_to_binary(json:encode(
        interop_failure_receipt_with_runtime(
            Peer, RunId, Identity, Rows, ImportedRuntime)))),
    ok = verify_failure_receipt_value(
        Imported, Peer, RunId, Identity, Rows),
    RuntimeMutants = [
        ImportedRuntime#{<<"private">> => <<"private-runtime-canary">>},
        ImportedRuntime#{<<"otp_version">> => <<"27.3">>},
        ImportedRuntime#{<<"otp_version">> => <<"29.0.5">>},
        ImportedRuntime#{<<"os_family">> => <<"win32">>},
        ImportedRuntime#{<<"word_size">> => true},
        ImportedRuntime#{<<"system_architecture">> => <<"private path">>}
    ],
    lists:foreach(fun(BadRuntime) ->
        rejected(fun() -> interop_failure_receipt_with_runtime(
            Peer, RunId, Identity, Rows, BadRuntime)
        end, invalid_failure_receipt_runtime_accepted)
    end, RuntimeMutants),
    io:format("cross-environment failure receipt accepted; "
              "runtime_mutants=~B rejected~n", [length(RuntimeMutants)]).

failure_outcome_contract_self_test(Peer) ->
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    ok = interop_audit_failure_outcome(Id, "success", []),
    ok = interop_audit_failure_outcome(Id, "failure", [Id]),
    Mutants = [{Id, "success", [Id]}, {Id, "failure", []},
        {Id, "failure", ["unrelated-peer"]},
        {Id, "cancelled", [Id]}, {Id, "skipped", []},
        {Id, "unknown", []}],
    lists:foreach(fun({PeerId, Outcome, FailureIds}) ->
        rejected(fun() -> interop_audit_failure_outcome(
            PeerId, Outcome, FailureIds)
        end, invalid_failure_outcome_accepted)
    end, Mutants),
    io:format("interop workflow outcome controls: valid=2 mutants=~B~n",
              [length(Mutants)]).

interop_directory_names_or_empty(Directory) ->
    Absolute = filename:absname(Directory),
    case interop_optional_directory_info(Absolute) of
        missing -> [];
        {present, _Info} ->
            Before = evidence_directory_info(Absolute),
            Names = case file:list_dir(Absolute) of
                {ok, Entries} when length(Entries) =< 257 -> lists:sort(Entries);
                {ok, _} -> erlang:error(interop_directory_entry_limit);
                {error, _} -> erlang:error(unreadable_interop_directory)
            end,
            After = evidence_directory_info(Absolute),
            interop_ensure(evidence_file_identity(Before) =:=
                           evidence_file_identity(After),
                           interop_directory_changed_while_reading),
            Names
    end.

interop_optional_directory_info(Path) ->
    interop_optional_directory_components(filename:split(Path), "").

interop_optional_directory_components([], _Parent) ->
    erlang:error(unsafe_interop_directory);
interop_optional_directory_components([Name | Rest], Parent) ->
    Current = interop_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case Rest of
                [] -> {present, Info};
                _ -> interop_optional_directory_components(Rest, Current)
            end;
        {ok, _} -> erlang:error(unsafe_interop_directory);
        {error, enoent} -> missing;
        {error, _} -> erlang:error(unreadable_interop_directory)
    end.

interop_failure_audit_path(Id) -> filename:join(
    ["build", "interop", "failure-audits", Id ++ ".json"]).

interop_audit_failure_directory(Peer, Source, RunId, Identity) ->
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    Directory = filename:join(["build", "interop", "failures", Id]),
    interop_audit_failure_directory_at(
        Peer, Source, RunId, Identity, Directory).

interop_audit_failure_directory_at(Peer, Source, RunId, Identity, Directory) ->
    Before = evidence_directory_info(Directory),
    Names = case file:list_dir(Directory) of
        {ok, Entries} -> lists:sort(Entries);
        {error, _} -> erlang:error(unreadable_failure_directory)
    end,
    interop_ensure(Names =/= [] andalso length(Names) =< 257,
                   invalid_failure_file_count),
    interop_ensure(length(Names) =:= length(lists:usort(Names)),
                   duplicate_failure_file),
    Rows = [interop_audit_failure_file(
                Peer, Source, RunId, Identity, Directory, Name)
            || Name <- Names],
    After = evidence_directory_info(Directory),
    interop_ensure(evidence_file_identity(Before) =:=
                   evidence_file_identity(After),
                   failure_directory_changed_while_reading),
    Drivers = [Row || Row <- Rows, maps:get(kind, Row) =:= <<"driver">>],
    interop_ensure(length(Drivers) =:= 1, missing_or_duplicate_driver_failure),
    ScenarioKeys = [{maps:get(role, Row), maps:get(scenario, Row)}
        || Row <- Rows, maps:get(kind, Row) =:= <<"scenario">>],
    interop_ensure(length(ScenarioKeys) =:= length(lists:usort(ScenarioKeys)),
                   duplicate_scenario_failure),
    Rows.

interop_audit_failure_file(Peer, _Source, RunId, Identity, Directory,
                           "driver.json") ->
    Report = evidence_json_decode(interop_read_bounded(
        filename:join(Directory, "driver.json"), 1048576)),
    interop_keys(Report, [<<"schema">>, <<"kind">>, <<"status">>,
        <<"peer">>, <<"run_id">>, <<"phase">>, <<"exit_status">>,
        <<"evidence_identity">>]),
    interop_ensure(maps:get(<<"schema">>, Report) =:= 1 andalso
                   maps:get(<<"kind">>, Report) =:= <<"driver">> andalso
                   maps:get(<<"status">>, Report) =:= <<"Failed">>,
                   invalid_driver_failure_status),
    interop_ensure(maps:get(<<"peer">>, Report) =:= maps:get(<<"id">>, Peer),
                   wrong_driver_failure_peer),
    interop_ensure(maps:get(<<"run_id">>, Report) =:= RunId,
                   stale_driver_failure_run),
    interop_ensure(lists:member(maps:get(<<"phase">>, Report),
        [<<"setup">>, <<"execution">>, <<"verification">>, <<"cleanup">>]),
        invalid_driver_failure_phase),
    interop_integer(maps:get(<<"exit_status">>, Report), 1, 255),
    ok = evidence_require_identity(Report, Identity),
    #{kind => <<"driver">>, phase => maps:get(<<"phase">>, Report),
      exit_status => maps:get(<<"exit_status">>, Report),
      completion_observed => false};
interop_audit_failure_file(Peer, Source, RunId, _Identity, Directory, Name) ->
    NameBytes = unicode:characters_to_binary(Name),
    interop_ensure(re:run(NameBytes, <<"^[0-9a-f]{64}\\.json$">>,
                          [{capture, none}]) =:= match,
                   invalid_failure_filename),
    Report = evidence_json_decode(interop_read_bounded(
        filename:join(Directory, Name), 1048576)),
    ok = interop_audit_failure_report(Peer, Report, Source, RunId),
    Role = maps:get(<<"role">>, Report),
    Scenario = maps:get(<<"scenario">>, Report),
    ExpectedName = <<(interop_bytes_digest([Role, <<0>>, Scenario]))/binary,
                     ".json">>,
    interop_ensure(NameBytes =:= ExpectedName, wrong_failure_filename),
    Completion = maps:get(<<"completion">>, Report),
    Result = maps:get(<<"result">>, Report),
    #{kind => <<"scenario">>, role => Role, scenario => Scenario,
      phase => maps:get(<<"phase">>, Report),
      result_kind => maps:get(<<"kind">>, Result),
      exit_status => maps:get(<<"exit_status">>, Result),
      completion_observed => is_map(Completion)}.

interop_failure_rerun_command("curl-h1-h2") -> <<"mise run interop-curl">>;
interop_failure_rerun_command("nghttp2-h2") -> <<"mise run interop-nghttp2">>;
interop_failure_rerun_command("aioquic-h3") -> <<"mise run interop-aioquic">>;
interop_failure_rerun_command("quic-go-h3") -> <<"mise run interop-quicgo">>;
interop_failure_rerun_command("ngtcp2-nghttp3-h3") -> <<"mise run interop-ngtcp2">>;
interop_failure_rerun_command("quiche-h3") -> <<"mise run interop-quiche">>;
interop_failure_rerun_command("chromium") -> <<"mise run interop-chromium">>;
interop_failure_rerun_command("firefox") -> <<"mise run interop-firefox">>;
interop_failure_rerun_command("masque-independent") -> <<"mise run interop-masque">>;
interop_failure_rerun_command("ohttp-go") -> <<"mise run interop-ohttp-go">>;
interop_failure_rerun_command("ohttp-typescript") ->
    <<"mise run interop-ohttp-typescript">>.

publish_driver_failure_and_invalidate(Path, Aggregate, PeerPath, RunId, Report) ->
    %% Invalidate readiness before publishing a failure. Do not import and
    %% rewrite arbitrary fields from the former peer report.
    ok = invalidate_matching_state(PeerPath, Aggregate, RunId),
    publish_driver_failure(Path, Report).

driver_failure_report(Id, RunId, Phase, ExitStatus) ->
    interop_ensure(length(Id) =< 64 andalso
        re:run(Id, "^[a-z0-9][a-z0-9-]*$", [{capture, none}]) =:= match,
        invalid_driver_peer),
    _ = peer(Id),
    interop_ensure(lists:member(Phase, ["setup", "execution", "verification", "cleanup"]),
        invalid_driver_phase),
    interop_ensure(length(ExitStatus) >= 1 andalso length(ExitStatus) =< 3,
        invalid_driver_exit_status),
    Status = list_to_integer(ExitStatus),
    interop_ensure(Status >= 1 andalso Status =< 255 andalso
        integer_to_list(Status) =:= ExitStatus, invalid_driver_exit_status),
    #{schema => 1, kind => <<"driver">>, status => <<"Failed">>,
      peer => list_to_binary(Id), run_id => RunId,
      phase => list_to_binary(Phase),
      exit_status => Status, evidence_identity => evidence_identity()}.

publish_driver_failure(Path, Report) ->
    Identity = maps:get(evidence_identity, Report),
    Identity = evidence_identity(),
    write_bytes_atomic(Path, [json:encode(Report), <<"\n">>]).

driver_failure_self_test() ->
    Identity = evidence_identity(),
    [Peer | _] = maps:get(<<"peers">>, interop_profile()),
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    RunId = binary:copy(<<"a">>, 64),
    lists:foreach(fun(Phase) ->
        Report = driver_failure_report(Id, RunId, Phase, "255"),
        interop_ensure(lists:sort(maps:keys(Report)) =:=
            lists:sort([schema, kind, status, peer, run_id, phase,
                        exit_status, evidence_identity]),
            unexpected_driver_fields),
        Identity = maps:get(evidence_identity, Report),
        RunId = maps:get(run_id, Report),
        <<"Failed">> = maps:get(status, Report),
        255 = maps:get(exit_status, Report)
    end, ["setup", "execution", "verification", "cleanup"]),
    lists:foreach(fun({BadId, BadPhase, BadStatus}) ->
        rejected(fun() -> driver_failure_report(BadId, RunId, BadPhase, BadStatus) end,
                 invalid_driver_input_accepted)
    end, [{"unknown-private-canary", "cleanup", "1"},
          {"../private-canary", "cleanup", "1"},
          {Id, "private-canary", "1"}, {Id, "cleanup", "0"},
          {Id, "cleanup", "-1"}, {Id, "cleanup", "256"},
          {Id, "cleanup", "01"}, {Id, "cleanup", "1e2"},
          {Id, "cleanup", "true"}]),
    Nonce = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16), lowercase)),
    Directory = filename:join(["build", "interop-self-test", "driver", Nonce]),
    Path = filename:join(Directory, "driver.json"),
    PeerPath = filename:join(Directory, "peer.json"),
    Aggregate = filename:join(Directory, "report.json"),
    Report = driver_failure_report(Id, RunId, "cleanup", "1"),
    try
        with_interop_state_lock(fun() ->
            ok = publish_driver_failure(Path, Report),
            Expected = evidence_json_decode(iolist_to_binary(json:encode(Report))),
            Expected = evidence_json_decode(interop_read(Path)),
            ok = publish_driver_failure(Path, Report),
            Expected = evidence_json_decode(interop_read(Path)),
            {ok, ["driver.json"]} = file:list_dir(Directory),
            Bad = Report#{evidence_identity => #{}},
            rejected(fun() -> publish_driver_failure(Path, Bad) end,
                     stale_driver_source_accepted),
            Expected = evidence_json_decode(interop_read(Path)),
            {ok, ["driver.json"]} = file:list_dir(Directory),
            ok = file:write_file(PeerPath,
                [<<"{\"status\":\"Ready\",\"run_id\":\"">>, RunId,
                 <<"\",\"private\":\"private-canary\"}">>]),
            ok = file:write_file(Aggregate, <<"{\"status\":\"Ready\"}">>),
            ok = publish_driver_failure_and_invalidate(
                Path, Aggregate, PeerPath, RunId, Report),
            interop_ensure(not filelib:is_regular(PeerPath),
                           driver_failure_retained_ready_peer),
            interop_ensure(not filelib:is_regular(Aggregate),
                           driver_failure_retained_ready_aggregate),
            Expected = evidence_json_decode(interop_read(Path)),
            {ok, ["driver.json"]} = file:list_dir(Directory),
            NewRun = binary:copy(<<"b">>, 64),
            ok = file:write_file(PeerPath,
                [<<"{\"status\":\"Running\",\"run_id\":\"">>, NewRun,
                 <<"\"}">>]),
            rejected(fun() -> invalidate_matching_peer(PeerPath, RunId) end,
                     stale_driver_invalidated_new_run),
            NewRun = maps:get(<<"run_id">>,
                evidence_json_decode(interop_read(PeerPath))),
            ok = file:write_file(Aggregate, <<"{\"status\":\"Ready\"}">>),
            rejected(fun() -> publish_driver_failure_and_invalidate(
                Path, Aggregate, PeerPath, RunId, Report) end,
                stale_driver_invalidated_new_aggregate),
            NewRun = maps:get(<<"run_id">>,
                evidence_json_decode(interop_read(PeerPath))),
            #{<<"status">> := <<"Ready">>} =
                evidence_json_decode(interop_read(Aggregate)),
            rejected(fun() -> prepare_state(PeerPath, Aggregate) end,
                     prepare_replaced_running_peer),
            NewRun = maps:get(<<"run_id">>,
                evidence_json_decode(interop_read(PeerPath))),
            #{<<"status">> := <<"Ready">>} =
                evidence_json_decode(interop_read(Aggregate)),
            ok = file:write_file(PeerPath,
                [<<"{\"status\":\"Ready\",\"run_id\":\"">>, NewRun,
                 <<"\"}">>]),
            ok = prepare_state(PeerPath, Aggregate),
            false = filelib:is_regular(PeerPath),
            false = filelib:is_regular(Aggregate)
        end)
    after file:delete(Path), file:delete(PeerPath), file:delete(Aggregate), file:del_dir(Directory) end,
    rejected(fun() -> interop_run_id(binary:copy(<<"g">>, 64)) end,
             invalid_run_id_accepted),
    io:put_chars("driver failure controls: 4 phases, 10 rejected inputs, publication, run-scoped invalidation and source identity verified\n").

run() ->
    with_interop_state_lock(fun() ->
        try run_locked()
        catch Class:Reason:Stacktrace ->
            retain_failed_aggregate(Class, Reason, Stacktrace),
            erlang:raise(Class, Reason, Stacktrace)
        end
    end).

retain_failed_aggregate(Class, Reason, Stacktrace) ->
    Path = "build/interop/report.json",
    case filelib:is_regular(Path) of
        true -> ok;
        false ->
            Identity = case get(interop_aggregate_identity) of
                Value when is_map(Value) -> Value;
                _ -> evidence_identity()
            end,
            Source = maps:get(<<"source_sha256">>, Identity),
            Failure = evidence_complete(#{schema => 2, status => <<"Failed">>,
                baseline_date => <<"2026-08-30">>, source_sha256 => Source,
                peers => 11, missing => [], runs => [],
                failure => diagnostic_failure_details(
                    Class, Reason, Stacktrace)}, Identity),
            write_report(Failure)
    end.

run_locked() ->
    Identity = evidence_begin("build/interop/report.json"),
    put(interop_aggregate_identity, Identity),
    _ = interop_verify_merge_receipt_if_aggregate(Identity),
    FailureIds = validate_published_failures_locked(Identity),
    interop_ensure(FailureIds =:= [], retained_interop_failure),
    Profile = evidence_json_decode(interop_read("standards/interop-profile.json")),
    interop_ensure(maps:get(<<"baseline_date">>, Profile) =:= <<"2026-08-30">>,
           invalid_interop_baseline),
    Peers = maps:get(<<"peers">>, Profile),
    Ids = [maps:get(<<"id">>, Peer) || Peer <- Peers],
    interop_ensure(length(Ids) =:= length(lists:usort(Ids)), duplicate_interop_peer),
    lists:foreach(fun audit_pin/1, Peers),
    Source = interop_source_digest(),
    Rows = [interop_peer_row(Peer, Source) || Peer <- Peers],
    Missing = [maps:get(peer, Row) || Row <- Rows,
        maps:get(status, Row) =/= <<"Ready">>],
    Status = case Missing of [] -> <<"Ready">>; _ -> <<"Blocked">> end,
    Report = #{schema => 2, status => Status,
               baseline_date => <<"2026-08-30">>,
               source_sha256 => Source,
               peers => length(Peers), missing => Missing, runs => Rows},
    write_report(evidence_complete(Report, Identity)),
    case Status of
        <<"Ready">> -> io:format("interop audit: all ~B peer rows ready~n",
                                  [length(Peers)]);
        _ -> erlang:error({interop_matrix_incomplete, Missing})
    end.

interop_verify_merge_receipt(Identity) ->
    {Mode, Major, Version} = interop_merge_workflow_identity(),
    ReceiptBytes = artifact_merge_read_regular(
        "build/interop/artifact-merge-receipt.json", 1048576),
    Receipt = evidence_json_decode(ReceiptBytes),
    Current0 = interop_merge_current_files(),
    Current1 = interop_merge_current_files(),
    interop_ensure(Current0 =:= Current1,
                   interop_merge_tree_changed_during_audit),
    interop_verify_merge_receipt_value(
        Receipt, Mode, Major, Version, Identity, execution_runtime(), Current1),
    #{receipt => Receipt,
      sha256 => interop_bytes_digest(ReceiptBytes)}.

interop_verify_merge_receipt_if_aggregate(Identity) ->
    case os:getenv("HTTP_INTEROP_ARTIFACT_MODE") of
        false -> local_peer_evidence;
        _Mode -> interop_verify_merge_receipt(Identity)
    end.

interop_merge_workflow_identity() ->
    Mode = case os:getenv("HTTP_INTEROP_ARTIFACT_MODE") of
        "pr" -> <<"pr">>;
        "nightly" -> <<"nightly">>;
        _ -> erlang:error(missing_or_invalid_interop_artifact_mode)
    end,
    Major = case os:getenv("HTTP_INTEROP_EXPECTED_OTP") of
        "28" -> <<"28">>;
        "29" -> <<"29">>;
        _ -> erlang:error(missing_or_invalid_interop_artifact_otp)
    end,
    Version = interop_expected_otp_version(Major),
    {Mode, Major, Version}.

interop_verify_merge_receipt_value(Receipt, Mode, Major, Version, Identity,
                                   Runtime, CurrentFiles) ->
    interop_keys(Receipt, [<<"schema">>, <<"status">>, <<"kind">>,
        <<"mode">>, <<"otp">>, <<"otp_version">>, <<"artifact_count">>,
        <<"input_file_count">>, <<"input_total_bytes">>, <<"file_count">>,
        <<"total_bytes">>, <<"bounds">>, <<"artifacts">>, <<"files">>,
        <<"execution_environment">>, <<"evidence_identity">>]),
    interop_ensure(maps:get(<<"schema">>, Receipt) =:= 1 andalso
        maps:get(<<"status">>, Receipt) =:= <<"Ready">> andalso
        maps:get(<<"kind">>, Receipt) =:= <<"interop">> andalso
        maps:get(<<"mode">>, Receipt) =:= Mode andalso
        maps:get(<<"otp">>, Receipt) =:= Major andalso
        maps:get(<<"otp_version">>, Receipt) =:= Version,
        invalid_interop_merge_receipt_identity),
    interop_ensure(maps:get(<<"evidence_identity">>, Receipt) =:= Identity,
                   stale_interop_merge_source_identity),
    interop_ensure(maps:get(<<"execution_environment">>, Receipt) =:= Runtime,
                   wrong_interop_merge_execution_runtime),
    {_, RuntimeMajor} = interop_audit_execution_runtime(Runtime),
    interop_ensure(RuntimeMajor =:= Major andalso
                   maps:get(<<"otp_version">>, Runtime) =:= Version,
                   wrong_interop_merge_execution_runtime),
    interop_verify_merge_bounds(maps:get(<<"bounds">>, Receipt)),
    Expected = lists:sort(artifact_merge_interop_expected(
        Mode, Major, Version)),
    ExpectedNames = [Name || {Name, _} <- Expected],
    Artifacts = maps:get(<<"artifacts">>, Receipt),
    Files = maps:get(<<"files">>, Receipt),
    interop_ensure(is_list(Artifacts) andalso is_list(Files),
                   invalid_interop_merge_receipt_inventory),
    Names = [artifact_merge_artifact_name(Artifact) || Artifact <- Artifacts],
    interop_ensure(Names =:= ExpectedNames andalso
                   length(Artifacts) =:= 11 andalso
                   maps:get(<<"artifact_count">>, Receipt) =:= 11,
                   wrong_interop_merge_artifact_set),
    PublicFiles = interop_merge_validate_files(Files, ExpectedNames),
    interop_ensure(PublicFiles =:= CurrentFiles,
                   stale_interop_merge_file_tree),
    lists:foreach(fun({Artifact, Peer}) ->
        interop_merge_validate_artifact(Artifact, Peer, Artifacts, Files)
    end, Expected),
    InputCount = lists:sum(
        [maps:get(<<"file_count">>, Artifact) || Artifact <- Artifacts]),
    InputBytes = lists:sum(
        [maps:get(<<"total_bytes">>, Artifact) || Artifact <- Artifacts]),
    TotalBytes = lists:sum([maps:get(<<"size">>, File) || File <- Files]),
    interop_ensure(maps:get(<<"input_file_count">>, Receipt) =:= InputCount andalso
        maps:get(<<"input_total_bytes">>, Receipt) =:= InputBytes andalso
        maps:get(<<"file_count">>, Receipt) =:= length(Files) andalso
        maps:get(<<"total_bytes">>, Receipt) =:= TotalBytes,
        invalid_interop_merge_receipt_totals),
    ok.

interop_verify_merge_bounds(Bounds) ->
    interop_keys(Bounds, [<<"maximum_artifacts">>, <<"maximum_entries">>,
        <<"maximum_depth">>, <<"maximum_path_bytes">>, <<"maximum_files">>,
        <<"maximum_file_bytes">>, <<"maximum_total_bytes">>]),
    interop_ensure(Bounds =:= #{<<"maximum_artifacts">> => 11,
        <<"maximum_entries">> => 16384, <<"maximum_depth">> => 64,
        <<"maximum_path_bytes">> => 4096, <<"maximum_files">> => 8192,
        <<"maximum_file_bytes">> => 134217728,
        <<"maximum_total_bytes">> => 536870912},
        invalid_interop_merge_receipt_bounds).

interop_merge_validate_files(Files, ExpectedNames) ->
    Public = [begin
        interop_keys(File, [<<"path">>, <<"size">>, <<"sha256">>,
                            <<"artifacts">>]),
        Path = maps:get(<<"path">>, File),
        ok = interop_merge_validate_relative_path(Path),
        Size = maps:get(<<"size">>, File),
        Digest = maps:get(<<"sha256">>, File),
        Owners = maps:get(<<"artifacts">>, File),
        interop_ensure(is_integer(Size) andalso Size >= 0 andalso
                       Size =< 134217728 andalso artifact_merge_hex(Digest),
                       invalid_interop_merge_file_record),
        interop_ensure(is_list(Owners) andalso Owners =/= [] andalso
                       Owners =:= lists:usort(Owners) andalso
                       lists:all(fun(Owner) ->
                           lists:member(Owner, ExpectedNames)
                       end, Owners), invalid_interop_merge_file_owners),
        #{<<"path">> => Path, <<"size">> => Size, <<"sha256">> => Digest}
    end || File <- Files],
    SortedFiles = lists:sort(fun interop_merge_receipt_file_less/2, Files),
    interop_ensure(Files =:= SortedFiles andalso length(Files) =< 8192 andalso
                   lists:sum([maps:get(<<"size">>, File) || File <- Files])
                       =< 536870912,
                   invalid_interop_merge_file_order_or_bounds),
    Keys = [evidence_portable_path_key(
        binary_to_list(maps:get(<<"path">>, File))) || File <- Files],
    interop_ensure(length(Keys) =:= length(lists:usort(Keys)),
                   portable_interop_merge_path_collision),
    Public.

interop_merge_receipt_file_less(A, B) ->
    PathA = maps:get(<<"path">>, A),
    PathB = maps:get(<<"path">>, B),
    {evidence_portable_path_key(binary_to_list(PathA)), PathA} <
    {evidence_portable_path_key(binary_to_list(PathB)), PathB}.

interop_merge_validate_artifact(Name, Peer, Artifacts, Files) ->
    [Artifact] = [Value || Value <- Artifacts,
        maps:get(<<"name">>, Value) =:= Name],
    interop_keys(Artifact, [<<"name">>, <<"file_count">>,
                            <<"total_bytes">>, <<"sha256">>]),
    Selected = [File || File <- Files,
        lists:member(Name, maps:get(<<"artifacts">>, File))],
    OwnPeer = <<"peers/", Peer/binary, ".json">>,
    OwnFailure = <<"failure-audits/", Peer/binary, ".json">>,
    Paths = [maps:get(<<"path">>, File) || File <- Selected],
    interop_ensure(lists:member(OwnPeer, Paths) orelse
                   lists:member(OwnFailure, Paths),
                   missing_own_interop_merge_peer_result),
    lists:foreach(fun(Path) ->
        interop_merge_validate_scoped_path(Path, Peer)
    end, Paths),
    Payload = [[maps:get(<<"path">>, File), 0,
                maps:get(<<"sha256">>, File), 0,
                integer_to_binary(maps:get(<<"size">>, File)), 0]
               || File <- Selected],
    ExpectedDigest = interop_bytes_digest(Payload),
    interop_ensure(maps:get(<<"file_count">>, Artifact) =:= length(Selected) andalso
        maps:get(<<"total_bytes">>, Artifact) =:=
            lists:sum([maps:get(<<"size">>, File) || File <- Selected]) andalso
        maps:get(<<"sha256">>, Artifact) =:= ExpectedDigest,
        invalid_interop_merge_artifact_summary).

interop_merge_validate_scoped_path(Path, Peer) ->
    [Top | Rest] = binary:split(Path, <<"/">>, [global]),
    interop_ensure(lists:member(Top, [<<"peers">>, <<"manifests">>,
        <<"go-build">>, <<"bin">>, <<"native">>, <<"failures">>,
        <<"failure-audits">>, <<"invocations">>, <<"browser">>]),
        unexpected_interop_merge_top_level),
    interop_ensure(interop_merge_peer_path(Top, Rest, Peer),
                   foreign_interop_merge_peer_path).

interop_merge_peer_path(<<"peers">>, [Name], Peer) ->
    Name =:= <<Peer/binary, ".json">>;
interop_merge_peer_path(<<"failure-audits">>, [Name], Peer) ->
    Name =:= <<Peer/binary, ".json">>;
interop_merge_peer_path(Top, [Name], Peer)
        when Top =:= <<"manifests">>; Top =:= <<"go-build">> ->
    interop_merge_prefixed_peer_file(Name, Peer);
interop_merge_peer_path(Top, [Peer | Rest], Peer)
        when (Top =:= <<"native">> orelse Top =:= <<"failures">> orelse
              Top =:= <<"invocations">> orelse Top =:= <<"browser">>),
             Rest =/= [] -> true;
interop_merge_peer_path(<<"bin">>, [Name], Peer) ->
    Name =:= interop_merge_peer_binary_name(Peer);
interop_merge_peer_path(_, _, _) -> false.

interop_merge_prefixed_peer_file(Name, Peer) ->
    Size = byte_size(Peer),
    case Name of
        <<Prefix:Size/binary, $., _/binary>> when Prefix =:= Peer -> true;
        <<Prefix:Size/binary, $-, _/binary>> when Prefix =:= Peer -> true;
        _ -> false
    end.

interop_merge_peer_binary_name(<<"quic-go-h3">>) -> <<"quic-go">>;
interop_merge_peer_binary_name(<<"ohttp-go">>) -> <<"ohttp-go">>;
interop_merge_peer_binary_name(<<"masque-independent">>) -> <<"masque-go">>;
interop_merge_peer_binary_name(_) -> <<>>.

interop_merge_current_files() ->
    Root = "build/interop",
    Info = interop_merge_link_info(Root),
    interop_ensure(element(3, Info) =:= directory,
                   invalid_interop_merge_output_root),
    {_Entries, Count, Bytes, Files0} =
        interop_merge_walk(Root, [], {0, 0, 0, []}),
    interop_ensure(Count =< 8192 andalso Bytes =< 536870912,
                   excessive_interop_merge_output),
    Files = lists:sort(fun interop_merge_public_file_less/2, Files0),
    Keys = [evidence_portable_path_key(
        binary_to_list(maps:get(<<"path">>, File))) || File <- Files],
    interop_ensure(length(Keys) =:= length(lists:usort(Keys)),
                   portable_interop_merge_path_collision),
    Files.

interop_merge_walk(Directory, Segments, {Entries0, Count0, Bytes0, Files0}) ->
    interop_ensure(length(Segments) =< 64,
                   excessive_interop_merge_output_depth),
    Names = case file:list_dir(Directory) of
        {ok, Values} -> lists:sort(Values);
        {error, _} -> erlang:error(unreadable_interop_merge_output)
    end,
    Entries = Entries0 + length(Names),
    interop_ensure(Entries =< 16384,
                   excessive_interop_merge_output_entries),
    lists:foldl(fun(Name, State) ->
        NextSegments = Segments ++ [Name],
        Relative = interop_merge_relative_path(NextSegments),
        Path = filename:join(Directory, Name),
        EntryInfo = interop_merge_link_info(Path),
        case {Segments, Name, element(3, EntryInfo)} of
            {[], "artifact-merge-receipt.json", regular} -> State;
            {[], "artifact-merge-receipt.json", _} ->
                erlang:error(invalid_interop_merge_receipt_type);
            {[], "report.json", regular} -> State;
            {[], "report.json", _} ->
                erlang:error(invalid_interop_merge_report_type);
            {[], "state-lock", directory} ->
                ok = interop_merge_validate_active_lock(Path),
                State;
            {[], "state-lock", _} ->
                erlang:error(invalid_interop_merge_state_lock_type);
            {_, _, directory} ->
                ok = interop_merge_validate_relative_path(Relative),
                interop_merge_walk(Path, NextSegments, State);
            {_, _, regular} ->
                ok = interop_merge_validate_relative_path(Relative),
                interop_merge_add_current_file(
                    Path, Relative, EntryInfo, State);
            {_, _, symlink} -> erlang:error(interop_merge_output_link_rejected);
            _ -> erlang:error(interop_merge_output_special_file_rejected)
        end
    end, {Entries, Count0, Bytes0, Files0}, Names).

interop_merge_validate_active_lock(Path) ->
    case get(interop_state_lock) of
        Lease when is_map(Lease) ->
            interop_ensure(filename:absname(Path) =:= maps:get(path, Lease),
                           foreign_interop_merge_state_lock),
            Owner = maps:get(owner, Lease),
            interop_ensure(filename:absname(Owner) =:=
                           filename:absname(filename:join(Path, "owner.json")),
                           foreign_interop_merge_state_lock),
            interop_ensure(file:list_dir(Path) =:= {ok, ["owner.json"]},
                           invalid_interop_merge_state_lock),
            interop_ensure(artifact_merge_read_regular(Owner, 4096) =:=
                           maps:get(bytes, Lease),
                           changed_interop_merge_state_lock),
            ok;
        _ ->
            erlang:error(unexpected_interop_merge_state_lock)
    end.

interop_merge_add_current_file(Path, Relative, Info,
                               {Entries, Count0, Bytes0, Files}) ->
    interop_ensure(element(9, Info) =:= 1,
                   interop_merge_output_hardlink_rejected),
    Size = element(2, Info),
    interop_ensure(is_integer(Size) andalso Size >= 0 andalso
                   Size =< 134217728,
                   excessive_interop_merge_output_file),
    Count = Count0 + 1,
    Bytes = Bytes0 + Size,
    interop_ensure(Count =< 8192 andalso Bytes =< 536870912,
                   excessive_interop_merge_output),
    Data = artifact_merge_read_regular(Path, 134217728),
    Record = #{<<"path">> => Relative, <<"size">> => Size,
        <<"sha256">> => interop_bytes_digest(Data)},
    {Entries, Count, Bytes, [Record | Files]}.

interop_merge_link_info(Path) ->
    case file:read_link_info(Path) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(unreadable_interop_merge_output)
    end.

interop_merge_relative_path(Segments) ->
    iolist_to_binary(lists:join(<<"/">>,
        [unicode:characters_to_binary(Segment) || Segment <- Segments])).

interop_merge_validate_relative_path(Path) when is_binary(Path) ->
    interop_ensure(byte_size(Path) > 0 andalso byte_size(Path) =< 4096,
                   invalid_interop_merge_output_path),
    Segments = binary:split(Path, <<"/">>, [global]),
    interop_ensure(Segments =/= [] andalso length(Segments) =< 64,
                   invalid_interop_merge_output_path),
    lists:foreach(fun interop_merge_validate_segment/1, Segments),
    [Top | _] = Segments,
    interop_ensure(lists:member(Top, [<<"peers">>, <<"manifests">>,
        <<"go-build">>, <<"bin">>, <<"native">>, <<"failures">>,
        <<"failure-audits">>, <<"invocations">>, <<"browser">>]),
        unexpected_interop_merge_top_level),
    ok;
interop_merge_validate_relative_path(_) ->
    erlang:error(invalid_interop_merge_output_path).

interop_merge_validate_segment(Segment) ->
    interop_ensure(is_binary(Segment) andalso byte_size(Segment) > 0 andalso
                   byte_size(Segment) =< 255,
                   invalid_interop_merge_output_segment),
    Name = case unicode:characters_to_list(Segment) of
        Value when is_list(Value) -> Value;
        _ -> erlang:error(invalid_interop_merge_output_segment)
    end,
    interop_ensure(Name =/= "." andalso Name =/= ".." andalso
        lists:all(fun(Character) ->
            Character >= 32 andalso Character =/= 127 andalso Character =/= 0
        end, Name), invalid_interop_merge_output_segment),
    interop_ensure(not lists:any(fun(Character) ->
        lists:member(Character, "\\/:<>\"|?*")
    end, Name), invalid_interop_merge_output_segment),
    Last = lists:last(Name),
    interop_ensure(Last =/= $. andalso Last =/= $\s,
                   non_portable_interop_merge_output_segment),
    Base = hd(string:split(Name, ".", leading)),
    PortableBase = string:casefold(
        unicode:characters_to_list(unicode:characters_to_nfc_binary(Base))),
    interop_ensure(not interop_merge_windows_device(PortableBase),
                   reserved_interop_merge_output_segment),
    ok.

interop_merge_windows_device("con") -> true;
interop_merge_windows_device("prn") -> true;
interop_merge_windows_device("aux") -> true;
interop_merge_windows_device("nul") -> true;
interop_merge_windows_device([$c, $o, $m, Digit])
        when Digit >= $1, Digit =< $9 -> true;
interop_merge_windows_device([$l, $p, $t, Digit])
        when Digit >= $1, Digit =< $9 -> true;
interop_merge_windows_device(_) -> false.

interop_merge_public_file_less(A, B) ->
    PathA = maps:get(<<"path">>, A),
    PathB = maps:get(<<"path">>, B),
    {evidence_portable_path_key(binary_to_list(PathA)), PathA} <
    {evidence_portable_path_key(binary_to_list(PathB)), PathB}.

audit_pin(Peer) ->
    case maps:get(<<"id">>, Peer) of
        <<"aioquic-h3">> ->
            interop_ensure(interop_file_digest(binary_to_list(maps:get(<<"lock">>, Peer)))
                   =:= maps:get(<<"lock_sha256">>, Peer),
                   aioquic_lock_drift);
        <<"quic-go-h3">> ->
            interop_ensure(interop_file_digest("packages/http3/test/interop/quicgo/go.sum")
                   =:= maps:get(<<"lock_sha256">>, Peer),
                   quicgo_lock_drift);
        <<"quiche-h3">> ->
            interop_ensure(interop_file_digest("packages/http3/test/interop/quiche/Cargo.lock")
                   =:= maps:get(<<"lock_sha256">>, Peer), quiche_lock_drift);
        <<"ngtcp2-nghttp3-h3">> ->
            case maps:get(<<"lock">>, Peer, null) of
                null -> ok;
                Lock -> interop_ensure(interop_file_digest(binary_to_list(Lock))
                       =:= maps:get(<<"lock_sha256">>, Peer), ngtcp2_lock_drift)
            end;
        _ -> ok
    end,
    case maps:get(<<"evidence">>, Peer, null) of
        null -> ok;
        Path -> interop_ensure(filelib:is_regular(binary_to_list(Path)),
                       {missing_interop_evidence_source, Path})
    end.

write_report(Report) ->
    write_json("build/interop/report.json", Report).


%% The auditor must check execution evidence, not merely the presence of a
%% runner. These adversarial cases exercise the same check used by the gate.
self_test() ->
    audit_pin_lock_self_test(),
    state_lock_self_test(),
    interop_merge_receipt_contract_self_test(),
    Profile = evidence_json_decode(interop_read("standards/interop-profile.json")),
    [Peer | _] = maps:get(<<"peers">>, Profile),
    Source = <<"current-source">>,
    Legacy = #{<<"schema">> => 1, <<"status">> => <<"Ready">>,
               <<"peer">> => maps:get(<<"id">>, Peer),
               <<"pin">> => maps:get(<<"pin">>, Peer),
               <<"source_sha256">> => Source,
               <<"roles">> => maps:get(<<"roles">>, Peer),
               <<"runtime">> => runtime(),
               <<"results">> => interop_expected_scenarios(Peer)},
    rejected(fun() -> interop_audit_peer_report(Peer, Legacy, Source) end,
             version_only_report_accepted),
    Nonce = binary:copy(<<"1">>, 64),
    Report = Legacy#{<<"schema">> => 2, <<"run_id">> => Nonce,
        <<"build">> => #{<<"target">> => <<"http">>, <<"manifest_sha256">> => Nonce,
                         <<"end_manifest_sha256">> => Nonce,
                         <<"artifact_sha256">> => Nonce},
        <<"invocations">> => [self_test_invocation(Peer, Scenario, Nonce, Source)
            || Scenario <- interop_expected_scenarios(Peer)]},
    ok = interop_audit_peer_report(Peer, Report, Source),
    ok = validate_running_report(Report#{<<"status">> => <<"Running">>},
                                 Source, Nonce),
    rejected(fun() -> validate_running_report(
        Report#{<<"status">> => <<"Running">>}, Source,
        binary:copy(<<"2">>, 64)) end, stale_finish_accepted),
    self_test_native_manifest(Peer, Report),
    self_test_rust_invocation(Peer, Report),
    self_test_native_invocation(Peer, Report),
    self_test_go_invocation(Peer, Report),
    self_test_node_invocation(Peer, Report),
    self_test_masque_native_receipt(Report),
    self_test_duplicate_peer_json(),
    failure_evidence_self_test(Peer),
    failure_receipt_runtime_self_test(),
    failure_outcome_contract_self_test(Peer),
    [Invocation | Rest] = maps:get(<<"invocations">>, Report),
    lists:foreach(fun(BadInvocation) ->
        rejected(fun() -> interop_audit_peer_report(Peer, Report#{
            <<"invocations">> => [BadInvocation | Rest]}, Source) end,
            invalid_invocation_accepted)
    end, [Invocation#{<<"run_id">> => binary:copy(<<"2">>, 64)},
          Invocation#{<<"source_sha256">> => <<"old-source">>},
          Invocation#{<<"identity">> => (maps:get(<<"identity">>, Invocation))#{<<"version">> => <<"curl 0.0.0">>}},
          Invocation#{<<"identity">> => maps:remove(<<"executable">>, maps:get(<<"identity">>, Invocation))},
          Invocation#{<<"completion">> => (maps:get(<<"completion">>, Invocation))#{<<"exit_status">> => 124}},
          Invocation#{<<"completion">> => (maps:get(<<"completion">>, Invocation))#{<<"exit_observed">> => false}},
          Invocation#{<<"argv">> => <<"private-endpoint-marker">>}]),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{<<"invocations">> => []}, Source) end,
             manual_scenario_without_execution_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"source_sha256">> => <<"old-source">>}, Source) end,
        stale_execution_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"status">> => <<"Running">>}, Source) end,
        incomplete_execution_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"pin">> => <<"unqualified-peer">>}, Source) end,
        different_peer_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"results">> => []}, Source) end,
        missing_scenarios_accepted),
    [First | _] = maps:get(<<"results">>, Report),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"results">> => [First | maps:get(<<"results">>, Report)]}, Source)
        end, duplicate_scenario_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"roles">> => []}, Source) end, omitted_role_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"payload">> => <<"must-not-escape">>}, Source) end,
        unredacted_field_accepted),
    rejected(fun() -> interop_audit_peer_report(Peer, Report#{
        <<"runtime">> => #{<<"os">> => <<"win32">>, <<"otp">> => <<"27">>}},
        Source) end, unsupported_otp_accepted),
    interop_ensure(byte_size(interop_source_digest()) =:= 64, invalid_source_digest),
    Identity = evidence_identity(),
    ok = evidence_require_identity(#{<<"evidence_identity">> => Identity},
                                    Identity),
    rejected(fun() -> evidence_require_identity(#{}, Identity) end,
             missing_common_identity_accepted),
    rejected(fun() -> evidence_require_identity(
        #{<<"evidence_identity">> => Identity#{<<"files">> => 0}}, Identity)
        end, different_common_identity_accepted),
    interop_reader_boundary_self_test(),
    io:put_chars("interop evidence adversarial tests passed\n").

audit_pin_lock_self_test() ->
    Peer = peer("aioquic-h3"),
    audit_pin(Peer),
    rejected(fun() -> audit_pin(Peer#{
        <<"lock">> => <<"packages/http3/test/interop/requirements.in">>})
    end, redirected_python_lock_accepted),
    rejected(fun() -> audit_pin(maps:remove(<<"lock">>, Peer)) end,
             missing_python_lock_accepted),
    io:put_chars("interop lock-source pin controls passed\n").

interop_merge_receipt_contract_self_test() ->
    Mode = <<"pr">>,
    Major = <<"28">>,
    Version = <<"28.5.0.6">>,
    Identity = #{<<"source_sha256">> => binary:copy(<<"a">>, 64)},
    Runtime = #{<<"otp_version">> => Version,
        <<"erts_version">> => <<"17.0.5">>, <<"os_family">> => <<"unix">>,
        <<"os_name">> => <<"linux">>,
        <<"system_architecture">> => <<"x86_64-pc-linux-gnu">>,
        <<"word_size">> => 8},
    Expected = lists:sort(artifact_merge_interop_expected(
        Mode, Major, Version)),
    Digest = interop_bytes_digest(<<"x">>),
    Files0 = [begin
        Path = <<"peers/", Peer/binary, ".json">>,
        #{<<"path">> => Path, <<"size">> => 1, <<"sha256">> => Digest,
          <<"artifacts">> => [Name]}
    end || {Name, Peer} <- Expected],
    Files = lists:sort(fun interop_merge_receipt_file_less/2, Files0),
    Artifacts = [interop_merge_fixture_artifact(Name, Files)
                 || {Name, _} <- Expected],
    Bounds = #{<<"maximum_artifacts">> => 11,
        <<"maximum_entries">> => 16384, <<"maximum_depth">> => 64,
        <<"maximum_path_bytes">> => 4096, <<"maximum_files">> => 8192,
        <<"maximum_file_bytes">> => 134217728,
        <<"maximum_total_bytes">> => 536870912},
    Receipt = #{<<"schema">> => 1, <<"status">> => <<"Ready">>,
        <<"kind">> => <<"interop">>, <<"mode">> => Mode,
        <<"otp">> => Major, <<"otp_version">> => Version,
        <<"artifact_count">> => 11, <<"input_file_count">> => 11,
        <<"input_total_bytes">> => 11, <<"file_count">> => 11,
        <<"total_bytes">> => 11, <<"bounds">> => Bounds,
        <<"artifacts">> => Artifacts, <<"files">> => Files,
        <<"execution_environment">> => Runtime,
        <<"evidence_identity">> => Identity},
    Current = [maps:without([<<"artifacts">>], File) || File <- Files],
    ok = interop_verify_merge_receipt_value(
        Receipt, Mode, Major, Version, Identity, Runtime, Current),
    Mutants = [
        Receipt#{<<"mode">> => <<"nightly">>},
        Receipt#{<<"otp">> => <<"29">>},
        Receipt#{<<"otp_version">> => <<"28.0">>},
        Receipt#{<<"evidence_identity">> => #{}},
        Receipt#{<<"execution_environment">> => Runtime#{
            <<"private">> => <<"canary">>}},
        Receipt#{<<"files">> => tl(Files)},
        Receipt#{<<"file_count">> => 10},
        Receipt#{<<"total_bytes">> => 10}
    ],
    lists:foreach(fun(Mutant) ->
        rejected(fun() -> interop_verify_merge_receipt_value(
            Mutant, Mode, Major, Version, Identity, Runtime, Current)
        end, invalid_interop_merge_receipt_mutant_accepted)
    end, Mutants),
    rejected(fun() -> interop_verify_merge_receipt_value(
        Receipt, Mode, Major, Version, Identity, Runtime, tl(Current))
    end, missing_current_interop_merge_file_accepted),
    [{_, FirstPeer} | _] = Expected,
    rejected(fun() -> interop_merge_validate_scoped_path(
        <<"peers/foreign.json">>, FirstPeer)
    end, foreign_interop_merge_scope_accepted),
    rejected(fun() -> interop_merge_validate_scoped_path(
        <<"private/unexpected.json">>, FirstPeer)
    end, unexpected_interop_merge_top_level_accepted),
    DeviceNames = ["CON", "con.txt", "PRN", "AUX.log", "NUL"] ++
        ["COM" ++ integer_to_list(Number) || Number <- lists:seq(1, 9)] ++
        ["LPT" ++ integer_to_list(Number) ++ ".json"
         || Number <- lists:seq(1, 9)],
    lists:foreach(fun(Name) ->
        rejected(fun() -> interop_merge_validate_segment(
            unicode:characters_to_binary(Name))
        end, non_portable_interop_merge_segment_accepted)
    end, ["trailing.", "trailing ", "stream:secret" | DeviceNames]),
    ok.

interop_merge_fixture_artifact(Name, Files) ->
    Selected = [File || File <- Files,
        lists:member(Name, maps:get(<<"artifacts">>, File))],
    Payload = [[maps:get(<<"path">>, File), 0,
                maps:get(<<"sha256">>, File), 0,
                integer_to_binary(maps:get(<<"size">>, File)), 0]
               || File <- Selected],
    #{<<"name">> => Name, <<"file_count">> => length(Selected),
      <<"total_bytes">> => lists:sum(
          [maps:get(<<"size">>, File) || File <- Selected]),
      <<"sha256">> => interop_bytes_digest(Payload)}.

failure_evidence_self_test(Peer) ->
    Source = binary:copy(<<"a">>, 64),
    RunId = binary:copy(<<"b">>, 64),
    [Scenario | _] = interop_expected_scenarios(Peer),
    Report = Scenario#{
        <<"schema">> => 1,
        <<"status">> => <<"Failed">>,
        <<"peer">> => maps:get(<<"id">>, Peer),
        <<"run_id">> => RunId,
        <<"source_sha256">> => Source,
        <<"phase">> => <<"identity_before">>,
        <<"completion">> => null,
        <<"result">> => #{<<"kind">> => <<"failed">>,
                            <<"exit_status">> => 1}},
    ok = interop_audit_failure_report(Peer, Report, Source, RunId),
    Completion = #{<<"outcome">> => <<"completed">>,
        <<"exit_status">> => 1, <<"exit_observed">> => true,
        <<"controlled_shutdown">> => false,
        <<"elapsed_milliseconds">> => 1,
        <<"stdout_bytes">> => 0, <<"stderr_bytes">> => 0},
    Completed = Report#{<<"phase">> => <<"exit_validation">>,
                        <<"completion">> => Completion},
    ok = interop_audit_failure_report(Peer, Completed, Source, RunId),
    Cancelled = Report#{<<"result">> => #{<<"kind">> => <<"cancelled">>,
                                           <<"exit_status">> => 143}},
    ok = interop_audit_failure_report(Peer, Cancelled, Source, RunId),
    Mutants = [
        Report#{<<"private">> => <<"private-endpoint-canary">>},
        Report#{<<"schema">> => 2},
        Report#{<<"status">> => <<"Ready">>},
        Report#{<<"peer">> => <<"unrelated-peer">>},
        Report#{<<"source_sha256">> => binary:copy(<<"c">>, 64)},
        Report#{<<"run_id">> => binary:copy(<<"d">>, 64)},
        Report#{<<"scenario">> => <<"private-scenario">>},
        Report#{<<"phase">> => <<"private-phase">>},
        Report#{<<"result">> => #{<<"kind">> => <<"failed">>,
                                    <<"exit_status">> => 0}},
        Report#{<<"result">> => #{<<"kind">> => <<"failed">>,
                                    <<"exit_status">> => 256}},
        Report#{<<"result">> => #{<<"kind">> => <<"failed">>,
                                    <<"exit_status">> => true}},
        Report#{<<"result">> => #{<<"kind">> => <<"failed">>,
                                    <<"exit_status">> => 1.0}},
        Report#{<<"result">> => #{<<"kind">> => <<"cancelled">>,
                                    <<"exit_status">> => 1}},
        Report#{<<"result">> => #{<<"kind">> => <<"failed">>,
                                    <<"exit_status">> => 143}},
        Report#{<<"result">> => #{<<"kind">> => <<"unknown">>,
                                    <<"exit_status">> => 1}},
        Report#{<<"completion">> => Completion},
        Completed#{<<"completion">> => null},
        Completed#{<<"completion">> => Completion#{
            <<"private">> => <<"private-body-canary">>}},
        Completed#{<<"completion">> => Completion#{
            <<"outcome">> => <<"unknown">>}},
        Completed#{<<"completion">> => Completion#{
            <<"exit_status">> => true}},
        Completed#{<<"completion">> => Completion#{
            <<"exit_observed">> => false}},
        Completed#{<<"completion">> => Completion#{
            <<"controlled_shutdown">> => 0}},
        Completed#{<<"completion">> => Completion#{
            <<"elapsed_milliseconds">> => 125001}},
        Completed#{<<"completion">> => Completion#{
            <<"stdout_bytes">> => 8388608, <<"stderr_bytes">> => 1}}
    ],
    lists:foreach(fun(Mutant) ->
        rejected(fun() -> interop_audit_failure_report(
            Peer, Mutant, Source, RunId)
        end, invalid_failure_evidence_accepted)
    end, Mutants),
    failure_directory_self_test(Peer),
    io:format("interop failed-scenario evidence controls: valid=3 "
              "mutants=~B~n", [length(Mutants)]).

failure_directory_self_test(Peer) ->
    Identity = evidence_identity(),
    Source = maps:get(<<"source_sha256">>, Identity),
    RunId = binary:copy(<<"e">>, 64),
    [Scenario | _] = interop_expected_scenarios(Peer),
    Failure = Scenario#{
        <<"schema">> => 1, <<"status">> => <<"Failed">>,
        <<"peer">> => maps:get(<<"id">>, Peer), <<"run_id">> => RunId,
        <<"source_sha256">> => Source,
        <<"phase">> => <<"identity_before">>, <<"completion">> => null,
        <<"result">> => #{<<"kind">> => <<"failed">>,
                            <<"exit_status">> => 1}},
    Name = binary_to_list(<<
        (interop_bytes_digest([maps:get(<<"role">>, Scenario), <<0>>,
                               maps:get(<<"scenario">>, Scenario)]))/binary,
        ".json">>),
    Driver = #{<<"schema">> => 1, <<"kind">> => <<"driver">>,
        <<"status">> => <<"Failed">>, <<"peer">> => maps:get(<<"id">>, Peer),
        <<"run_id">> => RunId, <<"phase">> => <<"cleanup">>,
        <<"exit_status">> => 1, <<"evidence_identity">> => Identity},
    Nonce = binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    Directory = filename:absname(filename:join(
        ["build", "interop-failure-self-test", Nonce])),
    ScenarioPath = filename:join(Directory, Name),
    DriverPath = filename:join(Directory, "driver.json"),
    ExtraPath = filename:join(Directory, "private.json"),
    HardlinkPath = filename:join(Directory,
        binary_to_list(binary:copy(<<"f">>, 64)) ++ ".json"),
    ok = filelib:ensure_dir(ScenarioPath),
    try
        ok = failure_fixture_write(ScenarioPath, Failure),
        ok = failure_fixture_write(DriverPath, Driver),
        Rows = interop_audit_failure_directory_at(
            Peer, Source, RunId, Identity, Directory),
        2 = length(Rows),
        [#{kind := <<"driver">>}] =
            [Row || Row <- Rows, maps:get(kind, Row) =:= <<"driver">>],
        [#{kind := <<"scenario">>}] =
            [Row || Row <- Rows, maps:get(kind, Row) =:= <<"scenario">>],
        ok = failure_fixture_write(ExtraPath,
            #{<<"private">> => <<"private-endpoint-canary">>}),
        rejected(fun() -> interop_audit_failure_directory_at(
            Peer, Source, RunId, Identity, Directory)
        end, invalid_failure_filename_accepted),
        ok = file:delete(ExtraPath),
        ok = failure_fixture_write(ScenarioPath,
            Failure#{<<"private">> => <<"private-body-canary">>}),
        rejected(fun() -> interop_audit_failure_directory_at(
            Peer, Source, RunId, Identity, Directory)
        end, private_failure_evidence_accepted),
        ok = failure_fixture_write(ScenarioPath, Failure),
        HardlinkState = case file:make_link(ScenarioPath, HardlinkPath) of
            ok ->
                rejected(fun() -> interop_audit_failure_directory_at(
                    Peer, Source, RunId, Identity, Directory)
                end, hardlinked_failure_evidence_accepted),
                ok = file:delete(HardlinkPath),
                <<"verified">>;
            {error, _} -> <<"unavailable">>
        end,
        ok = file:delete(DriverPath),
        rejected(fun() -> interop_audit_failure_directory_at(
            Peer, Source, RunId, Identity, Directory)
        end, missing_driver_failure_accepted),
        ok = failure_fixture_write(DriverPath,
            Driver#{<<"evidence_identity">> => Identity#{
                <<"source_sha256">> => binary:copy(<<"0">>, 64)}}),
        rejected(fun() -> interop_audit_failure_directory_at(
            Peer, Source, RunId, Identity, Directory)
        end, stale_driver_failure_accepted),
        ok = failure_fixture_write(DriverPath, Driver),
        ok = file:write_file(ScenarioPath, binary:copy(<<"x">>, 1048577)),
        rejected(fun() -> interop_audit_failure_directory_at(
            Peer, Source, RunId, Identity, Directory)
        end, oversized_failure_evidence_accepted),
        ok = failure_fixture_write(ScenarioPath, Failure),
        failure_cleanup_self_test(Peer, Failure, Driver, Name, Nonce),
        io:format("interop failure directory controls: files=2 hardlink=~s "
                  "stale=verified bounded=verified~n", [HardlinkState])
    after
        ok = file:del_dir_r(Directory)
    end.

failure_fixture_write(Path, Value) ->
    file:write_file(Path, [json:encode(Value), <<"\n">>]).

failure_cleanup_self_test(Peer, Failure, Driver, Name, Nonce) ->
    Root = filename:absname(filename:join(
        ["build", "interop-failure-cleanup-self-test", Nonce])),
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    Directory = filename:join([Root, "failures", Id]),
    AuditDirectory = filename:join([Root, "failure-audits"]),
    ScenarioPath = filename:join(Directory, Name),
    DriverPath = filename:join(Directory, "driver.json"),
    AuditPath = filename:join(AuditDirectory, Id ++ ".json"),
    Unexpected = filename:join(Directory, "private-canary.txt"),
    ok = filelib:ensure_dir(ScenarioPath),
    ok = filelib:ensure_dir(AuditPath),
    try
        ok = failure_fixture_write(ScenarioPath, Failure),
        ok = failure_fixture_write(DriverPath, Driver),
        ok = failure_fixture_write(AuditPath,
                                   #{<<"status">> => <<"fixture">>}),
        ok = file:write_file(Unexpected, <<"private-endpoint-canary">>),
        rejected(fun() -> clear_peer_failure_state_at(
            Peer, Directory, AuditDirectory)
        end, unexpected_stale_failure_deleted),
        true = filelib:is_regular(ScenarioPath),
        true = filelib:is_regular(DriverPath),
        true = filelib:is_regular(AuditPath),
        ok = file:delete(Unexpected),
        ok = clear_peer_failure_state_at(Peer, Directory, AuditDirectory),
        false = filelib:is_dir(Directory),
        false = filelib:is_regular(AuditPath),
        io:put_chars("interop failure cleanup controls: unknown=retained "
                     "known=cleared receipt=invalidated\n")
    after
        case file:del_dir_r(Root) of
            ok -> ok;
            {error, enoent} -> ok
        end
    end.

interop_reader_boundary_self_test() ->
    Nonce = binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    Root = filename:absname(filename:join(
        "build", "interop-reader-self-test-" ++ Nonce)),
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
        <<"current">> = interop_read_bounded(Original, 7),
        interop_reader_expect(fun() ->
            interop_read_bounded(Original, 6)
        end, oversized_or_invalid_peer_report),
        {ok, Info} = file:read_link_info(Original),
        StableIdentity = interop_file_identity(Info),
        StableIdentity = interop_file_identity(
            setelement(5, Info, changed_atime)),
        false = StableIdentity =:= interop_file_identity(
            setelement(6, Info, changed_mtime)),
        HardlinkState = case file:make_link(Original, Alias) of
            ok ->
                try
                    interop_reader_expect(fun() ->
                        interop_read_bounded(Original, 7)
                    end, peer_report_hardlink_rejected)
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
                interop_reader_expect(fun() ->
                    interop_read_bounded(Supplied, 1048576)
                end, peer_report_parent_link_rejected),
                interop_reader_expect(fun() ->
                    evidence_publication_ensure_directory(
                        filename:dirname(Supplied))
                end, evidence_publication_link_rejected),
                interop_reader_expect(fun() ->
                    interop_directory_names_or_empty(
                        filename:join(filename:dirname(Supplied), "missing"))
                end, unsafe_interop_directory),
                {<<"junction">>, <<"verified">>};
            none ->
                ok = file:write_file(ParentFile, <<"parent">>, [exclusive]),
                {Kind, State} = reader_boundary_make_parent_link(
                    ParentTarget, ParentLink),
                case State of
                    <<"verified">> ->
                        try
                            interop_reader_expect(fun() ->
                                interop_read_bounded(filename:join(
                                    ParentLink, "input.json"), 6)
                            end, peer_report_parent_link_rejected),
                            interop_reader_expect(fun() ->
                                evidence_publication_ensure_directory(ParentLink)
                            end, evidence_publication_link_rejected),
                            interop_reader_expect(fun() ->
                                interop_directory_names_or_empty(
                                    filename:join(ParentLink, "missing"))
                            end, unsafe_interop_directory)
                        after
                            ok = reader_boundary_remove_parent_link(ParentLink)
                        end;
                    <<"unavailable">> -> ok
                end,
                {Kind, State}
        end,
        io:format("interop reader hardlink=~s parent_component_kind=~s "
                  "parent_component_link=~s bounded_read=verified "
                  "identity_before_after=verified atime_stable=verified~n",
                  [HardlinkState, ParentKind, ParentState])
    after
        ok = file:del_dir_r(Root)
    end.

interop_reader_expect(Function, Expected) ->
    Result = try Function(), accepted
             catch error:Reason -> {rejected, Reason} end,
    interop_ensure(Result =:= {rejected, Expected},
                   interop_reader_mutant_accepted).

self_test_masque_native_receipt(Report) ->
    Hash=binary:copy(<<"a">>,64),Nonce=binary:copy(<<"b">>,32),
    Digest=#{<<"sha256">>=>Hash,<<"bytes">>=>1},
    Child=#{<<"schema">>=>1,<<"nonce">>=>Nonce,<<"completed_flows">>=>2,
        <<"completed_datagrams">>=>16,<<"completed_rejections">>=>1,<<"workers_down">>=>true},
    Completion=#{<<"outcome">>=><<"completed">>,<<"exit_status">>=>0,<<"exit_observed">>=>true,
        <<"controlled_shutdown">>=>false,<<"elapsed_milliseconds">>=>1,
        <<"stdout_bytes">>=>0,<<"stderr_bytes">>=>0},
    Native=#{<<"schema">>=>1,<<"status">>=><<"Passed">>,<<"role">>=><<"proxy">>,
        <<"configured_flows">>=>2,<<"configured_datagrams">>=>16,<<"configured_rejections">>=>1,
        <<"timeout_seconds">>=>45,<<"nonce">>=>Nonce,<<"child">>=>Child,
        <<"fixture">>=>#{<<"source">>=>Digest#{<<"sha256">>=>
            interop_file_digest("test/interop/masquego/http_masque_interop.erl")},
            <<"beam">>=>Digest,<<"runtime">>=>Digest},<<"completion">>=>Completion,
        <<"run_id">>=>maps:get(<<"run_id">>,Report),
        <<"source_sha256">>=>maps:get(<<"source_sha256">>,Report)},
    Check=fun(Value)->interop_audit_masque_native(Report,#{<<"role">>=><<"client">>,<<"native">>=>Value}) end,
    ok=Check(Native),
    lists:foreach(fun(Bad)->rejected(fun()->Check(Bad) end,invalid_native_opposite_accepted) end,
        [Native#{<<"status">>=><<"Failed">>},Native#{<<"child">>=>null},
         Native#{<<"run_id">>=>Hash},Native#{<<"source_sha256">>=>Hash},
         Native#{<<"role">>=><<"client">>},Native#{<<"configured_flows">>=>0},
         Native#{<<"timeout_seconds">>=>120},Native#{<<"nonce">>=><<"stale">>},
         Native#{<<"child">>=>Child#{<<"nonce">>=>binary:copy(<<"c">>,32)}},
         Native#{<<"child">>=>Child#{<<"completed_datagrams">>=>15}},
         Native#{<<"child">>=>Child#{<<"workers_down">>=>false}},
         Native#{<<"child">>=>Child#{<<"private">>=><<"private-native-marker">>}},
         Native#{<<"completion">>=>Completion#{<<"exit_observed">>=>false}},
         Native#{<<"completion">>=>Completion#{<<"exit_status">>=>1}},
         Native#{<<"completion">>=>Completion#{<<"stdout_bytes">>=>1}},
         Native#{<<"completion">>=>Completion#{<<"elapsed_milliseconds">>=>50001}},
         Native#{<<"private">>=><<"private-native-marker">>}]),
    self_test_masque_retained(Report,Native),ok.

self_test_masque_retained(Report,Proxy)->
    %% Synthetic schema fixtures exercise real retained-file requirements;
    %% they are not evidence that native endpoint work was executed.
    Client=Proxy#{<<"role">>=><<"client">>,<<"timeout_seconds">>=>30},
    Recorded=Report#{<<"invocations">>=>[#{<<"role">>=><<"client">>,<<"native">>=>Proxy},
        #{<<"role">>=><<"proxy">>,<<"native">>=>Client}]},
    Nonce=binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))),
    Directory="build/interop-self-test/masque-retained/"++Nonce,
    ClientPath=Directory++"/client.json",ProxyPath=Directory++"/proxy.json",ok=filelib:ensure_dir(ClientPath),
    Check=fun()->interop_audit_masque_retained_at(Recorded,Directory) end,
    try
        rejected(Check,missing_masque_native_sidecars_accepted),
        ok=file:write_file(ClientPath,json:encode(Client),[exclusive]),
        rejected(Check,missing_masque_proxy_sidecar_accepted),
        ok=file:write_file(ProxyPath,json:encode(Proxy),[exclusive]),ok=Check(),
        ok=file:write_file(ProxyPath,json:encode(Proxy#{<<"configured_datagrams">>=>15})),
        rejected(Check,replaced_masque_native_sidecar_accepted),
        ok=file:write_file(ProxyPath,json:encode(Proxy#{<<"private">>=><<"private-native-marker">>})),
        rejected(Check,private_masque_native_sidecar_accepted),
        ok=file:write_file(ProxyPath,json:encode(Proxy)),ok=file:delete(ClientPath),
        rejected(Check,deleted_masque_native_sidecar_accepted)
    after file:delete(ClientPath),file:delete(ProxyPath),file:del_dir(Directory) end.

self_test_native_manifest(Peer, Report) ->
    %% Imported Linux evidence remains valid on a Windows auditing host.
    Runtime = #{<<"otp_version">> => interop_expected_otp_version(<<"29">>), <<"erts_version">> => <<"17.0">>,
        <<"os_family">> => <<"unix">>, <<"os_name">> => <<"linux">>,
        <<"system_architecture">> => <<"x86_64-pc-linux-gnu">>, <<"word_size">> => 8},
    Imported = Report#{<<"runtime">> => #{<<"os">> => <<"linux">>, <<"otp">> => <<"29">>}},
    Sources = fresh_source_paths(fresh_packages("http")),
    Manifest = #{<<"schema">> => 3, <<"package">> => <<"http">>,
        <<"source_sha256">> => fresh_digest(Sources), <<"source_files">> => length(Sources),
        <<"artifact_sha256">> => maps:get(<<"artifact_sha256">>, maps:get(<<"build">>, Report)),
        <<"artifact_files">> => 100,
        <<"build_nonce">> => binary:copy(<<"0">>, 32),
        <<"prebuild_profile_state">> => <<"absent">>,
        <<"toolchain">> => #{<<"runtime">> => Runtime,
            <<"gleam">> => #{<<"declared_version">> => <<"1.18.1">>, <<"executable_sha256">> => binary:copy(<<"a">>, 64)},
            <<"rebar3">> => #{<<"declared_version">> => execution_tool_pin("rebar", interop_read(".mise.toml")), <<"executable_sha256">> => binary:copy(<<"b">>, 64)}}},
    ok = interop_audit_native_manifest(Peer, Imported, Manifest),
    WrongRuntime = Runtime#{<<"otp_version">> => <<"29.0.4">>},
    lists:foreach(fun(Bad) ->
        rejected(fun() -> interop_audit_native_manifest(Peer, Imported, Bad) end,
                 invalid_native_provenance_accepted)
    end, [Manifest#{<<"source_sha256">> => binary:copy(<<"c">>, 64)},
          Manifest#{<<"artifact_sha256">> => binary:copy(<<"d">>, 64)},
          Manifest#{<<"source_files">> => 0},
          Manifest#{<<"toolchain">> => (maps:get(<<"toolchain">>, Manifest))#{
              <<"runtime">> => WrongRuntime}},
          Manifest#{<<"toolchain">> => (maps:get(<<"toolchain">>, Manifest))#{
              <<"runtime">> => Runtime#{<<"host_path">> => <<"private-path-marker">>}}}]).

self_test_invocation(Peer, Scenario, Nonce, Source) ->
    Exit = case maps:get(<<"scenario">>, Scenario) of
        <<"untrusted certificate refused">> -> 60;
        _ -> 0
    end,
    Scenario#{<<"run_id">> => Nonce, <<"source_sha256">> => Source,
        <<"identity">> => #{<<"kind">> => <<"curl">>,
            <<"executable">> => #{<<"sha256">> => binary:copy(<<"a">>, 64), <<"bytes">> => 100},
            <<"version">> => maps:get(<<"pin">>, Peer), <<"lock_sha256">> => null,
            <<"fixture_sha256">> => null,
            <<"dependencies">> => [#{<<"name">> => <<"libcurl.so.4">>,
                <<"version">> => <<"binary">>, <<"sha256">> => binary:copy(<<"b">>, 64), <<"files">> => 1}]},
        <<"completion">> => #{<<"outcome">> => <<"completed">>, <<"exit_status">> => Exit,
            <<"controlled_shutdown">> => false,
            <<"exit_observed">> => true, <<"elapsed_milliseconds">> => 123,
            <<"stdout_bytes">> => 40, <<"stderr_bytes">> => 0}}.

self_test_duplicate_peer_json() ->
    Path = "build/interop-self-test/duplicate-peer.json",
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path,
        <<"{\"status\":\"private-marker\",\"sta\\u0074us\":\"Ready\"}">>),
    try rejected(fun() -> interop_read_peer_report(Path) end,
                 duplicate_peer_json_accepted)
    after ok = file:delete(Path) end.

self_test_go_invocation(_Peer, _Report) ->
    %% This positive control is a synthetic map, never an executed peer or a
    %% retained build. Production must additionally require actual artifacts.
    {GoPeer,Identity,Inputs,Module}=self_test_go_fixture(),
    Check=fun(I)->interop_go_receipt_shape(GoPeer,I,Inputs,Module) end,
    ok=Check(Identity),Build=maps:get(<<"build">>,Identity),
    Info=maps:get(<<"module_info">>,Build),[First|Rest]=maps:get(<<"steps">>,Build),
    BadBuilds=[Build#{<<"status">>=><<"Failed">>},Build#{<<"peer">>=><<"unknown">>},
        Build#{<<"nonce">>=><<"old-attempt">>},Build#{<<"sources">>=>[]},Build#{<<"recipes">>=>[]},
        Build#{<<"compiler">>=>#{<<"sha256">>=>binary:copy(<<"a">>,64),<<"bytes">>=>0}},
        Build#{<<"toolchain">>=>#{<<"sha256">>=>binary:copy(<<"a">>,64),<<"files">>=>0}},
        Build#{<<"binary">>=>(maps:get(<<"binary">>,Build))#{<<"bytes">>=>1000}},
        Build#{<<"module_info">>=>Info#{<<"version">>=><<"go1.26.0">>}},
        Build#{<<"module_info">>=>Info#{<<"dependencies">>=>[]}},
        Build#{<<"module_info">>=>Info#{<<"settings">>=>[]}},
        Build#{<<"steps">>=>Rest},Build#{<<"steps">>=>lists:reverse([First|Rest])},
        Build#{<<"steps">>=>[First#{<<"exit_status">>=>1}|Rest]},
        Build#{<<"steps">>=>[First#{<<"exit_observed">>=>false}|Rest]},
        Build#{<<"steps">>=>[First#{<<"controlled_shutdown">>=>true}|Rest]},
        Build#{<<"steps">>=>[First#{<<"stdout_bytes">>=>1048577}|Rest]},
        Build#{<<"private">>=><<"private-build-marker">>}],
    lists:foreach(fun(B)->rejected(fun()->Check(Identity#{<<"build">>=>B}) end,
        invalid_go_build_receipt_accepted) end,BadBuilds),
    lists:foreach(fun(I)->rejected(fun()->Check(I) end,invalid_go_invocation_identity_accepted) end,
        [maps:remove(<<"build">>,Identity),Identity#{<<"fixture_sha256">>=>null},
         Identity#{<<"dependencies">>=>[]},Identity#{<<"native">>=>#{}},
         Identity#{<<"version">>=><<"go1.26.0">>}]),
    rejected(fun()->interop_go_audit_identity(GoPeer,Identity) end,synthetic_go_build_became_execution),
    self_test_go_sources(),
    self_test_go_default_settings(GoPeer,Identity,Inputs,Module),
    self_test_go_attempts(GoPeer,Identity),
    self_test_go_elf(Identity),
    io:format("Go receipt controls: ~B synthetic mutations rejected; retained proof required~n",
        [length(BadBuilds)+5]).

self_test_go_fixture()->
    [Peer]=[P||P<-maps:get(<<"peers">>,interop_profile()),maps:get(<<"id">>,P)=:= <<"quic-go-h3">>],
    Hash=binary:copy(<<"a">>,64),D=#{<<"sha256">>=>Hash,<<"bytes">>=>1},
    LockBytes=interop_read(binary_to_list(maps:get(<<"lock">>,Peer))),
    [Name,Version]=binary:split(maps:get(<<"pin">>,Peer),<<"@">>),
    [Sum]=[S||Line<-binary:split(LockBytes,<<"\n">>,[global]),
        [N,V,S]<-[binary:split(string:trim(Line),<<" ">>,[global])],N=:=Name,V=:=Version],
    Sources=[D#{<<"path">>=><<"packages/http3/test/interop/quicgo/main.go">>}],
    Recipes=[D#{<<"path">>=><<"packages/http3/test/interop/run.sh">>}],
    Lock=#{<<"sha256">>=>interop_bytes_digest(LockBytes),<<"bytes">>=>byte_size(LockBytes)},
    Inputs=#{<<"sources">>=>Sources,<<"recipes">>=>Recipes,<<"lock">>=>Lock},
    Module= <<"example.com/http3-interop">>,
    Settings=lists:sort([#{<<"name">>=>N,<<"value">>=>V}||{N,V}<-
        [{<<"-buildmode">>,<<"exe">>},{<<"-compiler">>,<<"gc">>},{<<"-trimpath">>,<<"true">>},
         {<<"CGO_ENABLED">>,<<"0">>},{<<"GOOS">>,<<"linux">>},{<<"GOARCH">>,<<"amd64">>}]]),
    Info=#{<<"version">>=>maps:get(<<"go_version">>,Peer),<<"path">>=>Module,<<"module">>=>Module,
        <<"dependencies">>=>[#{<<"name">>=>Name,<<"version">>=>Version,<<"sum">>=>Sum}],<<"settings">>=>Settings},
    Steps=[#{<<"step">>=>Step,<<"outcome">>=><<"completed">>,<<"exit_status">>=>0,<<"exit_observed">>=>true,
        <<"controlled_shutdown">>=>false,<<"elapsed_milliseconds">>=>1,<<"stdout_bytes">>=>0,<<"stderr_bytes">>=>0}
        ||Step<-[<<"download">>,<<"verify_before">>,<<"build">>,<<"verify_after">>]],
    Build=Inputs#{<<"schema">>=>1,<<"status">>=><<"Passed">>,<<"peer">>=>maps:get(<<"id">>,Peer),
        <<"nonce">>=>binary:copy(<<"b">>,32),<<"compiler">>=>D,<<"binary">>=>D,
        <<"toolchain">>=>#{<<"sha256">>=>Hash,<<"files">>=>10},<<"module_info">>=>Info,<<"steps">>=>Steps},
    Identity=#{<<"kind">>=><<"go">>,<<"version">>=>maps:get(<<"go_version">>,Peer),<<"executable">>=>D,
        <<"lock_sha256">>=>maps:get(<<"lock_sha256">>,Peer),<<"fixture_sha256">>=>interop_go_rows_digest(Sources),
        <<"dependencies">>=>[#{<<"name">>=>Name,<<"version">>=>Version,<<"files">>=>0,
            <<"sha256">>=>interop_bytes_digest(Sum)}],<<"build">>=>Build},
    {Peer,Identity,Inputs,Module}.

self_test_go_sources()->
    Allowed=[<<"package p\nvar u = \"https://example.test\"\n">>,
        <<"package p\n// import \"C\"\nvar r = 'C'\n">>,<<"package p\n/* `C` */\n">>],
    lists:foreach(fun interop_go_source/1,Allowed),
    Bad=[<<"package p\n//go:embed secret\n">>,<<"package p\nimport \"C\"">>,
        <<"package p\nimport `C`">>,<<"package p\nimport \"\\x43\"">>,
        <<"package p\nimport (\"\\u0043\")">>,<<"package p\nimport \"\\U00000043\"">>,
        <<"package p\nimport \"\\103\"">>,<<"package p\nimport `\rC\r`">>,
        <<"package p\nvar x=\"https://private.test\"; import \"C\"">>],
    lists:foreach(fun(B)->rejected(fun()->interop_go_source(B) end,unbound_go_source_accepted) end,Bad),
    lists:foreach(fun(Name)->rejected(fun()->interop_go_supported_suffix(Name) end,
        native_go_input_accepted) end,["code.S","code.syso","code.c","code.SWIG","code.swigcxx"]),
    Nonce=binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))),
    Root="build/interop-self-test/go-sources/"++Nonce,
    Paths=[Root++"/go.mod",Root++"/go.sum",Root++"/main.go",Root++"/nested/extra.go",Root++"/nested/added.go"],
    [Mod,Sum,Main,Extra,Added]=Paths,ok=filelib:ensure_dir(Extra),
    try
        ok=file:write_file(Mod,<<"module fixture\n">>),ok=file:write_file(Sum,<<>>),
        ok=file:write_file(Main,<<"package main\n">>),ok=file:write_file(Extra,<<"package nested\n">>),
        Before=lists:sort(interop_go_walk([Root],0,[])),
        interop_ensure(Before=:=lists:sort([Mod,Sum,Main,Extra]),recursive_go_input_omitted),
        ok=file:write_file(Added,<<"package nested\n">>),After=lists:sort(interop_go_walk([Root],0,[])),
        interop_ensure(After=:=lists:sort(Paths),new_go_input_omitted),
        interop_ensure(interop_go_rows_digest(interop_go_inventory(Before,1048576))=/=
            interop_go_rows_digest(interop_go_inventory(After,1048576)),go_source_addition_not_bound)
    after
        [file:delete(P)||P<-Paths],file:del_dir(Root++"/nested"),file:del_dir(Root)
    end.

self_test_go_attempts(Peer,Identity)->
    Id=maps:get(<<"id">>,Peer),Nonce=maps:get(<<"nonce">>,maps:get(<<"build">>,Identity)),
    Attempt=#{<<"schema">>=>1,<<"peer">>=>Id,<<"nonce">>=>Nonce},
    ok=interop_go_attempt(Attempt,Id,Nonce),
    lists:foreach(fun(A)->rejected(fun()->interop_go_attempt(A,Id,Nonce) end,stale_go_attempt_accepted) end,
        [#{},Attempt#{<<"schema">>=>true},Attempt#{<<"peer">>=><<"other">>},
         Attempt#{<<"nonce">>=>binary:copy(<<"c">>,32)},Attempt#{<<"private">>=><<"private-attempt-marker">>}]).

self_test_go_default_settings(Peer,Identity,Inputs,Module)->
    Build=maps:get(<<"build">>,Identity),Info=maps:get(<<"module_info">>,Build),
    Settings=maps:get(<<"settings">>,Info),
    Check=fun(Value)->Default=#{<<"name">>=><<"DefaultGODEBUG">>,<<"value">>=>Value},
        New=Info#{<<"settings">>=>lists:sort([Default|Settings])},
        interop_go_receipt_shape(Peer,Identity#{<<"build">>=>Build#{<<"module_info">>=>New}},Inputs,Module)
    end,
    ok=Check(<<"containermaxprocs=0,updatemaxprocs=0">>),
    lists:foreach(fun(Value)->rejected(fun()->Check(Value) end,private_or_unbounded_go_defaults_accepted) end,
        [<<>>,<<"containermaxprocs=0,containermaxprocs=1">>,<<"private=/home/secret">>,
         <<"x=12345678901">>,<<"Upper=0">>,<<"x=1\nprivate=1">>,binary:copy(<<"a">>,4097)]).

self_test_go_elf(Identity)->
    Info=maps:get(<<"module_info">>,maps:get(<<"build">>,Identity)),
    Elf=self_test_go_elf_bytes(Info),
    interop_ensure(interop_go_elf_info(Elf)=:=Info,synthetic_go_buildinfo_parse_failed),
    Mutants=[<<"not-an-elf",Elf/binary>>,binary:part(Elf,0,100),
        self_test_go_replace(Elf,60,<<0,0>>),self_test_go_replace(Elf,62,<<255,255>>),
        self_test_go_replace(Elf,512,<<0>>),self_test_go_replace(Elf,527,<<0>>),
        self_test_go_replace(Elf,68,<<4:32/little>>),
        self_test_go_replace(Elf,400,<<0:64/little>>)],
    lists:foreach(fun(B)->rejected(fun()->interop_go_elf_info(B) end,invalid_go_elf_accepted) end,Mutants).
self_test_go_replace(B,At,New)-><<Prefix:At/binary,_:(byte_size(New))/binary,Suffix/binary>>=B,
    <<Prefix/binary,New/binary,Suffix/binary>>.
self_test_go_elf_bytes(Info)->
    Text=iolist_to_binary([["path\t",maps:get(<<"path">>,Info),"\nmod\t",maps:get(<<"module">>,Info),"\t(devel)\n"],
        [["dep\t",maps:get(<<"name">>,D),"\t",maps:get(<<"version">>,D),"\t",maps:get(<<"sum">>,D),"\n"]
            ||D<-maps:get(<<"dependencies">>,Info)],
        [["build\t",maps:get(<<"name">>,S),"=",maps:get(<<"value">>,S),"\n"]||S<-maps:get(<<"settings">>,Info)]]),
    Framed= <<0:128,Text/binary,0:128>>,Version=maps:get(<<"version">>,Info),
    Blob=iolist_to_binary([<<255," Go buildinf:",8,2,0:128>>,self_test_go_uvarint(byte_size(Version)),Version,
        self_test_go_uvarint(byte_size(Framed)),Framed]),
    Strings= <<0,".shstrtab",0,".go.buildinfo",0>>,
    Header= <<127,"ELF",2,1,1,0:72,2:16/little,62:16/little,1:32/little,0:64,
        64:64/little,256:64/little,0:32,64:16/little,56:16/little,1:16/little,
        64:16/little,3:16/little,1:16/little>>,
    Size=512+byte_size(Blob),Program= <<1:32/little,6:32/little,0:64,4194304:64/little,0:64,
        Size:64/little,Size:64/little,4096:64/little>>,
    Names= <<1:32/little,3:32/little,0:64,0:64,128:64/little,(byte_size(Strings)):64/little,0:192>>,
    Section= <<11:32/little,1:32/little,3:64/little,4194816:64/little,512:64/little,
        (byte_size(Blob)):64/little,0:64,16:64/little,0:64>>,
    <<Header/binary,Program/binary,0:64,Strings/binary,0:((256-128-byte_size(Strings))*8),
        0:512,Names/binary,Section/binary,0:512,Blob/binary>>.
self_test_go_uvarint(N) when N<128-> <<N>>;
self_test_go_uvarint(N)->[(N band 127) bor 128|self_test_go_uvarint(N bsr 7)].

self_test_node_invocation(Peer, Report) ->
    Hash = binary:copy(<<"a">>, 64),
    LockPath = "test/interop/ohttpts/package-lock.json",
    Fixture = "test/interop/ohttpts/peer.mjs",
    NodePeer = Peer#{<<"identity_kind">> => <<"node">>, <<"pin">> => <<"ohttp-ts@0.5.1">>,
        <<"node_version">> => <<"v26.8.2">>, <<"lock">> => list_to_binary(LockPath),
        <<"lock_sha256">> => interop_file_digest(LockPath), <<"fixture">> => list_to_binary(Fixture)},
    Lock = evidence_json_decode(interop_read(LockPath)),
    Dependencies = [#{<<"name">> => Name, <<"version">> => maps:get(<<"version">>, Metadata),
        <<"files">> => 10, <<"sha256">> => Hash}
        || {<<"node_modules/", Name/binary>>, Metadata} <- maps:to_list(maps:get(<<"packages">>, Lock))],
    [Invocation | _] = maps:get(<<"invocations">>, Report),
    Identity = (maps:get(<<"identity">>, Invocation))#{<<"kind">> => <<"node">>,
        <<"version">> => <<"v26.8.2">>, <<"lock_sha256">> => interop_file_digest(LockPath),
        <<"fixture_sha256">> => interop_file_digest(Fixture), <<"dependencies">> => Dependencies},
    Node = Invocation#{<<"identity">> => Identity},
    ok = interop_audit_invocation(NodePeer, Report, Node),
    [First | Rest] = Dependencies,
    lists:foreach(fun(Bad) ->
        rejected(fun() -> interop_audit_invocation(NodePeer, Report, Node#{<<"identity">> => Bad}) end,
                 invalid_node_identity_accepted)
    end, [Identity#{<<"version">> => <<"v26.8.1">>},
          Identity#{<<"fixture_sha256">> => Hash},
          Identity#{<<"dependencies">> => Rest},
          Identity#{<<"dependencies">> => [First#{<<"files">> => 0} | Rest]},
          Identity#{<<"dependencies">> => [First#{<<"version">> => <<"9.9.9">>} | Rest]}]).

self_test_rust_invocation(Peer, Report) ->
    Patch = "packages/http3/test/interop/quiche/identity_patch.py",
    Lock = "packages/http3/test/interop/quiche/Cargo.lock",
    Commit = <<"55886df3be579579207104c8e645825b6347a209">>,
    Hash = binary:copy(<<"a">>, 64),
    RustPeer = Peer#{<<"identity_kind">> => <<"rust">>,
        <<"pin">> => <<"quiche@0.29.3">>, <<"rust_version">> => <<"1.98.1">>,
        <<"source_commit">> => Commit, <<"identity_patch">> => list_to_binary(Patch),
        <<"lock_sha256">> => interop_file_digest(Lock)},
    [Invocation | _] = maps:get(<<"invocations">>, Report),
    Dependency = fun(Name, Version, Digest, Count) ->
        #{<<"name">> => Name, <<"version">> => Version,
          <<"sha256">> => Digest, <<"files">> => Count}
    end,
    Dependencies = [Dependency(<<"quiche">>, <<"0.29.3">>, Hash, 2153),
        Dependency(<<"quiche-source-revision">>, <<"git">>, interop_bytes_digest(Commit), 0),
        Dependency(<<"cargo-lock">>, <<"locked">>, interop_file_digest(Lock), 1)] ++
        [Dependency(Name, <<"1.98.1">>, Hash, 1)
            || Name <- [<<"rustc">>, <<"rustc-driver">>, <<"cargo">>]] ++
        [Dependency(<<"build-", Name/binary>>, <<"binary">>, Hash, 1)
            || Name <- [<<"cc">>, <<"c++">>, <<"clang">>, <<"cmake">>, <<"make">>, <<"ar">>, <<"ld">>]],
    Identity = (maps:get(<<"identity">>, Invocation))#{<<"kind">> => <<"rust">>,
        <<"version">> => <<"rustc 1.98.1">>,
        <<"lock_sha256">> => interop_file_digest(Lock),
        <<"fixture_sha256">> => interop_file_digest(Patch), <<"dependencies">> => Dependencies},
    Rust = Invocation#{<<"identity">> => Identity},
    ok = interop_audit_invocation(RustPeer, Report, Rust),
    lists:foreach(fun(BadIdentity) ->
        rejected(fun() -> interop_audit_invocation(RustPeer, Report,
            Rust#{<<"identity">> => BadIdentity}) end, unbound_rust_identity_accepted)
    end, [Identity#{<<"fixture_sha256">> => Hash},
          Identity#{<<"version">> => <<"rustc 1.0.0">>},
          Identity#{<<"dependencies">> => [D || D <- Dependencies,
              maps:get(<<"name">>, D) =/= <<"quiche-source-revision">>]},
          Identity#{<<"dependencies">> => [case maps:get(<<"name">>, D) of
              <<"quiche-source-revision">> -> D#{<<"sha256">> => Hash}; _ -> D end || D <- Dependencies]}]).

self_test_native_invocation(Peer, Report) ->
    Patch = "packages/http3/test/interop/ngtcp2/identity_patch.py",
    Recipe = "packages/http3/test/interop/ngtcp2/Dockerfile",
    LockPath = "packages/http3/test/interop/ngtcp2/sources.lock.json",
    Lock = evidence_json_decode(interop_read(LockPath)),
    Hash = binary:copy(<<"a">>, 64),
    NativePeer = Peer#{<<"identity_kind">> => <<"native">>,
        <<"pin">> => <<"ngtcp2@1.25.0">>, <<"compiler_version">> => <<"15.2.0">>,
        <<"identity_patch">> => list_to_binary(Patch), <<"build_recipe">> => list_to_binary(Recipe),
        <<"lock">> => list_to_binary(LockPath), <<"lock_sha256">> => interop_file_digest(LockPath)},
    [Invocation | _] = maps:get(<<"invocations">>, Report),
    Dependency = fun(Name, Version, Digest, Count) ->
        #{<<"name">> => Name, <<"version">> => Version, <<"sha256">> => Digest, <<"files">> => Count}
    end,
    Dependencies = lists:append([[Dependency(maps:get(<<"name">>, S), maps:get(<<"version">>, S), Hash, 100),
        Dependency(<<(maps:get(<<"name">>, S))/binary, "-archive">>, maps:get(<<"version">>, S),
                   maps:get(<<"sha256">>, S), 1)] || S <- maps:get(<<"sources">>, Lock)]) ++
        [Dependency(<<"build-", Name/binary>>, <<"binary">>, Hash, 1)
            || Name <- [<<"gcc">>, <<"g++">>, <<"cc1">>, <<"cc1plus">>, <<"as">>, <<"ld">>,
                        <<"ar">>, <<"ranlib">>, <<"cmake">>, <<"make">>, <<"pkg-config">>, <<"patchelf">>]] ++
        [Dependency(<<"peer-role">>, <<"client">>, interop_bytes_digest(<<"client">>), 0),
         Dependency(<<"source-lock">>, <<"locked">>, interop_file_digest(LockPath), 1),
         Dependency(<<"build-recipe">>, <<"locked">>, interop_file_digest(Recipe), 1)],
    Identity = (maps:get(<<"identity">>, Invocation))#{<<"kind">> => <<"native">>,
        <<"version">> => <<"gcc 15.2.0">>, <<"lock_sha256">> => interop_file_digest(LockPath),
        <<"fixture_sha256">> => interop_file_digest(Patch), <<"dependencies">> => Dependencies},
    Native = Invocation#{<<"identity">> => Identity},
    ok = interop_audit_invocation(NativePeer, Report, Native),
    lists:foreach(fun(BadIdentity) ->
        rejected(fun() -> interop_audit_invocation(NativePeer, Report,
            Native#{<<"identity">> => BadIdentity}) end, unbound_native_identity_accepted)
    end, [Identity#{<<"fixture_sha256">> => Hash}, Identity#{<<"version">> => <<"gcc 15.1.0">>}] ++
        [Identity#{<<"dependencies">> => [D || D <- Dependencies, maps:get(<<"name">>, D) =/= Name]}
         || Name <- [<<"nghttp3">>, <<"ngtcp2-archive">>, <<"build-recipe">>, <<"build-cc1">>, <<"peer-role">>]] ++
        [Identity#{<<"dependencies">> => [case maps:get(<<"name">>, D) of
             <<"peer-role">> -> D#{<<"version">> => <<"server">>}; _ -> D end || D <- Dependencies]}]).

peer(Id) ->
    IdBytes = unicode:characters_to_binary(Id),
    interop_ensure(re:run(IdBytes, <<"^[a-z0-9-]{1,64}$">>, [{capture, none}])
           =:= match, invalid_peer_id),
    case [P || P <- maps:get(<<"peers">>, interop_profile()),
               maps:get(<<"id">>, P) =:= IdBytes] of
        [Peer] -> Peer;
        _ -> erlang:error(unknown_peer)
    end.

prepare_peer(Id) ->
    with_interop_state_lock(fun() ->
        _ = peer(Id),
        prepare_state(interop_peer_path(Id), "build/interop/report.json")
    end).

prepare_state(PeerPath, Aggregate) ->
    ensure_peer_not_running(PeerPath),
    ok = delete_if_present(PeerPath),
    delete_if_present(Aggregate).

begin_peer(Id, ObservedPin) ->
    RunId = with_interop_state_lock(fun() ->
        begin_peer_locked(Id, ObservedPin)
    end),
    io:format("~s~n", [RunId]).

begin_peer_locked(Id, ObservedPin) ->
    Peer = peer(Id),
    Path = interop_peer_path(Id),
    %% Invalidate Ready before checking setup: drift must not leave old success.
    ensure_peer_not_running(Path),
    ok = delete_if_present(Path),
    ok = delete_if_present("build/interop/report.json"),
    audit_pin(Peer),
    interop_ensure(unicode:characters_to_binary(ObservedPin) =:=
           maps:get(<<"pin">>, Peer), wrong_peer_version),
    _ = interop_expected_scenarios(Peer),
    Build = retain_native_manifest(Id, Peer, "begin"),
    ok = delete_if_present(interop_manifest_path(Id, "end")),
    ok = clear_peer_failure_state(Peer),
    RunId = binary:encode_hex(crypto:strong_rand_bytes(32), lowercase),
    Report = #{<<"schema">> => 2, <<"status">> => <<"Running">>,
        <<"run_id">> => RunId,
        <<"peer">> => maps:get(<<"id">>, Peer),
        <<"pin">> => maps:get(<<"pin">>, Peer),
        <<"source_sha256">> => interop_source_digest(),
        <<"build">> => Build#{<<"end_manifest_sha256">> => null},
        <<"roles">> => maps:get(<<"roles">>, Peer),
        <<"runtime">> => runtime(), <<"results">> => [], <<"invocations">> => []},
    ok = write_json(Path, Report),
    RunId.

clear_peer_failure_state(Peer) ->
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    Directory = filename:join(["build", "interop", "failures", Id]),
    AuditDirectory = filename:join(["build", "interop", "failure-audits"]),
    clear_peer_failure_state_at(Peer, Directory, AuditDirectory).

clear_peer_failure_state_at(Peer, Directory, AuditDirectory) ->
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    Names = interop_directory_names_or_empty(Directory),
    Allowed = ["driver.json" | [binary_to_list(<<
        (interop_bytes_digest([maps:get(<<"role">>, Scenario), <<0>>,
                               maps:get(<<"scenario">>, Scenario)]))/binary,
        ".json">>) || Scenario <- interop_expected_scenarios(Peer)]],
    interop_ensure(lists:all(fun(Name) -> lists:member(Name, Allowed) end, Names),
                   unexpected_stale_failure_file),
    lists:foreach(fun(Name) ->
        ok = delete_if_present(filename:join(Directory, Name))
    end, Names),
    case file:del_dir(Directory) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_clear_stale_failure_directory)
    end,
    AuditName = Id ++ ".json",
    AuditNames = interop_directory_names_or_empty(AuditDirectory),
    case lists:member(AuditName, AuditNames) of
        true -> delete_if_present(filename:join(AuditDirectory, AuditName));
        false -> ok
    end.

ensure_peer_not_running(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, _} ->
            try interop_read_peer_report(Path) of
                #{<<"status">> := <<"Running">>} ->
                    erlang:error(peer_execution_already_running);
                _ -> ok
            catch
                error:peer_execution_already_running ->
                    erlang:error(peer_execution_already_running);
                _:_ -> ok
            end;
        {error, _} -> erlang:error(cannot_inspect_peer_result)
    end.

record_peer(Id, RunId0, Role, Scenario) ->
    RunId = interop_run_id(RunId0),
    with_interop_state_lock(fun() ->
        record_peer_locked(Id, RunId, Role, Scenario)
    end).

record_peer_locked(Id, RunId, Role, Scenario) ->
    Peer = peer(Id),
    Report = read_running(Id, RunId),
    Result = #{<<"role">> => unicode:characters_to_binary(Role),
               <<"scenario">> => unicode:characters_to_binary(Scenario)},
    interop_ensure(lists:member(Result, interop_expected_scenarios(Peer)), unknown_scenario),
    Results = maps:get(<<"results">>, Report),
    interop_ensure(not lists:member(Result, Results), duplicate_scenario_result),
    Name = binary_to_list(binary:encode_hex(crypto:hash(sha256,
        [unicode:characters_to_binary(Role), <<0>>, unicode:characters_to_binary(Scenario)]), lowercase)),
    PeerInvocation = interop_read_peer_report(filename:join(
        ["build", "interop", "invocations", Id, Name ++ ".json"])),
    Invocation = case Id of
        "masque-independent" ->
            NativeRole = case Role of "client" -> "proxy"; "proxy" -> "client" end,
            Native = interop_read_peer_report(filename:join(
                ["build", "interop", "native", Id, NativeRole ++ ".json"])),
            PeerInvocation#{<<"native">> => Native};
        Browser when Browser=:="chromium";Browser=:="firefox" ->
            Native = interop_read_peer_report(filename:join(
                ["build", "interop", "native", Id, Name ++ ".json"])),
            PeerInvocation#{<<"native">> => Native};
        _ -> PeerInvocation
    end,
    interop_audit_invocation(Peer, Report, Invocation),
    interop_ensure(maps:with([<<"role">>, <<"scenario">>], Invocation) =:= Result,
                   wrong_scenario_invocation),
    write_json(interop_peer_path(Id), Report#{<<"results">> => Results ++ [Result],
        <<"invocations">> => maps:get(<<"invocations">>, Report) ++ [Invocation]}).

complete_daemon(Id, RunId0, Role, Scenario) ->
    RunId = interop_run_id(RunId0),
    with_interop_state_lock(fun() ->
        complete_daemon_locked(Id, RunId, Role, Scenario)
    end).

complete_daemon_locked(Id, RunId, "server" = Role, Scenario)
  when Id =:= "nghttp2-h2"; Id =:= "quiche-h3"; Id =:= "ngtcp2-nghttp3-h3" ->
    Peer = peer(Id),
    Report = read_running(Id, RunId),
    Value = #{<<"role">> => list_to_binary(Role), <<"scenario">> => list_to_binary(Scenario)},
    interop_ensure(lists:member(Value, interop_expected_scenarios(Peer)), unknown_scenario),
    Name = binary_to_list(binary:encode_hex(crypto:hash(sha256,
        [Role, <<0>>, Scenario]), lowercase)),
    Path = filename:join(["build", "interop", "control", Id, Name ++ ".json"]),
    write_bytes_atomic(Path, maps:get(<<"run_id">>, Report));
complete_daemon_locked(_, _, _, _) -> erlang:error(unsupported_daemon_peer).

finish_peer(Id, RunId0) ->
    RunId = interop_run_id(RunId0),
    with_interop_state_lock(fun() -> finish_peer_locked(Id, RunId) end).

finish_peer_locked(Id, RunId) ->
    Peer = peer(Id),
    Running = read_running(Id, RunId),
    Current = retain_native_manifest(Id, Peer, "end"),
    interop_ensure(maps:remove(<<"end_manifest_sha256">>, maps:get(<<"build">>, Running)) =:= Current,
                   native_build_changed_during_execution),
    Report = Running#{<<"status">> => <<"Ready">>,
        <<"build">> => Current#{<<"end_manifest_sha256">> => maps:get(<<"manifest_sha256">>, Current)}},
    interop_audit_peer_report(Peer, Report, interop_source_digest()),
    interop_audit_retained_build(Peer, Report),
    write_json(interop_peer_path(Id), Report),
    io:format("interop execution verified: ~s~n", [Id]).

retain_native_manifest(Id, Peer, Phase) ->
    {Build, ManifestBytes} = interop_native_build(Peer),
    Path = interop_manifest_path(Id, Phase),
    ok = write_bytes_atomic(Path, ManifestBytes),
    interop_ensure(interop_file_digest(Path) =:= maps:get(<<"manifest_sha256">>, Build),
                   native_manifest_changed_during_capture),
    Build.

fail_peer(Id, RunId0) ->
    RunId = interop_run_id(RunId0),
    with_interop_state_lock(fun() ->
        _ = peer(Id),
        invalidate_matching_state(interop_peer_path(Id),
                                  "build/interop/report.json", RunId)
    end).

invalidate_matching_state(PeerPath, Aggregate, RunId) ->
    ok = invalidate_matching_peer(PeerPath, RunId),
    delete_if_present(Aggregate).

fail_peer_unconditionally(Id) ->
    with_interop_state_lock(fun() ->
        _ = peer(Id),
        ok = delete_if_present("build/interop/report.json"),
        delete_if_present(interop_peer_path(Id))
    end).

invalidate_matching_peer(Path, RunId) ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, _} ->
            try interop_read_peer_report(Path) of
                Report ->
                    interop_ensure(maps:get(<<"run_id">>, Report, undefined) =:=
                                   RunId, stale_peer_operation),
                    delete_if_present(Path)
            catch
                error:stale_peer_operation -> erlang:error(stale_peer_operation);
                _:_ -> delete_if_present(Path)
            end;
        {error, _} -> erlang:error(cannot_inspect_peer_result)
    end.

interop_run_id(Value) ->
    Bytes = unicode:characters_to_binary(Value),
    interop_ensure(re:run(Bytes, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:=
                   match, invalid_interop_run_id),
    Bytes.

read_running(Id, ExpectedRunId) ->
    _ = peer(Id),
    Report = interop_read_peer_report(interop_peer_path(Id)),
    validate_running_report(Report, interop_source_digest(), ExpectedRunId),
    Report.

validate_running_report(Report, ExpectedSource, ExpectedRunId) ->
    interop_ensure(maps:get(<<"status">>, Report, undefined) =:= <<"Running">>,
           peer_execution_not_running),
    interop_ensure(maps:get(<<"source_sha256">>, Report, undefined) =:= ExpectedSource,
           source_changed_during_execution),
    interop_ensure(maps:get(<<"run_id">>, Report, undefined) =:= ExpectedRunId,
                   stale_peer_operation),
    ok.

runtime() ->
    Os = case os:type() of
        {win32, _} -> <<"win32">>;
        {unix, darwin} -> <<"darwin">>;
        {unix, linux} -> <<"linux">>
    end,
    #{<<"os">> => Os,
      <<"otp">> => list_to_binary(erlang:system_info(otp_release))}.

delete_if_present(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> erlang:error({cannot_clear_stale_evidence, Reason})
    end.

write_json(Path, Report) ->
    write_bytes_atomic(Path, [json:encode(Report), <<"\n">>]).

write_bytes_atomic(Path, Data) ->
    interop_ensure(is_map(get(interop_state_lock)), interop_state_lock_required),
    Bytes = iolist_to_binary(Data),
    interop_ensure(byte_size(Bytes) =< 16777216, interop_state_output_too_large),
    Absolute = filename:absname(Path),
    case file:read_link_info(Absolute) of
        {error, enoent} ->
            evidence_publish_new(Absolute, Bytes, 16777216);
        {ok, _} ->
            Previous = evidence_publication_read(Absolute, 16777216),
            evidence_replace_locked(Absolute, Previous, Bytes, 16777216);
        {error, _} -> erlang:error(interop_state_output_unreadable)
    end.

with_interop_state_lock(Function) when is_function(Function, 0) ->
    interop_ensure(get(interop_state_lock) =:= undefined,
                   nested_interop_state_lock),
    Lease = acquire_interop_state_lock(),
    put(interop_state_lock, Lease),
    try Function()
    after
        erase(interop_state_lock),
        ok = release_interop_state_lock(Lease)
    end.

state_lock_self_test() ->
    Parent = self(),
    with_interop_state_lock(fun() ->
        {Pid, Ref} = spawn_monitor(fun() ->
            Result = try with_interop_state_lock(fun() -> unexpected end) of
                unexpected -> accepted
            catch error:Reason -> {rejected, Reason}
            end,
            Parent ! {interop_state_contender, self(), Result}
        end),
        receive
            {interop_state_contender, Pid, {rejected, interop_state_busy}} -> ok
        after 5000 -> erlang:error(interop_state_lock_self_test_timeout)
        end,
        receive
            {'DOWN', Ref, process, Pid, normal} -> ok
        after 5000 -> erlang:error(interop_state_contender_not_joined)
        end
    end),
    with_interop_state_lock(fun() -> ok end),
    ok.

acquire_interop_state_lock() ->
    Path = filename:absname("build/interop/state-lock"),
    _ = evidence_publication_ensure_directory(filename:dirname(Path)),
    case file:make_dir(Path) of
        ok -> ok;
        {error, eexist} -> erlang:error(interop_state_busy);
        {error, _} -> erlang:error(interop_state_lock_failed)
    end,
    _ = evidence_publication_directory_info(Path),
    Token = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Owner = filename:join(Path, "owner.json"),
    Bytes = iolist_to_binary([json:encode(#{schema => 1,
        kind => <<"interop_state_lock">>, token => Token}), <<"\n">>]),
    try
        ok = evidence_publish_new(Owner, Bytes, 4096),
        #{path => Path, owner => Owner, bytes => Bytes}
    catch
        Class:Reason:Stacktrace ->
            _ = file:delete(Owner),
            _ = file:del_dir(Path),
            erlang:raise(Class, Reason, Stacktrace)
    end.

release_interop_state_lock(Lease) ->
    Path = maps:get(path, Lease),
    Owner = maps:get(owner, Lease),
    _ = evidence_publication_directory_info(Path),
    Expected = maps:get(bytes, Lease),
    Expected = evidence_publication_read(Owner, 4096),
    {ok, ["owner.json"]} = file:list_dir(Path),
    ok = file:delete(Owner),
    ok = file:del_dir(Path),
    {error, enoent} = file:read_link_info(Path),
    ok.

rejected(Check, Reason) ->
    Rejected = try Check(), false catch error:_ -> true end,
    interop_ensure(Rejected, Reason).
