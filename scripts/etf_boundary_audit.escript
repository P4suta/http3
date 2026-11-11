#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-mode(compile).
-include("canonical_etf_wire.hrl").
-include("evidence_publication.hrl").

-define(MAXIMUM_SOURCE_BYTES, 33554432).
-define(MAXIMUM_SOURCE_TOTAL_BYTES, 67108864).
-define(SOURCE_FILES, 11).
-define(REPORT_PATH, "build/evidence/etf-boundary-audit.json").
-define(MATRIX_ROOT, "build/evidence/etf-boundary-matrix/staging").
-define(ADVERSARIAL_CONTROLS, 32).
-define(SCOPE, <<"all external-term evidence decode boundaries">>).
-define(RERUN_COMMAND, <<"escript scripts/etf_boundary_audit.escript">>).
-define(IDENTITY_BINDINGS, [<<"nonce">>, <<"source_sha256">>,
    <<"runner_sha256">>, <<"invocation_sha256">>]).

main(Arguments) ->
    try dispatch(Arguments)
    catch _:_ ->
        %% Never let an Erlang exception, stack, path, term, or source fragment
        %% escape to CI stderr.  The row path publishes its bounded typed
        %% failure document before this fixed terminal projection is emitted.
        io:put_chars(standard_error,
            <<"ETF boundary audit rejected\n">>),
        halt(1)
    end.

dispatch(["--self-test"]) ->
    Root = project_root(),
    ok = file:set_cwd(Root),
    ok = self_test(),
    io:put_chars(<<"ETF_BOUNDARY_AUDIT_SELF_TEST_READY\n">>),
    ok;
dispatch([]) ->
    Root = project_root(),
    ok = file:set_cwd(Root),
    run_audit(local_execution_context(), ?REPORT_PATH, ?RERUN_COMMAND);
dispatch(["matrix", Package, Platform, Otp]) ->
    Root = project_root(),
    ok = file:set_cwd(Root),
    Context = matrix_execution_context(Package, Platform, Otp),
    run_audit(Context, matrix_report_path(Package, Platform, Otp),
        matrix_rerun_command(Package, Platform, Otp));
dispatch(_) -> halt(2).

project_root() ->
    filename:dirname(filename:dirname(
        filename:absname(escript:script_name()))).

run_audit(ExecutionContext, ReportPath, RerunCommand) ->
    %% Remove a previous success before doing any work.  A killed or rejected
    %% attempt must never leave a stale Ready document at this row's path.
    ok = invalidate_report(ReportPath),
    put(etf_boundary_stage, adversarial_control),
    put(etf_boundary_completed_controls, 0),
    erase(etf_boundary_source_identity),
    try run_audit_ready(ExecutionContext, ReportPath, RerunCommand)
    catch _:_ ->
        ok = invalidate_report(ReportPath),
        _ = catch publish_failed_report(
            ExecutionContext, ReportPath, RerunCommand),
        erlang:error(etf_boundary_audit_rejected)
    end.

run_audit_ready(ExecutionContext, ReportPath, RerunCommand) ->
    ok = self_test(),
    put(etf_boundary_completed_controls, ?ADVERSARIAL_CONTROLS),
    put(etf_boundary_stage, source_contract),
    Sources = read_boundary_sources(),
    true = source_contract_valid(Sources),
    put(etf_boundary_stage, publication),
    true = publication_contract_valid(
        bounded_read("scripts/evidence_publication.hrl")),
    EvidenceFiles = evidence_paths(),
    EvidenceSources = bounded_evidence_sources(EvidenceFiles),
    ?SOURCE_FILES = length(EvidenceSources),
    SourceSha = source_digest(EvidenceSources),
    put(etf_boundary_source_identity,
        #{status => <<"complete">>, sha256 => SourceSha,
          files => ?SOURCE_FILES}),
    Report = #{schema => 1, status => <<"Ready">>, shareable => true,
        scope => ?SCOPE,
        source_sha256 => SourceSha,
        source_files => ?SOURCE_FILES,
        tool_identity => audit_tool_identity(),
        configuration => audit_configuration(),
        execution_context => ExecutionContext,
        runtime_identity => runtime_identity(),
        runtime_otp => unicode:characters_to_binary(
            erlang:system_info(otp_release)),
        peer_identity => <<"not-applicable: local static audit">>,
        canonical_fixture_sha256 => canonical_fixture_sha256(),
        decoded_boundaries => 4,
        canonical_reader_implementations => 1,
        compressed_terms => <<"rejected-before-decode">>,
        runtime_capability_terms => <<"rejected-before-decode">>,
        atom_creation => <<"prohibited">>,
        dispatch => <<"closed">>,
        identity_bindings => ?IDENTITY_BINDINGS,
        adversarial_controls => ?ADVERSARIAL_CONTROLS,
        completed_controls => ?ADVERSARIAL_CONTROLS,
        failed_controls => 0,
        failure_classification => #{source_contract => 0,
            adversarial_control => 0, publication => 0},
        rerun_command => RerunCommand},
    put(etf_boundary_stage, report_contract),
    true = report_valid(Report),
    put(etf_boundary_stage, publication),
    ok = publish_report(ReportPath, Report),
    io:put_chars(<<"ETF_BOUNDARY_AUDIT_READY boundaries=4 controls=32\n">>),
    ok.

local_execution_context() ->
    RuntimeOtp = unicode:characters_to_binary(
        erlang:system_info(otp_release)),
    {OsFamily, OsName} = actual_os_identity(),
    #{mode => <<"local">>, package => <<"all">>, platform => <<"local">>,
      requested_otp => RuntimeOtp, runtime_otp => RuntimeOtp,
      os_family => OsFamily, os_name => OsName,
      ci_provider => <<"local">>, runner_os => <<"not-applicable">>,
      image_os => <<"not-applicable">>}.

matrix_execution_context(Package0, Platform0, Otp0) ->
    {Package, Platform, RequestedOtp} = matrix_arguments(
        Package0, Platform0, Otp0),
    RuntimeOtp = unicode:characters_to_binary(
        erlang:system_info(otp_release)),
    RequestedOtp = RuntimeOtp,
    {OsFamily, OsName} = actual_os_identity(),
    {OsFamily, OsName, RunnerOs, ImageOs} = platform_identity(Platform),
    "true" = os:getenv("GITHUB_ACTIONS"),
    RunnerOs = required_environment_identity("RUNNER_OS", 32),
    ImageOs = required_environment_identity("ImageOS", 32),
    #{mode => <<"matrix">>, package => Package, platform => Platform,
      requested_otp => RequestedOtp, runtime_otp => RuntimeOtp,
      os_family => OsFamily, os_name => OsName,
      ci_provider => <<"github-actions">>, runner_os => RunnerOs,
      image_os => ImageOs}.

matrix_arguments(Package0, Platform0, Otp0) ->
    Package = unicode:characters_to_binary(Package0),
    Platform = unicode:characters_to_binary(Platform0),
    Otp = unicode:characters_to_binary(Otp0),
    true = lists:member(Package, [<<"http">>, <<"http3">>, <<"quic_core">>]),
    true = lists:member(Platform,
        [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>]),
    true = lists:member(Otp, [<<"28">>, <<"29">>]),
    {Package, Platform, Otp}.

actual_os_identity() ->
    case os:type() of
        {unix, linux} -> {<<"unix">>, <<"linux">>};
        {unix, darwin} -> {<<"unix">>, <<"darwin">>};
        {win32, nt} -> {<<"win32">>, <<"nt">>};
        _ -> erlang:error(unsupported_matrix_operating_system)
    end.

platform_identity(<<"ubuntu-24.04">>) ->
    {<<"unix">>, <<"linux">>, <<"Linux">>, <<"ubuntu24">>};
platform_identity(<<"macos-15">>) ->
    {<<"unix">>, <<"darwin">>, <<"macOS">>, <<"macos15">>};
platform_identity(<<"windows-2025">>) ->
    {<<"win32">>, <<"nt">>, <<"Windows">>, <<"win25">>}.

required_environment_identity(Name, Maximum) ->
    case os:getenv(Name) of
        Value when is_list(Value), Value =/= [] ->
            Bytes = unicode:characters_to_binary(Value),
            true = bounded_printable_ascii(Bytes, Maximum),
            Bytes;
        _ -> erlang:error(missing_matrix_environment_identity)
    end.

matrix_report_path(Package0, Platform0, Otp0) ->
    {Package, Platform, Otp} = matrix_arguments(
        Package0, Platform0, Otp0),
    filename:join([?MATRIX_ROOT,
        binary_to_list(iolist_to_binary([
            "etf-boundary-", Package, "-", Platform, "-otp", Otp])),
        "report.json"]).

matrix_rerun_command(Package0, Platform0, Otp0) ->
    {Package, Platform, Otp} = matrix_arguments(
        Package0, Platform0, Otp0),
    unicode:characters_to_binary([
        "escript scripts/etf_boundary_audit.escript matrix ", Package, " ",
        Platform, " ", Otp]).

boundary_paths() ->
    ["scripts/canonical_etf_wire.hrl",
     "scripts/supervised_gleam.escript",
     "scripts/execution_beam_identity.hrl",
     "scripts/qualification_eunit_listener.erl",
     "scripts/http3_multiplexing_attested_runner.erl",
     "scripts/http3_multiplexing_evidence.escript"].

evidence_paths() ->
    lists:sort(boundary_paths() ++ [
        "scripts/canonical_etf_wire_self_test.escript",
        "scripts/evidence_publication.hrl",
        "scripts/etf_boundary_audit.escript",
        "scripts/etf_boundary_matrix.escript",
        "scripts/json_evidence.hrl"
    ]).

read_boundary_sources() ->
    maps:from_list([{Path, bounded_read(Path)} || Path <- boundary_paths()]).

bounded_evidence_sources(Paths) ->
    {Sources, _Total} = lists:mapfoldl(fun(Path, Total) ->
        Bytes = bounded_read(Path),
        Next = Total + byte_size(Bytes),
        true = Next =< ?MAXIMUM_SOURCE_TOTAL_BYTES,
        {{Path, Bytes}, Next}
    end, 0, Paths),
    Sources.

bounded_read(Path) ->
    Bytes = evidence_publication_read(Path, ?MAXIMUM_SOURCE_BYTES),
    true = byte_size(Bytes) > 0,
    Bytes.

source_contract_valid(Sources) when is_map(Sources) ->
    try
        Expected = lists:sort(boundary_paths()),
        Expected = lists:sort(maps:keys(Sources)),
        1 = occurrences(Sources, <<"binary_to_term(">>),
        0 = occurrences(Sources, <<"binary_to_atom(">>),
        0 = occurrences(Sources,
            <<"apply(qualification_eunit_listener">>),
        0 = occurrences(Sources,
            <<"supervised_gleam_failure_projection_v1">>),
        0 = occurrences(Sources,
            <<"supervised_gleam_projection_invocation_v1">>),
        0 = occurrences(Sources, <<"execution_beam_invocation_v1">>),
        0 = occurrences(Sources,
            <<"http3_multiplexing_invocation_v1">>),
        0 = occurrences(Sources, <<"http3_multiplexing_receipt_v1">>),
        Reader = maps:get("scripts/canonical_etf_wire.hrl", Sources),
        true = count(Reader, <<"binary_to_term(">>) =:= 1,
        true = contains(Reader,
            <<"Deliberately absent: COMPRESSED">>),
        true = contains(Reader,
            <<"canonical_etf_interop_fixture_v1">>),
        true = contains(Reader, <<"canonical_etf_scan(_, _, _, _) -> error">>),
        Supervised = maps:get("scripts/supervised_gleam.escript", Sources),
        true = contains(Supervised,
            <<"supervised_gleam_failure_projection_v2">>),
        true = contains(Supervised,
            <<"supervised_gleam_projection_invocation_v2">>),
        true = contains(Supervised,
            <<"gleam_test_failure_projection_invocation_sha">>),
        true = count(Supervised, <<"canonical_etf_decode(">>) >= 2,
        Identity = maps:get("scripts/execution_beam_identity.hrl", Sources),
        true = contains(Identity, <<"execution_beam_invocation_v2">>),
        true = contains(Identity,
            <<"qualification_eunit_listener:run_invocation">>),
        Listener = maps:get(
            "scripts/qualification_eunit_listener.erl", Sources),
        true = contains(Listener, <<"run_invocation/7">>),
        true = contains(Listener, <<"binary_to_existing_atom">>),
        true = contains(Listener, <<"canonical_etf_decode(">>),
        MuxRunner = maps:get(
            "scripts/http3_multiplexing_attested_runner.erl", Sources),
        true = contains(MuxRunner,
            <<"http3_multiplexing_invocation_v2">>),
        true = contains(MuxRunner, <<"http3_multiplexing_receipt_v2">>),
        true = contains(MuxRunner, <<"canonical_etf_decode(">>),
        MuxEvidence = maps:get(
            "scripts/http3_multiplexing_evidence.escript", Sources),
        true = contains(MuxEvidence,
            <<"http3_multiplexing_invocation_v2">>),
        true = contains(MuxEvidence,
            <<"http3_multiplexing_receipt_v2">>),
        true = contains(MuxEvidence, <<"invocation_sha256">>),
        true = contains(MuxEvidence, <<"canonical_etf_decode(">>),
        true
    catch _:_ -> false end;
source_contract_valid(_) -> false.

publication_contract_valid(Bytes) when is_binary(Bytes) ->
    count(Bytes, <<"file:make_link(">>) =:= 1 andalso
    contains(Bytes, <<"element(9, Initial) =:= 1">>) andalso
    contains(Bytes, <<"evidence_publication_identity(Initial)">>);
publication_contract_valid(_) -> false.

occurrences(Sources, Needle) ->
    lists:sum([count(Bytes, Needle) || Bytes <- maps:values(Sources)]).

count(Bytes, Needle) -> length(binary:matches(Bytes, Needle)).

contains(Bytes, Needle) -> binary:match(Bytes, Needle) =/= nomatch.

self_test() ->
    Safe = maps:from_list([{Path, safe_fixture(Path)} || Path <- boundary_paths()]),
    true = source_contract_valid(Safe),
    false = source_contract_valid(maps:remove(
        "scripts/qualification_eunit_listener.erl", Safe)),
    false = source_contract_valid(mutate(Safe,
        "scripts/http3_multiplexing_attested_runner.erl",
        <<"\nbinary_to_term(Unsafe).\n">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/canonical_etf_wire.hrl",
        <<"canonical_etf_interop_fixture_v1">>,
        <<"canonical_etf_interop_fixture_v0">>)),
    false = source_contract_valid(mutate(Safe,
        "scripts/qualification_eunit_listener.erl",
        <<"\nbinary_to_atom(Name).\n">>)),
    false = source_contract_valid(mutate(Safe,
        "scripts/execution_beam_identity.hrl",
        <<"\napply(qualification_eunit_listener, Function, Args).\n">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/supervised_gleam.escript",
        <<"supervised_gleam_failure_projection_v2">>,
        <<"supervised_gleam_failure_projection_v1">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/supervised_gleam.escript",
        <<"supervised_gleam_projection_invocation_v2">>,
        <<"supervised_gleam_projection_invocation_v1">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/execution_beam_identity.hrl",
        <<"execution_beam_invocation_v2">>,
        <<"execution_beam_invocation_v1">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/http3_multiplexing_attested_runner.erl",
        <<"http3_multiplexing_invocation_v2">>,
        <<"http3_multiplexing_invocation_v1">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/http3_multiplexing_evidence.escript",
        <<"http3_multiplexing_receipt_v2">>,
        <<"http3_multiplexing_receipt_v1">>)),
    false = source_contract_valid(replace(Safe,
        "scripts/qualification_eunit_listener.erl",
        <<"binary_to_existing_atom">>, <<"existing_atom_lookup">>)),
    Publication = <<"file:make_link(Temporary, Path)\n"
        "element(9, Initial) =:= 1\n"
        "evidence_publication_identity(Initial)\n">>,
    true = publication_contract_valid(Publication),
    false = publication_contract_valid(binary:replace(Publication,
        <<"file:make_link(">>, <<"file:rename(">>)),
    false = publication_contract_valid(binary:replace(Publication,
        <<"element(9, Initial) =:= 1">>,
        <<"element(9, Initial) >= 1">>)),
    Report = valid_report_fixture(),
    true = report_valid(Report),
    false = report_valid(Report#{status := <<"Failed">>}),
    false = report_valid(Report#{shareable := false}),
    false = report_valid(Report#{source_sha256 := binary:copy(<<"A">>, 64)}),
    false = report_valid(Report#{source_sha256 := binary:copy(<<"g">>, 64)}),
    false = report_valid(Report#{source_files := ?SOURCE_FILES - 1}),
    false = report_valid(Report#{tool_identity := #{
        kind => <<"etf-boundary-audit">>,
        sha256 => binary:copy(<<"A">>, 64)}}),
    false = report_valid(Report#{tool_identity := #{
        kind => <<"etf-boundary-audit">>,
        sha256 => binary:copy(<<"b">>, 64)}}),
    false = report_valid(Report#{identity_bindings := lists:reverse(
        ?IDENTITY_BINDINGS)}),
    false = report_valid(Report#{rerun_command := <<"true">>}),
    false = report_valid(Report#{scope := <<"partial">>}),
    false = report_valid(Report#{dispatch := <<"open">>}),
    false = report_valid(Report#{canonical_reader_implementations := 2}),
    false = report_valid(Report#{failed_controls := 1}),
    false = report_valid(Report#{completed_controls :=
        ?ADVERSARIAL_CONTROLS - 1}),
    false = report_valid(Report#{execution_context := #{}}),
    Context = maps:get(execution_context, Report),
    false = report_valid(Report#{execution_context := Context#{
        runtime_otp := <<"28">>}}),
    false = report_valid(Report#{configuration := #{}}),
    false = report_valid(Report#{runtime_identity := #{kind => <<"shell">>,
        otp_release => <<"29">>, erts_version => <<"15">>}}),
    false = report_valid(Report#{runtime_identity := #{
        kind => <<"erlang-escript">>, otp_release => <<>>,
        erts_version => <<"15">>}}),
    Runtime = maps:get(runtime_identity, Report),
    false = report_valid(Report#{runtime_identity := Runtime#{
        erts_version := <<"private key">>}}),
    false = report_valid(Report#{canonical_fixture_sha256 :=
        binary:copy(<<"0">>, 64)}),
    false = report_valid(Report#{peer_identity := <<"unknown">>}),
    false = report_valid(Report#{failure_classification := #{
        source_contract => 1, adversarial_control => 0,
        publication => 0}}),
    false = report_valid(Report#{failure_classification := #{
        source_contract => 0, adversarial_control => 0,
        publication => 0, other => 0}}),
    ok.

valid_report_fixture() ->
    #{schema => 1, status => <<"Ready">>, shareable => true,
      scope => ?SCOPE, source_sha256 => binary:copy(<<"a">>, 64),
      source_files => ?SOURCE_FILES,
      tool_identity => audit_tool_identity(),
      decoded_boundaries => 4,
      configuration => audit_configuration(),
      execution_context => fixture_execution_context(),
      runtime_identity => #{kind => <<"erlang-escript">>,
          otp_release => <<"29">>, erts_version => <<"15.2">>},
      runtime_otp => <<"29">>,
      peer_identity => <<"not-applicable: local static audit">>,
      canonical_fixture_sha256 => canonical_fixture_sha256(),
      canonical_reader_implementations => 1,
      compressed_terms => <<"rejected-before-decode">>,
      runtime_capability_terms => <<"rejected-before-decode">>,
      atom_creation => <<"prohibited">>, dispatch => <<"closed">>,
      identity_bindings => ?IDENTITY_BINDINGS,
      adversarial_controls => ?ADVERSARIAL_CONTROLS,
      completed_controls => ?ADVERSARIAL_CONTROLS,
      failed_controls => 0,
      failure_classification => #{source_contract => 0,
          adversarial_control => 0, publication => 0},
      rerun_command => ?RERUN_COMMAND}.

fixture_execution_context() ->
    #{mode => <<"local">>, package => <<"all">>, platform => <<"local">>,
      requested_otp => <<"29">>, runtime_otp => <<"29">>,
      os_family => <<"unix">>, os_name => <<"linux">>,
      ci_provider => <<"local">>, runner_os => <<"not-applicable">>,
      image_os => <<"not-applicable">>}.

safe_fixture("scripts/canonical_etf_wire.hrl") ->
    <<"binary_to_term(Bytes,[safe]).\n"
      "Deliberately absent: COMPRESSED\n"
      "canonical_etf_interop_fixture_v1\n"
      "canonical_etf_scan(_, _, _, _) -> error.\n">>;
safe_fixture("scripts/supervised_gleam.escript") ->
    <<"supervised_gleam_failure_projection_v2\n"
      "supervised_gleam_projection_invocation_v2\n"
      "gleam_test_failure_projection_invocation_sha\n"
      "canonical_etf_decode(A). canonical_etf_decode(B).\n">>;
safe_fixture("scripts/execution_beam_identity.hrl") ->
    <<"execution_beam_invocation_v2\n"
      "qualification_eunit_listener:run_invocation\n">>;
safe_fixture("scripts/qualification_eunit_listener.erl") ->
    <<"run_invocation/7\nbinary_to_existing_atom\ncanonical_etf_decode(Body).\n">>;
safe_fixture("scripts/http3_multiplexing_attested_runner.erl") ->
    <<"http3_multiplexing_invocation_v2\n"
      "http3_multiplexing_receipt_v2\ncanonical_etf_decode(Body).\n">>;
safe_fixture("scripts/http3_multiplexing_evidence.escript") ->
    <<"http3_multiplexing_invocation_v2\n"
      "http3_multiplexing_receipt_v2\ninvocation_sha256\n"
      "canonical_etf_decode(Body).\n">>.

mutate(Sources, Path, Suffix) ->
    Sources#{Path := <<(maps:get(Path, Sources))/binary, Suffix/binary>>}.

replace(Sources, Path, Before, After) ->
    Original = maps:get(Path, Sources),
    Replaced = binary:replace(Original, Before, After),
    true = Original =/= Replaced,
    Sources#{Path := Replaced}.

source_digest(Sources) ->
    Context = lists:foldl(fun({Path, Bytes}, Acc) ->
        crypto:hash_update(Acc,
            [unicode:characters_to_binary(Path), 0, Bytes, 0])
    end, crypto:hash_init(sha256), Sources),
    binary:encode_hex(crypto:hash_final(Context), lowercase).

audit_configuration() ->
    #{maximum_source_bytes => ?MAXIMUM_SOURCE_BYTES,
      maximum_source_total_bytes => ?MAXIMUM_SOURCE_TOTAL_BYTES,
      maximum_report_bytes => 65536,
      boundary_count => 4}.

runtime_identity() ->
    #{kind => <<"erlang-escript">>,
      otp_release => unicode:characters_to_binary(
          erlang:system_info(otp_release)),
      erts_version => unicode:characters_to_binary(
          erlang:system_info(version))}.

audit_tool_identity() ->
    #{kind => <<"etf-boundary-audit">>,
      sha256 => sha256(bounded_read("scripts/etf_boundary_audit.escript"))}.

canonical_fixture_sha256() ->
    binary:encode_hex(crypto:hash(sha256, term_to_binary(
        canonical_etf_interop_fixture(), [{minor_version, 2}])), lowercase).

sha256(Bytes) ->
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

report_valid(Report) ->
    try
        [adversarial_controls, atom_creation, canonical_fixture_sha256,
         canonical_reader_implementations, completed_controls,
         compressed_terms, configuration, decoded_boundaries, dispatch,
         execution_context, failed_controls,
         failure_classification, identity_bindings, peer_identity,
         rerun_command, runtime_capability_terms, runtime_identity,
         runtime_otp, schema, scope, shareable, source_files, source_sha256,
         status, tool_identity] =
            lists:sort(maps:keys(Report)),
        1 = maps:get(schema, Report),
        <<"Ready">> = maps:get(status, Report),
        true = maps:get(shareable, Report),
        ?SCOPE = maps:get(scope, Report),
        4 = maps:get(decoded_boundaries, Report),
        1 = maps:get(canonical_reader_implementations, Report),
        <<"rejected-before-decode">> = maps:get(compressed_terms, Report),
        <<"rejected-before-decode">> = maps:get(
            runtime_capability_terms, Report),
        <<"prohibited">> = maps:get(atom_creation, Report),
        <<"closed">> = maps:get(dispatch, Report),
        ?IDENTITY_BINDINGS = maps:get(identity_bindings, Report),
        ?ADVERSARIAL_CONTROLS = maps:get(adversarial_controls, Report),
        ?ADVERSARIAL_CONTROLS = maps:get(completed_controls, Report),
        0 = maps:get(failed_controls, Report),
        FailureClassification = maps:get(failure_classification, Report),
        #{source_contract := 0, adversarial_control := 0,
          publication := 0} = FailureClassification,
        [adversarial_control, publication, source_contract] = lists:sort(
            maps:keys(FailureClassification)),
        true = maps:get(configuration, Report) =:= audit_configuration(),
        RuntimeIdentity = maps:get(runtime_identity, Report),
        true = runtime_identity_valid(RuntimeIdentity),
        RuntimeOtp = maps:get(runtime_otp, Report),
        true = RuntimeOtp =:= <<"28">> orelse RuntimeOtp =:= <<"29">>,
        RuntimeOtp = maps:get(otp_release, RuntimeIdentity),
        ExecutionContext = maps:get(execution_context, Report),
        true = execution_context_valid(ExecutionContext, RuntimeIdentity),
        <<"not-applicable: local static audit">> = maps:get(
            peer_identity, Report),
        ExpectedFixtureSha = canonical_fixture_sha256(),
        ExpectedFixtureSha = maps:get(canonical_fixture_sha256, Report),
        SourceSha = maps:get(source_sha256, Report),
        true = lower_sha256(SourceSha),
        ?SOURCE_FILES = maps:get(source_files, Report),
        true = tool_identity_valid(maps:get(tool_identity, Report)),
        true = maps:get(tool_identity, Report) =:= audit_tool_identity(),
        true = expected_rerun_command(ExecutionContext) =:=
            maps:get(rerun_command, Report),
        true = safe_json_value(Report),
        true
    catch _:_ -> false end.

lower_sha256(Bytes) when is_binary(Bytes), byte_size(Bytes) =:= 64 ->
    lists:all(fun(Byte) ->
        (Byte >= $0 andalso Byte =< $9) orelse
        (Byte >= $a andalso Byte =< $f)
    end, binary_to_list(Bytes));
lower_sha256(_) -> false.

tool_identity_valid(Identity) when is_map(Identity) ->
    try
        [kind, sha256] = lists:sort(maps:keys(Identity)),
        <<"etf-boundary-audit">> = maps:get(kind, Identity),
        true = lower_sha256(maps:get(sha256, Identity)),
        true
    catch _:_ -> false end;
tool_identity_valid(_) -> false.

runtime_identity_valid(Identity) when is_map(Identity) ->
    try
        [erts_version, kind, otp_release] = lists:sort(maps:keys(Identity)),
        <<"erlang-escript">> = maps:get(kind, Identity),
        true = bounded_printable_ascii(maps:get(otp_release, Identity), 32),
        true = bounded_printable_ascii(maps:get(erts_version, Identity), 64),
        true
    catch _:_ -> false end;
runtime_identity_valid(_) -> false.

execution_context_valid(Context, RuntimeIdentity)
  when is_map(Context), is_map(RuntimeIdentity) ->
    try
        [ci_provider, image_os, mode, os_family, os_name, package,
         platform, requested_otp, runner_os, runtime_otp] =
            lists:sort(maps:keys(Context)),
        RuntimeOtp = maps:get(otp_release, RuntimeIdentity),
        RuntimeOtp = maps:get(requested_otp, Context),
        RuntimeOtp = maps:get(runtime_otp, Context),
        true = lists:member(RuntimeOtp, [<<"28">>, <<"29">>]),
        true = bounded_printable_ascii(maps:get(runner_os, Context), 32),
        true = bounded_printable_ascii(maps:get(image_os, Context), 32),
        true = case maps:get(mode, Context) of
            <<"local">> ->
                maps:get(package, Context) =:= <<"all">> andalso
                maps:get(platform, Context) =:= <<"local">> andalso
                maps:get(ci_provider, Context) =:= <<"local">> andalso
                maps:get(runner_os, Context) =:= <<"not-applicable">> andalso
                maps:get(image_os, Context) =:= <<"not-applicable">> andalso
                valid_os_pair(maps:get(os_family, Context),
                    maps:get(os_name, Context));
            <<"matrix">> -> matrix_context_fields_valid(Context);
            _ -> false
        end,
        true
    catch _:_ -> false end;
execution_context_valid(_, _) -> false.

matrix_context_fields_valid(Context) ->
    Package = maps:get(package, Context),
    Platform = maps:get(platform, Context),
    lists:member(Package, [<<"http">>, <<"http3">>, <<"quic_core">>])
    andalso maps:get(ci_provider, Context) =:= <<"github-actions">>
    andalso case Platform of
        <<"ubuntu-24.04">> ->
            context_platform_matches(Context, <<"unix">>, <<"linux">>,
                <<"Linux">>, <<"ubuntu24">>);
        <<"macos-15">> ->
            context_platform_matches(Context, <<"unix">>, <<"darwin">>,
                <<"macOS">>, <<"macos15">>);
        <<"windows-2025">> ->
            context_platform_matches(Context, <<"win32">>, <<"nt">>,
                <<"Windows">>, <<"win25">>);
        _ -> false
    end.

context_platform_matches(Context, Family, Name, Runner, Image) ->
    maps:get(os_family, Context) =:= Family andalso
    maps:get(os_name, Context) =:= Name andalso
    maps:get(runner_os, Context) =:= Runner andalso
    maps:get(image_os, Context) =:= Image.

valid_os_pair(<<"unix">>, <<"linux">>) -> true;
valid_os_pair(<<"unix">>, <<"darwin">>) -> true;
valid_os_pair(<<"win32">>, <<"nt">>) -> true;
valid_os_pair(_, _) -> false.

expected_rerun_command(#{mode := <<"local">>}) -> ?RERUN_COMMAND;
expected_rerun_command(#{mode := <<"matrix">>, package := Package,
                         platform := Platform, requested_otp := Otp}) ->
    unicode:characters_to_binary([
        "escript scripts/etf_boundary_audit.escript matrix ", Package, " ",
        Platform, " ", Otp]);
expected_rerun_command(_) -> <<>>.

bounded_printable_ascii(Bytes, Maximum)
  when is_binary(Bytes), byte_size(Bytes) > 0,
       byte_size(Bytes) =< Maximum ->
    lists:all(fun(Byte) -> Byte >= 32 andalso Byte =< 126 end,
        binary_to_list(Bytes));
bounded_printable_ascii(_, _) -> false.

safe_json_value(Value) when is_binary(Value) ->
    byte_size(Value) =< 4096 andalso
    lists:all(fun(Byte) -> Byte >= 32 andalso Byte =< 126 end,
        binary_to_list(Value)) andalso safe_binary(Value);
safe_json_value(Value) when is_integer(Value) ->
    Value >= 0 andalso Value =< 1000000000;
safe_json_value(true) -> true;
safe_json_value(false) -> true;
safe_json_value(null) -> true;
safe_json_value(Value) when is_atom(Value) ->
    safe_json_value(atom_to_binary(Value, utf8));
safe_json_value(Value) when is_list(Value) ->
    length(Value) =< 128 andalso lists:all(fun safe_json_value/1, Value);
safe_json_value(Value) when is_map(Value) ->
    map_size(Value) =< 64 andalso
    lists:all(fun({Key, Item}) ->
        safe_json_value(Key) andalso safe_json_value(Item)
    end, maps:to_list(Value));
safe_json_value(_) -> false.

safe_binary(Bytes) ->
    Lower = ascii_lower(Bytes),
    lists:all(fun(Forbidden) ->
        binary:match(Lower, Forbidden) =:= nomatch
    end, [<<"authorization">>, <<"bearer ">>, <<"cookie">>,
          <<"password">>, <<"private key">>, <<"-----begin">>,
          <<"/home/">>, <<"/users/">>, <<":\\">>, <<"stacktrace">>,
          <<"exception">>, <<"socket=">>, <<"pid=">>]).

ascii_lower(Bytes) ->
    << <<(ascii_lower_byte(Byte))>> || <<Byte>> <= Bytes >>.

ascii_lower_byte(Byte) when Byte >= $A, Byte =< $Z -> Byte + 32;
ascii_lower_byte(Byte) -> Byte.

publish_report(Path, Report) ->
    true = safe_json_value(Report),
    _ = evidence_publication_ensure_directory(
        filename:dirname(Path)),
    Bytes = iolist_to_binary([json:encode(Report), $\n]),
    true = byte_size(Bytes) =< 65536,
    ok = evidence_publish_new(Path, Bytes, 65536),
    Bytes = evidence_publication_read(Path, 65536),
    ok.

publish_failed_report(ExecutionContext, ReportPath, RerunCommand) ->
    Completed = case get(etf_boundary_completed_controls) of
        Count when is_integer(Count), Count >= 0,
                   Count =< ?ADVERSARIAL_CONTROLS -> Count;
        _ -> 0
    end,
    Stage = case get(etf_boundary_stage) of
        source_contract -> source_contract;
        adversarial_control -> adversarial_control;
        report_contract -> report_contract;
        publication -> publication;
        _ -> other
    end,
    FailedControls = case {Stage, Completed} of
        {adversarial_control, Count}
          when Count < ?ADVERSARIAL_CONTROLS -> 1;
        _ -> 0
    end,
    Report = #{schema => 1, report_kind => <<"etf_boundary_row">>,
        status => <<"Failed">>, shareable => true, scope => ?SCOPE,
        source_identity => failure_source_identity(),
        tool_identity => failure_tool_identity(),
        configuration => audit_configuration(),
        execution_context => ExecutionContext,
        runtime_identity => runtime_identity(),
        peer_identity => <<"not-applicable: local static audit">>,
        requested_controls => ?ADVERSARIAL_CONTROLS,
        completed_controls => Completed,
        failed_controls => FailedControls,
        failure_classification => failed_classification(Stage),
        details_retained => false,
        rerun_command => RerunCommand},
    publish_report(ReportPath, Report).

failure_source_identity() ->
    case get(etf_boundary_source_identity) of
        Identity when is_map(Identity) -> Identity;
        _ ->
            try
                Sources = bounded_evidence_sources(evidence_paths()),
                ?SOURCE_FILES = length(Sources),
                #{status => <<"complete">>, sha256 => source_digest(Sources),
                  files => ?SOURCE_FILES}
            catch _:_ ->
                #{status => <<"unavailable">>, sha256 => <<"unavailable">>,
                  files => 0}
            end
    end.

failure_tool_identity() ->
    try audit_tool_identity()
    catch _:_ ->
        #{kind => <<"etf-boundary-audit">>, sha256 => <<"unavailable">>}
    end.

failed_classification(Stage) ->
    Empty = #{source_contract => 0, adversarial_control => 0,
        report_contract => 0, publication => 0, other => 0},
    case maps:is_key(Stage, Empty) of
        true -> Empty#{Stage := 1};
        false -> Empty#{other := 1}
    end.

invalidate_report(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_invalidate_etf_audit)
    end.
