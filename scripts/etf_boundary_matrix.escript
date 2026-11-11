#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-mode(compile).
-include("canonical_etf_wire.hrl").
-include("evidence_publication.hrl").
-include("json_evidence.hrl").

-define(INPUT_ROOT, "build/evidence/etf-boundary-matrix/inputs").
-define(OUTPUT_PATH, "build/evidence/etf-boundary-matrix/report.json").
-define(MAXIMUM_SOURCE_BYTES, 33554432).
-define(MAXIMUM_SOURCE_TOTAL_BYTES, 67108864).
-define(MAXIMUM_ROW_BYTES, 65536).
-define(MAXIMUM_AGGREGATE_BYTES, 131072).
-define(ROWS, 18).
-define(SOURCE_FILES, 11).
-define(BOUNDARIES, 4).
-define(ADVERSARIAL_CONTROLS, 32).
-define(SCOPE, <<"all external-term evidence decode boundaries across the required runtime matrix">>).
-define(RERUN_COMMAND, <<"escript scripts/etf_boundary_matrix.escript">>).
-define(IDENTITY_BINDINGS, [<<"nonce">>, <<"source_sha256">>,
    <<"runner_sha256">>, <<"invocation_sha256">>]).

main(Arguments) ->
    try dispatch(Arguments)
    catch _:_ ->
        %% The aggregate and its self-test have the same failure-secrecy
        %% boundary: never print a decoded term, path, exception, or stack.
        io:put_chars(standard_error,
            <<"ETF boundary matrix rejected\n">>),
        halt(1)
    end.

dispatch(["--self-test"]) ->
    ok = set_project_root(),
    ok = self_test(),
    io:put_chars(<<"ETF_BOUNDARY_MATRIX_SELF_TEST_READY\n">>),
    ok;
dispatch([]) ->
    ok = set_project_root(),
    %% Invalidate a previous Ready aggregate before inspecting any new input.
    %% A killed run therefore cannot preserve stale success evidence.
    ok = invalidate_report(?OUTPUT_PATH),
    put(etf_matrix_stage, source_identity),
    put(etf_matrix_verified_rows, 0),
    put(etf_matrix_artifact_directories, 0),
    erase(etf_matrix_source_identity),
    erase(etf_matrix_fixture_identity),
    try aggregate()
    catch _:_ ->
        %% A publication verification failure may have left this attempt's
        %% target behind.  Remove it before publishing the bounded failure.
        ok = invalidate_report(?OUTPUT_PATH),
        _ = catch publish_failed_report(),
        erlang:error(etf_boundary_matrix_rejected)
    end;
dispatch(_) -> halt(2).

set_project_root() ->
    Root = filename:dirname(filename:dirname(
        filename:absname(escript:script_name()))),
    file:set_cwd(Root).

aggregate() ->
    Expected = expected_rows(),
    SourceSha = current_source_sha256(),
    put(etf_matrix_source_identity,
        #{status => <<"complete">>, sha256 => SourceSha,
          files => ?SOURCE_FILES}),
    put(etf_matrix_stage, fixture_identity),
    FixtureSha = canonical_fixture_sha256(),
    put(etf_matrix_fixture_identity,
        #{status => <<"complete">>, sha256 => FixtureSha}),
    put(etf_matrix_stage, inventory),
    Inventory = read_inventory(?INPUT_ROOT),
    true = inventory_contract_valid(Inventory),
    put(etf_matrix_artifact_directories, ?ROWS),
    put(etf_matrix_stage, row_contract),
    Rows = read_rows(Expected, SourceSha, FixtureSha, []),
    true = matrix_rows_valid(Rows, SourceSha, FixtureSha),
    %% Detect a checkout mutation spanning the per-file bounded reads.
    put(etf_matrix_stage, source_identity),
    SourceSha = current_source_sha256(),
    Report = ready_report(Rows, SourceSha, FixtureSha),
    put(etf_matrix_stage, report_contract),
    true = aggregate_report_valid(Report),
    put(etf_matrix_stage, publication),
    ok = publish_document(?OUTPUT_PATH, Report, ?MAXIMUM_AGGREGATE_BYTES),
    io:put_chars(<<"ETF_BOUNDARY_MATRIX_READY rows=18 controls=576\n">>),
    ok.

read_inventory(Root) ->
    {ok, Names} = file:list_dir(Root),
    [{Name, artifact_directory_entries(filename:join(Root, Name))}
        || Name <- lists:sort(Names)].

artifact_directory_entries(Directory) ->
    {ok, Info} = file:read_link_info(Directory),
    true = element(1, Info) =:= file_info,
    true = element(3, Info) =:= directory,
    {ok, Entries} = file:list_dir(Directory),
    lists:sort(Entries).

inventory_contract_valid(Inventory) when is_list(Inventory) ->
    try
        ExpectedNames = lists:sort([artifact_name(Row)
            || Row <- expected_rows()]),
        ActualNames = lists:sort([Name || {Name, _} <- Inventory]),
        ?ROWS = length(Inventory),
        ?ROWS = length(lists:usort(ActualNames)),
        ExpectedNames = ActualNames,
        true = lists:all(fun({Name, Entries}) ->
            lists:member(Name, ExpectedNames) andalso
            Entries =:= ["report.json"]
        end, Inventory),
        true
    catch _:_ -> false end;
inventory_contract_valid(_) -> false.

read_row(Expected, SourceSha, FixtureSha) ->
    Path = filename:join([
        ?INPUT_ROOT, artifact_name(Expected), "report.json"]),
    Bytes = evidence_publication_read(Path, ?MAXIMUM_ROW_BYTES),
    Report = evidence_json_decode(Bytes),
    true = row_report_valid(Report, Expected, SourceSha, FixtureSha),
    row_summary(Expected, Report, sha256(Bytes)).

read_rows([], _SourceSha, _FixtureSha, Acc) ->
    lists:reverse(Acc);
read_rows([Expected | Rest], SourceSha, FixtureSha, Acc) ->
    Summary = read_row(Expected, SourceSha, FixtureSha),
    Verified = case get(etf_matrix_verified_rows) of
        Count when is_integer(Count), Count >= 0, Count < ?ROWS -> Count + 1;
        _ -> 1
    end,
    put(etf_matrix_verified_rows, Verified),
    read_rows(Rest, SourceSha, FixtureSha, [Summary | Acc]).

row_report_valid(Report, Expected, SourceSha, FixtureSha)
  when is_map(Report), is_map(Expected) ->
    try
        true = exact_keys(Report, row_report_keys()),
        1 = maps:get(<<"schema">>, Report),
        <<"Ready">> = maps:get(<<"status">>, Report),
        true = maps:get(<<"shareable">>, Report),
        <<"all external-term evidence decode boundaries">> =
            maps:get(<<"scope">>, Report),
        SourceSha = maps:get(<<"source_sha256">>, Report),
        true = lower_sha256(SourceSha),
        ?SOURCE_FILES = maps:get(<<"source_files">>, Report),
        true = row_tool_identity_valid(
            maps:get(<<"tool_identity">>, Report)),
        true = configuration_valid(maps:get(<<"configuration">>, Report)),
        Context = maps:get(<<"execution_context">>, Report),
        true = execution_context_valid(Context, Expected),
        Runtime = maps:get(<<"runtime_identity">>, Report),
        true = runtime_identity_valid(Runtime, Expected),
        ExpectedOtp = maps:get(otp, Expected),
        ExpectedOtp = maps:get(<<"runtime_otp">>, Report),
        ExpectedOtp = maps:get(<<"runtime_otp">>, Context),
        ExpectedOtp = maps:get(<<"otp_release">>, Runtime),
        <<"not-applicable: local static audit">> =
            maps:get(<<"peer_identity">>, Report),
        FixtureSha = maps:get(<<"canonical_fixture_sha256">>, Report),
        true = lower_sha256(FixtureSha),
        ?BOUNDARIES = maps:get(<<"decoded_boundaries">>, Report),
        1 = maps:get(<<"canonical_reader_implementations">>, Report),
        <<"rejected-before-decode">> = maps:get(<<"compressed_terms">>, Report),
        <<"rejected-before-decode">> =
            maps:get(<<"runtime_capability_terms">>, Report),
        <<"prohibited">> = maps:get(<<"atom_creation">>, Report),
        <<"closed">> = maps:get(<<"dispatch">>, Report),
        ?IDENTITY_BINDINGS = maps:get(<<"identity_bindings">>, Report),
        ?ADVERSARIAL_CONTROLS = maps:get(<<"adversarial_controls">>, Report),
        ?ADVERSARIAL_CONTROLS = maps:get(<<"completed_controls">>, Report),
        0 = maps:get(<<"failed_controls">>, Report),
        true = failure_classification_valid(
            maps:get(<<"failure_classification">>, Report)),
        ExpectedRerun = expected_row_rerun(Expected),
        ExpectedRerun = maps:get(<<"rerun_command">>, Report),
        true = safe_json_value(Report),
        true
    catch _:_ -> false end;
row_report_valid(_, _, _, _) -> false.

row_report_keys() ->
    [<<"adversarial_controls">>, <<"atom_creation">>,
     <<"canonical_fixture_sha256">>, <<"canonical_reader_implementations">>,
     <<"completed_controls">>, <<"compressed_terms">>, <<"configuration">>,
     <<"decoded_boundaries">>, <<"dispatch">>, <<"execution_context">>,
     <<"failed_controls">>, <<"failure_classification">>,
     <<"identity_bindings">>, <<"peer_identity">>, <<"rerun_command">>,
     <<"runtime_capability_terms">>, <<"runtime_identity">>, <<"runtime_otp">>,
     <<"schema">>, <<"scope">>, <<"shareable">>, <<"source_files">>,
     <<"source_sha256">>, <<"status">>, <<"tool_identity">>].

configuration_valid(Configuration) when is_map(Configuration) ->
    exact_keys(Configuration,
        [<<"boundary_count">>, <<"maximum_report_bytes">>,
         <<"maximum_source_bytes">>, <<"maximum_source_total_bytes">>])
    andalso
    maps:get(<<"boundary_count">>, Configuration, undefined) =:= ?BOUNDARIES
    andalso maps:get(<<"maximum_report_bytes">>, Configuration, undefined)
        =:= ?MAXIMUM_ROW_BYTES
    andalso maps:get(<<"maximum_source_bytes">>, Configuration, undefined)
        =:= ?MAXIMUM_SOURCE_BYTES
    andalso maps:get(
        <<"maximum_source_total_bytes">>, Configuration, undefined)
        =:= ?MAXIMUM_SOURCE_TOTAL_BYTES;
configuration_valid(_) -> false.

failure_classification_valid(Classification) when is_map(Classification) ->
    exact_keys(Classification,
        [<<"adversarial_control">>, <<"publication">>, <<"source_contract">>])
    andalso maps:get(<<"adversarial_control">>, Classification, undefined) =:= 0
    andalso maps:get(<<"publication">>, Classification, undefined) =:= 0
    andalso maps:get(<<"source_contract">>, Classification, undefined) =:= 0;
failure_classification_valid(_) -> false.

row_tool_identity_valid(Identity) when is_map(Identity) ->
    exact_keys(Identity, [<<"kind">>, <<"sha256">>]) andalso
    Identity =:= audit_tool_identity();
row_tool_identity_valid(_) -> false.

execution_context_valid(Context, Expected)
  when is_map(Context), is_map(Expected) ->
    try
        true = exact_keys(Context,
            [<<"ci_provider">>, <<"image_os">>, <<"mode">>, <<"os_family">>,
             <<"os_name">>, <<"package">>, <<"platform">>,
             <<"requested_otp">>, <<"runner_os">>, <<"runtime_otp">>]),
        <<"matrix">> = maps:get(<<"mode">>, Context),
        ExpectedPackage = maps:get(package, Expected),
        ExpectedPlatform = maps:get(platform, Expected),
        ExpectedOtp = maps:get(otp, Expected),
        ExpectedPackage = maps:get(<<"package">>, Context),
        ExpectedPlatform = maps:get(<<"platform">>, Context),
        ExpectedOtp = maps:get(<<"requested_otp">>, Context),
        ExpectedOtp = maps:get(<<"runtime_otp">>, Context),
        <<"github-actions">> = maps:get(<<"ci_provider">>, Context),
        {Family, Name, Runner, Image} = platform_identity(
            maps:get(platform, Expected)),
        Family = maps:get(<<"os_family">>, Context),
        Name = maps:get(<<"os_name">>, Context),
        Runner = maps:get(<<"runner_os">>, Context),
        Image = maps:get(<<"image_os">>, Context),
        true
    catch _:_ -> false end;
execution_context_valid(_, _) -> false.

runtime_identity_valid(Runtime, Expected)
  when is_map(Runtime), is_map(Expected) ->
    exact_keys(Runtime, [<<"erts_version">>, <<"kind">>, <<"otp_release">>])
    andalso maps:get(<<"kind">>, Runtime, undefined) =:= <<"erlang-escript">>
    andalso maps:get(<<"otp_release">>, Runtime, undefined) =:=
        maps:get(otp, Expected)
    andalso bounded_printable_ascii(
        maps:get(<<"erts_version">>, Runtime, undefined), 64);
runtime_identity_valid(_, _) -> false.

row_summary(Expected, Report, ReportSha) ->
    #{package => maps:get(package, Expected),
      platform => maps:get(platform, Expected), otp => maps:get(otp, Expected),
      status => <<"Ready">>, report_sha256 => ReportSha,
      source_sha256 => maps:get(<<"source_sha256">>, Report),
      canonical_fixture_sha256 =>
          maps:get(<<"canonical_fixture_sha256">>, Report),
      execution_context => maps:get(<<"execution_context">>, Report),
      runtime_identity => maps:get(<<"runtime_identity">>, Report),
      tool_identity => maps:get(<<"tool_identity">>, Report),
      decoded_boundaries => maps:get(<<"decoded_boundaries">>, Report),
      adversarial_controls => maps:get(<<"adversarial_controls">>, Report),
      completed_controls => maps:get(<<"completed_controls">>, Report),
      failed_controls => maps:get(<<"failed_controls">>, Report)}.

matrix_rows_valid(Rows, SourceSha, FixtureSha) when is_list(Rows) ->
    try
        ?ROWS = length(Rows),
        Expected = expected_rows(),
        Expected = [maps:with([package, platform, otp], Row) || Row <- Rows],
        ?ROWS = length(lists:usort([
            {maps:get(package, Row), maps:get(platform, Row), maps:get(otp, Row)}
            || Row <- Rows])),
        ?ROWS = length(lists:usort([maps:get(report_sha256, Row)
            || Row <- Rows])),
        true = lists:all(fun(Row) ->
            ExpectedRow = maps:with([package, platform, otp], Row),
            exact_keys(Row, row_summary_keys()) andalso
            maps:get(status, Row) =:= <<"Ready">> andalso
            maps:get(source_sha256, Row) =:= SourceSha andalso
            maps:get(canonical_fixture_sha256, Row) =:= FixtureSha andalso
            maps:get(tool_identity, Row) =:= audit_tool_identity() andalso
            lower_sha256(maps:get(report_sha256, Row)) andalso
            execution_context_valid(maps:get(execution_context, Row),
                ExpectedRow) andalso
            runtime_identity_valid(maps:get(runtime_identity, Row),
                ExpectedRow) andalso
            maps:get(decoded_boundaries, Row) =:= ?BOUNDARIES andalso
            maps:get(adversarial_controls, Row) =:= ?ADVERSARIAL_CONTROLS andalso
            maps:get(completed_controls, Row) =:= ?ADVERSARIAL_CONTROLS andalso
            maps:get(failed_controls, Row) =:= 0 andalso
            safe_json_value(Row)
        end, Rows),
        true
    catch _:_ -> false end;
matrix_rows_valid(_, _, _) -> false.

row_summary_keys() ->
    [adversarial_controls, canonical_fixture_sha256, completed_controls,
     decoded_boundaries, execution_context, failed_controls, otp, package,
     platform, report_sha256, runtime_identity, source_sha256, status,
     tool_identity].

ready_report(Rows, SourceSha, FixtureSha) ->
    #{schema => 1, report_kind => <<"etf_boundary_matrix">>,
      status => <<"Ready">>, shareable => true, scope => ?SCOPE,
      source_sha256 => SourceSha,
      source_files => ?SOURCE_FILES,
      canonical_fixture_sha256 => FixtureSha,
      tool_identity => matrix_tool_identity(),
      configuration => aggregate_configuration(),
      execution_context => aggregate_execution_context(),
      runtime_identity => runtime_identity(),
      peer_identity => <<"not-applicable: evidence aggregation">>,
      expected_rows => ?ROWS, verified_rows => ?ROWS,
      artifact_directories => ?ROWS, reports => ?ROWS,
      packages => [<<"http">>, <<"http3">>, <<"quic_core">>],
      platforms => [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>],
      otp_releases => [<<"28">>, <<"29">>],
      decoded_boundaries_per_row => ?BOUNDARIES,
      adversarial_controls_per_row => ?ADVERSARIAL_CONTROLS,
      requested_controls => ?ROWS * ?ADVERSARIAL_CONTROLS,
      completed_controls => ?ROWS * ?ADVERSARIAL_CONTROLS,
      failed_controls => 0,
      failure_classification => #{inventory => 0, row_contract => 0,
          source_identity => 0, fixture_identity => 0,
          report_contract => 0, publication => 0,
          unsafe_evidence => 0, other => 0},
      rows => Rows, rerun_command => ?RERUN_COMMAND}.

aggregate_report_valid(Report) when is_map(Report) ->
    try
        true = exact_keys(Report, aggregate_report_keys()),
        1 = maps:get(schema, Report),
        <<"etf_boundary_matrix">> = maps:get(report_kind, Report),
        <<"Ready">> = maps:get(status, Report),
        true = maps:get(shareable, Report),
        ?SCOPE = maps:get(scope, Report),
        SourceSha = maps:get(source_sha256, Report),
        FixtureSha = maps:get(canonical_fixture_sha256, Report),
        true = lower_sha256(SourceSha),
        true = lower_sha256(FixtureSha),
        ?SOURCE_FILES = maps:get(source_files, Report),
        true = maps:get(tool_identity, Report) =:= matrix_tool_identity(),
        true = maps:get(configuration, Report) =:= aggregate_configuration(),
        true = maps:get(execution_context, Report) =:=
            aggregate_execution_context(),
        true = maps:get(runtime_identity, Report) =:= runtime_identity(),
        <<"not-applicable: evidence aggregation">> =
            maps:get(peer_identity, Report),
        ?ROWS = maps:get(expected_rows, Report),
        ?ROWS = maps:get(verified_rows, Report),
        ?ROWS = maps:get(artifact_directories, Report),
        ?ROWS = maps:get(reports, Report),
        [<<"http">>, <<"http3">>, <<"quic_core">>] = maps:get(packages, Report),
        [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>] =
            maps:get(platforms, Report),
        [<<"28">>, <<"29">>] = maps:get(otp_releases, Report),
        ?BOUNDARIES = maps:get(decoded_boundaries_per_row, Report),
        ?ADVERSARIAL_CONTROLS = maps:get(adversarial_controls_per_row, Report),
        ExpectedControls = ?ROWS * ?ADVERSARIAL_CONTROLS,
        ExpectedControls = maps:get(requested_controls, Report),
        ExpectedControls = maps:get(completed_controls, Report),
        0 = maps:get(failed_controls, Report),
        true = aggregate_failure_classification_valid(
            maps:get(failure_classification, Report)),
        Rows = maps:get(rows, Report),
        true = matrix_rows_valid(Rows, SourceSha, FixtureSha),
        ?RERUN_COMMAND = maps:get(rerun_command, Report),
        true = safe_json_value(Report),
        true
    catch _:_ -> false end;
aggregate_report_valid(_) -> false.

aggregate_report_keys() ->
    [adversarial_controls_per_row, artifact_directories,
     canonical_fixture_sha256, completed_controls, configuration,
     decoded_boundaries_per_row, expected_rows, failed_controls,
     execution_context, failure_classification, otp_releases, packages,
     peer_identity, platforms, report_kind, reports, requested_controls,
     rerun_command, rows, runtime_identity, schema, scope, shareable,
     source_files, source_sha256, status, tool_identity, verified_rows].

aggregate_failure_classification_valid(Classification)
  when is_map(Classification) ->
    exact_keys(Classification,
        [fixture_identity, inventory, other, publication, report_contract,
         row_contract, source_identity, unsafe_evidence]) andalso
    lists:all(fun(Value) -> Value =:= 0 end, maps:values(Classification));
aggregate_failure_classification_valid(_) -> false.

expected_rows() ->
    [#{package => Package, platform => Platform, otp => Otp}
     || Package <- [<<"http">>, <<"http3">>, <<"quic_core">>],
        Platform <- [<<"ubuntu-24.04">>, <<"macos-15">>,
                     <<"windows-2025">>],
        Otp <- [<<"28">>, <<"29">>]].

artifact_name(Row) ->
    binary_to_list(iolist_to_binary([
        "etf-boundary-", maps:get(package, Row), "-",
        maps:get(platform, Row), "-otp", maps:get(otp, Row)])).

expected_row_rerun(Row) ->
    iolist_to_binary([
        "escript scripts/etf_boundary_audit.escript matrix ",
        maps:get(package, Row), " ", maps:get(platform, Row), " ",
        maps:get(otp, Row)]).

platform_identity(<<"ubuntu-24.04">>) ->
    {<<"unix">>, <<"linux">>, <<"Linux">>, <<"ubuntu24">>};
platform_identity(<<"macos-15">>) ->
    {<<"unix">>, <<"darwin">>, <<"macOS">>, <<"macos15">>};
platform_identity(<<"windows-2025">>) ->
    {<<"win32">>, <<"nt">>, <<"Windows">>, <<"win25">>}.

aggregate_configuration() ->
    #{maximum_source_bytes => ?MAXIMUM_SOURCE_BYTES,
      maximum_source_total_bytes => ?MAXIMUM_SOURCE_TOTAL_BYTES,
      maximum_row_bytes => ?MAXIMUM_ROW_BYTES,
      maximum_aggregate_bytes => ?MAXIMUM_AGGREGATE_BYTES,
      expected_rows => ?ROWS, source_files => ?SOURCE_FILES}.

runtime_identity() ->
    #{kind => <<"erlang-escript">>,
      otp_release => unicode:characters_to_binary(
          erlang:system_info(otp_release)),
      erts_version => unicode:characters_to_binary(
          erlang:system_info(version))}.

aggregate_execution_context() ->
    {Family, Name, ExpectedRunner, ExpectedImage} =
        current_platform_identity(),
    {CiProvider, Runner, Image} = case os:getenv("GITHUB_ACTIONS") of
        "true" -> {<<"github-actions">>, ExpectedRunner, ExpectedImage};
        _ -> {<<"local">>, <<"not-applicable">>, <<"not-applicable">>}
    end,
    #{mode => <<"matrix-aggregate">>, ci_provider => CiProvider,
      os_family => Family, os_name => Name, runner_os => Runner,
      image_os => Image,
      runtime_otp => unicode:characters_to_binary(
          erlang:system_info(otp_release))}.

current_platform_identity() ->
    case os:type() of
        {unix, linux} ->
            {<<"unix">>, <<"linux">>, <<"Linux">>, <<"ubuntu24">>};
        {unix, darwin} ->
            {<<"unix">>, <<"darwin">>, <<"macOS">>, <<"macos15">>};
        {win32, nt} ->
            {<<"win32">>, <<"nt">>, <<"Windows">>, <<"win25">>};
        _ -> erlang:error(unsupported_matrix_operating_system)
    end.

audit_tool_identity() ->
    #{<<"kind">> => <<"etf-boundary-audit">>,
      <<"sha256">> => sha256(evidence_publication_read(
          "scripts/etf_boundary_audit.escript", ?MAXIMUM_SOURCE_BYTES))}.

matrix_tool_identity() ->
    #{kind => <<"etf-boundary-matrix">>,
      sha256 => sha256(evidence_publication_read(
          "scripts/etf_boundary_matrix.escript", ?MAXIMUM_SOURCE_BYTES))}.

current_source_sha256() ->
    Sources = bounded_source_set(audit_source_paths()),
    source_digest(Sources).

bounded_source_set(Paths) ->
    {Sources, _Total} = lists:mapfoldl(fun(Path, Total) ->
        Bytes = evidence_publication_read(Path, ?MAXIMUM_SOURCE_BYTES),
        true = byte_size(Bytes) > 0,
        Next = Total + byte_size(Bytes),
        true = Next =< ?MAXIMUM_SOURCE_TOTAL_BYTES,
        {{Path, Bytes}, Next}
    end, 0, Paths),
    Sources.

audit_source_paths() ->
    lists:sort([
        "scripts/canonical_etf_wire.hrl",
        "scripts/supervised_gleam.escript",
        "scripts/execution_beam_identity.hrl",
        "scripts/qualification_eunit_listener.erl",
        "scripts/http3_multiplexing_attested_runner.erl",
        "scripts/http3_multiplexing_evidence.escript",
        "scripts/canonical_etf_wire_self_test.escript",
        "scripts/evidence_publication.hrl",
        "scripts/etf_boundary_audit.escript",
        "scripts/etf_boundary_matrix.escript",
        "scripts/json_evidence.hrl"]).

source_digest(Sources) ->
    Context = lists:foldl(fun({Path, Bytes}, Acc) ->
        crypto:hash_update(Acc,
            [unicode:characters_to_binary(Path), 0, Bytes, 0])
    end, crypto:hash_init(sha256), Sources),
    binary:encode_hex(crypto:hash_final(Context), lowercase).

canonical_fixture_sha256() ->
    binary:encode_hex(crypto:hash(sha256, term_to_binary(
        canonical_etf_interop_fixture(), [{minor_version, 2}])), lowercase).

sha256(Bytes) ->
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

lower_sha256(Bytes) when is_binary(Bytes), byte_size(Bytes) =:= 64 ->
    lists:all(fun(Byte) ->
        (Byte >= $0 andalso Byte =< $9) orelse
        (Byte >= $a andalso Byte =< $f)
    end, binary_to_list(Bytes));
lower_sha256(_) -> false.

exact_keys(Map, Keys) when is_map(Map), is_list(Keys) ->
    lists:sort(maps:keys(Map)) =:= lists:sort(Keys);
exact_keys(_, _) -> false.

bounded_printable_ascii(Bytes, Maximum)
  when is_binary(Bytes), byte_size(Bytes) > 0,
       byte_size(Bytes) =< Maximum ->
    lists:all(fun(Byte) -> Byte >= 32 andalso Byte =< 126 end,
        binary_to_list(Bytes)) andalso safe_binary(Bytes);
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

publish_document(Path, Report, Maximum) ->
    true = safe_json_value(Report),
    _ = evidence_publication_ensure_directory(filename:dirname(Path)),
    Bytes = iolist_to_binary([json:encode(Report), $\n]),
    true = byte_size(Bytes) > 0 andalso byte_size(Bytes) =< Maximum,
    ok = evidence_publish_new(Path, Bytes, Maximum),
    Bytes = evidence_publication_read(Path, Maximum),
    ok.

invalidate_report(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_invalidate_etf_matrix_report)
    end.

publish_failed_report() ->
    VerifiedRows = bounded_progress(etf_matrix_verified_rows, ?ROWS),
    ArtifactDirectories = bounded_progress(
        etf_matrix_artifact_directories, ?ROWS),
    Stage = failure_stage(),
    FailedControls = case {Stage, VerifiedRows} of
        {row_contract, Count} when Count < ?ROWS -> 1;
        _ -> 0
    end,
    Report = #{schema => 1, report_kind => <<"etf_boundary_matrix">>,
        status => <<"Failed">>, shareable => true, scope => ?SCOPE,
        source_identity => failure_source_identity(),
        canonical_fixture_identity => failure_fixture_identity(),
        tool_identity => failure_matrix_tool_identity(),
        configuration => aggregate_configuration(),
        execution_context => aggregate_execution_context(),
        runtime_identity => runtime_identity(),
        peer_identity => <<"not-applicable: evidence aggregation">>,
        expected_rows => ?ROWS, verified_rows => VerifiedRows,
        artifact_directories => ArtifactDirectories,
        reports => VerifiedRows,
        requested_controls => ?ROWS * ?ADVERSARIAL_CONTROLS,
        completed_controls => VerifiedRows * ?ADVERSARIAL_CONTROLS,
        failed_controls => FailedControls,
        details_retained => false,
        failure_classification => failed_matrix_classification(Stage),
        rerun_command => ?RERUN_COMMAND},
    publish_document(?OUTPUT_PATH, Report, ?MAXIMUM_AGGREGATE_BYTES).

bounded_progress(Key, Maximum) ->
    case get(Key) of
        Count when is_integer(Count), Count >= 0, Count =< Maximum -> Count;
        _ -> 0
    end.

failure_stage() ->
    case get(etf_matrix_stage) of
        inventory -> inventory;
        row_contract -> row_contract;
        source_identity -> source_identity;
        fixture_identity -> fixture_identity;
        report_contract -> report_contract;
        publication -> publication;
        unsafe_evidence -> unsafe_evidence;
        _ -> other
    end.

failed_matrix_classification(Stage) ->
    Empty = #{fixture_identity => 0, inventory => 0, other => 0,
        publication => 0, report_contract => 0, row_contract => 0,
        source_identity => 0, unsafe_evidence => 0},
    case maps:is_key(Stage, Empty) of
        true -> Empty#{Stage := 1};
        false -> Empty#{other := 1}
    end.

failure_source_identity() ->
    case get(etf_matrix_source_identity) of
        Identity when is_map(Identity) -> Identity;
        _ ->
            try
                Sha = current_source_sha256(),
                #{status => <<"complete">>, sha256 => Sha,
                  files => ?SOURCE_FILES}
            catch _:_ ->
                #{status => <<"unavailable">>, sha256 => <<"unavailable">>,
                  files => 0}
            end
    end.

failure_fixture_identity() ->
    case get(etf_matrix_fixture_identity) of
        Identity when is_map(Identity) -> Identity;
        _ ->
            try
                #{status => <<"complete">>,
                  sha256 => canonical_fixture_sha256()}
            catch _:_ ->
                #{status => <<"unavailable">>, sha256 => <<"unavailable">>}
            end
    end.

failure_matrix_tool_identity() ->
    try matrix_tool_identity()
    catch _:_ ->
        #{kind => <<"etf-boundary-matrix">>, sha256 => <<"unavailable">>}
    end.

self_test() ->
    SourceSha = binary:copy(<<"a">>, 64),
    FixtureSha = binary:copy(<<"b">>, 64),
    Reports = [fixture_report(Row, SourceSha, FixtureSha)
        || Row <- expected_rows()],
    true = report_set_valid(Reports, SourceSha, FixtureSha),
    [First, _Second | Rest] = Reports,
    false = report_set_valid(tl(Reports), SourceSha, FixtureSha),
    false = report_set_valid([First, First | Rest], SourceSha, FixtureSha),
    false = report_set_valid(Reports ++ [First], SourceSha, FixtureSha),
    false = report_set_valid([mutate_report_otp(First) | tl(Reports)],
        SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"source_sha256">> :=
        binary:copy(<<"c">>, 64)} | tl(Reports)], SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"canonical_fixture_sha256">> :=
        binary:copy(<<"c">>, 64)} | tl(Reports)], SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"status">> := <<"Failed">>} | tl(Reports)],
        SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"completed_controls">> := 31} | tl(Reports)],
        SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"source_files">> := ?SOURCE_FILES - 1}
        | tl(Reports)], SourceSha, FixtureSha),
    FirstTool = maps:get(<<"tool_identity">>, First),
    false = report_set_valid([First#{<<"tool_identity">> :=
        FirstTool#{<<"sha256">> := binary:copy(<<"A">>, 64)}} | tl(Reports)],
        SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"tool_identity">> :=
        FirstTool#{<<"sha256">> := binary:copy(<<"b">>, 64)}} | tl(Reports)],
        SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"source_sha256">> :=
        binary:copy(<<"A">>, 64)} | tl(Reports)], SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"canonical_fixture_sha256">> :=
        binary:copy(<<"B">>, 64)} | tl(Reports)], SourceSha, FixtureSha),
    FirstContext = maps:get(<<"execution_context">>, First),
    false = report_set_valid([First#{<<"execution_context">> :=
        FirstContext#{<<"mode">> := <<"local">>}} | tl(Reports)],
        SourceSha, FixtureSha),
    false = execution_context_valid(fixture_local_context(),
        hd(expected_rows())),
    FirstRuntime = maps:get(<<"runtime_identity">>, First),
    false = report_set_valid([First#{<<"runtime_identity">> :=
        FirstRuntime#{<<"erts_version">> := <<"C:\\Users\\private">>}}
        | tl(Reports)], SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"schema">> := <<"1">>} | tl(Reports)],
        SourceSha, FixtureSha),
    false = report_set_valid([First#{<<"extra">> => true} | tl(Reports)],
        SourceSha, FixtureSha),
    FirstFailure = maps:get(<<"failure_classification">>, First),
    false = report_set_valid([First#{<<"failure_classification">> :=
        FirstFailure#{<<"publication">> := 1}} | tl(Reports)],
        SourceSha, FixtureSha),
    Inventory = [{artifact_name(Row), ["report.json"]}
        || Row <- expected_rows()],
    true = inventory_contract_valid(Inventory),
    false = inventory_contract_valid(tl(Inventory)),
    [{FirstName, FirstEntries}, SecondInventory | InventoryRest] = Inventory,
    false = inventory_contract_valid(
        [{FirstName, FirstEntries}, {FirstName, FirstEntries} | InventoryRest]),
    false = inventory_contract_valid(Inventory ++ [{"extra", ["report.json"]}]),
    false = inventory_contract_valid(
        [{FirstName, ["report.json", "stale.json"]}, SecondInventory
         | InventoryRest]),
    Summaries = fixture_summaries(Reports),
    true = matrix_rows_valid(Summaries, SourceSha, FixtureSha),
    [FirstSummary | SummaryRest] = Summaries,
    false = matrix_rows_valid([FirstSummary#{report_sha256 :=
        binary:copy(<<"C">>, 64)} | SummaryRest], SourceSha, FixtureSha),
    false = matrix_rows_valid([FirstSummary#{unexpected => true}
        | SummaryRest], SourceSha, FixtureSha),
    Aggregate = ready_report(Summaries, SourceSha, FixtureSha),
    true = aggregate_report_valid(Aggregate),
    false = aggregate_report_valid(Aggregate#{verified_rows := 17}),
    false = aggregate_report_valid(Aggregate#{status := <<"Blocked">>}),
    false = aggregate_report_valid(Aggregate#{source_files :=
        ?SOURCE_FILES - 1}),
    AggregateTool = maps:get(tool_identity, Aggregate),
    false = aggregate_report_valid(Aggregate#{tool_identity :=
        AggregateTool#{sha256 := binary:copy(<<"A">>, 64)}}),
    false = aggregate_report_valid(Aggregate#{tool_identity :=
        AggregateTool#{sha256 := binary:copy(<<"b">>, 64)}}),
    io:put_chars(
        <<"missing duplicate extra otp source fixture status count hash context unsafe mutants rejected\n">>),
    ok.

report_set_valid(Reports, SourceSha, FixtureSha) when is_list(Reports) ->
    try
        Expected = expected_rows(),
        ?ROWS = length(Reports),
        ?ROWS = length(lists:usort([
            {maps:get(<<"package">>, maps:get(<<"execution_context">>, Report)),
             maps:get(<<"platform">>, maps:get(<<"execution_context">>, Report)),
             maps:get(<<"requested_otp">>, maps:get(<<"execution_context">>, Report))}
            || Report <- Reports])),
        true = lists:all(fun({Report, Row}) ->
            row_report_valid(Report, Row, SourceSha, FixtureSha)
        end, lists:zip(Reports, Expected)),
        true
    catch _:_ -> false end;
report_set_valid(_, _, _) -> false.

fixture_report(Row, SourceSha, FixtureSha) ->
    Context = fixture_context(Row),
    Otp = maps:get(otp, Row),
    #{<<"schema">> => 1, <<"status">> => <<"Ready">>,
      <<"shareable">> => true,
      <<"scope">> => <<"all external-term evidence decode boundaries">>,
      <<"source_sha256">> => SourceSha, <<"source_files">> => ?SOURCE_FILES,
      <<"tool_identity">> => audit_tool_identity(),
      <<"configuration">> => #{<<"maximum_source_bytes">> =>
          ?MAXIMUM_SOURCE_BYTES, <<"maximum_report_bytes">> =>
          ?MAXIMUM_ROW_BYTES, <<"maximum_source_total_bytes">> =>
          ?MAXIMUM_SOURCE_TOTAL_BYTES,
          <<"boundary_count">> => ?BOUNDARIES},
      <<"execution_context">> => Context,
      <<"runtime_identity">> => #{<<"kind">> => <<"erlang-escript">>,
          <<"otp_release">> => Otp, <<"erts_version">> => <<"17.0.5">>},
      <<"runtime_otp">> => Otp,
      <<"peer_identity">> => <<"not-applicable: local static audit">>,
      <<"canonical_fixture_sha256">> => FixtureSha,
      <<"decoded_boundaries">> => ?BOUNDARIES,
      <<"canonical_reader_implementations">> => 1,
      <<"compressed_terms">> => <<"rejected-before-decode">>,
      <<"runtime_capability_terms">> => <<"rejected-before-decode">>,
      <<"atom_creation">> => <<"prohibited">>, <<"dispatch">> => <<"closed">>,
      <<"identity_bindings">> => ?IDENTITY_BINDINGS,
      <<"adversarial_controls">> => ?ADVERSARIAL_CONTROLS,
      <<"completed_controls">> => ?ADVERSARIAL_CONTROLS,
      <<"failed_controls">> => 0,
      <<"failure_classification">> => #{<<"source_contract">> => 0,
          <<"adversarial_control">> => 0, <<"publication">> => 0},
      <<"rerun_command">> => expected_row_rerun(Row)}.

fixture_context(Row) ->
    {Family, Name, Runner, Image} = platform_identity(maps:get(platform, Row)),
    #{<<"mode">> => <<"matrix">>,
      <<"package">> => maps:get(package, Row),
      <<"platform">> => maps:get(platform, Row),
      <<"requested_otp">> => maps:get(otp, Row),
      <<"runtime_otp">> => maps:get(otp, Row),
      <<"os_family">> => Family, <<"os_name">> => Name,
      <<"ci_provider">> => <<"github-actions">>,
      <<"runner_os">> => Runner, <<"image_os">> => Image}.

fixture_local_context() ->
    #{<<"mode">> => <<"local">>, <<"package">> => <<"all">>,
      <<"platform">> => <<"local">>, <<"requested_otp">> => <<"28">>,
      <<"runtime_otp">> => <<"28">>, <<"os_family">> => <<"unix">>,
      <<"os_name">> => <<"linux">>, <<"ci_provider">> => <<"local">>,
      <<"runner_os">> => <<"not-applicable">>,
      <<"image_os">> => <<"not-applicable">>}.

mutate_report_otp(Report) ->
    Context = maps:get(<<"execution_context">>, Report),
    Runtime = maps:get(<<"runtime_identity">>, Report),
    Report#{<<"runtime_otp">> := <<"29">>,
        <<"execution_context">> := Context#{<<"requested_otp">> := <<"29">>,
            <<"runtime_otp">> := <<"29">>},
        <<"runtime_identity">> := Runtime#{<<"otp_release">> := <<"29">>}}.

fixture_summaries(Reports) ->
    [row_summary(Row, Report,
        sha256(iolist_to_binary([artifact_name(Row), maps:get(otp, Row)])))
     || {Row, Report} <- lists:zip(expected_rows(), Reports)].
