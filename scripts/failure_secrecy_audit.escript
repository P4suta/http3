#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% Failure output is an attack surface.  This audit deliberately retains only
%% rule identifiers and source coordinates; it never copies a rejected value,
%% source line, output tail, exception argument, or digest of rejected bytes.
-include("diagnostic_failure.hrl").
-include_lib("kernel/include/file.hrl").

-define(REPORT_DIRECTORY, "build/failure-secrecy/reports").
-define(MAX_SOURCE_FILES, 10000).
-define(MAX_SOURCE_FILE_BYTES, 4194304).
-define(MAX_SOURCE_BYTES, 134217728).
-define(MAX_ARTIFACTS, 64).
-define(MAX_ARTIFACT_BYTES, 16777216).
-define(MAX_ARTIFACT_TOTAL_BYTES, 134217728).
-define(MAX_JSON_DEPTH, 48).
-define(MAX_JSON_NODES, 100000).
-define(MAX_JSON_STRING_BYTES, 262144).
-define(MAX_FINDINGS, 64).
-define(MAX_REVIEW_LOCATIONS, 128).
-define(CRASH_SCAN_MILLISECONDS, 5000).
-define(MAX_CRASH_SCAN_DIRECTORIES, 10000).
-define(MAX_CRASH_SCAN_ENTRIES, 100000).
-define(PROCESS_SUPERVISOR_SELF_TEST_MARKER,
        <<"process_supervisor_self_test passed=true controls=60 "
          "relay_settlement=verified owned_run=verified">>).

main([]) -> guarded(fun audit/0, "failure-secrecy audit");
main(["audit"]) -> guarded(fun audit/0, "failure-secrecy audit");
main(["--self-test"]) -> guarded(fun self_test/0, "failure-secrecy self-test");
main(_) ->
    io:format(standard_error,
              "usage: failure_secrecy_audit.escript [audit|--self-test]~n", []),
    halt(2).

guarded(Function, Label) ->
    try Function() of
        ok -> ok
    catch
        Class:Reason:Stack ->
            Details = diagnostic_failure_details(Class, Reason, Stack),
            io:format(standard_error, "~s failed: ~s~n",
                      [Label, json:encode(Details#{stage => failure_stage(),
                          audit_control_id => audit_control_id(),
                          audit_check_index => audit_check_index(),
                          audit_failure_code => audit_failure_code(Reason)})]),
            halt(1)
    end.

audit() ->
    begin_progress(),
    try audit_with_progress()
    after end_progress() end.

audit_with_progress() ->
    progress(source_capture, 0, 0, ?MAX_SOURCE_FILES, ?MAX_SOURCE_BYTES),
    Sources = bounded_sources(),
    SourceBytes = lists:sum([byte_size(Bytes) || {_, Bytes} <- Sources]),
    progress(assertion_inventory, length(Sources), SourceBytes,
             ?MAX_SOURCE_FILES, ?MAX_SOURCE_BYTES),
    Inventory = assertion_inventory(Sources),
    progress(reporter_scan, maps:get(assertion_sites, Inventory), SourceBytes,
             ?MAX_SOURCE_FILES, ?MAX_SOURCE_BYTES),
    ReporterFindings = reporter_findings(Sources),
    WorkflowFindings = workflow_findings(Sources),
    progress(process_runner_scan,
             length(ReporterFindings) + length(WorkflowFindings), SourceBytes,
             ?MAX_FINDINGS, ?MAX_SOURCE_BYTES),
    PortInventory = port_runner_inventory(Sources),
    PortFindings = port_runner_findings(PortInventory),
    Contracts = contract_results(Sources),
    ContractFindings = [#{rule => maps:get(id, Row),
                          path => maps:get(path, Row),
                          line => maps:get(line, Row, 1)}
                        || Row <- Contracts, not maps:get(passed, Row)],
    progress(artifact_capture, 0, 0, ?MAX_ARTIFACTS,
             ?MAX_ARTIFACT_TOTAL_BYTES),
    Artifacts = bounded_authoritative_artifacts(),
    CrashResidues = crash_dump_snapshot("."),
    ArtifactPaths = [Path || {Path, _} <- Artifacts],
    ArtifactFindings = artifact_findings(Artifacts),
    ResidueRows = maps:get(rows, CrashResidues),
    ResidueFindings = case ResidueRows of
        [] -> [];
        _ -> [#{rule => <<"raw_crash_dump_retained">>,
                path => <<"workspace">>, line => 0}]
    end ++ case maps:get(complete, CrashResidues) of
        true -> [];
        false -> [#{rule => <<"crash_residue_scan_incomplete">>,
                    path => <<"workspace">>, line => 0}]
    end,
    ArtifactBytes = lists:sum([byte_size(Bytes) || {_, Bytes} <- Artifacts]),
    progress(artifact_scan, length(Artifacts), ArtifactBytes,
             ?MAX_ARTIFACTS, ?MAX_ARTIFACT_TOTAL_BYTES),
    Findings = bounded_findings(ReporterFindings ++ WorkflowFindings ++
                                PortFindings ++
                                ContractFindings ++ ArtifactFindings ++
                                ResidueFindings),
    Passed = Findings =:= [],
    SourceIdentity = source_identity(Sources),
    ArtifactIdentity = artifact_identity(Artifacts),
    ResidueIdentity = crash_residue_identity(CrashResidues),
    RuntimeIdentity = runtime_identity(),
    ExcludedDiagnostics = excluded_diagnostic_inventory(),
    ReportPath = report_path(SourceIdentity, ArtifactIdentity, ResidueIdentity,
                             RuntimeIdentity),
    Report0 = #{schema => 1,
        status => case Passed of true -> <<"Ready">>; false -> <<"Blocked">> end,
        passed => Passed,
        scope => <<"failure outputs and shareable qualification evidence">>,
        limits => limits(),
        source_identity => SourceIdentity,
        artifact_identity => ArtifactIdentity,
        crash_dump_residue => ResidueIdentity,
        runtime_identity => RuntimeIdentity,
        inventory => Inventory#{external_port_runners => PortInventory,
                                external_port_runner_count =>
                                    length(PortInventory)},
        contracts => Contracts,
        authoritative_artifacts => #{discovered => length(ArtifactPaths),
                                     paths => [list_to_binary(P) || P <- ArtifactPaths]},
        excluded_diagnostic_inputs => ExcludedDiagnostics,
        finding_count => length(ReporterFindings) + length(WorkflowFindings) +
                         length(PortFindings) +
                         length(ContractFindings) + length(ArtifactFindings) +
                         length(ResidueFindings),
        findings => Findings,
        findings_dropped => erlang:max(0,
            length(ReporterFindings) + length(WorkflowFindings) +
            length(PortFindings) +
            length(ContractFindings) + length(ArtifactFindings) +
            length(ResidueFindings) -
            ?MAX_FINDINGS),
        shareable => true,
        retained_sensitive_values => 0,
        rerun_command => audit_command(audit),
        self_test_command => audit_command(self_test),
        authoritative_path => list_to_binary(ReportPath)},
    [] = scan_json_value(Report0),
    Bytes = iolist_to_binary([json:encode(Report0), $\n]),
    [] = sensitive_string_categories(Bytes),
    progress(source_recheck, length(Sources), SourceBytes,
             ?MAX_SOURCE_FILES, ?MAX_SOURCE_BYTES),
    ensure(source_sets_equal(Sources, bounded_sources()),
           source_changed_during_audit),
    ensure(artifact_sets_equal(Artifacts, bounded_authoritative_artifacts()),
           evidence_changed_during_audit),
    ensure(crash_residue_sets_equal(CrashResidues, crash_dump_snapshot(".")),
           crash_dump_residue_changed_during_audit),
    progress(publish, length(Findings), byte_size(Bytes),
             ?MAX_FINDINGS, ?MAX_ARTIFACT_BYTES),
    write_immutable_report(ReportPath, Bytes),
    case source_sets_equal(Sources, bounded_sources()) andalso
         artifact_sets_equal(Artifacts, bounded_authoritative_artifacts()) andalso
         crash_residue_sets_equal(CrashResidues, crash_dump_snapshot(".")) of
        true -> ok;
        false ->
            ok = file:delete(ReportPath),
            erlang:error(source_or_evidence_changed_during_publication)
    end,
    io:format("failure_secrecy passed=~p assertions=~B review_candidates=~B "
              "artifacts=~B findings=~B evidence=~s~n",
              [Passed, maps:get(assertion_sites, Inventory),
               maps:get(review_candidate_count, Inventory), length(ArtifactPaths),
               maps:get(finding_count, Report0), ReportPath]),
    ensure(Passed, failure_secrecy_gate_blocked),
    ok.

limits() ->
    #{source_files => ?MAX_SOURCE_FILES,
      source_file_bytes => ?MAX_SOURCE_FILE_BYTES,
      source_total_bytes => ?MAX_SOURCE_BYTES,
      artifacts => ?MAX_ARTIFACTS,
      artifact_bytes => ?MAX_ARTIFACT_BYTES,
      artifact_total_bytes => ?MAX_ARTIFACT_TOTAL_BYTES,
      json_depth => ?MAX_JSON_DEPTH,
      json_nodes => ?MAX_JSON_NODES,
      json_string_bytes => ?MAX_JSON_STRING_BYTES,
      retained_findings => ?MAX_FINDINGS,
      retained_review_locations => ?MAX_REVIEW_LOCATIONS}.

%% Source inventory ---------------------------------------------------------

bounded_sources() ->
    Roots = audited_source_roots(),
    Paths0 = lists:append([source_paths(Root) || Root <- Roots]),
    Paths = lists:usort([normal_path(Path) || Path <- Paths0,
                                            is_source_path(Path)]),
    ensure(length(Paths) > 0 andalso length(Paths) =< ?MAX_SOURCE_FILES,
           invalid_source_file_count),
    {Rows, Total} = lists:mapfoldl(fun(Path, Count) ->
        Bytes = bounded_read(Path, ?MAX_SOURCE_FILE_BYTES),
        Next = Count + byte_size(Bytes),
        ensure(Next =< ?MAX_SOURCE_BYTES, source_inventory_too_large),
        {{Path, Bytes}, Next}
    end, 0, Paths),
    ensure(Total > 0, empty_source_inventory),
    Rows.

audited_source_roots() ->
    ["src", "test", "scripts", "packages/http3/src",
     "packages/http3/test", "packages/quic_core/src",
     "packages/quic_core/test", ".github/workflows"].

audited_source_path(Path0) ->
    Path = normal_path(Path0),
    is_source_path(Path) andalso lists:any(fun(Root) ->
        Path =:= Root orelse lists:prefix(Root ++ "/", Path)
    end, audited_source_roots()).

source_paths(Root) ->
    case filelib:is_dir(Root) of
        true -> filelib:fold_files(Root, ".*", true,
                                   fun(Path, Acc) -> [Path | Acc] end, []);
        false -> []
    end.

is_source_path(Path0) ->
    Path = string:lowercase(Path0),
    lists:any(fun(Suffix) -> lists:suffix(Suffix, Path) end,
              [".gleam", ".erl", ".hrl", ".escript", ".py", ".ps1",
               ".sh", ".js", ".mjs", ".yml", ".yaml"]).

normal_path(Path) ->
    lists:flatten(string:replace(Path, "\\", "/", all)).

source_identity(Sources) ->
    Digest = lists:foldl(fun({Path, Bytes}, Context0) ->
        PathBytes = unicode:characters_to_binary(Path),
        Context1 = crypto:hash_update(Context0,
            <<(byte_size(PathBytes)):64/unsigned-big, PathBytes/binary,
              (byte_size(Bytes)):64/unsigned-big>>),
        crypto:hash_update(Context1, Bytes)
    end, crypto:hash_init(sha256), Sources),
    #{files => length(Sources),
      bytes => lists:sum([byte_size(Bytes) || {_, Bytes} <- Sources]),
      sha256 => hex(crypto:hash_final(Digest)),
      tool_sha256 => file_sha256("scripts/failure_secrecy_audit.escript")}.

runtime_identity() ->
    #{otp_release => unicode:characters_to_binary(erlang:system_info(otp_release)),
      erts_version => unicode:characters_to_binary(erlang:system_info(version)),
       architecture => unicode:characters_to_binary(
           erlang:system_info(system_architecture))}.

audit_command(audit) ->
    <<"escript scripts/failure_secrecy_audit.escript audit">>;
audit_command(self_test) ->
    <<"escript scripts/failure_secrecy_audit.escript --self-test">>.

assertion_inventory(Sources) ->
    AssertionSites = lists:sum([assertion_count(Path, Bytes)
                                || {Path, Bytes} <- Sources]),
    PanicSites = lists:sum([match_count(Bytes,
        <<"(?:erlang:error|panic|throw|exit)\\s*\\(">>)
                           || {_, Bytes} <- Sources]),
    ReporterSites = lists:sum([match_count(Bytes,
        <<"(?:io:(?:format|put_chars)|logger:[a-z_]+)\\s*\\(">>)
                              || {_, Bytes} <- Sources]),
    Candidates0 = lists:append([review_candidates(Path, Bytes)
                                || {Path, Bytes} <- Sources]),
    Candidates = lists:sublist(Candidates0, ?MAX_REVIEW_LOCATIONS),
    Counts = category_counts([maps:get(classification, Row)
                              || Row <- Candidates0]),
    ReporterCandidates0 = lists:append([raw_reporter_candidates(Path, Bytes)
                                        || {Path, Bytes} <- Sources]),
    ReporterCandidates = lists:sublist(ReporterCandidates0,
                                       ?MAX_REVIEW_LOCATIONS),
    #{assertion_sites => AssertionSites,
      panic_or_exception_sites => PanicSites,
      output_or_reporter_sites => ReporterSites,
      review_candidate_count => length(Candidates0),
      review_candidates_retained => length(Candidates),
      review_candidates_dropped => erlang:max(0, length(Candidates0) -
                                                ?MAX_REVIEW_LOCATIONS),
      review_classification_counts => Counts,
      review_locations => Candidates,
      raw_reporter_review_count => length(ReporterCandidates0),
      raw_reporter_reviews_retained => length(ReporterCandidates),
      raw_reporter_reviews_dropped => erlang:max(0,
          length(ReporterCandidates0) - ?MAX_REVIEW_LOCATIONS),
      raw_reporter_review_locations => ReporterCandidates}.

assertion_count(Path, Bytes) ->
    case filename:extension(Path) of
        ".gleam" -> match_count(Bytes,
            <<"\\b(?:let\\s+)?assert\\b|\\bshould\\.[a-z_]+">>);
        ".erl" -> match_count(Bytes, <<"\\?assert[A-Za-z_]*\\s*\\(">>);
        ".hrl" -> match_count(Bytes, <<"\\?assert[A-Za-z_]*\\s*\\(">>);
        ".escript" -> match_count(Bytes, <<"\\?assert[A-Za-z_]*\\s*\\(">>);
        _ -> 0
    end.

review_candidates(Path, Bytes) ->
    case lists:member(filename:extension(Path), [".gleam", ".erl", ".hrl"]) of
        false -> [];
        true -> review_lines(Path, binary:split(Bytes, <<"\n">>, [global]), 1, [])
    end.

review_lines(_Path, [], _Line, Acc) -> lists:reverse(Acc);
review_lines(Path, [Bytes | Rest], Line, Acc) ->
    Next = case is_assertion_line(Bytes) andalso sensitive_assertion_word(Bytes) of
        true -> [#{path => list_to_binary(Path), line => Line,
                   classification => classify_assertion(Path, Bytes)} | Acc];
        false -> Acc
    end,
    review_lines(Path, Rest, Line + 1, Next).

is_assertion_line(Bytes) ->
    re:run(Bytes, <<"\\bassert\\b|\\?assert[A-Za-z_]*">>,
           [{capture, none}, unicode]) =:= match.

sensitive_assertion_word(Bytes) ->
    re:run(Bytes,
      <<"(?i)(authorization|cookie|body|payload|authority|destination|endpoint|"
        "socket|pid|process|reference|reason|stack|exception|request|response|"
        "private[_ -]?key|secret|token|bytes|key)">>,
      [{capture, none}, unicode]) =:= match.

classify_assertion(Path, Bytes) ->
    Runtime = re:run(Bytes,
      <<"(?:transport\\.|process\\.(?:receive|send)|body\\.(?:read|read_all)|"
        "client\\.(?:fetch|exchange|open_tunnel)|server_outcome|request_bytes|"
        "response_bytes|received[_a-z]*|socket|pid|endpoint)">>,
      [{capture, none}, unicode]) =:= match,
    Scalar = re:run(Bytes,
      <<"(?:result\\.is_|error\\.(?:kind|message)|byte_size|length|count|"
        "contains|is_process_alive|==\\s*(?:True|False|Nil|[0-9]+))">>,
      [{capture, none}, unicode]) =:= match,
    PublicFixture = string:find(Path, "/fixtures/") =/= nomatch orelse
                    string:find(Path, "/interop/") =/= nomatch orelse
                    (binary:match(Bytes, <<"\"">>) =/= nomatch andalso
                     not Runtime),
    case {Scalar, Runtime, PublicFixture} of
        {true, _, _} -> <<"safe_typed_or_scalar_observation">>;
        {false, true, _} -> <<"runtime_sensitive_review">>;
        {false, false, true} -> <<"public_synthetic_protocol_fixture">>;
        _ -> <<"unclassified_sensitive_name_review">>
    end.

category_counts(Categories) ->
    lists:foldl(fun(Category, Counts) ->
        Counts#{Category => maps:get(Category, Counts, 0) + 1}
    end, #{}, Categories).

raw_reporter_candidates(Path, Bytes) ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    raw_reporter_lines(Path, Lines, 1, []).

raw_reporter_lines(_Path, [], _Line, Acc) -> lists:reverse(Acc);
raw_reporter_lines(Path, [Bytes | Rest], Line, Acc) ->
    Output = re:run(Bytes,
        <<"(?:io:(?:format|put_chars)|logger:[a-z_]+)\\s*\\(">>,
        [{capture, none}, unicode]) =:= match,
    Sensitive = re:run(Bytes,
        <<"\\b(?:Result|Body|Headers|Socket|Pid|Reason|Stack|Stacktrace|"
          "Output|Tail|Payload|Cookie|Authorization|Endpoint|Authority|"
          "Request|Response|Bytes|Observation)\\b">>,
        [{capture, none}, unicode]) =:= match,
    Safe = binary:match(Bytes, <<"diagnostic_failure_details(">>) =/= nomatch
        orelse binary:match(Bytes, <<"failure_tag(">>) =/= nomatch,
    Next = case Output andalso Sensitive andalso not Safe of
        true -> [#{path => list_to_binary(Path), line => Line,
                   classification => <<"raw_reporter_manual_review">>} | Acc];
        false -> Acc
    end,
    raw_reporter_lines(Path, Rest, Line + 1, Next).

%% Static enforcement -------------------------------------------------------

reporter_findings(Sources) ->
    lists:append([unsafe_reporter_rows(Path, Bytes)
                  || {Path, Bytes} <- Sources,
                     lists:member(filename:extension(Path),
                                  [".escript", ".erl", ".hrl"]),
                     Path =/= "scripts/failure_secrecy_audit.escript"]).

unsafe_reporter_rows(Path, Bytes) ->
    Capturing = <<"catch\\s+([A-Z_][A-Za-z0-9_]*)\\s*:\\s*"
                  "([A-Z_][A-Za-z0-9_]*)\\s*:\\s*"
                  "([A-Z_][A-Za-z0-9_]*)\\s*->">>,
    case re:run(Bytes, Capturing,
                [global, {capture, [0, 1, 2, 3], index}, unicode]) of
        nomatch -> [];
        {match, Matches} -> lists:append([
            unsafe_catch_window(Path, Bytes, Whole,
                                [capture_bytes(Bytes, Class),
                                 capture_bytes(Bytes, Reason),
                                 capture_bytes(Bytes, Stack)])
            || [Whole, Class, Reason, Stack] <- Matches])
    end.

unsafe_catch_window(Path, Bytes, {Start, _}, Variables) ->
    Length = erlang:min(2400, byte_size(Bytes) - Start),
    Window = binary:part(Bytes, Start, Length),
    ReporterArguments = reporter_argument_lists(Window),
    Raw = lists:any(fun(Arguments) ->
        lists:any(fun(Variable) -> contains_identifier(Arguments, Variable) end,
                  Variables) andalso
        not reporter_arguments_are_projected(Arguments, Variables)
    end, ReporterArguments),
    case Raw of
        true -> [#{rule => <<"raw_exception_reporter">>,
                   path => list_to_binary(Path),
                   line => line_number(Bytes, Start)}];
        false -> []
    end.

capture_bytes(Bytes, {Start, Length}) -> binary:part(Bytes, Start, Length).

reporter_argument_lists(Window) ->
    %% Inspect each reporter call's own balanced argument expression. A safe
    %% projection elsewhere in the catch body, or later in the same reporter,
    %% cannot bless an earlier raw value.
    Pattern = <<"(?:io:(?:format|put_chars)|logger:[a-z_]+)\\s*\\(">>,
    case re:run(Window, Pattern,
                [global, {capture, first, index}, unicode]) of
        nomatch -> [];
        {match, Matches} ->
            lists:filtermap(fun([{Start, Length}]) ->
                argument_expression(Window, Start + Length)
            end, Matches)
    end.

argument_expression(Bytes, Start) when Start < byte_size(Bytes) ->
    case balanced_arguments(Bytes, Start, Start, 1, normal, 0) of
        {ok, End} -> {true, binary:part(Bytes, Start, End - Start)};
        incomplete -> false
    end;
argument_expression(_Bytes, _Start) -> false.

balanced_arguments(_Bytes, _Start, _Offset, _Depth, _State, Count)
  when Count > 1600 -> incomplete;
balanced_arguments(Bytes, _Start, Offset, _Depth, _State, _Count)
  when Offset >= byte_size(Bytes) -> incomplete;
balanced_arguments(Bytes, Start, Offset, Depth, normal, Count) ->
    case binary:at(Bytes, Offset) of
        $) when Depth =:= 1 -> {ok, Offset};
        $) -> balanced_arguments(Bytes, Start, Offset + 1, Depth - 1,
                                 normal, Count + 1);
        $( -> balanced_arguments(Bytes, Start, Offset + 1, Depth + 1,
                                 normal, Count + 1);
        $\" -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                   double_quote, Count + 1);
        $' -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                  single_quote, Count + 1);
        $% -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                  comment, Count + 1);
        _ -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                normal, Count + 1)
    end;
balanced_arguments(Bytes, Start, Offset, Depth, double_quote, Count) ->
    case binary:at(Bytes, Offset) of
        $\\ -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                    double_escape, Count + 1);
        $\" -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                   normal, Count + 1);
        _ -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                double_quote, Count + 1)
    end;
balanced_arguments(Bytes, Start, Offset, Depth, double_escape, Count) ->
    balanced_arguments(Bytes, Start, Offset + 1, Depth,
                       double_quote, Count + 1);
balanced_arguments(Bytes, Start, Offset, Depth, single_quote, Count) ->
    case binary:at(Bytes, Offset) of
        $\\ -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                    single_escape, Count + 1);
        $' -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                  normal, Count + 1);
        _ -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                single_quote, Count + 1)
    end;
balanced_arguments(Bytes, Start, Offset, Depth, single_escape, Count) ->
    balanced_arguments(Bytes, Start, Offset + 1, Depth,
                       single_quote, Count + 1);
balanced_arguments(Bytes, Start, Offset, Depth, comment, Count) ->
    case binary:at(Bytes, Offset) of
        $\n -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                   normal, Count + 1);
        _ -> balanced_arguments(Bytes, Start, Offset + 1, Depth,
                                comment, Count + 1)
    end.

contains_identifier(Bytes, Identifier) ->
    Pattern = <<"(?:^|[^A-Za-z0-9_])", Identifier/binary,
                "(?:$|[^A-Za-z0-9_])">>,
    re:run(Bytes, Pattern, [{capture, none}, unicode]) =:= match.

reporter_arguments_are_projected(Arguments, Variables) ->
    {ProjectionCount, Unprojected} = mask_projection_calls(Arguments),
    ProjectionCount > 0 andalso lists:all(fun(Variable) ->
        not contains_identifier(Unprojected, Variable)
    end, Variables).

mask_projection_calls(Bytes) -> mask_projection_calls(Bytes, 0, []).

mask_projection_calls(Bytes, Count, Acc) ->
    Matches = [{binary:match(Bytes, <<"diagnostic_failure_details(">>),
                byte_size(<<"diagnostic_failure_details(">>)},
               {binary:match(Bytes, <<"coverage_failure_details(">>),
                byte_size(<<"coverage_failure_details(">>)}],
    Present = [{Start, Length} || {{Start, _}, Length} <- Matches],
    case Present of
        [] -> {Count, iolist_to_binary(lists:reverse([Bytes | Acc]))};
        _ ->
            {Start, Length} = lists:min(Present),
            Prefix = binary:part(Bytes, 0, Start),
            ArgumentStart = Start + Length,
            case argument_expression(Bytes, ArgumentStart) of
                false -> {Count, iolist_to_binary(lists:reverse([Bytes | Acc]))};
                {true, ProjectionArguments} ->
                    End = ArgumentStart + byte_size(ProjectionArguments) + 1,
                    Suffix = binary:part(Bytes, End, byte_size(Bytes) - End),
                    mask_projection_calls(Suffix, Count + 1,
                                          [<<"typed_projection">>, Prefix | Acc])
            end
    end.

workflow_findings(Sources) ->
    Pattern = <<"(?im)^\\s*(?:run:\\s*)?.*\\b(?:gleam\\s+test|"
                "rebar3\\s+eunit|erl(?:\\.exe)?\\s+.*\\beunit:)\\b">>,
    lists:append([case re:run(Bytes, Pattern,
                              [global, {capture, first, index}, unicode]) of
        nomatch -> [];
        {match, Matches} ->
            [#{rule => <<"ci_bypasses_sanitizing_suite_runner">>,
               path => list_to_binary(Path), line => line_number(Bytes, Start)}
             || [{Start, _}] <- Matches]
    end || {Path, Bytes} <- Sources,
           lists:member(filename:extension(Path), [".yml", ".yaml"])]).

port_runner_inventory(Sources) ->
    lists:append([port_rows(Path, Bytes) || {Path, Bytes} <- Sources,
        lists:member(filename:extension(Path), [".escript", ".erl", ".hrl"]),
        Path =/= "scripts/failure_secrecy_audit.escript"]).

port_rows(Path, Bytes) ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    Sites = executable_port_lines(Bytes),
    [port_row(Path, Lines, Line) || Line <- Sites].

port_row(Path, Lines, Line) ->
    Site = function_window_for_line(Lines, Line),
    Collector = collector_window(Lines, Site),
    Context = <<Site/binary, "\n", Collector/binary>>,
    OwnedSupervisor = pinned_supervisor_launcher(Path, Site),
    SharedCollector = re:run(Site,
        <<"\\b(?:collect_eunit|command_collect|command_capture|await_child_exit|"
          "command_reap)\\s*\\(">>, [{capture, none}, unicode]) =:= match,
    Hidden = re:run(Site,
        <<"open_port\\s*\\([\\s\\S]{0,1600}?,\\s*hide(?:\\s*[,\\]])">>,
        [{capture, none}, unicode]) =:= match,
    Absolute = OwnedSupervisor orelse SharedCollector orelse
        (binary:match(Context, <<"monotonic_time(millisecond)">>) =/= nomatch
         andalso (binary:match(Context, <<"Deadline">>) =/= nomatch orelse
                  binary:match(Context, <<"deadline">>) =/= nomatch)),
    Bounded = OwnedSupervisor orelse SharedCollector orelse
        binary:match(Context, <<"output_exceeded(">>) =/= nomatch orelse
        re:run(Context,
            <<"(?:byte_size\\(Output\\)|\\bbytes\\b)[\\s\\S]{0,240}?"
              "(?:4096|65536|8388608|limit)">>,
            [{capture, none}, unicode]) =:= match,
    Reaped = OwnedSupervisor orelse SharedCollector orelse
        re:run(Context,
            <<"(?:await_child_exit|command_reap|kill_owned_child|"
              "child_exit_observed)\\s*\\(?">>,
            [{capture, none}, unicode]) =:= match,
    #{path => list_to_binary(Path), line => Line,
      hidden => Hidden, absolute_deadline => Absolute,
      bounded_output => Bounded, exit_or_reap_observed => Reaped,
      owned_supervisor => OwnedSupervisor}.

pinned_supervisor_launcher("scripts/process_runner.hrl", Site) ->
    lists:all(fun(Fragment) -> binary:match(Site, Fragment) =/= nomatch end,
        [<<"open_owned_process(">>, <<"scripts/process_supervisor.py">>,
         <<"process_supervisor_sha256()">>, <<"{packet, 4}">>,
         <<"await_supervisor_handshake(">>,
         <<"activate_process_supervisor(">>]);
pinned_supervisor_launcher(_, _) -> false.

function_window_for_line(Lines, Line) ->
    Start = function_start(Lines, erlang:min(Line, length(Lines))),
    End = function_end(Lines, Start + 1),
    iolist_to_binary(lists:join(<<"\n">>,
        lists:sublist(lists:nthtail(Start - 1, Lines), End - Start))).

function_start(_Lines, 1) -> 1;
function_start(Lines, Line) ->
    case function_header(lists:nth(Line, Lines)) of
        true -> Line;
        false -> function_start(Lines, Line - 1)
    end.

function_end(Lines, Line) when Line > length(Lines) -> length(Lines) + 1;
function_end(Lines, Line) ->
    case function_header(lists:nth(Line, Lines)) of
        true -> Line;
        false -> function_end(Lines, Line + 1)
    end.

function_header(Line) ->
    re:run(Line, <<"^[a-z][a-zA-Z0-9_]*\\s*\\(">>,
           [{capture, none}, unicode]) =:= match.

collector_window(Lines, Site) ->
    Pattern = <<"\\b([a-z][a-zA-Z0-9_]*)\\s*\\(Port(?:\\s*[,\\)])">>,
    Names = case re:run(Site, Pattern,
                        [global, {capture, [1], binary}, unicode]) of
        nomatch -> [];
        {match, Matches} -> [Name || [Name] <- Matches,
            re:run(Name, <<"(?:collect|await|reap)">>,
                   [{capture, none}]) =:= match]
    end,
    case Names of
        [Name | _] -> named_function_window(Lines, Name);
        [] -> <<>>
    end.

named_function_window(Lines, Name) ->
    Pattern = <<"^", Name/binary, "\\s*\\(">>,
    named_function_window(Lines, Pattern, 1).

named_function_window([], _Pattern, _Line) -> <<>>;
named_function_window([Bytes | Rest], Pattern, Line) ->
    case re:run(Bytes, Pattern, [{capture, none}, unicode]) of
        match -> function_window_for_line([Bytes | Rest], 1);
        nomatch -> named_function_window(Rest, Pattern, Line + 1)
    end.

%% Find executable calls without interpreting quoted mutation fixtures as code.
%% The scanner is deliberately lexical and finite: it tracks only Erlang's
%% comments, strings, quoted atoms and character literals, and retains line
%% numbers rather than source fragments.
executable_port_lines(Bytes) when is_binary(Bytes) ->
    lists:usort(executable_port_scan(Bytes, code, 1, none, [])).

executable_port_scan(<<>>, _State, _Line, _Previous, Acc) -> Acc;
executable_port_scan(<<$\n, Rest/binary>>, comment, Line, _Previous, Acc) ->
    executable_port_scan(Rest, code, Line + 1, $\n, Acc);
executable_port_scan(<<_Byte, Rest/binary>>, comment, Line, Previous, Acc) ->
    executable_port_scan(Rest, comment, Line, Previous, Acc);
executable_port_scan(<<$\\, $\n, Rest/binary>>, double_quote, Line,
                     Previous, Acc) ->
    executable_port_scan(Rest, double_quote, Line + 1, Previous, Acc);
executable_port_scan(<<$\\, _Escaped, Rest/binary>>, double_quote, Line,
                     Previous, Acc) ->
    executable_port_scan(Rest, double_quote, Line, Previous, Acc);
executable_port_scan(<<$\", Rest/binary>>, double_quote, Line, _Previous, Acc) ->
    executable_port_scan(Rest, code, Line, $\", Acc);
executable_port_scan(<<$\n, Rest/binary>>, double_quote, Line, Previous, Acc) ->
    executable_port_scan(Rest, double_quote, Line + 1, Previous, Acc);
executable_port_scan(<<_Byte, Rest/binary>>, double_quote, Line,
                     Previous, Acc) ->
    executable_port_scan(Rest, double_quote, Line, Previous, Acc);
executable_port_scan(<<$\\, $\n, Rest/binary>>, single_quote, Line,
                     Previous, Acc) ->
    executable_port_scan(Rest, single_quote, Line + 1, Previous, Acc);
executable_port_scan(<<$\\, _Escaped, Rest/binary>>, single_quote, Line,
                     Previous, Acc) ->
    executable_port_scan(Rest, single_quote, Line, Previous, Acc);
executable_port_scan(<<$', Rest/binary>>, single_quote, Line, _Previous, Acc) ->
    executable_port_scan(Rest, code, Line, $', Acc);
executable_port_scan(<<$\n, Rest/binary>>, single_quote, Line, Previous, Acc) ->
    executable_port_scan(Rest, single_quote, Line + 1, Previous, Acc);
executable_port_scan(<<_Byte, Rest/binary>>, single_quote, Line,
                     Previous, Acc) ->
    executable_port_scan(Rest, single_quote, Line, Previous, Acc);
executable_port_scan(<<$%, Rest/binary>>, code, Line, _Previous, Acc) ->
    executable_port_scan(Rest, comment, Line, $%, Acc);
executable_port_scan(<<$\", Rest/binary>>, code, Line, _Previous, Acc) ->
    executable_port_scan(Rest, double_quote, Line, $\", Acc);
executable_port_scan(<<$', Rest/binary>>, code, Line, _Previous, Acc) ->
    executable_port_scan(Rest, single_quote, Line, $', Acc);
executable_port_scan(<<$$, $\\, $\n, Rest/binary>>, code, Line,
                     _Previous, Acc) ->
    executable_port_scan(Rest, code, Line + 1, $\n, Acc);
executable_port_scan(<<$$, $\\, _Escaped, Rest/binary>>, code, Line,
                     _Previous, Acc) ->
    executable_port_scan(Rest, code, Line, $x, Acc);
executable_port_scan(<<$$, _Character, Rest/binary>>, code, Line,
                     _Previous, Acc) ->
    executable_port_scan(Rest, code, Line, $x, Acc);
executable_port_scan(<<"open_port", Rest/binary>>, code, Line,
                     Previous, Acc) ->
    Boundary = not erlang_identifier_byte(Previous),
    Next = case Boundary andalso port_call_follows(Rest) of
        true -> [Line | Acc];
        false -> Acc
    end,
    executable_port_scan(Rest, code, Line, $t, Next);
executable_port_scan(<<$\n, Rest/binary>>, code, Line, _Previous, Acc) ->
    executable_port_scan(Rest, code, Line + 1, $\n, Acc);
executable_port_scan(<<Byte, Rest/binary>>, code, Line, _Previous, Acc) ->
    executable_port_scan(Rest, code, Line, Byte, Acc).

erlang_identifier_byte(Byte) when Byte >= $a, Byte =< $z -> true;
erlang_identifier_byte(Byte) when Byte >= $A, Byte =< $Z -> true;
erlang_identifier_byte(Byte) when Byte >= $0, Byte =< $9 -> true;
erlang_identifier_byte($_) -> true;
erlang_identifier_byte($@) -> true;
erlang_identifier_byte(_) -> false.

port_call_follows(<<$(, _/binary>>) -> true;
port_call_follows(<<Byte, Rest/binary>>)
  when Byte =:= $\s; Byte =:= $\t; Byte =:= $\r; Byte =:= $\n ->
    port_call_follows(Rest);
port_call_follows(<<$%, Rest/binary>>) ->
    port_call_follows(skip_port_comment(Rest));
port_call_follows(_) -> false.

skip_port_comment(<<$\n, Rest/binary>>) -> <<$\n, Rest/binary>>;
skip_port_comment(<<_Byte, Rest/binary>>) -> skip_port_comment(Rest);
skip_port_comment(<<>>) -> <<>>.

port_runner_findings(Inventory) ->
    lists:append([port_row_findings(Row) || Row <- Inventory]).

port_row_findings(Row) ->
    Path = maps:get(path, Row),
    Line = maps:get(line, Row),
    Checks = [{hidden, <<"external_child_not_hidden">>},
              {owned_supervisor, <<"external_child_unowned_tree">>},
              {absolute_deadline, <<"external_child_relative_deadline">>},
              {bounded_output, <<"external_child_unbounded_output">>},
              {exit_or_reap_observed,
               <<"external_child_exit_unconfirmed">>}],
    [#{rule => Rule, path => Path, line => Line}
     || {Key, Rule} <- Checks, not maps:get(Key, Row)].

contract_results(Sources) ->
    [contract(Sources, <<"typed_exception_projection">>,
       "scripts/diagnostic_failure.hrl",
       [<<"diagnostic_failure_details(Class, Reason, Stack)">>,
        <<"diagnostic_failure_category(_)">>,
        <<"lists:sublist(Stack, 16)">>,
        <<"diagnostic_known_function(Module, Function, Count)">>]),
     contract(Sources, <<"eunit_listener_payload_elision">>,
       "scripts/qualification_eunit_listener.erl",
       [<<"Details = diagnostic_failure_details(Class, Reason, Stack)">>,
        <<"Count < 64">>, <<"failures_dropped">>,
        <<"cancellation({exit, _})">>]),
     absolute_bounded_hidden_child_contract(Sources),
     package_safe_process_contract(Sources),
     contract(Sources, <<"bundle_failure_is_typed">>,
       "scripts/audit_bundle.escript",
       [<<"failure => diagnostic_failure_details(Class, Reason, Stack)">>,
        <<"bundle_validate_capture">>, <<"validated_evidence_files()">>]),
     contract(Sources, <<"qpack_oracle_failure_is_redacted">>,
       "packages/http3/test/interop/qpack_oracle.py",
       [<<"safe_stderr_line(\"qpack oracle failed\")">>,
        <<"return failure_exit_status(error)">>,
        <<"raise SystemExit(run_cli(sys.argv[1:]))">>,
        <<"sys.stderr = BrokenSink()">>]),
     contract(Sources, <<"interop_peer_failure_is_typed_and_redacted">>,
       "scripts/interop_peer.py",
       [<<"def failure_result(error):">>,
        <<"def validate_peer_failure_report(report):">>,
        <<"return validate_peer_failure_report(report)">>,
        <<"except BaseException as error:">>,
        <<"failure = peer_failure_report(">>,
        <<"write_json_atomic(failure_path, failure)">>,
        <<"def safe_failure_line():">>,
        <<"return failure_exit_status(error)">>,
        <<"sys.exit(cli())">>]),
     contract(Sources, <<"interop_failure_json_has_closed_schema">>,
       "scripts/interop_evidence.hrl",
       [<<"interop_audit_failure_report(Peer, Report, Source, RunId)">>,
        <<"unknown_failure_scenario">>,
        <<"invalid_failure_result">>,
        <<"unexpected_failure_completion">>,
        <<"oversized_failure_output">>]),
     contract(Sources, <<"interop_failure_files_are_independently_audited">>,
       "scripts/interop_audit.escript",
       [<<"interop_audit_failure_directory_at(Peer, Source, RunId, Identity, Directory)">>,
        <<"interop_read_bounded(">>,
        <<"failure_directory_changed_while_reading">>,
        <<"missing_or_duplicate_driver_failure">>,
        <<"retained_interop_failure">>,
        <<"build\", \"interop\", \"failure-audits">>]),
     contract(Sources, <<"interop_notice_sink_failure_is_bounded">>,
       "scripts/interop_notice.py",
       [<<"def safe_failure_line(code):">>,
        <<"except BaseException:">>,
        <<"safe_failure_line(failure_code(error))">>,
        <<"return failure_exit_status(error)">>]),
     contract(Sources, <<"chromium_driver_failure_is_typed_and_redacted">>,
       "test/interop/browser/run.py",
       [<<"def safe_failure_line(message):">>,
        <<"except BaseException as error:">>,
        <<"record_active_failure(\"chromium\", ACTIVE_RUN_ID, ACTIVE_PHASE, status)">>,
        <<"safe_failure_line(\"Chromium interoperability failed\")">>,
        <<"return status">>]),
     contract(Sources, <<"firefox_driver_failure_is_typed_and_redacted">>,
       "test/interop/browser/firefox_run.py",
       [<<"except BaseException as error:">>,
        <<"record_active_failure(\"firefox\", ACTIVE_RUN_ID, ACTIVE_PHASE, status)">>,
        <<"safe_failure_line(\"Firefox interoperability failed\")">>,
        <<"return status">>]),
     contract(Sources, <<"go_peer_build_failure_is_typed_and_redacted">>,
       "scripts/interop_go_build.py",
       [<<"except BaseException:">>,
        <<"write_json_atomic(destination, {\"schema\": 1, \"status\": \"Failed\"})">>,
        <<"peer_tools.install_signal_handlers()">>,
        <<"safe_line(\"Independent Go peer build failed\", sys.stderr)">>,
        <<"status = peer_tools.command_exit_status(error)">>]),
     contract(Sources, <<"masque_native_failure_is_typed_and_redacted">>,
       "test/interop/masquego/native_runner.py",
        [<<"def safe_failure_line():">>,
        <<"install_signal_handlers()">>,
        <<"except BaseException as error:">>,
        <<"status = command_exit_status(error)">>]),
     contract(Sources, <<"browser_native_failure_is_typed_and_redacted">>,
       "test/interop/browser/native_runner.py",
        [<<"def safe_failure_line():">>,
        <<"install_signal_handlers()">>,
        <<"except BaseException as error:">>,
        <<"status = command_exit_status(error)">>]),
     exit_status_deadline_contract(Sources),
     evaluation_temp_contract(Sources),
     unconfirmed_child_contract(Sources),
     owned_process_tree_contract(Sources),
     windows_process_isolation_contract(Sources),
     runner_output_limit_contract(Sources),
     command_terminal_control_contract(Sources),
     crash_dump_contract(Sources)].

absolute_bounded_hidden_child_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    OpenRegion = bounded_region(Bytes,
        <<"open_owned_process(Executable, Arguments, Directory, Environment, Deadline) ->">>,
        <<"\nprocess_supervisor_python() ->">>, 16000),
    Checks = [
        binary:match(Bytes,
            <<"Deadline = erlang:monotonic_time(millisecond) + Milliseconds">>)
            =/= nomatch,
        binary:match(Bytes, <<"limit => 8388608">>) =/= nomatch,
        ordered_fragments(Bytes, [
            <<"TailSize = erlang:min(Size, 65536)">>,
            <<"binary:copy(binary:part(Combined, Size - TailSize, TailSize))">>
        ]),
        ordered_fragments(Bytes, [
            <<"{\"ERL_CRASH_DUMP_BYTES\", \"0\"}">>,
            <<"{\"ERL_CRASH_DUMP_SECONDS\", \"0\"}">>
        ]),
        ordered_fragments(OpenRegion, [
            <<"open_port({spawn_executable, Python}">>,
            <<"stderr_to_stdout">>,
            <<"hide">>,
            <<"{packet, 4}">>
        ])
    ],
    contract_check_result(<<"absolute_bounded_hidden_child">>, Path, Bytes,
                          <<"Deadline = erlang:monotonic_time(millisecond)">>,
                          Checks).

exit_status_deadline_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    Checks = exit_status_deadline_checks(Bytes),
    contract_check_result(<<"exit_status_rechecks_absolute_deadline">>, Path,
        Bytes, <<"{Port, {exit_status, Status}}">>, Checks).

exit_status_rechecks_deadline(<<>>) -> false;
exit_status_rechecks_deadline(Bytes) ->
    Checks = exit_status_deadline_checks(Bytes),
    Checks =/= [] andalso lists:all(fun(Check) -> Check =:= true end, Checks).

exit_status_deadline_checks(<<>>) -> [];
exit_status_deadline_checks(Bytes) ->
    Region = bounded_region(Bytes,
        <<"collect_before_deadline(Port, Output, Deadline) ->">>,
        <<"\nnew_output() ->">>, 12000),
    Helper = bounded_region(Bytes,
        <<"finish_exit_status(_Status, Output, true) ->">>,
        <<"\nprocess_completion_verified(">>, 5000),
    [
        ordered_fragments(Region, [
            <<"Remaining = Deadline - erlang:monotonic_time(millisecond)">>,
            <<"case Remaining =< 0 of">>,
            <<"true -> stop_child(Port, Output)">>
        ]),
        re:run(Region,
            <<"\\{Port,\\s*\\{exit_status,\\s*Status\\}\\}\\s*->[\\s\\S]{0,1800}?"
              "DeadlineExpired\\s*=\\s*erlang:monotonic_time"
              "\\(millisecond\\)\\s*>=\\s*Deadline[\\s\\S]{0,500}?"
              "finish_exit_status\\(Status,\\s*[A-Za-z][A-Za-z0-9_]*,"
              "\\s*DeadlineExpired\\)">>,
            [{capture, none}, unicode]) =:= match,
        ordered_fragments(Helper, [
            <<"finish_exit_status(_Status, Output, true) ->">>,
            <<"{124, finish_output(Output, true, true)}">>,
            <<"finish_exit_status(Status, Output, false) ->">>,
            <<"{Status, finish_output(Output, Status =:= 124, true)}">>
        ]),
        re:run(Region,
            <<"after\\s+Remaining\\s*->\\s*stop_child\\(Port,\\s*Output\\)">>,
            [{capture, none}, unicode]) =:= match
    ].

evaluation_temp_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    Region = bounded_region(Bytes,
        <<"run_child_evaluation(Directory, Paths, Evaluation, Milliseconds) ->">>,
        <<"\nrun_child_boot(Directory, Paths, Evaluation, Milliseconds) ->">>,
        16000),
    Checks = [binary:match(Region, <<"filename:join(\"build/process-runner\"">>)
                  =/= nomatch,
              binary:match(Region, <<"crypto:strong_rand_bytes(">>) =/= nomatch,
              binary:match(Region, <<"file:write_file(InputPath, Input, [exclusive])">>)
                  =/= nomatch,
              cleanup_is_typed(Region, <<"InputPath">>,
                               <<"cannot_remove_child_evaluation">>),
              not audited_source_path(
                  "build/process-runner/evaluation-audit-mutant.erl")],
    Completed = length([ok || true <- Checks]),
    #{id => <<"child_evaluation_temp_isolated_and_removed">>,
      path => list_to_binary(Path), line => source_line(Bytes, <<"InputPath =">>),
      checks => length(Checks), completed => Completed,
      passed => Completed =:= length(Checks)}.

unconfirmed_child_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    CompletionRegion = bounded_region(Bytes,
        <<"case maps:get(child_exit_observed, Output) of">>,
        <<"\n    after">>, 8000),
    Checks = [binary:match(Bytes,
                  <<"case maps:get(child_exit_observed, Output) of">>) =/= nomatch,
              ordered_fragments(CompletionRegion,
                  [<<"false ->">>,
                   <<"erlang:error(child_exit_unconfirmed)">>]),
              re:run(Bytes,
                  <<"cleanup_child_artifacts\\(_CrashDumpPath,"
                    "\\s*_CrashDumpDirectory,\\s*running\\)\\s*->"
                    "[\\s\\S]{0,1000}?\\bok\\s*[;.]">>,
                  [{capture, none}, unicode]) =:= match,
              binary:match(Bytes,
                  <<"child_evaluation_external_process_forbidden">>) =/= nomatch],
    contract_check_result(<<"unconfirmed_child_cannot_complete">>, Path, Bytes,
        <<"case maps:get(child_exit_observed, Output) of">>, Checks).

owned_process_tree_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    SupervisorPath = "scripts/process_supervisor.py",
    Supervisor = source_bytes(Sources, SupervisorPath),
    CapturePath = "scripts/command_capture.hrl",
    Capture = source_bytes(Sources, CapturePath),
    StopRegion = bounded_region(Bytes, <<"stop_child(Port, Output) ->">>,
                                <<"\nawait_child_exit(">>, 6000),
    OpenRegistrationRegion = bounded_region(Bytes,
        <<"case try_register_owned_tree(Port, ProvisionalIdentity) of">>,
        <<"\n    HandshakeDeadline =">>, 6000),
    ActivationRegion = bounded_region(Bytes,
        <<"activate_process_supervisor(Port, Identity, Deadline, "
          "Register, Start, Close) ->">>,
        <<"\nrecover_uncertain_supervisor_start(">>, 8000),
    UncertainRecoveryRegion = bounded_region(Bytes,
        <<"recover_uncertain_supervisor_start(Port, Identity, Deadline">>,
        <<"\nrecover_owned_supervisor(">>, 4000),
    OwnedRecoveryRegion = bounded_region(Bytes,
        <<"recover_owned_supervisor(Port, Identity, Close) ->">>,
        <<"\nsafe_close_callback(">>, 8000),
    KillOffset = binary:match(StopRegion, <<"kill_owned_child(Port)">>),
    JoinOffset = binary:match(StopRegion, <<"await_child_exit(Port">>),
    KillBeforeJoin = case {KillOffset, JoinOffset} of
        {{KillAt, _}, {JoinAt, _}} -> KillAt < JoinAt;
        _ -> false
    end,
    RecoveryKill = binary:match(OwnedRecoveryRegion, <<"kill_owned_child(Port)">>),
    RecoveryJoin = binary:match(OwnedRecoveryRegion, <<"await_child_exit(Port">>),
    RecoveryUnregister = binary:match(
        OwnedRecoveryRegion, <<"unregister_owned_tree(Port)">>),
    RecoveryClose = binary:match(
        OwnedRecoveryRegion, <<"safe_close_callback(Close, Port)">>),
    RecoveryKillBeforeJoin = case {RecoveryKill, RecoveryJoin} of
        {{RecoveryKillAt, _}, {RecoveryJoinAt, _}} ->
            RecoveryKillAt < RecoveryJoinAt;
        _ -> false
    end,
    RecoveryOrder = case {RecoveryKill, RecoveryJoin, RecoveryUnregister,
                          RecoveryClose} of
        {{KillAt0, _}, {JoinAt0, _}, {UnregisterAt, _}, {CloseAt, _}} ->
            KillAt0 < JoinAt0 andalso JoinAt0 < UnregisterAt andalso
                UnregisterAt < CloseAt;
        _ -> false
    end,
    Checks = [binary:match(Bytes, <<"process_supervisor_sha256()">>) =/= nomatch,
              binary:match(Bytes, <<"{packet, 4}">>) =/= nomatch,
              binary:match(Bytes, <<"await_supervisor_handshake(">>) =/= nomatch,
              binary:match(Bytes, <<"activate_process_supervisor(">>) =/= nomatch,
              ordered_fragments(OpenRegistrationRegion, [
                  <<"error ->">>,
                  <<"recover_owned_supervisor(">>,
                  <<"erlang:error(process_supervisor_registration_failed)">>,
                  <<"erlang:error(child_exit_unconfirmed)">>
              ]),
              ordered_fragments(ActivationRegion, [
                  <<"false ->">>,
                  <<"recover_owned_supervisor(Port, Identity, Close)">>,
                  <<"erlang:error(process_supervisor_registration_failed)">>,
                  <<"true ->">>,
                  <<"case Started of">>,
                  <<"false ->">>,
                  <<"recover_uncertain_supervisor_start(">>,
                  <<"erlang:error(process_supervisor_start_unconfirmed)">>
              ]),
              ordered_fragments(UncertainRecoveryRegion, [
                  <<"true = is_integer(Deadline)">>,
                  <<"recover_owned_supervisor(Port, Identity, Close)">>
              ]),
              RecoveryKillBeforeJoin,
              RecoveryOrder,
              ordered_fragments(OwnedRecoveryRegion, [
                  <<"kill_owned_child(Port)">>,
                  <<"await_child_exit(Port">>,
                  <<"{exited, _Attested} ->">>,
                  <<"unregister_owned_tree(Port)">>,
                  <<"safe_close_callback(Close, Port)">>
              ]),
              binary:match(Supervisor,
                  <<"start_outcome = wait_for_start(deadline)">>) =/= nomatch,
              binary:match(Supervisor,
                  <<"if start_outcome != \"start\":">>) =/= nomatch,
              binary:match(Supervisor,
                  <<"if start_outcome == \"deadline\":">>) =/= nomatch,
              binary:match(Supervisor,
                  <<"write_packet(b\"F|124|1|0|1|1\")">>) =/= nomatch,
              binary:match(Bytes, <<"attest_owned_exit(">>) =/= nomatch,
              binary:match(Capture, <<"open_owned_process(">>) =/= nomatch,
              binary:match(Capture, <<"open_port(">>) =:= nomatch,
              binary:match(Supervisor,
                           <<"options[\"start_new_session\"] = supervisor_root">>)
                  =/= nomatch,
              binary:match(Supervisor, <<"os.killpg(">>) =/= nomatch,
              binary:match(Supervisor,
                           <<"JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE">>) =/= nomatch,
              binary:match(Supervisor, <<"CREATE_SUSPENDED">>) =/= nomatch,
              binary:match(Supervisor,
                           <<"AssignProcessToJobObject">>) =/= nomatch,
              binary:match(Supervisor, <<"options[\"close_fds\"] = True">>)
                  =/= nomatch,
              binary:match(Supervisor, <<"CreatePseudoConsole">>) =/= nomatch,
              binary:match(Supervisor,
                           <<"PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE">>) =/= nomatch,
              binary:match(Supervisor,
                           <<"close_console_while_draining">>) =/= nomatch,
              binary:match(Supervisor, <<"console_isolated">>) =/= nomatch,
              binary:match(Supervisor, <<"F|{status}|">>) =/= nomatch,
              KillBeforeJoin],
    Completed = length([ok || true <- Checks]),
    FailedCheckIndices = [Index || {Check, Index} <- lists:zip(
        Checks, lists:seq(1, length(Checks))), Check =/= true],
    #{id => <<"owned_native_process_tree_is_joined">>,
      path => list_to_binary(Path),
      line => source_line(Bytes, <<"open_owned_process(Executable">>),
      checks => length(Checks), completed => Completed,
      failed_check_indices => FailedCheckIndices,
      passed => Completed =:= length(Checks)}.

package_safe_process_contract(Sources) ->
    Path = "scripts/package_suite.escript",
    Bytes = source_bytes(Sources, Path),
    SafeFunction = bounded_region(Bytes,
        <<"package_safe_process(Process) ->">>,
        <<"\n\npackage_process_keys()">>, 2000),
    ValidationRegion = bounded_region(Bytes,
        <<"package_process_valid(Process) when is_map(Process) ->">>,
        <<"\npackage_process_valid(_)">>, 5000),
    Keys = package_process_key_names(Bytes),
    ExpectedKeys = package_process_expected_keys(),
    Checks = [
        binary:match(Bytes,
            <<"process => package_safe_process(Output)">>) =/= nomatch,
        re:run(SafeFunction,
            <<"^package_safe_process\\(Process\\)\\s*->\\s*"
              "maps:with\\(package_process_keys\\(\\), Process\\)\\.\\s*$">>,
            [{capture, none}, unicode]) =:= match,
        Keys =:= ExpectedKeys,
        not lists:member(<<"tail">>, Keys),
        not lists:member(<<"output_sha256">>, Keys),
        ordered_fragments(ValidationRegion, [
            <<"lists:sort(maps:keys(Process)) =:=">>,
            <<"lists:sort(package_process_keys())">>,
            <<"process_completion_verified(Process)">>
        ]),
        binary:match(Bytes, <<"failure => diagnostic_failure_details">>)
            =/= nomatch,
        binary:match(Bytes, <<"qualification_eunit_listener:run">>)
            =/= nomatch
    ],
    contract_check_result(<<"suite_report_strips_child_output">>, Path, Bytes,
        <<"package_safe_process(Process) ->">>, Checks).

package_process_key_names(Bytes) ->
    Region = bounded_region(Bytes, <<"package_process_keys() ->">>,
        <<"\n\npackage_process_valid(">>, 4000),
    case re:run(Region,
        <<"^package_process_keys\\(\\)\\s*->\\s*(\\[[\\s\\S]*\\])\\.\\s*$">>,
        [{capture, [1], binary}, unicode]) of
        {match, [Expression]} -> package_process_literal_keys(Expression);
        nomatch -> invalid
    end.

package_process_literal_keys(Expression) ->
    case re:run(Expression,
        <<"^\\[\\s*[a-z][a-z0-9_]*(?:\\s*,\\s*[a-z][a-z0-9_]*)*\\s*\\]$">>,
        [{capture, none}, unicode]) of
        match ->
            Compact = re:replace(Expression, <<"[\\s\\[\\]]">>, <<>>,
                                 [global, {return, binary}, unicode]),
            binary:split(Compact, <<",">>, [global]);
        nomatch -> invalid
    end.

package_process_expected_keys() ->
    [<<"output_bytes">>, <<"output_hashed_bytes">>, <<"output_limit_bytes">>,
     <<"output_digest_complete">>, <<"output_limit_exceeded">>,
     <<"vm_process_heap_words">>, <<"vm_heap_includes_shared_binaries">>,
     <<"crash_dumps_disabled">>, <<"timed_out">>, <<"child_exit_observed">>,
     <<"process_supervisor">>, <<"process_supervisor_protocol_valid">>,
     <<"process_supervisor_failure_code">>,
     <<"process_supervisor_attestation_failure">>,
     <<"process_supervisor_reported_status">>,
     <<"process_supervisor_observed_status">>, <<"native_tree_empty">>,
     <<"native_console_isolated">>, <<"native_descendant_outlived">>,
     <<"native_termination_requested">>].

windows_process_isolation_contract(Sources) ->
    Path = "scripts/process_supervisor.py",
    Supervisor = source_bytes(Sources, Path),
    WatcherPath = "scripts/windows_process_visibility_watch.ps1",
    Watcher = source_bytes(Sources, WatcherPath),
    LauncherPath = "scripts/windows_console_inheritance_audit.ps1",
    Launcher = source_bytes(Sources, LauncherPath),
    AttributeRegion = bounded_region(Supervisor,
        <<"if not KERNEL32.UpdateProcThreadAttribute(">>,
        <<"\n\n        startup = STARTUPINFOEX()">>, 3000),
    StandardHandleRegion = bounded_region(Supervisor,
        <<"standard_handle_ids = (">>, <<"\n        if not created:">>, 7000),
    ResumeRegion = bounded_region(Supervisor,
        <<"    def resume(self) -> None:">>,
        <<"\n    def close_console_while_draining(">>, 4000),
    DrainRegion = bounded_region(Supervisor,
        <<"    def close_console_while_draining(">>,
        <<"\n    def close_console_before_resume(">>, 6000),
    SuperviseRegion = bounded_region(Supervisor,
        <<"def supervise_windows(">>, <<"\n\ndef arguments()">>, 20000),
    AbnormalRegion = bounded_region(Supervisor,
        <<"def windows_abnormal_exit_category(">>,
        <<"\n\ndef wait_until(">>, 6000),
    SupervisorSelfTest = bounded_region(Supervisor,
        <<"def self_test() -> int:">>,
        <<"\n\ndef windows_fault_self_test()">>, 16000),
    NativeSelfTest = bounded_region(Watcher,
        <<"    $current = [System.Diagnostics.Process]::GetCurrentProcess()">>,
        <<"\nfunction Get-SafeParentName">>, 8000),
    TrapRegion = bounded_region(Watcher,
        <<"trap {">>, <<"\nfunction Get-PrivateSignalPath">>, 5000),
    ParentRegion = bounded_region(Watcher,
        <<"function Get-SafeParentName">>,
        <<"\nfunction Get-TargetProcesses">>, 6000),
    TargetRegion = bounded_region(Watcher,
        <<"function Get-TargetProcesses">>,
        <<"\nfunction Get-InternalProcessIdentity">>, 8000),
    OwnershipRegion = bounded_region(Watcher,
        <<"function Get-RetainedOwnedParent">>,
        <<"\nfunction Stop-ObservedTarget">>, 18000),
    OwnerBindingRegion = bounded_region(Watcher,
        <<"if (-not $stopObservation -and $RequireOwnerBinding)">>,
        <<"\n$watch = [System.Diagnostics.Stopwatch]::StartNew()">>, 16000),
    SamplingRegion = bounded_region(Watcher,
        <<"while (-not $stopObservation -and $watch.ElapsedMilliseconds">>,
        <<"\n$watch.Stop()">>, 26000),
    PublicationRegion = bounded_region(Watcher,
        <<"$remainingIdentities = @{}">>,
        <<"\n$script:watcherStep = 'publication'">>, 18000),
    LauncherOwnerRegion = bounded_region(Launcher,
        <<"$watcher = Start-Process">>,
        <<"\n    $fixtureStdoutTask =">>, 14000),
    FailureCategories = [
        {<<"0xC0000005">>, <<"child_access_violation">>},
        {<<"0xC0000008">>, <<"child_invalid_handle">>},
        {<<"0xC000000D">>, <<"child_invalid_parameter">>},
        {<<"0xC0000017">>, <<"child_no_memory">>},
        {<<"0xC000001D">>, <<"child_illegal_instruction">>},
        {<<"0xC0000022">>, <<"child_access_denied">>},
        {<<"0xC000007B">>, <<"child_invalid_image">>},
        {<<"0xC00000FD">>, <<"child_stack_overflow">>},
        {<<"0xC000012F">>, <<"child_invalid_image">>},
        {<<"0xC0000135">>, <<"child_dependency_missing">>},
        {<<"0xC0000139">>, <<"child_entrypoint_missing">>},
        {<<"0xC000013A">>, <<"child_controlled_interrupt">>},
        {<<"0xC0000142">>, <<"child_initialization_failed">>},
        {<<"0xC0000374">>, <<"child_heap_corruption">>},
        {<<"0xC0000409">>, <<"child_fast_fail">>},
        {<<"0xC0000417">>, <<"child_invalid_crt_parameter">>},
        {<<"0xC0000420">>, <<"child_assertion_failure">>},
        {<<"0x40000015">>, <<"child_fatal_application_exit">>},
        {<<"0xFFFFFFFF">>, <<"child_runtime_abort">>}
    ],
    FixedCategoryChecks = [
        binary:match(AbnormalRegion,
            <<Code/binary, ": \"", Category/binary, "\"">>) =/= nomatch
        || {Code, Category} <- FailureCategories
    ],
    Checks0 = [
        match_count(AttributeRegion,
            <<"KERNEL32\\.UpdateProcThreadAttribute\\(">>) =:= 1,
        ordered_fragments(AttributeRegion, [
            <<"PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE">>,
            <<"ctypes.c_void_p(int(pseudoconsole.value))">>,
            <<"ctypes.sizeof(ctypes.c_void_p)">>
        ]),
        binary:match(AttributeRegion,
            <<"ctypes.byref(pseudoconsole),\n            ctypes.sizeof">>) =:= nomatch,
        ordered_fragments(StandardHandleRegion, [
            <<"STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE">>,
            <<"saved_standard_handles: list[int | None] = []">>,
            <<"cleared_standard_handles = 0">>,
            <<"restore_failed = False">>,
            <<"try:">>,
            <<"for standard_handle_id in standard_handle_ids:">>,
            <<"KERNEL32.GetStdHandle(standard_handle_id)">>,
            <<"standard_handle_id, wintypes.HANDLE()">>,
            <<"cleared_standard_handles += 1">>,
            <<"created = bool(KERNEL32.CreateProcessW(">>,
            <<"argv[0], command_line, None, None, False">>,
            <<"finally:">>,
            <<"for index in range(cleared_standard_handles):">>,
            <<"restored = saved_standard_handles[index]">>,
            <<"standard_handle_ids[index]">>,
            <<"wintypes.HANDLE(restored or 0)">>,
            <<"restore_failed = True">>,
            <<"if restore_failed:">>,
            <<"raise SupervisorFailure(\"console_prestart_setup_failed\")">>
        ]),
        match_count(StandardHandleRegion,
            <<"KERNEL32\\.SetStdHandle\\(">>) =:= 2,
        binary:match(ResumeRegion,
            <<"close_windows_handle(self._input_write)">>) =:= nomatch,
        ordered_fragments(ResumeRegion, [
            <<"self._resumed = True">>,
            <<"thread_closed = close_windows_handle(self._thread)">>,
            <<"if not thread_closed:">>,
            <<"raise SupervisorFailure(\"console_prestart_cleanup_failed\")">>
        ]),
        ordered_fragments(SuperviseRegion, [
            <<"child.resume()">>,
            <<"returncode = child.wait(timeout=TREE_JOIN_SECONDS)">>,
            <<"console_closed = child.close_console_while_draining(relay)">>
        ]),
        ordered_fragments(DrainRegion, [
            <<"input_closed = close_windows_handle(self._input_write)">>,
            <<"self._input_write = 0">>,
            <<"relay.join(timeout=TREE_JOIN_SECONDS)">>,
            <<"self._console_close_completed.wait(timeout=TREE_JOIN_SECONDS)">>
        ]),
        binary:match(AbnormalRegion,
            <<"if returncode <= 255:\n        return None">>) =/= nomatch,
        binary:match(AbnormalRegion,
            <<"}.get(returncode & 0xFFFFFFFF, \"child_abnormal_exit\")">>)
            =/= nomatch,
        binary:match(SuperviseRegion,
            <<"write_packet(b\"E|\" + abnormal_exit.encode(\"ascii\"))">>)
            =/= nomatch,
        binary:match(SupervisorSelfTest,
            ?PROCESS_SUPERVISOR_SELF_TEST_MARKER)
            =/= nomatch,
        binary:match(Watcher, <<"$targetNames.Count -ne 14">>) =/= nomatch,
        binary:match(Watcher, <<"$terminableNames.Count -ne 13">>) =/= nomatch,
        ordered_fragments(Watcher, [
            <<"[switch] $RequireOwnerBinding">>,
            <<"function Remove-PrivateSignal">>,
            <<"Remove-PrivateSignal -Path $script:readySignalPath">>,
            <<"Remove-PrivateSignal -Path $script:ownerSignalPath">>,
            <<"function Get-PrivateSignalPath">>,
            <<"'windows-process-visibility-' + $Token + '.' + $Kind">>,
            <<"function ConvertFrom-OwnerBindingBytes">>,
            <<"$Bytes.Length -lt 5 -or $Bytes.Length -gt 48">>,
            <<"$processId -gt [int]::MaxValue">>,
            <<"$RequireOwnerBinding -and $ReadyToken -eq ''">>
        ]),
        binary:match(Watcher,
            <<"(?<pid>[1-9][0-9]{0,9}):(?<ticks>[1-9][0-9]{0,18})\\n$">>)
            =/= nomatch,
        ordered_fragments(TrapRegion, [
            <<"Remove-PrivateSignal -Path $script:readySignalPath">>,
            <<"Remove-PrivateSignal -Path $script:ownerSignalPath">>,
            <<"foreach ($retained in $script:retainedTargets)">>,
            <<"$retained.process.Dispose()">>
        ]),
        ordered_fragments(NativeSelfTest, [
            <<"$current = [System.Diagnostics.Process]::GetCurrentProcess()">>,
            <<"ParentProcessId($current.Handle)">>,
            <<"VisibleWindowState(">>,
            <<"catch {">>,
            <<"\"failure_code\":\"native_boundary_unavailable\"">>,
            <<"finally {">>,
            <<"$current.Dispose()">>,
            <<"\"controls\":32,\"passed\":true">>
        ]),
        ordered_fragments(TargetRegion, [
            <<"[System.Diagnostics.Process]::GetProcessesByName($name)">>,
            <<"$processHandle = [IntPtr]$process.Handle">>,
            <<"$processId = $process.Id">>,
            <<"$startTicks = $process.StartTime.ToUniversalTime().Ticks">>,
            <<"-NotePropertyName HttpTargetName">>,
            <<"-NotePropertyValue $name -Force">>,
            <<"-NotePropertyName HttpProcessId">>,
            <<"-NotePropertyName HttpStartTicks">>,
            <<"-NotePropertyName HttpProcessHandle">>,
            <<"-NotePropertyValue $processHandle -Force">>,
            <<"$result += $process">>
        ]),
        ordered_fragments(TargetRegion, [
            <<"catch {">>,
            <<"if (-not $RequireOwnerBinding) { throw }">>,
            <<"foreach ($retained in $result)">>,
            <<"$retained.Dispose()">>,
            <<"throw">>
        ]),
        binary:match(ParentRegion,
            <<"ParentProcessId(\n            [IntPtr]$Process.HttpProcessHandle)">>)
            =/= nomatch,
        ordered_fragments(OwnershipRegion, [
            <<"-not [bool]$candidate.owned">>,
            <<"[int64]$candidate.start_ticks -gt $ChildStartTicks">>,
            <<"$candidate.process.ExitTime.ToUniversalTime().Ticks -ge">>,
            <<"for ($depth = 0; $depth -lt 64; $depth += 1)">>,
            <<"[HttpProcessVisibilityNative]::ParentProcessId($cursorHandle)">>,
            <<"$visited.Add($parentId)">>,
            <<"$parentHandle = [IntPtr]$parent.Handle">>,
            <<"$parentStartTicks -gt $childStartTicks">>,
            <<"$cursorHandle = $parentHandle">>,
            <<"foreach ($ancestor in $openedAncestors) { $ancestor.Dispose() }">>,
            <<"function Add-RetainedOwnedTarget">>,
            <<"owned = $true">>
        ]),
        ordered_fragments(OwnerBindingRegion, [
            <<"Get-PrivateSignalPath">>,
            <<"-Token $ReadyToken -Kind 'owner'">>,
            <<"$ownerClock.ElapsedMilliseconds -lt 10000">>,
            <<"ConvertFrom-OwnerBindingBytes -Bytes $ownerBytes">>,
            <<"$ownerProcessId -ne [int]$ownerBinding.process_id">>,
            <<"$ownerStartTicks -ne [int64]$ownerBinding.start_ticks">>,
            <<"-NotePropertyName HttpProcessHandle">>,
            <<"$script:ownedIdentities[$script:ownerRootIdentity] = $true">>,
            <<"Add-RetainedOwnedTarget">>,
            <<"$ownerBindingVerified = $true">>,
            <<"Remove-PrivateSignal">>,
            <<"$ownerBindingCleanupConfirmed">>,
            <<"throw 'owner_binding_cleanup_failed'">>
        ]),
        ordered_fragments(SamplingRegion, [
            <<"$script:watcherStep = 'sampling_ownership'">>,
            <<"$ownership = if (">>,
            <<"$script:ownedIdentities.ContainsKey($identity)">>,
            <<"Test-ProcessOwnership -Process $process">>,
            <<"if (-not $ownership.owned)">>,
            <<"$ignoredUnownedCandidates = [Math]::Min(">>,
            <<"65535, $ignoredUnownedCandidates + 1)">>,
            <<"continue">>,
            <<"if ($ownership.root) { $ownerRootObserved = $true }">>,
            <<"$script:ownedIdentities[$identity] = $true">>,
            <<"$retainProcess = Add-RetainedOwnedTarget">>
        ]),
        ordered_fragments(LauncherOwnerRegion, [
            <<"'-ReadyToken', $token">>,
            <<"'-RequireOwnerBinding'">>,
            <<"$fixture.Start()">>,
            <<"$fixture.StartTime.ToUniversalTime().Ticks.ToString(">>,
            <<"[System.IO.FileMode]::CreateNew">>,
            <<"[System.IO.FileShare]::None">>,
            <<"$ownerStream.Write($ownerBytes, 0, $ownerBytes.Length)">>,
            <<"$ownerStream.Flush($true)">>,
            <<"$ownerBytes = $null">>,
            <<"$ownerStream.Dispose()">>
        ]),
        ordered_fragments(PublicationRegion, [
            <<"$retained.process.Dispose()">>,
            <<"$script:retainedTargets.Clear()">>,
            <<"$observationComplete -and\n    $baselineForbiddenCount -eq 0">>
        ]),
        ordered_fragments(PublicationRegion, [
            <<"$visibleEvents -eq 0">>,
            <<"$unverifiedEvents -eq 0">>,
            <<"(-not $lineageRequired -or $lineageComplete)">>,
            <<"(-not $RequireOwnerBinding -or (">>,
            <<"$ownerBindingVerified">>,
            <<"$ownerBindingCleanupConfirmed">>,
            <<"$ownerRootObserved">>,
            <<"$remaining -eq 0">>,
            <<"owner_binding_required = [bool]$RequireOwnerBinding">>,
            <<"owner_binding_verified = $ownerBindingVerified">>,
            <<"owner_binding_cleanup_confirmed = $ownerBindingCleanupConfirmed">>,
            <<"owner_root_observed = $ownerRootObserved">>,
            <<"ignored_unowned_candidate_count = $ignoredUnownedCandidates">>,
            <<"unverified_parent_event_count = $unverifiedParentEvents">>,
            <<"lineage_required = $lineageRequired">>,
            <<"lineage_complete = $lineageComplete">>
        ]),
        binary:match(PublicationRegion,
            <<"(-not $RequireOwnerBinding -or (\n"
              "        $ownerBindingVerified -and\n"
              "        $ownerBindingCleanupConfirmed -and\n"
              "        $ownerRootObserved\n"
              "    )) -and">>) =/= nomatch,
        ordered_fragments(Launcher, [
            <<"$watchStdout -notmatch [regex]::Escape($token)">>,
            <<"$null -eq $watchJson.PSObject.Properties['owner_process_id']">>,
            <<"$null -eq $watchJson.PSObject.Properties['owner_start_ticks']">>,
            <<"$null -eq $watchJson.PSObject.Properties['owner_signal_path']">>,
            <<"$null -eq $watchJson.PSObject.Properties['ready_token']">>,
            <<"$watchJson.owner_binding_required -eq $true">>,
            <<"$watchJson.owner_binding_verified -eq $true">>,
            <<"$watchJson.owner_binding_cleanup_confirmed -eq $true">>,
            <<"$watchJson.owner_root_observed -eq $true">>,
            <<"$watchJson.ignored_unowned_candidate_count -ge 1">>,
            <<"$watchJson.sample_observation_failure_code -eq 'none'">>,
            <<"$watchJson.sample_observation_failure_ownership_step -eq 'none'">>
        ]),
        binary:match(Watcher,
            <<"return $OwnerBound -or $StageName -eq 'console-inheritance'">>)
            =/= nomatch,
        binary:match(Watcher,
            <<"-StageName $Stage -OwnerBound ([bool]$RequireOwnerBinding)">>)
            =/= nomatch
    ],
    Checks = Checks0 ++ FixedCategoryChecks,
    Completed = length([ok || true <- Checks]),
    FailedCheckIndices = [Index || {Check, Index} <- lists:zip(
        Checks, lists:seq(1, length(Checks))), Check =/= true],
    #{id => <<"windows_process_isolation_is_fail_closed">>,
      path => list_to_binary(Path),
      line => source_line(Supervisor,
                          <<"def create_windows_pseudoconsole_child(">>),
      checks => length(Checks), completed => Completed,
      failed_check_indices => lists:sublist(FailedCheckIndices, 256),
      passed => Completed =:= length(Checks),
      watcher_path => list_to_binary(WatcherPath),
      launcher_path => list_to_binary(LauncherPath)}.

runner_output_limit_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    Capture = source_bytes(Sources, "scripts/command_capture.hrl"),
    Checks = [
        binary:match(Bytes, <<"supervisor_output_limit_seen => false">>)
            =/= nomatch,
        binary:match(Bytes,
            <<"Code =:= <<\"supervisor_output_limit\">> orelse">>) =/= nomatch,
        binary:match(Bytes,
            <<"output_limit_exceeded => Count > Limit orelse SupervisorLimited">>)
            =/= nomatch,
        binary:match(Bytes,
            <<"output_digest_complete => Count =< Limit andalso not SupervisorLimited">>)
            =/= nomatch,
        binary:match(Capture,
            <<"command_exit_outcome(<<\"supervisor_output_limit\">>, _, 125) -> "
              "output_limit">>) =/= nomatch,
        binary:match(Capture,
            <<"output_limit_exceeded => Outcome =:= output_limit">>) =/= nomatch,
        binary:match(Capture,
            <<"output_digest_complete => Outcome =/= output_limit">>) =/= nomatch
    ],
    Completed = length([ok || true <- Checks]),
    #{id => <<"supervisor_output_limit_is_typed">>,
      path => list_to_binary(Path),
      line => source_line(Bytes, <<"supervisor_output_limit_seen">>),
      checks => length(Checks), completed => Completed,
      passed => Completed =:= length(Checks)}.

command_terminal_control_contract(Sources) ->
    Path = "scripts/command_capture.hrl",
    Bytes = source_bytes(Sources, Path),
    CollectRegion = bounded_region(Bytes,
        <<"command_collect(Port, State = #{deadline := Deadline}) ->">>,
        <<"\ncommand_stop(Port, State, Outcome)">>, 18000),
    FailureRegion = bounded_region(Bytes,
        <<"command_failure_result(State, Proof) ->">>,
        <<"\n%% Windows ConPTY">>, 8000),
    SuccessRegion = bounded_region(Bytes,
        <<"command_capture_success_result(_State, Semantic, Proof) ->">>,
        <<"\n%% Windows ConPTY">>, 4000),
    SemanticRegion = bounded_region(Bytes,
        <<"command_semantic_output(Bytes) when is_binary(Bytes) ->">>,
        <<"\ncommand_proof(State, Outcome, Exit, Joined) ->">>, 12000),
    ProofRegion = bounded_region(Bytes,
        <<"command_proof(State, Outcome, Exit, Joined) ->">>,
        <<"\ncommand_supervisor_proof">>, 5000),
    Checks = [
        ordered_fragments(CollectRegion, [
            <<"maps:get(bytes, Next) > maps:get(limit, Next)">>,
            <<"command_stop(Port, Next#{chunks => []}, output_limit)">>,
            <<"Raw = iolist_to_binary(lists:reverse(">>,
            <<"{Semantic, Removed} = command_semantic_output(Raw)">>,
            <<"terminal_control_bytes_removed => Removed">>,
            <<"command_capture_success_result(">>
        ]),
        ordered_fragments(FailureRegion, [
            <<"Raw = iolist_to_binary(lists:reverse(maps:get(chunks, State)))">>,
            <<"{Semantic, Removed} = command_semantic_output(Raw)">>,
            <<"SafeProof = Proof#{terminal_control_bytes_removed => Removed}">>,
            <<"Projection = try Projector(Semantic)">>
        ]),
        ordered_fragments(SuccessRegion, [
            <<"case command_success_verified(Proof) of">>,
            <<"true -> {ok, Semantic, Proof}">>,
            <<"false -> {error, Proof}">>
        ]),
        ordered_fragments(SemanticRegion, [
            <<"case binary:match(Bytes, <<27>>) of">>,
            <<"command_semantic_escape(Rest, NextChunks, Removed + 1)">>,
            <<"command_semantic_escape(<<\"[\", Rest/binary>>">>,
            <<"command_semantic_escape(<<\"]\", Rest/binary>>">>,
            <<"when Byte >= 16#40, Byte =< 16#7e">>,
            <<"when Byte >= 16#20, Byte =< 16#3f">>,
            <<"StringTerminator = binary:match(Bytes, <<27, $\\\\>>)">>,
            <<"none -> {<<>>, byte_size(Bytes)}">>,
            <<"command_first_terminal({Bell, 1}, {St, 2}) when Bell =< St">>
        ]),
        match_count(Bytes,
            <<"terminal_control_bytes_removed => Removed">>) =:= 2,
        ordered_fragments(ProofRegion, [
            <<"output_bytes => maps:get(bytes, State)">>,
            <<"terminal_control_bytes_removed =>">>,
            <<"maps:get(terminal_control_bytes_removed, State, 0)">>
        ])
    ],
    Completed = length([ok || true <- Checks]),
    FailedCheckIndices = [Index || {Check, Index} <- lists:zip(
        Checks, lists:seq(1, length(Checks))), Check =/= true],
    #{id => <<"terminal_controls_are_bounded_and_payload_free">>,
      path => list_to_binary(Path),
      line => source_line(Bytes, <<"command_semantic_output(Bytes)">>),
      checks => length(Checks), completed => Completed,
      failed_check_indices => FailedCheckIndices,
      passed => Completed =:= length(Checks)}.

crash_dump_contract(Sources) ->
    Path = "scripts/process_runner.hrl",
    Bytes = source_bytes(Sources, Path),
    Checks = [binary:match(Bytes, <<"\"ERL_CRASH_DUMP_BYTES\", \"0\"">>)
                  =/= nomatch,
              binary:match(Bytes, <<"\"ERL_CRASH_DUMP_SECONDS\", \"0\"">>)
                  =/= nomatch,
              unique_crash_dump_path(Bytes),
              re:run(Bytes,
                  <<"\\{\\s*\"ERL_CRASH_DUMP\"\\s*,\\s*CrashDumpPath\\s*\\}">>,
                  [{capture, none}, unicode]) =:= match,
              crash_cleanup_is_safe(Bytes)],
    Completed = length([ok || true <- Checks]),
    #{id => <<"crash_dump_isolated_and_removed">>,
      path => list_to_binary(Path),
      line => source_line(Bytes, <<"ERL_CRASH_DUMP_BYTES">>),
      checks => length(Checks), completed => Completed,
      passed => Completed =:= length(Checks),
      required_behavior =>
          <<"unique isolated path plus bounded parent cleanup">>}.

unique_crash_dump_path(Bytes) ->
    Assignment = re:run(Bytes,
        <<"CrashDumpPath\\s*=[\\s\\S]{0,1000}?build/process-runner"
          "[\\s\\S]{0,1000}?crypto:strong_rand_bytes\\(">>,
        [{capture, none}, unicode]) =:= match,
    Assignment andalso binary:match(Bytes, <<"erl_crash.dump">>) =/= nomatch.

crash_cleanup_is_safe(Bytes) ->
    CalledAfter = re:run(Bytes,
        <<"after[\\s\\S]{0,500}?cleanup_child_artifacts\\(CrashDumpPath,"
          "\\s*CrashDumpDirectory,[\\s\\S]{0,200}?erase\\(CleanupKey\\)\\)">>,
        [{capture, none}, unicode]) =:= match,
    RetainsUnconfirmed = re:run(Bytes,
        <<"cleanup_child_artifacts\\(_CrashDumpPath,\\s*_CrashDumpDirectory,"
          "\\s*running\\)\\s*->[\\s\\S]{0,300}?ok">>,
        [{capture, none}, unicode]) =:= match,
    Helper = bounded_region(Bytes,
        <<"cleanup_child_artifacts(CrashDumpPath, CrashDumpDirectory, State)">>,
        <<"\nchild_start_category(">>, 4000),
    DeletesConfirmed = binary:match(Helper,
        <<"file:delete(CrashDumpPath)">>) =/= nomatch andalso
        binary:match(Helper,
            <<"erlang:error(cannot_remove_child_crash_dump)">>) =/= nomatch andalso
        re:run(Helper,
            <<"erlang:error\\(\\{cannot_remove_child_crash_dump,">>,
            [{capture, none}, unicode]) =:= nomatch,
    CalledAfter andalso RetainsUnconfirmed andalso DeletesConfirmed.

cleanup_is_typed(Bytes, PathName, FixedCategory) ->
    AfterPattern = iolist_to_binary([
        <<"after[\\s\\S]{0,1800}?file:delete\\(">>, PathName,
        <<"\\)[\\s\\S]{0,900}?erlang:error\\(">>, FixedCategory, <<"\\)">>]),
    HasAfterCleanup = re:run(Bytes, AfterPattern,
        [{capture, none}, unicode]) =:= match,
    RawPattern = iolist_to_binary([
        <<"erlang:error\\(\\{">>, FixedCategory,
        <<"\\s*,[\\s\\S]{0,160}?\\}\\)">>]),
    RawFailure = re:run(Bytes, RawPattern,
        [{capture, none}, unicode]) =:= match,
    HasAfterCleanup andalso not RawFailure.

source_bytes(Sources, Path) ->
    case lists:keyfind(Path, 1, Sources) of
        {_, Bytes} -> Bytes;
        false -> <<>>
    end.

source_line(<<>>, _Needle) -> 1;
source_line(Bytes, Needle) ->
    case binary:match(Bytes, Needle) of
        {Start, _} -> line_number(Bytes, Start);
        nomatch -> 1
    end.

bounded_region(Bytes, StartNeedle, EndNeedle, Limit) ->
    case binary:match(Bytes, StartNeedle) of
        nomatch -> <<>>;
        {Start, _} ->
            Available = erlang:min(Limit, byte_size(Bytes) - Start),
            Tail = binary:part(Bytes, Start, Available),
            case binary:match(Tail, EndNeedle) of
                nomatch -> Tail;
                {End, _} -> binary:part(Tail, 0, End)
            end
    end.

ordered_fragments(_Bytes, []) -> true;
ordered_fragments(Bytes, [Fragment | Rest]) ->
    case binary:match(Bytes, Fragment) of
        nomatch -> false;
        {Start, Length} ->
            Next = Start + Length,
            ordered_fragments(
                binary:part(Bytes, Next, byte_size(Bytes) - Next), Rest)
    end.

contract(Sources, Id, Path, Required) ->
    case lists:keyfind(Path, 1, Sources) of
        false -> #{id => Id, path => list_to_binary(Path), line => 1,
                   passed => false, checks => length(Required), completed => 0,
                   failed_check_indices => lists:seq(1, length(Required))};
        {_, Bytes} ->
            Checks = [binary:match(Bytes, Fragment) =/= nomatch
                      || Fragment <- Required],
            contract_check_result(Id, Path, Bytes, <<>>, Checks)
    end.

contract_check_result(Id, Path, Bytes, Needle, Checks) ->
    Completed = length([ok || true <- Checks]),
    Failed = [Index || {Check, Index} <-
        lists:zip(Checks, lists:seq(1, length(Checks))), Check =/= true],
    #{id => Id, path => list_to_binary(Path),
      line => case Needle of <<>> -> 1; _ -> source_line(Bytes, Needle) end,
      passed => Checks =/= [] andalso Completed =:= length(Checks),
      checks => length(Checks), completed => Completed,
      failed_check_indices => Failed}.

%% Shareable artifact enforcement ------------------------------------------

authoritative_paths() ->
    ["coverage-evidence.json",
     "build/coverage/changed.json", "build/coverage/full.json",
     "build/campaign/property.json", "build/campaign/fuzz.json",
     "build/http-model/result.json",
     "build/campaign/aggregates/property.json",
     "build/campaign/aggregates/fuzz.json",
     "build/campaign/aggregates/model.json",
     "build/fault/hostile-peer.json", "build/fault/stability.json",
     "build/credential-matrix/report.json", "build/runtime-matrix/report.json",
     "build/requirements/report.json", "build/qlog/report.json",
     "build/structured-fields-oracle/report.json",
     "build/qpack-differential/report.json", "build/examples/report.json",
     "build/release-sim/report.json", "build/interop/report.json",
     "build/performance/report.json",
     "build/performance/hot-path-profile.json",
     "build/performance/current/idle-wakeup.json",
     "build/performance/current/protocols.json",
     "build/performance/current/idle-wakeup-execution.json",
     "build/performance/current/idle-wakeup.raw.json",
     "build/audit-bundle/manifest.json", "build/audit-bundle/archive.json",
     "build/release-candidate/report.json"].

excluded_diagnostic_inventory() ->
    Paths = lists:sort(filelib:wildcard(
        "build/rfc6455-evidence/*.tail.log")),
    ensure(length(Paths) =< 512, too_many_excluded_diagnostic_inputs),
    Sizes = [begin
        Size = filelib:file_size(Path),
        ensure(is_integer(Size) andalso Size >= 0 andalso Size =< ?MAX_ARTIFACT_BYTES,
               excluded_diagnostic_input_too_large),
        Size
    end || Path <- Paths],
    #{classification => <<"raw_diagnostic_non_authoritative">>,
      collection_policy => <<"excluded_from_shareable_evidence">>,
      files => length(Paths), bytes => lists:sum(Sizes), contents_read => false}.

bounded_authoritative_artifacts() ->
    Paths = [Path || Path <- authoritative_paths(), filelib:is_regular(Path)],
    ensure(length(Paths) =< ?MAX_ARTIFACTS, too_many_authoritative_artifacts),
    {Artifacts, _Total} = lists:mapfoldl(fun(Path, Count) ->
        Bytes = bounded_read(Path, ?MAX_ARTIFACT_BYTES),
        Next = Count + byte_size(Bytes),
        ensure(Next =< ?MAX_ARTIFACT_TOTAL_BYTES,
               authoritative_artifacts_too_large),
        {{Path, Bytes}, Next}
    end, 0, Paths),
    lists:keysort(1, Artifacts).

artifact_identity(Artifacts) ->
    Digest = lists:foldl(fun({Path, Bytes}, Context0) ->
        PathBytes = unicode:characters_to_binary(Path),
        Context1 = crypto:hash_update(Context0,
            <<(byte_size(PathBytes)):64/unsigned-big, PathBytes/binary,
              (byte_size(Bytes)):64/unsigned-big>>),
        crypto:hash_update(Context1, Bytes)
    end, crypto:hash_init(sha256), Artifacts),
    #{files => length(Artifacts),
      bytes => lists:sum([byte_size(Bytes) || {_, Bytes} <- Artifacts]),
      sha256 => hex(crypto:hash_final(Digest))}.

crash_dump_snapshot(Root) ->
    AbsoluteRoot = filename:absname(Root),
    Deadline = erlang:monotonic_time(millisecond) +
               ?CRASH_SCAN_MILLISECONDS,
    Initial = #{root => AbsoluteRoot, deadline => Deadline,
        rows => [], directories => 0, entries => 0, complete => true,
        incomplete_reason => none, pruned => #{}},
    RootDump = filename:join(AbsoluteRoot, "erl_crash.dump"),
    WithRoot = inspect_crash_file(RootDump, Initial),
    Queue = [filename:join(AbsoluteRoot, Name)
             || Name <- ["packages", "build"]],
    Final = crash_walk(Queue, WithRoot),
    Rows = lists:usort(maps:get(rows, Final)),
    ensure(length(Rows) =< 32, too_many_crash_dump_residues),
    #{rows => Rows, complete => maps:get(complete, Final),
      incomplete_reason => maps:get(incomplete_reason, Final),
      scanned_directories => maps:get(directories, Final),
      scanned_entries => maps:get(entries, Final),
      pruned => maps:get(pruned, Final)}.

crash_walk([], State) -> State;
crash_walk(_Queue, #{complete := false} = State) -> State;
crash_walk(Queue, State) ->
    case erlang:monotonic_time(millisecond) >= maps:get(deadline, State) of
        true -> State#{complete => false, incomplete_reason => deadline};
        false -> crash_walk_before_deadline(Queue, State)
    end.

crash_walk_before_deadline([Directory | Rest], State) ->
    Directories = maps:get(directories, State),
    case Directories >= ?MAX_CRASH_SCAN_DIRECTORIES of
        true -> State#{complete => false, incomplete_reason => directory_limit};
        false ->
            case file:read_link_info(Directory) of
                {error, enoent} -> crash_walk(Rest, State);
                {ok, #file_info{type = symlink}} ->
                    crash_walk(Rest, increment_pruned(reparse_point, State));
                {ok, #file_info{type = directory}} ->
                    case file:list_dir(Directory) of
                        {ok, Names0} ->
                            Names = lists:sort(Names0),
                            Count = maps:get(entries, State) + length(Names),
                            case Count > ?MAX_CRASH_SCAN_ENTRIES of
                                true -> State#{complete => false,
                                    incomplete_reason => entry_limit};
                                false ->
                                    Next0 = State#{directories => Directories + 1,
                                                   entries => Count},
                                    case prune_directory_contents(Names) of
                                        none ->
                                            {Children, Next} = crash_entries(
                                                Directory, Names, [], Next0),
                                            crash_walk(Rest ++ lists:reverse(Children), Next);
                                        Category ->
                                            Next = inspect_direct_crash_entry(
                                                Directory, Names,
                                                increment_pruned(Category, Next0)),
                                            crash_walk(Rest, Next)
                                    end
                            end;
                        {error, _} -> State#{complete => false,
                            incomplete_reason => directory_unreadable}
                    end;
                {ok, _} -> crash_walk(Rest, State);
                {error, _} -> State#{complete => false,
                    incomplete_reason => metadata_unreadable}
            end
    end.

prune_directory_contents(Names) ->
    case lists:member(".git", Names) of
        true -> worktree_snapshot;
        false ->
            Required = ["gleam.toml", "packages", "scripts", "src"],
            case lists:all(fun(Name) -> lists:member(Name, Names) end,
                           Required) of
                true -> source_snapshot;
                false -> none
            end
    end.

inspect_direct_crash_entry(Directory, Names, State) ->
    case lists:member("erl_crash.dump", Names) of
        true -> inspect_crash_file(filename:join(Directory, "erl_crash.dump"),
                                   State);
        false -> State
    end.

crash_entries(_Directory, [], Children, State) -> {Children, State};
crash_entries(Directory, [Name | Rest], Children, State0) ->
    Path = filename:join(Directory, Name),
    case prune_directory(Name) of
        none ->
            case file:read_link_info(Path) of
                {ok, #file_info{type = directory}} ->
                    case crash_descend_policy(Path, State0) of
                        descend ->
                            crash_entries(Directory, Rest,
                                          [Path | Children], State0);
                        Category ->
                            crash_entries(Directory, Rest, Children,
                                increment_pruned(Category, State0))
                    end;
                {ok, #file_info{type = regular}} when Name =:= "erl_crash.dump" ->
                    crash_entries(Directory, Rest, Children,
                                  inspect_crash_file(Path, State0));
                {ok, #file_info{type = symlink}} ->
                    crash_entries(Directory, Rest, Children,
                                  increment_pruned(reparse_point, State0));
                {ok, _} -> crash_entries(Directory, Rest, Children, State0);
                {error, _} -> {Children, State0#{complete => false,
                    incomplete_reason => metadata_unreadable}}
            end;
        Category ->
            crash_entries(Directory, Rest, Children,
                          increment_pruned(Category, State0))
    end.

crash_descend_policy(Path, State) ->
    Components = filename:split(relative_to_root(Path, maps:get(root, State))),
    case Components of
        ["packages" | _] -> descend;
        ["build", "process-runner" | _] -> descend;
        ["build", "diagnostics", "process-runner" | _] -> descend;
        ["build" | _] when length(Components) =< 3 -> descend;
        ["build" | _] -> generated_depth_limit;
        _ -> generated_depth_limit
    end.

prune_directory(".git") -> version_control_cache;
prune_directory("_build") -> beam_build_cache;
prune_directory("dev") -> beam_build_cache;
prune_directory("prod") -> beam_build_cache;
prune_directory("deps") -> dependency_cache;
prune_directory("node_modules") -> dependency_cache;
prune_directory("vendor") -> dependency_cache;
prune_directory(".gomodcache") -> go_module_cache;
prune_directory("go-module-cache") -> go_module_cache;
prune_directory("toolchains") -> toolchain_cache;
prune_directory("interop-tools") -> toolchain_cache;
prune_directory("bundle-tools") -> toolchain_cache;
prune_directory("venv") -> python_environment;
prune_directory(".venv") -> python_environment;
prune_directory("interop-venv") -> python_environment;
prune_directory("__pycache__") -> python_cache;
prune_directory("corpus") -> raw_corpus_cache;
prune_directory("corpora") -> raw_corpus_cache;
prune_directory("fuzz-corpus") -> raw_corpus_cache;
prune_directory("failure-secrecy") -> audit_internal_cache;
prune_directory(_) -> none.

increment_pruned(Category, State) ->
    Counts = maps:get(pruned, State),
    State#{pruned => Counts#{Category => maps:get(Category, Counts, 0) + 1}}.

inspect_crash_file(Path, State) ->
    case file:read_link_info(Path) of
        {error, enoent} -> State;
        {ok, #file_info{type = regular, size = Size, mtime = Modified}}
          when is_integer(Size), Size >= 0 ->
            Root = maps:get(root, State),
            Relative = relative_to_root(Path, Root),
            State#{rows => [{Relative, Size, Modified} | maps:get(rows, State)]};
        {ok, #file_info{type = symlink}} ->
            increment_pruned(reparse_point, State);
        {ok, _} -> State;
        {error, _} -> State#{complete => false,
            incomplete_reason => metadata_unreadable}
    end.

relative_to_root(Path0, Root0) ->
    Path = normal_path(filename:absname(Path0)),
    Root = normal_path(filename:absname(Root0)),
    Prefix = Root ++ "/",
    case lists:prefix(Prefix, Path) of
        true -> lists:nthtail(length(Prefix), Path);
        false -> "outside_workspace"
    end.

crash_residue_identity(Snapshot) ->
    Rows = maps:get(rows, Snapshot),
    %% Paths participate only in the internal before/after equality check.
    %% Shareable identity hashes finite metadata, never a rejected path.
    Metadata = lists:sort([{Size, Modified}
                           || {_Path, Size, Modified} <- Rows]),
    Bytes = term_to_binary(Metadata, [deterministic]),
    #{files => length(Rows),
      total_bytes => lists:sum([Size || {_Path, Size, _Modified} <- Rows]),
      metadata_sha256 => hex(crypto:hash(sha256, Bytes)),
      contents_read => false,
      scan_complete => maps:get(complete, Snapshot),
      incomplete_reason => maps:get(incomplete_reason, Snapshot),
      scanned_directories => maps:get(scanned_directories, Snapshot),
      scanned_entries => maps:get(scanned_entries, Snapshot),
      pruned => maps:get(pruned, Snapshot),
      limits => #{milliseconds => ?CRASH_SCAN_MILLISECONDS,
                  directories => ?MAX_CRASH_SCAN_DIRECTORIES,
                  entries => ?MAX_CRASH_SCAN_ENTRIES}}.

crash_residue_sets_equal(Before, After) ->
    maps:get(rows, Before) =:= maps:get(rows, After) andalso
    maps:get(complete, Before) =:= maps:get(complete, After) andalso
    maps:get(incomplete_reason, Before) =:= maps:get(incomplete_reason, After).

artifact_findings(Artifacts) ->
    lists:append([artifact_path_findings(Path, Bytes)
                  || {Path, Bytes} <- Artifacts]).

artifact_path_findings(Path, Bytes) ->
    Categories = case decode_unique(Bytes) of
        {ok, Value} -> scan_json_value(Value);
        {error, duplicate_key} -> [<<"duplicate_json_key">>];
        {error, _} -> [<<"invalid_json">>]
    end,
    [#{rule => Category, path => list_to_binary(normal_path(Path))}
     || Category <- lists:usort(Categories)].

decode_unique(Bytes) ->
    Decoders = #{object_start => fun(_Old) -> #{} end,
      object_push => fun(Key, Value, Object) ->
          case maps:is_key(Key, Object) of
              true -> throw(failure_secrecy_duplicate_key);
              false -> maps:put(Key, Value, Object)
          end
      end,
      object_finish => fun(Object, Old) -> {Object, Old} end},
    try json:decode(Bytes, ok, Decoders) of
        {Value, ok, Rest} ->
            case only_json_whitespace(Rest) of
                true -> {ok, Value};
                false -> {error, trailing_bytes}
            end;
        _ -> {error, invalid_json}
    catch
        throw:failure_secrecy_duplicate_key -> {error, duplicate_key};
        _:_ -> {error, invalid_json}
    end.

only_json_whitespace(Bytes) ->
    re:run(Bytes, <<"^[\\x20\\x09\\x0a\\x0d]*$">>,
           [{capture, none}]) =:= match.

scan_json_value(Value) ->
    try
        {_Count, Categories} = scan_value(Value, 0, 0, [], []),
        lists:usort(Categories)
    catch
        throw:json_depth_limit -> [<<"json_depth_limit">>];
        throw:json_node_limit -> [<<"json_node_limit">>]
    end.

scan_value(_Value, Depth, _Count, _Acc, _Context)
  when Depth > ?MAX_JSON_DEPTH ->
    throw(json_depth_limit);
scan_value(_Value, _Depth, Count, _Acc, _Context)
  when Count >= ?MAX_JSON_NODES ->
    throw(json_node_limit);
scan_value(Value, Depth, Count, Acc, Context) when is_map(Value) ->
    lists:foldl(fun({Key, Child}, {N0, A0}) ->
        Normal = normalized_key_any(Key),
        KeyCategories = key_categories(Key, Child, Context, Value),
        scan_value(Child, Depth + 1, N0 + 1, KeyCategories ++ A0,
                   [Normal | Context])
    end, {Count + 1, Acc}, lists:keysort(1, maps:to_list(Value)));
scan_value(Value, Depth, Count, Acc, Context) when is_list(Value) ->
    lists:foldl(fun(Child, {N0, A0}) ->
        scan_value(Child, Depth + 1, N0 + 1, A0, Context)
    end, {Count + 1, Acc}, Value);
scan_value(Value, _Depth, Count, Acc, _Context) when is_binary(Value) ->
    SizeCategories = case byte_size(Value) > ?MAX_JSON_STRING_BYTES of
        true -> [<<"json_string_limit">>];
        false -> []
    end,
    {Count + 1, sensitive_string_categories(Value) ++ SizeCategories ++ Acc};
scan_value(_Value, _Depth, Count, Acc, _Context) -> {Count + 1, Acc}.

key_categories(Key, Value, Context, Parent) when is_binary(Key) ->
    Normal = normalized_key(Key),
    Forbidden = case key_policy(Normal, Value) of
        ok -> [];
        Category -> [Category]
    end,
    Special = case Normal of
        <<"exception_reason">> -> typed_reason_categories(Value);
        <<"reason">> -> case is_failure_context(Context, Parent) of
            true -> typed_reason_categories(Value);
            false -> []
        end;
        <<"stacktrace">> -> stacktrace_categories(Value);
        _ -> []
    end,
    Forbidden ++ Special;
key_categories(Key, Value, Context, Parent) when is_atom(Key) ->
    key_categories(atom_to_binary(Key), Value, Context, Parent);
key_categories(_Key, _Value, _Context, _Parent) ->
    [<<"non_string_json_key">>].

normalized_key_any(Key) when is_binary(Key) -> normalized_key(Key);
normalized_key_any(Key) when is_atom(Key) -> normalized_key(atom_to_binary(Key));
normalized_key_any(_) -> <<"unknown">>.

normalized_key(Key) ->
    Lower = string:lowercase(Key),
    binary:replace(binary:replace(Lower, <<"-">>, <<"_">>, [global]),
                   <<" ">>, <<"_">>, [global]).

is_failure_context(Context, Parent) ->
    ContextFailure = lists:any(fun(Key) ->
        binary:match(Key, <<"failure">>) =/= nomatch orelse
        binary:match(Key, <<"exception">>) =/= nomatch orelse
        binary:match(Key, <<"runner_error">>) =/= nomatch
    end, Context),
    ParentKeys = [normalized_key_any(Key) || Key <- maps:keys(Parent)],
    ContextFailure orelse lists:member(<<"exception_class">>, ParentKeys)
                   orelse lists:member(<<"stacktrace">>, ParentKeys).

key_policy(<<"authorization">>, _) -> <<"authorization_field">>;
key_policy(<<"proxy_authorization">>, _) -> <<"authorization_field">>;
key_policy(<<"cookie">>, _) -> <<"cookie_field">>;
key_policy(<<"set_cookie">>, _) -> <<"cookie_field">>;
key_policy(<<"body">>, Value) -> raw_or_metric(<<"body_field">>, Value);
key_policy(<<"request_body">>, Value) -> raw_or_metric(<<"body_field">>, Value);
key_policy(<<"response_body">>, Value) -> raw_or_metric(<<"body_field">>, Value);
key_policy(<<"payload">>, Value) -> raw_or_metric(<<"payload_field">>, Value);
key_policy(<<"raw_payload">>, _) -> <<"payload_field">>;
key_policy(<<"raw_body">>, _) -> <<"body_field">>;
key_policy(<<"socket">>, _) -> <<"runtime_handle_field">>;
key_policy(<<"socket_handle">>, _) -> <<"runtime_handle_field">>;
key_policy(<<"pid">>, _) -> <<"runtime_handle_field">>;
key_policy(<<"os_pid">>, _) -> <<"runtime_handle_field">>;
key_policy(<<"reference">>, _) -> <<"runtime_handle_field">>;
key_policy(<<"process_reference">>, _) -> <<"runtime_handle_field">>;
key_policy(<<"endpoint">>, _) -> <<"destination_field">>;
key_policy(<<"destination">>, _) -> <<"destination_field">>;
key_policy(<<"authority">>, _) -> <<"destination_field">>;
key_policy(<<"output_tail">>, _) -> <<"raw_output_field">>;
key_policy(<<"tail">>, _) -> <<"raw_output_field">>;
key_policy(<<"stdout">>, _) -> <<"raw_output_field">>;
key_policy(<<"stderr">>, _) -> <<"raw_output_field">>;
key_policy(<<"raw_output">>, _) -> <<"raw_output_field">>;
key_policy(<<"stack_args">>, _) -> <<"raw_stack_field">>;
key_policy(<<"exception_args">>, _) -> <<"raw_stack_field">>;
key_policy(_, _) -> ok.

raw_or_metric(_Category, Value) when is_integer(Value); is_float(Value);
                                           is_boolean(Value); Value =:= null -> ok;
raw_or_metric(Category, _) -> Category.

typed_reason_categories(Value) when is_binary(Value) ->
    case byte_size(Value) =< 96 andalso
         re:run(Value, <<"^[a-z][a-z0-9_-]*$">>,
                [{capture, none}, unicode]) =:= match of
        true -> [];
        false -> [<<"raw_exception_reason">>]
    end;
typed_reason_categories(_) -> [<<"raw_exception_reason">>].

stacktrace_categories(Value) when is_binary(Value) ->
    case decode_unique(Value) of
        {ok, Stack} -> stacktrace_categories(Stack);
        _ -> [<<"raw_stack_field">>]
    end;
stacktrace_categories(Value) when is_list(Value), length(Value) =< 16 ->
    case lists:all(fun valid_stack_frame/1, Value) of
        true -> [];
        false -> [<<"raw_stack_field">>]
    end;
stacktrace_categories(_) -> [<<"raw_stack_field">>].

valid_stack_frame(Frame) when is_map(Frame) ->
    Allowed = [<<"module">>, <<"function">>, <<"arity">>, <<"line">>],
    lists:sort(maps:keys(Frame)) =:= lists:sort(Allowed) andalso
    valid_identifier(maps:get(<<"module">>, Frame)) andalso
    valid_identifier(maps:get(<<"function">>, Frame)) andalso
    is_integer(maps:get(<<"arity">>, Frame)) andalso
    maps:get(<<"arity">>, Frame) >= 0 andalso maps:get(<<"arity">>, Frame) =< 255 andalso
    is_integer(maps:get(<<"line">>, Frame)) andalso maps:get(<<"line">>, Frame) >= 0;
valid_stack_frame(_) -> false.

valid_identifier(Value) when is_binary(Value), byte_size(Value) =< 128 ->
    re:run(Value, <<"^[a-zA-Z0-9_@]+$">>, [{capture, none}]) =:= match;
valid_identifier(_) -> false.

sensitive_string_categories(Value) ->
    Checks =
      [{<<"authorization_value">>,
        <<"(?i)(?:authorization|proxy-authorization)\\s*:">>},
       {<<"cookie_value">>, <<"(?i)(?:set-cookie|cookie)\\s*:">>},
       {<<"credential_value">>,
        <<"(?i)\\b(?:bearer|basic)\\s+[A-Za-z0-9._~+/=-]{4,}">>},
       {<<"private_key_value">>,
        <<"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----">>},
       {<<"runtime_handle_value">>,
        <<"(?:#[Pp][Ii][Dd]<|#[Pp]ort<|#[Rr]ef<|<[0-9]+\\.[0-9]+\\.[0-9]+>)">>},
       {<<"user_home_path">>,
         <<"(?i)(?:[A-Z]:[\\\\/]Users[\\\\/][^\\s]+|/home/[^/\\s]+|/Users/[^/\\s]+)">>},
       {<<"otp_error_report">>, <<"=ERROR REPORT====">>},
       {<<"raw_exception_report">>,
        <<"(?i)(?:\\*\\* exception (?:error|exit|throw)|"
          "exception (?:error|exit|throw):)">>},
       {<<"url_userinfo">>, <<"://[^/\\s:@]+:[^/@\\s]+@">>},
       {<<"private_control_marker">>, private_marker()}],
    Matched = [Category || {Category, Pattern} <- Checks,
                           re:run(Value, Pattern,
                                  [{capture, none}, unicode]) =:= match],
    case binary:match(Value, <<0>>) of
        nomatch -> Matched;
        _ -> [<<"nul_in_retained_string">> | Matched]
    end.

private_marker() ->
    <<"failure-secrecy-", "private-marker-", "74e2">>.

%% Adversarial controls -----------------------------------------------------

self_test() ->
    Safe = safe_artifact(),
    [] = scan_json_value(Safe),
    [] = scan_json_value(#{requirement =>
        #{reason => <<"Public interoperability rationale may contain spaces.">>}}),
    {ok, _} = decode_unique(iolist_to_binary(json:encode(Safe))),
    Mutants = artifact_mutants(),
    lists:foreach(fun({Id, Value}) ->
        Categories = scan_json_value(Value),
        ensure(Categories =/= [], {undetected_artifact_mutant, Id})
    end, Mutants),
    Duplicate = <<"{\"schema\":1,\"schema\":2}">>,
    ensure(decode_unique(Duplicate) =:= {error, duplicate_key},
           duplicate_json_key_accepted),
    ensure(decode_unique(<<"{\"schema\":1} trailing">>) =:=
           {error, trailing_bytes}, trailing_json_accepted),
    OldBarrier = <<"catch Class:Reason:Stacktrace ->\n"
                   "io:format(standard_error, \"failed ~p:~p ~p\", "
                   "[Class, Reason, Stacktrace])\nend.">>,
    OldTrace = <<"catch Class:Reason:Stacktrace ->\n"
                 "io:format(standard_error, \"trace failed ~p:~p~n~p\", "
                 "[Class, Reason, Stacktrace])\nend.">>,
    SafeCatch = <<"catch Class:Reason:Stack ->\n"
                  "io:format(standard_error, \"failed ~s\", "
                  "[json:encode(diagnostic_failure_details(Class, Reason, Stack))])\n"
                  "end.">>,
    LateProjectionBypass = <<"catch Class:Reason:Stack ->\n"
        "io:format(standard_error, \"failed ~p\", [Reason]),\n"
        "_ = diagnostic_failure_details(Class, Reason, Stack)\nend.">>,
    SameReporterBypass = <<"catch Class:Reason:Stack ->\n"
        "io:format(standard_error, \"failed ~p ~p\", "
        "[Reason, diagnostic_failure_details(Class, Reason, Stack)])\nend.">>,
    PutCharsReason = <<"catch Class:Reason:Stack ->\n"
        "io:put_chars(standard_error, Reason)\nend.">>,
    FixedCountThenRaise = <<"catch Class:Reason:Stack ->\n"
        "io:format(standard_error, \"retained ~B files\", [length(Files)]),\n"
        "erlang:raise(Class, Reason, Stack)\nend.">>,
    ensure(unsafe_reporter_rows("mutant.erl", OldBarrier) =/= [],
           old_barrier_reporter_accepted),
    ensure(unsafe_reporter_rows("mutant.erl", OldTrace) =/= [],
           old_trace_reporter_accepted),
    ensure(unsafe_reporter_rows("mutant.erl", LateProjectionBypass) =/= [],
           late_projection_bypass_accepted),
    ensure(unsafe_reporter_rows("mutant.erl", SameReporterBypass) =/= [],
           same_reporter_projection_bypass_accepted),
    ensure(unsafe_reporter_rows("mutant.erl", PutCharsReason) =/= [],
           put_chars_reason_accepted),
    ensure(unsafe_reporter_rows("safe.erl", SafeCatch) =:= [],
           typed_reporter_rejected),
    ensure(unsafe_reporter_rows("safe.erl", FixedCountThenRaise) =:= [],
           fixed_scalar_reporter_rejected),
    WorkflowSources = [{".github/workflows/mutant.yml",
                        <<"steps:\n  - run: gleam test\n">>}],
    ensure(workflow_findings(WorkflowSources) =/= [],
           direct_ci_test_accepted),
    OutsideCatch = <<"report(Result) -> io:format(\"~p\", [Result]).">>,
    ensure(raw_reporter_candidates("outside.erl", OutsideCatch) =/= [],
           outside_catch_reporter_not_classified),
    WindowsProcessControls = windows_process_isolation_controls(),
    TerminalControlControls = command_terminal_control_controls(),
    RunnerContractControls = runner_contract_controls(),
    PackageProcessControls = package_process_controls(),
    failure_code_controls(),
    port_runner_controls(),
    ephemeral_artifact_control(),
    crash_dump_controls(),
    source_set_controls(),
    immutable_publication_control(),
    runtime_report_path_control(),
    ReportMutation = Safe#{payload => private_marker()},
    ensure(scan_json_value(ReportMutation) =/= [], unsafe_report_mutation_accepted),
    Controls = length(Mutants) + 74 + WindowsProcessControls
        + TerminalControlControls + RunnerContractControls
        + PackageProcessControls,
    io:format("failure_secrecy_self_test controls=~B passed=true retained_private_values=0~n",
              [Controls]),
    ok.

safe_artifact() ->
    Stack = [#{<<"module">> => <<"qualification_eunit_listener">>,
               <<"function">> => <<"handle_end">>,
               <<"arity">> => 3, <<"line">> => 73}],
    #{schema => 1, status => <<"Ready">>, completed => 12,
      failure => #{exception_class => <<"error">>,
                   exception_reason => <<"validation_failed">>,
                   stacktrace => iolist_to_binary(json:encode(Stack))},
      process => #{output_bytes => 0, output_limit_bytes => 8388608,
                   output_limit_exceeded => false, child_exit_observed => true},
      peer => #{tool => <<"nghttp2">>, role => <<"client">>},
      rerun_command => <<"escript scripts/failure_secrecy_audit.escript audit">>}.

artifact_mutants() ->
    Marker = private_marker(),
    [{authorization_header,
      #{note => <<"Authorization: Bearer ", Marker/binary>>}},
     {cookie_header, #{note => <<"Cookie: sid=", Marker/binary>>}},
     {credential, #{note => <<"Bearer ", Marker/binary>>}},
     {private_key, #{note => <<"-----BEGIN PRIVATE KEY-----\n", Marker/binary>>}},
     {pid_value, #{note => <<"<0.144.0>">>}},
     {port_value, #{note => <<"#Port<0.17>">>}},
     {reference_value, #{note => <<"#Ref<0.1.2.3>">>}},
      {windows_home, #{path => <<"C:\\Users\\private-user\\trace.log">>}},
      {windows_home_slash, #{path => <<"C:/Users/private-user/trace.log">>}},
      {unix_home, #{path => <<"/home/private-user/trace.log">>}},
      {otp_error_report, #{note => <<"=ERROR REPORT==== fixed">>}},
      {raw_exception_report, #{note => <<"** exception error: fixed">>}},
     {url_userinfo, #{peer => <<"https://private-user:private-pass@example.test/">>}},
     {nul_cookie_key, #{key => <<"example.test", 0, "/", 0, "session">>}},
     {body_field, #{body => <<"private bytes">>}},
     {payload_field, #{payload => <<"private bytes">>}},
     {socket_field, #{socket => 19}},
     {pid_field, #{os_pid => 1234}},
     {endpoint_field, #{endpoint => <<"198.51.100.7:443">>}},
     {tail_field, #{tail => Marker}},
     {raw_reason, #{failure =>
         #{reason => <<"{badmatch, private-value}">>}}},
     {stack_args, #{stacktrace => [#{<<"module">> => <<"m">>,
         <<"function">> => <<"f">>, <<"arity">> => 1, <<"line">> => 1,
         <<"args">> => [Marker]}]}},
     {long_string, #{note => binary:copy(<<"x">>, ?MAX_JSON_STRING_BYTES + 1)}},
      {nested_marker, #{source_sha256 => Marker}}].

ephemeral_artifact_control() ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
    Directory = filename:join(["build", "failure-secrecy",
                               "self-test-" ++ binary_to_list(Nonce)]),
    Path = filename:join(Directory, "private.json"),
    ok = filelib:ensure_dir(Path),
    try
        Bytes = iolist_to_binary(json:encode(#{note => private_marker()})),
        ok = file:write_file(Path, Bytes, [exclusive]),
        Read = bounded_read(Path, 4096),
        {ok, Value} = decode_unique(Read),
        ensure(scan_json_value(Value) =/= [], ephemeral_marker_not_detected)
    after
        _ = file:delete(Path),
        _ = file:del_dir(Directory)
    end,
    ensure(not filelib:is_regular(Path), ephemeral_marker_retained).

crash_dump_controls() ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
    Directory = filename:join(["build", "failure-secrecy",
                               "crash-self-test-" ++ binary_to_list(Nonce)]),
    Paths = [filename:join(Directory, "erl_crash.dump"),
             filename:join([Directory, "packages", "http3", "erl_crash.dump"]),
             filename:join([Directory, "packages", "quic_core", "nested",
                            "erl_crash.dump"]),
             filename:join([Directory, "build", "process-runner", "run",
                            "erl_crash.dump"]),
             filename:join([Directory, "build", "diagnostics", "run",
                            "erl_crash.dump"])],
    CacheRoot = filename:join([Directory, "build", "diagnostics",
                               "go-module-cache"]),
    try
        lists:foreach(fun(Path) ->
            ok = filelib:ensure_dir(Path),
            ok = file:write_file(Path, <<"synthetic crash residue">>, [exclusive])
        end, Paths),
        lists:foreach(fun(Index) ->
            CachePath = filename:join([CacheRoot, integer_to_list(Index),
                                       "nested", "erl_crash.dump"]),
            ok = filelib:ensure_dir(CachePath),
            ok = file:write_file(CachePath, <<"pruned private cache">>, [exclusive])
        end, lists:seq(1, 64)),
        Started = erlang:monotonic_time(millisecond),
        Snapshot = crash_dump_snapshot(Directory),
        Elapsed = erlang:monotonic_time(millisecond) - Started,
        5 = length(maps:get(rows, Snapshot)),
        true = maps:get(complete, Snapshot),
        true = Elapsed < ?CRASH_SCAN_MILLISECONDS,
        true = maps:get(go_module_cache, maps:get(pruned, Snapshot), 0) >= 1,
        Identity = crash_residue_identity(Snapshot),
        ensure(maps:get(contents_read, Identity) =:= false,
               crash_dump_contents_read),
        ensure(not maps:is_key(paths, Identity), crash_dump_paths_retained)
    after
        safe_remove_crash_fixture(Directory)
    end,
    WorkspaceSnapshot = crash_dump_snapshot("."),
    ensure(maps:get(complete, WorkspaceSnapshot),
           workspace_crash_scan_incomplete),
    Unsafe = [{"scripts/process_runner.hrl",
        <<"{env,[{\"ERL_CRASH_DUMP_BYTES\",\"0\"},"
          "{\"ERL_CRASH_DUMP_SECONDS\",\"0\"}]}.">>}],
    ensure(not maps:get(passed, crash_dump_contract(Unsafe)),
           unisolated_crash_dump_runner_accepted),
    Safe = [{"scripts/process_runner.hrl",
        <<"run_child_boot() ->\n"
          "CrashDumpPath = filename:join(\"build/process-runner\", "
          "\"erl-\" ++ binary_to_list(binary:encode_hex("
          "crypto:strong_rand_bytes(16))) ++ \"-erl_crash.dump\"),\n"
          "CrashDumpDirectory=filename:dirname(CrashDumpPath),CleanupKey=make_ref(),"
          "try open_port(x, [{env,[{\"ERL_CRASH_DUMP_BYTES\", \"0\"},"
          "{\"ERL_CRASH_DUMP_SECONDS\", \"0\"},"
          "{\"ERL_CRASH_DUMP\", CrashDumpPath}]}])\n"
          "after cleanup_child_artifacts(CrashDumpPath, CrashDumpDirectory,"
          "erase(CleanupKey)) end.\n"
          "cleanup_child_artifacts(_CrashDumpPath,_CrashDumpDirectory,running)->ok;\n"
          "cleanup_child_artifacts(CrashDumpPath, CrashDumpDirectory, State)"
          " when State=:=confirmed -> case file:delete(CrashDumpPath) of "
          "ok->ok;{error,enoent}->ok;_->erlang:error("
          "cannot_remove_child_crash_dump) end.">>}],
    ensure(maps:get(passed, crash_dump_contract(Safe)),
           isolated_crash_dump_runner_rejected),
    RawCleanup = [{"scripts/process_runner.hrl",
        <<"CrashDumpPath = filename:join(\"build/process-runner\", "
          "binary_to_list(crypto:strong_rand_bytes(16)) ++ \"erl_crash.dump\"),"
          "{\"ERL_CRASH_DUMP_BYTES\", \"0\"},"
          "{\"ERL_CRASH_DUMP_SECONDS\", \"0\"},"
          "{\"ERL_CRASH_DUMP\", CrashDumpPath},try ok after "
          "case file:delete(CrashDumpPath) of {error,Reason}->"
          "erlang:error({cannot_remove_child_crash_dump,Reason}) end end.">>}],
    ensure(not maps:get(passed, crash_dump_contract(RawCleanup)),
           raw_crash_cleanup_reason_accepted).

safe_remove_crash_fixture(Directory) ->
    Absolute = normal_path(filename:absname(Directory)),
    Root = normal_path(filename:absname(
        filename:join(["build", "failure-secrecy", "crash-self-test-"]))),
    ensure(lists:prefix(Root, Absolute), invalid_crash_fixture_cleanup_target),
    case file:del_dir_r(Directory) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_remove_crash_fixture)
    end.

package_process_controls() ->
    Path = "scripts/package_suite.escript",
    Source = bounded_read(Path, ?MAX_SOURCE_FILE_BYTES),
    Current = package_safe_process_contract([{Path, Source}]),
    put(failure_secrecy_control_id, package_process_current_contract),
    put(failure_secrecy_check_index, first_failed_check_index(Current)),
    ensure(maps:get(passed, Current), current_package_process_contract_rejected),
    Mutations = [
        {package_process_tail_key, <<"tail">>},
        {package_process_output_digest_key, <<"output_sha256">>},
        {package_process_unknown_key, <<"unknown_process_key">>}
    ],
    lists:foreach(fun({Id, AddedKey}) ->
        put(failure_secrecy_control_id, Id),
        Before = <<"native_termination_requested].">>,
        After = <<"native_termination_requested, ", AddedKey/binary, "].">>,
        Mutated = binary:replace(Source, Before, After),
        ensure(Mutated =/= Source,
               {windows_process_contract_mutant_not_applied, Id}),
        Result = package_safe_process_contract([{Path, Mutated}]),
        put(failure_secrecy_check_index, first_failed_check_index(Result)),
        ensure(not maps:get(passed, Result),
               {windows_process_contract_mutant_accepted, Id})
    end, Mutations),
    erase(failure_secrecy_check_index),
    erase(failure_secrecy_control_id),
    1 + length(Mutations).

runner_contract_controls() ->
    RunnerPath = "scripts/process_runner.hrl",
    RunnerSource = bounded_read(RunnerPath, ?MAX_SOURCE_FILE_BYTES),
    CurrentSources = [{RunnerPath, RunnerSource}],
    CurrentContracts = [
        {runner_absolute_current_contract,
         absolute_bounded_hidden_child_contract(CurrentSources)},
        {runner_exit_deadline_current_contract,
         exit_status_deadline_contract(CurrentSources)},
        {runner_unconfirmed_current_contract,
         unconfirmed_child_contract(CurrentSources)}
    ],
    lists:foreach(fun({Id, ContractResult}) ->
        put(failure_secrecy_control_id, Id),
        ControlId = fixed_audit_control_id(Id),
        ensure(ControlId =/= <<"unknown">>, runner_control_id_missing),
        ensure(sensitive_string_categories(ControlId) =:= [],
               unsafe_runner_control_id),
        put(failure_secrecy_check_index,
            first_failed_check_index(ContractResult)),
        ensure(maps:get(passed, ContractResult),
               current_runner_contract_rejected)
    end, CurrentContracts),
    erase(failure_secrecy_check_index),
    RunnerMutations = [
        {runner_absolute_deadline,
         <<"Deadline = erlang:monotonic_time(millisecond) + Milliseconds">>,
         <<"Deadline = erlang:monotonic_time(millisecond) + 0">>},
        {runner_output_limit,
         <<"limit => 8388608">>, <<"limit => 0">>},
        {runner_tail_copy,
         <<"TailSize = erlang:min(Size, 65536)">>,
         <<"TailSize = Size">>},
        {runner_crash_dump_disable,
         <<"{\"ERL_CRASH_DUMP_BYTES\", \"0\"}">>,
         <<"{\"ERL_CRASH_DUMP_BYTES\", \"1\"}">>},
        {runner_hidden_port,
         <<"hide, {packet, 4}">>, <<"show, {packet, 4}">>}
    ],
    lists:foreach(fun({Id, Before, After}) ->
        put(failure_secrecy_control_id, Id),
        ControlId = fixed_audit_control_id(Id),
        ensure(ControlId =/= <<"unknown">>, runner_control_id_missing),
        ensure(sensitive_string_categories(ControlId) =:= [],
               unsafe_runner_control_id),
        Mutated = binary:replace(RunnerSource, Before, After),
        ensure(Mutated =/= RunnerSource,
               {windows_process_contract_mutant_not_applied, Id}),
        MutantResult = absolute_bounded_hidden_child_contract(
            [{RunnerPath, Mutated}]),
        put(failure_secrecy_check_index,
            first_failed_check_index(MutantResult)),
        ensure(not maps:get(passed, MutantResult),
               {windows_process_contract_mutant_accepted, Id})
    end, RunnerMutations),
    erase(failure_secrecy_check_index),
    erase(failure_secrecy_control_id),
    UnsafeExit = <<"collect_before_deadline(Port, Output, Deadline) ->\n"
        "Remaining = Deadline - erlang:monotonic_time(millisecond),\n"
        "receive {Port, {exit_status, Status}} -> "
        "{Status, finish_output(Output, false, true)}\n"
        "after Remaining -> stop_child(Port, Output) end.\nnew_output() -> #{}.\n">>,
    ensure(not exit_status_rechecks_deadline(UnsafeExit),
           late_exit_status_mutant_accepted),
    UnrelatedClock = <<"collect_before_deadline(Port, Output, Deadline) ->\n"
        "_ = erlang:monotonic_time(millisecond) >= Deadline,\n"
        "receive {Port, {exit_status, Status}} -> "
        "{Status, finish_output(Output, false, true)}\n"
        "after Remaining -> stop_child(Port, Output) end.\nnew_output() -> #{}.\n">>,
    ensure(not exit_status_rechecks_deadline(UnrelatedClock),
           unrelated_deadline_check_blessed_exit),
    SafeExit = <<"collect_before_deadline(Port, Output, Deadline) ->\n"
        "Remaining = Deadline - erlang:monotonic_time(millisecond),\n"
        "case Remaining =< 0 of true -> stop_child(Port, Output); false ->\n"
        "receive {Port, {exit_status, Status}} ->\n"
        "DeadlineExpired = erlang:monotonic_time(millisecond) >= Deadline,\n"
        "finish_exit_status(Status, Output, DeadlineExpired)\n"
        "after Remaining -> stop_child(Port, Output) end end.\n"
        "finish_exit_status(_Status, Output, true) ->\n"
        "{124, finish_output(Output, true, true)};\n"
        "finish_exit_status(Status, Output, false) ->\n"
        "{Status, finish_output(Output, Status =:= 124, true)}.\n"
        "process_completion_verified(Output) -> true.\nnew_output() -> #{}.\n">>,
    ensure(exit_status_rechecks_deadline(SafeExit),
           deadline_rechecking_exit_rejected),
    SafeTemp = [{"scripts/process_runner.hrl",
        <<"run_child_evaluation(Directory, Paths, Evaluation, Milliseconds) ->\n"
          "InputPath = filename:join(\"build/process-runner\", "
          "binary_to_list(crypto:strong_rand_bytes(16))),"
          "ok=file:write_file(InputPath, Input, [exclusive]),"
          "try run_child_boot(Directory,Paths,Evaluation,Milliseconds) after "
          "case file:delete(InputPath) of ok->ok;{error,enoent}->ok;"
          "_->erlang:error(cannot_remove_child_evaluation) end end.\n"
          "run_child_boot(Directory, Paths, Evaluation, Milliseconds) -> ok.\n">>}],
    ensure(maps:get(passed, evaluation_temp_contract(SafeTemp)),
           isolated_evaluation_temp_rejected),
    RawTemp = [{"scripts/process_runner.hrl",
        <<"run_child_evaluation(Directory, Paths, Evaluation, Milliseconds) ->\n"
          "InputPath = filename:join(\"build/process-runner\", "
          "binary_to_list(crypto:strong_rand_bytes(16))),"
          "ok=file:write_file(InputPath, Input, [exclusive]),"
          "try run_child_boot(Directory,Paths,Evaluation,Milliseconds) after "
          "case file:delete(InputPath) of {error,Reason}->"
          "erlang:error({cannot_remove_child_evaluation,Reason}) end end.\n"
          "run_child_boot(Directory, Paths, Evaluation, Milliseconds) -> ok.\n">>}],
    ensure(not maps:get(passed, evaluation_temp_contract(RawTemp)),
           raw_evaluation_cleanup_reason_accepted),
    UnsafeCompletion = [{"scripts/process_runner.hrl",
        <<"run()->{Status,Output}=collect_eunit(P,O,D),{Status,Output}.\n">>}],
    ensure(not maps:get(passed,
                        unconfirmed_child_contract(UnsafeCompletion)),
           unconfirmed_completion_mutant_accepted),
    SafeCompletion = [{"scripts/process_runner.hrl",
        <<"run()->{Status,Output}=collect_eunit(P,O,D),"
          "case maps:get(child_exit_observed, Output) of true->{Status,Output};"
          "false -> erlang:error(child_exit_unconfirmed) end,"
          "child_evaluation_external_process_forbidden.\n"
          "cleanup_child_artifacts(_CrashDumpPath, _CrashDumpDirectory, running)"
          " -> ok.\n">>}],
    ensure(maps:get(passed, unconfirmed_child_contract(SafeCompletion)),
           confirmed_completion_contract_rejected),
    PidOnlyTree = [{"scripts/process_runner.hrl",
        <<"owned_child_command(Erl,Arguments)->{Erl,Arguments,pid_only}.\n"
          "register_owned_tree(Port,TreeMode)->ok.\n"
          "stop_child(Port,Output)->kill_owned_child(Port),"
          "await_child_exit(Port,Output,deadline).\n"
          "await_owned_tree_empty(Port)->true.\n"
          "kill_owned_child(Port)->run(\"kill\",[pid(Port)]).\n">>}],
    ensure(not maps:get(passed, owned_process_tree_contract(PidOnlyTree)),
           pid_only_teardown_mutant_accepted),
    TreeSources = [
        {RunnerPath, RunnerSource},
        {"scripts/command_capture.hrl",
         bounded_read("scripts/command_capture.hrl", ?MAX_SOURCE_FILE_BYTES)},
        {"scripts/process_supervisor.py",
         bounded_read("scripts/process_supervisor.py", ?MAX_SOURCE_FILE_BYTES)}
    ],
    TreeContract = owned_process_tree_contract(TreeSources),
    put(failure_secrecy_control_id, owned_tree_current_contract),
    put(failure_secrecy_check_index, first_failed_check_index(TreeContract)),
    ensure(maps:get(passed, TreeContract),
           owned_tree_contract_rejected),
    RecoveryMutations = [
        {registration_failure_immediate_close,
         <<"case recover_owned_supervisor(Port, Identity, Close) of">>,
         <<"safe_close_callback(Close, Port),\n"
           "            case confirmed of">>},
        {uncertain_start_immediate_close,
         <<"true = is_integer(Deadline),\n"
           "    recover_owned_supervisor(Port, Identity, Close).">>,
         <<"true = is_integer(Deadline),\n"
           "    safe_close_callback(Close, Port),\n"
           "    confirmed.">>},
        {owned_recovery_without_join,
         <<"_ = kill_owned_child(Port),\n"
           "        await_child_exit(Port, new_output(Identity), TeardownDeadline)">>,
         <<"_ = kill_owned_child(Port),\n"
           "        {exited, new_output(Identity)}">>},
        {owned_recovery_close_before_join,
         <<"_ = kill_owned_child(Port),\n"
           "        await_child_exit(Port, new_output(Identity), TeardownDeadline)">>,
         <<"_ = kill_owned_child(Port),\n"
           "        safe_close_callback(Close, Port),\n"
           "        await_child_exit(Port, new_output(Identity), TeardownDeadline)">>}
    ],
    lists:foreach(fun({Id, Before, After}) ->
        put(failure_secrecy_control_id, Id),
        Mutated = binary:replace(RunnerSource, Before, After),
        ensure(Mutated =/= RunnerSource,
               {windows_process_contract_mutant_not_applied, Id}),
        MutantSources = lists:keyreplace(
            RunnerPath, 1, TreeSources, {RunnerPath, Mutated}),
        Result = owned_process_tree_contract(MutantSources),
        put(failure_secrecy_check_index, first_failed_check_index(Result)),
        ensure(not maps:get(passed, Result),
               {windows_process_contract_mutant_accepted, Id})
    end, RecoveryMutations),
    erase(failure_secrecy_check_index),
    erase(failure_secrecy_control_id),
    OutputSafe = [
        {"scripts/process_runner.hrl",
         <<"new_output()->#{supervisor_output_limit_seen => false}.\n"
           "packet(Code)->Code =:= <<\"supervisor_output_limit\">> orelse false.\n"
           "finish()->#{output_limit_exceeded => Count > Limit orelse SupervisorLimited,"
           "output_digest_complete => Count =< Limit andalso not SupervisorLimited}.\n">>},
        {"scripts/command_capture.hrl",
         <<"command_exit_outcome(<<\"supervisor_output_limit\">>, _, 125) -> output_limit.\n"
           "proof()->#{output_limit_exceeded => Outcome =:= output_limit,"
           "output_digest_complete => Outcome =/= output_limit}.\n">>}
    ],
    ensure(maps:get(passed, runner_output_limit_contract(OutputSafe)),
           supervisor_output_limit_contract_rejected),
    OutputUnsafe = [{OutputPath, binary:replace(OutputSource,
        <<"Count > Limit orelse SupervisorLimited">>, <<"Count > Limit">>)}
        || {OutputPath, OutputSource} <- OutputSafe],
    ensure(not maps:get(passed, runner_output_limit_contract(OutputUnsafe)),
            supervisor_output_limit_mutant_accepted),
    length(CurrentContracts) + length(RunnerMutations) + 1
        + length(RecoveryMutations).

command_terminal_control_controls() ->
    Path = "scripts/command_capture.hrl",
    Source = bounded_read(Path, ?MAX_SOURCE_FILE_BYTES),
    Sources = [{Path, Source}],
    put(failure_secrecy_control_id, terminal_control_current_contract),
    CurrentContract = command_terminal_control_contract(Sources),
    put(failure_secrecy_check_index,
        first_failed_check_index(CurrentContract)),
    ensure(maps:get(passed, CurrentContract),
           current_terminal_control_contract_rejected),
    erase(failure_secrecy_check_index),
    Mutations = [
        {terminal_control_success_bypass, Path,
         <<"{Semantic, Removed} = command_semantic_output(Raw),\n"
           "                            Sanitized = Attested#{">>,
         <<"{Semantic, Removed} = {Raw, 0},\n"
           "                            Sanitized = Attested#{">>},
        {terminal_control_failure_bypass, Path,
         <<"{Semantic, Removed} = command_semantic_output(Raw),\n"
           "    SafeProof = Proof#{terminal_control_bytes_removed => Removed}">>,
         <<"{Semantic, Removed} = {Raw, 0},\n"
           "    SafeProof = Proof#{terminal_control_bytes_removed => Removed}">>},
        {terminal_control_failure_projection, Path,
         <<"Projection = try Projector(Semantic)">>,
         <<"Projection = try Projector(Raw)">>},
        {terminal_control_unterminated_osc, Path,
         <<"none -> {<<>>, byte_size(Bytes)}">>,
         <<"none -> {Bytes, 0}">>},
        {terminal_control_csi_range, Path,
         <<"when Byte >= 16#40, Byte =< 16#7e">>,
         <<"when Byte >= 16#40, Byte =< 16#ff">>},
        {terminal_control_evidence, Path,
         <<"terminal_control_bytes_removed => Removed},">>,
         <<"terminal_control_bytes_removed => 0},">>},
        {terminal_control_unverified_success, Path,
         <<"false -> {error, Proof}">>,
         <<"false -> {ok, Semantic, Proof}">>}
    ],
    lists:foreach(fun({Id, MutationPath, Before, After}) ->
        put(failure_secrecy_control_id, Id),
        ControlId = fixed_audit_control_id(Id),
        ensure(ControlId =/= <<"unknown">>, terminal_control_id_missing),
        ensure(sensitive_string_categories(ControlId) =:= [],
               unsafe_terminal_control_id),
        Original = source_bytes(Sources, MutationPath),
        Mutated = binary:replace(Original, Before, After),
        ensure(Mutated =/= Original,
               {windows_process_contract_mutant_not_applied, Id}),
        MutantSources = [{MutationPath, Mutated}],
        ensure(not maps:get(passed,
                            command_terminal_control_contract(MutantSources)),
               {windows_process_contract_mutant_accepted, Id})
    end, Mutations),
    erase(failure_secrecy_control_id),
    1 + length(Mutations).

windows_process_isolation_controls() ->
    SupervisorPath = "scripts/process_supervisor.py",
    WatcherPath = "scripts/windows_process_visibility_watch.ps1",
    LauncherPath = "scripts/windows_console_inheritance_audit.ps1",
    Supervisor = bounded_read(SupervisorPath, ?MAX_SOURCE_FILE_BYTES),
    Watcher = bounded_read(WatcherPath, ?MAX_SOURCE_FILE_BYTES),
    Launcher = bounded_read(LauncherPath, ?MAX_SOURCE_FILE_BYTES),
    Sources = [{SupervisorPath, Supervisor}, {WatcherPath, Watcher},
               {LauncherPath, Launcher}],
    CurrentContract = windows_process_isolation_contract(Sources),
    put(failure_secrecy_check_index,
        first_failed_check_index(CurrentContract)),
    ensure(maps:get(passed, CurrentContract),
           current_windows_process_contract_rejected),
    erase(failure_secrecy_check_index),
    Mutations = [
        {direct_hpcon_value, SupervisorPath,
         <<"ctypes.c_void_p(int(pseudoconsole.value)),\n"
           "            ctypes.sizeof(ctypes.c_void_p)">>,
         <<"ctypes.byref(pseudoconsole),\n"
           "            ctypes.sizeof(ctypes.c_void_p)">>},
        {standard_handle_clear, SupervisorPath,
         <<"standard_handle_id, wintypes.HANDLE()\n                )">>,
         <<"standard_handle_id, wintypes.HANDLE(1)\n                )">>},
        {standard_handle_finally, SupervisorPath,
         <<"        finally:\n"
           "            for index in range(cleared_standard_handles):">>,
         <<"        if created:\n"
           "            for index in range(cleared_standard_handles):">>},
        {standard_handle_restore, SupervisorPath,
         <<"wintypes.HANDLE(restored or 0),">>,
         <<"wintypes.HANDLE(),">>},
        {conpty_input_writer_lifetime, SupervisorPath,
         <<"        self._resumed = True\n"
           "        thread_closed = close_windows_handle(self._thread)">>,
         <<"        self._resumed = True\n"
           "        close_windows_handle(self._input_write)\n"
           "        thread_closed = close_windows_handle(self._thread)">>},
        {conpty_close_after_exit, SupervisorPath,
         <<"console_closed = child.close_console_while_draining(relay)">>,
         <<"console_closed = True">>},
        {fixed_abnormal_category, SupervisorPath,
         <<"0xC000013A: \"child_controlled_interrupt\"">>,
         <<"0xC000013A: \"child_abnormal_exit\"">>},
        {fixed_abnormal_fallback, SupervisorPath,
         <<"}.get(returncode & 0xFFFFFFFF, \"child_abnormal_exit\")">>,
         <<"}.get(returncode & 0xFFFFFFFF, str(returncode))">>},
        {supervisor_control_count, SupervisorPath,
         ?PROCESS_SUPERVISOR_SELF_TEST_MARKER,
         <<"process_supervisor_self_test passed=true controls=42">>},
        {watcher_native_handle, WatcherPath,
         <<"ParentProcessId($current.Handle)">>,
         <<"ParentProcessId([IntPtr]::Zero)">>},
        {watcher_native_failure_projection, WatcherPath,
         <<"\"failure_code\":\"native_boundary_unavailable\"">>,
         <<"\"failure_code\":\"native_boundary_unknown\"">>},
         {watcher_preopened_handle, WatcherPath,
          <<"$processHandle = [IntPtr]$process.Handle">>,
          <<"$processHandle = [IntPtr]::Zero">>},
         {watcher_cached_target_name, WatcherPath,
          <<"-NotePropertyName HttpTargetName">>,
          <<"-NotePropertyName UnverifiedTargetName">>},
         {watcher_cached_process_start, WatcherPath,
          <<"-NotePropertyName HttpStartTicks">>,
          <<"-NotePropertyName UnverifiedStartTicks">>},
         {watcher_cached_process_handle, WatcherPath,
          <<"-NotePropertyName HttpProcessHandle">>,
          <<"-NotePropertyName UnverifiedProcessHandle">>},
        {watcher_retained_handle_disposal, WatcherPath,
         <<"$retained.Dispose()">>, <<"$null = $retained.Id">>},
         {watcher_control_count, WatcherPath,
          <<"\"controls\":32,\"passed\":true">>,
          <<"\"controls\":31,\"passed\":true">>},
         {watcher_lineage_policy, WatcherPath,
          <<"return $OwnerBound -or $StageName -eq 'console-inheritance'">>,
          <<"return $false">>},
         {watcher_owner_binding_switch, WatcherPath,
          <<"[switch] $RequireOwnerBinding">>,
          <<"[switch] $IgnoreOwnerBinding">>},
         {watcher_owner_binding_bound, WatcherPath,
          <<"$Bytes.Length -lt 5 -or $Bytes.Length -gt 48">>,
          <<"$Bytes.Length -lt 0 -or $Bytes.Length -gt 4800">>},
         {watcher_owner_binding_format, WatcherPath,
          <<"(?<pid>[1-9][0-9]{0,9}):(?<ticks>[1-9][0-9]{0,18})\\n$">>,
          <<"(?<pid>[0-9]+):(?<ticks>[0-9]+)">>},
         {watcher_trap_owner_cleanup, WatcherPath,
          <<"Remove-PrivateSignal -Path $script:ownerSignalPath">>,
          <<"Remove-PrivateSignal -Path $script:readySignalPath">>},
         {watcher_owner_pid_identity, WatcherPath,
          <<"$ownerProcessId -ne [int]$ownerBinding.process_id -or">>,
          <<"$false -or">>},
         {watcher_owner_start_identity, WatcherPath,
          <<"$ownerStartTicks -ne [int64]$ownerBinding.start_ticks -or">>,
          <<"$false -or">>},
         {watcher_ancestry_depth, WatcherPath,
          <<"for ($depth = 0; $depth -lt 64; $depth += 1)">>,
          <<"for ($depth = 0; $depth -lt 640; $depth += 1)">>},
         {watcher_ancestry_cycle, WatcherPath,
          <<"$parentId -le 0 -or -not $visited.Add($parentId)">>,
          <<"$parentId -le 0 -or $false">>},
         {watcher_ancestry_start, WatcherPath,
          <<"if ($parentStartTicks -gt $childStartTicks) {">>,
          <<"if ($false) {">>},
         {watcher_unowned_filter, WatcherPath,
          <<"if (-not $ownership.owned) {">>,
          <<"if ($false) {">>},
         {watcher_unowned_counter_bound, WatcherPath,
          <<"65535, $ignoredUnownedCandidates + 1)">>,
          <<"[int]::MaxValue, $ignoredUnownedCandidates + 1)">>},
         {watcher_owner_root_observation, WatcherPath,
          <<"if ($ownership.root) { $ownerRootObserved = $true }">>,
          <<"$ownerRootObserved = $true">>},
         {watcher_owner_cleanup_confirmation, WatcherPath,
          <<"throw 'owner_binding_cleanup_failed'">>,
          <<"$observationComplete = $true">>},
         {watcher_owner_pass_condition, WatcherPath,
          <<"$ownerBindingVerified -and\n"
            "        $ownerBindingCleanupConfirmed -and">>,
          <<"$true -and\n"
            "        $ownerBindingCleanupConfirmed -and">>},
         {watcher_normal_retained_disposal, WatcherPath,
          <<"        $retained.process.Dispose()\n    }\n    catch {">>,
          <<"        $null = $retained.process.Id\n    }\n    catch {">>},
         {launcher_owner_binding_flag, LauncherPath,
          <<"'-RequireOwnerBinding'">>, <<"'-IgnoreOwnerBinding'">>},
         {launcher_owner_create_new, LauncherPath,
          <<"[System.IO.FileMode]::CreateNew">>,
          <<"[System.IO.FileMode]::OpenOrCreate">>},
         {launcher_owner_exclusive_write, LauncherPath,
          <<"[System.IO.FileShare]::None">>,
          <<"[System.IO.FileShare]::Read">>},
         {launcher_owner_durable_flush, LauncherPath,
          <<"$ownerStream.Flush($true)">>,
          <<"$ownerStream.Flush($false)">>},
         {launcher_unowned_adversary, LauncherPath,
          <<"$watchJson.ignored_unowned_candidate_count -ge 1">>,
          <<"$watchJson.ignored_unowned_candidate_count -ge 0">>},
         {launcher_token_redaction, LauncherPath,
          <<"$watchStdout -notmatch [regex]::Escape($token)">>,
          <<"$true">>},
        {watcher_fail_closed_observation, WatcherPath,
         <<"$observationComplete -and\n    $baselineForbiddenCount -eq 0">>,
         <<"$true -and\n    $baselineForbiddenCount -eq 0">>}
    ],
    lists:foreach(fun({Id, MutationPath, Before, After}) ->
        put(failure_secrecy_control_id, Id),
        ControlId = fixed_audit_control_id(Id),
        ensure(ControlId =/= <<"unknown">>,
               audit_control_id_missing),
        ensure(sensitive_string_categories(ControlId) =:= [],
               unsafe_audit_control_id),
        Original = source_bytes(Sources, MutationPath),
        Mutated = binary:replace(Original, Before, After),
        ensure(Mutated =/= Original,
               {windows_process_contract_mutant_not_applied, Id}),
        MutantSources = lists:keyreplace(
            MutationPath, 1, Sources, {MutationPath, Mutated}),
        ensure(not maps:get(passed,
                            windows_process_isolation_contract(MutantSources)),
               {windows_process_contract_mutant_accepted, Id})
    end, Mutations),
    erase(failure_secrecy_control_id),
    1 + length(Mutations).

failure_code_controls() ->
    ensure(audit_command(audit) =:=
           <<"escript scripts/failure_secrecy_audit.escript audit">>,
           audit_replay_command_drift),
    ensure(audit_command(self_test) =:=
           <<"escript scripts/failure_secrecy_audit.escript --self-test">>,
           audit_self_test_command_drift),
    ensure(audit_failure_code(source_changed_during_audit) =:=
           <<"source_changed_during_audit">>, source_change_code_lost),
    ensure(audit_failure_code(failure_secrecy_gate_blocked) =:=
           <<"failure_secrecy_gate_blocked">>, blocked_code_lost),
    Private = audit_failure_code({private_marker(), self(), make_ref()}),
    ensure(Private =:= <<"validation_failed">>, raw_failure_code_retained),
    ensure(sensitive_string_categories(Private) =:= [],
           unsafe_failure_code_projection),
    NotApplied = audit_failure_code(
        {windows_process_contract_mutant_not_applied, private_marker()}),
    Accepted = audit_failure_code(
        {windows_process_contract_mutant_accepted, private_marker()}),
    ensure(NotApplied =:= <<"mutation_not_applied">>,
           mutation_not_applied_code_lost),
    ensure(Accepted =:= <<"mutation_accepted">>,
           mutation_accepted_code_lost),
    ensure(sensitive_string_categories(<<NotApplied/binary, Accepted/binary>>)
               =:= [],
           unsafe_mutation_failure_projection),
    put(failure_secrecy_control_id, direct_hpcon_value),
    ensure(audit_control_id() =:= <<"direct_hpcon_value">>,
           known_audit_control_id_lost),
    put(failure_secrecy_control_id, private_marker()),
    UnknownControl = audit_control_id(),
    erase(failure_secrecy_control_id),
    ensure(UnknownControl =:= <<"unknown">>, raw_audit_control_id_retained),
    ensure(sensitive_string_categories(UnknownControl) =:= [],
           unsafe_audit_control_id_projection),
    put(failure_secrecy_check_index, 17),
    ensure(audit_check_index() =:= 17, known_audit_check_index_lost),
    put(failure_secrecy_check_index, private_marker()),
    UnknownCheck = audit_check_index(),
    erase(failure_secrecy_check_index),
    ensure(UnknownCheck =:= 0, raw_audit_check_index_retained).

port_runner_controls() ->
    put(failure_secrecy_control_id, current_port_inventory),
    CurrentPortControl = fixed_audit_control_id(current_port_inventory),
    ensure(CurrentPortControl =/= <<"unknown">>, port_control_id_missing),
    ensure(sensitive_string_categories(CurrentPortControl) =:= [],
           unsafe_port_control_id),
    ensure(port_runner_findings(port_runner_inventory(bounded_sources())) =:= [],
           current_port_inventory_rejected),
    erase(failure_secrecy_control_id),
    Unsafe = [{"scripts/mutant.escript",
        <<"run() -> P=open_port({spawn_executable,E},"
          "[binary,exit_status,use_stdio,stderr_to_stdout,hide]),"
          "collect(P,[]).\n"
          "collect(P,Output)->receive {P,{data,B}}->collect(P,[B|Output]);"
          "{P,{exit_status,S}}->{S,Output} after 30000->"
          "port_close(P),{124,Output} end.\n">>}],
    UnsafeRows = port_runner_inventory(Unsafe),
    UnsafeRules = [maps:get(rule, Finding)
                   || Finding <- port_runner_findings(UnsafeRows)],
    ensure(lists:member(<<"external_child_relative_deadline">>, UnsafeRules),
           relative_deadline_mutant_accepted),
    ensure(lists:member(<<"external_child_unbounded_output">>, UnsafeRules),
           output_accumulation_mutant_accepted),
    ensure(lists:member(<<"external_child_exit_unconfirmed">>, UnsafeRules),
           unjoined_timeout_mutant_accepted),
    ensure(lists:member(<<"external_child_unowned_tree">>, UnsafeRules),
           direct_collector_runner_blessed),
    Safe = [{"scripts/process_runner.hrl",
        <<"open_owned_process(E,A,D,V,Deadline)->\n"
          "S=\"scripts/process_supervisor.py\",H=process_supervisor_sha256(),"
          "P=open_port({spawn_executable,S},[binary,exit_status,use_stdio,"
          "stderr_to_stdout,hide,{packet, 4}]),"
          "await_supervisor_handshake(P,H,Deadline),"
          "activate_process_supervisor(P,H,Deadline,R,S,C).\n">>}],
    ensure(port_runner_findings(port_runner_inventory(Safe)) =:= [],
           bounded_owned_runner_rejected),
    HideOnly = [{"scripts/hide_only.escript",
        <<"run()->open_port({spawn_executable,E},"
          "[binary,exit_status,use_stdio,stderr_to_stdout,hide]).\n">>}],
    ensure(length(port_runner_findings(port_runner_inventory(HideOnly))) =:= 4,
           hide_only_runner_accepted),
    SiblingBypass = [{"scripts/sibling.escript",
        <<"safe()->P=open_port({spawn_executable,E},[binary,exit_status,"
          "use_stdio,stderr_to_stdout,hide]),collect_eunit(P,new_output(),"
          "erlang:monotonic_time(millisecond)+1000).\n"
          "unsafe()->P=open_port({spawn_executable,E},[binary,exit_status,"
          "use_stdio,stderr_to_stdout,hide]),collect(P,[]).\n"
          "collect(P,O)->receive {P,{data,B}}->collect(P,[B|O]);"
          "{P,{exit_status,S}}->{S,O} after 30000->port_close(P),"
          "{124,O} end.\n">>}],
    SiblingFindings = port_runner_findings(port_runner_inventory(SiblingBypass)),
    ensure(length(SiblingFindings) >= 3,
           unrelated_safe_runner_blessed_unsafe_site),
    Lexical = <<"fixture() ->\n"
        "  [<<\"quoted fixture\",\n"
        "     \"open_port({spawn_executable, forbidden}, [])\">>,\n"
        "   'open_port(', $\", $\\\"].\n"
        "% open_port({spawn_executable, forbidden}, []).\n"
        "real() -> erlang:open_port % comment between tokens\n"
        "  ({spawn_executable, E}, []).\n"
        "identifier() -> not_open_port({spawn_executable, E}, []).\n">>,
    ensure(executable_port_lines(Lexical) =:= [6],
           quoted_port_fixture_classified_as_executable),
    ensure(length(port_runner_inventory(
        [{"scripts/lexical.escript", Lexical}])) =:= 1,
        lexical_port_inventory_count_drift),
    ensure(executable_port_lines(
        <<"a() -> 'open_port(', \"open_port(\", not_open_port().\n">>) =:= [],
        non_executable_port_token_accepted).

source_set_controls() ->
    Original = [{"a", <<"one">>}, {"b", <<"two">>}],
    ensure(source_sets_equal(Original, Original), stable_source_set_rejected),
    ensure(not source_sets_equal(Original,
        [{"a", <<"changed">>}, {"b", <<"two">>}]),
        changed_source_set_accepted),
    ensure(not source_sets_equal(Original, [{"a", <<"one">>}]),
        removed_source_accepted),
    ensure(not source_sets_equal(Original,
        [{"a", <<"one">>}, {"b", <<"two">>}, {"c", <<>>}]),
        added_source_accepted),
    ensure(artifact_sets_equal(Original, Original), stable_artifact_set_rejected),
    ensure(not artifact_sets_equal(Original, [{"a", <<"one">>}]),
        changed_artifact_set_accepted),
    ensure(audited_source_path("scripts/example.escript"),
        authored_source_path_excluded),
    ensure(not audited_source_path(
        "build/process-runner/evaluation-audit-mutant.erl"),
        evaluation_temp_joined_source_identity).

immutable_publication_control() ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
    Directory = filename:join(["build", "failure-secrecy",
                               "publication-self-test-" ++ binary_to_list(Nonce)]),
    Path = filename:join(Directory, "report.json"),
    Bytes = <<"{\"schema\":1,\"status\":\"Ready\"}\n">>,
    Digest = crypto:hash(sha256, Bytes),
    try
        write_immutable_report(Path, Bytes),
        ensure(bounded_read(Path, 4096) =:= Bytes,
               immutable_publication_content_mismatch),
        ensure(crypto:hash(sha256, bounded_read(Path, 4096)) =:= Digest,
               immutable_publication_digest_mismatch),
        write_immutable_report(Path, Bytes),
        ensure(expect_error(fun() ->
            write_immutable_report(Path,
                <<"{\"schema\":1,\"status\":\"Blocked\"}\n">>)
        end), immutable_collision_accepted),
        ensure(crypto:hash(sha256, bounded_read(Path, 4096)) =:= Digest,
               immutable_collision_replaced_target)
    after
        _ = file:delete(Path),
        _ = file:del_dir(Directory)
    end.

runtime_report_path_control() ->
    Source = #{sha256 => binary:copy(<<"a">>, 64)},
    Artifacts = #{sha256 => binary:copy(<<"b">>, 64)},
    Residues = #{metadata_sha256 => binary:copy(<<"c">>, 64)},
    Otp28 = #{otp_release => <<"28">>, erts_version => <<"16.2">>,
              architecture => <<"win32-x86_64">>},
    Otp29 = Otp28#{otp_release => <<"29">>, erts_version => <<"17.0">>},
    ensure(report_path(Source, Artifacts, Residues, Otp28) =/=
               report_path(Source, Artifacts, Residues, Otp29),
           runtime_report_path_collision).

expect_error(Function) ->
    try Function() of _ -> false catch _:_ -> true end.

%% Utilities ---------------------------------------------------------------

begin_progress() ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
    Directory = filename:join(["build", "failure-secrecy", "progress",
        "run-" ++ binary_to_list(Nonce)]),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    put(failure_secrecy_progress_directory, Directory),
    put(failure_secrecy_progress_events, []),
    put(failure_secrecy_progress_sequence, 0),
    put(failure_secrecy_stage, starting),
    progress(starting, 0, 0, 1, 1).

progress(Stage, Completed, Bytes, CountLimit, ByteLimit)
  when is_atom(Stage), is_integer(Completed), Completed >= 0,
       is_integer(Bytes), Bytes >= 0,
       is_integer(CountLimit), CountLimit > 0,
       is_integer(ByteLimit), ByteLimit > 0 ->
    put(failure_secrecy_stage, Stage),
    Sequence = get(failure_secrecy_progress_sequence) + 1,
    put(failure_secrecy_progress_sequence, Sequence),
    Directory = get(failure_secrecy_progress_directory),
    Name = lists:flatten(io_lib:format("event-~4..0B.json", [Sequence])),
    Path = filename:join(Directory, Name),
    Event = #{schema => 1, sequence => Sequence,
        stage => atom_to_binary(Stage),
        monotonic_milliseconds => erlang:monotonic_time(millisecond),
        completed => Completed, input_bytes => Bytes,
        count_limit => CountLimit, byte_limit => ByteLimit},
    [] = scan_json_value(Event),
    ok = file:write_file(Path, [json:encode(Event), $\n], [exclusive, sync]),
    put(failure_secrecy_progress_events,
        [Path | get(failure_secrecy_progress_events)]),
    ok.

end_progress() ->
    case get(failure_secrecy_progress_events) of
        Events when is_list(Events) ->
            lists:foreach(fun(Path) ->
                case file:delete(Path) of
                    ok -> ok;
                    {error, enoent} -> ok;
                    {error, _} -> erlang:error(cannot_remove_audit_progress)
                end
            end, Events);
        _ -> ok
    end,
    case get(failure_secrecy_progress_directory) of
        Directory when is_list(Directory) ->
            case file:del_dir(Directory) of
                ok -> ok;
                {error, enoent} -> ok;
                {error, _} -> erlang:error(cannot_remove_audit_progress)
            end;
        _ -> ok
    end.

failure_stage() ->
    case get(failure_secrecy_stage) of
        starting -> <<"starting">>;
        source_capture -> <<"source_capture">>;
        assertion_inventory -> <<"assertion_inventory">>;
        reporter_scan -> <<"reporter_scan">>;
        process_runner_scan -> <<"process_runner_scan">>;
        artifact_capture -> <<"artifact_capture">>;
        artifact_scan -> <<"artifact_scan">>;
        source_recheck -> <<"source_recheck">>;
        publish -> <<"publish">>;
        _ -> <<"unknown">>
    end.

audit_failure_code(source_changed_during_audit) ->
    <<"source_changed_during_audit">>;
audit_failure_code(evidence_changed_during_audit) ->
    <<"evidence_changed_during_audit">>;
audit_failure_code(crash_dump_residue_changed_during_audit) ->
    <<"crash_residue_changed_during_audit">>;
audit_failure_code(source_or_evidence_changed_during_publication) ->
    <<"source_changed_during_publication">>;
audit_failure_code(failure_secrecy_gate_blocked) ->
    <<"failure_secrecy_gate_blocked">>;
audit_failure_code(cannot_remove_audit_progress) ->
    <<"audit_progress_cleanup_failed">>;
audit_failure_code({windows_process_contract_mutant_not_applied, _}) ->
    <<"mutation_not_applied">>;
audit_failure_code({windows_process_contract_mutant_accepted, _}) ->
    <<"mutation_accepted">>;
audit_failure_code(_) -> <<"validation_failed">>.

%% A failed mutation control must be identifiable without projecting the
%% exception term.  Keep the vocabulary finite: arbitrary process-dictionary
%% values collapse to unknown and can never enter failure output.
audit_control_id() ->
    fixed_audit_control_id(get(failure_secrecy_control_id)).

audit_check_index() ->
    case get(failure_secrecy_check_index) of
        Index when is_integer(Index), Index > 0, Index =< 256 -> Index;
        _ -> 0
    end.

first_failed_check_index(#{failed_check_indices := [Index | _]})
        when is_integer(Index), Index > 0, Index =< 256 -> Index;
first_failed_check_index(_) -> 0.

fixed_audit_control_id(direct_hpcon_value) -> <<"direct_hpcon_value">>;
fixed_audit_control_id(standard_handle_clear) -> <<"standard_handle_clear">>;
fixed_audit_control_id(standard_handle_finally) -> <<"standard_handle_finally">>;
fixed_audit_control_id(standard_handle_restore) -> <<"standard_handle_restore">>;
fixed_audit_control_id(conpty_input_writer_lifetime) -> <<"conpty_input_writer_lifetime">>;
fixed_audit_control_id(conpty_close_after_exit) -> <<"conpty_close_after_exit">>;
fixed_audit_control_id(fixed_abnormal_category) -> <<"fixed_abnormal_category">>;
fixed_audit_control_id(fixed_abnormal_fallback) -> <<"fixed_abnormal_fallback">>;
fixed_audit_control_id(supervisor_control_count) -> <<"supervisor_control_count">>;
fixed_audit_control_id(watcher_native_handle) -> <<"watcher_native_handle">>;
fixed_audit_control_id(watcher_native_failure_projection) ->
    <<"watcher_native_failure_projection">>;
fixed_audit_control_id(watcher_preopened_handle) -> <<"watcher_preopened_handle">>;
fixed_audit_control_id(watcher_cached_target_name) -> <<"watcher_cached_target_name">>;
fixed_audit_control_id(watcher_cached_process_start) -> <<"watcher_cached_process_start">>;
fixed_audit_control_id(watcher_cached_process_handle) ->
    <<"watcher_cached_process_handle">>;
fixed_audit_control_id(watcher_retained_handle_disposal) ->
    <<"watcher_retained_handle_disposal">>;
fixed_audit_control_id(watcher_control_count) -> <<"watcher_control_count">>;
fixed_audit_control_id(watcher_lineage_policy) -> <<"watcher_lineage_policy">>;
fixed_audit_control_id(watcher_owner_binding_switch) ->
    <<"watcher_owner_binding_switch">>;
fixed_audit_control_id(watcher_owner_binding_bound) ->
    <<"watcher_owner_binding_bound">>;
fixed_audit_control_id(watcher_owner_binding_format) ->
    <<"watcher_owner_binding_format">>;
fixed_audit_control_id(watcher_trap_owner_cleanup) ->
    <<"watcher_trap_owner_cleanup">>;
fixed_audit_control_id(watcher_owner_pid_identity) ->
    <<"watcher_owner_pid_identity">>;
fixed_audit_control_id(watcher_owner_start_identity) ->
    <<"watcher_owner_start_identity">>;
fixed_audit_control_id(watcher_ancestry_depth) ->
    <<"watcher_ancestry_depth">>;
fixed_audit_control_id(watcher_ancestry_cycle) ->
    <<"watcher_ancestry_cycle">>;
fixed_audit_control_id(watcher_ancestry_start) ->
    <<"watcher_ancestry_start">>;
fixed_audit_control_id(watcher_unowned_filter) ->
    <<"watcher_unowned_filter">>;
fixed_audit_control_id(watcher_unowned_counter_bound) ->
    <<"watcher_unowned_counter_bound">>;
fixed_audit_control_id(watcher_owner_root_observation) ->
    <<"watcher_owner_root_observation">>;
fixed_audit_control_id(watcher_owner_cleanup_confirmation) ->
    <<"watcher_owner_cleanup_confirmation">>;
fixed_audit_control_id(watcher_owner_pass_condition) ->
    <<"watcher_owner_pass_condition">>;
fixed_audit_control_id(watcher_normal_retained_disposal) ->
    <<"watcher_normal_retained_disposal">>;
fixed_audit_control_id(launcher_owner_binding_flag) ->
    <<"launcher_owner_binding_flag">>;
fixed_audit_control_id(launcher_owner_create_new) ->
    <<"launcher_owner_create_new">>;
fixed_audit_control_id(launcher_owner_exclusive_write) ->
    <<"launcher_owner_exclusive_write">>;
fixed_audit_control_id(launcher_owner_durable_flush) ->
    <<"launcher_owner_durable_flush">>;
fixed_audit_control_id(launcher_unowned_adversary) ->
    <<"launcher_unowned_adversary">>;
fixed_audit_control_id(launcher_token_redaction) ->
    <<"launcher_token_redaction">>;
fixed_audit_control_id(terminal_control_current_contract) ->
    <<"terminal_control_current_contract">>;
fixed_audit_control_id(terminal_control_success_bypass) ->
    <<"terminal_control_success_bypass">>;
fixed_audit_control_id(terminal_control_failure_bypass) ->
    <<"terminal_control_failure_bypass">>;
fixed_audit_control_id(terminal_control_failure_projection) ->
    <<"terminal_control_failure_projection">>;
fixed_audit_control_id(terminal_control_unterminated_osc) ->
    <<"terminal_control_unterminated_osc">>;
fixed_audit_control_id(terminal_control_csi_range) ->
    <<"terminal_control_csi_range">>;
fixed_audit_control_id(terminal_control_evidence) ->
    <<"terminal_control_evidence">>;
fixed_audit_control_id(terminal_control_unverified_success) ->
    <<"terminal_control_unverified_success">>;
fixed_audit_control_id(current_port_inventory) ->
    <<"current_port_inventory">>;
fixed_audit_control_id(runner_absolute_current_contract) ->
    <<"runner_absolute_current_contract">>;
fixed_audit_control_id(runner_exit_deadline_current_contract) ->
    <<"runner_exit_deadline_current_contract">>;
fixed_audit_control_id(runner_unconfirmed_current_contract) ->
    <<"runner_unconfirmed_current_contract">>;
fixed_audit_control_id(runner_absolute_deadline) ->
    <<"runner_absolute_deadline">>;
fixed_audit_control_id(runner_output_limit) ->
    <<"runner_output_limit">>;
fixed_audit_control_id(runner_tail_copy) ->
    <<"runner_tail_copy">>;
fixed_audit_control_id(runner_crash_dump_disable) ->
    <<"runner_crash_dump_disable">>;
fixed_audit_control_id(runner_hidden_port) ->
    <<"runner_hidden_port">>;
fixed_audit_control_id(package_process_current_contract) ->
    <<"package_process_current_contract">>;
fixed_audit_control_id(package_process_tail_key) ->
    <<"package_process_tail_key">>;
fixed_audit_control_id(package_process_output_digest_key) ->
    <<"package_process_output_digest_key">>;
fixed_audit_control_id(package_process_unknown_key) ->
    <<"package_process_unknown_key">>;
fixed_audit_control_id(owned_tree_current_contract) ->
    <<"owned_tree_current_contract">>;
fixed_audit_control_id(registration_failure_immediate_close) ->
    <<"registration_failure_immediate_close">>;
fixed_audit_control_id(uncertain_start_immediate_close) ->
    <<"uncertain_start_immediate_close">>;
fixed_audit_control_id(owned_recovery_without_join) ->
    <<"owned_recovery_without_join">>;
fixed_audit_control_id(owned_recovery_close_before_join) ->
    <<"owned_recovery_close_before_join">>;
fixed_audit_control_id(watcher_fail_closed_observation) ->
    <<"watcher_fail_closed_observation">>;
fixed_audit_control_id(_) -> <<"unknown">>.

report_path(SourceIdentity, ArtifactIdentity, ResidueIdentity,
            RuntimeIdentity) ->
    Source = maps:get(sha256, SourceIdentity),
    Artifacts = maps:get(sha256, ArtifactIdentity),
    Residues = maps:get(metadata_sha256, ResidueIdentity),
    Runtime = crypto:hash(sha256,
        term_to_binary(RuntimeIdentity, [deterministic])),
    Name = hex(crypto:hash(sha256,
        <<Source/binary, 0, Artifacts/binary, 0, Residues/binary, 0,
          Runtime/binary>>)),
    filename:join(?REPORT_DIRECTORY,
                  "report-" ++ binary_to_list(Name) ++ ".json").

write_immutable_report(Path, Bytes) ->
    ok = filelib:ensure_dir(Path),
    case filelib:is_regular(Path) of
        true ->
            ensure(bounded_read(Path, ?MAX_ARTIFACT_BYTES) =:= Bytes,
                   immutable_report_collision);
        false ->
            Nonce = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
            Temporary = Path ++ "." ++ binary_to_list(Nonce) ++ ".tmp",
            ok = file:write_file(Temporary, Bytes, [exclusive, sync]),
            %% Linking a fully written same-directory file creates the target
            %% atomically and, unlike rename on Windows, never replaces it.
            case file:make_link(Temporary, Path) of
                ok -> ok = file:delete(Temporary);
                {error, eexist} ->
                    ok = file:delete(Temporary),
                    ensure(bounded_read(Path, ?MAX_ARTIFACT_BYTES) =:= Bytes,
                           immutable_report_collision);
                {error, Reason} ->
                    _ = file:delete(Temporary),
                    erlang:error({cannot_publish_report,
                                  file_error_category(Reason)})
            end
    end.

source_sets_equal(Before, After) -> Before =:= After.
artifact_sets_equal(Before, After) -> Before =:= After.

bounded_read(Path, Limit) ->
    {ok, Handle} = file:open(Path, [read, binary, raw]),
    try
        case file:read(Handle, Limit + 1) of
            eof -> <<>>;
            {ok, Bytes} ->
                ensure(byte_size(Bytes) =< Limit, input_file_too_large),
                ensure(file:read(Handle, 1) =:= eof, input_file_too_large),
                Bytes
        end
    after ok = file:close(Handle) end.

file_sha256(Path) ->
    hex(crypto:hash(sha256, bounded_read(Path, ?MAX_SOURCE_FILE_BYTES))).

file_error_category(eacces) -> access_denied;
file_error_category(enospc) -> storage_exhausted;
file_error_category(enoent) -> missing_parent;
file_error_category(_) -> operating_system_failure.

line_number(Bytes, Offset) ->
    Prefix = binary:part(Bytes, 0, Offset),
    length(binary:matches(Prefix, <<"\n">>)) + 1.

match_count(Bytes, Pattern) ->
    case re:run(Bytes, Pattern, [global, {capture, none}, unicode]) of
        nomatch -> 0;
        match ->
            %% With {capture,none}, global returns `match` and not coordinates.
            match_count_with_coordinates(Bytes, Pattern)
    end.

match_count_with_coordinates(Bytes, Pattern) ->
    case re:run(Bytes, Pattern, [global, {capture, first, index}, unicode]) of
        nomatch -> 0;
        {match, Matches} -> length(Matches)
    end.

bounded_findings(Findings) -> lists:sublist(Findings, ?MAX_FINDINGS).

ensure(true, _) -> ok;
ensure(false, Reason) -> erlang:error(Reason).

hex(Bytes) ->
    iolist_to_binary([io_lib:format("~2.16.0b", [Byte]) || <<Byte>> <= Bytes]).
