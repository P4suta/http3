#!/usr/bin/env escript
%%! +S 2:2 +SDcpu 1 +SDio 1 +A 1 +hmax 134217728 +hmaxib true +hmaxk true +hmaxel false

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% Keep the OHTTP entropy boundary consistent across compiler output, the
%% reviewed API snapshot, and the Hex archive that users install. The archive
%% check is intentionally independent of the release simulator's inventory
%% comparison: it rejects a rebound artifact that reintroduces a test-only key
%% or nonce control even when its checksum and report digest are also changed.

-include("json_evidence.hrl").

-define(API_REPORT, "build/ohttp-distribution/api.json").
-define(RELEASE_REPORT, "build/ohttp-distribution/release.json").
-define(LEGACY_SELF_TEST_REPORT, "build/ohttp-distribution/self-test.json").
-define(INTERFACE, "build/http-package-interface.json").
-define(SNAPSHOT, "api/http.snapshot").
-define(SOURCE, "src/http/ohttp.gleam").
-define(FFI_SOURCE, "src/http_ohttp_ffi.erl").
-define(RELEASE_SIM_REPORT, "build/release-sim/report.json").
-define(MAX_INTERFACE_BYTES, 16 * 1024 * 1024).
-define(MAX_SNAPSHOT_BYTES, 4 * 1024 * 1024).
-define(MAX_SOURCE_BYTES, 2 * 1024 * 1024).
-define(MAX_RELEASE_REPORT_BYTES, 16 * 1024 * 1024).
-define(MAX_ARCHIVE_BYTES, 128 * 1024 * 1024).
-define(MAX_ARCHIVE_FILES, 2048).

main(Arguments) ->
    Root = filename:dirname(filename:dirname(filename:absname(escript:script_name()))),
    ok = file:set_cwd(Root),
    put(ohttp_gate_identity, gate_identity()),
    try dispatch(Arguments) of
        ok -> ok
    catch
        _:_ ->
            preserve_failure(Arguments),
            %% Inputs can be adversarial. Never echo an input fragment or an
            %% absolute path into shareable CI output.
            io:format(standard_error,
                      "OHTTP distribution contract failed; see the bounded gate phase~n", []),
            halt(1)
    end.

dispatch(["--api"]) -> audit_api_command();
dispatch(["--release"]) -> audit_release_command();
dispatch(["--self-test"]) -> self_test();
dispatch(_) -> erlang:error(ohttp_distribution_audit_usage).

forbidden_symbols() ->
    [
        <<"deterministic_client">>,
        <<"deterministic_test_client">>,
        <<"seal_response_bytes_with_nonce">>,
        <<"new_deterministic_claim">>,
        <<"claim_deterministic_key">>
    ].

required_functions() -> [<<"client">>, <<"seal_response_bytes">>].

audit_api_command() ->
    invalidate(?API_REPORT),
    InterfaceBytes = read_limited(?INTERFACE, ?MAX_INTERFACE_BYTES),
    Snapshot = read_limited(?SNAPSHOT, ?MAX_SNAPSHOT_BYTES),
    Source = read_limited(?SOURCE, ?MAX_SOURCE_BYTES),
    FfiSource = read_limited(?FFI_SOURCE, ?MAX_SOURCE_BYTES),
    Contract = audit_api(InterfaceBytes, Snapshot, Source),
    audit_no_forbidden(FfiSource),
    unchanged(?INTERFACE, ?MAX_INTERFACE_BYTES, InterfaceBytes),
    unchanged(?SNAPSHOT, ?MAX_SNAPSHOT_BYTES, Snapshot),
    unchanged(?SOURCE, ?MAX_SOURCE_BYTES, Source),
    unchanged(?FFI_SOURCE, ?MAX_SOURCE_BYTES, FfiSource),
    ensure_gate_identity_unchanged(),
    Report = (base_report(<<"compiler-interface-and-snapshot">>, Source))#{
         interface_sha256 => digest(InterfaceBytes),
         snapshot_sha256 => digest(Snapshot),
         ffi_source_sha256 => digest(FfiSource),
         contract_entries => maps:get(contract_entries, Contract),
         completion => #{completed => 5, expected => 5},
         rerun_command => <<"escript scripts/ohttp_distribution_audit.escript --api">>},
    write_report(?API_REPORT, Report),
    io:format("OHTTP compiler API and canonical snapshot contract ok~n", []).

audit_release_command() ->
    invalidate(?RELEASE_REPORT),
    ReleaseReportBytes = read_limited(?RELEASE_SIM_REPORT, ?MAX_RELEASE_REPORT_BYTES),
    ReleaseReport = evidence_json_decode(ReleaseReportBytes),
    Source = read_limited(?SOURCE, ?MAX_SOURCE_BYTES),
    FfiSource = read_limited(?FFI_SOURCE, ?MAX_SOURCE_BYTES),
    Archive = release_http_archive(ReleaseReport),
    Path = binary_to_list(maps:get(<<"path">>, Archive)),
    ArchiveBytes = read_limited(Path, ?MAX_ARCHIVE_BYTES),
    ReportedArchiveSha = maps:get(<<"sha256">>, Archive),
    ReportedArchiveSha = digest(ArchiveBytes),
    ArchiveResult = audit_archive(ArchiveBytes, Source, FfiSource),
    unchanged(?RELEASE_SIM_REPORT, ?MAX_RELEASE_REPORT_BYTES, ReleaseReportBytes),
    unchanged(Path, ?MAX_ARCHIVE_BYTES, ArchiveBytes),
    unchanged(?SOURCE, ?MAX_SOURCE_BYTES, Source),
    unchanged(?FFI_SOURCE, ?MAX_SOURCE_BYTES, FfiSource),
    ensure_gate_identity_unchanged(),
    Report = (base_report(<<"canonical-hex-archive">>, Source))#{
         release_report_sha256 => digest(ReleaseReportBytes),
         archive_sha256 => digest(ArchiveBytes),
         ffi_source_sha256 => digest(FfiSource),
         archive_files => maps:get(files, ArchiveResult),
         test_artifacts_absent => true,
         archive_source_matches_workspace => true,
         archive_ffi_source_matches_workspace => true,
         completion => #{completed => 5, expected => 5},
         rerun_command => <<"escript scripts/ohttp_distribution_audit.escript --release">>},
    write_report(?RELEASE_REPORT, Report),
    io:format("OHTTP canonical distribution contract ok~n", []).

base_report(Scope, Source) ->
    #{schema => 1, status => <<"Ready">>,
      gate => <<"ohttp-entropy-boundary-v1">>, scope => Scope,
      classification => <<"none">>,
      source_sha256 => digest(Source),
      forbidden_symbols_checked => length(forbidden_symbols()),
      required_functions_checked => length(required_functions()),
      context_reuse_error_checked => true,
      finite_input_limits => true,
      tool_identity => get(ohttp_gate_identity)}.

gate_identity() ->
    Script = read_limited("scripts/ohttp_distribution_audit.escript", 2 * 1024 * 1024),
    Settings = read_limited(".mise.toml", 2 * 1024 * 1024),
    #{otp => list_to_binary(erlang:system_info(otp_release)),
      erts => list_to_binary(erlang:system_info(version)),
      script_sha256 => digest(Script), settings_sha256 => digest(Settings)}.

ensure_gate_identity_unchanged() ->
    Expected = get(ohttp_gate_identity),
    Expected = gate_identity(),
    ok.

audit_api(InterfaceBytes, Snapshot, Source) ->
    audit_no_forbidden(InterfaceBytes),
    audit_no_forbidden(Snapshot),
    audit_source(Source),
    Interface = evidence_json_decode(InterfaceBytes),
    audit_decoded_no_forbidden(Interface),
    true = maps:get(<<"name">>, Interface) =:= <<"http">>,
    Modules = maps:get(<<"modules">>, Interface),
    true = is_map(Modules) andalso map_size(Modules) > 0 andalso
        map_size(Modules) =< 4096,
    Module = maps:get(<<"http/ohttp">>, Modules),
    Functions = maps:get(<<"functions">>, Module),
    Types = maps:get(<<"types">>, Module),
    true = is_map(Functions) andalso map_size(Functions) =< 4096,
    true = is_map(Types) andalso map_size(Types) =< 1024,
    lists:foreach(fun(Name) -> true = maps:is_key(Name, Functions) end,
                  required_functions()),
    Error = maps:get(<<"Error">>, Types),
    Constructors = maps:get(<<"constructors">>, Error),
    true = is_list(Constructors) andalso length(Constructors) =< 256,
    ConstructorNames = [maps:get(<<"name">>, Constructor) || Constructor <- Constructors],
    true = lists:all(fun(Name) -> is_binary(Name) andalso byte_size(Name) =< 128 end,
                     ConstructorNames),
    true = length(ConstructorNames) =:= length(lists:usort(ConstructorNames)),
    true = lists:member(<<"ContextReuseDetected">>, ConstructorNames),
    ContractLines = [canonical_line(<<"function">>, <<"http/ohttp">>, Name,
                                    maps:get(Name, Functions))
                     || Name <- required_functions()] ++
        [canonical_line(<<"type">>, <<"http/ohttp">>, <<"Error">>, Error)],
    SnapshotLines = bounded_lines(Snapshot, 16384),
    1 = count_line(<<"module http http/ohttp">>, SnapshotLines),
    lists:foreach(fun(Line) -> 1 = count_line(Line, SnapshotLines) end, ContractLines),
    #{contract_entries => length(ContractLines) + 1}.

audit_source(Source) ->
    audit_no_forbidden(Source),
    true = regex_present(Source, <<"(?m)^pub[\\t ]+fn[\\t ]+client[\\t ]*\\(">>),
    true = regex_present(Source,
                         <<"(?m)^pub[\\t ]+fn[\\t ]+seal_response_bytes[\\t ]*\\(">>),
    true = regex_present(Source, <<"(?m)^[\\t ]*ContextReuseDetected(?:[\\t ]|$)">>),
    ok.

audit_no_forbidden(Bytes) when is_binary(Bytes) ->
    lists:foreach(fun(Symbol) -> nomatch = binary:match(Bytes, Symbol) end,
                  forbidden_symbols()).

audit_decoded_no_forbidden(Value) when is_binary(Value) ->
    audit_no_forbidden(Value);
audit_decoded_no_forbidden(Value) when is_list(Value) ->
    lists:foreach(fun audit_decoded_no_forbidden/1, Value);
audit_decoded_no_forbidden(Value) when is_map(Value) ->
    lists:foreach(fun({Key, Child}) ->
        audit_decoded_no_forbidden(Key),
        audit_decoded_no_forbidden(Child)
    end, maps:to_list(Value));
audit_decoded_no_forbidden(_) -> ok.

canonical_line(Kind, Module, Name, Value) ->
    Semantic = strip_metadata(Value),
    iolist_to_binary([Kind, <<" ">>, Module, <<"/">>, Name, <<" ">>,
                      io_lib:format("~0p", [Semantic])]).

strip_metadata(Value) when is_map(Value) ->
    maps:map(fun(_Key, Child) -> strip_metadata(Child) end,
             maps:without([<<"documentation">>, <<"deprecation">>,
                           <<"implementations">>], Value));
strip_metadata(Value) when is_list(Value) -> lists:map(fun strip_metadata/1, Value);
strip_metadata(Value) -> Value.

bounded_lines(Bytes, Maximum) ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    true = length(Lines) =< Maximum,
    Lines.

count_line(Line, Lines) -> length([ok || Candidate <- Lines, Candidate =:= Line]).

regex_present(Bytes, Pattern) ->
    case re:run(Bytes, Pattern, [unicode]) of
        {match, _} -> true;
        nomatch -> false
    end.

release_http_archive(Report) ->
    release_http_archive_at(Report, "build/release-sim").

release_http_archive_at(Report, ExpectedRoot) ->
    true = is_map(Report),
    <<"Ready">> = maps:get(<<"status">>, Report),
    Artifacts = maps:get(<<"artifacts">>, Report),
    true = is_list(Artifacts) andalso length(Artifacts) > 0 andalso
        length(Artifacts) =< 16,
    Matches = [Artifact || Artifact <- Artifacts,
                           maps:get(<<"name">>, Artifact, undefined) =:= <<"http">>],
    [Archive] = Matches,
    Path = maps:get(<<"path">>, Archive),
    Sha = maps:get(<<"sha256">>, Archive),
    true = is_binary(Path) andalso byte_size(Path) > 0 andalso byte_size(Path) =< 512,
    true = valid_sha256(Sha),
    true = canonical_release_archive_path(binary_to_list(Path), ExpectedRoot),
    Archive.

canonical_release_archive_path(Path, ExpectedRoot) ->
    Normal = filename:split(filename:absname(Path)),
    Root = filename:split(filename:absname(ExpectedRoot)),
    case drop_prefix(Root, Normal) of
        ["run-" ++ Nonce, "pass-b", "http-0.1.0.tar"] -> valid_nonce(Nonce);
        _ -> false
    end.

drop_prefix([Part | Prefix], [Part | Path]) -> drop_prefix(Prefix, Path);
drop_prefix([], Path) -> Path;
drop_prefix(_, _) -> not_within_root.

valid_nonce(Nonce) ->
    length(Nonce) =:= 32 andalso
        lists:all(fun is_lower_hex/1, Nonce).

is_lower_hex(Character) ->
    (Character >= $0 andalso Character =< $9) orelse
        (Character >= $a andalso Character =< $f) orelse
        (Character >= $A andalso Character =< $F).

valid_sha256(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    lists:all(fun is_lower_hex/1, binary_to_list(Value));
valid_sha256(_) -> false.

audit_archive(ArchiveBytes, ExpectedSource, ExpectedFfiSource) ->
    true = byte_size(ArchiveBytes) =< ?MAX_ARCHIVE_BYTES,
    {ok, Outer0} = erl_tar:extract({binary, ArchiveBytes},
                                   [memory, {max_size, ?MAX_ARCHIVE_BYTES}]),
    Outer = normalize_members(Outer0),
    ["CHECKSUM", "VERSION", "contents.tar.gz", "metadata.config"] =
        lists:sort([Name || {Name, _} <- Outer]),
    true = length(Outer) =:= length(lists:ukeysort(1, Outer)),
    <<"3">> = member("VERSION", Outer),
    Metadata = member("metadata.config", Outer),
    true = byte_size(Metadata) =< 1024 * 1024,
    audit_no_forbidden(Metadata),
    Contents = member("contents.tar.gz", Outer),
    true = byte_size(Contents) =< ?MAX_ARCHIVE_BYTES,
    StoredChecksum = member("CHECKSUM", Outer),
    true = valid_sha256(StoredChecksum),
    StoredChecksum = digest_parts([<<"3">>, Metadata, Contents]),
    true = canonical_archive_modes(ArchiveBytes, Contents),
    {ok, Inner0} = erl_tar:extract({binary, Contents},
                                   [compressed, memory,
                                    {max_size, ?MAX_ARCHIVE_BYTES}]),
    Inner = normalize_members(Inner0),
    true = length(Inner) > 0 andalso length(Inner) =< ?MAX_ARCHIVE_FILES,
    true = length(Inner) =:= length(lists:ukeysort(1, Inner)),
    true = lists:sum([byte_size(Bytes) || {_, Bytes} <- Inner]) =<
        ?MAX_ARCHIVE_BYTES,
    lists:foreach(fun audit_distribution_member/1, Inner),
    ExpectedSource = member("src/http/ohttp.gleam", Inner),
    ExpectedFfiSource = member("src/http_ohttp_ffi.erl", Inner),
    audit_source(ExpectedSource),
    #{files => length(Inner)}.

normalize_members(Members) ->
    true = lists:all(fun
        ({Name, Bytes}) when (is_list(Name) orelse is_binary(Name)), is_binary(Bytes) -> true;
        (_) -> false
    end, Members),
    [{normalize_member_name(Name), Bytes} || {Name, Bytes} <- Members].

normalize_member_name(Name) when is_list(Name) -> normalize_slashes(Name);
normalize_member_name(Name) when is_binary(Name) ->
    normalize_slashes(unicode:characters_to_list(Name, utf8)).

audit_distribution_member({Name, Contents}) ->
    true = is_list(Name) andalso length(Name) > 0 andalso length(Name) =< 512,
    true = is_binary(Contents),
    true = filename:pathtype(Name) =:= relative,
    true = Name =:= normalize_slashes(filename:join(filename:split(Name))),
    Parts = filename:split(Name),
    true = lists:all(fun(Part) -> Part =/= "." andalso Part =/= ".." andalso
                                      Part =/= "" end, Parts),
    LowerParts = [string:lowercase(Part) || Part <- Parts],
    false = lists:any(fun(Part) -> lists:member(Part,
        ["test", "tests", "fixture", "fixtures", "build", "_build", ".git"])
                      end, LowerParts),
    LowerBase = string:lowercase(filename:basename(Name)),
    nomatch = string:find(LowerBase, "fixture"),
    nomatch = string:find(LowerBase, "_test."),
    true = allowed_distribution_path(Name),
    audit_no_forbidden(Contents).

allowed_distribution_path("LICENSE") -> true;
allowed_distribution_path("README.md") -> true;
allowed_distribution_path("gleam.toml") -> true;
allowed_distribution_path("LICENSES/" ++ Rest) ->
    Rest =/= [] andalso filename:dirname(Rest) =:= ".";
allowed_distribution_path("src/" ++ Rest) ->
    Rest =/= [] andalso lists:member(string:lowercase(filename:extension(Rest)),
                                     [".gleam", ".erl", ".hrl"]);
allowed_distribution_path(_) -> false.

normalize_slashes(Path) -> lists:flatten(string:replace(Path, "\\", "/", all)).

canonical_archive_modes(ArchiveBytes, Contents) ->
    {ok, OuterTable} = erl_tar:table({binary, ArchiveBytes}, [verbose]),
    {ok, InnerTable} = erl_tar:table({binary, Contents}, [compressed, verbose]),
    lists:all(fun
        ({_, regular, _, 0, 8#100644, 0, 0}) -> true;
        (_) -> false
    end, OuterTable ++ InnerTable).

member(Name, Members) ->
    case [Bytes || {Candidate, Bytes} <- Members, Candidate =:= Name] of
        [Bytes] -> Bytes;
        _ -> erlang:error(invalid_archive_members)
    end.

self_test() ->
    SelfTestReport = self_test_report_path(),
    invalidate(?LEGACY_SELF_TEST_REPORT),
    invalidate(SelfTestReport),
    Source = fixture_source(),
    InterfaceMap = fixture_interface(),
    Interface = encode(InterfaceMap),
    Snapshot = fixture_snapshot(InterfaceMap),
    _ = audit_api(Interface, Snapshot, Source),

    ForbiddenCases = lists:sum([begin
        expect_rejected(fun() -> audit_api(
            encode(InterfaceMap#{<<"forbidden-control">> => Symbol}), Snapshot, Source) end),
        expect_rejected(fun() -> audit_api(
            Interface, <<Snapshot/binary, Symbol/binary, "\n">>, Source) end),
        expect_rejected(fun() -> audit_api(
            Interface, Snapshot, <<Source/binary, "\n// ", Symbol/binary>>) end),
        3
    end || Symbol <- forbidden_symbols()]),
    EscapedForbidden = binary:replace(
        encode(InterfaceMap#{<<"forbidden-control">> => <<"deterministic_client">>}),
        <<"deterministic_client">>, <<"deterministic\\u005fclient">>),
    expect_rejected(fun() -> audit_api(EscapedForbidden, Snapshot, Source) end),

    Module = fixture_module(InterfaceMap),
    Functions = maps:get(<<"functions">>, Module),
    MissingFunctionCases = [begin
        Bad = replace_fixture_module(InterfaceMap,
            Module#{<<"functions">> => maps:remove(Name, Functions)}),
        expect_rejected(fun() -> audit_api(encode(Bad), Snapshot, Source) end),
        1
    end || Name <- required_functions()],
    Error = maps:get(<<"Error">>, maps:get(<<"types">>, Module)),
    ErrorWithoutContext = Error#{<<"constructors">> => []},
    BadTypes = (maps:get(<<"types">>, Module))#{<<"Error">> => ErrorWithoutContext},
    MissingContext = replace_fixture_module(InterfaceMap, Module#{<<"types">> => BadTypes}),
    expect_rejected(fun() -> audit_api(encode(MissingContext), Snapshot, Source) end),

    ContractLines = binary:split(Snapshot, <<"\n">>, [global]),
    SnapshotCases = [begin
        Reduced = join_lines([Line || Line <- ContractLines, Line =/= Removed]),
        expect_rejected(fun() -> audit_api(Interface, Reduced, Source) end),
        1
    end || Removed <- [<<"module http http/ohttp">> |
                       fixture_contract_lines(InterfaceMap)]],
    SourceCases = [begin
        expect_rejected(fun() -> audit_source(BadSource) end),
        1
    end || BadSource <- [
        <<"pub type Error { ContextReuseDetected }\n",
          "pub fn seal_response_bytes() { Nil }\n">>,
        <<"pub type Error { ContextReuseDetected }\n",
          "pub fn client() { Nil }\n">>,
        <<"pub type Error { Other }\n",
          "pub fn client() { Nil }\n",
          "pub fn seal_response_bytes() { Nil }\n">>
    ]],
    ChangedClient = (maps:get(<<"client">>, Functions))#{<<"return">> => <<"changed">>},
    ChangedFunctions = Functions#{<<"client">> => ChangedClient},
    ChangedInterface = replace_fixture_module(InterfaceMap,
        Module#{<<"functions">> => ChangedFunctions}),
    expect_rejected(fun() -> audit_api(encode(ChangedInterface), Snapshot, Source) end),

    Nonce = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))),
    SelfTestRoot = filename:join(["build", "ohttp-distribution", "self-test-runs"]),
    ArchivePath = filename:join([SelfTestRoot, "run-" ++ Nonce,
                                 "pass-b", "http-0.1.0.tar"]),
    ok = filelib:ensure_dir(ArchivePath),
    GoodArchive = test_archive(ArchivePath, Source, [], 8#100644, valid),
    FfiSource = fixture_ffi_source(),
    #{files := GoodFiles} = audit_archive(GoodArchive, Source, FfiSource),
    ArchiveSha = digest(GoodArchive),
    Artifact = #{<<"name">> => <<"http">>,
                 <<"path">> => unicode:characters_to_binary(ArchivePath),
                 <<"sha256">> => ArchiveSha},
    ReleaseReport = #{<<"status">> => <<"Ready">>,
                      <<"artifacts">> => [Artifact]},
    Artifact = release_http_archive_at(ReleaseReport, SelfTestRoot),
    expect_rejected(fun() -> release_http_archive(ReleaseReport) end),

    WrongSource = <<Source/binary, "\n// archive-source-drift">>,
    expect_rejected(fun() -> audit_archive(GoodArchive, WrongSource, FfiSource) end),
    expect_rejected(fun() -> audit_archive(
        GoodArchive, Source, <<FfiSource/binary, "\n% archive-ffi-drift">>) end),
    expect_rejected(fun() -> audit_inner_for_test([
        {"src/http/ohttp.gleam", Source},
        {"src/http_ohttp_ffi.erl", FfiSource},
        {"src/extra.gleam", <<"// deterministic_client\n">>}
    ], Source, FfiSource) end),
    expect_rejected(fun() -> audit_distribution_member(
        {"src/http_ohttp_ffi.erl", <<"new_deterministic_claim() -> ok.\n">>}) end),
    BadPathCases = [begin
        expect_rejected(fun() -> audit_distribution_member({Path, <<>>}) end),
        1
    end || Path <- ["test/ohttp_test.gleam", "src/ohttp_fixture.gleam",
                    "src/ohttp_test.gleam", "build/ohttp.beam"]],

    BadChecksumPath = filename:join(filename:dirname(ArchivePath), "bad-checksum.tar"),
    BadChecksum = test_archive(BadChecksumPath, Source, [], 8#100644, invalid),
    expect_rejected(fun() -> audit_archive(BadChecksum, Source, FfiSource) end),
    BadModePath = filename:join(filename:dirname(ArchivePath), "bad-mode.tar"),
    BadMode = archive_header_mutation(GoodArchive, 100, <<"0000600", 0>>),
    ok = file:write_file(BadModePath, BadMode, [exclusive]),
    expect_rejected(fun() -> audit_archive(BadMode, Source, FfiSource) end),
    BadMemberPath = filename:join(filename:dirname(ArchivePath), "bad-member.tar"),
    BadMember = test_archive(BadMemberPath, Source,
        [{"test/ohttp_test.gleam", <<"test">>}], 8#100644, valid),
    expect_rejected(fun() -> audit_archive(BadMember, Source, FfiSource) end),

    ReleaseMutations = [
        ReleaseReport#{<<"status">> => <<"Running">>},
        ReleaseReport#{<<"artifacts">> => [Artifact#{<<"sha256">> =>
            binary:copy(<<"0">>, 64)}]},
        ReleaseReport#{<<"artifacts">> => [Artifact, Artifact]},
        ReleaseReport#{<<"artifacts">> => [Artifact#{<<"path">> =>
            <<"build/ohttp-distribution/http-0.1.0.tar">>}]},
        ReleaseReport#{<<"artifacts">> => []}
    ],
    lists:foreach(fun(BadReport) ->
        expect_rejected(fun() ->
            A = release_http_archive_at(BadReport, SelfTestRoot),
            P = binary_to_list(maps:get(<<"path">>, A)),
            B = read_limited(P, ?MAX_ARCHIVE_BYTES),
            Reported = maps:get(<<"sha256">>, A),
            Reported = digest(B)
        end)
    end, ReleaseMutations),
    expect_rejected(fun() -> evidence_json_decode(
        <<"{\"name\":\"http\",\"na\\u006de\":\"forged\"}">>) end),

    Controls = ForbiddenCases + 1 + lists:sum(MissingFunctionCases) + 1 +
        lists:sum(SnapshotCases) + lists:sum(SourceCases) + 1 + 4 +
        lists:sum(BadPathCases) + 3 + length(ReleaseMutations) + 2,
    cleanup_self_test_archives(
        [ArchivePath, BadChecksumPath, BadModePath, BadMemberPath]),
    ensure_gate_identity_unchanged(),
    Report = (base_report(<<"adversarial-self-test">>, Source))#{
         controls => Controls, positive_api_contract => true,
         positive_canonical_archive => true, positive_archive_files => GoodFiles,
         duplicate_json_keys_rejected => true,
         rebound_release_inputs_rejected => true,
         temporary_archives_removed => true,
         completion => #{completed => Controls + 3,
                         expected => Controls + 3},
         rerun_command =>
             <<"escript scripts/ohttp_distribution_audit.escript --self-test">>},
    write_report(SelfTestReport, Report),
    io:format("OHTTP distribution audit: ~B adversarial controls passed~n", [Controls]).

cleanup_self_test_archives(Paths) ->
    lists:foreach(fun(Path) -> ok = file:delete(Path) end, Paths),
    PassDirectory = filename:dirname(hd(Paths)),
    RunDirectory = filename:dirname(PassDirectory),
    ok = file:del_dir(PassDirectory),
    ok = file:del_dir(RunDirectory).

fixture_source() ->
    <<"pub type Error {\n  ContextReuseDetected\n}\n\n",
      "pub fn client() { Nil }\n\n",
      "pub fn seal_response_bytes() { Nil }\n">>.

fixture_ffi_source() ->
    <<"-module(http_ohttp_ffi).\n",
      "-export([new_context_claim/0, claim_context/1]).\n",
      "new_context_claim() -> make_ref().\n",
      "claim_context(_) -> true.\n">>.

fixture_interface() ->
    Function = #{<<"documentation">> => null, <<"deprecation">> => null,
                 <<"implementations">> => #{<<"gleam">> => true},
                 <<"parameters">> => [], <<"return">> => <<"Nil">>},
    Error = #{<<"documentation">> => null, <<"deprecation">> => null,
              <<"parameters">> => 0,
              <<"constructors">> => [#{<<"documentation">> => null,
                  <<"name">> => <<"ContextReuseDetected">>,
                  <<"parameters">> => []}]},
    #{<<"name">> => <<"http">>,
      <<"modules">> => #{<<"http/ohttp">> => #{
          <<"functions">> => #{<<"client">> => Function,
                                <<"seal_response_bytes">> => Function},
          <<"types">> => #{<<"Error">> => Error}}}}.

fixture_module(Interface) ->
    maps:get(<<"http/ohttp">>, maps:get(<<"modules">>, Interface)).

replace_fixture_module(Interface, Module) ->
    Interface#{<<"modules">> => #{<<"http/ohttp">> => Module}}.

fixture_contract_lines(Interface) ->
    Module = fixture_module(Interface),
    Functions = maps:get(<<"functions">>, Module),
    Types = maps:get(<<"types">>, Module),
    [canonical_line(<<"function">>, <<"http/ohttp">>, Name,
                    maps:get(Name, Functions)) || Name <- required_functions()] ++
        [canonical_line(<<"type">>, <<"http/ohttp">>, <<"Error">>,
                        maps:get(<<"Error">>, Types))].

fixture_snapshot(Interface) ->
    join_lines([<<"module http http/ohttp">> | fixture_contract_lines(Interface)]).

join_lines(Lines) -> iolist_to_binary([lists:join(<<"\n">>, Lines), <<"\n">>]).

test_archive(Path, Source, Extra, Mode, ChecksumMode) ->
    Inner = [{"LICENSE", <<"fixture license">>},
             {"README.md", <<"fixture package">>},
             {"gleam.toml", <<"name = \"http\"\nversion = \"0.1.0\"\n">>},
             {"src/http/ohttp.gleam", Source},
             {"src/http_ohttp_ffi.erl", fixture_ffi_source()} | Extra],
    ContentPath = Path ++ ".contents.tar.gz",
    Options = [compressed, {mtime, 0}, {atime, 0}, {ctime, 0},
               {uid, 0}, {gid, 0}, {mode, Mode}],
    ok = erl_tar:create(ContentPath, Inner, Options),
    Contents = read_limited(ContentPath, ?MAX_ARCHIVE_BYTES),
    ok = file:delete(ContentPath),
    Metadata = <<"fixture metadata">>,
    Actual = digest_parts([<<"3">>, Metadata, Contents]),
    Checksum = case ChecksumMode of
        valid -> Actual;
        invalid -> binary:copy(<<"0">>, 64)
    end,
    ok = erl_tar:create(Path,
        [{"VERSION", <<"3">>}, {"metadata.config", Metadata},
         {"contents.tar.gz", Contents}, {"CHECKSUM", Checksum}],
        [{mtime, 0}, {atime, 0}, {ctime, 0}, {uid, 0}, {gid, 0},
         {mode, Mode}]),
    read_limited(Path, ?MAX_ARCHIVE_BYTES).

archive_header_mutation(<<Header:512/binary, Rest/binary>>, Offset, Field) ->
    Length = byte_size(Field),
    <<Before:Offset/binary, _:Length/binary, After/binary>> = Header,
    Patched = <<Before/binary, Field/binary, After/binary>>,
    <<Start:148/binary, _:8/binary, End/binary>> = Patched,
    Sum = lists:sum(binary_to_list(<<Start/binary, "        ", End/binary>>)),
    Octal = integer_to_binary(Sum, 8),
    Padding = binary:copy(<<"0">>, 6 - byte_size(Octal)),
    <<Start/binary, Padding/binary, Octal/binary, 0, 32,
      End/binary, Rest/binary>>.

%% A narrow seam lets the self-test mutate the already-extracted member set.
%% The production command always reaches this policy through audit_archive/2.
audit_inner_for_test(Inner, ExpectedSource, ExpectedFfiSource) ->
    lists:foreach(fun audit_distribution_member/1, Inner),
    ExpectedSource = member("src/http/ohttp.gleam", Inner),
    ExpectedFfiSource = member("src/http_ohttp_ffi.erl", Inner),
    audit_source(ExpectedSource).

expect_rejected(Action) ->
    case try Action(), accepted catch _:_ -> rejected end of
        rejected -> ok;
        accepted -> erlang:error(adversarial_control_accepted)
    end.

read_limited(Path, Maximum) ->
    {ok, File} = file:open(Path, [read, binary, raw]),
    try
        {ok, Bytes} = file:read(File, Maximum + 1),
        true = byte_size(Bytes) =< Maximum,
        eof = file:read(File, 1),
        Bytes
    after
        ok = file:close(File)
    end.

unchanged(Path, Maximum, Expected) ->
    Expected = read_limited(Path, Maximum),
    ok.

digest(Bytes) -> binary:encode_hex(crypto:hash(sha256, Bytes)).
digest_parts(Parts) -> binary:encode_hex(crypto:hash(sha256, Parts)).
encode(Value) -> iolist_to_binary(json:encode(Value)).

invalidate(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_invalidate_old_ohttp_gate_report)
    end.

write_report(Path, Report) ->
    ok = filelib:ensure_dir(Path),
    Temporary = Path ++ ".tmp-" ++
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))),
    try
        ok = file:write_file(Temporary, json:encode(Report), [exclusive]),
        ok = file:rename(Temporary, Path)
    after
        _ = file:delete(Temporary)
    end.

preserve_failure(Arguments) ->
    case failure_destination(Arguments) of
        none -> ok;
        {Path, Scope, Rerun} ->
            try
                invalidate(Path),
                Identity = case get(ohttp_gate_identity) of
                    Value when is_map(Value) -> Value;
                    _ -> unavailable
                end,
                write_report(Path, #{schema => 1, status => <<"Failed">>,
                    gate => <<"ohttp-entropy-boundary-v1">>, scope => Scope,
                    classification => <<"contract_violation">>,
                    details_retained => false, tool_identity => Identity,
                    input_identity => failure_input_identity(Arguments),
                    completion => #{completed => 0, expected => 1},
                    rerun_command => Rerun})
            catch _:_ -> ok end
    end.

failure_input_identity(["--api"]) ->
    #{source_sha256 => safe_digest(?SOURCE, ?MAX_SOURCE_BYTES),
      ffi_source_sha256 => safe_digest(?FFI_SOURCE, ?MAX_SOURCE_BYTES),
      interface_sha256 => safe_digest(?INTERFACE, ?MAX_INTERFACE_BYTES),
      snapshot_sha256 => safe_digest(?SNAPSHOT, ?MAX_SNAPSHOT_BYTES)};
failure_input_identity(["--release"]) ->
    #{source_sha256 => safe_digest(?SOURCE, ?MAX_SOURCE_BYTES),
      ffi_source_sha256 => safe_digest(?FFI_SOURCE, ?MAX_SOURCE_BYTES),
      release_report_sha256 =>
          safe_digest(?RELEASE_SIM_REPORT, ?MAX_RELEASE_REPORT_BYTES)};
failure_input_identity(["--self-test"]) ->
    #{source_sha256 => safe_digest(?SOURCE, ?MAX_SOURCE_BYTES)};
failure_input_identity(_) -> #{}.

safe_digest(Path, Maximum) ->
    try digest(read_limited(Path, Maximum)) catch _:_ -> null end.

failure_destination(["--api"]) ->
    {?API_REPORT, <<"compiler-interface-and-snapshot">>,
     <<"escript scripts/ohttp_distribution_audit.escript --api">>};
failure_destination(["--release"]) ->
    {?RELEASE_REPORT, <<"canonical-hex-archive">>,
     <<"escript scripts/ohttp_distribution_audit.escript --release">>};
failure_destination(["--self-test"]) ->
    {self_test_report_path(), <<"adversarial-self-test">>,
     <<"escript scripts/ohttp_distribution_audit.escript --self-test">>};
failure_destination(_) -> none.

self_test_report_path() ->
    "build/ohttp-distribution/self-test-otp-" ++
        erlang:system_info(otp_release) ++ ".json".
