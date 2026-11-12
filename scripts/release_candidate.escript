#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("bundle_capture.hrl").
-include("command_capture.hrl").
-compile({nowarn_unused_function, [{evidence_begin, 1}, {evidence_require_identity, 2},
    {evidence_complete, 2}, {execution_runtime, 0}, {bundle_validate_capture, 3},
    {bundle_root_files, 0}, {bundle_tree, 1}, {bundle_walk, 4},
    {bundle_directory_components, 2}, {bundle_entries, 1}, {bundle_archive, 2}]}).

main([]) -> candidate_safe(fun run/0);
main(["--self-test"]) -> candidate_safe(fun identity_self_test/0);
main(_) -> erlang:error(release_candidate_usage).

candidate_safe(Action) ->
    try Action() catch Class:Reason:Stack ->
        io:format(standard_error, "release candidate failed: ~p~n",
                  [diagnostic_failure_details(Class, Reason, Stack)]),
        halt(1)
    end.

run() ->
    SourceCandidate = source_candidate(),
    Attestation = audit_attestation(SourceCandidate),
    SignedCommit = verify_signed_commit(),
    Ready = maps:get(valid, SourceCandidate)
            andalso maps:get(valid, Attestation)
            andalso maps:get(valid, SignedCommit),
    Status = case Ready of true -> <<"Ready">>;
                               false -> <<"ExternalPending">> end,
    Report = #{status => Status, source_candidate => SourceCandidate,
               independent_audit => Attestation,
               signed_commit => SignedCommit,
               publication_performed => false,
               tag_performed => false, push_performed => false,
               version_changed => false},
    Path = "build/release-candidate/report.json",
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    case Ready of
        true ->
            io:put_chars("release-candidate external conditions verified\n"),
            ok;
        false ->
            io:format(standard_error,
                      "release-candidate: ExternalPending (source candidate: ~p, "
                      "independent audit: ~p, signed candidate commit: ~p)~n",
                      [maps:get(valid, SourceCandidate),
                       maps:get(valid, Attestation),
                       maps:get(valid, SignedCommit)]),
            halt(1)
    end.

source_candidate() ->
    ManifestPath = "build/audit-bundle/manifest.json",
    ArchiveReportPath = "build/audit-bundle/archive.json",
    ArchivePath = "build/audit-bundle/audit-bundle.tar",
    case {file:read_file(ManifestPath), file:read_file(ArchiveReportPath),
          file:read_file(ArchivePath)} of
        {{ok, ManifestBytes}, {ok, ArchiveReportBytes}, {ok, ArchiveBytes}} ->
            try
                Manifest = evidence_json_decode(ManifestBytes),
                ArchiveReport = evidence_json_decode(ArchiveReportBytes),
                SourceSha = maps:get(<<"source_sha256">>, Manifest, <<>>),
                ArchiveSha = maps:get(<<"sha256">>, ArchiveReport, <<>>),
                CurrentIdentity = evidence_identity(),
                CurrentSourceSha = maps:get(<<"source_sha256">>, CurrentIdentity),
                ActualArchiveSha = hex(crypto:hash(sha256, ArchiveBytes)),
                Valid = maps:get(<<"schema">>, Manifest, undefined) =:= 2
                        andalso maps:get(<<"schema">>, ArchiveReport, undefined) =:= 2
                        andalso maps:get(<<"status">>, Manifest, undefined)
                        =:= <<"Ready">>
                        andalso maps:get(<<"status">>, ArchiveReport,
                                         undefined) =:= <<"Ready">>
                        andalso SourceSha =:= CurrentSourceSha
                        andalso maps:get(<<"evidence_identity">>, Manifest, undefined) =:= CurrentIdentity
                        andalso maps:get(<<"evidence_identity">>, ArchiveReport, undefined) =:= CurrentIdentity
                        andalso maps:get(<<"manifest_sha256">>, ArchiveReport, undefined)
                            =:= hex(crypto:hash(sha256, ManifestBytes))
                        andalso ArchiveSha =:= ActualArchiveSha,
                #{valid => Valid, source_sha256 => SourceSha,
                  archive_sha256 => ActualArchiveSha}
            catch
                _:_ -> #{valid => false, reason => <<"invalid-evidence">>}
            end;
        _ -> #{valid => false, reason => <<"missing">>}
    end.

audit_attestation(SourceCandidate) ->
    Path = "audit/third-party-attestation.json",
    SignaturePath = "audit/third-party-attestation.json.sig",
    KeyringPath = "audit/trusted-auditors.gpg",
    case {file:read_file(Path), filelib:is_regular(SignaturePath),
          filelib:is_regular(KeyringPath)} of
        {{error, enoent}, _, _} ->
            #{valid => false, reason => <<"missing">>};
        {{ok, _}, false, _} ->
            #{valid => false, reason => <<"missing-detached-signature">>};
        {{ok, _}, _, false} ->
            #{valid => false, reason => <<"missing-trusted-keyring">>};
        {{error, Reason}, _, _} ->
            #{valid => false,
              reason => unicode:characters_to_binary(
                  io_lib:format("~p", [Reason]))};
        {{ok, Bytes}, true, true} ->
            verify_attestation(Bytes, Path, SignaturePath, KeyringPath,
                               SourceCandidate)
    end.

verify_attestation(Bytes, Path, SignaturePath, KeyringPath, SourceCandidate) ->
    try json:decode(Bytes) of
        Value ->
            Auditor = maps:get(<<"auditor">>, Value, <<>>),
            SourceSha = maps:get(<<"source_sha256">>, Value, <<>>),
            Signature = verify_detached_signature(KeyringPath, SignaturePath,
                                                  Path),
            Valid = maps:get(valid, SourceCandidate)
                    andalso maps:get(<<"status">>, Value, undefined)
                            =:= <<"Attested">>
                    andalso is_binary(Auditor) andalso byte_size(Auditor) > 0
                    andalso SourceSha
                            =:= maps:get(source_sha256, SourceCandidate, <<>>)
                    andalso maps:get(valid, Signature),
            #{valid => Valid, path => list_to_binary(Path),
              sha256 => hex(crypto:hash(sha256, Bytes)),
              signature => Signature}
    catch
        _:_ -> #{valid => false, reason => <<"invalid-json">>}
    end.

verify_detached_signature(KeyringPath, SignaturePath, StatementPath) ->
    case run_executable("gpgv", ["--keyring", KeyringPath, SignaturePath,
                                  StatementPath]) of
        {unavailable, _} ->
            #{valid => false, reason => <<"gpgv-unavailable">>};
        {Status, Output} ->
            #{valid => Status =:= 0,
              verification_output_sha256 =>
                  hex(crypto:hash(sha256, Output))}
    end.

verify_signed_commit() ->
    case run_executable("git", ["verify-commit", "HEAD"]) of
        {unavailable, _} ->
            #{valid => false, reason => <<"git-unavailable">>};
        {VerifyStatus, VerifyOutput} ->
            {TreeStatus, TreeOutput} = run_executable(
                "git", ["status", "--porcelain=v1", "--untracked-files=normal"]),
            Clean = TreeStatus =:= 0 andalso TreeOutput =:= <<>>,
            #{valid => VerifyStatus =:= 0 andalso Clean,
              commit_signature_valid => VerifyStatus =:= 0,
              candidate_worktree_clean => Clean,
              verification_output_sha256 =>
                  hex(crypto:hash(sha256, VerifyOutput)),
              worktree_status_sha256 =>
                  hex(crypto:hash(sha256, TreeOutput))}
    end.

run_executable(Name, Args) ->
    case os:find_executable(Name) of
        false -> {unavailable, <<>>};
        Executable ->
            case command_capture(Executable, Args, filename:absname("."),
                                 30000, 16777216, []) of
                {ok, Output, _Proof} -> {0, Output};
                {error, Proof} -> {command_failure_status(Proof), <<>>}
            end
    end.

command_failure_status(#{exit_status := Status}) when is_integer(Status) -> Status;
command_failure_status(#{outcome := deadline}) -> 124;
command_failure_status(#{outcome := output_limit}) -> 125;
command_failure_status(#{outcome := reap_failed}) -> 126;
command_failure_status(_) -> 127.

source_digest() ->
    maps:get(<<"source_sha256">>, evidence_identity()).

identity_self_test() ->
    Paths = evidence_source_paths(),
    false = lists:member("erl_crash.dump", Paths),
    Captured = bundle_capture(Paths),
    Directory = "build/release-candidate-self-test/run-" ++
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))),
    bundle_materialize(Directory, Captured),
    bundle_with_directory(Directory, fun() ->
        Before = source_digest(),
        ok = file:write_file("erl_crash.dump", <<"private-crash-marker">>),
        Before = source_digest(),
        {"src/http.gleam", Source} = lists:keyfind("src/http.gleam", 1, Captured),
        ok = file:write_file("src/http.gleam", [Source, <<"\n// changed authored input\n">>]),
        true = Before =/= source_digest(),
        ok = file:write_file("src/http.gleam", Source),
        Before = source_digest(),
        identity_publication_self_test(),
        io:put_chars("release candidate identity: crash dump excluded; authored changes and mismatched publication rejected\n")
    end).

identity_publication_self_test() ->
    Identity = evidence_identity(),
    Manifest = #{schema => 2, status => <<"Ready">>, evidence_identity => Identity,
        source_sha256 => maps:get(<<"source_sha256">>, Identity)},
    ManifestBytes = iolist_to_binary(json:encode(Manifest)),
    ArchiveBytes = <<"isolated identity fixture">>,
    Archive = #{schema => 2, status => <<"Ready">>, evidence_identity => Identity,
        sha256 => hex(crypto:hash(sha256, ArchiveBytes)),
        manifest_sha256 => hex(crypto:hash(sha256, ManifestBytes))},
    ok = filelib:ensure_dir("build/audit-bundle/manifest.json"),
    ok = file:write_file("build/audit-bundle/manifest.json", ManifestBytes),
    ok = file:write_file("build/audit-bundle/archive.json", json:encode(Archive)),
    ok = file:write_file("build/audit-bundle/audit-bundle.tar", ArchiveBytes),
    #{valid := true} = source_candidate(),
    ok = file:write_file("build/audit-bundle/manifest.json", json:encode(Manifest#{files => []})),
    #{valid := false} = source_candidate(),
    ok = file:write_file("build/audit-bundle/manifest.json", ManifestBytes),
    ok = file:write_file("build/audit-bundle/archive.json", json:encode(Archive#{evidence_identity => #{}})),
    #{valid := false} = source_candidate(),
    ok.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).
