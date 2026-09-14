#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main([]) -> run();
main(_) -> erlang:error(release_candidate_usage).

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
                Manifest = json:decode(ManifestBytes),
                ArchiveReport = json:decode(ArchiveReportBytes),
                SourceSha = maps:get(<<"source_sha256">>, Manifest, <<>>),
                ArchiveSha = maps:get(<<"sha256">>, ArchiveReport, <<>>),
                CurrentSourceSha = source_digest(),
                ActualArchiveSha = hex(crypto:hash(sha256, ArchiveBytes)),
                Valid = maps:get(<<"status">>, Manifest, undefined)
                        =:= <<"Ready">>
                        andalso maps:get(<<"status">>, ArchiveReport,
                                         undefined) =:= <<"Ready">>
                        andalso SourceSha =:= CurrentSourceSha
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
            Port = open_port({spawn_executable, Executable},
                             [binary, exit_status, use_stdio, stderr_to_stdout,
                              {args, Args}, {cd, filename:absname(".")}]),
            {Status, Output} = collect(Port, []),
            {Status, iolist_to_binary(lists:reverse(Output))}
    end.

source_digest() ->
    Paths = source_paths(),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

source_paths() ->
    {ok, Entries} = file:list_dir("."),
    lists:sort(lists:append([collect_source_path(Entry) || Entry <- Entries])).

collect_source_path(Path) ->
    case filelib:is_dir(Path) of
        true ->
            case excluded_source_directory(filename:basename(Path)) of
                true -> [];
                false ->
                    {ok, Entries} = file:list_dir(Path),
                    lists:append([
                        collect_source_path(filename:join(Path, Entry))
                        || Entry <- Entries
                    ])
            end;
        false ->
            case filelib:is_regular(Path) of
                true -> [Path];
                false -> []
            end
    end.

excluded_source_directory(Name) ->
    lists:member(Name, [".agents", ".claude", ".codex", ".git", ".idea",
                        ".vscode", "_build", "audit", "build", "deps"]).

read(Path) ->
    {ok, Bytes} = file:read_file(Path),
    Bytes.

collect(Port, Output) ->
    receive
        {Port, {data, Bytes}} -> collect(Port, [Bytes | Output]);
        {Port, {exit_status, Status}} -> {Status, Output}
    after 30000 ->
        port_close(Port),
        {124, Output}
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).
