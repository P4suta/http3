%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% Shared, archive-compatible identity for executable qualification evidence.
%% Paths are explicit repository families, never a user's home or local cache.
-include("diagnostic_failure.hrl").
-include("file_identity.hrl").
-include("execution_identity.hrl").
-include("json_evidence.hrl").
-compile({nowarn_unused_function, [{evidence_complete, 2}]}).
evidence_begin(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_invalidate_prior_evidence)
    end,
    evidence_identity().

evidence_identity() ->
    Paths = evidence_source_paths(),
    Digest = evidence_digest_files(Paths),
    evidence_ensure(Paths =:= evidence_source_paths(),
                    source_set_changed_while_identifying),
    #{<<"schema">> => 2,
      <<"source_sha256">> => Digest,
      <<"files">> => length(Paths)}.

evidence_source_paths() ->
    Roots = evidence_source_roots(),
    Static = evidence_static_source_paths(),
    Discovered = lists:append([evidence_tree_files(Root) || Root <- Roots]),
    %% CONFORMANCE is generated from these very reports; including it would
    %% make qualification depend on its own output. All authored docs remain
    %% inputs, including executable examples and migration contracts.
    Paths = lists:usort([Path || Path <- Static ++ Discovered,
                                 Path =/= "docs/CONFORMANCE.md"]),
    evidence_ensure(length(Paths) =< 100000, source_entry_limit),
    Normalized = [evidence_portable_path_key(Path)
                  || Path <- Paths],
    evidence_ensure(length(Normalized) =:= length(lists:usort(Normalized)),
                    source_case_collision),
    lists:foreach(fun(Path) -> _ = evidence_regular_info(Path) end, Paths),
    Paths.

-spec evidence_source_roots() -> [string()].
evidence_source_roots() ->
    ["src", "test", "scripts", "standards", "api", ".github", "LICENSES",
             "docs", "packages/http3/docs", "packages/quic_core/docs",
             "packages/http3/benchmarks", "packages/http3/LICENSES", "packages/quic_core/LICENSES",
             "packages/http3/src", "packages/http3/test",
             "packages/quic_core/src", "packages/quic_core/test"].

-spec evidence_static_source_paths() -> [string()].
evidence_static_source_paths() ->
    [".mise.toml", ".gitattributes", "qualification.json", "coverage-policy.json",
              "README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "SUPPORT.md", "CLAUDE.md",
              "LICENSE", "REUSE.toml", "docs/V1.md", "_typos.toml", ".gitignore", ".gitleaksignore",
              ".markdownlint-cli2.yaml", ".osv-scanner.toml", ".semgrep.yml", ".taplo.toml",
              "gleam.toml", "manifest.toml", "mix.exs", "mix.lock",
              "packages/http3/gleam.toml", "packages/http3/manifest.toml", "packages/http3/README.md", "packages/http3/LICENSE",
              "packages/http3/mix.exs", "packages/http3/mix.lock", "packages/quic_core/mix.exs",
              "packages/quic_core/gleam.toml", "packages/quic_core/manifest.toml", "packages/quic_core/README.md", "packages/quic_core/LICENSE"].

evidence_digest_files(Paths) ->
    evidence_ensure(Paths =:= lists:usort(Paths), duplicate_source_path),
    file_identity_digest(Paths, fun evidence_read_source/1, uppercase).

evidence_read_source(Path) ->
    Initial = evidence_regular_info(Path),
    Size = element(2, Initial),
    evidence_ensure(is_integer(Size) andalso Size >= 0 andalso
                    Size =< 134217728, source_size_rejected),
    evidence_ensure(element(9, Initial) =:= 1, source_hardlink_rejected),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> erlang:error(source_read_failed)
    end,
    {Bytes, Finished} = try
        Opened = evidence_handle_info(File),
        evidence_ensure(element(3, Opened) =:= regular andalso
                        element(9, Opened) =:= 1 andalso
                        evidence_file_identity(Initial) =:=
                            evidence_file_identity(Opened),
                        source_changed_while_reading),
        Captured = evidence_read_bounded(File, Size, []),
        FinalHandle = evidence_handle_info(File),
        evidence_ensure(evidence_file_identity(Opened) =:=
                            evidence_file_identity(FinalHandle) andalso
                        byte_size(Captured) =:= Size,
                        source_changed_while_reading),
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = evidence_regular_info(Path),
    evidence_ensure(evidence_file_identity(Finished) =:=
                        evidence_file_identity(FinalPath),
                    source_changed_while_reading),
    Bytes.

evidence_tree_files(Root) ->
    {_Remaining, Files} = evidence_walk_tree(Root, 0, 100000, []),
    lists:sort(Files).

evidence_walk_tree(Path, Depth, Remaining, Acc) ->
    evidence_ensure(Depth =< 64, source_tree_depth_limit),
    Before = evidence_directory_info(Path),
    Names = case file:list_dir(Path) of
        {ok, Entries} -> lists:sort(Entries);
        {error, _} -> erlang:error(source_tree_read_failed)
    end,
    evidence_ensure(length(Names) =< Remaining, source_entry_limit),
    Result = lists:foldl(fun(Name, {Left, Paths}) ->
        evidence_ensure(Left > 0, source_entry_limit),
        evidence_ensure(Name =/= "" andalso Name =/= "." andalso
                        Name =/= "..", unsafe_source_path),
        Member = filename:join(Path, Name),
        case file:read_link_info(Member) of
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= directory ->
                evidence_walk_tree(Member, Depth + 1, Left - 1, Paths);
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= regular ->
                {Left - 1, [Member | Paths]};
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= symlink ->
                erlang:error(source_tree_link_rejected);
            {ok, _} -> erlang:error(source_tree_special_file_rejected);
            {error, enoent} -> erlang:error(source_tree_changed_while_reading);
            {error, _} -> erlang:error(source_tree_inspection_failed)
        end
    end, {Remaining, Acc}, Names),
    After = evidence_directory_info(Path),
    evidence_ensure(evidence_file_identity(Before) =:=
                        evidence_file_identity(After),
                    source_tree_changed_while_reading),
    Result.

evidence_read_bounded(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            evidence_read_bounded(File, Remaining - byte_size(Chunk),
                                  [Chunk | Acc]);
        {ok, _} -> erlang:error(source_changed_while_reading);
        {error, _} -> erlang:error(source_read_failed)
    end.

evidence_handle_info(File) ->
    case file:read_file_info(File) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(source_inspection_failed)
    end.

evidence_regular_info(Path) ->
    evidence_regular_components(filename:split(filename:absname(Path)), "").

evidence_regular_components([Name], Parent) ->
    Current = evidence_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(source_link_rejected);
        {ok, _} -> erlang:error(source_special_file_rejected);
        {error, enoent} -> erlang:error(source_missing);
        {error, _} -> erlang:error(source_inspection_failed)
    end;
evidence_regular_components([Name | Rest], Parent) ->
    Current = evidence_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            evidence_regular_components(Rest, Current);
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(source_parent_link_rejected);
        {ok, _} -> erlang:error(source_parent_rejected);
        {error, enoent} -> erlang:error(source_missing);
        {error, _} -> erlang:error(source_inspection_failed)
    end;
evidence_regular_components([], _) -> erlang:error(unsafe_source_path).

evidence_directory_info(Path) ->
    evidence_directory_components(filename:split(filename:absname(Path)), "").

evidence_directory_components([], _) -> erlang:error(unsafe_source_path);
evidence_directory_components([Name | Rest], Parent) ->
    Current = evidence_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case Rest of
                [] -> Info;
                _ -> evidence_directory_components(Rest, Current)
            end;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(source_tree_link_rejected);
        {ok, _} -> erlang:error(source_tree_special_file_rejected);
        {error, enoent} -> erlang:error(source_tree_missing);
        {error, _} -> erlang:error(source_tree_inspection_failed)
    end.

evidence_join_component("", Name) -> Name;
evidence_join_component(Parent, Name) -> filename:join(Parent, Name).

evidence_file_identity(Info) ->
    %% Access time is intentionally excluded because verification reads may
    %% update it.  The remaining identity fields catch mutation/replacement.
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

evidence_normalized_path(Path) ->
    [case Character of $\\ -> $/; _ -> Character end || Character <- Path].

evidence_portable_path_key(Path) ->
    Normalized = unicode:characters_to_nfc_binary(
        evidence_normalized_path(Path)),
    unicode:characters_to_nfc_binary(string:casefold(Normalized)).

evidence_ensure(true, _) -> ok;
evidence_ensure(false, Reason) -> erlang:error(Reason).

evidence_require_identity(Report, Current) ->
    case maps:get(<<"evidence_identity">>, Report, undefined) of
        Current -> ok;
        _ -> erlang:error(stale_or_missing_evidence_identity)
    end.

evidence_complete(Report, Initial) ->
    evidence_require_identity(#{<<"evidence_identity">> => Initial},
                              evidence_identity()),
    Report#{evidence_identity => Initial,
            execution_environment => execution_runtime()}.
