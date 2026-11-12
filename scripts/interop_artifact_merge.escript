#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% Assemble independently downloaded interoperability artifacts without
%% allowing the artifact client to overwrite colliding paths.
-include("evidence_identity.hrl").
-include("artifact_merge_evidence.hrl").

-define(MAX_FILES, 8192).
-define(MAX_ENTRIES, 16384).
-define(MAX_DEPTH, 64).
-define(MAX_PATH_BYTES, 4096).
-define(MAX_FILE_BYTES, 134217728).
-define(MAX_TOTAL_BYTES, 536870912).
-define(MAX_RECEIPT_BYTES, 1048576).

main(Arguments) ->
    try dispatch(Arguments) of
        ok -> ok
    catch Class:Reason:Stacktrace ->
        io:format(standard_error, "interop artifact merge failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stacktrace))]),
        halt(1)
    end.

dispatch(["--self-test"]) -> merge_self_test();
dispatch(["campaign", Mode]) when Mode =:= "model"; Mode =:= "property";
                                      Mode =:= "fuzz" ->
    merge_campaign_run(Mode);
dispatch(["credential"]) -> merge_credential_run();
dispatch([Mode, Major, Version]) -> merge_run(Mode, Major, Version);
dispatch(_) -> erlang:error(interop_artifact_merge_usage).

merge_run(Mode, Major, Version) ->
    Spec0 = (merge_spec(Mode, Major, Version))#{kind => <<"interop">>},
    merge_run_spec(Spec0, "build/interop-artifacts", "build/interop",
                   "build/interop-merge/failure.json").

merge_campaign_run(Mode) ->
    Names = ["nightly-" ++ Mode ++ "-shard-" ++ integer_to_list(Id)
             || Id <- lists:seq(0, 7)],
    Destination = case Mode of
        "model" -> "build/model";
        _ -> filename:join(["build", "campaign", Mode])
    end,
    Spec = #{kind => <<"campaign">>, mode => list_to_binary(Mode),
        otp => <<"29">>, otp_version => <<"29.0.5">>,
        expected => Names},
    Failure = filename:join(["build", "artifact-merge",
                             "campaign-" ++ Mode ++ "-failure.json"]),
    merge_run_spec(Spec, "build/campaign-artifacts", Destination, Failure).

merge_credential_run() ->
    Names = ["nightly-credential-" ++ Os ++ "-otp-" ++ Otp
             || Os <- ["ubuntu-24.04", "macos-15", "windows-2025"],
                Otp <- ["28", "29"]],
    Spec = #{kind => <<"credential">>, mode => <<"credential">>,
        otp => <<"29">>, otp_version => <<"29.0.5">>,
        expected => lists:sort(Names)},
    merge_run_spec(Spec, "build/credential-artifacts",
                   "build/credential-matrix/local",
                   "build/artifact-merge/credential-failure.json").

merge_run_spec(Spec0, InputRoot, Destination, FailurePath) ->
    Identity = evidence_identity(),
    Spec = Spec0#{execution_environment => execution_runtime()},
    merge_invalidate_regular(FailurePath),
    try
        ok = merge_validate_assembler_runtime(Spec),
        Receipt = merge_assemble_at(InputRoot, Destination, Spec, Identity),
        io:format("evidence artifact merge: Ready, kind=~s artifacts=~B files=~B bytes=~B~n",
            [maps:get(kind, Spec), maps:get(artifact_count, Receipt), maps:get(file_count, Receipt),
             maps:get(total_bytes, Receipt)]),
        ok
    catch Class:Reason:Stacktrace ->
        Failure = #{schema => 1, status => <<"Failed">>,
            kind => maps:get(kind, Spec), mode => maps:get(mode, Spec),
            otp => maps:get(otp, Spec),
            otp_version => maps:get(otp_version, Spec),
            expected_artifacts => [list_to_binary(Name) || Name <- maps:get(expected, Spec)],
            execution_environment => maps:get(execution_environment, Spec),
            failure => diagnostic_failure_details(Class, Reason, Stacktrace),
            evidence_identity => Identity},
        ok = merge_write_json_atomic(FailurePath, Failure),
        erlang:raise(Class, Reason, Stacktrace)
    end.

merge_spec("pr", "28", "28.5.0.6") -> merge_spec_value("pr", "28", "28.5.0.6");
merge_spec("pr", "29", "29.0.5") -> merge_spec_value("pr", "29", "29.0.5");
merge_spec("nightly", "28", "28.5.0.6") -> merge_spec_value("nightly", "28", "28.5.0.6");
merge_spec("nightly", "29", "29.0.5") -> merge_spec_value("nightly", "29", "29.0.5");
merge_spec(_, _, _) -> erlang:error(invalid_interop_artifact_merge_spec).

merge_spec_value(Mode, Major, Version) ->
    Expected = artifact_merge_interop_expected(
        list_to_binary(Mode), list_to_binary(Major), list_to_binary(Version)),
    ArtifactPeers = maps:from_list([{binary_to_list(Artifact), binary_to_list(Peer)}
                                    || {Artifact, Peer} <- Expected]),
    #{mode => list_to_binary(Mode), otp => list_to_binary(Major),
      otp_version => list_to_binary(Version),
      expected => lists:sort(maps:keys(ArtifactPeers)),
      artifact_peers => ArtifactPeers}.

merge_validate_assembler_runtime(Spec) ->
    Runtime = maps:get(execution_environment, Spec),
    merge_ensure(lists:sort(maps:keys(Runtime)) =:=
        [<<"erts_version">>, <<"os_family">>, <<"os_name">>, <<"otp_version">>,
         <<"system_architecture">>, <<"word_size">>],
        invalid_interop_merge_runtime),
    merge_ensure(maps:get(<<"otp_version">>, Runtime) =:= maps:get(otp_version, Spec),
                 wrong_interop_merge_runtime),
    merge_ensure({maps:get(<<"os_family">>, Runtime), maps:get(<<"os_name">>, Runtime)}
                 =:= {<<"unix">>, <<"linux">>}, wrong_interop_merge_platform),
    ok.

merge_assemble_at(InputRoot, Destination, Spec, Identity) ->
    {Artifacts0, Records0} = merge_collect(InputRoot, Spec),
    {Files, _ByPath} = merge_resolve_records(Records0),
    Nonce = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16), lowercase)),
    Temp = filename:join(filename:dirname(Destination), ".interop-merge-" ++ Nonce),
    merge_assert_managed_path(Temp),
    merge_assert_managed_path(Destination),
    ok = filelib:ensure_dir(filename:join(Temp, "placeholder")),
    try
        lists:foreach(fun(File) -> merge_copy_verified(File, Temp) end, Files),
        %% Re-enumerate and re-hash every input after copying. A producer cannot
        %% add, remove or replace a file between validation and publication.
        {Artifacts1, Records1} = merge_collect(InputRoot, Spec),
        {Files1, _} = merge_resolve_records(Records1),
        merge_ensure(merge_public_artifacts(Artifacts0) =:=
                     merge_public_artifacts(Artifacts1), input_artifacts_changed),
        merge_ensure(merge_public_files(Files) =:= merge_public_files(Files1),
                     input_files_changed),
        %% Bind publication to the source tree again after every staged byte
        %% has been copied and revalidated.  A source mutation during assembly
        %% cannot leave a Ready receipt carrying the earlier identity.
        Identity = evidence_identity(),
        Receipt = merge_receipt(Spec, Identity, Artifacts1, Files1),
        ok = merge_write_json_exclusive(
            filename:join(Temp, "artifact-merge-receipt.json"), Receipt),
        ok = merge_publish_directory(Temp, Destination, Nonce),
        Receipt
    after
        merge_remove_if_present(Temp)
    end.

merge_collect(Root, Spec) ->
    Expected = maps:get(expected, Spec),
    RootInfo = merge_link_info(Root, missing_interop_artifact_staging),
    merge_require_input_type(element(3, RootInfo)),
    {ok, Names0} = merge_list_dir(Root),
    Names = lists:sort(Names0),
    ok = merge_validate_artifact_names(Names, Expected),
    Initial = {0, 0, 0, []},
    Final = lists:foldl(fun(Name, State0) ->
        Path = filename:join(Root, Name),
        Info = merge_link_info(Path, missing_interop_artifact_directory),
        merge_ensure(element(3, Info) =:= directory,
                     non_directory_interop_artifact),
        merge_walk_directory(Path, [], Name, State0)
    end, Initial, Names),
    {_Entries, Count, Bytes, Records} = Final,
    merge_enforce_limits(Count, Bytes),
    lists:foreach(fun(Name) ->
        merge_validate_artifact_scope(Name, Records, Spec)
    end, Names),
    Artifacts = [merge_artifact_summary(Name, Records) || Name <- Names],
    {Artifacts, lists:sort(fun merge_record_less/2, Records)}.

merge_validate_artifact_scope(Name, Records, Spec) ->
    case maps:find(artifact_peers, Spec) of
        error -> ok;
        {ok, ArtifactPeers} ->
            Peer = maps:get(Name, ArtifactPeers),
            PeerBytes = list_to_binary(Peer),
            Selected = [maps:get(path, Record) || Record <- Records,
                maps:get(artifact, Record) =:= list_to_binary(Name)],
            OwnPeer = <<"peers/", PeerBytes/binary, ".json">>,
            OwnFailure = <<"failure-audits/", PeerBytes/binary, ".json">>,
            merge_ensure(lists:member(OwnPeer, Selected) orelse
                         lists:member(OwnFailure, Selected),
                         missing_own_interop_peer_result),
            lists:foreach(fun(Path) ->
                merge_validate_scoped_path(Path, PeerBytes)
            end, Selected)
    end.

merge_validate_scoped_path(Path, Peer) ->
    Segments = binary:split(Path, <<"/">>, [global]),
    [Top | Rest] = Segments,
    merge_ensure(lists:member(Top, [<<"peers">>, <<"manifests">>,
        <<"go-build">>, <<"bin">>, <<"native">>, <<"failures">>,
        <<"failure-audits">>, <<"invocations">>, <<"browser">>]),
        unexpected_interop_artifact_top_level),
    merge_validate_peer_scoped_path(Top, Rest, Peer).

merge_validate_peer_scoped_path(<<"peers">>, [Name], Peer) ->
    merge_ensure(Name =:= <<Peer/binary, ".json">>,
                 foreign_interop_peer_path);
merge_validate_peer_scoped_path(<<"failure-audits">>, [Name], Peer) ->
    merge_ensure(Name =:= <<Peer/binary, ".json">>,
                 foreign_interop_peer_path);
merge_validate_peer_scoped_path(Top, [Name], Peer)
        when Top =:= <<"manifests">>; Top =:= <<"go-build">> ->
    merge_ensure(binary_prefixed_peer_file(Name, Peer),
                 foreign_interop_peer_path);
merge_validate_peer_scoped_path(Top, [Peer | Rest], Peer)
        when (Top =:= <<"native">> orelse Top =:= <<"failures">> orelse
              Top =:= <<"invocations">> orelse Top =:= <<"browser">>),
             Rest =/= [] -> ok;
merge_validate_peer_scoped_path(<<"bin">>, [Name], Peer) ->
    merge_ensure(Name =:= merge_peer_binary_name(Peer),
                 foreign_interop_peer_path);
merge_validate_peer_scoped_path(_, _, _) ->
    erlang:error(foreign_or_invalid_interop_peer_path).

binary_prefixed_peer_file(Name, Peer) ->
    Size = byte_size(Peer),
    case Name of
        <<Prefix:Size/binary, $., _/binary>> when Prefix =:= Peer -> true;
        <<Prefix:Size/binary, $-, _/binary>> when Prefix =:= Peer -> true;
        _ -> false
    end.

merge_peer_binary_name(<<"quic-go-h3">>) -> <<"quic-go">>;
merge_peer_binary_name(<<"ohttp-go">>) -> <<"ohttp-go">>;
merge_peer_binary_name(<<"masque-independent">>) -> <<"masque-go">>;
merge_peer_binary_name(_) -> <<>>.

merge_validate_artifact_names(Names, Expected) ->
    merge_ensure(length(Names) =:= length(lists:usort(Names)),
                 duplicate_interop_artifact_name),
    Portable = [evidence_portable_path_key(Name) || Name <- Names],
    merge_ensure(length(Portable) =:= length(lists:usort(Portable)),
                 portable_duplicate_interop_artifact_name),
    merge_ensure(Names =:= lists:sort(Expected),
                 missing_or_extra_interop_artifact),
    merge_ensure(length(Names) =:= length(Expected) andalso Names =/= [],
                 invalid_evidence_artifact_count),
    ok.

merge_walk_directory(Directory, Segments, Artifact, State0) ->
    merge_ensure(length(Segments) =< ?MAX_DEPTH,
                 excessive_interop_artifact_depth),
    {ok, Names} = merge_list_dir(Directory),
    State1 = merge_add_entries(length(Names), State0),
    lists:foldl(fun(Name, State) ->
        ok = merge_validate_segment(Name),
        Path = filename:join(Directory, Name),
        Info = merge_link_info(Path, interop_artifact_entry_disappeared),
        case element(3, Info) of
            directory -> merge_walk_directory(Path, Segments ++ [Name], Artifact, State);
            regular -> merge_add_file(Path, Segments ++ [Name], Artifact, Info, State);
            symlink -> erlang:error(interop_artifact_link_rejected);
            _ -> erlang:error(interop_artifact_non_regular_rejected)
        end
    end, State1, lists:sort(Names)).

merge_add_entries(Added, {Entries, Count, Bytes, Records}) ->
    Total = Entries + Added,
    merge_ensure(Total =< ?MAX_ENTRIES, excessive_interop_artifact_entries),
    {Total, Count, Bytes, Records}.

merge_add_file(Path, Segments, Artifact, Info,
               {Entries, Count0, Bytes0, Records}) ->
    merge_ensure(element(9, Info) =:= 1, interop_artifact_hardlink_rejected),
    Size = element(2, Info),
    merge_ensure(is_integer(Size) andalso Size >= 0 andalso
                 Size =< ?MAX_FILE_BYTES, excessive_interop_artifact_file),
    Count = Count0 + 1,
    Bytes = Bytes0 + Size,
    merge_enforce_limits(Count, Bytes),
    Relative = merge_relative_path(Segments),
    Data = merge_read_stable(Path, Info, Size),
    Digest = merge_digest(Data),
    Record = #{artifact => list_to_binary(Artifact), path => Relative,
        portable_path => evidence_portable_path_key(binary_to_list(Relative)),
        size => Size, sha256 => Digest, source => Path},
    {Entries, Count, Bytes, [Record | Records]}.

merge_enforce_limits(Count, Bytes) ->
    merge_ensure(is_integer(Count) andalso Count >= 0 andalso Count =< ?MAX_FILES,
                 excessive_interop_artifact_files),
    merge_ensure(is_integer(Bytes) andalso Bytes >= 0 andalso Bytes =< ?MAX_TOTAL_BYTES,
                 excessive_interop_artifact_bytes),
    ok.

merge_validate_segment(Name) ->
    merge_ensure(is_list(Name) andalso Name =/= [] andalso Name =/= "." andalso
                 Name =/= "..", interop_artifact_path_traversal),
    merge_ensure(not lists:member($/, Name) andalso not lists:member($\\, Name),
                 interop_artifact_path_traversal),
    merge_ensure(lists:all(fun(Character) ->
        Character >= 32 andalso Character =/= 127 andalso Character =/= 0
    end, Name), invalid_interop_artifact_path),
    merge_ensure(not lists:any(fun(Character) ->
        lists:member(Character, "<>:\"|?*")
    end, Name), interop_artifact_windows_reserved_character_rejected),
    Last = lists:last(Name),
    merge_ensure(Last =/= $. andalso Last =/= $\s,
                 interop_artifact_non_portable_suffix),
    Base = hd(string:split(Name, ".", leading)),
    PortableBase = string:casefold(
        unicode:characters_to_list(unicode:characters_to_nfc_binary(Base))),
    merge_ensure(not merge_windows_device_basename(PortableBase),
                 interop_artifact_windows_device_rejected),
    merge_ensure(byte_size(unicode:characters_to_binary(Name)) =< 255,
                 excessive_interop_artifact_segment),
    ok.

merge_windows_device_basename("con") -> true;
merge_windows_device_basename("prn") -> true;
merge_windows_device_basename("aux") -> true;
merge_windows_device_basename("nul") -> true;
merge_windows_device_basename([$c, $o, $m, Digit])
        when Digit >= $1, Digit =< $9 -> true;
merge_windows_device_basename([$l, $p, $t, Digit])
        when Digit >= $1, Digit =< $9 -> true;
merge_windows_device_basename(_) -> false.

merge_relative_path(Segments) ->
    merge_ensure(Segments =/= [], empty_interop_artifact_path),
    merge_ensure(length(Segments) =< ?MAX_DEPTH,
                 excessive_interop_artifact_depth),
    lists:foreach(fun merge_validate_segment/1, Segments),
    Relative = iolist_to_binary(lists:join(<<"/">>,
        [unicode:characters_to_binary(Segment) || Segment <- Segments])),
    merge_ensure(byte_size(Relative) =< ?MAX_PATH_BYTES,
                 excessive_interop_artifact_path),
    Relative.

merge_resolve_records(Records) ->
    Sorted = lists:sort(fun merge_record_less/2, Records),
    Map = lists:foldl(fun(Record, ByPath) ->
        Key = maps:get(portable_path, Record),
        case maps:find(Key, ByPath) of
            error -> maps:put(Key, Record#{artifacts =>
                       [maps:get(artifact, Record)]}, ByPath);
            {ok, Prior} ->
                merge_ensure(maps:get(path, Prior) =:= maps:get(path, Record),
                             portable_interop_path_collision),
                merge_ensure(maps:get(size, Prior) =:= maps:get(size, Record) andalso
                             maps:get(sha256, Prior) =:= maps:get(sha256, Record),
                             differing_interop_path_collision),
                Names = lists:usort([maps:get(artifact, Record) |
                                     maps:get(artifacts, Prior)]),
                merge_ensure(length(Names) =:= length(maps:get(artifacts, Prior)) + 1,
                             duplicate_interop_path_in_artifact),
                maps:put(Key, Prior#{artifacts => Names}, ByPath)
        end
    end, #{}, Sorted),
    Keys = lists:sort(maps:keys(Map)),
    Files = [maps:get(Key, Map) || Key <- Keys],
    {Files, Map}.

merge_record_less(A, B) ->
    {maps:get(portable_path, A), maps:get(path, A), maps:get(artifact, A)} <
    {maps:get(portable_path, B), maps:get(path, B), maps:get(artifact, B)}.

merge_copy_verified(Record, Root) ->
    Destination = merge_destination_path(Root, maps:get(path, Record)),
    ok = filelib:ensure_dir(Destination),
    Info = merge_link_info(maps:get(source, Record), input_file_changed),
    Data = merge_read_stable(maps:get(source, Record), Info, maps:get(size, Record)),
    merge_ensure(merge_digest(Data) =:= maps:get(sha256, Record), input_file_changed),
    merge_write_exclusive(Destination, Data).

merge_destination_path(Root, Relative) ->
    Segments = binary:split(Relative, <<"/">>, [global]),
    merge_ensure(Segments =/= [] andalso lists:all(fun(Segment) ->
        Segment =/= <<>> andalso Segment =/= <<".">> andalso Segment =/= <<"..">>
    end, Segments), interop_artifact_path_traversal),
    filename:join([Root | [binary_to_list(Segment) || Segment <- Segments]]).

merge_receipt(Spec, Identity, Artifacts, Files) ->
    Total = lists:sum([maps:get(size, File) || File <- Files]),
    InputFiles = lists:sum([maps:get(file_count, Artifact) || Artifact <- Artifacts]),
    InputBytes = lists:sum([maps:get(total_bytes, Artifact) || Artifact <- Artifacts]),
    #{schema => 1, status => <<"Ready">>, kind => maps:get(kind, Spec),
      mode => maps:get(mode, Spec),
      otp => maps:get(otp, Spec), otp_version => maps:get(otp_version, Spec),
      artifact_count => length(Artifacts), input_file_count => InputFiles,
      input_total_bytes => InputBytes, file_count => length(Files), total_bytes => Total,
      bounds => #{maximum_artifacts => length(maps:get(expected, Spec)),
                  maximum_entries => ?MAX_ENTRIES,
                  maximum_depth => ?MAX_DEPTH, maximum_path_bytes => ?MAX_PATH_BYTES,
                  maximum_files => ?MAX_FILES, maximum_file_bytes => ?MAX_FILE_BYTES,
                  maximum_total_bytes => ?MAX_TOTAL_BYTES},
      artifacts => merge_public_artifacts(Artifacts),
      files => merge_public_files(Files),
      execution_environment => maps:get(execution_environment, Spec),
      evidence_identity => Identity}.

merge_artifact_summary(Name, Records) ->
    Selected = lists:sort(fun merge_record_less/2,
        [Record || Record <- Records,
                   maps:get(artifact, Record) =:= list_to_binary(Name)]),
    merge_ensure(Selected =/= [], empty_interop_artifact),
    Payload = [[maps:get(path, Record), 0, maps:get(sha256, Record), 0,
                integer_to_binary(maps:get(size, Record)), 0]
               || Record <- Selected],
    #{name => list_to_binary(Name), file_count => length(Selected),
      total_bytes => lists:sum([maps:get(size, Record) || Record <- Selected]),
      sha256 => merge_digest(Payload)}.

merge_public_artifacts(Artifacts) ->
    [#{name => maps:get(name, Artifact), file_count => maps:get(file_count, Artifact),
       total_bytes => maps:get(total_bytes, Artifact), sha256 => maps:get(sha256, Artifact)}
     || Artifact <- Artifacts].

merge_public_files(Files) ->
    [#{path => maps:get(path, File), size => maps:get(size, File),
       sha256 => maps:get(sha256, File),
       artifacts => lists:sort(maps:get(artifacts, File))}
     || File <- Files].

merge_publish_directory(Temp, Destination, Nonce) ->
    Backup = filename:join(filename:dirname(Destination),
                           ".interop-stale-" ++ Nonce),
    merge_assert_managed_path(Backup),
    case file:read_link_info(Destination) of
        {error, enoent} -> merge_rename(Temp, Destination);
        {ok, Info} when element(3, Info) =:= directory ->
            merge_rename(Destination, Backup),
            case file:rename(Temp, Destination) of
                ok -> merge_remove_tree(Backup);
                {error, _} ->
                    _ = file:rename(Backup, Destination),
                    erlang:error(cannot_publish_interop_artifact_merge)
            end;
        {ok, _} -> erlang:error(unsafe_existing_interop_output);
        {error, _} -> erlang:error(cannot_inspect_existing_interop_output)
    end.

merge_assert_managed_path(Path) ->
    Build = evidence_normalized_path(filename:absname("build")),
    Absolute = evidence_normalized_path(filename:absname(Path)),
    Prefix = Build ++ "/",
    merge_ensure(lists:prefix(Prefix, Absolute), unsafe_interop_merge_path),
    ok.

merge_remove_if_present(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, _} -> merge_remove_tree(Path);
        {error, _} -> erlang:error(cannot_inspect_interop_merge_temporary)
    end.

merge_remove_tree(Path) ->
    merge_assert_managed_path(Path),
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, Info} when element(3, Info) =:= directory ->
            {ok, Names} = merge_list_dir(Path),
            lists:foreach(fun(Name) -> merge_remove_tree(filename:join(Path, Name)) end,
                          Names),
            case file:del_dir(Path) of
                ok -> ok;
                {error, _} -> erlang:error(cannot_remove_interop_merge_directory)
            end;
        {ok, Info} when element(3, Info) =:= regular;
                        element(3, Info) =:= symlink ->
            case file:delete(Path) of
                ok -> ok;
                {error, _} -> erlang:error(cannot_remove_interop_merge_file)
            end;
        {ok, _} -> erlang:error(interop_merge_special_file_rejected);
        {error, _} -> erlang:error(cannot_inspect_interop_merge_path)
    end.

merge_read_stable(Path, Initial, Size) ->
    merge_ensure(element(3, Initial) =:= regular, interop_artifact_non_regular_rejected),
    merge_ensure(element(9, Initial) =:= 1, interop_artifact_hardlink_rejected),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> erlang:error(cannot_open_interop_artifact_file)
    end,
    {Data, Opened, Finished} = try
        OpenInfo = merge_handle_info(File),
        merge_ensure(merge_info_identity(Initial) =:= merge_info_identity(OpenInfo),
                     input_file_changed),
        Bytes = merge_read_chunks(File, Size, []),
        FinalInfo = merge_handle_info(File),
        {Bytes, OpenInfo, FinalInfo}
    after
        ok = file:close(File)
    end,
    FinalPath = merge_link_info(Path, input_file_changed),
    merge_ensure(merge_info_identity(Opened) =:= merge_info_identity(Finished) andalso
                 merge_info_identity(Finished) =:= merge_info_identity(FinalPath) andalso
                 byte_size(Data) =:= Size, input_file_changed),
    Data.

merge_read_chunks(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            merge_read_chunks(File, Remaining - byte_size(Chunk), [Chunk | Acc]);
        {ok, _} -> erlang:error(input_file_changed);
        {error, _} -> erlang:error(cannot_read_interop_artifact_file)
    end.

merge_info_identity(Info) ->
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

merge_link_info(Path, Reason) ->
    case file:read_link_info(Path) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(Reason)
    end.

merge_handle_info(File) ->
    case file:read_file_info(File) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(cannot_inspect_open_interop_artifact)
    end.

merge_list_dir(Path) ->
    case file:list_dir(Path) of
        {ok, Names} -> {ok, Names};
        {error, _} -> erlang:error(cannot_enumerate_interop_artifact)
    end.

merge_require_input_type(directory) -> ok;
merge_require_input_type(symlink) -> erlang:error(interop_artifact_root_link_rejected);
merge_require_input_type(_) -> erlang:error(interop_artifact_root_non_directory).

merge_write_exclusive(Path, Data) ->
    case file:open(Path, [write, binary, raw, exclusive]) of
        {ok, File} ->
            try
                ok = file:write(File, Data),
                ok = file:sync(File)
            after
                ok = file:close(File)
            end;
        {error, _} -> erlang:error(cannot_create_interop_merge_file)
    end.

merge_write_json_exclusive(Path, Value) ->
    merge_write_exclusive(Path, merge_json_bytes(Value)).

merge_json_bytes(Value) ->
    Bytes = iolist_to_binary([json:encode(Value), <<"\n">>]),
    merge_ensure(byte_size(Bytes) =< ?MAX_RECEIPT_BYTES,
                 interop_artifact_receipt_too_large),
    Bytes.

merge_write_json_atomic(Path, Value) ->
    ok = filelib:ensure_dir(Path),
    Temp = Path ++ ".tmp-" ++ binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    try
        ok = merge_write_json_exclusive(Temp, Value),
        merge_invalidate_regular(Path),
        merge_rename(Temp, Path)
    after
        case file:delete(Temp) of ok -> ok; {error, enoent} -> ok; _ -> ok end
    end.

merge_invalidate_regular(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, Info} when element(3, Info) =:= regular, element(9, Info) =:= 1 ->
            case file:delete(Path) of
                ok -> ok;
                {error, _} -> erlang:error(cannot_invalidate_interop_merge_evidence)
            end;
        {ok, _} -> erlang:error(unsafe_interop_merge_evidence_path);
        {error, _} -> erlang:error(cannot_inspect_interop_merge_evidence)
    end.

merge_rename(From, To) ->
    case file:rename(From, To) of
        ok -> ok;
        {error, _} -> erlang:error(cannot_publish_interop_artifact_merge)
    end.

merge_digest(Data) -> binary:encode_hex(crypto:hash(sha256, Data), lowercase).

merge_ensure(true, _) -> ok;
merge_ensure(false, Reason) -> erlang:error(Reason).

merge_rejected(Fun, Reason) ->
    Rejected = try Fun(), false catch _:_ -> true end,
    merge_ensure(Rejected, Reason).

merge_self_test() ->
    Runtime = #{<<"otp_version">> => <<"28.5.0.6">>,
        <<"erts_version">> => <<"17.0.5">>, <<"os_family">> => <<"unix">>,
        <<"os_name">> => <<"linux">>,
        <<"system_architecture">> => <<"x86_64-pc-linux-gnu">>,
        <<"word_size">> => 8},
    Spec = (merge_spec("pr", "28", "28.5.0.6"))#{kind => <<"interop">>,
        execution_environment => Runtime},
    ok = merge_validate_assembler_runtime(Spec),
    merge_rejected(fun() -> merge_validate_assembler_runtime(Spec#{
        execution_environment => Runtime#{<<"otp_version">> => <<"28.0">>}}) end,
        wrong_runtime_accepted),
    Expected = maps:get(expected, Spec),
    ok = merge_validate_artifact_names(Expected, Expected),
    merge_rejected(fun() -> merge_validate_artifact_names(tl(Expected), Expected) end,
                   missing_artifact_accepted),
    merge_rejected(fun() -> merge_validate_artifact_names(
        lists:sort(["unexpected" | Expected]), Expected) end, extra_artifact_accepted),
    merge_rejected(fun() -> merge_validate_artifact_names(
        lists:sort([hd(Expected), hd(Expected) | tl(Expected)]), Expected) end,
        duplicate_artifact_accepted),
    merge_rejected(fun() -> merge_validate_segment("..") end,
                   path_traversal_accepted),
    merge_rejected(fun() -> merge_validate_segment("nested\\escape") end,
                   backslash_traversal_accepted),
    DeviceNames = ["CON", "con.txt", "PRN", "AUX.log", "NUL"] ++
        ["COM" ++ integer_to_list(Number) || Number <- lists:seq(1, 9)] ++
        ["LPT" ++ integer_to_list(Number) ++ ".json"
         || Number <- lists:seq(1, 9)],
    lists:foreach(fun(Name) ->
        merge_rejected(fun() -> merge_validate_segment(Name) end,
                       non_portable_path_accepted)
    end, ["trailing.", "trailing ", "stream:secret", "less<than",
          "quote\"name", "pipe|name", "wild?name", "star*name" |
          DeviceNames]),
    merge_rejected(fun() -> merge_validate_segment(lists:duplicate(256, $a)) end,
                   oversized_segment_accepted),
    merge_rejected(fun() -> merge_relative_path(lists:duplicate(65, "a")) end,
                   excessive_depth_accepted),
    merge_rejected(fun() -> merge_relative_path(
        lists:duplicate(17, lists:duplicate(255, $a))) end,
        oversized_path_accepted),
    merge_rejected(fun() -> merge_require_input_type(symlink) end,
                   link_type_accepted),
    merge_rejected(fun() -> merge_require_input_type(device) end,
                   special_type_accepted),
    merge_rejected(fun() -> merge_enforce_limits(?MAX_FILES + 1, 0) end,
                   excessive_file_count_accepted),
    merge_rejected(fun() -> merge_enforce_limits(1, ?MAX_TOTAL_BYTES + 1) end,
                   excessive_bytes_accepted),
    merge_rejected(fun() -> merge_artifact_summary("empty", []) end,
                   empty_artifact_accepted),
    merge_rejected(fun() -> merge_json_bytes(#{payload =>
        binary:copy(<<"x">>, ?MAX_RECEIPT_BYTES)}) end,
        oversized_receipt_accepted),
    HashA = merge_digest(<<"same">>),
    HashB = merge_digest(<<"different">>),
    Base = #{artifact => <<"a">>, path => <<"peers/example.json">>,
             portable_path => <<"peers/example.json">>, size => 4,
             sha256 => HashA, source => "fixture-a"},
    Identical = Base#{artifact => <<"b">>, source => "fixture-b"},
    {[Deduplicated], _} = merge_resolve_records([Base, Identical]),
    [<<"a">>, <<"b">>] = maps:get(artifacts, Deduplicated),
    merge_rejected(fun() -> merge_resolve_records([
        Base, Identical#{sha256 => HashB}]) end, differing_collision_accepted),
    merge_rejected(fun() -> merge_resolve_records([
        Base, Identical#{path => <<"Peers/Example.json">>}]) end,
        portable_collision_accepted),
    ArtifactPeers = maps:get(artifact_peers, Spec),
    FirstArtifact = hd(Expected),
    FirstPeer = list_to_binary(maps:get(FirstArtifact, ArtifactPeers)),
    ScopeBase = #{artifact => list_to_binary(FirstArtifact), size => 1,
        sha256 => HashA, source => "fixture", portable_path => <<>>},
    OwnPath = <<"peers/", FirstPeer/binary, ".json">>,
    ok = merge_validate_artifact_scope(FirstArtifact,
        [ScopeBase#{path => OwnPath, portable_path => OwnPath}], Spec),
    merge_rejected(fun() -> merge_validate_artifact_scope(FirstArtifact,
        [ScopeBase#{path => OwnPath, portable_path => OwnPath},
         ScopeBase#{path => <<"peers/foreign.json">>,
                    portable_path => <<"peers/foreign.json">>}], Spec) end,
        foreign_peer_scope_accepted),
    merge_rejected(fun() -> merge_validate_artifact_scope(FirstArtifact,
        [ScopeBase#{path => OwnPath, portable_path => OwnPath},
         ScopeBase#{path => <<"private/unexpected.json">>,
                    portable_path => <<"private/unexpected.json">>}], Spec) end,
        unexpected_top_level_accepted),
    merge_rejected(fun() -> merge_validate_artifact_scope(FirstArtifact,
        [ScopeBase#{path => <<"manifests/foreign.begin.json">>,
                    portable_path => <<"manifests/foreign.begin.json">>}], Spec) end,
        missing_own_peer_result_accepted),
    merge_filesystem_self_test(Spec),
    io:put_chars("interop artifact merge controls: exact-set bounded-tree links traversal collisions stable-copy atomic-publication verified\n").

merge_filesystem_self_test(Spec) ->
    Nonce = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8), lowercase)),
    Root = filename:join("build", "interop-artifact-merge-self-test-" ++ Nonce),
    Inputs = filename:join(Root, "inputs"),
    Destination = filename:join(Root, "output"),
    merge_assert_managed_path(Root),
    Expected = maps:get(expected, Spec),
    Identity = evidence_identity(),
    try
        lists:foreach(fun(Name) ->
            Directory = filename:join(Inputs, Name),
            Peer = maps:get(Name, maps:get(artifact_peers, Spec)),
            Result = filename:join([Directory, "peers", Peer ++ ".json"]),
            ok = filelib:ensure_dir(Result),
            ok = file:write_file(Result, list_to_binary(Name))
        end, Expected),
        ok = filelib:ensure_dir(filename:join(Destination, "stale.json")),
        ok = file:write_file(filename:join(Destination, "stale.json"), <<"stale">>),
        Receipt = merge_assemble_at(Inputs, Destination, Spec, Identity),
        11 = maps:get(artifact_count, Receipt),
        false = filelib:is_regular(filename:join(Destination, "stale.json")),
        true = filelib:is_regular(filename:join(Destination,
                                                "artifact-merge-receipt.json")),
        First = hd(Expected),
        FirstPeer = maps:get(First, maps:get(artifact_peers, Spec)),
        Existing = filename:join([Inputs, First, "peers", FirstPeer ++ ".json"]),
        Link = filename:join([Inputs, First, "peers", "forbidden-link"]),
        ok = file:make_symlink(FirstPeer ++ ".json", Link),
        merge_rejected(fun() -> merge_collect(Inputs, Spec) end,
                       filesystem_link_accepted),
        ok = file:delete(Link),
        Hardlink = filename:join([Inputs, First, "peers", "forbidden-hardlink"]),
        ok = file:make_link(Existing, Hardlink),
        merge_rejected(fun() -> merge_collect(Inputs, Spec) end,
                       filesystem_hardlink_accepted)
    after
        merge_remove_if_present(Root)
    end.
