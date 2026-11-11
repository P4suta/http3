%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_ARTIFACT_MERGE_EVIDENCE_HRL).
-define(HTTP_ARTIFACT_MERGE_EVIDENCE_HRL, true).

artifact_merge_campaign_expected(Mode) ->
    [{list_to_binary("nightly-" ++ Mode ++ "-shard-" ++ integer_to_list(Id)),
      list_to_binary("shard-" ++ integer_to_list(Id) ++ ".json")}
     || Id <- lists:seq(0, 7)].

artifact_merge_campaign_receipt_path("model") ->
    "build/model/artifact-merge-receipt.json";
artifact_merge_campaign_receipt_path(Mode) ->
    filename:join(["build", "campaign", Mode, "artifact-merge-receipt.json"]).

artifact_merge_verify_campaign(Mode, Identity) ->
    artifact_merge_verify(artifact_merge_campaign_receipt_path(Mode),
        <<"campaign">>, list_to_binary(Mode),
        artifact_merge_campaign_expected(Mode), Identity).

artifact_merge_credential_expected() ->
    [{list_to_binary("nightly-credential-" ++ Os ++ "-otp-" ++ Otp),
      list_to_binary(Os ++ "-otp" ++ Otp ++ ".json")}
     || Os <- ["ubuntu-24.04", "macos-15", "windows-2025"],
        Otp <- ["28", "29"]].

artifact_merge_verify_credential(Identity) ->
    artifact_merge_verify(
        "build/credential-matrix/local/artifact-merge-receipt.json",
        <<"credential">>, <<"credential">>,
        artifact_merge_credential_expected(), Identity).

artifact_merge_interop_expected(Mode, Major, Version) ->
    Prefix = <<Mode/binary, "-interop-">>,
    Suffix = <<"-otp-", Major/binary>>,
    [{<<Prefix/binary, Artifact/binary, Suffix/binary>>, Peer}
     || {Artifact, Peer} <-
        [{<<"curl">>, <<"curl-h1-h2">>},
         {<<"nghttp2">>, <<"nghttp2-h2">>},
         {<<"aioquic">>, <<"aioquic-h3">>},
         {<<"quicgo">>, <<"quic-go-h3">>},
         {<<"quiche">>, <<"quiche-h3">>},
         {<<"ngtcp2">>, <<"ngtcp2-nghttp3-h3">>},
         {<<"ohttp-go">>, <<"ohttp-go">>},
         {<<"ohttp-typescript">>, <<"ohttp-typescript">>},
         {<<"masque">>, <<"masque-independent">>}]] ++
    [{<<Peer/binary, "-interop-otp-", Version/binary>>, Peer}
     || Peer <- [<<"chromium">>, <<"firefox">>]].

artifact_merge_verify(Path, Kind, Mode, Expected0, Identity) ->
    Bytes = artifact_merge_read_regular(Path, 1048576),
    Receipt = evidence_json_decode(Bytes),
    true = artifact_merge_exact_keys(Receipt, [schema, status, kind, mode, otp,
        otp_version, artifact_count, input_file_count, input_total_bytes,
        file_count, total_bytes, bounds, artifacts, files,
        execution_environment, evidence_identity]),
    1 = maps:get(<<"schema">>, Receipt),
    <<"Ready">> = maps:get(<<"status">>, Receipt),
    Kind = maps:get(<<"kind">>, Receipt),
    Mode = maps:get(<<"mode">>, Receipt),
    Identity = maps:get(<<"evidence_identity">>, Receipt),
    Runtime = execution_runtime(),
    Runtime = maps:get(<<"execution_environment">>, Receipt),
    Version = maps:get(<<"otp_version">>, Runtime),
    Version = maps:get(<<"otp_version">>, Receipt),
    [Major | _] = binary:split(Version, <<".">>, [global]),
    Major = maps:get(<<"otp">>, Receipt),
    Expected = lists:sort(Expected0),
    Count = length(Expected),
    Count = maps:get(<<"artifact_count">>, Receipt),
    Bounds = maps:get(<<"bounds">>, Receipt),
    true = artifact_merge_exact_keys(Bounds, [maximum_artifacts, maximum_entries,
        maximum_depth, maximum_path_bytes, maximum_files,
        maximum_file_bytes, maximum_total_bytes]),
    Count = maps:get(<<"maximum_artifacts">>, Bounds),
    16384 = maps:get(<<"maximum_entries">>, Bounds),
    64 = maps:get(<<"maximum_depth">>, Bounds),
    4096 = maps:get(<<"maximum_path_bytes">>, Bounds),
    8192 = maps:get(<<"maximum_files">>, Bounds),
    134217728 = maps:get(<<"maximum_file_bytes">>, Bounds),
    536870912 = maps:get(<<"maximum_total_bytes">>, Bounds),
    Artifacts = maps:get(<<"artifacts">>, Receipt),
    Files = maps:get(<<"files">>, Receipt),
    true = is_list(Artifacts) andalso is_list(Files),
    ExpectedNames = lists:sort([Name || {Name, _} <- Expected]),
    ExpectedPaths = lists:sort([Relative || {_, Relative} <- Expected]),
    ExpectedNames = [artifact_merge_artifact_name(A) || A <- Artifacts],
    ExpectedPaths = [artifact_merge_file_path(F) || F <- Files],
    Count = length(Artifacts),
    Count = length(Files),
    Count = maps:get(<<"input_file_count">>, Receipt),
    Count = maps:get(<<"file_count">>, Receipt),
    lists:foreach(fun({Name, Relative}) ->
        [Artifact] = [A || A <- Artifacts,
                           maps:get(<<"name">>, A) =:= Name],
        [File] = [F || F <- Files, maps:get(<<"path">>, F) =:= Relative],
        [Name] = maps:get(<<"artifacts">>, File),
        1 = maps:get(<<"file_count">>, Artifact),
        Size = maps:get(<<"size">>, File),
        Size = maps:get(<<"total_bytes">>, Artifact),
        true = is_integer(Size) andalso Size > 0 andalso Size =< 16777216,
        Digest = maps:get(<<"sha256">>, File),
        true = artifact_merge_hex(Digest),
        ArtifactDigest = binary:encode_hex(crypto:hash(sha256,
            [Relative, 0, Digest, 0, integer_to_binary(Size), 0]), lowercase),
        ArtifactDigest = maps:get(<<"sha256">>, Artifact),
        FullPath = artifact_merge_output_path(Kind, Mode, Relative),
        FileBytes = artifact_merge_read_regular(FullPath, 16777216),
        Size = byte_size(FileBytes),
        Digest = binary:encode_hex(crypto:hash(sha256, FileBytes), lowercase)
    end, Expected),
    Total = lists:sum([maps:get(<<"size">>, File) || File <- Files]),
    Total = maps:get(<<"input_total_bytes">>, Receipt),
    Total = maps:get(<<"total_bytes">>, Receipt),
    #{receipt => Receipt,
      sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase)}.

artifact_merge_artifact_name(Artifact) ->
    true = artifact_merge_exact_keys(Artifact, [name, file_count, total_bytes, sha256]),
    maps:get(<<"name">>, Artifact).

artifact_merge_file_path(File) ->
    true = artifact_merge_exact_keys(File, [path, size, sha256, artifacts]),
    maps:get(<<"path">>, File).

artifact_merge_output_path(<<"campaign">>, <<"model">>, Relative) ->
    filename:join("build/model", binary_to_list(Relative));
artifact_merge_output_path(<<"campaign">>, Mode, Relative) ->
    filename:join(["build", "campaign", binary_to_list(Mode),
                   binary_to_list(Relative)]);
artifact_merge_output_path(<<"credential">>, <<"credential">>, Relative) ->
    filename:join(["build", "credential-matrix", "local",
                   binary_to_list(Relative)]).

artifact_merge_exact_keys(Map, Keys) when is_map(Map) ->
    Expected = lists:sort([artifact_merge_binary_key(Key) || Key <- Keys]),
    lists:sort(maps:keys(Map)) =:= Expected;
artifact_merge_exact_keys(_, _) -> false.

artifact_merge_binary_key(Key) when is_atom(Key) -> atom_to_binary(Key, utf8);
artifact_merge_binary_key(Key) when is_binary(Key) -> Key.

artifact_merge_hex(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 64 andalso
    lists:all(fun(Character) ->
        (Character >= $0 andalso Character =< $9) orelse
        (Character >= $a andalso Character =< $f)
    end, binary_to_list(Value)).

artifact_merge_read_regular(Path, Maximum)
        when is_integer(Maximum), Maximum >= 0 ->
    Initial = artifact_merge_link_info(Path),
    true = element(3, Initial) =:= regular,
    true = element(9, Initial) =:= 1,
    Size = element(2, Initial),
    true = is_integer(Size) andalso Size >= 0 andalso Size =< Maximum,
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> erlang:error(unreadable_artifact_merge_evidence)
    end,
    {Bytes, Finished} = try
        Opened = artifact_merge_handle_info(File),
        true = artifact_merge_file_identity(Initial) =:=
               artifact_merge_file_identity(Opened),
        Captured = artifact_merge_read_chunks(File, Size, []),
        FinalHandle = artifact_merge_handle_info(File),
        true = artifact_merge_file_identity(Opened) =:=
               artifact_merge_file_identity(FinalHandle),
        true = byte_size(Captured) =:= Size,
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = artifact_merge_link_info(Path),
    true = artifact_merge_file_identity(Finished) =:=
           artifact_merge_file_identity(FinalPath),
    Bytes;
artifact_merge_read_regular(_, _) ->
    erlang:error(invalid_artifact_merge_read_limit).

artifact_merge_link_info(Path) ->
    case file:read_link_info(Path) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(unreadable_artifact_merge_evidence)
    end.

artifact_merge_handle_info(File) ->
    case file:read_file_info(File) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(unreadable_artifact_merge_evidence)
    end.

artifact_merge_read_chunks(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            artifact_merge_read_chunks(
                File, Remaining - byte_size(Chunk), [Chunk | Acc]);
        {ok, _} -> erlang:error(artifact_merge_evidence_changed);
        {error, _} -> erlang:error(unreadable_artifact_merge_evidence)
    end.

artifact_merge_file_identity(Info) ->
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

-endif.
