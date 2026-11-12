%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_EVIDENCE_PUBLICATION_HRL).
-define(HTTP_EVIDENCE_PUBLICATION_HRL, true).
-compile({nowarn_unused_function, [
    {evidence_publish_new, 3},
    {evidence_replace_locked, 4},
    {evidence_publication_read, 2},
    {evidence_publication_ensure_directory, 1}
]}).

%% Publish a complete immutable document without ever exposing a partial target.
%% The hard-link operation is the cross-platform no-replace commit point.
evidence_publish_new(Path0, Bytes, Maximum)
  when is_binary(Bytes), is_integer(Maximum), Maximum > 0 ->
    true = byte_size(Bytes) > 0 andalso byte_size(Bytes) =< Maximum,
    Path = filename:absname(Path0),
    Parent = filename:dirname(Path),
    ParentInfo = evidence_publication_ensure_directory(Parent),
    true = evidence_publication_path_absent(Path),
    Temporary = evidence_publication_temporary(Path),
    try
        ok = evidence_publication_write_temporary(Temporary, Bytes),
        true = evidence_publication_directory_identity(ParentInfo) =:=
            evidence_publication_directory_identity(
                evidence_publication_directory_info(Parent)),
        case file:make_link(Temporary, Path) of
            ok -> ok;
            {error, eexist} -> erlang:error(evidence_publication_conflict);
            {error, _} -> erlang:error(evidence_publication_failed)
        end,
        ok = file:delete(Temporary),
        Bytes = evidence_publication_read(Path, Maximum),
        ok
    after evidence_publication_delete_temporary(Temporary) end.

%% Callers must hold the corresponding writer/verification lock.  The expected
%% bytes prevent a stale owner from replacing a newer document.  Deleting the
%% old name before rename is required by Windows and is safe only under that
%% lock; a missing or changed old target fails closed before publication.
evidence_replace_locked(Path0, ExpectedOld, Bytes, Maximum)
  when is_binary(ExpectedOld), is_binary(Bytes),
       is_integer(Maximum), Maximum > 0 ->
    true = byte_size(Bytes) > 0 andalso byte_size(Bytes) =< Maximum,
    Path = filename:absname(Path0),
    Parent = filename:dirname(Path),
    ParentInfo = evidence_publication_directory_info(Parent),
    ExpectedOld = evidence_publication_read(Path, Maximum),
    Temporary = evidence_publication_temporary(Path),
    try
        ok = evidence_publication_write_temporary(Temporary, Bytes),
        ExpectedOld = evidence_publication_read(Path, Maximum),
        true = evidence_publication_directory_identity(ParentInfo) =:=
            evidence_publication_directory_identity(
                evidence_publication_directory_info(Parent)),
        ok = file:delete(Path),
        case file:rename(Temporary, Path) of
            ok -> ok;
            {error, _} -> erlang:error(evidence_publication_replace_failed)
        end,
        Bytes = evidence_publication_read(Path, Maximum),
        ok
    after evidence_publication_delete_temporary(Temporary) end.

evidence_publication_write_temporary(Path, Bytes) ->
    {ok, Handle} = file:open(Path, [write, binary, raw, exclusive]),
    try
        ok = file:write(Handle, Bytes),
        ok = file:sync(Handle)
    after ok = file:close(Handle) end.

evidence_publication_temporary(Path) ->
    Path ++ ".pending-" ++ binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(16), lowercase)).

evidence_publication_delete_temporary(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> ok
    end.

evidence_publication_read(Path, Maximum) ->
    Initial = evidence_publication_regular_info(Path),
    Size = element(2, Initial),
    true = is_integer(Size) andalso Size >= 0 andalso Size =< Maximum,
    true = element(9, Initial) =:= 1,
    {ok, Handle} = file:open(Path, [read, binary, raw]),
    ReadResult = try
        {ok, Opened} = file:read_file_info(Handle),
        true = element(3, Opened) =:= regular andalso element(9, Opened) =:= 1,
        true = evidence_publication_identity(Initial) =:=
            evidence_publication_identity(Opened),
        ReadBytes = evidence_publication_read_chunks(Handle, Size, []),
        {ok, FinishedInfo} = file:read_file_info(Handle),
        true = evidence_publication_identity(Opened) =:=
            evidence_publication_identity(FinishedInfo),
        true = byte_size(ReadBytes) =:= Size,
        {ReadBytes, FinishedInfo}
    after ok = file:close(Handle) end,
    {Captured, Finished} = ReadResult,
    FinalPath = evidence_publication_regular_info(Path),
    true = evidence_publication_identity(Finished) =:=
        evidence_publication_identity(FinalPath),
    Captured.

evidence_publication_read_chunks(Handle, Remaining, Acc) ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(Handle, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            evidence_publication_read_chunks(
                Handle, Remaining - byte_size(Chunk), [Chunk | Acc]);
        _ -> erlang:error(evidence_publication_changed)
    end.

evidence_publication_regular_info(Path) ->
    evidence_publication_components(filename:split(filename:absname(Path)), "").

evidence_publication_directory_info(Path) ->
    evidence_publication_directory_components(
        filename:split(filename:absname(Path)), "").

evidence_publication_ensure_directory(Path0) ->
    Path = filename:absname(Path0),
    evidence_publication_ensure_components(filename:split(Path), "").

evidence_publication_ensure_components([], _) ->
    erlang:error(evidence_publication_unsafe_path);
evidence_publication_ensure_components([Name | Rest], Parent) ->
    Current = case Parent of "" -> Name; _ -> filename:join(Parent, Name) end,
    Info = case file:read_link_info(Current) of
        {ok, Existing} when element(1, Existing) =:= file_info,
                            element(3, Existing) =:= directory -> Existing;
        {ok, Existing} when element(1, Existing) =:= file_info,
                            element(3, Existing) =:= symlink ->
            erlang:error(evidence_publication_link_rejected);
        {ok, _} -> erlang:error(evidence_publication_type_rejected);
        {error, enoent} ->
            case file:make_dir(Current) of
                ok -> ok;
                {error, eexist} -> ok;
                {error, _} -> erlang:error(evidence_publication_directory_failed)
            end,
            case file:read_link_info(Current) of
                {ok, Created} when element(1, Created) =:= file_info,
                                   element(3, Created) =:= directory -> Created;
                {ok, Created} when element(1, Created) =:= file_info,
                                   element(3, Created) =:= symlink ->
                    erlang:error(evidence_publication_link_rejected);
                _ -> erlang:error(evidence_publication_directory_failed)
            end;
        {error, _} -> erlang:error(evidence_publication_inspection_failed)
    end,
    case Rest of
        [] -> Info;
        _ -> evidence_publication_ensure_components(Rest, Current)
    end.

evidence_publication_directory_components([], _) ->
    erlang:error(evidence_publication_unsafe_path);
evidence_publication_directory_components([Name | Rest], Parent) ->
    Current = case Parent of "" -> Name; _ -> filename:join(Parent, Name) end,
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case Rest of
                [] -> Info;
                _ -> evidence_publication_directory_components(Rest, Current)
            end;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(evidence_publication_link_rejected);
        {ok, _} -> erlang:error(evidence_publication_type_rejected);
        {error, enoent} -> erlang:error(evidence_publication_missing);
        {error, _} -> erlang:error(evidence_publication_inspection_failed)
    end.

evidence_publication_components([], _) ->
    erlang:error(evidence_publication_unsafe_path);
evidence_publication_components([Name | Rest], Parent) ->
    Current = case Parent of "" -> Name; _ -> filename:join(Parent, Name) end,
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory, Rest =/= [] ->
            evidence_publication_components(Rest, Current);
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular, Rest =:= [] -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(evidence_publication_link_rejected);
        {ok, _} -> erlang:error(evidence_publication_type_rejected);
        {error, enoent} -> erlang:error(evidence_publication_missing);
        {error, _} -> erlang:error(evidence_publication_inspection_failed)
    end.

evidence_publication_identity(Info) ->
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

%% Directory size, link count and timestamps change as the temporary and final
%% names are created.  Device/inode plus stable ownership and mode fields bind
%% the commit to the directory object without treating our own mutation as a
%% concurrent replacement.
evidence_publication_directory_identity(Info) ->
    {element(3, Info), element(4, Info), element(8, Info),
     element(10, Info), element(11, Info), element(12, Info),
     element(13, Info), element(14, Info)}.

evidence_publication_path_absent(Path) ->
    case file:read_link_info(Path) of {error, enoent} -> true; _ -> false end.

-endif.
