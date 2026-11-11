%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_BUNDLE_CAPTURE_HRL).
-define(HTTP_BUNDLE_CAPTURE_HRL, true).
-include_lib("kernel/include/file.hrl").

%% The archive consumes these binaries, never paths reopened after validation.
%% Context is kept in the private mirror and is not implicitly published.
bundle_limits() -> #{file_bytes => 134217728, total_bytes => 536870912,
                     files => 32768, depth => 32}.

bundle_path(Path) when is_list(Path), Path =/= [], length(Path) =< 1024 ->
    Parts = string:split(Path, "/", all),
    true = filename:pathtype(Path) =:= relative,
    true = lists:all(fun(P) -> P =/= [] andalso P =/= "." andalso P =/= ".." end, Parts),
    true = lists:all(fun(C) -> C >= 32 andalso C =/= 127 andalso C =/= $\\ andalso C =/= $: end, Path),
    true = length(Parts) =< maps:get(depth, bundle_limits()),
    Path;
bundle_path(_) -> error(unsafe_bundle_path).

bundle_regular(Path) ->
    _ = bundle_path(Path),
    Parts = filename:split(Path),
    bundle_components(Parts, "").
bundle_components([Name], Parent) ->
    {ok, Info} = file:read_link_info(bundle_join(Parent, Name)),
    true = Info#file_info.type =:= regular,
    Info;
bundle_components([Name | Rest], Parent) ->
    Path = bundle_join(Parent, Name),
    {ok, Info} = file:read_link_info(Path),
    true = Info#file_info.type =:= directory,
    bundle_components(Rest, Path).

bundle_join("", Name) -> Name;
bundle_join(Parent, Name) -> filename:join(Parent, Name).

bundle_read(Path, Maximum) ->
    Info = bundle_regular(Path),
    true = Info#file_info.size =< Maximum,
    {ok, File} = file:open(Path, [read, binary, raw]),
    try
        {ok, Opened} = file:read_file_info(File),
        true = Opened#file_info.type =:= regular,
        true = bundle_file_identity(Info) =:= bundle_file_identity(Opened),
        true = Opened#file_info.size =< Maximum,
        %% Reading Maximum for every tiny input forces large temporary buffers
        %% on some file drivers. The observed size plus one still detects
        %% growth, while keeping each allocation proportional to this file.
        Bytes = case file:read(File, Opened#file_info.size + 1) of
            eof -> <<>>;
            {ok, B} when byte_size(B) =< Maximum -> B;
            _ -> error(bundle_file_limit)
        end,
        {ok, Finished} = file:read_file_info(File),
        true = bundle_file_identity(Opened) =:= bundle_file_identity(Finished),
        true = bundle_file_identity(Finished) =:= bundle_file_identity(bundle_regular(Path)),
        true = byte_size(Bytes) =:= Finished#file_info.size,
        Bytes
    after ok = file:close(File) end.

bundle_file_identity(I) ->
    {I#file_info.type, I#file_info.size, I#file_info.mtime, I#file_info.ctime,
     I#file_info.inode, I#file_info.major_device, I#file_info.minor_device}.

bundle_capture(Paths) -> bundle_capture(Paths, bundle_limits()).
bundle_capture(Paths, Limits) ->
    true = length(Paths) =< maps:get(files, Limits),
    true = Paths =:= lists:usort(Paths),
    true = length(Paths) =:= length(lists:usort([string:lowercase(P) || P <- Paths])),
    {_, Captured} = lists:foldl(fun(Path, {Total, Acc}) ->
        Bytes = bundle_read(Path, maps:get(file_bytes, Limits)),
        NewTotal = Total + byte_size(Bytes),
        true = NewTotal =< maps:get(total_bytes, Limits),
        {NewTotal, [{Path, Bytes} | Acc]}
    end, {0, []}, Paths),
    lists:reverse(Captured).

bundle_tree(Root) ->
    _ = bundle_path(Root),
    {_, Files} = bundle_walk(Root, 0, maps:get(files, bundle_limits()), []),
    lists:sort(Files).
bundle_walk(Root, Depth, Remaining, Acc) ->
    true = Depth =< maps:get(depth, bundle_limits()),
    %% Check every directory ancestor before following it.
    _ = bundle_directory_components(filename:split(Root), ""),
    {ok, Names} = file:list_dir(Root),
    true = length(Names) =< Remaining,
    lists:foldl(fun(Name, {Left, Paths}) ->
        true = Left > 0,
        Path = bundle_path(filename:join(Root, Name)),
        {ok, Info} = file:read_link_info(Path),
        case Info#file_info.type of
            regular -> {Left - 1, [Path | Paths]};
            directory -> bundle_walk(Path, Depth + 1, Left - 1, Paths);
            _ -> error(non_regular_bundle_member)
        end
    end, {Remaining, Acc}, lists:sort(Names)).
bundle_directory_components([], _) -> ok;
bundle_directory_components([Name | Rest], Parent) ->
    Path = bundle_join(Parent, Name),
    {ok, Info} = file:read_link_info(Path),
    true = Info#file_info.type =:= directory,
    bundle_directory_components(Rest, Path).

bundle_materialize(Directory, Captured) ->
    _ = bundle_path(Directory),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    lists:foreach(fun({Path, Bytes}) ->
        Destination = filename:join(Directory, Path),
        ok = filelib:ensure_dir(Destination),
        ok = file:write_file(Destination, Bytes, [binary, exclusive])
    end, Captured).

bundle_with_directory(Directory, Action) ->
    {ok, Previous} = file:get_cwd(),
    ok = file:set_cwd(Directory),
    try Action() after ok = file:set_cwd(Previous) end.

bundle_validate_capture(Directory, Captured, Validate) ->
    bundle_with_directory(Directory, fun() ->
        Result = Validate(),
        %% A validator may compile in memory; it must not replace any input or
        %% add an unselected file that affects a wildcard or module inventory.
        Actual = bundle_root_files(),
        true = Actual =:= [Path || {Path, _} <- Captured],
        lists:foreach(fun({Path, Bytes}) ->
            true = bundle_read(Path, maps:get(file_bytes, bundle_limits())) =:= Bytes
        end, Captured),
        Result
    end).

bundle_root_files() ->
    {ok, Names} = file:list_dir("."),
    lists:sort(lists:append([begin
        _ = bundle_path(Name),
        {ok, Info} = file:read_link_info(Name),
        case Info#file_info.type of
            regular -> [Name];
            directory -> bundle_tree(Name);
            _ -> error(non_regular_bundle_member)
        end
    end || Name <- Names])).

bundle_entries(Captured) ->
    [#{path => unicode:characters_to_binary(Path), bytes => byte_size(Bytes),
       sha256 => binary:encode_hex(crypto:hash(sha256, Bytes))} || {Path, Bytes} <- Captured].

bundle_archive(Archive, Captured) ->
    ok = erl_tar:create(Archive, Captured,
        [{mtime, 0}, {atime, 0}, {ctime, 0}, {uid, 0}, {gid, 0}, {mode, 8#100644}]),
    Bytes = bundle_read(Archive, maps:get(total_bytes, bundle_limits()) + 67108864),
    {ok, Extracted} = erl_tar:extract({binary, Bytes}, [memory]),
    true = lists:keysort(1, Extracted) =:= Captured,
    Bytes.
-endif.
