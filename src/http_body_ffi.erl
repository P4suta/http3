%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_body_ffi).

-export([
    file_size/1,
    is_cancelled/1,
    mark_cancelled/1,
    new_cancel_handle/0,
    read_file_chunk/3
]).

-spec new_cancel_handle() -> atomics:atomics_ref().
new_cancel_handle() ->
    atomics:new(1, [{signed, false}]).

-spec mark_cancelled(atomics:atomics_ref()) -> boolean().
mark_cancelled(Handle) ->
    try atomics:exchange(Handle, 1, 1) of
        0 -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec is_cancelled(atomics:atomics_ref()) -> boolean().
is_cancelled(Handle) ->
    try atomics:get(Handle, 1) of
        0 -> false;
        _ -> true
    catch
        _:_ -> true
    end.

-spec file_size(binary()) -> {ok, non_neg_integer()} | {error, nil}.
file_size(Path) when is_binary(Path) ->
    with_file(Path, fun(File) ->
        case file:position(File, eof) of
            {ok, Size} when is_integer(Size), Size >= 0 -> {ok, Size};
            _ -> {error, nil}
        end
    end);
file_size(_) ->
    {error, nil}.

-spec read_file_chunk(binary(), non_neg_integer(), pos_integer()) ->
    {ok, binary()} | {error, nil}.
read_file_chunk(Path, Offset, Maximum)
    when is_binary(Path), is_integer(Offset), Offset >= 0,
         is_integer(Maximum), Maximum > 0 ->
    with_file(Path, fun(File) ->
        case file:pread(File, Offset, Maximum) of
            eof -> {ok, <<>>};
            {ok, Bytes} when is_binary(Bytes) -> {ok, Bytes};
            _ -> {error, nil}
        end
    end);
read_file_chunk(_, _, _) ->
    {error, nil}.

-spec with_file(binary(), fun((file:io_device()) -> term())) -> term().
with_file(Path, Fun) ->
    try file:open(Path, [read, binary, raw]) of
        {ok, File} ->
            try Fun(File)
            after
                _ = file:close(File)
            end;
        {error, _Reason} ->
            {error, nil}
    catch
        _:_ -> {error, nil}
    end.
