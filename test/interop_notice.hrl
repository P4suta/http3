%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Shared by test-only native endpoints. The payload is a fixed bounded
%% readiness record, never a packet, certificate or exception value.
-ifndef(INTEROP_NOTICE_READ_ONLY).
interop_publish_notice(Path, Bytes) ->
    interop_publish_notice_with(Path, Bytes, fun file:write/2).

interop_publish_notice_with(Path, Bytes, Write)
  when is_binary(Bytes), byte_size(Bytes) > 0, byte_size(Bytes) =< 256 ->
    Pending = Path ++ ".pending",
    {ok, File} = file:open(Pending, [write, raw, binary, exclusive]),
    try
        ok = Write(File, Bytes),
        ok = file:close(File),
        ok = file:make_link(Pending, Path)
    after file:close(File), file:delete(Pending) end.
-endif.

interop_read_notice(Path, Limit) when is_integer(Limit), Limit > 0, Limit =< 256 ->
    case file:open(Path, [read, raw, binary]) of
        {ok, File} ->
            try
                case file:read(File, Limit + 1) of
                    {ok, Bytes} when byte_size(Bytes) =< Limit -> {ok, Bytes};
                    {ok, _} -> {error, notice_too_large};
                    eof -> {ok, <<>>};
                    Error -> Error
                end
            after file:close(File) end;
        Error -> Error
    end.
