%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_FILE_IDENTITY_HRL).
-define(HTTP_FILE_IDENTITY_HRL, true).

%% Length-prefix the path and hash each file separately. A delimiter alone
%% cannot separate arbitrary binary contents from the following file's name.
file_identity_digest(Paths, Read, Casing) ->
    Sorted = lists:sort(Paths),
    Material = [<<"http3-file-set-v2", 0, (length(Sorted)):64/unsigned-big>> |
        [file_identity_frame(Path, Read(Path)) || Path <- Sorted]],
    binary:encode_hex(crypto:hash(sha256, Material), Casing).

file_identity_frame(Path, Contents) ->
    Name = unicode:characters_to_binary(Path),
    <<(byte_size(Name)):64/unsigned-big, Name/binary,
      (crypto:hash(sha256, Contents))/binary>>.

-endif.
