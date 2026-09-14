%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(compression_test_ffi).

-export([rfc1951_full_range_vector/0, rfc1952_optional_header_vector/0]).

%% Construct this independently of the production encoder. The first stored
%% block seeds exactly 32 KiB of history. The final fixed-Huffman block emits
%% length code 285 (258 bytes) at distance code 29 (32768 bytes), exercising
%% both maxima required of a conforming DEFLATE decoder.
-spec rfc1951_full_range_vector() -> {binary(), binary()}.
rfc1951_full_range_vector() ->
    History = binary:copy(list_to_binary(lists:seq(0, 255)), 128),
    Output = <<History/binary, (binary:part(History, 0, 258))/binary>>,
    Adler32 = erlang:adler32(Output),
    StoredBlock = <<0, 0, 128, 255, 127, History/binary>>,
    FixedMaximumCopy = <<27, 189, 255, 31, 0>>,
    Zlib = <<120, 1, StoredBlock/binary, FixedMaximumCopy/binary,
             Adler32:32/big>>,
    {Zlib, Output}.

%% Include every optional gzip header field, a non-ASCII LATIN-1 filename,
%% the corrected Apollo "Ap" subfield identifier from erratum 7517, and a
%% valid FHCRC. This fixture is independent of the production gzip encoder,
%% which intentionally emits only the deterministic minimal header.
-spec rfc1952_optional_header_vector() -> binary().
rfc1952_optional_header_vector() ->
    Extra = <<"Ap", 2:16/little, 1, 2>>,
    Header = <<31, 139, 8, 30, 0:32/little, 0, 255,
               (byte_size(Extra)):16/little, Extra/binary,
               "caf", 16#e9, 0, "line1", 10, "line2", 0>>,
    HeaderCrc16 = erlang:crc32(Header) band 16#ffff,
    DeflateAndTrailer = <<203, 72, 205, 201, 201, 7, 0,
                          134, 166, 16, 54, 5, 0, 0, 0>>,
    <<Header/binary, HeaderCrc16:16/little, DeflateAndTrailer/binary>>.
