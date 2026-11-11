%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(compression_test_ffi).

-export([rfc1951_full_range_vector/0, rfc1952_optional_header_vector/0,
         rfc8878_erratum_7297_vectors/0]).

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

%% The retained frame was produced by Zstandard CLI v1.5.7 from a deterministic
%% 256-byte corpus. The executable SHA-256 was
%% 959e8299adfbbc039f7d2aede537666aba5e605dec1169f582d88898554a728e;
%% the frame and decoded corpus SHA-256 values are respectively
%% 6e05708ba6e9026c6b0b23743c7ba34920e3ead1495c2f6a07e3086d22a56cc5 and
%% e41b5c9ffe12d9d878f388cc50812782256f173d0f6a2c4d6758800ad8e821f1.
%% It is independent of the production encoder and contains a four-stream
%% compressed literals section. The format-2 and format-3 controls preserve
%% its Huffman payload while expressing the same sizes in the other two legal
%% four-stream header layouts. Each negative fixture mutates exactly one size
%% to every value below the corrected lower bound of six from erratum 7297.
-spec rfc8878_erratum_7297_vectors() ->
    {[binary()], binary(), [binary()], [binary()]}.
rfc8878_erratum_7297_vectors() ->
    Base = decode_hex([
        <<"28b52ffd600000e506000610361e4065eca50cc1e4438030faad8d5f70d5128ac">>,
        <<"b4b3b436160d3611445d7042d002c002d0098c2a218f01a6ba45c6b62bf54b6">>,
        <<"4880ab11548dacfa226efa2991bbe2c752b5c40cbe8f38d40ea81b52533085ee">>,
        <<"df8938abc02762e331c6c0f4dd3697ce7893a10c1394e26cdb8e3759ca8b097">>,
        <<"d7427e84ce8194e0e5586ba854f324333a5ed620d79a2996406ae8351dc10a1f">>,
        <<"577257017232ac80cb3fc544597c35989d7ad8738fc3756a4adda3825f5805097">>,
        <<"b58ec789c6c64fa4ffd502e4e10f934b9bfbea9e3f97dc1fe504bc82c20031ac">>,
        <<"11aebe9d1f00">>
    ]),
    Expected = decode_hex([
        <<"686130626c347169352c696e6b777836616c674c53356e726a38456f77442e41">>,
        <<"54674c3862723262743938537a70547137622c2e70374c374c6e363030334855">>,
        <<"2e48614c696e44336471496467497167664845373152736f31352c4e6a655270">>,
        <<"20557a6964626e7a6774624e717744793461313455376633524e2e414454782e">>,
        <<"6c52556a78552e4131737131204c44336e546b726f7773757a38686b34535463">>,
        <<"726a787333376d6e707565547961387a486f646d4e534e677064486164457730">>,
        <<"78656a7174492c7575336d30325433206e48317164534478662e4c776e6a6c6e">>,
        <<"44767735384f2c7478676b66556a3437656635734e747041764c456f374e4c2c">>
    ]),
    Formats = [1, 2, 3],
    Valid = [rfc8878_four_stream_frame(Base, Format, 256, 216)
             || Format <- Formats],
    RegeneratedUnderflow = [
        rfc8878_four_stream_frame(Base, Format, Size, 216)
        || Format <- Formats, Size <- lists:seq(0, 5)
    ],
    CompressedUnderflow = [
        rfc8878_four_stream_frame(Base, Format, 256, Size)
        || Format <- Formats, Size <- lists:seq(0, 5)
    ],
    {Valid, Expected, RegeneratedUnderflow, CompressedUnderflow}.

-spec rfc8878_four_stream_frame(binary(), 1..3, non_neg_integer(),
                                non_neg_integer()) -> binary().
rfc8878_four_stream_frame(Base, Format, RegeneratedSize, CompressedSize) ->
    <<FrameHeader:7/binary, _OldBlockAndLiteralsHeader:6/binary,
      Payload/binary>> = Base,
    LiteralsHeader = rfc8878_four_stream_header(
        Format, RegeneratedSize, CompressedSize),
    BlockSize = byte_size(Payload) + byte_size(LiteralsHeader),
    %% Last_Block=1 and Block_Type=2 (compressed).
    BlockHeader = 1 bor (2 bsl 1) bor (BlockSize bsl 3),
    <<FrameHeader/binary, BlockHeader:24/little,
      LiteralsHeader/binary, Payload/binary>>.

-spec rfc8878_four_stream_header(1..3, non_neg_integer(),
                                 non_neg_integer()) -> binary().
rfc8878_four_stream_header(1, RegeneratedSize, CompressedSize) ->
    Value = 2 bor (1 bsl 2) bor (RegeneratedSize bsl 4)
            bor (CompressedSize bsl 14),
    <<Value:24/little>>;
rfc8878_four_stream_header(2, RegeneratedSize, CompressedSize) ->
    Value = 2 bor (2 bsl 2) bor (RegeneratedSize bsl 4)
            bor (CompressedSize bsl 18),
    <<Value:32/little>>;
rfc8878_four_stream_header(3, RegeneratedSize, CompressedSize) ->
    Value = 2 bor (3 bsl 2) bor (RegeneratedSize bsl 4)
            bor (CompressedSize bsl 22),
    <<Value:40/little>>.

-spec decode_hex(iodata()) -> binary().
decode_hex(Hex) ->
    binary:decode_hex(iolist_to_binary(Hex)).
