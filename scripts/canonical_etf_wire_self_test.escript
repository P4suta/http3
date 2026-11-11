#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-mode(compile).
-compile(nowarn_unused_function).
-include("canonical_etf_wire.hrl").

main([]) ->
    Term = #{schema => 1,
             rows => [{ready, 3}, {failed, 0}],
             digest => binary:copy(<<"a">>, 64)},
    Bytes = term_to_binary(Term, [{minor_version, 2}]),
    {ok, Term} = canonical_etf_decode(Bytes, 4096, 16, 64),
    Interop = canonical_etf_interop_fixture(),
    InteropBytes = term_to_binary(Interop, [{minor_version, 2}]),
    {ok, Interop} = canonical_etf_decode(InteropBytes, 4096, 16, 128),

    %% Alternate encodings, concatenated terms and duplicate map keys cannot
    %% acquire a valid application meaning after decoding.
    error = canonical_etf_decode(
        <<131, 98, 0, 0, 0, 1>>, 64, 4, 4),
    error = canonical_etf_decode(<<Bytes/binary, 0>>, 4096, 16, 64),
    error = canonical_etf_decode(
        <<131, 116, 0, 0, 0, 2,
          97, 1, 97, 2,
          97, 1, 97, 3>>, 64, 8, 16),

    %% Compressed ETF and runtime/executable capabilities are rejected by the
    %% byte scanner, before binary_to_term/2 is reached.
    Compressed = term_to_binary(
        lists:duplicate(4096, <<"compressible">>), [compressed]),
    <<131, 80, _/binary>> = Compressed,
    error = canonical_etf_decode(Compressed, byte_size(Compressed), 16, 5000),
    error = canonical_etf_decode(<<131, 103, 0>>, 64, 8, 8),
    error = canonical_etf_decode(<<131, 102, 0>>, 64, 8, 8),
    error = canonical_etf_decode(<<131, 101, 0>>, 64, 8, 8),
    error = canonical_etf_decode(<<131, 112, 0>>, 64, 8, 8),
    error = canonical_etf_decode(<<131, 113, 0>>, 64, 8, 8),

    %% [safe] must also reject an otherwise well-formed atom that was not
    %% already present in the VM's atom table.  The name remains binary data in
    %% this module and therefore cannot create the atom as a side effect.
    Unknown = <<"http_etf_unknown_atom_7f3b6f8db942">>,
    UnknownLength = byte_size(Unknown),
    UnknownWire = <<131, 119, UnknownLength:8, Unknown/binary>>,
    error = canonical_etf_decode(UnknownWire, 128, 4, 4),

    Deep = term_to_binary({{{{{bounded}}}}}, [{minor_version, 2}]),
    error = canonical_etf_decode(Deep, 256, 3, 32),
    error = canonical_etf_decode(Bytes, 4096, 16, 4),
    error = canonical_etf_decode(Bytes, byte_size(Bytes) - 1, 16, 64),
    error = canonical_etf_decode(<<>>, 64, 8, 8),
    io:put_chars(<<"CANONICAL_ETF_WIRE_SELF_TEST_READY\n">>),
    ok;
main(_) ->
    halt(2).
