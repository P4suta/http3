%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_CANONICAL_ETF_WIRE_HRL).
-define(HTTP_CANONICAL_ETF_WIRE_HRL, true).
-compile({nowarn_unused_function, [
    {canonical_etf_decode, 4},
    {canonical_etf_interop_fixture, 0},
    {canonical_etf_scan, 4},
    {canonical_etf_leaf_bytes, 3},
    {canonical_etf_composite, 5}
]}).

%% A value with every accepted data family whose minor-version-2 bytes must be
%% identical on OTP 28 and 29.  Each runtime emits, hashes and decodes this
%% exact value; the matrix aggregate compares those hashes across all rows.
canonical_etf_interop_fixture() ->
    {canonical_etf_interop_fixture_v1,
     #{schema => 1,
       integers => [-2147483649, -1, 0, 255, 256, 2147483647,
                    2147483648, (1 bsl 130)],
       float => 1.5,
       bytes => <<0, 127, 128, 255>>,
       bits => <<5:3>>,
       nested => [{ready, 3}, {failed, 0}],
       improper => [head | tail]}}.

%% Validate the external-term wire representation before binary_to_term/2.
%% The reader accepts only finite, data-only ETF nodes, rejects compressed
%% terms and executable/runtime capabilities, and requires the exact canonical
%% minor-version-2 encoding after the safe decode.  Callers still validate the
%% closed application schema after this generic boundary.
canonical_etf_decode(Bytes, MaximumBytes, MaximumDepth, MaximumNodes)
  when is_binary(Bytes), is_integer(MaximumBytes), MaximumBytes > 1,
       is_integer(MaximumDepth), MaximumDepth > 0,
       is_integer(MaximumNodes), MaximumNodes > 0 ->
    try
        true = byte_size(Bytes) > 1,
        true = byte_size(Bytes) =< MaximumBytes,
        <<131, Wire/binary>> = Bytes,
        {ok, <<>>, Remaining} = canonical_etf_scan(
            Wire, 0, MaximumDepth, MaximumNodes),
        true = Remaining >= 0,
        Term = erlang:binary_to_term(Bytes, [safe]),
        Bytes = erlang:term_to_binary(Term, [{minor_version, 2}]),
        {ok, Term}
    catch _:_ -> error end;
canonical_etf_decode(_, _, _, _) -> error.

canonical_etf_scan(_, Depth, MaximumDepth, _) when Depth > MaximumDepth ->
    error;
canonical_etf_scan(_, _, _, Budget) when Budget =< 0 ->
    error;
%% SMALL_INTEGER_EXT
canonical_etf_scan(<<97, _:8, Rest/binary>>, _, _, Budget) ->
    {ok, Rest, Budget - 1};
%% INTEGER_EXT
canonical_etf_scan(<<98, _:32, Rest/binary>>, _, _, Budget) ->
    {ok, Rest, Budget - 1};
%% FLOAT_EXT and NEW_FLOAT_EXT
canonical_etf_scan(<<99, _:31/binary, Rest/binary>>, _, _, Budget) ->
    {ok, Rest, Budget - 1};
canonical_etf_scan(<<70, _:8/binary, Rest/binary>>, _, _, Budget) ->
    {ok, Rest, Budget - 1};
%% ATOM_EXT, SMALL_ATOM_EXT, ATOM_UTF8_EXT, SMALL_ATOM_UTF8_EXT.  The
%% subsequent [safe] decode additionally requires every atom to exist already.
canonical_etf_scan(<<100, Length:16, Rest0/binary>>, _, _, Budget) ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
canonical_etf_scan(<<115, Length:8, Rest0/binary>>, _, _, Budget) ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
canonical_etf_scan(<<118, Length:16, Rest0/binary>>, _, _, Budget) ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
canonical_etf_scan(<<119, Length:8, Rest0/binary>>, _, _, Budget) ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
%% SMALL_TUPLE_EXT and LARGE_TUPLE_EXT
canonical_etf_scan(<<104, Arity:8, Rest/binary>>, Depth, MaximumDepth,
                   Budget) ->
    canonical_etf_composite(
        Arity, Rest, Depth, MaximumDepth, Budget - 1);
canonical_etf_scan(<<105, Arity:32, Rest/binary>>, Depth, MaximumDepth,
                   Budget) ->
    canonical_etf_composite(
        Arity, Rest, Depth, MaximumDepth, Budget - 1);
%% NIL_EXT
canonical_etf_scan(<<106, Rest/binary>>, _, _, Budget) ->
    {ok, Rest, Budget - 1};
%% STRING_EXT
canonical_etf_scan(<<107, Length:16, Rest0/binary>>, _, _, Budget) ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
%% LIST_EXT.  The tail is a term and is scanned separately, including for an
%% improper list. Canonical re-encoding rejects noncanonical zero-length lists.
canonical_etf_scan(<<108, Length:32, Rest/binary>>, Depth, MaximumDepth,
                   Budget) when Length =< Budget - 1 ->
    case canonical_etf_composite(
             Length, Rest, Depth, MaximumDepth, Budget - 1) of
        {ok, Tail0, Remaining0} ->
            canonical_etf_scan(
                Tail0, Depth + 1, MaximumDepth, Remaining0);
        error -> error
    end;
%% BINARY_EXT
canonical_etf_scan(<<109, Length:32, Rest0/binary>>, _, _, Budget) ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
%% SMALL_BIG_EXT and LARGE_BIG_EXT
canonical_etf_scan(<<110, Length:8, Sign:8, Rest0/binary>>, _, _, Budget)
  when Sign =:= 0; Sign =:= 1 ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
canonical_etf_scan(<<111, Length:32, Sign:8, Rest0/binary>>, _, _, Budget)
  when Sign =:= 0; Sign =:= 1 ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
%% MAP_EXT
canonical_etf_scan(<<116, Arity:32, Rest/binary>>, Depth, MaximumDepth,
                   Budget) when Arity =< (Budget - 1) div 2 ->
    canonical_etf_composite(
        Arity * 2, Rest, Depth, MaximumDepth, Budget - 1);
%% BIT_BINARY_EXT
canonical_etf_scan(<<77, Length:32, Bits:8, Rest0/binary>>, _, _, Budget)
  when Bits >= 1, Bits =< 8 ->
    canonical_etf_leaf_bytes(Length, Rest0, Budget);
%% Deliberately absent: COMPRESSED, atom-cache references, PIDs, ports,
%% references, funs and exports.  They are not evidence data.
canonical_etf_scan(_, _, _, _) -> error.

canonical_etf_leaf_bytes(Length, Rest0, Budget)
  when is_integer(Length), Length >= 0, Length =< byte_size(Rest0) ->
    <<_:Length/binary, Rest/binary>> = Rest0,
    {ok, Rest, Budget - 1};
canonical_etf_leaf_bytes(_, _, _) -> error.

canonical_etf_composite(Count, Rest, _, _, Budget)
  when Count =:= 0, Budget >= 0 ->
    {ok, Rest, Budget};
canonical_etf_composite(Count, Rest0, Depth, MaximumDepth, Budget)
  when is_integer(Count), Count > 0, Count =< Budget ->
    case canonical_etf_scan(
             Rest0, Depth + 1, MaximumDepth, Budget) of
        {ok, Rest1, Remaining1} ->
            canonical_etf_composite(
                Count - 1, Rest1, Depth, MaximumDepth, Remaining1);
        error -> error
    end;
canonical_etf_composite(_, _, _, _, _) -> error.

-endif.
