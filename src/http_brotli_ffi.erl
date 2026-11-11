%% SPDX-FileCopyrightText: 2015 Google Inc.
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT
%%
%% Pure BEAM RFC 7932 decoder. No native library, process, ETS table, or global
%% state is created. Every input read, output growth, and parser iteration is
%% charged to the caller's finite budget. One work unit is 1024 primitive
%% parser/output steps. Output storage grows in fixed 1024-byte chunks rather
%% than allocating the advertised window up front.
%% Canonical-code, context, and distance layout follows RFC 7932 and the MIT
%% Google decoder at revision 4508218e7fef90fa4273286f7a415065946f2c43:
%% https://github.com/google/brotli/tree/4508218e7fef90fa4273286f7a415065946f2c43/java/org/brotli/dec
%% Raw dictionary behavior follows RFC 9841 section 3.2 and RFC 9842 section 4.
%% See LICENSES/LicenseRef-Brotli-MIT.txt for the preserved upstream license.
-module(http_brotli_ffi).
-export([decode/6]).
-include("http_brotli_tables.hrl").

-record(s, {input, bit = 0, remaining, allowed, window = 0,
            dictionary = <<>>, size = 0, chunks, partial = <<>>,
            distances = {4, 11, 15, 16}, large = false}).
-record(block, {count = 1, left = 16777216, previous = 1, current = 0,
                types, lengths, used = 1}).
-record(meta, {literal, command, distance, postfix, direct, modes,
               literal_map, distance_map, literal_trees, command_trees,
               distance_trees}).

-spec decode(binary(), binary(), non_neg_integer(), pos_integer(),
             pos_integer(), pos_integer()) -> {ok, binary()} | {error, 1 | 2}.
decode(Input, Dictionary, MaximumOutput, MaximumRatio, MaximumWork, WindowLog)
  when is_binary(Input), is_binary(Dictionary), is_integer(MaximumOutput),
       MaximumOutput >= 0, is_integer(MaximumRatio), MaximumRatio > 0,
       is_integer(MaximumWork), MaximumWork > 0, is_integer(WindowLog),
       WindowLog >= 10, WindowLog =< 27 ->
    try
        Initial = #s{input = Input, remaining = MaximumWork * 1024,
                     allowed = min(MaximumOutput, byte_size(Input) * MaximumRatio),
                     dictionary = Dictionary, chunks = array:new()},
        {Bits, Header} = window_bits(Initial),
        ensure(Bits =< WindowLog, 2),
        Final = metablocks(Header#s{window = (1 bsl Bits) - 16}),
        {ok, iolist_to_binary([array:to_list(Final#s.chunks), Final#s.partial])}
    catch
        throw:{brotli, Code} -> {error, Code}
    end;
decode(_, _, _, _, _, _) -> {error, 1}.

ensure(true, _) -> ok;
ensure(false, Code) -> throw({brotli, Code}).

spend(Count, S = #s{remaining = Left}) ->
    ensure(Count =< Left, 2),
    S#s{remaining = Left - Count}.

bits(Count, S) when Count >= 0, Count =< 62 ->
    ensure(S#s.bit + Count =< bit_size(S#s.input), 1),
    read_bits(Count, spend(1, S), 0, 0).

read_bits(0, S, _, Value) -> {Value, S};
read_bits(Count, S = #s{input = Input, bit = Offset}, Shift, Value) ->
    Available = min(Count, 8 - (Offset band 7)),
    Byte = binary:at(Input, Offset bsr 3),
    Part = (Byte bsr (Offset band 7)) band ((1 bsl Available) - 1),
    read_bits(Count - Available, S#s{bit = Offset + Available},
              Shift + Available, Value bor (Part bsl Shift)).

aligned(S) ->
    {Padding, Next} = bits((8 - (S#s.bit band 7)) band 7, S),
    ensure(Padding =:= 0, 1),
    Next.

window_bits(S) ->
    case bits(1, S) of
        {0, Next} -> {16, Next};
        {1, Next} ->
            case bits(3, Next) of
                {0, More} ->
                    {Small, Last} = bits(3, More),
                    case Small of
                        0 -> {17, Last};
                        1 -> large_window(Last);
                        _ -> {8 + Small, Last}
                    end;
                {Large, More} -> {17 + Large, More}
            end
    end.

large_window(S) ->
    ensure(S#s.dictionary =/= <<>>, 1),
    {Reserved, S1} = bits(1, S),
    ensure(Reserved =:= 0, 1),
    {Width, S2} = bits(6, S1),
    ensure(Width >= 10, 1),
    %% RFC 9842 restricts DCB windows to 16 MiB even though RFC 9841's
    %% alternative header can represent much larger windows. That fixed wire
    %% contract is an encoding error; only a valid advertised window above the
    %% caller's configured ceiling is a resource-limit failure.
    ensure(Width =< 24, 1),
    {Width, S2#s{large = true}}.

metablocks(S0) ->
    {Last, S1} = bits(1, S0),
    {Empty, S2} = case Last of
        1 -> bits(1, S1);
        0 -> {0, S1}
    end,
    case Empty of
        1 -> finish(S2);
        0 ->
            {Nibbles, S3} = bits(2, S2),
            case Nibbles of
                3 ->
                    S4 = metadata(S3),
                    next_metablock(Last, S4);
                _ ->
                    Count = Nibbles + 4,
                    {LengthMinusOne, S4} = bits(Count * 4, S3),
                    ensure(Count =:= 4 orelse
                           (LengthMinusOne bsr ((Count - 1) * 4)) =/= 0, 1),
                    Length = LengthMinusOne + 1,
                    ensure(S4#s.size + Length =< S4#s.allowed, 2),
                    {Stored, S5} = case Last of
                        0 -> bits(1, S4);
                        1 -> {0, S4}
                    end,
                    S6 = case Stored of
                        1 -> stored(Length, aligned(S5));
                        0 -> compressed(Length, S5)
                    end,
                    next_metablock(Last, S6)
            end
    end.

next_metablock(0, S) -> metablocks(S);
next_metablock(1, S) -> finish(S).

finish(S) ->
    Next = aligned(S),
    ensure(Next#s.bit =:= bit_size(Next#s.input), 1),
    Next.

metadata(S0) ->
    {Reserved, S1} = bits(1, S0),
    ensure(Reserved =:= 0, 1),
    {Bytes, S2} = bits(2, S1),
    {Length, S3} = case Bytes of
        0 -> {0, S2};
        _ ->
            {MinusOne, Next} = bits(Bytes * 8, S2),
            ensure(Bytes =:= 1 orelse
                   (MinusOne bsr ((Bytes - 1) * 8)) =/= 0, 1),
            {MinusOne + 1, Next}
    end,
    S4 = aligned(S3),
    ensure(S4#s.bit + Length * 8 =< bit_size(S4#s.input), 1),
    spend(1 + Length, S4#s{bit = S4#s.bit + Length * 8}).

stored(Length, S) ->
    ensure(S#s.bit + Length * 8 =< bit_size(S#s.input), 1),
    Value = binary:part(S#s.input, S#s.bit bsr 3, Length),
    append(Value, S#s{bit = S#s.bit + Length * 8}).

append(Value, S) ->
    ensure(S#s.size + byte_size(Value) =< S#s.allowed, 2),
    append_chunks(Value, spend(byte_size(Value), S)).

append_chunks(<<>>, S) -> S;
append_chunks(Value, S = #s{partial = Partial, chunks = Chunks, size = Size}) ->
    Count = min(byte_size(Value), 1024 - byte_size(Partial)),
    <<Part:Count/binary, Rest/binary>> = Value,
    Chunk = <<Partial/binary, Part/binary>>,
    case byte_size(Chunk) of
        1024 ->
            append_chunks(Rest, S#s{partial = <<>>, size = Size + Count,
                                    chunks = array:set(Size div 1024, Chunk, Chunks)});
        _ -> S#s{partial = Chunk, size = Size + Count}
    end.

%% RFC 7932 sections 3 and 6. Trees contain at most 704 symbols, and the
%% three block-type alphabets contain at most 258 symbols each. Canonical
%% codes are stored sparsely; no allocation depends on a 2^15 lookup table.
varbyte(S) ->
    case bits(1, S) of
        {0, Next} -> {0, Next};
        {1, Next} ->
            case bits(3, Next) of
                {0, Last} -> {1, Last};
                {N, More} ->
                    {Value, Last} = bits(N, More),
                    {Value + (1 bsl N), Last}
            end
    end.

huffman(Alphabet, S) ->
    %% Reserve work before allocating lengths, sorting canonical codes, or
    %% constructing the sparse tree. Alphabet is bounded by the wire grammar.
    Reserved = spend(Alphabet * (width(Alphabet - 1, 0) + 1), S),
    {Kind, Next} = bits(2, Reserved),
    case Kind of
        1 -> simple_huffman(Alphabet, Next);
        _ -> complex_huffman(Alphabet, Kind, Next)
    end.

simple_huffman(Alphabet, S0) ->
    {MinusOne, S1} = bits(2, S0),
    Count = MinusOne + 1,
    {Symbols, S2} = read_values(Count, width(Alphabet - 1, 0), S1, []),
    ensure(length(lists:usort(Symbols)) =:= Count, 1),
    ensure(lists:all(fun(Symbol) -> Symbol < Alphabet end, Symbols), 1),
    {Lengths, S3} = case Count of
        1 -> {[0], S2};
        2 -> {[1, 1], S2};
        3 -> {[1, 2, 2], S2};
        4 ->
            case bits(1, S2) of
                {0, More} -> {[2, 2, 2, 2], More};
                {1, More} -> {[1, 2, 3, 3], More}
            end
    end,
    case Symbols of
        [Only] -> {{single, Only}, S3};
        _ -> {tree(lists:zip(Lengths, Symbols)), S3}
    end.

width(0, Width) -> Width;
width(Value, Width) -> width(Value bsr 1, Width + 1).

read_values(Count, Width, S) -> read_values(Count, Width, S, []).

read_values(0, _, S, Reversed) -> {lists:reverse(Reversed), S};
read_values(Count, Width, S, Reversed) ->
    {Value, Next} = bits(Width, S),
    read_values(Count - 1, Width, Next, [Value | Reversed]).

complex_huffman(Alphabet, Skip, S0) ->
    Order = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    {Codes, Space, S1} = length_alphabet(lists:nthtail(Skip, Order), 32, [], S0),
    ensure(Space =:= 0 orelse length(Codes) =:= 1, 1),
    LengthTree = case Codes of
        [{_, Only}] -> {single, Only};
        _ -> tree(Codes)
    end,
    {Lengths, S2} = code_lengths(Alphabet, LengthTree, 0, 8, 0, 0, 32768, [], S1),
    {tree(Lengths), S2}.

length_alphabet(_, 0, Codes, S) -> {Codes, 0, S};
length_alphabet([], Space, Codes, S) -> {Codes, Space, S};
length_alphabet([Symbol | Rest], Space, Codes, S0) ->
    {Length, S1} = length_code(S0),
    case Length of
        0 -> length_alphabet(Rest, Space, Codes, S1);
        _ ->
            Left = Space - (32 bsr Length),
            ensure(Left >= 0, 1),
            length_alphabet(Rest, Left, [{Length, Symbol} | Codes], S1)
    end.

length_code(S) ->
    case bits(2, S) of
        {0, Next} -> {0, Next};
        {1, Next} -> {4, Next};
        {2, Next} -> {3, Next};
        {3, Next} ->
            case bits(1, Next) of
                {0, More} -> {2, More};
                {1, More} ->
                    case bits(1, More) of
                        {0, Last} -> {1, Last};
                        {1, Last} -> {5, Last}
                    end
            end
    end.

code_lengths(_, _, _, _, _, _, 0, Acc, S) -> {Acc, S};
code_lengths(Alphabet, _, Index, _, _, _, _, _, _) when Index >= Alphabet ->
    throw({brotli, 1});
code_lengths(Alphabet, Tree, Index, Previous, Repeat, RepeatLength, Space, Acc, S0) ->
    {Code, S1} = symbol(Tree, S0),
    case Code < 16 of
        true ->
            {NextPrevious, NextAcc, Used} = case Code of
                0 -> {Previous, Acc, 0};
                _ -> {Code, [{Code, Index} | Acc], 32768 bsr Code}
            end,
            ensure(Used =< Space, 1),
            code_lengths(Alphabet, Tree, Index + 1, NextPrevious, 0,
                         RepeatLength, Space - Used, NextAcc, S1);
        false ->
            ExtraBits = Code - 14,
            Length = case Code of
                16 -> Previous;
                17 -> 0
            end,
            OldRepeat = case Length =:= RepeatLength of
                true -> Repeat;
                false -> 0
            end,
            Base = case OldRepeat of
                0 -> 0;
                _ -> (OldRepeat - 2) bsl ExtraBits
            end,
            {Extra, S2} = bits(ExtraBits, S1),
            NewRepeat = Base + Extra + 3,
            Delta = NewRepeat - OldRepeat,
            ensure(Index + Delta =< Alphabet, 1),
            Used = case Length of
                0 -> 0;
                _ -> Delta bsl (15 - Length)
            end,
            ensure(Used =< Space, 1),
            S3 = spend(Delta, S2),
            Added = case Length of
                0 -> Acc;
                _ -> [{Length, I} || I <- lists:seq(Index, Index + Delta - 1)] ++ Acc
            end,
            code_lengths(Alphabet, Tree, Index + Delta, Previous, NewRepeat,
                         Length, Space - Used, Added, S3)
    end.

tree(Codes) ->
    Sorted = lists:sort(Codes),
    ensure(Sorted =/= [], 1),
    {Map, Max, NextCode} = canonical(Sorted, 0, 0, #{}),
    ensure(NextCode =:= (1 bsl Max), 1),
    {tree, Map, Max}.

canonical([], Code, Previous, Map) -> {Map, Previous, Code};
canonical([{Length, Symbol} | Rest], Code, Previous, Map) ->
    Shifted = Code bsl (Length - Previous),
    ensure(Length > 0 andalso Length =< 15 andalso Shifted < (1 bsl Length), 1),
    canonical(Rest, Shifted + 1, Length, Map#{{Length, Shifted} => Symbol}).

symbol({single, Value}, S) -> {Value, spend(1, S)};
symbol({tree, Map, Max}, S) -> symbol_bits(Map, Max, 0, 0, S).

symbol_bits(_, Max, Max, _, _) -> throw({brotli, 1});
symbol_bits(Map, Max, Length, Code, S) ->
    {Bit, Next} = bits(1, S),
    Prefix = (Code bsl 1) bor Bit,
    case maps:find({Length + 1, Prefix}, Map) of
        {ok, Value} -> {Value, Next};
        error -> symbol_bits(Map, Max, Length + 1, Prefix, Next)
    end.

block(S0) ->
    {MinusOne, S1} = varbyte(S0),
    Count = MinusOne + 1,
    case Count of
        1 -> {#block{}, S1};
        _ ->
            {Types, S2} = huffman(Count + 2, S1),
            {Lengths, S3} = huffman(26, S2),
            {Left, S4} = block_length(Lengths, S3),
            {#block{count = Count, left = Left, types = Types, lengths = Lengths}, S4}
    end.

block_length(Tree, S) ->
    Offsets = {1,5,9,13,17,25,33,41,49,65,81,97,113,145,177,209,241,305,
               369,497,753,1265,2289,4337,8433,16625},
    Widths = {2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,6,6,7,8,9,10,11,12,13,24},
    {Code, S1} = symbol(Tree, S),
    {Extra, S2} = bits(element(Code + 1, Widths), S1),
    {element(Code + 1, Offsets) + Extra, S2}.

switch(Block = #block{left = Left}, S) when Left > 0 ->
    {Block#block{left = Left - 1}, S};
switch(Block, S0) ->
    {Code, S1} = symbol(Block#block.types, S0),
    {Left, S2} = block_length(Block#block.lengths, S1),
    NextType = case Code of
        0 -> Block#block.previous;
        1 -> Block#block.current + 1;
        _ -> Code - 2
    end rem Block#block.count,
    ensure(NextType =/= Block#block.current, 1),
    {Block#block{left = Left - 1, previous = Block#block.current,
                  current = NextType, used = Block#block.used bor (1 bsl NextType)}, S2}.

context_map(Count, S0) ->
    {MinusOne, S1} = varbyte(S0),
    Trees = MinusOne + 1,
    case Trees of
        1 ->
            Reserved = spend(Count, S1),
            {1, list_to_tuple(lists:duplicate(Count, 0)), Reserved};
        _ ->
            {Rle, S2} = bits(1, S1),
            {MaxRun, S3} = case Rle of
                0 -> {0, S2};
                1 ->
                    {Value, Next} = bits(4, S2),
                    {Value + 1, Next}
            end,
            {Tree, S4} = huffman(Trees + MaxRun, S3),
            {Values, S5} = context_values(Count, MaxRun, Tree, [], S4),
            {Mtf, S6} = bits(1, S5),
            S7 = spend(Count, S6),
            {Map, S8} = case Mtf of
                0 -> {Values, S7};
                1 -> unmtf(Values, lists:seq(0, 255), [], spend(256, S7))
            end,
            %% At most 256 indices and 16384 map cells. Validate after inverse
            %% MTF: its encoded ranks are not the declared tree indices.
            S9 = spend(Count, S8),
            Used = lists:foldl(fun(V, Acc) ->
                ensure(V < Trees, 1),
                Acc bor (1 bsl V)
            end, 0, Map),
            ensure(Used =:= (1 bsl Trees) - 1, 1),
            {Trees, list_to_tuple(Map), S9}
    end.

context_values(0, _, _, Acc, S) -> {lists:reverse(Acc), S};
context_values(Count, MaxRun, Tree, Acc, S0) ->
    {Code, S1} = symbol(Tree, S0),
    case Code > 0 andalso Code =< MaxRun of
        true ->
            {Extra, S2} = bits(Code, S1),
            Run = (1 bsl Code) + Extra,
            ensure(Run =< Count, 1),
            S3 = spend(Run, S2),
            context_values(Count - Run, MaxRun, Tree,
                           lists:duplicate(Run, 0) ++ Acc, S3);
        false ->
            Value = case Code of
                0 -> 0;
                _ -> Code - MaxRun
            end,
            context_values(Count - 1, MaxRun, Tree, [Value | Acc], S1)
    end.

unmtf([], _, Acc, S) -> {lists:reverse(Acc), S};
unmtf([Index | Rest], Order, Acc, S0) ->
    S1 = spend(Index + 1, S0),
    {Before, [Value | After]} = lists:split(Index, Order),
    unmtf(Rest, [Value | Before ++ After], [Value | Acc], S1).

trees(0, _, S, Acc) -> {list_to_tuple(lists:reverse(Acc)), S};
trees(Count, Alphabet, S0, Acc) ->
    {Tree, S1} = huffman(Alphabet, S0),
    trees(Count - 1, Alphabet, S1, [Tree | Acc]).

compressed(Length, S0) ->
    {Literal, S1} = block(S0),
    {Command, S2} = block(S1),
    {Distance, S3} = block(S2),
    {Postfix, S4} = bits(2, S3),
    {DirectHigh, S5} = bits(4, S4),
    Direct = DirectHigh bsl Postfix,
    {ModeList, S6} = read_values(Literal#block.count, 2, S5),
    {LiteralCount, LiteralMap, S7} = context_map(Literal#block.count * 64, S6),
    {DistanceCount, DistanceMap, S8} = context_map(Distance#block.count * 4, S7),
    {LiteralTrees, S9} = trees(LiteralCount, 256, S8, []),
    {CommandTrees, S10} = trees(Command#block.count, 704, S9, []),
    DistanceBits = case S10#s.large of
        true -> 124;
        false -> 48
    end,
    {DistanceTrees, S11} = distance_trees(DistanceCount,
        16 + Direct + (DistanceBits bsl Postfix), Postfix, Direct, S10, []),
    Meta = #meta{literal = Literal, command = Command, distance = Distance,
                 postfix = Postfix, direct = Direct, modes = list_to_tuple(ModeList),
                 literal_map = LiteralMap, distance_map = DistanceMap,
                 literal_trees = LiteralTrees, command_trees = CommandTrees,
                 distance_trees = DistanceTrees},
    commands(S11#s.size + Length, Meta, S11).

distance_trees(0, _, _, _, S, Acc) -> {list_to_tuple(lists:reverse(Acc)), S};
distance_trees(Count, Alphabet, Postfix, Direct, S0, Acc) ->
    {Tree, S1} = huffman(Alphabet, S0),
    Codes = case Tree of
        {single, Value} -> [Value];
        {tree, Map, _} -> maps:values(Map)
    end,
    %% RFC 9841 section 6 forbids such symbols in the alphabet, even if the
    %% final command emits only literals and never reads the distance tree.
    lists:foreach(fun(Code) ->
        ensure(distance_maximum(Code, Postfix, Direct) =< (1 bsl 63) - 4, 1)
    end, Codes),
    distance_trees(Count-1, Alphabet, Postfix, Direct, S1, [Tree|Acc]).

distance_maximum(Code, _, Direct) when Code < 16 + Direct -> 16;
distance_maximum(Code, Postfix, Direct) ->
    Value = Code - Direct - 16,
    Low = Value band ((1 bsl Postfix) - 1),
    High = Value bsr Postfix,
    Width = (High bsr 1) + 1,
    Offset = ((2 + (High band 1)) bsl Width) - 4,
    ((Offset + (1 bsl Width) - 1) bsl Postfix) + Low + Direct + 1.

commands(End, Meta, S) when S#s.size =:= End -> complete_compressed(Meta, S);
commands(End, Meta0, S0) ->
    {Block, S1} = switch(Meta0#meta.command, S0),
    {Code, S2} = symbol(element(Block#block.current + 1, Meta0#meta.command_trees), S1),
    {Insert, Copy, Implicit, S3} = command_lengths(Code, S2),
    ensure(S3#s.size + Insert =< End, 1),
    {Meta1, S4} = literals(Insert, Meta0#meta{command = Block}, S3),
    case S4#s.size =:= End of
        true -> complete_compressed(Meta1, S4);
        false ->
            {Distance, DistanceCode, Meta2, S5} = distance(Copy, Implicit, Meta1, S4),
            S6 = copy(Distance, DistanceCode, Copy, End, S5),
            commands(End, Meta2, S6)
    end.

complete_compressed(Meta, S) ->
    %% One bounded bitmap per category; the initial block is implicitly type
    %% zero even when that category has no symbols in the final command.
    lists:foreach(fun(Block) ->
        ensure(Block#block.used =:= (1 bsl Block#block.count) - 1, 1)
    end, [Meta#meta.literal, Meta#meta.command, Meta#meta.distance]),
    spend(3, S).

command_lengths(Code, S0) ->
    Range = Code bsr 6,
    Group = case Range < 2 of
        true -> Range;
        false -> Range - 2
    end,
    InsertCode = (((16#29850 bsr (Group * 2)) band 3) bsl 3) bor ((Code bsr 3) band 7),
    CopyCode = (((16#26244 bsr (Group * 2)) band 3) bsl 3) bor (Code band 7),
    InsertWidths = {0,0,0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,7,8,9,10,12,14,24},
    CopyWidths = {0,0,0,0,0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,7,8,9,10,24},
    {InsertExtra, S1} = bits(element(InsertCode + 1, InsertWidths), S0),
    {CopyExtra, S2} = bits(element(CopyCode + 1, CopyWidths), S1),
    {length_base(InsertCode, InsertWidths, 0) + InsertExtra,
     length_base(CopyCode, CopyWidths, 2) + CopyExtra, Range < 2, S2}.

length_base(0, _, Acc) -> Acc;
length_base(Code, Widths, Acc) ->
    length_base(Code - 1, Widths, Acc + (1 bsl element(Code, Widths))).

literals(0, Meta, S) -> {Meta, S};
literals(Count, Meta, S0) ->
    {Block, S1} = switch(Meta#meta.literal, S0),
    Mode = element(Block#block.current + 1, Meta#meta.modes),
    Context = literal_context(Mode, previous_byte(1, S1), previous_byte(2, S1)),
    Index = element(Block#block.current * 64 + Context + 1, Meta#meta.literal_map),
    {Byte, S2} = symbol(element(Index + 1, Meta#meta.literal_trees), S1),
    literals(Count - 1, Meta#meta{literal = Block}, append(<<Byte>>, S2)).

previous_byte(Distance, S) when Distance > S#s.size -> 0;
previous_byte(Distance, S) -> output_byte(S#s.size - Distance, S).

output_byte(Index, S) ->
    ChunkIndex = Index div 1024,
    Chunk = case ChunkIndex =:= S#s.size div 1024 of
        true -> S#s.partial;
        false -> array:get(ChunkIndex, S#s.chunks)
    end,
    binary:at(Chunk, Index rem 1024).

literal_context(0, Previous, _) -> Previous band 63;
literal_context(1, Previous, _) -> Previous bsr 2;
literal_context(2, Previous, Before) -> utf8_context(Previous, Before);
literal_context(3, Previous, Before) -> (signed_context(Previous) bsl 3) bor signed_context(Before).

signed_context(0) -> 0;
signed_context(Byte) when Byte < 16 -> 1;
signed_context(Byte) when Byte < 240 -> 2 + (Byte bsr 6);
signed_context(Byte) when Byte < 255 -> 6;
signed_context(255) -> 7.

utf8_context(Previous, Before) ->
    binary:at(?BROTLI_UTF8_CONTEXT, Previous) bor
    binary:at(?BROTLI_UTF8_CONTEXT, 256 + Before).

distance(_Copy, true, Meta, S) -> {element(1, S#s.distances), 0, Meta, S};
distance(Copy, false, Meta, S0) ->
    {Block, S1} = switch(Meta#meta.distance, S0),
    Context = min(Copy, 5) - 2,
    Index = element(Block#block.current * 4 + Context + 1, Meta#meta.distance_map),
    {Code, S2} = symbol(element(Index + 1, Meta#meta.distance_trees), S1),
    {Value, S3} = distance_value(Code, Meta#meta.postfix, Meta#meta.direct, S2),
    ensure(Value > 0, 1),
    {Value, Code, Meta#meta{distance = Block}, S3}.

distance_value(Code, _, _, S) when Code < 16 ->
    Indexes = {1,2,3,4,1,1,1,1,1,1,2,2,2,2,2,2},
    Deltas = {0,0,0,0,-1,1,-2,2,-3,3,-1,1,-2,2,-3,3},
    {element(element(Code + 1, Indexes), S#s.distances) + element(Code + 1, Deltas), S};
distance_value(Code, _, Direct, S) when Code < 16 + Direct -> {Code - 15, S};
distance_value(Code, Postfix, Direct, S0) ->
    Value = Code - Direct - 16,
    Low = Value band ((1 bsl Postfix) - 1),
    High = Value bsr Postfix,
    Width = (High bsr 1) + 1,
    Offset = ((2 + (High band 1)) bsl Width) - 4,
    ensure(((Offset + (1 bsl Width) - 1) bsl Postfix) + Low + Direct + 1
           =< (1 bsl 63) - 4, 1),
    {Extra, S1} = bits(Width, S0),
    {((Offset + Extra) bsl Postfix) + Low + Direct + 1, S1}.

copy(Distance, Code, Length, End, S) ->
    Maximum = min(S#s.size, S#s.window),
    case Distance =< Maximum of
        true ->
            ensure(S#s.size + Length =< End, 1),
            copy_history(Length, Distance, cache_distance(Distance, Code, S));
        false -> dictionary_copy(Distance - Maximum - 1, Distance, Code, Length, End, S)
    end.

cache_distance(_, 0, S) -> S;
cache_distance(Distance, _, S = #s{distances = {First, Second, Third, _}}) ->
    S#s{distances = {Distance, First, Second, Third}}.

copy_history(0, _, S) -> S;
copy_history(Count, Distance, S) ->
    Byte = output_byte(S#s.size - Distance, S),
    copy_history(Count - 1, Distance, append(<<Byte>>, S)).

dictionary_copy(Address, Distance, Code, Length, End, S) ->
    DictionaryLength = byte_size(S#s.dictionary),
    case Address < DictionaryLength of
        true ->
            ensure(S#s.size + Length =< End, 1),
            Start = DictionaryLength - Address - 1,
            PrefixLength = min(Length, DictionaryLength - Start),
            Prefix = binary:part(S#s.dictionary, Start, PrefixLength),
            WindowStart = S#s.size - min(S#s.size, S#s.window),
            Next = append(Prefix, cache_distance(Distance, Code, S)),
            copy_history(Length - PrefixLength, Next#s.size - WindowStart, Next);
        false ->
            Value = static_word(Address - DictionaryLength, Length),
            ensure(S#s.size + byte_size(Value) =< End, 1),
            append(Value, S)
    end.

static_word(Address, Length) ->
    ensure(Length >= 4 andalso Length =< 24, 1),
    SizeBits = {0,0,0,0,10,10,11,11,10,10,10,10,10,9,9,8,7,7,8,7,7,6,6,5,5},
    Width = element(Length + 1, SizeBits),
    Index = Address band ((1 bsl Width) - 1),
    Transform = Address bsr Width,
    ensure(Transform < 121, 1),
    Offset = dictionary_offset(Length - 1, SizeBits, 0) + Index * Length,
    Word = binary:part(?BROTLI_DICTIONARY, Offset, Length),
    PrefixIndex = binary:at(?BROTLI_TRANSFORMS, Transform * 3),
    Operation = binary:at(?BROTLI_TRANSFORMS, Transform * 3 + 1),
    SuffixIndex = binary:at(?BROTLI_TRANSFORMS, Transform * 3 + 2),
    Prefix = element(PrefixIndex + 1, ?BROTLI_AFFIXES),
    Suffix = element(SuffixIndex + 1, ?BROTLI_AFFIXES),
    Changed = transform_word(Operation, Word),
    <<Prefix/binary, Changed/binary, Suffix/binary>>.

dictionary_offset(3, _, Sum) -> Sum;
dictionary_offset(Length, Widths, Sum) ->
    dictionary_offset(Length - 1, Widths,
                      Sum + (Length bsl element(Length + 1, Widths))).

transform_word(0, Word) -> Word;
transform_word(Count, Word) when Count >= 1, Count =< 9 ->
    binary:part(Word, 0, max(0, byte_size(Word) - Count));
transform_word(10, Word) -> ferment(Word, false, []);
transform_word(11, Word) -> ferment(Word, true, []);
transform_word(Operation, Word) when Operation >= 12, Operation =< 20 ->
    Drop = min(byte_size(Word), Operation - 11),
    binary:part(Word, Drop, byte_size(Word) - Drop).

ferment(<<>>, _, Acc) -> iolist_to_binary(lists:reverse(Acc));
ferment(Word, All, Acc) ->
    {Part, Rest} = ferment_scalar(Word),
    case All of
        true -> ferment(Rest, All, [Part | Acc]);
        false -> iolist_to_binary(lists:reverse([Rest, Part | Acc]))
    end.

ferment_scalar(<<First, Rest/binary>>) when First < 192 ->
    Value = case First >= 97 andalso First =< 122 of
        true -> First bxor 32;
        false -> First
    end,
    {<<Value>>, Rest};
ferment_scalar(<<First, Second, Rest/binary>>) when First < 224 ->
    {<<First, (Second bxor 32)>>, Rest};
ferment_scalar(<<First, Second, Third, Rest/binary>>) when First >= 224 ->
    {<<First, Second, (Third bxor 5)>>, Rest};
ferment_scalar(Word) -> {Word, <<>>}.
