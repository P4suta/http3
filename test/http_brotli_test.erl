%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_brotli_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

contracts() ->
    Basic = [
        {"malformed private arguments", fun malformed_private_arguments_are_typed_case/0},
        {"all standard windows and exact limits", fun all_standard_windows_and_exact_limits_case/0},
        {"truncation padding trailing reserved bits", fun truncation_padding_trailing_and_reserved_bits_case/0},
        {"metadata excluded from output and history", fun metadata_does_not_become_output_or_history_case/0},
        {"RFC meta-block length padding and cumulative limits", fun metablock_header_and_cumulative_limits_case/0},
        {"independent compressed resource limits", fun independent_compressed_ratio_output_and_work_limits_case/0},
        {"5000 random malformed bitstreams", fun malformed_bitstreams_never_escape_or_exceed_output_case/0},
        {"all compressed single-bit mutations", fun mutated_compressed_bitstreams_remain_total_case/0},
        {"unused oversized distance symbols", fun unused_large_distance_symbols_are_rejected_case/0},
        {"raw dictionary crossing into current window", fun raw_dictionary_copy_crosses_into_the_current_window_case/0},
        {"history allocation is lazy at the initial window", fun lazy_initial_history_allocation_case/0},
        {"history allocation grows with decoded chunks", fun incremental_history_allocation_case/0}
    ],
    BlockContracts = lists:append([[
        {"adjacent " ++ atom_to_list(Category) ++ " block types differ", fun() -> adjacent_block_types_are_distinct_case(Category) end},
        {"declared " ++ atom_to_list(Category) ++ " block interval", fun() -> declared_block_types_are_used_case(Category) end}
    ] || Category <- [literal,command,distance]]),
    MapContracts = [{"complete " ++ atom_to_list(Category) ++ " context map", fun() -> context_map_uses_all_declared_trees_case(Category) end}
        || Category <- [literal,distance]],
    [{Name,{timeout,60,Run}} || {Name,Run} <- Basic ++ BlockContracts ++ MapContracts] ++ google_rfc_synthetic_vectors_case().

adjacent_block_types_are_distinct_case(Category) ->
    assert_block_output(Category,2,[3,2]),
    %% Explicit switch symbols 2 and 3 mean types 0 and 1. Both declared
    %% types occur; only the first 0 -> 0 switch makes this stream invalid.
    ?assertEqual({error,1}, run(block_stream(Category,2,[2,3]))).

declared_block_types_are_used_case(Category) ->
    assert_block_output(Category,3,[1,1]),
    assert_block_output(Category,256,lists:duplicate(255,1)),
    CopyEnded = block_stream(Category,3,[1,1],copy),
    ?assertEqual({ok,binary:copy(<<"x">>,9)},run(CopyEnded)),
    ?assertEqual({error,1},run(block_stream(Category,3,[3],copy))),
    ?assertEqual({error,1}, run(block_stream(Category,3,[3]))),
    ?assertEqual({error,1}, run(block_stream(Category,3,[4]))),
    ?assertEqual({error,1},run(block_stream(Category,256,lists:duplicate(254,1)))).

context_map_uses_all_declared_trees_case(Category) ->
        Cells = case Category of literal -> 64; distance -> 4 end,
        lists:foreach(fun(Mtf) ->
            Complete = [0,1,2|lists:duplicate(Cells-3,0)],
            ?assertEqual({ok,<<"x">>},run(map_stream(Category,3,Complete,Mtf))),
            ?assertEqual({error,1},run(map_stream(Category,3,lists:duplicate(Cells,0),Mtf))),
            MissingMiddle = [0,2|lists:duplicate(Cells-2,0)],
            ?assertEqual({error,1},run(map_stream(Category,3,MissingMiddle,Mtf)))
        end,[0,1]),
        ?assertEqual({error,1},run(rle_map_stream(Category,false))),
        ?assertEqual({ok,<<"x">>},run(rle_map_stream(Category,true))),
        Commands = case Category of literal -> 4; distance -> 65 end,
        ?assertEqual({ok,binary:copy(<<"x">>,3*Commands-2)},run(maximum_map_stream(Category,1))),
        ?assertEqual({error,1},run(maximum_map_stream(Category,0))).

lazy_initial_history_allocation_case() ->
    Empty = pack(window(24) ++ [{1,1},{1,1}]),
    EmptyStats = allocation_observation(Empty,0),
    SmallStats = allocation_observation(stored(24,<<"x">>),1),
    ?assertEqual(0,maps:get(chunk_sets,EmptyStats)),
    ?assertEqual(0,maps:get(chunk_sets,SmallStats)),
    ?assertEqual(true,maps:get(heap_allocated_words,EmptyStats) < 16384),
    ?assertEqual(true,maps:get(heap_allocated_words,SmallStats) < 16384),
    ?assertEqual(true,maps:get(referenced_binary_bytes,SmallStats) < 65536).

incremental_history_allocation_case() ->
    lists:foreach(fun(Size) ->
        Bytes = binary:copy(<<"x">>,Size),
        Observation = allocation_observation(stored(24,Bytes),Size),
        ?assertEqual(Size div 1024,maps:get(chunk_sets,Observation)),
        ?assertEqual(true,maps:get(heap_allocated_words,Observation) < 65536),
        ?assertEqual(true,maps:get(referenced_binary_bytes,Observation) < 131072)
    end,[1023,1024,1025,4096]),
    %% Each stored meta-block adds another complete chunk to the same history.
    First = stored(24,binary:copy(<<"x">>,1024)),
    Prefix = binary:part(First,0,byte_size(First)-1),
    Following = <<(pack([{0,1},{0,2},{1023,16},{1,1}]))/binary,(binary:copy(<<"x">>,1024))/binary>>,
    Input = <<Prefix/binary,(binary:copy(Following,3))/binary,3>>,
    ?assertEqual(4,maps:get(chunk_sets,allocation_observation(Input,4096))).

allocation_observation(Input,ExpectedSize) ->
    %% OTP call_memory records allocated heap words without sending arguments,
    %% return values, binary contents, or trace messages to the collector.
    {module,http_brotli_ffi} = code:ensure_loaded(http_brotli_ffi),
    {module,array} = code:ensure_loaded(array),
    Parent = self(), Ref = make_ref(),
    Session = trace:session_create(brotli_allocation_contract,Parent,[]),
    Functions = [{http_brotli_ffi,decode,6},{http_brotli_ffi,append_chunks,2},{array,set,3}],
    [1 = trace:function(Session,MFA,true,[call_memory]) || MFA <- Functions],
    {Worker,Monitor} = spawn_opt(fun() ->
        OwnerMonitor = erlang:monitor(process,Parent),
        try receive {Ref,run} ->
            Result = decode(Input,<<>>,ExpectedSize,1000,4096,24),
            {binary,Binaries} = process_info(self(),binary),
            {memory,Memory} = process_info(self(),memory),
            Shape = case Result of {ok,Output} -> {ok,byte_size(Output)}; {error,Code} -> {error,Code} end,
            Parent ! {Ref,observed,Shape,Memory,lists:sum([N || {_,N,_} <- Binaries])},
            receive {Ref,stop} -> ok; {'DOWN',OwnerMonitor,process,Parent,_} -> ok
                after 5000 -> ok end;
            {'DOWN',OwnerMonitor,process,Parent,_} -> ok
        after 5000 -> ok end
        after erlang:demonitor(OwnerMonitor,[flush]) end
    end,[monitor,{max_heap_size,#{size=>131072,kill=>true,error_logger=>false,include_shared_binaries=>true}}]),
    try
        1 = trace:process(Session,Worker,true,[call,silent]),
        Worker ! {Ref,run},
        receive
            {Ref,observed,Shape,Memory,BinaryBytes} ->
                ?assertEqual({ok,ExpectedSize},Shape),
                [1 = trace:function(Session,MFA,pause,[call_memory]) || MFA <- Functions],
                Counts = [allocation_counter(Session,MFA,Worker) || MFA <- Functions],
                [{1,_},_,{Sets,_}] = Counts,
                #{chunk_sets=>Sets,heap_allocated_words=>lists:sum([Words || {_,Words} <- Counts]),
                  observed_process_bytes=>Memory,referenced_binary_bytes=>BinaryBytes};
            {'DOWN',Monitor,process,Worker,killed} -> erlang:error(system_limit);
            {'DOWN',Monitor,process,Worker,_} -> erlang:error(allocation_worker_failed)
        after 2000 -> erlang:error(allocation_observation_timeout)
        end
    after
        true = trace:session_destroy(Session),
        Worker ! {Ref,stop},
        case is_process_alive(Worker) of
            false -> erlang:demonitor(Monitor,[flush]);
            true -> receive {'DOWN',Monitor,process,Worker,_} -> ok
                after 1000 -> exit(Worker,kill),receive {'DOWN',Monitor,process,Worker,_} -> ok
                    after 1000 -> erlang:error(allocation_worker_kill_join_timeout) end,
                    erlang:error(allocation_worker_join_timeout)
                end
        end
    end.

allocation_counter(Session,MFA,Worker) ->
    case trace:info(Session,MFA,call_memory) of
        {call_memory,[]} -> {0,0};
        {call_memory,[{Worker,Calls,Words}]} -> {Calls,Words}
    end.

%% Independently encoded RFC fields: every command inserts x and copies two
%% bytes at distance one; the final command ends immediately after its literal.
%% Thus block category coverage is observable without mirroring decoder state.
assert_block_output(Category,Count,Codes) ->
    Commands = length(Codes)+1+case Category of distance -> 1; _ -> 0 end,
    ?assertEqual({ok,binary:copy(<<"x">>,3*Commands-2)},run(block_stream(Category,Count,Codes))).

block_stream(Category,Count,Codes) ->
    block_stream(Category,Count,Codes,literal).

block_stream(Category,Count,Codes,Final) ->
    Commands = length(Codes)+1+case {Category,Final} of {distance,literal} -> 1; _ -> 0 end,
    Length = 3*Commands-case Final of literal -> 2; copy -> 0 end,
    Counts = [case C of Category -> Count; _ -> 1 end || C <- [literal,command,distance]],
    [LiteralCount,CommandCount,_] = Counts,
    Descriptors = lists:append([case C of
        Category -> block_fields(Count,Codes);
        _ -> [{0,1}]
    end || C <- [literal,command,distance]]),
    Switches = lists:append([symbol_fields(Code,lists:usort(Codes)) ++ [{0,2}] || Code <- Codes]),
    pack(window(16) ++ [{1,1},{0,1},{0,2},{Length-1,16}] ++ Descriptors ++
        [{0,2},{1,4}] ++ lists:duplicate(LiteralCount,{0,2}) ++ [{0,1},{0,1}] ++
        simple_tree(256,[120]) ++ lists:append(lists:duplicate(CommandCount,simple_tree(704,[136]))) ++
        simple_tree(65,[16]) ++ Switches).

block_fields(Count,Codes) ->
    varbyte_fields(Count-1) ++ simple_tree(Count+2,lists:usort(Codes)) ++
        simple_tree(26,[0]) ++ [{0,2}].

map_stream(Category,Trees,Values,Mtf) ->
    Encoded = case Mtf of 0 -> Values; 1 -> mtf_fields(Values,lists:seq(0,255),[]) end,
    Symbols = lists:usort(Encoded),
    Map = varbyte_fields(Trees-1) ++ [{0,1}] ++ simple_tree(Trees,Symbols) ++
        lists:append([symbol_fields(Value,Symbols) || Value <- Encoded]) ++ [{Mtf,1}],
    single_command_map_stream(Category,Trees,Map).

rle_map_stream(Category,Complete) ->
    Cells = case Category of literal -> 64; distance -> 4 end,
    RunBits = width(Cells,0)-case Complete of true -> 2; false -> 1 end,
    Symbols = case Complete of true -> [RunBits,RunBits+1]; false -> [RunBits] end,
    Encoded = symbol_fields(RunBits,Symbols) ++ [{0,RunBits}] ++ case Complete of
        true -> lists:duplicate(Cells div 2,{1,1});
        false -> []
    end,
    Map = varbyte_fields(1) ++ [{1,1},{RunBits-1,4}] ++ simple_tree(2+RunBits,Symbols) ++ Encoded ++ [{0,1}],
    single_command_map_stream(Category,2,Map).

single_command_map_stream(Category,Trees,Map) ->
    {Maps,LiteralTrees,DistanceTrees} = case Category of
        literal -> {Map ++ [{0,1}],Trees,1};
        distance -> {[{0,1}] ++ Map,1,Trees}
    end,
    pack(window(16) ++ [{1,1},{0,1},{0,2},{0,16},{0,1},{0,1},{0,1},{0,2},{1,4},{0,2}] ++ Maps ++
        lists:append(lists:duplicate(LiteralTrees,simple_tree(256,[120]))) ++ simple_tree(704,[136]) ++
        lists:append(lists:duplicate(DistanceTrees,simple_tree(65,[16])))).

maximum_map_stream(Category,Mtf) ->
    Count = case Category of literal -> 4; distance -> 64 end,
    Commands = case Category of literal -> Count; distance -> Count+1 end,
    Descriptors = lists:append([case C of Category -> block_fields(Count,[1]); _ -> [{0,1}] end
        || C <- [literal,command,distance]]),
    LiteralCount = case Category of literal -> Count; distance -> 1 end,
    %% Repeated MTF rank 255 enumerates exactly [255,254,..,0]. Without MTF
    %% this map has only index 255: its maximum is valid, its coverage is not.
    Map = varbyte_fields(255) ++ [{0,1}] ++ simple_tree(256,[255]) ++ [{Mtf,1}],
    {Maps,LTrees,DTrees} = case Category of literal -> {Map++[{0,1}],256,1}; distance -> {[{0,1}]++Map,1,256} end,
    pack(window(16) ++ [{1,1},{0,1},{0,2},{3*Commands-3,16}] ++ Descriptors ++ [{0,2},{1,4}] ++
        lists:duplicate(LiteralCount,{0,2}) ++ Maps ++ lists:append(lists:duplicate(LTrees,simple_tree(256,[120]))) ++
        simple_tree(704,[136]) ++ lists:append(lists:duplicate(DTrees,simple_tree(65,[16]))) ++
        lists:duplicate(Count-1,{0,2})).

mtf_fields([],_,Acc) -> lists:reverse(Acc);
mtf_fields([Value|Rest],Order,Acc) ->
    {Before,[Value|After]} = lists:splitwith(fun(X) -> X =/= Value end,Order),
    mtf_fields(Rest,[Value|Before++After],[length(Before)|Acc]).

varbyte_fields(0) -> [{0,1}];
varbyte_fields(1) -> [{1,1},{0,3}];
varbyte_fields(Value) ->
    Width = width(Value,0)-1,
    [{1,1},{Width,3},{Value-(1 bsl Width),Width}].

simple_tree(Alphabet,Symbols) ->
    [{1,2},{length(Symbols)-1,2}] ++ [{S,width(Alphabet-1,0)} || S <- Symbols].

symbol_fields(_,[_]) -> [];
symbol_fields(Value,[First,Second]) ->
    [{case Value of First -> 0; Second -> 1 end,1}];
symbol_fields(Value,[First,Second,Third]) ->
    case Value of First -> [{0,1}]; Second -> [{1,1},{0,1}]; Third -> [{1,1},{1,1}] end.

malformed_private_arguments_are_typed_case() ->
    Defaults = [<<6>>, <<>>, 4096, 1000, 4096, 24],
    lists:foreach(fun(Index) ->
        lists:foreach(fun(Value) ->
            Args = replace(Index, Value, Defaults),
            ?assertEqual({error, 1}, apply(http_brotli_ffi, decode, Args))
        end, [invalid, undefined, [], {}, 1.5])
    end, lists:seq(1, 6)),
    lists:foreach(fun({Index, Value}) ->
        ?assertEqual({error, 1}, apply(http_brotli_ffi, decode,
                                     replace(Index, Value, Defaults)))
    end, [{3,-1},{4,0},{5,0},{6,9},{6,28}]).

google_rfc_synthetic_vectors_case() ->
    {ok, Json} = file:read_file("test/fixtures/brotli-google-synthetic.json"),
    #{<<"cases">> := Cases} = json:decode(Json),
    lists:map(fun(#{<<"name">> := Name, <<"compressed_hex">> := Hex,
                   <<"success">> := Success, <<"output_bytes">> := Size,
                   <<"output_sha256">> := Hash}) ->
        {binary_to_list(Name),{timeout,60,fun() ->
            Input = binary:decode_hex(Hex),
            Actual = decode(Input,<<>>,16777216,16777216,131072,24),
            case {Success, Actual} of
                {true, {ok, Output}} ->
                    ?assertEqual({Name,Size,Hash},
                                 {Name,byte_size(Output),binary:encode_hex(crypto:hash(sha256,Output))});
                {false, {error,1}} -> ok;
                _ -> ?assertEqual({Name,Success}, {Name,Actual})
            end
        end}}
    end, Cases).

all_standard_windows_and_exact_limits_case() ->
    lists:foreach(fun(Window) ->
        Input = stored(Window, <<"window">>),
        ?assertEqual({ok, <<"window">>}, decode(Input, <<>>, 6, 1000, 4096, Window)),
        ?assertEqual({error, 2}, decode(Input, <<>>, 5, 1000, 4096, Window)),
        case Window > 10 of
            true -> ?assertEqual({error, 2}, decode(Input, <<>>, 6, 1000, 4096, Window-1));
            false -> ok
        end
    end, lists:seq(10, 24)).

truncation_padding_trailing_and_reserved_bits_case() ->
    Input = stored(16, <<"hello">>),
    lists:foreach(fun(Length) ->
        ?assertEqual({error, 1}, run(binary:part(Input, 0, Length)))
    end, lists:seq(0, byte_size(Input)-1)),
    <<First, Second, Third, Rest/binary>> = Input,
    ?assertEqual({error, 1}, run(<<First, Second, (Third bor 128), Rest/binary>>)),
    ?assertEqual({error, 1}, run(<<Input/binary, 0>>)),
    ?assertEqual({error, 1}, run(<<6, 0>>)),
    ?assertEqual({error, 1}, run(<<134>>)),
    ?assertEqual({error, 1}, run(<<17>>)).

metadata_does_not_become_output_or_history_case() ->
    %% Independent .NET 10 BrotliDecoder returns Done with no output and
    %% consumes the complete final metadata block for both fixtures.
    ?assertEqual({ok, <<>>}, run(<<26>>)),
    ?assertEqual({ok, <<>>}, run(<<90,2,"abc">>)),
    %% WBITS16, non-final metadata, one length byte describing 3 bytes.
    Header = pack([{0,1},{0,1},{3,2},{0,1},{1,2},{2,8}]),
    ?assertEqual({ok, <<>>}, run(<<Header/binary,"abc",3>>)),
    EmptyMetadata = pack([{0,1},{0,1},{3,2},{0,1},{0,2}]),
    ?assertEqual({ok, <<>>}, run(<<EmptyMetadata/binary,3>>)),
    Reserved = pack([{0,1},{0,1},{3,2},{1,1},{0,2}]),
    ?assertEqual({error,1}, run(<<Reserved/binary,3>>)),
    Nonminimal = pack([{0,1},{0,1},{3,2},{0,1},{2,2},{0,16}]),
    ?assertEqual({error,1}, run(<<Nonminimal/binary,0,3>>)),
    ?assertEqual({error,1}, run(Header)).

independent_compressed_ratio_output_and_work_limits_case() ->
    Input = binary:decode_hex(<<"1BFF04F8056EC0C6DAA8702D0AA805DB01">>),
    Expected = binary:copy(<<"abcde">>,256),
    ?assertEqual({ok,Expected}, decode(Input,<<>>,1280,1000,4096,24)),
    ?assertEqual({error,2}, decode(Input,<<>>,1279,1000,4096,24)),
    ?assertEqual({error,2}, decode(Input,<<>>,4096,75,4096,24)),
    ?assertEqual({ok,Expected}, decode(Input,<<>>,4096,76,4096,24)),
    ?assertEqual({error,2}, decode(Input,<<>>,4096,1000,1,24)).

metablock_header_and_cumulative_limits_case() ->
    %% An empty metadata block has seven meaningful bits after WBITS16.
    ?assertEqual({ok,<<>>}, run(<<12,3>>)),
    ?assertEqual({error,1}, run(<<140,3>>)),
    %% Both longer MLEN forms must have a nonzero highest nibble.
    lists:foreach(fun(Nibbles) ->
        Nonminimal = pack(window(16) ++
            [{0,1},{Nibbles-4,2},{0,Nibbles*4},{1,1}]),
        ?assertEqual({error,1},run(<<Nonminimal/binary,"x",3>>))
    end,[5,6]),
    First = stored(16,<<"abc">>),
    Prefix = binary:part(First,0,byte_size(First)-1),
    Second = pack([{0,1},{0,2},{2,16},{1,1}]),
    Both = <<Prefix/binary,Second/binary,"def",3>>,
    ?assertEqual({ok,<<"abcdef">>},decode(Both,<<>>,6,1000,4096,24)),
    ?assertEqual({error,2},decode(Both,<<>>,5,1000,4096,24)),
    %% One static-word command consumes 71 bits; its final padding bit is
    %% independently known from this RFC field layout, not from the decoder.
    Final = pack(window(16) ++ copy_fields(4,1,0,15,7)),
    ?assertEqual({ok,<<"time">>},run(Final)),
    BytesBefore = byte_size(Final)-1,
    <<Before:BytesBefore/binary,Last>> = Final,
    ?assertEqual({error,1},run(<<Before/binary,(Last bor 128)>>)).

malformed_bitstreams_never_escape_or_exceed_output_case() ->
    Seed = rand:seed_s(exsss,{2026,9,10}),
    _FinalSeed = lists:foldl(fun(_, State0) ->
        {Length, State1} = rand:uniform_s(128, State0),
        {Input, State2} = random_bytes(Length-1, State1, []),
        Result = decode(Input,<<>>,4096,1000,4,24),
        case Result of
            {ok, Output} -> ?assert(byte_size(Output) =< 4096);
            {error, Code} -> ?assert(Code =:= 1 orelse Code =:= 2)
        end,
        State2
    end, Seed, lists:seq(1,5000)),
    ok.

mutated_compressed_bitstreams_remain_total_case() ->
    Input = binary:decode_hex(<<"1B5700008C946EE662844A073D58AA2BFDAD42D108C837B430D880038704F2171AE47AB6CC2EB1B363B24509CBC346D9EA0F93F20900">>),
    lists:foreach(fun(Index) ->
        <<Before:Index/binary, Byte, After/binary>> = Input,
        lists:foreach(fun(Bit) ->
            Mutated = <<Before/binary,(Byte bxor (1 bsl Bit)),After/binary>>,
            case decode(Mutated,<<>>,4096,1000,16,24) of
                {ok, Output} -> ?assert(byte_size(Output) =< 4096);
                {error, Code} -> ?assert(Code =:= 1 orelse Code =:= 2)
            end
        end, lists:seq(0,7))
    end, lists:seq(0,byte_size(Input)-1)).

unused_large_distance_symbols_are_rejected_case() ->
    lists:foreach(fun(Postfix) ->
        lists:foreach(fun(DirectHigh) ->
            Alphabet = 16 + (DirectHigh bsl Postfix) + (124 bsl Postfix),
            Input = unused_distance_stream(Postfix, DirectHigh, Alphabet-1),
            ?assertEqual({error,1}, decode(Input,<<"dictionary">>,64,1000,4096,24))
        end, [0,15])
    end, lists:seq(0,3)),
    %% Code 137 can represent at most 2^63-5; 138 can exceed the RFC ceiling.
    ?assertEqual({ok,<<"x">>}, decode(unused_distance_stream(0,0,137),<<"dict">>,64,1000,4096,24)),
    ?assertEqual({error,1}, decode(unused_distance_stream(0,0,138),<<"dict">>,64,1000,4096,24)).

raw_dictionary_copy_crosses_into_the_current_window_case() ->
    First = pack(window(16) ++ copy_fields(6,3,0,15,7)),
    ?assertEqual({ok,<<"abcabc">>}, decode(First,<<"abc">>,64,1000,4096,24)),
    Stored = stored(16,<<"XY">>),
    Prefix = binary:part(Stored,0,byte_size(Stored)-1),
    Last = pack(copy_fields(7,4,0,15,7)),
    ?assertEqual({ok,<<"XYbcXYbcX">>}, decode(<<Prefix/binary,Last/binary>>,<<"abc">>,64,1000,4096,24)),
    Large = pack([{17,8},{24,6}] ++ copy_fields(6,3,0,15,8)),
    ?assertEqual({ok,<<"abcabc">>}, decode(Large,<<"abc">>,64,1000,4096,24)),
    ?assertEqual({error,2}, decode(Large,<<"abc">>,64,1000,4096,23)),
    ?assertEqual({error,1}, run(Large)),
    TooLarge = pack([{17,8},{25,6}] ++ copy_fields(6,3,0,15,8)),
    ?assertEqual({error,1}, decode(TooLarge,<<"abc">>,64,1000,4096,27)).

run(Input) -> decode(Input, <<>>, 65536, 1000, 4096, 24).
decode(Input, Dict, Output, Ratio, Work, Window) ->
    http_brotli_ffi:decode(Input, Dict, Output, Ratio, Work, Window).

replace(1, Value, [_|Rest]) -> [Value|Rest];
replace(Index, Value, [First|Rest]) -> [First|replace(Index-1, Value, Rest)].

random_bytes(0, State, Reversed) -> {list_to_binary(Reversed), State};
random_bytes(Count, State0, Reversed) ->
    {Byte, State1} = rand:uniform_s(256, State0),
    random_bytes(Count-1, State1, [Byte-1|Reversed]).

stored(Window, Bytes) ->
    Header = pack(window(Window) ++ [{0,1},{0,2},{byte_size(Bytes)-1,16},{1,1}]),
    <<Header/binary,Bytes/binary,3>>.

window(16) -> [{0,1}];
window(17) -> [{1,1},{0,3},{0,3}];
window(Width) when Width < 16 -> [{1,1},{0,3},{Width-8,3}];
window(Width) -> [{1,1},{Width-17,3}].

pack(Values) ->
    {Integer, Length} = lists:foldl(fun({Value, Width},{Acc, Bits}) ->
        {Acc bor (Value bsl Bits), Bits+Width}
    end, {0,0}, Values),
    Size = ((Length+7) div 8)*8,
    <<Integer:Size/little>>.

copy_fields(Length, Distance, Postfix, Direct, DistanceWidth) ->
    [{1,1},{0,1},{0,2},{Length-1,16},
     {0,1},{0,1},{0,1},{Postfix,2},{Direct,4},{0,2},{0,1},{0,1},
     {1,2},{0,2},{42,8},
     {1,2},{0,2},{128+Length-2,10},
     {1,2},{0,2},{15+Distance,DistanceWidth}].

unused_distance_stream(Postfix, DirectHigh, Symbol) ->
    Alphabet = 16 + (DirectHigh bsl Postfix) + (124 bsl Postfix),
    Width = width(Alphabet-1,0),
    pack([{17,8},{22,6},{1,1},{0,1},{0,2},{0,16},
          {0,1},{0,1},{0,1},{Postfix,2},{DirectHigh,4},{0,2},{0,1},{0,1},
          {1,2},{0,2},{120,8},
          {1,2},{0,2},{136,10},
          {1,2},{0,2},{Symbol,Width}]).

width(0, Width) -> Width;
width(Value, Width) -> width(Value bsr 1, Width+1).
