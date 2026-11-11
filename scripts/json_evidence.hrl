%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_JSON_EVIDENCE_HRL).
-define(HTTP_JSON_EVIDENCE_HRL, true).

%% Imported evidence must account for every key, including escaped duplicate
%% spellings. Bound nesting and node count as well as the input bytes. Errors
%% never carry an input fragment into a shareable failure report.
evidence_json_decode(Bytes) when is_binary(Bytes), byte_size(Bytes) =< 16777216 ->
    try
        StartObject = fun(Acc) -> evidence_json_start(Acc, #{}) end,
        StartArray = fun(Acc) -> evidence_json_start(Acc, []) end,
        PushObject = fun(Key, Value, {Depth, Count, Object}) ->
            false = maps:is_key(Key, Object),
            true = Count < 1000000,
            {Depth, Count + 1, Object#{Key => Value}}
        end,
        PushArray = fun(Value, {Depth, Count, Array}) ->
            true = Count < 1000000, {Depth, Count + 1, [Value | Array]}
        end,
        FinishObject = fun({_, Count, Object}, {Depth, _, Outer}) ->
            {Object, {Depth, Count, Outer}}
        end,
        FinishArray = fun({_, Count, Array}, {Depth, _, Outer}) ->
            {lists:reverse(Array), {Depth, Count, Outer}}
        end,
        {Value, {0, _, none}, Rest} = json:decode(Bytes, {0, 0, none},
            #{object_start => StartObject, object_push => PushObject, object_finish => FinishObject,
              array_start => StartArray, array_push => PushArray, array_finish => FinishArray}),
        true = lists:all(fun(C) -> C =:= 32 orelse C =:= 9 orelse C =:= 10 orelse C =:= 13 end,
                         binary_to_list(Rest)), Value
    catch _:_ -> erlang:error(invalid_evidence_json) end;
evidence_json_decode(_) -> erlang:error(invalid_evidence_json).
evidence_json_start({Depth, Count, _}, Container) ->
    true = Depth < 128 andalso Count < 1000000,
    {Depth + 1, Count + 1, Container}.
-endif.
