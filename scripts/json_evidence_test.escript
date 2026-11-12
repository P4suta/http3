#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("json_evidence.hrl").
main([]) ->
    #{<<"x">> := [#{}, [], 1, true, null, #{<<"y">> := <<"z">>}]} =
        evidence_json_decode(<<" {\"x\":[{},[],1,true,null,{\"y\":\"z\"}]} \r\n">>),
    Inputs = [<<"{\"x\":\"private-marker\",\"x\":1}">>,
              <<"{\"x\":1,\"\\u0078\":2}">>,
              <<"[{\"nested\":1,\"nested\":2}]">>,
              <<"{} {}">>, <<"{\"private-marker\":" >>,
              iolist_to_binary([lists:duplicate(129, $[), "0", lists:duplicate(129, $])])],
    lists:foreach(fun(Bytes) ->
        Rejected = try evidence_json_decode(Bytes), false
                   catch error:invalid_evidence_json -> true end,
        true = Rejected
    end, Inputs),
    io:put_chars("strict evidence JSON: nested/escaped duplicate keys, trailing data and excessive depth rejected\n").
