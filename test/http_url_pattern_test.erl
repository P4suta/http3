%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_url_pattern_test).
-include_lib("eunit/include/eunit.hrl").
-export([reference_contracts/0, full_reference_contracts/0, independent_contracts/0]).

reference_contracts() ->
    {ok, Bytes} = file:read_file("test/fixtures/urlpattern-wpt.json"),
    true = byte_size(Bytes) < 131072,
    #{<<"schema">> := 1, <<"vectors">> := Rows} = json:decode(Bytes),
    136 = length(Rows),
    [{integer_to_list(maps:get(<<"index">>, Row)), fun() -> check(Row) end} || Row <- Rows].

check(#{<<"pattern">> := Pattern, <<"valid">> := false}) ->
    Rejected = case 'http@internal@url_pattern@component':compile_path(Pattern) of
        {error, invalid_pattern} -> true;
        _ -> false
    end,
    ?assert(Rejected);
check(#{<<"pattern">> := Pattern, <<"input">> := Input,
        <<"valid">> := true, <<"matched">> := Expected}) ->
    Matched = case 'http@internal@url_pattern@component':compile_path(Pattern) of
        {ok, Compiled} ->
            case 'http@internal@url_pattern@component':matches(Compiled, Input, 8388608) of
                {ok, {Expected, _Remaining}} -> true;
                _ -> false
            end;
        _ -> false
    end,
    ?assert(Matched).

full_reference_contracts() ->
    {ok, Bytes} = file:read_file("test/fixtures/urlpattern-constructor-wpt.json"),
    true = byte_size(Bytes) < 131072,
    #{<<"schema">> := 1, <<"vectors">> := Rows} = json:decode(Bytes),
    33 = length(Rows),
    [{integer_to_list(maps:get(<<"index">>, Row)), fun() -> check_full(Row) end} || Row <- Rows].

check_full(#{<<"pattern">> := Pattern, <<"base">> := Base, <<"valid">> := Valid} = Row) ->
    Passed = case 'http@internal@url_pattern@url':parse(Base) of
        {ok, BaseUrl} ->
            case 'http@internal@url_pattern@pattern':compile(Pattern, BaseUrl, 8388608) of
                {error, invalid_pattern} when Valid =:= false -> true;
                {ok, {Compiled, Work}} when Valid =:= true ->
                    case 'http@internal@url_pattern@url':parse(maps:get(<<"input">>, Row)) of
                        {ok, Input} ->
                            Expected = maps:get(<<"matched">>, Row),
                            case 'http@internal@url_pattern@pattern':matches(Compiled, Input, Work) of
                                {ok, {Expected, _Remaining}} -> true;
                                _ -> false
                            end;
                        _ -> false
                    end;
                _ -> false
            end;
        _ -> false
    end,
    ?assert(Passed).

independent_contracts() ->
    {ok, {_, #{<<"cases">> := Rows}, _}} = http_url_pattern_profile_test:load_profile(),
    [{integer_to_list(maps:get(<<"id">>, Row)), fun() -> check_independent(Row) end} || Row <- Rows].

check_independent(#{<<"pattern">> := Pattern, <<"base">> := Base,
                    <<"candidate">> := Candidate, <<"expected">> := Expected}) ->
    Observed = case 'http@internal@url_pattern@url':parse(Base) of
        {ok, BaseUrl} ->
            case 'http@internal@url_pattern@pattern':compile(Pattern, BaseUrl, 8388608) of
                {error, invalid_pattern} -> <<"invalid_pattern">>;
                {ok, {Compiled, Work}} ->
                    case 'http@internal@url_pattern@url':parse(Candidate) of
                        {ok, Url} ->
                            case 'http@internal@url_pattern@pattern':matches(Compiled, Url, Work) of
                                {ok, {true, _}} -> <<"matched">>;
                                {ok, {false, _}} -> <<"not_matched">>;
                                _ -> <<"unexpected_match_error">>
                            end;
                        _ -> <<"invalid_candidate">>
                    end;
                _ -> <<"unexpected_compile_error">>
            end;
        _ -> <<"invalid_base">>
    end,
    ?assertEqual(Expected, Observed).
