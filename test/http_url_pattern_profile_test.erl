%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_url_pattern_profile_test).
-export([profile_contracts/0, matrix_contracts/0, load_profile/0]).
-include_lib("eunit/include/eunit.hrl").
-include("url_pattern_profile.hrl").

profile_contracts() ->
    [{"valid_profile", fun valid_profile/0},
     {"duplicate_case_id", fun duplicate_case_id/0},
     {"missing_requirement", fun missing_requirement/0},
     {"stale_profile_pin", fun stale_profile_pin/0},
     {"hostname_divergence_metadata", fun hostname_divergence_metadata/0},
     {"missing_matrix_case", fun missing_matrix_case/0},
     {"duplicate_matrix_id", fun duplicate_matrix_id/0},
     {"missing_step", fun missing_step/0},
     {"wrong_normative_decision", fun wrong_normative_decision/0},
     {"unknown_profile_field", fun unknown_profile_field/0},
     {"changed_expected_value", fun changed_expected_value/0},
     {"duplicate_json_key", fun duplicate_json_key/0}].

load_profile() -> upp_inputs().
matrix_contracts() ->
    {_,_,C}=inputs(),
    [{binary_to_list(maps:get(<<"id">>,R)),fun()->?assert(matrix_case(R)) end}
     ||R<-maps:get(<<"cases">>,C)].

inputs() ->
    {ok,Inputs}=upp_inputs(),Inputs.
valid_profile() -> {P,F,C}=inputs(),?assert(upp_valid(P,F,C)).
duplicate_case_id() ->
    {P,F,C}=inputs(),[A,B|T]=maps:get(<<"cases">>,F),
    F1=F#{<<"cases">>=>[A,B#{<<"id">>=>maps:get(<<"id">>,A)}|T]},
    ?assertNot(upp_valid(P,F1,C)).
missing_requirement() ->
    {P,F,C}=inputs(),[_|T]=maps:get(<<"requirements">>,P),
    ?assertNot(upp_valid(P#{<<"requirements">>=>T},F,C)).
stale_profile_pin() ->
    {P,F,C}=inputs(),Pins=maps:get(<<"pins">>,P),
    ?assertNot(upp_valid(P#{<<"pins">>=>Pins#{<<"callbacks">>=>maps:get(<<"urlpattern">>,Pins)}},F,C)).
hostname_divergence_metadata() ->
    {P,F,C}=inputs(),
    ?assertNot(upp_valid(P,F#{<<"hostname_reference_disagreements">>=>[]},C)).
missing_matrix_case() ->
    {P,F,C}=inputs(),[_|T]=maps:get(<<"cases">>,C),
    ?assertNot(upp_valid(P,F,C#{<<"cases">>=>T})).
duplicate_matrix_id() ->
    {P,F,C}=inputs(),[A,B|T]=maps:get(<<"cases">>,C),
    ?assertNot(upp_valid(P,F,C#{<<"cases">>=>[A,B#{<<"id">>=>maps:get(<<"id">>,A)}|T]})).
missing_step() ->
    {P,F,C}=inputs(),[A|T]=maps:get(<<"requirements">>,P),
    ?assertNot(upp_valid(P#{<<"requirements">>=>[A#{<<"steps">>=>[]}|T]},F,C)).
wrong_normative_decision() ->
    {P,F,C}=inputs(),Rows=maps:get(<<"hostname_object_controls">>,F),
    Changed=[case maps:get(<<"id">>,R) of 8->R#{<<"normative">>=><<"reference_agreement">>};_->R end||R<-Rows],
    ?assertNot(upp_valid(P,F#{<<"hostname_object_controls">>=>Changed},C)).
unknown_profile_field() ->
    {P,F,C}=inputs(),?assertNot(upp_valid(P#{<<"unexpected">>=><<"private-control">>},F,C)).
changed_expected_value() ->
    {P,F,C}=inputs(),[A|T]=maps:get(<<"cases">>,F),
    ?assertNot(upp_valid(P,F#{<<"cases">>=>[A#{<<"expected">>=><<"invalid_pattern">>}|T]},C)).
duplicate_json_key() ->
    Rejected=try upp_json_decode(<<"{\"schema\":1,\"\\u0073chema\":1}">>),false catch _:_ ->true end,
    ?assert(Rejected).

matrix_case(#{<<"kind">>:=<<"constructor">>,<<"input">>:=Input,<<"expected">>:=Expected}) ->
    case 'http@internal@url_pattern@constructor':parse(Input) of
        {ok,Map}->maps:from_list([{atom_to_binary(K),V}||{K,V}<-maps:to_list(Map)])=:=Expected;
        _->false
    end;
matrix_case(#{<<"kind">>:=<<"component">>}=R) ->
    Options={options,maps:get(<<"separator">>,R),maps:get(<<"prefix">>,R),fun(X)->{ok,X} end},
    Actual=case 'http@internal@url_pattern@component':compile_component(maps:get(<<"pattern">>,R),Options) of
        {error,invalid_pattern}-><<"invalid_pattern">>;
        {ok,C}->match_result('http@internal@url_pattern@component':matches_canonical(C,maps:get(<<"input">>,R),8388608));
        _-><<"unexpected_error">>
    end,
    Actual=:=maps:get(<<"expected">>,R);
matrix_case(#{<<"kind">>:=<<"encoding">>}=R) ->
    encoding_result('http@internal@url_pattern@encoding':encode(encoding_kind(maps:get(<<"encoding">>,R)),maps:get(<<"input">>,R)),maps:get(<<"expected">>,R));
matrix_case(#{<<"kind">>:=<<"host">>}=R) ->
    case 'http@internal@url_pattern@host':canonicalize(maps:get(<<"input">>,R)) of
        {ok,Value}->Value=:=maps:get(<<"expected">>,R);
        {error,nil}->maps:get(<<"expected">>,R)=:=null;
        _->false
    end;
matrix_case(#{<<"kind">>:=<<"full">>}=R) ->
    {ok,Base}='http@internal@url_pattern@url':parse(maps:get(<<"base">>,R)),
    Actual=case 'http@internal@url_pattern@pattern':compile(maps:get(<<"pattern">>,R),Base,8388608) of
        {error,invalid_pattern}-><<"invalid_pattern">>;
        {ok,{C,W}} when W>=0,W=<8388608 ->
            case 'http@internal@url_pattern@url':parse(maps:get(<<"candidate">>,R)) of
                {ok,URL}->match_result('http@internal@url_pattern@pattern':matches(C,URL,W));
                _-><<"invalid_candidate">>
            end;
        _-><<"unexpected_error">>
    end,
    Actual=:=maps:get(<<"expected">>,R);
matrix_case(#{<<"kind">>:=<<"budget">>}=R) ->
    Result=budget(maps:get(<<"operation">>,R),maps:get(<<"amount">>,R)),
    Actual=case Result of {ok,_}-><<"ok">>;{error,work_limit_exceeded}-><<"work_limit_exceeded">>;_-><<"unexpected_error">> end,
    Actual=:=maps:get(<<"expected">>,R).

match_result({ok,{true,W}}) when W>=0,W=<8388608-><<"matched">>;
match_result({ok,{false,W}}) when W>=0,W=<8388608-><<"not_matched">>;
match_result(_)-><<"unexpected_error">>.
encoding_result({ok,Value},Expected)->Value=:=Expected;
encoding_result({error,invalid_pattern},null)->true;
encoding_result(_,_)->false.
encoding_kind(<<"protocol">>)->protocol;
encoding_kind(<<"userinfo">>)->userinfo;
encoding_kind(<<"port">>)->port;
encoding_kind(<<"search">>)->search;
encoding_kind(<<"hash">>)->hash;
encoding_kind(<<"opaque_path">>)->opaque_path;
encoding_kind(<<"ipv6_pattern">>)->ipv6_pattern.

budget(<<"compile">>,W)->
    {ok,U}='http@internal@url_pattern@url':parse(<<"https://example.com/base">>),
    credit_result('http@internal@url_pattern@pattern':compile(<<"/*">>,U,W),W);
budget(<<"match">>,W)->
    {ok,U}='http@internal@url_pattern@url':parse(<<"https://example.com/base">>),
    {ok,{C,_}}='http@internal@url_pattern@pattern':compile(<<"/*">>,U,8388608),
    credit_result('http@internal@url_pattern@pattern':matches(C,U,W),W);
budget(<<"authored">>,N)->'http@internal@url_pattern@component':compile_path(binary:copy(<<"a">>,N));
budget(<<"derived">>,N)->'http@internal@url_pattern@component':compile_component(binary:copy(<<"a">>,N),{options,-1,-1,fun(X)->{ok,X} end});
budget(<<"encoding">>,N)->'http@internal@url_pattern@encoding':encode(userinfo,binary:copy(<<"a">>,N));
budget(<<"expanded">>,N)->'http@internal@url_pattern@encoding':encode(userinfo,binary:copy(<<" ">>,N));
budget(<<"candidate">>,N)->
    {ok,C}='http@internal@url_pattern@component':compile_path(<<"*">>),
    'http@internal@url_pattern@component':matches_canonical(C,binary:copy(<<"a">>,N),8388608).

credit_result({ok,{_,Remaining}},Before) when Remaining>=0,Remaining=<Before ->{ok,nil};
credit_result({error,work_limit_exceeded},_)->{error,work_limit_exceeded};
credit_result(_,_)->{error,invalid_credit_result}.
