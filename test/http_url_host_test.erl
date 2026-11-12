%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_url_host_test).
-export([reference_contracts/0, run/0]).

reference_contracts() ->
    {Hosts, Idna, Nfc, _Node} = fixtures(),
    groups(host, Hosts) ++ groups(idna, Idna) ++ groups(nfc, Nfc).

groups(Kind, Rows) -> groups(Kind, Rows, 0).
groups(_Kind, [], _Index) -> [];
groups(Kind, Rows, Index) ->
    {Group, Rest} = lists:split(min(128, length(Rows)), Rows),
    [{atom_to_list(Kind) ++ integer_to_list(Index), fun() ->
        lists:foreach(fun(Row) ->
            case check(Kind, Row) of
                true -> ok;
                false -> erlang:error({host_reference_failed, Kind, maps:get(<<"index">>, Row)})
            end
        end, Group)
    end} | groups(Kind, Rest, Index + 1)].

run() ->
    {Hosts, Idna, Nfc, Node} = fixtures(),
    H = [maps:get(<<"index">>, R) || R <- Hosts, not check(host, R)],
    I = [maps:get(<<"index">>, R) || R <- Idna, not check(idna, R)],
    N = [maps:get(<<"index">>, R) || R <- Nfc, not check(nfc, R)],
    D = [maps:get(<<"index">>, R) || R <- Node, not check(host, R)],
    #{hosts => length(Hosts), idna => length(Idna), nfc => length(Nfc), failed_hosts => length(H),
      failed_idna => length(I), idna_indices => lists:sublist(I, 128),
      node_compared => length(Node), node_differences => length(D), node_indices => lists:sublist(D, 128),
      failed_nfc => length(N), host_indices => lists:sublist(H, 128),
      nfc_indices => lists:sublist(N, 128)}.

check(host, #{<<"input">> := Input, <<"output">> := Expected}) ->
    Result = case Expected of null -> {error, nil}; _ -> {ok, Expected} end,
    'http@internal@url_pattern@host':canonicalize(Input) =:= Result;
check(idna, #{<<"input">> := Input, <<"output">> := Expected}) ->
    Result = case Expected of null -> {error, nil}; _ -> {ok, Expected} end,
    'http@internal@url_pattern@host_idna':to_ascii(Input) =:= Result;
check(nfc, #{<<"fields">> := [A, B, C, D, E]}) ->
    lists:all(fun({Input, Expected}) ->
        'http@internal@url_pattern@host_nfc':normalize(Input) =:= Expected
    end, [{A, B}, {B, B}, {C, B}, {D, D}, {E, D}]).

fixtures() ->
    {ok, F} = file:open("test/fixtures/url-host-reference.json", [read, raw, binary]),
    {ok, Bytes} = try file:read(F, 8388609) after file:close(F) end,
    true = byte_size(Bytes) =< 8388608,
    <<"EB9B8363B3600F054011E66E08C87BDEF0C1E16C15558F279D291573E4FF22CB">> =
        binary:encode_hex(crypto:hash(sha256, Bytes)),
    #{<<"schema">> := 1, <<"ordinaryHosts">> := Hosts, <<"idna">> := Idna,
      <<"nfc">> := Nfc, <<"hosts">> := Node} = json:decode(Bytes),
    479 = length(Hosts), 6387 = length(Idna), 19965 = length(Nfc), 7926 = length(Node),
    {Hosts, Idna, Nfc, Node}.
