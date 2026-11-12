%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
http_model_valid_child(Child, Mode, Domains, Seed, Count, Nonce) when is_map(Child) ->
    try
        true = http_model_exact_keys(Child, [<<"schema">>, <<"nonce">>, <<"mode">>, <<"status">>, <<"domains">>]),
        1 = maps:get(<<"schema">>, Child),
        Nonce = maps:get(<<"nonce">>, Child),
        ModeText = atom_to_binary(Mode), ModeText = maps:get(<<"mode">>, Child),
        Status = maps:get(<<"status">>, Child),
        true = lists:member(Status, [<<"Passed">>, <<"Failed">>]),
        Rows = maps:get(<<"domains">>, Child),
        true = is_list(Rows) andalso Rows =/= [] andalso length(Rows) =< length(Domains),
        Names = [maps:get(<<"domain">>, Row) || Row <- Rows],
        Names = lists:sublist(Domains, length(Rows)),
        true = lists:all(fun(Row) -> http_model_valid_row(Row, Mode, Seed, Count) end, Rows),
        States = [maps:get(<<"status">>, Row) || Row <- Rows],
        case Status of
            <<"Passed">> -> Names =:= Domains andalso lists:all(fun(S) -> S =:= <<"Passed">> end, States);
            <<"Failed">> -> lists:last(States) =:= <<"Failed">> andalso
                            length([S || S <- States, S =:= <<"Failed">>]) =:= 1
        end
    catch _:_ -> false end;
http_model_valid_child(_, _, _, _, _, _) -> false.

http_model_valid_row(Row, Mode, Seed, Count) ->
    Seed = maps:get(<<"seed">>, Row),
    case {Mode, maps:get(<<"status">>, Row)} of
        {campaign, <<"Passed">>} ->
            true = http_model_exact_keys(Row, [<<"domain">>, <<"seed">>, <<"cases">>, <<"transitions">>, <<"sha256">>, <<"status">>]),
            Count = maps:get(<<"cases">>, Row),
            http_model_valid_success(Row, campaign, Count);
        {campaign, <<"Failed">>} ->
            true = http_model_exact_keys(Row, [<<"domain">>, <<"seed">>, <<"cases">>, <<"case_seed">>, <<"failure_step">>,
                                    <<"invariant">>, <<"minimization">>, <<"status">>]),
            true = http_model_bounded(maps:get(<<"cases">>, Row), 0, Count - 1),
            true = http_model_bounded(maps:get(<<"case_seed">>, Row), 0, 2147483646),
            true = maps:get(<<"case_seed">>, Row) =:= http_model_advance_seed(Seed, maps:get(<<"cases">>, Row)),
            true = http_model_valid_failure(Row),
            http_model_valid_minimization(maps:get(<<"minimization">>, Row));
        {replay, <<"Passed">>} ->
            true = http_model_exact_keys(Row, [<<"domain">>, <<"seed">>, <<"prefix_steps">>, <<"transitions">>, <<"sha256">>, <<"status">>]),
            Count = maps:get(<<"prefix_steps">>, Row), http_model_valid_success(Row, replay, Count);
        {replay, <<"Failed">>} ->
            true = http_model_exact_keys(Row, [<<"domain">>, <<"seed">>, <<"prefix_steps">>, <<"failure_step">>, <<"invariant">>, <<"status">>]),
            Count = maps:get(<<"prefix_steps">>, Row), http_model_valid_failure(Row)
    end.
http_model_valid_success(Row, Mode, Count) ->
    {Cases, Steps} = case Mode of campaign -> {Count, 32}; replay -> {1, Count} end,
    {Minimum, Maximum} = case maps:get(<<"domain">>, Row) of
        <<"http1">> -> {3 * Cases, 130 * Cases};
        <<"http2">> -> {2 * Steps * Cases, 2 * Steps * Cases};
        <<"hpack">> -> {Steps * Cases, Steps * Cases};
        <<"pool">> -> {(Steps + 3) * Cases, (Steps + 3) * Cases};
        <<"cancellation">> -> {(Steps + 1) * Cases, (Steps + 1) * Cases};
        <<"drain">> -> {5 * Cases, 7 * Cases}
    end,
    http_model_bounded(maps:get(<<"transitions">>, Row), Minimum, Maximum) andalso http_model_sha256(maps:get(<<"sha256">>, Row)).

http_model_advance_seed(Seed, 0) -> Seed;
http_model_advance_seed(Seed, Count) -> http_model_advance_seed(((Seed + 1) * 48271) rem 2147483647, Count - 1).
http_model_valid_failure(Row) ->
    http_model_bounded(maps:get(<<"failure_step">>, Row), 0, 256) andalso http_model_bounded(maps:get(<<"invariant">>, Row), 1, 999).
http_model_valid_minimization(Map) ->
    http_model_exact_keys(Map, [<<"verified">>, <<"prefix_steps">>, <<"failure_step">>, <<"scope">>]) andalso
    is_boolean(maps:get(<<"verified">>, Map)) andalso http_model_bounded(maps:get(<<"prefix_steps">>, Map), 1, 32) andalso
    http_model_bounded(maps:get(<<"failure_step">>, Map), 0, 256) andalso
    lists:member(maps:get(<<"scope">>, Map), [<<"independent_case">>, <<"transition_prefix">>, <<"unstable_reproduction">>]).
http_model_exact_keys(Map, Keys) when is_map(Map) -> lists:sort(maps:keys(Map)) =:= lists:sort(Keys);
http_model_exact_keys(_, _) -> false.
http_model_bounded(N, Minimum, Maximum) -> is_integer(N) andalso N >= Minimum andalso N =< Maximum.
http_model_sha256(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    lists:all(fun(C) -> C >= $0 andalso C =< $9 orelse C >= $a andalso C =< $f end, binary_to_list(Value));
http_model_sha256(_) -> false.
