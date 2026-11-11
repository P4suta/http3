%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

requirement_symbol_self_test() ->
    Fixture = <<"scripts/requirements_symbol_fixture.erl">>,
    Cases = [
        {declared_function, <<"declared/2">>, accepted},
        {name_without_arity, <<"declared">>, accepted},
        {quoted_function, <<"quoted_name/0">>, accepted},
        {guarded_clauses, <<"guarded/2">>, accepted},
        {macro_function, <<"macro_name/1">>, accepted},
        {wrong_arity, <<"declared/99">>, rejected},
        {comment_only, <<"comment_only/1">>, rejected},
        {string_only, <<"string_only/1">>, rejected},
        {atom_only, <<"atom_only">>, rejected},
        {call_only, <<"call_only/0">>, rejected},
        {type_only, <<"type_only/0">>, rejected},
        {inactive_branch, <<"inactive/0">>, rejected},
        {included_definition, <<"included_only/0">>, rejected},
        {forged_file_origin, <<"forged_origin/0">>, rejected},
        {root_file_metadata, <<"root_after_file_metadata/0">>, accepted}
    ],
    References = [{Kind, Fixture, Symbol, Expected} || {Kind, Symbol, Expected} <- Cases] ++ [
        {escript_function, <<"scripts/requirements_symbol_fixture.escript">>, <<"main/1">>, accepted},
        {escript_wrong_arity, <<"scripts/requirements_symbol_fixture.escript">>, <<"main/2">>, rejected},
        {escript_comment_only, <<"scripts/requirements_symbol_fixture.escript">>, <<"script_comment_only/1">>, rejected}
    ],
    ReferenceRows = [begin
        Observed = try assert_evidence_reference(#{<<"path">> => Path, <<"symbol">> => Symbol}) of
            ok -> accepted
        catch
            error:{missing_evidence_symbol, _, _} -> rejected;
            _:_ -> unexpected_failure
        end,
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Path, Symbol, Expected} <- References],
    Rows = ReferenceRows ++ requirement_symbol_parse_failure_tests(),
    Failed = length([R || R <- Rows, not maps:get(passed, R)]),
    Report = #{schema => 1, scope => <<"Erlang requirement function declaration and arity">>,
        nonce => binary:encode_hex(crypto:strong_rand_bytes(16)),
        completed => length(Rows), failed => Failed, cases => Rows},
    ok = file:write_file("build/requirements/symbol-self-test.json", json:encode(Report)),
    io:format("requirement symbol controls: ~B completed, ~B failed~n", [length(Rows), Failed]),
    ensure(Failed =:= 0, self_test_non_function_requirement_evidence_accepted),
    ok.

requirement_symbol_parse_failure_tests() ->
    Nonce = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))),
    Path = filename:join(["build", "requirements", "reference-fixtures", Nonce ++ ".erl"]),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, <<"-module(malformed_fixture).\ndeclared() -> ok.\nnot valid syntax.\n">>, [exclusive]),
    Parse = fun(Kind) ->
        Observed = try requirement_parse_erlang(list_to_binary(Path)) of
            _ -> accepted
        catch error:{invalid_evidence_source, _} -> rejected; _:_ -> unexpected_failure end,
        #{kind => Kind, expected => rejected, observed => Observed, passed => Observed =:= rejected}
    end,
    Malformed = try Parse(malformed_source_after_declaration) after ok = file:delete(Path) end,
    [Malformed, Parse(missing_source)].
