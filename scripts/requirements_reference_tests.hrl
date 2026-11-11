%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

requirement_reference_self_test() ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16)),
    Fixture = filename:join(["build", "requirements", "reference-fixtures",
                            binary_to_list(Nonce) ++ ".gleam"]),
    ok = filelib:ensure_dir(Fixture),
    ok = file:write_file(Fixture, <<"pub fn generated_proof() { Nil }\n">>, [exclusive]),
    Cases = [
        {authored, <<"scripts/requirements_audit.escript">>, accepted},
        {dot_alias, <<"./scripts/requirements_audit.escript">>, rejected},
        {parent_alias, <<"scripts/../scripts/requirements_audit.escript">>, rejected},
        {absolute_alias, list_to_binary(filename:absname("scripts/requirements_audit.escript")), rejected},
        {unbound_generated_file, list_to_binary(Fixture), rejected}
    ],
    Rows = [begin
        Observed = try assert_file(Path) of
            ok -> accepted
        catch
            error:{unbound_evidence_file, _} -> rejected;
            _:_ -> unexpected_failure
        end,
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Path, Expected} <- Cases],
    Failed = length([R || R <- Rows, not maps:get(passed, R)]),
    Report = #{schema => 1, scope => <<"requirement evidence source membership">>,
        nonce => Nonce, completed => length(Rows), failed => Failed, cases => Rows},
    ok = file:write_file("build/requirements/reference-self-test.json", json:encode(Report)),
    ok = file:delete(Fixture),
    io:format("requirement reference controls: ~B completed, ~B failed~n", [length(Rows), Failed]),
    ensure(Failed =:= 0, self_test_unbound_requirement_evidence_accepted),
    ok.
