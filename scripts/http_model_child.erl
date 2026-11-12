%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_model_child).
-export([run/5, replay/6]).

run(Domains, Seed, Cases, Path, Nonce) ->
    nil = http_models_ffi:self_test(),
    {Status, Rows} = domains(Domains, Seed, Cases, []),
    write(Path, #{schema => 1, nonce => Nonce, mode => <<"campaign">>,
                  status => Status, domains => Rows}),
    halt(case Status of <<"Passed">> -> 0; _ -> 1 end).

domains([], _, _, Rows) -> {<<"Passed">>, lists:reverse(Rows)};
domains([Domain | Rest], Seed, Cases, Rows) ->
    case http_models_ffi:run(Domain, Seed, Cases) of
        {ok, {model_summary, Cases, Transitions, Digest}} ->
            Row = #{domain => Domain, seed => Seed, cases => Cases,
                    transitions => Transitions, sha256 => Digest, status => <<"Passed">>},
            domains(Rest, Seed, Cases, [Row | Rows]);
        {error, {model_failure, Case, CaseSeed, Step, Code}} ->
            Minimized = minimize(Domain, CaseSeed, Code),
            Row = #{domain => Domain, seed => Seed, cases => Case,
                    case_seed => CaseSeed, failure_step => Step,
                    invariant => Code, minimization => Minimized,
                    status => <<"Failed">>},
            {<<"Failed">>, lists:reverse([Row | Rows])}
    end.

minimize(Domain, Seed, Code) ->
    case http_models_ffi:minimize(Domain, Seed, Code) of
        {ok, {Prefix, Step, Code}} ->
            Scope = case Domain of
                <<"http1">> -> <<"independent_case">>;
                <<"drain">> -> <<"independent_case">>;
                _ -> <<"transition_prefix">>
            end,
            #{verified => true, prefix_steps => Prefix, failure_step => Step,
              scope => Scope};
        {error, nil} ->
            #{verified => false, prefix_steps => 32, failure_step => 0,
              scope => <<"unstable_reproduction">>}
    end.

replay(Domain, Seed, Steps, Path, Nonce, _Reserved) ->
    Result = case http_models_ffi:replay(Domain, Seed, Steps) of
        {ok, {Transitions, Snapshot}} ->
            #{domain => Domain, seed => Seed, prefix_steps => Steps,
              transitions => Transitions, status => <<"Passed">>,
              sha256 => hex(crypto:hash(sha256, term_to_binary(Snapshot, [deterministic])))};
        {error, {model_failure, _, Seed, Step, Code}} ->
            #{domain => Domain, seed => Seed, prefix_steps => Steps,
              failure_step => Step, invariant => Code, status => <<"Failed">>}
    end,
    Status = maps:get(status, Result),
    write(Path, #{schema => 1, nonce => Nonce, mode => <<"replay">>,
                  status => Status, domains => [Result]}),
    halt(case Status of <<"Passed">> -> 0; _ -> 1 end).

write(Path, Report) -> ok = file:write_file(Path, [json:encode(Report), $\n]).
hex(Binary) -> iolist_to_binary([io_lib:format("~2.16.0b", [Byte]) || <<Byte>> <= Binary]).
