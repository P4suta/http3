%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_CAMPAIGN_CHILD_EVIDENCE_HRL).
-define(HTTP_CAMPAIGN_CHILD_EVIDENCE_HRL, true).
-include("runtime_matrix_evidence.hrl").

generated_child_valid(Child, Request, Nonce, Runtime) ->
    try
        true = suite_exact_keys(Child, [schema, nonce, mode, family, seed, requested_cases,
            retained_seeds, execution_environment, status, completed_cases, result, failure]),
        1 = maps:get(<<"schema">>, Child), Nonce = maps:get(<<"nonce">>, Child),
        Runtime = maps:get(<<"execution_environment">>, Child),
        true = maps:with(maps:keys(Request), Child) =:= Request,
        Cases = maps:get(<<"requested_cases">>, Request),
        Completed = maps:get(<<"completed_cases">>, Child),
        true = generated_integer(Completed, 0, Cases),
        case maps:get(<<"status">>, Child) of
            <<"Passed">> ->
                Cases = Completed, null = maps:get(<<"failure">>, Child),
                generated_result_valid(maps:get(<<"result">>, Child), Request);
            <<"Failed">> ->
                null = maps:get(<<"result">>, Child),
                Failure = maps:get(<<"failure">>, Child),
                true = suite_exact_keys(Failure, [scope, minimal_generated_prefix,
                    deterministic_replay, exception_class, classification]),
                true = lists:member(maps:get(<<"exception_class">>, Failure),
                    [<<"error">>, <<"exit">>, <<"throw">>, <<"unknown">>]),
                true = lists:member(maps:get(<<"classification">>, Failure),
                    [<<"pattern_mismatch">>, <<"unexpected_variant">>, <<"assertion_failed">>,
                     <<"callback_failed">>, <<"invalid_argument">>, <<"resource_limit">>,
                     <<"deadline_exceeded">>, <<"validation_failed">>]),
                Scope = maps:get(<<"scope">>, Failure),
                Prefix = maps:get(<<"minimal_generated_prefix">>, Failure),
                Repeated = maps:get(<<"deterministic_replay">>, Failure),
                case Scope of
                    <<"generated">> -> Repeated =:= true andalso generated_integer(Prefix, 1, Cases)
                        andalso Completed =:= Prefix - 1;
                    <<"retained_or_setup">> -> Repeated =:= true andalso Prefix =:= null andalso Completed =:= 0;
                    <<"non_reproducible">> -> Repeated =:= false andalso Prefix =:= null andalso Completed =:= 0;
                    <<"unlocalized">> -> Repeated =:= false andalso Prefix =:= null andalso Completed =:= 0
                end
        end
    catch _:_ -> false end.

generated_result_valid(Result, Request) ->
    true = runtime_matrix_hex(maps:get(<<"final_sha256">>, Result)),
    case maps:get(<<"mode">>, Request) of
        <<"model">> ->
            suite_exact_keys(Result, [final_sha256, oracle_ack_checks, ecn_oracle_events,
                application_limited_checks, hystart_oracle_rounds, topology_oracle_modes]) andalso
            maps:remove(<<"final_sha256">>, Result) =:= #{<<"oracle_ack_checks">> => 200,
                <<"ecn_oracle_events">> => 9, <<"application_limited_checks">> => 1,
                <<"hystart_oracle_rounds">> => 5, <<"topology_oracle_modes">> => 2};
        Mode ->
            Cases = maps:get(<<"requested_cases">>, Request), Retained = maps:get(<<"retained_seeds">>, Request),
            Observed = Cases + Retained,
            ExpectedHash = binary:encode_hex(crypto:hash(sha256, term_to_binary({Mode,
                maps:get(<<"family">>, Request), maps:get(<<"seed">>, Request), Cases, Retained, Observed}))),
            suite_exact_keys(Result, [observed_cases, final_sha256]) andalso
            maps:get(<<"observed_cases">>, Result) =:= Observed andalso
            maps:get(<<"final_sha256">>, Result) =:= ExpectedHash
    end.

generated_execution_valid(Execution, Request, Runtime, RunnerDigest) ->
    try
        true = suite_exact_keys(Execution, [request, nonce, deadline_ms, runner_sha256,
            exit_status, process, child, child_sha256]),
        Request = maps:get(<<"request">>, Execution),
        600000 = maps:get(<<"deadline_ms">>, Execution),
        0 = maps:get(<<"exit_status">>, Execution),
        RunnerDigest = maps:get(<<"runner_sha256">>, Execution),
        true = runtime_matrix_process_valid(maps:get(<<"process">>, Execution)),
        Nonce = maps:get(<<"nonce">>, Execution),
        true = is_binary(Nonce) andalso
            re:run(Nonce, <<"^[0-9A-Fa-f]{32}$">>, [{capture, none}]) =:= match,
        Child = maps:get(<<"child">>, Execution),
        true = generated_child_valid(Child, Request, Nonce, Runtime),
        <<"Passed">> = maps:get(<<"status">>, Child),
        generated_json_digest(Child) =:= maps:get(<<"child_sha256">>, Execution)
    catch _:_ -> false end.

generated_json_digest(Term) -> binary:encode_hex(crypto:hash(sha256, json:encode(Term))).
generated_integer(N, Min, Max) -> is_integer(N) andalso N >= Min andalso N =< Max.

generated_compile_runner() ->
    [case compile:file(Source, [binary, deterministic, return_errors, return_warnings, {i, "scripts"}]) of
        {ok, Module, Bytes, []} -> {Module, Bytes};
        _ -> erlang:error(campaign_runner_compile_failed)
    end || Source <- ["scripts/campaign_child.erl", "scripts/campaign_model.erl"]].
generated_runner_digest(Compiled) ->
    binary:encode_hex(crypto:hash(sha256, [[atom_to_binary(Module), 0, Bytes]
                                         || {Module, Bytes} <- Compiled])).
generated_requests("model", Seed, Cases) ->
    [#{mode => <<"model">>, family => <<"quic-cubic-rfc9438-rfc9406">>,
        seed => Seed, requested_cases => Cases, retained_seeds => 0}];
generated_requests(Mode, Seed, Cases) ->
    Next = (Seed * 48271 + 1) rem 2147483647,
    Last = (Next * 48271 + 1) rem 2147483647,
    [#{mode => list_to_binary(Mode), family => Family, seed => Value,
        requested_cases => Cases, retained_seeds => case Mode of "property" -> 0; "fuzz" -> Retained end}
     || {Family, Value, Retained} <- [{<<"http3-wire">>, Seed, 16},
        {<<"quic-core-wire">>, Next, 16}, {<<"http-masque">>, Last, 18}]].

generated_replay("model", _, _, Seed, Cases, diagnostic) ->
    iolist_to_binary(io_lib:format("escript scripts/model.escript replay ~B ~B", [Seed, Cases]));
generated_replay(Mode, Shard, Shards, _, _, qualification) ->
    Script = case Mode of "model" -> "model.escript"; _ -> "campaign.escript " ++ Mode end,
    Suffix = case Shards of 1 -> ""; _ -> io_lib:format(" --shard ~B --shards ~B", [Shard, Shards]) end,
    iolist_to_binary(["escript scripts/", Script, Suffix]).

-endif.
