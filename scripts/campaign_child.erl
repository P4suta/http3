%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(campaign_child).
-export([run/4, evaluate/5, localize/3]).
-include("execution_identity.hrl").
-include("diagnostic_failure.hrl").

%% Each family, including its reproductions, has one independently guarded VM.
%% Persist the first failure before localization, so a blocked replay cannot
%% erase the original result. Neither exception values nor raw output escape.
run(Request, Path, Nonce, _Reserved) ->
    Base = Request#{schema => 1, nonce => Nonce,
                    execution_environment => execution_runtime()},
    Function = fun(Cases) -> evaluate(maps:get(mode, Request), maps:get(family, Request),
        maps:get(seed, Request), Cases, maps:get(retained_seeds, Request)) end,
    Cases = maps:get(requested_cases, Request),
    case capture(Function, Cases) of
        {ok, Result} ->
            write(Path, Base#{status => <<"Passed">>, completed_cases => Cases,
                result => Result, failure => null}), halt(0);
        {error, Failure} = Initial ->
            Failed = Base#{status => <<"Failed">>, completed_cases => 0,
                result => null, failure => localization(<<"unlocalized">>, null, false, Failure)},
            write(Path, Failed),
            Located = localize(fun(N) -> capture(Function, N) end, Cases, Initial),
            Completed = case maps:get(minimal_generated_prefix, Located) of
                null -> 0; N -> erlang:max(0, N - 1)
            end,
            write(Path, Failed#{completed_cases => Completed, failure => Located}), halt(1)
    end.

evaluate(<<"model">>, <<"quic-cubic-rfc9438-rfc9406">>, Seed, Cases, 0) ->
    campaign_model:run(Seed, Cases);
evaluate(Mode, Family, Seed, Cases, Retained) ->
    Module = corpus(Mode, Family),
    Observed = Module:exercise_from(Seed, Cases),
    case Observed =:= Cases + Retained of
        true -> #{observed_cases => Observed,
            final_sha256 => binary:encode_hex(crypto:hash(sha256,
                term_to_binary({Mode, Family, Seed, Cases, Retained, Observed})))};
        false -> erlang:error(campaign_count_mismatch)
    end.

corpus(<<"property">>, <<"http3-wire">>) -> 'native@property_corpus';
corpus(<<"fuzz">>, <<"http3-wire">>) -> 'native@fuzz_corpus';
corpus(<<"property">>, <<"quic-core-wire">>) -> property_corpus;
corpus(<<"fuzz">>, <<"quic-core-wire">>) -> fuzz_corpus;
corpus(<<"property">>, <<"http-masque">>) -> masque_property_corpus;
corpus(<<"fuzz">>, <<"http-masque">>) -> masque_fuzz_corpus.

capture(Function, Cases) ->
    try {ok, Function(Cases)}
    catch Class:Reason:_ ->
        Details = diagnostic_failure_details(Class, Reason, []),
        {error, #{exception_class => maps:get(exception_class, Details),
                  classification => maps:get(exception_reason, Details)}}
    end.

localize(Run, Cases, {error, Initial}) ->
    case Run(0) of
        {error, Failure} -> localization(<<"retained_or_setup">>, null, true, Failure);
        {ok, _} ->
            case Run(Cases) of
                {ok, _} -> localization(<<"non_reproducible">>, null, false, Initial);
                {error, Failure} -> minimize(Run, 0, Cases, Failure)
            end
    end.
minimize(_, Passing, Failing, Failure) when Failing =:= Passing + 1 ->
    localization(<<"generated">>, Failing, true, Failure);
minimize(Run, Passing, Failing, Failure) ->
    Middle = Passing + (Failing - Passing) div 2,
    case Run(Middle) of
        {ok, _} -> minimize(Run, Middle, Failing, Failure);
        {error, Next} -> minimize(Run, Passing, Middle, Next)
    end.
localization(Scope, Prefix, Deterministic, Failure) ->
    Failure#{scope => Scope, minimal_generated_prefix => Prefix,
             deterministic_replay => Deterministic}.
write(Path, Report) ->
    Bytes = iolist_to_binary([json:encode(Report), $\n]),
    true = byte_size(Bytes) =< 65536,
    Temporary = Path ++ ".pending",
    ok = file:write_file(Temporary, Bytes),
    %% Windows rename does not replace existing files. Invalidate the previous
    %% checkpoint only after the complete replacement is safely written.
    case file:delete(Path) of ok -> ok; {error, enoent} -> ok end,
    ok = file:rename(Temporary, Path).
