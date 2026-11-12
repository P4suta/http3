%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_models_ffi).
-export([run/3, replay/3, minimize/3, self_test/0]).

%% Finite, payload-free failure schema shared with the ordinary Gleam tests.
%% Each case has its own seed, so a failure replays without earlier actors or
%% protocol state. The first failing step is the shortest executed prefix.
run(Name, Seed, Cases) when is_binary(Name), is_integer(Seed), Seed >= 0,
                            Seed < 2147483647, is_integer(Cases), Cases > 0,
                            Cases =< 10000 ->
    case domain(Name) of
        invalid -> {error, {model_failure, 0, Seed, 0, 901}};
        Domain ->
            Deadline = erlang:monotonic_time(millisecond) + 600000,
            cases(Domain, Seed, Cases, 0, 0, crypto:hash_init(sha256), Deadline)
    end;
run(_, _, _) -> {error, {model_failure, 0, 0, 0, 901}}.

replay(Name, CaseSeed, Steps) when is_binary(Name), is_integer(CaseSeed),
                                 CaseSeed >= 0, CaseSeed < 2147483647,
                                 is_integer(Steps), Steps > 0, Steps =< 32 ->
    case domain(Name) of
        invalid -> {error, {model_failure, 0, CaseSeed, 0, 901}};
        Domain -> case_result(Domain, CaseSeed, Steps, 0)
    end;
replay(_, _, _) -> {error, {model_failure, 0, 0, 0, 901}}.

%% Every case starts independently. Remove all preceding cases, then search
%% the finite transition prefixes for the first one reproducing the same
%% invariant. Framing and executor-drain cases are indivisible scenarios.
minimize(Name, CaseSeed, Code) when is_binary(Name), is_integer(CaseSeed),
                                  CaseSeed >= 0, CaseSeed < 2147483647,
                                  is_integer(Code), Code > 0, Code < 1000 ->
    case domain(Name) of
        invalid -> {error, nil};
        Domain when Domain =:= http1; Domain =:= drain ->
            minimized(Domain, CaseSeed, Code, 32, 32);
        Domain -> minimized(Domain, CaseSeed, Code, 1, 32)
    end;
minimize(_, _, _) -> {error, nil}.

minimized(Domain, Seed, Code, Prefix, Maximum) ->
    Run = fun(Length) -> case_result(Domain, Seed, Length, 0) end,
    minimize_prefix(Run, Code, Prefix, Maximum).

minimize_prefix(_Run, _Code, Prefix, Maximum) when Prefix > Maximum -> {error, nil};
minimize_prefix(Run, Code, Prefix, Maximum) ->
    case Run(Prefix) of
        {error, {model_failure, 0, _, Step, Code}} -> {ok, {Prefix, Step, Code}};
        _ -> minimize_prefix(Run, Code, Prefix + 1, Maximum)
    end.

domain(<<"http1">>) -> http1;
domain(<<"http2">>) -> http2;
domain(<<"hpack">>) -> hpack;
domain(<<"pool">>) -> pool;
domain(<<"cancellation">>) -> cancellation;
domain(<<"drain">>) -> drain;
domain(_) -> invalid.

cases(_Domain, _Seed, 0, Count, Transitions, Hash, _Deadline) ->
    {ok, {model_summary, Count, Transitions, hex(crypto:hash_final(Hash))}};
cases(Domain, Seed, Remaining, Count, Transitions, Hash, Deadline) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        false -> {error, {model_failure, Count, Seed, 0, 902}};
        true ->
            case case_result(Domain, Seed, 32, Count) of
                {error, _} = Failure -> Failure;
                {ok, {Used, Snapshot}} ->
                    Updated = crypto:hash_update(Hash, term_to_binary({Seed, Used, Snapshot}, [deterministic])),
                    Next = ((Seed + 1) * 48271) rem 2147483647,
                    cases(Domain, Next, Remaining - 1, Count + 1, Transitions + Used, Updated, Deadline)
            end
    end.

case_result(Domain, Seed, Steps, Case) ->
    try execute(Domain, Seed, Steps) of
        {Used, Snapshot} when is_integer(Used), Used >= 0, Used =< 256 ->
            {ok, {Used, Snapshot}};
        _ -> {error, {model_failure, Case, Seed, 0, 903}}
    catch
        throw:Failure when is_tuple(Failure), tuple_size(Failure) >= 3,
                           element(1, Failure) =:= model_failure,
                           is_integer(element(2, Failure)), is_integer(element(3, Failure)) ->
            {error, {model_failure, Case, Seed, element(2, Failure), element(3, Failure)}};
        %% Unexpected exceptions remain failures and never print backend
        %% terms, bodies, endpoints, opaque handles, or exception messages.
        error:_ -> {error, {model_failure, Case, Seed, 0, 904}};
        exit:_ -> {error, {model_failure, Case, Seed, 0, 905}};
        throw:_ -> {error, {model_failure, Case, Seed, 0, 906}}
    end.

execute(Domain, Seed, Steps) when Domain =:= http1; Domain =:= http2; Domain =:= hpack ->
    http_model_protocols:run(Domain, Seed, Steps);
execute(Domain, Seed, Steps) -> http_model_runtime:run(Domain, Seed, Steps).

hex(Binary) -> iolist_to_binary([io_lib:format("~2.16.0b", [Byte]) || <<Byte>> <= Binary]).

self_test() ->
    Invalid = [run(<<"unknown">>, 1, 1), run(<<"http1">>, -1, 1),
               run(<<"http1">>, 1, 0), run(<<"http1">>, 1, 10001),
               replay(<<"http1">>, 1, 33)],
    true = lists:all(fun({error, {model_failure, _, _, _, 901}}) -> true;
                        (_) -> false end, Invalid),
    {ok, First} = run(<<"http2">>, 104729, 8),
    {ok, First} = run(<<"http2">>, 104729, 8),
    {ok, {Count, _}} = replay(<<"http2">>, 104729, 3),
    true = Count =:= 6,
    Reproducer = fun(Prefix) ->
        case Prefix >= 7 of
            true -> {error, {model_failure, 0, 11, 7, 777}};
            false -> {ok, {Prefix, nil}}
        end
    end,
    {ok, {7, 7, 777}} = minimize_prefix(Reproducer, 777, 1, 32),
    {error, nil} = minimize_prefix(Reproducer, 778, 1, 32),
    nil.
