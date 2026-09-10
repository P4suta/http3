#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(PR_CASES, 10000).
-define(NIGHTLY_CASES, 1000000).
-define(MODULUS, 2147483647).

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "campaign failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["--self-test"]) ->
    self_test();
run([Mode]) when Mode =:= "property"; Mode =:= "fuzz" ->
    campaign(Mode, 0, 1, ?PR_CASES);
run([Mode, "--shard", ShardText, "--shards", ShardsText])
        when Mode =:= "property"; Mode =:= "fuzz" ->
    {Shard, Shards} = parsed_shards(ShardText, ShardsText),
    ensure(?NIGHTLY_CASES rem Shards =:= 0,
           {nightly_cases_not_divisible, ?NIGHTLY_CASES, Shards}),
    campaign(Mode, Shard, Shards, ?NIGHTLY_CASES div Shards);
run([Mode, "--shards", ShardsText, "--shard", ShardText])
        when Mode =:= "property"; Mode =:= "fuzz" ->
    run([Mode, "--shard", ShardText, "--shards", ShardsText]);
run(_) ->
    erlang:error({usage,
                  "--self-test | property|fuzz [--shard N --shards N]"}).

campaign(Mode, Shard, Shards, Cases) ->
    add_code_paths(),
    clear_stale_reports(Mode, Shard, Shards),
    Seed = campaign_seed(Mode, Shard),
    CoreSeed = next_seed(Seed),
    HttpSeed = next_seed(CoreSeed),
    SourceDigest = source_digest(Mode),
    Runs = [
        run_one(Mode, <<"http3-wire">>, http3_module(Mode),
                Seed, Cases, retained(Mode, http3), Shard, Shards,
                SourceDigest),
        run_one(Mode, <<"quic-core-wire">>, core_module(Mode),
                CoreSeed, Cases, retained(Mode, quic_core), Shard, Shards,
                SourceDigest),
        run_one(Mode, <<"http-masque">>, http_module(Mode),
                HttpSeed, Cases, retained(Mode, http), Shard, Shards,
                SourceDigest)
    ],
    Report = #{status => <<"Ready">>, campaign => list_to_binary(Mode),
               shard => Shard, shards => Shards,
               generated_cases => lists:sum([maps:get(generated_cases, Run)
                                              || Run <- Runs]),
               generated_cases_per_family => Cases,
               source_sha256 => SourceDigest, runs => Runs},
    Path = filename:join(
             ["build", "campaign", Mode,
              "shard-" ++ integer_to_list(Shard) ++ ".json"]),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    %% Keep the stable PR report path for status and audit-bundle consumers.
    case Shards of
        1 ->
            Stable = filename:join(["build", "campaign", Mode ++ ".json"]),
            ok = file:write_file(Stable, [json:encode(Report), <<"\n">>]);
        _ -> ok
    end,
    io:format("~s campaign shard ~B/~B: ~B generated cases across ~B families~n",
              [Mode, Shard, Shards, maps:get(generated_cases, Report),
               length(Runs)]),
    ok.

run_one(Mode, Family, Module, Seed, Cases, Retained, Shard, Shards,
        SourceDigest) ->
    ensure(code:which(Module) =/= non_existing, {missing_corpus_beam, Module}),
    Run = fun(Prefix) ->
        capture_prefix(Module, Family, Seed, Prefix, Retained)
    end,
    case Run(Cases) of
        {ok, Observed} ->
            Digest = hex(crypto:hash(
                           sha256,
                           term_to_binary({Mode, Family, Module, Seed, Cases,
                                           Retained, Observed}))),
            #{family => Family, module => atom_to_binary(Module), seed => Seed,
              generated_cases => Cases, retained_seeds => Retained,
              command_output_sha256 => Digest};
        {error, _, _, _} = InitialFailure ->
            Located = locate_failure(Run, Cases, InitialFailure),
            Path = write_failure_report(
                     Mode, Family, Module, Seed, Cases, Retained,
                     Shard, Shards, SourceDigest, Located),
            erlang:error({campaign_family_failed, Family, Path})
    end.

capture_prefix(Module, Family, Seed, Cases, Retained) ->
    try apply(Module, exercise_from, [Seed, Cases]) of
        Observed ->
            Expected = Cases + Retained,
            ensure(Observed =:= Expected,
                   {campaign_count_mismatch, Family, Expected, Observed}),
            {ok, Observed}
    catch
        Class:Reason:Stacktrace -> {error, Class, Reason, Stacktrace}
    end.

locate_failure(Run, Cases, InitialFailure) ->
    case Run(0) of
        {error, _, _, _} = Failure ->
            {<<"retained_or_setup">>, null, true, Failure};
        {ok, _} ->
            case Run(Cases) of
                {ok, _} ->
                    {<<"non_reproducible">>, null, false, InitialFailure};
                {error, _, _, _} = ReplayFailure ->
                    {Prefix, Failure} =
                        minimize_failure(Run, 0, Cases, ReplayFailure),
                    {<<"generated">>, Prefix, true, Failure}
            end
    end.

minimize_failure(_Run, Passing, Failing, Failure)
        when Failing =:= Passing + 1 ->
    {Failing, Failure};
minimize_failure(Run, Passing, Failing, Failure) ->
    Middle = Passing + (Failing - Passing) div 2,
    case Run(Middle) of
        {ok, _} ->
            minimize_failure(Run, Middle, Failing, Failure);
        {error, _, _, _} = MiddleFailure ->
            minimize_failure(Run, Passing, Middle, MiddleFailure)
    end.

write_failure_report(Mode, Family, Module, Seed, Cases, Retained,
                     Shard, Shards, SourceDigest,
                     Located) ->
    Report = failure_report(
               Mode, Family, Module, Seed, Cases, Retained,
               Shard, Shards, SourceDigest, Located),
    Path = failure_path(Mode, Family, Shard),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    io:format(standard_error,
              "~s campaign family ~s failed; minimized evidence: ~s~n",
              [Mode, Family, Path]),
    Path.

failure_report(Mode, Family, Module, Seed, Cases, Retained,
               Shard, Shards, SourceDigest,
               {Scope, Prefix, Deterministic, Failure}) ->
    ReplayCases = case Prefix of null -> Cases; _ -> Prefix end,
    GeneratedIndex = case Prefix of null -> null; _ -> Prefix - 1 end,
    Details = failure_details(Failure),
    maps:merge(
      #{status => <<"Failed">>, campaign => list_to_binary(Mode),
        shard => Shard, shards => Shards, family => Family,
        module => atom_to_binary(Module), seed => Seed,
        requested_generated_cases => Cases,
        retained_seeds => Retained, failure_scope => Scope,
        minimal_generated_prefix => Prefix,
        generated_case_index_zero_based => GeneratedIndex,
        deterministic_replay => Deterministic,
        replay_generated_cases => ReplayCases,
        replay_command => replay_command(Module, Seed, ReplayCases, Retained),
        source_sha256 => SourceDigest},
      Details).

failure_details({error, Class, Reason, Stacktrace}) ->
    #{exception_class => atom_to_binary(Class),
      exception_reason => bounded_term(Reason, 2048),
      stacktrace => bounded_term(Stacktrace, 8192)}.

replay_command(Module, Seed, Cases, Retained) ->
    Expected = Cases + Retained,
    unicode:characters_to_binary(
      io_lib:format(
        "erl -noshell -pa build/dev/erlang/*/ebin "
        "packages/http3/build/dev/erlang/*/ebin "
        "packages/quic_core/build/dev/erlang/*/ebin "
        "-eval '~B = ~p:exercise_from(~B, ~B), halt(0).'",
        [Expected, Module, Seed, Cases])).

bounded_term(Term, MaximumCharacters) ->
    Characters = unicode:characters_to_list(io_lib:format("~0P", [Term, 20])),
    unicode:characters_to_binary(
      lists:sublist(Characters, MaximumCharacters)).

http3_module("property") -> 'native@property_corpus';
http3_module("fuzz") -> 'native@fuzz_corpus'.

core_module("property") -> property_corpus;
core_module("fuzz") -> fuzz_corpus.

http_module("property") -> masque_property_corpus;
http_module("fuzz") -> masque_fuzz_corpus.

retained("property", _Package) -> 0;
retained("fuzz", http3) -> 16;
retained("fuzz", quic_core) -> 16;
retained("fuzz", http) -> 18.

campaign_seed("property", Shard) ->
    positive_seed(982451653 + Shard * 104729);
campaign_seed("fuzz", Shard) ->
    positive_seed(1597463007 + Shard * 104729).

positive_seed(Value) -> 1 + Value rem (?MODULUS - 1).

next_seed(Seed) -> (Seed * 48271 + 1) rem ?MODULUS.

parsed_shards(ShardText, ShardsText) ->
    Shard = list_to_integer(ShardText),
    Shards = list_to_integer(ShardsText),
    ensure(Shards > 0 andalso Shard >= 0 andalso Shard < Shards,
           {invalid_shard, Shard, Shards}),
    {Shard, Shards}.

clear_stale_reports(Mode, Shard, Shards) ->
    lists:foreach(fun delete_generated_report/1,
                  stale_report_paths(Mode, Shard, Shards)).

stale_report_paths(Mode, Shard, Shards) ->
    ShardPath = filename:join(
                  ["build", "campaign", Mode,
                   "shard-" ++ integer_to_list(Shard) ++ ".json"]),
    FailurePaths = [failure_path(Mode, Family, Shard)
                    || Family <- [<<"http3-wire">>, <<"quic-core-wire">>,
                                  <<"http-masque">>]],
    StablePaths = case Shards of
        1 -> [filename:join(["build", "campaign", Mode ++ ".json"])];
        _ -> []
    end,
    [ShardPath | StablePaths ++ FailurePaths].

failure_path(Mode, Family, Shard) ->
    filename:join(
      ["build", "campaign", Mode,
       "failure-shard-" ++ integer_to_list(Shard) ++ "-"
       ++ binary_to_list(Family) ++ ".json"]).

delete_generated_report(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> erlang:error({cannot_delete_stale_report,
                                        Path, Reason})
    end.

add_code_paths() ->
    Roots = ["build/dev/erlang",
             "packages/http3/build/dev/erlang",
             "packages/quic_core/build/dev/erlang"],
    Paths = lists:usort(lists:append([
        filelib:wildcard(filename:join(Root, "*/ebin")) || Root <- Roots
    ])),
    lists:foreach(
      fun(Path) -> true = code:add_patha(filename:absname(Path)) end,
      Paths).

source_digest(Mode) ->
    Paths = source_paths(Mode),
    ensure(Paths =/= [], {missing_campaign_sources, Mode}),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

source_paths(Mode) ->
    Suffix = case Mode of "property" -> "property"; "fuzz" -> "fuzz" end,
    lists:usort(
        ["gleam.toml", "manifest.toml",
         "packages/http3/gleam.toml", "packages/http3/manifest.toml",
         "packages/quic_core/gleam.toml",
         "packages/quic_core/manifest.toml",
         "scripts/campaign.escript"]
        ++ production_source_paths()
        ++ filelib:wildcard("test/*" ++ Suffix ++ "*.gleam")
        ++ filelib:wildcard(
             "packages/http3/test/native/*" ++ Suffix ++ "*.gleam")
        ++ filelib:wildcard(
             "packages/quic_core/test/*" ++ Suffix ++ "*.gleam")).

production_source_paths() ->
    lists:append([source_tree("src"),
                  source_tree("packages/http3/src"),
                  source_tree("packages/quic_core/src")]).

source_tree(Directory) ->
    filelib:fold_files(
      Directory, ".*", true,
      fun(Path, Paths) -> [Path | Paths] end,
      []).

self_test() ->
    PropertyPaths = source_paths("property"),
    ProductionPaths = production_source_paths(),
    RepresentativeProductionPaths =
        ["src/http/masque.gleam", "src/http_server_ffi.erl",
         "packages/http3/src/http3.gleam",
         "packages/http3/src/http3_internal_transport_ffi.erl",
         "packages/quic_core/src/quic_core.gleam",
         "packages/quic_core/src/quic_core_udp_ffi.erl"],
    ensure(length(ProductionPaths) >= length(RepresentativeProductionPaths),
           {production_source_discovery_too_small, ProductionPaths}),
    MissingRepresentatives = RepresentativeProductionPaths -- ProductionPaths,
    ensure(MissingRepresentatives =:= [],
           {production_source_discovery_incomplete, MissingRepresentatives}),
    MissingProductionPaths = ProductionPaths -- PropertyPaths,
    ensure(MissingProductionPaths =:= [],
           {production_sources_missing_from_digest, MissingProductionPaths}),
    ensure(PropertyPaths =:= lists:usort(PropertyPaths),
           {campaign_sources_not_canonical, PropertyPaths}),

    Generated = fun(Prefix) when Prefix >= 37 ->
                        {error, error, {synthetic_failure, Prefix}, []};
                   (Prefix) -> {ok, Prefix}
                end,
    Initial = Generated(100),
    {<<"generated">>, 37, true,
     {error, error, {synthetic_failure, 37}, []}} =
        locate_failure(Generated, 100, Initial),

    Retained = fun(_Prefix) ->
                       {error, throw, synthetic_retained_failure, []}
               end,
    {<<"retained_or_setup">>, null, true,
     {error, throw, synthetic_retained_failure, []}} =
        locate_failure(Retained, 100, Retained(100)),

    NonReproducible = fun(Prefix) ->
        case get(campaign_self_test_failure) of
            undefined ->
                put(campaign_self_test_failure, seen),
                {error, exit, synthetic_transient_failure, []};
            seen -> {ok, Prefix}
        end
    end,
    erase(campaign_self_test_failure),
    Transient = NonReproducible(100),
    {<<"non_reproducible">>, null, false,
     {error, exit, synthetic_transient_failure, []}} =
        locate_failure(NonReproducible, 100, Transient),
    erase(campaign_self_test_failure),

    Bounded = bounded_term(binary:copy(<<"x">>, 10000), 32),
    ensure(byte_size(Bounded) =< 32, {unbounded_failure_text, byte_size(Bounded)}),
    Replay = replay_command(masque_property_corpus, 123, 37, 0),
    ensure(binary:match(Replay, <<"exercise_from(123, 37)">>) =/= nomatch,
           {invalid_replay_command, Replay}),
    FailureReport = failure_report(
                      "property", <<"synthetic">>, masque_property_corpus,
                      123, 100, 0, 0, 1, <<"SOURCE">>,
                      {<<"generated">>, 37, true, Initial}),
    ensure(maps:get(minimal_generated_prefix, FailureReport) =:= 37,
           {invalid_failure_prefix, FailureReport}),
    ensure(maps:get(generated_case_index_zero_based, FailureReport) =:= 36,
           {invalid_failure_index, FailureReport}),
    ensure(byte_size(maps:get(exception_reason, FailureReport)) =< 2048,
           {unbounded_failure_reason, FailureReport}),
    _EncodedFailureReport = json:encode(FailureReport),
    stale_report_self_test(),
    io:format("campaign self-test ok (complete production-source digest, "
              "minimal generated prefix, retained/setup classification, "
              "transient detection, bounded trace, replay, stale-report "
              "cleanup)~n"),
    ok.

stale_report_self_test() ->
    Mode = "self-test-" ++ integer_to_list(
                            erlang:unique_integer([positive, monotonic])),
    Shard = 7,
    Paths = stale_report_paths(Mode, Shard, 1),
    lists:foreach(
      fun(Path) ->
          ok = filelib:ensure_dir(Path),
          ok = file:write_file(Path, <<"stale\n">>)
      end,
      Paths),
    ensure(lists:all(fun filelib:is_file/1, Paths),
           {stale_report_fixture_missing, Paths}),
    clear_stale_reports(Mode, Shard, 1),
    ensure(lists:all(fun(Path) -> not filelib:is_file(Path) end, Paths),
           {stale_report_not_removed, Paths}),
    Directory = filename:join(["build", "campaign", Mode]),
    ok = file:del_dir(Directory),
    ok.

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte])
                      || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
