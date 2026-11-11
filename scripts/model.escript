#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("campaign_runner.hrl").
-include("campaign_runner_tests.hrl").

main(Arguments) ->
    try run(Arguments) catch Class:Reason:Stack ->
        io:format(standard_error, "model failed: ~s~n", [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.
run(["--self-test"]) -> generated_self_test();
run(["replay", SeedText, CasesText]) ->
    Seed = list_to_integer(SeedText), Cases = list_to_integer(CasesText),
    true = generated_integer(Seed, 0, 2147483646) andalso generated_integer(Cases, 0, 1000000),
    generated_execute("model", 0, 1, Seed, Cases, diagnostic);
run([]) -> model(0, 1);
run(["--shard", Id, "--shards", Total]) -> model(list_to_integer(Id), list_to_integer(Total));
run(["--shards", Total, "--shard", Id]) -> run(["--shard", Id, "--shards", Total]);
run(_) -> erlang:error(invalid_model_arguments).
model(Shard, Shards) ->
    true = Shards >= 1 andalso Shards =< 1024 andalso Shard >= 0 andalso Shard < Shards,
    true = 1000000 rem Shards =:= 0,
    Cases = case Shards of 1 -> 10000; _ -> 1000000 div Shards end,
    generated_execute("model", Shard, Shards, 982451653 + Shard * 104729, Cases, qualification).
hex(Bytes) -> binary:encode_hex(Bytes).
