#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("campaign_runner.hrl").
-include("campaign_runner_tests.hrl").

main(Arguments) ->
    try run(Arguments) catch Class:Reason:Stack ->
        io:format(standard_error, "campaign failed: ~s~n", [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.
run(["--self-test"]) -> generated_self_test();
run([Mode]) when Mode =:= "property"; Mode =:= "fuzz" -> campaign(Mode, 0, 1);
run([Mode, "--shard", Id, "--shards", Total]) when Mode =:= "property"; Mode =:= "fuzz" ->
    campaign(Mode, list_to_integer(Id), list_to_integer(Total));
run([Mode, "--shards", Total, "--shard", Id]) -> run([Mode, "--shard", Id, "--shards", Total]);
run(_) -> erlang:error(invalid_campaign_arguments).
campaign(Mode, Shard, Shards) ->
    true = Shards >= 1 andalso Shards =< 1024 andalso Shard >= 0 andalso Shard < Shards,
    true = 1000000 rem Shards =:= 0,
    Cases = case Shards of 1 -> 10000; _ -> 1000000 div Shards end,
    Base = case Mode of "property" -> 982451653; "fuzz" -> 1597463007 end,
    Seed = 1 + (Base + Shard * 104729) rem 2147483646,
    generated_execute(Mode, Shard, Shards, Seed, Cases, qualification).
hex(Bytes) -> binary:encode_hex(Bytes).
