%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_multiplexing_attested_runner).
-export([run_from_file/6]).

-include("execution_beam_identity.hrl").

-define(MAXIMUM_INVOCATION_BYTES, 16777216).
-define(MAXIMUM_RECEIPT_BYTES, 1048576).

run_from_file(InvocationPath, ExpectedInvocationSha, ExpectedNonce,
              ExpectedSourceSha, ExpectedRunnerSha,
              ExpectedRunnerSourceSha) ->
    try
        InvocationBytes = execution_beam_read(
            InvocationPath, ?MAXIMUM_INVOCATION_BYTES),
        true = execution_beam_digest(ExpectedInvocationSha, 64),
        true = execution_beam_digest(ExpectedNonce, 32),
        true = execution_beam_digest(ExpectedSourceSha, 64),
        true = execution_beam_digest(ExpectedRunnerSha, 64),
        true = execution_beam_digest(ExpectedRunnerSourceSha, 64),
        ExpectedInvocationSha = binary:encode_hex(
            crypto:hash(sha256, InvocationBytes), lowercase),
        {ok, Invocation} = canonical_etf_decode(
            InvocationBytes, ?MAXIMUM_INVOCATION_BYTES, 64, 2000000),
        {http3_multiplexing_invocation_v2, ReceiptPath, ExpectedNonce,
         ExpectedSourceSha, ExpectedRunnerSha, ExpectedRunnerSourceSha,
         BuildRoot, Inventory, RequiredModules} = Invocation,
        true = is_list(RequiredModules) andalso RequiredModules =/= [],
        true = length(RequiredModules) =< 64,
        true = runner_loaded(ExpectedRunnerSha),
        {Observed, Multiplexed, Unavailable, Unexpected,
         BaselineRoles, FinalRoles, CensusVerified} =
            'http3_multiplexing_probe':batch_observation_summary(),
        Status = normalize_status(Observed),
        Counters = counters(Multiplexed, Unavailable, Unexpected,
            BaselineRoles, FinalRoles, CensusVerified),
        true = counters_valid(Status, Counters),
        InventorySha = maps:get(sha256, Inventory),
        Attestation0 = execution_beam_loaded_attestation(
            Inventory, BuildRoot, RequiredModules),
        Attestation = Attestation0#{
            runner_sha256 => ExpectedRunnerSha,
            loaded_beams_verified =>
                maps:get(loaded_beams_verified, Attestation0, false)
                    andalso runner_loaded(ExpectedRunnerSha)},
        true = execution_beam_attestation_valid(
            Attestation, ExpectedRunnerSha, InventorySha),
        Receipt = receipt_term(
            ExpectedNonce, ExpectedSourceSha, ExpectedRunnerSourceSha,
            ExpectedInvocationSha, Status,
            Multiplexed + Unavailable + Unexpected, Counters, Attestation),
        ok = execution_beam_publish_new(
            ReceiptPath,
            term_to_binary(Receipt, [{minor_version, 2}]),
            ?MAXIMUM_RECEIPT_BYTES),
        io:put_chars([marker(Status), <<"\n">>]),
        erlang:halt(Status)
    catch
        _:_ ->
            io:put_chars(<<"HTTP3_MULTIPLEXING_UNEXPECTED_FINITE_PHASE\n">>),
            erlang:halt(43)
    end.

normalize_status(0) -> 0;
normalize_status(42) -> 42;
normalize_status(_) -> 43.

marker(0) -> <<"HTTP3_MULTIPLEXING_READY_COMPLETED_3">>;
marker(42) -> <<"HTTP3_MULTIPLEXING_EXPECTED_RED_UNAVAILABLE_3">>;
marker(_) -> <<"HTTP3_MULTIPLEXING_UNEXPECTED_FINITE_PHASE">>.

receipt_term(Nonce, SourceSha, RunnerSourceSha, InvocationSha, Status,
             Completed, Counters, Attestation) ->
    {http3_multiplexing_receipt_v2,
     Nonce, SourceSha, RunnerSourceSha, InvocationSha,
     Status, Completed, marker(Status),
     counters_term(Counters), attestation_term(Attestation)}.

counters_term(Counters) ->
    Fixture = maps:get(fixture_roles, Counters),
    Lifecycle = maps:get(lifecycle_baseline, Counters),
    Resource = maps:get(resource_census, Counters),
    {http3_multiplexing_counters_v1,
     maps:get(schema, Counters), maps:get(repetitions, Counters),
     maps:get(multiplexed, Counters), maps:get(unavailable, Counters),
     maps:get(unexpected, Counters),
     {http3_multiplexing_fixture_roles_v1,
      maps:get(baseline, Fixture), maps:get(final, Fixture)},
     {http3_multiplexing_lifecycle_census_v1,
      maps:get(registered, Lifecycle), maps:get(pooled, Lifecycle),
      maps:get(caller_owned, Lifecycle), maps:get(monitored, Lifecycle),
      maps:get(pending, Lifecycle), maps:get(verified_cases, Lifecycle)},
     {http3_multiplexing_resource_census_v1,
      maps:get(workers_baseline, Resource),
      maps:get(memory_baseline, Resource),
      maps:get(workers_final, Resource), maps:get(memory_final, Resource),
      maps:get(verified_cases, Resource)}}.

attestation_term(Attestation) ->
    {http3_multiplexing_beam_identity_v1,
     maps:get(runner_sha256, Attestation),
     maps:get(expected_inventory_sha256, Attestation),
     maps:get(loaded_beam_sha256, Attestation),
     maps:get(loaded_beam_count, Attestation),
     maps:get(loaded_beams_verified, Attestation)}.

counters(Multiplexed, Unavailable, Unexpected, BaselineRoles, FinalRoles,
         CensusVerified) ->
    #{schema => 1, repetitions => 3, multiplexed => Multiplexed,
      unavailable => Unavailable, unexpected => Unexpected,
      fixture_roles => #{baseline => BaselineRoles, final => FinalRoles},
      lifecycle_baseline => #{registered => 0, pooled => 0,
          caller_owned => 0, monitored => 0, pending => 0,
          verified_cases => CensusVerified},
      resource_census => #{workers_baseline => 0, memory_baseline => 0,
          workers_final => 0, memory_final => 0,
          verified_cases => CensusVerified}}.

counters_valid(Status, Counters) ->
    try
        [fixture_roles, lifecycle_baseline, multiplexed, repetitions,
         resource_census, schema, unavailable, unexpected] =
            lists:sort(maps:keys(Counters)),
        1 = maps:get(schema, Counters),
        3 = maps:get(repetitions, Counters),
        Values = [maps:get(multiplexed, Counters),
                  maps:get(unavailable, Counters),
                  maps:get(unexpected, Counters)],
        true = lists:all(fun(Value) ->
            is_integer(Value) andalso Value >= 0 andalso Value =< 3
        end, Values),
        3 = lists:sum(Values),
        #{baseline := 0, final := 0} = maps:get(fixture_roles, Counters),
        Lifecycle = maps:get(lifecycle_baseline, Counters),
        #{registered := 0, pooled := 0, caller_owned := 0,
          monitored := 0, pending := 0, verified_cases := 3} = Lifecycle,
        Resource = maps:get(resource_census, Counters),
        #{workers_baseline := 0, memory_baseline := 0,
          workers_final := 0, memory_final := 0,
          verified_cases := 3} = Resource,
        true = case Status of
            0 -> Values =:= [3, 0, 0];
            42 -> Values =:= [0, 3, 0];
            _ -> false
        end,
        true
    catch _:_ -> false end.

runner_loaded(ExpectedSha) ->
    try
        {?MODULE, Bytes, ObjectFile} = code:get_object_code(?MODULE),
        true = is_binary(Bytes) andalso byte_size(Bytes) > 0
            andalso byte_size(Bytes) =< 4194304,
        Bytes = execution_beam_read(ObjectFile, 4194304),
        ExpectedSha = binary:encode_hex(
            crypto:hash(sha256, Bytes), lowercase),
        {ok, {?MODULE, Md5}} = beam_lib:md5(Bytes),
        Md5 = ?MODULE:module_info(md5),
        true
    catch _:_ -> false end.
