%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
campaign_adversarial_self_test() ->
    Hash = binary:copy(<<"A">>, 64), Runtime = execution_runtime(),
    Identity = #{<<"schema">> => 2, <<"source_sha256">> => Hash, <<"files">> => 1},
    Catalog = #{source_sha256 => Hash, source_files => 1},
    Context = #{runner_sha256 => Hash,
                catalogs => #{<<"http">> => Catalog, <<"http3">> => Catalog, <<"core">> => Catalog}},
    lists:foreach(fun(Mode) ->
        lists:foreach(fun(Shards) ->
            lists:foreach(fun(Id) ->
                Good = campaign_test_report(Mode, Id, Shards, Identity, Runtime, Hash),
                ok = campaign_audit_report(Mode, Id, Shards, Good, Identity, Context),
                [First | Rest] = maps:get(<<"executions">>, Good),
                Child = maps:get(<<"child">>, First),
                WrongChild = Child#{<<"completed_cases">> => 0},
                WrongResult = First#{<<"child">> => WrongChild,
                    <<"child_sha256">> => generated_json_digest(WrongChild)},
                Bads = [Good#{<<"evidence_identity">> => #{}}, Good#{<<"status">> => <<"DiagnosticPassed">>},
                    Good#{<<"requested_cases">> => 100}, Good#{<<"seed">> => 0},
                    Good#{<<"completed_cases">> => 0}, Good#{<<"executions">> => Rest},
                    Good#{<<"executions">> => [WrongResult | Rest]},
                    Good#{<<"executions">> => [First#{<<"exit_status">> => 1} | Rest]},
                    Good#{<<"executions">> => [First#{<<"process">> =>
                        (maps:get(<<"process">>, First))#{<<"child_exit_observed">> => false}} | Rest]},
                    Good#{<<"execution_environment">> => Runtime#{<<"otp_version">> => <<"27.0">>}},
                    Good#{<<"build_identities">> => #{}}, Good#{<<"runner_sha256">> => <<>>},
                    Good#{<<"private">> => <<"private-marker">>}],
                lists:foreach(fun(Bad) -> campaign_reject(fun() ->
                    campaign_audit_report(Mode, Id, Shards, Bad, Identity, Context) end) end, Bads)
            end, lists:seq(0, Shards - 1))
        end, [1, 8]),
        Rows = [#{shard => Id, status => <<"Ready">>, report_sha256 => Hash,
                  replay_command => <<"fixture">>, nonces => [campaign_test_nonce(Id, 0)]} || Id <- lists:seq(0, 7)],
        Families = case Mode of "model" -> 1; _ -> 3 end,
        Summary = runtime_matrix_json(#{schema => 2, status => <<"Ready">>, campaign => list_to_binary(Mode),
            shards => 8, completed_shards => 8, generated_cases_per_family => 1000000,
            generated_cases => Families * 1000000, runs => Rows,
            evidence_identity => Identity, execution_environment => Runtime}),
        ok = campaign_audit_summary(Mode, Summary, Rows, Identity),
        campaign_reject(fun() -> campaign_audit_summary(Mode, Summary, tl(Rows), Identity) end),
        Replayed = [Row#{nonces := [<<"replayed">>]} || Row <- Rows],
        campaign_reject(fun() -> campaign_audit_summary(Mode, Summary#{<<"runs">> := runtime_matrix_json(Replayed)}, Replayed, Identity) end),
        campaign_reject(fun() -> campaign_audit_summary(Mode, Summary#{<<"private">> => <<"private-marker">>}, Rows, Identity) end)
    end, ["model", "property", "fuzz"]),
    io:put_chars("campaign evidence: exact family/shard/case, current source/build/runtime, child exit, replay and unknown-field adversarial checks passed\n").

campaign_test_report(Mode, Id, Shards, Identity, Runtime, Hash) ->
    Cases = case Shards of 1 -> 10000; 8 -> 125000 end, Seed = campaign_seed(Mode, Id),
    Requests = generated_requests(Mode, Seed, Cases),
    Executions = [campaign_test_execution(Request, Runtime, Hash, campaign_test_nonce(Id, Ordinal))
        || {Request, Ordinal} <- lists:zip(Requests, lists:seq(1, length(Requests)))],
    Targets = case Mode of "model" -> [core]; _ -> [http, http3, core] end,
    Tool = #{declared_version => <<"1.18.1">>, executable_sha256 => Hash},
    Builds = maps:from_list([{Target, #{schema => 3, package => atom_to_binary(Target),
        source_sha256 => Hash, source_files => 1, artifact_sha256 => Hash, artifact_files => 1,
        build_nonce => binary:copy(<<"1">>, 32),
        prebuild_profile_state => <<"absent">>,
        toolchain => #{runtime => Runtime, gleam => Tool, rebar3 => Tool#{declared_version := <<"3.27.0">>}}}}
        || Target <- Targets]),
    runtime_matrix_json(#{schema => 2, status => <<"Ready">>, mode => list_to_binary(Mode),
        shard => Id, shards => Shards, seed => Seed, requested_cases => Cases,
        scope => <<"qualification">>, shareable => true, evidence_identity => Identity,
        replay_command => generated_replay(Mode, Id, Shards, Seed, Cases, qualification),
        executions => Executions, build_identities => Builds, execution_environment => Runtime,
        runner_sha256 => Hash, configured_families => length(Requests), completed_cases => Cases * length(Requests)}).
campaign_test_nonce(Id, Ordinal) -> iolist_to_binary(io_lib:format("~32.16.0B", [1 + Id * 10 + Ordinal])).
campaign_test_execution(Request, Runtime, Hash, Nonce) ->
    Cases = maps:get(requested_cases, Request),
    Result = case maps:get(mode, Request) of
        <<"model">> -> #{final_sha256 => Hash, oracle_ack_checks => 200, ecn_oracle_events => 9,
            application_limited_checks => 1, hystart_oracle_rounds => 5, topology_oracle_modes => 2};
        Mode -> Retained = maps:get(retained_seeds, Request), Observed = Cases + Retained,
            #{observed_cases => Observed, final_sha256 => binary:encode_hex(crypto:hash(sha256,
                term_to_binary({Mode, maps:get(family, Request), maps:get(seed, Request), Cases, Retained, Observed})))}
    end,
    Child = runtime_matrix_json(Request#{schema => 1, nonce => Nonce, execution_environment => Runtime,
        status => <<"Passed">>, completed_cases => Cases, result => Result, failure => null}),
    #{request => Request, nonce => Nonce, deadline_ms => 600000, runner_sha256 => Hash, exit_status => 0,
      process => runtime_matrix_process_fixture(#{output_bytes => 0, output_hashed_bytes => 0, output_limit_bytes => 8388608,
          output_digest_complete => true, output_limit_exceeded => false, vm_process_heap_words => 33554432,
          vm_heap_includes_shared_binaries => true, crash_dumps_disabled => true, timed_out => false, child_exit_observed => true}),
      child => Child, child_sha256 => generated_json_digest(Child)}.
campaign_reject(Function) ->
    Rejected = try Function(), false catch _:_ -> true end,
    campaign_ensure(Rejected, invalid_campaign_evidence_accepted).
