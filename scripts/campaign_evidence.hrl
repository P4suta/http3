%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("campaign_child_evidence.hrl").
-include("artifact_merge_evidence.hrl").

campaign_context() ->
    #{runner_sha256 => generated_runner_digest(generated_compile_runner()),
      catalogs => maps:from_list([{list_to_binary(Target),
        begin Sources = fresh_source_paths(fresh_packages(Target)),
            #{source_sha256 => fresh_digest(Sources), source_files => length(Sources)} end}
        || Target <- ["http", "http3", "core"]])}.

campaign_verify_aggregate(Mode, Report) ->
    Identity = evidence_identity(), Context = campaign_context(),
    Rows = [campaign_read_row(Mode, Id, Identity, Context) || Id <- lists:seq(0, 7)],
    campaign_audit_summary(Mode, Report, Rows, Identity).

campaign_audit_summary(Mode, Report, Rows, Identity) ->
    campaign_ensure(length(Rows) =:= 8 andalso
        lists:all(fun(Row) -> maps:get(status, Row) =:= <<"Ready">> end, Rows), incomplete_campaign_evidence),
    campaign_ensure([maps:get(shard, Row) || Row <- Rows] =:= lists:seq(0, 7), missing_or_duplicate_campaign_shard),
    Nonces = lists:append([maps:get(nonces, Row) || Row <- Rows]),
    campaign_ensure(length(Nonces) =:= length(lists:usort(Nonces)), replayed_campaign_nonce),
    Families = case Mode of "model" -> 1; _ -> 3 end,
    Runtime = maps:get(<<"execution_environment">>, Report),
    campaign_ensure(campaign_runtime_valid(Runtime), invalid_aggregate_runtime),
    Expected = #{schema => 2, status => <<"Ready">>, campaign => list_to_binary(Mode),
        shards => 8, completed_shards => 8, generated_cases_per_family => 1000000,
        generated_cases => 1000000 * Families, runs => Rows,
        execution_environment => Runtime, evidence_identity => Identity},
    campaign_ensure(Report =:= runtime_matrix_json(Expected), stale_or_incomplete_campaign_aggregate).

campaign_read_row(Mode, Id, Identity, Context) ->
    Path = campaign_row_path(Mode, Id),
    Replay = generated_replay(Mode, Id, 8, 0, 125000, qualification),
    try
        Report = evidence_json_decode(runtime_matrix_read(Path, 1048576)),
        campaign_audit_report(Mode, Id, 8, Report, Identity, Context),
        #{shard => Id, status => <<"Ready">>, replay_command => Replay,
          report_sha256 => generated_json_digest(Report),
          nonces => [maps:get(<<"nonce">>, E) || E <- maps:get(<<"executions">>, Report)]}
    catch
        error:{badmatch, {error, enoent}} ->
            #{shard => Id, status => <<"Blocked">>, failure => <<"missing_shard">>, replay_command => Replay};
        error:stale_or_missing_evidence_identity ->
            #{shard => Id, status => <<"Blocked">>, failure => <<"stale_source">>, replay_command => Replay};
        _:_ -> #{shard => Id, status => <<"Blocked">>, failure => <<"invalid_or_incomplete_shard">>, replay_command => Replay}
    end.

campaign_row_path("model", Id) -> filename:join("build/model", "shard-" ++ integer_to_list(Id) ++ ".json");
campaign_row_path(Mode, Id) -> filename:join(["build/campaign", Mode, "shard-" ++ integer_to_list(Id) ++ ".json"]).

campaign_audit_report(Mode, Id, Shards, Report, Identity, Context) ->
    evidence_require_identity(Report, Identity),
    campaign_ensure(suite_exact_keys(Report, [schema, status, mode, shard, shards, seed,
        requested_cases, scope, shareable, evidence_identity, replay_command, executions,
        build_identities, execution_environment, runner_sha256, configured_families, completed_cases]), invalid_campaign_schema),
    2 = maps:get(<<"schema">>, Report), <<"Ready">> = maps:get(<<"status">>, Report),
    <<"qualification">> = maps:get(<<"scope">>, Report), true = maps:get(<<"shareable">>, Report),
    ModeText = list_to_binary(Mode), ModeText = maps:get(<<"mode">>, Report),
    Id = maps:get(<<"shard">>, Report), Shards = maps:get(<<"shards">>, Report),
    true = lists:member(Shards, [1, 8]), true = Id >= 0 andalso Id < Shards,
    Cases = case Shards of 1 -> 10000; 8 -> 125000 end,
    Cases = maps:get(<<"requested_cases">>, Report),
    Seed = campaign_seed(Mode, Id), Seed = maps:get(<<"seed">>, Report),
    Replay = generated_replay(Mode, Id, Shards, Seed, Cases, qualification),
    Replay = maps:get(<<"replay_command">>, Report),
    Runtime = maps:get(<<"execution_environment">>, Report), true = campaign_runtime_valid(Runtime),
    Digest = maps:get(runner_sha256, Context), Digest = maps:get(<<"runner_sha256">>, Report),
    Requests = [runtime_matrix_json(Request) || Request <- generated_requests(Mode, Seed, Cases)],
    Runs = maps:get(<<"executions">>, Report),
    true = is_list(Runs) andalso length(Runs) =:= length(Requests),
    true = length(Runs) =:= maps:get(<<"configured_families">>, Report),
    true = Cases * length(Runs) =:= maps:get(<<"completed_cases">>, Report),
    true = lists:all(fun({Run, Request}) -> generated_execution_valid(Run, Request, Runtime, Digest) end,
                     lists:zip(Runs, Requests)),
    Nonces = [maps:get(<<"nonce">>, Run) || Run <- Runs],
    true = length(Nonces) =:= length(lists:usort(Nonces)),
    Targets = case Mode of "model" -> [core]; _ -> [http, http3, core] end,
    Builds = maps:get(<<"build_identities">>, Report), true = suite_exact_keys(Builds, Targets),
    true = lists:all(fun(TargetAtom) -> Target = atom_to_binary(TargetAtom),
        runtime_matrix_build_valid(maps:get(Target, Builds), Target,
            maps:get(Target, maps:get(catalogs, Context)), Runtime)
    end, Targets), ok.

campaign_seed("model", Id) -> 982451653 + Id * 104729;
campaign_seed(Mode, Id) ->
    Base = case Mode of "property" -> 982451653; "fuzz" -> 1597463007 end,
    1 + (Base + Id * 104729) rem 2147483646.
campaign_runtime_valid(Runtime) ->
    try
        Os = case maps:get(<<"os_name">>, Runtime) of
            <<"linux">> -> <<"ubuntu-24.04">>; <<"darwin">> -> <<"macos-15">>; <<"nt">> -> <<"windows-2025">>
        end,
        [Major | _] = binary:split(maps:get(<<"otp_version">>, Runtime), <<".">>, [global]),
        true = lists:member(Major, [<<"28">>, <<"29">>]),
        runtime_matrix_environment_valid(Runtime, #{os => Os, otp => binary_to_integer(Major)})
    catch _:_ -> false end.
campaign_ensure(true, _) -> ok;
campaign_ensure(false, Reason) -> erlang:error(Reason).
