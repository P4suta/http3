#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("campaign_evidence.hrl").
-include("campaign_audit_tests.hrl").

main(["--self-test"]) -> self_test();
main(["--verify", Mode]) when Mode =:= "property"; Mode =:= "fuzz"; Mode =:= "model" ->
    Bytes = runtime_matrix_read(filename:join(["build", "campaign", "aggregates", Mode ++ ".json"]), 1048576),
    campaign_verify_aggregate(Mode, evidence_json_decode(Bytes));
main(["--artifact", Mode]) when Mode =:= "property"; Mode =:= "fuzz";
                                    Mode =:= "model" ->
    aggregate(Mode, artifact);
main([Mode]) when Mode =:= "property"; Mode =:= "fuzz"; Mode =:= "model" ->
    aggregate(Mode, local);
main(_) -> erlang:error(campaign_aggregate_usage).

aggregate(Mode, SourceMode) ->
    Path = filename:join(["build", "campaign", "aggregates", Mode ++ ".json"]),
    Identity = evidence_begin(Path),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(#{schema => 2, status => <<"Failed">>,
        campaign => list_to_binary(Mode), evidence_identity => Identity, completed_shards => 0}), $\n]),
    try aggregate_ready(Mode, Path, Identity, SourceMode)
    catch Class:Reason:Stack ->
        Previous = evidence_json_decode(runtime_matrix_read(Path, 1048576)),
        Failed = Previous#{<<"status">> => <<"Failed">>,
            <<"failure">> => diagnostic_failure_details(Class, Reason, Stack)},
        ok = file:write_file(Path, [json:encode(Failed), $\n]),
        io:put_chars(standard_error, "campaign aggregate failed; bounded failure evidence retained\n"), halt(1)
    end.

aggregate_ready(Mode, Path, Identity, SourceMode) ->
    case SourceMode of
        artifact -> _ = artifact_merge_verify_campaign(Mode, Identity);
        local -> ok
    end,
    Context = campaign_context(),
    Rows = [campaign_read_row(Mode, Id, Identity, Context) || Id <- lists:seq(0, 7)],
    Completed = [Row || Row <- Rows, maps:get(status, Row) =:= <<"Ready">>],
    Nonces = lists:append([maps:get(nonces, Row) || Row <- Completed]),
    Complete = length(Completed) =:= 8 andalso length(Nonces) =:= length(lists:usort(Nonces)),
    Status = case Complete of true -> <<"Ready">>; false -> <<"Blocked">> end,
    Families = case Mode of "model" -> 1; _ -> 3 end,
    Report = evidence_complete(#{schema => 2, status => Status,
        campaign => list_to_binary(Mode), shards => 8,
        completed_shards => length(Completed),
        generated_cases_per_family => length(Completed) * 125000,
        generated_cases => length(Completed) * 125000 * Families,
        runs => Rows}, Identity),
    case Status of <<"Ready">> -> campaign_audit_summary(Mode, runtime_matrix_json(Report), Rows, Identity); _ -> ok end,
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    io:format("~s campaign aggregate: ~B/8 complete shards~n",
              [Mode, length(Completed)]),
    case Status of <<"Ready">> -> ok; _ -> halt(1) end.

self_test() -> campaign_adversarial_self_test().
