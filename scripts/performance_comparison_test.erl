%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_comparison_test).
-include_lib("eunit/include/eunit.hrl").

observed_identical_host_conditions_match_test()->
    ?assert(performance_comparison:validate_host(host())),
    ?assertEqual(ok,performance_comparison:compare_hosts(host(),host())).

every_static_condition_mismatch_blocks_test()->
    Changes=[{kernel_sha256,digest(2)},{cpu_model_sha256,digest(2)},
        {governor_sha256,digest(2)},{affinity_cpus,[0,1]},{cpuset_cpus,[0,1]},
        {schedulers_online,2},{dirty_cpu_schedulers_online,2},
        {cpu_quota_us,200000},{cpu_period_us,200000},
        {memory_limit_bytes,2147483648},{memory_swap_limit_bytes,1048576},
        {pids_limit,2048}],
    lists:foreach(fun({Key,Value})->
        ?assertMatch({error,_},performance_comparison:compare_hosts(host(),(host())#{Key:=Value}))
    end,Changes).

missing_declared_and_extra_host_values_are_not_observations_test()->
    ?assertNot(performance_comparison:validate_host(maps:remove(cpu_model_sha256,host()))),
    ?assertNot(performance_comparison:validate_host((host())#{cpu_model_sha256:=null})),
    ?assertNot(performance_comparison:validate_host((host())#{provenance:= <<"declared">>})),
    ?assertNot(performance_comparison:validate_host((host())#{private_extra=><<"private">>})),
    ?assertNot(performance_comparison:validate_host((host())#{affinity_cpus:=[0,0,1,2]})).

matching_numbers_without_execution_cannot_qualify_test()->
    Report=performance_comparison:pair_preflight(spec(),side(current),side(reference)),
    ?assertEqual(<<"Blocked">>,maps:get(status,Report)),
    ?assertEqual(true,maps:get(conditions_match,Report)),
    ?assert(lists:member(<<"unbound_execution_receipts">>,maps:get(violations,Report))),
    ?assert(lists:member(<<"unobserved_container_image">>,maps:get(violations,Report))).

paired_order_nonce_and_start_end_conditions_must_match_test()->
    S=spec(),A=side(current),B=side(reference),
    Bad=[B#{pair_nonce:=nonce(9)},B#{run_nonce:=maps:get(run_nonce,A)},
        B#{position:=1},B#{host_end:=(host())#{schedulers_online:=2}}],
    lists:foreach(fun(Other)->
        ?assertEqual(false,maps:get(conditions_match,performance_comparison:pair_preflight(S,A,Other)))
    end,Bad),
    Reverse=S#{current_position:=2},
    ?assertEqual(true,maps:get(conditions_match,performance_comparison:pair_preflight(
        Reverse,A#{position:=2},B#{position:=1}))),
    ?assertEqual(false,maps:get(conditions_match,performance_comparison:pair_preflight(S,
        A#{host_start:=(host())#{schedulers_online:=2}},B))).

role_protocol_workload_counterparty_and_source_must_bind_test()->
    Changes=[{role,<<"server">>},{protocol,2},{workload_sha256,digest(4)},
        {counterparty_sha256,digest(4)},{candidate_source_sha256,digest(4)},
        {kind,<<"historical_csv">>}],
    lists:foreach(fun({Key,Value})->
        Report=performance_comparison:pair_preflight(spec(),side(current),(side(reference))#{Key:=Value}),
        ?assertEqual(false,maps:get(conditions_match,Report)),
        ?assertEqual(<<"Blocked">>,maps:get(status,Report))
    end,Changes).

baseline_is_explicit_distinct_and_never_auto_selected_test()->
    Baseline=(side(reference))#{kind:= <<"baseline">>,source_sha256:=digest(2)},
    Spec=(spec())#{comparison:= <<"baseline">>,other_source_sha256:=digest(2)},
    ?assertEqual(true,maps:get(conditions_match,performance_comparison:pair_preflight(Spec,side(current),Baseline))),
    Same=Baseline#{source_sha256:=digest(1)},
    ?assertEqual(false,maps:get(conditions_match,performance_comparison:pair_preflight(Spec,side(current),Same))),
    ?assertEqual(false,maps:get(conditions_match,performance_comparison:pair_preflight(maps:remove(other_source_sha256,Spec),side(current),Baseline))).

host()->#{schema=>1,provenance=><<"runtime_probe">>,platform=><<"linux-cgroup-v2">>,
    kernel_sha256=>digest(1),cpu_model_sha256=>digest(1),governor_sha256=>digest(1),
    affinity_cpus=>[0,1,2,3],cpuset_cpus=>[0,1,2,3],
    schedulers_online=>4,dirty_cpu_schedulers_online=>4,
    cpu_quota_us=>400000,cpu_period_us=>100000,memory_limit_bytes=>4294967296,
    memory_swap_limit_bytes=>0,pids_limit=>1024}.
spec()->#{schema=>1,comparison=><<"reference">>,protocol=>3,role=><<"client">>,
    pair_nonce=>nonce(3),current_position=>1,
    workload_sha256=>digest(3),candidate_source_sha256=>digest(1),
    other_source_sha256=>digest(2),counterparty_sha256=>digest(3),
    image_digest=><<"sha256:",(digest(3))/binary>>}.
side(Kind)->#{schema=>1,kind=>atom_to_binary(Kind),protocol=>3,role=><<"client">>,
    pair_nonce=>nonce(3),run_nonce=>case Kind of current->nonce(1);reference->nonce(2) end,
    position=>case Kind of current->1;reference->2 end,
    workload_sha256=>digest(3),candidate_source_sha256=>digest(1),
    source_sha256=>case Kind of current->digest(1);reference->digest(2) end,
    counterparty_sha256=>digest(3),host_start=>host(),host_end=>host(),
    image_digest=><<"sha256:",(digest(3))/binary>>,image_provenance=><<"declared">>}.
digest(N)->binary:encode_hex(<<N:256>>,lowercase).
nonce(N)->binary:encode_hex(<<N:128>>,lowercase).
