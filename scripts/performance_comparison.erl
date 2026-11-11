%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_comparison).
-export([validate_host/1,compare_hosts/2,pair_preflight/3]).

%% Structural compatibility is not proof that any endpoint was measured.
%% These functions cannot produce Ready. The controller must later bind its
%% actual image inspection and both owned measurement executions separately.
validate_host(Value)->
    try
        H=fields(Value,host_keys()),1=maps:get(schema,H),
        <<"runtime_probe">>=maps:get(provenance,H),
        <<"linux-cgroup-v2">>=maps:get(platform,H),
        true=lists:all(fun(K)->digest(maps:get(K,H)) end,
            [kernel_sha256,cpu_model_sha256,governor_sha256]),
        Affinity=maps:get(affinity_cpus,H),Cpuset=maps:get(cpuset_cpus,H),
        true=cpus(Affinity) andalso cpus(Cpuset),
        true=lists:all(fun(Cpu)->lists:member(Cpu,Cpuset) end,Affinity),
        true=number(maps:get(schedulers_online,H),1,length(Affinity)),
        true=number(maps:get(dirty_cpu_schedulers_online,H),1,4096),
        true=limit(maps:get(cpu_quota_us,H),1),
        true=number(maps:get(cpu_period_us,H),1,1000000000),
        true=lists:all(fun(K)->limit(maps:get(K,H),0) end,
            [memory_limit_bytes,memory_swap_limit_bytes,pids_limit]),true
    catch _:_ ->false end.

compare_hosts(Left,Right)->
    case validate_host(Left) andalso validate_host(Right) of
        false->{error,invalid_host_observation};
        true->
            A=fields(Left,host_keys()),B=fields(Right,host_keys()),
            Changed=[atom_to_binary(K)||K<-host_keys(),maps:get(K,A)=/=maps:get(K,B)],
            case Changed of []->ok;_->{error,{host_condition_mismatch,Changed}} end
    end.

pair_preflight(Specification,Current,Other)->
    Conditions=try
        S=fields(Specification,spec_keys()),true=valid_spec(S),
        A=fields(Current,side_keys()),B=fields(Other,side_keys()),
        true=valid_side(A) andalso valid_side(B),
        <<"current">>=maps:get(kind,A),
        true=maps:get(kind,B)=:=maps:get(comparison,S),
        true=maps:get(source_sha256,A)=:=maps:get(candidate_source_sha256,S),
        true=maps:get(source_sha256,B)=:=maps:get(other_source_sha256,S),
        true=maps:get(run_nonce,A)=/=maps:get(run_nonce,B),
        true=maps:get(position,A)=:=maps:get(current_position,S),
        true=maps:get(position,B)=:=3-maps:get(current_position,S),
        true=lists:all(fun(K)->maps:get(K,S)=:=maps:get(K,A)
            andalso maps:get(K,A)=:=maps:get(K,B) end,
            [pair_nonce,protocol,role,workload_sha256,candidate_source_sha256,counterparty_sha256,image_digest]),
        Host=maps:get(host_start,A),
        ok=compare_hosts(Host,maps:get(host_end,A)),
        ok=compare_hosts(Host,maps:get(host_start,B)),
        ok=compare_hosts(Host,maps:get(host_end,B)),true
    catch _:_ ->false end,
    Missing=[<<"unbound_execution_receipts">>,<<"unobserved_container_image">>],
    #{schema=>1,status=><<"Blocked">>,conditions_match=>Conditions,
        scope=><<"condition preflight only; no performance qualification">>,
        violations=>case Conditions of true->Missing;false->[<<"incompatible_pair_conditions">>|Missing] end}.

valid_spec(S)->
    maps:get(schema,S)=:=1 andalso lists:member(maps:get(comparison,S),[<<"reference">>,<<"baseline">>])
    andalso protocol_role(S) andalso all_digests(S,[workload_sha256,candidate_source_sha256,
        other_source_sha256,counterparty_sha256])
    andalso maps:get(candidate_source_sha256,S)=/=maps:get(other_source_sha256,S)
    andalso nonce(maps:get(pair_nonce,S)) andalso number(maps:get(current_position,S),1,2)
    andalso image_digest(maps:get(image_digest,S)).
valid_side(S)->
    maps:get(schema,S)=:=1 andalso lists:member(maps:get(kind,S),[<<"current">>,<<"reference">>,<<"baseline">>])
    andalso protocol_role(S) andalso all_digests(S,[workload_sha256,candidate_source_sha256,
        source_sha256,counterparty_sha256])
    andalso image_digest(maps:get(image_digest,S))
    andalso maps:get(image_provenance,S)=:=<<"declared">>
    andalso nonce(maps:get(pair_nonce,S)) andalso nonce(maps:get(run_nonce,S))
    andalso number(maps:get(position,S),1,2)
    andalso validate_host(maps:get(host_start,S)) andalso validate_host(maps:get(host_end,S)).
protocol_role(S)->number(maps:get(protocol,S),1,3)
    andalso lists:member(maps:get(role,S),[<<"client">>,<<"server">>]).
all_digests(S,Keys)->lists:all(fun(K)->digest(maps:get(K,S)) end,Keys).
host_keys()->[schema,provenance,platform,kernel_sha256,cpu_model_sha256,governor_sha256,
    affinity_cpus,cpuset_cpus,schedulers_online,dirty_cpu_schedulers_online,
    cpu_quota_us,cpu_period_us,memory_limit_bytes,memory_swap_limit_bytes,pids_limit].
spec_keys()->[schema,comparison,protocol,role,pair_nonce,current_position,workload_sha256,candidate_source_sha256,
    other_source_sha256,counterparty_sha256,image_digest].
side_keys()->[schema,kind,protocol,role,pair_nonce,run_nonce,position,workload_sha256,candidate_source_sha256,
    source_sha256,counterparty_sha256,host_start,host_end,image_digest,image_provenance].
fields(Value,Keys) when is_map(Value),map_size(Value)=:=length(Keys)->
    Sorted=lists:sort(Keys),
    case lists:sort(maps:keys(Value)) of
        Sorted->Value;
        _->Binaries=lists:sort([atom_to_binary(K)||K<-Keys]),
            Binaries=lists:sort(maps:keys(Value)),
            maps:from_list([{K,maps:get(atom_to_binary(K),Value)}||K<-Keys])
    end.
number(Value,Min,Max)->is_integer(Value) andalso Value>=Min andalso Value=<Max.
limit(<<"unlimited">>,_)->true;
limit(Value,Min)->number(Value,Min,9223372036854775807).
cpus(Cpus)->is_list(Cpus) andalso length(Cpus)>0 andalso length(Cpus)=<4096
    andalso Cpus=:=lists:usort(Cpus)
    andalso lists:all(fun(Cpu)->number(Cpu,0,1048575) end,Cpus).
digest(Bytes) when is_binary(Bytes),byte_size(Bytes)=:=64->
    lists:all(fun(C)->(C>=$0 andalso C=<$9) orelse (C>=$a andalso C=<$f) end,binary_to_list(Bytes));
digest(_)->false.
image_digest(<<"sha256:",Digest/binary>>)->digest(Digest);
image_digest(_)->false.
nonce(Bytes) when is_binary(Bytes),byte_size(Bytes)=:=32->
    lists:all(fun(C)->(C>=$0 andalso C=<$9) orelse (C>=$a andalso C=<$f) end,binary_to_list(Bytes));
nonce(_)->false.
