%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PROTOCOL_PERFORMANCE_EXECUTION_HRL).
-define(HTTP_PROTOCOL_PERFORMANCE_EXECUTION_HRL,true).
-include("runtime_matrix_evidence.hrl").
-include("protocol_performance_data.hrl").

ppr_path() -> "build/performance/current/protocols.json".
ppr_deadline() -> 300000.
ppr_replay() -> <<"bash scripts/fresh_build.sh http && escript scripts/protocol_performance_runner.escript">>.
ppr_scope() -> <<"verified TLS public client/server; one VM per protocol; one warmup and five measured sequential trials; sampled VM peaks; endpoint cleanup and convergence">>.

ppr_check_profile() ->
    Profile=evidence_json_decode(runtime_matrix_read("standards/performance-profile.json",1048576)),
    Expected=runtime_matrix_json(pp_profile()),
    Expected=maps:get(<<"unified_protocol_workload">>,Profile),ok.

ppr_compile() ->
    [begin
        {ok,Module,Bytes,[]} = compile:file(Path,
            [binary,deterministic,return_errors,return_warnings,{i,"scripts"}]),
        {Module,Bytes}
    end || {Module,Path} <- [
        {protocol_performance_child,"scripts/protocol_performance_child.erl"},
        {protocol_tls_prime,"scripts/protocol_tls_prime.erl"},
        {http_protocol_observer,"test/http_protocol_observer.erl"}]].

ppr_digest(Compiled) -> binary:encode_hex(crypto:hash(sha256,
    [[atom_to_binary(Module),0,Bytes] || {Module,Bytes} <- Compiled])).

ppr_load_observer(Compiled) ->
    Bytes=proplists:get_value(http_protocol_observer,Compiled),
    {module,http_protocol_observer}=code:load_binary(http_protocol_observer,"verified-protocol-observer",Bytes),ok.

ppr_nonce(Nonce) -> is_binary(Nonce) andalso byte_size(Nonce)=:=32 andalso
    re:run(Nonce,<<"^[0-9A-F]{32}$">>,[{capture,none}])=:=match.

ppr_execution_paths(Execution,Compiled) ->
    Nonce=maps:get(<<"nonce">>,Execution),true=ppr_nonce(Nonce),
    Directory="build/performance/protocol-runner/"++binary_to_list(Nonce),
    [filename:join(Directory,"child.json")|
        [filename:join(Directory,atom_to_list(Module)++".beam") || {Module,_} <- Compiled]].

ppr_retained_valid(Execution,Compiled) ->
    try
        [ChildPath|Paths]=ppr_execution_paths(Execution,Compiled),
        true=lists:sort(filelib:wildcard(filename:join(filename:dirname(ChildPath),"*")))
            =:=lists:sort([ChildPath|Paths]),
        true=lists:all(fun({{_,Bytes},Path})->runtime_matrix_read(Path,16777216)=:=Bytes end,
            lists:zip(Compiled,Paths)),
        Child=evidence_json_decode(runtime_matrix_read(ChildPath,1048576)),
        Child=maps:get(<<"child">>,Execution),
        pp_child_valid(Child,maps:get(<<"protocol">>,Execution),maps:get(<<"nonce">>,Execution))
            orelse Child=:=#{<<"invalid_child_schema">>=>true}
    catch _:_ -> false end.

ppr_execution_valid(Execution,Protocol) ->
    try
        true=suite_exact_keys(Execution,[protocol,nonce,deadline_ms,elapsed_ms,exit_status,process,child]),
        Protocol=maps:get(<<"protocol">>,Execution),
        true=lists:member(Protocol,[1,2,3]),
        Nonce=maps:get(<<"nonce">>,Execution),true=ppr_nonce(Nonce),
        Deadline=ppr_deadline(),Deadline=maps:get(<<"deadline_ms">>,Execution),
        Elapsed=maps:get(<<"elapsed_ms">>,Execution),
        true=is_integer(Elapsed) andalso Elapsed>=0 andalso Elapsed<Deadline,
        0=maps:get(<<"exit_status">>,Execution),
        Process=maps:get(<<"process">>,Execution),true=runtime_matrix_process_valid(Process),
        %% The measurement child has no reason to write arbitrary output. Even
        %% bounded unexpected output prevents this artifact from qualifying.
        0=maps:get(<<"output_bytes">>,Process),
        Child=maps:get(<<"child">>,Execution),
        pp_child_valid(Child,Protocol,Nonce) andalso pp_child_passed(Child)
    catch _:_ -> false end.

ppr_report_valid(Report,Identity,Build,Compiled) ->
    try
        true=suite_exact_keys(Report,[schema,status,shareable,scope,configuration,
            configured_protocols,completed_protocols,executions,summary,build_identity,
            runner_sha256,replay_command,evidence_identity,execution_environment]),
        1=maps:get(<<"schema">>,Report),<<"Ready">>=maps:get(<<"status">>,Report),
        true=maps:get(<<"shareable">>,Report),
        Scope=ppr_scope(),Scope=maps:get(<<"scope">>,Report),
        Profile=runtime_matrix_json(pp_profile()),Profile=maps:get(<<"configuration">>,Report),
        [1,2,3]=maps:get(<<"configured_protocols">>,Report),
        3=maps:get(<<"completed_protocols">>,Report),
        Identity=maps:get(<<"evidence_identity">>,Report),Build=maps:get(<<"build_identity">>,Report),
        Digest=ppr_digest(Compiled),Digest=maps:get(<<"runner_sha256">>,Report),
        Replay=ppr_replay(),Replay=maps:get(<<"replay_command">>,Report),
        Runtime=maps:get(<<"runtime">>,maps:get(<<"toolchain">>,Build)),
        Runtime=maps:get(<<"execution_environment">>,Report),
        Executions=maps:get(<<"executions">>,Report),
        true=is_list(Executions) andalso length(Executions)=:=3,
        true=lists:all(fun({Protocol,Execution})->ppr_execution_valid(Execution,Protocol) end,
            lists:zip([1,2,3],Executions)),
        Nonces=[maps:get(<<"nonce">>,Execution) || Execution<-Executions],
        3=length(lists:usort(Nonces)),
        Summary=runtime_matrix_json(pp_summary([maps:get(<<"child">>,Execution)||Execution<-Executions])),
        true=is_list(Summary) andalso length(Summary)=:=3,
        [1,2,3]=[maps:get(<<"protocol">>,Entry)||Entry<-Summary],
        true=lists:all(fun(Entry)->maps:get(<<"status">>,Entry)=:=<<"Passed">> end,Summary),
        Summary=maps:get(<<"summary">>,Report),true
    catch _:_ -> false end.

ppr_verify() ->
    ok=ppr_check_profile(),
    Build=fresh_verified_report("http"),Compiled=ppr_compile(),ok=ppr_load_observer(Compiled),
    Report=evidence_json_decode(runtime_matrix_read(ppr_path(),4194304)),
    true=ppr_report_valid(Report,evidence_identity(),Build,Compiled),
    true=lists:all(fun(Execution)->ppr_retained_valid(Execution,Compiled) end,
        maps:get(<<"executions">>,Report)),
    Report.

ppr_bundle_paths() ->
    Report=ppr_verify(),Compiled=ppr_compile(),
    lists:append([ppr_execution_paths(Execution,Compiled)||Execution<-maps:get(<<"executions">>,Report)]).

ppr_export(Executions,Compiled,Path) ->
    Entries=lists:append([begin
        true=ppr_retained_valid(Execution,Compiled),
        [ChildPath|Paths]=ppr_execution_paths(Execution,Compiled),
        ChildBytes=runtime_matrix_read(ChildPath,1048576),
        Expected=maps:get(<<"child">>,Execution),Expected=evidence_json_decode(ChildBytes),
        BeamEntries=[begin
            Bytes=runtime_matrix_read(BeamPath,16777216),
            {lists:flatten(string:replace(BeamPath,"\\","/",all)),Bytes}
        end || {{_,Bytes},BeamPath}<-lists:zip(Compiled,Paths)],
        [{lists:flatten(string:replace(ChildPath,"\\","/",all)),ChildBytes}|BeamEntries]
    end || Execution<-Executions]),
    ok=erl_tar:create(Path,Entries,[]),{ok,Entries}=erl_tar:extract(Path,[memory]),ok.
-endif.
