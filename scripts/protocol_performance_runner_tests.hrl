%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
ppr_self_test() ->
    Compiled=ppr_compile(),ok=ppr_load_observer(Compiled),
    {Empty,EmptyCode}=ppr_fixture(Compiled,"halt(0)",30000),
    0=maps:get(exit_status,Empty),false=ppr_execution_valid(runtime_matrix_json(Empty),1),
    ppr_schema_self_test(Compiled,Empty),
    Retained=runtime_matrix_json(Empty),
    retained_execution_self_test(fun()->ppr_retained_valid(Retained,EmptyCode) end,
        ppr_execution_paths(Retained,EmptyCode)),
    false=ppr_retained_valid(Retained,Compiled),
    {Private,_}=ppr_fixture(Compiled,"erlang:error({badmatch,<<\"private-protocol-marker\">>})",30000),
    1=maps:get(exit_status,Private),
    {Forged,_}=ppr_fixture(Compiled,
        "ok=file:write_file(Path,json:encode(#{schema=>1,status=><<\"Ready\">>,nonce=>Nonce,"
        "private=><<\"private-protocol-marker\">>})),halt(0)",30000),
    0=maps:get(exit_status,Forged),
    {Stalled,_}=ppr_fixture(Compiled,"receive never->ok end",30000),
    124=maps:get(exit_status,Stalled),true=maps:get(timed_out,maps:get(process,Stalled)),
    {Flood,_}=ppr_fixture(Compiled,
        "lists:foreach(fun(_)->io:put_chars(binary:copy(<<\"private-protocol-marker\">>,65536)) end,"
        "lists:seq(1,64)),halt(0)",30000),
    125=maps:get(exit_status,Flood),true=maps:get(output_limit_exceeded,maps:get(process,Flood)),
    lists:foreach(fun(Execution)->
        true=maps:get(child_exit_observed,maps:get(process,Execution)),
        false=ppr_execution_valid(runtime_matrix_json(Execution),1),
        true=binary:match(iolist_to_binary(json:encode(Execution)),<<"private-protocol-marker">>)=:=nomatch
    end,[Empty,Private,Forged,Stalled,Flood]),
    io:put_chars("protocol runner: no-work, private failure, forged report, stall, flood and retained-code substitution rejected; every VM joined\n").

ppr_fixture(Compiled,Body,Deadline) ->
    Directory=filename:absname("build/diagnostics/protocol-runner/"++
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16)))),
    Source=filename:join(Directory,"protocol_performance_child.erl"),ok=filelib:ensure_dir(Source),
    Checkpoint=filename:join(Directory,"entered"),
    Prefix=io_lib:format("ok=file:write_file(~0tp,<<1>>,[exclusive]),",[Checkpoint]),
    ok=file:write_file(Source,["-module(protocol_performance_child).\n"
        "-compile(nowarn_unused_vars).\n-export([run/3]).\nrun(Path,Nonce,Protocol)->",Prefix,Body,".\n"]),
    {ok,protocol_performance_child,Bytes,[]}=compile:file(Source,[binary,return_errors,return_warnings]),
    FixtureCode=[case Module of protocol_performance_child->{Module,Bytes};_->{Module,Code} end
        || {Module,Code}<-Compiled],
    Execution=ppr_run_child(1,FixtureCode,Deadline),
    %% Prove the requested fault actually ran. Bootstrap slowness alone cannot
    %% count as a successful deadline/flood regression control.
    <<1>>=runtime_matrix_read(Checkpoint,1),
    {Execution,FixtureCode}.

%% Shape controls use explicitly synthetic workload values and real bounded
%% observer records. They never write a qualification report. Separate actual
%% child-directory tests above enforce that these values cannot supply proof.
ppr_schema_self_test(Compiled,Empty) ->
    {ok,protocol_performance_data_test,Bytes,[]}=
        compile:file("scripts/protocol_performance_data_test.erl",
            [binary,export_all,nowarn_export_all,return_errors,return_warnings,{i,"scripts"}]),
    {module,protocol_performance_data_test}=code:load_binary(protocol_performance_data_test,"schema-controls",Bytes),
    Executions=[begin
        Nonce=binary:copy(integer_to_binary(Protocol),32),
        Child=(protocol_performance_data_test:fixture_child(Protocol))#{nonce:=Nonce},
        Empty#{protocol:=Protocol,nonce:=Nonce,deadline_ms:=ppr_deadline(),elapsed_ms:=1000,child:=Child}
    end || Protocol<-[1,2,3]],
    Identity=#{<<"schema">>=>2,<<"files">>=>1,<<"source_sha256">>=>binary:copy(<<"A">>,64)},
    Build=#{<<"toolchain">>=>#{<<"runtime">>=>execution_runtime()}},
    Report=runtime_matrix_json(#{schema=>1,status=><<"Ready">>,shareable=>true,scope=>ppr_scope(),
        configuration=>pp_profile(),configured_protocols=>[1,2,3],completed_protocols=>3,
        executions=>Executions,summary=>pp_summary([maps:get(child,E)||E<-Executions]),
        build_identity=>Build,runner_sha256=>ppr_digest(Compiled),replay_command=>ppr_replay(),
        evidence_identity=>Identity,execution_environment=>execution_runtime()}),
    true=ppr_report_valid(Report,Identity,Build,Compiled),
    [First,Second,Third]=maps:get(<<"executions">>,Report),
    Summary=maps:get(<<"summary">>,Report),[FirstSummary|RestSummary]=Summary,
    Changed=maps:get(<<"requests_per_second">>,FirstSummary)+1,
    BadReports=[Report#{<<"private">>=><<"private-protocol-marker">>},
        Report#{<<"evidence_identity">>:=#{}},Report#{<<"build_identity">>:=#{}},
        Report#{<<"runner_sha256">>:=binary:copy(<<"B">>,64)},
        Report#{<<"configuration">>:=#{}},Report#{<<"scope">>:=<<"unverified">>},
        Report#{<<"completed_protocols">>:=0},Report#{<<"executions">>:=[First,Second]},
        Report#{<<"executions">>:=[Second,First,Third]},Report#{<<"executions">>:=[First,First,Third]},
        Report#{<<"executions">>:=[First#{<<"exit_status">>:=1},Second,Third]},
        Report#{<<"executions">>:=[First#{<<"deadline_ms">>:=ppr_deadline()+1},Second,Third]},
        Report#{<<"executions">>:=[First#{<<"elapsed_ms">>:=ppr_deadline()},Second,Third]},
        Report#{<<"executions">>:=[First#{<<"process">>:=#{}},Second,Third]},
        Report#{<<"summary">>:=[FirstSummary#{<<"requests_per_second">>:=Changed}|RestSummary]},
        Report#{<<"summary">>:=RestSummary},Report#{<<"replay_command">>:=<<"unverified">>}],
    lists:foreach(fun(Bad)->false=ppr_report_valid(Bad,Identity,Build,Compiled) end,BadReports),
    true=lists:all(fun(E)->not ppr_retained_valid(E,Compiled) end,maps:get(<<"executions">>,Report)),
    io:put_chars("protocol report: source/build/code, complete protocol set, deadlines, exit, summary and unknown-field controls passed\n").
