%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(protocol_observer_controls).
-export([run/0, run_with_evidence/0]).
-compile(nowarn_unused_function).
-include("process_runner.hrl").
-include("suite_evidence.hrl").

%% Global-zero measurement controls need an owned VM. Other ordinary tests
%% may deliberately leave active fixtures in the parent VM; those must never
%% become an accepted measurement baseline or contaminate these controls.
run() ->
    case run_with_evidence() of
        {ok,Evidence} -> maps:get(passed,Evidence);
        {error,_} -> false
    end.

run_with_evidence() ->
    try
        Root=filename:absname("."),
        Nonce=hex(crypto:strong_rand_bytes(16)),
        Directory=filename:join([Root,"build","protocol-observer-controls",binary_to_list(Nonce)]),
        ChildPath=filename:join(Directory,"child.json"),
        DiagnosticPath=filename:join(Directory,"diagnostic.json"),
        ok=filelib:ensure_dir(ChildPath),
        {ok,qualification_eunit_listener,Beam,[]}=compile:file(
            filename:join(Root,"scripts/qualification_eunit_listener.erl"),
            [binary,return_errors,return_warnings,{i,filename:join(Root,"scripts")}]),
        ok=file:write_file(filename:join(Directory,"qualification_eunit_listener.beam"),Beam),
        Units=[#{module=><<"http_protocol_observer_test">>,function=><<"contracts">>,kind=><<"generator">>}],
        ControlCount=length(http_protocol_observer_test:contracts()),
        true=ControlCount>0 andalso ControlCount=<256,
        Eval=lists:flatten(io_lib:format(
            "ok=application:set_env(http,protocol_observer_diagnostic_path,~0tp),"
            "{module,http_protocol_observer_test}=code:ensure_loaded(http_protocol_observer_test),"
            "qualification_eunit_listener:run(~0tp,~0tp,~0tp).",
            [DiagnosticPath,Units,ChildPath,Nonce])),
        {Status,Output}=run_child_evaluation(Root,
            [Directory,filename:dirname(code:which(http_protocol_observer)),
             filename:dirname(code:which(http_protocol_observer_test))],Eval,30000),
        {ok,File}=file:open(ChildPath,[read,binary,raw]),
        Read=try file:read(File,8388609) after file:close(File) end,
        {ok,Bytes}=Read,
        true=byte_size(Bytes)=<8388608,
        RawChild=json:decode(Bytes),
        Child=suite_safe_child(RawChild,Units,Nonce),
        DiagnosticBytes=bounded_file(DiagnosticPath,65536),
        Diagnostic=json:decode(DiagnosticBytes),
        DiagnosticValid=diagnostic_valid(Diagnostic),
        CompletedValid=completed_child_valid(RawChild,Units,Nonce,ControlCount),
        ChildValidatorSelfTest=completed_validator_self_test(
            RawChild,Units,Nonce,ControlCount),
        DiagnosticValidatorSelfTest=diagnostic_validator_self_test(Diagnostic),
        TestPassed=CompletedValid andalso suite_child_valid(RawChild,Units,Nonce),
        ExpectedStatus=case TestPassed of true->0;false->1 end,
        InfrastructureValid=CompletedValid andalso ChildValidatorSelfTest
            andalso DiagnosticValidatorSelfTest andalso Status=:=ExpectedStatus
            andalso process_status_verified(Status,ExpectedStatus,Output)
            andalso maps:get(output_bytes,Output,-1)=:=0 andalso DiagnosticValid,
        Passed=InfrastructureValid andalso TestPassed,
        ExecutionPath=filename:join(Directory,"execution.json"),
        Evidence=#{schema=>1,passed=>Passed,infrastructure_valid=>InfrastructureValid,
              child_validator_self_test=>ChildValidatorSelfTest,
              diagnostic_validator_self_test=>DiagnosticValidatorSelfTest,
              completed_tests=>suite_completed_tests(Child),
              passed_tests=>child_count(Child,<<"passed">>),
              child=>Child,exit_status=>Status,
              diagnostic=>#{file=><<"diagnostic.json">>,valid=>DiagnosticValid,
                bytes=>byte_size(DiagnosticBytes),sha256=>hex(crypto:hash(sha256,DiagnosticBytes))},
              process=>maps:without([tail,output_sha256],Output)},
        ok=file:write_file(ExecutionPath,json:encode(Evidence),[exclusive]),
        case InfrastructureValid of
            true->{ok,Evidence#{execution_path=>ExecutionPath}};
            false->{error,invalid_control_execution}
        end
    catch _:_ -> {error,control_infrastructure_failed} end.

hex(Bytes)->string:lowercase(binary:encode_hex(Bytes)).

bounded_file(Path,Limit) ->
    {ok,Handle}=file:open(Path,[read,binary,raw]),
    try
        {ok,Bytes}=file:read(Handle,Limit+1),
        true=byte_size(Bytes)=<Limit,
        eof=file:read(Handle,1),
        Bytes
    after file:close(Handle) end.

diagnostic_valid(Value) ->
    try
        [<<"diagnostic_case">>,<<"report">>,<<"schema">>]=lists:sort(maps:keys(Value)),
        1=maps:get(<<"schema">>,Value),
        <<"actual_workload_cleanup_convergence">>=maps:get(<<"diagnostic_case">>,Value),
        true=http_protocol_observer:valid_report(maps:get(<<"report">>,Value)),
        true
    catch _:_ -> false end.

completed_child_valid(Child,Units,Nonce,ControlCount) ->
    try
        true=suite_child_schema_valid(Child,Units,Nonce),
        true=maps:get(<<"listener_completed">>,Child),
        true=maps:get(<<"eunit_completed">>,Child),
        0=maps:get(<<"unexpected_events">>,Child),
        ControlCount=suite_completed_tests(Child),
        Rows=maps:get(<<"units">>,Child),
        true=lists:all(fun completed_row_valid/1,Rows),
        maps:get(<<"failure_count">>,Child)=:=child_count(Child,<<"failed">>)
    catch _:_ -> false end.

completed_row_valid(Row) ->
    Counts=maps:get(<<"counts">>,Row),
    Started=maps:get(<<"started">>,Counts),
    Completed=maps:get(<<"completed">>,Counts),
    Started=:=Completed andalso Completed=:=
        maps:get(<<"passed">>,Counts)+maps:get(<<"failed">>,Counts)
        +maps:get(<<"skipped">>,Counts)+maps:get(<<"cancelled">>,Counts).

child_count(#{<<"units">>:=Rows},Key) ->
    lists:sum([maps:get(Key,maps:get(<<"counts">>,Row)) || Row<-Rows]);
child_count(_,_) -> 0.

completed_validator_self_test(Child,Units,Nonce,ControlCount) ->
    completed_child_valid(Child,Units,Nonce,ControlCount)
        andalso not completed_child_valid(
            maps:remove(<<"units">>,Child),Units,Nonce,ControlCount)
        andalso not completed_child_valid(
            Child#{<<"run_nonce">>:=<<"stale">>},Units,Nonce,ControlCount)
        andalso not completed_child_valid(
            Child#{<<"listener_completed">>:=false},Units,Nonce,ControlCount)
        andalso not completed_child_valid(
            forge_completed_count(Child),Units,Nonce,ControlCount)
        andalso not completed_child_valid(
            Child#{<<"failure_count">>:=maps:get(<<"failure_count">>,Child)+1},
            Units,Nonce,ControlCount).

forge_completed_count(Child=#{<<"units">>:=[Row|Rest]}) ->
    Counts=maps:get(<<"counts">>,Row),
    Completed=maps:get(<<"completed">>,Counts),
    Child#{<<"units">>:=[Row#{<<"counts">>:=
        Counts#{<<"completed">>:=max(0,Completed-1)}}|Rest]}.

diagnostic_validator_self_test(Diagnostic) ->
    diagnostic_valid(Diagnostic)
        andalso not diagnostic_valid(maps:remove(<<"report">>,Diagnostic))
        andalso not diagnostic_valid(Diagnostic#{<<"unknown">>=>0})
        andalso not diagnostic_valid(
            Diagnostic#{<<"diagnostic_case">>:=<<"forged">>}).
