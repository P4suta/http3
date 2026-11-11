#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("process_runner.hrl").
-include("suite_evidence.hrl").

main([])->
    try
        {DataPassed,DataCount}=controls(),
        {TlsPassed,TlsCount}=tls_controls(),
        Passed=DataPassed andalso TlsPassed,
        io:format("protocol performance controls: ~p data and ~p TLS cases, passed=~p~n",
            [DataCount,TlsCount,Passed]),
        halt(case Passed of true->0;false->1 end)
    catch _:_ ->io:format(standard_error,"protocol performance controls failed before validated completion~n",[]),halt(1)
    end;
main(_)->halt(2).

controls()->
    Root=filename:absname("."),Nonce=hex(crypto:strong_rand_bytes(16)),
    Directory=filename:join([Root,"build","protocol-performance-controls",binary_to_list(Nonce)]),
    ChildPath=filename:join(Directory,"child.json"),ok=filelib:ensure_dir(ChildPath),
    %% Verify the production module exposes no test callback injection.
    {ok,protocol_performance_child,Production,[]}=compile:file("scripts/protocol_performance_child.erl",
        [binary,return_errors,return_warnings,{i,"scripts"}]),
    {ok,{protocol_performance_child,[{exports,Exports}]}}=beam_lib:chunks(Production,[exports]),
    false=lists:keymember(collect_with,1,Exports),false=lists:keymember(prime_dns,1,Exports),
    lists:foreach(fun({Source,Extra})->
        {ok,Module,Beam,[]}=compile:file(Source,[binary,return_errors,return_warnings,{i,"scripts"}|Extra]),
        ok=file:write_file(filename:join(Directory,atom_to_list(Module)++".beam"),Beam),
        case Module of
            protocol_performance_data_test->{module,Module}=code:load_binary(Module,Source,Beam);
            _->ok
        end
    end,[{"scripts/protocol_performance_child.erl",[{d,'TEST'}]},
        {"scripts/protocol_performance_data_test.erl",[]},
        {"test/http_protocol_observer.erl",[]},
        {"scripts/qualification_eunit_listener.erl",[]}]),
    Count=length(protocol_performance_data_test:contracts()),true=Count>0 andalso Count=<256,
    Units=[#{module=><<"protocol_performance_data_test">>,function=><<"contracts">>,kind=><<"generator">>}],
    execute_controls(Root,Directory,ChildPath,Nonce,Units,Count).

tls_controls()->
    Root=filename:absname("."),Nonce=hex(crypto:strong_rand_bytes(16)),
    Directory=filename:join([Root,"build","protocol-tls-controls",binary_to_list(Nonce)]),
    ChildPath=filename:join(Directory,"child.json"),ok=filelib:ensure_dir(ChildPath),
    {ok,protocol_tls_prime,Production,[]}=compile:file("scripts/protocol_tls_prime.erl",
        [binary,return_errors,return_warnings]),
    {ok,{protocol_tls_prime,[{exports,ProductionExports}]}}=beam_lib:chunks(Production,[exports]),
    false=lists:keymember(run_for_test,1,ProductionExports),
    Compiled=[begin
        {ok,Module,Beam,[]}=compile:file(Source,[binary,return_errors,return_warnings,{i,"scripts"}|Extra]),
        ok=file:write_file(filename:join(Directory,atom_to_list(Module)++".beam"),Beam),
        {Module,Beam}
    end||{Source,Extra}<-[{"scripts/protocol_tls_prime.erl",[{d,'TEST'}]},
        {"scripts/protocol_tls_prime_test.erl",[]},{"scripts/qualification_eunit_listener.erl",[]}]],
    {ok,{protocol_tls_prime_test,[{exports,Exports}]}}=
        beam_lib:chunks(proplists:get_value(protocol_tls_prime_test,Compiled),[exports]),
    Names=lists:sort([Name||{Name,0}<-Exports,lists:suffix("_test",atom_to_list(Name))]),
    %% This control must precede every other TLS exchange in its own VM: an
    %% earlier test must not prime the very service whose initialization it proves.
    First=prime_prevents_a_later_tls_upgrade_adding_an_otp_service_test,
    true=lists:member(First,Names),Count=length(Names),true=Count>=6 andalso Count=<32,
    Units=[#{module=><<"protocol_tls_prime_test">>,function=>atom_to_binary(Name),kind=><<"test">>}
        || Name<-[First|lists:delete(First,Names)]],
    execute_controls(Root,Directory,ChildPath,Nonce,Units,Count).

execute_controls(Root,Directory,ChildPath,Nonce,Units,Count)->
    Evaluation=lists:flatten(io_lib:format("qualification_eunit_listener:run(~0tp,~0tp,~0tp).",[Units,ChildPath,Nonce])),
    {Status,Output}=run_child_evaluation(Root,[Directory],Evaluation,60000),
    {ok,File}=file:open(ChildPath,[read,binary,raw]),
    Read=try file:read(File,8388609) after file:close(File) end,{ok,Bytes}=Read,
    true=byte_size(Bytes)=<8388608,
    Child=suite_safe_child(json:decode(Bytes),Units,Nonce),
    Passed=process_status_verified(Status,0,Output) andalso
        suite_child_valid(Child,Units,Nonce)
        andalso suite_completed_tests(Child)=:=Count andalso maps:get(<<"failure_count">>,Child)=:=0
        andalso maps:get(output_bytes,Output,-1)=:=0,
    ok=file:write_file(filename:join(Directory,"execution.json"),json:encode(
        #{schema=>1,passed=>Passed,configured_tests=>Count,child=>Child,exit_status=>Status,
          process=>maps:without([tail,output_sha256],Output)})),
    {Passed,Count}.

hex(Bytes)->binary:encode_hex(Bytes).
