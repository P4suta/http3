#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("diagnostic_failure.hrl").
-include_lib("kernel/include/file.hrl").

main([]) -> run();
main(["--self-test"]) -> run();
main(["--observer-source",Source,"--expect-pass"]) -> run_source(Source,true);
main(["--observer-source",Source,"--expect-failure"]) -> run_source(Source,false);
main(_) -> halt(2).

run() ->
    try
        Root=filename:absname("."),
        ok=load_paths(Root),
        {module,http_protocol_observer}=code:ensure_loaded(http_protocol_observer),
        {module,http_protocol_observer_test}=code:ensure_loaded(http_protocol_observer_test),
        {ok,Control}=run_controls(Root),
        true=maps:get(passed,Control),
        io:put_chars("protocol observer controls: passed with bounded convergence diagnostic\n")
    catch Class:Reason:Stack ->
        io:format(standard_error,"protocol observer controls failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class,Reason,Stack))]),
        halt(1)
    end.

run_source(Source,ExpectedPassed) ->
    try
        Root=filename:absname("."),
        ok=load_paths(Root),
        relative=filename:pathtype(Source),
        SafeSource=filelib:safe_relative_path(Source,Root),
        true=SafeSource=/=unsafe,
        Observer=filename:absname(SafeSource,Root),
        true=filelib:is_regular(Observer),
        {ok,Info}=file:read_file_info(Observer),
        true=Info#file_info.size>0 andalso Info#file_info.size=<1048576,
        Nonce=string:lowercase(binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16)))),
        Directory=filename:join([Root,"build","protocol-observer-mutations",Nonce]),
        ok=filelib:ensure_dir(filename:join(Directory,"placeholder")),
        ok=compile_to(Observer,Directory),
        Test=filename:join(Root,"test/http_protocol_observer_test.erl"),
        ok=compile_to(Test,Directory),
        true=code:add_patha(Directory),
        ok=load_abs(Directory,http_protocol_observer),
        ok=load_abs(Directory,http_protocol_observer_test),
        {ok,Control}=run_controls(Root),
        Passed=maps:get(passed,Control),
        Evidence=#{schema=>1,expected=>case ExpectedPassed of true-><<"pass">>;false-><<"failure">> end,
            observed_passed=>Passed,expectation_met=>Passed=:=ExpectedPassed,
            mutant_detected=>not ExpectedPassed andalso not Passed,
            observer_source_sha256=>hash_file(Observer),test_source_sha256=>hash_file(Test),
            controls_source_sha256=>hash_file(filename:join(Root,"scripts/protocol_observer_controls.erl")),
            runner_source_sha256=>hash_file(filename:join(Root,"scripts/protocol_observer_test.escript")),
            observer_beam_sha256=>hash_file(filename:join(Directory,"http_protocol_observer.beam")),
            test_beam_sha256=>hash_file(filename:join(Directory,"http_protocol_observer_test.beam")),
            observer_source=>relative_path_binary(SafeSource),
            control=>control_evidence(Root,Control),
            otp_release=>unicode:characters_to_binary(erlang:system_info(otp_release)),
            erts_version=>unicode:characters_to_binary(erlang:system_info(version))},
        ok=file:write_file(filename:join(Directory,"execution.json"),json:encode(Evidence),[exclusive]),
        true=Passed=:=ExpectedPassed,
        io:put_chars(case ExpectedPassed of
            true->"protocol observer controls: isolated current source passed\n";
            false->"protocol observer controls: prior-source mutant detected\n"
        end)
    catch Class:Reason:Stack ->
        io:format(standard_error,"protocol observer mutant failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class,Reason,Stack))]),
        halt(1)
    end.

load_paths(Root) ->
    Paths=filelib:wildcard(filename:join([Root,"build","dev","erlang","*","ebin"])),
    true=Paths=/=[],
    code:add_pathsa(Paths).

run_controls(Root) ->
    {ok,protocol_observer_controls,Beam,[]}=compile:file(
        filename:join(Root,"scripts/protocol_observer_controls.erl"),
        [binary,return_errors,return_warnings,{i,filename:join(Root,"scripts")}]),
    code:purge(protocol_observer_controls),code:delete(protocol_observer_controls),
    {module,protocol_observer_controls}=code:load_binary(protocol_observer_controls,
        "scripts/protocol_observer_controls.erl",Beam),
    protocol_observer_controls:run_with_evidence().

compile_to(Path,Directory) ->
    {ok,Module,Beam,[]}=compile:file(Path,[binary,return_errors,return_warnings]),
    ok=file:write_file(filename:join(Directory,atom_to_list(Module)++".beam"),Beam,[exclusive]).

load_abs(Directory,Module) ->
    code:purge(Module),code:delete(Module),
    {module,Module}=code:load_abs(filename:join(Directory,atom_to_list(Module))),ok.

hash_file(Path) ->
    {ok,Bytes}=file:read_file(Path),
    true=byte_size(Bytes)=<1048576,
    hex(crypto:hash(sha256,Bytes)).

hex(Bytes) -> string:lowercase(binary:encode_hex(Bytes)).

relative_path_binary(Path) ->
    binary:replace(unicode:characters_to_binary(Path,utf8),<<"\\">>,<<"/">>,[global]).

control_evidence(Root,Control) ->
    Artifact=maps:get(execution_path,Control),
    Nonce=filename:basename(filename:dirname(Artifact)),
    match=re:run(Nonce,"^[0-9a-f]{32}$",[{capture,none}]),
    Relative=filename:join(["build","protocol-observer-controls",Nonce,"execution.json"]),
    Artifact=filename:absname(Relative,Root),
    Child=maps:get(child,Control),
    #{execution_file=>relative_path_binary(Relative),
      execution_sha256=>hash_file(Artifact),
      diagnostic_sha256=>maps:get(sha256,maps:get(diagnostic,Control)),
      completed_tests=>maps:get(completed_tests,Control),
      passed_tests=>maps:get(passed_tests,Control),
      failure_count=>maps:get(<<"failure_count">>,Child),
      failure_classifications=>[maps:get(<<"classification">>,Failure)
        || Failure<-maps:get(<<"failures">>,Child)]}.
