#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("suite_evidence.hrl").
-include("evidence_identity.hrl").
-include("performance_comparison_evidence.hrl").
main(Args)->
    try dispatch(Args)
    catch Class:Reason:Stack->
        io:format("comparison evidence failed: ~s~n",[json:encode(diagnostic_failure_details(Class,Reason,Stack))]),halt(1)
    end.
dispatch(["--self-test"])->
    Modules=[performance_comparison,performance_comparison_test,performance_comparison_host,
        performance_comparison_host_test,performance_comparison_evidence_test,qualification_eunit_listener],
    Nonce=hex(crypto:strong_rand_bytes(16)),
    Directory=filename:absname("build/performance/comparison-tests/"++binary_to_list(Nonce)),
    Path=filename:join(Directory,"child.json"),ok=filelib:ensure_dir(Path),
    Compiled=[begin
        {ok,M,B,[]}=compile:file("scripts/"++atom_to_list(M)++".erl",
            [binary,deterministic,return_errors,return_warnings,{i,"scripts"}]),
        File=filename:join(Directory,atom_to_list(M)++".beam"),ok=file:write_file(File,B,[exclusive]),
        {M,B,File}
    end||M<-Modules],
    Names=[observed_identical_host_conditions_match_test,every_static_condition_mismatch_blocks_test,
        missing_declared_and_extra_host_values_are_not_observations_test,
        matching_numbers_without_execution_cannot_qualify_test,
        paired_order_nonce_and_start_end_conditions_must_match_test,
        role_protocol_workload_counterparty_and_source_must_bind_test,
        baseline_is_explicit_distinct_and_never_auto_selected_test],
    HostNames=[bounded_cpu_ranges_expand_exactly_test,
        cpu_model_is_observed_per_allowed_cpu_and_dynamic_frequency_is_ignored_test,
        limits_are_bounded_and_unlimited_is_explicit_test,
        image_input_is_content_addressed_but_never_observed_test,
        actual_capture_is_strict_and_missing_conditions_cannot_qualify_test,
        cgroup_namespace_must_identify_the_actual_visible_root_test],
    Units=[#{module=>atom_to_binary(M),function=>atom_to_binary(F),kind=><<"test">>}
        ||{M,Tests}<-[{performance_comparison_test,Names},{performance_comparison_host_test,HostNames},
            {performance_comparison_evidence_test,[receipt_requires_source_helper_runtime_nonce_exit_and_no_output_test,
                retained_child_and_beam_must_be_exact_selected_bytes_test]}],F<-Tests],
    Loads=[io_lib:format("(fun()->{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),{module,~p}=code:load_binary(~p,\"comparison-test\",B) end)(),",
        [File,crypto:hash(sha256,B),M,M])||{M,B,File}<-Compiled],
    Eval=lists:flatten([Loads,io_lib:format("qualification_eunit_listener:run(~0tp,~0tp,~0tp).",[Units,Path,Nonce])]),
    {Exit,Output}=run_child_evaluation(filename:absname("."),[Directory],Eval,30000),
    Child=evidence_json_decode(runtime_matrix_read(Path,1048576)),
    true=process_status_verified(Exit,0,Output),
    true=suite_child_schema_valid(Child,Units,Nonce),
    true=(Exit=:=0)=:=suite_child_valid(Child,Units,Nonce),
    ok=file:write_file(filename:join(Directory,"execution.json"),json:encode(#{schema=>1,
        exit_status=>Exit,nonce=>Nonce,child=>Child,process=>maps:without([tail,output_sha256],Output),
        beams=>[#{module=>atom_to_binary(M),sha256=>hex(crypto:hash(sha256,B))}||{M,B,_}<-Compiled]})),
    io:format("comparison controls: exit=~B completed=~B joined=true nonce=~s~n",[Exit,suite_completed_tests(Child),Nonce]),
    halt(Exit);
dispatch(["--capture"])->capture_host(null);
dispatch(["--capture",Image])->capture_host(list_to_binary(Image));
dispatch(["--verify"])->
    Identity=evidence_identity(),Compiled=pcmp_compile(),pcmp_load(Compiled),
    Report=evidence_json_decode(runtime_matrix_read("build/performance/comparison/current-host.json",1048576)),
    evidence_require_identity(Report,Identity),
    true=pcmp_receipt_valid(Report,Identity,Compiled,execution_runtime()),
    true=pcmp_retained_valid(Report,Compiled),
    Identity=evidence_identity(),
    io:format("comparison host capture verified: qualification=Blocked~n");
dispatch(_)->halt(2).

capture_host(Image)->
    Path="build/performance/comparison/current-host.json",ok=filelib:ensure_dir(Path),Initial=evidence_begin(Path),
    Compiled=pcmp_compile(),pcmp_load(Compiled),
    true=Image=:=null orelse performance_comparison_host:validate_image(Image),
    Nonce=hex(crypto:strong_rand_bytes(16)),Directory=filename:absname(pcmp_directory(Nonce)),
    ChildPath=filename:join(Directory,"child.json"),ok=filelib:ensure_dir(ChildPath),
    Artifacts=[begin File=filename:join(Directory,atom_to_list(M)++".beam"),
        ok=file:write_file(File,B,[exclusive]),{M,B,File} end||{M,B}<-Compiled],
    Loads=[io_lib:format("(fun()->{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),{module,~p}=code:load_binary(~p,\"comparison-host\",B) end)(),",
        [File,crypto:hash(sha256,B),M,M])||{M,B,File}<-Artifacts],
    Eval=lists:flatten([Loads,io_lib:format("performance_comparison_capture:run(~0tp,~0tp,~0tp).",[ChildPath,Nonce,Image])]),
    Started=erlang:monotonic_time(millisecond),
    {Exit,Output}=run_child_evaluation(filename:absname("."),[Directory],Eval,30000),
    Base=#{schema=>1,status=><<"Failed">>,qualification_status=><<"Blocked">>,nonce=>Nonce,
        deadline_ms=>30000,elapsed_ms=>erlang:monotonic_time(millisecond)-Started,runner_sha256=>pcmp_digest(Compiled),
        exit_status=>Exit,child=>null,process=>maps:without([tail,output_sha256],Output),
        evidence_identity=>Initial,execution_environment=>execution_runtime()},
    %% Preserve actual process outcomes even if parsing, source binding, or
    %% completion validation below fails. Private output never enters evidence.
    ok=file:write_file(Path,json:encode(Base)),
    try
        Child=evidence_json_decode(runtime_matrix_read(ChildPath,1048576)),
        Report=Base#{status:= <<"Captured">>,child:=Child},
        Normalized=evidence_json_decode(iolist_to_binary(json:encode(Report))),
        true=pcmp_receipt_valid(Normalized,Initial,Compiled,execution_runtime()),
        true=pcmp_retained_valid(Normalized,Compiled),
        Complete=evidence_complete(Report,Initial),ok=file:write_file(Path,json:encode(Complete)),
        io:format("comparison host captured: observation=~s qualification=Blocked joined=true nonce=~s~n",
            [maps:get(<<"status">>,maps:get(<<"capture">>,Child)),Nonce])
    catch Class:Reason:Stack->
        ok=file:write_file(Path,json:encode(Base#{failure=>diagnostic_failure_details(Class,Reason,Stack)})),
        erlang:raise(Class,Reason,Stack)
    end.
hex(B)->binary:encode_hex(B).
