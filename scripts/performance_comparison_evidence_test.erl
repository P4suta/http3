%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_comparison_evidence_test).
-compile(nowarn_unused_function).
-include_lib("eunit/include/eunit.hrl").
-include("evidence_identity.hrl").
-include("performance_comparison_evidence.hrl").

receipt_requires_source_helper_runtime_nonce_exit_and_no_output_test()->
    {Report,Identity,Compiled,Runtime}=fixture(),
    ?assert(pcmp_receipt_valid(Report,Identity,Compiled,Runtime)),
    Mutations=[{<<"status">>,<<"Ready">>},{<<"qualification_status">>,<<"Ready">>},
        {<<"evidence_identity">>,#{}},{<<"runner_sha256">>,binary:copy(<<"0">>,64)},
        {<<"execution_environment">>,#{}},{<<"nonce">>,binary:copy(<<"B">>,32)},
        {<<"exit_status">>,1},{<<"elapsed_ms">>,30000},{<<"deadline_ms">>,60000}],
    lists:foreach(fun({K,V})->?assertNot(pcmp_receipt_valid(Report#{K:=V},Identity,Compiled,Runtime)) end,Mutations),
    P=maps:get(<<"process">>,Report),
    lists:foreach(fun({K,V})->?assertNot(pcmp_receipt_valid(Report#{<<"process">>:=P#{K:=V}},Identity,Compiled,Runtime)) end,
        [{<<"child_exit_observed">>,false},{<<"timed_out">>,true},{<<"output_bytes">>,1},
         {<<"vm_process_heap_words">>,134217728}]),
    ?assertNot(pcmp_receipt_valid(Report#{<<"private">>=><<"hidden">>},Identity,Compiled,Runtime)),
    ?assertNot(pcmp_receipt_valid(Report,Identity,[{fake,<<"different">>}],Runtime)).

retained_child_and_beam_must_be_exact_selected_bytes_test()->
    {Original,_,Compiled,_}=fixture(),Nonce=binary:encode_hex(crypto:strong_rand_bytes(16)),
    Child=(maps:get(<<"child">>,Original))#{<<"nonce">>:=Nonce},
    Report=Original#{<<"nonce">>:=Nonce,<<"child">>:=Child},
    Directory=pcmp_directory(Nonce),ChildPath=filename:join(Directory,"child.json"),
    BeamPath=filename:join(Directory,"fake.beam"),ExtraPath=filename:join(Directory,"unexpected.json"),
    ok=filelib:ensure_dir(ChildPath),[{fake,Bytes}]=Compiled,
    try
        ok=file:write_file(ChildPath,json:encode(Child),[exclusive]),ok=file:write_file(BeamPath,Bytes,[exclusive]),
        ?assert(pcmp_retained_valid(Report,Compiled)),
        ok=file:write_file(BeamPath,<<"changed">>),?assertNot(pcmp_retained_valid(Report,Compiled)),
        ok=file:write_file(BeamPath,Bytes),ok=file:write_file(ChildPath,json:encode(Child#{<<"nonce">>:=binary:copy(<<"C">>,32)})),
        ?assertNot(pcmp_retained_valid(Report,Compiled)),
        ok=file:write_file(ChildPath,json:encode(Child)),ok=file:write_file(ExtraPath,<<"{}">>),
        ?assertNot(pcmp_retained_valid(Report,Compiled)),ok=file:delete(ExtraPath),
        ok=file:delete(BeamPath),?assertNot(pcmp_retained_valid(Report,Compiled))
    after
        [file:delete(P)||P<-[ChildPath,BeamPath,ExtraPath]],file:del_dir(Directory)
    end.

fixture()->
    Nonce=binary:copy(<<"A">>,32),Runtime=#{<<"test_runtime">>=>true},Identity=#{<<"test_source">>=>true},
    Compiled=[{fake,<<"fixed-helper-bytes">>}],
    {ok,Capture}=performance_comparison_host:capture(null),
    Report=#{schema=>1,status=><<"Captured">>,qualification_status=><<"Blocked">>,nonce=>Nonce,
        deadline_ms=>30000,elapsed_ms=>1,runner_sha256=>pcmp_digest(Compiled),exit_status=>0,
        child=>#{schema=>1,nonce=>Nonce,capture=>Capture,runtime=>Runtime,elapsed_ms=>0},
        process=>runtime_matrix_process_fixture(#{output_bytes=>0,output_hashed_bytes=>0,output_limit_bytes=>8388608,
            output_digest_complete=>true,output_limit_exceeded=>false,vm_process_heap_words=>33554432,
            vm_heap_includes_shared_binaries=>true,crash_dumps_disabled=>true,timed_out=>false,child_exit_observed=>true}),
        evidence_identity=>Identity,execution_environment=>Runtime},
    {evidence_json_decode(iolist_to_binary(json:encode(Report))),Identity,Compiled,Runtime}.
