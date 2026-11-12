%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_COMPARISON_EVIDENCE_HRL).
-define(HTTP_PERFORMANCE_COMPARISON_EVIDENCE_HRL,true).
-include("runtime_matrix_evidence.hrl").

pcmp_compile()->
    [begin
        {ok,M,B,[]}=compile:file("scripts/"++atom_to_list(M)++".erl",
            [binary,deterministic,return_errors,return_warnings,{i,"scripts"}]),{M,B}
    end||M<-[performance_comparison,performance_comparison_host,performance_comparison_capture]].
pcmp_digest(Compiled)->binary:encode_hex(crypto:hash(sha256,
    [[atom_to_binary(M),0,B]||{M,B}<-Compiled])).
pcmp_load(Compiled)->lists:foreach(fun({M,B})->
    {module,M}=code:load_binary(M,"comparison-current-verified-helper",B)
end,Compiled).
pcmp_child_valid(Child,Nonce,Runtime)->
    try
        true=suite_exact_keys(Child,[schema,nonce,capture,runtime,elapsed_ms]),
        1=maps:get(<<"schema">>,Child),Nonce=maps:get(<<"nonce">>,Child),
        Runtime=maps:get(<<"runtime">>,Child),
        Millis=maps:get(<<"elapsed_ms">>,Child),true=is_integer(Millis) andalso Millis>=0 andalso Millis<30000,
        performance_comparison_host:validate_capture(maps:get(<<"capture">>,Child))
    catch _:_ ->false end.
pcmp_receipt_valid(Report,Identity,Compiled,Runtime)->
    try
        true=suite_exact_keys(Report,[schema,status,qualification_status,nonce,deadline_ms,
            elapsed_ms,runner_sha256,child,exit_status,process,evidence_identity,execution_environment]),
        1=maps:get(<<"schema">>,Report),<<"Captured">>=maps:get(<<"status">>,Report),
        <<"Blocked">>=maps:get(<<"qualification_status">>,Report),
        Identity=maps:get(<<"evidence_identity">>,Report),Runtime=maps:get(<<"execution_environment">>,Report),
        Digest=pcmp_digest(Compiled),Digest=maps:get(<<"runner_sha256">>,Report),
        30000=maps:get(<<"deadline_ms">>,Report),0=maps:get(<<"exit_status">>,Report),
        Elapsed=maps:get(<<"elapsed_ms">>,Report),true=is_integer(Elapsed) andalso Elapsed>=0 andalso Elapsed<30000,
        Process=maps:get(<<"process">>,Report),true=runtime_matrix_process_valid(Process),0=maps:get(<<"output_bytes">>,Process),
        Nonce=maps:get(<<"nonce">>,Report),true=pcmp_nonce(Nonce),
        Child=maps:get(<<"child">>,Report),true=pcmp_child_valid(Child,Nonce,Runtime),
        true=maps:get(<<"elapsed_ms">>,Child)=<Elapsed,true
    catch _:_ ->false end.
pcmp_nonce(N)->is_binary(N) andalso byte_size(N)=:=32
    andalso re:run(N,<<"^[0-9A-F]{32}$">>,[{capture,none}])=:=match.
pcmp_directory(Nonce)->true=pcmp_nonce(Nonce),
    "build/performance/comparison/"++binary_to_list(Nonce).
pcmp_retained_valid(Report,Compiled)->
    try
        Directory=pcmp_directory(maps:get(<<"nonce">>,Report)),
        ChildPath=filename:join(Directory,"child.json"),
        Paths=[filename:join(Directory,atom_to_list(M)++".beam")||{M,_}<-Compiled],
        true=lists:sort(filelib:wildcard(filename:join(Directory,"*")))=:=lists:sort([ChildPath|Paths]),
        true=lists:all(fun({Path,{_,B}})->B=:=runtime_matrix_read(Path,16777216) end,lists:zip(Paths,Compiled)),
        Child=evidence_json_decode(runtime_matrix_read(ChildPath,1048576)),Child=maps:get(<<"child">>,Report),true
    catch _:_ ->false end.
-endif.
