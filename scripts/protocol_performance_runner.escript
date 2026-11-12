#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("evidence_identity.hrl").
-include("process_runner.hrl").
-include("protocol_performance_execution.hrl").
-include("retained_execution_tests.hrl").
-include("protocol_performance_runner_tests.hrl").

main(Arguments) ->
    try command(Arguments) catch Class:Reason:Stack ->
        io:format(standard_error,"protocol performance failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class,Reason,Stack))]),halt(1)
    end.
command([]) -> execute();
command(["--self-test"]) -> ppr_invalidation_self_test(),ppr_self_test();
command(["--invalidate"]) -> ppr_invalidate();
command(["--verify"]) -> _=ppr_verify(),io:put_chars("protocol performance: retained source/build/executions verified\n");
command(_) -> erlang:error(invalid_arguments).

execute() ->
    ok=ppr_invalidate(),
    %% Keep the Failed report in place if current-source identity cannot be read.
    Path=ppr_path(),ok=filelib:ensure_dir(Path),Identity=evidence_identity(),
    Proof="build/performance/current/protocols-execution-proof.tar",
    Initial=#{schema=>1,status=><<"Failed">>,shareable=>true,scope=>ppr_scope(),
        configuration=>pp_profile(),configured_protocols=>[1,2,3],completed_protocols=>0,
        executions=>[],summary=>[],evidence_identity=>Identity,replay_command=>ppr_replay()},
    ok=ppr_write(Path,Initial),
    ok=ppr_check_profile(),
    try fresh_with_verified_build("http",fun(Snapshot)->
        execute_locked(Path,Proof,Initial,Identity,Snapshot)
    end),
    _=ppr_verify(),
    io:put_chars("protocol performance: all three protocols completed warmup and five trials with retained execution proof\n")
    catch Class:Reason:Stacktrace ->
        ok=ppr_invalidate(),
        erlang:raise(Class,Reason,Stacktrace)
    end.

execute_locked(Path,Proof,Initial,Identity,Snapshot) ->
    Build=maps:get(report,Snapshot),
    Compiled=ppr_compile(),ok=ppr_load_observer(Compiled),
    Base=Initial#{build_identity=>Build,runner_sha256=>ppr_digest(Compiled),execution_environment=>execution_runtime()},
    Final=lists:foldl(fun(Protocol,Before)->
        Execution=ppr_run_child(Protocol,Compiled,ppr_deadline()),
        Executions=maps:get(executions,Before)++[Execution],
        Completed=length([ok || Entry<-Executions,
            ppr_execution_valid(runtime_matrix_json(Entry),maps:get(protocol,Entry))]),
        Next=Before#{executions=>Executions,completed_protocols=>Completed},
        ok=ppr_write(Path,Next),
        ok=ppr_export(runtime_matrix_json(Executions),Compiled,Proof),
        io:format("protocol ~B: child exit=~B, joined=~p, measurement accepted=~p\n",
            [Protocol,maps:get(exit_status,Execution),
             maps:get(child_exit_observed,maps:get(process,Execution)),
             ppr_execution_valid(runtime_matrix_json(Execution),Protocol)]),Next
    end,Base,[1,2,3]),
    FinalSnapshot=fresh_verify_locked("http"),
    Build=maps:get(report,FinalSnapshot),
    true=maps:get(sha256,Snapshot)=:=maps:get(sha256,FinalSnapshot),
    true=maps:get(completed_protocols,Final)=:=3,
    Summary=pp_summary([maps:get(child,Execution)||Execution<-maps:get(executions,Final)]),
    Ready=evidence_complete(Final#{status=><<"Ready">>,summary=>Summary},Identity),
    true=ppr_report_valid(runtime_matrix_json(Ready),Identity,Build,Compiled),
    ok=ppr_write(Path,Ready).

ppr_run_child(Protocol,Compiled,Deadline) ->
    Nonce=binary:encode_hex(crypto:strong_rand_bytes(16)),
    Directory=filename:absname("build/performance/protocol-runner/"++binary_to_list(Nonce)),
    ChildPath=filename:join(Directory,"child.json"),ok=filelib:ensure_dir(ChildPath),
    Loads=[begin
        File=filename:join(Directory,atom_to_list(Module)++".beam"),ok=file:write_file(File,Bytes,[exclusive]),
        io_lib:format("(fun()->{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),"
            "{module,~p}=code:load_binary(~p,~0tp,B) end)(),",
            [File,crypto:hash(sha256,Bytes),Module,Module,atom_to_list(Module)++".beam"])
    end || {Module,Bytes}<-Compiled],
    Paths=[Directory|[filename:absname(P)||P<-filelib:wildcard("build/dev/erlang/*/ebin")]],
    Evaluation=[Loads,io_lib:format("protocol_performance_child:run(~0tp,~0tp,~B).",[ChildPath,Nonce,Protocol])],
    Started=erlang:monotonic_time(millisecond),
    {Exit,Output}=run_child_evaluation(filename:absname("."),Paths,lists:flatten(Evaluation),Deadline),
    Elapsed=erlang:monotonic_time(millisecond)-Started,
    Child=try evidence_json_decode(runtime_matrix_read(ChildPath,1048576)) catch _:_ ->#{} end,
    Safe=case pp_child_valid(Child,Protocol,Nonce) of true->Child;false->#{invalid_child_schema=>true} end,
    ok=ppr_write(ChildPath,Safe),
    #{protocol=>Protocol,nonce=>Nonce,deadline_ms=>Deadline,elapsed_ms=>Elapsed,exit_status=>Exit,
        process=>maps:without([tail,output_sha256],Output),child=>Safe}.

ppr_write(Path,Report) -> file:write_file(Path,[json:encode(Report),$\n]).
hex(Bytes) -> binary:encode_hex(Bytes).

ppr_invalidate() ->
    ppr_invalidate(ppr_path(),"build/performance/current/protocols-execution-proof.tar").

ppr_invalidate(Path,Proof) ->
    ok=filelib:ensure_dir(Path),
    Failed=#{schema=>1,status=><<"Failed">>,shareable=>true,
        failure=><<"execution_not_completed">>,configured_protocols=>[1,2,3],
        completed_protocols=>0,executions=>[]},
    ok=ppr_write(Path,Failed),
    case file:delete(Proof) of
        ok->ok;
        {error,enoent}->ok;
        _->erlang:error(cannot_invalidate_execution_proof)
    end.

ppr_invalidation_self_test() ->
    Stem=filename:absname("build/diagnostics/protocol-runner/invalidate-"++
        binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    Path=Stem++".json",Proof=Stem++".tar",Marker = <<"private-stale-protocol-marker">>,
    ok=filelib:ensure_dir(Path),ok=file:write_file(Path,Marker),ok=file:write_file(Proof,Marker),
    ok=ppr_invalidate(Path,Proof),
    Failed=evidence_json_decode(runtime_matrix_read(Path,4096)),
    <<"Failed">>=maps:get(<<"status">>,Failed),
    nomatch=binary:match(iolist_to_binary(json:encode(Failed)),Marker),
    false=filelib:is_file(Proof),ok.
