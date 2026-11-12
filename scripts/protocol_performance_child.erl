%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(protocol_performance_child).
-export([run/3]).
-ifdef(TEST).
-export([collect_with/4,prime_dns/0]).
-endif.
-compile(nowarn_unused_function).
-include("protocol_performance_data.hrl").

%% One VM owns a protocol's warmup and five subsequent measured trials. Work
%% deadlines are absolute native monotonic times, never injected clocks.
%% Reserve20s inside the270s global bound for observer cleanup/convergence and
%% child joins. The separate300s process_runner bound also observes VM exit.
run(Path,Nonce,Protocol)->
    Started=erlang:monotonic_time(microsecond),
    Deadline=erlang:monotonic_time(millisecond)+270000,
    Watchdog=spawn(fun()->receive stop->ok after 270000->halt(2) end end),
    Result=try
        true=pp_int(Protocol,1,3),true=is_binary(Nonce) andalso byte_size(Nonce)=:=32,
        Preparation=prepare(),
        collect(Protocol,Nonce,fun()->http_protocol_benchmark:run(Protocol,100,1024) end,
            Started,Deadline,Preparation)
    catch _:_ -> failed_child(Protocol,Nonce,Started,pp_failure_leaf(<<"preparation">>)) end,
    case pp_child_valid(Result,Protocol,Nonce) of
        true->ok=file:write_file(Path,[json:encode(Result),$\n]);
        false->halt(2)
    end,
    Monitor=monitor(process,Watchdog),Watchdog!stop,
    receive {'DOWN',Monitor,process,Watchdog,_}->ok after 1000->halt(2) end,
    halt(case pp_child_passed(Result) of true->0;false->1 end).

prepare()->
    try
        {ok,_}=application:ensure_all_started(ssl),
        ok=prime_dns(),
        ok=protocol_tls_prime:run(),
        %% Load fixed public API modules and native socket diagnostics before
        %% the first baseline. No project actor or network socket is retained.
        {module,http_protocol_benchmark}=code:ensure_loaded(http_protocol_benchmark),
        _=http_protocol_observer:runtime_sample(),ok
    catch _:_ ->pp_failure_leaf(<<"preparation">>) end.

prime_dns()->
    Parent=self(),Ref=make_ref(),Deadline=erlang:monotonic_time(millisecond)+2000,
    Workers=[begin
        {Pid,Monitor}=spawn_opt(fun()->
            proc_lib:set_label(<<"measurement.protocol.preparation">>),
            Code=try inet:getaddrs("localhost",Family) of
                {ok,Addresses} when is_list(Addresses),Addresses=/=[]->1;
                {error,_}->0;_->2
            catch _:_ ->2 end,
            Parent!{Ref,self(),Code}
        end,[link,monitor,{max_heap_size,#{size=>4194304,include_shared_binaries=>true,
            kill=>true,error_logger=>false}}]),
        {Pid,Monitor}
    end||Family<-[inet6,inet]],
    try
        Codes=[receive {Ref,Pid,Code}->Code
            after max(0,Deadline-erlang:monotonic_time(millisecond))->2 end||{Pid,_}<-Workers],
        case lists:all(fun(Code)->Code=:=0 orelse Code=:=1 end,Codes)
            andalso lists:member(1,Codes) of true->ok;false->error end
    after
        lists:foreach(fun({Pid,_})->unlink(Pid),exit(Pid,kill) end,Workers),
        lists:foreach(fun({Pid,Monitor})->
            receive {'DOWN',Monitor,process,Pid,_}->ok after 1000->exit(dns_prepare_join_failed) end,
            unlink(Pid),receive {'EXIT',Pid,_}->ok after 0->ok end,
            receive {Ref,Pid,_}->ok after 0->ok end
        end,Workers)
    end.

collect(Protocol,Nonce,Work,Started,Deadline,Preparation)->
    Rows=rows(lists:seq(0,5),Protocol,Work,Deadline,Preparation,[]),
    Completed=length([Row||Row<-Rows,pp_row_completed(Row)]),
    Passed=Preparation=:=ok andalso Completed=:=6
        andalso lists:all(fun(Row)->maps:get(status,Row)=:=<<"Passed">> end,Rows),
    #{schema=>1,status=>pp_status(Passed),nonce=>Nonce,protocol=>Protocol,
      configured_trials=>6,completed_trials=>Completed,requests=>100,payload_bytes=>1024,
      elapsed_ms=>max(0,(erlang:monotonic_time(microsecond)-Started+999) div 1000),
      global_timeout_ms=>270000,row_timeout_ms=>60000,rows=>Rows,
      failure=>case Preparation of ok->null;Failure->Failure end}.

rows([],_,_,_,_,Acc)->lists:reverse(Acc);
rows([Trial|Rest],Protocol,Work,Deadline,Allowed,Acc)->
    Now=erlang:monotonic_time(millisecond),
    Row=case {Allowed,Deadline-Now>20000} of
        {ok,true}->observe(Trial,Protocol,Work,min(Now+60000,Deadline-20000));
        {ok,false}->skipped(Trial,pp_failure_leaf(<<"global_timeout">>));
        {Failure,_}->skipped(Trial,Failure)
    end,
    Next=case maps:get(observation,Row) of
        null->maps:get(failure,Row);
        Observation->case pp_get(converged,Observation) andalso pp_get(children_down,Observation) of
            true->ok;false->pp_failure_leaf(<<"observer">>) end
    end,
    rows(Rest,Protocol,Work,Deadline,Next,[Row|Acc]).

observe(Trial,Protocol,Work,Deadline)->
    %% This unnamed single-entry table is a private capability shared only by
    %% this owner and its callback. Projection happens before insertion. The
    %% owner never receives a raw benchmark return value in its mailbox.
    Table=ets:new(protocol_measurement_result,[set,public]),
    try
        Observation=http_protocol_observer:measure(fun()->
            {Sample,Failure}=project_call(Work,Protocol),
            true=ets:insert_new(Table,{result,Sample,Failure}),
            case Failure of null->ok;_-> {error,1} end
        end,fun()->ok end,#{deadline_ms=>Deadline,sample_interval_ms=>10,max_samples=>4096,
            cleanup_timeout_ms=>1000,convergence_timeout_ms=>10000}),
        {Sample,Primary}=case ets:lookup(Table,result) of
            [{result,S,F}]->{S,F};[]->{null,pp_failure_leaf(<<"observer">>)} end,
        Failure=case {Primary,pp_get(status,Observation)} of
            {null,<<"ok">>}->null;{null,_}->pp_failure_leaf(<<"observer">>);{Cause,_}->Cause end,
        Passed=Sample=/=null andalso Failure=:=null andalso pp_get(status,Observation)=:=<<"ok">>,
        #{trial=>Trial,status=>pp_status(Passed),sample=>Sample,failure=>Failure,observation=>Observation}
    after ets:delete(Table) end.

project_call(Work,Protocol)->
    try Work() of
        {ok,Native}->case pp_sample(Native) of
            {ok,Safe}->case maps:get(protocol,Safe)=:=Protocol of
                true->{Safe,null};false->{null,pp_failure_leaf(<<"invalid_result">>)} end;
            error->{null,pp_failure_leaf(<<"invalid_result">>)} end;
        {error,Failure}->{null,pp_failure(Failure)};
        _->{null,pp_failure_leaf(<<"invalid_result">>)}
    catch Class:_->
        {null,(pp_failure_leaf(<<"exception">>))#{error:=case Class of
            error-><<"error">>;exit-><<"exit">>;throw-><<"throw">> end}}
    end.

skipped(Trial,Failure)->#{trial=>Trial,status=><<"Failed">>,sample=>null,failure=>Failure,observation=>null}.
failed_child(Protocol,Nonce,Started,Failure)->
    collect(Protocol,Nonce,fun()->{error,{invalid,0}} end,Started,
        erlang:monotonic_time(millisecond),Failure).

-ifdef(TEST).
%% Only the separately compiled control BEAM exposes callback injection. The
%% production child accepts exactly a protocol number and the fixed profile.
collect_with(Protocol,Nonce,Work,Remaining)->
    collect(Protocol,Nonce,Work,erlang:monotonic_time(microsecond),
        erlang:monotonic_time(millisecond)+Remaining,ok).
-endif.
