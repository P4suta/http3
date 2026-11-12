-module(http3_read_deadline_test_ffi).
-export([late_delivery/3,late_observation/3]).

%% Test-only ownership barrier. Never reads a mailbox or formats a value.
%% The two readers retain normal bounded runtime calls and are joined even
%% when fixture setup fails. Only a finite phase code and boolean escape.
late_delivery(Kind, Handle, Send) ->
    Actor=actor(Kind,Handle), Owner=self(), Ref=make_ref(),
    Deadline=now_ms()+1000, put({?MODULE,Ref},0),
    Children=[spawn_monitor(fun()->
        Result=read(Kind,Handle,Deadline),
        Code=case Result of
            {error,concurrent_receive}->1;
            {error,{failure,{timeout,operation}}}->2;
            _->3
        end,
        Owner!{Ref,self(),Code}
    end)||_<-[1,2]],
    try
        true=receive {Ref,_,1}->true after 700->false end,
        put({?MODULE,Ref},1),
        true=suspend_at_select(Actor,min(Deadline-100,now_ms()+300)),
        put({?MODULE,Ref},2),
        try
            true=Send(),
            put({?MODULE,Ref},3),
            true=receive {Ref,_,2}->true after 1500->false end,
            put({?MODULE,Ref},4),
            true=join(Children,now_ms()+300),
            put({?MODULE,Ref},5)
        after
            true=erlang:resume_process(Actor)
        end,
        Result=read(Kind,Handle,now_ms()+1000),
        Retained=case {Kind,Result} of
            {1,{ok,{response,200,[]}}}->true;
            {2,{ok,{data,<<"body">>}}}->true;
            _->false
        end,
        {6,Retained}
    catch _:_ -> {get({?MODULE,Ref}),false}
    after
        lists:foreach(fun({Pid,_})->case is_process_alive(Pid) of true->exit(Pid,kill);false->ok end end,Children),
        true=join(Children,now_ms()+300),
        lists:foreach(fun({_,M})->erase({?MODULE,M}) end,Children),
        erase({?MODULE,Ref}),
        flush(Ref)
    end.

%% The actor replies before expiry, but the caller cannot observe that reply
%% until after expiry. Only mailbox length is inspected; messages stay private.
late_observation(Kind,Handle,Send)->
    Owner=self(),Ref=make_ref(),Deadline=now_ms()+1000,put({?MODULE,Ref},0),
    Children=[spawn_monitor(fun()->
        Code=case read(Kind,Handle,Deadline) of
            {error,concurrent_receive}->1;
            {error,{failure,{timeout,operation}}}->2;
            _->3
        end,
        Owner!{Ref,self(),Code}
    end)||_<-[1,2]],
    try
        Rejected=receive {Ref,P,1}->P after 700->none end,
        [Reader]=[P||{P,_}<-Children,P=/=Rejected],
        put({?MODULE,Ref},1),
        true=suspend_at_select(Reader,min(Deadline-100,now_ms()+300)),
        put({?MODULE,Ref},2),
        try
            true=Send(),put({?MODULE,Ref},3),
            true=await_queued_reply(Reader,Deadline-100),put({?MODULE,Ref},4),
            receive after max(0,Deadline-now_ms()+1)->ok end,
            put({?MODULE,Ref},5)
        after true=erlang:resume_process(Reader) end,
        TimedOut=receive {Ref,Reader,Code}->Code=:=2 after 500->false end,
        true=join(Children,now_ms()+300),
        {6,TimedOut}
    catch _:_->{get({?MODULE,Ref}),false}
    after
        lists:foreach(fun({Pid,_})->case is_process_alive(Pid) of true->exit(Pid,kill);false->ok end end,Children),
        true=join(Children,now_ms()+300),
        lists:foreach(fun({_,M})->erase({?MODULE,M}) end,Children),
        erase({?MODULE,Ref}),flush(Ref)
    end.

await_queued_reply(Pid,Deadline)->
    case {process_info(Pid,message_queue_len),now_ms()<Deadline} of
        {{message_queue_len,N},true} when N>0->true;
        {_,false}->false;
        _->receive after 1->await_queued_reply(Pid,Deadline) end
    end.

actor(1,Handle)->
    {ok,Pid}=http3_test_ffi:connection_worker(Handle),Pid;
actor(2,{request,{request,{request,{connection,_,Pid,_},_,_}},_,_,_,_,_,_}) when is_pid(Pid)->Pid.
read(1,H,D)->'http3@client':next_event_until(H,D);
read(2,H,D)->'http3@server':next_event_until(H,D).
suspend_at_select(Pid,Deadline)->
    true=erlang:suspend_process(Pid,[unless_suspending]),
    Waiting=case process_info(Pid,current_stacktrace) of
        {current_stacktrace,[{gleam_erlang_ffi,select,2,_}|_]}->true;
        _->false
    end,
    case {Waiting,now_ms()<Deadline} of
        {true,true}->true;
        {_,false}->true=erlang:resume_process(Pid),false;
        _->true=erlang:resume_process(Pid),receive after 1->suspend_at_select(Pid,Deadline) end
    end.
join([],_) -> true;
join([{Pid,Monitor}|Rest],Deadline)->
    case get({?MODULE,Monitor}) of
        true->join(Rest,Deadline);
        _->receive {'DOWN',Monitor,process,Pid,_}->put({?MODULE,Monitor},true),join(Rest,Deadline)
           after max(0,Deadline-now_ms())->false end
    end.
flush(Ref)->receive {Ref,_,_}->flush(Ref) after 0->ok end.
now_ms()->'quic_core@diagnostics':monotonic_milliseconds().
