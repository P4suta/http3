%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_dictionary_window_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

contracts() ->
    [{"DCB actual WBITS 24 backward copy",{timeout,180,fun dcb_window_case/0}},
     {"DCB window/output/work refusal",{timeout,30,fun dcb_limits_case/0}},
     {"DCZ hash and actual dictionary dependence",{timeout,30,fun dcz_dictionary_case/0}},
     {"DCZ output/work refusal",{timeout,30,fun dcz_limits_case/0}},
     {"window worker owner death joins",{timeout,10,fun owner_death_case/0}},
     {"window trace preserves unrelated owner messages",{timeout,30,fun trace_mailbox_isolation_case/0}},
     {"native codec contexts close after success and refusal",{timeout,30,fun native_context_cleanup_case/0}}] ++
    [{"DCZ actual distance " ++ integer_to_list(Log),{timeout,180,
        fun() -> dcz_window_case(Log) end}} || Log <- lists:seq(23,27)] ++
    [{"public DCZ encoder dictionary boundary " ++ integer_to_list(Size),{timeout,180,
        fun() -> dcz_encoder_window_case(Size) end}}
        || Size <- [1,6710886,6710887,13421773,107374183]].

dcb_window_case() ->
    Row = row(<<"dcb">>,24),
    {Observation,Copies} = bounded(fun() ->
        Dictionary = dictionary(Row),
        decoded_observation(decode(Row,Dictionary,limits(Row,24)))
    end,copy_trace),
    assert_output(Row,Observation),
    Distance = maps:get(<<"backward_distance">>,Row),
    ?assertEqual(true,lists:member(Distance,[D || {D,_} <- Copies])),
    ?assertEqual(128,lists:sum([N || {D,N} <- Copies,D =:= Distance])).

dcb_limits_case() ->
    Row = row(<<"dcb">>,24),
    {Results,[]} = bounded(fun() ->
        Dictionary = dictionary(Row), Limit = limits(Row,24),
        [decode(Row,Dictionary,limits(Row,23)),
         decode(Row,Dictionary,setelement(3,Limit,128)),
         decode(Row,Dictionary,setelement(5,Limit,1))]
    end,none),
    ?assertEqual(lists:duplicate(3,{error,limit_exceeded}),Results).

dcz_window_case(Log) ->
    Row = row(<<"dcz">>,Log),
    {{Observation,LowerRejected},[]} = bounded(fun() ->
        Dictionary = dictionary(Row),
        ?assertEqual(maps:get(<<"dictionary_sha256">>,Row),sha(Dictionary)),
        Window = 1 bsl Log,
        ?assertEqual(Window,maps:get(<<"backward_distance">>,Row)),
        ?assertEqual(true,Window =< min(1 bsl 27,max(1 bsl 23,(5*byte_size(Dictionary)) div 4))),
        Result = decoded_observation(decode(Row,Dictionary,limits(Row,Log))),
        %% Lowering the actual native streaming window must reject the SAME
        %% encoded stream. Content-size headers are deliberately absent.
        LowerRejected = case decode(Row,Dictionary,limits(Row,Log-1)) of
            {error,_} -> true;
            {ok,_} -> false
        end,
        {Result,LowerRejected}
    end,none),
    assert_output(Row,Observation),
    ?assertEqual(true,LowerRejected).

dcz_dictionary_case() ->
    Row = row(<<"dcz">>,23),
    {Results,[]} = bounded(fun() ->
        Dictionary = dictionary(Row),
        <<_:128/binary,Tail/binary>> = Dictionary,
        Modified = <<(binary:copy(<<"?">>,128))/binary,Tail/binary>>,
        Limit = limits(Row,23),
        Framed = frame(Row,Dictionary),
        WrongHash = 'http@compression':decode(dictionary_zstandard,Framed,{some,Modified},Limit),
        Missing = 'http@compression':decode(dictionary_zstandard,Framed,none,Limit),
        %% Rehashing the altered raw dictionary gets past framing, but must
        %% not reproduce the independent output. This proves prefix use.
        Changed = decoded_observation(decode(Row,Modified,Limit)),
        {WrongHash,Missing,Changed}
    end,none),
    {WrongHash,Missing,Changed} = Results,
    ?assertEqual({error,dictionary_mismatch},WrongHash),
    ?assertEqual({error,dictionary_required},Missing),
    ?assertNotEqual({ok,maps:get(<<"output_bytes">>,Row),maps:get(<<"output_sha256">>,Row)},Changed).

dcz_limits_case() ->
    Row = row(<<"dcz">>,23),
    {Results,[]} = bounded(fun() ->
        Dictionary = dictionary(Row), Limit = limits(Row,23),
        [decode(Row,Dictionary,setelement(3,Limit,128)),
         decode(Row,Dictionary,setelement(5,Limit,1))]
    end,none),
    ?assertEqual(lists:duplicate(2,{error,limit_exceeded}),Results).

native_context_cleanup_case() ->
    Row = row(<<"dcz">>,23),
    {Results,Calls} = bounded(fun() ->
        Dictionary = dictionary(Row), Limit = limits(Row,23),
        [decoded_observation(decode(Row,Dictionary,Limit)),
         decode(Row,Dictionary,setelement(3,Limit,128)),
         decode(Row,Dictionary,setelement(5,Limit,1)),
         decode(Row,Dictionary,limits(Row,22))]
    end,context_trace),
    [Complete|Failures] = Results,
    assert_output(Row,Complete),
    ?assertEqual([{error,limit_exceeded},{error,limit_exceeded},{error,invalid_encoding}],Failures),
    ?assertEqual(4,length([context || context <- Calls])),
    ?assertEqual(4,length([close || close <- Calls])).

trace_mailbox_isolation_case() ->
    Ref = make_ref(), Message = {unrelated_owner_message,Ref},
    self() ! Message,
    try
        native_context_cleanup_case(),
        Present = receive Message -> true after 0 -> false end,
        ?assertEqual(true,Present)
    after receive Message -> ok after 0 -> ok end end.

dcz_encoder_window_case(DictionarySize) ->
    {Observation,[]} = bounded(fun() ->
        %% Exercise an output longer than the minimum advertised window,
        %% including content shared with both the dictionary and prior output.
        Prefix = prefix(),
        Dictionary = binary:part(binary:copy(Prefix,(DictionarySize+127) div 128),0,DictionarySize),
        Input = <<(binary:copy(<<"x">>,(1 bsl 23)+129))/binary,Prefix/binary>>,
        Limit = {limits,max(DictionarySize,byte_size(Input)),byte_size(Input),1048576,65536,27,max(1,DictionarySize)},
        {ok,Encoded} = 'http@compression':encode(dictionary_zstandard,Input,{some,Dictionary},Limit),
        Hash = crypto:hash(sha256,Dictionary),
        <<16#5e,16#2a,16#4d,16#18,32,0,0,0,Hash:32/binary,Stream/binary>> = Encoded,
        {ok,#{windowSize := Window}} = zstd:get_frame_header(Stream),
        %% RFC 9842 Section 5 says LOWER, not lower-or-equal. The public
        %% encoder's emitted header is measured, not a requested option.
        Bound = min(1 bsl 27,max(1 bsl 23,(5*DictionarySize) div 4)),
        {ok,Decoded} = 'http@compression':decode(dictionary_zstandard,Encoded,{some,Dictionary},Limit),
        {Window < Bound,byte_size(Decoded) =:= byte_size(Input),sha(Decoded) =:= sha(Input)}
    end,none),
    ?assertEqual({true,true,true},Observation).

row(Coding,Log) ->
    {ok,Bytes} = file:read_file("test/fixtures/codec-window/manifest.json"),
    #{<<"schema">> := 1,<<"rows">> := Rows} = json:decode(Bytes),
    [Row] = [R || R <- Rows,maps:get(<<"coding">>,R) =:= Coding,maps:get(<<"window_log">>,R) =:= Log],
    Row.

prefix() ->
    iolist_to_binary([crypto:hash(sha256,<<"RFC9842 independent window prefix",N>>) || N <- lists:seq(0,3)]).

dictionary(#{<<"coding">> := <<"dcb">>,<<"dictionary_hex">> := Hex}) -> binary:decode_hex(Hex);
dictionary(#{<<"dictionary_bytes">> := Size}) ->
    <<(prefix())/binary,(binary:copy(<<"d">>,Size-128))/binary>>.

limits(Row,Log) ->
    DictionarySize = maps:get(<<"dictionary_bytes">>,Row,128),
    {limits,max(1024,DictionarySize),maps:get(<<"output_bytes">>,Row),1048576,65536,Log,DictionarySize}.

frame(Row,Dictionary) ->
    {ok,Stream} = file:read_file(filename:join("test/fixtures/codec-window",maps:get(<<"file">>,Row))),
    ?assertEqual(maps:get(<<"encoded_sha256">>,Row),sha(Stream)),
    Hash = crypto:hash(sha256,Dictionary),
    case maps:get(<<"coding">>,Row) of
        <<"dcb">> -> <<16#ff,16#44,16#43,16#42,Hash/binary,Stream/binary>>;
        <<"dcz">> -> <<16#5e,16#2a,16#4d,16#18,32,0,0,0,Hash/binary,Stream/binary>>
    end.

decode(Row,Dictionary,Limits) ->
    Coding = case maps:get(<<"coding">>,Row) of <<"dcb">> -> dictionary_brotli; <<"dcz">> -> dictionary_zstandard end,
    'http@compression':decode(Coding,frame(Row,Dictionary),{some,Dictionary},Limits).

decoded_observation({ok,Bytes}) -> {ok,byte_size(Bytes),sha(Bytes)};
decoded_observation({error,Reason}) -> {error,Reason}.

assert_output(Row,Observation) ->
    ?assertEqual({ok,maps:get(<<"output_bytes">>,Row),maps:get(<<"output_sha256">>,Row)},Observation).

sha(Bytes) -> binary:encode_hex(crypto:hash(sha256,Bytes),lowercase).

bounded(Action,Trace) ->
    Parent = self(), Ref = make_ref(),
    {Guardian,GuardianMonitor} = spawn_monitor(fun() -> guardian(Parent,Ref,Action) end),
    try
        {Worker,WorkerMonitor} = receive {Ref,worker,Pid} -> {Pid,monitor(process,Pid)} after 3000 -> error(worker_start_timeout) end,
        try
            Session = trace_start(Trace,Worker),
            try
                Worker ! {Ref,run},
                Result = receive {Ref,result,Value} -> Value;
                    {'DOWN',WorkerMonitor,process,Worker,_} -> error(window_worker_failed)
                after 120000 -> error(window_worker_timeout) end,
                receive {'DOWN',WorkerMonitor,process,Worker,normal} -> ok after 3000 -> error(worker_join_timeout) end,
                receive {'DOWN',GuardianMonitor,process,Guardian,normal} -> ok after 3000 -> error(guardian_join_timeout) end,
                {Result,trace_finish(Session,Worker,[])}
            after case Session of none -> ok; _ -> trace:session_destroy(Session) end end
        after erlang:demonitor(WorkerMonitor,[flush]) end
    after
        Guardian ! {Ref,stop},
        stop_and_join(Guardian),
        erlang:demonitor(GuardianMonitor,[flush])
    end.

guardian(Parent,Ref,Action) ->
    OwnerMonitor = monitor(process,Parent),
    {Worker,WorkerMonitor} = spawn_opt(fun() ->
        receive {Ref,run} -> Parent ! {Ref,result,Action()} after 3000 -> error(no_start) end
    end,[monitor,{max_heap_size,#{size=>33554432,kill=>true,error_logger=>false,include_shared_binaries=>true}}]),
    Parent ! {Ref,worker,Worker},
    receive
        {'DOWN',WorkerMonitor,process,Worker,_} -> ok;
        {'DOWN',OwnerMonitor,process,Parent,_} -> kill_and_join(Worker,WorkerMonitor);
        {Ref,stop} -> kill_and_join(Worker,WorkerMonitor)
    after 125000 -> kill_and_join(Worker,WorkerMonitor) end,
    demonitor(OwnerMonitor,[flush]).

kill_and_join(Worker,Monitor) ->
    exit(Worker,kill),
    receive {'DOWN',Monitor,process,Worker,_} -> ok after 3000 -> error(worker_cleanup_timeout) end.

stop_and_join(Guardian) ->
    Monitor = monitor(process,Guardian),
    receive {'DOWN',Monitor,process,Guardian,_} -> ok after 4000 -> error(guardian_cleanup_timeout) end.

trace_start(none,_Worker) -> none;
trace_start(context_trace,Worker) ->
    {module,zstd} = code:ensure_loaded(zstd),
    Session = trace:session_create(dictionary_window_context,self(),[]),
    [1 = trace:function(Session,{zstd,F,A},true,[local]) || {F,A} <- [{context,2},{close,1}]],
    1 = trace:process(Session,Worker,true,[call,arity]),
    Session;
trace_start(copy_trace,Worker) ->
    {module,http_brotli_ffi} = code:ensure_loaded(http_brotli_ffi),
    Session = trace:session_create(dictionary_window_copy,self(),[]),
    1 = trace:function(Session,{http_brotli_ffi,copy,5},
        [{['$1','_','$2','_','_'],[],[{message,{{'$1','$2'}}}]}],[local]),
    1 = trace:process(Session,Worker,true,[call,arity]),
    Session.

trace_finish(none,_Worker,[]) -> [];
trace_finish(Session,Worker,Copies) ->
    Delivered = trace:delivered(Session,all),
    collect_trace(Worker,Delivered,Copies,erlang:monotonic_time(millisecond)+3000).

collect_trace(Worker,Delivered,Copies,Deadline) ->
    Left = max(0,Deadline-erlang:monotonic_time(millisecond)),
    receive
        {trace,Worker,call,{http_brotli_ffi,copy,5},{Distance,Length}}
            when is_integer(Distance),is_integer(Length),Distance > 0,Length > 0,length(Copies) < 16 ->
            collect_trace(Worker,Delivered,[{Distance,Length}|Copies],Deadline);
        {trace,Worker,call,{zstd,context,2}} when length(Copies) < 16 ->
            collect_trace(Worker,Delivered,[context|Copies],Deadline);
        {trace,Worker,call,{zstd,close,1}} when length(Copies) < 16 ->
            collect_trace(Worker,Delivered,[close|Copies],Deadline);
        {trace_delivered,all,Delivered} -> Copies;
        Unexpected when is_tuple(Unexpected),tuple_size(Unexpected) >= 2,
            element(1,Unexpected) =:= trace,element(2,Unexpected) =:= Worker ->
            error(non_scalar_or_excess_trace)
    after Left -> error(trace_delivery_timeout) end.

owner_death_case() ->
    Test = self(), Ref = make_ref(),
    {Owner,OwnerMonitor} = spawn_monitor(fun() ->
        Owner = self(),
        {Guard,GuardMonitor} = spawn_monitor(fun() -> guardian(Owner,Ref,fun() ->
            {ok,Context} = zstd:context(decompress,#{windowLogMax=>27}),
            %% Retain the real native resource only in its owned worker. The
            %% owner is killed after this acknowledgement, not before setup.
            put(native_context,Context),Test ! {Ref,context_opened},
            receive never -> zstd:close(Context) end
        end) end),
        receive {Ref,worker,Worker} ->
            Test ! {Ref,owned,Guard,Worker},Worker ! {Ref,run},
            receive {'DOWN',GuardMonitor,process,Guard,_} -> ok end
        end
    end),
    receive {Ref,owned,Guard,Worker} ->
        GM = monitor(process,Guard), WM = monitor(process,Worker),
        receive {Ref,context_opened} -> ok after 3000 -> error(context_start_timeout) end,
        exit(Owner,kill),
        receive {'DOWN',OwnerMonitor,process,Owner,killed} -> ok after 1000 -> error(owner_join_timeout) end,
        receive {'DOWN',WM,process,Worker,_} -> ok after 4000 -> error(worker_owner_cleanup_timeout) end,
        receive {'DOWN',GM,process,Guard,_} -> ok after 4000 -> error(guardian_owner_cleanup_timeout) end
    after 3000 -> error(owner_start_timeout) end.
