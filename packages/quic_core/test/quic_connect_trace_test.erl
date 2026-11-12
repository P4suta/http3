%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_connect_trace_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

contracts() -> [
    {"fixed storage, scalar publication, reuse", fun fixed_storage/0},
    {"concurrent bounded publication", {timeout,10,fun concurrent/0}},
    {"unavailable loss counter is explicitly incomplete", fun counter_exhaustion/0},
    {"attempt exhaustion is finite and counted", fun attempt_exhaustion/0},
    {"orphaned publication never blocks readers or writers", fun orphaned/0},
    {"trace survives allocating process exit", fun lifetime/0},
    {"malformed scalar fields never enter snapshot", fun malformed/0},
    {"family outcomes are bounded and carry no resolver terms", fun resolution_events/0}
].

fixed_storage() ->
    Trace = {quic_connect_trace,Cells,_} = quic_core_connect_trace_ffi:new(),
    ?assertMatch(#{size := 712}, atomics:info(Cells)),
    ?assertEqual({true,0,[]}, quic_core_connect_trace_ffi:snapshot(Trace)),
    ?assertEqual(1, quic_core_connect_trace_ffi:begin_attempt(Trace)),
    ?assertEqual(2, quic_core_connect_trace_ffi:begin_attempt(Trace)),
    nil = quic_core_connect_trace_ffi:record(Trace,1,0,1,1),
    nil = quic_core_connect_trace_ffi:record(Trace,1,0,1,2),
    {true,0,[{1,1,0,1,1,First},{2,1,0,1,2,Last}]} = quic_core_connect_trace_ffi:snapshot(Trace),
    ?assert(First >= 0 andalso Last >= First).

concurrent() ->
    Trace = quic_core_connect_trace_ffi:new(),
    Owner = self(),
    Attempts = [quic_core_connect_trace_ffi:begin_attempt(Trace) || _ <- lists:seq(1,40)],
    Workers = [spawn_monitor(fun() ->
        lists:foreach(fun(_) -> quic_core_connect_trace_ffi:record(Trace,Id,1,3,1) end,
                      lists:seq(1,25)),
        Owner ! {done,self()}
    end) || Id <- Attempts],
    lists:foreach(fun({Pid,Ref}) ->
        receive {done,Pid} -> ok after 2000 -> error(worker_timeout) end,
        receive {'DOWN',Ref,process,Pid,normal} -> ok after 2000 -> error(worker_survived) end
    end, Workers),
    {Consistent,Dropped,Events} = quic_core_connect_trace_ffi:snapshot(Trace),
    ?assertEqual(64,length(Events)),
    %% A fixed CAS budget must never delay network work. Counter contention
    %% is explicitly reported as an incomplete lower bound, not exact loss.
    ?assert(Dropped >= 0 andalso Dropped =< 936),
    ?assertEqual(Dropped =:= 936, Consistent),
    ?assertEqual(lists:seq(1,64), [element(1,Event) || Event <- Events]),
    lists:foreach(fun({_,Attempt,1,3,1,Time}) ->
        ?assert(Attempt > 0 andalso Attempt =< 40 andalso Time >= 0)
    end, Events).

counter_exhaustion() ->
    Trace = {quic_connect_trace,Cells,_} = quic_core_connect_trace_ffi:new(),
    atomics:put(Cells,2,2147483647),
    nil = quic_core_connect_trace_ffi:record(Trace,0,0,1,1),
    ?assertEqual({false,2147483647,[]}, quic_core_connect_trace_ffi:snapshot(Trace)),
    nil = quic_core_connect_trace_ffi:record(Trace,1,0,1,1),
    ?assertMatch({false,2147483647,[{1,1,0,1,1,_}]}, quic_core_connect_trace_ffi:snapshot(Trace)).

attempt_exhaustion() ->
    Trace = {quic_connect_trace,Cells,_} = quic_core_connect_trace_ffi:new(),
    atomics:put(Cells,3,2147483647),
    ?assertEqual(0,quic_core_connect_trace_ffi:begin_attempt(Trace)),
    ?assertEqual(2147483647,atomics:get(Cells,3)),
    ?assertEqual({true,1,[]},quic_core_connect_trace_ffi:snapshot(Trace)).

orphaned() ->
    Trace = {quic_connect_trace,Cells,_} = quic_core_connect_trace_ffi:new(),
    atomics:put(Cells,1,1),
    ?assertEqual({false,0,[]}, quic_core_connect_trace_ffi:snapshot(Trace)),
    nil = quic_core_connect_trace_ffi:record(Trace,1,0,1,2),
    ?assertMatch({false,0,[{2,1,0,1,2,_}]}, quic_core_connect_trace_ffi:snapshot(Trace)).

lifetime() ->
    Owner = self(),
    {Pid,Ref} = spawn_monitor(fun() -> Owner ! {trace,quic_core_connect_trace_ffi:new()} end),
    Trace = receive {trace,Value} -> Value after 1000 -> error(missing_trace) end,
    receive {'DOWN',Ref,process,Pid,normal} -> ok after 1000 -> error(owner_alive) end,
    nil = quic_core_connect_trace_ffi:record(Trace,1,1,4,4),
    ?assertMatch({true,0,[{1,1,1,4,4,_}]}, quic_core_connect_trace_ffi:snapshot(Trace)).

malformed() ->
    Trace = quic_core_connect_trace_ffi:new(),
    lists:foreach(fun(Args) ->
        nil = apply(quic_core_connect_trace_ffi,record,[Trace|Args])
    end, [[0,0,1,1],[1,-1,1,1],[1,0,0,1],[1,0,5,1],[1,0,1,0],[1,0,1,6],
          [1,<<"secret">>,1,1],[1,0,1,{error,<<"secret">>}]]),
    ?assertEqual({true,8,[]},quic_core_connect_trace_ffi:snapshot(Trace)).

resolution_events() ->
    Trace = quic_core_connect_trace_ffi:new(),
    nil = quic_core_connect_trace_ffi:record_resolution(Trace, 1, 6, 1),
    nil = quic_core_connect_trace_ffi:record_resolution(Trace, 1, 4, 1),
    nil = quic_core_connect_trace_ffi:record_resolution(Trace, 1, 4, 2),
    nil = quic_core_connect_trace_ffi:record_resolution(Trace, 1, 6, 5),
    %% Joined cancellation cannot rewrite a completed family outcome.
    nil = quic_core_connect_trace_ffi:record_resolution(Trace, 1, 4, 6),
    nil = quic_core_connect_trace_ffi:record_resolution(Trace, 1, <<"private-host">>, 4),
    {true,1,Events} = quic_core_connect_trace_ffi:resolution_snapshot(Trace),
    ?assertEqual([{1,6,1},{1,4,1},{1,4,2},{1,6,5}],
        [{Attempt,Family,Outcome} || {_,Attempt,Family,Outcome,_} <- Events]),
    ?assertEqual({true,0,[]}, quic_core_connect_trace_ffi:snapshot(Trace)),
    lists:foreach(fun(Index) ->
        quic_core_connect_trace_ffi:record_resolution(Trace, Index, 4, 1)
    end, lists:seq(2,80)),
    {true,20,Full} = quic_core_connect_trace_ffi:resolution_snapshot(Trace),
    ?assertEqual(64, length(Full)).
