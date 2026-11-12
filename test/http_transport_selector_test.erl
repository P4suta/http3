%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_transport_selector_test).
-include_lib("eunit/include/eunit.hrl").
-export([contracts/0]).

contracts() -> [fun control_keeps_credit/0, fun monitor_is_selected/0,
                fun other_socket_is_not_consumed/0, fun deadline_closes/0,
                fun invalid_policy_is_rejected/0].

control_keeps_credit() -> with_pair(fun(Client, Server) ->
    Ref = make_ref(), self() ! {Ref, ready},
    {Armed, Empty, Kind, Message} = ok_value(http_transport_ffi:read_or_select(
        Server, 4, 1000, selector(Ref))),
    ?assert(Empty =:= <<>> andalso Kind =:= 2 andalso Message =:= {some, ready}),
    ?assert(maps:get(armed, Armed, false)),
    ok_value(http_transport_ffi:send(Client, <<"abcdefghij">>)),
    {Second, First, 0, none} = ok_value(http_transport_ffi:read_or_select(
        Armed, 4, 1000, {selector, #{}})),
    {Third, Next, 0} = ok_value(http_transport_ffi:read(Second, 4, 1000)),
    {_, Last, 0} = ok_value(http_transport_ffi:read(Third, 4, 1000)),
    ?assert(<<First/binary, Next/binary, Last/binary>> =:= <<"abcdefghij">>),
    ?assert(byte_size(First) =< 4 andalso byte_size(Next) =< 4 andalso byte_size(Last) =< 4)
end).

monitor_is_selected() -> with_pair(fun(_, Server) ->
    {Pid, Monitor} = spawn_monitor(fun() -> receive finish -> ok end end),
    Pid ! finish,
    Transform = fun({process_down, Ref, Process, normal}) -> Ref =:= Monitor andalso Process =:= Pid end,
    {_, _, Kind, Selected} = ok_value(http_transport_ffi:read_or_select(
        Server, 4, 1000, {selector, #{Monitor => Transform}})),
    ?assert(Kind =:= 2 andalso Selected =:= {some, true}),
    ?assert(not is_process_alive(Pid))
end).

other_socket_is_not_consumed() -> with_pair(fun(_, Server) ->
    with_pair(fun(OtherClient, OtherServer) ->
        Ref = make_ref(), self() ! {Ref, ready},
        {ArmedOther, _, _, _} = ok_value(http_transport_ffi:read_or_select(
            OtherServer, 4, 1000, selector(Ref))),
        ok_value(http_transport_ffi:send(OtherClient, <<"peer">>)),
        OtherSocket = maps:get(socket, OtherServer),
        %% Requeue an actual active-once packet to make the interleaving exact.
        Queued = receive
            {tcp, OtherSocket, _} = Packet -> self() ! Packet, true
        after 1000 -> false end,
        ?assert(Queued),
        self() ! {Ref, ready},
        {_, _, Kind, Selected} = ok_value(http_transport_ffi:read_or_select(
            Server, 4, 1000, selector(Ref))),
        ?assert(Kind =:= 2 andalso Selected =:= {some, ready}),
        {_, Bytes, 0} = ok_value(http_transport_ffi:read(ArmedOther, 4, 1000)),
        ?assert(Bytes =:= <<"peer">>)
    end)
end).

deadline_closes() -> with_pair(fun(_, Server) ->
    TimedOut = http_transport_ffi:read_or_select(Server, 4, 5, {selector, #{}}) =:= {error, 2},
    Closed = case http_transport_ffi:read(Server, 4, 5) of
        {ok, {_, <<>>, 1}} -> true;
        _ -> false
    end,
    ?assert(TimedOut andalso Closed)
end).

invalid_policy_is_rejected() -> with_pair(fun(_, Server) ->
    TooMany = maps:from_list([{{make_ref(), 2}, fun(_) -> ready end} || _ <- lists:seq(1, 33)]),
    Results = [http_transport_ffi:read_or_select(Server, 0, 10, {selector, #{}}),
               http_transport_ffi:read_or_select(Server, 4, 0, {selector, #{}}),
               http_transport_ffi:read_or_select(Server, 4, 10, {selector, TooMany}),
               http_transport_ffi:read_or_select(Server, 4, 10, invalid)],
    ?assert(lists:all(fun(Result) -> Result =:= {error, 1} end, Results)),
    ?assert(not http_transport_ffi:read_end_is_terminal(Server))
end).

selector(Ref) -> {selector, #{{Ref, 2} => fun({_, Message}) -> Message end}}.

with_pair(Run) ->
    Listener = ok_value(http_transport_ffi:listen(<<127,0,0,1>>, 0, 8, 1000)),
    try
        {_, Port} = ok_value(http_transport_ffi:local_endpoint(Listener)),
        Client = ok_value(http_transport_ffi:connect(<<"127.0.0.1">>, Port, 1000, 1000)),
        try
            Server = ok_value(http_transport_ffi:accept(Listener, 1000)),
            try Run(Client, Server)
            after http_transport_ffi:close(Server) end
        after http_transport_ffi:close(Client) end
    after http_transport_ffi:stop(Listener) end.

ok_value({ok, Value}) -> Value;
ok_value(_) -> error(fixture_setup_failed).
