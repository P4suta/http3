%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Independent MASQUE peer fixture using public HTTP/3 and CONNECT-UDP APIs.
-module(http_masque_interop).
-export([run_client/2, run_proxy/2, run_client/4, run_proxy/4]).
-include("../../interop_notice.hrl").

-define(FIXTURES, "packages/http3/test/fixtures").

limits() -> {limits,128,4096,4,4,4}.
packet(Flow,Sequence) -> <<Flow,Sequence,(binary:copy(<<16#5a>>,62))/binary>>.

run_client(Port,TargetPort) -> outcome(client(Port,TargetPort)).
run_client(Port,TargetPort,ResultPath,Nonce) ->
    publish(client(Port,TargetPort),ResultPath,Nonce).

client(Port,TargetPort) ->
    safe(fun() ->
        phase(1),
        {_,_,Ca} = credentials(),
        {ok,C0} = http3@client:with_ca_certificate(http3@client:new(),Ca),
        {ok,C1} = http3@client:with_timeout(C0,5000),
        {ok,Address} = http3@address:from_bytes(<<127,0,0,1>>),
        C2 = http3@client:with_connect_address(C1,Address),
        {ok,Connection} = http3@client:connect(http3@client:with_http_datagrams(C2),<<"localhost">>,Port),
        try
            phase(2),
            First = open_flow(Connection,Port,TargetPort,<<"127.0.0.1">>),
            try
                Second = open_flow(Connection,Port,TargetPort,<<"127.0.0.1">>),
                try
                    phase(3),
                    Flows = [http3@client:stream_transport(First),http3@client:stream_transport(Second)],
                    lists:foreach(fun(Sequence) ->
                        lists:foreach(fun({Transport,Id}) ->
                            Payload = packet(Id,Sequence),
                            {ok,nil} = http3@transport:send_datagram(Transport,<<0,Payload/binary>>)
                        end,lists:zip(Flows,[0,1])),
                        lists:foreach(fun({Transport,Id}) ->
                            Payload = packet(Id,Sequence),
                            {ok,<<0,Payload/binary>>} = http3@transport:next_datagram(Transport),
                            add(datagrams,1)
                        end,lists:zip(Flows,[0,1]))
                    end,lists:seq(0,7)),
                    phase(4),
                    {ok,Denied} = http3@client:open_extended_connect(Connection,
                        request(Port,TargetPort,<<"127.0.0.2">>),<<"connect-udp">>),
                    try
                        {ok,{response,502,_}} = http3@client:next_event(Denied),
                        add(rejections,1)
                    after close_stream(Denied) end,
                    ok
                after close_stream(Second) end
            after close_stream(First) end
        after {ok,_} = http3@client:close(Connection) end
    end).

open_flow(Connection,Port,TargetPort,Host) ->
    {ok,Stream} = http3@client:open_extended_connect(Connection,request(Port,TargetPort,Host),<<"connect-udp">>),
    try
        {ok,{response,200,Headers}} = http3@client:next_event(Stream),
        <<"?1">> = proplists:get_value(<<"capsule-protocol">>,Headers),
        add(flows,1),
        Stream
    catch Class:Reason:Stack -> close_stream(Stream),erlang:raise(Class,Reason,Stack) end.

request(Port,TargetPort,Host) ->
    Path = <<"/.well-known/masque/udp/",Host/binary,"/",(integer_to_binary(TargetPort))/binary,"/">>,
    {request,get,[{<<"capsule-protocol">>,<<"?1">>}],nil,https,<<"localhost">>,{some,Port},Path,none}.

close_stream(Stream) -> {ok,_} = http3@client:cancel(Stream),ok.

run_proxy(StopPath,ReadyPath) -> outcome(proxy_run(StopPath,ReadyPath)).
run_proxy(StopPath,ReadyPath,ResultPath,Nonce) ->
    publish(proxy_run(StopPath,ReadyPath),ResultPath,Nonce).

proxy_run(StopPath,ReadyPath) ->
    safe(fun() ->
        phase(5),
        Trap = process_flag(trap_exit,true),
        Deadline = erlang:monotonic_time(millisecond)+40000,
        {ok,EchoSocket} = gen_udp:open(0,[binary,{active,false},{ip,{127,0,0,1}},
            {recbuf,8192},{buffer,2048}]),
        try
            {ok,{_,TargetPort}} = inet:sockname(EchoSocket),
            Echo = worker(fun() ->
                receive start -> echo(EchoSocket,16,[],[],Deadline)
                after 1000 -> error(echo_start) end
            end),
            try
                ok = gen_udp:controlling_process(EchoSocket,element(1,Echo)),
                element(1,Echo)!start,
                proxy(StopPath,ReadyPath,TargetPort,Echo,Deadline)
            after stop_workers([Echo],Deadline+3000) end
        after gen_udp:close(EchoSocket),process_flag(trap_exit,Trap) end
    end).

proxy(StopPath,ReadyPath,TargetPort,Echo,Deadline) ->
    {Certificate,PrivateKey,_} = credentials(),
    {ok,C0} = http3@server:new(Certificate,PrivateKey),
    {ok,Configuration} = http3@server:with_timeout(C0,10000),
    {ok,Listener} = http@masque:start_udp_proxy_listener(Configuration,limits()),
    try
        {ok,Port} = http@masque:udp_proxy_listener_port(Listener),
        {ok,P0} = http@masque:deny_all(limits()),
        {ok,P1} = http@masque:allow_udp(P0,{udp_target,<<"127.0.0.1">>,TargetPort}),
        {ok,Policy} = http@masque:allow_udp_destination(P1,{ip_prefix,{ipv4,<<127,0,0,1>>},32}),
        {ok,Setup} = http@masque:proxy_setup_config({token_identifier,<<"fixture">>},1000,2000,262144),
        Ready = iolist_to_binary(json:encode(#{port=>Port,target=>TargetPort})),
        true = byte_size(Ready) =< 256,
        ok = interop_publish_notice(ReadyPath,iolist_to_binary(Ready)),
        phase(6),
        First = establish(Listener,Policy,Setup),
        try
            Relay1 = worker(fun() -> relay(First,Deadline) end),
            try
                Second = establish(Listener,Policy,Setup),
                try
                    Relay2 = worker(fun() -> relay(Second,Deadline) end),
                    try
                        phase(7),
                        {ok,{udp_proxy_request_accepted,Denied}} = http@masque:accept_udp_proxy_request(Listener),
                        {ok,{system_udp_proxy_policy_rejected,502}} = establish_request(Denied,Policy,Setup),
                        add(rejections,1),
                        phase(8),
                        ok = await_workers([Relay1,Relay2,Echo],Deadline),
                        ok = await_stop(StopPath,Deadline),
                        phase(9),
                        Snapshot = http@masque:udp_proxy_listener_snapshot(Listener),
                        %% Public snapshot: consistency, accepts, setup success and policy denial.
                        check(element(2,Snapshot),11),
                        check(element(5,Snapshot) =:= 3,12),
                        check(element(9,Snapshot) =:= 3,13),
                        check(element(10,Snapshot) =:= 2,14),
                        check(element(11,Snapshot) =:= 1,15),
                        ok
                    after stop_workers([Relay2],Deadline+3000) end
                after close_proxy(Second) end
            after stop_workers([Relay1],Deadline+3000) end
        after close_proxy(First) end
    after
        case http@masque:stop_udp_proxy_listener(Listener) of
            {ok,_} -> ok; _ -> phase(17),error(listener_cleanup)
        end
    end.

establish(Listener,Policy,Setup) ->
    {ok,{udp_proxy_request_accepted,Accepted}} = http@masque:accept_udp_proxy_request(Listener),
    {ok,{system_udp_proxy_established,Active,_}} = establish_request(Accepted,Policy,Setup),
    add(flows,1),
    Active.

establish_request(Accepted,Policy,Setup) ->
    http@masque:establish_system_udp_proxy_request(Accepted,Policy,Setup,
        http@masque:udp_proxy_idle_timeout_disabled(),fun(_,_) -> {error,dns_lookup_failed} end).

relay(Active,Deadline) ->
    Transport = http@masque:system_udp_proxy_transport(Active),
    Session = http@masque:system_udp_proxy_session(Active),
    relay(Transport,Session,0,Deadline).

relay(_,_,8,_) -> {relay,8};
relay(Transport,Session,Count,Deadline) ->
    true = erlang:monotonic_time(millisecond) < Deadline,
    {ok,<<0,Payload:64/binary>>=Datagram} = http3@transport:next_datagram(Transport),
    {system_udp_sent,Next} = http@masque:forward_system_udp_datagram(Session,Datagram),
    {system_udp_forward,Received,<<0,Payload/binary>>=Reply} = http@masque:receive_system_udp_datagram(Next,2000),
    {ok,nil} = http3@transport:send_datagram(Transport,Reply),
    relay(Transport,Received,Count+1,Deadline).

close_proxy(Active) ->
    case http@masque:close_udp_proxy_session(http@masque:system_udp_proxy_session(Active)) of
        {ok,nil} -> ok;
        {error,udp_proxy_termination_in_progress} -> phase(20),error(session_cleanup);
        {error,{udp_proxy_cleanup_incomplete,none,{some,udp_request_stream_cleanup_failed}}} ->
            phase(21),error(session_cleanup);
        {error,{udp_proxy_cleanup_incomplete,none,{some,udp_request_stream_cleanup_timeout}}} ->
            phase(22),error(session_cleanup);
        {error,{udp_proxy_cleanup_incomplete,{some,_},none}} -> phase(23),error(session_cleanup);
        {error,{udp_proxy_cleanup_incomplete,none,{some,udp_request_stream_cleanup_in_progress}}} ->
            phase(24),error(session_cleanup);
        {error,{udp_proxy_cleanup_incomplete,{some,_},{some,_}}} -> phase(25),error(session_cleanup);
        {error,_} -> phase(26),error(session_cleanup);
        {ok,_} -> phase(27),error(session_cleanup);
        _ -> phase(28),error(session_cleanup)
    end.

echo(_,0,Seen,Sources,_) -> 16 = length(Seen),2 = length(Sources),{echo,16};
echo(Socket,Left,Seen,Sources,Deadline) ->
    {ok,{Address,Port,<<Flow,Sequence,_/binary>>=Bytes}} = gen_udp:recv(Socket,65,remaining(Deadline)),
    true = Flow < 2 andalso Sequence < 8,
    Bytes = packet(Flow,Sequence),
    false = lists:member({Flow,Sequence},Seen),
    Source = {Address,Port},
    Next = case lists:keyfind(Flow,1,Sources) of
        false -> false = lists:member(Source,[S || {_,S} <- Sources]),[{Flow,Source}|Sources];
        {Flow,Source} -> Sources
    end,
    ok = gen_udp:send(Socket,Address,Port,Bytes),
    echo(Socket,Left-1,[{Flow,Sequence}|Seen],Next,Deadline).

worker(Callback) ->
    Parent = self(), Reference = make_ref(),
    {Pid,Monitor} = spawn_opt(fun() ->
        proc_lib:set_label(<<"interop.masque.worker">>),
        Result = try Callback() of
            {relay,8} -> {relay,8}; {echo,16} -> {echo,16}; _ -> failed
        catch _:_ -> failed end,
        Parent!{Reference,self(),Result}
    end,[link,monitor,{max_heap_size,#{size=>1048576,include_shared_binaries=>true,
        kill=>true,error_logger=>false}}]),
    add(workers_started,1),
    {Pid,Monitor,Reference}.

await_workers([],_) -> ok;
await_workers([{Pid,Monitor,Reference}|Rest],Deadline) ->
    receive
        {Reference,Pid,{relay,Count}} when Count =:= 8 -> add(datagrams,Count);
        {Reference,Pid,{echo,16}} -> ok;
        {Reference,Pid,failed} -> error(worker_failed)
        after remaining(Deadline) -> error(worker_timeout) end,
    receive {'DOWN',Monitor,process,Pid,normal} -> ok
        after remaining(Deadline) -> error(worker_join) end,
    add(workers_joined,1),
    await_workers(Rest,Deadline).

stop_workers(Workers,Deadline) ->
    lists:foreach(fun({Pid,_,_}) -> exit(Pid,kill) end,Workers),
    lists:foreach(fun({Pid,OldMonitor,Reference}) ->
        Monitor = monitor(process,Pid),
        receive {'DOWN',Monitor,process,Pid,_} -> ok
            after remaining(Deadline) -> error(worker_cleanup) end,
        demonitor(OldMonitor,[flush]),unlink(Pid),
        receive {'EXIT',Pid,_} -> ok after 0 -> ok end,
        receive {Reference,Pid,_} -> ok after 0 -> ok end
    end,Workers).

await_stop(Path,Deadline) ->
    case interop_read_notice(Path,32) of
        {ok,<<"complete">>} -> ok;
        {error,enoent} ->
            true = erlang:monotonic_time(millisecond) < Deadline,
            receive after 25 -> await_stop(Path,Deadline) end;
        _ -> error(invalid_completion)
    end.

credentials() ->
    {ok,Certificate} = file:read_file(filename:join(?FIXTURES,"server.pem")),
    {ok,PrivateKey} = file:read_file(filename:join(?FIXTURES,"server-key.pem")),
    {ok,CaPem} = file:read_file(filename:join(?FIXTURES,"ca.pem")),
    [{'Certificate',Ca,not_encrypted}] = public_key:pem_decode(CaPem),
    {Certificate,PrivateKey,Ca}.

phase(Code) -> put(masque_fixture_phase,Code),ok.
check(true,_) -> ok;
check(false,Code) -> phase(Code),error(contract).
remaining(Deadline) -> max(0,Deadline-erlang:monotonic_time(millisecond)).
safe(Callback) ->
    phase(0),
    put(masque_fixture_counts,#{flows=>0,datagrams=>0,rejections=>0,
        workers_started=>0,workers_joined=>0}),
    try
        Value = Callback(),
        check(Value =:= ok,18),
        Counts = get(masque_fixture_counts),
        check(maps:get(workers_started,Counts) =:= maps:get(workers_joined,Counts),19),
        {ok,Counts}
    catch _:_ -> {error,get(masque_fixture_phase)}
    after erase(masque_fixture_phase),erase(masque_fixture_counts) end.

add(Key,Amount) ->
    Counts = get(masque_fixture_counts),
    put(masque_fixture_counts,maps:update_with(Key,fun(N) -> N+Amount end,Counts)),ok.

outcome({ok,_}) -> ok;
outcome({error,Code}) -> {error,Code}.

publish({error,Code},Path,Nonce) ->
    Fixed = case is_integer(Code) andalso Code >= 1 andalso Code =< 32 of
        true -> Code; false -> 255
    end,
    try
        ok = valid_nonce(Nonce),
        ok = file:write_file(Path,json:encode(#{schema=>1,nonce=>Nonce,failure_phase=>Fixed}),[exclusive])
    catch _:_ -> ok end,
    {error,Fixed};
publish({ok,Counts},Path,Nonce) ->
    try
        ok = valid_nonce(Nonce),
        true = maps:get(workers_started,Counts) =:= maps:get(workers_joined,Counts),
        Result = #{schema=>1,nonce=>Nonce,completed_flows=>maps:get(flows,Counts),
            completed_datagrams=>maps:get(datagrams,Counts),
            completed_rejections=>maps:get(rejections,Counts),workers_down=>true},
        ok = file:write_file(Path,json:encode(Result),[exclusive])
    catch _:_ -> {error,10} end.

valid_nonce(Nonce) ->
    true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32,
    match = re:run(Nonce,<<"^[a-f0-9]{32}$">>,[{capture,none}]),ok.
