%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(protocol_tls_prime_test).
-include_lib("eunit/include/eunit.hrl").

prime_prevents_a_later_tls_upgrade_adding_an_otp_service_test() ->
    {ok,_} = application:ensure_all_started(ssl),
    ok = protocol_tls_prime:run(),
    Before = caches(),
    ok = protocol_tls_prime:run_for_test(trusted,none),
    ?assertEqual(Before,caches()),
    ?assertEqual(1,Before),
    ?assertEqual(0,length(helpers())),
    ?assertEqual(0,length(network_ports())).

untrusted_certificate_still_fails_closed_test() ->
    ?assertEqual({error,authentication},protocol_tls_prime:run_for_test(untrusted,none)),
    ?assertEqual(0,length(helpers())),
    ?assertEqual(0,length(network_ports())).

stopped_handshake_has_finite_cleanup_test() ->
    Started = erlang:monotonic_time(millisecond),
    ?assertEqual({error,timeout},protocol_tls_prime:run_for_test(hold,none)),
    ?assert(erlang:monotonic_time(millisecond)-Started < 5000),
    ?assertEqual(0,length(helpers())),
    ?assertEqual(0,length(network_ports())).

owner_death_releases_both_workers_and_tcp_sockets_test() ->
    Parent = self(),
    {Owner,OwnerMonitor} = spawn_monitor(fun() -> protocol_tls_prime:run_for_test(hold,Parent) end),
    Workers = receive {tls_prime_workers,Owner,Pids} -> Pids after 1000 -> error(missing_workers) end,
    Monitors = [{Pid,monitor(process,Pid)} || Pid <- Workers],
    receive {tls_prime_connected,Client} -> ?assert(lists:member(Client,Workers))
        after 1000 -> error(missing_connection) end,
    ?assert(length(network_ports()) >= 2),
    exit(Owner,kill),
    receive {'DOWN',OwnerMonitor,process,Owner,_} -> ok after 1000 -> error(owner_alive) end,
    lists:foreach(fun({Pid,Monitor}) ->
        receive {'DOWN',Monitor,process,Pid,_} -> ok after 1000 -> error(worker_alive) end
    end,Monitors),
    ?assertEqual(0,length(helpers())),
    ?assertEqual(0,length(network_ports())).

unrelated_owner_monitor_messages_are_preserved_test() ->
    Reference = make_ref(), Owner = self(),
    self() ! {'DOWN',Reference,process,Owner,normal},
    Outcome = protocol_tls_prime:run(),
    Preserved = receive {'DOWN',Reference,process,Owner,normal} -> true
        after 0 -> false end,
    ?assertEqual({ok,true},{Outcome,Preserved}).

repeated_verified_cycles_leave_only_the_primed_global_service_test() ->
    ok = protocol_tls_prime:run(),
    Before = caches(),
    lists:foreach(fun(_) -> ok = protocol_tls_prime:run() end,lists:seq(1,10)),
    ?assertEqual(Before,caches()),
    ?assertEqual(0,length(helpers())),
    ?assertEqual(0,length(network_ports())).

caches() ->
    length([Pid || Pid <- processes(),
        {dictionary,Dictionary} <- [process_info(Pid,dictionary)],
        {ssl_server_session_cache,_,_} <- [proplists:get_value('$initial_call',Dictionary)]]).
helpers() ->
    [Pid || Pid <- processes(), {label,Label} <- [process_info(Pid,label)],
        Label =:= <<"measurement.protocol.tls_server">> orelse Label =:= <<"measurement.protocol.tls_client">>].
network_ports() ->
    [Port || Port <- erlang:ports(),{name,"tcp_inet"} <- [erlang:port_info(Port,name)]].
