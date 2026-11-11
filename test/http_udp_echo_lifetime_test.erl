%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_udp_echo_lifetime_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

contracts() ->
    [{atom_to_list(Reason), fun() -> advisory_does_not_end_echo(Reason) end}
     || Reason <- [econnreset, econnrefused, enetunreach, ehostunreach]]
    ++ [{"fatal socket error", fun fatal_error_still_closes_echo/0}].

advisory_does_not_end_echo(Reason) ->
    {Echo = {http_test_udp_echo, Owner, _, _}, {udp_endpoint, _, Port}} =
        http_test_ffi:start_udp_echo_server(),
    {ok, Client} = gen_udp:open(0, [binary, inet, {active, false}]),
    try
        %% Exactly the owned echo socket; no global process/socket inventory.
        {links, Links} = process_info(Owner, links),
        [Socket] = [P || P <- Links, is_port(P)],
        Monitor = monitor(process, Owner),
        Owner ! {udp_error, Socket, Reason},
        ok = gen_udp:send(Client, {127,0,0,1}, Port, <<"other-peer">>),
        Received = case gen_udp:recv(Client, 64, 500) of
            {ok, {{127,0,0,1}, Port, <<"other-peer">>}} -> true;
            _ -> false
        end,
        Alive = is_process_alive(Owner),
        demonitor(Monitor, [flush]),
        ?assertEqual(true, Received),
        ?assertEqual(true, Alive)
    after
        gen_udp:close(Client),
        http_test_ffi:stop_udp_echo_server(Echo)
    end.

fatal_error_still_closes_echo() ->
    {Echo = {http_test_udp_echo, Owner, _, _}, _} =
        http_test_ffi:start_udp_echo_server(),
    Monitor = monitor(process, Owner),
    try
        {links, Links} = process_info(Owner, links),
        [Socket] = [P || P <- Links, is_port(P)],
        Owner ! {udp_error, Socket, eperm},
        Exited = receive {'DOWN', Monitor, process, Owner, _} -> true
            after 500 -> false end,
        Closed = erlang:port_info(Socket) =:= undefined,
        ?assertEqual(true, Exited),
        ?assertEqual(true, Closed)
    after
        demonitor(Monitor, [flush]),
        http_test_ffi:stop_udp_echo_server(Echo)
    end.
