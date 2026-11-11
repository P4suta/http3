%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(protocol_tls_prime).
-export([run/0]).
-ifdef(TEST).
-export([run_for_test/2]).
-endif.

%% Prime OTP's lazy upgraded-socket TLS service through public APIs only.
%% The caller starts ssl before invoking this helper. The operation has 3s;
%% socket disposal and observed worker exits share a 5s absolute deadline.
run() -> cycle(trusted, none).

cycle(Mode, Observer) ->
    Started = erlang:monotonic_time(millisecond),
    OperationDeadline = Started + 3000,
    CleanupDeadline = Started + 5000,
    Trap = process_flag(trap_exit, true),
    try
        case gen_tcp:listen(0, [binary, {active, false}, {ip, {127,0,0,1}}, {reuseaddr, true}]) of
            {error, _} -> {error, listen};
            {ok, Listener} ->
                try
                    {ok, {_, Port}} = inet:sockname(Listener),
                    Owner = self(), Reference = make_ref(),
                    Server = worker(Owner, Reference, <<"measurement.protocol.tls_server">>,
                        fun() -> server(Listener, OperationDeadline) end),
                    try
                        Client = worker(Owner, Reference, <<"measurement.protocol.tls_client">>,
                            fun() -> client(Port, Mode, Observer, OperationDeadline) end),
                        Workers = [Server, Client],
                        try
                            notify(Observer, Workers),
                            Outcome = try await(Reference, Workers, [], [], OperationDeadline)
                                catch _:_ -> {error, worker} end,
                            gen_tcp:close(Listener),
                            case stop_workers(Workers, CleanupDeadline) of
                                true -> Outcome;
                                false -> {error, cleanup}
                            end
                        after stop_workers(Workers, CleanupDeadline) end
                    after stop_workers([Server], CleanupDeadline) end
                after gen_tcp:close(Listener) end
        end
    catch _:_ -> {error, preparation}
    after process_flag(trap_exit, Trap) end.

worker(Owner, Reference, Label, Callback) ->
    spawn_opt(fun() ->
        proc_lib:set_label(Label),
        Outcome = try Callback() catch _:_ -> worker end,
        Owner ! {Reference, self(), Outcome}
    end, [link, monitor, {max_heap_size, #{size => 1048576,
        include_shared_binaries => true, kill => true, error_logger => false}}]).

notify(none, _) -> ok;
notify(Observer, Workers) when is_pid(Observer) ->
    Observer ! {tls_prime_workers, self(), [Pid || {Pid,_} <- Workers]}, ok.

await(_, Workers, Results, Down, _) when length(Workers) =:= length(Down) ->
    case [Code || {_,Code} <- Results] of
        [ok,ok] -> ok;
        Codes ->
            case lists:member(authentication, Codes) of
                true -> {error, authentication};
                false -> case lists:member(tls_options,Codes) of
                    true -> {error,tls_options}; false -> {error,exchange} end
            end
    end;
await(Reference, [{Server,ServerMonitor},{Client,ClientMonitor}] = Workers,
        Results, Down, Deadline) ->
    receive
        {Reference, Pid, Code} when Pid =:= Server; Pid =:= Client ->
            case lists:keymember(Pid,1,Workers) andalso not lists:keymember(Pid,1,Results) of
                true -> await(Reference,Workers,[{Pid,Code}|Results],Down,Deadline);
                false -> {error, worker}
            end;
        {'DOWN', Monitor, process, Pid, _}
                when Monitor =:= ServerMonitor, Pid =:= Server;
                     Monitor =:= ClientMonitor, Pid =:= Client ->
            case lists:member({Pid,Monitor},Workers) andalso not lists:member(Pid,Down) of
                true -> await(Reference,Workers,Results,[Pid|Down],Deadline);
                false -> {error, worker}
            end
    after remaining(Deadline) -> {error, timeout}
    end.

stop_workers(Workers, Deadline) ->
    lists:foreach(fun({Pid,_}) -> exit(Pid,kill) end,Workers),
    lists:foldl(fun({Pid,OldMonitor},Joined) ->
        Monitor = monitor(process,Pid),
        Down = receive {'DOWN',Monitor,process,Pid,_} -> true
            after remaining(Deadline) -> false end,
        demonitor(Monitor,[flush]), demonitor(OldMonitor,[flush]),
        unlink(Pid), receive {'EXIT',Pid,_} -> ok after 0 -> ok end,
        Joined andalso Down
    end,true,Workers).

server(Listener, Deadline) ->
    case gen_tcp:accept(Listener,remaining(Deadline)) of
        {error,_} -> accept;
        {ok, Tcp} ->
            try
                Options = [{certfile, "packages/http3/test/fixtures/server.pem"},
                    {keyfile, "packages/http3/test/fixtures/server-key.pem"},
                    {verify,verify_none}, {versions,['tlsv1.3','tlsv1.2']}, {alpn_preferred_protocols,[<<"http/1.1">>]},
                    {reuse_sessions,false}, {log_level,none}, {active,false}, binary],
                case ssl:handshake(Tcp,Options,remaining(Deadline)) of
                    {error,Failure} -> tls_failure(Failure);
                    {ok,Tls} ->
                        try
                            ok = tls13(Tls),
                            {ok,<<"http/1.1">>} = ssl:negotiated_protocol(Tls),
                            {ok,<<"ping">>} = ssl:recv(Tls,4,remaining(Deadline)),
                            ok = ssl:send(Tls,<<"pong">>), ok
                        after ssl:close(Tls) end
                end
            after gen_tcp:close(Tcp) end
    end.

client(Port, hold, Observer, Deadline) ->
    {ok,Socket} = gen_tcp:connect({127,0,0,1},Port,[binary,{active,false}],remaining(Deadline)),
    case is_pid(Observer) of true -> Observer ! {tls_prime_connected,self()}; false -> ok end,
    try receive after 60000 -> exchange end after gen_tcp:close(Socket) end;
client(Port, Mode, _, Deadline) ->
    Ca = case Mode of
        trusted -> "packages/http3/test/fixtures/ca.pem";
        untrusted -> "packages/quic_core/test/fixtures/ecdsa-p256-server.pem"
    end,
    Options = [{verify,verify_peer}, {cacertfile,Ca}, {server_name_indication,"localhost"},
        {customize_hostname_check,[{match_fun,public_key:pkix_verify_hostname_match_fun(https)}]},
        {versions,['tlsv1.3']}, {alpn_advertised_protocols,[<<"http/1.1">>]},
        {log_level,none}, {active,false}, binary],
    case ssl:connect({127,0,0,1},Port,Options,remaining(Deadline)) of
        {error,Failure} -> tls_failure(Failure);
        {ok,Tls} ->
            try
                ok = tls13(Tls),
                {ok,<<"http/1.1">>} = ssl:negotiated_protocol(Tls),
                ok = ssl:send(Tls,<<"ping">>),
                {ok,<<"pong">>} = ssl:recv(Tls,4,remaining(Deadline)), ok
            after ssl:close(Tls) end
    end.

tls_failure({options,_}) -> tls_options;
tls_failure({options,_,_}) -> tls_options;
tls_failure({dtls_upgrade,notsup}) -> upgrade;
tls_failure({tls_alert,{unknown_ca,_}}) -> authentication;
tls_failure({tls_alert,{bad_certificate,_}}) -> authentication;
tls_failure(closed) -> closed;
tls_failure(timeout) -> timeout;
tls_failure(_) -> handshake.

tls13(Tls) ->
    case ssl:connection_information(Tls,[protocol]) of
        {ok,[{protocol,'tlsv1.3'}]} -> ok;
        _ -> error(protocol)
    end.

remaining(Deadline) -> max(0,Deadline-erlang:monotonic_time(millisecond)).

-ifdef(TEST).
run_for_test(Mode, Observer) -> cycle(Mode,Observer).
-endif.
