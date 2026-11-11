%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_connection_lifetime_tests).
-include_lib("eunit/include/eunit.hrl").

connection_crash_releases_qlog_while_listener_continues_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Certificate = required(quic_core_test_ffi:fixture(<<"server.pem">>)),
        Key = required(quic_core_test_ffi:fixture(<<"server-key.pem">>)),
        Ca = required(quic_core_test_ffi:fixture(<<"ca.pem">>)),
        Deadlines = lists:foldl(fun(Phase, D) ->
            required('quic_core@config':with_deadline(D, Phase, 2000))
        end, 'quic_core@config':default_deadlines(), [connect, handshake, operation]),
        Config0 = required('quic_core@server':new(Certificate, Key, <<"qlog-lifetime">>)),
        Config1 = 'quic_core@server':with_address_family(Config0, ipv4),
        Config2 = 'quic_core@server':with_deadlines(Config1, Deadlines),
        Config = required('quic_core@server':with_qlog(Config2, Directory)),
        Listener = required('quic_core@server':start(Config)),
        ListenerActor = required(quic_core_test_ffi:labelled_pid(Listener, <<"quic_core.listener">>)),
        try
            Port = required('quic_core@server':port(Listener)),
            ClientConfig0 = required('quic_core@client':new(<<"localhost">>, Port, <<"qlog-lifetime">>)),
            ClientConfig1 = 'quic_core@client':with_address_family(ClientConfig0, ipv4),
            ClientConfig2 = required('quic_core@client':with_ca_certificates(ClientConfig1, Ca)),
            ClientConfig = 'quic_core@client':with_deadlines(ClientConfig2, Deadlines),
            Client = required('quic_core@client':connect(ClientConfig)),
            try
                Peer = required('quic_core@server':accept(Listener)),
                Actor = required(quic_core_test_ffi:labelled_pid(Peer, <<"quic_core.connection">>)),
                Writer = writer_owned_by(ListenerActor),
                {monitors, Monitors} = process_info(Writer, monitors),
                Children = [P || {process, P} <- Monitors, is_pid(P), P =/= ListenerActor,
                                 P =/= Actor],
                Devices = [P || P <- Children, diagnostic_admission_or_worker(P)],
                ?assert(length(Children) =:= 3 andalso length(Devices) =:= 1),
                [Device] = Devices,
                try
                    true = erlang:suspend_process(Device),
                    ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
                    %% This round trip proves an accepted unfinished event.
                    Queued = case quic_core_qlog_ffi:stats(Writer) of
                        {ok, {_Dropped, _Errors, N}} when N > 0 -> true;
                        _ -> false
                    end,
                    ?assert(Queued),
                    Deadline = erlang:monotonic_time(millisecond) + 6500,
                    exit(Actor, kill),
                    %% A blocked diagnostic device must not make the listener
                    %% wait for this connection's flush before accepting others.
                    Neighbour = required('quic_core@client':connect(ClientConfig)),
                    try
                        NeighbourPeer = required('quic_core@server':accept(Listener)),
                        ?assert('quic_core@server':phase(NeighbourPeer) =:= {ok, established}),
                        ?assert(is_process_alive(ListenerActor)),
                        ?assert(joined([Actor, Writer | Children], Deadline))
                    after _ = 'quic_core@client':close(Neighbour) end
                after
                    lists:foreach(fun(P) -> exit(P, kill) end, [Writer | Children]),
                    ?assert(joined([Writer | Children], erlang:monotonic_time(millisecond) + 1000))
                end
            after _ = 'quic_core@client':close(Client) end
        after
            ?assert('quic_core@server':stop(Listener) =:= {ok, stopped}),
            ?assert(joined([ListenerActor], erlang:monotonic_time(millisecond) + 1000))
        end
    end) end}.

required(Result) ->
    ?assert(is_tuple(Result) andalso tuple_size(Result) =:= 2 andalso element(1, Result) =:= ok),
    element(2, Result).

writer_owned_by(Owner) ->
    {monitored_by, Monitors} = process_info(Owner, monitored_by),
    Writers = [P || P <- Monitors, diagnostic_admission_or_worker(P)],
    ?assert(length(Writers) =:= 1),
    hd(Writers).

diagnostic_admission_or_worker(Pid) ->
    proc_lib:get_label(Pid) =:= <<"quic_core.qlog_writer">>
        andalso process_info(Pid, trap_exit) =:= {trap_exit, false}.

joined(Pids, Deadline) ->
    Monitors = [{P, erlang:monitor(process, P)} || P <- Pids],
    try lists:all(fun({P, M}) ->
        Remaining = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
        receive {'DOWN', M, process, P, _} -> true after Remaining -> false end
    end, Monitors)
    after lists:foreach(fun({_P, M}) -> erlang:demonitor(M, [flush]) end, Monitors) end.
