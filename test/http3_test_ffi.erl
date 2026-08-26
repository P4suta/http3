-module(http3_test_ffi).

-export([
    concurrent_cancellations/1,
    concurrent_accepts/1,
    concurrent_next_datagrams/2,
    concurrent_next_events/1,
    connection_owner_cleanup/3,
    checkpoint/1,
    await_task/1,
    new_signal/0,
    pause_milliseconds/1,
    qlog_event_count/2,
    release_signal/1,
    repeated_bytes/1,
    server_credentials/0,
    server_certificate_selection_credentials/0,
    server_owner_cleanup/1,
    start_task/1,
    with_corrupting_proxy/3,
    with_delaying_proxy/3,
    with_duplicating_proxy/3,
    with_lossy_proxy/3,
    with_mtu_limited_proxy/3,
    with_qlog_directory/1,
    with_reordering_proxy/3,
    with_temp_override/1,
    with_tmpdir_override/1,
    write_probe_file/1
]).

-define(FIXTURE_TIMEOUT, 2000).
-define(CONCURRENCY_TIMEOUT, 5000).

-spec pause_milliseconds(non_neg_integer()) -> nil.
pause_milliseconds(Milliseconds) ->
    timer:sleep(Milliseconds).

%% Runs Fun with the path of a uniquely named scratch directory, reports how
%% many qlog traces were written there, and deletes the directory afterwards.
-spec with_qlog_directory(fun((binary()) -> term())) -> term().
with_qlog_directory(Fun) when is_function(Fun, 1) ->
    Directory = unique_scratch_path("http3-qlog-test-"),
    try
        Result = Fun(list_to_binary(Directory)),
        Files = filelib:wildcard(filename:join(Directory, "*.qlog")),
        {Result, length(Files)}
    after
        _ = file:del_dir_r(Directory)
    end.

%% Points TMPDIR at a fresh scratch directory for the duration of Fun, then
%% restores the previous environment and deletes the directory.
-spec with_tmpdir_override(fun((binary()) -> term())) -> term().
with_tmpdir_override(Fun) when is_function(Fun, 1) ->
    with_environment_override("TMPDIR", "http3-tmpdir-test-", Fun).

%% Unsets TMPDIR and points TEMP at a fresh scratch directory, exercising the
%% documented TEMP fallback of temporary_root/0.
-spec with_temp_override(fun((binary()) -> term())) -> term().
with_temp_override(Fun) when is_function(Fun, 1) ->
    with_environment_override("TEMP", "http3-temp-test-", Fun).

%% Mutates the process-global environment, so it relies on gleeunit running
%% test modules sequentially; every variable it touches is restored afterwards.
-spec with_environment_override(
    string(), string(), fun((binary()) -> term())
) -> term().
with_environment_override(Name, Prefix, Fun) ->
    Root = unique_scratch_path(Prefix),
    ok = filelib:ensure_path(Root),
    Previous = [
        {Candidate, os:getenv(Candidate)}
     || Candidate <- ["TMPDIR", "TEMP", "TMP"]
    ],
    lists:foreach(fun({Candidate, _}) -> os:unsetenv(Candidate) end, Previous),
    true = os:putenv(Name, Root),
    try Fun(list_to_binary(Root))
    after
        lists:foreach(
            fun({Candidate, Value}) -> restore_environment(Candidate, Value) end,
            Previous
        ),
        _ = file:del_dir_r(Root)
    end.

%% Creates Directory, writes one file inside it, and reports whether that file
%% exists, proving the fixture root is writable.
-spec write_probe_file(binary()) -> boolean().
write_probe_file(Directory) when is_binary(Directory) ->
    Path = filename:join(binary_to_list(Directory), "probe.txt"),
    ok =:= filelib:ensure_dir(Path)
        andalso ok =:= file:write_file(Path, <<"probe">>)
        andalso filelib:is_regular(Path).

%% Returns a unique, not-yet-created path under the OS temporary directory.
-spec unique_scratch_path(string()) -> string().
unique_scratch_path(Prefix) ->
    Suffix = integer_to_list(erlang:unique_integer([positive, monotonic])),
    filename:join(temporary_root(), Prefix ++ Suffix).

%% First non-empty of TMPDIR, TEMP, and TMP, falling back to "/tmp", so the
%% fixtures also work where /tmp is read-only or absent, such as on Windows.
-spec temporary_root() -> string().
temporary_root() ->
    first_environment_value(["TMPDIR", "TEMP", "TMP"], "/tmp").

-spec first_environment_value([string()], string()) -> string().
first_environment_value([], Default) ->
    Default;
first_environment_value([Name | Rest], Default) ->
    case os:getenv(Name) of
        [_ | _] = Value -> Value;
        _ -> first_environment_value(Rest, Default)
    end.

-spec restore_environment(string(), string() | false) -> ok.
restore_environment(Name, false) ->
    _ = os:unsetenv(Name),
    ok;
restore_environment(Name, Value) ->
    _ = os:putenv(Name, Value),
    ok.

-spec qlog_event_count(binary(), binary()) -> non_neg_integer().
qlog_event_count(Directory, EventName)
    when is_binary(Directory), is_binary(EventName) ->
    Pattern = <<"\"name\":\"", EventName/binary, "\"">>,
    Files = filelib:wildcard(filename:join(binary_to_list(Directory), "*.qlog")),
    lists:sum([
        case file:read_file(File) of
            {ok, Contents} -> length(binary:matches(Contents, Pattern));
            {error, _Reason} -> 0
        end
     || File <- Files
    ]).

-spec start_task(fun(() -> term())) -> tuple().
start_task(Fun) when is_function(Fun, 0) ->
    Owner = self(),
    Ref = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        Outcome = try Fun() of
            Result -> {ok, Result}
        catch
            Class:Reason:Stacktrace -> {raised, Class, Reason, Stacktrace}
        end,
        Owner ! {Ref, task_result, Outcome}
    end),
    {http3_test_task, Pid, Monitor, Ref}.

-spec await_task(tuple()) -> term().
await_task({http3_test_task, Pid, Monitor, Ref}) ->
    receive
        {Ref, task_result, {ok, Result}} ->
            await_process_down(Pid, Monitor),
            Result;
        {Ref, task_result, {raised, Class, Reason, Stacktrace}} ->
            await_process_down(Pid, Monitor),
            erlang:raise(Class, Reason, Stacktrace);
        {'DOWN', Monitor, process, Pid, Reason} ->
            receive
                {Ref, task_result, {ok, Result}} -> Result;
                {Ref, task_result, {raised, Class, RaisedReason, Stacktrace}} ->
                    erlang:raise(Class, RaisedReason, Stacktrace)
            after 0 ->
                erlang:error({test_task_stopped, Reason})
            end
    after ?CONCURRENCY_TIMEOUT * 2 ->
        exit(Pid, kill),
        await_process_down(Pid, Monitor),
        erlang:error(test_task_timeout)
    end.

-spec server_credentials() -> {binary(), binary(), binary()}.
server_credentials() ->
    {ok, CertificatePem} = file:read_file(fixture_path("server.pem")),
    {ok, PrivateKeyPem} = file:read_file(fixture_path("server-key.pem")),
    {CertificatePem, PrivateKeyPem, read_certificate("ca.pem")}.

-spec server_certificate_selection_credentials() ->
    {binary(), binary(), binary(), binary(), binary()}.
server_certificate_selection_credentials() ->
    {ok, FallbackCertificate} =
        file:read_file(fixture_path("default-server.pem")),
    {ok, FallbackPrivateKey} =
        file:read_file(fixture_path("default-server-key.pem")),
    {Certificate, PrivateKey, CaCertificate} = server_credentials(),
    {
        FallbackCertificate,
        FallbackPrivateKey,
        Certificate,
        PrivateKey,
        CaCertificate
    }.

-spec new_signal() -> tuple().
new_signal() ->
    {http3_test_signal, self(), make_ref()}.

-spec checkpoint(tuple()) -> nil.
checkpoint({http3_test_signal, Owner, Ref}) ->
    Owner ! {Ref, checkpoint, self()},
    receive
        {Ref, continue} -> nil
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(checkpoint_timeout)
    end.

-spec release_signal(tuple()) -> nil.
release_signal({http3_test_signal, Owner, Ref}) when Owner =:= self() ->
    receive
        {Ref, checkpoint, Process} ->
            Process ! {Ref, continue},
            nil
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(signal_timeout)
    end.

-spec concurrent_accepts(term()) -> [term()].
concurrent_accepts(Listener) ->
    Parent = self(),
    StartRef = make_ref(),
    Workers = [
        spawn_monitor(fun() ->
            receive
                {start, StartRef} ->
                    Parent ! {StartRef, self(), http3@server:accept(Listener)}
            end
        end)
     || _ <- lists:seq(1, 2)
    ],
    [Pid ! {start, StartRef} || {Pid, _Monitor} <- Workers],
    First = receive
        {StartRef, _FirstPid, FirstResult} -> FirstResult
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(concurrent_accept_timeout)
    end,
    _ = http3@server:stop(Listener),
    Second = receive
        {StartRef, _SecondPid, SecondResult} -> SecondResult
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(blocked_accept_cleanup_timeout)
    end,
    await_test_workers(Workers),
    [First, Second].

-spec server_owner_cleanup(term()) -> boolean().
server_owner_cleanup(Configuration) ->
    Parent = self(),
    Ref = make_ref(),
    {Creator, CreatorMonitor} = spawn_monitor(fun() ->
        case http3@server:start(Configuration) of
            {ok, {listener,
                  {listener,
                   {listener, _Commands, Worker, _Timeout, _DrainTimeout}}}}
                    when is_pid(Worker) ->
                Parent ! {Ref, worker, Worker};
            Error ->
                Parent ! {Ref, error, Error}
        end
    end),
    receive
        {Ref, worker, Worker} ->
            WorkerMonitor = monitor(process, Worker),
            await_process_down(Creator, CreatorMonitor),
            receive
                {'DOWN', WorkerMonitor, process, Worker, _Reason} -> true
            after ?CONCURRENCY_TIMEOUT ->
                demonitor(WorkerMonitor, [flush]),
                false
            end;
        {Ref, error, _Error} ->
            await_process_down(Creator, CreatorMonitor),
            false;
        {'DOWN', CreatorMonitor, process, Creator, _Reason} ->
            false
    after ?CONCURRENCY_TIMEOUT ->
        exit(Creator, kill),
        await_process_down(Creator, CreatorMonitor),
        false
    end.

-spec concurrent_next_events(term()) -> [term()].
concurrent_next_events(Stream) ->
    Parent = self(),
    StartRef = make_ref(),
    Workers = [
        spawn_monitor(fun() ->
            receive
                {start, StartRef} ->
                    Parent ! {StartRef, self(), http3@client:next_event(Stream)}
            end
        end)
     || _ <- lists:seq(1, 2)
    ],
    [Pid ! {start, StartRef} || {Pid, _Monitor} <- Workers],
    First = receive
        {StartRef, _FirstPid, FirstResult} -> FirstResult
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(concurrent_receive_timeout)
    end,
    _ = http3@client:cancel(Stream),
    Second = receive
        {StartRef, _SecondPid, SecondResult} -> SecondResult
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(blocked_receive_cleanup_timeout)
    end,
    await_test_workers(Workers),
    [First, Second].

-spec concurrent_cancellations(term()) -> [term()].
concurrent_cancellations(Stream) ->
    Parent = self(),
    StartRef = make_ref(),
    Workers = [
        spawn_monitor(fun() ->
            receive
                {start, StartRef} ->
                    Parent ! {StartRef, self(), http3@client:cancel(Stream)}
            end
        end)
     || _ <- lists:seq(1, 2)
    ],
    [Pid ! {start, StartRef} || {Pid, _Monitor} <- Workers],
    Results = collect_test_results(StartRef, 2, []),
    await_test_workers(Workers),
    Results.

-spec concurrent_next_datagrams(term(), fun(() -> nil)) -> [term()].
concurrent_next_datagrams(Stream, Release) when is_function(Release, 0) ->
    Parent = self(),
    StartRef = make_ref(),
    Workers = [
        spawn_monitor(fun() ->
            receive
                {start, StartRef} ->
                    Parent ! {
                        StartRef,
                        self(),
                        http3@transport:next_datagram(Stream)
                    }
            end
        end)
     || _ <- lists:seq(1, 2)
    ],
    [Pid ! {start, StartRef} || {Pid, _Monitor} <- Workers],
    First = receive
        {StartRef, _FirstPid, FirstResult} -> FirstResult
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(concurrent_datagram_receive_timeout)
    end,
    nil = Release(),
    Second = receive
        {StartRef, _SecondPid, SecondResult} -> SecondResult
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(blocked_datagram_receive_timeout)
    end,
    await_test_workers(Workers),
    [First, Second].

-spec repeated_bytes(non_neg_integer()) -> binary().
repeated_bytes(Size) when is_integer(Size), Size >= 0 ->
    binary:copy(<<"x">>, Size).

-spec connection_owner_cleanup(term(), binary(), inet:port_number()) -> boolean().
connection_owner_cleanup(Configuration, Host, Port) ->
    Parent = self(),
    Ref = make_ref(),
    {Creator, CreatorMonitor} = spawn_monitor(fun() ->
        case http3@client:connect(Configuration, Host, Port) of
            {ok, Connection} ->
                case connection_worker(Connection) of
                    {ok, Worker} -> Parent ! {Ref, worker, Worker};
                    error -> Parent ! {Ref, error, invalid_connection_handle}
                end;
            Error ->
                Parent ! {Ref, error, Error}
        end
    end),
    receive
        {Ref, worker, Worker} ->
            WorkerMonitor = monitor(process, Worker),
            await_process_down(Creator, CreatorMonitor),
            receive
                {'DOWN', WorkerMonitor, process, Worker, _Reason} -> true
            after ?CONCURRENCY_TIMEOUT ->
                demonitor(WorkerMonitor, [flush]),
                false
            end;
        {Ref, error, _Error} ->
            await_process_down(Creator, CreatorMonitor),
            false;
        {'DOWN', CreatorMonitor, process, Creator, _Reason} ->
            false
    after ?CONCURRENCY_TIMEOUT ->
        exit(Creator, kill),
        await_process_down(Creator, CreatorMonitor),
        false
    end.

connection_worker({connection, {http3_connection, Worker, _Timeout}}) when is_pid(Worker) ->
    {ok, Worker};
connection_worker(
    {connection, {connection, {connection, _Commands, Worker, _Timeout, _Host, _Port}}}
) when is_pid(Worker) ->
    {ok, Worker};
connection_worker(_Connection) ->
    error.

collect_test_results(_Ref, 0, Results) ->
    Results;
collect_test_results(Ref, Remaining, Results) ->
    receive
        {Ref, _Pid, Result} ->
            collect_test_results(Ref, Remaining - 1, [Result | Results])
    after ?CONCURRENCY_TIMEOUT ->
        erlang:error(concurrent_operation_timeout)
    end.

await_test_workers(Workers) ->
    lists:foreach(
        fun({Pid, Monitor}) -> await_process_down(Pid, Monitor) end,
        Workers
    ).

await_process_down(Pid, Monitor) ->
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after ?CONCURRENCY_TIMEOUT ->
        exit(Pid, kill),
        receive
            {'DOWN', Monitor, process, Pid, _Reason} -> ok
        after ?FIXTURE_TIMEOUT ->
            demonitor(Monitor, [flush]),
            ok
        end
    end.

-spec with_lossy_proxy(
    inet:port_number(), binary(), fun((inet:port_number(), binary()) -> Result)
) -> Result.
with_lossy_proxy(ServerPort, CaCert, Fun) when is_function(Fun, 2) ->
    with_proxy(ServerPort, packet_loss, Fun, CaCert).

-spec with_duplicating_proxy(
    inet:port_number(), binary(), fun((inet:port_number(), binary()) -> Result)
) -> Result.
with_duplicating_proxy(ServerPort, CaCert, Fun) when is_function(Fun, 2) ->
    with_proxy(ServerPort, duplication, Fun, CaCert).

-spec with_corrupting_proxy(
    inet:port_number(), binary(), fun((inet:port_number(), binary()) -> Result)
) -> Result.
with_corrupting_proxy(ServerPort, CaCert, Fun) when is_function(Fun, 2) ->
    with_proxy(ServerPort, corruption, Fun, CaCert).

-spec with_delaying_proxy(
    inet:port_number(), binary(), fun((inet:port_number(), binary()) -> Result)
) -> Result.
with_delaying_proxy(ServerPort, CaCert, Fun) when is_function(Fun, 2) ->
    with_proxy(ServerPort, delay, Fun, CaCert).

-spec with_mtu_limited_proxy(
    inet:port_number(), binary(), fun((inet:port_number(), binary()) -> Result)
) -> Result.
with_mtu_limited_proxy(ServerPort, CaCert, Fun) when is_function(Fun, 2) ->
    with_proxy(ServerPort, mtu_limit, Fun, CaCert).

-spec with_reordering_proxy(
    inet:port_number(), binary(), fun((inet:port_number(), binary()) -> Result)
) -> Result.
with_reordering_proxy(ServerPort, CaCert, Fun) when is_function(Fun, 2) ->
    with_proxy(ServerPort, reordering, Fun, CaCert).

with_proxy(ServerPort, Mode, Fun, CaCert) ->
    {Proxy, Monitor, ProxyPort} = start_proxy(ServerPort, Mode),
    try
        Fun(ProxyPort, CaCert)
    after
        stop_proxy(Proxy, Monitor)
    end.

start_proxy(ServerPort, Mode) ->
    Parent = self(),
    ReadyRef = make_ref(),
    {Proxy, Monitor} = spawn_monitor(fun() ->
        start_proxy_socket(Parent, ReadyRef, ServerPort, Mode)
    end),
    receive
        {ReadyRef, ready, ProxyPort} ->
            {Proxy, Monitor, ProxyPort};
        {ReadyRef, error, Reason} ->
            await_proxy_down(Proxy, Monitor),
            erlang:error({proxy_start_failed, Reason});
        {'DOWN', Monitor, process, Proxy, Reason} ->
            erlang:error({proxy_start_failed, Reason})
    after ?FIXTURE_TIMEOUT ->
        exit(Proxy, kill),
        await_proxy_down(Proxy, Monitor),
        erlang:error(proxy_start_timeout)
    end.

start_proxy_socket(Parent, ReadyRef, ServerPort, Mode) ->
    case gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]) of
        {ok, Socket} ->
            {ok, {{127, 0, 0, 1}, ProxyPort}} = inet:sockname(Socket),
            Parent ! {ReadyRef, ready, ProxyPort},
            proxy_loop(Socket, ServerPort, Mode, undefined, initial_proxy_state(Mode));
        {error, Reason} ->
            Parent ! {ReadyRef, error, Reason}
    end.

initial_proxy_state(packet_loss) ->
    #{drop_client => true};
initial_proxy_state(duplication) ->
    #{duplicate_client => true};
initial_proxy_state(corruption) ->
    #{corrupt_client => true, corrupt_server => true};
initial_proxy_state(delay) ->
    #{delay_client => true};
initial_proxy_state(mtu_limit) ->
    #{dropped_large => 0};
initial_proxy_state(reordering) ->
    #{held_client => undefined, reordering_done => false}.

proxy_loop(Socket, ServerPort, Mode, Client, State) ->
    receive
        {udp, Socket, _Address, ServerPort, Packet} ->
            NewState = proxy_server_packet(Socket, Mode, Client, Packet, State),
            proxy_loop(Socket, ServerPort, Mode, Client, NewState);
        {udp, Socket, Address, ClientPort, Packet} ->
            NewState = proxy_client_packet(Socket, ServerPort, Mode, Packet, State),
            proxy_loop(Socket, ServerPort, Mode, {Address, ClientPort}, NewState);
        {forward_delayed_client, Packet} ->
            ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
            proxy_loop(Socket, ServerPort, Mode, Client, State);
        stop ->
            ensure_fault_was_exercised(Mode, State),
            gen_udp:close(Socket)
    after ?FIXTURE_TIMEOUT * 4 ->
        gen_udp:close(Socket)
    end.

proxy_client_packet(_Socket, _ServerPort, packet_loss, _Packet, #{drop_client := true} = State) ->
    State#{drop_client => false};
proxy_client_packet(
    Socket,
    ServerPort,
    duplication,
    Packet,
    #{duplicate_client := true} = State
) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
    State#{duplicate_client => false};
proxy_client_packet(
    Socket,
    ServerPort,
    corruption,
    Packet = <<First, _/binary>>,
    #{corrupt_client := true} = State
) when First band 16#80 =:= 0 ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, corrupt_packet(Packet)),
    State#{corrupt_client => false};
proxy_client_packet(
    _Socket,
    _ServerPort,
    delay,
    Packet,
    #{delay_client := true} = State
) ->
    _ = erlang:send_after(100, self(), {forward_delayed_client, Packet}),
    State#{delay_client => false};
proxy_client_packet(
    _Socket,
    _ServerPort,
    mtu_limit,
    Packet,
    #{dropped_large := Dropped} = State
) when byte_size(Packet) > 1200 ->
    State#{dropped_large => Dropped + 1};
proxy_client_packet(
    _Socket,
    _ServerPort,
    reordering,
    Packet,
    #{held_client := undefined, reordering_done := false} = State
) ->
    State#{held_client => Packet};
proxy_client_packet(
    Socket,
    ServerPort,
    reordering,
    Packet,
    #{held_client := Held, reordering_done := false} = State
) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Held),
    State#{held_client => undefined, reordering_done => true};
proxy_client_packet(Socket, ServerPort, _Mode, Packet, State) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, ServerPort, Packet),
    State.

corrupt_packet(Packet) when byte_size(Packet) > 0 ->
    PrefixSize = bit_size(Packet) - 8,
    <<Prefix:PrefixSize/bits, Last>> = Packet,
    <<Prefix/bits, (Last bxor 1)>>.

proxy_server_packet(_Socket, _Mode, undefined, _Packet, State) ->
    State;
proxy_server_packet(
    Socket,
    corruption,
    Client,
    Packet = <<First, _/binary>>,
    #{corrupt_server := true} = State
) when First band 16#80 =:= 0 ->
    ok = send_to_client(Socket, Client, corrupt_packet(Packet)),
    State#{corrupt_server => false};
proxy_server_packet(
    _Socket,
    mtu_limit,
    _Client,
    Packet,
    #{dropped_large := Dropped} = State
) when byte_size(Packet) > 1200 ->
    State#{dropped_large => Dropped + 1};
proxy_server_packet(Socket, _Mode, Client, Packet, State) ->
    ok = send_to_client(Socket, Client, Packet),
    State.

send_to_client(Socket, {Address, Port}, Packet) ->
    gen_udp:send(Socket, Address, Port, Packet).

ensure_fault_was_exercised(packet_loss, #{drop_client := true}) ->
    erlang:error(packet_loss_fault_not_exercised);
ensure_fault_was_exercised(duplication, #{duplicate_client := true}) ->
    erlang:error(duplication_fault_not_exercised);
ensure_fault_was_exercised(corruption, #{corrupt_client := true}) ->
    erlang:error(client_corruption_fault_not_exercised);
ensure_fault_was_exercised(corruption, #{corrupt_server := true}) ->
    erlang:error(server_corruption_fault_not_exercised);
ensure_fault_was_exercised(delay, #{delay_client := true}) ->
    erlang:error(delay_fault_not_exercised);
ensure_fault_was_exercised(reordering, #{reordering_done := false}) ->
    erlang:error(reordering_fault_not_exercised);
ensure_fault_was_exercised(mtu_limit, #{dropped_large := 0}) ->
    erlang:error(mtu_fault_not_exercised);
ensure_fault_was_exercised(_Mode, _State) ->
    ok.

stop_proxy(Proxy, Monitor) ->
    Proxy ! stop,
    case await_proxy_down(Proxy, Monitor) of
        normal -> ok;
        Reason -> erlang:error({proxy_stop_failed, Reason})
    end.

await_proxy_down(Proxy, Monitor) ->
    receive
        {'DOWN', Monitor, process, Proxy, Reason} -> Reason
    after ?FIXTURE_TIMEOUT ->
        exit(Proxy, kill),
        receive
            {'DOWN', Monitor, process, Proxy, Reason} -> Reason
        after ?FIXTURE_TIMEOUT ->
            demonitor(Monitor, [flush]),
            timeout
        end
    end.

read_certificate(Name) ->
    {ok, Pem} = file:read_file(fixture_path(Name)),
    [{_, Der, _}] = public_key:pem_decode(Pem),
    Der.

fixture_path(Name) ->
    filename:join(["test", "fixtures", Name]).
