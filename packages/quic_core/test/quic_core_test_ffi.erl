-module(quic_core_test_ffi).

-export([
    connection_handle/1,
    fixture/1,
    inject_relay_connection_reset/1,
    labelled_pid/2,
    linux_platform/0,
    mailbox_deliveries/1,
    mailbox_length/1,
    maximum_relay_batch/0,
    processes_labelled_under/2,
    socket_buffer_bytes/1,
    socket_dont_fragment_values/1,
    trace_frame_progress/3,
    traced_routed_connection_id/2
]).

%% IPPROTO_IP / IP_MTU_DISCOVER and IPPROTO_IPV6 / IPV6_MTU_DISCOVER, the
%% Linux socket options that carry the Don't-Fragment policy DPLPMTUD needs
%% (RFC 8899 section 3). Read back as native-endian 32-bit integers.
-define(IPPROTO_IP, 0).
-define(IP_MTU_DISCOVER, 10).
-define(IPPROTO_IPV6, 41).
-define(IPV6_MTU_DISCOVER, 23).

-spec inject_relay_connection_reset(term()) -> nil.
inject_relay_connection_reset(#{pid := Pid, socket := Socket}) ->
    Pid ! {udp_error, Socket, econnreset},
    timer:sleep(50),
    nil.

%% Count the live processes that carry one fixed `proc_lib:set_label/1` label
%% and were spawned by one owning actor, so topology tests can pin how many
%% actors of a role one endpoint owns right now without counting the leftovers
%% of any other endpoint.
-spec processes_labelled_under(binary(), pid()) -> integer().
processes_labelled_under(Label, Parent) ->
    length([Pid || Pid <- erlang:processes(),
                   proc_lib:get_label(Pid) =:= Label,
                   parent_of(Pid) =:= Parent]).

-spec parent_of(pid()) -> pid() | undefined.
parent_of(Pid) ->
    case erlang:process_info(Pid, parent) of
        {parent, Parent} when is_pid(Parent) -> Parent;
        _Other -> undefined
    end.

%% The relay's maximum batch, read straight from the transport FFI, so a test
%% pins the listener's delivery window against the value the relay actually
%% uses rather than against a copy of it.
-spec maximum_relay_batch() -> integer().
maximum_relay_batch() ->
    quic_core_udp_ffi:maximum_relay_batch().

%% Report the number of messages waiting in one connection actor's mailbox, so
%% a credit test can pin that a flooded connection actor never accumulates an
%% unbounded backlog of routed inbound batches. A dead process reports
%% `{error, nil}`.
-spec mailbox_length(pid()) -> {ok, integer()} | {error, nil}.
mailbox_length(Pid) when is_pid(Pid) ->
    case erlang:process_info(Pid, message_queue_len) of
        {message_queue_len, Length} -> {ok, Length};
        undefined -> {error, nil}
    end;
mailbox_length(_Other) ->
    {error, nil}.

%% Report one connection actor's mailbox as the credit window sees it: how
%% many messages are waiting, and for each message that carries routed inbound
%% datagrams, how many datagrams it carries and how many bytes they total.
%% Both halves of the listener's delivery window are then observable from a
%% test: the outstanding datagrams and bytes summed over the whole mailbox can
%% never exceed the window, and one message per relay batch -- rather than one
%% message per datagram -- shows up as a single message carrying many
%% datagrams. Read in one `process_info/2` call so the two views cannot drift.
-spec mailbox_deliveries(pid()) ->
    {ok, {integer(), [{integer(), integer()}]}} | {error, nil}.
mailbox_deliveries(Pid) when is_pid(Pid) ->
    case erlang:process_info(Pid, messages) of
        {messages, Messages} ->
            {ok, {length(Messages), delivery_sizes(Messages, [])}};
        undefined -> {error, nil}
    end;
mailbox_deliveries(_Other) ->
    {error, nil}.

-spec delivery_sizes([term()], [{integer(), integer()}]) ->
    [{integer(), integer()}].
delivery_sizes([], Sizes) ->
    lists:reverse(Sizes);
delivery_sizes([Message | Rest], Sizes) ->
    case routed_size(Message, 0, 0) of
        {0, 0} -> delivery_sizes(Rest, Sizes);
        Size -> delivery_sizes(Rest, [Size | Sizes])
    end.

%% Sum the routed datagrams nested anywhere inside one mailbox message, so the
%% seam does not depend on how a delivery command or its subject tag is shaped.
-spec routed_size(term(), integer(), integer()) -> {integer(), integer()}.
routed_size({routed_datagram, _Peer, Payload, _Marking}, Count, Bytes)
        when is_binary(Payload) ->
    {Count + 1, Bytes + byte_size(Payload)};
routed_size(Tuple, Count, Bytes) when is_tuple(Tuple) ->
    routed_size(tuple_to_list(Tuple), Count, Bytes);
routed_size([Head | Tail], Count, Bytes) ->
    {NextCount, NextBytes} = routed_size(Head, Count, Bytes),
    routed_size(Tail, NextCount, NextBytes);
routed_size(_Other, Count, Bytes) ->
    {Count, Bytes}.

-spec first_routed_id(term()) -> {ok, binary()} | {error, nil}.
first_routed_id({routed_datagram, _Peer, <<First, Id:8/binary, _/binary>>,
                 _Marking}) when First < 128 ->
    {ok, Id};
first_routed_id(Tuple) when is_tuple(Tuple) ->
    first_routed_id(tuple_to_list(Tuple));
first_routed_id([Head | Tail]) ->
    case first_routed_id(Head) of
        {ok, Id} -> {ok, Id};
        {error, nil} -> first_routed_id(Tail)
    end;
first_routed_id(_Other) ->
    {error, nil}.

%% Report the connection ID the listener routes to one actor by watching what
%% that actor receives rather than what is left waiting in its mailbox. A
%% connection whose owner keeps reading drains its mailbox as fast as the
%% listener fills it, so a mailbox poll is a race that a healthy connection
%% usually wins; a receive trace sees every routed datagram exactly once,
%% whether or not the actor has already taken it off the mailbox. The wait is
%% bounded by the caller and the trace is always turned off again.
-spec traced_routed_connection_id(pid(), integer()) ->
    {ok, binary()} | {error, nil}.
traced_routed_connection_id(Pid, BoundMilliseconds) when is_pid(Pid) ->
    erlang:trace(Pid, true, ['receive']),
    Deadline = erlang:monotonic_time(millisecond) + BoundMilliseconds,
    try
        await_traced_id(Pid, Deadline)
    after
        erlang:trace(Pid, false, ['receive'])
    end;
traced_routed_connection_id(_Other, _BoundMilliseconds) ->
    {error, nil}.

%% Run one bounded test action while tracing only payload-free STREAM and ACK
%% metadata at the core commit/receive boundary. The match specifications
%% compute payload byte lengths inside the VM and never send frame bytes or
%% connection state to the tracer mailbox. This makes the trace safe to retain
%% in an assertion failure even when the stream payload itself is sensitive.
-spec trace_frame_progress(pid(), pid(), fun(() -> Result)) ->
    {Result, [tuple()]} when Result :: term().
trace_frame_progress(Client, Server, Action)
        when is_pid(Client), is_pid(Server), is_function(Action, 0) ->
    Module = 'quic_core@internal@connection_state',
    Commit = {Module, commit_packet, 7},
    Receive = {Module, receive_packet, 6},
    Tick = {Module, tick, 2},
    _ = erlang:trace_pattern(Commit, commit_progress_spec(), []),
    _ = erlang:trace_pattern(Receive, receive_progress_spec(), []),
    _ = erlang:trace_pattern(Tick, tick_progress_spec(), []),
    _ = erlang:trace(Client, true, [call, {tracer, self()}]),
    _ = erlang:trace(Server, true, [call, {tracer, self()}]),
    try
        Result = Action(),
        %% The action's deadline and the transport's recovery deadline can be
        %% the same millisecond. Retain a short, fixed tail so the trace shows
        %% the event that lost the race instead of ending one scheduler turn
        %% before it. This delay is diagnostic-only and occurs after Result is
        %% already fixed.
        timer:sleep(100),
        stop_progress_trace([Client, Server], [Commit, Receive, Tick]),
        {Result, collect_progress_trace(Client, Server, 1024, [])}
    catch
        Class:Reason:Stacktrace ->
            stop_progress_trace([Client, Server], [Commit, Receive, Tick]),
            _ = collect_progress_trace(Client, Server, 1024, []),
            erlang:raise(Class, Reason, Stacktrace)
    end.

-spec commit_progress_spec() -> [tuple()].
commit_progress_spec() ->
    [stream_progress_clause(stream_commit, 7),
     stream_after_frame_clause(stream_commit, 7),
     ack_progress_clause(ack_commit, 7)].

-spec receive_progress_spec() -> [tuple()].
receive_progress_spec() ->
    [stream_progress_clause(stream_receive, 6),
     stream_after_frame_clause(stream_receive, 6),
     ack_progress_clause(ack_receive, 6)].

-spec stream_progress_clause(atom(), 6 | 7) -> tuple().
stream_progress_clause(Tag, 7) ->
    {['_', '_', '$1', [{stream, '$2', '$3', '$4', '$5'}],
      '_', '_', '$6'], [],
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]};
stream_progress_clause(Tag, 6) ->
    {['_', '_', '$1', [{stream, '$2', '$3', '$4', '$5'}], '_', '$6'], [],
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]}.

-spec stream_after_frame_clause(atom(), 6 | 7) -> tuple().
stream_after_frame_clause(Tag, 7) ->
    {['_', '_', '$1', ['_', {stream, '$2', '$3', '$4', '$5'}],
      '_', '_', '$6'], [],
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]};
stream_after_frame_clause(Tag, 6) ->
    {['_', '_', '$1', ['_', {stream, '$2', '$3', '$4', '$5'}], '_', '$6'],
     [],
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]}.

-spec ack_progress_clause(atom(), 6 | 7) -> tuple().
ack_progress_clause(Tag, 7) ->
    {['_', '_', '$1', [{ack, '_'}], '_', '_', '$2'], [],
     [{message, {{Tag, '$1', '$2'}}}]};
ack_progress_clause(Tag, 6) ->
    {['_', '_', '$1', [{ack, '_'}], '_', '$2'], [],
     [{message, {{Tag, '$1', '$2'}}}]}.

-spec tick_progress_spec() -> [tuple()].
tick_progress_spec() ->
    [{['_', '$1'], [], [{message, {{connection_tick, '$1'}}}]}].

-spec stop_progress_trace([pid()], [tuple()]) -> ok.
stop_progress_trace(Pids, Patterns) ->
    lists:foreach(fun(Pid) ->
        _ = erlang:trace(Pid, false, [call])
    end, Pids),
    lists:foreach(fun await_trace_delivery/1, Pids),
    lists:foreach(fun(Pattern) ->
        _ = erlang:trace_pattern(Pattern, false, [])
    end, Patterns),
    ok.

-spec await_trace_delivery(pid()) -> ok.
await_trace_delivery(Pid) ->
    Reference = erlang:trace_delivered(Pid),
    receive
        {trace_delivered, Pid, Reference} -> ok
    after 1000 ->
        ok
    end.

-spec collect_progress_trace(pid(), pid(), non_neg_integer(), [tuple()]) ->
    [tuple()].
collect_progress_trace(_Client, _Server, 0, Accumulated) ->
    lists:reverse(Accumulated);
collect_progress_trace(Client, Server, Remaining, Accumulated) ->
    receive
        {trace, Pid, call, _Mfa,
         {stream_commit, Packet, Stream, Offset, Bytes, Finished, At}} ->
            Event = {stream_committed, trace_endpoint(Pid, Client, Server),
                     Packet, Stream, Offset, Bytes, Finished, At},
            collect_progress_trace(Client, Server, Remaining - 1,
                                   [Event | Accumulated]);
        {trace, Pid, call, _Mfa,
         {stream_receive, Packet, Stream, Offset, Bytes, Finished, At}} ->
            Event = {stream_received, trace_endpoint(Pid, Client, Server),
                     Packet, Stream, Offset, Bytes, Finished, At},
            collect_progress_trace(Client, Server, Remaining - 1,
                                   [Event | Accumulated]);
        {trace, Pid, call, _Mfa, {ack_commit, Packet, At}} ->
            Event = {ack_committed, trace_endpoint(Pid, Client, Server),
                     Packet, At},
            collect_progress_trace(Client, Server, Remaining - 1,
                                   [Event | Accumulated]);
        {trace, Pid, call, _Mfa, {ack_receive, Packet, At}} ->
            Event = {ack_received, trace_endpoint(Pid, Client, Server),
                     Packet, At},
            collect_progress_trace(Client, Server, Remaining - 1,
                                   [Event | Accumulated]);
        {trace, Pid, call, _Mfa, {connection_tick, At}} ->
            Event = {connection_ticked,
                     trace_endpoint(Pid, Client, Server), At},
            collect_progress_trace(Client, Server, Remaining - 1,
                                   [Event | Accumulated])
    after 0 ->
        lists:reverse(Accumulated)
    end.

-spec trace_endpoint(pid(), pid(), pid()) -> client_endpoint | server_endpoint.
trace_endpoint(Client, Client, _Server) -> client_endpoint;
trace_endpoint(_Pid, _Client, _Server) -> server_endpoint.

-spec await_traced_id(pid(), integer()) -> {ok, binary()} | {error, nil}.
await_traced_id(Pid, Deadline) ->
    case Deadline - erlang:monotonic_time(millisecond) of
        Remaining when Remaining =< 0 ->
            {error, nil};
        Remaining ->
            receive
                {trace, Pid, 'receive', Message} ->
                    case first_routed_id(Message) of
                        {ok, Id} -> {ok, Id};
                        {error, nil} -> await_traced_id(Pid, Deadline)
                    end
            after Remaining ->
                {error, nil}
            end
    end.

%% Unwrap the connection actor handle inside one opaque public connection, so a
%% test can ask that actor for state no public API publishes. The public handle
%% is a single-field wrapper around the actor handle, so the actor handle is its
%% one payload; anything else is not a connection and is reported as such.
-spec connection_handle(term()) -> {ok, term()} | {error, nil}.
connection_handle(Handle) when is_tuple(Handle), tuple_size(Handle) =:= 2 ->
    {ok, element(2, Handle)};
connection_handle(_Other) ->
    {error, nil}.

%% Find the process behind one opaque public handle by its fixed role label, so
%% a lifecycle test can watch exactly the actor that handle names.
-spec labelled_pid(term(), binary()) -> {ok, pid()} | {error, nil}.
labelled_pid(Handle, Label) ->
    case labelled_pids(Handle, Label) of
        [Pid | _Rest] -> {ok, Pid};
        [] -> {error, nil}
    end.

-spec labelled_pids(term(), binary()) -> [pid()].
labelled_pids(Pid, Label) when is_pid(Pid) ->
    case proc_lib:get_label(Pid) =:= Label of
        true -> [Pid];
        false -> []
    end;
labelled_pids(Tuple, Label) when is_tuple(Tuple) ->
    labelled_pids(tuple_to_list(Tuple), Label);
labelled_pids(Map, Label) when is_map(Map) ->
    labelled_pids(maps:to_list(Map), Label);
labelled_pids([Head | Tail], Label) ->
    labelled_pids(Head, Label) ++ labelled_pids(Tail, Label);
labelled_pids(_Other, _Label) ->
    [].

%% Report the inet user-level receive buffer (`buffer`) of every socket behind
%% a production UDP handle, so tests can pin the per-datagram allocation size.
-spec socket_buffer_bytes(term()) -> [integer()].
socket_buffer_bytes(Handle) ->
    lists:filtermap(fun(Socket) ->
        case inet:getopts(Socket, [buffer, recbuf, sndbuf]) of
            {ok, Options} ->
                {buffer, Bytes} = lists:keyfind(buffer, 1, Options),
                {true, Bytes};
            {error, _Reason} -> false
        end
    end, handle_sockets(Handle)).

%% Report whether the Linux raw socket options this test reads back exist.
-spec linux_platform() -> boolean().
linux_platform() ->
    os:type() =:= {unix, linux}.

%% Report the kernel Don't-Fragment policy of every socket behind a production
%% UDP handle, so tests can pin that QUIC datagrams are never fragmented
%% locally. A socket whose option cannot be read reports -1.
-spec socket_dont_fragment_values(term()) -> [integer()].
socket_dont_fragment_values(#{socket := Socket6, ipv4_socket := Socket4}) ->
    [dont_fragment_value(Socket6, 6), dont_fragment_value(Socket4, 4)];
socket_dont_fragment_values(#{socket := Socket, family := Family}) ->
    [dont_fragment_value(Socket, Family)].

-spec dont_fragment_value(gen_udp:socket(), 4 | 6) -> integer().
dont_fragment_value(Socket, 4) ->
    raw_integer(Socket, ?IPPROTO_IP, ?IP_MTU_DISCOVER);
dont_fragment_value(Socket, 6) ->
    raw_integer(Socket, ?IPPROTO_IPV6, ?IPV6_MTU_DISCOVER).

-spec raw_integer(gen_udp:socket(), integer(), integer()) -> integer().
raw_integer(Socket, Level, Option) ->
    case inet:getopts(Socket, [{raw, Level, Option, 4}]) of
        {ok, [{raw, Level, Option, <<Value:32/native>>}]} -> Value;
        _Other -> -1
    end.

-spec handle_sockets(term()) -> [gen_udp:socket()].
handle_sockets(#{socket := Socket6, ipv4_socket := Socket4}) ->
    [Socket6, Socket4];
handle_sockets(#{socket := Socket}) ->
    [Socket].

-spec fixture(binary()) -> {ok, binary()} | {error, nil}.
fixture(Name) when Name =:= <<"ca.pem">>;
                   Name =:= <<"client.pem">>;
                   Name =:= <<"client-key.pem">>;
                   Name =:= <<"ecdsa-p256-server.pem">>;
                   Name =:= <<"ecdsa-p256-server-key.pem">>;
                   Name =:= <<"ecdsa-p384-server.pem">>;
                   Name =:= <<"ecdsa-p384-server-key.pem">>;
                   Name =:= <<"rsa-pss-server.pem">>;
                   Name =:= <<"rsa-pss-server-key.pem">>;
                   Name =:= <<"server.pem">>;
                   Name =:= <<"server-key.pem">> ->
    read_fixture(Name, [
        <<"../../test/fixtures/">>,
        <<"test/fixtures/">>
    ]);
fixture(_Name) ->
    {error, nil}.

-spec read_fixture(binary(), [binary()]) -> {ok, binary()} | {error, nil}.
read_fixture(_Name, []) ->
    {error, nil};
read_fixture(Name, [Prefix | Rest]) ->
    case file:read_file(<<Prefix/binary, Name/binary>>) of
        {ok, Bytes} -> {ok, Bytes};
        {error, _Reason} -> read_fixture(Name, Rest)
    end.
