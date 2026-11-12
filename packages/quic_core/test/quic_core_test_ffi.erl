-module(quic_core_test_ffi).

-export([
    bounded_test/2,
    hold_credit_until_drop/4,
    credit_barrier_contract/1,
    credit_trace_probe/4,
    connection_handle/1,
    delayed_send_reply_observation/0,
    send_observation_contract/1,
    send_while_actor_suspended/1,
    migration_without_spare_identifier/1,
    replenish_client_identifiers/1,
    rotate_server_peer_identifier/1,
    migration_rollback_observation/2,
    fixture/1,
    without_system_roots/1,
    inject_relay_connection_reset/1,
    await_relay_stopped/1,
    await_mailbox_command/3,
    labelled_pid/2,
    linux_platform/0,
    mailbox_deliveries/1,
    mailbox_length/1,
    maximum_relay_batch/0,
    processes_labelled_under/2,
    socket_buffer_bytes/1,
    socket_dont_fragment_values/1,
    trace_frame_progress/3,
    traced_routed_connection_id/2,
    with_quiescent_connection/2
]).

%% EUnit's ordinary five-second default also includes cold VM module loading
%% and TLS setup. Keep a finite whole-case descriptor independent of the
%% operation and resource bounds asserted by a live transport fixture.
-spec bounded_test(integer(), fun(() -> nil)) -> tuple().
bounded_test(Milliseconds, Run) when is_integer(Milliseconds), Milliseconds > 0,
                                    Milliseconds =< 60000, is_function(Run, 0) ->
    {timeout, Milliseconds / 1000, Run}.

%% Hold the receiving actor until the router has actually refused credit.
%% An isolated trace session emits at most ONE envelope: disable_trace runs
%% inside the tracee's match specification, before it can route another batch.
%% Arity removes all arguments from that envelope, including Admission's
%% datagrams. Only the positive scalar drop count reaches the caller.
%% The guardian owns the suspension, so its death also releases the actor.
-spec hold_credit_until_drop(pid(), pid(), 1..10000, fun(() -> A)) ->
    {A, {ok, pos_integer()} | {error, nil}}.
hold_credit_until_drop(Listener, Actor, Milliseconds, Action) ->
    credit_barrier(Listener, Actor, Milliseconds, Action,
        {'quic_core@internal@runtime@server_worker', take_within_credit, 4}).

credit_barrier(Listener, Actor, Milliseconds, Action, Mfa)
        when is_pid(Listener), is_pid(Actor), Listener =/= Actor,
             is_integer(Milliseconds), Milliseconds > 0, Milliseconds =< 10000,
             is_function(Action, 0) ->
    Owner = self(), Token = make_ref(),
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    {Guardian, Monitor} = spawn_opt(fun() ->
        credit_guardian(Owner, Token, Listener, Actor, Deadline, Mfa)
    end, [monitor, {max_heap_size, #{size => 131072, kill => true,
        error_logger => false, include_shared_binaries => true}}]),
    try
        receive
            {Token, ready} -> ok;
            {'DOWN', Monitor, process, Guardian, _} ->
                error(credit_barrier_setup_failed)
        after min(1000, Milliseconds) -> error(credit_barrier_setup_timeout)
        end,
        Result = Action(),
        Wait = max(0, Deadline - erlang:monotonic_time(millisecond)) + 1000,
        Observation = receive
            {Token, result, Value} -> Value;
            {'DOWN', Monitor, process, Guardian, _} ->
                error(credit_barrier_guardian_failed)
        after Wait -> error(credit_barrier_result_timeout)
        end,
        receive {'DOWN', Monitor, process, Guardian, normal} -> ok
        after 1000 -> error(credit_barrier_join_timeout)
        end,
        {Result, Observation}
    after
        Guardian ! {Token, stop},
        case is_process_alive(Guardian) of
            false -> ok;
            true ->
                receive {'DOWN', Monitor, process, Guardian, _} -> ok
                after 1000 ->
                    exit(Guardian, kill),
                    receive {'DOWN', Monitor, process, Guardian, _} -> ok
                    after 1000 -> error(credit_barrier_cleanup_timeout)
                    end
                end
        end,
        _ = demonitor(Monitor, [flush]),
        receive {Token, ready} -> ok after 0 -> ok end,
        receive {Token, result, _} -> ok after 0 -> ok end
    end.

credit_guardian(Owner, Token, Listener, Actor, Deadline, Mfa) ->
    OwnerMonitor = monitor(process, Owner),
    ListenerMonitor = monitor(process, Listener),
    ActorMonitor = monitor(process, Actor),
    Session = trace:session_create(credit_barrier, self(), []),
    Observation = try
        1 = trace:function(Session, Mfa, credit_drop_spec(), [local]),
        SuspendToken = make_ref(),
        true = erlang:suspend_process(Actor, [{asynchronous, SuspendToken}]),
        Wait = max(0, Deadline - erlang:monotonic_time(millisecond)),
        receive
            {SuspendToken, suspended} ->
                1 = trace:process(Session, Listener, true, [call, arity]),
                Owner ! {Token, ready},
                credit_drop_event(OwnerMonitor, ListenerMonitor, ActorMonitor,
                    Token, Listener, Deadline, Mfa);
            _ -> {error, nil}
        after Wait -> {error, nil}
        end
    after
        %% Cleanup precedes publication, including timeout, cancellation and
        %% owner/tracee death. A killed guardian releases its own suspension
        %% automatically; no unrelated suspension or trace session is touched.
        _ = trace:session_destroy(Session),
        try erlang:resume_process(Actor) catch error:badarg -> ok end,
        _ = demonitor(OwnerMonitor, [flush]),
        _ = demonitor(ListenerMonitor, [flush]),
        _ = demonitor(ActorMonitor, [flush])
    end,
    Owner ! {Token, result, Observation}.

credit_drop_spec() ->
    [{[[], '_', '_', {admission, '_', '_', '_', '$1'}],
      [{is_integer, '$1'}, {'>', '$1', 0}, {'=<', '$1', 4611686018427387903}],
      [{message, {{credit_exhausted, '$1'}}}, {disable_trace, call}]}].

credit_drop_event(OwnerMonitor, ListenerMonitor, ActorMonitor, Token,
                  Listener, Deadline, Mfa) ->
    Wait = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {trace, Listener, call, Mfa, {credit_exhausted, Count}}
                when is_integer(Count), Count > 0,
                     Count =< 4611686018427387903 -> {ok, Count};
        {'DOWN', OwnerMonitor, process, _, _} -> {error, nil};
        {'DOWN', ListenerMonitor, process, _, _} -> {error, nil};
        {'DOWN', ActorMonitor, process, _, _} -> {error, nil};
        {Token, stop} -> {error, nil};
        _ -> error(credit_barrier_invalid_envelope)
    after Wait -> {error, nil}
    end.

%% The probe deliberately carries private data in every argument position the
%% production Admission can occupy. It is used only by ordinary test leaves.
credit_trace_probe(_, _, _, _) -> nil.

-spec credit_barrier_contract(0..7) -> boolean().
credit_barrier_contract(Case) ->
    Sessions = lists:sort(trace:session_info(all)),
    {messages, Messages} = process_info(self(), messages),
    ok = credit_barrier_case(Case),
    Sessions = lists:sort(trace:session_info(all)),
    {messages, Messages} = process_info(self(), messages),
    true.

credit_barrier_case(0) ->
    %% Check the actual VM envelope and source-side one-shot bound directly.
    Session = trace:session_create(credit_contract, self(), []),
    Listener = spawn(fun credit_probe_loop/0),
    try
        1 = trace:function(Session, {?MODULE, credit_trace_probe, 4},
                           credit_drop_spec(), [local]),
        1 = trace:process(Session, Listener, true, [call, arity]),
        Listener ! {probe, 10000, self()},
        receive
            {trace, Listener, call, {?MODULE, credit_trace_probe, 4},
             {credit_exhausted, 7}} -> ok
        after 1000 -> error(credit_scalar_envelope_missing)
        end,
        receive probe_finished -> ok after 1000 -> error(credit_probe_timeout) end,
        Reference = trace:delivered(Session, Listener),
        receive {trace_delivered, Listener, Reference} -> ok
        after 1000 -> error(credit_probe_delivery_timeout)
        end,
        receive {trace, Listener, _, _, _} -> error(credit_probe_not_one_shot)
        after 0 -> ok end
    after
        _ = trace:session_destroy(Session),
        credit_stop_process(Listener)
    end;
credit_barrier_case(Case) when Case >= 1, Case =< 7 ->
    Actor = spawn(fun credit_actor_loop/0),
    Listener = spawn(fun credit_probe_loop/0),
    try
        credit_guard_contract(Case, Listener, Actor),
        case is_process_alive(Actor) of
            true ->
                Actor ! {ping, self()},
                receive pong -> ok after 1000 -> error(credit_actor_left_suspended) end;
            false -> ok
        end
    after
        credit_stop_process(Actor), credit_stop_process(Listener)
    end.

credit_guard_contract(1, Listener, Actor) ->
    {nil, {ok, 7}} = credit_barrier(Listener, Actor, 1000, fun() ->
        {status, suspended} = process_info(Actor, status),
        Listener ! {probe, 10000, self()},
        receive probe_finished -> nil after 1000 -> error(credit_probe_timeout) end
    end, {?MODULE, credit_trace_probe, 4}), ok;
credit_guard_contract(2, Listener, Actor) ->
    Started = erlang:monotonic_time(millisecond),
    {nil, {error, nil}} = credit_barrier(Listener, Actor, 40, fun() -> nil end,
                                       {?MODULE, credit_trace_probe, 4}),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    true = Elapsed >= 40 andalso Elapsed < 1000, ok;
credit_guard_contract(3, Listener, Actor) ->
    try credit_barrier(Listener, Actor, 1000, fun() ->
        throw(credit_action_failed)
    end, {?MODULE, credit_trace_probe, 4}) of
        _ -> error(credit_exception_lost)
    catch throw:credit_action_failed -> ok end;
credit_guard_contract(4, Listener, Actor) ->
    Parent = self(), Tag = make_ref(),
    {Owner, Monitor} = spawn_monitor(fun() ->
        credit_barrier(Listener, Actor, 1000, fun() ->
            Parent ! {Tag, ready}, receive stop -> nil end
        end, {?MODULE, credit_trace_probe, 4})
    end),
    receive {Tag, ready} -> ok after 1000 -> error(credit_owner_not_ready) end,
    {monitored_by, Watchers} = process_info(Owner, monitored_by),
    [Guardian] = lists:delete(self(), Watchers),
    GuardianMonitor = monitor(process, Guardian),
    exit(Owner, kill),
    receive {'DOWN', Monitor, process, Owner, killed} -> ok
    after 1000 -> error(credit_owner_join_timeout) end,
    receive {'DOWN', GuardianMonitor, process, Guardian, normal} -> ok
    after 1000 -> error(credit_guardian_leaked) end;
credit_guard_contract(5, Listener, Actor) ->
    {nil, {error, nil}} = credit_barrier(Listener, Actor, 1000, fun() ->
        credit_stop_process(Listener), nil
    end, {?MODULE, credit_trace_probe, 4}), ok;
credit_guard_contract(6, Listener, Actor) ->
    Session = trace:session_create(credit_independent, self(), []),
    try
        1 = trace:function(Session, {?MODULE, credit_trace_probe, 4},
            [{['_', '_', '_', '_'], [], [{message, independent_probe}]}], [local]),
        1 = trace:process(Session, Listener, true, [call, arity]),
        {nil, {ok, 7}} = credit_barrier(Listener, Actor, 1000, fun() ->
            Listener ! {probe, 2, self()},
            receive probe_finished -> nil after 1000 -> error(credit_probe_timeout) end
        end, {?MODULE, credit_trace_probe, 4}),
        %% Both calls remain visible to the independent observer even though
        %% the guardian's session disables itself during the first call.
        lists:foreach(fun(_) ->
            receive {trace, Listener, call, {?MODULE, credit_trace_probe, 4},
                     independent_probe} -> ok
            after 1000 -> error(credit_independent_trace_changed) end
        end, [1, 2])
    after _ = trace:session_destroy(Session) end;
credit_guard_contract(7, Listener, Actor) ->
    {nil, {error, nil}} = credit_barrier(Listener, Actor, 1000, fun() ->
        credit_stop_process(Actor), nil
    end, {?MODULE, credit_trace_probe, 4}), ok.

credit_actor_loop() ->
    receive
        {ping, Owner} -> Owner ! pong, credit_actor_loop()
    end.

credit_probe_loop() ->
    receive
        {probe, Count, Owner} ->
            Private = binary:copy(<<"private-credit-payload">>, 50000),
            lists:foreach(fun(_) ->
                ?MODULE:credit_trace_probe([], Private, {Private, self()},
                    {admission, [Private], 0, 0, 7})
            end, lists:seq(1, Count)),
            Owner ! probe_finished,
            credit_probe_loop()
    end.

credit_stop_process(Pid) ->
    Monitor = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Monitor, process, Pid, _} -> ok
    after 1000 -> error(credit_process_join_timeout)
    end.

%% A sequential test-only trust-store fixture. It uses OTP's real loader and
%% restores both its configuration and cache, including an originally absent cache.
-spec without_system_roots(fun(() -> A)) -> A.
without_system_roots(Run) ->
    {ok, _} = application:ensure_all_started(public_key),
    PreviousPath = application:get_env(public_key, cacerts_path),
    PreviousCache = persistent_term:get(pubkey_os_cacerts, not_loaded),
    Missing = filename:join(filename:dirname(code:which(?MODULE)),
        "missing-system-roots-" ++ integer_to_list(erlang:unique_integer([positive]))),
    false = filelib:is_file(Missing),
    ok = application:set_env(public_key, cacerts_path, Missing),
    _ = public_key:cacerts_clear(),
    try
        case quic_core_tls_ffi:system_trust_store() of
            {error, _} -> Run();
            {ok, _} -> erlang:error(system_roots_fixture_failed)
        end
    after
        case PreviousPath of
            {ok, Path} -> application:set_env(public_key, cacerts_path, Path);
            undefined -> application:unset_env(public_key, cacerts_path)
        end,
        case PreviousCache of
            not_loaded -> public_key:cacerts_clear();
            Cache -> persistent_term:put(pubkey_os_cacerts, Cache)
        end
    end.

%% A stand-in connection actor isolates the real public send wrapper's reply
%% deadline from UDP scheduling. The actor admits the command and then cannot
%% release its typed memory refusal until the caller has already returned.
%% The returned observation contains no subject, process, tag, or stream data.
-spec delayed_send_reply_observation() -> map().
delayed_send_reply_observation() ->
    Owner = self(),
    Token = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Commands = 'gleam@erlang@process':new_subject(),
        {subject, _, Tag} = Commands,
        Owner ! {Token, ready, Commands},
        receive
            {Tag, {send, _Stream, _Bytes, _Finish, Observation, Deadline}} ->
                true = quic_core_send_observation_ffi:park(Observation, true),
                Owner ! {Token, admitted, Observation, Deadline},
                receive
                    {Token, release} ->
                        Published = quic_core_send_observation_ffi:publish(
                            Observation, {error, endpoint_memory_exceeded}),
                        Owner ! {Token, replied, Published,
                                 quic_core_udp_ffi:monotonic_millisecond()}
                after 5000 -> exit(reply_barrier_timeout)
                end
        after 5000 -> exit(send_admission_timeout)
        end
    end),
    try
        Commands = receive
            {Token, ready, Subject} -> Subject
        after 1000 -> erlang:error(delayed_worker_start_timeout)
        end,
        Terminal = quic_core_terminal_close_ffi:new(),
        Handle = {stream, {stream, {connection, Commands, Worker, 25, Terminal}, 1}},
        Started = quic_core_udp_ffi:monotonic_millisecond(),
        Result = 'quic_core@server':send(Handle, <<1>>),
        Returned = quic_core_udp_ffi:monotonic_millisecond(),
        {Observation, Deadline} = receive
            {Token, admitted, Shared, At} -> {Shared, At}
        after 1000 -> erlang:error(delayed_worker_not_admitted)
        end,
        Worker ! {Token, release},
        {Published, Replied} = receive
            {Token, replied, Accepted, ReplyAt} -> {Accepted, ReplyAt}
        after 1000 -> erlang:error(delayed_worker_reply_timeout)
        end,
        #{tag := ReplyTag, state := State} = Observation,
        Residue = receive
            {ReplyTag, _} -> true
        after 0 -> false
        end,
        #{caller_result => Result,
          actor_result => {error, endpoint_memory_exceeded},
          publication_accepted => Published,
          caller_duration_milliseconds => Returned - Started,
          caller_deadline_elapsed => Returned >= Deadline,
          actor_replied_after_caller => Replied >= Returned,
          table_deleted => ets:info(State) =:= undefined,
          duplicate_reply => Residue}
    after
        exit(Worker, kill),
        receive
            {'DOWN', Monitor, process, Worker, _} -> ok
        after 1000 -> erlang:error(delayed_worker_cleanup_timeout)
        end
    end.

%% Runs the actual public send against a live connection actor, holding that
%% actor until the caller has expired. Resumption always happens before return.
-spec send_while_actor_suspended(term()) -> term().
send_while_actor_suspended(
        {stream, {stream, {connection, Commands, Worker, _, Terminal}, Identifier}}) ->
    true = erlang:suspend_process(Worker),
    try
        Handle = {stream, {stream, {connection, Commands, Worker, 25, Terminal}, Identifier}},
        'quic_core@server':send(Handle, <<"expired-must-not-arrive">>)
    after
        true = erlang:resume_process(Worker)
    end.

%% Fixed test cases exercise terminal ownership separately from UDP scheduling.
%% Every owned table, worker monitor and tagged notification must converge.
-spec send_observation_contract(0..7) -> boolean().
send_observation_contract(Case) ->
    Tables = owned_tables(),
    ok = observation_case(Case),
    Tables = owned_tables(),
    true.

observation_case(0) ->
    #{caller_result := {error, {failure, {overload, endpoint_memory}}},
      publication_accepted := false, table_deleted := true,
      caller_deadline_elapsed := true, actor_replied_after_caller := true,
      duplicate_reply := false, caller_duration_milliseconds := Duration} =
        delayed_send_reply_observation(),
    true = Duration < 2000,
    ok;
observation_case(1) ->
    Observation = quic_core_send_observation_ffi:new(),
    true = quic_core_send_observation_ffi:park(Observation, true),
    {deadline_expired, true} = quic_core_send_observation_ffi:await(Observation, self(), 0),
    false = quic_core_send_observation_ffi:park(Observation, false),
    false = quic_core_send_observation_ffi:publish(Observation, {ok, nil}),
    observation_closed(Observation);
observation_case(2) ->
    Observation = quic_core_send_observation_ffi:new(),
    true = quic_core_send_observation_ffi:park(Observation, true),
    true = quic_core_send_observation_ffi:park(Observation, false),
    {deadline_expired, false} = quic_core_send_observation_ffi:await(Observation, self(), 0),
    observation_closed(Observation);
observation_case(3) ->
    Observation = quic_core_send_observation_ffi:new(),
    Exact = {error, {stream_queue_failure, {send_buffer_limit_exceeded, 1234}}},
    true = quic_core_send_observation_ffi:publish(Observation, Exact),
    false = quic_core_send_observation_ffi:publish(Observation, {ok, nil}),
    false = quic_core_send_observation_ffi:park(Observation, false),
    {replied, Exact} = quic_core_send_observation_ffi:await(Observation, self(), 0),
    observation_closed(Observation);
observation_case(4) ->
    Observation = quic_core_send_observation_ffi:new(),
    #{state := State, alias := Alias, tag := Tag} = Observation,
    %% Hold notification at the private fixed-row publication boundary.
    1 = ets:select_replace(State, [{{1, pending, '_'}, [], [{const, {1, done, {ok, nil}}}]}]),
    {replied, {ok, nil}} = quic_core_send_observation_ffi:await(Observation, self(), 0),
    Alias ! {Tag, ready},
    observation_closed(Observation);
observation_case(5) ->
    Observation = quic_core_send_observation_ffi:new(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        true = quic_core_send_observation_ffi:publish(Observation, {ok, nil})
    end),
    join_fixture_worker(Worker, Monitor),
    {replied, {ok, nil}} = quic_core_send_observation_ffi:await(Observation, Worker, 1000),
    observation_closed(Observation);
observation_case(6) ->
    Owner = self(), Token = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Observation = quic_core_send_observation_ffi:new(),
        Owner ! {Token, Observation}
    end),
    Observation = receive {Token, Shared} -> Shared after 1000 -> error(owner_fixture_timeout) end,
    join_fixture_worker(Worker, Monitor),
    false = quic_core_send_observation_ffi:park(Observation, true),
    false = quic_core_send_observation_ffi:publish(Observation, {ok, nil}),
    observation_closed(Observation);
observation_case(7) ->
    lists:foreach(fun(_) -> observation_terminal_race() end, lists:seq(1, 250)).

observation_terminal_race() ->
    Observation = quic_core_send_observation_ffi:new(),
    true = quic_core_send_observation_ffi:park(Observation, true),
    Owner = self(), Token = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Published = quic_core_send_observation_ffi:publish(Observation, {ok, nil}),
        Owner ! {Token, Published}
    end),
    Outcome = quic_core_send_observation_ffi:await(Observation, Worker, 0),
    Published = receive {Token, Value} -> Value after 1000 -> error(race_fixture_timeout) end,
    case Published of
        true -> {replied, {ok, nil}} = Outcome;
        false -> {deadline_expired, true} = Outcome
    end,
    join_fixture_worker(Worker, Monitor),
    observation_closed(Observation).

join_fixture_worker(Worker, Monitor) ->
    receive
        {'DOWN', Monitor, process, Worker, normal} -> ok;
        {'DOWN', Monitor, process, Worker, Reason} -> error({fixture_exit, Reason})
    after 1000 ->
        exit(Worker, kill),
        receive {'DOWN', Monitor, process, Worker, _} -> ok after 1000 -> ok end,
        error(fixture_cleanup_timeout)
    end,
    false = is_process_alive(Worker),
    ok.

observation_closed(#{state := State, tag := Tag}) ->
    undefined = ets:info(State),
    receive {Tag, _} -> error(observation_mailbox_residue) after 0 -> ok end.

owned_tables() ->
    lists:sort([Table || Table <- ets:all(), ets:info(Table, owner) =:= self()]).

%% The real established driver/peer state comes from a finite in-memory TLS
%% handshake. No initial UDP socket is needed: refusal must precede opening a
%% replacement. On the old fallback path, close the newly opened test socket.
-spec migration_without_spare_identifier(term()) -> boolean().
migration_without_spare_identifier(Connection) ->
    State = {state, nil, Connection, none, version1, <<"sample">>, none, true},
    case 'quic_core@internal@runtime@client_transport':migrate(State) of
        {error, migration_unavailable} -> true;
        {ok, Next} ->
            _ = 'quic_core@internal@udp':close(element(2, Next)),
            false;
        _ -> false
    end.

%% Borrow only the in-memory runtime state. These fixtures allocate no socket
%% and delegate issuance/rotation to production functions unchanged.
-spec replenish_client_identifiers(term()) -> term().
replenish_client_identifiers(Connection) ->
    State = {state, nil, Connection, none, version1, <<"sample">>, none, true},
    case 'quic_core@internal@runtime@client_transport':replenish_local_connection_ids(State) of
        {ok, Next} -> {ok, element(3, Next)};
        Error -> Error
    end.

-spec rotate_server_peer_identifier(term()) -> term().
rotate_server_peer_identifier({state, Configuration, Connection, TicketIssued}) ->
    case 'quic_core@internal@runtime@connection':rotate_peer_connection_id(Connection) of
        {ok, Next} -> {ok, {state, Configuration, Next, TicketIssued}};
        Error -> Error
    end.

-spec migration_rollback_observation(term(), integer()) -> tuple().
migration_rollback_observation(Connection, Now) ->
    {ok, Original} = quic_core_udp_ffi:open(<<127,0,0,1>>, 0),
    try
        State = {state, Original, Connection, none, version1, <<"sample">>, none, true},
        {ok, Migrating} = 'quic_core@internal@runtime@client_transport':migrate_at(State, Now),
        Probe = element(2, Migrating),
        try
            Moved = element(3, Migrating),
            Before = runtime_peer_identifier(Moved),
            {ok, Expired} = 'quic_core@internal@runtime@connection':tick(Moved, Now + 10000),
            Outcome = 'quic_core@internal@runtime@client_transport':take_events(setelement(3, Migrating, Expired)),
            {Rotated, Refused} = case Outcome of
                {ok, {Next, _}} -> {Before =/= runtime_peer_identifier(element(3, Next)), false};
                {error, migration_unavailable} -> {false, true};
                %% Legacy shape retained only to prove the pre-fix failure.
                {Next, _} when is_tuple(Next) -> {Before =/= runtime_peer_identifier(element(3, Next)), false}
            end,
            {rollback_observation, Rotated, Refused,
             socket_is_closed(Original), socket_is_closed(Probe)}
        after _ = quic_core_udp_ffi:close(Probe)
        end
    after _ = quic_core_udp_ffi:close(Original)
    end.

runtime_peer_identifier(Connection) ->
    'quic_core@internal@driver':peer_connection_id(element(3, Connection)).

socket_is_closed(Socket) ->
    case quic_core_udp_ffi:local_endpoint(Socket) of
        {error, _} -> true;
        {ok, _} -> false
    end.

%% IPPROTO_IP / IP_MTU_DISCOVER and IPPROTO_IPV6 / IPV6_MTU_DISCOVER, the
%% Linux socket options that carry the Don't-Fragment policy DPLPMTUD needs
%% (RFC 8899 section 3). Read back as native-endian 32-bit integers.
-define(IPPROTO_IP, 0).
-define(IP_MTU_DISCOVER, 10).
-define(IPPROTO_IPV6, 41).
-define(IPV6_MTU_DISCOVER, 23).
-define(RELAY_BARRIER_TIMEOUT, 1000).

-spec inject_relay_connection_reset(term()) -> {ok, nil} | {error, nil}.
inject_relay_connection_reset(
        #{pid := Pid, reference := Reference, socket := Socket})
        when is_pid(Pid), is_reference(Reference) ->
    ProbeReference = make_ref(),
    Monitor = erlang:monitor(process, Pid),
    Deadline = erlang:monotonic_time(millisecond) + ?RELAY_BARRIER_TIMEOUT,
    %% Both messages have this process as sender. The relay's probe reply can
    %% therefore only arrive after it has handled the injected advisory and
    %% completed the deactivate/reactivate transition.
    Pid ! {udp_error, Socket, econnreset},
    Pid ! {quic_core_udp_probe, Reference, self(), ProbeReference},
    Remaining = max(0, Deadline - erlang:monotonic_time(millisecond)),
    Result = receive
        {quic_core_udp_probed, Reference, ProbeReference} -> {ok, nil};
        {'DOWN', Monitor, process, Pid, _Reason} -> {error, nil}
    after Remaining ->
        {error, nil}
    end,
    _ = erlang:demonitor(Monitor, [flush]),
    Result;
inject_relay_connection_reset(_Relay) ->
    {error, nil}.

-spec await_relay_stopped(term()) -> {ok, nil} | {error, nil}.
await_relay_stopped(#{pid := Pid, sockets := Sockets})
        when is_pid(Pid), is_list(Sockets), Sockets =/= [] ->
    Monitor = erlang:monitor(process, Pid),
    Deadline = erlang:monotonic_time(millisecond) + ?RELAY_BARRIER_TIMEOUT,
    Remaining = max(0, Deadline - erlang:monotonic_time(millisecond)),
    Down = receive
        {'DOWN', Monitor, process, Pid, _Reason} -> true
    after Remaining ->
        false
    end,
    _ = erlang:demonitor(Monitor, [flush]),
    case Down andalso lists:all(fun relay_socket_closed/1, Sockets) of
        true -> {ok, nil};
        false -> {error, nil}
    end;
await_relay_stopped(_Relay) ->
    {error, nil}.

relay_socket_closed(Socket) ->
    try inet:sockname(Socket) of
        {error, closed} -> true;
        {error, einval} -> true;
        {error, badarg} -> true;
        {error, _UnexpectedReason} -> false;
        {ok, _Endpoint} -> false
    catch
        error:badarg -> true;
        _Class:_UnexpectedReason -> false
    end.

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

%% Wait until one paused connection actor has an allowlisted command in its
%% mailbox. The projector returns only a boolean: subjects, payloads, stream
%% identifiers and process identities never cross the FFI boundary. Tests use
%% this as a causal synchronization point instead of sleeping and hoping a
%% caller managed to enqueue its operation.
-spec await_mailbox_command(pid(), 1..5, 1..10000) -> boolean().
await_mailbox_command(Pid, Code, Milliseconds)
        when is_pid(Pid), is_integer(Code), Code >= 1, Code =< 5,
             is_integer(Milliseconds), Milliseconds >= 1,
             Milliseconds =< 10000 ->
    Tag = case Code of
        1 -> accept_stream;
        2 -> 'receive';
        3 -> receive_datagram;
        4 -> ping;
        5 -> terminate_and_wait
    end,
    await_mailbox_command_loop(
        Pid, Tag, erlang:monotonic_time(millisecond) + Milliseconds
    );
await_mailbox_command(_Pid, _Code, _Milliseconds) ->
    false.

await_mailbox_command_loop(Pid, Tag, Deadline) ->
    case erlang:process_info(Pid, messages) of
        {messages, Messages} ->
            case lists:any(fun(Message) ->
                contains_command(Message, Tag, 0)
            end, Messages) of
                true -> true;
                false ->
                    case erlang:monotonic_time(millisecond) >= Deadline of
                        true -> false;
                        false ->
                            receive after 1 -> ok end,
                            await_mailbox_command_loop(Pid, Tag, Deadline)
                    end
            end;
        undefined -> false
    end.

contains_command(_Value, _Tag, Depth) when Depth >= 4 -> false;
contains_command(Value, Tag, _Depth)
        when is_tuple(Value), tuple_size(Value) >= 1,
             element(1, Value) =:= Tag -> true;
contains_command(Value, Tag, Depth) when is_tuple(Value) ->
    lists:any(fun(Element) -> contains_command(Element, Tag, Depth + 1) end,
              tuple_to_list(Value));
contains_command(_Value, _Tag, _Depth) -> false.

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
    Pids = lists:usort([Client, Server]),
    Patterns = [Commit, Receive, Tick],
    Owner = self(),
    Token = make_ref(),
    {Collector, Monitor} = spawn_opt(fun() ->
        OwnerMonitor = monitor(process, Owner),
        _ = erlang:trace_pattern(Commit, commit_progress_spec(), []),
        _ = erlang:trace_pattern(Receive, receive_progress_spec(), []),
        _ = erlang:trace_pattern(Tick, tick_progress_spec(), []),
        %% A match-spec message supplements the VM envelope; only `arity`
        %% prevents that envelope retaining every original call argument.
        lists:foreach(fun(Pid) ->
            _ = erlang:trace(Pid, true, [call, arity, {tracer, self()}])
        end, Pids),
        Owner ! {Token, ready},
        try
            progress_collector(Client, Server, Owner, OwnerMonitor, Token,
                               erlang:monotonic_time(millisecond) + 30000,
                               1023, [])
        after
            stop_progress_trace(Pids, Patterns)
        end
    end, [monitor, {message_queue_data, off_heap},
          {max_heap_size, #{size => 1048576, kill => true,
                            error_logger => false, include_shared_binaries => true}}]),
    try
        receive
            {Token, ready} -> ok;
            {'DOWN', Monitor, process, Collector, _} -> error(progress_trace_setup_failed)
        after 1000 -> error(progress_trace_setup_timeout)
        end,
        Result = Action(),
        %% The action's deadline and the transport's recovery deadline can be
        %% the same millisecond. Retain a short, fixed tail so the trace shows
        %% the event that lost the race instead of ending one scheduler turn
        %% before it. This delay is diagnostic-only and occurs after Result is
        %% already fixed.
        timer:sleep(100),
        %% Stop at the source, then use a delivery barrier before publishing
        %% the bounded prefix. The caller never receives trace envelopes.
        stop_progress_trace(Pids, Patterns),
        Collector ! {Token, finish},
        Events = receive
            {Token, events, Captured} -> Captured;
            {'DOWN', Monitor, process, Collector, _} -> error(progress_trace_collector_failed)
        after 1000 -> error(progress_trace_finish_timeout)
        end,
        receive {'DOWN', Monitor, process, Collector, normal} -> ok
        after 1000 -> error(progress_trace_join_timeout)
        end,
        {Result, Events}
    after
        stop_progress_trace(Pids, Patterns),
        case is_process_alive(Collector) of
            false -> ok;
            true ->
                exit(Collector, kill),
                receive {'DOWN', Monitor, process, Collector, _} -> ok
                after 1000 -> error(progress_trace_cleanup_timeout)
                end
        end,
        _ = demonitor(Monitor, [flush]),
        receive {Token, events, _} -> ok after 0 -> ok end,
        receive {Token, ready} -> ok after 0 -> ok end
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
      '_', '_', '$6'], stream_progress_guards(),
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]};
stream_progress_clause(Tag, 6) ->
    {['_', '_', '$1', [{stream, '$2', '$3', '$4', '$5'}], '_', '$6'], stream_progress_guards(),
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]}.

-spec stream_after_frame_clause(atom(), 6 | 7) -> tuple().
stream_after_frame_clause(Tag, 7) ->
    {['_', '_', '$1', ['_', {stream, '$2', '$3', '$4', '$5'}],
      '_', '_', '$6'], stream_progress_guards(),
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]};
stream_after_frame_clause(Tag, 6) ->
    {['_', '_', '$1', ['_', {stream, '$2', '$3', '$4', '$5'}], '_', '$6'],
     stream_progress_guards(),
     [{message, {{Tag, '$1', '$2', '$3', {byte_size, '$4'}, '$5', '$6'}}}]}.

-spec ack_progress_clause(atom(), 6 | 7) -> tuple().
ack_progress_clause(Tag, 7) ->
    {['_', '_', '$1', [{ack, '_'}], '_', '_', '$2'],
     progress_integer_guards('$1', 0, 4611686018427387903)
         ++ progress_integer_guards('$2', -9223372036854775808, 9223372036854775807),
     [{message, {{Tag, '$1', '$2'}}}]};
ack_progress_clause(Tag, 6) ->
    {['_', '_', '$1', [{ack, '_'}], '_', '$2'],
     progress_integer_guards('$1', 0, 4611686018427387903)
         ++ progress_integer_guards('$2', -9223372036854775808, 9223372036854775807),
     [{message, {{Tag, '$1', '$2'}}}]}.

-spec tick_progress_spec() -> [tuple()].
tick_progress_spec() ->
    [{['_', '$1'],
      progress_integer_guards('$1', -9223372036854775808, 9223372036854775807),
      [{message, {{connection_tick, '$1'}}}]}].

stream_progress_guards() ->
    lists:append([progress_integer_guards(Name, 0, 4611686018427387903)
                  || Name <- ['$1', '$2', '$3']])
        ++ [{is_binary, '$4'}, {is_boolean, '$5'}]
        ++ progress_integer_guards('$6', -9223372036854775808, 9223372036854775807).

progress_integer_guards(Name, Minimum, Maximum) ->
    [{is_integer, Name}, {'>=', Name, Minimum}, {'=<', Name, Maximum}].

-spec stop_progress_trace([pid()], [tuple()]) -> ok.
stop_progress_trace(Pids, Patterns) ->
    lists:foreach(fun(Pid) ->
        try erlang:trace(Pid, false, [call, arity])
        catch error:badarg -> ok end
    end, Pids),
    lists:foreach(fun await_trace_delivery/1, Pids),
    lists:foreach(fun(Pattern) ->
        _ = erlang:trace_pattern(Pattern, false, [])
    end, Patterns),
    ok.

-spec await_trace_delivery(pid()) -> ok.
await_trace_delivery(Pid) ->
    try erlang:trace_delivered(Pid) of
        Reference ->
            receive
                {trace_delivered, Pid, Reference} -> ok
            after 1000 -> error(progress_trace_delivery_timeout)
            end
    catch error:badarg -> ok end.

%% The collector drains concurrently with the action. After 1,023 events it
%% stops both trace sources and retains one explicit truncation marker. Its
%% heap and lifetime are independently finite even if trace delivery outruns it.
progress_collector(Client, Server, Owner, OwnerMonitor, Token, Deadline,
                   Remaining, Accumulated) ->
    Wait = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _} -> ok;
        {Token, finish} ->
            Owner ! {Token, events, lists:reverse(Accumulated)};
        Message ->
            case progress_event(Message, Client, Server) of
                {ok, Event} when Remaining > 0 ->
                    progress_collector(Client, Server, Owner, OwnerMonitor,
                        Token, Deadline, Remaining - 1, [Event | Accumulated]);
                {ok, _} when Remaining =:= 0 ->
                    lists:foreach(fun(Pid) ->
                        try erlang:trace(Pid, false, [call, arity])
                        catch error:badarg -> ok end
                    end, lists:usort([Client, Server])),
                    progress_collector(Client, Server, Owner, OwnerMonitor,
                        Token, Deadline, -1, [trace_truncated | Accumulated]);
                _ ->
                    progress_collector(Client, Server, Owner, OwnerMonitor,
                        Token, Deadline, Remaining, Accumulated)
            end
    after Wait -> error(progress_trace_lifetime_exceeded)
    end.

progress_event({trace, Pid, call,
                {'quic_core@internal@connection_state', Function, Arity}, Data},
               Client, Server) when Pid =:= Client; Pid =:= Server ->
    Endpoint = trace_endpoint(Pid, Client, Server),
    case {Function, Arity, Data} of
        {commit_packet, 7, {stream_commit, Packet, Stream, Offset, Bytes, Fin, At}} ->
            scalar_stream_event(stream_committed, Endpoint, Packet, Stream,
                                Offset, Bytes, Fin, At);
        {receive_packet, 6, {stream_receive, Packet, Stream, Offset, Bytes, Fin, At}} ->
            scalar_stream_event(stream_received, Endpoint, Packet, Stream,
                                Offset, Bytes, Fin, At);
        {commit_packet, 7, {ack_commit, Packet, At}} ->
            scalar_ack_event(ack_committed, Endpoint, Packet, At);
        {receive_packet, 6, {ack_receive, Packet, At}} ->
            scalar_ack_event(ack_received, Endpoint, Packet, At);
        {tick, 2, {connection_tick, At}} when is_integer(At),
                At >= -9223372036854775808, At =< 9223372036854775807 ->
            {ok, {connection_ticked, Endpoint, At}};
        _ -> invalid
    end;
progress_event(_, _, _) -> invalid.

scalar_stream_event(Tag, Endpoint, Packet, Stream, Offset, Bytes, Fin, At)
        when is_integer(Packet), Packet >= 0, Packet =< 4611686018427387903,
             is_integer(Stream), Stream >= 0, Stream =< 4611686018427387903,
             is_integer(Offset), Offset >= 0, Offset =< 4611686018427387903,
             is_integer(Bytes), Bytes >= 0, Bytes =< 4611686018427387903,
             is_boolean(Fin), is_integer(At),
             At >= -9223372036854775808, At =< 9223372036854775807 ->
    {ok, {Tag, Endpoint, Packet, Stream, Offset, Bytes, Fin, At}};
scalar_stream_event(_, _, _, _, _, _, _, _) -> invalid.

scalar_ack_event(Tag, Endpoint, Packet, At)
        when is_integer(Packet), Packet >= 0, Packet =< 4611686018427387903,
             is_integer(At), At >= -9223372036854775808,
             At =< 9223372036854775807 ->
    {ok, {Tag, Endpoint, Packet, At}};
scalar_ack_event(_, _, _, _) -> invalid.

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

%% Run one qlog/admission observation after the connection actor has reached a
%% causal loop barrier. Unlike an external suspend, the acknowledgement cannot
%% freeze the actor inside a synchronous budget request. The independently
%% supervised gate releases on an explicit callback action, owner death, or an
%% absolute deadline, and the actor confirms it left the barrier before the
%% helper returns.
-spec with_quiescent_connection(term(), fun((pid(), fun(() -> ok)) -> A)) -> A.
with_quiescent_connection(
        {connection, {connection, Commands, Worker, _, _}}, Run)
        when is_pid(Worker), is_function(Run, 2) ->
    Owner = self(), Token = make_ref(),
    Entered = 'gleam@erlang@process':new_subject(),
    Resumed = 'gleam@erlang@process':new_subject(),
    {subject, Owner, EnteredTag} = Entered,
    {subject, Owner, ResumedTag} = Resumed,
    Released = atomics:new(1, []),
    Gate = spawn(fun() -> diagnostic_gate(Owner, Token) end),
    GateMonitor = erlang:monitor(process, Gate),
    WorkerMonitor = erlang:monitor(process, Worker),
    Release = fun() -> release_diagnostic_gate(
        Gate, GateMonitor, Worker, WorkerMonitor, Token, ResumedTag, Released
    ) end,
    'gleam@erlang@process':send(
        Commands, {diagnostic_pause, Owner, Gate, Entered, Resumed}
    ),
    try
        receive
            {EnteredTag, nil} -> Run(Worker, Release);
            {'DOWN', WorkerMonitor, process, Worker, _} ->
                erlang:error(diagnostic_barrier_worker_exited);
            {'DOWN', GateMonitor, process, Gate, _} ->
                erlang:error(diagnostic_barrier_gate_exited)
        after 2000 ->
            erlang:error(diagnostic_barrier_entry_timeout)
        end
    after
        _ = Release(),
        _ = erlang:demonitor(WorkerMonitor, [flush]),
        _ = erlang:demonitor(GateMonitor, [flush]),
        receive {EnteredTag, nil} -> ok after 0 -> ok end,
        receive {ResumedTag, nil} -> ok after 0 -> ok end
    end;
with_quiescent_connection(_Connection, _Run) ->
    erlang:error(diagnostic_barrier_invalid_connection).

diagnostic_gate(Owner, Token) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    receive
        {Token, release} -> ok;
        {'DOWN', OwnerMonitor, process, Owner, _} -> ok
    after 8000 -> ok
    end,
    _ = erlang:demonitor(OwnerMonitor, [flush]),
    ok.

release_diagnostic_gate(
        Gate, GateMonitor, Worker, WorkerMonitor, Token, ResumedTag, Released) ->
    case atomics:compare_exchange(Released, 1, 0, 1) of
        ok ->
            Gate ! {Token, release},
            receive
                {ResumedTag, nil} -> ok;
                {'DOWN', WorkerMonitor, process, Worker, _} -> ok
            after 2000 ->
                erlang:error(diagnostic_barrier_resume_timeout)
            end,
            receive
                {'DOWN', GateMonitor, process, Gate, _} -> ok
            after 2000 ->
                erlang:error(diagnostic_barrier_gate_join_timeout)
            end;
        _ -> ok
    end.

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
                   Name =:= <<"server-key.pem">>;
                   Name =:= <<"weak-rsa1024-server.pem">>;
                   Name =:= <<"weak-rsa1024-server-key.pem">> ->
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
