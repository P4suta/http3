%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_client_ffi).

-export([
    activate_http3_candidate_before/5,
    activate_http3_candidate_within/5,
    adopt_http3_lease_before/3,
    adopt_http3_lease_within/3,
    await_http3_dial/1,
    attach_http3_resource/3,
    attach_resource/2,
    attach_reserved_socket/2,
    attach_reserved_socket_before/3,
    attach_reserved_socket_within/3,
    begin_http3_dial_before/4,
    begin_http3_dial_within/4,
    cancel_resource/1,
    checkin_resource/3,
    checkin_resource_within/4,
    checkout_resource/2,
    checkout_resource_within/3,
    checkin_socket/3,
    checkin_http2/6,
    call_http3_reuse_before/2,
    call_https_resolver/4,
    call_https_resolver_before/5,
    call_policy_adapter/2,
    call_policy_adapter_before/2,
    call_policy_adapter_registration_probe_before/3,
    cancel_race/1,
    claim_connection_close/1,
    cancel_resource_within/2,
    checkout_socket/2,
    checkout_http2/3,
    checkout_http3_shared_before/3,
    checkout_http3_shared_within/3,
    close/1,
    close_before/3,
    close_http2_pool/1,
    close_policy_store/1,
    drain/1,
    drain_http2_pool/1,
    expire_http3_dial_waiters_probe_within/3,
    is_closed/1,
    lifecycle_owner/1,
    lifecycle_pending_count/1,
    http3_dial_snapshot/1,
    http3_dial_snapshot/2,
    http3_shared_snapshot/1,
    http3_shared_snapshot/2,
    http3_close_deadline_probe/4,
    lifecycle_snapshot/1,
    mark_connection_released/1,
    new_connection_guard/0,
    new_http3_close_handle/1,
    new_http2_pool/3,
    new_http2_pool_with_handoff_probe/4,
    new_lifecycle/3,
    new_grouped_policy_store/3,
    new_lifecycle_with_handoff_probe/4,
    new_lifecycle_with_handoff_probe/5,
    new_policy_store/2,
    new_race_cancellation/0,
    policy_store_get/3,
    policy_store_list/2,
    policy_store_put/6,
    policy_store_put_grouped/7,
    policy_store_touch/3,
    register_socket/3,
    register_socket_before/4,
    register_socket_within/4,
    reserve_resource/2,
    reserve_resource_before/3,
    reserve_resource_within/3,
    settle_http3_dial_probe_within/3,
    replace_socket/3,
    replace_socket_before/4,
    replace_socket_within/4,
    race_cancelled/1,
    release_http3_lease_within/3,
    release_http3_lease_before/3,
    retire_http3_candidate_within/2,
    retire_http3_candidate_confirmed_before/2,
    retire_http3_candidate_confirmed_within/2,
    state/1,
    transfer_and_adopt_socket_owner/3,
    transfer_and_adopt_socket_owner_before/4,
    transfer_and_adopt_socket_owner_within/4,
    unregister_socket/1,
    unregister_socket_before/2,
    unregister_socket_within/2
]).

-define(OWNER_TIMEOUT, 10000).
-define(CLEANUP_TIMEOUT, 1000).
-define(GUARDED_CALLBACK_MAX_HEAP_WORDS, 16777216).
-define(HTTP3_LOGICAL_LEASE_FACTOR, 100).
-define(HTTP3_DIAL_WAITER_FACTOR, 100).
-define(HTTP3_LEASE_ACTIVE, 0).
-define(HTTP3_LEASE_RELEASED, 1).
-define(HTTP3_LEASE_TERMINAL_OWNED, 2).
-type lifecycle() :: #{state := atomics:atomics_ref(), owner := pid()}.
-type registration() :: {http_client_registration, pid(), reference()}.
-type owned_socket() :: {owned_socket, term(), pid(), reference()}.
-type pending_socket_handoff() ::
    {pending_socket_handoff, reference(), term(), pid(), reference(), pid(),
        reference(), integer()}.
-type http3_resource_owner() ::
    {http3_resource_owner, pid(), reference()}.
-type resource_owner() :: pid() | http3_resource_owner().
-type pending_resource_owner() :: {reference(), resource_owner()}.
-type pending_resource_checkout() ::
    {pending_resource_checkout, reference(), pid(), reference(), reference(),
        resource_owner(), reference(), binary(), term(), integer(), integer()}.
-type borrowed_resource_checkout() ::
    {borrowed_resource_checkout, reference(), pid(), reference(), resource_owner(),
        reference()}.
-type http3_lease() ::
    {http3_stream_lease, pid(), reference(), reference(), reference(),
        atomics:atomics_ref()}.
-type http3_lease_entry() ::
    {reference(), atomics:atomics_ref(), pid(), reference()}.
-type http3_shared_mode() :: accepting | draining | closing.
-type http3_dial_waiter() ::
    {reference(), pid(), reference(), reference(), integer()}.
-type http3_dial_attachment() ::
    none | {resource_owner(), reference()}.
-type http3_dial() ::
    {http3_dial, binary(), pid(), reference(), reference(), integer(),
        http3_dial_attachment(), [http3_dial_waiter()]}.
-type http3_dial_wait() ::
    {http3_dial_wait, pid(), reference(), reference(), reference(), integer()}.
-type http3_shared_resource() ::
    {shared_http3, resource_owner(), reference(), binary(), term(),
        http3_shared_mode(), none | integer(), reference(),
        [http3_lease_entry()]}.
-type closing_http3_candidate() ::
    {closing_http3_candidate, resource_owner(), reference(), integer()}.
-type registered_value() ::
    owned_socket()
    | pending_socket_handoff()
    | {resource_reservation, pid(), reference()}
    | {owned_resource, resource_owner(), reference()}
    | http3_dial()
    | http3_shared_resource()
    | closing_http3_candidate()
    | pending_resource_checkout()
    | borrowed_resource_checkout().
-type registered_socket() :: {reference(), binary(), registered_value()}.
-type pooled_socket() :: {binary(), reference(), term(), integer()}.
-type pool_limits() :: {pos_integer(), pos_integer(), pos_integer()}.
-type http2_pool() :: #{state := atomics:atomics_ref(), owner := pid()}.
-type cleanup() :: fun(() -> term()).
-type http2_session() :: {binary(), term(), term(), cleanup(), integer()}.
-type policy_store() :: #{state := atomics:atomics_ref(), owner := pid()}.
-type policy_item() ::
    {binary(), binary(), term(), integer(), pos_integer(), binary()}.

%% Publish an owner handle only after its fixed role is visible to the global
%% resource census. No endpoint or caller data is ever part of a label.
-spec spawn_labelled(binary(), fun(() -> no_return())) -> pid().
spawn_labelled(Label, Run) ->
    Parent = self(), Reference = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() ->
        labelled_init(Label, Run, Parent, Reference)
    end),
    receive
        {Reference, labelled} -> demonitor(Monitor, [flush]), Pid;
        {'DOWN', Monitor, process, Pid, _} -> erlang:error(client_owner_start_failed)
    after ?OWNER_TIMEOUT ->
        exit(Pid, kill),
        receive {'DOWN', Monitor, process, Pid, _} -> ok after 1000 -> ok end,
        demonitor(Monitor, [flush]),
        erlang:error(client_owner_start_timeout)
    end.

%% These owners terminate through exit/1 after their terminal cleanup. Keeping
%% that contract on a named entry point also describes the spawned closure.
-spec labelled_init(binary(), fun(() -> no_return()), pid(), reference()) ->
    no_return().
labelled_init(Label, Run, Parent, Reference) ->
    ok = proc_lib:set_label(Label),
    Parent ! {Reference, labelled},
    Run().

-spec call_policy_adapter(fun(), pos_integer()) ->
    {ok, term()} | {error, integer()}.
call_policy_adapter(Run, TimeoutMilliseconds)
    when is_function(Run, 0), is_integer(TimeoutMilliseconds),
         TimeoutMilliseconds > 0,
         TimeoutMilliseconds =< 2147483647 ->
    Started = erlang:monotonic_time(millisecond),
    call_policy_adapter_before(Run, Started + TimeoutMilliseconds);
call_policy_adapter(_Run, _TimeoutMilliseconds) ->
    {error, 1}.

%% Absolute production entrance. The relative compatibility wrapper above
%% constructs this boundary exactly once; no worker or supervisor rebases it.
-spec call_policy_adapter_before(fun(), integer()) ->
    {ok, term()} | {error, integer()}.
call_policy_adapter_before(Run, Deadline)
    when is_function(Run, 0), is_integer(Deadline) ->
    map_policy_adapter_result(call_guarded_client_callback_before(
        Run,
        Deadline,
        <<"http.client.policy_worker">>,
        <<"http.client.policy_supervisor">>,
        no_probe
    ));
call_policy_adapter_before(_Run, _Deadline) ->
    {error, 1}.

%% Payload-free internal synchronization contract used by deterministic
%% lifecycle tests. The observer receives actor identities and a fresh
%% reference only; no host, request, callback value, or exception is emitted.
-spec call_policy_adapter_registration_probe_before(fun(), integer(), pid()) ->
    {ok, term()} | {error, integer()}.
call_policy_adapter_registration_probe_before(Run, Deadline, Observer)
    when is_function(Run, 0), is_integer(Deadline), is_pid(Observer) ->
    ProbeReference = make_ref(),
    map_policy_adapter_result(call_guarded_client_callback_before(
        Run,
        Deadline,
        <<"http.client.policy_worker">>,
        <<"http.client.policy_supervisor">>,
        {registration_probe, Observer, ProbeReference}
    ));
call_policy_adapter_registration_probe_before(_Run, _Deadline, _Observer) ->
    {error, 1}.

-spec map_policy_adapter_result({ok, term()} | {error, integer()}) ->
    {ok, term()} | {error, integer()}.
map_policy_adapter_result({ok, {ok, Value}}) -> {ok, Value};
map_policy_adapter_result({ok, _Malformed}) -> {error, 1};
map_policy_adapter_result({error, 0}) -> {error, 2};
map_policy_adapter_result({error, 2}) -> {error, 2};
map_policy_adapter_result({error, _Failure}) -> {error, 1}.

%% Run the advisory HTTP/3 reuse query under a caller-owned absolute deadline.
%% The unlinked supervisor remains responsible for a blocked checker if the
%% calling exchange is killed. It publishes through a revocable alias only
%% after the checker monitor has delivered DOWN, then exits normally so the
%% caller can join both stages before accepting the result.
-spec call_http3_reuse_before(fun(() -> term()), integer()) ->
    {ok, term()} | {error, integer()}.
call_http3_reuse_before(Run, Deadline)
    when is_function(Run, 0), is_integer(Deadline) ->
    call_guarded_client_callback_before(
        Run,
        Deadline,
        <<"http.client.http3_reuse_checker">>,
        <<"http.client.http3_reuse_supervisor">>,
        no_probe
    );
call_http3_reuse_before(_Run, _Deadline) ->
    {error, 1}.

-spec call_guarded_client_callback_before(
    fun(() -> term()), integer(), binary(), binary(),
    no_probe | {registration_probe, pid(), reference()}
) -> {ok, term()} | {error, integer()}.
call_guarded_client_callback_before(
    Run, Deadline, WorkerLabel, SupervisorLabel, RegistrationProbe
) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        false ->
            {error, 0};
        true ->
            Caller = self(),
            Reference = make_ref(),
            ReplyAlias = erlang:alias(),
            CleanupDeadline = Deadline + ?CLEANUP_TIMEOUT,
            Result = case start_http3_reuse_worker(
                Caller, Reference, Run, WorkerLabel
            ) of
                {ok, Worker, WorkerMonitor} ->
                    call_http3_reuse_with_worker(
                        Caller, ReplyAlias, Reference, Worker, WorkerMonitor,
                        Deadline, CleanupDeadline, SupervisorLabel,
                        RegistrationProbe
                    );
                error ->
                    {error, 1}
            end,
            _ = erlang:unalias(ReplyAlias),
            flush_http3_reuse_reply(Reference),
            Result
    end.

-spec start_http3_reuse_worker(pid(), reference(), fun(() -> term()), binary()) ->
    {ok, pid(), reference()} | error.
start_http3_reuse_worker(Caller, Reference, Run, WorkerLabel) ->
    try spawn_opt(fun() ->
        http3_reuse_worker(Caller, Reference, Run, WorkerLabel)
    end, guarded_callback_spawn_options()) of
        {Worker, WorkerMonitor} -> {ok, Worker, WorkerMonitor}
    catch
        _Class:_Reason -> error
    end.

-spec call_http3_reuse_with_worker(
    pid(), reference(), reference(), pid(), reference(), integer(), integer(),
    binary(), no_probe | {registration_probe, pid(), reference()}
) -> {ok, term()} | {error, integer()}.
call_http3_reuse_with_worker(
    Caller, ReplyAlias, Reference, Worker, WorkerMonitor, Deadline,
    CleanupDeadline, SupervisorLabel, RegistrationProbe
) ->
    Result = case start_http3_reuse_supervisor(
        Caller, ReplyAlias, Reference, Worker, Deadline, CleanupDeadline,
        SupervisorLabel, RegistrationProbe
    ) of
        {ok, Supervisor, SupervisorMonitor} ->
            await_http3_reuse_supervisor(
                Supervisor, SupervisorMonitor, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline
            );
        error ->
            exit(Worker, kill),
            case join_http3_reuse_processes(
                none, none, true, Worker, WorkerMonitor, false,
                CleanupDeadline
            ) of
                true -> {error, 1};
                false -> {error, 2}
            end
    end,
    demonitor(WorkerMonitor, [flush]),
    Result.

-spec start_http3_reuse_supervisor(
    pid(), reference(), reference(), pid(), integer(), integer(), binary(),
    no_probe | {registration_probe, pid(), reference()}
) -> {ok, pid(), reference()} | error.
start_http3_reuse_supervisor(
    Caller, ReplyAlias, Reference, Worker, Deadline, CleanupDeadline,
    SupervisorLabel, RegistrationProbe
) ->
    try spawn_opt(fun() ->
        http3_reuse_supervisor(
            Caller, ReplyAlias, Reference, Worker, Deadline, CleanupDeadline,
            SupervisorLabel, RegistrationProbe
        )
    end, guarded_callback_spawn_options()) of
        {Supervisor, Monitor} -> {ok, Supervisor, Monitor}
    catch
        _Class:_Reason -> error
    end.

-spec guarded_callback_spawn_options() -> [term()].
guarded_callback_spawn_options() ->
    [
        monitor,
        {max_heap_size, #{
            size => ?GUARDED_CALLBACK_MAX_HEAP_WORDS,
            kill => true,
            error_logger => false,
            include_shared_binaries => true
        }}
    ].

-spec await_http3_reuse_supervisor(
    pid(), reference(), reference(), pid(), reference(), integer(), integer()
) -> {ok, term()} | {error, integer()}.
await_http3_reuse_supervisor(
    Supervisor, Monitor, Reference, Worker, WorkerMonitor, Deadline,
    CleanupDeadline
) ->
    Result = receive
        {Reference, http3_reuse_registered, Worker, RegistrationReference}
                when is_pid(Worker), is_reference(RegistrationReference) ->
            RegisteredResult = case erlang:monotonic_time(millisecond)
                < Deadline
            of
                true ->
                    Supervisor ! {
                        RegistrationReference, http3_reuse_start, self()
                    },
                    await_http3_reuse_outcome(
                        Supervisor, Monitor, Reference, Worker,
                        WorkerMonitor, Deadline, CleanupDeadline, none, false
                    );
                false ->
                    exit(Supervisor, kill),
                    exit(Worker, kill),
                    cleanup_http3_reuse_timeout(
                        Supervisor, Monitor, false, Worker, WorkerMonitor,
                        false, CleanupDeadline
                    )
            end,
            RegisteredResult;
        {'DOWN', Monitor, process, Supervisor, Reason} ->
            finish_http3_reuse_outcome(
                Reason, Supervisor, Monitor, true, Worker, WorkerMonitor,
                Deadline, CleanupDeadline, none, false
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            exit(Supervisor, kill),
            finish_http3_reuse_outcome(
                worker_down_before_registration,
                Supervisor, Monitor, false, Worker, WorkerMonitor,
                Deadline, CleanupDeadline, none, true
            )
    after deadline_remaining(Deadline) ->
        exit(Supervisor, kill),
        exit(Worker, kill),
        cleanup_http3_reuse_timeout(
            Supervisor, Monitor, false, Worker, WorkerMonitor, false,
            CleanupDeadline
        )
    end,
    demonitor(Monitor, [flush]),
    Result.

-spec await_http3_reuse_outcome(
    pid(), reference(), reference(), pid(), reference(), integer(),
    integer(), none | {some, term()}, boolean()
) -> {ok, term()} | {error, integer()}.
await_http3_reuse_outcome(
    Supervisor, SupervisorMonitor, Reference, Worker, WorkerMonitor,
    Deadline, CleanupDeadline, Outcome, WorkerDown
) ->
    receive
        {Reference, http3_reuse_result, Value} ->
            await_http3_reuse_outcome(
                Supervisor, SupervisorMonitor, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline, {some, Value},
                WorkerDown
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            await_http3_reuse_outcome(
                Supervisor, SupervisorMonitor, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline, Outcome, true
            );
        {'DOWN', SupervisorMonitor, process, Supervisor, Reason} ->
            finish_http3_reuse_outcome(
                Reason, Supervisor, SupervisorMonitor, true, Worker,
                WorkerMonitor, Deadline, CleanupDeadline, Outcome, WorkerDown
            )
    after deadline_remaining(Deadline) ->
        exit(Supervisor, kill),
        case WorkerDown of
            true -> ok;
            false -> exit(Worker, kill)
        end,
        cleanup_http3_reuse_timeout(
            Supervisor, SupervisorMonitor, false, Worker, WorkerMonitor,
            WorkerDown, CleanupDeadline
        )
    end.

-spec finish_http3_reuse_outcome(
    term(), pid(), reference(), boolean(), pid(), reference(), integer(),
    integer(), none | {some, term()}, boolean()
) -> {ok, term()} | {error, integer()}.
finish_http3_reuse_outcome(
    normal, Supervisor, SupervisorMonitor, true, Worker, WorkerMonitor,
    Deadline, CleanupDeadline, {some, Outcome}, WorkerDown
) ->
    case join_http3_reuse_processes(
        Supervisor, SupervisorMonitor, true, Worker, WorkerMonitor,
        WorkerDown, Deadline
    ) of
        true ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {ok, Outcome};
                false -> {error, 0}
            end;
        false ->
            exit(Worker, kill),
            case join_http3_reuse_processes(
                Supervisor, SupervisorMonitor, true, Worker, WorkerMonitor,
                false, CleanupDeadline
            ) of
                true -> {error, 0};
                false -> {error, 2}
            end
    end;
finish_http3_reuse_outcome(
    _Reason, Supervisor, SupervisorMonitor, SupervisorDown, Worker,
    WorkerMonitor, Deadline, CleanupDeadline, _Outcome, WorkerDown
) ->
    FailureCode = case erlang:monotonic_time(millisecond) < Deadline of
        true -> 1;
        false -> 0
    end,
    case SupervisorDown of
        true -> ok;
        false -> exit(Supervisor, kill)
    end,
    case WorkerDown of
        true -> ok;
        false -> exit(Worker, kill)
    end,
    case join_http3_reuse_processes(
        Supervisor, SupervisorMonitor, SupervisorDown, Worker, WorkerMonitor,
        WorkerDown, CleanupDeadline
    ) of
        true -> {error, FailureCode};
        false -> {error, 2}
    end.

-spec cleanup_http3_reuse_timeout(
    pid(), reference(), boolean(), pid(), reference(), boolean(), integer()
) -> {error, integer()}.
cleanup_http3_reuse_timeout(
    Supervisor, SupervisorMonitor, SupervisorDown, Worker, WorkerMonitor,
    WorkerDown, CleanupDeadline
) ->
    case join_http3_reuse_processes(
        Supervisor, SupervisorMonitor, SupervisorDown, Worker, WorkerMonitor,
        WorkerDown, CleanupDeadline
    ) of
        true -> {error, 0};
        false -> {error, 2}
    end.

-spec join_http3_reuse_processes(
    none | pid(), none | reference(), boolean(), pid(), reference(), boolean(),
    integer()
) -> boolean().
join_http3_reuse_processes(
    _Supervisor, _SupervisorMonitor, true, _Worker, _WorkerMonitor, true,
    _Deadline
) ->
    true;
join_http3_reuse_processes(
    Supervisor, SupervisorMonitor, false, Worker, WorkerMonitor, false, Deadline
) ->
    receive
        {'DOWN', SupervisorMonitor, process, Supervisor, _Reason} ->
            join_http3_reuse_processes(
                Supervisor, SupervisorMonitor, true, Worker, WorkerMonitor,
                false, Deadline
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            join_http3_reuse_processes(
                Supervisor, SupervisorMonitor, false, Worker, WorkerMonitor,
                true, Deadline
            )
    after deadline_remaining(Deadline) ->
        false
    end;
join_http3_reuse_processes(
    Supervisor, SupervisorMonitor, false, _Worker, _WorkerMonitor, true, Deadline
) ->
    receive
        {'DOWN', SupervisorMonitor, process, Supervisor, _Reason} -> true
    after deadline_remaining(Deadline) ->
        false
    end;
join_http3_reuse_processes(
    _Supervisor, _SupervisorMonitor, true, Worker, WorkerMonitor, false, Deadline
) ->
    receive
        {'DOWN', WorkerMonitor, process, Worker, _Reason} -> true
    after deadline_remaining(Deadline) ->
        false
    end.

-spec http3_reuse_supervisor(
    pid(), reference(), reference(), pid(), integer(), integer(), binary(),
    no_probe | {registration_probe, pid(), reference()}
) -> ok.
http3_reuse_supervisor(
    Caller, ReplyAlias, Reference, Worker, Deadline, CleanupDeadline,
    SupervisorLabel, RegistrationProbe
) ->
    ok = proc_lib:set_label(SupervisorLabel),
    process_flag(trap_exit, true),
    CallerMonitor = monitor(process, Caller),
    WorkerMonitor = monitor(process, Worker),
    link(Worker),
    RegistrationReference = make_ref(),
    case guarded_callback_registration_probe(
        RegistrationProbe,
        Caller,
        CallerMonitor,
        Worker,
        Deadline
    ) of
        caller_down ->
            terminate_http3_reuse_worker(
                CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
            );
        timed_out ->
            terminate_http3_reuse_worker(
                CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
            );
        continue ->
            case erlang:monotonic_time(millisecond) < Deadline
                andalso erlang:is_process_alive(Caller)
                andalso erlang:is_process_alive(Worker)
            of
                false ->
                    terminate_http3_reuse_worker(
                        CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
                    );
                true ->
                    ReplyAlias ! {
                        Reference,
                        http3_reuse_registered,
                        Worker,
                        RegistrationReference
                    },
                    http3_reuse_supervisor_wait_for_start(
                        Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                        WorkerMonitor, RegistrationReference, Deadline,
                        CleanupDeadline
                    )
            end
    end.

-spec guarded_callback_registration_probe(
    no_probe | {registration_probe, pid(), reference()},
    pid(), reference(), pid(), integer()
) -> continue | caller_down | timed_out.
guarded_callback_registration_probe(
    no_probe, _Caller, _CallerMonitor, _Worker, _Deadline
) ->
    continue;
guarded_callback_registration_probe(
    {registration_probe, Observer, ProbeReference},
    Caller,
    CallerMonitor,
    Worker,
    Deadline
) ->
    Observer ! {
        http_client_guarded_callback_pre_registration,
        ProbeReference,
        self(),
        Worker
    },
    receive
        {ProbeReference, continue_registration} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> continue;
                false -> timed_out
            end;
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            caller_down
    after deadline_remaining(Deadline) ->
        timed_out
    end.

-spec http3_reuse_worker(pid(), reference(), fun(() -> term()), binary()) -> ok.
http3_reuse_worker(Caller, Reference, Run, WorkerLabel) ->
    %% The caller owns this monitor before either supervisor creation or
    %% arbitrary callback code, closing both pre-registration death windows.
    process_flag(trap_exit, false),
    ok = proc_lib:set_label(WorkerLabel),
    CallerMonitor = monitor(process, Caller),
    receive
        {Reference, http3_reuse_start, Supervisor} when is_pid(Supervisor) ->
            demonitor(CallerMonitor, [flush]),
            Message = try Run() of
                Outcome -> {
                    Reference, http3_reuse_worker_result, self(), Outcome
                }
            catch
                _Class:_Reason -> {
                    Reference, http3_reuse_worker_failed, self()
                }
            end,
            Supervisor ! Message,
            ok;
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            ok
    end.

-spec http3_reuse_supervisor_wait_for_start(
    pid(), reference(), reference(), reference(), pid(), reference(),
    reference(), integer(), integer()
) -> ok.
http3_reuse_supervisor_wait_for_start(
    Caller, CallerMonitor, ReplyAlias, Reference, Worker, WorkerMonitor,
    RegistrationReference, Deadline, CleanupDeadline
) ->
    receive
        {RegistrationReference, http3_reuse_start, Caller} ->
            case erlang:monotonic_time(millisecond) < Deadline
                andalso erlang:is_process_alive(Caller)
            of
                true ->
                    Worker ! {Reference, http3_reuse_start, self()},
                    http3_reuse_supervisor_wait(
                        Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                        WorkerMonitor, Deadline, CleanupDeadline
                    );
                false ->
                    terminate_http3_reuse_worker(
                        CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
                    )
            end;
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            terminate_http3_reuse_worker(
                CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            demonitor(CallerMonitor, [flush]),
            ok;
        {'EXIT', Worker, _Reason} ->
            http3_reuse_supervisor_wait_for_start(
                Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                WorkerMonitor, RegistrationReference, Deadline,
                CleanupDeadline
            )
    after deadline_remaining(Deadline) ->
        terminate_http3_reuse_worker(
            CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
        )
    end,
    ok.

-spec http3_reuse_supervisor_wait(
    pid(), reference(), reference(), reference(), pid(), reference(), integer(),
    integer()
) -> ok.
http3_reuse_supervisor_wait(
    Caller, CallerMonitor, ReplyAlias, Reference, Worker, WorkerMonitor,
    Deadline, CleanupDeadline
) ->
    receive
        {Reference, http3_reuse_worker_result, Worker, Outcome} ->
            await_http3_reuse_worker_down(
                Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline, {ok, Outcome}
            );
        {Reference, http3_reuse_worker_failed, Worker} ->
            await_http3_reuse_worker_down(
                Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline, error
            );
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            terminate_http3_reuse_worker(
                CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
            );
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            demonitor(CallerMonitor, [flush]),
            ok;
        {'EXIT', Worker, _Reason} ->
            http3_reuse_supervisor_wait(
                Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline
            )
    after deadline_remaining(Deadline) ->
        terminate_http3_reuse_worker(
            CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
        )
    end.

-spec await_http3_reuse_worker_down(
    pid(), reference(), reference(), reference(), pid(), reference(), integer(),
    integer(), {ok, term()} | error
) -> ok.
await_http3_reuse_worker_down(
    Caller, CallerMonitor, ReplyAlias, Reference, Worker, WorkerMonitor,
    Deadline, CleanupDeadline, Outcome
) ->
    receive
        {'DOWN', WorkerMonitor, process, Worker, _Reason} ->
            demonitor(CallerMonitor, [flush]),
            case {
                Outcome,
                erlang:is_process_alive(Caller),
                erlang:monotonic_time(millisecond) < Deadline
            } of
                {{ok, Value}, true, true} ->
                    ReplyAlias ! {Reference, http3_reuse_result, Value},
                    ok;
                {_, _, _} ->
                    ok
            end;
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            terminate_http3_reuse_worker(
                CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
            );
        {'EXIT', Worker, _Reason} ->
            await_http3_reuse_worker_down(
                Caller, CallerMonitor, ReplyAlias, Reference, Worker,
                WorkerMonitor, Deadline, CleanupDeadline, Outcome
            )
    after deadline_remaining(Deadline) ->
        terminate_http3_reuse_worker(
            CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
        )
    end.

-spec terminate_http3_reuse_worker(
    reference(), pid(), reference(), integer()
) -> ok.
terminate_http3_reuse_worker(
    CallerMonitor, Worker, WorkerMonitor, CleanupDeadline
) ->
    exit(Worker, kill),
    _ = receive
        {'DOWN', WorkerMonitor, process, Worker, _Reason} -> joined;
        {'EXIT', Worker, _Reason} ->
            receive
                {'DOWN', WorkerMonitor, process, Worker, _DownReason} -> joined
            after deadline_remaining(CleanupDeadline) -> unconfirmed
            end
    after deadline_remaining(CleanupDeadline) ->
        unconfirmed
    end,
    demonitor(WorkerMonitor, [flush]),
    demonitor(CallerMonitor, [flush]),
    ok.

-spec flush_http3_reuse_reply(reference()) -> ok.
flush_http3_reuse_reply(Reference) ->
    receive
        {Reference, http3_reuse_registered, _Worker,
         _RegistrationReference} ->
            flush_http3_reuse_reply(Reference);
        {Reference, http3_reuse_result, _Outcome} ->
            flush_http3_reuse_reply(Reference)
    after 0 ->
        ok
    end.

-spec call_https_resolver(fun(), binary(), integer(), pos_integer()) ->
    {ok, [term()]} | {error, integer()}.
call_https_resolver(Resolver, Host, Port, TimeoutMilliseconds)
    when is_function(Resolver, 3), is_binary(Host),
         is_integer(Port), Port > 0, Port =< 65535,
         is_integer(TimeoutMilliseconds),
         TimeoutMilliseconds > 0, TimeoutMilliseconds =< 2147483647 ->
    Started = erlang:monotonic_time(millisecond),
    call_https_resolver_before(
        Resolver,
        Host,
        Port,
        TimeoutMilliseconds,
        Started + TimeoutMilliseconds
    );
call_https_resolver(_Resolver, _Host, _Port, _TimeoutMilliseconds) ->
    {error, 1}.

%% The callback's finite allocation and its phase boundary are intentionally
%% distinct. The allocation is passed through unchanged, while this FFI and
%% every lifecycle actor retain the supplied absolute deadline.
-spec call_https_resolver_before(
    fun(), binary(), integer(), pos_integer(), integer()
) -> {ok, [term()]} | {error, integer()}.
call_https_resolver_before(
    Resolver, Host, Port, AllocatedMilliseconds, Deadline
)
    when is_function(Resolver, 3), is_binary(Host),
         is_integer(Port), Port > 0, Port =< 65535,
         is_integer(AllocatedMilliseconds), AllocatedMilliseconds > 0,
         AllocatedMilliseconds =< 2147483647,
         is_integer(Deadline) ->
    Outcome = call_guarded_client_callback_before(
        fun() -> Resolver(Host, Port, AllocatedMilliseconds) end,
        Deadline,
        <<"http.client.https_resolver_worker">>,
        <<"http.client.https_resolver_supervisor">>,
        no_probe
    ),
    map_https_resolver_result(Outcome);
call_https_resolver_before(
    _Resolver, _Host, _Port, _AllocatedMilliseconds, _Deadline
) ->
    {error, 1}.

-spec map_https_resolver_result({ok, term()} | {error, integer()}) ->
    {ok, [term()]} | {error, integer()}.
map_https_resolver_result({ok, {ok, Records}}) when is_list(Records) ->
    {ok, Records};
map_https_resolver_result({ok, _Malformed}) -> {error, 1};
map_https_resolver_result({error, 0}) -> {error, 2};
map_https_resolver_result({error, 2}) -> {error, 2};
map_https_resolver_result({error, _Failure}) -> {error, 1}.

-spec new_policy_store(integer(), integer()) -> policy_store().
new_policy_store(MaximumEntries, MaximumBytes)
    when MaximumEntries > 0, MaximumEntries =< 65536,
         MaximumBytes > 0, MaximumBytes =< 67108864 ->
    %% A store whose items carry no group has no group ceiling to reach, so the
    %% whole entry ceiling stands in for it.
    new_grouped_policy_store(MaximumEntries, MaximumBytes, MaximumEntries);
new_policy_store(_MaximumEntries, _MaximumBytes) ->
    new_policy_store(1, 1).

%% A store whose items carry a group, none of which may occupy more than
%% MaximumPerGroup entries once the store is over its own ceiling.
-spec new_grouped_policy_store(integer(), integer(), integer()) ->
    policy_store().
new_grouped_policy_store(MaximumEntries, MaximumBytes, MaximumPerGroup)
    when MaximumEntries > 0, MaximumEntries =< 65536,
         MaximumBytes > 0, MaximumBytes =< 67108864,
         MaximumPerGroup > 0, MaximumPerGroup =< MaximumEntries ->
    State = atomics:new(1, [{signed, false}]),
    Owner = spawn_labelled(<<"http.policy_store">>, fun() ->
        policy_store_loop(
            State, [], MaximumEntries, MaximumBytes, MaximumPerGroup
        )
    end),
    #{state => State, owner => Owner};
new_grouped_policy_store(_MaximumEntries, _MaximumBytes, _MaximumPerGroup) ->
    new_grouped_policy_store(1, 1, 1).

-spec policy_store_put(
    policy_store(), binary(), binary(), term(), integer(), integer()
) -> boolean().
policy_store_put(Store, Partition, Key, Value, ExpiresAt, RetainedBytes) ->
    policy_store_put_grouped(
        Store, Partition, Key, Value, ExpiresAt, RetainedBytes, <<>>
    ).

-spec policy_store_put_grouped(
    policy_store(), binary(), binary(), term(), integer(), integer(), binary()
) -> boolean().
policy_store_put_grouped(
    #{state := State, owner := Owner},
    Partition,
    Key,
    Value,
    ExpiresAt,
    RetainedBytes,
    Group
) when is_binary(Partition), is_binary(Key), is_binary(Group),
       is_integer(ExpiresAt), RetainedBytes > 0 ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Owner ! {
                policy_put,
                self(),
                Reference,
                Partition,
                Key,
                Value,
                ExpiresAt,
                RetainedBytes,
                Group
            },
            receive
                {Reference, Stored} when is_boolean(Stored) -> Stored
            after ?OWNER_TIMEOUT ->
                false
            end;
        _ -> false
    end;
policy_store_put_grouped(
    _Store, _Partition, _Key, _Value, _ExpiresAt, _Bytes, _Group
) ->
    false.

-spec policy_store_list(policy_store(), binary()) -> [term()].
policy_store_list(#{state := State, owner := Owner}, Partition)
    when is_binary(Partition) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Owner ! {policy_list, self(), Reference, Partition},
            receive
                {Reference, Values} when is_list(Values) -> Values
            after ?OWNER_TIMEOUT ->
                []
            end;
        _ -> []
    end;
policy_store_list(_Store, _Partition) ->
    [].

-spec policy_store_get(policy_store(), binary(), binary()) ->
    {ok, term()} | {error, integer()}.
policy_store_get(#{state := State, owner := Owner}, Partition, Key)
    when is_binary(Partition), is_binary(Key) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Owner ! {policy_get, self(), Reference, Partition, Key},
            receive
                {Reference, {ok, Value}} -> {ok, Value};
                {Reference, missing} -> {error, 0}
            after ?OWNER_TIMEOUT ->
                {error, 1}
            end;
        _ -> {error, 1}
    end;
policy_store_get(_Store, _Partition, _Key) ->
    {error, 1}.

-spec policy_store_touch(policy_store(), binary(), [binary()]) -> nil.
policy_store_touch(_Store, _Partition, []) ->
    nil;
policy_store_touch(#{state := State, owner := Owner}, Partition, Keys)
    when is_binary(Partition), is_list(Keys), length(Keys) =< 65536 ->
    case safe_state(State) of
        0 ->
            case lists:all(fun erlang:is_binary/1, Keys) of
                true ->
                    Reference = make_ref(),
                    Owner ! {policy_touch, self(), Reference, Partition, Keys},
                    receive
                        {Reference, done} -> nil
                    after ?OWNER_TIMEOUT ->
                        nil
                    end;
                false -> nil
            end;
        _ -> nil
    end;
policy_store_touch(_Store, _Partition, _Keys) ->
    nil.

-spec close_policy_store(policy_store()) -> nil.
close_policy_store(#{state := State, owner := Owner}) ->
    case atomics:exchange(State, 1, 1) of
        0 ->
            Reference = make_ref(),
            Owner ! {policy_close, self(), Reference},
            receive
                {Reference, done} -> nil
            after ?OWNER_TIMEOUT ->
                nil
            end;
        _ -> nil
    end;
close_policy_store(_Store) ->
    nil.

-spec policy_store_loop(
    atomics:atomics_ref(), [policy_item()], pos_integer(), pos_integer(),
    pos_integer()
) -> no_return().
policy_store_loop(State, Existing, MaximumEntries, MaximumBytes, PerGroup) ->
    Now = erlang:monotonic_time(millisecond),
    Items = prune_policy_items(Existing, Now, []),
    Continue = fun(Next) ->
        policy_store_loop(State, Next, MaximumEntries, MaximumBytes, PerGroup)
    end,
    receive
        {
            policy_put,
            Sender,
            Reference,
            Partition,
            Key,
            Value,
            ExpiresAt,
            RetainedBytes,
            Group
        } ->
            WithoutPrevious = remove_policy_item(
                Partition, Key, Items, []
            ),
            case RetainedBytes =< MaximumBytes of
                false ->
                    Sender ! {Reference, false},
                    Continue(WithoutPrevious);
                true when ExpiresAt =< Now ->
                    Sender ! {Reference, true},
                    Continue(WithoutPrevious);
                true ->
                    Updated = retain_policy_capacity(
                        [
                            {
                                Partition,
                                Key,
                                Value,
                                ExpiresAt,
                                RetainedBytes,
                                Group
                            }
                            | WithoutPrevious
                        ],
                        MaximumEntries,
                        MaximumBytes,
                        PerGroup
                    ),
                    Sender ! {Reference, true},
                    Continue(Updated)
            end;
        {policy_list, Sender, Reference, Partition} ->
            Values = [
                Value
             || {ItemPartition, _Key, Value, _ExpiresAt, _Bytes, _Group}
                    <- Items,
                ItemPartition =:= Partition
            ],
            Sender ! {Reference, Values},
            Continue(Items);
        {policy_touch, Sender, Reference, Partition, Keys} ->
            Sender ! {Reference, done},
            Continue(promote_policy_items(Partition, Keys, Items));
        {policy_get, Sender, Reference, Partition, Key} ->
            case find_policy_item(Partition, Key, Items) of
                {ok, Value} ->
                    Sender ! {Reference, {ok, Value}},
                    Continue(promote_policy_item(Partition, Key, Items));
                error ->
                    Sender ! {Reference, missing},
                    Continue(Items)
            end;
        {policy_close, Sender, Reference} ->
            Sender ! {Reference, done},
            exit(normal)
    after policy_store_wait(Items, Now) ->
        Continue(Items)
    end.

-spec prune_policy_items([policy_item()], integer(), [policy_item()]) ->
    [policy_item()].
prune_policy_items([], _Now, Retained) ->
    lists:reverse(Retained);
prune_policy_items([{_, _, _, ExpiresAt, _, _} | Rest], Now, Retained)
    when ExpiresAt =< Now ->
    prune_policy_items(Rest, Now, Retained);
prune_policy_items([Item | Rest], Now, Retained) ->
    prune_policy_items(Rest, Now, [Item | Retained]).

-spec remove_policy_item(
    binary(), binary(), [policy_item()], [policy_item()]
) -> [policy_item()].
remove_policy_item(_Partition, _Key, [], Retained) ->
    lists:reverse(Retained);
remove_policy_item(
    Partition,
    Key,
    [{Partition, Key, _Value, _ExpiresAt, _Bytes, _Group} | Rest],
    Retained
) ->
    lists:reverse(Retained, Rest);
remove_policy_item(Partition, Key, [Item | Rest], Retained) ->
    remove_policy_item(Partition, Key, Rest, [Item | Retained]).

-spec find_policy_item(binary(), binary(), [policy_item()]) ->
    {ok, term()} | error.
find_policy_item(_Partition, _Key, []) ->
    error;
find_policy_item(
    Partition,
    Key,
    [{Partition, Key, Value, _ExpiresAt, _Bytes, _Group} | _Rest]
) ->
    {ok, Value};
find_policy_item(Partition, Key, [_Item | Rest]) ->
    find_policy_item(Partition, Key, Rest).

-spec promote_policy_item(binary(), binary(), [policy_item()]) ->
    [policy_item()].
promote_policy_item(Partition, Key, Items) ->
    promote_policy_item(Partition, Key, Items, []).

-spec promote_policy_item(
    binary(), binary(), [policy_item()], [policy_item()]
) -> [policy_item()].
promote_policy_item(_Partition, _Key, [], Earlier) ->
    lists:reverse(Earlier);
promote_policy_item(
    Partition,
    Key,
    [{Partition, Key, _Value, _ExpiresAt, _Bytes, _Group} = Found | Rest],
    Earlier
) ->
    [Found | lists:reverse(Earlier, Rest)];
promote_policy_item(Partition, Key, [Item | Rest], Earlier) ->
    promote_policy_item(Partition, Key, Rest, [Item | Earlier]).

%% Move every named key to the front, in the order given, so the cookies a
%% request carried become the most recently accessed and the tail of the list
%% stays the earliest last access.
-spec promote_policy_items(binary(), [binary()], [policy_item()]) ->
    [policy_item()].
promote_policy_items(Partition, Keys, Items) ->
    lists:foldl(
        fun(Key, Acc) -> promote_policy_item(Partition, Key, Acc) end,
        Items,
        lists:reverse(Keys)
    ).

%% RFC 6265 section 5.3: when excess entries have to go, the ones that share a
%% group with more than the ceiling's worth of others go before the rest, and
%% within either tier the earliest last access goes first. The list is held most
%% recently accessed first, so its tail is that order already. Expired entries
%% are gone before this runs, which is the tier above both of these.
%%
%% Only as many as the store is over by are taken from the over-represented
%% tier: the clause sets a priority order for removing excess, not a ceiling
%% that holds when there is no excess to remove.
-spec retain_policy_capacity(
    [policy_item()], pos_integer(), pos_integer(), pos_integer()
) -> [policy_item()].
retain_policy_capacity(Items, MaximumEntries, MaximumBytes, MaximumPerGroup) ->
    case policy_items_fit(Items, MaximumEntries, MaximumBytes, 0, 0) of
        true ->
            Items;
        false ->
            case oldest_over_represented(Items, MaximumPerGroup) of
                {ok, Item} ->
                    retain_policy_capacity(
                        lists:delete(Item, Items),
                        MaximumEntries,
                        MaximumBytes,
                        MaximumPerGroup
                    );
                error ->
                    retain_policy_capacity(
                        Items, MaximumEntries, MaximumBytes, 0, 0, []
                    )
            end
    end.

-spec policy_items_fit(
    [policy_item()], pos_integer(), pos_integer(), non_neg_integer(),
    non_neg_integer()
) -> boolean().
policy_items_fit([], _MaximumEntries, _MaximumBytes, _Count, _Bytes) ->
    true;
policy_items_fit(
    [{_, _, _, _, ItemBytes, _} | Rest], MaximumEntries, MaximumBytes,
    Count, Bytes
) ->
    Count + 1 =< MaximumEntries andalso
        Bytes + ItemBytes =< MaximumBytes andalso
        policy_items_fit(
            Rest, MaximumEntries, MaximumBytes, Count + 1, Bytes + ItemBytes
        ).

%% The last entry, and so the earliest accessed, belonging to a group that holds
%% more than the ceiling. An entry whose group is empty belongs to no group and
%% is never over-represented, which is how every store but the cookie one
%% behaves.
-spec oldest_over_represented([policy_item()], pos_integer()) ->
    {ok, policy_item()} | error.
oldest_over_represented(Items, MaximumPerGroup) ->
    Counts = lists:foldl(
        fun
            ({_, _, _, _, _, <<>>}, Acc) -> Acc;
            ({_, _, _, _, _, Group}, Acc) ->
                Acc#{Group => maps:get(Group, Acc, 0) + 1}
        end,
        #{},
        Items
    ),
    Over = [
        Item
     || {_, _, _, _, _, Group} = Item <- Items,
        Group =/= <<>>,
        maps:get(Group, Counts, 0) > MaximumPerGroup
    ],
    case lists:reverse(Over) of
        [Oldest | _] -> {ok, Oldest};
        [] -> error
    end.

-spec retain_policy_capacity(
    [policy_item()],
    pos_integer(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    [policy_item()]
) -> [policy_item()].
retain_policy_capacity([], _MaximumEntries, _MaximumBytes, _Count, _Bytes, Acc) ->
    lists:reverse(Acc);
retain_policy_capacity(
    _Items, MaximumEntries, _MaximumBytes, Count, _Bytes, Acc
) when Count >= MaximumEntries ->
    lists:reverse(Acc);
retain_policy_capacity(
    [{_, _, _, _, ItemBytes, _} = Item | Rest],
    MaximumEntries,
    MaximumBytes,
    Count,
    Bytes,
    Acc
) ->
    case Bytes + ItemBytes =< MaximumBytes of
        true ->
            retain_policy_capacity(
                Rest,
                MaximumEntries,
                MaximumBytes,
                Count + 1,
                Bytes + ItemBytes,
                [Item | Acc]
            );
        false -> lists:reverse(Acc)
    end.

-spec policy_store_wait([policy_item()], integer()) -> pos_integer().
policy_store_wait([], _Now) ->
    2147483647;
policy_store_wait(Items, Now) ->
    Earliest = lists:min([
        ExpiresAt
     || {_Partition, _Key, _Value, ExpiresAt, _Bytes, _Group} <- Items
    ]),
    erlang:max(1, erlang:min(2147483647, Earliest - Now)).

-spec new_http2_pool(integer(), integer(), integer()) -> http2_pool().
new_http2_pool(Maximum, PerOrigin, IdleMilliseconds)
    when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
         Maximum =< 2147483647, IdleMilliseconds > 0,
         IdleMilliseconds =< 2147483647 ->
    new_http2_pool_with_probe(
        Maximum, PerOrigin, IdleMilliseconds, no_handoff_probe
    );
new_http2_pool(_Maximum, _PerOrigin, _IdleMilliseconds) ->
    new_http2_pool(1, 1, 1).

%% Private deterministic synchronization seam. The observer sees only a fresh
%% reference, a finite phase atom, and the actor pid; socket and endpoint data
%% never leave the handoff implementation through this channel.
-spec new_http2_pool_with_handoff_probe(
    integer(), integer(), integer(), pid()
) -> http2_pool().
new_http2_pool_with_handoff_probe(
    Maximum, PerOrigin, IdleMilliseconds, Observer
) when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
       Maximum =< 2147483647, IdleMilliseconds > 0,
       IdleMilliseconds =< 2147483647, is_pid(Observer) ->
    ProbeReference = make_ref(),
    Pool = new_http2_pool_with_probe(
        Maximum,
        PerOrigin,
        IdleMilliseconds,
        {handoff_probe, Observer, ProbeReference}
    ),
    Pool#{handoff_probe => ProbeReference,
        handoff_probe_control => {Observer, ProbeReference}};
new_http2_pool_with_handoff_probe(
    _Maximum, _PerOrigin, _IdleMilliseconds, _Observer
) ->
    new_http2_pool(1, 1, 1).

-spec new_http2_pool_with_probe(
    pos_integer(), pos_integer(), pos_integer(), term()
) -> http2_pool().
new_http2_pool_with_probe(Maximum, PerOrigin, IdleMilliseconds, Probe) ->
    State = atomics:new(1, [{signed, false}]),
    Limits = {Maximum, PerOrigin, IdleMilliseconds},
    Owner = spawn_labelled(<<"http.http2_pool">>, fun() ->
        install_socket_handoff_probe(Probe),
        http2_pool_loop(State, [], Limits)
    end),
    #{state => State, owner => Owner}.

-spec checkout_http2(http2_pool(), lifecycle(), binary()) ->
    {ok, {term(), term(), cleanup()}} | {error, integer()}.
checkout_http2(#{state := State, owner := Owner}, Lifecycle, Origin)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> checkout_http2_from_owner(Owner, Lifecycle, Origin);
        _ -> {error, 1}
    end;
checkout_http2(_Pool, _Lifecycle, _Origin) ->
    {error, 1}.

-spec checkout_http2_from_owner(pid(), lifecycle(), binary()) ->
    {ok, {term(), term(), cleanup()}} | {error, integer()}.
checkout_http2_from_owner(Owner, Lifecycle, Origin) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
    Monitor = monitor(process, Owner),
    Owner ! {
        checkout_http2, self(), ReplyAlias, Reference, Lifecycle, Origin,
        Deadline
    },
    Result = await_http2_checkout_offer(
        Owner, Monitor, ReplyAlias, Reference, Deadline
    ),
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_socket_handoff_replies(Reference),
    Result.

-spec await_http2_checkout_offer(
    pid(), reference(), reference(), reference(), integer()
) -> {ok, {term(), term(), cleanup()}} | {error, integer()}.
await_http2_checkout_offer(Owner, Monitor, ReplyAlias, Reference, Deadline) ->
    receive
        {Reference, {socket_handoff_offer, HandoffReference, Socket,
                WireState, Cleanup}} ->
            Owner ! {socket_handoff_ready, self(), HandoffReference},
            await_http2_checkout_commit(
                Owner, Monitor, ReplyAlias, Reference, HandoffReference,
                Socket, WireState, Cleanup, Deadline
            );
        {Reference, empty} ->
            {error, 0};
        {Reference, closed} ->
            {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} ->
            {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end.

-spec await_http2_checkout_commit(
    pid(), reference(), reference(), reference(), reference(), term(), term(),
    cleanup(), integer()
) -> {ok, {term(), term(), cleanup()}} | {error, integer()}.
await_http2_checkout_commit(
    Owner, Monitor, ReplyAlias, Reference, HandoffReference, Socket,
    WireState, Cleanup, Deadline
) ->
    receive
        {Reference, {socket_handoff_committed, HandoffReference}} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {ok, {Socket, WireState, Cleanup}};
                false ->
                    _ = http_transport_ffi:close(Socket),
                    {error, 1}
            end;
        {Reference, {socket_handoff_retry, HandoffReference}} ->
            _ = http_transport_ffi:close(Socket),
            await_http2_checkout_offer(
                Owner, Monitor, ReplyAlias, Reference, Deadline
            );
        {Reference, {socket_handoff_rejected, HandoffReference}} ->
            _ = http_transport_ffi:close(Socket),
            {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} ->
            _ = http_transport_ffi:close(Socket),
            {error, 1}
    after deadline_remaining(Deadline) ->
        Owner ! {abort_socket_handoff, self(), HandoffReference},
        _ = http_transport_ffi:close(Socket),
        {error, 1}
    end.

-spec checkin_http2(
    http2_pool(), lifecycle(), binary(), term(), term(), cleanup()
) ->
    boolean().
checkin_http2(
    #{state := State, owner := Owner},
    Lifecycle,
    Origin,
    Socket,
    WireState,
    Cleanup
) when is_binary(Origin), byte_size(Origin) > 0, is_function(Cleanup, 0) ->
    case safe_state(State) of
        0 ->
            checkin_http2_with_owner(
                Owner, Lifecycle, Origin, Socket, WireState, Cleanup
            );
        _ ->
            _ = http_transport_ffi:close(Socket),
            false
    end;
checkin_http2(_Pool, _Lifecycle, _Origin, Socket, _WireState, _Cleanup) ->
    _ = http_transport_ffi:close(Socket),
    false.

-spec checkin_http2_with_owner(
    pid(), lifecycle(), binary(), term(), term(), cleanup()
) ->
    boolean().
checkin_http2_with_owner(
    Owner, Lifecycle, Origin, Socket, WireState, Cleanup
) ->
    Reference = make_ref(),
    HandoffReference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
    Monitor = monitor(process, Owner),
    Owner ! {
        checkin_http2, self(), ReplyAlias, Reference, HandoffReference,
        Lifecycle, Origin, Socket, WireState, Cleanup, Deadline
    },
    Result = await_http2_checkin_ready(
        Owner, Monitor, ReplyAlias, Reference, HandoffReference, Socket,
        Deadline
    ),
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_socket_handoff_replies(Reference),
    case Result of
        true -> true;
        false ->
            _ = http_transport_ffi:close(Socket),
            abort_registered_socket_handoff(Lifecycle, HandoffReference),
            false
    end.

-spec await_http2_checkin_ready(
    pid(), reference(), reference(), reference(), reference(), term(), integer()
) -> boolean().
await_http2_checkin_ready(
    Owner, Monitor, _ReplyAlias, Reference, HandoffReference, Socket, Deadline
) ->
    receive
        {Reference, {socket_handoff_ready, HandoffReference}} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                false -> false;
                true ->
                    case http_transport_ffi:transfer_owner(Socket, Owner) of
                        {ok, nil} ->
                            Owner ! {
                                socket_handoff_transferred, self(),
                                HandoffReference
                            },
                            await_http2_checkin_commit(
                                Owner, Monitor, Reference, HandoffReference,
                                Deadline
                            );
                        {error, _Reason} ->
                            Owner ! {
                                abort_socket_handoff, self(), HandoffReference
                            },
                            false
                    end
            end;
        {Reference, {socket_handoff_rejected, HandoffReference}} ->
            false;
        {'DOWN', Monitor, process, Owner, _Reason} ->
            false
    after deadline_remaining(Deadline) ->
        Owner ! {abort_socket_handoff, self(), HandoffReference},
        false
    end.

-spec await_http2_checkin_commit(
    pid(), reference(), reference(), reference(), integer()
) -> boolean().
await_http2_checkin_commit(
    Owner, Monitor, Reference, HandoffReference, Deadline
) ->
    receive
        {Reference, {socket_handoff_committed, HandoffReference}} ->
            erlang:monotonic_time(millisecond) < Deadline;
        {Reference, {socket_handoff_rejected, HandoffReference}} ->
            false;
        {'DOWN', Monitor, process, Owner, _Reason} ->
            false
    after deadline_remaining(Deadline) ->
        Owner ! {abort_socket_handoff, self(), HandoffReference},
        false
    end.

-spec drain_http2_pool(http2_pool()) -> nil.
drain_http2_pool(#{state := State, owner := Owner}) ->
    _ = transition_http2_pool(State, 1),
    http2_pool_call(Owner, drain),
    nil;
drain_http2_pool(_Pool) ->
    nil.

-spec close_http2_pool(http2_pool()) -> nil.
close_http2_pool(#{state := State, owner := Owner}) ->
    case atomics:exchange(State, 1, 2) of
        Previous when Previous =:= 0; Previous =:= 1 ->
            http2_pool_call(Owner, close);
        _ -> nil
    end;
close_http2_pool(_Pool) ->
    nil.

-spec transition_http2_pool(atomics:atomics_ref(), 1) -> nil.
transition_http2_pool(State, Next) ->
    case safe_state(State) of
        0 ->
            case atomics:compare_exchange(State, 1, 0, Next) of
                ok -> nil;
                _ -> transition_http2_pool(State, Next)
            end;
        _ -> nil
    end.

-spec http2_pool_call(pid(), drain | close) -> nil.
http2_pool_call(Owner, Command) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Monitor = monitor(process, Owner),
    Deadline = erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
    Owner ! {Command, ReplyAlias, Reference},
    _ = receive
        {Reference, done} -> done;
        {'DOWN', Monitor, process, Owner, _Reason} -> owner_down
    after deadline_remaining(Deadline) ->
        timeout
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_socket_handoff_replies(Reference),
    nil.

-spec http2_pool_loop(
    atomics:atomics_ref(),
    [http2_session()],
    pool_limits()
) -> no_return().
http2_pool_loop(State, ExistingSessions, Limits) ->
    Sessions = prune_http2_sessions(ExistingSessions),
    receive
        {checkout_http2, Sender, ReplyAlias, Reference, Lifecycle, Origin,
                Deadline} ->
            checkout_http2_session(
                State,
                Sessions,
                Lifecycle,
                Origin,
                Sender,
                ReplyAlias,
                Reference,
                Deadline,
                Limits
            );
        {
            checkin_http2,
            Sender,
            ReplyAlias,
            Reference,
            HandoffReference,
            Lifecycle,
            Origin,
            Socket,
            WireState,
            Cleanup,
            Deadline
        } ->
            case safe_state(State) =:= 0
                andalso erlang:monotonic_time(millisecond) < Deadline
                andalso http2_pool_has_capacity(Origin, Sessions, Limits)
                andalso begin_registered_socket_handoff_before(
                    Lifecycle, Socket, Sender, self(), HandoffReference,
                    Deadline
                ) =:= {ok, nil}
            of
                true ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_ready, HandoffReference}}
                    ),
                    finish_http2_checkin_handoff(
                        State, Sessions, Lifecycle, Origin, Socket, WireState,
                        Cleanup, Sender, ReplyAlias, Reference,
                        HandoffReference, Deadline, Limits
                    );
                false ->
                    abort_registered_socket_handoff(
                        Lifecycle, HandoffReference
                    ),
                    _ = http_transport_ffi:close(Socket),
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_rejected,
                            HandoffReference}}
                    ),
                    http2_pool_loop(State, Sessions, Limits)
            end;
        {drain, Sender, Reference} ->
            close_http2_sessions(Sessions),
            Sender ! {Reference, done},
            http2_pool_loop(State, [], Limits);
        {abort_socket_handoff, _Sender, _HandoffReference} ->
            http2_pool_loop(State, Sessions, Limits);
        {socket_handoff_ready, _Sender, _HandoffReference} ->
            http2_pool_loop(State, Sessions, Limits);
        {socket_handoff_transferred, _Sender, _HandoffReference} ->
            http2_pool_loop(State, Sessions, Limits);
        {close, Sender, Reference} ->
            close_http2_sessions(Sessions),
            Sender ! {Reference, done},
            exit(normal)
    after http2_pool_wait(Sessions) ->
        http2_pool_loop(State, Sessions, Limits)
    end.

-spec checkout_http2_session(
    atomics:atomics_ref(),
    [http2_session()],
    lifecycle(),
    binary(),
    pid(),
    reference(),
    reference(),
    integer(),
    pool_limits()
) -> no_return().
checkout_http2_session(
    State, Sessions, Lifecycle, Origin, Sender, ReplyAlias, Reference,
    Deadline, Limits
) ->
    case safe_state(State) =:= 0
        andalso erlang:monotonic_time(millisecond) < Deadline
        andalso is_process_alive(Sender)
    of
        true ->
            case take_http2_origin(Origin, Sessions, []) of
                empty ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, empty}
                    ),
                    http2_pool_loop(State, Sessions, Limits);
                {found, Socket, WireState, Cleanup, Remaining} ->
                    HandoffReference = make_ref(),
                    case begin_registered_socket_handoff_before(
                        Lifecycle, Socket, self(), Sender, HandoffReference,
                        Deadline
                    ) of
                        {ok, nil} ->
                            send_resource_checkout_reply(
                                ReplyAlias,
                                {Reference, {socket_handoff_offer,
                                    HandoffReference, Socket, WireState,
                                    Cleanup}}
                            ),
                            finish_http2_checkout_handoff(
                                State, Remaining, Lifecycle, Origin, Socket,
                                WireState, Cleanup, Sender, ReplyAlias,
                                Reference, HandoffReference, Deadline, Limits
                            );
                        {error, _Code} ->
                            _ = http_transport_ffi:close(Socket),
                            run_cleanup(Cleanup),
                            checkout_http2_session(
                                State,
                                Remaining,
                                Lifecycle,
                                Origin,
                                Sender,
                                ReplyAlias,
                                Reference,
                                Deadline,
                                Limits
                            )
                    end
            end;
        false ->
            send_resource_checkout_reply(ReplyAlias, {Reference, closed}),
            http2_pool_loop(State, Sessions, Limits)
    end.

-spec finish_http2_checkin_handoff(
    atomics:atomics_ref(), [http2_session()], lifecycle(), binary(), term(),
    term(), cleanup(), pid(), reference(), reference(), reference(), integer(),
    pool_limits()
) -> no_return().
finish_http2_checkin_handoff(
    State, Sessions, Lifecycle, Origin, Socket, WireState, Cleanup, Sender,
    ReplyAlias, Reference, HandoffReference, Deadline,
    Limits = {_Maximum, _PerOrigin, IdleMilliseconds}
) ->
    SenderMonitor = monitor(process, Sender),
    Outcome = receive
        {socket_handoff_transferred, Sender, HandoffReference} ->
            case pause_socket_handoff(
                Deadline, http2_checkin_after_transfer
            ) of
                continue ->
                    case safe_state(State) =:= 0
                        andalso is_process_alive(Sender)
                        andalso erlang:monotonic_time(millisecond) < Deadline
                    of
                        true -> commit_registered_socket_handoff_before(
                            Lifecycle, HandoffReference, Deadline
                        );
                        false -> {error, 1}
                    end;
                stop -> {error, 1}
            end;
        {abort_socket_handoff, Sender, HandoffReference} ->
            {error, 1};
        {'DOWN', SenderMonitor, process, Sender, _Reason} ->
            {error, 1};
        Control = {drain, _ControlSender, _ControlReference} ->
            self() ! Control,
            {error, 1};
        Control = {close, _ControlSender, _ControlReference} ->
            self() ! Control,
            {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end,
    demonitor(SenderMonitor, [flush]),
    case Outcome of
        {ok, nil} ->
            IdleDeadline = erlang:monotonic_time(millisecond)
                + IdleMilliseconds,
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_committed, HandoffReference}}
            ),
            http2_pool_loop(
                State,
                [{Origin, Socket, WireState, Cleanup, IdleDeadline} | Sessions],
                Limits
            );
        {error, _Code} ->
            abort_registered_socket_handoff(Lifecycle, HandoffReference),
            _ = http_transport_ffi:close(Socket),
            run_cleanup(Cleanup),
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_rejected, HandoffReference}}
            ),
            http2_pool_loop(State, Sessions, Limits)
    end.

-spec finish_http2_checkout_handoff(
    atomics:atomics_ref(), [http2_session()], lifecycle(), binary(), term(),
    term(), cleanup(), pid(), reference(), reference(), reference(), integer(),
    pool_limits()
) -> no_return().
finish_http2_checkout_handoff(
    State, Remaining, Lifecycle, Origin, Socket, _WireState, Cleanup, Sender,
    ReplyAlias, Reference, HandoffReference, Deadline, Limits
) ->
    SenderMonitor = monitor(process, Sender),
    Outcome = receive
        {socket_handoff_ready, Sender, HandoffReference} ->
            case erlang:monotonic_time(millisecond) < Deadline
                andalso safe_state(State) =:= 0
                andalso is_process_alive(Sender)
            of
                true ->
                    case http_transport_ffi:transfer_owner(Socket, Sender) of
                        {ok, nil} ->
                            case pause_socket_handoff(
                                Deadline, http2_checkout_after_transfer
                            ) of
                                continue ->
                                    commit_registered_socket_handoff_before(
                                        Lifecycle, HandoffReference, Deadline
                                    );
                                stop -> {error, 1}
                            end;
                        {error, _Reason} -> {error, 1}
                    end;
                false -> {error, 1}
            end;
        {abort_socket_handoff, Sender, HandoffReference} ->
            {error, 1};
        {'DOWN', SenderMonitor, process, Sender, _Reason} ->
            {error, 1};
        Control = {drain, _ControlSender, _ControlReference} ->
            self() ! Control,
            {error, 1};
        Control = {close, _ControlSender, _ControlReference} ->
            self() ! Control,
            {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end,
    demonitor(SenderMonitor, [flush]),
    case Outcome of
        {ok, nil} ->
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_committed, HandoffReference}}
            ),
            http2_pool_loop(State, Remaining, Limits);
        {error, _Code} ->
            abort_registered_socket_handoff(Lifecycle, HandoffReference),
            _ = http_transport_ffi:close(Socket),
            run_cleanup(Cleanup),
            case safe_state(State) =:= 0
                andalso is_process_alive(Sender)
                andalso erlang:monotonic_time(millisecond) < Deadline
            of
                true ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_retry, HandoffReference}}
                    ),
                    checkout_http2_session(
                        State, Remaining, Lifecycle, Origin, Sender,
                        ReplyAlias, Reference, Deadline, Limits
                    );
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_rejected,
                            HandoffReference}}
                    ),
                    http2_pool_loop(State, Remaining, Limits)
            end
    end.

-spec take_http2_origin(binary(), [http2_session()], [http2_session()]) ->
    empty | {found, term(), term(), cleanup(), [http2_session()]}.
take_http2_origin(_Origin, [], _Earlier) ->
    empty;
take_http2_origin(
    Origin,
    [{Origin, Socket, State, Cleanup, _} | Rest],
    Earlier
) ->
    {found, Socket, State, Cleanup, lists:reverse(Earlier, Rest)};
take_http2_origin(Origin, [Session | Rest], Earlier) ->
    take_http2_origin(Origin, Rest, [Session | Earlier]).

-spec http2_pool_has_capacity(binary(), [http2_session()], pool_limits()) ->
    boolean().
http2_pool_has_capacity(Origin, Sessions, {Maximum, PerOrigin, _Idle}) ->
    length(Sessions) < Maximum andalso
        count_http2_origin(Origin, Sessions, 0) < PerOrigin.

-spec count_http2_origin(binary(), [http2_session()], non_neg_integer()) ->
    non_neg_integer().
count_http2_origin(_Origin, [], Count) ->
    Count;
count_http2_origin(Origin, [{Origin, _, _, _, _} | Rest], Count) ->
    count_http2_origin(Origin, Rest, Count + 1);
count_http2_origin(Origin, [_ | Rest], Count) ->
    count_http2_origin(Origin, Rest, Count).

-spec prune_http2_sessions([http2_session()]) -> [http2_session()].
prune_http2_sessions(Sessions) ->
    prune_http2_sessions(
        Sessions,
        erlang:monotonic_time(millisecond),
        []
    ).

-spec prune_http2_sessions(
    [http2_session()], integer(), [http2_session()]
) -> [http2_session()].
prune_http2_sessions([], _Now, Retained) ->
    lists:reverse(Retained);
prune_http2_sessions(
    [{_, Socket, _, Cleanup, Deadline} | Rest], Now, Retained
)
    when Deadline =< Now ->
    _ = http_transport_ffi:close(Socket),
    run_cleanup(Cleanup),
    prune_http2_sessions(Rest, Now, Retained);
prune_http2_sessions([Session | Rest], Now, Retained) ->
    prune_http2_sessions(Rest, Now, [Session | Retained]).

-spec http2_pool_wait([http2_session()]) -> pos_integer().
http2_pool_wait([]) ->
    2147483647;
http2_pool_wait(Sessions) ->
    Now = erlang:monotonic_time(millisecond),
    Earliest = lists:min([
        Deadline
     || {_Origin, _Socket, _WireState, _Cleanup, Deadline} <- Sessions
    ]),
    erlang:max(1, Earliest - Now).

-spec close_http2_sessions([http2_session()]) -> nil.
close_http2_sessions(Sessions) ->
    lists:foreach(
        fun({_Origin, Socket, _WireState, Cleanup, _Deadline}) ->
            _ = http_transport_ffi:close(Socket),
            run_cleanup(Cleanup)
        end,
        Sessions
    ),
    nil.

-spec run_cleanup(cleanup()) -> nil.
run_cleanup(Cleanup) ->
    try Cleanup() of
        _ -> nil
    catch
        _Class:_Reason -> nil
    end.

-spec new_connection_guard() -> atomics:atomics_ref().
new_connection_guard() ->
    atomics:new(1, [{signed, false}]).

-spec mark_connection_released(atomics:atomics_ref()) -> boolean().
mark_connection_released(Guard) ->
    claim_connection_state(Guard, 1).

-spec claim_connection_close(atomics:atomics_ref()) -> boolean().
claim_connection_close(Guard) ->
    claim_connection_state(Guard, 2).

-spec claim_connection_state(atomics:atomics_ref(), 1 | 2) -> boolean().
claim_connection_state(Guard, State) ->
    try atomics:compare_exchange(Guard, 1, 0, State) of
        ok -> true;
        _Actual -> false
    catch
        _Class:_Reason -> false
    end.

-spec new_race_cancellation() -> atomics:atomics_ref().
new_race_cancellation() ->
    atomics:new(1, [{signed, false}]).

-spec cancel_race(atomics:atomics_ref()) -> nil.
cancel_race(Cancellation) ->
    try atomics:put(Cancellation, 1, 1) of
        ok -> nil
    catch
        _Class:_Reason -> nil
    end.

-spec race_cancelled(atomics:atomics_ref()) -> boolean().
race_cancelled(Cancellation) ->
    try atomics:get(Cancellation, 1) of
        0 -> false;
        _ -> true
    catch
        _Class:_Reason -> true
    end.

-spec new_lifecycle(integer(), integer(), integer()) -> lifecycle().
new_lifecycle(Maximum, PerOrigin, IdleMilliseconds)
    when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
         Maximum =< 2147483647, IdleMilliseconds > 0,
         IdleMilliseconds =< 2147483647 ->
    new_lifecycle_with_probe(
        Maximum, PerOrigin, IdleMilliseconds, no_handoff_probe
    );
new_lifecycle(_Maximum, _PerOrigin, _IdleMilliseconds) ->
    new_lifecycle(1, 1, 1).

-spec new_lifecycle_with_handoff_probe(
    integer(), integer(), integer(), pid()
) -> lifecycle().
new_lifecycle_with_handoff_probe(
    Maximum, PerOrigin, IdleMilliseconds, Observer
) when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
       Maximum =< 2147483647, IdleMilliseconds > 0,
       IdleMilliseconds =< 2147483647, is_pid(Observer) ->
    ProbeReference = make_ref(),
    Lifecycle = new_lifecycle_with_probe(
        Maximum,
        PerOrigin,
        IdleMilliseconds,
        {handoff_probe, Observer, ProbeReference}
    ),
    Lifecycle#{handoff_probe => ProbeReference,
        handoff_probe_control => {Observer, ProbeReference}};
new_lifecycle_with_handoff_probe(
    _Maximum, _PerOrigin, _IdleMilliseconds, _Observer
) ->
    new_lifecycle(1, 1, 1).

%% Test-only primitive fault seam. The factory result never crosses the probe
%% channel; a throw, exit, invalid return, badarg or system_limit is collapsed
%% into the same finite handoff rejection.
-spec new_lifecycle_with_handoff_probe(
    integer(), integer(), integer(), pid(), fun((pid()) -> continue)
) -> lifecycle().
new_lifecycle_with_handoff_probe(
    Maximum, PerOrigin, IdleMilliseconds, Observer, MonitorFactory
) when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
       Maximum =< 2147483647, IdleMilliseconds > 0,
       IdleMilliseconds =< 2147483647, is_pid(Observer),
       is_function(MonitorFactory, 1) ->
    ProbeReference = make_ref(),
    Lifecycle = new_lifecycle_with_probe(
        Maximum,
        PerOrigin,
        IdleMilliseconds,
        {handoff_probe, Observer, ProbeReference,
            {monitor_factory, MonitorFactory}}
    ),
    Lifecycle#{handoff_probe => ProbeReference,
        handoff_probe_control => {Observer, ProbeReference}};
new_lifecycle_with_handoff_probe(
    _Maximum, _PerOrigin, _IdleMilliseconds, _Observer, _MonitorFactory
) ->
    new_lifecycle(1, 1, 1).

-spec new_lifecycle_with_probe(
    pos_integer(), pos_integer(), pos_integer(), term()
) -> lifecycle().
new_lifecycle_with_probe(Maximum, PerOrigin, IdleMilliseconds, Probe) ->
    State = atomics:new(1, [{signed, false}]),
    Limits = {Maximum, PerOrigin, IdleMilliseconds},
    Owner = spawn_labelled(<<"http.client_lifecycle">>, fun() ->
        install_socket_handoff_probe(Probe),
        lifecycle_loop(State, [], [], Limits)
    end),
    #{state => State, owner => Owner}.

-spec install_socket_handoff_probe(term()) -> ok.
install_socket_handoff_probe(
    Probe = {handoff_probe, Observer, Reference}
) when is_pid(Observer), is_reference(Reference) ->
    _ = put(http_client_socket_handoff_probe, Probe),
    ok;
install_socket_handoff_probe(
    {handoff_probe, Observer, Reference,
        {monitor_factory, MonitorFactory}}
) when is_pid(Observer), is_reference(Reference),
       is_function(MonitorFactory, 1) ->
    _ = put(http_client_socket_handoff_probe,
            {handoff_probe, Observer, Reference}),
    _ = put(http_client_socket_handoff_monitor_factory, MonitorFactory),
    ok;
install_socket_handoff_probe(_Probe) ->
    ok.

-spec pause_socket_handoff(integer(), atom()) -> continue | stop.
pause_socket_handoff(Deadline, Phase) ->
    case get(http_client_socket_handoff_probe) of
        {handoff_probe, Observer, Reference}
            when is_pid(Observer), is_reference(Reference) ->
            Observer ! {http_client_socket_handoff, Reference, Phase, self()},
            receive
                {http_client_socket_handoff_continue, Reference} ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true -> continue;
                        false -> stop
                    end;
                Control = {drain, _Sender, _ControlReference} ->
                    self() ! Control,
                    stop;
                Control = {close, _Sender, _ControlReference} ->
                    self() ! Control,
                    stop;
                drain_pool ->
                    self() ! drain_pool,
                    stop;
                Control = {close_before, _ReplyAlias, _ControlReference,
                        _ControlDeadline, _JoinConfirmation} ->
                    self() ! Control,
                    stop
            after deadline_remaining(Deadline) ->
                stop
            end;
        _ ->
            continue
    end.

-spec state(lifecycle()) -> 0 | 1 | 2.
state(#{state := State}) ->
    try atomics:get(State, 1) of
        0 -> 0;
        1 -> 1;
        _ -> 2
    catch
        _Class:_Reason -> 2
    end;
state(_Lifecycle) ->
    2.

-spec is_closed(lifecycle()) -> boolean().
is_closed(Lifecycle) ->
    state(Lifecycle) =:= 2.

-spec lifecycle_owner(lifecycle()) -> pid().
lifecycle_owner(#{owner := Owner}) -> Owner.

%% Return only finite counts and caller-relative ownership. This deliberately
%% omits socket handles, owner pids, monitor references, origins, and pool keys.
-spec lifecycle_snapshot(lifecycle()) ->
    {integer(), integer(), integer(), integer()}.
lifecycle_snapshot(#{owner := Owner}) ->
    Reference = make_ref(),
    case resource_call(Owner, {lifecycle_snapshot, self(), Reference}, Reference) of
        {ok, Snapshot} -> Snapshot;
        {error, _Code} -> {-1, -1, -1, -1}
    end;
lifecycle_snapshot(_Lifecycle) -> {-1, -1, -1, -1}.

%% Test-facing closed observation of shared HTTP/3 state. It contains only
%% finite counts: physical, accepting, draining, closing, active leases, idle.
-spec http3_shared_snapshot(lifecycle()) ->
    {integer(), integer(), integer(), integer(), integer(), integer()}.
http3_shared_snapshot(Lifecycle) ->
    http3_shared_snapshot(Lifecycle, ?CLEANUP_TIMEOUT).

-spec http3_shared_snapshot(lifecycle(), non_neg_integer()) ->
    {integer(), integer(), integer(), integer(), integer(), integer()}.
http3_shared_snapshot(
    #{owner := Owner}, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    Monitor = monitor(process, Owner),
    Owner ! {http3_shared_snapshot, ReplyAlias, Reference},
    Snapshot = receive
        {Reference, {ok, {Physical, Accepting, Draining, Closing, Leases,
                Idle} = Counts}}
          when is_integer(Physical), Physical >= 0,
               is_integer(Accepting), Accepting >= 0,
               is_integer(Draining), Draining >= 0,
               is_integer(Closing), Closing >= 0,
               is_integer(Leases), Leases >= 0,
               is_integer(Idle), Idle >= 0 -> Counts;
        {Reference, _InvalidReply} -> {-1, -1, -1, -1, -1, -1};
        {'DOWN', Monitor, process, Owner, _Reason} ->
            {-1, -1, -1, -1, -1, -1}
    after deadline_remaining(Deadline) ->
        {-1, -1, -1, -1, -1, -1}
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_http3_operation_replies(Reference),
    Snapshot;
http3_shared_snapshot(_Lifecycle, _TimeoutMilliseconds) ->
    {-1, -1, -1, -1, -1, -1}.

%% Test-facing closed observation of in-flight HTTP/3 connection generation.
%% Only the number of physical dials and their registered waiters is exposed;
%% keys, owners, references, endpoints, and connections never cross this API.
-spec http3_dial_snapshot(lifecycle()) -> {integer(), integer()}.
http3_dial_snapshot(Lifecycle) ->
    http3_dial_snapshot(Lifecycle, ?CLEANUP_TIMEOUT).

-spec http3_dial_snapshot(lifecycle(), non_neg_integer()) ->
    {integer(), integer()}.
http3_dial_snapshot(
    #{state := State, owner := Owner}, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    Monitor = monitor(process, Owner),
    Owner ! {http3_dial_snapshot, ReplyAlias, Reference},
    Snapshot = receive
        {Reference, {ok, {Inflight, Waiters} = Counts}}
          when is_integer(Inflight), Inflight >= 0,
               is_integer(Waiters), Waiters >= 0 -> Counts;
        {Reference, _InvalidReply} -> {-1, -1};
        {'DOWN', Monitor, process, Owner, _Reason} -> {-1, -1}
    after deadline_remaining(Deadline) ->
        {-1, -1}
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_http3_operation_replies(Reference),
    case {Snapshot, safe_state(State)} of
        {{-1, -1}, 3} -> {0, 0};
        _ -> Snapshot
    end;
http3_dial_snapshot(_Lifecycle, _TimeoutMilliseconds) -> {-1, -1}.

%% Test-facing finite observation of in-flight reusable-resource handoffs.
-spec lifecycle_pending_count(lifecycle()) -> integer().
lifecycle_pending_count(#{owner := Owner}) ->
    Reference = make_ref(),
    case resource_call(
        Owner, {lifecycle_pending_count, self(), Reference}, Reference
    ) of
        {ok, Count} when is_integer(Count), Count >= 0 -> Count;
        {error, _Code} -> -1
    end;
lifecycle_pending_count(_Lifecycle) -> -1.

-spec drain(lifecycle()) -> 1 | 2.
drain(#{state := State, owner := Owner}) ->
    try drain_loop(State) of
        Result ->
            Owner ! drain_pool,
            Result
    catch
        _Class:_Reason -> 2
    end;
drain(_Lifecycle) ->
    2.

-spec drain_loop(atomics:atomics_ref()) -> 1 | 2.
drain_loop(State) ->
    case atomics:get(State, 1) of
        0 ->
            case atomics:compare_exchange(State, 1, 0, 1) of
                ok -> 1;
                _Actual -> drain_loop(State)
            end;
        1 -> 1;
        _ -> 2
    end.

-spec register_socket(lifecycle(), binary(), term()) ->
    {ok, registration()} | {error, integer()}.
register_socket(#{state := State, owner := Owner}, Origin, Socket)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> register_with_owner(Owner, Origin, Socket);
        _ ->
            _ = http_transport_ffi:close(Socket),
            {error, 1}
    end;
register_socket(_Lifecycle, _Origin, Socket) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% Register a race candidate only within its original exchange deadline. A
%% timeout closes the socket and enqueues abandonment from the same sender, so
%% a registration accepted just before the deadline cannot remain unowned.
-spec register_socket_within(
    lifecycle(), binary(), term(), non_neg_integer()
) -> {ok, registration()} | {error, integer()}.
register_socket_within(
    #{state := State, owner := Owner}, Origin, Socket, TimeoutMilliseconds
) when is_binary(Origin), byte_size(Origin) > 0,
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    register_socket_before(
        #{state => State, owner => Owner}, Origin, Socket, Deadline
    );
register_socket_within(_Lifecycle, _Origin, Socket, _TimeoutMilliseconds) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% Preserve the caller's absolute exchange deadline across scheduler stalls.
-spec register_socket_before(lifecycle(), binary(), term(), integer()) ->
    {ok, registration()} | {error, integer()}.
register_socket_before(
    #{state := State, owner := Owner}, Origin, Socket, Deadline
) when is_binary(Origin), byte_size(Origin) > 0, is_integer(Deadline) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            ReplyAlias = erlang:alias(),
            RequestedToken = make_ref(),
            Result = resource_call_before(
                Owner,
                {register_socket_before, self(), ReplyAlias, Reference,
                    RequestedToken, Origin, Socket, Deadline},
                ReplyAlias,
                Reference,
                Deadline
            ),
            case Result of
                {ok, RegisteredToken} when is_reference(RegisteredToken) ->
                    {ok, {http_client_registration, Owner, RegisteredToken}};
                {error, Code} ->
                    _ = http_transport_ffi:close(Socket),
                    Owner ! {abandon_socket, Socket},
                    {error, Code};
                _ ->
                    _ = http_transport_ffi:close(Socket),
                    Owner ! {abandon_socket, Socket},
                    {error, 1}
            end;
        _ ->
            _ = http_transport_ffi:close(Socket),
            {error, 1}
    end;
register_socket_before(_Lifecycle, _Origin, Socket, _Deadline) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% Reserve the shared connection budget before creating any connection.
%% Reservations monitor their caller until attach_resource transfers the
%% lifetime to the admitted connection actor. No backend handle is inspected.
-spec reserve_resource(lifecycle(), binary()) ->
    {ok, registration()} | {error, integer()}.
reserve_resource(#{state := State, owner := Owner}, Origin)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 ->
            Token = make_ref(),
            case resource_call(Owner, {reserve_resource, self(), Token, Origin}, Token) of
                {ok, nil} -> {ok, {http_client_registration, Owner, Token}};
                {error, Code} ->
                    Owner ! {unregister_socket, Token},
                    {error, Code};
                _ ->
                    Owner ! {unregister_socket, Token},
                    {error, 1}
            end;
        _ -> {error, 1}
    end;
reserve_resource(_Lifecycle, _Origin) -> {error, 1}.

%% Reserve within the caller's remaining absolute deadline. On every failure,
%% including a timed-out acknowledgement, unregister is sent by the same
%% process after reserve so a late reservation cannot retain capacity.
-spec reserve_resource_within(lifecycle(), binary(), non_neg_integer()) ->
    {ok, registration()} | {error, integer()}.
reserve_resource_within(#{state := State, owner := Owner}, Origin,
                        TimeoutMilliseconds)
    when is_binary(Origin), byte_size(Origin) > 0,
         is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
         TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    reserve_resource_before(#{state => State, owner => Owner}, Origin, Deadline);
reserve_resource_within(_Lifecycle, _Origin, _TimeoutMilliseconds) ->
    {error, 1}.

-spec reserve_resource_before(lifecycle(), binary(), integer()) ->
    {ok, registration()} | {error, integer()}.
reserve_resource_before(
    #{state := State, owner := Owner}, Origin, Deadline
) when is_binary(Origin), byte_size(Origin) > 0, is_integer(Deadline) ->
    case safe_state(State) of
        0 ->
            Token = make_ref(),
            ReplyAlias = erlang:alias(),
            case resource_call_before(
                Owner,
                {reserve_resource_before, self(), ReplyAlias, Token, Origin,
                    Deadline},
                ReplyAlias,
                Token,
                Deadline
            ) of
                {ok, nil} -> {ok, {http_client_registration, Owner, Token}};
                {error, Code} ->
                    Owner ! {unregister_socket, Token},
                    {error, Code}
            end;
        _ -> {error, 1}
    end;
reserve_resource_before(_Lifecycle, _Origin, _Deadline) ->
    {error, 1}.

%% Atomically join or create the one in-flight HTTP/3 dial for a pool key.
%% A follower receives a private wait capability only after the lifecycle
%% owner has installed its process monitor and absolute deadline.
-spec begin_http3_dial_within(
    lifecycle(), binary(), binary(), non_neg_integer()
) -> {ok, term()} | {error, integer()}.
begin_http3_dial_within(
    #{state := State, owner := Owner}, Origin, Key, TimeoutMilliseconds
) when is_binary(Origin), byte_size(Origin) > 0,
       is_binary(Key), byte_size(Key) > 0,
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    begin_http3_dial_before(
        #{state => State, owner => Owner}, Origin, Key, Deadline
    );
begin_http3_dial_within(
    _Lifecycle, _Origin, _Key, _TimeoutMilliseconds
) ->
    {error, 1}.

-spec begin_http3_dial_before(
    lifecycle(), binary(), binary(), integer()
) -> {ok, term()} | {error, integer()}.
begin_http3_dial_before(
    #{state := State, owner := Owner}, Origin, Key, Deadline
) when is_binary(Origin), byte_size(Origin) > 0,
       is_binary(Key), byte_size(Key) > 0, is_integer(Deadline) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            ReplyAlias = erlang:alias(),
            Monitor = monitor(process, Owner),
            Owner ! {begin_http3_dial, self(), ReplyAlias, Reference,
                Origin, Key, Deadline},
            begin_http3_dial_reply(
                Owner, ReplyAlias, Reference, Monitor, Deadline
            );
        _ -> {error, 1}
    end;
begin_http3_dial_before(_Lifecycle, _Origin, _Key, _Deadline) ->
    {error, 1}.

-spec begin_http3_dial_reply(
    pid(), reference(), reference(), reference(), integer()
) -> {ok, term()} | {error, integer()}.
begin_http3_dial_reply(Owner, ReplyAlias, Reference, Monitor, Deadline) ->
    Result = receive
        {Reference, {leader, Token}} when is_reference(Token) ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    {complete, {ok, {http3_dial_leader,
                        {http_client_registration, Owner, Token}}}};
                false -> {complete, {error, 1}}
            end;
        {Reference, waiting} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    {waiting, {ok, {http3_dial_waiting,
                        {http3_dial_wait, Owner, ReplyAlias, Reference,
                            Monitor, Deadline}}}};
                false -> {complete, {error, 1}}
            end;
        {Reference, published} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {complete, {ok, http3_dial_published}};
                false -> {complete, {error, 1}}
            end;
        {Reference, {error, Code}}
          when Code =:= 0; Code =:= 1; Code =:= 2; Code =:= 3 ->
            {complete, {error, Code}};
        {Reference, _InvalidReply} -> {complete, {error, 1}};
        {'DOWN', Monitor, process, Owner, _Reason} ->
            {complete, {error, 1}}
    after deadline_remaining(Deadline) ->
        {complete, {error, 1}}
    end,
    case Result of
        {waiting, Waiting} -> Waiting;
        {complete, Reply} ->
            case Reply of
                {error, _} ->
                    Owner ! {abandon_http3_dial, self(), Reference};
                {ok, _} -> ok
            end,
            demonitor(Monitor, [flush]),
            _ = erlang:unalias(ReplyAlias),
            flush_http3_operation_replies(Reference),
            Reply
    end.

%% Await the terminal publication result for a previously acknowledged
%% follower. The stored deadline cannot be extended by output or scheduling.
-spec await_http3_dial(http3_dial_wait()) ->
    {ok, nil} | {error, integer()}.
await_http3_dial(
    {http3_dial_wait, Owner, ReplyAlias, Reference, Monitor, Deadline}
) when is_pid(Owner), is_reference(ReplyAlias), is_reference(Reference),
       is_reference(Monitor), is_integer(Deadline) ->
    Result = receive
        {Reference, published} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {ok, nil};
                false -> {error, 1}
            end;
        {Reference, failed} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {error, 3};
                false -> {error, 1}
            end;
        {Reference, {error, Code}}
          when Code =:= 1; Code =:= 3 -> {error, Code};
        {Reference, _InvalidReply} -> {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end,
    case Result of
        {ok, nil} -> ok;
        {error, _} ->
            Owner ! {abandon_http3_dial, self(), Reference}
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_http3_operation_replies(Reference),
    Result;
await_http3_dial(_Wait) -> {error, 1}.

%% Deterministic mutation seam for lifecycle tests. The opaque registration is
%% the only authority, and the lifecycle owner applies the same waiter
%% settlement path used by a real publication or dial failure.
-spec settle_http3_dial_probe_within(
    registration(), boolean(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
settle_http3_dial_probe_within(
    {http_client_registration, Owner, Token}, Published,
    TimeoutMilliseconds
) when is_boolean(Published), is_integer(TimeoutMilliseconds),
       TimeoutMilliseconds >= 0, TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    resource_call_within(
        Owner,
        {settle_http3_dial_probe, self(), Reference, Token, Published,
            Deadline},
        Reference,
        TimeoutMilliseconds
    );
settle_http3_dial_probe_within(
    _Registration, _Published, _TimeoutMilliseconds
) ->
    {error, 1}.

%% Advance only the waiter-deadline view used by the broker's deterministic
%% tests. The leader deadline and physical reservation remain unchanged. The
%% acknowledgement is emitted by the lifecycle actor after pruning.
-spec expire_http3_dial_waiters_probe_within(
    registration(), non_neg_integer(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
expire_http3_dial_waiters_probe_within(
    {http_client_registration, Owner, Token}, AdvanceMilliseconds,
    TimeoutMilliseconds
) when is_integer(AdvanceMilliseconds), AdvanceMilliseconds >= 0,
       AdvanceMilliseconds =< 2147483647,
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    resource_call_within(
        Owner,
        {expire_http3_dial_waiters_probe, self(), Reference, Token,
            AdvanceMilliseconds, Deadline},
        Reference,
        TimeoutMilliseconds
    );
expire_http3_dial_waiters_probe_within(
    _Registration, _AdvanceMilliseconds, _TimeoutMilliseconds
) ->
    {error, 1}.

%% Adopt the dial winner into its already charged reservation. Failed or late
%% adoption closes the socket; the caller cancels the unconsumed reservation.
-spec attach_reserved_socket(registration(), term()) ->
    {ok, nil} | {error, integer()}.
attach_reserved_socket({http_client_registration, Owner, Token}, Socket) ->
    Reference = make_ref(),
    Result = resource_call(Owner,
        {attach_reserved_socket, self(), Reference, Token, Socket}, Reference),
    case Result of
        {ok, nil} -> Result;
        _ ->
            _ = http_transport_ffi:close(Socket),
            Owner ! {unregister_socket, Token},
            Result
    end;
attach_reserved_socket(_Registration, Socket) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% Attach a race reservation without extending the exchange deadline. The
%% lifecycle actor validates the same absolute deadline before mutating state;
%% a failed acknowledgement is followed by unregister from this sender so an
%% accepted late mutation cannot retain the connection budget.
-spec attach_reserved_socket_within(
    registration(), term(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
attach_reserved_socket_within(
    {http_client_registration, Owner, Token}, Socket, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    attach_reserved_socket_before(
        {http_client_registration, Owner, Token}, Socket, Deadline
    );
attach_reserved_socket_within(
    _Registration, Socket, _TimeoutMilliseconds
) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

-spec attach_reserved_socket_before(registration(), term(), integer()) ->
    {ok, nil} | {error, integer()}.
attach_reserved_socket_before(
    {http_client_registration, Owner, Token}, Socket, Deadline
) when is_integer(Deadline) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Result = resource_call_before(
        Owner,
        {attach_reserved_socket_before, self(), ReplyAlias, Reference, Token,
            Socket, Deadline},
        ReplyAlias,
        Reference,
        Deadline
    ),
    case Result of
        {ok, nil} -> Result;
        _ ->
            _ = http_transport_ffi:close(Socket),
            Owner ! {unregister_socket, Token},
            Result
    end;
attach_reserved_socket_before(
    _Registration, Socket, _Deadline
) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% TLS owns the same connection through a different transport handle. Replace
%% its entry atomically with a fresh token: cleanup retained by the raw phase
%% cannot release the upgraded phase, and capacity never becomes available.
-spec replace_socket(lifecycle(), term(), term()) ->
    {ok, nil} | {error, integer()}.
replace_socket(#{owner := Owner}, Previous, Socket) ->
    Token = make_ref(),
    Result = resource_call(Owner,
        {replace_socket, self(), Token, Previous, Socket}, Token),
    case Result of
        {ok, nil} -> Result;
        _ ->
            _ = http_transport_ffi:close(Socket),
            Owner ! {unregister_socket, Token},
            Result
    end;
replace_socket(_Lifecycle, _Previous, Socket) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% Replace a raw race socket by its TLS handle only before the original
%% exchange deadline. The new token is removed after any unacknowledged result
%% so a reply delayed past the deadline cannot publish a usable candidate.
-spec replace_socket_within(
    lifecycle(), term(), term(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
replace_socket_within(
    Lifecycle = #{owner := _Owner}, Previous, Socket, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    replace_socket_before(Lifecycle, Previous, Socket, Deadline);
replace_socket_within(
    _Lifecycle, _Previous, Socket, _TimeoutMilliseconds
) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

-spec replace_socket_before(lifecycle(), term(), term(), integer()) ->
    {ok, nil} | {error, integer()}.
replace_socket_before(
    #{owner := Owner}, Previous, Socket, Deadline
) when is_integer(Deadline) ->
    Token = make_ref(),
    ReplyAlias = erlang:alias(),
    Result = resource_call_before(
        Owner,
        {replace_socket_before, self(), ReplyAlias, Token, Previous, Socket,
            Deadline},
        ReplyAlias,
        Token,
        Deadline
    ),
    case Result of
        {ok, nil} -> Result;
        _ ->
            _ = http_transport_ffi:close(Socket),
            Owner ! {unregister_socket, Token},
            Result
    end;
replace_socket_before(
    _Lifecycle, _Previous, Socket, _Deadline
) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

%% Combined transfer-and-ledger operation used by connection contenders. The
%% lifecycle records both parties first, so killing the old owner on the next
%% instruction cannot strand a socket in the as-yet-uninformed new owner.
-spec transfer_and_adopt_socket_owner(lifecycle(), term(), pid()) ->
    {ok, nil} | {error, integer()}.
transfer_and_adopt_socket_owner(Lifecycle, Socket, Owner) ->
    transfer_and_adopt_socket_owner_before(
        Lifecycle,
        Socket,
        Owner,
        erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT
    ).

-spec transfer_and_adopt_socket_owner_within(
    lifecycle(), term(), pid(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
transfer_and_adopt_socket_owner_within(
    Lifecycle, Socket, Owner, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    transfer_and_adopt_socket_owner_before(
        Lifecycle,
        Socket,
        Owner,
        erlang:monotonic_time(millisecond) + TimeoutMilliseconds
    );
transfer_and_adopt_socket_owner_within(
    _Lifecycle, Socket, _Owner, _TimeoutMilliseconds
) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

-spec transfer_and_adopt_socket_owner_before(
    lifecycle(), term(), pid(), integer()
) -> {ok, nil} | {error, integer()}.
transfer_and_adopt_socket_owner_before(
    Lifecycle, Socket, Owner, Deadline
) when is_pid(Owner), is_integer(Deadline) ->
    HandoffReference = make_ref(),
    case begin_registered_socket_handoff_before(
        Lifecycle, Socket, self(), Owner, HandoffReference, Deadline
    ) of
        {ok, nil} ->
            Result = case erlang:monotonic_time(millisecond) < Deadline of
                false -> {error, 1};
                true ->
                    case http_transport_ffi:transfer_owner(Socket, Owner) of
                        {ok, nil} ->
                            case pause_socket_handoff_from_handle(
                                Lifecycle,
                                Deadline,
                                contender_owner_after_transfer
                            ) of
                                continue ->
                                    commit_registered_socket_handoff_before(
                                        Lifecycle, HandoffReference, Deadline
                                    );
                                stop -> {error, 1}
                            end;
                        {error, Code} -> {error, Code}
                    end
            end,
            case Result of
                {ok, nil} -> Result;
                {error, _Code} ->
                    abort_registered_socket_handoff(
                        Lifecycle, HandoffReference
                    ),
                    _ = http_transport_ffi:close(Socket),
                    Result
            end;
        {error, Code} ->
            _ = http_transport_ffi:close(Socket),
            {error, Code}
    end;
transfer_and_adopt_socket_owner_before(
    _Lifecycle, Socket, _Owner, _Deadline
) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

-spec pause_socket_handoff_from_handle(lifecycle(), integer(), atom()) ->
    continue | stop.
pause_socket_handoff_from_handle(Lifecycle, Deadline, Phase) ->
    case maps:get(handoff_probe_control, Lifecycle, no_handoff_probe) of
        {Observer, Reference}
            when is_pid(Observer), is_reference(Reference) ->
            Observer ! {http_client_socket_handoff, Reference, Phase, self()},
            receive
                {http_client_socket_handoff_continue, Reference} ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true -> continue;
                        false -> stop
                    end
            after deadline_remaining(Deadline) ->
                stop
            end;
        _ ->
            continue
    end.

%% Record both sides before a pool moves a registered transport. Until commit,
%% either party's DOWN closes and removes the socket. This is the durable
%% recovery point for the instruction boundary after controlling_process/2.
-spec begin_registered_socket_handoff_before(
    lifecycle(), term(), pid(), pid(), reference(), integer()
) -> {ok, nil} | {error, integer()}.
begin_registered_socket_handoff_before(
    #{owner := LifecycleOwner}, Socket, Previous, Owner, HandoffReference,
    Deadline
) when is_pid(Previous), is_pid(Owner), is_reference(HandoffReference),
       is_integer(Deadline) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Result = resource_call_before(
        LifecycleOwner,
        {begin_socket_handoff, self(), ReplyAlias, Reference,
            HandoffReference, Socket, Previous, Owner, Deadline},
        ReplyAlias,
        Reference,
        Deadline
    ),
    case Result of
        {ok, nil} -> Result;
        _ ->
            LifecycleOwner ! {abort_socket_handoff, HandoffReference},
            Result
    end;
begin_registered_socket_handoff_before(
    _Lifecycle, _Socket, _Previous, _Owner, _HandoffReference, _Deadline
) ->
    {error, 1}.

-spec commit_registered_socket_handoff_before(
    lifecycle(), reference(), integer()
) -> {ok, nil} | {error, integer()}.
commit_registered_socket_handoff_before(
    #{owner := LifecycleOwner}, HandoffReference, Deadline
) when is_reference(HandoffReference), is_integer(Deadline) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Result = resource_call_before(
        LifecycleOwner,
        {commit_socket_handoff, self(), ReplyAlias, Reference,
            HandoffReference, Deadline},
        ReplyAlias,
        Reference,
        Deadline
    ),
    case Result of
        {ok, nil} -> Result;
        _ ->
            LifecycleOwner ! {abort_socket_handoff, HandoffReference},
            Result
    end;
commit_registered_socket_handoff_before(
    _Lifecycle, _HandoffReference, _Deadline
) ->
    {error, 1}.

-spec abort_registered_socket_handoff(lifecycle(), reference()) -> ok.
abort_registered_socket_handoff(
    #{owner := LifecycleOwner}, HandoffReference
) when is_reference(HandoffReference) ->
    LifecycleOwner ! {abort_socket_handoff, HandoffReference},
    ok;
abort_registered_socket_handoff(_Lifecycle, _HandoffReference) ->
    ok.

-spec attach_resource(registration(), pid()) -> {ok, nil} | {error, integer()}.
attach_resource({http_client_registration, Owner, Token}, ResourceOwner)
    when is_pid(ResourceOwner) ->
    Reference = make_ref(),
    Result = resource_call(Owner,
        {attach_resource, self(), Reference, Token, ResourceOwner}, Reference),
    case Result of
        {ok, nil} -> Result;
        _ -> exit(ResourceOwner, kill), Result
    end;
attach_resource(_Registration, ResourceOwner) when is_pid(ResourceOwner) ->
    exit(ResourceOwner, kill),
    {error, 1};
attach_resource(_Registration, _ResourceOwner) -> {error, 1}.

%% Capture only the subject's process and private tag. The lifecycle guardian
%% later sends the encoded close command directly; no caller closure executes
%% in the guardian and no endpoint data is retained in this capability.
-spec new_http3_close_handle(term()) ->
    {http3_close_handle, pid(), reference()} | invalid_http3_close_handle.
new_http3_close_handle({subject, Owner, Tag})
    when is_pid(Owner), is_reference(Tag) ->
    {http3_close_handle, Owner, Tag};
new_http3_close_handle(_Subject) ->
    invalid_http3_close_handle.

-spec attach_http3_resource(registration(), pid(), term()) ->
    {ok, nil} | {error, integer()}.
attach_http3_resource(
    {http_client_registration, LifecycleOwner, Token},
    ResourceOwner,
    {http3_close_handle, ResourceOwner, Tag}
) when is_pid(ResourceOwner), is_reference(Tag) ->
    Reference = make_ref(),
    WrappedOwner = {http3_resource_owner, ResourceOwner, Tag},
    Result = resource_call(
        LifecycleOwner,
        {attach_http3_resource, self(), Reference, Token, WrappedOwner},
        Reference
    ),
    case Result of
        {ok, nil} -> Result;
        _ -> force_resource_owner_shutdown(WrappedOwner), Result
    end;
attach_http3_resource(_Registration, ResourceOwner, _CloseHandle)
    when is_pid(ResourceOwner) ->
    exit(ResourceOwner, kill),
    {error, 1};
attach_http3_resource(_Registration, _ResourceOwner, _CloseHandle) ->
    {error, 1}.

%% Publish an authenticated candidate and its first logical stream lease in
%% one lifecycle-owner turn. A timeout is followed by ordered abandon and
%% candidate-retirement messages, so a late owner turn cannot retain either a
%% logical lease or an unobserved physical candidate.
-spec activate_http3_candidate_within(
    registration(), binary(), term(), boolean(), non_neg_integer()
) -> {ok, {term(), http3_lease()}} | {error, integer()}.
activate_http3_candidate_within(
    {http_client_registration, Owner, Token}, Key, Connection, AllowShare,
    TimeoutMilliseconds
) when is_binary(Key), byte_size(Key) > 0,
       is_boolean(AllowShare),
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    activate_http3_candidate_before(
        {http_client_registration, Owner, Token}, Key, Connection, AllowShare,
        Deadline
    );
activate_http3_candidate_within(
    _Registration, _Key, _Connection, _AllowShare, _TimeoutMilliseconds
) ->
    {error, 1}.

-spec activate_http3_candidate_before(
    registration(), binary(), term(), boolean(), integer()
) -> {ok, {term(), http3_lease()}} | {error, integer()}.
activate_http3_candidate_before(
    {http_client_registration, Owner, Token}, Key, Connection, AllowShare,
    Deadline
) when is_binary(Key), byte_size(Key) > 0,
       is_boolean(AllowShare), is_integer(Deadline) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Monitor = monitor(process, Owner),
    Owner ! {activate_http3_candidate, self(), ReplyAlias, Reference,
        Token, Key, Connection, AllowShare, Deadline},
    Result = receive
        {Reference, {ok, {_SharedConnection, _Lease}} = Activated} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> Activated;
                false -> {error, 1}
            end;
        {Reference, {error, Code}}
          when Code =:= 0; Code =:= 1; Code =:= 2 -> {error, Code};
        {Reference, _InvalidReply} -> {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_http3_operation_replies(Reference),
    case Result of
        {ok, _} -> Result;
        {error, _} ->
            Owner ! {abandon_http3_lease, self(), Reference},
            Owner ! {retire_http3_candidate, Token, Deadline},
            Result
    end;
activate_http3_candidate_before(
    _Registration, _Key, _Connection, _AllowShare, _Deadline
) ->
    {error, 1}.

%% Checkout never removes the physical HTTP/3 entry. It creates a separately
%% monitored logical capability and cancels the idle generation atomically.
-spec checkout_http3_shared_within(
    lifecycle(), binary(), non_neg_integer()
) -> {ok, {term(), http3_lease()}} | {error, integer()}.
checkout_http3_shared_within(
    #{state := State, owner := Owner}, Key, TimeoutMilliseconds
) when is_binary(Key), byte_size(Key) > 0,
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    checkout_http3_shared_before(
        #{state => State, owner => Owner}, Key, Deadline
    );
checkout_http3_shared_within(_Lifecycle, _Key, _TimeoutMilliseconds) ->
    {error, 1}.

-spec checkout_http3_shared_before(lifecycle(), binary(), integer()) ->
    {ok, {term(), http3_lease()}} | {error, integer()}.
checkout_http3_shared_before(
    #{state := State, owner := Owner}, Key, Deadline
) when is_binary(Key), byte_size(Key) > 0, is_integer(Deadline) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            ReplyAlias = erlang:alias(),
            Monitor = monitor(process, Owner),
            Owner ! {checkout_http3_shared, self(), ReplyAlias, Reference,
                Key, Deadline},
            Result = receive
                {Reference, {ok, {_Connection, _Lease}} = CheckedOut} ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true -> CheckedOut;
                        false -> {error, 1}
                    end;
                {Reference, {error, Code}}
                  when Code =:= 0; Code =:= 1; Code =:= 2 ->
                    {error, Code};
                {Reference, _InvalidReply} -> {error, 1};
                {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
            after deadline_remaining(Deadline) ->
                {error, 1}
            end,
            demonitor(Monitor, [flush]),
            _ = erlang:unalias(ReplyAlias),
            flush_http3_operation_replies(Reference),
            case Result of
                {ok, _} -> Result;
                {error, _} ->
                    Owner ! {abandon_http3_lease, self(), Reference},
                    Result
            end;
        _ -> {error, 1}
    end;
checkout_http3_shared_before(_Lifecycle, _Key, _Deadline) ->
    {error, 1}.

%% Only the opaque capability tuple authorizes adoption. The cleanup helper
%% that eventually releases the lease is intentionally not required to be the
%% monitored holder; only the holder monitor moves to the request reaper.
-spec adopt_http3_lease_within(
    http3_lease(), pid(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
adopt_http3_lease_within(
    Lease = {http3_stream_lease, Owner, _Token, _LeaseReference,
        _Capability, _Guard},
    Holder,
    TimeoutMilliseconds
) when is_pid(Owner), is_pid(Holder),
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    adopt_http3_lease_before(Lease, Holder, Deadline);
adopt_http3_lease_within(_Lease, _Holder, _TimeoutMilliseconds) ->
    {error, 1}.

-spec adopt_http3_lease_before(http3_lease(), pid(), integer()) ->
    {ok, nil} | {error, integer()}.
adopt_http3_lease_before(
    Lease = {http3_stream_lease, Owner, _Token, _LeaseReference,
        _Capability, Guard},
    Holder,
    Deadline
) when is_pid(Owner), is_pid(Holder), is_integer(Deadline) ->
    case {erlang:monotonic_time(millisecond) < Deadline,
          http3_lease_guard_state(Guard)} of
        {true, ?HTTP3_LEASE_ACTIVE} ->
            Reference = make_ref(),
            ReplyAlias = erlang:alias(),
            Monitor = monitor(process, Owner),
            Owner ! {adopt_http3_lease, ReplyAlias, Reference, Lease,
                Holder, Deadline},
            Result = receive
                {Reference, {ok, nil}} ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true -> {ok, nil};
                        false -> {error, 1}
                    end;
                {Reference, {error, 1}} -> {error, 1};
                {Reference, _InvalidReply} -> {error, 1};
                {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
            after deadline_remaining(Deadline) ->
                {error, 1}
            end,
            demonitor(Monitor, [flush]),
            _ = erlang:unalias(ReplyAlias),
            flush_http3_operation_replies(Reference),
            Result;
        _ -> {error, 1}
    end;
adopt_http3_lease_before(_Lease, _Holder, _Deadline) ->
    {error, 1}.

%% Release is idempotent. If terminal close owns the physical connection, or
%% if the actor reply is lost after committing the transition, the guard is
%% the finite typed acknowledgement and prevents a close/release cycle.
-spec release_http3_lease_within(
    http3_lease(), boolean(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
release_http3_lease_within(
    Lease = {http3_stream_lease, Owner, _Token, _LeaseReference,
        _Capability, _Guard},
    Reusable,
    TimeoutMilliseconds
) when is_pid(Owner), is_boolean(Reusable),
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    release_http3_lease_before(Lease, Reusable, Deadline);
release_http3_lease_within(_Lease, _Reusable, _TimeoutMilliseconds) ->
    {error, 1}.

-spec release_http3_lease_before(http3_lease(), boolean(), integer()) ->
    {ok, nil} | {error, integer()}.
release_http3_lease_before(
    Lease = {http3_stream_lease, Owner, _Token, _LeaseReference,
        _Capability, Guard},
    Reusable,
    Deadline
) when is_pid(Owner), is_boolean(Reusable), is_integer(Deadline) ->
    case {erlang:monotonic_time(millisecond) < Deadline,
          http3_lease_guard_state(Guard)} of
        {false, _} -> {error, 1};
        {true, ?HTTP3_LEASE_RELEASED} -> {ok, nil};
        {true, ?HTTP3_LEASE_TERMINAL_OWNED} -> {ok, nil};
        {true, ?HTTP3_LEASE_ACTIVE} ->
            Reference = make_ref(),
            ReplyAlias = erlang:alias(),
            Monitor = monitor(process, Owner),
            Owner ! {release_http3_lease, ReplyAlias, Reference, Lease,
                Reusable, Deadline},
            Result = receive
                {Reference, {ok, nil}} ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true -> {ok, nil};
                        false -> {error, 1}
                    end;
                {Reference, {error, 1}} -> {error, 1};
                {Reference, _InvalidReply} -> {error, 1};
                {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
            after deadline_remaining(Deadline) ->
                {error, 1}
            end,
            demonitor(Monitor, [flush]),
            _ = erlang:unalias(ReplyAlias),
            flush_http3_operation_replies(Reference),
            case {erlang:monotonic_time(millisecond) < Deadline, Result,
                  http3_lease_guard_state(Guard)} of
                {true, {ok, nil}, _} -> {ok, nil};
                {true, _, ?HTTP3_LEASE_RELEASED} -> {ok, nil};
                {true, _, ?HTTP3_LEASE_TERMINAL_OWNED} -> {ok, nil};
                _ -> {error, 1}
            end;
        _ -> {error, 1}
    end;
release_http3_lease_before(_Lease, _Reusable, _Deadline) ->
    {error, 1}.

%% A candidate loser is closed through its typed physical owner and remains
%% charged until that owner's DOWN is observed by the lifecycle actor.
-spec retire_http3_candidate_within(registration(), non_neg_integer()) ->
    {ok, nil} | {error, integer()}.
retire_http3_candidate_within(
    {http_client_registration, Owner, Token}, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    Monitor = monitor(process, Owner),
    Owner ! {retire_http3_candidate, ReplyAlias, Reference, Token, Deadline},
    Result = receive
        {Reference, {ok, nil}} -> {ok, nil};
        {Reference, {error, 1}} -> {error, 1};
        {Reference, _InvalidReply} -> {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_http3_operation_replies(Reference),
    case Result of
        {ok, nil} -> Result;
        _ ->
            Owner ! {retire_http3_candidate, Token, Deadline},
            Result
    end;
retire_http3_candidate_within(_Registration, _TimeoutMilliseconds) ->
    {error, 1}.

%% Retire an unselected HTTP/3 candidate and acknowledge only after the
%% physical owner has exited and the charged registry entry has been removed.
%% Expiry forces the owner down but returns an error, preventing a competing
%% connection from being committed without cleanup evidence.
-spec retire_http3_candidate_confirmed_within(
    registration(), non_neg_integer()
) -> {ok, nil} | {error, integer()}.
retire_http3_candidate_confirmed_within(
    {http_client_registration, Owner, Token}, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    retire_http3_candidate_confirmed_before(
        {http_client_registration, Owner, Token}, Deadline
    );
retire_http3_candidate_confirmed_within(
    _Registration, _TimeoutMilliseconds
) ->
    {error, 1}.

-spec retire_http3_candidate_confirmed_before(registration(), integer()) ->
    {ok, nil} | {error, integer()}.
retire_http3_candidate_confirmed_before(
    {http_client_registration, Owner, Token}, Deadline
) when is_integer(Deadline) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Result = resource_call_before(
        Owner,
        {retire_http3_candidate_confirmed, self(), ReplyAlias, Reference,
            Token, Deadline},
        ReplyAlias,
        Reference,
        Deadline
    ),
    case Result of
        {ok, nil} -> Result;
        _ ->
            %% Ordered fallback guarantees eventual retirement even when the
            %% deadline no longer permits reporting successful cleanup.
            Owner ! {retire_http3_candidate, Token, Deadline},
            Result
    end;
retire_http3_candidate_confirmed_before(_Registration, _Deadline) ->
    {error, 1}.

-spec flush_http3_operation_replies(reference()) -> ok.
flush_http3_operation_replies(Reference) ->
    receive
        {Reference, _Reply} -> flush_http3_operation_replies(Reference)
    after 0 -> ok
    end.

-spec cancel_resource(registration()) -> nil.
cancel_resource({http_client_registration, Owner, Token}) ->
    Reference = make_ref(),
    _ = resource_call_within(
        Owner,
        {cancel_resource, self(), Reference, Token},
        Reference,
        ?CLEANUP_TIMEOUT
    ),
    nil;
cancel_resource(_Registration) -> nil.

%% Deadline-aware cancellation used by connection-race guardians. Returning
%% false keeps the guardian's own resource lease quarantined; it never turns
%% an unobserved lifecycle mutation into confirmed cleanup.
-spec cancel_resource_within(registration(), non_neg_integer()) -> boolean().
cancel_resource_within(
    {http_client_registration, Owner, Token}, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    resource_call_within(
        Owner,
        {cancel_resource, self(), Reference, Token},
        Reference,
        TimeoutMilliseconds
    ) =:= {ok, nil};
cancel_resource_within(_Registration, _TimeoutMilliseconds) -> false.

-spec checkin_resource(registration(), binary(), term()) -> boolean().
checkin_resource({http_client_registration, Owner, Token}, Key, Value)
    when is_binary(Key), byte_size(Key) > 0 ->
    Reference = make_ref(),
    resource_call(Owner,
        {checkin_resource, self(), Reference, Token, Key, Value}, Reference)
        =:= {ok, nil};
checkin_resource(_Registration, _Key, _Value) -> false.

%% Deadline-aware check-in for callbacks that must finish before their
%% supervisor's cleanup bound. If this returns false the caller must enqueue a
%% cancellation for the same token; per-sender message ordering then prevents
%% a late check-in from leaving the resource pooled.
-spec checkin_resource_within(
    registration(), binary(), term(), non_neg_integer()
) -> boolean().
checkin_resource_within(
    {http_client_registration, Owner, Token}, Key, Value, TimeoutMilliseconds
) when is_binary(Key), byte_size(Key) > 0,
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Reference = make_ref(),
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    resource_call_within(
        Owner,
        {checkin_resource_before, self(), Reference, Token, Key, Value,
            Deadline},
        Reference,
        TimeoutMilliseconds
    ) =:= {ok, nil};
checkin_resource_within(_Registration, _Key, _Value, _TimeoutMilliseconds) ->
    false.

-spec checkout_resource(lifecycle(), binary()) ->
    {ok, term()} | {error, integer()}.
checkout_resource(#{state := State, owner := Owner}, Key)
    when is_binary(Key), byte_size(Key) > 0 ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            resource_call(Owner,
                {checkout_resource, self(), Reference, Key}, Reference);
        _ -> {error, 1}
    end;
checkout_resource(_Lifecycle, _Key) -> {error, 1}.

%% Bound a reusable-resource checkout by the caller's absolute deadline. The
%% owner validates the same deadline before changing its pool, so a request
%% that waited behind another owner message cannot remove a value after its
%% caller has already timed out.
-spec checkout_resource_within(lifecycle(), binary(), non_neg_integer()) ->
    {ok, term()} | {error, integer()}.
checkout_resource_within(
    #{state := State, owner := Owner}, Key, TimeoutMilliseconds
) when is_binary(Key), byte_size(Key) > 0,
       is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
            ReplyAlias = erlang:alias(),
            try checkout_resource_offer(
                Owner, Key, ReplyAlias, Reference, Deadline
            )
            after
                _ = erlang:unalias(ReplyAlias),
                flush_resource_checkout_replies(Reference)
            end;
        _ -> {error, 1}
    end;
checkout_resource_within(_Lifecycle, _Key, _TimeoutMilliseconds) ->
    {error, 1}.

-spec checkout_resource_offer(
    pid(), binary(), reference(), reference(), integer()
) ->
    {ok, term()} | {error, integer()}.
checkout_resource_offer(Owner, Key, ReplyAlias, Reference, Deadline) ->
    Monitor = monitor(process, Owner),
    Owner ! {checkout_resource_before, self(), ReplyAlias, Reference, Key,
        Deadline},
    Result = receive
        {Reference, {offer, Value}} ->
            checkout_resource_confirm(
                Owner, Monitor, ReplyAlias, Reference, Value, Deadline
            );
        {Reference, {error, Code}} -> {error, Code};
        {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
    after deadline_remaining(Deadline) ->
        Owner ! {abandon_resource_checkout, self(), Reference},
        {error, 1}
    end,
    demonitor(Monitor, [flush]),
    Result.

-spec checkout_resource_confirm(
    pid(), reference(), reference(), reference(), term(), integer()
) -> {ok, term()} | {error, integer()}.
checkout_resource_confirm(
    Owner, Monitor, ReplyAlias, Reference, Value, Deadline
) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        false ->
            Owner ! {abandon_resource_checkout, self(), Reference},
            {error, 1};
        true ->
            Owner ! {confirm_resource_checkout, self(), ReplyAlias, Reference},
            receive
                {Reference, confirmed} ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true -> {ok, Value};
                        false ->
                            Owner ! {abandon_resource_checkout, self(),
                                Reference},
                            {error, 1}
                    end;
                {Reference, rejected} -> {error, 1};
                {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
            after deadline_remaining(Deadline) ->
                Owner ! {abandon_resource_checkout, self(), Reference},
                {error, 1}
            end
    end.

-spec flush_resource_checkout_replies(reference()) -> ok.
flush_resource_checkout_replies(Reference) ->
    receive
        {Reference, _Reply} -> flush_resource_checkout_replies(Reference)
    after 0 -> ok
    end.

-spec deadline_remaining(integer()) -> non_neg_integer().
deadline_remaining(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

-spec resource_call(pid(), tuple(), reference()) ->
    {ok, term()} | {error, integer()}.
resource_call(Owner, Message, Reference) ->
    resource_call_within(Owner, Message, Reference, ?OWNER_TIMEOUT).

-spec resource_call_within(pid(), tuple(), reference(), non_neg_integer()) ->
    {ok, term()} | {error, integer()}.
resource_call_within(Owner, Message, Reference, TimeoutMilliseconds)
    when is_pid(Owner), is_integer(TimeoutMilliseconds),
         TimeoutMilliseconds >= 0, TimeoutMilliseconds =< 2147483647 ->
    Monitor = monitor(process, Owner),
    Owner ! Message,
    receive
        {Reference, Result} -> demonitor(Monitor, [flush]), Result;
        {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
    after TimeoutMilliseconds ->
        demonitor(Monitor, [flush]),
        {error, 1}
    end;
resource_call_within(_Owner, _Message, _Reference, _TimeoutMilliseconds) ->
    {error, 1}.

%% Call a lifecycle actor with the already-established operation deadline.
%% Replies use a process alias, so a response produced after timeout is
%% discarded by the VM instead of becoming residue in a long-lived caller.
-spec resource_call_before(
    pid(), tuple(), reference(), reference(), integer()
) -> {ok, term()} | {error, integer()}.
resource_call_before(Owner, Message, ReplyAlias, Reference, Deadline)
    when is_pid(Owner), is_tuple(Message), is_reference(ReplyAlias),
         is_reference(Reference), is_integer(Deadline) ->
    Monitor = monitor(process, Owner),
    Owner ! Message,
    Result = receive
        {Reference, Reply} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> Reply;
                false -> {error, 1}
            end;
        {'DOWN', Monitor, process, Owner, _Reason} -> {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end,
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_http3_operation_replies(Reference),
    Result;
resource_call_before(_Owner, _Message, ReplyAlias, _Reference, _Deadline) ->
    _ = try erlang:unalias(ReplyAlias) catch _:_ -> false end,
    {error, 1}.

-spec register_with_owner(pid(), binary(), term()) ->
    {ok, registration()} | {error, integer()}.
register_with_owner(Owner, Origin, Socket) ->
    Reference = make_ref(),
    Token = make_ref(),
    Owner ! {register_socket, self(), Reference, Token, Origin, Socket},
    receive
        {Reference, {ok, RegisteredToken}} when is_reference(RegisteredToken) ->
            {ok, {http_client_registration, Owner, RegisteredToken}};
        {Reference, {error, Code}} ->
            {error, Code}
    after ?OWNER_TIMEOUT ->
        _ = http_transport_ffi:close(Socket),
        Owner ! {abandon_socket, Socket},
        {error, 1}
    end.

-spec unregister_socket(registration()) -> nil.
unregister_socket({http_client_registration, Owner, Token}) ->
    Reference = make_ref(),
    _ = resource_call_within(
        Owner,
        {unregister_socket, self(), Reference, Token},
        Reference,
        ?CLEANUP_TIMEOUT
    ),
    nil;
unregister_socket(_Registration) ->
    nil.

%% Confirm lifecycle removal without extending a connection race deadline.
-spec unregister_socket_within(registration(), non_neg_integer()) -> boolean().
unregister_socket_within(
    {http_client_registration, Owner, Token}, TimeoutMilliseconds
) when is_integer(TimeoutMilliseconds), TimeoutMilliseconds >= 0,
       TimeoutMilliseconds =< 2147483647 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMilliseconds,
    unregister_socket_before(
        {http_client_registration, Owner, Token}, Deadline
    );
unregister_socket_within(_Registration, _TimeoutMilliseconds) ->
    false.

-spec unregister_socket_before(registration(), integer()) -> boolean().
unregister_socket_before(
    {http_client_registration, Owner, Token}, Deadline
) when is_integer(Deadline) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Result = resource_call_before(
        Owner,
        {unregister_socket, ReplyAlias, Reference, Token},
        ReplyAlias,
        Reference,
        Deadline
    ),
    case Result of
        {ok, nil} -> true;
        _ ->
            Owner ! {unregister_socket, Token},
            false
    end;
unregister_socket_before(_Registration, _Deadline) ->
    false.

-spec checkout_socket(lifecycle(), binary()) ->
    {ok, term()} | {error, integer()}.
checkout_socket(#{state := State, owner := Owner}, Origin)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> checkout_from_owner(Owner, Origin);
        _ -> {error, 1}
    end;
checkout_socket(_Lifecycle, _Origin) ->
    {error, 1}.

-spec checkout_from_owner(pid(), binary()) ->
    {ok, term()} | {error, integer()}.
checkout_from_owner(Owner, Origin) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
    Monitor = monitor(process, Owner),
    Owner ! {
        checkout_socket, self(), ReplyAlias, Reference, Origin, Deadline
    },
    Result = await_socket_checkout_offer(
        Owner, Monitor, ReplyAlias, Reference, Deadline
    ),
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_socket_handoff_replies(Reference),
    Result.

-spec await_socket_checkout_offer(
    pid(), reference(), reference(), reference(), integer()
) -> {ok, term()} | {error, integer()}.
await_socket_checkout_offer(Owner, Monitor, ReplyAlias, Reference, Deadline) ->
    receive
        {Reference, {socket_handoff_offer, HandoffReference, Socket}} ->
            Owner ! {socket_handoff_ready, self(), HandoffReference},
            await_socket_checkout_commit(
                Owner, Monitor, ReplyAlias, Reference, HandoffReference,
                Socket, Deadline
            );
        {Reference, empty} ->
            {error, 0};
        {Reference, closed} ->
            {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} ->
            {error, 1}
    after deadline_remaining(Deadline) ->
        {error, 1}
    end.

-spec await_socket_checkout_commit(
    pid(), reference(), reference(), reference(), reference(), term(), integer()
) -> {ok, term()} | {error, integer()}.
await_socket_checkout_commit(
    Owner, Monitor, ReplyAlias, Reference, HandoffReference, Socket, Deadline
) ->
    receive
        {Reference, {socket_handoff_committed, HandoffReference}} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {ok, Socket};
                false ->
                    _ = http_transport_ffi:close(Socket),
                    {error, 1}
            end;
        {Reference, {socket_handoff_retry, HandoffReference}} ->
            _ = http_transport_ffi:close(Socket),
            await_socket_checkout_offer(
                Owner, Monitor, ReplyAlias, Reference, Deadline
            );
        {Reference, {socket_handoff_rejected, HandoffReference}} ->
            _ = http_transport_ffi:close(Socket),
            {error, 1};
        {'DOWN', Monitor, process, Owner, _Reason} ->
            _ = http_transport_ffi:close(Socket),
            {error, 1}
    after deadline_remaining(Deadline) ->
        Owner ! {abort_socket_handoff, self(), HandoffReference},
        _ = http_transport_ffi:close(Socket),
        {error, 1}
    end.

-spec checkin_socket(lifecycle(), binary(), term()) -> boolean().
checkin_socket(
    #{state := State, owner := Owner},
    Origin,
    Socket
) when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> checkin_with_owner(Owner, Origin, Socket);
        _ ->
            _ = http_transport_ffi:close(Socket),
            false
    end;
checkin_socket(_Lifecycle, _Origin, Socket) ->
    _ = http_transport_ffi:close(Socket),
    false.

-spec checkin_with_owner(pid(), binary(), term()) -> boolean().
checkin_with_owner(Owner, Origin, Socket) ->
    Reference = make_ref(),
    HandoffReference = make_ref(),
    ReplyAlias = erlang:alias(),
    Deadline = erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
    Monitor = monitor(process, Owner),
    Owner ! {
        checkin_socket, self(), ReplyAlias, Reference, HandoffReference,
        Origin, Socket, Deadline
    },
    Result = await_socket_checkin_ready(
        Owner, Monitor, Reference, HandoffReference, Socket, Deadline
    ),
    demonitor(Monitor, [flush]),
    _ = erlang:unalias(ReplyAlias),
    flush_socket_handoff_replies(Reference),
    case Result of
        true -> true;
        false ->
            _ = http_transport_ffi:close(Socket),
            false
    end.

-spec await_socket_checkin_ready(
    pid(), reference(), reference(), reference(), term(), integer()
) -> boolean().
await_socket_checkin_ready(
    Owner, Monitor, Reference, HandoffReference, Socket, Deadline
) ->
    receive
        {Reference, {socket_handoff_ready, HandoffReference}} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                false -> false;
                true ->
                    case http_transport_ffi:transfer_owner(Socket, Owner) of
                        {ok, nil} ->
                            Owner ! {
                                socket_handoff_transferred, self(),
                                HandoffReference
                            },
                            await_socket_checkin_commit(
                                Owner, Monitor, Reference, HandoffReference,
                                Deadline
                            );
                        {error, _Reason} ->
                            Owner ! {
                                abort_socket_handoff, self(), HandoffReference
                            },
                            false
                    end
            end;
        {Reference, {socket_handoff_rejected, HandoffReference}} ->
            false;
        {'DOWN', Monitor, process, Owner, _Reason} ->
            false
    after deadline_remaining(Deadline) ->
        Owner ! {abort_socket_handoff, self(), HandoffReference},
        false
    end.

-spec await_socket_checkin_commit(
    pid(), reference(), reference(), reference(), integer()
) -> boolean().
await_socket_checkin_commit(
    Owner, Monitor, Reference, HandoffReference, Deadline
) ->
    receive
        {Reference, {socket_handoff_committed, HandoffReference}} ->
            erlang:monotonic_time(millisecond) < Deadline;
        {Reference, {socket_handoff_rejected, HandoffReference}} ->
            false;
        {'DOWN', Monitor, process, Owner, _Reason} ->
            false
    after deadline_remaining(Deadline) ->
        Owner ! {abort_socket_handoff, self(), HandoffReference},
        false
    end.

-spec close(lifecycle()) -> nil.
close(Lifecycle) ->
    _ = close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
        true
    ),
    nil.

%% Deadline-aware typed close used by the public client. The join-confirmation
%% argument is an explicit deterministic test seam; production always passes
%% true. Every process-owned connection monitor shares the same absolute
%% deadline and remains owned by the lifecycle until its DOWN is confirmed.
-spec close_before(lifecycle(), integer(), boolean()) ->
    {ok, nil} | {error, integer()}.
close_before(#{state := State, owner := Owner}, Deadline, JoinConfirmation)
    when is_integer(Deadline), is_boolean(JoinConfirmation) ->
    try close_state_before(State, Owner, Deadline, JoinConfirmation)
    catch
        _Class:_Reason -> {error, 1}
    end;
close_before(_Lifecycle, _Deadline, _JoinConfirmation) ->
    {error, 1}.

-spec close_state_before(
    atomics:atomics_ref(), pid(), integer(), boolean()
) -> {ok, nil} | {error, integer()}.
close_state_before(State, Owner, Deadline, JoinConfirmation) ->
    case safe_state(State) of
        Open when Open =:= 0; Open =:= 1 ->
            case atomics:compare_exchange(State, 1, Open, 2) of
                ok ->
                    close_owner_before(
                        State, Owner, Deadline, JoinConfirmation
                    );
                _Actual ->
                    close_state_before(
                        State, Owner, Deadline, JoinConfirmation
                    )
            end;
        2 ->
            await_closed_before(State, Deadline);
        3 ->
            {ok, nil};
        4 ->
            await_closed_before(State, Deadline);
        _ ->
            {error, 1}
    end.

-spec close_owner_before(
    atomics:atomics_ref(), pid(), integer(), boolean()
) -> {ok, nil} | {error, integer()}.
close_owner_before(State, Owner, Deadline, JoinConfirmation) ->
    Reference = make_ref(),
    ReplyAlias = erlang:alias(),
    Monitor = monitor(process, Owner),
    Owner ! {
        close_before,
        ReplyAlias,
        Reference,
        Deadline,
        JoinConfirmation
    },
    try
        receive
            {Reference, {ok, nil}} ->
                await_lifecycle_owner_down(
                    State, Owner, Monitor, Deadline
                );
            {Reference, {error, _Code}} ->
                {error, 1};
            {'DOWN', Monitor, process, Owner, _Reason} ->
                close_state_result(State)
        after deadline_remaining(Deadline) ->
            {error, 1}
        end
    after
        _ = erlang:unalias(ReplyAlias),
        demonitor(Monitor, [flush])
    end.

-spec await_lifecycle_owner_down(
    atomics:atomics_ref(), pid(), reference(), integer()
) -> {ok, nil} | {error, integer()}.
await_lifecycle_owner_down(State, Owner, Monitor, Deadline) ->
    receive
        {'DOWN', Monitor, process, Owner, _Reason} ->
            close_state_result(State)
    after deadline_remaining(Deadline) ->
        {error, 1}
    end.

-spec close_state_result(atomics:atomics_ref()) ->
    {ok, nil} | {error, integer()}.
close_state_result(State) ->
    case safe_state(State) of
        3 -> {ok, nil};
        _ -> {error, 1}
    end.

-spec await_closed_before(atomics:atomics_ref(), integer()) ->
    {ok, nil} | {error, integer()}.
await_closed_before(State, Deadline) ->
    case safe_state(State) of
        3 ->
            {ok, nil};
        Closing when Closing =:= 2; Closing =:= 4 ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    receive after 1 ->
                        await_closed_before(State, Deadline)
                    end;
                false ->
                    {error, 1}
            end;
        _ ->
            {error, 1}
    end.

-spec lifecycle_loop(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pool_limits()
) -> no_return().
lifecycle_loop(State, ExistingSockets, ExistingPool, Limits) ->
    {Sockets, Pool} = prune_expired(
        State, ExistingSockets, ExistingPool, Limits
    ),
    receive
        {begin_http3_dial, Sender, ReplyAlias, Reference, Origin, Key,
                Deadline} ->
            begin_http3_dial(
                State, Sockets, Pool, Sender, ReplyAlias, Reference,
                Origin, Key, Deadline, Limits
            );
        {abandon_http3_dial, Sender, Reference} ->
            abandon_http3_dial(
                State, Sockets, Pool, Sender, Reference, Limits
            );
        {settle_http3_dial_probe, Sender, Reference, Token, Published,
                Deadline} ->
            settle_http3_dial_probe(
                State, Sockets, Pool, Sender, Reference, Token,
                Published, Deadline, Limits
            );
        {expire_http3_dial_waiters_probe, Sender, Reference, Token,
                AdvanceMilliseconds, Deadline} ->
            expire_http3_dial_waiters_probe(
                State, Sockets, Pool, Sender, Reference, Token,
                AdvanceMilliseconds, Deadline, Limits
            );
        {reserve_resource_before, Sender, ReplyAlias, Token, Origin,
                Deadline} ->
            BeforeDeadline =
                erlang:monotonic_time(millisecond) < Deadline,
            case BeforeDeadline andalso safe_state(State) =:= 0
                    andalso is_process_alive(Sender) of
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Token, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits);
                true ->
                    case connection_has_capacity(Origin, Sockets, Limits) of
                        false ->
                            send_resource_checkout_reply(
                                ReplyAlias, {Token, {error, 2}}
                            ),
                            lifecycle_loop(State, Sockets, Pool, Limits);
                        true ->
                            Monitor = monitor(process, Sender),
                            Entry = {Token, Origin,
                                {resource_reservation, Sender, Monitor}},
                            send_resource_checkout_reply(
                                ReplyAlias, {Token, {ok, nil}}
                            ),
                            lifecycle_loop(
                                State, [Entry | Sockets], Pool, Limits
                            )
                    end
            end;
        {reserve_resource, Sender, Token, Origin} ->
            case safe_state(State) =:= 0 andalso is_process_alive(Sender) of
                false ->
                    Sender ! {Token, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits);
                true ->
                    case connection_has_capacity(Origin, Sockets, Limits) of
                        false ->
                            Sender ! {Token, {error, 2}},
                            lifecycle_loop(State, Sockets, Pool, Limits);
                        true ->
                            Monitor = monitor(process, Sender),
                            Entry = {Token, Origin, {resource_reservation, Sender, Monitor}},
                            Sender ! {Token, {ok, nil}},
                            lifecycle_loop(State, [Entry | Sockets], Pool, Limits)
                    end
            end;
        {attach_resource, Sender, Reference, Token, ResourceOwner} ->
            case {safe_state(State), lists:keyfind(Token, 1, Sockets)} of
                {0, {Token, Origin, {resource_reservation, _Caller, Monitor}}}
                    when is_pid(ResourceOwner) ->
                    demonitor(Monitor, [flush]),
                    ResourceMonitor = monitor(process, ResourceOwner),
                    Entry = {Token, Origin, {owned_resource, ResourceOwner, ResourceMonitor}},
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(State, [Entry | lists:keydelete(Token, 1, Sockets)], Pool, Limits);
                _ ->
                    exit(ResourceOwner, kill),
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {attach_http3_resource, Sender, Reference, Token,
                ResourceOwner = {http3_resource_owner, PhysicalOwner, Tag}}
            when is_pid(PhysicalOwner), is_reference(Tag) ->
            case {safe_state(State), lists:keyfind(Token, 1, Sockets)} of
                {0, {Token, Origin,
                        {http3_dial, Key, Leader, LeaderMonitor,
                            ClaimReference, DialDeadline, none, Waiters}}} ->
                    ResourceMonitor = monitor(process, PhysicalOwner),
                    Attached = {http3_dial, Key, Leader, LeaderMonitor,
                        ClaimReference, DialDeadline,
                        {ResourceOwner, ResourceMonitor}, Waiters},
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(
                        State,
                        store_socket(Token, Origin, Attached, Sockets),
                        Pool,
                        Limits
                    );
                {0, {Token, Origin,
                        {resource_reservation, _Caller, Monitor}}} ->
                    demonitor(Monitor, [flush]),
                    ResourceMonitor = monitor(process, PhysicalOwner),
                    Entry = {Token, Origin,
                        {owned_resource, ResourceOwner, ResourceMonitor}},
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(
                        State,
                        [Entry | lists:keydelete(Token, 1, Sockets)],
                        Pool,
                        Limits
                    );
                _ ->
                    force_resource_owner_shutdown(ResourceOwner),
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {attach_http3_resource, Sender, Reference, _Token, _ResourceOwner} ->
            Sender ! {Reference, {error, 1}},
            lifecycle_loop(State, Sockets, Pool, Limits);
        {activate_http3_candidate, Sender, ReplyAlias, LeaseReference,
                Token, Key, Connection, AllowShare, Deadline} ->
            activate_http3_candidate(
                State, Sockets, Pool, Sender, ReplyAlias, LeaseReference,
                Token, Key, Connection, AllowShare, Deadline, Limits
            );
        {checkout_http3_shared, Sender, ReplyAlias, LeaseReference, Key,
                Deadline} ->
            checkout_http3_shared(
                State, Sockets, Pool, Sender, ReplyAlias, LeaseReference,
                Key, Deadline, Limits
            );
        {adopt_http3_lease, Sender, Reference, Lease, Holder, Deadline} ->
            adopt_http3_lease(
                State, Sockets, Pool, Sender, Reference, Lease, Holder,
                Deadline, Limits
            );
        {release_http3_lease, Sender, Reference, Lease, Reusable, Deadline} ->
            release_http3_lease(
                State, Sockets, Pool, Sender, Reference, Lease, Reusable,
                Deadline, Limits
            );
        {abandon_http3_lease, Sender, LeaseReference} ->
            abandon_http3_lease(
                State, Sockets, Pool, Sender, LeaseReference, Limits
            );
        {retire_http3_candidate_confirmed, _Sender, ReplyAlias, Reference,
                Token, Deadline} ->
            UpdatedSockets = retire_http3_candidate_entries(
                Sockets, Token, Deadline
            ),
            case await_http3_candidate_retirement(
                UpdatedSockets, Token, Deadline
            ) of
                {confirmed, ConfirmedSockets} ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {ok, nil}}
                    ),
                    lifecycle_loop(
                        State, ConfirmedSockets,
                        remove_pool_token(Token, Pool), Limits
                    );
                {unconfirmed, UnconfirmedSockets} ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(
                        State, UnconfirmedSockets,
                        remove_pool_token(Token, Pool), Limits
                    )
            end;
        {retire_http3_candidate, Sender, Reference, Token, Deadline} ->
            UpdatedSockets = retire_http3_candidate_entries(
                Sockets, Token, Deadline
            ),
            send_resource_checkout_reply(
                Sender, {Reference, {ok, nil}}
            ),
            lifecycle_loop(State, UpdatedSockets, Pool, Limits);
        {retire_http3_candidate, Token, Deadline} ->
            lifecycle_loop(
                State,
                retire_http3_candidate_entries(Sockets, Token, Deadline),
                Pool,
                Limits
            );
        {attach_reserved_socket_before, Sender, ReplyAlias, Reference, Token,
                Socket, Deadline} ->
            BeforeDeadline = is_integer(Deadline) andalso
                erlang:monotonic_time(millisecond) < Deadline,
            case {BeforeDeadline, safe_state(State), is_process_alive(Sender),
                  lists:keyfind(Token, 1, Sockets)} of
                {true, 0, true,
                 {Token, Origin,
                  {resource_reservation, Sender, Monitor}}} ->
                    Owned = new_owned_socket(Socket, Sender),
                    demonitor(Monitor, [flush]),
                    Entry = {Token, Origin, Owned},
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {ok, nil}}
                    ),
                    lifecycle_loop(State,
                        [Entry | lists:keydelete(Token, 1, Sockets)], Pool,
                        Limits);
                _ ->
                    _ = http_transport_ffi:close(Socket),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {attach_reserved_socket, Sender, Reference, Token, Socket} ->
            case {safe_state(State), is_process_alive(Sender),
                  lists:keyfind(Token, 1, Sockets)} of
                {0, true, {Token, Origin, {resource_reservation, Sender, Monitor}}} ->
                    Owned = new_owned_socket(Socket, Sender),
                    demonitor(Monitor, [flush]),
                    Entry = {Token, Origin, Owned},
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(State,
                        [Entry | lists:keydelete(Token, 1, Sockets)], Pool, Limits);
                _ ->
                    _ = http_transport_ffi:close(Socket),
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {replace_socket_before, Sender, ReplyAlias, Token, Previous, Socket,
                Deadline} ->
            BeforeDeadline = is_integer(Deadline) andalso
                erlang:monotonic_time(millisecond) < Deadline,
            case {BeforeDeadline, safe_state(State), is_process_alive(Sender),
                  socket_token(Previous, Sockets)} of
                {true, 0, true, {ok, PreviousToken}} ->
                    {PreviousToken, Origin, PreviousOwned} =
                        lists:keyfind(PreviousToken, 1, Sockets),
                    case owned_socket_owner(PreviousOwned) =:= Sender of
                        true ->
                            Owned = new_owned_socket(Socket, Sender),
                            release_registered_monitor(PreviousOwned),
                            Entry = {Token, Origin, Owned},
                            send_resource_checkout_reply(
                                ReplyAlias, {Token, {ok, nil}}
                            ),
                            lifecycle_loop(State,
                                [Entry |
                                 lists:keydelete(PreviousToken, 1, Sockets)],
                                remove_pool_token(PreviousToken, Pool),
                                Limits);
                        false ->
                            _ = http_transport_ffi:close(Socket),
                            send_resource_checkout_reply(
                                ReplyAlias, {Token, {error, 1}}
                            ),
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                _ ->
                    _ = http_transport_ffi:close(Socket),
                    send_resource_checkout_reply(
                        ReplyAlias, {Token, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {replace_socket, Sender, Token, Previous, Socket} ->
            case {safe_state(State), is_process_alive(Sender),
                  socket_token(Previous, Sockets)} of
                {0, true, {ok, PreviousToken}} ->
                    {PreviousToken, Origin, PreviousOwned} =
                        lists:keyfind(PreviousToken, 1, Sockets),
                    case owned_socket_owner(PreviousOwned) =:= Sender of
                        true ->
                            Owned = new_owned_socket(Socket, Sender),
                            release_registered_monitor(PreviousOwned),
                            Entry = {Token, Origin, Owned},
                            Sender ! {Token, {ok, nil}},
                            lifecycle_loop(State,
                                [Entry | lists:keydelete(PreviousToken, 1, Sockets)],
                                remove_pool_token(PreviousToken, Pool), Limits);
                        false ->
                            _ = http_transport_ffi:close(Socket),
                            Sender ! {Token, {error, 1}},
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                _ ->
                    _ = http_transport_ffi:close(Socket),
                    Sender ! {Token, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {cancel_resource, Sender, Reference, Token} ->
            UpdatedSockets = case lists:keyfind(Token, 1, Sockets) of
                {Token, Origin, Dial = {http3_dial, _, _, _, _, _, _, _}} ->
                    retire_http3_dial_entry(
                        Token, Origin, Dial,
                        erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
                        failed, Sockets
                    );
                {Token, _, Value} ->
                    reject_pending_resource_checkout(Value),
                    close_registered_value(Value),
                    lists:keydelete(Token, 1, Sockets);
                false -> Sockets
            end,
            Sender ! {Reference, {ok, nil}},
            lifecycle_loop(State, UpdatedSockets,
                remove_pool_token(Token, Pool), Limits);
        {checkin_resource_before, Sender, Reference, Token, Key, Value,
                Deadline} ->
            BeforeDeadline =
                erlang:monotonic_time(millisecond) < Deadline,
            case {BeforeDeadline, safe_state(State),
                    lists:keyfind(Token, 1, Sockets)} of
                {true, 0, {Token, Origin, Registered}} ->
                    case resource_for_checkin(Registered) of
                        {ok, ResourceOwner, ResourceMonitor} ->
                            case resource_owner_alive(ResourceOwner)
                                    andalso is_process_alive(Sender) of
                                true ->
                                    release_checkout_monitor(Registered),
                                    Owned = {owned_resource, ResourceOwner,
                                        ResourceMonitor},
                                    UpdatedSockets = store_socket(
                                        Token, Origin, Owned, Sockets
                                    ),
                                    {_Maximum, _PerOrigin, Idle} = Limits,
                                    PoolDeadline =
                                        erlang:monotonic_time(millisecond)
                                        + Idle,
                                    Updated = [{Key, Token,
                                        {resource_value, Value}, PoolDeadline} |
                                        remove_pool_token(Token, Pool)],
                                    Sender ! {Reference, {ok, nil}},
                                    lifecycle_loop(
                                        State,
                                        UpdatedSockets,
                                        Updated,
                                        Limits
                                    );
                                false ->
                                    Sender ! {Reference, {error, 1}},
                                    lifecycle_loop(
                                        State, Sockets, Pool, Limits
                                    )
                            end;
                        error ->
                            Sender ! {Reference, {error, 1}},
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                _ ->
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {checkin_resource, Sender, Reference, Token, Key, Value} ->
            case {safe_state(State), lists:keyfind(Token, 1, Sockets)} of
                {0, {Token, Origin, Registered}} ->
                    case resource_for_checkin(Registered) of
                        {ok, ResourceOwner, ResourceMonitor} ->
                            case resource_owner_alive(ResourceOwner)
                                    andalso is_process_alive(Sender) of
                                true ->
                                    release_checkout_monitor(Registered),
                                    Owned = {owned_resource, ResourceOwner,
                                        ResourceMonitor},
                                    UpdatedSockets = store_socket(
                                        Token, Origin, Owned, Sockets
                                    ),
                                    {_Maximum, _PerOrigin, Idle} = Limits,
                                    Deadline =
                                        erlang:monotonic_time(millisecond)
                                        + Idle,
                                    Updated = [{Key, Token,
                                        {resource_value, Value}, Deadline} |
                                        remove_pool_token(Token, Pool)],
                                    Sender ! {Reference, {ok, nil}},
                                    lifecycle_loop(
                                        State,
                                        UpdatedSockets,
                                        Updated,
                                        Limits
                                    );
                                false ->
                                    Sender ! {Reference, {error, 1}},
                                    lifecycle_loop(
                                        State, Sockets, Pool, Limits
                                    )
                            end;
                        error ->
                            Sender ! {Reference, {error, 1}},
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                _ ->
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {checkout_resource, Sender, Reference, Key} ->
            case {safe_state(State), take_origin(Key, Pool, [])} of
                {0, {found, Token, {resource_value, Value}, Remaining}} ->
                    case is_process_alive(Sender) andalso live_resource(Token, Sockets) of
                        true ->
                            Sender ! {Reference, {ok, Value}},
                            lifecycle_loop(State, Sockets, Remaining, Limits);
                        false ->
                            Sender ! {Reference, {error, 0}},
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                {0, _} ->
                    Sender ! {Reference, {error, 0}},
                    lifecycle_loop(State, Sockets, Pool, Limits);
                _ ->
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {checkout_resource_before, Sender, ReplyAlias, Reference, Key,
                Deadline} ->
            BeforeDeadline =
                erlang:monotonic_time(millisecond) < Deadline,
            case {BeforeDeadline, safe_state(State),
                    is_process_alive(Sender),
                    pending_resource_has_capacity(Sockets, Limits)} of
                {true, 0, true, true} ->
                    offer_resource_checkout(
                        State,
                        Sockets,
                        Pool,
                        Key,
                        Sender,
                        ReplyAlias,
                        Reference,
                        Deadline,
                        Limits
                    );
                {true, 0, true, false} ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 2}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits);
                _ ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {confirm_resource_checkout, Sender, ReplyAlias, Reference} ->
            confirm_resource_checkout(
                State, Sockets, Pool, Sender, ReplyAlias, Reference, Limits
            );
        {abandon_resource_checkout, Sender, Reference} ->
            abandon_resource_checkout(
                State, Sockets, Pool, Sender, Reference, Limits
            );
        {'DOWN', Monitor, process, _Pid, _Reason} ->
            handle_registered_down(
                State, Sockets, Pool, Monitor, Limits
            );
        {register_socket_before, Sender, ReplyAlias, Reference,
                RequestedToken, Origin, Socket, Deadline} ->
            BeforeDeadline = is_integer(Deadline) andalso
                erlang:monotonic_time(millisecond) < Deadline,
            case BeforeDeadline andalso safe_state(State) =:= 0
                    andalso is_process_alive(Sender) of
                true ->
                    case register_or_refresh(
                        RequestedToken,
                        Origin,
                        Socket,
                        Sender,
                        Sockets,
                        Limits
                    ) of
                        {ok, Token, UpdatedSockets} ->
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {ok, Token}}
                            ),
                            lifecycle_loop(
                                State,
                                UpdatedSockets,
                                Pool,
                                Limits
                            );
                        {handoff, Token} ->
                            close_registered_value(
                                owned_socket_value(Token, Sockets)
                            ),
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {error, 1}}
                            ),
                            lifecycle_loop(
                                State,
                                lists:keydelete(Token, 1, Sockets),
                                remove_pool_token(Token, Pool),
                                Limits
                            );
                        capacity ->
                            _ = http_transport_ffi:close(Socket),
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {error, 2}}
                            ),
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                false ->
                    _ = http_transport_ffi:close(Socket),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {register_socket, Sender, Reference, RequestedToken, Origin, Socket} ->
            case safe_state(State) =:= 0 andalso is_process_alive(Sender) of
                true ->
                    case register_or_refresh(
                        RequestedToken,
                        Origin,
                        Socket,
                        Sender,
                        Sockets,
                        Limits
                    ) of
                        {ok, Token, UpdatedSockets} ->
                            Sender ! {Reference, {ok, Token}},
                            lifecycle_loop(
                                State,
                                UpdatedSockets,
                                Pool,
                                Limits
                            );
                        {handoff, Token} ->
                            close_registered_value(
                                owned_socket_value(Token, Sockets)
                            ),
                            Sender ! {Reference, {error, 1}},
                            lifecycle_loop(
                                State,
                                lists:keydelete(Token, 1, Sockets),
                                remove_pool_token(Token, Pool),
                                Limits
                            );
                        capacity ->
                            _ = http_transport_ffi:close(Socket),
                            Sender ! {Reference, {error, 2}},
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                false ->
                    _ = http_transport_ffi:close(Socket),
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {begin_socket_handoff, Sender, ReplyAlias, Reference,
                HandoffReference, Socket, Previous, Owner, Deadline} ->
            BeforeDeadline = is_integer(Deadline) andalso
                erlang:monotonic_time(millisecond) < Deadline,
            case BeforeDeadline andalso safe_state(State) =:= 0
                andalso is_pid(Sender)
                andalso is_pid(Previous)
                andalso is_pid(Owner)
                andalso is_process_alive(Sender)
                andalso is_process_alive(Previous)
                andalso is_process_alive(Owner)
            of
                true ->
                    case begin_socket_handoff_entry(
                        HandoffReference, Socket, Previous, Owner, Deadline,
                        Sockets
                    ) of
                        {ok, Token, UpdatedSockets} ->
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {ok, nil}}
                            ),
                            lifecycle_loop(
                                State,
                                UpdatedSockets,
                                remove_pool_token(Token, Pool),
                                Limits
                            );
                        error ->
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {error, 1}}
                            ),
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {commit_socket_handoff, Sender, ReplyAlias, Reference,
                HandoffReference, Deadline} ->
            BeforeDeadline = is_integer(Deadline) andalso
                erlang:monotonic_time(millisecond) < Deadline,
            case BeforeDeadline andalso safe_state(State) =:= 0
                andalso is_pid(Sender)
                andalso is_process_alive(Sender)
            of
                true ->
                    case commit_socket_handoff_entry(
                        HandoffReference, Sockets
                    ) of
                        {ok, UpdatedSockets} ->
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {ok, nil}}
                            ),
                            lifecycle_loop(
                                State, UpdatedSockets, Pool, Limits
                            );
                        error ->
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {error, 1}}
                            ),
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                false ->
                    {AbortedSockets, AbortedPool} =
                        abort_socket_handoff_entry(
                            HandoffReference, Sockets, Pool
                        ),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(
                        State, AbortedSockets, AbortedPool, Limits
                    )
            end;
        {abort_socket_handoff, HandoffReference} ->
            {AbortedSockets, AbortedPool} = abort_socket_handoff_entry(
                HandoffReference, Sockets, Pool
            ),
            lifecycle_loop(State, AbortedSockets, AbortedPool, Limits);
        {abort_socket_handoff, _Sender, HandoffReference} ->
            {AbortedSockets, AbortedPool} = abort_socket_handoff_entry(
                HandoffReference, Sockets, Pool
            ),
            lifecycle_loop(State, AbortedSockets, AbortedPool, Limits);
        {socket_handoff_ready, _Sender, _HandoffReference} ->
            lifecycle_loop(State, Sockets, Pool, Limits);
        {socket_handoff_transferred, _Sender, _HandoffReference} ->
            lifecycle_loop(State, Sockets, Pool, Limits);
        {lifecycle_snapshot, Sender, Reference} ->
            CallerOwned = length([
                ok ||
                    {_Token, _Origin,
                        {owned_socket, _Socket, SocketOwner, _Monitor}}
                        <- Sockets,
                    SocketOwner =:= Sender
            ]),
            Monitored = length([
                ok || {_Token, _Origin, Value} <- Sockets,
                    resource_monitor(Value) =/= none
            ]),
            Pooled = length(Pool) + http3_idle_shared_count(Sockets),
            Sender ! {Reference, {ok, {
                length(Sockets), Pooled, CallerOwned, Monitored
            }}},
            lifecycle_loop(State, Sockets, Pool, Limits);
        {http3_shared_snapshot, Sender, Reference} ->
            send_resource_checkout_reply(
                Sender, {Reference, {ok, http3_shared_counts(Sockets)}}
            ),
            lifecycle_loop(State, Sockets, Pool, Limits);
        {http3_dial_snapshot, Sender, Reference} ->
            send_resource_checkout_reply(
                Sender, {Reference, {ok, http3_dial_counts(Sockets)}}
            ),
            lifecycle_loop(State, Sockets, Pool, Limits);
        {lifecycle_pending_count, Sender, Reference} ->
            Sender ! {Reference, {ok, pending_resource_count(Sockets)}},
            lifecycle_loop(State, Sockets, Pool, Limits);
        {unregister_socket, Sender, Reference, Token} ->
            case lists:keyfind(Token, 1, Sockets) of
                {Token, Origin,
                 Shared = {shared_http3, _, _, _, _, _, _, _, _}} ->
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(
                        State,
                        store_socket(
                            Token, Origin,
                            terminalize_http3_shared_value(Shared, true),
                            Sockets
                        ),
                        remove_pool_token(Token, Pool),
                        Limits
                    );
                {Token, _, {closing_http3_candidate, _, _, _}} ->
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(State, Sockets, Pool, Limits);
                {Token, Origin,
                 Dial = {http3_dial, _, _, _, _, _, _, _}} ->
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(
                        State,
                        retire_http3_dial_entry(
                            Token, Origin, Dial,
                            erlang:monotonic_time(millisecond)
                                + ?OWNER_TIMEOUT,
                            failed, Sockets
                        ),
                        remove_pool_token(Token, Pool),
                        Limits
                    );
                _ ->
                    release_resource_monitor(Token, Sockets),
                    Sender ! {Reference, {ok, nil}},
                    lifecycle_loop(
                        State,
                        lists:keydelete(Token, 1, Sockets),
                        remove_pool_token(Token, Pool),
                        Limits
                    )
            end;
        {unregister_socket, Token} ->
            case lists:keyfind(Token, 1, Sockets) of
                {Token, Origin,
                 Shared = {shared_http3, _, _, _, _, _, _, _, _}} ->
                    lifecycle_loop(
                        State,
                        store_socket(
                            Token, Origin,
                            terminalize_http3_shared_value(Shared, true),
                            Sockets
                        ),
                        remove_pool_token(Token, Pool),
                        Limits
                    );
                {Token, _, {closing_http3_candidate, _, _, _}} ->
                    lifecycle_loop(State, Sockets, Pool, Limits);
                {Token, Origin,
                 Dial = {http3_dial, _, _, _, _, _, _, _}} ->
                    lifecycle_loop(
                        State,
                        retire_http3_dial_entry(
                            Token, Origin, Dial,
                            erlang:monotonic_time(millisecond)
                                + ?OWNER_TIMEOUT,
                            failed, Sockets
                        ),
                        remove_pool_token(Token, Pool),
                        Limits
                    );
                _ ->
                    release_resource_monitor(Token, Sockets),
                    lifecycle_loop(
                        State,
                        lists:keydelete(Token, 1, Sockets),
                        remove_pool_token(Token, Pool),
                        Limits
                    )
            end;
        {abandon_socket, Socket} ->
            case socket_token(Socket, Sockets) of
                {ok, Token} ->
                    lifecycle_loop(
                        State,
                        drop_registered_token(Token, Sockets),
                        remove_pool_token(Token, Pool),
                        Limits
                    );
                error -> lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {checkout_socket, Sender, ReplyAlias, Reference, Origin, Deadline} ->
            case safe_state(State) of
                0 ->
                    checkout_pooled(
                        State,
                        Sockets,
                        Pool,
                        Origin,
                        Sender,
                        ReplyAlias,
                        Reference,
                        Deadline,
                        Limits
                    );
                _ ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, closed}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {checkin_socket, Sender, ReplyAlias, Reference, HandoffReference,
                Origin, Socket, Deadline} ->
            checkin_pooled(
                State,
                Sockets,
                Pool,
                Origin,
                Socket,
                Sender,
                ReplyAlias,
                Reference,
                HandoffReference,
                Deadline,
                Limits
            );
        drain_pool ->
            {RemainingSockets, _EmptyPool} = close_pool(Sockets, Pool),
            Http3Deadline = erlang:monotonic_time(millisecond)
                + ?OWNER_TIMEOUT,
            DrainingSockets = drain_http3_shared_entries(
                RemainingSockets, Http3Deadline
            ),
            {DrainedSockets, DrainedPool} = prune_pending_resources(
                State,
                DrainingSockets,
                [],
                Limits,
                erlang:monotonic_time(millisecond)
            ),
            lifecycle_loop(State, DrainedSockets, DrainedPool, Limits);
        {close_before, ReplyAlias, Reference, Deadline, JoinConfirmation} ->
            PendingOwnerMonitors = begin_registered_shutdown(
                Sockets, Deadline
            ),
            case await_registered_shutdown(
                PendingOwnerMonitors, Deadline, JoinConfirmation
            ) of
                joined ->
                    atomics:put(State, 1, 3),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {ok, nil}}
                    ),
                    exit(normal);
                {unconfirmed, UnconfirmedMonitors} ->
                    atomics:put(State, 1, 4),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_close_quarantine(State, UnconfirmedMonitors)
            end
    after lifecycle_wait(Sockets, Pool, Limits) ->
        lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec begin_http3_dial(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), binary(), binary(), integer(), pool_limits()
) -> no_return().
begin_http3_dial(
    State, Sockets, Pool, Sender, ReplyAlias, Reference, Origin, Key,
    Deadline, Limits
) ->
    BeforeDeadline = erlang:monotonic_time(millisecond) < Deadline,
    case BeforeDeadline andalso safe_state(State) =:= 0
        andalso is_process_alive(Sender)
    of
        false ->
            send_resource_checkout_reply(
                ReplyAlias, {Reference, {error, 1}}
            ),
            lifecycle_loop(State, Sockets, Pool, Limits);
        true ->
            case find_accepting_http3(
                Key, Sockets, http3_logical_lease_limit(Limits)
            ) of
                {found, _Token, _StoredOrigin, _Shared} ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, published}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits);
                _NoAcceptingConnection ->
                    begin_unshared_http3_dial(
                        State, Sockets, Pool, Sender, ReplyAlias, Reference,
                        Origin, Key, Deadline, Limits
                    )
            end
    end.

-spec begin_unshared_http3_dial(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), binary(), binary(), integer(), pool_limits()
) -> no_return().
begin_unshared_http3_dial(
    State, Sockets, Pool, Sender, ReplyAlias, Reference, Origin, Key,
    Deadline, Limits
) ->
    case find_http3_dial(Key, Sockets) of
        {found, Token, StoredOrigin,
         {http3_dial, Key, Leader, LeaderMonitor, ClaimReference,
            DialDeadline, Attachment, Waiters}} ->
            %% The leader consumes the first logical stream lease on publish.
            %% Keeping at most factor-1 followers means every acknowledged
            %% waiter can immediately claim one lease on that connection.
            case length(Waiters) < (?HTTP3_DIAL_WAITER_FACTOR - 1) of
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits);
                true ->
                    CallerMonitor = monitor(process, Sender),
                    Waiter = {Reference, Sender, CallerMonitor, ReplyAlias,
                        Deadline},
                    UpdatedDial = {http3_dial, Key, Leader, LeaderMonitor,
                        ClaimReference, DialDeadline, Attachment,
                        [Waiter | Waiters]},
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, waiting}
                    ),
                    lifecycle_loop(
                        State,
                        store_socket(Token, StoredOrigin, UpdatedDial, Sockets),
                        Pool,
                        Limits
                    )
            end;
        none ->
            case connection_has_capacity(Origin, Sockets, Limits) of
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 2}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits);
                true ->
                    Token = make_ref(),
                    LeaderMonitor = monitor(process, Sender),
                    Dial = {http3_dial, Key, Sender, LeaderMonitor,
                        Reference, Deadline, none, []},
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {leader, Token}}
                    ),
                    lifecycle_loop(
                        State, [{Token, Origin, Dial} | Sockets], Pool, Limits
                    )
            end
    end.

-spec abandon_http3_dial(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), pool_limits()
) -> no_return().
abandon_http3_dial(State, Sockets, Pool, Sender, Reference, Limits) ->
    case find_http3_dial_caller(Sender, Reference, Sockets) of
        {leader, Token, _Origin, Dial} ->
            close_registered_value(Dial),
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        {waiter, Token, Origin,
         {http3_dial, Key, Leader, LeaderMonitor, ClaimReference,
            DialDeadline, Attachment, Waiters},
         {_Reference, _Sender, CallerMonitor, _ReplyAlias,
            _WaiterDeadline}} ->
            demonitor(CallerMonitor, [flush]),
            UpdatedDial = {http3_dial, Key, Leader, LeaderMonitor,
                ClaimReference, DialDeadline, Attachment,
                lists:keydelete(Reference, 1, Waiters)},
            lifecycle_loop(
                State,
                store_socket(Token, Origin, UpdatedDial, Sockets),
                Pool,
                Limits
            );
        none -> lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec settle_http3_dial_probe(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), boolean(), integer(), pool_limits()
) -> no_return().
settle_http3_dial_probe(
    State, Sockets, Pool, Sender, Reference, Token, Published, Deadline,
    Limits
) ->
    BeforeDeadline = erlang:monotonic_time(millisecond) < Deadline,
    case {BeforeDeadline, safe_state(State), is_boolean(Published),
            lists:keyfind(Token, 1, Sockets)} of
        {true, 0, true, {Token, _Origin, Dial = {http3_dial, _, _, _, _,
                _, _, _}}} ->
            Outcome = case Published of
                true -> published;
                false -> failed
            end,
            settle_http3_dial_and_close(Dial, Outcome),
            Sender ! {Reference, {ok, nil}},
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        _ ->
            Sender ! {Reference, {error, 1}},
            lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec expire_http3_dial_waiters_probe(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), term(), integer(), pool_limits()
) -> no_return().
expire_http3_dial_waiters_probe(
    State, Sockets, Pool, Sender, Reference, Token, AdvanceMilliseconds,
    Deadline, Limits
) ->
    Now = erlang:monotonic_time(millisecond),
    ValidAdvance = is_integer(AdvanceMilliseconds)
        andalso AdvanceMilliseconds >= 0
        andalso AdvanceMilliseconds =< 2147483647,
    case {Now < Deadline, safe_state(State), is_process_alive(Sender),
            ValidAdvance, lists:keyfind(Token, 1, Sockets)} of
        {true, 0, true, true,
         {Token, Origin,
          {http3_dial, Key, Leader, LeaderMonitor, ClaimReference,
            DialDeadline, Attachment, Waiters}}} ->
            LiveWaiters = prune_http3_dial_waiters(
                Waiters, Now + AdvanceMilliseconds
            ),
            UpdatedDial = {http3_dial, Key, Leader, LeaderMonitor,
                ClaimReference, DialDeadline, Attachment, LiveWaiters},
            Sender ! {Reference, {ok, nil}},
            lifecycle_loop(
                State,
                store_socket(Token, Origin, UpdatedDial, Sockets),
                Pool,
                Limits
            );
        _ ->
            Sender ! {Reference, {error, 1}},
            lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec find_http3_dial(binary(), [registered_socket()]) ->
    none | {found, reference(), binary(), http3_dial()}.
find_http3_dial(_Key, []) -> none;
find_http3_dial(
    Key,
    [{Token, Origin, Dial = {http3_dial, Key, _Leader, _LeaderMonitor,
        _ClaimReference, _Deadline, _Attachment, _Waiters}} | _Rest]
) ->
    {found, Token, Origin, Dial};
find_http3_dial(Key, [_Entry | Rest]) -> find_http3_dial(Key, Rest).

-spec find_http3_dial_caller(pid(), reference(), [registered_socket()]) ->
    none |
    {leader, reference(), binary(), http3_dial()} |
    {waiter, reference(), binary(), http3_dial(), http3_dial_waiter()}.
find_http3_dial_caller(_Sender, _Reference, []) -> none;
find_http3_dial_caller(
    Sender,
    Reference,
    [{Token, Origin,
      Dial = {http3_dial, _Key, Sender, _LeaderMonitor, Reference,
        _Deadline, _Attachment, _Waiters}} | _Rest]
) ->
    {leader, Token, Origin, Dial};
find_http3_dial_caller(
    Sender,
    Reference,
    [{Token, Origin,
      Dial = {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
        _Deadline, _Attachment, Waiters}} | Rest]
) ->
    case lists:keyfind(Reference, 1, Waiters) of
        Waiter = {Reference, Sender, _Monitor, _ReplyAlias,
            _WaiterDeadline} ->
            {waiter, Token, Origin, Dial, Waiter};
        _ -> find_http3_dial_caller(Sender, Reference, Rest)
    end;
find_http3_dial_caller(Sender, Reference, [_Entry | Rest]) ->
    find_http3_dial_caller(Sender, Reference, Rest).

-spec notify_http3_dial_waiters(
    http3_dial(), published | failed | {error, 1}
) -> ok.
notify_http3_dial_waiters(
    {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference, _Deadline,
        _Attachment, Waiters},
    Outcome
) ->
    lists:foreach(
        fun({Reference, _Caller, _CallerMonitor, ReplyAlias,
                _WaiterDeadline}) ->
            send_resource_checkout_reply(ReplyAlias, {Reference, Outcome})
        end,
        Waiters
    ).

-spec release_http3_dial_caller_monitors(http3_dial()) -> ok.
release_http3_dial_caller_monitors(
    {http3_dial, _Key, _Leader, LeaderMonitor, _ClaimReference, _Deadline,
        _Attachment, Waiters}
) ->
    demonitor(LeaderMonitor, [flush]),
    lists:foreach(
        fun({_Reference, _Caller, CallerMonitor, _ReplyAlias,
                _WaiterDeadline}) ->
            demonitor(CallerMonitor, [flush])
        end,
        Waiters
    ),
    ok.

-spec publish_http3_dial_callers(http3_dial()) -> ok.
publish_http3_dial_callers(Dial) ->
    notify_http3_dial_waiters(Dial, published),
    release_http3_dial_caller_monitors(Dial).

-spec settle_http3_dial_and_close(
    http3_dial(), published | failed | {error, 1}
) -> ok.
settle_http3_dial_and_close(Dial, Outcome) ->
    notify_http3_dial_waiters(Dial, Outcome),
    release_http3_dial_caller_monitors(Dial),
    close_http3_dial_attachment(Dial).

-spec close_http3_dial_attachment(http3_dial()) -> ok.
close_http3_dial_attachment(
    {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference, _Deadline,
        none, _Waiters}
) -> ok;
close_http3_dial_attachment(
    {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference, _Deadline,
        {ResourceOwner, ResourceMonitor}, _Waiters}
) ->
    force_resource_owner_shutdown(ResourceOwner),
    demonitor(ResourceMonitor, [flush]),
    ok.

-spec activate_http3_candidate(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), reference(), binary(), term(), boolean(),
    integer(), pool_limits()
) -> no_return().
activate_http3_candidate(
    State, Sockets, Pool, Sender, ReplyAlias, LeaseReference, Token, Key,
    Connection, AllowShare, Deadline, Limits
) ->
    Candidate = lists:keyfind(Token, 1, Sockets),
    BeforeDeadline = erlang:monotonic_time(millisecond) < Deadline,
    case {BeforeDeadline, safe_state(State), is_process_alive(Sender),
          Candidate} of
        {true, 0, true,
         {Token, Origin,
          Dial = {http3_dial, Key, _Leader, _LeaderMonitor,
            _ClaimReference, _DialDeadline,
            {ResourceOwner = {http3_resource_owner, PhysicalOwner, Tag},
                ResourceMonitor}, _Waiters}}}
          when is_pid(PhysicalOwner), is_reference(Tag) ->
            publish_http3_dial_callers(Dial),
            activate_http3_owned_candidate(
                State, Sockets, Pool, Sender, ReplyAlias, LeaseReference,
                Token, Origin, Key, Connection, AllowShare, Deadline,
                ResourceOwner, ResourceMonitor, Limits
            );
        {true, 0, true,
         {Token, Origin,
          {owned_resource,
           ResourceOwner = {http3_resource_owner, PhysicalOwner, Tag},
           ResourceMonitor}}}
          when is_pid(PhysicalOwner), is_reference(Tag) ->
            activate_http3_owned_candidate(
                State, Sockets, Pool, Sender, ReplyAlias, LeaseReference,
                Token, Origin, Key, Connection, AllowShare, Deadline,
                ResourceOwner, ResourceMonitor, Limits
            );
        _ ->
            Updated = retire_http3_candidate_entries(
                Sockets, Token, Deadline
            ),
            send_resource_checkout_reply(
                ReplyAlias, {LeaseReference, {error, 1}}
            ),
            lifecycle_loop(State, Updated, Pool, Limits)
    end.

-spec activate_http3_owned_candidate(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), reference(), binary(), binary(), term(),
    boolean(), integer(), resource_owner(), reference(), pool_limits()
) -> no_return().
activate_http3_owned_candidate(
    State, Sockets, Pool, Sender, ReplyAlias, LeaseReference, Token, Origin,
    Key, Connection, AllowShare, Deadline, ResourceOwner, ResourceMonitor,
    Limits
) ->
    LogicalLimit = http3_logical_lease_limit(Limits),
    SharedCandidate = case AllowShare of
        true -> find_accepting_http3(Key, Sockets, LogicalLimit);
        false -> empty
    end,
    case SharedCandidate of
        {found, SharedToken, SharedOrigin,
         Shared = {shared_http3, _SharedOwner, _SharedMonitor,
            Key, SharedConnection, accepting, _IdleDeadline,
            Capability, Leases}} ->
            {Lease, LeaseEntry} = new_http3_lease(
                self(), SharedToken, LeaseReference, Capability, Sender
            ),
            UpdatedShared = set_http3_shared_leases(
                Shared, none, [LeaseEntry | Leases]
            ),
            CloseDeadline = bounded_http3_close_deadline(Deadline),
            begin_resource_owner_shutdown(ResourceOwner, CloseDeadline),
            ClosingCandidate = {closing_http3_candidate,
                ResourceOwner, ResourceMonitor, CloseDeadline},
            Updated0 = store_socket(
                Token, Origin, ClosingCandidate, Sockets
            ),
            Updated = store_socket(
                SharedToken, SharedOrigin, UpdatedShared, Updated0
            ),
            send_resource_checkout_reply(
                ReplyAlias,
                {LeaseReference, {ok, {SharedConnection, Lease}}}
            ),
            lifecycle_loop(State, Updated, Pool, Limits);
        CandidateStatus
          when CandidateStatus =:= capacity;
               CandidateStatus =:= empty ->
            Capability = make_ref(),
            {Lease, LeaseEntry} = new_http3_lease(
                self(), Token, LeaseReference, Capability, Sender
            ),
            Shared = {shared_http3, ResourceOwner, ResourceMonitor,
                Key, Connection, accepting, none, Capability, [LeaseEntry]},
            send_resource_checkout_reply(
                ReplyAlias, {LeaseReference, {ok, {Connection, Lease}}}
            ),
            lifecycle_loop(
                State,
                store_socket(Token, Origin, Shared, Sockets),
                Pool,
                Limits
            )
    end.

-spec checkout_http3_shared(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), reference(), binary(), integer(), pool_limits()
) -> no_return().
checkout_http3_shared(
    State, Sockets, Pool, Sender, ReplyAlias, LeaseReference, Key, Deadline,
    Limits
) ->
    BeforeDeadline = erlang:monotonic_time(millisecond) < Deadline,
    LogicalLimit = http3_logical_lease_limit(Limits),
    case BeforeDeadline andalso safe_state(State) =:= 0
        andalso is_process_alive(Sender)
    of
        false ->
            send_resource_checkout_reply(
                ReplyAlias, {LeaseReference, {error, 1}}
            ),
            lifecycle_loop(State, Sockets, Pool, Limits);
        true ->
            case find_accepting_http3(Key, Sockets, LogicalLimit) of
                {found, Token, Origin,
                 Shared = {shared_http3, _ResourceOwner, _ResourceMonitor,
                    Key, Connection, accepting, _IdleDeadline, Capability,
                    Leases}} ->
                    {Lease, LeaseEntry} = new_http3_lease(
                        self(), Token, LeaseReference, Capability, Sender
                    ),
                    UpdatedShared = set_http3_shared_leases(
                        Shared, none, [LeaseEntry | Leases]
                    ),
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {LeaseReference, {ok, {Connection, Lease}}}
                    ),
                    lifecycle_loop(
                        State,
                        store_socket(Token, Origin, UpdatedShared, Sockets),
                        Pool,
                        Limits
                    );
                capacity ->
                    send_resource_checkout_reply(
                        %% A full logical ledger does not consume another
                        %% physical slot. Let the caller reserve a new
                        %% candidate; the ordinary physical admission limit
                        %% remains authoritative.
                        ReplyAlias, {LeaseReference, {error, 0}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits);
                empty ->
                    send_resource_checkout_reply(
                        ReplyAlias, {LeaseReference, {error, 0}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end
    end.

-spec adopt_http3_lease(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()],
    pid() | reference(), reference(), term(), pid(), integer(), pool_limits()
) -> no_return().
adopt_http3_lease(
    State, Sockets, Pool, ReplyTo, Reference,
    {http3_stream_lease, LifecycleOwner, Token, LeaseReference,
        Capability, Guard},
    Holder, Deadline, Limits
) when LifecycleOwner =:= self(), is_pid(Holder) ->
    case {erlang:monotonic_time(millisecond) < Deadline,
          safe_state(State), is_process_alive(Holder),
          find_http3_lease(
              Token, LeaseReference, Capability, Guard, Sockets
          )} of
        {true, LifecycleState, true,
         {found, Origin,
          Shared = {shared_http3, _ResourceOwner, _ResourceMonitor, _Key,
              _Connection, _Mode, _IdleDeadline, _Capability, Leases},
          {_LeaseReference, Guard, _PreviousHolder, PreviousMonitor}}}
          when LifecycleState =:= 0; LifecycleState =:= 1 ->
            NewMonitor = monitor(process, Holder),
            demonitor(PreviousMonitor, [flush]),
            UpdatedLease = {LeaseReference, Guard, Holder, NewMonitor},
            UpdatedShared = set_http3_shared_leases(
                Shared,
                none,
                [UpdatedLease | lists:keydelete(LeaseReference, 1, Leases)]
            ),
            send_resource_checkout_reply(ReplyTo, {Reference, {ok, nil}}),
            lifecycle_loop(
                State,
                store_socket(Token, Origin, UpdatedShared, Sockets),
                Pool,
                Limits
            );
        _ ->
            send_resource_checkout_reply(ReplyTo, {Reference, {error, 1}}),
            lifecycle_loop(State, Sockets, Pool, Limits)
    end;
adopt_http3_lease(
    State, Sockets, Pool, ReplyTo, Reference, _Lease, _Holder, _Deadline,
    Limits
) ->
    send_resource_checkout_reply(ReplyTo, {Reference, {error, 1}}),
    lifecycle_loop(State, Sockets, Pool, Limits).

-spec release_http3_lease(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()],
    pid() | reference(), reference(), term(), boolean(), integer(),
    pool_limits()
) -> no_return().
release_http3_lease(
    State, Sockets, Pool, ReplyTo, Reference,
    {http3_stream_lease, LifecycleOwner, Token, LeaseReference, Capability,
        Guard},
    Reusable, Deadline, Limits
) when LifecycleOwner =:= self(), is_boolean(Reusable) ->
    case {erlang:monotonic_time(millisecond) < Deadline,
          find_http3_lease(
              Token, LeaseReference, Capability, Guard, Sockets
          )} of
        {true, {found, Origin, Shared, LeaseEntry}} ->
            release_http3_lease_monitor(LeaseEntry),
            case http3_mark_lease_released(Guard) of
                true ->
                    UpdatedShared = finish_http3_lease_release(
                        State,
                        remove_http3_shared_lease(Shared, LeaseReference),
                        Reusable,
                        Limits
                    ),
                    send_resource_checkout_reply(
                        ReplyTo, {Reference, {ok, nil}}
                    ),
                    lifecycle_loop(
                        State,
                        store_socket(Token, Origin, UpdatedShared, Sockets),
                        Pool,
                        Limits
                    );
                false ->
                    send_resource_checkout_reply(
                        ReplyTo, {Reference, {error, 1}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {true, none} ->
            Reply = case http3_lease_guard_state(Guard) of
                ?HTTP3_LEASE_RELEASED -> {ok, nil};
                ?HTTP3_LEASE_TERMINAL_OWNED -> {ok, nil};
                _ -> {error, 1}
            end,
            send_resource_checkout_reply(ReplyTo, {Reference, Reply}),
            lifecycle_loop(State, Sockets, Pool, Limits);
        {false, _} ->
            send_resource_checkout_reply(
                ReplyTo, {Reference, {error, 1}}
            ),
            lifecycle_loop(State, Sockets, Pool, Limits)
    end;
release_http3_lease(
    State, Sockets, Pool, ReplyTo, Reference, _Lease, _Reusable, _Deadline,
    Limits
) ->
    send_resource_checkout_reply(ReplyTo, {Reference, {error, 1}}),
    lifecycle_loop(State, Sockets, Pool, Limits).

-spec abandon_http3_lease(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], pid(),
    reference(), pool_limits()
) -> no_return().
abandon_http3_lease(
    State, Sockets, Pool, Sender, LeaseReference, Limits
) ->
    case find_http3_lease_by_holder(LeaseReference, Sender, Sockets) of
        {found, Token, Origin, Shared,
         LeaseEntry = {_LeaseReference, Guard, _Holder, _Monitor}} ->
            release_http3_lease_monitor(LeaseEntry),
            _ = http3_mark_lease_released(Guard),
            UpdatedShared = finish_http3_lease_release(
                State,
                remove_http3_shared_lease(Shared, LeaseReference),
                true,
                Limits
            ),
            lifecycle_loop(
                State,
                store_socket(Token, Origin, UpdatedShared, Sockets),
                Pool,
                Limits
            );
        none -> lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec find_accepting_http3(binary(), [registered_socket()], pos_integer()) ->
    empty | capacity |
    {found, reference(), binary(), http3_shared_resource()}.
find_accepting_http3(Key, Sockets, Limit) ->
    find_accepting_http3(Key, Sockets, Limit, false).

-spec find_accepting_http3(
    binary(), [registered_socket()], pos_integer(), boolean()
) -> empty | capacity |
    {found, reference(), binary(), http3_shared_resource()}.
find_accepting_http3(_Key, [], _Limit, true) -> capacity;
find_accepting_http3(_Key, [], _Limit, false) -> empty;
find_accepting_http3(
    Key,
    [{Token, Origin,
      Shared = {shared_http3, ResourceOwner, _ResourceMonitor, Key,
          _Connection, accepting, _IdleDeadline, _Capability, Leases}} |
     Rest],
    Limit,
    Full
) ->
    case resource_owner_alive(ResourceOwner) of
        false -> find_accepting_http3(Key, Rest, Limit, Full);
        true ->
            case length(Leases) < Limit of
                true -> {found, Token, Origin, Shared};
                false -> find_accepting_http3(Key, Rest, Limit, true)
            end
    end;
find_accepting_http3(Key, [_Entry | Rest], Limit, Full) ->
    find_accepting_http3(Key, Rest, Limit, Full).

-spec new_http3_lease(
    pid(), reference(), reference(), reference(), pid()
) -> {http3_lease(), http3_lease_entry()}.
new_http3_lease(Owner, Token, LeaseReference, Capability, Holder) ->
    Guard = atomics:new(1, [{signed, false}]),
    Monitor = monitor(process, Holder),
    Lease = {http3_stream_lease, Owner, Token, LeaseReference, Capability,
        Guard},
    {Lease, {LeaseReference, Guard, Holder, Monitor}}.

-spec set_http3_shared_leases(
    http3_shared_resource(), none | integer(), [http3_lease_entry()]
) -> http3_shared_resource().
set_http3_shared_leases(
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        _IdleDeadline, Capability, _PreviousLeases},
    IdleDeadline,
    Leases
) ->
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        IdleDeadline, Capability, Leases}.

-spec find_http3_lease(
    reference(), reference(), reference(), atomics:atomics_ref(),
    [registered_socket()]
) -> none |
    {found, binary(), http3_shared_resource(), http3_lease_entry()}.
find_http3_lease(Token, LeaseReference, Capability, Guard, Sockets) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, Origin,
         Shared = {shared_http3, _ResourceOwner, _ResourceMonitor, _Key,
             _Connection, _Mode, _IdleDeadline, Capability, Leases}} ->
            case lists:keyfind(LeaseReference, 1, Leases) of
                LeaseEntry = {LeaseReference, Guard, _Holder, _Monitor} ->
                    {found, Origin, Shared, LeaseEntry};
                _ -> none
            end;
        _ -> none
    end.

-spec find_http3_lease_by_holder(
    reference(), pid(), [registered_socket()]
) -> none |
    {found, reference(), binary(), http3_shared_resource(),
        http3_lease_entry()}.
find_http3_lease_by_holder(_LeaseReference, _Holder, []) -> none;
find_http3_lease_by_holder(
    LeaseReference,
    Holder,
    [{Token, Origin,
      Shared = {shared_http3, _ResourceOwner, _ResourceMonitor, _Key,
          _Connection, _Mode, _IdleDeadline, _Capability, Leases}} | Rest]
) ->
    case lists:keyfind(LeaseReference, 1, Leases) of
        LeaseEntry = {LeaseReference, _Guard, Holder, _Monitor} ->
            {found, Token, Origin, Shared, LeaseEntry};
        _ -> find_http3_lease_by_holder(LeaseReference, Holder, Rest)
    end;
find_http3_lease_by_holder(LeaseReference, Holder, [_Entry | Rest]) ->
    find_http3_lease_by_holder(LeaseReference, Holder, Rest).

-spec remove_http3_shared_lease(
    http3_shared_resource(), reference()
) -> http3_shared_resource().
remove_http3_shared_lease(
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        IdleDeadline, Capability, Leases},
    LeaseReference
) ->
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        IdleDeadline, Capability,
        lists:keydelete(LeaseReference, 1, Leases)}.

-spec finish_http3_lease_release(
    atomics:atomics_ref(), http3_shared_resource(), boolean(), pool_limits()
) -> http3_shared_resource().
finish_http3_lease_release(
    State,
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        _IdleDeadline, Capability, Leases},
    Reusable,
    {_Maximum, _PerOrigin, IdleMilliseconds}
) ->
    NextMode = case safe_state(State) =:= 0 andalso Reusable
        andalso Mode =:= accepting
    of
        true -> accepting;
        false -> draining
    end,
    case {NextMode, Leases} of
        {accepting, []} ->
            {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
                accepting,
                erlang:monotonic_time(millisecond) + IdleMilliseconds,
                Capability, []};
        {accepting, _} ->
            {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
                accepting, none, Capability, Leases};
        {draining, []} ->
            CloseDeadline = erlang:monotonic_time(millisecond)
                + ?OWNER_TIMEOUT,
            begin_resource_owner_shutdown(
                ResourceOwner,
                CloseDeadline
            ),
            {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
                closing, CloseDeadline, Capability, []};
        {draining, _} ->
            {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
                draining, none, Capability, Leases}
    end.

-spec release_http3_lease_monitor(http3_lease_entry()) -> ok.
release_http3_lease_monitor({_LeaseReference, _Guard, _Holder, Monitor}) ->
    demonitor(Monitor, [flush]),
    ok.

-spec http3_mark_lease_released(atomics:atomics_ref()) -> boolean().
http3_mark_lease_released(Guard) ->
    try atomics:compare_exchange(
        Guard, 1, ?HTTP3_LEASE_ACTIVE, ?HTTP3_LEASE_RELEASED
    ) of
        ok -> true;
        ?HTTP3_LEASE_RELEASED -> true;
        _ -> false
    catch _:_ -> false end.

-spec http3_mark_lease_terminal(atomics:atomics_ref()) -> ok.
http3_mark_lease_terminal(Guard) ->
    try atomics:compare_exchange(
        Guard, 1, ?HTTP3_LEASE_ACTIVE, ?HTTP3_LEASE_TERMINAL_OWNED
    ) of
        _ -> ok
    catch _:_ -> ok end.

-spec http3_lease_guard_state(atomics:atomics_ref()) -> integer().
http3_lease_guard_state(Guard) ->
    try atomics:get(Guard, 1)
    catch _:_ -> -1 end.

-spec http3_logical_lease_limit(pool_limits()) -> pos_integer().
http3_logical_lease_limit({_Maximum, _PerOrigin, _IdleMilliseconds}) ->
    %% This is a per-physical-connection ledger bound. The upper HTTP resource
    %% controller separately admits Maximum * this factor across all physical
    %% connections, so a full connection can scale out without first exhausting
    %% the global request budget.
    ?HTTP3_LOGICAL_LEASE_FACTOR.

-spec retire_http3_candidate_entries(
    [registered_socket()], reference(), integer()
) -> [registered_socket()].
retire_http3_candidate_entries(Sockets, Token, Deadline) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, Origin, Dial = {http3_dial, _, _, _, _, _, _, _}} ->
            retire_http3_dial_entry(
                Token, Origin, Dial, Deadline, failed, Sockets
            );
        {Token, Origin,
         {owned_resource,
          ResourceOwner = {http3_resource_owner, PhysicalOwner, Tag},
          ResourceMonitor}}
          when is_pid(PhysicalOwner), is_reference(Tag) ->
            CloseDeadline = bounded_http3_close_deadline(Deadline),
            begin_resource_owner_shutdown(ResourceOwner, CloseDeadline),
            store_socket(
                Token,
                Origin,
                {closing_http3_candidate, ResourceOwner, ResourceMonitor,
                    CloseDeadline},
                Sockets
            );
        {Token, _Origin,
         {closing_http3_candidate, _ResourceOwner, _ResourceMonitor,
             _CloseDeadline}} ->
            Sockets;
        {Token, Origin, Shared = {shared_http3, _, _, _, _, _, _, _, _}} ->
            %% This token identifies the newly authenticated candidate rather
            %% than an older shared entry. A late activation is unused, but
            %% remains a late physical success and must still be recovered.
            store_socket(
                Token,
                Origin,
                drain_http3_shared_value(
                    Shared, bounded_http3_close_deadline(Deadline)
                ),
                Sockets
            );
        {Token, _Origin, Reservation = {resource_reservation, _, _}} ->
            close_registered_value(Reservation),
            lists:keydelete(Token, 1, Sockets);
        _ -> Sockets
    end.

-spec await_http3_candidate_retirement(
    [registered_socket()], reference(), integer()
) -> {confirmed, [registered_socket()]} |
     {unconfirmed, [registered_socket()]}.
await_http3_candidate_retirement(Sockets, Token, Deadline) ->
    case lists:keyfind(Token, 1, Sockets) of
        false ->
            {confirmed, Sockets};
        {Token, _Origin,
         {closing_http3_candidate, ResourceOwner, ResourceMonitor,
          _CloseDeadline}} ->
            receive
                {unregister_socket, Sender, Reference, Token}
                        when (is_pid(Sender) orelse is_reference(Sender)),
                             is_reference(Reference) ->
                    send_resource_checkout_reply(
                        Sender, {Reference, {ok, nil}}
                    ),
                    await_http3_candidate_retirement(Sockets, Token, Deadline);
                {'DOWN', ResourceMonitor, process, _Pid, _Reason} ->
                    {confirmed, lists:keydelete(Token, 1, Sockets)}
            after deadline_remaining(Deadline) ->
                force_resource_owner_shutdown(ResourceOwner),
                {unconfirmed, Sockets}
            end;
        {Token, _Origin, Value} ->
            close_registered_value(Value),
            {confirmed, lists:keydelete(Token, 1, Sockets)}
    end.

-spec retire_http3_dial_entry(
    reference(), binary(), http3_dial(), integer(),
    failed | {error, 1}, [registered_socket()]
) -> [registered_socket()].
retire_http3_dial_entry(
    Token, Origin,
    Dial = {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
        _DialDeadline, Attachment, _Waiters},
    Deadline, Outcome, Sockets
) ->
    notify_http3_dial_waiters(Dial, Outcome),
    release_http3_dial_caller_monitors(Dial),
    case Attachment of
        none -> lists:keydelete(Token, 1, Sockets);
        {ResourceOwner, ResourceMonitor} ->
            CloseDeadline = bounded_http3_close_deadline(Deadline),
            begin_resource_owner_shutdown(ResourceOwner, CloseDeadline),
            store_socket(
                Token,
                Origin,
                {closing_http3_candidate, ResourceOwner, ResourceMonitor,
                    CloseDeadline},
                Sockets
            )
    end.

-spec bounded_http3_close_deadline(integer()) -> integer().
bounded_http3_close_deadline(CallerDeadline) ->
    bounded_http3_close_deadline_at(
        CallerDeadline, erlang:monotonic_time(millisecond)
    ).

-spec bounded_http3_close_deadline_at(integer(), integer()) -> integer().
bounded_http3_close_deadline_at(CallerDeadline, Now) ->
    erlang:min(CallerDeadline, Now + ?OWNER_TIMEOUT).

%% Closed test seam for deadline generation and non-extension. It never exposes
%% a process, connection, token, endpoint, or stored lifecycle state.
-spec http3_close_deadline_probe(
    http3_shared_mode(), none | integer(), integer(), integer()
) -> integer().
http3_close_deadline_probe(closing, Existing, _Requested, _Now)
    when is_integer(Existing) -> Existing;
http3_close_deadline_probe(Mode, _Existing, Requested, Now)
    when Mode =:= accepting; Mode =:= draining ->
    bounded_http3_close_deadline_at(Requested, Now);
http3_close_deadline_probe(_Mode, _Existing, Requested, Now) ->
    bounded_http3_close_deadline_at(Requested, Now).

-spec drain_http3_shared_value(http3_shared_resource(), integer()) ->
    http3_shared_resource().
drain_http3_shared_value(
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        ExistingDeadline, Capability, []},
    Deadline
) ->
    CloseDeadline = existing_or_bounded_http3_close_deadline(
        Mode, ExistingDeadline, Deadline
    ),
    begin_resource_owner_shutdown(ResourceOwner, CloseDeadline),
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, closing,
        CloseDeadline, Capability, []};
drain_http3_shared_value(
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        ExistingDeadline, Capability, Leases},
    _Deadline
) ->
    case {Mode, ExistingDeadline} of
        {closing, CloseDeadline} when is_integer(CloseDeadline) ->
            {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
                closing, CloseDeadline, Capability, Leases};
        _ ->
            {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
                draining, none, Capability, Leases}
    end.

-spec terminalize_http3_shared_value(
    http3_shared_resource(), boolean()
) -> http3_shared_resource().
terminalize_http3_shared_value(
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        ExistingDeadline, Capability, Leases},
    BeginShutdown
) ->
    CloseDeadline = existing_or_bounded_http3_close_deadline(
        Mode,
        ExistingDeadline,
        erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT
    ),
    lists:foreach(
        fun(Lease = {_LeaseReference, Guard, _Holder, _Monitor}) ->
            http3_mark_lease_terminal(Guard),
            release_http3_lease_monitor(Lease)
        end,
        Leases
    ),
    case BeginShutdown of
        true ->
            begin_resource_owner_shutdown(ResourceOwner, CloseDeadline);
        false -> ok
    end,
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, closing,
        CloseDeadline, Capability, []}.

-spec existing_or_bounded_http3_close_deadline(
    http3_shared_mode(), none | integer(), integer()
) -> integer().
existing_or_bounded_http3_close_deadline(
    closing, ExistingDeadline, _RequestedDeadline
) when is_integer(ExistingDeadline) ->
    ExistingDeadline;
existing_or_bounded_http3_close_deadline(
    _Mode, _ExistingDeadline, RequestedDeadline
) ->
    bounded_http3_close_deadline(RequestedDeadline).

-spec drain_http3_shared_entries([registered_socket()], integer()) ->
    [registered_socket()].
drain_http3_shared_entries([], _Deadline) -> [];
drain_http3_shared_entries(
    [{Token, Origin,
      Shared = {shared_http3, _, _, _, _, _, _, _, _}} | Rest],
    Deadline
) ->
    [{Token, Origin, drain_http3_shared_value(Shared, Deadline)} |
     drain_http3_shared_entries(Rest, Deadline)];
drain_http3_shared_entries([Entry | Rest], Deadline) ->
    [Entry | drain_http3_shared_entries(Rest, Deadline)].

-spec http3_idle_shared_count([registered_socket()]) -> non_neg_integer().
http3_idle_shared_count(Sockets) ->
    length([ok ||
        {_Token, _Origin,
         {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
          accepting, IdleDeadline, _Capability, []}} <- Sockets,
        is_integer(IdleDeadline)]).

-spec http3_shared_counts([registered_socket()]) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(),
        non_neg_integer(), non_neg_integer(), non_neg_integer()}.
http3_shared_counts(Sockets) ->
    Shared = [Value ||
        {_Token, _Origin,
         Value = {shared_http3, _ResourceOwner, _ResourceMonitor, _Key,
             _Connection, _Mode, _IdleDeadline, _Capability, _Leases}}
            <- Sockets],
    Accepting = length([ok ||
        {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
         accepting, _IdleDeadline, _Capability, _Leases} <- Shared]),
    Draining = length([ok ||
        {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
         draining, _IdleDeadline, _Capability, _Leases} <- Shared]),
    Closing = length([ok ||
        {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
         closing, _IdleDeadline, _Capability, _Leases} <- Shared]),
    Leases = lists:sum([length(Entries) ||
        {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
         _Mode, _IdleDeadline, _Capability, Entries} <- Shared]),
    {length(Shared), Accepting, Draining, Closing, Leases,
        http3_idle_shared_count(Sockets)}.

-spec http3_dial_counts([registered_socket()]) ->
    {non_neg_integer(), non_neg_integer()}.
http3_dial_counts(Sockets) ->
    Dials = [Dial ||
        {_Token, _Origin,
         Dial = {http3_dial, _Key, _Leader, _LeaderMonitor,
            _ClaimReference, _Deadline, _Attachment, _Waiters}} <- Sockets],
    Waiters = lists:sum([length(Entries) ||
        {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
            _Deadline, _Attachment, Entries} <- Dials]),
    {length(Dials), Waiters}.

-spec offer_resource_checkout(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    binary(),
    pid(),
    reference(),
    reference(),
    integer(),
    pool_limits()
) -> no_return().
offer_resource_checkout(
    State, Sockets, Pool, Key, Sender, ReplyAlias, Reference, Deadline, Limits
) ->
    case take_resource_origin(Key, Pool, []) of
        empty ->
            send_resource_checkout_reply(
                ReplyAlias, {Reference, {error, 0}}
            ),
            lifecycle_loop(State, Sockets, Pool, Limits);
        {found, Token, Value, PoolDeadline, Remaining} ->
            case lists:keyfind(Token, 1, Sockets) of
                {Token, Origin,
                    {owned_resource, ResourceOwner, ResourceMonitor}} ->
                    Now = erlang:monotonic_time(millisecond),
                    case resource_owner_alive(ResourceOwner)
                        andalso Now < PoolDeadline
                        andalso Now < Deadline
                    of
                        true ->
                            CallerMonitor = monitor(process, Sender),
                            Pending = {pending_resource_checkout,
                                Reference, Sender, CallerMonitor,
                                ReplyAlias, ResourceOwner, ResourceMonitor,
                                Key, Value, PoolDeadline, Deadline},
                            UpdatedSockets = store_socket(
                                Token, Origin, Pending, Sockets
                            ),
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {offer, Value}}
                            ),
                            lifecycle_loop(
                                State, UpdatedSockets, Remaining, Limits
                            );
                        false ->
                            close_registered_value(
                                {owned_resource, ResourceOwner,
                                    ResourceMonitor}
                            ),
                            send_resource_checkout_reply(
                                ReplyAlias, {Reference, {error, 0}}
                            ),
                            lifecycle_loop(
                                State,
                                lists:keydelete(Token, 1, Sockets),
                                Remaining,
                                Limits
                            )
                    end;
                {Token, _Origin, Registered} ->
                    close_registered_value(Registered),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 0}}
                    ),
                    lifecycle_loop(
                        State,
                        lists:keydelete(Token, 1, Sockets),
                        Remaining,
                        Limits
                    );
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 0}}
                    ),
                    lifecycle_loop(State, Sockets, Remaining, Limits)
            end
    end.

-spec confirm_resource_checkout(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pid(),
    reference(),
    reference(),
    pool_limits()
) -> no_return().
confirm_resource_checkout(
    State, Sockets, Pool, Sender, ReplyAlias, Reference, Limits
) ->
    case find_resource_checkout(Reference, Sockets) of
        {pending, Token, Origin,
            Pending = {pending_resource_checkout, Reference, Sender,
                CallerMonitor, ReplyAlias, ResourceOwner, ResourceMonitor,
                _Key, _Value, PoolDeadline, CheckoutDeadline}} ->
            Now = erlang:monotonic_time(millisecond),
            case safe_state(State) =:= 0
                andalso is_process_alive(Sender)
                andalso resource_owner_alive(ResourceOwner)
                andalso Now < CheckoutDeadline
                andalso Now < PoolDeadline
            of
                true ->
                    Borrowed = {borrowed_resource_checkout, Reference,
                        Sender, CallerMonitor, ResourceOwner, ResourceMonitor},
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, confirmed}
                    ),
                    lifecycle_loop(
                        State,
                        store_socket(Token, Origin, Borrowed, Sockets),
                        Pool,
                        Limits
                    );
                false ->
                    {UpdatedSockets, UpdatedPool} = restore_pending_resource(
                        State, Token, Origin, Pending, Sockets, Pool, Limits,
                        Now
                    ),
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, rejected}
                    ),
                    lifecycle_loop(
                        State, UpdatedSockets, UpdatedPool, Limits
                    )
            end;
        _ ->
            send_resource_checkout_reply(ReplyAlias, {Reference, rejected}),
            lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec abandon_resource_checkout(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pid(),
    reference(),
    pool_limits()
) -> no_return().
abandon_resource_checkout(State, Sockets, Pool, Sender, Reference, Limits) ->
    case find_resource_checkout(Reference, Sockets) of
        {pending, Token, Origin,
            Pending = {pending_resource_checkout, Reference, Sender,
                _CallerMonitor, _ReplyAlias, _ResourceOwner, _ResourceMonitor,
                _Key, _Value, _PoolDeadline, _CheckoutDeadline}} ->
            {UpdatedSockets, UpdatedPool} = restore_pending_resource(
                State,
                Token,
                Origin,
                Pending,
                Sockets,
                Pool,
                Limits,
                erlang:monotonic_time(millisecond)
            ),
            lifecycle_loop(State, UpdatedSockets, UpdatedPool, Limits);
        {borrowed, Token, _Origin,
            Borrowed = {borrowed_resource_checkout, Reference, Sender,
                _CallerMonitor, _ResourceOwner, _ResourceMonitor}} ->
            close_registered_value(Borrowed),
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        _ -> lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec handle_registered_down(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    reference(),
    pool_limits()
) -> no_return().
handle_registered_down(State, Sockets, Pool, Monitor, Limits) ->
    case find_socket_handoff_monitor(Monitor, Sockets) of
        {found, Token, Pending} ->
            close_registered_value(Pending),
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        none ->
            handle_registered_down_after_socket_handoff(
                State, Sockets, Pool, Monitor, Limits
            )
    end.

-spec handle_registered_down_after_socket_handoff(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()],
    reference(), pool_limits()
) -> no_return().
handle_registered_down_after_socket_handoff(
    State, Sockets, Pool, Monitor, Limits
) ->
    case find_http3_dial_monitor(Monitor, Sockets) of
        {resource, Token, _Origin, Dial} ->
            close_registered_value(Dial),
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        {leader, Token, Origin, Dial} ->
            lifecycle_loop(
                State,
                retire_http3_dial_entry(
                    Token, Origin, Dial,
                    erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT,
                    failed, Sockets
                ),
                remove_pool_token(Token, Pool),
                Limits
            );
        {waiter, Token, Origin,
         {http3_dial, Key, Leader, LeaderMonitor, ClaimReference,
            Deadline, Attachment, Waiters}} ->
            Updated = {http3_dial, Key, Leader, LeaderMonitor,
                ClaimReference, Deadline, Attachment,
                remove_http3_dial_waiter_by_monitor(Waiters, Monitor)},
            lifecycle_loop(
                State, store_socket(Token, Origin, Updated, Sockets), Pool,
                Limits
            );
        none ->
            case find_http3_lease_monitor(Monitor, Sockets) of
                {found, Token, Origin, Shared,
                 {_LeaseReference, Guard, _Holder, Monitor}} ->
                    _ = http3_mark_lease_released(Guard),
                    UpdatedShared = finish_http3_lease_release(
                        State,
                        remove_http3_shared_lease_by_monitor(Shared, Monitor),
                        false,
                        Limits
                    ),
                    lifecycle_loop(
                        State,
                        store_socket(Token, Origin, UpdatedShared, Sockets),
                        Pool,
                        Limits
                    );
                none ->
                    handle_registered_down_other(
                        State, Sockets, Pool, Monitor, Limits
                    )
            end
    end.

-spec find_socket_handoff_monitor(reference(), [registered_socket()]) ->
    {found, reference(), pending_socket_handoff()} | none.
find_socket_handoff_monitor(_Monitor, []) ->
    none;
find_socket_handoff_monitor(
    Monitor,
    [{Token, _Origin,
        Pending = {pending_socket_handoff, _HandoffReference, _Socket,
            _PreviousOwner, PreviousMonitor, _Owner, OwnerMonitor,
            _Deadline}} | _Rest]
) when Monitor =:= PreviousMonitor; Monitor =:= OwnerMonitor ->
    {found, Token, Pending};
find_socket_handoff_monitor(Monitor, [_Entry | Rest]) ->
    find_socket_handoff_monitor(Monitor, Rest).

-spec find_http3_dial_monitor(reference(), [registered_socket()]) ->
    none |
    {leader, reference(), binary(), http3_dial()} |
    {resource, reference(), binary(), http3_dial()} |
    {waiter, reference(), binary(), http3_dial()}.
find_http3_dial_monitor(_Monitor, []) -> none;
find_http3_dial_monitor(
    Monitor,
    [{Token, Origin,
      Dial = {http3_dial, _Key, _Leader, Monitor, _ClaimReference,
        _Deadline, _Attachment, _Waiters}} | _Rest]
) ->
    {leader, Token, Origin, Dial};
find_http3_dial_monitor(
    Monitor,
    [{Token, Origin,
      Dial = {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
        _Deadline, {_ResourceOwner, Monitor}, _Waiters}} | _Rest]
) ->
    {resource, Token, Origin, Dial};
find_http3_dial_monitor(
    Monitor,
    [{Token, Origin,
      Dial = {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
        _Deadline, _Attachment, Waiters}} | Rest]
) ->
    case lists:keymember(Monitor, 3, Waiters) of
        true -> {waiter, Token, Origin, Dial};
        false -> find_http3_dial_monitor(Monitor, Rest)
    end;
find_http3_dial_monitor(Monitor, [_Entry | Rest]) ->
    find_http3_dial_monitor(Monitor, Rest).

-spec remove_http3_dial_waiter_by_monitor(
    [http3_dial_waiter()], reference()
) -> [http3_dial_waiter()].
remove_http3_dial_waiter_by_monitor(Waiters, Monitor) ->
    [Waiter ||
        Waiter = {_Reference, _Caller, CallerMonitor, _ReplyAlias, _Deadline}
            <- Waiters,
        CallerMonitor =/= Monitor].

-spec handle_registered_down_other(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    reference(),
    pool_limits()
) -> no_return().
handle_registered_down_other(State, Sockets, Pool, Monitor, Limits) ->
    case find_checkout_monitor(Monitor, Sockets) of
        {pending, Token, Origin, Pending} ->
            {UpdatedSockets, UpdatedPool} = restore_pending_resource(
                State,
                Token,
                Origin,
                Pending,
                Sockets,
                Pool,
                Limits,
                erlang:monotonic_time(millisecond)
            ),
            lifecycle_loop(State, UpdatedSockets, UpdatedPool, Limits);
        {borrowed, Token, _Origin, Borrowed} ->
            close_registered_value(Borrowed),
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        none ->
            RemovedEntries = [Entry ||
                Entry = {_Token, _Origin, Value} <- Sockets,
                resource_monitor(Value) =:= Monitor],
            lists:foreach(fun({_Token, _Origin, Value}) ->
                reject_pending_resource_checkout(Value),
                close_registered_value(Value)
            end, RemovedEntries),
            Removed = [Token || {Token, _Origin, _Value} <- RemovedEntries],
            UpdatedSockets = [Entry || Entry = {Token, _, _} <- Sockets,
                not lists:member(Token, Removed)],
            UpdatedPool = [Entry || Entry = {_, Token, _, _} <- Pool,
                not lists:member(Token, Removed)],
            lifecycle_loop(State, UpdatedSockets, UpdatedPool, Limits)
    end.

-spec find_http3_lease_monitor(reference(), [registered_socket()]) ->
    none |
    {found, reference(), binary(), http3_shared_resource(),
        http3_lease_entry()}.
find_http3_lease_monitor(_Monitor, []) -> none;
find_http3_lease_monitor(
    Monitor,
    [{Token, Origin,
      Shared = {shared_http3, _ResourceOwner, _ResourceMonitor, _Key,
          _Connection, _Mode, _IdleDeadline, _Capability, Leases}} | Rest]
) ->
    case lists:keyfind(Monitor, 4, Leases) of
        LeaseEntry = {_LeaseReference, _Guard, _Holder, Monitor} ->
            {found, Token, Origin, Shared, LeaseEntry};
        false -> find_http3_lease_monitor(Monitor, Rest)
    end;
find_http3_lease_monitor(Monitor, [_Entry | Rest]) ->
    find_http3_lease_monitor(Monitor, Rest).

-spec remove_http3_shared_lease_by_monitor(
    http3_shared_resource(), reference()
) -> http3_shared_resource().
remove_http3_shared_lease_by_monitor(
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        IdleDeadline, Capability, Leases},
    Monitor
) ->
    {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection, Mode,
        IdleDeadline, Capability,
        [Lease || Lease = {_, _, _, LeaseMonitor} <- Leases,
            LeaseMonitor =/= Monitor]}.

-spec find_resource_checkout(reference(), [registered_socket()]) ->
    {pending | borrowed, reference(), binary(), registered_value()} | none.
find_resource_checkout(_Reference, []) -> none;
find_resource_checkout(
    Reference,
    [{Token, Origin,
        Pending = {pending_resource_checkout, Reference, _Caller,
            _CallerMonitor, _ReplyAlias, _ResourceOwner, _ResourceMonitor,
            _Key, _Value, _PoolDeadline, _CheckoutDeadline}} | _Rest]
) ->
    {pending, Token, Origin, Pending};
find_resource_checkout(
    Reference,
    [{Token, Origin,
        Borrowed = {borrowed_resource_checkout, Reference, _Caller,
            _CallerMonitor, _ResourceOwner, _ResourceMonitor}} | _Rest]
) ->
    {borrowed, Token, Origin, Borrowed};
find_resource_checkout(Reference, [_Entry | Rest]) ->
    find_resource_checkout(Reference, Rest).

-spec find_checkout_monitor(reference(), [registered_socket()]) ->
    {pending | borrowed, reference(), binary(), registered_value()} | none.
find_checkout_monitor(_Monitor, []) -> none;
find_checkout_monitor(
    Monitor,
    [{Token, Origin,
        Pending = {pending_resource_checkout, _Reference, _Caller, Monitor,
            _ReplyAlias, _ResourceOwner, _ResourceMonitor, _Key, _Value,
            _PoolDeadline, _CheckoutDeadline}} | _Rest]
) ->
    {pending, Token, Origin, Pending};
find_checkout_monitor(
    Monitor,
    [{Token, Origin,
        Borrowed = {borrowed_resource_checkout, _Reference, _Caller, Monitor,
            _ResourceOwner, _ResourceMonitor}} | _Rest]
) ->
    {borrowed, Token, Origin, Borrowed};
find_checkout_monitor(Monitor, [_Entry | Rest]) ->
    find_checkout_monitor(Monitor, Rest).

-spec restore_pending_resource(
    atomics:atomics_ref(),
    reference(),
    binary(),
    pending_resource_checkout(),
    [registered_socket()],
    [pooled_socket()],
    pool_limits(),
    integer()
) -> {[registered_socket()], [pooled_socket()]}.
restore_pending_resource(
    State,
    Token,
    Origin,
    Pending = {pending_resource_checkout, _Reference, _Caller,
        CallerMonitor, _ReplyAlias, ResourceOwner, ResourceMonitor, Key,
        Value, PoolDeadline, _CheckoutDeadline},
    Sockets,
    Pool,
    Limits,
    Now
) ->
    CanRestore = safe_state(State) =:= 0
        andalso resource_owner_alive(ResourceOwner)
        andalso Now < PoolDeadline
        andalso pool_has_capacity(Key, Pool, Limits),
    case CanRestore of
        true ->
            demonitor(CallerMonitor, [flush]),
            Owned = {owned_resource, ResourceOwner, ResourceMonitor},
            {
                store_socket(Token, Origin, Owned, Sockets),
                [{Key, Token, {resource_value, Value}, PoolDeadline} |
                    remove_pool_token(Token, Pool)]
            };
        false ->
            close_registered_value(Pending),
            {
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool)
            }
    end.

-spec pending_resource_has_capacity(
    [registered_socket()], pool_limits()
) -> boolean().
pending_resource_has_capacity(Sockets, {Maximum, _PerOrigin, _Idle}) ->
    pending_resource_count(Sockets) < Maximum.

-spec pending_resource_count([registered_socket()]) -> non_neg_integer().
pending_resource_count(Sockets) ->
    length([ok ||
        {_Token, _Origin,
            {pending_resource_checkout, _, _, _, _, _, _, _, _, _, _}}
                <- Sockets]).

-spec resource_for_checkin(registered_value()) ->
    {ok, resource_owner(), reference()} | error.
resource_for_checkin({owned_resource, Owner, Monitor}) ->
    {ok, Owner, Monitor};
resource_for_checkin(
    {borrowed_resource_checkout, _Reference, _Caller, _CallerMonitor,
        ResourceOwner, ResourceMonitor}
) ->
    {ok, ResourceOwner, ResourceMonitor};
resource_for_checkin(_Value) -> error.

-spec release_checkout_monitor(registered_value()) -> ok.
release_checkout_monitor(
    {borrowed_resource_checkout, _Reference, _Caller, CallerMonitor,
        _ResourceOwner, _ResourceMonitor}
) ->
    demonitor(CallerMonitor, [flush]),
    ok;
release_checkout_monitor(_Value) -> ok.

-spec send_resource_checkout_reply(pid() | reference(), term()) -> ok.
send_resource_checkout_reply(ReplyTo, Reply) ->
    try ReplyTo ! Reply of
        _ -> ok
    catch
        error:badarg -> ok
    end.

-spec flush_socket_handoff_replies(reference()) -> ok.
flush_socket_handoff_replies(Reference) ->
    receive
        {Reference, _Reply} -> flush_socket_handoff_replies(Reference)
    after 0 ->
        ok
    end.

-spec reject_pending_resource_checkout(registered_value()) -> ok.
reject_pending_resource_checkout(
    {pending_resource_checkout, Reference, _Caller, _CallerMonitor,
        ReplyAlias, _ResourceOwner, _ResourceMonitor, _Key, _Value,
        _PoolDeadline, _CheckoutDeadline}
) ->
    send_resource_checkout_reply(ReplyAlias, {Reference, rejected}),
    ok;
reject_pending_resource_checkout(_Value) -> ok.

-spec live_resource(reference(), [registered_socket()]) -> boolean().
live_resource(Token, Sockets) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, _Origin, {owned_resource, Owner, _Monitor}} ->
            resource_owner_alive(Owner);
        {Token, _Origin,
            {borrowed_resource_checkout, _Reference, _Caller,
                _CallerMonitor, Owner, _Monitor}} ->
            resource_owner_alive(Owner);
        _ -> false
    end.

-spec resource_monitor(term()) -> reference() | none.
resource_monitor({resource_reservation, _Pid, Monitor}) -> Monitor;
resource_monitor({owned_resource, _Pid, Monitor}) -> Monitor;
resource_monitor(
    {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference, _Deadline,
        {_ResourceOwner, ResourceMonitor}, _Waiters}
) -> ResourceMonitor;
resource_monitor(
    {http3_dial, _Key, _Leader, LeaderMonitor, _ClaimReference, _Deadline,
        none, _Waiters}
) -> LeaderMonitor;
resource_monitor(
    {pending_resource_checkout, _Reference, _Caller, _CallerMonitor,
        _ReplyAlias, _ResourceOwner, ResourceMonitor, _Key, _Value,
        _PoolDeadline, _CheckoutDeadline}
) -> ResourceMonitor;
resource_monitor(
    {borrowed_resource_checkout, _Reference, _Caller, _CallerMonitor,
        _ResourceOwner, ResourceMonitor}
) -> ResourceMonitor;
resource_monitor(
    {shared_http3, _ResourceOwner, ResourceMonitor, _Key, _Connection,
        _Mode, _IdleDeadline, _Capability, _Leases}
) -> ResourceMonitor;
resource_monitor(
    {closing_http3_candidate, _ResourceOwner, ResourceMonitor, _CloseDeadline}
) -> ResourceMonitor;
resource_monitor(
    {pending_socket_handoff, _HandoffReference, _Socket, _PreviousOwner,
        _PreviousMonitor, _Owner, OwnerMonitor, _Deadline}
) -> OwnerMonitor;
resource_monitor({owned_socket, _Socket, _Pid, Monitor}) -> Monitor;
resource_monitor(_Value) -> none.

-spec owned_socket_owner(registered_value()) -> pid() | none.
owned_socket_owner({owned_socket, _Socket, Owner, _Monitor}) -> Owner;
owned_socket_owner(_Value) -> none.

-spec new_owned_socket(term(), pid()) -> owned_socket().
new_owned_socket(Socket, Owner) ->
    {owned_socket, Socket, Owner, monitor(process, Owner)}.

-spec release_registered_monitor(registered_value()) -> ok.
release_registered_monitor(
    {pending_resource_checkout, _Reference, _Caller, CallerMonitor,
        _ReplyAlias, _ResourceOwner, ResourceMonitor, _Key, _Value,
        _PoolDeadline, _CheckoutDeadline}
) ->
    demonitor(CallerMonitor, [flush]),
    demonitor(ResourceMonitor, [flush]),
    ok;
release_registered_monitor(
    {borrowed_resource_checkout, _Reference, _Caller, CallerMonitor,
        _ResourceOwner, ResourceMonitor}
) ->
    demonitor(CallerMonitor, [flush]),
    demonitor(ResourceMonitor, [flush]),
    ok;
release_registered_monitor(
    Shared = {shared_http3, _ResourceOwner, ResourceMonitor, _Key,
        _Connection, _Mode, _IdleDeadline, _Capability, _Leases}
) ->
    _ = terminalize_http3_shared_value(Shared, false),
    demonitor(ResourceMonitor, [flush]),
    ok;
release_registered_monitor(
    {closing_http3_candidate, _ResourceOwner, ResourceMonitor, _CloseDeadline}
) ->
    demonitor(ResourceMonitor, [flush]),
    ok;
release_registered_monitor(
    {pending_socket_handoff, _HandoffReference, _Socket, _PreviousOwner,
        PreviousMonitor, _Owner, OwnerMonitor, _Deadline}
) ->
    demonitor(PreviousMonitor, [flush]),
    demonitor(OwnerMonitor, [flush]),
    ok;
release_registered_monitor(Dial = {http3_dial, _, _, _, _, _, _, _}) ->
    settle_http3_dial_and_close(Dial, failed);
release_registered_monitor(Value) ->
    case resource_monitor(Value) of
        none -> ok;
        Monitor -> demonitor(Monitor, [flush]), ok
    end.

-spec release_resource_monitor(reference(), [registered_socket()]) -> ok.
release_resource_monitor(Token, Sockets) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, _, Value} ->
            release_registered_monitor(Value);
        false -> ok
    end.

%% Resource wrappers preserve the private typed close subject across idle,
%% offered, and borrowed pool states. Generic resource owners retain the
%% established force-close contract.
-spec resource_owner_pid(resource_owner()) -> pid().
resource_owner_pid(Pid) when is_pid(Pid) ->
    Pid;
resource_owner_pid({http3_resource_owner, Pid, _Tag}) ->
    Pid.

-spec resource_owner_alive(resource_owner()) -> boolean().
resource_owner_alive(ResourceOwner) ->
    is_process_alive(resource_owner_pid(ResourceOwner)).

-spec begin_resource_owner_shutdown(resource_owner(), integer()) -> ok.
begin_resource_owner_shutdown(
    {http3_resource_owner, ResourceOwner, Tag}, Deadline
) ->
    ResourceOwner ! {Tag, {close, Deadline}},
    ok;
begin_resource_owner_shutdown(ResourceOwner, _Deadline)
    when is_pid(ResourceOwner) ->
    exit(ResourceOwner, kill),
    ok.

-spec force_resource_owner_shutdown(resource_owner()) -> ok.
force_resource_owner_shutdown(ResourceOwner) ->
    exit(resource_owner_pid(ResourceOwner), kill),
    ok.

-spec force_pending_resource_owners([pending_resource_owner()]) -> ok.
force_pending_resource_owners(Pending) ->
    lists:foreach(
        fun({_Monitor, ResourceOwner}) ->
            force_resource_owner_shutdown(ResourceOwner)
        end,
        Pending
    ).

%% Start terminal cleanup without discarding monitors for lifecycle-owned
%% connection processes. Socket entries are different: an idle pooled socket
%% is owned by this lifecycle process itself, so its transport close is the
%% terminal confirmation and its self-monitor must not be joined.
-spec begin_registered_shutdown([registered_socket()], integer()) ->
    [pending_resource_owner()].
begin_registered_shutdown(Sockets, Deadline) ->
    lists:usort(lists:foldl(
        fun({_Token, _Origin, Value}, Pending) ->
            reject_pending_resource_checkout(Value),
            begin_registered_value_shutdown(Value, Pending, Deadline)
        end,
        [],
        Sockets
    )).

-spec begin_registered_value_shutdown(
    term(), [pending_resource_owner()], integer()
) ->
    [pending_resource_owner()].
begin_registered_value_shutdown(
    {resource_reservation, _Pid, Monitor}, Pending, _Deadline
) ->
    demonitor(Monitor, [flush]),
    Pending;
begin_registered_value_shutdown(
    Dial = {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
        _DialDeadline, Attachment, _Waiters},
    Pending,
    Deadline
) ->
    notify_http3_dial_waiters(Dial, {error, 1}),
    release_http3_dial_caller_monitors(Dial),
    case Attachment of
        none -> Pending;
        {ResourceOwner, ResourceMonitor} ->
            begin_resource_owner_shutdown(ResourceOwner, Deadline),
            [{ResourceMonitor, ResourceOwner} | Pending]
    end;
begin_registered_value_shutdown(
    {owned_resource, ResourceOwner, Monitor}, Pending, Deadline
) ->
    begin_resource_owner_shutdown(ResourceOwner, Deadline),
    [{Monitor, ResourceOwner} | Pending];
begin_registered_value_shutdown(
    {pending_resource_checkout, _Reference, _Caller, CallerMonitor,
        _ReplyAlias, ResourceOwner, ResourceMonitor, _Key, _Value,
        _PoolDeadline, _CheckoutDeadline},
    Pending,
    Deadline
) ->
    begin_resource_owner_shutdown(ResourceOwner, Deadline),
    demonitor(CallerMonitor, [flush]),
    [{ResourceMonitor, ResourceOwner} | Pending];
begin_registered_value_shutdown(
    {borrowed_resource_checkout, _Reference, _Caller, CallerMonitor,
        ResourceOwner, ResourceMonitor},
    Pending,
    Deadline
) ->
    begin_resource_owner_shutdown(ResourceOwner, Deadline),
    demonitor(CallerMonitor, [flush]),
    [{ResourceMonitor, ResourceOwner} | Pending];
begin_registered_value_shutdown(
    Shared = {shared_http3, ResourceOwner, ResourceMonitor, _Key,
        _Connection, _Mode, _IdleDeadline, _Capability, _Leases},
    Pending,
    Deadline
) ->
    _ = terminalize_http3_shared_value(Shared, false),
    begin_resource_owner_shutdown(ResourceOwner, Deadline),
    [{ResourceMonitor, ResourceOwner} | Pending];
begin_registered_value_shutdown(
    {closing_http3_candidate, ResourceOwner, ResourceMonitor, _CloseDeadline},
    Pending,
    Deadline
) ->
    begin_resource_owner_shutdown(ResourceOwner, Deadline),
    [{ResourceMonitor, ResourceOwner} | Pending];
begin_registered_value_shutdown(
    Handoff = {pending_socket_handoff, _HandoffReference, _Socket,
        _PreviousOwner, _PreviousMonitor, _Owner, _OwnerMonitor,
        _HandoffDeadline},
    Pending,
    _Deadline
) ->
    close_registered_value(Handoff),
    Pending;
begin_registered_value_shutdown(
    {owned_socket, Socket, _Pid, Monitor}, Pending, _Deadline
) ->
    _ = http_transport_ffi:close(Socket),
    demonitor(Monitor, [flush]),
    Pending.

-spec await_registered_shutdown(
    [pending_resource_owner()], integer(), boolean()
) -> joined | {unconfirmed, [pending_resource_owner()]}.
await_registered_shutdown([], _Deadline, _JoinConfirmation) ->
    joined;
await_registered_shutdown(Pending, _Deadline, false) ->
    force_pending_resource_owners(Pending),
    {unconfirmed, Pending};
await_registered_shutdown(Pending, Deadline, true) ->
    receive
        {unregister_socket, Sender, Reference, _Token}
                when (is_pid(Sender) orelse is_reference(Sender)),
                     is_reference(Reference) ->
            send_resource_checkout_reply(Sender, {Reference, {error, 1}}),
            await_registered_shutdown(Pending, Deadline, true);
        {'DOWN', Monitor, process, _Pid, _Reason} ->
            case lists:keymember(Monitor, 1, Pending) of
                true ->
                    await_registered_shutdown(
                        lists:keydelete(Monitor, 1, Pending), Deadline, true
                    );
                false ->
                    await_registered_shutdown(Pending, Deadline, true)
            end
    after deadline_remaining(Deadline) ->
        force_pending_resource_owners(Pending),
        {unconfirmed, Pending}
    end.

%% A failed close never relinquishes an unconfirmed monitor. The owner remains
%% quarantined until every late DOWN arrives, then publishes the terminal state
%% exactly once. No admission or pool state survives in this loop.
-spec lifecycle_close_quarantine(
    atomics:atomics_ref(), [pending_resource_owner()]
) ->
    no_return().
lifecycle_close_quarantine(State, []) ->
    atomics:put(State, 1, 3),
    exit(normal);
lifecycle_close_quarantine(State, Pending) ->
    receive
        {'DOWN', Monitor, process, _Pid, _Reason} ->
            case lists:keymember(Monitor, 1, Pending) of
                true ->
                    lifecycle_close_quarantine(
                        State, lists:keydelete(Monitor, 1, Pending)
                    );
                false ->
                    lifecycle_close_quarantine(State, Pending)
            end;
        {attach_resource, Sender, Reference, _Token, ResourceOwner} ->
            exit(ResourceOwner, kill),
            Sender ! {Reference, {error, 1}},
            lifecycle_close_quarantine(State, Pending);
        {attach_http3_resource, Sender, Reference, _Token,
                ResourceOwner = {http3_resource_owner, PhysicalOwner, Tag}}
            when is_pid(PhysicalOwner), is_reference(Tag) ->
            force_resource_owner_shutdown(ResourceOwner),
            Sender ! {Reference, {error, 1}},
            lifecycle_close_quarantine(State, Pending);
        {attach_http3_resource, Sender, Reference, _Token, _ResourceOwner} ->
            Sender ! {Reference, {error, 1}},
            lifecycle_close_quarantine(State, Pending);
        {attach_reserved_socket, Sender, Reference, _Token, Socket} ->
            _ = http_transport_ffi:close(Socket),
            Sender ! {Reference, {error, 1}},
            lifecycle_close_quarantine(State, Pending)
    end.

-spec close_registered_value(term()) -> ok.
close_registered_value({resource_reservation, _Pid, Monitor}) ->
    demonitor(Monitor, [flush]), ok;
close_registered_value(Dial = {http3_dial, _, _, _, _, _, _, _}) ->
    settle_http3_dial_and_close(Dial, failed);
close_registered_value({owned_resource, ResourceOwner, Monitor}) ->
    force_resource_owner_shutdown(ResourceOwner),
    demonitor(Monitor, [flush]),
    ok;
close_registered_value(
    {pending_resource_checkout, _Reference, _Caller, CallerMonitor,
        _ReplyAlias, ResourceOwner, ResourceMonitor, _Key, _Value,
        _PoolDeadline, _CheckoutDeadline}
) ->
    force_resource_owner_shutdown(ResourceOwner),
    demonitor(CallerMonitor, [flush]),
    demonitor(ResourceMonitor, [flush]),
    ok;
close_registered_value(
    {borrowed_resource_checkout, _Reference, _Caller, CallerMonitor,
        ResourceOwner, ResourceMonitor}
) ->
    force_resource_owner_shutdown(ResourceOwner),
    demonitor(CallerMonitor, [flush]),
    demonitor(ResourceMonitor, [flush]),
    ok;
close_registered_value(
    Shared = {shared_http3, ResourceOwner, ResourceMonitor, _Key,
        _Connection, _Mode, _IdleDeadline, _Capability, _Leases}
) ->
    _ = terminalize_http3_shared_value(Shared, false),
    force_resource_owner_shutdown(ResourceOwner),
    demonitor(ResourceMonitor, [flush]),
    ok;
close_registered_value(
    {closing_http3_candidate, ResourceOwner, ResourceMonitor, _CloseDeadline}
) ->
    force_resource_owner_shutdown(ResourceOwner),
    demonitor(ResourceMonitor, [flush]),
    ok;
close_registered_value(
    {pending_socket_handoff, _HandoffReference, Socket, _PreviousOwner,
        PreviousMonitor, _Owner, OwnerMonitor, _Deadline}
) ->
    _ = http_transport_ffi:close(Socket),
    demonitor(PreviousMonitor, [flush]),
    demonitor(OwnerMonitor, [flush]),
    ok;
close_registered_value({owned_socket, Socket, _Pid, Monitor}) ->
    _ = http_transport_ffi:close(Socket),
    demonitor(Monitor, [flush]),
    ok.

-spec close_pooled_value(reference(), term(), [registered_socket()]) -> ok.
close_pooled_value(Token, {resource_value, _Value}, Sockets) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, _, Resource} -> close_registered_value(Resource);
        false -> ok
    end;
close_pooled_value(Token, Socket, Sockets) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, _, Resource} -> close_registered_value(Resource);
        false -> _ = http_transport_ffi:close(Socket), ok
    end.

-spec register_or_refresh(
    reference(), binary(), term(), pid(), [registered_socket()], pool_limits()
) -> {ok, reference(), [registered_socket()]} | {handoff, reference()} |
    capacity.
register_or_refresh(RequestedToken, Origin, Socket, Owner, Sockets, Limits) ->
    case socket_token(Socket, Sockets) of
        {ok, Token} ->
            case owned_socket_value(Token, Sockets) of
                {pending_socket_handoff, _, _, _, _, _, _, _} ->
                    {handoff, Token};
                Previous ->
                    Owned = new_owned_socket(Socket, Owner),
                    release_registered_monitor(Previous),
                    {ok, Token, store_socket(Token, Origin, Owned, Sockets)}
            end;
        error ->
            case connection_has_capacity(Origin, Sockets, Limits) of
                false -> capacity;
                true ->
                    Owned = new_owned_socket(Socket, Owner),
                    {ok, RequestedToken,
                        [{RequestedToken, Origin, Owned} | Sockets]}
            end
    end.

-spec begin_socket_handoff_entry(
    reference(), term(), pid(), pid(), integer(), [registered_socket()]
) -> {ok, reference(), [registered_socket()]} | error.
begin_socket_handoff_entry(
    HandoffReference, Socket, PreviousOwner, Owner, Deadline, Sockets
) ->
    case socket_token(Socket, Sockets) of
        {ok, Token} ->
            case lists:keyfind(Token, 1, Sockets) of
                {Token, Origin,
                    {owned_socket, _Stored, PreviousOwner, PreviousMonitor}} ->
                    case safe_socket_handoff_monitor(Owner) of
                        {ok, OwnerMonitor} ->
                            Pending = {pending_socket_handoff,
                                HandoffReference, Socket, PreviousOwner,
                                PreviousMonitor, Owner, OwnerMonitor,
                                Deadline},
                            {ok, Token,
                                store_socket(Token, Origin, Pending, Sockets)};
                        error ->
                            %% PreviousMonitor remains live and Sockets is
                            %% unchanged. The caller still owns the transport
                            %% and receives the typed rejection before closing.
                            error
                    end;
                _ ->
                    error
            end;
        error ->
            error
    end.

-spec safe_socket_handoff_monitor(pid()) -> {ok, reference()} | error.
safe_socket_handoff_monitor(Owner) when is_pid(Owner) ->
    try socket_handoff_monitor(Owner) of
        Monitor -> {ok, Monitor}
    catch
        _Class:_Reason -> error
    end;
safe_socket_handoff_monitor(_Owner) ->
    error.

-spec socket_handoff_monitor(pid()) -> term().
socket_handoff_monitor(Owner) ->
    case get(http_client_socket_handoff_monitor_factory) of
        MonitorFactory when is_function(MonitorFactory, 1) ->
            case MonitorFactory(Owner) of
                continue -> monitor(process, Owner);
                _Invalid -> erlang:error(invalid_handoff_monitor_factory_result)
            end;
        _ ->
            monitor(process, Owner)
    end.

-spec commit_socket_handoff_entry(reference(), [registered_socket()]) ->
    {ok, [registered_socket()]} | error.
commit_socket_handoff_entry(HandoffReference, Sockets) ->
    case find_socket_handoff(HandoffReference, Sockets) of
        {ok, Token, Origin,
            {pending_socket_handoff, HandoffReference, Socket,
                _PreviousOwner, PreviousMonitor, Owner, OwnerMonitor,
                Deadline}} ->
            case erlang:monotonic_time(millisecond) < Deadline
                andalso is_process_alive(Owner)
            of
                true ->
                    demonitor(PreviousMonitor, [flush]),
                    Owned = {owned_socket, Socket, Owner, OwnerMonitor},
                    {ok, store_socket(Token, Origin, Owned, Sockets)};
                false ->
                    error
            end;
        error ->
            error
    end.

-spec abort_socket_handoff_entry(
    reference(), [registered_socket()], [pooled_socket()]
) -> {[registered_socket()], [pooled_socket()]}.
abort_socket_handoff_entry(HandoffReference, Sockets, Pool) ->
    case find_socket_handoff(HandoffReference, Sockets) of
        {ok, Token, _Origin, Pending} ->
            close_registered_value(Pending),
            {
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool)
            };
        error ->
            {Sockets, Pool}
    end.

-spec find_socket_handoff(reference(), [registered_socket()]) ->
    {ok, reference(), binary(), pending_socket_handoff()} | error.
find_socket_handoff(_HandoffReference, []) ->
    error;
find_socket_handoff(
    HandoffReference,
    [{Token, Origin,
        Pending = {pending_socket_handoff, HandoffReference, _Socket,
            _PreviousOwner, _PreviousMonitor, _Owner, _OwnerMonitor,
            _Deadline}} | _Rest]
) ->
    {ok, Token, Origin, Pending};
find_socket_handoff(HandoffReference, [_Entry | Rest]) ->
    find_socket_handoff(HandoffReference, Rest).

-spec checkout_pooled(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    binary(),
    pid(),
    reference(),
    reference(),
    integer(),
    pool_limits()
) -> no_return().
checkout_pooled(
    State, Sockets, Pool, Origin, Sender, ReplyAlias, Reference, Deadline,
    Limits
) ->
    case take_origin(Origin, Pool, []) of
        empty ->
            send_resource_checkout_reply(ReplyAlias, {Reference, empty}),
            lifecycle_loop(State, Sockets, Pool, Limits);
        {found, Token, Socket, RemainingPool} ->
            HandoffReference = make_ref(),
            case begin_socket_handoff_entry(
                HandoffReference, Socket, self(), Sender, Deadline, Sockets
            ) of
                {ok, Token, PendingSockets} ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_offer, HandoffReference,
                            Socket}}
                    ),
                    finish_socket_checkout_handoff(
                        State, PendingSockets, RemainingPool, Origin, Sender,
                        ReplyAlias, Reference, HandoffReference, Socket,
                        Deadline, Limits
                    );
                error ->
                    _ = http_transport_ffi:close(Socket),
                    checkout_pooled(
                        State,
                        drop_registered_token(Token, Sockets),
                        RemainingPool,
                        Origin,
                        Sender,
                        ReplyAlias,
                        Reference,
                        Deadline,
                        Limits
                    )
            end
    end.

-spec finish_socket_checkout_handoff(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], binary(),
    pid(), reference(), reference(), reference(), term(), integer(),
    pool_limits()
) -> no_return().
finish_socket_checkout_handoff(
    State, Sockets, Pool, Origin, Sender, ReplyAlias, Reference,
    HandoffReference, Socket, Deadline, Limits
) ->
    {ok, _Token, _StoredOrigin,
        {pending_socket_handoff, HandoffReference, _StoredSocket,
            _PreviousOwner, _PreviousMonitor, Sender, SenderMonitor,
            Deadline}} = find_socket_handoff(HandoffReference, Sockets),
    Outcome = receive
        {socket_handoff_ready, Sender, HandoffReference} ->
            case erlang:monotonic_time(millisecond) < Deadline
                andalso safe_state(State) =:= 0
                andalso is_process_alive(Sender)
            of
                true ->
                    case http_transport_ffi:transfer_owner(Socket, Sender) of
                        {ok, nil} ->
                            case pause_socket_handoff(
                                Deadline, http1_checkout_after_transfer
                            ) of
                                continue ->
                                    commit_socket_handoff_entry(
                                        HandoffReference, Sockets
                                    );
                                stop -> error
                            end;
                        {error, _Reason} -> error
                    end;
                false -> error
            end;
        {abort_socket_handoff, Sender, HandoffReference} ->
            error;
        {'DOWN', SenderMonitor, process, Sender, _Reason} ->
            error;
        drain_pool ->
            self() ! drain_pool,
            error;
        Control = {close_before, _ControlReplyAlias, _ControlReference,
                _ControlDeadline, _JoinConfirmation} ->
            self() ! Control,
            error
    after deadline_remaining(Deadline) ->
        error
    end,
    case Outcome of
        {ok, UpdatedSockets} ->
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_committed, HandoffReference}}
            ),
            lifecycle_loop(State, UpdatedSockets, Pool, Limits);
        error ->
            {AbortedSockets, AbortedPool} = abort_socket_handoff_entry(
                HandoffReference, Sockets, Pool
            ),
            case safe_state(State) =:= 0
                andalso is_process_alive(Sender)
                andalso erlang:monotonic_time(millisecond) < Deadline
            of
                true ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_retry, HandoffReference}}
                    ),
                    checkout_pooled(
                        State, AbortedSockets, AbortedPool, Origin, Sender,
                        ReplyAlias, Reference, Deadline, Limits
                    );
                false ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_rejected,
                            HandoffReference}}
                    ),
                    lifecycle_loop(State, AbortedSockets, AbortedPool, Limits)
            end
    end.

-spec checkin_pooled(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    binary(),
    term(),
    pid(),
    reference(),
    reference(),
    reference(),
    integer(),
    pool_limits()
) -> no_return().
checkin_pooled(
    State,
    Sockets,
    Pool,
    Origin,
    Socket,
    Sender,
    ReplyAlias,
    Reference,
    HandoffReference,
    Deadline,
    Limits = {_Maximum, _PerOrigin, IdleMilliseconds}
) ->
    case safe_state(State) =:= 0 andalso
        pool_has_capacity(Origin, Pool, Limits) andalso
        erlang:monotonic_time(millisecond) < Deadline andalso
        is_process_alive(Sender)
    of
        true ->
            case begin_socket_handoff_entry(
                HandoffReference, Socket, Sender, self(), Deadline, Sockets
            ) of
                {ok, Token, PendingSockets} ->
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_ready, HandoffReference}}
                    ),
                    finish_socket_checkin_handoff(
                        State, PendingSockets, Pool, Origin, Socket, Sender,
                        ReplyAlias, Reference, HandoffReference, Token,
                        Deadline, IdleMilliseconds, Limits
                    );
                error ->
                    _ = http_transport_ffi:close(Socket),
                    send_resource_checkout_reply(
                        ReplyAlias,
                        {Reference, {socket_handoff_rejected,
                            HandoffReference}}
                    ),
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        false ->
            _ = http_transport_ffi:close(Socket),
            UpdatedSockets = drop_socket(Socket, Sockets),
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_rejected, HandoffReference}}
            ),
            lifecycle_loop(State, UpdatedSockets, Pool, Limits)
    end.

-spec finish_socket_checkin_handoff(
    atomics:atomics_ref(), [registered_socket()], [pooled_socket()], binary(),
    term(), pid(), reference(), reference(), reference(), reference(),
    integer(), pos_integer(), pool_limits()
) -> no_return().
finish_socket_checkin_handoff(
    State, Sockets, Pool, Origin, Socket, Sender, ReplyAlias, Reference,
    HandoffReference, Token, Deadline, IdleMilliseconds, Limits
) ->
    {ok, Token, _StoredOrigin,
        {pending_socket_handoff, HandoffReference, _StoredSocket, Sender,
            SenderMonitor, _Owner, _OwnerMonitor, Deadline}} =
        find_socket_handoff(HandoffReference, Sockets),
    Outcome = receive
        {socket_handoff_transferred, Sender, HandoffReference} ->
            case pause_socket_handoff(
                Deadline, http1_checkin_after_transfer
            ) of
                continue ->
                    case safe_state(State) =:= 0
                        andalso is_process_alive(Sender)
                        andalso erlang:monotonic_time(millisecond) < Deadline
                    of
                        true -> commit_socket_handoff_entry(
                            HandoffReference, Sockets
                        );
                        false -> error
                    end;
                stop -> error
            end;
        {abort_socket_handoff, Sender, HandoffReference} ->
            error;
        {'DOWN', SenderMonitor, process, Sender, _Reason} ->
            error;
        drain_pool ->
            self() ! drain_pool,
            error;
        Control = {close_before, _ControlReplyAlias, _ControlReference,
                _ControlDeadline, _JoinConfirmation} ->
            self() ! Control,
            error
    after deadline_remaining(Deadline) ->
        error
    end,
    case Outcome of
        {ok, UpdatedSockets} ->
            IdleDeadline = erlang:monotonic_time(millisecond)
                + IdleMilliseconds,
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_committed, HandoffReference}}
            ),
            lifecycle_loop(
                State,
                UpdatedSockets,
                [{Origin, Token, Socket, IdleDeadline} |
                    remove_pool_token(Token, Pool)],
                Limits
            );
        error ->
            {AbortedSockets, AbortedPool} = abort_socket_handoff_entry(
                HandoffReference, Sockets, Pool
            ),
            send_resource_checkout_reply(
                ReplyAlias,
                {Reference, {socket_handoff_rejected, HandoffReference}}
            ),
            lifecycle_loop(State, AbortedSockets, AbortedPool, Limits)
    end.

-spec pool_has_capacity(binary(), [pooled_socket()], pool_limits()) -> boolean().
pool_has_capacity(Origin, Pool, {Maximum, PerOrigin, _IdleMilliseconds}) ->
    length(Pool) < Maximum andalso
        count_origin(Origin, Pool, 0) < PerOrigin.

-spec connection_has_capacity(
    binary(), [registered_socket()], pool_limits()
) -> boolean().
connection_has_capacity(
    Origin,
    Sockets,
    {Maximum, PerOrigin, _IdleMilliseconds}
) ->
    length(Sockets) < Maximum andalso
        count_registered_origin(Origin, Sockets, 0) < PerOrigin.

-spec count_registered_origin(
    binary(), [registered_socket()], non_neg_integer()
) -> non_neg_integer().
count_registered_origin(_Origin, [], Count) ->
    Count;
count_registered_origin(Origin, [{_, Origin, _} | Rest], Count) ->
    count_registered_origin(Origin, Rest, Count + 1);
count_registered_origin(Origin, [_ | Rest], Count) ->
    count_registered_origin(Origin, Rest, Count).

-spec count_origin(binary(), [pooled_socket()], non_neg_integer()) ->
    non_neg_integer().
count_origin(_Origin, [], Count) ->
    Count;
count_origin(Origin, [{Origin, _, _, _} | Rest], Count) ->
    count_origin(Origin, Rest, Count + 1);
count_origin(Origin, [_ | Rest], Count) ->
    count_origin(Origin, Rest, Count).

-spec take_origin(binary(), [pooled_socket()], [pooled_socket()]) ->
    empty | {found, reference(), term(), [pooled_socket()]}.
take_origin(_Origin, [], _Earlier) ->
    empty;
take_origin(Origin, [{Origin, Token, Socket, _} | Rest], Earlier) ->
    {found, Token, Socket, lists:reverse(Earlier, Rest)};
take_origin(Origin, [Entry | Rest], Earlier) ->
    take_origin(Origin, Rest, [Entry | Earlier]).

-spec take_resource_origin(binary(), [pooled_socket()], [pooled_socket()]) ->
    empty |
    {found, reference(), term(), integer(), [pooled_socket()]}.
take_resource_origin(_Key, [], _Earlier) ->
    empty;
take_resource_origin(
    Key,
    [{Key, Token, {resource_value, Value}, PoolDeadline} | Rest],
    Earlier
) ->
    {found, Token, Value, PoolDeadline, lists:reverse(Earlier, Rest)};
take_resource_origin(Key, [Entry | Rest], Earlier) ->
    take_resource_origin(Key, Rest, [Entry | Earlier]).

-spec prune_expired(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pool_limits()
) ->
    {[registered_socket()], [pooled_socket()]}.
prune_expired(State, Sockets, Pool, Limits) ->
    Now = erlang:monotonic_time(millisecond),
    {HandoffSockets, HandoffPool} = prune_expired_socket_handoffs(
        Sockets, Pool, Now
    ),
    {RetainedSockets, RetainedPool} = prune_expired_pool(
        HandoffSockets,
        HandoffPool,
        Now,
        []
    ),
    Http3RetainedSockets = prune_expired_http3_shared(
        RetainedSockets, Now
    ),
    prune_pending_resources(
        State, Http3RetainedSockets, RetainedPool, Limits, Now
    ).

-spec prune_expired_socket_handoffs(
    [registered_socket()], [pooled_socket()], integer()
) -> {[registered_socket()], [pooled_socket()]}.
prune_expired_socket_handoffs(Sockets, Pool, Now) ->
    lists:foldl(
        fun
            ({Token, _Origin,
                Pending = {pending_socket_handoff, _HandoffReference,
                    _Socket, _PreviousOwner, _PreviousMonitor, _Owner,
                    _OwnerMonitor, Deadline}}, {KeptSockets, KeptPool})
                    when Deadline =< Now ->
                close_registered_value(Pending),
                {
                    lists:keydelete(Token, 1, KeptSockets),
                    remove_pool_token(Token, KeptPool)
                };
            (_Entry, Acc) ->
                Acc
        end,
        {Sockets, Pool},
        Sockets
    ).

-spec prune_expired_http3_shared([registered_socket()], integer()) ->
    [registered_socket()].
prune_expired_http3_shared([], _Now) -> [];
prune_expired_http3_shared(
    [{Token, Origin,
      Shared = {shared_http3, _ResourceOwner, _ResourceMonitor, _Key,
          _Connection, accepting, IdleDeadline, _Capability, []}} | Rest],
    Now
) when is_integer(IdleDeadline), IdleDeadline =< Now ->
    [{Token, Origin,
      drain_http3_shared_value(Shared, Now + ?OWNER_TIMEOUT)} |
     prune_expired_http3_shared(Rest, Now)];
prune_expired_http3_shared(
    [{Token, Origin,
      {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
          closing, CloseDeadline, Capability, Leases}} | Rest],
    Now
) when is_integer(CloseDeadline), CloseDeadline =< Now ->
    force_resource_owner_shutdown(ResourceOwner),
    [{Token, Origin,
      {shared_http3, ResourceOwner, ResourceMonitor, Key, Connection,
          closing, Now + ?OWNER_TIMEOUT, Capability, Leases}} |
     prune_expired_http3_shared(Rest, Now)];
prune_expired_http3_shared(
    [{Token, Origin,
      {closing_http3_candidate, ResourceOwner, ResourceMonitor,
          CloseDeadline}} | Rest],
    Now
) when is_integer(CloseDeadline), CloseDeadline =< Now ->
    force_resource_owner_shutdown(ResourceOwner),
    [{Token, Origin,
      {closing_http3_candidate, ResourceOwner, ResourceMonitor,
          Now + ?OWNER_TIMEOUT}} |
     prune_expired_http3_shared(Rest, Now)];
prune_expired_http3_shared([Entry | Rest], Now) ->
    [Entry | prune_expired_http3_shared(Rest, Now)].

-spec prune_expired_pool(
    [registered_socket()],
    [pooled_socket()],
    integer(),
    [pooled_socket()]
) -> {[registered_socket()], [pooled_socket()]}.
prune_expired_pool(Sockets, [], _Now, Retained) ->
    {Sockets, lists:reverse(Retained)};
prune_expired_pool(
    Sockets, [{_, Token, Socket, Deadline} | Rest], Now, Retained
)
    when Deadline =< Now ->
    close_pooled_value(Token, Socket, Sockets),
    prune_expired_pool(
        lists:keydelete(Token, 1, Sockets), Rest, Now, Retained
    );
prune_expired_pool(Sockets, [Entry | Rest], Now, Retained) ->
    prune_expired_pool(Sockets, Rest, Now, [Entry | Retained]).

-spec prune_pending_resources(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pool_limits(),
    integer()
) -> {[registered_socket()], [pooled_socket()]}.
prune_pending_resources(State, Sockets, Pool, Limits, Now) ->
    prune_pending_resources(State, Sockets, Pool, Limits, Now, []).

-spec prune_pending_resources(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pool_limits(),
    integer(),
    [registered_socket()]
) -> {[registered_socket()], [pooled_socket()]}.
prune_pending_resources(_State, [], Pool, _Limits, _Now, Retained) ->
    {lists:reverse(Retained), Pool};
prune_pending_resources(
    State,
    [{Token, Origin,
      {http3_dial, Key, Leader, LeaderMonitor, ClaimReference,
        DialDeadline, Attachment, Waiters}} | Rest],
    Pool,
    Limits,
    Now,
    Retained
) ->
    LiveWaiters = prune_http3_dial_waiters(Waiters, Now),
    Dial = {http3_dial, Key, Leader, LeaderMonitor, ClaimReference,
        DialDeadline, Attachment, LiveWaiters},
    Terminal = case safe_state(State) of
        0 ->
            case DialDeadline =< Now orelse not is_process_alive(Leader)
                orelse not http3_dial_attachment_alive(Attachment)
            of
                true -> failed;
                false -> retain
            end;
        _ -> {error, 1}
    end,
    case Terminal of
        retain ->
            prune_pending_resources(
                State, Rest, Pool, Limits, Now,
                [{Token, Origin, Dial} | Retained]
            );
        Outcome ->
            Settled = retire_http3_dial_entry(
                Token, Origin, Dial, Now + ?OWNER_TIMEOUT, Outcome,
                [{Token, Origin, Dial}]
            ),
            UpdatedRetained = case Settled of
                [] -> Retained;
                [Closing] -> [Closing | Retained]
            end,
            prune_pending_resources(
                State, Rest, remove_pool_token(Token, Pool), Limits, Now,
                UpdatedRetained
            )
    end;
prune_pending_resources(
    State,
    [{Token, Origin,
        Pending = {pending_resource_checkout, _Reference, _Caller,
            CallerMonitor, _ReplyAlias, ResourceOwner, ResourceMonitor, Key,
            Value, PoolDeadline, CheckoutDeadline}} | Rest],
    Pool,
    Limits,
    Now,
    Retained
) ->
    case safe_state(State) =/= 0 orelse CheckoutDeadline =< Now
        orelse PoolDeadline =< Now
    of
        false ->
            prune_pending_resources(
                State,
                Rest,
                Pool,
                Limits,
                Now,
                [{Token, Origin, Pending} | Retained]
            );
        true ->
            CanRestore = safe_state(State) =:= 0
                andalso resource_owner_alive(ResourceOwner)
                andalso Now < PoolDeadline
                andalso pool_has_capacity(Key, Pool, Limits),
            reject_pending_resource_checkout(Pending),
            case CanRestore of
                true ->
                    demonitor(CallerMonitor, [flush]),
                    Owned = {owned_resource, ResourceOwner, ResourceMonitor},
                    prune_pending_resources(
                        State,
                        Rest,
                        [{Key, Token, {resource_value, Value}, PoolDeadline} |
                            remove_pool_token(Token, Pool)],
                        Limits,
                        Now,
                        [{Token, Origin, Owned} | Retained]
                    );
                false ->
                    close_registered_value(Pending),
                    prune_pending_resources(
                        State,
                        Rest,
                        remove_pool_token(Token, Pool),
                        Limits,
                        Now,
                        Retained
                    )
            end
    end;
prune_pending_resources(
    State, [Entry | Rest], Pool, Limits, Now, Retained
) ->
    prune_pending_resources(
        State, Rest, Pool, Limits, Now, [Entry | Retained]
    ).

-spec prune_http3_dial_waiters(
    [http3_dial_waiter()], integer()
) -> [http3_dial_waiter()].
prune_http3_dial_waiters([], _Now) -> [];
prune_http3_dial_waiters(
    [Waiter = {Reference, Caller, CallerMonitor, ReplyAlias, Deadline} | Rest],
    Now
) ->
    case Deadline > Now andalso is_process_alive(Caller) of
        true -> [Waiter | prune_http3_dial_waiters(Rest, Now)];
        false ->
            case is_process_alive(Caller) andalso Deadline =< Now of
                true ->
                    send_resource_checkout_reply(
                        ReplyAlias, {Reference, {error, 1}}
                    );
                false -> ok
            end,
            demonitor(CallerMonitor, [flush]),
            prune_http3_dial_waiters(Rest, Now)
    end.

-spec http3_dial_attachment_alive(http3_dial_attachment()) -> boolean().
http3_dial_attachment_alive(none) -> true;
http3_dial_attachment_alive({ResourceOwner, _ResourceMonitor}) ->
    resource_owner_alive(ResourceOwner).

-spec lifecycle_wait(
    [registered_socket()], [pooled_socket()], pool_limits()
) -> pos_integer().
lifecycle_wait(Sockets, Pool, Limits) ->
    erlang:min(
        erlang:min(
            erlang:min(pool_wait(Pool, Limits), pending_resource_wait(Sockets)),
            http3_dial_wait(Sockets)
        ),
        http3_idle_wait(Sockets)
    ).

-spec http3_dial_wait([registered_socket()]) -> pos_integer().
http3_dial_wait(Sockets) ->
    DialDeadlines = [Deadline ||
        {_Token, _Origin,
         {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
            Deadline, _Attachment, _Waiters}} <- Sockets],
    WaiterDeadlines = lists:append([[
        Deadline ||
            {_Reference, _Caller, _CallerMonitor, _ReplyAlias, Deadline}
                <- Waiters
    ] ||
        {_Token, _Origin,
         {http3_dial, _Key, _Leader, _LeaderMonitor, _ClaimReference,
            _DialDeadline, _Attachment, Waiters}} <- Sockets]),
    case DialDeadlines ++ WaiterDeadlines of
        [] -> 2147483647;
        Deadlines ->
            Now = erlang:monotonic_time(millisecond),
            erlang:max(1, lists:min(Deadlines) - Now)
    end.

-spec http3_idle_wait([registered_socket()]) -> pos_integer().
http3_idle_wait(Sockets) ->
    IdleDeadlines = [IdleDeadline ||
        {_Token, _Origin,
         {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
           accepting, IdleDeadline, _Capability, []}} <- Sockets,
        is_integer(IdleDeadline)],
    ClosingDeadlines = [CloseDeadline ||
        {_Token, _Origin,
         {shared_http3, _ResourceOwner, _ResourceMonitor, _Key, _Connection,
          closing, CloseDeadline, _Capability, _Leases}} <- Sockets,
        is_integer(CloseDeadline)],
    CandidateDeadlines = [CloseDeadline ||
        {_Token, _Origin,
         {closing_http3_candidate, _ResourceOwner, _ResourceMonitor,
          CloseDeadline}} <- Sockets,
        is_integer(CloseDeadline)],
    Deadlines = IdleDeadlines ++ ClosingDeadlines ++ CandidateDeadlines,
    case Deadlines of
        [] -> 2147483647;
        _ ->
            Now = erlang:monotonic_time(millisecond),
            erlang:max(1, lists:min(Deadlines) - Now)
    end.

-spec pending_resource_wait([registered_socket()]) -> pos_integer().
pending_resource_wait(Sockets) ->
    Deadlines = [erlang:min(PoolDeadline, CheckoutDeadline) ||
        {_Token, _Origin,
            {pending_resource_checkout, _Reference, _Caller,
                _CallerMonitor, _ReplyAlias, _ResourceOwner,
                _ResourceMonitor, _Key, _Value, PoolDeadline,
                CheckoutDeadline}} <- Sockets],
    case Deadlines of
        [] -> 2147483647;
        _ ->
            Now = erlang:monotonic_time(millisecond),
            erlang:max(1, lists:min(Deadlines) - Now)
    end.

-spec pool_wait([pooled_socket()], pool_limits()) -> pos_integer().
pool_wait([], {_Maximum, _PerOrigin, _IdleMilliseconds}) ->
    2147483647;
pool_wait(Pool, _Limits) ->
    Now = erlang:monotonic_time(millisecond),
    Earliest = lists:min([Deadline || {_, _, _, Deadline} <- Pool]),
    erlang:max(1, Earliest - Now).

-spec close_pool([registered_socket()], [pooled_socket()]) ->
    {[registered_socket()], []}.
close_pool(Sockets, Pool) ->
    Remaining = lists:foldl(
        fun({_Origin, Token, Socket, _Deadline}, Acc) ->
            close_pooled_value(Token, Socket, Acc),
            lists:keydelete(Token, 1, Acc)
        end,
        Sockets,
        Pool
    ),
    {Remaining, []}.

-spec remove_pool_token(reference(), [pooled_socket()]) -> [pooled_socket()].
remove_pool_token(Token, Pool) ->
    [Entry || Entry = {_, EntryToken, _, _} <- Pool, EntryToken =/= Token].

-spec socket_token(term(), [registered_socket()]) ->
    {ok, reference()} | error.
socket_token(_Socket, []) ->
    error;
socket_token(Socket, [{Token, _Origin, Candidate} | Rest]) ->
    case same_socket(Socket, Candidate) of
        true -> {ok, Token};
        false -> socket_token(Socket, Rest)
    end.

-spec owned_socket_value(reference(), [registered_socket()]) ->
    registered_value().
owned_socket_value(Token, Sockets) ->
    {Token, _Origin, Value} = lists:keyfind(Token, 1, Sockets),
    Value.

-spec store_socket(
    reference(), binary(), registered_value(), [registered_socket()]
) ->
    [registered_socket()].
store_socket(Token, Origin, Value, Sockets) ->
    [{Token, Origin, Value} | lists:keydelete(Token, 1, Sockets)].

-spec drop_registered_token(reference(), [registered_socket()]) ->
    [registered_socket()].
drop_registered_token(Token, Sockets) ->
    case lists:keyfind(Token, 1, Sockets) of
        {Token, _Origin, Value} -> release_registered_monitor(Value);
        false -> ok
    end,
    lists:keydelete(Token, 1, Sockets).

-spec drop_socket(term(), [registered_socket()]) -> [registered_socket()].
drop_socket(Socket, Sockets) ->
    case socket_token(Socket, Sockets) of
        {ok, Token} -> drop_registered_token(Token, Sockets);
        error -> Sockets
    end.

-spec same_socket(term(), term()) -> boolean().
same_socket(Socket, {owned_socket, Candidate, _Owner, _Monitor}) ->
    same_socket(Socket, Candidate);
same_socket(
    Socket,
    {pending_socket_handoff, _HandoffReference, Candidate, _PreviousOwner,
        _PreviousMonitor, _Owner, _OwnerMonitor, _Deadline}
) ->
    same_socket(Socket, Candidate);
same_socket(
    #{kind := Kind, socket := Socket},
    #{kind := Kind, socket := Socket}
) ->
    true;
same_socket(_Left, _Right) ->
    false.

-spec safe_state(atomics:atomics_ref()) -> integer().
safe_state(State) ->
    try atomics:get(State, 1)
    catch
        _Class:_Reason -> 3
    end.
