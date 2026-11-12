%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_client_callback_guard_test).
-include_lib("eunit/include/eunit.hrl").

-define(OBSERVATION_MILLISECONDS, 5000).
-define(CALLBACK_TIMEOUT_MILLISECONDS, 1000).

policy_success_joins_worker_and_supervisor_test() ->
    Deadline = deadline(?OBSERVATION_MILLISECONDS),
    Observation = case http_client_ffi:call_policy_adapter_before(
        fun() ->
            case process_info(self(), links) of
                {links, [Supervisor]} when is_pid(Supervisor) ->
                    {ok, {self(), Supervisor}};
                _ ->
                    {error, no_supervisor}
            end
        end,
        Deadline
    ) of
        {ok, {Worker, Supervisor}} ->
            {process_state(Worker, worker_down, worker_alive),
             process_state(Supervisor, supervisor_down, supervisor_alive)};
        _ ->
            unexpected_result
    end,
    ?assertEqual({worker_down, supervisor_down}, Observation).

policy_exception_is_redacted_and_leaves_no_mailbox_residue_test_() ->
    {spawn, fun policy_exception_mailbox_contract/0}.

policy_exception_mailbox_contract() ->
    Outcome = http_client_ffi:call_policy_adapter_before(
        fun() -> erlang:error({private_policy_fixture, <<"secret">>}) end,
        deadline(?OBSERVATION_MILLISECONDS)
    ),
    ?assertEqual({error, 1}, Outcome),
    ?assertEqual(queue_empty, mailbox_state()).

expired_policy_deadline_never_starts_callback_test() ->
    Observer = self(),
    Started = make_ref(),
    Outcome = http_client_ffi:call_policy_adapter_before(
        fun() ->
            Observer ! {Started, callback_started},
            {ok, unexpected}
        end,
        erlang:monotonic_time(millisecond)
    ),
    ?assertEqual(
        {{error, 2}, callback_not_started},
        {Outcome, callback_start_state(Started)}
    ).

resolver_receives_allocated_budget_separate_from_deadline_test() ->
    Observer = self(),
    Seen = make_ref(),
    Outcome = http_client_ffi:call_https_resolver_before(
        fun(Host, Port, AllocatedMilliseconds) ->
            Observer ! {Seen, Host, Port, AllocatedMilliseconds},
            {ok, []}
        end,
        <<"resolver.invalid">>,
        443,
        37,
        deadline(?OBSERVATION_MILLISECONDS)
    ),
    Observation = receive
        {Seen, <<"resolver.invalid">>, 443, 37} -> allocated_budget_preserved
    after ?OBSERVATION_MILLISECONDS ->
        allocation_not_observed
    end,
    ?assertEqual({{ok, []}, allocated_budget_preserved}, {Outcome, Observation}).

resolver_allocation_cannot_rebase_expired_phase_deadline_test() ->
    Observer = self(),
    Started = make_ref(),
    Expired = erlang:monotonic_time(millisecond),
    Outcome = http_client_ffi:call_https_resolver_before(
        fun(_Host, _Port, _AllocatedMilliseconds) ->
            Observer ! {Started, resolver_started},
            {ok, []}
        end,
        <<"resolver.invalid">>,
        443,
        60000,
        Expired
    ),
    StartedState = receive
        {Started, resolver_started} -> resolver_started
    after 0 ->
        resolver_not_started
    end,
    ?assertEqual({{error, 2}, resolver_not_started}, {Outcome, StartedState}).

policy_timeout_reaps_trapping_callback_and_supervisor_before_return_test() ->
    Observer = self(),
    Started = make_ref(),
    Returned = make_ref(),
    ObservationDeadline = deadline(?OBSERVATION_MILLISECONDS),
    {Caller, CallerMonitor} = erlang:spawn_monitor(fun() ->
        Outcome = http_client_ffi:call_policy_adapter_before(
            fun() ->
                process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Supervisor]} ->
                        Observer ! {Started, self(), Supervisor};
                    _ ->
                        Observer ! {Started, self(), no_supervisor}
                end,
                receive callback_stays_blocked -> {ok, unexpected} end
            end,
            deadline(?CALLBACK_TIMEOUT_MILLISECONDS)
        ),
        Observer ! {
            Returned,
            Outcome,
            mailbox_state()
        }
    end),
    Observation = case await_started(Started, ObservationDeadline) of
        {started, Worker, Supervisor} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            SupervisorMonitor = erlang:monitor(process, Supervisor),
            ReturnedState = receive
                {Returned, Result, QueueState} -> {Result, QueueState}
            after remaining(ObservationDeadline) ->
                caller_not_returned
            end,
            Immediate = {
                process_state(Worker, worker_down, worker_alive),
                process_state(Supervisor, supervisor_down, supervisor_alive)
            },
            Down = {
                named_down(Worker, WorkerMonitor, worker_down, worker_not_down,
                    ObservationDeadline),
                named_down(Supervisor, SupervisorMonitor,
                    supervisor_down, supervisor_not_down, ObservationDeadline),
                named_down(Caller, CallerMonitor, caller_down, caller_not_down,
                    ObservationDeadline)
            },
            {ReturnedState, Immediate, Down};
        callback_not_started ->
            exit(Caller, kill),
            callback_not_started
    end,
    ?assertEqual(
        {
            {{error, 2}, queue_empty},
            {worker_down, supervisor_down},
            {worker_down, supervisor_down, caller_down}
        },
        Observation
    ).

policy_caller_death_reaps_trapping_callback_and_supervisor_test() ->
    Observer = self(),
    Started = make_ref(),
    ObservationDeadline = deadline(?OBSERVATION_MILLISECONDS),
    {Caller, CallerMonitor} = erlang:spawn_monitor(fun() ->
        _ = http_client_ffi:call_policy_adapter_before(
            fun() ->
                process_flag(trap_exit, true),
                case process_info(self(), links) of
                    {links, [Supervisor]} ->
                        Observer ! {Started, self(), Supervisor};
                    _ ->
                        Observer ! {Started, self(), no_supervisor}
                end,
                receive callback_stays_blocked -> {ok, unexpected} end
            end,
            deadline(?OBSERVATION_MILLISECONDS)
        )
    end),
    Observation = case await_started(Started, ObservationDeadline) of
        {started, Worker, Supervisor} ->
            WorkerMonitor = erlang:monitor(process, Worker),
            SupervisorMonitor = erlang:monitor(process, Supervisor),
            exit(Caller, kill),
            {
                named_down(Caller, CallerMonitor, caller_down, caller_not_down,
                    ObservationDeadline),
                named_down(Worker, WorkerMonitor, worker_down, worker_not_down,
                    ObservationDeadline),
                named_down(Supervisor, SupervisorMonitor,
                    supervisor_down, supervisor_not_down, ObservationDeadline)
            };
        callback_not_started ->
            exit(Caller, kill),
            callback_not_started
    end,
    ?assertEqual(
        {caller_down, worker_down, supervisor_down},
        Observation
    ).

policy_pre_registration_supervisor_death_reaps_both_without_start_test() ->
    Observer = self(),
    Started = make_ref(),
    Returned = make_ref(),
    ObservationDeadline = deadline(?OBSERVATION_MILLISECONDS),
    {Caller, CallerMonitor} = erlang:spawn_monitor(fun() ->
        Outcome = http_client_ffi:call_policy_adapter_registration_probe_before(
            fun() ->
                Observer ! {Started, callback_started},
                {ok, unexpected}
            end,
            deadline(?OBSERVATION_MILLISECONDS),
            Observer
        ),
        Observer ! {Returned, Outcome, mailbox_state()}
    end),
    Observation = receive
        {http_client_guarded_callback_pre_registration, _ProbeReference,
         Supervisor, Worker} ->
            SupervisorMonitor = erlang:monitor(process, Supervisor),
            WorkerMonitor = erlang:monitor(process, Worker),
            exit(Supervisor, kill),
            ReturnedState = receive
                {Returned, Result, QueueState} -> {Result, QueueState}
            after remaining(ObservationDeadline) ->
                caller_not_returned
            end,
            {
                ReturnedState,
                named_down(Worker, WorkerMonitor, worker_down, worker_not_down,
                    ObservationDeadline),
                named_down(Supervisor, SupervisorMonitor,
                    supervisor_down, supervisor_not_down, ObservationDeadline),
                named_down(Caller, CallerMonitor, caller_down, caller_not_down,
                    ObservationDeadline),
                callback_start_state(Started)
            }
    after remaining(ObservationDeadline) ->
        exit(Caller, kill),
        registration_not_observed
    end,
    ?assertEqual(
        {
            {{error, 1}, queue_empty},
            worker_down,
            supervisor_down,
            caller_down,
            callback_not_started
        },
        Observation
    ).

deadline(Milliseconds) ->
    erlang:monotonic_time(millisecond) + Milliseconds.

remaining(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

mailbox_state() ->
    case process_info(self(), message_queue_len) of
        {message_queue_len, 0} -> queue_empty;
        {message_queue_len, _} -> queue_not_empty
    end.

callback_start_state(Started) ->
    receive
        {Started, callback_started} -> callback_started
    after 0 ->
        callback_not_started
    end.

await_started(Started, Deadline) ->
    receive
        {Started, Worker, Supervisor}
                when is_pid(Worker), is_pid(Supervisor) ->
            {started, Worker, Supervisor};
        {Started, _Worker, no_supervisor} ->
            callback_not_started
    after remaining(Deadline) ->
        callback_not_started
    end.

process_state(Process, Down, Alive) ->
    case erlang:is_process_alive(Process) of
        true -> Alive;
        false -> Down
    end.

named_down(Process, Monitor, Down, TimedOut, Deadline) ->
    receive
        {'DOWN', Monitor, process, Process, _Reason} -> Down
    after remaining(Deadline) ->
        TimedOut
    end.
