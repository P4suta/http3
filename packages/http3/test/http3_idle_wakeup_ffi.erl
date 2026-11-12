%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_idle_wakeup_ffi).

-export([
    begin_observation/1,
    fail/1,
    finish/2,
    monotonic_millisecond/0,
    mark_phase/1,
    quiescence_progress/7,
    take_diagnostics/0,
    observe_enter/1,
    observe_leave/2,
    passed/1,
    self_test/0,
    ownership_regression_test/0,
    start/4,
    write/1,
    take_evidence/0
]).

-define(SYNC_TIMEOUT_MILLISECONDS, 5000).

-spec fail(term()) -> no_return().
fail(Reason) ->
    erlang:error({http3_idle_wakeup_failed, Reason}).

-type trace_handle() ::
    {http3_idle_wakeup_trace, pid(), reference()}.

-spec start(non_neg_integer(), pos_integer(), pos_integer(), pos_integer()) ->
    {ok, trace_handle()} | {error, integer()}.
start(QuiescenceMilliseconds, StableSamples, PollMilliseconds, MaximumAttempts)
        when is_integer(QuiescenceMilliseconds), QuiescenceMilliseconds >= 0,
             is_integer(StableSamples), StableSamples > 0,
             is_integer(PollMilliseconds), PollMilliseconds > 0,
             is_integer(MaximumAttempts), MaximumAttempts >= StableSamples ->
    Owner = self(),
    case actor_snapshot(Owner) of
        {error, _Counts} ->
            {error, 1};
        {ok, PidRoles} ->
            start_collector(Owner, PidRoles, QuiescenceMilliseconds,
                StableSamples, PollMilliseconds, MaximumAttempts)
    end;
start(_QuiescenceMilliseconds, _StableSamples, _PollMilliseconds,
      _MaximumAttempts) ->
    {error, 3}.

-spec monotonic_millisecond() -> integer().
monotonic_millisecond() ->
    erlang:monotonic_time(millisecond).

-spec begin_observation(trace_handle()) -> {ok, nil} | {error, integer()}.
begin_observation({http3_idle_wakeup_trace, Collector, Monitor}) ->
    request(Collector, Monitor, begin_observation).

-spec finish(trace_handle(), non_neg_integer()) ->
    {ok, map()} | {error, integer()}.
finish({http3_idle_wakeup_trace, Collector, Monitor}, MinimumMilliseconds)
        when is_integer(MinimumMilliseconds), MinimumMilliseconds >= 0 ->
    request(Collector, Monitor, {finish, MinimumMilliseconds});
finish(_Handle, _MinimumMilliseconds) ->
    {error, 3}.

-spec passed(map()) -> boolean().
passed(Evidence) when is_map(Evidence) ->
    maps:get(<<"status">>, Evidence, <<"Failed">>) =:= <<"Ready">>;
passed(_Other) ->
    false.

-spec write(map()) -> nil.
write(Evidence) when is_map(Evidence) ->
    put({?MODULE, evidence}, Evidence),
    nil.

take_evidence() -> erase({?MODULE, evidence}).

%% One finite record belongs to the fixture process. It contains no runtime
%% handles or protocol payloads and survives a later setup/cleanup failure.
mark_phase(Phase) when is_integer(Phase), Phase >= 0, Phase =< 14 ->
    Now = monotonic_millisecond(),
    Initial = #{phase => Phase, start => Now, phase_start => Now,
                elapsed => #{}, quiescence => null, topology => null},
    State = case {Phase, get({?MODULE, diagnostic})} of
        {0, _} -> Initial;
        {_, undefined} -> Initial;
        {_, #{phase := Phase} = Current} -> Current;
        {_, Current} -> (complete_phase(Current, Now))#{phase := Phase, phase_start := Now}
    end,
    put({?MODULE, diagnostic}, State), nil.

quiescence_progress(Sample, Stable, ClientFlight, ServerFlight, ClientRecovery, ServerRecovery, Changed)
        when is_integer(Sample), Sample >= 0, Sample =< 80,
             is_integer(Stable), Stable >= 0, Stable =< 5,
             is_integer(ClientFlight), ClientFlight >= 0,
             is_integer(ServerFlight), ServerFlight >= 0,
             is_boolean(ClientRecovery), is_boolean(ServerRecovery), is_boolean(Changed) ->
    update_diagnostic(quiescence, #{sample => Sample, stable_samples => Stable,
        client_bytes_in_flight => bounded_counter(ClientFlight),
        server_bytes_in_flight => bounded_counter(ServerFlight),
        client_in_recovery => ClientRecovery, server_in_recovery => ServerRecovery,
        traffic_changed => Changed}), nil.

take_diagnostics() ->
    case erase({?MODULE, diagnostic}) of
        undefined -> null;
        State ->
            Now = monotonic_millisecond(), Finished = complete_phase(State, Now),
            #{schema => 1, phase => maps:get(phase, State),
              elapsed_milliseconds => bounded_counter(Now - maps:get(start, State)),
              phases => [#{phase => Phase, elapsed_milliseconds => Time} ||
                         {Phase, Time} <- lists:sort(maps:to_list(maps:get(elapsed, Finished)))],
              quiescence => maps:get(quiescence, State), topology => maps:get(topology, State)}
    end.

complete_phase(State, Now) ->
    Phase = maps:get(phase, State), Elapsed = maps:get(elapsed, State),
    Time = maps:get(Phase, Elapsed, 0) + erlang:max(0, Now - maps:get(phase_start, State)),
    State#{elapsed := Elapsed#{Phase => bounded_counter(Time)}}.

bounded_counter(Value) -> erlang:min(2147483647, erlang:max(0, Value)).
update_diagnostic(Key, Value) ->
    case get({?MODULE, diagnostic}) of
        undefined -> ok;
        State -> put({?MODULE, diagnostic}, State#{Key := Value}), ok
    end.
observe_enter(Timeout) -> http3_idle_observer:enter(Timeout).
observe_leave(Timeout, Outcome) -> http3_idle_observer:leave(Timeout, Outcome).

%% Keep the evidence classifier executable without sockets or timing. The
%% live qualification below separately exercises BEAM tracing and actor
%% topology; this pins fail-closed status construction for malformed inputs.
-spec self_test() -> ok.
self_test() ->
    nil = mark_phase(0), nil = mark_phase(8),
    nil = quiescence_progress(1, 0, 99, 0, true, false, true),
    nil = mark_phase(14),
    #{phase := 14, phases := [#{phase := 0}, #{phase := 8}, #{phase := 14}],
      quiescence := #{sample := 1, client_bytes_in_flight := 99}, topology := null} = take_diagnostics(),
    null = take_diagnostics(),
    RoleRows = [
        role_row(Label, Count, Count, empty_stat())
     || {Label, Count} <- expected_roles()
    ],
    Ready = evidence(
        2500, 2500, true, 0, 0, RoleRows, true
    ),
    true = passed(Ready),
    FailedTimeout = evidence(
        2500, 2500, true, 1, 0, RoleRows, true
    ),
    false = passed(FailedTimeout),
    FailedDuration = evidence(
        2499, 2500, true, 0, 0, RoleRows, true
    ),
    false = passed(FailedDuration),
    FailedLiveness = evidence(
        2500, 2500, true, 0, 0, RoleRows, false
    ),
    false = passed(FailedLiveness),
    PreObservation = (empty_stat())#{
        timed_calls := 7,
        forever_calls := 5,
        current_wait_class := wait_second_calls,
        current_forever_wait := true
    },
    Reset = reset_stat(PreObservation),
    0 = maps:get(timed_calls, Reset),
    0 = maps:get(forever_calls, Reset),
    wait_second_calls = maps:get(current_wait_class, Reset),
    true = maps:get(current_forever_wait, Reset),
    BoundaryState = #{stats => #{self() => empty_stat()}},
    TimedBoundary = record_timed_return(self(), false, BoundaryState),
    TimedBoundaryStat = maps:get(self(), maps:get(stats, TimedBoundary)),
    1 = maps:get(timed_boundary_message_returns, TimedBoundaryStat),
    UnboundedBoundary = record_unbounded_return(self(), BoundaryState),
    UnboundedBoundaryStat = maps:get(
        self(), maps:get(stats, UnboundedBoundary)
    ),
    1 = maps:get(forever_boundary_message_returns, UnboundedBoundaryStat),
    MissingLeave = record_timed_call(self(), 10,
        record_timed_call(self(), 10, BoundaryState)),
    true = maps:get(sync_failed, MissingLeave),
    MissingCrossKind = record_unbounded_call(self(),
        record_timed_call(self(), 10, BoundaryState)),
    true = maps:get(sync_failed, MissingCrossKind),
    false = maps:get(sync_failed,
        handle_trace({idle_scalar, self(), message, zero},
            BoundaryState#{events_received => 0, pid_roles => #{self() => test},
                           sync_failed => false})),
    true = maps:get(sync_failed, handle_trace({private, <<"idle-private-marker">>},
        BoundaryState#{sync_failed => false})),
    ok = http3_idle_observer:self_test(),
    ok = lifecycle_controls(),
    nil = ownership_regression_test(),
    ok.

%% A winning connection outlives the setup actor that spawned it. Its existing
%% owner monitor remains authoritative; a sibling owner's connection must not
%% be included when observing only this owner's subtree.
ownership_regression_test() ->
    Parent = self(),
    {OtherOwner, OtherMonitor} = spawn_monitor(fun() ->
        proc_lib:set_label(<<"http3.client">>), receive stop -> ok end
    end),
    {Owner, OwnerMonitor} = spawn_monitor(fun() ->
        proc_lib:set_label(<<"http3.client">>),
        Parent ! idle_owner_ready, receive stop -> ok end
    end),
    receive idle_owner_ready -> ok after 1000 -> error(idle_owner_missing) end,
    {Starter, StarterMonitor} = spawn_monitor(fun() ->
        Winner = spawn(fun() ->
            proc_lib:set_label(<<"quic_core.client">>),
            _ = monitor(process, Owner),
            Parent ! idle_winner_ready, receive stop -> ok end
        end),
        Parent ! {idle_winner, Winner}
    end),
    Winner = receive {idle_winner, Pid} -> Pid after 1000 -> error(idle_winner_missing) end,
    WinnerMonitor = monitor(process, Winner),
    try
        receive idle_winner_ready -> ok after 1000 -> error(idle_winner_not_ready) end,
        receive {'DOWN', StarterMonitor, process, Starter, normal} -> ok
            after 1000 -> error(idle_starter_not_joined) end,
        false = is_process_alive(Starter),
        false = descendant_of(Winner, Owner, 64),
        <<"quic_core.client">> = maps:get(Winner, current_expected_actors(Owner)),
        false = maps:is_key(Winner, current_expected_actors(OtherOwner)),
        nil
    after
        exit(Winner, kill), exit(Owner, kill), exit(OtherOwner, kill),
        receive {'DOWN', WinnerMonitor, process, Winner, _} -> ok after 1000 -> error(idle_winner_cleanup) end,
        receive {'DOWN', OwnerMonitor, process, Owner, _} -> ok after 1000 -> error(idle_owner_cleanup) end,
        receive {'DOWN', OtherMonitor, process, OtherOwner, _} -> ok after 1000 -> error(idle_other_owner_cleanup) end
    end.

lifecycle_controls() ->
    Roles = #{self() => <<"http3.client">>},
    {ok, Trace = {http3_idle_wakeup_trace, Collector, _}} =
        start_collector(self(), Roles, 0, 5, 100, 80),
    {ok, nil} = begin_observation(Trace),
    ok = observe_enter(1000), ok = observe_leave(1000, message),
    {ok, Evidence} = finish(Trace, 0),
    false = is_process_alive(Collector),
    #{events_sent := 2, events_received := 2, events_dropped := 0,
      invalid_events := 0} = maps:get(<<"observer">>, Evidence),
    %% A sent event removed before delivery is an incomplete observation, even
    %% if every actor remains alive and the timeout count happens to be zero.
    Handle = http3_idle_observer:open(Roles, self()),
    try
        ok = observe_enter(1000), receive {idle_scalar, _, _, _} -> ok end,
        {false, _} = await_delivery(1,
            #{events_received => 0}, erlang:monotonic_time(millisecond), true)
    after true = http3_idle_observer:close(Handle) end,
    Parent = self(),
    {Owner, OwnerMonitor} = spawn_monitor(fun() ->
        {ok, {http3_idle_wakeup_trace, Child, _}} =
            start_collector(self(), #{self() => <<"http3.client">>}, 0, 5, 100, 80),
        Parent ! {owned_collector, Child}, receive never -> ok end
    end),
    Child = receive {owned_collector, Pid} -> Pid
        after 3000 -> erlang:error(missing_collector) end,
    ChildMonitor = erlang:monitor(process, Child),
    exit(Owner, kill),
    receive {'DOWN', OwnerMonitor, process, Owner, killed} -> ok end,
    receive {'DOWN', ChildMonitor, process, Child, normal} -> ok
        after 3000 -> erlang:error(owner_death_leaked_collector) end,
    Probe = http3_idle_observer:open(Roles, self()),
    true = http3_idle_observer:close(Probe),
    ok.

start_collector(Owner, PidRoles, QuiescenceMilliseconds, StableSamples,
                PollMilliseconds, MaximumAttempts) ->
    {Collector, Monitor} = spawn_opt(fun() ->
        OwnerMonitor = erlang:monitor(process, Owner),
        receive {configuration, Handle} ->
            collector_loop(#{
                owner => Owner, owner_monitor => OwnerMonitor,
                observer => Handle, events_received => 0,
                pid_roles => PidRoles, start_pid_roles => PidRoles,
                stats => empty_stats(PidRoles), started_milliseconds => undefined,
                unexpected_exits => 0,
                quiescence_maximum_attempts => MaximumAttempts,
                quiescence_milliseconds => QuiescenceMilliseconds,
                quiescence_poll_milliseconds => PollMilliseconds,
                quiescence_stable_samples => StableSamples, sync_failed => false})
        after ?SYNC_TIMEOUT_MILLISECONDS -> exit(normal)
        end
    end, [monitor, {max_heap_size, #{size => 2097152, kill => true,
                                   error_logger => false,
                                   include_shared_binaries => true}}]),
    try http3_idle_observer:open(PidRoles, Collector) of
        Handle ->
            Collector ! {configuration, Handle},
            {ok, {http3_idle_wakeup_trace, Collector, Monitor}}
    catch _:_ ->
        kill_and_join(Collector, Monitor), {error, 2}
    end.

request(Collector, Monitor, Operation) ->
    Reference = make_ref(),
    Collector ! {request, self(), Reference, Operation},
    receive
        {Reference, Reply} ->
            case Operation of
                {finish, _} ->
                    receive {'DOWN', Monitor, process, Collector, normal} -> Reply;
                            {'DOWN', Monitor, process, Collector, _} -> {error, 4}
                    after ?SYNC_TIMEOUT_MILLISECONDS ->
                        kill_and_join(Collector, Monitor), {error, 5}
                    end;
                _ -> Reply
            end;
        {'DOWN', Monitor, process, Collector, _Reason} ->
            _ = http3_idle_observer:cleanup(Collector), {error, 4}
    after ?SYNC_TIMEOUT_MILLISECONDS * 2 ->
        kill_and_join(Collector, Monitor), {error, 5}
    end.

kill_and_join(Collector, Monitor) ->
    exit(Collector, kill),
    receive {'DOWN', Monitor, process, Collector, _} ->
        _ = http3_idle_observer:cleanup(Collector), ok
    after ?SYNC_TIMEOUT_MILLISECONDS -> erlang:error(observer_not_reaped)
    end.

collector_loop(State) ->
    OwnerMonitor = maps:get(owner_monitor, State),
    Owner = maps:get(owner, State),
    Handle = maps:get(observer, State),
    receive
        {request, Owner, Reference, begin_observation} ->
            {Synced, State1} = synchronize(State),
            Started = erlang:monotonic_time(millisecond),
            State2 = State1#{stats => reset_stats(maps:get(stats, State1)),
                started_milliseconds => Started, unexpected_exits => 0,
                sync_failed => maps:get(sync_failed, State1) orelse not Synced},
            ok = http3_idle_observer:resume(Handle),
            Owner ! {Reference, case Synced of
                true -> {ok, nil}; false -> {error, 6}
            end},
            collector_loop(State2);
        {request, Owner, Reference, {finish, MinimumMilliseconds}} ->
            Ended = erlang:monotonic_time(millisecond),
            Closed = http3_idle_observer:close(Handle),
            {Synced, State1} = synchronize(State),
            Evidence = build_evidence(State1#{sync_failed =>
                maps:get(sync_failed, State1) orelse not Synced orelse not Closed},
                Ended, MinimumMilliseconds),
            Owner ! {Reference, {ok, Evidence}},
            exit(normal);
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            _ = http3_idle_observer:close(Handle), exit(normal);
        Message -> collector_loop(handle_trace(Message, State))
    end.

handle_trace({idle_scalar, Pid, Operation, Class}, State)
        when is_map_key(Pid, map_get(pid_roles, State)),
             (Operation =:= enter orelse Operation =:= message orelse Operation =:= timeout),
             (Class =:= zero orelse Class =:= short orelse Class =:= second
              orelse Class =:= long orelse Class =:= unbounded) ->
    Counted = State#{events_received := maps:get(events_received, State) + 1},
    case {Operation, Class} of
        {enter, unbounded} -> record_unbounded_call(Pid, Counted);
        {enter, _} -> record_timed_call(Pid, class_timeout(Class), Counted);
        {message, unbounded} -> record_unbounded_return(Pid, Counted);
        {timeout, unbounded} -> Counted#{sync_failed := true};
        {message, _} -> record_timed_return(Pid, false, Counted);
        {timeout, _} -> record_timed_return(Pid, true, Counted)
    end;
handle_trace(_Message, State) -> State#{sync_failed := true}.

class_timeout(zero) -> 0;
class_timeout(short) -> 100;
class_timeout(second) -> 1000;
class_timeout(long) -> 2000.
record_timed_call(Pid, Within, State) ->
    Stats = maps:get(stats, State),
    case maps:find(Pid, Stats) of
        error -> State;
        {ok, Stat} ->
            Missing = maps:get(current_wait_class, Stat) =/= no_wait
                orelse maps:get(current_forever_wait, Stat),
            Class = wait_class(Within),
            Next = Stat#{
                timed_calls := maps:get(timed_calls, Stat) + 1,
                Class := maps:get(Class, Stat) + 1,
                current_wait_class := Class
            },
            State#{stats := Stats#{Pid := Next},
                sync_failed => maps:get(sync_failed, State, false) orelse Missing}
    end.

record_timed_return(Pid, TimedOut, State) ->
    Stats = maps:get(stats, State),
    case maps:find(Pid, Stats) of
        error -> State;
        {ok, Stat} ->
            Class = maps:get(current_wait_class, Stat),
            BoundaryStat = case Class of
                no_wait -> Stat#{
                    timed_boundary_message_returns :=
                        maps:get(timed_boundary_message_returns, Stat) + 1
                };
                _ -> Stat
            end,
            Next0 = case TimedOut of
                true ->
                    TimeoutClass = timeout_class(Class),
                    BoundaryStat#{
                        deadline_timeouts :=
                            maps:get(deadline_timeouts, BoundaryStat) + 1,
                        TimeoutClass := maps:get(TimeoutClass, BoundaryStat) + 1
                    };
                false -> BoundaryStat#{
                    timed_message_returns :=
                        maps:get(timed_message_returns, BoundaryStat) + 1
                }
            end,
            Next = Next0#{current_wait_class := no_wait},
            State#{stats := Stats#{Pid := Next}}
    end.

record_unbounded_call(Pid, State) ->
    Stats = maps:get(stats, State),
    case maps:find(Pid, Stats) of
        error -> State;
        {ok, Stat} ->
            Missing = maps:get(current_wait_class, Stat) =/= no_wait
                orelse maps:get(current_forever_wait, Stat),
            Next = Stat#{
                forever_calls := maps:get(forever_calls, Stat) + 1,
                current_forever_wait := true
            },
            State#{stats := Stats#{Pid := Next},
                sync_failed => maps:get(sync_failed, State, false) orelse Missing}
    end.

record_unbounded_return(Pid, State) ->
    Stats = maps:get(stats, State),
    case maps:find(Pid, Stats) of
        error -> State;
        {ok, Stat} ->
            BoundaryStat = case maps:get(current_forever_wait, Stat) of
                false -> Stat#{
                    forever_boundary_message_returns :=
                        maps:get(forever_boundary_message_returns, Stat) + 1
                };
                true -> Stat
            end,
            Next = BoundaryStat#{
                forever_message_returns :=
                    maps:get(forever_message_returns, BoundaryStat) + 1,
                current_forever_wait := false
            },
            State#{stats := Stats#{Pid := Next}}
    end.

wait_class(Within) when Within =< 0 -> wait_zero_calls;
wait_class(Within) when Within =< 100 -> wait_short_calls;
wait_class(Within) when Within =< 1500 -> wait_second_calls;
wait_class(_Within) -> wait_long_calls.

timeout_class(wait_zero_calls) -> timeout_zero_returns;
timeout_class(wait_short_calls) -> timeout_short_returns;
timeout_class(wait_second_calls) -> timeout_second_returns;
timeout_class(wait_long_calls) -> timeout_long_returns;
timeout_class(no_wait) -> timeout_unclassified_returns.

synchronize(State) ->
    Handle = maps:get(observer, State),
    Paused = http3_idle_observer:pause(Handle),
    Snapshot = http3_idle_observer:snapshot(Handle),
    Valid = Paused andalso maps:get(events_dropped, Snapshot) =:= 0
        andalso maps:get(invalid_events, Snapshot) =:= 0,
    Deadline = erlang:monotonic_time(millisecond) + ?SYNC_TIMEOUT_MILLISECONDS,
    await_delivery(maps:get(events_sent, Snapshot), State, Deadline, Valid).

await_delivery(Target, State, _Deadline, Valid)
        when map_get(events_received, State) =:= Target -> {Valid, State};
await_delivery(Target, State, Deadline, Valid) ->
    Remaining = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {idle_scalar, _, _, _} = Message ->
            await_delivery(Target, handle_trace(Message, State), Deadline, Valid)
    after Remaining -> {false, State}
    end.
build_evidence(State, Ended, MinimumMilliseconds) ->
    Owner = maps:get(owner, State),
    Started = maps:get(started_milliseconds, State, Ended),
    Elapsed = max(0, Ended - value_or(Started, Ended)),
    StartPidRoles = maps:get(start_pid_roles, State),
    EndSnapshot = actor_snapshot(Owner),
    {EndPidRoles, EndExact} = case EndSnapshot of
        {ok, Values} -> {Values, true};
        {error, _Counts} -> {current_expected_actors(Owner), false}
    end,
    Stable = EndExact andalso same_actor_set(StartPidRoles, EndPidRoles),
    Stats = maps:get(stats, State),
    TimeoutReturns = sum_stat(Stats, deadline_timeouts),
    UnexpectedExits = maps:get(unexpected_exits, State),
    RoleRows = [
        role_row(
            Label,
            count_label(StartPidRoles, Label),
            count_label(EndPidRoles, Label),
            aggregate_label(StartPidRoles, Stats, Label)
        )
     || {Label, _Expected} <- expected_roles()
    ],
    Liveness = required_liveness(RoleRows),
    Evidence0 = evidence(
        Elapsed,
        MinimumMilliseconds,
        Stable,
        TimeoutReturns,
        UnexpectedExits,
        RoleRows,
        Liveness
    ),
    Evidence0#{
        <<"observer">> => (http3_idle_observer:snapshot(maps:get(observer, State)))#{
            events_received => maps:get(events_received, State)},
        <<"quiescence_confirmed">> => true,
        <<"quiescence_maximum_attempts">> =>
            maps:get(quiescence_maximum_attempts, State),
        <<"quiescence_milliseconds">> =>
            maps:get(quiescence_milliseconds, State),
        <<"quiescence_poll_milliseconds">> =>
            maps:get(quiescence_poll_milliseconds, State),
        <<"quiescence_required_stable_samples">> =>
            maps:get(quiescence_stable_samples, State),
        <<"trace_synchronized">> => not maps:get(sync_failed, State),
        <<"status">> => status(
            passed(Evidence0) andalso not maps:get(sync_failed, State)
        )
    }.

evidence(
  Elapsed,
  MinimumMilliseconds,
  Stable,
  TimeoutReturns,
  UnexpectedExits,
  RoleRows,
  Liveness
) ->
    Ready = Elapsed >= MinimumMilliseconds
        andalso Stable
        andalso TimeoutReturns =:= 0
        andalso UnexpectedExits =:= 0
        andalso Liveness,
    #{
        <<"schema">> => 2,
        <<"status">> => status(Ready),
        <<"shareable">> => true,
        <<"redacted">> => true,
        <<"observation_milliseconds">> => Elapsed,
        <<"minimum_observation_milliseconds">> => MinimumMilliseconds,
        <<"actor_set_stable">> => Stable,
        <<"expected_actor_count">> => expected_actor_count(),
        <<"deadline_timeout_returns">> => TimeoutReturns,
        <<"unexpected_actor_exits">> => UnexpectedExits,
        <<"required_actor_liveness">> => Liveness,
        <<"trace_synchronized">> => true,
        <<"trace_primitive">> => <<"gleam_erlang_ffi:select/1,2">>,
        <<"roles">> => RoleRows
    }.

status(true) -> <<"Ready">>;
status(false) -> <<"Failed">>.

role_row(Label, StartCount, EndCount, Stat) ->
    #{
        <<"label">> => Label,
        <<"expected_actors">> => expected_for(Label),
        <<"actors_start">> => StartCount,
        <<"actors_end">> => EndCount,
        <<"timed_wait_calls">> => maps:get(timed_calls, Stat),
        <<"timed_message_returns">> => maps:get(timed_message_returns, Stat),
        <<"timed_boundary_message_returns">> =>
            maps:get(timed_boundary_message_returns, Stat),
        <<"deadline_timeout_returns">> => maps:get(deadline_timeouts, Stat),
        <<"wait_zero_calls">> => maps:get(wait_zero_calls, Stat),
        <<"wait_short_calls">> => maps:get(wait_short_calls, Stat),
        <<"wait_second_calls">> => maps:get(wait_second_calls, Stat),
        <<"wait_long_calls">> => maps:get(wait_long_calls, Stat),
        <<"timeout_zero_returns">> => maps:get(timeout_zero_returns, Stat),
        <<"timeout_short_returns">> => maps:get(timeout_short_returns, Stat),
        <<"timeout_second_returns">> => maps:get(timeout_second_returns, Stat),
        <<"timeout_long_returns">> => maps:get(timeout_long_returns, Stat),
        <<"timeout_unclassified_returns">> =>
            maps:get(timeout_unclassified_returns, Stat),
        <<"unbounded_wait_calls">> => maps:get(forever_calls, Stat),
        <<"unbounded_message_returns">> =>
            maps:get(forever_message_returns, Stat),
        <<"unbounded_boundary_message_returns">> =>
            maps:get(forever_boundary_message_returns, Stat)
    }.

required_liveness(RoleRows) ->
    lists:all(fun(Label) ->
        case lists:search(
          fun(Row) -> maps:get(<<"label">>, Row) =:= Label end,
          RoleRows
        ) of
            {value, Row} ->
                maps:get(<<"timed_message_returns">>, Row)
                    + maps:get(<<"unbounded_message_returns">>, Row) > 0;
            false -> false
        end
    end, [
        <<"http3.client">>,
        <<"http3.connection">>,
        <<"quic_core.client">>,
        <<"quic_core.connection">>
    ]).

aggregate_label(PidRoles, Stats, Label) ->
    maps:fold(fun(Pid, PidLabel, Accumulator) ->
        case PidLabel =:= Label of
            true -> add_stats(Accumulator, maps:get(Pid, Stats, empty_stat()));
            false -> Accumulator
        end
    end, empty_stat(), PidRoles).

add_stats(Left, Right) ->
    lists:foldl(fun(Key, Accumulator) ->
        Accumulator#{Key := maps:get(Key, Left) + maps:get(Key, Right)}
    end, Left#{current_wait_class := no_wait,
               current_forever_wait := false}, numeric_stat_keys()).

sum_stat(Stats, Key) ->
    maps:fold(fun(_Pid, Stat, Total) ->
        Total + maps:get(Key, Stat)
    end, 0, Stats).

empty_stats(PidRoles) ->
    maps:map(fun(_Pid, _Label) -> empty_stat() end, PidRoles).

reset_stats(Stats) ->
    maps:map(fun(_Pid, Stat) -> reset_stat(Stat) end, Stats).

reset_stat(Stat) ->
    (empty_stat())#{
        current_wait_class := maps:get(current_wait_class, Stat),
        current_forever_wait := maps:get(current_forever_wait, Stat)
    }.

empty_stat() ->
    #{
        timed_calls => 0,
        timed_message_returns => 0,
        timed_boundary_message_returns => 0,
        deadline_timeouts => 0,
        wait_zero_calls => 0,
        wait_short_calls => 0,
        wait_second_calls => 0,
        wait_long_calls => 0,
        timeout_zero_returns => 0,
        timeout_short_returns => 0,
        timeout_second_returns => 0,
        timeout_long_returns => 0,
        timeout_unclassified_returns => 0,
        forever_calls => 0,
        forever_message_returns => 0,
        forever_boundary_message_returns => 0,
        current_wait_class => no_wait,
        current_forever_wait => false
    }.

numeric_stat_keys() ->
    [
        timed_calls,
        timed_message_returns,
        timed_boundary_message_returns,
        deadline_timeouts,
        wait_zero_calls,
        wait_short_calls,
        wait_second_calls,
        wait_long_calls,
        timeout_zero_returns,
        timeout_short_returns,
        timeout_second_returns,
        timeout_long_returns,
        timeout_unclassified_returns,
        forever_calls,
        forever_message_returns,
        forever_boundary_message_returns
    ].

actor_snapshot(Root) ->
    PidRoles = current_expected_actors(Root),
    Counts = role_counts(PidRoles),
    update_diagnostic(topology, [#{label => Label, observed => bounded_counter(maps:get(Label, Counts, 0))}
        || {Label, _} <- expected_roles()]),
    case lists:all(fun({Label, Expected}) ->
        maps:get(Label, Counts, 0) =:= Expected
    end, expected_roles()) of
        true -> {ok, PidRoles};
        false -> {error, Counts}
    end.

current_expected_actors(Root) ->
    Expected = maps:from_list(expected_roles()),
    maps:from_list(lists:filtermap(fun(Pid) ->
        Label = safe_label(Pid),
        case maps:is_key(Label, Expected) andalso
                (descendant_of(Pid, Root, 64) orelse monitored_client_of(Pid, Label, Root)) of
            true -> {true, {Pid, Label}};
            false -> false
        end
    end, erlang:processes())).

%% The connection race retires its setup supervisor after publishing a winner.
%% That actor's historical parent can no longer establish its subtree. Follow
%% only the existing QUIC client's lifetime monitor to its live HTTP/3 owner;
%% unrelated labelled actors are never admitted by a global label match.
monitored_client_of(Pid, <<"quic_core.client">>, Root) ->
    case erlang:process_info(Pid, monitors) of
        {monitors, Monitors} ->
            Owners = lists:usort([Owner || {process, Owner} <- Monitors,
                is_pid(Owner), safe_label(Owner) =:= <<"http3.client">>,
                descendant_of(Owner, Root, 64)]),
            length(Owners) =:= 1;
        _ -> false
    end;
monitored_client_of(_, _, _) -> false.

descendant_of(Pid, Root, _Remaining) when Pid =:= Root ->
    true;
descendant_of(_Pid, _Root, 0) ->
    false;
descendant_of(Pid, Root, Remaining) ->
    case process_parent(Pid) of
        undefined -> false;
        Parent -> descendant_of(Parent, Root, Remaining - 1)
    end.

process_parent(Pid) ->
    try erlang:process_info(Pid, parent) of
        {parent, Parent} when is_pid(Parent) -> Parent;
        _ -> undefined
    catch
        _Class:_Reason -> undefined
    end.

safe_label(Pid) ->
    try proc_lib:get_label(Pid) of
        Label when is_binary(Label) -> Label;
        _ -> <<>>
    catch
        _Class:_Reason -> <<>>
    end.

role_counts(PidRoles) ->
    maps:fold(fun(_Pid, Label, Counts) ->
        Counts#{Label => maps:get(Label, Counts, 0) + 1}
    end, #{}, PidRoles).

count_label(PidRoles, Label) ->
    maps:fold(fun(_Pid, PidLabel, Count) ->
        case PidLabel =:= Label of
            true -> Count + 1;
            false -> Count
        end
    end, 0, PidRoles).

same_actor_set(Left, Right) ->
    lists:sort(maps:to_list(Left)) =:= lists:sort(maps:to_list(Right)).

expected_for(Label) ->
    proplists:get_value(Label, expected_roles(), 0).

expected_actor_count() ->
    lists:sum([Count || {_Label, Count} <- expected_roles()]).

expected_roles() ->
    [
        {<<"http3.client">>, 1},
        {<<"http3.listener">>, 1},
        {<<"http3.acceptor">>, 1},
        {<<"http3.connection">>, 1},
        {<<"quic_core.client">>, 1},
        {<<"quic_core.listener">>, 1},
        {<<"quic_core.connection">>, 1},
        {<<"quic_core.udp_relay">>, 1}
    ].

value_or(undefined, Default) -> Default;
value_or(Value, _Default) -> Value.
