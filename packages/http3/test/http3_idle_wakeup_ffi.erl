-module(http3_idle_wakeup_ffi).

-export([
    begin_observation/1,
    fail/1,
    finish/2,
    monotonic_millisecond/0,
    passed/1,
    self_test/0,
    start/4,
    write/1
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
            case install_trace_patterns() of
                ok -> start_collector(
                    Owner, PidRoles, QuiescenceMilliseconds,
                    StableSamples, PollMilliseconds, MaximumAttempts
                );
                error -> {error, 2}
            end
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
    io:put_chars([json:encode(Evidence), $\n]),
    nil.

%% Keep the evidence classifier executable without sockets or timing. The
%% live qualification below separately exercises BEAM tracing and actor
%% topology; this pins fail-closed status construction for malformed inputs.
-spec self_test() -> ok.
self_test() ->
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
    ok.

start_collector(Owner, PidRoles, QuiescenceMilliseconds, StableSamples,
                PollMilliseconds, MaximumAttempts) ->
    Collector = spawn(fun() ->
        OwnerMonitor = erlang:monitor(process, Owner),
        collector_loop(#{
            owner => Owner,
            owner_monitor => OwnerMonitor,
            pid_roles => PidRoles,
            start_pid_roles => PidRoles,
            stats => empty_stats(PidRoles),
            started_milliseconds => undefined,
            unexpected_exits => 0,
            quiescence_maximum_attempts => MaximumAttempts,
            quiescence_milliseconds => QuiescenceMilliseconds,
            quiescence_poll_milliseconds => PollMilliseconds,
            quiescence_stable_samples => StableSamples,
            sync_failed => false
        })
    end),
    Monitor = erlang:monitor(process, Collector),
    case enable_tracing(maps:keys(PidRoles), Collector, []) of
        {ok, Traced} ->
            Collector ! {traced, Traced},
            {ok, {http3_idle_wakeup_trace, Collector, Monitor}};
        {error, Traced} ->
            disable_tracing(Traced),
            uninstall_trace_patterns(),
            exit(Collector, kill),
            receive
                {'DOWN', Monitor, process, Collector, _Reason} -> ok
            after ?SYNC_TIMEOUT_MILLISECONDS -> ok
            end,
            {error, 2}
    end.

request(Collector, Monitor, Operation) ->
    Reference = make_ref(),
    Collector ! {request, self(), Reference, Operation},
    receive
        {Reference, Reply} -> Reply;
        {'DOWN', Monitor, process, Collector, _Reason} -> {error, 4}
    after ?SYNC_TIMEOUT_MILLISECONDS * 2 ->
        {error, 5}
    end.

collector_loop(State) ->
    OwnerMonitor = maps:get(owner_monitor, State),
    receive
        {traced, Traced} ->
            collector_loop(State#{traced => Traced});
        {request, Caller, Reference, begin_observation} ->
            {Synced, State1} = synchronize(State),
            Started = erlang:monotonic_time(millisecond),
            State2 = State1#{
                %% Preserve an observed select that crossed the observation
                %% boundary while zeroing every measurement counter. A trace
                %% may also attach after an actor entered select; unmatched
                %% returns from that case are classified explicitly below.
                stats => reset_stats(maps:get(stats, State1)),
                started_milliseconds => Started,
                unexpected_exits => 0,
                sync_failed => not Synced
            },
            Caller ! {Reference, case Synced of
                true -> {ok, nil};
                false -> {error, 6}
            end},
            collector_loop(State2);
        {request, Caller, Reference, {finish, MinimumMilliseconds}} ->
            Ended = erlang:monotonic_time(millisecond),
            Traced = maps:get(traced, State, []),
            disable_tracing(Traced),
            {Synced, State1} = synchronize(State),
            uninstall_trace_patterns(),
            Evidence = build_evidence(
                State1#{sync_failed =>
                    maps:get(sync_failed, State1) orelse not Synced},
                Ended,
                MinimumMilliseconds
            ),
            Caller ! {Reference, {ok, Evidence}},
            exit(normal);
        {'DOWN', OwnerMonitor, process, _Owner, _Reason} ->
            disable_tracing(maps:get(traced, State, [])),
            uninstall_trace_patterns(),
            exit(normal);
        Message ->
            collector_loop(handle_trace(Message, State))
    end.

handle_trace(
  {trace, Pid, call, {gleam_erlang_ffi, select, [_Selector, Within]}}, State
) when is_integer(Within) ->
    record_timed_call(Pid, Within, State);
handle_trace(
  {trace, Pid, return_from, {gleam_erlang_ffi, select, 2}, {error, nil}},
  State
) ->
    record_timed_return(Pid, true, State);
handle_trace(
  {trace, Pid, return_from, {gleam_erlang_ffi, select, 2}, _Result}, State
) ->
    record_timed_return(Pid, false, State);
handle_trace(
  {trace, Pid, call, {gleam_erlang_ffi, select, Arguments}}, State
) when is_list(Arguments), length(Arguments) =:= 1 ->
    record_unbounded_call(Pid, State);
handle_trace(
  {trace, Pid, return_from, {gleam_erlang_ffi, select, 1}, _Result}, State
) ->
    record_unbounded_return(Pid, State);
handle_trace({trace, Pid, exit, _Reason}, State) ->
    case maps:is_key(Pid, maps:get(pid_roles, State)) of
        true -> State#{unexpected_exits := maps:get(unexpected_exits, State) + 1};
        false -> State
    end;
handle_trace(_Message, State) ->
    State.

record_timed_call(Pid, Within, State) ->
    Stats = maps:get(stats, State),
    case maps:find(Pid, Stats) of
        error -> State;
        {ok, Stat} ->
            Class = wait_class(Within),
            Next = Stat#{
                timed_calls := maps:get(timed_calls, Stat) + 1,
                Class := maps:get(Class, Stat) + 1,
                current_wait_class := Class
            },
            State#{stats := Stats#{Pid := Next}}
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
            Next = Stat#{
                forever_calls := maps:get(forever_calls, Stat) + 1,
                current_forever_wait := true
            },
            State#{stats := Stats#{Pid := Next}}
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
    Pids = maps:keys(maps:get(pid_roles, State)),
    {References, RequestedAll} = delivery_references(Pids, [], true),
    Deadline = erlang:monotonic_time(millisecond)
        + ?SYNC_TIMEOUT_MILLISECONDS,
    await_delivery(References, State, Deadline, RequestedAll).

delivery_references([], References, RequestedAll) ->
    {References, RequestedAll};
delivery_references([Pid | Rest], References, RequestedAll) ->
    try erlang:trace_delivered(Pid) of
        Reference ->
            delivery_references(
                Rest, [{Pid, Reference} | References], RequestedAll
            )
    catch
        _Class:_Reason ->
            delivery_references(Rest, References, false)
    end.

await_delivery([], State, _Deadline, RequestedAll) ->
    {RequestedAll, State};
await_delivery(References, State, Deadline, RequestedAll) ->
    Remaining = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {trace_delivered, Pid, Reference} ->
            await_delivery(
                lists:delete({Pid, Reference}, References),
                State,
                Deadline,
                RequestedAll
            );
        Message ->
            await_delivery(
                References,
                handle_trace(Message, State),
                Deadline,
                RequestedAll
            )
    after Remaining ->
        {false, State}
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

install_trace_patterns() ->
    case code:ensure_loaded(gleam_erlang_ffi) of
        {module, gleam_erlang_ffi} ->
            MatchSpecification = [{'_', [], [{return_trace}]}],
            try
                _ = erlang:trace_pattern(
                    {gleam_erlang_ffi, select, 1},
                    MatchSpecification,
                    [local]
                ),
                _ = erlang:trace_pattern(
                    {gleam_erlang_ffi, select, 2},
                    MatchSpecification,
                    [local]
                ),
                ok
            catch
                _Class:_Reason ->
                    uninstall_trace_patterns(),
                    error
            end;
        _ -> error
    end.

uninstall_trace_patterns() ->
    _ = erlang:trace_pattern(
        {gleam_erlang_ffi, select, 1}, false, [local]
    ),
    _ = erlang:trace_pattern(
        {gleam_erlang_ffi, select, 2}, false, [local]
    ),
    ok.

enable_tracing([], _Collector, Traced) ->
    {ok, Traced};
enable_tracing([Pid | Rest], Collector, Traced) ->
    try erlang:trace(Pid, true, [call, procs, {tracer, Collector}]) of
        1 -> enable_tracing(Rest, Collector, [Pid | Traced]);
        _ -> {error, Traced}
    catch
        _Class:_Reason -> {error, Traced}
    end.

disable_tracing(Pids) ->
    lists:foreach(fun(Pid) ->
        try erlang:trace(Pid, false, [call, procs]) of
            _ -> ok
        catch
            _Class:_Reason -> ok
        end
    end, Pids).

actor_snapshot(Root) ->
    PidRoles = current_expected_actors(Root),
    Counts = role_counts(PidRoles),
    case lists:all(fun({Label, Expected}) ->
        maps:get(Label, Counts, 0) =:= Expected
    end, expected_roles()) of
        true -> {ok, PidRoles};
        false -> {error, Counts}
    end.

current_expected_actors(Root) ->
    Expected = maps:from_list(expected_roles()),
    maps:from_list(lists:filtermap(fun(Pid) ->
        case descendant_of(Pid, Root, 64) of
            false -> false;
            true ->
                Label = safe_label(Pid),
                case maps:is_key(Label, Expected) of
                    true -> {true, {Pid, Label}};
                    false -> false
                end
        end
    end, erlang:processes())).

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
