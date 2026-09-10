-module(http3_benchmark_barrier_ffi).

-export([
    arrive_connection_barrier/2,
    await_completion_latch/2,
    await_connection_barrier/1,
    fail_completion_latch/1,
    fail_connection_barrier/1,
    release_completion_latch/1,
    start_completion_latch/2,
    start_connection_barrier/2,
    stop_completion_latch/1,
    stop_connection_barrier/1
]).

-define(REPLY_GRACE_MILLISECONDS, 1000).
-define(STOP_TIMEOUT_MILLISECONDS, 5000).

-spec start_connection_barrier(pos_integer(), integer()) -> tuple().
start_connection_barrier(ExpectedWorkers, DeadlineMicroseconds)
        when is_integer(ExpectedWorkers), ExpectedWorkers > 0,
             is_integer(DeadlineMicroseconds) ->
    Owner = self(),
    {Process, Monitor} = spawn_monitor(fun() ->
        connection_barrier_start(Owner, ExpectedWorkers, DeadlineMicroseconds)
    end),
    {http3_benchmark_connection_barrier, Process, Monitor, DeadlineMicroseconds}.

-spec arrive_connection_barrier(tuple(), integer()) -> boolean().
arrive_connection_barrier(
  {http3_benchmark_connection_barrier, Process, _OwnerMonitor,
   DeadlineMicroseconds},
  Worker) when is_integer(Worker) ->
    Reference = make_ref(),
    Monitor = erlang:monitor(process, Process),
    Process ! {connection_barrier_arrive, self(), Reference, Worker},
    await_worker_reply(Process, Monitor, Reference, DeadlineMicroseconds).

-spec await_connection_barrier(tuple()) -> boolean().
await_connection_barrier(
  {http3_benchmark_connection_barrier, Process, OwnerMonitor,
   DeadlineMicroseconds}) ->
    Reference = make_ref(),
    Process ! {await_connection_barrier, self(), Reference},
    receive
        {Reference, connection_barrier_outcome, Outcome} -> Outcome;
        {'DOWN', OwnerMonitor, process, Process, _Reason} -> false
    after reply_timeout(DeadlineMicroseconds) ->
        Process ! connection_barrier_failed,
        false
    end.

-spec fail_connection_barrier(tuple()) -> nil.
fail_connection_barrier(
  {http3_benchmark_connection_barrier, Process, _OwnerMonitor,
   _DeadlineMicroseconds}) ->
    Process ! connection_barrier_failed,
    nil.

-spec stop_connection_barrier(tuple()) -> nil.
stop_connection_barrier(
  {http3_benchmark_connection_barrier, Process, OwnerMonitor,
   _DeadlineMicroseconds}) ->
    case erlang:is_process_alive(Process) of
        false ->
            consume_stopped_monitor(Process, OwnerMonitor);
        true ->
            Reference = make_ref(),
            Process ! {stop_connection_barrier, self(), Reference},
            receive
                {Reference, connection_barrier_stopped} ->
                    await_stopped_monitor(Process, OwnerMonitor);
                {'DOWN', OwnerMonitor, process, Process, normal} -> ok;
                {'DOWN', OwnerMonitor, process, Process, Reason} ->
                    erlang:error({benchmark_connection_barrier_failed, Reason})
            after ?STOP_TIMEOUT_MILLISECONDS ->
                exit(Process, kill),
                await_killed_monitor(Process, OwnerMonitor),
                erlang:error(benchmark_connection_barrier_stop_timeout)
            end
    end,
    nil.

-spec start_completion_latch(pos_integer(), integer()) -> tuple().
start_completion_latch(ExpectedWorkers, DeadlineMicroseconds)
        when is_integer(ExpectedWorkers), ExpectedWorkers > 0,
             is_integer(DeadlineMicroseconds) ->
    Owner = self(),
    {Process, Monitor} = spawn_monitor(fun() ->
        completion_latch_start(Owner, ExpectedWorkers, DeadlineMicroseconds)
    end),
    {http3_benchmark_completion_latch, Process, Monitor, DeadlineMicroseconds}.

-spec await_completion_latch(tuple(), integer()) -> boolean().
await_completion_latch(
  {http3_benchmark_completion_latch, Process, _OwnerMonitor,
   DeadlineMicroseconds},
  Worker) when is_integer(Worker) ->
    Reference = make_ref(),
    Monitor = erlang:monitor(process, Process),
    Process ! {completion_latch_wait, self(), Reference, Worker},
    await_completion_reply(Process, Monitor, Reference, DeadlineMicroseconds).

-spec release_completion_latch(tuple()) -> boolean().
release_completion_latch(
  {http3_benchmark_completion_latch, Process, OwnerMonitor,
   DeadlineMicroseconds}) ->
    Reference = make_ref(),
    Process ! {release_completion_latch, self(), Reference},
    receive
        {Reference, completion_latch_release, Outcome} -> Outcome;
        {'DOWN', OwnerMonitor, process, Process, _Reason} -> false
    after reply_timeout(DeadlineMicroseconds) ->
        Process ! completion_latch_failed,
        false
    end.

-spec fail_completion_latch(tuple()) -> nil.
fail_completion_latch(
  {http3_benchmark_completion_latch, Process, _OwnerMonitor,
   _DeadlineMicroseconds}) ->
    Process ! completion_latch_failed,
    nil.

-spec stop_completion_latch(tuple()) -> nil.
stop_completion_latch(
  {http3_benchmark_completion_latch, Process, OwnerMonitor,
   _DeadlineMicroseconds}) ->
    case erlang:is_process_alive(Process) of
        false ->
            consume_completion_latch_monitor(Process, OwnerMonitor);
        true ->
            Reference = make_ref(),
            Process ! {stop_completion_latch, self(), Reference},
            receive
                {Reference, completion_latch_stopped} ->
                    await_completion_latch_monitor(Process, OwnerMonitor);
                {'DOWN', OwnerMonitor, process, Process, normal} -> ok;
                {'DOWN', OwnerMonitor, process, Process, Reason} ->
                    erlang:error({benchmark_completion_latch_failed, Reason})
            after ?STOP_TIMEOUT_MILLISECONDS ->
                exit(Process, kill),
                await_killed_monitor(Process, OwnerMonitor),
                erlang:error(benchmark_completion_latch_stop_timeout)
            end
    end,
    nil.

completion_latch_start(Owner, ExpectedWorkers, DeadlineMicroseconds) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    Timer = erlang:send_after(deadline_timeout(DeadlineMicroseconds), self(),
                              completion_latch_deadline),
    completion_latch_loop(
      #{owner => Owner, owner_monitor => OwnerMonitor,
        expected_workers => ExpectedWorkers, arrived_workers => #{},
        worker_waiters => [], outcome => pending, timer => Timer}).

completion_latch_loop(State) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    receive
        {completion_latch_wait, Process, Reference, Worker} ->
            completion_latch_loop(
              handle_completion_waiter(State, Process, Reference, Worker));
        {release_completion_latch, Owner, Reference} ->
            Released = release_latch(State),
            Outcome = maps:get(outcome, Released) =:= released,
            Owner ! {Reference, completion_latch_release, Outcome},
            completion_latch_loop(Released);
        {release_completion_latch, Process, Reference} ->
            Process ! {Reference, completion_latch_release, false},
            completion_latch_loop(State);
        completion_latch_failed ->
            completion_latch_loop(fail_latch(State));
        completion_latch_deadline ->
            completion_latch_loop(fail_latch(State#{timer => undefined}));
        {stop_completion_latch, Owner, Reference} ->
            cancel_deadline_timer(State),
            _ = fail_latch(State),
            Owner ! {Reference, completion_latch_stopped},
            ok;
        {stop_completion_latch, Process, Reference} ->
            Process ! {Reference, completion_latch_stopped},
            completion_latch_loop(State);
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            cancel_deadline_timer(State),
            _ = fail_latch(State),
            ok
    end.

handle_completion_waiter(State, Process, Reference, Worker) ->
    ExpectedWorkers = maps:get(expected_workers, State),
    ArrivedWorkers = maps:get(arrived_workers, State),
    Valid = Worker >= 0 andalso Worker < ExpectedWorkers
            andalso not maps:is_key(Worker, ArrivedWorkers),
    case {maps:get(outcome, State), Valid} of
        {failed, _} ->
            Process ! {Reference, completion_latch_outcome, false},
            State;
        {released, true} ->
            Process ! {Reference, completion_latch_outcome, true},
            State#{arrived_workers => maps:put(Worker, true, ArrivedWorkers)};
        {released, false} ->
            Process ! {Reference, completion_latch_outcome, false},
            State;
        {pending, true} ->
            State#{arrived_workers => maps:put(Worker, true, ArrivedWorkers),
                   worker_waiters =>
                       [{Process, Reference}
                        | maps:get(worker_waiters, State)]};
        {pending, false} ->
            fail_latch(
              State#{worker_waiters =>
                         [{Process, Reference}
                          | maps:get(worker_waiters, State)]})
    end.

release_latch(#{outcome := released} = State) -> State;
release_latch(#{outcome := failed} = State) -> State;
release_latch(State) ->
    cancel_deadline_timer(State),
    reply_completion_waiters(maps:get(worker_waiters, State), true),
    State#{worker_waiters => [], outcome => released, timer => undefined}.

fail_latch(#{outcome := failed} = State) -> State;
fail_latch(#{outcome := released} = State) -> State;
fail_latch(State) ->
    cancel_deadline_timer(State),
    reply_completion_waiters(maps:get(worker_waiters, State), false),
    State#{worker_waiters => [], outcome => failed, timer => undefined}.

reply_completion_waiters(Waiters, Outcome) ->
    lists:foreach(
      fun({Process, Reference}) ->
          Process ! {Reference, completion_latch_outcome, Outcome}
      end,
      Waiters).

await_completion_reply(Process, Monitor, Reference, DeadlineMicroseconds) ->
    receive
        {Reference, completion_latch_outcome, Outcome} ->
            erlang:demonitor(Monitor, [flush]),
            Outcome;
        {'DOWN', Monitor, process, Process, _Reason} -> false
    after reply_timeout(DeadlineMicroseconds) ->
        erlang:demonitor(Monitor, [flush]),
        Process ! completion_latch_failed,
        false
    end.

consume_completion_latch_monitor(Process, Monitor) ->
    receive
        {'DOWN', Monitor, process, Process, normal} -> ok;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({benchmark_completion_latch_failed, Reason})
    after 0 -> ok
    end.

await_completion_latch_monitor(Process, Monitor) ->
    receive
        {'DOWN', Monitor, process, Process, normal} -> ok;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({benchmark_completion_latch_failed, Reason})
    after ?STOP_TIMEOUT_MILLISECONDS ->
        exit(Process, kill),
        await_killed_monitor(Process, Monitor),
        erlang:error(benchmark_completion_latch_stop_timeout)
    end.

connection_barrier_start(Owner, ExpectedWorkers, DeadlineMicroseconds) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    Timer = erlang:send_after(deadline_timeout(DeadlineMicroseconds), self(),
                              connection_barrier_deadline),
    connection_barrier_loop(
      #{owner => Owner, owner_monitor => OwnerMonitor,
        expected_workers => ExpectedWorkers, arrived_workers => #{},
        worker_waiters => [], owner_waiter => undefined, outcome => pending,
        timer => Timer}).

connection_barrier_loop(State) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    receive
        {connection_barrier_arrive, Process, Reference, Worker} ->
            connection_barrier_loop(
              handle_worker_arrival(State, Process, Reference, Worker));
        {await_connection_barrier, Owner, Reference} ->
            connection_barrier_loop(
              handle_owner_waiter(State, Owner, Reference));
        {await_connection_barrier, Process, Reference} ->
            Process ! {Reference, connection_barrier_outcome, false},
            connection_barrier_loop(State);
        connection_barrier_failed ->
            connection_barrier_loop(fail_barrier(State));
        connection_barrier_deadline ->
            connection_barrier_loop(fail_barrier(State#{timer => undefined}));
        {stop_connection_barrier, Owner, Reference} ->
            cancel_deadline_timer(State),
            _ = fail_barrier(State),
            Owner ! {Reference, connection_barrier_stopped},
            ok;
        {stop_connection_barrier, Process, Reference} ->
            Process ! {Reference, connection_barrier_stopped},
            connection_barrier_loop(State);
        {'DOWN', OwnerMonitor, process, Owner, _Reason} ->
            cancel_deadline_timer(State),
            _ = fail_barrier(State),
            ok
    end.

handle_worker_arrival(State, Process, Reference, Worker) ->
    case maps:get(outcome, State) of
        failed ->
            Process ! {Reference, connection_barrier_outcome, false},
            State;
        ready ->
            Process ! {Reference, connection_barrier_outcome, false},
            State;
        pending ->
            ExpectedWorkers = maps:get(expected_workers, State),
            ArrivedWorkers = maps:get(arrived_workers, State),
            case Worker >= 0 andalso Worker < ExpectedWorkers
                 andalso not maps:is_key(Worker, ArrivedWorkers) of
                false ->
                    fail_barrier(
                      State#{worker_waiters =>
                                 [{Process, Reference}
                                  | maps:get(worker_waiters, State)]});
                true ->
                    UpdatedWorkers = maps:put(Worker, true, ArrivedWorkers),
                    UpdatedState =
                        State#{arrived_workers => UpdatedWorkers,
                               worker_waiters =>
                                   [{Process, Reference}
                                    | maps:get(worker_waiters, State)]},
                    case map_size(UpdatedWorkers) =:= ExpectedWorkers of
                        true -> ready_barrier(UpdatedState);
                        false -> UpdatedState
                    end
            end
    end.

handle_owner_waiter(State, Owner, Reference) ->
    case maps:get(outcome, State) of
        ready ->
            Owner ! {Reference, connection_barrier_outcome, true},
            State;
        failed ->
            Owner ! {Reference, connection_barrier_outcome, false},
            State;
        pending ->
            case maps:get(owner_waiter, State) of
                undefined -> State#{owner_waiter => {Owner, Reference}};
                _Existing ->
                    Owner ! {Reference, connection_barrier_outcome, false},
                    fail_barrier(State)
            end
    end.

ready_barrier(State) ->
    cancel_deadline_timer(State),
    reply_workers(maps:get(worker_waiters, State), true),
    reply_owner(maps:get(owner_waiter, State), true),
    State#{worker_waiters => [], owner_waiter => undefined, outcome => ready,
           timer => undefined}.

fail_barrier(#{outcome := failed} = State) ->
    State;
fail_barrier(#{outcome := ready} = State) ->
    State;
fail_barrier(State) ->
    cancel_deadline_timer(State),
    reply_workers(maps:get(worker_waiters, State), false),
    reply_owner(maps:get(owner_waiter, State), false),
    State#{worker_waiters => [], owner_waiter => undefined, outcome => failed,
           timer => undefined}.

reply_workers(Waiters, Outcome) ->
    lists:foreach(
      fun({Process, Reference}) ->
          Process ! {Reference, connection_barrier_outcome, Outcome}
      end,
      Waiters).

reply_owner(undefined, _Outcome) ->
    ok;
reply_owner({Owner, Reference}, Outcome) ->
    Owner ! {Reference, connection_barrier_outcome, Outcome},
    ok.

await_worker_reply(Process, Monitor, Reference, DeadlineMicroseconds) ->
    receive
        {Reference, connection_barrier_outcome, Outcome} ->
            erlang:demonitor(Monitor, [flush]),
            Outcome;
        {'DOWN', Monitor, process, Process, _Reason} -> false
    after reply_timeout(DeadlineMicroseconds) ->
        erlang:demonitor(Monitor, [flush]),
        Process ! connection_barrier_failed,
        false
    end.

reply_timeout(DeadlineMicroseconds) ->
    deadline_timeout(DeadlineMicroseconds) + ?REPLY_GRACE_MILLISECONDS.

deadline_timeout(DeadlineMicroseconds) ->
    RemainingMicroseconds =
        max(0, DeadlineMicroseconds - erlang:monotonic_time(microsecond)),
    (RemainingMicroseconds + 999) div 1000.

cancel_deadline_timer(State) ->
    case maps:get(timer, State) of
        undefined -> ok;
        Timer ->
            _ = erlang:cancel_timer(Timer),
            ok
    end.

consume_stopped_monitor(Process, Monitor) ->
    receive
        {'DOWN', Monitor, process, Process, normal} -> ok;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({benchmark_connection_barrier_failed, Reason})
    after 0 -> ok
    end.

await_stopped_monitor(Process, Monitor) ->
    receive
        {'DOWN', Monitor, process, Process, normal} -> ok;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({benchmark_connection_barrier_failed, Reason})
    after ?STOP_TIMEOUT_MILLISECONDS ->
        exit(Process, kill),
        await_killed_monitor(Process, Monitor),
        erlang:error(benchmark_connection_barrier_stop_timeout)
    end.

await_killed_monitor(Process, Monitor) ->
    receive
        {'DOWN', Monitor, process, Process, _Reason} -> ok
    after ?STOP_TIMEOUT_MILLISECONDS -> ok
    end.
