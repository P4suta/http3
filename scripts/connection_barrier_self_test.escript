#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main([]) ->
    guarded_self_test();
main(_) ->
    io:format(standard_error, "usage: connection_barrier_self_test.escript~n", []),
    halt(1).

guarded_self_test() ->
    try self_test() of
        ok -> io:format("HTTP/3 benchmark connection barrier self-test passed~n", [])
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "connection barrier self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

self_test() ->
    load_barrier_module(),
    ready_releases_every_worker(),
    failure_releases_current_and_late_workers(),
    duplicate_worker_fails_closed(),
    deadline_releases_waiters(),
    owner_exit_stops_barrier(),
    completion_latch_waits_for_owner_release(),
    completion_latch_accepts_late_waiters_after_release(),
    completion_latch_failure_releases_current_and_late_waiters(),
    completion_latch_duplicate_worker_fails_closed(),
    completion_latch_rejects_non_owner_release(),
    completion_latch_deadline_releases_waiters(),
    completion_latch_stop_releases_waiters(),
    owner_exit_stops_completion_latch(),
    ok.

ready_releases_every_worker() ->
    Barrier = start_barrier(2, 2000),
    First = start_arrival(Barrier, 0),
    Second = start_arrival(Barrier, 1),
    true = http3_benchmark_barrier_ffi:await_connection_barrier(Barrier),
    true = await_arrival(First),
    true = await_arrival(Second),
    nil = http3_benchmark_barrier_ffi:stop_connection_barrier(Barrier),
    ok.

failure_releases_current_and_late_workers() ->
    Barrier = start_barrier(2, 2000),
    Waiting = start_arrival(Barrier, 0),
    timer:sleep(10),
    nil = http3_benchmark_barrier_ffi:fail_connection_barrier(Barrier),
    false = http3_benchmark_barrier_ffi:await_connection_barrier(Barrier),
    false = await_arrival(Waiting),
    false = http3_benchmark_barrier_ffi:arrive_connection_barrier(Barrier, 1),
    nil = http3_benchmark_barrier_ffi:stop_connection_barrier(Barrier),
    ok.

duplicate_worker_fails_closed() ->
    Barrier = start_barrier(2, 2000),
    First = start_arrival(Barrier, 0),
    Duplicate = start_arrival(Barrier, 0),
    false = http3_benchmark_barrier_ffi:await_connection_barrier(Barrier),
    false = await_arrival(First),
    false = await_arrival(Duplicate),
    nil = http3_benchmark_barrier_ffi:stop_connection_barrier(Barrier),
    ok.

deadline_releases_waiters() ->
    Barrier = start_barrier(2, 50),
    Waiting = start_arrival(Barrier, 0),
    Started = erlang:monotonic_time(millisecond),
    false = http3_benchmark_barrier_ffi:await_connection_barrier(Barrier),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    ensure(Elapsed >= 25, {barrier_deadline_too_early, Elapsed}),
    ensure(Elapsed =< 2000, {barrier_deadline_too_late, Elapsed}),
    false = await_arrival(Waiting),
    nil = http3_benchmark_barrier_ffi:stop_connection_barrier(Barrier),
    ok.

owner_exit_stops_barrier() ->
    Parent = self(),
    Owner = spawn(fun() ->
        Barrier = start_barrier(1, 2000),
        Parent ! {owner_barrier, self(), Barrier},
        receive
            stop_barrier_owner -> ok
        end
    end),
    receive
        {owner_barrier, Owner,
         {http3_benchmark_connection_barrier, BarrierProcess, _Monitor,
          _Deadline}} ->
            BarrierMonitor = erlang:monitor(process, BarrierProcess),
            Owner ! stop_barrier_owner,
            receive
                {'DOWN', BarrierMonitor, process, BarrierProcess, normal} -> ok;
                {'DOWN', BarrierMonitor, process, BarrierProcess, Reason} ->
                    erlang:error({barrier_owner_cleanup_failed, Reason})
            after 2000 -> erlang:error(barrier_owner_cleanup_timeout)
            end
    after 2000 -> erlang:error(barrier_owner_fixture_timeout)
    end.

completion_latch_waits_for_owner_release() ->
    Latch = start_latch(2, 2000),
    First = start_latch_waiter(Latch, 0),
    Second = start_latch_waiter(Latch, 1),
    timer:sleep(10),
    ensure(waiter_alive(First), completion_latch_first_released_early),
    ensure(waiter_alive(Second), completion_latch_second_released_early),
    true = http3_benchmark_barrier_ffi:release_completion_latch(Latch),
    true = await_latch_waiter(First),
    true = await_latch_waiter(Second),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    ok.

completion_latch_accepts_late_waiters_after_release() ->
    Latch = start_latch(2, 2000),
    true = http3_benchmark_barrier_ffi:release_completion_latch(Latch),
    true = http3_benchmark_barrier_ffi:await_completion_latch(Latch, 0),
    true = http3_benchmark_barrier_ffi:await_completion_latch(Latch, 1),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    ok.

completion_latch_failure_releases_current_and_late_waiters() ->
    Latch = start_latch(2, 2000),
    Waiting = start_latch_waiter(Latch, 0),
    timer:sleep(10),
    nil = http3_benchmark_barrier_ffi:fail_completion_latch(Latch),
    false = await_latch_waiter(Waiting),
    false = http3_benchmark_barrier_ffi:await_completion_latch(Latch, 1),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    ok.

completion_latch_duplicate_worker_fails_closed() ->
    Latch = start_latch(2, 2000),
    First = start_latch_waiter(Latch, 0),
    Duplicate = start_latch_waiter(Latch, 0),
    false = await_latch_waiter(First),
    false = await_latch_waiter(Duplicate),
    false = http3_benchmark_barrier_ffi:await_completion_latch(Latch, 1),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    ok.

completion_latch_rejects_non_owner_release() ->
    Latch = start_latch(1, 2000),
    Waiting = start_latch_waiter(Latch, 0),
    Parent = self(),
    Reference = make_ref(),
    spawn(fun() ->
        Result = http3_benchmark_barrier_ffi:release_completion_latch(Latch),
        Parent ! {Reference, non_owner_release, Result}
    end),
    receive
        {Reference, non_owner_release, false} -> ok
    after 2000 -> erlang:error(non_owner_release_timeout)
    end,
    ensure(waiter_alive(Waiting), non_owner_released_completion_latch),
    true = http3_benchmark_barrier_ffi:release_completion_latch(Latch),
    true = await_latch_waiter(Waiting),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    ok.

completion_latch_deadline_releases_waiters() ->
    Latch = start_latch(1, 50),
    Waiting = start_latch_waiter(Latch, 0),
    Started = erlang:monotonic_time(millisecond),
    false = await_latch_waiter(Waiting),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    ensure(Elapsed >= 25, {completion_latch_deadline_too_early, Elapsed}),
    ensure(Elapsed =< 2000, {completion_latch_deadline_too_late, Elapsed}),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    ok.

completion_latch_stop_releases_waiters() ->
    Latch = start_latch(1, 2000),
    Waiting = start_latch_waiter(Latch, 0),
    timer:sleep(10),
    nil = http3_benchmark_barrier_ffi:stop_completion_latch(Latch),
    false = await_latch_waiter(Waiting),
    ok.

owner_exit_stops_completion_latch() ->
    Parent = self(),
    Owner = spawn(fun() ->
        Latch = start_latch(1, 2000),
        Parent ! {owner_latch, self(), Latch},
        receive
            stop_latch_owner -> ok
        end
    end),
    receive
        {owner_latch, Owner,
         {http3_benchmark_completion_latch, LatchProcess, _Monitor,
          _Deadline}} ->
            LatchMonitor = erlang:monitor(process, LatchProcess),
            Owner ! stop_latch_owner,
            receive
                {'DOWN', LatchMonitor, process, LatchProcess, normal} -> ok;
                {'DOWN', LatchMonitor, process, LatchProcess, Reason} ->
                    erlang:error({completion_latch_owner_cleanup_failed, Reason})
            after 2000 -> erlang:error(completion_latch_owner_cleanup_timeout)
            end
    after 2000 -> erlang:error(completion_latch_owner_fixture_timeout)
    end.

start_barrier(Expected, TimeoutMilliseconds) ->
    Deadline = erlang:monotonic_time(microsecond) + TimeoutMilliseconds * 1000,
    http3_benchmark_barrier_ffi:start_connection_barrier(Expected, Deadline).

start_arrival(Barrier, Worker) ->
    Parent = self(),
    Reference = make_ref(),
    {Process, Monitor} = spawn_monitor(fun() ->
        Result = http3_benchmark_barrier_ffi:arrive_connection_barrier(
                   Barrier, Worker),
        Parent ! {Reference, barrier_arrival, Result}
    end),
    {Process, Monitor, Reference}.

start_latch(Expected, TimeoutMilliseconds) ->
    Deadline = erlang:monotonic_time(microsecond) + TimeoutMilliseconds * 1000,
    http3_benchmark_barrier_ffi:start_completion_latch(Expected, Deadline).

start_latch_waiter(Latch, Worker) ->
    Parent = self(),
    Reference = make_ref(),
    {Process, Monitor} = spawn_monitor(fun() ->
        Result = http3_benchmark_barrier_ffi:await_completion_latch(
                   Latch, Worker),
        Parent ! {Reference, completion_latch_waiter, Result}
    end),
    {Process, Monitor, Reference}.

waiter_alive({Process, _Monitor, _Reference}) ->
    erlang:is_process_alive(Process).

await_latch_waiter({Process, Monitor, Reference}) ->
    receive
        {Reference, completion_latch_waiter, Result} ->
            receive
                {'DOWN', Monitor, process, Process, normal} -> Result;
                {'DOWN', Monitor, process, Process, Reason} ->
                    erlang:error({completion_latch_waiter_failed, Reason})
            after 2000 -> erlang:error(completion_latch_waiter_cleanup_timeout)
            end;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({completion_latch_waiter_stopped_without_result,
                          Reason})
    after 2000 -> erlang:error(completion_latch_waiter_timeout)
    end.

await_arrival({Process, Monitor, Reference}) ->
    receive
        {Reference, barrier_arrival, Result} ->
            receive
                {'DOWN', Monitor, process, Process, normal} -> Result;
                {'DOWN', Monitor, process, Process, Reason} ->
                    erlang:error({barrier_arrival_failed, Reason})
            after 2000 -> erlang:error(barrier_arrival_cleanup_timeout)
            end;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({barrier_arrival_stopped_without_result, Reason})
    after 2000 -> erlang:error(barrier_arrival_timeout)
    end.

load_barrier_module() ->
    Script = filename:absname(escript:script_name()),
    Root = filename:dirname(filename:dirname(Script)),
    EbinPattern = filename:join(
                    [Root, "packages", "http3", "build", "dev", "erlang",
                     "*", "ebin"]),
    EbinDirectories = filelib:wildcard(EbinPattern),
    ensure(EbinDirectories =/= [], {missing_http3_build, EbinPattern}),
    lists:foreach(fun(Directory) -> true = code:add_patha(Directory) end,
                  EbinDirectories),
    {module, http3_benchmark_barrier_ffi} =
        code:ensure_loaded(http3_benchmark_barrier_ffi),
    ok.

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
