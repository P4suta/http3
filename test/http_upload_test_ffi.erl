%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Test-only callback lifetime observation. No native values escape snapshots.
-module(http_upload_test_ffi).
-export([new_probe/0, started/1, cleanup/1, snapshot/1, stop_pull/1, dispose/1,
         await_cleanup/2, suspend/1, resume/1,
         pause_upload/2, resume_upload/1, released/1, release_snapshot/1]).

new_probe() ->
    Probe = ets:new(?MODULE, [public, set]),
    ets:insert(Probe, {owner, self()}),
    Probe.
started(Probe) -> ets:insert(Probe, {pull, self()}), nil.
cleanup(Probe) ->
    _ = ets:update_counter(Probe, calls, 1, {calls, 0}),
    case alive(Probe) of
        true -> _ = ets:update_counter(Probe, premature, 1, {premature, 0});
        false -> ok
    end,
    [{owner, Owner}] = ets:lookup(Probe, owner),
    Owner ! {upload_cleanup, Probe},
    nil.
await_cleanup(Probe, Timeout) ->
    receive {upload_cleanup, Probe} -> true after Timeout -> false end.
suspend(Pid) -> erlang:suspend_process(Pid), nil.
resume(Pid) -> erlang:resume_process(Pid), nil.
pause_upload(Probe, {upload, Reaper, _, _, _}) ->
    case process_info(Reaper, monitors) of
        {monitors, [{process, Guardian}]} ->
            erlang:suspend_process(Guardian),
            ets:insert(Probe, {guardian, Guardian}),
            true;
        _ -> false
    end.
resume_upload(Probe) ->
    [{guardian, Guardian}] = ets:lookup(Probe, guardian),
    erlang:resume_process(Guardian),
    nil.
released(Probe) ->
    [{guardian, Guardian}] = ets:lookup(Probe, guardian),
    ets:insert(Probe, {release_guardian_alive, is_process_alive(Guardian)}),
    _ = ets:update_counter(Probe, releases, 1, {releases, 0}),
    nil.
release_snapshot(Probe) ->
    Alive = case ets:lookup(Probe, release_guardian_alive) of
        [{release_guardian_alive, Value}] -> Value;
        [] -> false
    end,
    {count(Probe, releases), Alive}.
snapshot(Probe) -> {alive(Probe), count(Probe, calls), count(Probe, premature)}.
alive(Probe) -> case ets:lookup(Probe, pull) of
    [{pull, Pid}] -> is_process_alive(Pid);
    [] -> false
end.
count(Probe, Key) -> case ets:lookup(Probe, Key) of
    [{Key, Value}] -> Value;
    [] -> 0
end.
stop_pull(Probe) ->
    case ets:lookup(Probe, pull) of
        [{pull, Pid}] ->
            Monitor = monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', Monitor, process, Pid, _} -> ok
            after 1000 -> demonitor(Monitor, [flush]) end;
        [] -> ok
    end,
    nil.
dispose(Probe) -> ets:delete(Probe), nil.
