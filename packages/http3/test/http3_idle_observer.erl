%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_idle_observer).
-export([open/2, close/1, cleanup/1, pause/1, resume/1, snapshot/1,
         enter/1, leave/2, self_test/0]).

-define(KEY, {?MODULE, observation}).
-define(LIMIT, 4096).

%% The only observed inputs are a receive timeout and a fixed outcome atom.
%% Classification happens in the observed actor, before any mailbox send.
%% Neither callback arguments nor callback return values reach this module.
open(PidRoles, Collector) when is_map(PidRoles), map_size(PidRoles) =< 8,
                              is_pid(Collector) ->
    undefined = persistent_term:get(?KEY, undefined),
    Counters = atomics:new(6, [{signed, false}]),
    atomics:put(Counters, 2, 1),
    Handle = {Collector, PidRoles, Counters},
    persistent_term:put(?KEY, Handle),
    Handle.

pause({_Collector, _Roles, Counters}) ->
    atomics:put(Counters, 2, 0),
    await_writers(Counters, erlang:monotonic_time(millisecond) + 1000).

resume({_Collector, _Roles, Counters}) -> atomics:put(Counters, 2, 1).

close(Handle) ->
    case persistent_term:get(?KEY, undefined) of
        Handle -> persistent_term:erase(?KEY);
        _ -> ok
    end,
    pause(Handle).

cleanup(Collector) ->
    case persistent_term:get(?KEY, undefined) of
        {Collector, _, _} = Handle -> close(Handle);
        _ -> true
    end.

await_writers(Counters, Deadline) ->
    case atomics:get(Counters, 1) of
        0 -> true;
        _ ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> receive after 1 -> await_writers(Counters, Deadline) end;
                false -> false
            end
    end.

snapshot({_Collector, _Roles, Counters}) ->
    #{event_limit => ?LIMIT, events_sent => atomics:get(Counters, 4),
      events_dropped => atomics:get(Counters, 5),
      invalid_events => atomics:get(Counters, 6)}.

enter(Timeout) -> emit(enter, classify(Timeout)).
leave(Timeout, message) -> emit(message, classify(Timeout));
leave(Timeout, timeout) -> emit(timeout, classify(Timeout));
leave(_Timeout, _Unknown) -> emit(invalid, invalid).

classify(infinity) -> unbounded;
classify(Within) when is_integer(Within), Within >= 0, Within =< 16#ffffffff ->
    if Within =:= 0 -> zero;
       Within =< 100 -> short;
       Within =< 1500 -> second;
       true -> long
    end;
classify(_) -> invalid.

emit(Operation, Class) ->
    case persistent_term:get(?KEY, undefined) of
        {Collector, Roles, Counters} when is_map_key(self(), Roles) ->
            atomics:add(Counters, 1, 1),
            try
                case {atomics:get(Counters, 2), Operation, Class} of
                    {0, _, _} -> ok;
                    {_, invalid, _} -> atomics:add(Counters, 6, 1);
                    {_, _, invalid} -> atomics:add(Counters, 6, 1);
                    _ ->
                        Number = atomics:add_get(Counters, 3, 1),
                        case Number =< ?LIMIT of
                            true ->
                                Collector ! {idle_scalar, self(), Operation, Class},
                                atomics:add(Counters, 4, 1);
                            false -> atomics:add(Counters, 5, 1)
                        end
                end
            after atomics:sub(Counters, 1, 1) end;
        _ -> ok
    end,
    ok.

self_test() ->
    Handle = open(#{self() => <<"http3.client">>}, self()),
    try
        ok = enter(0), ok = leave(0, timeout),
        ok = enter(infinity), ok = leave(infinity, message),
        [{idle_scalar, _, enter, zero}, {idle_scalar, _, timeout, zero},
         {idle_scalar, _, enter, unbounded}, {idle_scalar, _, message, unbounded}]
            = take_events([]),
        %% Hostile terms cannot be copied to the collector, even through this
        %% test-only public seam. They only increment a finite invalid counter.
        ok = enter({private, <<"idle-private-marker">>}),
        ok = leave(1, {private, <<"idle-private-marker">>}),
        [] = take_events([]),
        #{invalid_events := 2} = snapshot(Handle),
        lists:foreach(fun(_) -> enter(1) end, lists:seq(1, 10000)),
        #{events_sent := ?LIMIT, events_dropped := 5908} = snapshot(Handle),
        ?LIMIT = length(take_events([])) + 4,
        true = pause(Handle), ok = enter(1), [] = take_events([]),
        ok = resume(Handle), ok
    after true = close(Handle) end,
    ok = enter(0), [] = take_events([]),
    ok.

take_events(Acc) ->
    receive {idle_scalar, _, _, _} = Event -> take_events([Event | Acc])
    after 0 -> lists:reverse(Acc)
    end.
