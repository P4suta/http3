%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Fixed-size, scalar-only connect observations. No process, ETS table, socket,
%% endpoint, or callback result is retained. The opaque atomics allocation is
%% reclaimed when its last trace handle becomes unreachable.
-module(quic_core_connect_trace_ffi).
-export([new/0, begin_attempt/1, record/5, snapshot/1, record_resolution/4, resolution_snapshot/1]).
-define(CAPACITY, 64).
-define(MAXIMUM, 2147483647).
-define(RESOLUTION_BASE, 388).

-spec new() -> tuple().
new() ->
    {quic_connect_trace, atomics:new(?RESOLUTION_BASE + 4 + ?CAPACITY * 5, [{signed,true}]),
     erlang:monotonic_time(millisecond)}.

-spec begin_attempt(tuple()) -> non_neg_integer().
begin_attempt({quic_connect_trace, Cells, _}) ->
    case reserve(Cells, 3, ?MAXIMUM, 16) of
        full -> lost(Cells), 0;
        Index -> Index + 1
    end.

-spec record(tuple(), pos_integer(), non_neg_integer(), 1..4, 1..5) -> nil.
record({quic_connect_trace, Cells, Started}, Attempt, Candidate, Phase, Outcome)
  when is_integer(Attempt), Attempt > 0, Attempt =< ?MAXIMUM,
       is_integer(Candidate), Candidate >= 0, Candidate =< ?MAXIMUM,
       is_integer(Phase), Phase >= 1, Phase =< 4,
       is_integer(Outcome), Outcome >= 1, Outcome =< 5 ->
    case reserve(Cells, 1, ?CAPACITY, 16) of
        full -> lost(Cells);
        Index ->
            Offset = 4 + Index * 6,
            atomics:put(Cells, Offset+2, Attempt),
            atomics:put(Cells, Offset+3, Candidate),
            atomics:put(Cells, Offset+4, Phase),
            atomics:put(Cells, Offset+5, Outcome),
            atomics:put(Cells, Offset+6, min(?MAXIMUM,
                max(0, erlang:monotonic_time(millisecond)-Started))),
            %% Publish only after every immutable scalar is initialized.
            atomics:put(Cells, Offset+1, Index+1)
    end,
    nil;
record({quic_connect_trace, Cells, _}, _, _, _, _) -> lost(Cells), nil.

-spec snapshot(tuple()) -> {boolean(), non_neg_integer(), [tuple()]}.
snapshot({quic_connect_trace, Cells, _}) ->
    Count = atomics:get(Cells, 1),
    Rows = [read_row(Cells, Index) || Index <- lists:seq(0, Count-1)],
    Events = [Row || Row <- Rows, element(1, Row) > 0],
    {Count =:= atomics:get(Cells, 1) andalso length(Events) =:= Count
        andalso atomics:get(Cells, 4) =:= 0,
     atomics:get(Cells, 2), Events}.

read_row(Cells, Index) ->
    Offset = 4 + Index * 6,
    %% Read the publication marker first; an unpublished slot never exposes
    %% partially initialized fields, even when its writer exits permanently.
    case atomics:get(Cells, Offset+1) of
        0 -> {0,0,0,0,0,0};
        Sequence -> list_to_tuple([Sequence |
            [atomics:get(Cells, Offset+Field) || Field <- lists:seq(2,6)]])
    end.

reserve(_, _, _, 0) -> full;
reserve(Cells, Slot, Maximum, Remaining) ->
    Current = atomics:get(Cells, Slot),
    case Current >= Maximum of
        true -> full;
        false -> case atomics:compare_exchange(Cells, Slot, Current, Current+1) of
            ok -> Current;
            _ -> reserve(Cells, Slot, Maximum, Remaining-1)
        end
    end.

lost(Cells) ->
    case reserve(Cells, 2, ?MAXIMUM, 16) of
        full -> atomics:put(Cells, 4, 1);
        _ -> ok
    end.

%% Independent scalar evidence distinguishes each family's callback result
%% from its deadline, owner cancellation, and unexpected worker termination.
%% Main NameResolution timing stops when dialing first becomes eligible.
-spec record_resolution(tuple(), pos_integer(), 4 | 6, 1..7) -> nil.
record_resolution(Trace = {quic_connect_trace, Cells, Started}, Attempt, Family, Outcome)
  when is_integer(Attempt), Attempt > 0, Attempt =< ?MAXIMUM,
       (Family =:= 4 orelse Family =:= 6), is_integer(Outcome), Outcome >= 1, Outcome =< 7 ->
    case Outcome >= 5 andalso resolution_finished(Trace, Attempt, Family) of
        true -> nil;
        false ->
            case reserve(Cells, ?RESOLUTION_BASE+1, ?CAPACITY, 16) of
                full -> resolution_lost(Cells);
                Index ->
                    Offset = ?RESOLUTION_BASE + 4 + Index * 5,
                    atomics:put(Cells, Offset+2, Attempt),
                    atomics:put(Cells, Offset+3, Family),
                    atomics:put(Cells, Offset+4, Outcome),
                    atomics:put(Cells, Offset+5, min(?MAXIMUM,
                        max(0, erlang:monotonic_time(millisecond)-Started))),
                    atomics:put(Cells, Offset+1, Index+1)
            end,
            nil
    end;
record_resolution({quic_connect_trace, Cells, _}, _, _, _) -> resolution_lost(Cells), nil.

-spec resolution_snapshot(tuple()) -> {boolean(), non_neg_integer(), [tuple()]}.
resolution_snapshot({quic_connect_trace, Cells, _}) ->
    Count = atomics:get(Cells, ?RESOLUTION_BASE+1),
    Rows = [resolution_row(Cells, Index) || Index <- lists:seq(0, Count-1)],
    Events = [Row || Row <- Rows, element(1, Row) > 0],
    {Count =:= atomics:get(Cells, ?RESOLUTION_BASE+1) andalso length(Events) =:= Count
        andalso atomics:get(Cells, ?RESOLUTION_BASE+4) =:= 0,
     atomics:get(Cells, ?RESOLUTION_BASE+2), Events}.

resolution_row(Cells, Index) ->
    Offset = ?RESOLUTION_BASE + 4 + Index * 5,
    case atomics:get(Cells, Offset+1) of
        0 -> {0,0,0,0,0};
        Sequence -> list_to_tuple([Sequence |
            [atomics:get(Cells, Offset+Field) || Field <- lists:seq(2,5)]])
    end.

resolution_finished(Trace, Attempt, Family) ->
    {_,_,Events} = resolution_snapshot(Trace),
    lists:any(fun({_,A,F,O,_}) -> A =:= Attempt andalso F =:= Family andalso O =/= 1 end, Events).

resolution_lost(Cells) ->
    case reserve(Cells, ?RESOLUTION_BASE+2, ?MAXIMUM, 16) of
        full -> atomics:put(Cells, ?RESOLUTION_BASE+4, 1);
        _ -> ok
    end.
