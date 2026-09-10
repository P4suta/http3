%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_http2_listener_ffi).

-export([
    new/0,
    record_listener_ready/2,
    record_state/2,
    record_accept/2,
    record_connection_start/3,
    record_connection_exit/1,
    record_connection_failure/1,
    record_drain_request/2,
    record_drain_receipt/1,
    record_goaway/3,
    record_drain_completion/1,
    snapshot/1
]).

-define(STATE, 1).
-define(LISTENER_READY_MILLISECONDS, 2).
-define(ACCEPTED_CONNECTIONS, 3).
-define(ACCEPT_FAILURES, 4).
-define(CONNECTION_START_ATTEMPTS, 5).
-define(STARTED_CONNECTIONS, 6).
-define(CONNECTION_START_FAILURES, 7).
-define(ACTIVE_CONNECTIONS, 8).
-define(EXITED_CONNECTIONS, 9).
-define(DRAIN_REQUESTS, 10).
-define(CONNECTION_DRAIN_COMMANDS, 11).
-define(CONNECTION_DRAIN_RECEIPTS, 12).
-define(GOAWAY_ATTEMPTS, 13).
-define(GOAWAYS_SENT, 14).
-define(GOAWAY_FAILURES, 15).
-define(DRAIN_COMPLETIONS, 16).
-define(CONNECTION_FAILURES, 17).
-define(LAST_CONNECTION_START_MILLISECONDS, 18).
-define(MAXIMUM_CONNECTION_START_MILLISECONDS, 19).
-define(LAST_GOAWAY_MILLISECONDS, 20).
-define(MAXIMUM_GOAWAY_MILLISECONDS, 21).
-define(GENERATION, 22).
-define(ACTIVE_WRITERS, 23).

-define(RUNNING, 0).
-define(DRAINING, 1).
-define(STOPPED, 2).
-define(MAXIMUM_COUNTER, 9223372036854775807).
-define(MAXIMUM_SNAPSHOT_RETRIES, 64).

-type diagnostics() ::
    {http_http2_listener_diagnostics, atomics:atomics_ref()}.

-spec new() -> diagnostics().
new() ->
    Counters = atomics:new(23, [{signed, false}]),
    {http_http2_listener_diagnostics, Counters}.

-spec record_listener_ready(diagnostics(), non_neg_integer()) -> nil.
record_listener_ready(Diagnostics, ElapsedMilliseconds)
    when is_integer(ElapsedMilliseconds), ElapsedMilliseconds >= 0 ->
    with_write(Diagnostics, fun(Counters) ->
        atomics:put(
            Counters,
            ?LISTENER_READY_MILLISECONDS,
            bounded_counter(ElapsedMilliseconds)
        )
    end),
    nil;
record_listener_ready(_Diagnostics, _ElapsedMilliseconds) ->
    nil.

-spec record_state(diagnostics(), 0..2) -> nil.
record_state(Diagnostics, State)
    when is_integer(State), State >= ?RUNNING, State =< ?STOPPED ->
    with_write(Diagnostics, fun(Counters) ->
        Current = safe_atomic_get(Counters, ?STATE, ?STOPPED),
        case State >= Current of
            true -> atomics:put(Counters, ?STATE, State);
            false -> ok
        end
    end),
    nil;
record_state(_Diagnostics, _State) ->
    nil.

-spec record_accept(diagnostics(), boolean()) -> nil.
record_accept(Diagnostics, Succeeded) when is_boolean(Succeeded) ->
    with_write(Diagnostics, fun(Counters) ->
        case Succeeded of
            true -> saturating_increment(Counters, ?ACCEPTED_CONNECTIONS);
            false -> saturating_increment(Counters, ?ACCEPT_FAILURES)
        end
    end),
    nil;
record_accept(_Diagnostics, _Succeeded) ->
    nil.

-spec record_connection_start(diagnostics(), boolean(), non_neg_integer()) -> nil.
record_connection_start(Diagnostics, Succeeded, ElapsedMilliseconds)
    when is_boolean(Succeeded), is_integer(ElapsedMilliseconds),
         ElapsedMilliseconds >= 0 ->
    with_write(Diagnostics, fun(Counters) ->
        Elapsed = bounded_counter(ElapsedMilliseconds),
        saturating_increment(Counters, ?CONNECTION_START_ATTEMPTS),
        atomics:put(Counters, ?LAST_CONNECTION_START_MILLISECONDS, Elapsed),
        saturating_max(
            Counters,
            ?MAXIMUM_CONNECTION_START_MILLISECONDS,
            Elapsed
        ),
        case Succeeded of
            true ->
                saturating_increment(Counters, ?STARTED_CONNECTIONS),
                saturating_increment(Counters, ?ACTIVE_CONNECTIONS);
            false ->
                saturating_increment(Counters, ?CONNECTION_START_FAILURES)
        end
    end),
    nil;
record_connection_start(_Diagnostics, _Succeeded, _ElapsedMilliseconds) ->
    nil.

-spec record_connection_exit(diagnostics()) -> nil.
record_connection_exit(Diagnostics) ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?EXITED_CONNECTIONS),
        bounded_decrement(Counters, ?ACTIVE_CONNECTIONS)
    end),
    nil.

-spec record_connection_failure(diagnostics()) -> nil.
record_connection_failure(Diagnostics) ->
    record_increment(Diagnostics, ?CONNECTION_FAILURES),
    nil.

-spec record_drain_request(diagnostics(), non_neg_integer()) -> nil.
record_drain_request(Diagnostics, ConnectionCommands)
    when is_integer(ConnectionCommands), ConnectionCommands >= 0 ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?DRAIN_REQUESTS),
        saturating_add(
            Counters,
            ?CONNECTION_DRAIN_COMMANDS,
            bounded_counter(ConnectionCommands)
        )
    end),
    nil;
record_drain_request(_Diagnostics, _ConnectionCommands) ->
    nil.

-spec record_drain_receipt(diagnostics()) -> nil.
record_drain_receipt(Diagnostics) ->
    record_increment(Diagnostics, ?CONNECTION_DRAIN_RECEIPTS),
    nil.

-spec record_goaway(diagnostics(), boolean(), non_neg_integer()) -> nil.
record_goaway(Diagnostics, Succeeded, ElapsedMilliseconds)
    when is_boolean(Succeeded), is_integer(ElapsedMilliseconds),
         ElapsedMilliseconds >= 0 ->
    with_write(Diagnostics, fun(Counters) ->
        Elapsed = bounded_counter(ElapsedMilliseconds),
        saturating_increment(Counters, ?GOAWAY_ATTEMPTS),
        atomics:put(Counters, ?LAST_GOAWAY_MILLISECONDS, Elapsed),
        saturating_max(Counters, ?MAXIMUM_GOAWAY_MILLISECONDS, Elapsed),
        case Succeeded of
            true -> saturating_increment(Counters, ?GOAWAYS_SENT);
            false -> saturating_increment(Counters, ?GOAWAY_FAILURES)
        end
    end),
    nil;
record_goaway(_Diagnostics, _Succeeded, _ElapsedMilliseconds) ->
    nil.

-spec record_drain_completion(diagnostics()) -> nil.
record_drain_completion(Diagnostics) ->
    record_increment(Diagnostics, ?DRAIN_COMPLETIONS),
    nil.

-spec snapshot(diagnostics()) ->
    {boolean(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer()}.
snapshot(Diagnostics) ->
    case diagnostics_counters(Diagnostics) of
        {ok, Counters} -> snapshot(Counters, ?MAXIMUM_SNAPSHOT_RETRIES);
        error -> inconsistent_snapshot()
    end.

-spec snapshot(atomics:atomics_ref(), non_neg_integer()) ->
    {boolean(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer()}.
snapshot(Counters, 0) ->
    snapshot_values(Counters, false);
snapshot(Counters, Remaining) ->
    GenerationBefore = safe_atomic_get(Counters, ?GENERATION, -1),
    ActiveBefore = safe_atomic_get(Counters, ?ACTIVE_WRITERS, 1),
    Values = snapshot_values(Counters, true),
    ActiveAfter = safe_atomic_get(Counters, ?ACTIVE_WRITERS, 1),
    GenerationAfter = safe_atomic_get(Counters, ?GENERATION, -2),
    case ActiveBefore =:= 0 andalso ActiveAfter =:= 0 andalso
         GenerationBefore =:= GenerationAfter of
        true -> Values;
        false ->
            erlang:yield(),
            snapshot(Counters, Remaining - 1)
    end.

-spec snapshot_values(atomics:atomics_ref(), boolean()) ->
    {boolean(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer()}.
snapshot_values(Counters, Consistent) ->
    {
        Consistent,
        normalize_state(safe_atomic_get(Counters, ?STATE, ?STOPPED)),
        safe_atomic_get(Counters, ?LISTENER_READY_MILLISECONDS, 0),
        safe_atomic_get(Counters, ?ACCEPTED_CONNECTIONS, 0),
        safe_atomic_get(Counters, ?ACCEPT_FAILURES, 0),
        safe_atomic_get(Counters, ?CONNECTION_START_ATTEMPTS, 0),
        safe_atomic_get(Counters, ?STARTED_CONNECTIONS, 0),
        safe_atomic_get(Counters, ?CONNECTION_START_FAILURES, 0),
        safe_atomic_get(Counters, ?ACTIVE_CONNECTIONS, 0),
        safe_atomic_get(Counters, ?EXITED_CONNECTIONS, 0),
        safe_atomic_get(Counters, ?DRAIN_REQUESTS, 0),
        safe_atomic_get(Counters, ?CONNECTION_DRAIN_COMMANDS, 0),
        safe_atomic_get(Counters, ?CONNECTION_DRAIN_RECEIPTS, 0),
        safe_atomic_get(Counters, ?GOAWAY_ATTEMPTS, 0),
        safe_atomic_get(Counters, ?GOAWAYS_SENT, 0),
        safe_atomic_get(Counters, ?GOAWAY_FAILURES, 0),
        safe_atomic_get(Counters, ?DRAIN_COMPLETIONS, 0),
        safe_atomic_get(Counters, ?CONNECTION_FAILURES, 0),
        safe_atomic_get(Counters, ?LAST_CONNECTION_START_MILLISECONDS, 0),
        safe_atomic_get(Counters, ?MAXIMUM_CONNECTION_START_MILLISECONDS, 0),
        safe_atomic_get(Counters, ?LAST_GOAWAY_MILLISECONDS, 0),
        safe_atomic_get(Counters, ?MAXIMUM_GOAWAY_MILLISECONDS, 0)
    }.

-spec inconsistent_snapshot() ->
    {false, integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer()}.
inconsistent_snapshot() ->
    {false, ?STOPPED, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0}.

-spec record_increment(term(), pos_integer()) -> ok.
record_increment(Diagnostics, Index) ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, Index)
    end).

-spec with_write(term(), fun((atomics:atomics_ref()) -> term())) -> ok.
with_write(Diagnostics, Update) ->
    case diagnostics_counters(Diagnostics) of
        error -> ok;
        {ok, Counters} ->
            try atomics:add(Counters, ?ACTIVE_WRITERS, 1) of
                ok ->
                    try Update(Counters) of
                        _ -> ok
                    catch
                        _:_ -> ok
                    after
                        saturating_increment(Counters, ?GENERATION),
                        safe_atomic_subtract(Counters, ?ACTIVE_WRITERS, 1)
                    end
            catch
                _:_ -> ok
            end
    end.

-spec diagnostics_counters(term()) ->
    {ok, atomics:atomics_ref()} | error.
diagnostics_counters({http_http2_listener_diagnostics, Counters}) ->
    try atomics:get(Counters, ?ACTIVE_WRITERS) of
        _Value -> {ok, Counters}
    catch
        _:_ -> error
    end;
diagnostics_counters(_Diagnostics) ->
    error.

-spec saturating_increment(atomics:atomics_ref(), pos_integer()) -> ok.
saturating_increment(Counters, Index) ->
    saturating_add(Counters, Index, 1).

-spec saturating_add(
    atomics:atomics_ref(), pos_integer(), non_neg_integer()
) -> ok.
saturating_add(_Counters, _Index, 0) ->
    ok;
saturating_add(Counters, Index, Amount) ->
    try atomics:get(Counters, Index) of
        Current when Current >= ?MAXIMUM_COUNTER -> ok;
        Current ->
            Candidate = erlang:min(Current + Amount, ?MAXIMUM_COUNTER),
            case atomics:compare_exchange(Counters, Index, Current, Candidate) of
                ok -> ok;
                _ -> saturating_add(Counters, Index, Amount)
            end
    catch
        _:_ -> ok
    end.

-spec saturating_max(atomics:atomics_ref(), pos_integer(), non_neg_integer()) -> ok.
saturating_max(Counters, Index, Candidate) ->
    try atomics:get(Counters, Index) of
        Current when Current >= Candidate -> ok;
        Current ->
            case atomics:compare_exchange(Counters, Index, Current, Candidate) of
                ok -> ok;
                _ -> saturating_max(Counters, Index, Candidate)
            end
    catch
        _:_ -> ok
    end.

-spec bounded_decrement(atomics:atomics_ref(), pos_integer()) -> ok.
bounded_decrement(Counters, Index) ->
    try atomics:get(Counters, Index) of
        0 -> ok;
        Current ->
            case atomics:compare_exchange(Counters, Index, Current, Current - 1) of
                ok -> ok;
                _ -> bounded_decrement(Counters, Index)
            end
    catch
        _:_ -> ok
    end.

-spec safe_atomic_get(atomics:atomics_ref(), pos_integer(), integer()) -> integer().
safe_atomic_get(Counters, Index, Default) ->
    try atomics:get(Counters, Index) of
        Value when is_integer(Value), Value >= 0 -> Value;
        _ -> Default
    catch
        _:_ -> Default
    end.

-spec safe_atomic_subtract(
    atomics:atomics_ref(), pos_integer(), non_neg_integer()
) -> ok.
safe_atomic_subtract(Counters, Index, Amount) ->
    try atomics:sub(Counters, Index, Amount) of
        ok -> ok
    catch
        _:_ -> ok
    end.

-spec bounded_counter(non_neg_integer()) -> non_neg_integer().
bounded_counter(Value) when Value > ?MAXIMUM_COUNTER -> ?MAXIMUM_COUNTER;
bounded_counter(Value) -> Value.

-spec normalize_state(integer()) -> 0..2.
normalize_state(?RUNNING) -> ?RUNNING;
normalize_state(?DRAINING) -> ?DRAINING;
normalize_state(_) -> ?STOPPED.
