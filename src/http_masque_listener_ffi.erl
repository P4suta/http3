%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_masque_listener_ffi).

-export([
    new/0,
    record_accept/2,
    record_setup/2,
    record_setup_cleanup/2,
    record_setup_duplicate/1,
    record_drain/2,
    record_stop/2,
    snapshot/1
]).

-define(STATE, 1).
-define(ACCEPT_CALLS, 2).
-define(ACCEPTED_REQUESTS, 3).
-define(REJECTED_REQUESTS, 4).
-define(ACCEPT_FAILURES, 5).
-define(REJECTION_RESPONSE_FAILURES, 6).
-define(SETUP_CALLS, 7).
-define(ESTABLISHED_REQUESTS, 8).
-define(POLICY_REJECTIONS, 9).
-define(SETUP_REJECTIONS, 10).
-define(SETUP_RESPONSE_FAILURES, 11).
-define(DUPLICATE_SETUP_ATTEMPTS, 12).
-define(SETUP_RESPONSE_CLEANUP_CALLS, 13).
-define(SETUP_RESPONSE_CLEANUP_FAILURES, 14).
-define(DRAIN_CALLS, 15).
-define(STOP_CALLS, 16).
-define(LIFECYCLE_FAILURES, 17).
-define(GENERATION, 18).
-define(ACTIVE_WRITERS, 19).

-define(LISTENING, 1).
-define(STOPPED, 2).
-define(MAXIMUM_COUNTER, 9223372036854775807).
-define(MAXIMUM_SNAPSHOT_RETRIES, 64).

-type diagnostics() ::
    {http_masque_listener_diagnostics, atomics:atomics_ref()}.

-spec new() -> diagnostics().
new() ->
    Counters = atomics:new(19, [{signed, false}]),
    atomics:put(Counters, ?STATE, ?LISTENING),
    {http_masque_listener_diagnostics, Counters}.

-spec record_accept(diagnostics(), 1..4) -> nil.
record_accept(Diagnostics, Outcome)
    when is_integer(Outcome), Outcome >= 1, Outcome =< 4 ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?ACCEPT_CALLS),
        record_accept_outcome(Counters, Outcome)
    end),
    nil;
record_accept(_Diagnostics, _Outcome) ->
    nil.

-spec record_setup(diagnostics(), 1..4) -> nil.
record_setup(Diagnostics, Outcome)
    when is_integer(Outcome), Outcome >= 1, Outcome =< 4 ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?SETUP_CALLS),
        record_setup_outcome(Counters, Outcome)
    end),
    nil;
record_setup(_Diagnostics, _Outcome) ->
    nil.

-spec record_setup_cleanup(diagnostics(), boolean()) -> nil.
record_setup_cleanup(Diagnostics, Succeeded) when is_boolean(Succeeded) ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?SETUP_RESPONSE_CLEANUP_CALLS),
        case Succeeded of
            true -> ok;
            false -> saturating_increment(
                Counters, ?SETUP_RESPONSE_CLEANUP_FAILURES
            )
        end
    end),
    nil;
record_setup_cleanup(_Diagnostics, _Succeeded) ->
    nil.

-spec record_setup_duplicate(diagnostics()) -> nil.
record_setup_duplicate(Diagnostics) ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, ?DUPLICATE_SETUP_ATTEMPTS)
    end),
    nil.

-spec record_drain(diagnostics(), boolean()) -> nil.
record_drain(Diagnostics, Succeeded) when is_boolean(Succeeded) ->
    record_lifecycle(Diagnostics, ?DRAIN_CALLS, Succeeded),
    nil;
record_drain(_Diagnostics, _Succeeded) ->
    nil.

-spec record_stop(diagnostics(), boolean()) -> nil.
record_stop(Diagnostics, Succeeded) when is_boolean(Succeeded) ->
    record_lifecycle(Diagnostics, ?STOP_CALLS, Succeeded),
    nil;
record_stop(_Diagnostics, _Succeeded) ->
    nil.

-spec snapshot(diagnostics()) ->
    {boolean(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer()}.
snapshot(Diagnostics) ->
    case diagnostics_counters(Diagnostics) of
        {ok, Counters} -> snapshot(Counters, ?MAXIMUM_SNAPSHOT_RETRIES);
        error -> inconsistent_snapshot()
    end.

-spec snapshot(atomics:atomics_ref(), non_neg_integer()) ->
    {boolean(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer()}.
snapshot(Counters, 0) ->
    snapshot_values(Counters, false);
snapshot(Counters, Remaining) ->
    GenerationBefore = safe_atomic_get(Counters, ?GENERATION, -1),
    ActiveBefore = safe_atomic_get(Counters, ?ACTIVE_WRITERS, 1),
    Values = snapshot_values(Counters, true),
    ActiveAfter = safe_atomic_get(Counters, ?ACTIVE_WRITERS, 1),
    GenerationAfter = safe_atomic_get(Counters, ?GENERATION, -2),
    State = element(2, Values),
    case ActiveBefore =:= 0 andalso ActiveAfter =:= 0 andalso
         GenerationBefore =:= GenerationAfter andalso
         (State =:= ?LISTENING orelse State =:= ?STOPPED) of
        true -> Values;
        false ->
            erlang:yield(),
            snapshot(Counters, Remaining - 1)
    end.

-spec snapshot_values(atomics:atomics_ref(), boolean()) ->
    {boolean(), integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer()}.
snapshot_values(Counters, Consistent) ->
    State = safe_atomic_get(Counters, ?STATE, ?STOPPED),
    {
        Consistent andalso (State =:= ?LISTENING orelse State =:= ?STOPPED),
        normalize_state(State),
        safe_atomic_get(Counters, ?ACCEPT_CALLS, 0),
        safe_atomic_get(Counters, ?ACCEPTED_REQUESTS, 0),
        safe_atomic_get(Counters, ?REJECTED_REQUESTS, 0),
        safe_atomic_get(Counters, ?ACCEPT_FAILURES, 0),
        safe_atomic_get(Counters, ?REJECTION_RESPONSE_FAILURES, 0),
        safe_atomic_get(Counters, ?SETUP_CALLS, 0),
        safe_atomic_get(Counters, ?ESTABLISHED_REQUESTS, 0),
        safe_atomic_get(Counters, ?POLICY_REJECTIONS, 0),
        safe_atomic_get(Counters, ?SETUP_REJECTIONS, 0),
        safe_atomic_get(Counters, ?SETUP_RESPONSE_FAILURES, 0),
        safe_atomic_get(Counters, ?DUPLICATE_SETUP_ATTEMPTS, 0),
        safe_atomic_get(Counters, ?SETUP_RESPONSE_CLEANUP_CALLS, 0),
        safe_atomic_get(Counters, ?SETUP_RESPONSE_CLEANUP_FAILURES, 0),
        safe_atomic_get(Counters, ?DRAIN_CALLS, 0),
        safe_atomic_get(Counters, ?STOP_CALLS, 0),
        safe_atomic_get(Counters, ?LIFECYCLE_FAILURES, 0)
    }.

-spec inconsistent_snapshot() ->
    {false, integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer(), integer(),
     integer(), integer(), integer(), integer(), integer()}.
inconsistent_snapshot() ->
    {false, ?STOPPED, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}.

-spec record_accept_outcome(atomics:atomics_ref(), 1..4) -> ok.
record_accept_outcome(Counters, 1) ->
    saturating_increment(Counters, ?ACCEPTED_REQUESTS);
record_accept_outcome(Counters, 2) ->
    saturating_increment(Counters, ?REJECTED_REQUESTS);
record_accept_outcome(Counters, 3) ->
    saturating_increment(Counters, ?ACCEPT_FAILURES);
record_accept_outcome(Counters, 4) ->
    saturating_increment(Counters, ?REJECTED_REQUESTS),
    saturating_increment(Counters, ?REJECTION_RESPONSE_FAILURES).

-spec record_setup_outcome(atomics:atomics_ref(), 1..4) -> ok.
record_setup_outcome(Counters, 1) ->
    saturating_increment(Counters, ?ESTABLISHED_REQUESTS);
record_setup_outcome(Counters, 2) ->
    saturating_increment(Counters, ?POLICY_REJECTIONS);
record_setup_outcome(Counters, 3) ->
    saturating_increment(Counters, ?SETUP_REJECTIONS);
record_setup_outcome(Counters, 4) ->
    saturating_increment(Counters, ?SETUP_RESPONSE_FAILURES).

-spec record_lifecycle(diagnostics(), pos_integer(), boolean()) -> ok.
record_lifecycle(Diagnostics, Counter, Succeeded) ->
    with_write(Diagnostics, fun(Counters) ->
        saturating_increment(Counters, Counter),
        case Succeeded of
            true -> atomics:put(Counters, ?STATE, ?STOPPED);
            false -> saturating_increment(Counters, ?LIFECYCLE_FAILURES)
        end
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
diagnostics_counters({http_masque_listener_diagnostics, Counters}) ->
    try atomics:get(Counters, ?ACTIVE_WRITERS) of
        _Value -> {ok, Counters}
    catch
        _:_ -> error
    end;
diagnostics_counters(_Diagnostics) ->
    error.

-spec saturating_increment(atomics:atomics_ref(), pos_integer()) -> ok.
saturating_increment(Counters, Index) ->
    try atomics:add_get(Counters, Index, 1) of
        Value when Value > ?MAXIMUM_COUNTER ->
            atomics:put(Counters, Index, ?MAXIMUM_COUNTER);
        _ -> ok
    catch
        _:_ -> ok
    end.

-spec safe_atomic_get(
    atomics:atomics_ref(), pos_integer(), integer()
) -> integer().
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

-spec normalize_state(integer()) -> ?LISTENING | ?STOPPED.
normalize_state(?LISTENING) -> ?LISTENING;
normalize_state(_State) -> ?STOPPED.
