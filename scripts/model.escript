#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(OUTPUT, "build/model").
-define(CUBIC, 'quic_core@internal@cubic').
-define(SCALE, 1000000).

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "model gate failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(Arguments) ->
    {Shard, Shards} = parse_arguments(Arguments),
    Cases = case Shards of
        1 -> 10000;
        _ -> ceiling_div(1000000, Shards)
    end,
    add_code_paths(),
    ensure(code:which(?CUBIC) =/= non_existing, missing_cubic_beam),
    OracleChecks = cubic_oracle(),
    EcnChecks = ecn_oracle(),
    LimitedChecks = application_limited_oracle(),
    HystartChecks = hystart_oracle(),
    TopologyChecks = topology_oracle(),
    Seed = 982451653 + Shard * 104729,
    {FinalState, FinalModel, FinalSeed} =
        model_cases(Cases, Seed, initial_model()),
    assert_invariants(FinalState, FinalModel),
    Digest = hex(crypto:hash(sha256,
                             term_to_binary({FinalState, FinalModel,
                                             FinalSeed}))),
    Report = #{status => <<"Ready">>,
               family => <<"quic-cubic-rfc9438-rfc9406">>,
               shard => Shard,
               shards => Shards,
               cases => Cases,
               oracle_ack_checks => OracleChecks,
               ecn_oracle_events => EcnChecks,
               application_limited_checks => LimitedChecks,
               hystart_oracle_rounds => HystartChecks,
               topology_oracle_modes => TopologyChecks,
               seed => Seed,
               source_sha256 => source_digest(),
               final_sha256 => Digest},
    ok = filelib:ensure_dir(filename:join(?OUTPUT, "placeholder")),
    Path = filename:join(?OUTPUT,
                         "shard-" ++ integer_to_list(Shard) ++ ".json"),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    io:format("model shard ~B/~B: ~B transitions, ~B CUBIC ACKs, "
              "~B ECN events, ~B HyStart++ rounds, ~s~n",
              [Shard, Shards, Cases, OracleChecks, EcnChecks,
               HystartChecks, Digest]),
    ok.

parse_arguments([]) -> {0, 1};
parse_arguments(["--shard", Shard, "--shards", Shards]) ->
    parsed_shards(Shard, Shards);
parse_arguments(["--shards", Shards, "--shard", Shard]) ->
    parsed_shards(Shard, Shards);
parse_arguments(_) ->
    erlang:error({usage, "[--shard N --shards N]"}).

parsed_shards(ShardText, ShardsText) ->
    Shard = list_to_integer(ShardText),
    Shards = list_to_integer(ShardsText),
    ensure(Shards > 0 andalso Shard >= 0 andalso Shard < Shards,
           {invalid_shard, Shard, Shards}),
    {Shard, Shards}.

initial_model() ->
    {ok, State} = call(new, [1200]),
    {State, #{flight => 0, mds => 1200, clock => 1}}.

model_cases(0, Seed, {State, Model}) -> {State, Model, Seed};
model_cases(Remaining, Seed0, {State0, Model0}) ->
    Seed = next_seed(Seed0),
    {State, Model} = model_step(Seed rem 8, Seed, State0, Model0),
    assert_invariants(State, Model),
    model_cases(Remaining - 1, Seed, {State, Model}).

model_step(0, Seed, State, Model) ->
    Bytes = 1 + Seed rem maps:get(mds, Model),
    case call(can_send, [State, Bytes]) of
        true ->
            {ok, Next} = call(on_packet_sent, [State, Bytes, true]),
            {Next, Model#{flight := maps:get(flight, Model) + Bytes}};
        false -> {State, Model}
    end;
model_step(1, Seed, State, Model) ->
    consume_flight(ack, Seed, State, Model, false);
model_step(2, Seed, State, Model) ->
    consume_flight(loss, Seed, State, Model, false);
model_step(3, Seed, State, Model) ->
    consume_flight(ack, Seed, State, Model, true);
model_step(4, Seed, State, Model) ->
    Flight = maps:get(flight, Model),
    case Flight of
        0 -> {State, Model};
        _ ->
            Bytes = 1 + Seed rem Flight,
            {ok, Next} = call(abandon_in_flight, [State, Bytes]),
            {Next, Model#{flight := Flight - Bytes}}
    end;
model_step(5, Seed, State, Model) ->
    Mds = 1200 + Seed rem 64328,
    {ok, Next} = call(set_maximum_datagram_size, [State, Mds]),
    {Next, Model#{mds := Mds}};
model_step(6, _Seed, State, Model) ->
    Next = call(on_persistent_congestion, [State]),
    Floor = 2 * maps:get(mds, Model),
    ensure(call(congestion_window, [Next]) >= Floor,
           {persistent_congestion_window_below_floor,
            call(congestion_window, [Next]), Floor}),
    {Next, Model};
model_step(7, _Seed, State, Model) ->
    Clock = maps:get(clock, Model),
    {ok, Next} = call(on_congestion_experienced, [State, Clock]),
    {Next, Model#{clock := Clock + 1}}.

consume_flight(_Kind, _Seed, State, #{flight := 0} = Model, _Limited) ->
    {State, Model};
consume_flight(Kind, Seed, State, Model, Limited) ->
    Flight = maps:get(flight, Model),
    Bytes = 1 + Seed rem Flight,
    Clock = maps:get(clock, Model),
    Rtt = 1 + Seed rem 250,
    Next = case Kind of
        ack ->
            {ok, Value} = call(on_packet_acked,
                               [State, Bytes, Clock, Clock + Rtt, Rtt,
                                Limited]),
            Value;
        loss ->
            {ok, Value} = call(on_packet_lost,
                               [State, Bytes, Clock, Clock + Rtt]),
            ensure(call(congestion_window, [Value]) >=
                       2 * maps:get(mds, Model),
                   {loss_window_below_rfc9002_floor,
                    call(congestion_window, [Value]), maps:get(mds, Model)}),
            Value
    end,
    {Next, Model#{flight := Flight - Bytes,
                  clock := Clock + Rtt + 1}}.

assert_invariants(State, Model) ->
    Flight = maps:get(flight, Model),
    Mds = maps:get(mds, Model),
    Window = call(congestion_window, [State]),
    ensure(call(bytes_in_flight, [State]) =:= Flight,
           {flight_accounting, Flight, call(bytes_in_flight, [State])}),
    ensure(Flight >= 0, {negative_flight, Flight}),
    ensure(Window > 0, {non_positive_window, Window, Mds}),
    ensure(call(can_send, [State, -1]) =:= false, negative_send_admitted),
    ensure(call(can_send, [State, 0]) =:= (Flight =< Window),
           {zero_send_inconsistent, Flight, Window}),
    ensure(is_error(call(on_packet_acked,
                         [State, Flight + 1, 0, 1, 1, false])),
           oversized_ack_admitted),
    ensure(is_error(call(on_packet_lost, [State, Flight + 1, 0, 1])),
           oversized_loss_admitted),
    ok.

%% This oracle is deliberately separate from the Gleam implementation. It
%% follows RFC 9438's fixed-point CUBIC and Reno-friendly calculations after
%% one deterministic recovery transition and compares every observable cwnd.
cubic_oracle() ->
    {ok, S0} = call(new, [1200]),
    %% Fill cwnd before acknowledging. RFC 9438 requires cwnd-based QUIC
    %% controllers to suppress growth for sparse application-limited flight.
    {ok, S1} = call(on_packet_sent, [S0, 12000, true]),
    {ok, S2} = call(on_packet_acked, [S1, 1200, 10, 20, 10, false]),
    {ok, S2Drained} = call(abandon_in_flight, [S2, 10800]),
    {ok, S3} = call(on_packet_sent, [S2Drained, 1200, true]),
    {ok, S4} = call(on_packet_lost, [S3, 1200, 30, 40]),
    ensure(call(congestion_window, [S4]) =:= 9240, oracle_recovery_vector),
    Oracle0 = #{scaled => 9240 * ?SCALE, estimated => 9240 * ?SCALE,
                maximum => 13200, prior => 13200, epoch => undefined,
                k => 0, last => undefined},
    oracle_acks(200, 50, S4, Oracle0).

oracle_acks(0, _Now, _State, _Oracle) -> 200;
oracle_acks(Remaining, Now, State0, Oracle0) ->
    Window = call(congestion_window, [State0]),
    Flight = call(bytes_in_flight, [State0]),
    {ok, Sent} = call(on_packet_sent, [State0, Window - Flight, true]),
    {ok, State} = call(on_packet_acked,
                       [Sent, 1200, Now - 1, Now, 10, false]),
    Oracle = oracle_ack(Oracle0, 1200, Now, 10),
    Expected = maps:get(scaled, Oracle) div ?SCALE,
    Actual = call(congestion_window, [State]),
    ensure(Actual =:= Expected,
           {cubic_oracle_difference, 201 - Remaining, Expected, Actual}),
    oracle_acks(Remaining - 1, Now + 37, State, Oracle).

%% RFC 9438 section 4.6 has a distinct one-SMSS ECN floor and a further
%% sending-rate response. These vectors are independent of the Gleam formula.
ecn_oracle() ->
    {ok, S0} = call(new, [1200]),
    Expected = [8400, 5880, 4116, 2881, 2016, 1411, 1200],
    S7 = ecn_windows(Expected, 1, S0),
    ensure(call(pacing_window, [S7]) =:= 1200,
           {ecn_floor_pacing_window, call(pacing_window, [S7])}),
    {ok, S8} = call(on_congestion_experienced, [S7, 8]),
    ensure(call(pacing_window, [S8]) =:= 600,
           {first_persistent_ecn_backoff, call(pacing_window, [S8])}),
    {ok, S9} = call(on_congestion_experienced, [S8, 9]),
    ensure(call(pacing_window, [S9]) =:= 300,
           {second_persistent_ecn_backoff, call(pacing_window, [S9])}),
    ensure(is_error(call(on_congestion_experienced, [S9, -1])),
           negative_ecn_clock_admitted),
    9.

ecn_windows([], _Now, State) -> State;
ecn_windows([Expected | Rest], Now, State0) ->
    {ok, State} = call(on_congestion_experienced, [State0, Now]),
    Actual = call(congestion_window, [State]),
    ensure(Actual =:= Expected,
           {ecn_window_difference, Now, Expected, Actual}),
    ecn_windows(Rest, Now + 1, State).

application_limited_oracle() ->
    {ok, S0} = call(new, [1200]),
    {ok, S1} = call(on_packet_sent, [S0, 1200, true]),
    {ok, S2} = call(on_packet_acked, [S1, 1200, 1, 11, 10, false]),
    ensure(call(congestion_window, [S2]) =:= 12000,
           {sparse_flight_grew_cwnd, call(congestion_window, [S2])}),
    1.

%% Drive the RFC 9406 state machine using sparse flight so this checks RTT
%% observation and round accounting independently of cwnd growth.
hystart_oracle() ->
    {ok, S0} = call(new, [1200]),
    {S1, Clock1} = hystart_acks(10, 10, 1, S0),
    {S2, Clock2} = hystart_acks(8, 14, Clock1, S1),
    ensure(call(slow_start_mode, [S2]) =:= conservative_slow_start,
           hystart_did_not_enter_css),
    {S3, _Clock3} = finish_css_rounds(S2, Clock2, 0, 5, 512),
    ensure(call(phase, [S3]) =:= congestion_avoidance,
           hystart_did_not_enter_congestion_avoidance),
    {hystart_snapshot, false, standard_slow_start, 5, 0} =
        call(hystart_snapshot, [S3]),
    5.

hystart_acks(0, _Rtt, Clock, State) -> {State, Clock};
hystart_acks(Remaining, Rtt, Clock, State0) ->
    {ok, Sent} = call(on_packet_sent, [State0, 1200, true]),
    {ok, State} = call(on_packet_acked,
                       [Sent, 1200, Clock, Clock + Rtt, Rtt, false]),
    hystart_acks(Remaining - 1, Rtt, Clock + Rtt + 1, State).

finish_css_rounds(State, Clock, Target, Target, _Budget) -> {State, Clock};
finish_css_rounds(_State, _Clock, _Completed, _Target, 0) ->
    erlang:error(hystart_css_round_budget_exhausted);
finish_css_rounds(State0, Clock, Completed, Target, Budget) ->
    {hystart_snapshot, _Enabled, _Mode, Before, _Samples} =
        call(hystart_snapshot, [State0]),
    {State, NextClock} = hystart_acks(1, 14, Clock, State0),
    {hystart_snapshot, _NextEnabled, _NextMode, After, _NextSamples} =
        call(hystart_snapshot, [State]),
    NextCompleted = case After > Before of true -> After; false -> Completed end,
    finish_css_rounds(State, NextClock, NextCompleted, Target, Budget - 1).

topology_oracle() ->
    {ok, Enabled0} = call(new_with_fast_convergence, [1200, true]),
    {ok, Disabled0} = call(new_with_fast_convergence, [1200, false]),
    {ok, Enabled1} = call(on_packet_lost, [Enabled0, 0, 1, 1]),
    {ok, Disabled1} = call(on_packet_lost, [Disabled0, 0, 1, 1]),
    {ok, Enabled} = call(on_packet_lost, [Enabled1, 0, 2, 2]),
    {ok, Disabled} = call(on_packet_lost, [Disabled1, 0, 2, 2]),
    {curve_snapshot, 7140, 8400, 0, true} = call(curve_snapshot, [Enabled]),
    {curve_snapshot, 8400, 8400, 0, false} = call(curve_snapshot, [Disabled]),
    2.

oracle_ack(Oracle0, Acknowledged, Now, Rtt) ->
    Oracle1 = ensure_oracle_epoch(Oracle0, Now),
    Current = maps:get(scaled, Oracle1),
    Prior = maps:get(prior, Oracle1),
    Estimated0 = maps:get(estimated, Oracle1),
    Alpha = case Estimated0 >= Prior * ?SCALE of true -> 17; false -> 9 end,
    Increment = ?SCALE * Alpha * 1200 * Acknowledged div
                (17 * maximum(Current div ?SCALE, 1)),
    Estimated = Estimated0 + Increment,
    Elapsed = maximum(Now - maps:get(epoch, Oracle1), 0),
    CubicNow = oracle_cubic_window(Oracle1, Elapsed),
    Scaled = case CubicNow < Estimated of
        true -> maximum(Current, Estimated);
        false ->
            Calculated = oracle_cubic_window(Oracle1, Elapsed + Rtt),
            Target = minimum(maximum(Calculated, Current), Current * 3 div 2),
            Current + (Target - Current) * Acknowledged div
                      maximum(Current div ?SCALE, 1)
    end,
    Oracle1#{scaled := Scaled, estimated := Estimated, last := Now}.

ensure_oracle_epoch(#{epoch := undefined} = Oracle, Now) ->
    Current = maps:get(scaled, Oracle) div ?SCALE,
    Difference = maximum(maps:get(maximum, Oracle) - Current, 0),
    KCubed = Difference * 5 * 1000000000 div (2 * 1200),
    Oracle#{epoch := Now, last := Now, k := integer_cube_root(KCubed)};
ensure_oracle_epoch(Oracle, _Now) -> Oracle.

oracle_cubic_window(Oracle, Elapsed) ->
    Offset = Elapsed - maps:get(k, Oracle),
    Delta = 1200 * 2 * Offset * Offset * Offset * ?SCALE div 5000000000,
    maximum(maps:get(maximum, Oracle) * ?SCALE + Delta, 0).

integer_cube_root(Value) when Value =< 0 -> 0;
integer_cube_root(Value) -> cube_root_search(Value, 0, Value + 1).

cube_root_search(_Value, Low, High) when High - Low =< 1 -> Low;
cube_root_search(Value, Low, High) ->
    Middle = (Low + High) div 2,
    case Middle * Middle * Middle =< Value of
        true -> cube_root_search(Value, Middle, High);
        false -> cube_root_search(Value, Low, Middle)
    end.

call(Function, Arguments) -> apply(?CUBIC, Function, Arguments).

is_error({error, _}) -> true;
is_error(_) -> false.

add_code_paths() ->
    Roots = ["packages/quic_core/build/dev/erlang"],
    Paths = lists:append([filelib:wildcard(filename:join(Root, "*/ebin"))
                          || Root <- Roots]),
    lists:foreach(fun(Path) -> true = code:add_patha(filename:absname(Path)) end,
                  Paths).

next_seed(Seed) -> (Seed * 48271 + 1) rem 2147483647.

ceiling_div(Value, Divisor) -> (Value + Divisor - 1) div Divisor.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

source_digest() ->
    Paths = ["packages/quic_core/gleam.toml",
             "packages/quic_core/src/quic_core/internal/cubic.gleam",
             "packages/quic_core/test/cubic_test.gleam",
             "scripts/model.escript"],
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).

maximum(First, Second) when First >= Second -> First;
maximum(_First, Second) -> Second.

minimum(First, Second) when First =< Second -> First;
minimum(_First, Second) -> Second.
