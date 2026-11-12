%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_HOST_EVIDENCE_HRL).
-define(HTTP_PERFORMANCE_HOST_EVIDENCE_HRL, true).

%% Validate before copying or hashing an imported snapshot. Every nonnumeric
%% value is either a fixed enum or the observed runtime identity of this VM.
performance_host_valid(Snapshot, Label) ->
    try
        true = Label =:= <<"start">> orelse Label =:= <<"end">>,
        true = suite_exact_keys(Snapshot, [schema, status, label, shareable,
            captured_system_time_milliseconds, runtime, probes]),
        1 = maps:get(<<"schema">>, Snapshot), <<"Captured">> = maps:get(<<"status">>, Snapshot),
        Label = maps:get(<<"label">>, Snapshot), false = maps:get(<<"shareable">>, Snapshot),
        true = performance_host_number(maps:get(<<"captured_system_time_milliseconds">>, Snapshot)),
        Runtime = maps:get(<<"runtime">>, Snapshot),
        true = suite_exact_keys(Runtime, [otp_release, system_architecture, os_family, os_name,
            logical_processors, logical_processors_available, schedulers_online, dirty_cpu_schedulers_online]),
        {Family, Name} = os:type(),
        Expected = #{<<"otp_release">> => list_to_binary(erlang:system_info(otp_release)),
            <<"system_architecture">> => list_to_binary(erlang:system_info(system_architecture)),
            <<"os_family">> => atom_to_binary(Family), <<"os_name">> => atom_to_binary(Name)},
        Expected = maps:with(maps:keys(Expected), Runtime),
        true = lists:all(fun(K) ->
            V = maps:get(atom_to_binary(K), Runtime),
            (is_integer(V) andalso V >= 0 andalso V =< 1048576) orelse V =:= <<"unknown">>
        end, [logical_processors, logical_processors_available, schedulers_online, dirty_cpu_schedulers_online]),
        Probes = maps:get(<<"probes">>, Snapshot),
        true = suite_exact_keys(Probes, performance_host_probe_names()),
        lists:all(fun({K, V}) -> performance_host_probe_valid(K, V) end, maps:to_list(Probes))
    catch _:_ -> false end.

performance_host_probe_names() -> [load_average, cpu_pressure, memory_pressure, io_pressure,
    cpu_accounting, memory, cgroup_cpu_accounting, cgroup_cpu_limit, cgroup_memory_current,
    cgroup_memory_peak, cgroup_memory_limit, cgroup_memory_events, cpu_frequency, thermal].
performance_host_number(V) -> is_integer(V) andalso V >= 0 andalso V =< 9223372036854775807.
performance_host_numbers(Map, Keys) ->
    suite_exact_keys(Map, Keys) andalso lists:all(fun performance_host_number/1, maps:values(Map)).
performance_host_optional_numbers(Map, Required, Optional) ->
    Allowed = [atom_to_binary(K) || K <- Required ++ Optional],
    is_map(Map) andalso lists:all(fun(K) -> maps:is_key(atom_to_binary(K), Map) end, Required)
    andalso lists:all(fun(K) -> lists:member(K, Allowed) end, maps:keys(Map))
    andalso lists:all(fun performance_host_number/1, maps:values(Map)).
performance_host_probe_valid(Name, Probe) ->
    try
        Status = maps:get(<<"status">>, Probe), Rest = maps:remove(<<"status">>, Probe),
        case Status of
            <<"Unavailable">> -> performance_host_unavailable(Rest);
            <<"Invalid">> -> performance_host_invalid(Rest);
            <<"Available">> -> performance_host_values(Name, Rest, Status);
            <<"Partial">> when Name =:= <<"cpu_frequency">>; Name =:= <<"thermal">> ->
                performance_host_values(Name, Rest, Status);
            _ -> false
        end
    catch _:_ -> false end.
performance_host_reason(Reason) -> lists:member(Reason, [<<"enoent">>, <<"enotdir">>,
    <<"eacces">>, <<"eperm">>, <<"enotsup">>, <<"einval">>, <<"eio">>, <<"emfile">>,
    <<"enfile">>, <<"invalid_value">>, <<"invalid_shape">>, <<"missing_counter">>, <<"probe_error">>]).
performance_host_unavailable(Rest) ->
    Reason = maps:get(<<"reason">>, Rest),
    case Reason of
        <<"no_readable_sources">> ->
            true = suite_exact_keys(Rest, [reason, source_count, sampled_source_count, error_count, truncated]),
            Source = maps:get(<<"source_count">>, Rest), Sampled = maps:get(<<"sampled_source_count">>, Rest),
            performance_host_number(Source) andalso Sampled =:= min(Source, 4096)
            andalso maps:get(<<"error_count">>, Rest) =:= Sampled
            andalso maps:get(<<"truncated">>, Rest) =:= (Source > Sampled);
        _ -> suite_exact_keys(Rest, [reason]) andalso
            (Reason =:= <<"no_sources">> orelse performance_host_reason(Reason))
    end.
performance_host_invalid(Rest) ->
    case maps:get(<<"reason">>, Rest) of
        <<"probe_too_large">> -> Rest =:= #{<<"reason">> => <<"probe_too_large">>,
            <<"observed_bytes">> => 1048577, <<"maximum_bytes">> => 1048576};
        Reason -> suite_exact_keys(Rest, [reason]) andalso performance_host_reason(Reason)
    end.
performance_host_values(<<"load_average">>, Rest, _) ->
    performance_host_numbers(Rest, [load_1m_milli, load_5m_milli, load_15m_milli, runnable_entities, total_entities]);
performance_host_values(Name, Rest, _) when Name =:= <<"cpu_pressure">>; Name =:= <<"memory_pressure">>; Name =:= <<"io_pressure">> ->
    true = maps:is_key(<<"some">>, Rest),
    true = lists:all(fun(K) -> K =:= <<"some">> orelse K =:= <<"full">> end, maps:keys(Rest)),
    lists:all(fun(V) -> performance_host_numbers(V, [avg10_basis_points, avg60_basis_points,
        avg300_basis_points, total_microseconds]) andalso
        lists:all(fun(K) -> maps:get(K, V) =< 10000 end,
            [<<"avg10_basis_points">>, <<"avg60_basis_points">>, <<"avg300_basis_points">>]) end, maps:values(Rest));
performance_host_values(<<"cpu_accounting">>, Rest, _) ->
    performance_host_numbers(Rest, [total_ticks, busy_ticks, idle_ticks, user_ticks, nice_ticks,
        system_ticks, io_wait_ticks, irq_ticks, soft_irq_ticks, steal_ticks, context_switches,
        processes_created, processes_running, processes_blocked]);
performance_host_values(<<"memory">>, Rest, _) ->
    performance_host_numbers(Rest, [total_bytes, free_bytes, available_bytes, buffers_bytes,
        cached_bytes, swap_total_bytes, swap_free_bytes]);
performance_host_values(<<"cgroup_cpu_accounting">>, Rest, _) ->
    suite_exact_keys(Rest, [counters]) andalso performance_host_optional_numbers(maps:get(<<"counters">>, Rest),
        [usage_usec, user_usec, system_usec], [nr_periods, nr_throttled, throttled_usec, nr_bursts, burst_usec]);
performance_host_values(<<"cgroup_memory_events">>, Rest, _) ->
    suite_exact_keys(Rest, [counters]) andalso performance_host_optional_numbers(maps:get(<<"counters">>, Rest),
        [], [low, high, max, oom, oom_kill, oom_group_kill]);
performance_host_values(<<"cgroup_cpu_limit">>, Rest, _) ->
    true = suite_exact_keys(Rest, [unlimited, quota_microseconds, period_microseconds]),
    P = maps:get(<<"period_microseconds">>, Rest),
    performance_host_number(P) andalso P > 0 andalso performance_host_limit(Rest, <<"quota_microseconds">>);
performance_host_values(Name, Rest, _) when Name =:= <<"cgroup_memory_current">>; Name =:= <<"cgroup_memory_peak">>; Name =:= <<"cgroup_memory_limit">> ->
    suite_exact_keys(Rest, [unlimited, value]) andalso performance_host_limit(Rest, <<"value">>);
performance_host_values(Name, Rest, Status) when Name =:= <<"cpu_frequency">>; Name =:= <<"thermal">> ->
    true = suite_exact_keys(Rest, [source_count, sampled_source_count, readable_count, error_count,
        truncated, minimum, maximum, average]),
    Source = maps:get(<<"source_count">>, Rest), Sampled = maps:get(<<"sampled_source_count">>, Rest),
    Read = maps:get(<<"readable_count">>, Rest), Errors = maps:get(<<"error_count">>, Rest),
    Min = maps:get(<<"minimum">>, Rest), Max = maps:get(<<"maximum">>, Rest), Avg = maps:get(<<"average">>, Rest),
    {Lower, Upper} = case Name of <<"thermal">> -> {-273150, 500000}; _ -> {0, 10000000000} end,
    performance_host_number(Source) andalso Sampled =:= min(Source, 4096)
    andalso performance_host_number(Read) andalso Read > 0 andalso performance_host_number(Errors)
    andalso Read + Errors =:= Sampled andalso maps:get(<<"truncated">>, Rest) =:= (Source > Sampled)
    andalso ((Status =:= <<"Available">>) =:= (Errors =:= 0 andalso Source =:= Sampled))
    andalso is_integer(Min) andalso is_integer(Max) andalso is_integer(Avg)
    andalso Min >= Lower andalso Max =< Upper andalso Min =< Avg andalso Avg =< Max.
performance_host_limit(Rest, Key) ->
    case maps:get(<<"unlimited">>, Rest) of
        true -> maps:get(Key, Rest) =:= null;
        false -> performance_host_number(maps:get(Key, Rest));
        _ -> false
    end.
host_deltas(Start, End) ->
    TotalTicks = host_delta(
                   Start, End,
                   [<<"cpu_accounting">>, <<"total_ticks">>]),
    BusyTicks = host_delta(
                  Start, End,
                  [<<"cpu_accounting">>, <<"busy_ticks">>]),
    #{duration_milliseconds =>
          snapshot_integer(End, <<"captured_system_time_milliseconds">>, 0)
          - snapshot_integer(Start,
                             <<"captured_system_time_milliseconds">>, 0),
      cpu_total_ticks => TotalTicks,
      cpu_busy_ticks => BusyTicks,
      cpu_busy_basis_points => cpu_busy_basis_points(BusyTicks, TotalTicks),
      context_switches => host_delta(
          Start, End,
          [<<"cpu_accounting">>, <<"context_switches">>]),
      processes_created => host_delta(
          Start, End,
          [<<"cpu_accounting">>, <<"processes_created">>]),
      cpu_pressure_some_microseconds => pressure_delta(
          Start, End, <<"cpu_pressure">>, <<"some">>),
      cpu_pressure_full_microseconds => pressure_delta(
          Start, End, <<"cpu_pressure">>, <<"full">>),
      memory_pressure_some_microseconds => pressure_delta(
          Start, End, <<"memory_pressure">>, <<"some">>),
      memory_pressure_full_microseconds => pressure_delta(
          Start, End, <<"memory_pressure">>, <<"full">>),
      io_pressure_some_microseconds => pressure_delta(
          Start, End, <<"io_pressure">>, <<"some">>),
      io_pressure_full_microseconds => pressure_delta(
          Start, End, <<"io_pressure">>, <<"full">>),
      cgroup_cpu_usage_microseconds => host_delta(
          Start, End,
          [<<"cgroup_cpu_accounting">>, <<"counters">>, <<"usage_usec">>]),
      cgroup_cpu_throttled_periods => host_delta(
          Start, End,
          [<<"cgroup_cpu_accounting">>, <<"counters">>,
           <<"nr_throttled">>]),
      cgroup_cpu_throttled_microseconds => host_delta(
          Start, End,
          [<<"cgroup_cpu_accounting">>, <<"counters">>,
           <<"throttled_usec">>]),
      memory_available_bytes_change => host_delta(
          Start, End, [<<"memory">>, <<"available_bytes">>]),
      load_1m_milli_start => host_probe_value(
          Start, [<<"load_average">>, <<"load_1m_milli">>]),
      load_1m_milli_end => host_probe_value(
          End, [<<"load_average">>, <<"load_1m_milli">>]),
      cpu_frequency_average_start => host_probe_value(
          Start, [<<"cpu_frequency">>, <<"average">>]),
      cpu_frequency_average_end => host_probe_value(
          End, [<<"cpu_frequency">>, <<"average">>]),
      thermal_maximum_start => host_probe_value(
          Start, [<<"thermal">>, <<"maximum">>]),
      thermal_maximum_end => host_probe_value(
          End, [<<"thermal">>, <<"maximum">>])}.

pressure_delta(Start, End, Probe, Kind) ->
    host_delta(Start, End,
               [Probe, Kind, <<"total_microseconds">>]).

host_delta(Start, End, Path) ->
    case {host_probe_value(Start, Path), host_probe_value(End, Path)} of
        {Before, After} when is_integer(Before), is_integer(After) ->
            After - Before;
        {_, _} -> null
    end.

host_probe_value(Snapshot, Path) ->
    Probes = maps:get(<<"probes">>, Snapshot, #{}),
    nested_value(Probes, Path).

nested_value(Value, []) -> Value;
nested_value(Map, [Key | Rest]) when is_map(Map) ->
    case maps:find(Key, Map) of
        {ok, Value} -> nested_value(Value, Rest);
        error -> null
    end;
nested_value(_Value, _Path) -> null.

cpu_busy_basis_points(Busy, Total)
        when is_integer(Busy), is_integer(Total), Total > 0,
             Busy >= 0, Busy =< Total ->
    Busy * 10000 div Total;
cpu_busy_basis_points(_Busy, _Total) -> null.

snapshot_integer(Snapshot, Key, Default) ->
    case maps:get(Key, Snapshot, Default) of
        Value when is_integer(Value) -> Value;
        _ -> Default
    end.

join_path(Path) ->
    iolist_to_binary(lists:join(<<"/">>, Path)).

-endif.
