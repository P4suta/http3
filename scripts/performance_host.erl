%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_host).
-export([capture/1, self_test/0]).
-define(MAX_PROBE_BYTES, 1048576).
-define(MAX_SENSOR_SOURCES, 4096).
capture(Label) when Label =:= <<"start">>; Label =:= <<"end">> ->
    #{schema => 1, status => <<"Captured">>, label => Label, shareable => false,
      captured_system_time_milliseconds => erlang:system_time(millisecond),
      runtime => runtime_identity(), probes => probes()}.
runtime_identity() ->
    {OsFamily, OsName} = os:type(),
    #{otp_release => list_to_binary(erlang:system_info(otp_release)),
      system_architecture =>
          list_to_binary(erlang:system_info(system_architecture)),
      os_family => atom_to_binary(OsFamily),
      os_name => atom_to_binary(OsName),
      logical_processors => system_info(logical_processors),
      logical_processors_available =>
          system_info(logical_processors_available),
      schedulers_online => system_info(schedulers_online),
      dirty_cpu_schedulers_online => system_info(dirty_cpu_schedulers_online)}.

system_info(Item) ->
    case erlang:system_info(Item) of
        Value when is_integer(Value) -> Value;
        Value when is_atom(Value) -> atom_to_binary(Value)
    end.

probes() ->
    #{load_average =>
          probe_file("/proc/loadavg", fun parse_load_average/1),
      cpu_pressure =>
          probe_file("/proc/pressure/cpu", fun parse_pressure/1),
      memory_pressure =>
          probe_file("/proc/pressure/memory", fun parse_pressure/1),
      io_pressure =>
          probe_file("/proc/pressure/io", fun parse_pressure/1),
      cpu_accounting =>
          probe_file("/proc/stat", fun parse_cpu_accounting/1),
      memory =>
          probe_file("/proc/meminfo", fun parse_memory/1),
      cgroup_cpu_accounting =>
          probe_file("/sys/fs/cgroup/cpu.stat",
                     fun parse_cgroup_cpu_accounting/1),
      cgroup_cpu_limit =>
          probe_file("/sys/fs/cgroup/cpu.max", fun parse_cgroup_cpu_limit/1),
      cgroup_memory_current =>
          probe_file("/sys/fs/cgroup/memory.current",
                     fun parse_scalar_limit/1),
      cgroup_memory_peak =>
          probe_file("/sys/fs/cgroup/memory.peak", fun parse_scalar_limit/1),
      cgroup_memory_limit =>
          probe_file("/sys/fs/cgroup/memory.max", fun parse_scalar_limit/1),
      cgroup_memory_events =>
          probe_file("/sys/fs/cgroup/memory.events",
                     fun parse_cgroup_memory_events/1),
      cpu_frequency =>
          probe_integer_files(
            "/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq",
            0, 10000000000),
      thermal =>
          probe_integer_files("/sys/class/thermal/thermal_zone*/temp",
                              -273150, 500000)}.

probe_file(Path, Parser) ->
    probe_read(read_probe_file(Path), Parser).

read_probe_file(Path) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, File} ->
            try file:read(File, ?MAX_PROBE_BYTES + 1) of
                eof -> {ok, <<>>};
                Result -> Result
            after file:close(File) end;
        {error, Reason} -> {error, Reason}
    end.

probe_read(Result, Parser) ->
    case Result of
        {ok, Bytes} when byte_size(Bytes) =< ?MAX_PROBE_BYTES ->
            try Parser(Bytes) of
                Values when is_map(Values) ->
                    maps:put(status, <<"Available">>, Values)
            catch
                _Class:Reason ->
                    #{status => <<"Invalid">>,
                      reason => reason_category(Reason)}
            end;
        {ok, Bytes} ->
            #{status => <<"Invalid">>, reason => <<"probe_too_large">>,
              observed_bytes => byte_size(Bytes),
              maximum_bytes => ?MAX_PROBE_BYTES};
        {error, Reason} ->
            #{status => <<"Unavailable">>,
              reason => reason_category(Reason)}
    end.

probe_integer_files(Pattern, Minimum, Maximum) ->
    Paths = lists:sort(filelib:wildcard(Pattern)),
    case Paths of
        [] ->
            #{status => <<"Unavailable">>, reason => <<"no_sources">>};
        _ ->
            Selected = lists:sublist(Paths, ?MAX_SENSOR_SOURCES),
            {Values, Errors} = lists:foldl(
              fun(Path, {Found, Failed}) ->
                  case read_bounded_integer(Path, Minimum, Maximum) of
                      {ok, Value} -> {[Value | Found], Failed};
                      error -> {Found, Failed + 1}
                  end
              end,
              {[], 0}, Selected),
            aggregate_probe(Paths, Selected, Values, Errors)
    end.

aggregate_probe(Paths, Selected, [], Errors) ->
    #{status => <<"Unavailable">>, reason => <<"no_readable_sources">>,
      source_count => length(Paths), sampled_source_count => length(Selected),
      error_count => Errors,
      truncated => length(Paths) > length(Selected)};
aggregate_probe(Paths, Selected, Values, Errors) ->
    Count = length(Values),
    Status = case Errors =:= 0 andalso length(Paths) =:= length(Selected) of
        true -> <<"Available">>;
        false -> <<"Partial">>
    end,
    #{status => Status, source_count => length(Paths),
      sampled_source_count => length(Selected), readable_count => Count,
      error_count => Errors, truncated => length(Paths) > length(Selected),
      minimum => lists:min(Values), maximum => lists:max(Values),
      average => lists:sum(Values) div Count}.

read_bounded_integer(Path, Minimum, Maximum) ->
    case file:read_file(Path) of
        {ok, Bytes} when byte_size(Bytes) =< 128 ->
            try binary_to_integer(trim(Bytes)) of
                Value when Value >= Minimum, Value =< Maximum -> {ok, Value};
                _ -> error
            catch
                error:badarg -> error
            end;
        _ -> error
    end.

parse_load_average(Bytes) ->
    case tokens(Bytes) of
        [One, Five, Fifteen, RunnableAndEntities | _] ->
            [Runnable, Entities] =
                binary:split(RunnableAndEntities, <<"/">>, [global]),
            #{load_1m_milli => decimal_scaled(One, 3),
              load_5m_milli => decimal_scaled(Five, 3),
              load_15m_milli => decimal_scaled(Fifteen, 3),
              runnable_entities => nonnegative(Runnable),
              total_entities => positive(Entities)};
        _ -> erlang:error(invalid_load_average)
    end.

parse_pressure(Bytes) ->
    Lines = nonempty_lines(Bytes),
    Parsed = lists:foldl(fun parse_pressure_line/2, #{}, Lines),
    ensure(maps:is_key(<<"some">>, Parsed), missing_pressure_some),
    Parsed.

parse_pressure_line(Line, Accumulator) ->
    case tokens(Line) of
        [Level | Fields] when Level =:= <<"some">>; Level =:= <<"full">> ->
            Values = key_value_fields(Fields),
            Statistics =
                #{avg10_basis_points =>
                      decimal_scaled(maps:get(<<"avg10">>, Values), 2),
                  avg60_basis_points =>
                      decimal_scaled(maps:get(<<"avg60">>, Values), 2),
                  avg300_basis_points =>
                      decimal_scaled(maps:get(<<"avg300">>, Values), 2),
                  total_microseconds =>
                      nonnegative(maps:get(<<"total">>, Values))},
            maps:put(Level, Statistics, Accumulator);
        _ -> erlang:error(invalid_pressure_line)
    end.

parse_cpu_accounting(Bytes) ->
    Lines = nonempty_lines(Bytes),
    CpuLines = [Line || Line <- Lines,
                        binary:match(Line, <<"cpu ">>) =:= {0, 4}],
    [CpuLine] = CpuLines,
    [<<"cpu">> | CounterFields] = tokens(CpuLine),
    ensure(length(CounterFields) >= 8, incomplete_cpu_accounting),
    [User, Nice, System, Idle, IoWait, Irq, SoftIrq, Steal] =
        [nonnegative(Field) || Field <- lists:sublist(CounterFields, 8)],
    IdleTotal = Idle + IoWait,
    Busy = User + Nice + System + Irq + SoftIrq + Steal,
    #{total_ticks => Busy + IdleTotal, busy_ticks => Busy,
      idle_ticks => IdleTotal, user_ticks => User, nice_ticks => Nice,
      system_ticks => System, io_wait_ticks => IoWait, irq_ticks => Irq,
      soft_irq_ticks => SoftIrq, steal_ticks => Steal,
      context_switches => scalar_line(<<"ctxt">>, Lines),
      processes_created => scalar_line(<<"processes">>, Lines),
      processes_running => scalar_line(<<"procs_running">>, Lines),
      processes_blocked => scalar_line(<<"procs_blocked">>, Lines)}.

scalar_line(Name, Lines) ->
    Matches = [Value || Line <- Lines,
                        [Key, Value] <- [tokens(Line)], Key =:= Name],
    case Matches of
        [Value] -> nonnegative(Value);
        _ -> erlang:error({invalid_scalar_line, Name})
    end.

parse_memory(Bytes) ->
    Values = lists:foldl(fun parse_memory_line/2, #{}, nonempty_lines(Bytes)),
    Required = [<<"MemTotal">>, <<"MemFree">>, <<"MemAvailable">>,
                <<"Buffers">>, <<"Cached">>, <<"SwapTotal">>,
                <<"SwapFree">>],
    lists:foldl(fun(Key, Accumulator) ->
        maps:put(memory_key(Key), maps:get(Key, Values) * 1024, Accumulator)
    end, #{}, Required).

parse_memory_line(Line, Accumulator) ->
    case binary:split(Line, <<":">>, [global]) of
        [Key, Rest] ->
            case tokens(Rest) of
                [Value, <<"kB">>] ->
                    maps:put(Key, nonnegative(Value), Accumulator);
                [Value] ->
                    maps:put(Key, nonnegative(Value), Accumulator);
                _ -> Accumulator
            end;
        _ -> Accumulator
    end.

memory_key(<<"MemTotal">>) -> total_bytes;
memory_key(<<"MemFree">>) -> free_bytes;
memory_key(<<"MemAvailable">>) -> available_bytes;
memory_key(<<"Buffers">>) -> buffers_bytes;
memory_key(<<"Cached">>) -> cached_bytes;
memory_key(<<"SwapTotal">>) -> swap_total_bytes;
memory_key(<<"SwapFree">>) -> swap_free_bytes.

parse_cgroup_cpu_accounting(Bytes) ->
    Values = line_key_values(Bytes),
    Required = [<<"usage_usec">>, <<"user_usec">>, <<"system_usec">>],
    lists:foreach(fun(Key) -> maps:get(Key, Values) end, Required),
    Optional = [<<"nr_periods">>, <<"nr_throttled">>,
                <<"throttled_usec">>, <<"nr_bursts">>, <<"burst_usec">>],
    #{counters => select_keys(Required ++ Optional, Values)}.

parse_cgroup_memory_events(Bytes) ->
    Values = line_key_values(Bytes),
    #{counters => select_keys(
        [<<"low">>, <<"high">>, <<"max">>, <<"oom">>, <<"oom_kill">>,
         <<"oom_group_kill">>], Values)}.

line_key_values(Bytes) ->
    lists:foldl(fun(Line, Accumulator) ->
        case tokens(Line) of
            [Key, Value] -> maps:put(Key, nonnegative(Value), Accumulator);
            _ -> erlang:error(invalid_key_value_line)
        end
    end, #{}, nonempty_lines(Bytes)).

select_keys(Keys, Values) ->
    lists:foldl(fun(Key, Accumulator) ->
        case maps:find(Key, Values) of
            {ok, Value} -> maps:put(Key, Value, Accumulator);
            error -> Accumulator
        end
    end, #{}, Keys).

parse_cgroup_cpu_limit(Bytes) ->
    case tokens(Bytes) of
        [<<"max">>, Period] ->
            #{unlimited => true, quota_microseconds => null,
              period_microseconds => positive(Period)};
        [Quota, Period] ->
            #{unlimited => false, quota_microseconds => positive(Quota),
              period_microseconds => positive(Period)};
        _ -> erlang:error(invalid_cgroup_cpu_limit)
    end.

parse_scalar_limit(Bytes) ->
    case trim(Bytes) of
        <<"max">> -> #{unlimited => true, value => null};
        Value -> #{unlimited => false, value => nonnegative(Value)}
    end.

key_value_fields(Fields) ->
    lists:foldl(fun(Field, Accumulator) ->
        case binary:split(Field, <<"=">>, [global]) of
            [Key, Value] -> maps:put(Key, Value, Accumulator);
            _ -> erlang:error(invalid_key_value_field)
        end
    end, #{}, Fields).

decimal_scaled(Value, FractionDigits) ->
    case binary:split(Value, <<".">>, [global]) of
        [Whole] -> nonnegative(Whole) * power10(FractionDigits);
        [Whole, Fraction] ->
            ensure(byte_size(Fraction) =< FractionDigits,
                   excessive_decimal_precision),
            Padding = binary:copy(<<"0">>, FractionDigits - byte_size(Fraction)),
            nonnegative(Whole) * power10(FractionDigits)
            + nonnegative(<<Fraction/binary, Padding/binary>>);
        _ -> erlang:error(invalid_decimal)
    end.

power10(0) -> 1;
power10(Count) when Count > 0 -> 10 * power10(Count - 1).

positive(Value) ->
    Parsed = nonnegative(Value),
    ensure(Parsed > 0, expected_positive_integer),
    Parsed.

nonnegative(Value) ->
    try binary_to_integer(Value) of
        Parsed when Parsed >= 0 -> Parsed;
        _ -> erlang:error(expected_nonnegative_integer)
    catch
        error:badarg -> erlang:error(expected_integer)
    end.

tokens(Bytes) ->
    [list_to_binary(Token)
     || Token <- string:lexemes(binary_to_list(Bytes), " \t\r\n")].

nonempty_lines(Bytes) ->
    [trim(Line) || Line <- binary:split(Bytes, <<"\n">>, [global]),
                   trim(Line) =/= <<>>].

trim(Bytes) ->
    list_to_binary(string:trim(binary_to_list(Bytes))).

reason_category(Reason) when Reason =:= enoent; Reason =:= enotdir;
                             Reason =:= eacces; Reason =:= eperm;
                             Reason =:= enotsup; Reason =:= einval;
                             Reason =:= eio; Reason =:= emfile;
                             Reason =:= enfile -> atom_to_binary(Reason);
reason_category(badarg) -> <<"invalid_value">>;
reason_category({badmatch, _}) -> <<"invalid_shape">>;
reason_category(function_clause) -> <<"invalid_shape">>;
reason_category({badkey, _}) -> <<"missing_counter">>;
reason_category(_) -> <<"probe_error">>.

self_test() ->
    PrivateReason = performance_probe_private_reason_fixture,
    SafeReason = reason_category({PrivateReason, <<"private probe payload">>}),
    true = SafeReason =:= <<"probe_error">>,
    bounded_probe_read_self_test(),
    Load = parse_load_average(<<"2.25 5.86 6.43 3/512 999\n">>),
    ensure(maps:get(load_1m_milli, Load) =:= 2250, load_one),
    ensure(maps:get(runnable_entities, Load) =:= 3, load_runnable),
    Pressure = parse_pressure(
      <<"some avg10=5.26 avg60=5.10 avg300=14.34 total=12345\n"
        "full avg10=0.01 avg60=0.02 avg300=0.03 total=44\n">>),
    Some = maps:get(<<"some">>, Pressure),
    ensure(maps:get(avg10_basis_points, Some) =:= 526, pressure_average),
    ensure(maps:get(total_microseconds, Some) =:= 12345, pressure_total),
    Cpu = parse_cpu_accounting(
      <<"cpu  10 2 3 20 5 1 2 4 0 0\nctxt 100\nprocesses 7\n"
        "procs_running 2\nprocs_blocked 1\n">>),
    ensure(maps:get(busy_ticks, Cpu) =:= 22, cpu_busy),
    ensure(maps:get(total_ticks, Cpu) =:= 47, cpu_total),
    Memory = parse_memory(
      <<"MemTotal: 100 kB\nMemFree: 10 kB\nMemAvailable: 30 kB\n"
        "Buffers: 2 kB\nCached: 4 kB\nSwapTotal: 8 kB\n"
        "SwapFree: 6 kB\n">>),
    ensure(maps:get(available_bytes, Memory) =:= 30720, memory_available),
    Cgroup = parse_cgroup_cpu_accounting(
      <<"usage_usec 20\nuser_usec 12\nsystem_usec 8\nnr_periods 3\n"
        "nr_throttled 1\nthrottled_usec 4\n">>),
    ensure(maps:get(<<"nr_throttled">>, maps:get(counters, Cgroup)) =:= 1,
           cgroup_throttled),
    #{unlimited := true, quota_microseconds := null,
      period_microseconds := 100000} =
        parse_cgroup_cpu_limit(<<"max 100000\n">>),
    #{unlimited := false, value := 4096} = parse_scalar_limit(<<"4096\n">>),
    Missing = probe_file(
      "/definitely-not-a-real-http3-performance-probe",
      fun parse_load_average/1),
    ensure(maps:get(status, Missing) =:= <<"Unavailable">>, unavailable_probe),
    Invalid = probe_read({ok, <<"synthetic-probe-value">>}, fun(_Bytes) ->
        erlang:error(deliberate_parser_failure)
    end),
    ensure(maps:get(status, Invalid) =:= <<"Invalid">>, invalid_probe),
    ensure(maps:get(reason, Invalid) =:= <<"probe_error">>,
           bounded_invalid_reason),
    io:put_chars(
      "host snapshot self-test: bounded numeric parsers and absence states ok\n"),
    ok.

bounded_probe_read_self_test() ->
    Directory = filename:join("build/host-probe-self-test",
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(12)))),
    Path = filename:join(Directory, "oversized"),
    ok = filelib:ensure_dir(Path),
    try
        ok = file:write_file(Path, binary:copy(<<0>>, ?MAX_PROBE_BYTES * 2)),
        Result = probe_file(Path, fun(_) -> erlang:error(parser_must_not_run) end),
        ReadBounded = maps:get(observed_bytes, Result) =:= ?MAX_PROBE_BYTES + 1,
        io:format("host_probe read_bounded=~p~n", [ReadBounded]),
        ensure(ReadBounded, unbounded_probe_read),
        ensure(maps:get(reason, Result) =:= <<"probe_too_large">>, oversized_probe_reason)
    after file:delete(Path), file:del_dir(Directory) end.

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
