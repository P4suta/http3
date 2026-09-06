#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% This reporter deliberately revalidates every value emitted by the live
%% fixture.  The raw fixture is useful diagnostic data, but it is not
%% qualification evidence until its configuration, topology, counters, and
%% source digest have all been checked here.

-define(PROFILE_PATH, "standards/performance-profile.json").
-define(OUTPUT_PATH, "build/performance/current/idle-wakeup.json").
-define(RAW_PATH, "build/performance/current/idle-wakeup.raw.json").
-define(LOG_PATH, "build/performance/current/idle-wakeup.log").
-define(MAXIMUM_INPUT_BYTES, 1048576).
-define(MAXIMUM_LOG_BYTES, 16777216).

main(["--self-test"]) ->
    guarded_self_test();
main([ExitStatus, RawEvidencePath, LogPath]) ->
    guarded_run(ExitStatus, RawEvidencePath, LogPath);
main(_) ->
    erlang:error({usage, "[--self-test] | EXIT_STATUS RAW_EVIDENCE LOG"}).

guarded_self_test() ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "idle-wakeup reporter self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

guarded_run(ExitStatusText, RawEvidencePath, LogPath) ->
    try run(ExitStatusText, RawEvidencePath, LogPath) of
        ok -> ok;
        {failed, Violations} ->
            io:format(standard_error,
                      "idle-wakeup evidence failed: ~p~n", [Violations]),
            halt(1)
    catch
        Class:Reason:Stacktrace ->
            _ = try write_emergency_report(LogPath, Class, Reason) of
                ok -> ok
            catch
                _:_ -> emergency_report_unavailable
            end,
            io:format(standard_error,
                      "idle-wakeup reporter failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(ExitStatusText, RawEvidencePath, LogPath) ->
    ensure(RawEvidencePath =:= ?RAW_PATH,
           unexpected_idle_wakeup_raw_evidence_path),
    ensure(LogPath =:= ?LOG_PATH, unexpected_idle_wakeup_log_path),
    ExitStatus = parse_nonnegative(ExitStatusText),
    ProfileBytes = read_bounded(?PROFILE_PATH, ?MAXIMUM_INPUT_BYTES),
    Profile = decode_map(ProfileBytes, invalid_performance_profile),
    EvidenceProfile = maps:get(<<"performance_evidence">>, Profile),
    Idle = validate_profile(Profile, EvidenceProfile),
    RawBytes = read_bounded(RawEvidencePath, ?MAXIMUM_INPUT_BYTES),
    Raw = decode_map(RawBytes, invalid_idle_wakeup_fixture),
    Log = read_bounded(LogPath, ?MAXIMUM_LOG_BYTES),
    Violations = validate_run(ExitStatus, Raw, Idle),
    Status = case Violations of [] -> <<"Ready">>; _ -> <<"Failed">> end,
    Report =
        #{schema => maps:get(<<"report_schema">>, EvidenceProfile),
          status => Status,
          kind => <<"idle-wakeup">>,
          shareable => true,
          redacted => true,
          baseline_date => maps:get(<<"baseline_date">>, Profile),
          profile_sha256 => hex(crypto:hash(sha256, ProfileBytes)),
          source_sha256 => source_digest(EvidenceProfile),
          otp_release => list_to_binary(erlang:system_info(otp_release)),
          system_architecture => list_to_binary(
                                   erlang:system_info(system_architecture)),
          exit_status => ExitStatus,
          configuration => Idle,
          satisfies => maps:get(<<"satisfies">>, Idle),
          raw_fixture =>
              #{path => list_to_binary(RawEvidencePath),
                bytes => byte_size(RawBytes),
                sha256 => hex(crypto:hash(sha256, RawBytes)),
                content_included => true,
                shareable => true},
          log => log_evidence(Log, LogPath),
          evidence => Raw,
          violations => Violations},
    write_report(Report),
    case Violations of
        [] ->
            io:format(
              "idle-wakeup evidence: ~B actors, ~B ms observation, "
              "~B deadline timeouts~n",
              [maps:get(<<"expected_actor_count">>, Raw),
               maps:get(<<"observation_milliseconds">>, Raw),
               maps:get(<<"deadline_timeout_returns">>, Raw)]),
            ok;
        _ -> {failed, Violations}
    end.

validate_profile(Profile, Evidence) ->
    ensure(maps:get(<<"baseline_date">>, Profile) =:= <<"2026-08-30">>,
           unexpected_performance_baseline),
    ensure(maps:get(<<"report_schema">>, Evidence) =:= 3,
           unsupported_performance_report_schema),
    Idle = maps:get(<<"idle_wakeup">>, Evidence),
    ensure(is_map(Idle), invalid_idle_wakeup_profile),
    ensure(maps:get(<<"fixture_schema">>, Idle) =:= 2,
           unsupported_idle_wakeup_fixture_schema),
    ensure(maps:get(<<"artifact">>, Idle) =:= <<?OUTPUT_PATH>>,
           unexpected_idle_wakeup_artifact),
    ensure(maps:get(<<"raw_artifact">>, Idle) =:= <<?RAW_PATH>>,
           unexpected_idle_wakeup_raw_artifact),
    ensure(maps:get(<<"log_artifact">>, Idle) =:= <<?LOG_PATH>>,
           unexpected_idle_wakeup_log_artifact),
    ensure(maps:get(<<"minimum_observation_milliseconds">>, Idle) =:= 2500,
           weakened_idle_observation),
    ensure(maps:get(<<"expected_actor_count">>, Idle) =:= 8,
           idle_actor_count_drift),
    ensure(maps:get(<<"quiescence_required_stable_samples">>, Idle) =:= 5,
           weakened_idle_quiescence_samples),
    ensure(maps:get(<<"quiescence_poll_milliseconds">>, Idle) =:= 100,
           idle_quiescence_poll_drift),
    ensure(maps:get(<<"quiescence_maximum_attempts">>, Idle) =:= 80,
           weakened_idle_quiescence_attempts),
    ensure(maps:get(<<"maximum_quiescence_milliseconds">>, Idle) =:= 8000,
           weakened_idle_quiescence_bound),
    ensure(maps:get(<<"maximum_quiescence_milliseconds">>, Idle)
           =:= maps:get(<<"quiescence_poll_milliseconds">>, Idle)
               * maps:get(<<"quiescence_maximum_attempts">>, Idle),
           inconsistent_idle_quiescence_bound),
    ensure(maps:get(<<"trace_primitive">>, Idle)
           =:= <<"gleam_erlang_ffi:select/1,2">>,
           idle_trace_primitive_drift),
    Roles = maps:get(<<"required_roles">>, Idle),
    ensure(Roles =:= expected_roles(), idle_role_topology_drift),
    ensure(unique(Roles), duplicate_idle_roles),
    LivenessRoles = maps:get(<<"required_liveness_roles">>, Idle),
    ensure(LivenessRoles =:= expected_liveness_roles(),
           idle_liveness_role_drift),
    ensure(unique(LivenessRoles), duplicate_idle_liveness_roles),
    ensure(missing(LivenessRoles, Roles) =:= [], unknown_idle_liveness_role),
    Satisfies = maps:get(<<"satisfies">>, Idle),
    ensure(Satisfies =:= [<<"idle-periodic-wakeup-zero">>],
           idle_satisfaction_drift),
    ensure(missing(Satisfies,
                   maps:get(<<"required_resource_assertions">>, Profile))
           =:= [], unknown_idle_satisfaction),
    SourceFiles = maps:get(<<"source_files">>, Evidence),
    SourceRoots = maps:get(<<"production_source_roots">>, Evidence),
    ensure(SourceFiles =/= [] andalso unique(SourceFiles),
           invalid_performance_source_files),
    ensure(SourceRoots =/= [] andalso unique(SourceRoots),
           invalid_performance_source_roots),
    Idle.

validate_run(ExitStatus, Raw, Idle) ->
    problem(ExitStatus =/= 0, <<"workload-exit-status">>,
            #{expected => 0, observed => ExitStatus})
    ++ validate_evidence(Raw, Idle).

validate_evidence(Raw, Idle) when is_map(Raw) ->
    Roles = maps:get(<<"roles">>, Raw, invalid),
    lists:append([
        equal_problem(Raw, <<"schema">>, maps:get(<<"fixture_schema">>, Idle),
                      <<"fixture-schema">>),
        equal_problem(Raw, <<"status">>, <<"Ready">>,
                      <<"fixture-status">>),
        equal_problem(Raw, <<"shareable">>, true,
                      <<"fixture-shareability">>),
        equal_problem(Raw, <<"redacted">>, true,
                      <<"fixture-redaction">>),
        equal_problem(Raw, <<"quiescence_confirmed">>, true,
                      <<"quiescence-not-confirmed">>),
        equal_problem(
          Raw, <<"quiescence_required_stable_samples">>,
          maps:get(<<"quiescence_required_stable_samples">>, Idle),
          <<"quiescence-sample-configuration">>),
        equal_problem(
          Raw, <<"quiescence_poll_milliseconds">>,
          maps:get(<<"quiescence_poll_milliseconds">>, Idle),
          <<"quiescence-poll-configuration">>),
        equal_problem(
          Raw, <<"quiescence_maximum_attempts">>,
          maps:get(<<"quiescence_maximum_attempts">>, Idle),
          <<"quiescence-attempt-configuration">>),
        bounded_integer_problem(
          Raw, <<"quiescence_milliseconds">>, 0,
          maps:get(<<"maximum_quiescence_milliseconds">>, Idle),
          <<"quiescence-duration">>),
        equal_problem(
          Raw, <<"minimum_observation_milliseconds">>,
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
          <<"observation-configuration">>),
        minimum_integer_problem(
          Raw, <<"observation_milliseconds">>,
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
          <<"observation-duration">>),
        equal_problem(Raw, <<"actor_set_stable">>, true,
                      <<"actor-set-stability">>),
        equal_problem(Raw, <<"expected_actor_count">>,
                      maps:get(<<"expected_actor_count">>, Idle),
                      <<"actor-count">>),
        equal_problem(Raw, <<"deadline_timeout_returns">>, 0,
                      <<"deadline-timeout-returns">>),
        equal_problem(Raw, <<"unexpected_actor_exits">>, 0,
                      <<"unexpected-actor-exits">>),
        equal_problem(Raw, <<"required_actor_liveness">>, true,
                      <<"required-actor-liveness">>),
        equal_problem(Raw, <<"trace_synchronized">>, true,
                      <<"trace-synchronization">>),
        equal_problem(Raw, <<"trace_primitive">>,
                      maps:get(<<"trace_primitive">>, Idle),
                      <<"trace-primitive">>),
        validate_roles(Roles, Idle),
        global_timeout_problem(Raw, Roles)
    ]);
validate_evidence(_Raw, _Idle) ->
    [violation(<<"fixture-shape">>, #{})].

validate_roles(Roles, Idle) when is_list(Roles) ->
    Labels = [maps:get(<<"label">>, Role, invalid)
              || Role <- Roles, is_map(Role)],
    ShapeProblems =
        problem(length(Labels) =/= length(Roles), <<"role-shape">>, #{})
        ++ problem(Labels =/= maps:get(<<"required_roles">>, Idle),
                   <<"role-topology">>,
                   #{expected => maps:get(<<"required_roles">>, Idle),
                     observed => Labels})
        ++ problem(not unique(Labels), <<"duplicate-role">>, #{}),
    ShapeProblems
    ++ lists:append([validate_role(Role, Idle)
                     || Role <- Roles, is_map(Role)]);
validate_roles(_Roles, _Idle) ->
    [violation(<<"roles-shape">>, #{})].

validate_role(Role, Idle) ->
    Label = maps:get(<<"label">>, Role, <<"unknown">>),
    NumericKeys = role_numeric_keys(),
    InvalidNumbers = [Key || Key <- NumericKeys,
                             not nonnegative_map_integer(Role, Key)],
    TimedCalls = integer_or_negative(Role, <<"timed_wait_calls">>),
    WaitClasses = sum_keys(
      Role,
      [<<"wait_zero_calls">>, <<"wait_short_calls">>,
       <<"wait_second_calls">>, <<"wait_long_calls">>]),
    TimeoutReturns = integer_or_negative(Role, <<"deadline_timeout_returns">>),
    TimeoutClasses = sum_keys(
      Role,
      [<<"timeout_zero_returns">>, <<"timeout_short_returns">>,
       <<"timeout_second_returns">>, <<"timeout_long_returns">>,
       <<"timeout_unclassified_returns">>]),
    LivenessRequired = lists:member(
                         Label, maps:get(<<"required_liveness_roles">>, Idle)),
    MessageReturns = integer_or_negative(Role, <<"timed_message_returns">>)
                     + integer_or_negative(
                         Role, <<"unbounded_message_returns">>),
    lists:append([
        problem(InvalidNumbers =/= [], <<"role-counter-shape">>,
                #{role => Label, invalid => InvalidNumbers}),
        role_equal_problem(Role, Label, <<"expected_actors">>, 1,
                           <<"role-expected-count">>),
        role_equal_problem(Role, Label, <<"actors_start">>, 1,
                           <<"role-start-count">>),
        role_equal_problem(Role, Label, <<"actors_end">>, 1,
                           <<"role-end-count">>),
        role_equal_problem(Role, Label, <<"deadline_timeout_returns">>, 0,
                           <<"role-deadline-timeout">>),
        problem(TimedCalls =/= WaitClasses, <<"timed-wait-class-sum">>,
                #{role => Label, calls => TimedCalls,
                  class_sum => WaitClasses}),
        problem(TimeoutReturns =/= TimeoutClasses,
                <<"timeout-class-sum">>,
                #{role => Label, returns => TimeoutReturns,
                  class_sum => TimeoutClasses}),
        problem(integer_or_negative(Role, <<"timed_boundary_message_returns">>)
                > integer_or_negative(Role, <<"expected_actors">>),
                <<"timed-boundary-return-bound">>, #{role => Label}),
        problem(integer_or_negative(Role, <<"timed_message_returns">>)
                > TimedCalls
                    + integer_or_negative(
                        Role, <<"timed_boundary_message_returns">>),
                <<"timed-return-without-call">>, #{role => Label}),
        problem(
          integer_or_negative(
            Role, <<"unbounded_boundary_message_returns">>)
          > integer_or_negative(Role, <<"expected_actors">>),
          <<"unbounded-boundary-return-bound">>, #{role => Label}),
        problem(integer_or_negative(Role, <<"unbounded_message_returns">>)
                > integer_or_negative(Role, <<"unbounded_wait_calls">>)
                    + integer_or_negative(
                        Role, <<"unbounded_boundary_message_returns">>),
                <<"unbounded-return-without-call">>, #{role => Label}),
        problem(LivenessRequired andalso MessageReturns =< 0,
                <<"role-liveness">>, #{role => Label})
    ]).

global_timeout_problem(Raw, Roles) when is_list(Roles) ->
    ValidRoles = [Role || Role <- Roles, is_map(Role)],
    RowTotal = lists:sum([
        erlang:max(0, integer_or_negative(Role, <<"deadline_timeout_returns">>))
        || Role <- ValidRoles
    ]),
    Global = maps:get(<<"deadline_timeout_returns">>, Raw, invalid),
    problem(not is_integer(Global) orelse Global =/= RowTotal,
            <<"global-timeout-sum">>,
            #{observed => json_value(Global), row_sum => RowTotal});
global_timeout_problem(_Raw, _Roles) -> [].

role_numeric_keys() ->
    [<<"expected_actors">>, <<"actors_start">>, <<"actors_end">>,
     <<"timed_wait_calls">>, <<"timed_message_returns">>,
     <<"timed_boundary_message_returns">>,
     <<"deadline_timeout_returns">>, <<"wait_zero_calls">>,
     <<"wait_short_calls">>, <<"wait_second_calls">>,
     <<"wait_long_calls">>, <<"timeout_zero_returns">>,
     <<"timeout_short_returns">>, <<"timeout_second_returns">>,
     <<"timeout_long_returns">>, <<"timeout_unclassified_returns">>,
     <<"unbounded_wait_calls">>, <<"unbounded_message_returns">>,
     <<"unbounded_boundary_message_returns">>].

equal_problem(Map, Key, Expected, Id) ->
    Observed = maps:get(Key, Map, invalid),
    problem(Observed =/= Expected, Id,
            #{expected => Expected, observed => json_value(Observed)}).

role_equal_problem(Role, Label, Key, Expected, Id) ->
    Observed = maps:get(Key, Role, invalid),
    problem(Observed =/= Expected, Id,
            #{role => Label, expected => Expected,
              observed => json_value(Observed)}).

bounded_integer_problem(Map, Key, Minimum, Maximum, Id) ->
    Value = maps:get(Key, Map, invalid),
    problem(not is_integer(Value) orelse Value < Minimum orelse Value > Maximum,
            Id, #{minimum => Minimum, maximum => Maximum,
                  observed => json_value(Value)}).

minimum_integer_problem(Map, Key, Minimum, Id) ->
    Value = maps:get(Key, Map, invalid),
    problem(not is_integer(Value) orelse Value < Minimum,
            Id, #{minimum => Minimum, observed => json_value(Value)}).

sum_keys(Map, Keys) ->
    lists:sum([erlang:max(0, integer_or_negative(Map, Key)) || Key <- Keys]).

integer_or_negative(Map, Key) ->
    case maps:get(Key, Map, invalid) of
        Value when is_integer(Value), Value >= 0 -> Value;
        _ -> -1
    end.

nonnegative_map_integer(Map, Key) ->
    case maps:get(Key, Map, invalid) of
        Value when is_integer(Value), Value >= 0 -> true;
        _ -> false
    end.

log_evidence(Log, LogPath) ->
    #{path => list_to_binary(LogPath),
      bytes => byte_size(Log),
      sha256 => hex(crypto:hash(sha256, Log)),
      content_included => false,
      shareable => false}.

source_digest(Evidence) ->
    Explicit = [binary_to_list(Path)
                || Path <- maps:get(<<"source_files">>, Evidence)],
    Roots = [binary_to_list(Path)
             || Path <- maps:get(<<"production_source_roots">>, Evidence)],
    Production = lists:append([
        filelib:fold_files(Root, ".*\\.(gleam|erl|hrl)$", true,
                           fun(Path, Paths) -> [Path | Paths] end, [])
        || Root <- Roots
    ]),
    Paths = lists:usort(Explicit ++ Production),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

write_report(Report) ->
    ok = filelib:ensure_dir(?OUTPUT_PATH),
    ok = file:write_file(?OUTPUT_PATH, [json:encode(Report), <<"\n">>]).

write_emergency_report(LogPath, Class, Reason) ->
    Report =
        #{schema => 3,
          status => <<"Failed">>,
          kind => <<"idle-wakeup">>,
          shareable => true,
          redacted => true,
          log => safe_log_evidence(LogPath),
          reporter_error =>
              #{class => safe_atom(Class), reason => reason_tag(Reason),
                detail_included => false},
          violations => [violation(<<"reporter-failure">>, #{})]},
    write_report(Report).

safe_log_evidence(?LOG_PATH = LogPath) ->
    case filelib:file_size(LogPath) of
        Size when is_integer(Size), Size >= 0, Size =< ?MAXIMUM_LOG_BYTES ->
            case file:read_file(LogPath) of
                {ok, Bytes} -> log_evidence(Bytes, LogPath);
                {error, Reason} ->
                    #{path => <<?LOG_PATH>>, content_included => false,
                      status => <<"Unavailable">>, reason => safe_atom(Reason)}
            end;
        Size when is_integer(Size), Size > ?MAXIMUM_LOG_BYTES ->
            #{path => <<?LOG_PATH>>, bytes => Size, content_included => false,
              status => <<"TooLarge">>};
        _ ->
            #{path => <<?LOG_PATH>>, content_included => false,
              status => <<"Unavailable">>}
    end;
safe_log_evidence(_UnexpectedPath) ->
    #{path => <<?LOG_PATH>>, content_included => false,
      status => <<"Unavailable">>, reason => <<"unexpected-path">>}.

self_test() ->
    ProfileBytes = read_bounded(?PROFILE_PATH, ?MAXIMUM_INPUT_BYTES),
    Profile = decode_map(ProfileBytes, invalid_performance_profile),
    EvidenceProfile = maps:get(<<"performance_evidence">>, Profile),
    Idle = validate_profile(Profile, EvidenceProfile),
    Good = fixture_evidence(Idle),
    [] = validate_run(0, Good, Idle),
    expect_violation(validate_run(7, Good, Idle),
                     <<"workload-exit-status">>),
    expect_violation(
      validate_run(0, Good#{<<"deadline_timeout_returns">> := 1}, Idle),
      <<"deadline-timeout-returns">>),
    Roles = maps:get(<<"roles">>, Good),
    expect_violation(
      validate_run(0, Good#{<<"roles">> := lists:droplast(Roles)}, Idle),
      <<"role-topology">>),
    expect_violation(
      validate_run(
        0,
        Good#{<<"quiescence_required_stable_samples">> := 4},
        Idle),
      <<"quiescence-sample-configuration">>),
    expect_violation(
      validate_run(0, Good#{<<"quiescence_milliseconds">> := 8001}, Idle),
      <<"quiescence-duration">>),
    expect_violation(
      validate_run(0, Good#{<<"observation_milliseconds">> := 2499}, Idle),
      <<"observation-duration">>),
    [FirstRole | RemainingRoles] = Roles,
    NegativeRole = FirstRole#{<<"timed_wait_calls">> := -1},
    expect_violation(
      validate_run(0, Good#{<<"roles">> :=
                                [NegativeRole | RemainingRoles]}, Idle),
      <<"role-counter-shape">>),
    InconsistentRole = FirstRole#{<<"timed_wait_calls">> := 2},
    expect_violation(
      validate_run(0, Good#{<<"roles">> :=
                                [InconsistentRole | RemainingRoles]}, Idle),
      <<"timed-wait-class-sum">>),
    expect_violation(
      validate_run(0, Good#{<<"trace_synchronized">> := false}, Idle),
      <<"trace-synchronization">>),
    ensure(valid_digest(source_digest(EvidenceProfile)),
           idle_source_digest_shape),
    io:put_chars(
      "idle-wakeup reporter self-test: configuration, topology, timing, "
      "counter, and staleness inputs pinned\n"),
    ok.

fixture_evidence(Idle) ->
    Liveness = maps:get(<<"required_liveness_roles">>, Idle),
    Roles = [fixture_role(Label, lists:member(Label, Liveness))
             || Label <- maps:get(<<"required_roles">>, Idle)],
    #{<<"schema">> => maps:get(<<"fixture_schema">>, Idle),
      <<"status">> => <<"Ready">>,
      <<"shareable">> => true,
      <<"redacted">> => true,
      <<"quiescence_confirmed">> => true,
      <<"quiescence_maximum_attempts">> =>
          maps:get(<<"quiescence_maximum_attempts">>, Idle),
      <<"quiescence_milliseconds">> => 600,
      <<"quiescence_poll_milliseconds">> =>
          maps:get(<<"quiescence_poll_milliseconds">>, Idle),
      <<"quiescence_required_stable_samples">> =>
          maps:get(<<"quiescence_required_stable_samples">>, Idle),
      <<"observation_milliseconds">> =>
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
      <<"minimum_observation_milliseconds">> =>
          maps:get(<<"minimum_observation_milliseconds">>, Idle),
      <<"actor_set_stable">> => true,
      <<"expected_actor_count">> =>
          maps:get(<<"expected_actor_count">>, Idle),
      <<"deadline_timeout_returns">> => 0,
      <<"unexpected_actor_exits">> => 0,
      <<"required_actor_liveness">> => true,
      <<"trace_synchronized">> => true,
      <<"trace_primitive">> => maps:get(<<"trace_primitive">>, Idle),
      <<"roles">> => Roles}.

fixture_role(Label, LivenessRequired) ->
    Unbounded = case LivenessRequired of true -> 1; false -> 0 end,
    #{<<"label">> => Label,
      <<"expected_actors">> => 1,
      <<"actors_start">> => 1,
      <<"actors_end">> => 1,
      <<"timed_wait_calls">> => 0,
      <<"timed_message_returns">> => 0,
      <<"timed_boundary_message_returns">> => 0,
      <<"deadline_timeout_returns">> => 0,
      <<"wait_zero_calls">> => 0,
      <<"wait_short_calls">> => 0,
      <<"wait_second_calls">> => 0,
      <<"wait_long_calls">> => 0,
      <<"timeout_zero_returns">> => 0,
      <<"timeout_short_returns">> => 0,
      <<"timeout_second_returns">> => 0,
      <<"timeout_long_returns">> => 0,
      <<"timeout_unclassified_returns">> => 0,
      <<"unbounded_wait_calls">> => Unbounded,
      <<"unbounded_message_returns">> => Unbounded,
      <<"unbounded_boundary_message_returns">> => 0}.

expect_violation(Violations, Id) ->
    ensure(lists:any(fun(Violation) ->
        maps:get(id, Violation) =:= Id
    end, Violations), {missing_self_test_violation, Id}).

expected_roles() ->
    [<<"http3.client">>, <<"http3.listener">>, <<"http3.acceptor">>,
     <<"http3.connection">>, <<"quic_core.client">>,
     <<"quic_core.listener">>, <<"quic_core.connection">>,
     <<"quic_core.udp_relay">>].

expected_liveness_roles() ->
    [<<"http3.client">>, <<"http3.connection">>,
     <<"quic_core.client">>, <<"quic_core.connection">>].

parse_nonnegative(Text) ->
    try list_to_integer(Text) of
        Value when Value >= 0 -> Value;
        _ -> erlang:error({invalid_exit_status, Text})
    catch
        error:badarg -> erlang:error({invalid_exit_status, Text})
    end.

decode_map(Bytes, Error) ->
    try json:decode(Bytes) of
        Value when is_map(Value) -> Value;
        _ -> erlang:error(Error)
    catch
        _:_ -> erlang:error(Error)
    end.

read_bounded(Path, MaximumBytes) ->
    case file:read_file(Path) of
        {ok, Bytes} when byte_size(Bytes) =< MaximumBytes -> Bytes;
        {ok, _Bytes} -> erlang:error({input_too_large, Path, MaximumBytes});
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

problem(true, Id, Evidence) -> [violation(Id, Evidence)];
problem(false, _Id, _Evidence) -> [].

violation(Id, Evidence) ->
    maps:merge(#{scope => <<"idle-wakeup">>, id => Id}, Evidence).

missing(Required, Observed) ->
    [Value || Value <- Required, not lists:member(Value, Observed)].

unique(Values) -> length(Values) =:= length(lists:usort(Values)).

json_value(invalid) -> null;
json_value(Value) -> Value.

valid_digest(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    lists:all(fun(Character) ->
        (Character >= $0 andalso Character =< $9)
        orelse (Character >= $a andalso Character =< $f)
        orelse (Character >= $A andalso Character =< $F)
    end, binary_to_list(Value));
valid_digest(_Value) -> false.

safe_atom(Value) when is_atom(Value) -> atom_to_binary(Value);
safe_atom(_Value) -> <<"unknown">>.

reason_tag(Reason) when is_atom(Reason) -> atom_to_binary(Reason);
reason_tag(Reason) when is_tuple(Reason), tuple_size(Reason) > 0,
                        is_atom(element(1, Reason)) ->
    atom_to_binary(element(1, Reason));
reason_tag(_Reason) -> <<"unclassified">>.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte])
                      || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
