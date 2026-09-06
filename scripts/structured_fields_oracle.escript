#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(SF_MODULE, 'http@structured_fields').
-define(REPORT, "build/structured-fields-oracle/report.json").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "Structured Fields oracle gate failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["--self-test"]) ->
    add_code_paths(),
    self_test();
run(["run", LockPath, CorpusDirectory]) ->
    add_code_paths(),
    Lock = read_json(LockPath),
    Fixtures = validate_lock(Lock),
    ok = validate_checkout_commit(Lock, CorpusDirectory),
    ok = validate_fixture_names(Fixtures, CorpusDirectory),
    Summary = lists:foldl(
        fun(Fixture, Acc) ->
            exercise_fixture(Fixture, CorpusDirectory, Acc)
        end,
        empty_summary(),
        Fixtures),
    ok = validate_expected_summary(maps:get(<<"expected">>, Lock), Summary),
    Report = #{
        <<"schema">> => 1,
        <<"status">> => <<"Ready">>,
        <<"oracle">> => #{
            <<"name">> => maps:get(<<"name">>, Lock),
            <<"repository">> => maps:get(<<"repository">>, Lock),
            <<"commit">> => maps:get(<<"commit">>, Lock),
            <<"corpus_sha256">> => corpus_digest(Fixtures, CorpusDirectory)
        },
        <<"summary">> => summary_json(Summary),
        <<"implementation_sha256">> => implementation_digest(LockPath)
    },
    ok = write_json(?REPORT, Report),
    io:format("Structured Fields oracle passed ~B cases: ~B mandatory valid, "
              "~B mandatory failures, ~B advisory accepted, ~B advisory "
              "rejected; report: ~s~n",
              [maps:get(cases, Summary),
               maps:get(mandatory_valid, Summary),
               maps:get(must_fail, Summary),
               maps:get(can_fail_accepted, Summary),
               maps:get(can_fail_rejected, Summary),
               ?REPORT]),
    ok;
run(_) ->
    erlang:error({usage,
                  "--self-test | run LOCK_PATH CORPUS_DIRECTORY"}).

self_test() ->
    Valid = #{<<"name">> => <<"valid list">>,
              <<"raw">> => [<<"1, token">>],
              <<"header_type">> => <<"list">>,
              <<"expected">> => []},
    MustFail = #{<<"name">> => <<"invalid boolean">>,
                 <<"raw">> => [<<"?2">>],
                 <<"header_type">> => <<"item">>,
                 <<"must_fail">> => true},
    CanFail = #{<<"name">> => <<"unpadded base64">>,
                <<"raw">> => [<<":aGVsbG8:">>],
                <<"header_type">> => <<"item">>,
                <<"can_fail">> => true,
                <<"canonical">> => [<<":aGVsbG8=:">>],
                <<"expected">> => []},
    Summary0 = exercise_case(Valid, <<"self.json">>, 1, empty_summary()),
    Summary1 = exercise_case(MustFail, <<"self.json">>, 2, Summary0),
    Summary2 = exercise_case(CanFail, <<"self.json">>, 3, Summary1),
    ensure(maps:get(cases, Summary2) =:= 3, self_test_case_count),
    ensure(maps:get(mandatory_valid, Summary2) =:= 1,
           self_test_valid_count),
    ensure(maps:get(must_fail, Summary2) =:= 1,
           self_test_failure_count),
    ensure(maps:get(can_fail_rejected, Summary2) =:= 1,
           self_test_advisory_count),
    expect_validation(fun() ->
        exercise_case(MustFail#{<<"raw">> := [<<"1">>]},
                      <<"self.json">>, 4, empty_summary())
    end),
    expect_validation(fun() ->
        exercise_case(Valid#{<<"canonical">> => [<<"2">>]},
                      <<"self.json">>, 5, empty_summary())
    end),
    expect_validation(fun() ->
        exercise_case(Valid#{<<"header_type">> := <<"unknown">>},
                      <<"self.json">>, 6, empty_summary())
    end),
    io:format("Structured Fields oracle self-test ok "
              "(3 execution paths, 3 adversarial cases)~n"),
    ok.

validate_lock(Lock) ->
    ensure(is_map(Lock), invalid_lock),
    ensure(maps:get(<<"schema">>, Lock) =:= 1, invalid_lock_schema),
    Commit = required_binary(Lock, <<"commit">>),
    ensure(is_sha1(Commit), invalid_commit),
    ensure(maps:get(<<"reviewed_on">>, Lock) =:= <<"2026-08-30">>,
           stale_oracle_review),
    Expected = maps:get(<<"expected">>, Lock),
    ensure(is_map(Expected), invalid_expected_summary),
    Fixtures = maps:get(<<"fixtures">>, Lock),
    ensure(is_list(Fixtures) andalso Fixtures =/= [], missing_fixtures),
    Paths = [validate_fixture_lock(Fixture) || Fixture <- Fixtures],
    ensure(length(Paths) =:= length(lists:usort(Paths)),
           duplicate_fixture_path),
    Fixtures.

validate_fixture_lock(Fixture) ->
    ensure(is_map(Fixture), invalid_fixture_lock),
    Path = required_binary(Fixture, <<"path">>),
    ensure(filename:basename(binary_to_list(Path)) =:= binary_to_list(Path),
           {nested_fixture_path, Path}),
    ensure(filename:extension(binary_to_list(Path)) =:= ".json",
           {invalid_fixture_extension, Path}),
    ensure(is_sha256(required_binary(Fixture, <<"sha256">>)),
           {invalid_fixture_digest, Path}),
    lists:foreach(fun(Key) ->
        Value = maps:get(Key, Fixture),
        ensure(is_integer(Value) andalso Value >= 0,
               {invalid_fixture_count, Path, Key})
    end, [<<"cases">>, <<"must_fail">>, <<"can_fail">>]),
    Path.

validate_checkout_commit(Lock, CorpusDirectory) ->
    HeadPath = filename:join([CorpusDirectory, ".git", "HEAD"]),
    Head = read(HeadPath),
    Commit = maps:get(<<"commit">>, Lock),
    ensure(Head =:= <<Commit/binary, "\n">>,
           {oracle_checkout_not_detached_at_pinned_commit, Head}),
    ok.

validate_fixture_names(Fixtures, CorpusDirectory) ->
    Expected = lists:sort(
        [binary_to_list(maps:get(<<"path">>, Fixture))
         || Fixture <- Fixtures]),
    {ok, Entries} = file:list_dir(CorpusDirectory),
    Actual = lists:sort(
        [Entry || Entry <- Entries, filename:extension(Entry) =:= ".json"]),
    ensure(Actual =:= Expected, {fixture_inventory_drift, Expected, Actual}),
    ok.

exercise_fixture(Fixture, CorpusDirectory, Summary0) ->
    Path = maps:get(<<"path">>, Fixture),
    FullPath = filename:join(CorpusDirectory, binary_to_list(Path)),
    Bytes = read(FullPath),
    ensure(hex(crypto:hash(sha256, Bytes)) =:= maps:get(<<"sha256">>, Fixture),
           {fixture_digest_drift, Path}),
    Cases = decode_json(Bytes, FullPath),
    ensure(is_list(Cases), {fixture_not_array, Path}),
    ensure(length(Cases) =:= maps:get(<<"cases">>, Fixture),
           {fixture_case_count_drift, Path}),
    {Summary, Counts} = exercise_cases(Cases, Path, 1, Summary0,
                                       #{must_fail => 0, can_fail => 0}),
    ensure(maps:get(must_fail, Counts) =:= maps:get(<<"must_fail">>, Fixture),
           {fixture_must_fail_count_drift, Path}),
    ensure(maps:get(can_fail, Counts) =:= maps:get(<<"can_fail">>, Fixture),
           {fixture_can_fail_count_drift, Path}),
    Summary.

exercise_cases([], _Path, _Index, Summary, Counts) -> {Summary, Counts};
exercise_cases([Case | Rest], Path, Index, Summary0, Counts0) ->
    MustFail = maps:get(<<"must_fail">>, Case, false),
    CanFail = maps:get(<<"can_fail">>, Case, false),
    Summary = exercise_case(Case, Path, Index, Summary0),
    Counts = Counts0#{
        must_fail := maps:get(must_fail, Counts0) + bool_int(MustFail),
        can_fail := maps:get(can_fail, Counts0) + bool_int(CanFail)
    },
    exercise_cases(Rest, Path, Index + 1, Summary, Counts).

exercise_case(Case, Path, Index, Summary0) ->
    ensure(is_map(Case), {case_not_object, Path, Index}),
    Name = required_binary(Case, <<"name">>),
    Raw = maps:get(<<"raw">>, Case),
    ensure(is_binary_list(Raw) andalso Raw =/= [],
           {invalid_raw_lines, Path, Index, Name}),
    HeaderType = required_binary(Case, <<"header_type">>),
    MustFail = maps:get(<<"must_fail">>, Case, false),
    CanFail = maps:get(<<"can_fail">>, Case, false),
    ensure(is_boolean(MustFail) andalso is_boolean(CanFail),
           {invalid_case_policy, Path, Index, Name}),
    ensure(not (MustFail andalso CanFail),
           {conflicting_case_policy, Path, Index, Name}),
    Outcome = parse(HeaderType, Raw, Path, Index, Name),
    Summary = increment(Summary0, cases),
    case {MustFail, CanFail, Outcome} of
        {true, false, {error, _}} -> increment(Summary, must_fail);
        {true, false, {ok, _}} ->
            validation({accepted_mandatory_failure, Path, Index, Name});
        {false, true, {error, _}} ->
            increment(increment(Summary, can_fail), can_fail_rejected);
        {false, true, {ok, Value}} ->
            ok = verify_canonical(HeaderType, Value, Case,
                                  Path, Index, Name),
            increment(increment(Summary, can_fail), can_fail_accepted);
        {false, false, {error, Error}} ->
            validation({rejected_mandatory_valid, Path, Index, Name, Error});
        {false, false, {ok, Value}} ->
            ok = verify_canonical(HeaderType, Value, Case,
                                  Path, Index, Name),
            increment(Summary, mandatory_valid)
    end.

parse(<<"item">>, Raw, _Path, _Index, _Name) ->
    apply(?SF_MODULE, parse_item_field_lines, [Raw]);
parse(<<"list">>, Raw, _Path, _Index, _Name) ->
    apply(?SF_MODULE, parse_list_field_lines, [Raw]);
parse(<<"dictionary">>, Raw, _Path, _Index, _Name) ->
    apply(?SF_MODULE, parse_dictionary_field_lines, [Raw]);
parse(HeaderType, _Raw, Path, Index, Name) ->
    validation({invalid_header_type, Path, Index, Name, HeaderType}).

verify_canonical(HeaderType, Value, Case, Path, Index, Name) ->
    Expected = canonical(Case, Path, Index, Name),
    Outcome = serialize(HeaderType, Value),
    case Outcome of
        {ok, Expected} -> ok;
        {ok, Actual} ->
            validation({canonical_difference, Path, Index, Name,
                        Expected, Actual});
        {error, Error} ->
            validation({valid_value_not_serializable, Path, Index, Name,
                        Error})
    end.

serialize(<<"item">>, Value) -> apply(?SF_MODULE, serialize_item, [Value]);
serialize(<<"list">>, Value) -> apply(?SF_MODULE, serialize_list, [Value]);
serialize(<<"dictionary">>, Value) ->
    apply(?SF_MODULE, serialize_dictionary, [Value]).

canonical(Case, Path, Index, Name) ->
    Values = maps:get(<<"canonical">>, Case, maps:get(<<"raw">>, Case)),
    case Values of
        [] -> <<>>;
        [Value] when is_binary(Value) -> Value;
        _ -> validation({invalid_canonical_lines, Path, Index, Name})
    end.

empty_summary() ->
    #{cases => 0,
      mandatory_valid => 0,
      must_fail => 0,
      can_fail => 0,
      can_fail_accepted => 0,
      can_fail_rejected => 0}.

increment(Summary, Key) ->
    maps:update_with(Key, fun(Value) -> Value + 1 end, Summary).

validate_expected_summary(Expected, Summary) ->
    Pairs = [{<<"cases">>, cases},
             {<<"must_fail">>, must_fail},
             {<<"can_fail">>, can_fail},
             {<<"mandatory_valid">>, mandatory_valid}],
    lists:foreach(fun({JsonKey, SummaryKey}) ->
        ensure(maps:get(JsonKey, Expected) =:= maps:get(SummaryKey, Summary),
               {oracle_summary_drift, JsonKey,
                maps:get(JsonKey, Expected), maps:get(SummaryKey, Summary)})
    end, Pairs),
    ensure(maps:get(can_fail_accepted, Summary) +
           maps:get(can_fail_rejected, Summary) =:=
           maps:get(can_fail, Summary), advisory_summary_drift),
    ok.

summary_json(Summary) ->
    #{<<"cases">> => maps:get(cases, Summary),
      <<"mandatory_valid">> => maps:get(mandatory_valid, Summary),
      <<"must_fail">> => maps:get(must_fail, Summary),
      <<"can_fail">> => maps:get(can_fail, Summary),
      <<"can_fail_accepted">> => maps:get(can_fail_accepted, Summary),
      <<"can_fail_rejected">> => maps:get(can_fail_rejected, Summary)}.

corpus_digest(Fixtures, CorpusDirectory) ->
    Bytes = [[maps:get(<<"path">>, Fixture), 0,
              read(filename:join(
                  CorpusDirectory,
                  binary_to_list(maps:get(<<"path">>, Fixture))))]
             || Fixture <- Fixtures],
    hex(crypto:hash(sha256, Bytes)).

implementation_digest(LockPath) ->
    Paths = ["scripts/structured_fields_oracle.escript",
             "src/http/structured_fields.gleam",
             "test/structured_fields_test.gleam",
             LockPath],
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

add_code_paths() ->
    Paths = filelib:wildcard("build/dev/erlang/*/ebin"),
    ensure(Paths =/= [], missing_compiled_http_package),
    lists:foreach(fun(Path) -> true = code:add_patha(Path) end, Paths),
    ensure(code:which(?SF_MODULE) =/= non_existing,
           missing_structured_fields_module),
    ok.

required_binary(Map, Key) ->
    Value = maps:get(Key, Map),
    ensure(is_binary(Value) andalso byte_size(Value) > 0,
           {missing_binary, Key}),
    Value.

is_binary_list(Value) when is_list(Value) ->
    lists:all(fun is_binary/1, Value);
is_binary_list(_) -> false.

is_sha1(Value) when is_binary(Value), byte_size(Value) =:= 40 ->
    is_lower_hex(Value);
is_sha1(_) -> false.

is_sha256(Value) when is_binary(Value), byte_size(Value) =:= 64 ->
    is_lower_hex(Value);
is_sha256(_) -> false.

is_lower_hex(<<>>) -> true;
is_lower_hex(<<Byte, Rest/binary>>)
  when (Byte >= $0 andalso Byte =< $9) orelse
       (Byte >= $a andalso Byte =< $f) -> is_lower_hex(Rest);
is_lower_hex(_) -> false.

bool_int(true) -> 1;
bool_int(false) -> 0.

read_json(Path) -> decode_json(read(Path), Path).

decode_json(Bytes, Path) ->
    try json:decode(Bytes) of
        Value -> Value
    catch
        _:_ -> validation({invalid_json, Path})
    end.

write_json(Path, Value) ->
    ok = filelib:ensure_dir(Path),
    file:write_file(Path, [json:encode(Value), <<"\n">>]).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Bytes) ->
    << <<(hex_digit(Byte bsr 4)), (hex_digit(Byte band 16#0f))>>
       || <<Byte>> <= Bytes >>.

hex_digit(Value) when Value < 10 -> $0 + Value;
hex_digit(Value) -> $a + Value - 10.

expect_validation(Fun) ->
    try Fun() of
        _ -> erlang:error(expected_validation_failure)
    catch
        error:{validation, _} -> ok
    end.

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> validation(Reason).

validation(Reason) -> erlang:error({validation, Reason}).
