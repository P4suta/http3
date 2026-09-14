#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(DECODER, 'http3@internal@qpack@decoder').
-define(ENCODER, 'http3@internal@qpack@encoder').
-define(INSTRUCTION, 'http3@internal@qpack@instruction').
-define(OUTPUT, "build/qpack-differential/report.json").
-define(VERSION, <<"0.3.24">>).
-define(CAPACITY, 512).
-define(BLOCKED_STREAMS, 8).

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "QPACK differential gate failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["exercise", OraclePath, ImplementationPath]) ->
    add_code_paths(),
    Oracle = read_json(OraclePath),
    OracleSummary = exercise_oracle(Oracle),
    Implementation = implementation_transcript(),
    _ = validate_transcript(Implementation, <<"http3-to-pylsqpack">>),
    ok = write_json(ImplementationPath, Implementation),
    io:format("http3 decoded pylsqpack corpus: ~B cases, ~B fields, "
              "~B blocked; implementation corpus: ~B cases~n",
              [maps:get(cases, OracleSummary),
               maps:get(fields, OracleSummary),
               maps:get(blocked_cases, OracleSummary),
               length(maps:get(<<"steps">>, Implementation))]),
    ok;
run(["finalize", OraclePath, ImplementationPath, OracleReportPath]) ->
    add_code_paths(),
    finalize(OraclePath, ImplementationPath, OracleReportPath);
run(_) ->
    erlang:error({usage,
                  "--self-test | exercise ORACLE IMPLEMENTATION | "
                  "finalize ORACLE IMPLEMENTATION ORACLE_REPORT"}).

self_test() ->
    add_code_paths(),
    ensure(decode_hex(<<"00ff7F">>) =:= <<0, 255, 127>>,
           self_test_hex_round_trip),
    expect_validation(invalid_hex,
                      fun() -> decode_hex(<<"0x">>) end),
    Valid = minimal_transcript(),
    _ = validate_transcript(Valid, <<"http3-to-pylsqpack">>),
    expect_validation(wrong_direction,
                      fun() -> validate_transcript(
                          Valid, <<"pylsqpack-to-http3">>) end),
    [Step] = maps:get(<<"steps">>, Valid),
    Duplicate = Valid#{<<"steps">> := [Step, Step]},
    expect_validation(duplicate_stream,
                      fun() -> validate_transcript(
                          Duplicate, <<"http3-to-pylsqpack">>) end),
    EmptyHeaders = Valid#{<<"steps">> :=
                         [Step#{<<"headers">> := []}]},
    expect_validation(empty_headers,
                      fun() -> validate_transcript(
                          EmptyHeaders, <<"http3-to-pylsqpack">>) end),
    BadDelivery = Valid#{<<"steps">> :=
                        [Step#{<<"delivery">> := <<"later">>}]},
    expect_validation(bad_delivery,
                      fun() -> validate_transcript(
                          BadDelivery, <<"http3-to-pylsqpack">>) end),
    Implementation = implementation_transcript(),
    Summary = validate_transcript(Implementation, <<"http3-to-pylsqpack">>),
    ensure(maps:get(blocked_cases, Summary) >= 2,
           self_test_blocked_coverage),
    io:format("QPACK differential schema self-test ok (5 adversarial cases)~n"),
    ok.

minimal_transcript() ->
    #{<<"schema">> => 1,
      <<"direction">> => <<"http3-to-pylsqpack">>,
      <<"oracle">> => #{<<"name">> => <<"pylsqpack">>,
                        <<"version">> => ?VERSION},
      <<"configuration">> => configuration(),
      <<"steps">> =>
          [#{<<"id">> => <<"one">>,
             <<"stream_id">> => 0,
             <<"delivery">> => <<"encoder_first">>,
             <<"encoder_stream">> => <<>>,
             <<"field_section">> => <<"0000d1">>,
             <<"headers">> =>
                 [#{<<"name">> => <<"3a6d6574686f64">>,
                    <<"value">> => <<"474554">>}]}]}.

configuration() ->
    #{<<"maximum_table_capacity">> => ?CAPACITY,
      <<"maximum_blocked_streams">> => ?BLOCKED_STREAMS}.

exercise_oracle(Document) ->
    Validation = validate_transcript(Document, <<"pylsqpack-to-http3">>),
    ok = validate_oracle_lock(Document),
    Configuration = maps:get(<<"configuration">>, Document),
    Capacity = maps:get(<<"maximum_table_capacity">>, Configuration),
    Blocked = maps:get(<<"maximum_blocked_streams">>, Configuration),
    {ok, Decoder0} = call(?DECODER, new, [Capacity, Blocked, 64, 16384]),
    Prefix = decode_hex(required(Document, <<"encoder_stream_prefix">>)),
    {Decoder, PrefixInstructions} = apply_encoder_bytes(Decoder0, Prefix, 0),
    {_, Summary} = lists:foldl(
        fun exercise_oracle_step/2,
        {Decoder,
         #{cases => 0, fields => 0, blocked_cases => 0,
           encoder_instructions => PrefixInstructions,
           feedback_instructions => 0, feedback_bytes => 0}},
        maps:get(<<"steps">>, Document)),
    ensure(maps:get(cases, Summary) =:= maps:get(cases, Validation),
           oracle_case_count_drift),
    ensure(maps:get(blocked_cases, Summary) >= 2,
           oracle_blocked_coverage_missing),
    Summary.

exercise_oracle_step(Step, {Decoder0, Summary0}) ->
    StreamId = maps:get(<<"stream_id">>, Step),
    Delivery = maps:get(<<"delivery">>, Step),
    EncoderBytes = decode_hex(maps:get(<<"encoder_stream">>, Step)),
    Section = decode_hex(maps:get(<<"field_section">>, Step)),
    Expected = headers_from_json(maps:get(<<"headers">>, Step)),
    {Decoder1, Headers, BlockedCase, EncoderInstructions} =
        case Delivery of
            <<"header_first">> ->
                {ok, {blocked, BlockedState, _Required}} =
                    call(?DECODER, decode, [Decoder0, StreamId, Section]),
                {ReadyState, Parsed} =
                    apply_encoder_bytes(BlockedState, EncoderBytes, 0),
                {ok, {decoded, DecodedState, DecodedHeaders}} =
                    call(?DECODER, retry_blocked, [ReadyState, StreamId]),
                {DecodedState, DecodedHeaders, 1, Parsed};
            <<"header_before_encoder_unblocked">> ->
                {ok, {decoded, HeaderState, DecodedHeaders}} =
                    call(?DECODER, decode, [Decoder0, StreamId, Section]),
                {DecodedState, Parsed} =
                    apply_encoder_bytes(HeaderState, EncoderBytes, 0),
                {DecodedState, DecodedHeaders, 0, Parsed};
            <<"encoder_first">> ->
                {ReadyState, Parsed} =
                    apply_encoder_bytes(Decoder0, EncoderBytes, 0),
                {ok, {decoded, DecodedState, DecodedHeaders}} =
                    call(?DECODER, decode, [ReadyState, StreamId, Section]),
                {DecodedState, DecodedHeaders, 0, Parsed}
        end,
    ensure(Headers =:= Expected,
           {oracle_header_difference, maps:get(<<"id">>, Step),
            Expected, Headers}),
    OracleFeedback = decode_hex(maps:get(<<"decoder_stream">>, Step)),
    OracleFeedbackCount = count_decoder_bytes(OracleFeedback, 0),
    {Decoder, Feedback} = call(?DECODER, take_instructions, [Decoder1]),
    FeedbackBytes = encode_decoder_instructions(Feedback, <<>>),
    {Decoder,
     Summary0#{cases := maps:get(cases, Summary0) + 1,
               fields := maps:get(fields, Summary0) + length(Headers),
               blocked_cases := maps:get(blocked_cases, Summary0) + BlockedCase,
               encoder_instructions :=
                   maps:get(encoder_instructions, Summary0) + EncoderInstructions,
               feedback_instructions :=
                   maps:get(feedback_instructions, Summary0) + length(Feedback)
                   + OracleFeedbackCount,
               feedback_bytes := maps:get(feedback_bytes, Summary0)
                   + byte_size(FeedbackBytes) + byte_size(OracleFeedback)}}.

apply_encoder_bytes(State, <<>>, Count) -> {State, Count};
apply_encoder_bytes(State0, Bytes, Count) ->
    case call(?INSTRUCTION, decode_encoder,
              [Bytes, call(?INSTRUCTION, default_limits, [])]) of
        {ok, {Incoming, Rest}} ->
            ensure(byte_size(Rest) < byte_size(Bytes),
                   encoder_instruction_made_no_progress),
            {ok, State} = call(?DECODER, apply_encoder_instruction,
                               [State0, Incoming]),
            apply_encoder_bytes(State, Rest, Count + 1);
        {error, Error} ->
            erlang:error({oracle_encoder_stream_rejected, Error})
    end.

count_decoder_bytes(<<>>, Count) -> Count;
count_decoder_bytes(Bytes, Count) ->
    case call(?INSTRUCTION, decode_decoder, [Bytes]) of
        {ok, {_Incoming, Rest}} ->
            ensure(byte_size(Rest) < byte_size(Bytes),
                   decoder_instruction_made_no_progress),
            count_decoder_bytes(Rest, Count + 1);
        {error, Error} ->
            erlang:error({oracle_decoder_stream_rejected, Error})
    end.

implementation_transcript() ->
    {ok, Encoder0} = call(?ENCODER, new,
                          [?CAPACITY, ?CAPACITY, ?BLOCKED_STREAMS, 64, 16384]),
    Static = [{header, <<":method">>, <<"GET">>, false},
              {header, <<":scheme">>, <<"https">>, false},
              {header, <<":path">>, <<"/">>, false}],
    Literal = [{header, <<"x-http3-oracle">>, <<"literal-value">>, false},
               {header, <<"authorization">>, <<"redacted-value">>, true}],
    Dynamic = {header, <<"x-dynamic">>, <<"alpha">>, false},
    Cache = {header, <<"cache-control">>, <<"private, max-age=0">>, false},
    Binary = {header, <<"x-binary">>, <<0, 255, 127, 1>>, false},
    {Encoder1, Step1} = implementation_step(
        Encoder0, <<"static">>, 0, Static, none,
        <<"encoder_first">>, false, true),
    {Encoder2, Step2} = implementation_step(
        Encoder1, <<"literal-never">>, 4, Literal, none,
        <<"encoder_first">>, false, true),
    {Encoder3, Step3} = implementation_step(
        Encoder2, <<"dynamic-insert">>, 8, [Dynamic | Static],
        {insert, Dynamic}, <<"header_first">>, true, false),
    {Encoder4, Step4} = implementation_step(
        Encoder3, <<"dynamic-known-at-decoder">>, 12, [Dynamic, Cache], none,
        <<"encoder_first">>, true, true),
    {Encoder5, Step5} = implementation_step(
        Encoder4, <<"static-name-insert">>, 16, [Cache, Dynamic],
        {insert, Cache}, <<"header_first">>, true, true),
    {Encoder6, Step6} = implementation_step(
        Encoder5, <<"duplicate">>, 20, [Dynamic],
        {duplicate, 0}, <<"header_first">>, true, false),
    {_Encoder7, Step7} = implementation_step(
        Encoder6, <<"binary-literal">>, 24, [Binary, {header, <<":method">>,
                                                    <<"POST">>, false}], none,
        <<"encoder_first">>, false, false),
    #{<<"schema">> => 1,
      <<"direction">> => <<"http3-to-pylsqpack">>,
      <<"oracle">> => #{<<"name">> => <<"pylsqpack">>,
                        <<"version">> => ?VERSION},
      <<"configuration">> => configuration(),
      <<"steps">> => [Step1, Step2, Step3, Step4, Step5, Step6, Step7]}.

implementation_step(State0, Id, StreamId, Headers, Action, Delivery,
                    AllowBlocking, PreferHuffman) ->
    State1 = case Action of
        none -> State0;
        {insert, Header} ->
            {ok, Inserted} = call(?ENCODER, insert, [State0, Header]),
            Inserted;
        {duplicate, AbsoluteIndex} ->
            {ok, Duplicated} = call(?ENCODER, duplicate,
                                    [State0, AbsoluteIndex]),
            Duplicated
    end,
    {State2, Instructions} = call(?ENCODER, take_instructions, [State1]),
    EncoderBytes = encode_encoder_instructions(
        Instructions, PreferHuffman, <<>>),
    {ok, {State, Section}} = call(?ENCODER, encode,
                                  [State2, StreamId, Headers,
                                   AllowBlocking, PreferHuffman]),
    {State,
     #{<<"id">> => Id,
       <<"stream_id">> => StreamId,
       <<"delivery">> => Delivery,
       <<"encoder_stream">> => encode_hex(EncoderBytes),
       <<"field_section">> => encode_hex(Section),
       <<"headers">> => headers_to_json(Headers)}}.

encode_encoder_instructions([], _PreferHuffman, Accumulator) -> Accumulator;
encode_encoder_instructions([Instruction | Rest], PreferHuffman, Accumulator) ->
    {ok, Bytes} = call(?INSTRUCTION, encode_encoder,
                       [Instruction, PreferHuffman]),
    encode_encoder_instructions(Rest, PreferHuffman,
                                <<Accumulator/binary, Bytes/binary>>).

encode_decoder_instructions([], Accumulator) -> Accumulator;
encode_decoder_instructions([Instruction | Rest], Accumulator) ->
    {ok, Bytes} = call(?INSTRUCTION, encode_decoder, [Instruction]),
    encode_decoder_instructions(Rest, <<Accumulator/binary, Bytes/binary>>).

headers_to_json(Headers) ->
    [#{<<"name">> => encode_hex(Name), <<"value">> => encode_hex(Value)}
     || {header, Name, Value, _Never} <- Headers].

headers_from_json(Headers) ->
    [{header,
      decode_hex(required(Header, <<"name">>)),
      decode_hex(required(Header, <<"value">>)),
      false}
     || Header <- Headers].

validate_transcript(Document, ExpectedDirection) when is_map(Document) ->
    ensure_validation(required(Document, <<"schema">>) =:= 1, invalid_schema),
    ensure_validation(required(Document, <<"direction">>) =:= ExpectedDirection,
                      invalid_direction),
    Oracle = required(Document, <<"oracle">>),
    ensure_validation(is_map(Oracle), invalid_oracle),
    ensure_validation(required(Oracle, <<"name">>) =:= <<"pylsqpack">>,
                      invalid_oracle_name),
    ensure_validation(required(Oracle, <<"version">>) =:= ?VERSION,
                      invalid_oracle_version),
    Configuration = required(Document, <<"configuration">>),
    ensure_validation(is_map(Configuration), invalid_configuration),
    ensure_validation(required(Configuration,
                               <<"maximum_table_capacity">>) =:= ?CAPACITY,
                      capacity_drift),
    ensure_validation(required(Configuration,
                               <<"maximum_blocked_streams">>) =:=
                      ?BLOCKED_STREAMS, blocked_stream_drift),
    Steps = required(Document, <<"steps">>),
    ensure_validation(is_list(Steps) andalso length(Steps) > 0
                      andalso length(Steps) =< 1024, invalid_steps),
    Summary = lists:foldl(
        fun(Step, Acc) -> validate_step(Step, ExpectedDirection, Acc) end,
        #{streams => #{}, cases => 0, fields => 0, blocked_cases => 0,
          encoded_bytes => 0}, Steps),
    maps:remove(streams, Summary);
validate_transcript(_Document, _ExpectedDirection) ->
    validation(invalid_document).

validate_step(Step, Direction, Summary) ->
    ensure_validation(is_map(Step), invalid_step),
    Id = required(Step, <<"id">>),
    ensure_validation(is_binary(Id) andalso byte_size(Id) > 0
                      andalso byte_size(Id) =< 128, invalid_step_id),
    StreamId = required(Step, <<"stream_id">>),
    ensure_validation(is_integer(StreamId) andalso StreamId >= 0
                      andalso StreamId =< 4611686018427387903,
                      invalid_stream_id),
    Streams = maps:get(streams, Summary),
    ensure_validation(not maps:is_key(StreamId, Streams), duplicate_stream_id),
    Delivery = required(Step, <<"delivery">>),
    Allowed = case Direction of
        <<"pylsqpack-to-http3">> ->
            [<<"encoder_first">>, <<"header_first">>,
             <<"header_before_encoder_unblocked">>];
        <<"http3-to-pylsqpack">> ->
            [<<"encoder_first">>, <<"header_first">>]
    end,
    ensure_validation(lists:member(Delivery, Allowed), invalid_delivery),
    EncoderBytes = decode_hex(required(Step, <<"encoder_stream">>)),
    Section = decode_hex(required(Step, <<"field_section">>)),
    ensure_validation(byte_size(Section) > 0, empty_field_section),
    Headers = required(Step, <<"headers">>),
    ensure_validation(is_list(Headers) andalso length(Headers) > 0
                      andalso length(Headers) =< 64, invalid_headers),
    lists:foreach(fun validate_header_json/1, Headers),
    DecoderBytes = case Direction of
        <<"pylsqpack-to-http3">> ->
            decode_hex(required(Step, <<"decoder_stream">>));
        <<"http3-to-pylsqpack">> -> <<>>
    end,
    Encoded = byte_size(EncoderBytes) + byte_size(Section)
              + byte_size(DecoderBytes),
    ensure_validation(Encoded =< 1048576, step_too_large),
    Summary#{streams := Streams#{StreamId => true},
             cases := maps:get(cases, Summary) + 1,
             fields := maps:get(fields, Summary) + length(Headers),
             blocked_cases := maps:get(blocked_cases, Summary)
                 + case Delivery of <<"header_first">> -> 1; _ -> 0 end,
             encoded_bytes := maps:get(encoded_bytes, Summary) + Encoded}.

validate_header_json(Header) ->
    ensure_validation(is_map(Header), invalid_header),
    Name = decode_hex(required(Header, <<"name">>)),
    _Value = decode_hex(required(Header, <<"value">>)),
    ensure_validation(byte_size(Name) > 0 andalso byte_size(Name) =< 65536,
                      invalid_header_name).

finalize(OraclePath, ImplementationPath, OracleReportPath) ->
    Oracle = read_json(OraclePath),
    OracleSummary = validate_transcript(Oracle, <<"pylsqpack-to-http3">>),
    ok = validate_oracle_lock(Oracle),
    Implementation = read_json(ImplementationPath),
    ImplementationSummary = validate_transcript(
        Implementation, <<"http3-to-pylsqpack">>),
    OracleReport = read_json(OracleReportPath),
    ensure_validation(required(OracleReport, <<"schema">>) =:= 1,
                      invalid_oracle_report_schema),
    ensure_validation(required(OracleReport, <<"status">>) =:= <<"Ready">>,
                      oracle_report_not_ready),
    ensure_validation(required(OracleReport, <<"direction">>) =:=
                      <<"http3-to-pylsqpack">>, invalid_oracle_report_direction),
    ReportOracle = required(OracleReport, <<"oracle">>),
    ensure_validation(is_map(ReportOracle), invalid_oracle_report_oracle),
    ensure_validation(required(ReportOracle, <<"name">>) =:=
                      <<"pylsqpack">>, invalid_oracle_report_name),
    ensure_validation(required(ReportOracle, <<"version">>) =:= ?VERSION,
                      invalid_oracle_report_version),
    ensure_validation(required(OracleReport, <<"cases">>) =:=
                      maps:get(cases, ImplementationSummary),
                      oracle_report_case_drift),
    ensure_validation(required(OracleReport, <<"fields">>) =:=
                      maps:get(fields, ImplementationSummary),
                      oracle_report_field_drift),
    ensure_validation(required(OracleReport, <<"blocked_cases">>) =:=
                      maps:get(blocked_cases, ImplementationSummary),
                      oracle_report_blocked_drift),
    ImplementationDigest = digest_file(ImplementationPath),
    ensure_validation(required(OracleReport, <<"implementation_sha256">>) =:=
                      ImplementationDigest, oracle_report_digest_drift),
    Report =
        #{schema => 1,
          status => <<"Ready">>,
          family => <<"qpack-rfc9204-differential">>,
          oracle => #{name => <<"pylsqpack">>, version => ?VERSION},
          directions =>
              [summary_json(<<"pylsqpack-to-http3">>, OracleSummary),
               summary_json(<<"http3-to-pylsqpack">>,
                            ImplementationSummary)],
          oracle_corpus_sha256 => digest_file(OraclePath),
          implementation_corpus_sha256 => ImplementationDigest,
          oracle_report_sha256 => digest_file(OracleReportPath),
          source_sha256 => source_digest()},
    ok = write_json(?OUTPUT, Report),
    io:format("QPACK differential gate Ready: ~B bidirectional cases, "
              "~B fields, ~B blocked~n",
              [maps:get(cases, OracleSummary)
                   + maps:get(cases, ImplementationSummary),
               maps:get(fields, OracleSummary)
                   + maps:get(fields, ImplementationSummary),
               maps:get(blocked_cases, OracleSummary)
                   + maps:get(blocked_cases, ImplementationSummary)]),
    ok.

summary_json(Direction, Summary) ->
    #{direction => Direction,
      cases => maps:get(cases, Summary),
      fields => maps:get(fields, Summary),
      blocked_cases => maps:get(blocked_cases, Summary),
      encoded_bytes => maps:get(encoded_bytes, Summary)}.

source_digest() ->
    Paths = ["scripts/qpack_differential.escript",
             "packages/http3/test/interop/qpack_oracle.py",
             "packages/http3/test/interop/requirements.lock",
             "packages/http3/src/http3/internal/qpack/decoder.gleam",
             "packages/http3/src/http3/internal/qpack/encoder.gleam",
             "packages/http3/src/http3/internal/qpack/field_section.gleam",
             "packages/http3/src/http3/internal/qpack/instruction.gleam",
             "packages/http3/src/http3/internal/qpack/instruction_stream.gleam"],
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

validate_oracle_lock(Document) ->
    Oracle = required(Document, <<"oracle">>),
    Path = binary_to_list(required(Oracle, <<"requirements_lock">>)),
    Expected = required(Oracle, <<"requirements_lock_sha256">>),
    ensure_validation(Path =:=
                      "packages/http3/test/interop/requirements.lock",
                      oracle_lock_path_drift),
    Lock = read(Path),
    ensure_validation(binary:match(Lock, <<"pylsqpack==0.3.24">>) =/=
                      nomatch, oracle_version_not_pinned),
    ensure_validation(digest_file(Path) =:= Expected, oracle_lock_digest_drift).

read_json(Path) ->
    try json:decode(read(Path)) of
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

digest_file(Path) -> hex(crypto:hash(sha256, read(Path))).

encode_hex(Bytes) ->
    list_to_binary(string:lowercase(binary_to_list(binary:encode_hex(Bytes)))).

decode_hex(Value) when is_binary(Value), byte_size(Value) rem 2 =:= 0 ->
    decode_hex(Value, <<>>);
decode_hex(_Value) -> validation(invalid_hex).

decode_hex(<<>>, Accumulator) -> Accumulator;
decode_hex(<<High, Low, Rest/binary>>, Accumulator) ->
    Byte = hex_nibble(High) * 16 + hex_nibble(Low),
    decode_hex(Rest, <<Accumulator/binary, Byte>>).

hex_nibble(Value) when Value >= $0, Value =< $9 -> Value - $0;
hex_nibble(Value) when Value >= $a, Value =< $f -> Value - $a + 10;
hex_nibble(Value) when Value >= $A, Value =< $F -> Value - $A + 10;
hex_nibble(_Value) -> validation(invalid_hex_digit).

required(Map, Key) when is_map(Map) ->
    case maps:find(Key, Map) of
        {ok, Value} -> Value;
        error -> validation({missing_key, Key})
    end;
required(_Value, Key) -> validation({not_a_map, Key}).

expect_validation(Name, Fun) ->
    try Fun() of
        _ -> erlang:error({self_test_expected_validation_failure, Name})
    catch
        error:{validation, _} -> ok
    end.

ensure_validation(true, _Reason) -> ok;
ensure_validation(false, Reason) -> validation(Reason).

validation(Reason) -> erlang:error({validation, Reason}).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).

call(Module, Function, Arguments) -> apply(Module, Function, Arguments).

add_code_paths() ->
    Roots = ["packages/http3/build/dev/erlang"],
    Paths = lists:append(
        [filelib:wildcard(filename:join(Root, "*/ebin")) || Root <- Roots]),
    lists:foreach(
        fun(Path) -> true = code:add_patha(filename:absname(Path)) end, Paths).

hex(Binary) ->
    encode_hex(Binary).
