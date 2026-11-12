#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("evidence_publication.hrl").
-include("fresh_build_identity.hrl").
-compile({nowarn_unused_function, [{evidence_begin, 1}]}).

-define(DECODER, 'http3@internal@qpack@decoder').
-define(ENCODER, 'http3@internal@qpack@encoder').
-define(INSTRUCTION, 'http3@internal@qpack@instruction').
-define(OUTPUT, "build/qpack-differential/report.json").
-define(VERSION, <<"1.0.0">>).
-define(CAPACITY, 512).
-define(BLOCKED_STREAMS, 8).
-define(SCHEMA, 2).
-define(MAX_INPUT_BYTES, 2097152).
-define(MAX_OUTPUT_BYTES, 2097152).
-define(MAX_JSON_DEPTH, 64).
-define(MAX_JSON_NODES, 100000).
-define(MAX_CONTAINER_ITEMS, 4096).
-define(MAX_JSON_INTEGER_TOKEN_BYTES, 32).
-define(MAX_STEPS, 1024).
-define(MAX_HEADERS, 64).
-define(MAX_TOTAL_FIELDS, 65536).
-define(MAX_PREFIX_BYTES, 1048576).
-define(MAX_STEP_BYTES, 1048576).
-define(MAX_TOTAL_ENCODED_BYTES, 2097152).
-define(MAX_INSTRUCTIONS, 65536).
-define(MAX_HEADER_NAME_BYTES, 65536).
-define(MAX_HEADER_VALUE_BYTES, 1048576).
-define(MAX_STEP_ID_BYTES, 128).
-define(RUN_ID_BYTES, 32).
-define(LOCK_SUFFIX, ".qpack-lock").
-define(LOCK_OWNER, "owner.json").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            Details = diagnostic_failure_details(Class, Reason, Stacktrace),
            Failure = iolist_to_binary([
                json:encode(#{schema => 1, status => <<"Failed">>,
                              failure => maps:with(
                                  [exception_class, exception_reason],
                                  Details)}), <<"\n">>]),
            safe_emit(standard_error, Failure),
            halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["exercise", OraclePath, ImplementationPath]) ->
    with_qpack_lock(ImplementationPath, fun() ->
        IdentityPath = ImplementationPath ++ ".identity.json",
        Identity = qpack_evidence_begin(IdentityPath),
        qpack_invalidate(ImplementationPath),
        qpack_publication_transaction([ImplementationPath, IdentityPath], fun() ->
            fresh_with_verified_build("http3", fun(Snapshot) ->
                exercise_verified(OraclePath, ImplementationPath, Identity,
                                  Snapshot)
            end)
        end)
    end);
run(["finalize", OraclePath, ImplementationPath, OracleReportPath]) ->
    with_qpack_lock(?OUTPUT, fun() ->
        Identity = qpack_evidence_begin(?OUTPUT),
        qpack_publication_transaction([?OUTPUT], fun() ->
            fresh_with_verified_build("http3", fun(Snapshot) ->
                finalize_verified(OraclePath, ImplementationPath,
                                  OracleReportPath, Identity, Snapshot)
            end)
        end)
    end);
run(_) ->
    erlang:error({usage,
                  "--self-test | exercise ORACLE IMPLEMENTATION | "
                  "finalize ORACLE IMPLEMENTATION ORACLE_REPORT"}).

exercise_verified(OraclePath, ImplementationPath, Identity, Snapshot) ->
    Build = maps:get(report, Snapshot),
    add_code_paths(),
    {Oracle, OracleBytes, OracleDigest} = read_json(OraclePath),
    OracleSummary = exercise_oracle(Oracle),
    OracleRunId = required(Oracle, <<"oracle_run_id">>),
    OracleIdentity = required(Oracle, <<"oracle">>),
    Implementation = implementation_transcript(OracleRunId, OracleIdentity),
    _ = validate_transcript(Implementation, <<"http3-to-pylsqpack">>),
    ImplementationPublished = write_json(ImplementationPath, Implementation),
    FinalSnapshot = fresh_verify_locked("http3"),
    Build = maps:get(report, FinalSnapshot),
    true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
        _ = write_json(ImplementationPath ++ ".identity.json",
        evidence_complete(#{artifact_sha256 => maps:get(sha256, ImplementationPublished),
            artifact_bytes => maps:get(size, ImplementationPublished),
            oracle_corpus_sha256 => OracleDigest,
            oracle_corpus_bytes => byte_size(OracleBytes),
            oracle_run_id => OracleRunId,
            oracle_identity => OracleIdentity,
            oracle_execution => oracle_execution_summary(OracleSummary),
            build_identity => Build,
            build_manifest_sha256 => maps:get(sha256, Snapshot)}, Identity)),
    ensure(maps:get(cases, OracleSummary) > 0, oracle_case_count_missing),
    ok.

finalize_verified(OraclePath, ImplementationPath, OracleReportPath, Identity,
                  Snapshot) ->
    Build = maps:get(report, Snapshot),
    {Captured, CapturedBytes, CapturedDigest} =
        read_json(ImplementationPath ++ ".identity.json"),
    evidence_require_identity(Captured, Identity),
    ensure_validation(required(Captured, <<"execution_environment">>) =:=
                      execution_runtime(),
                      implementation_execution_environment_changed),
    ensure_validation(maps:get(<<"build_identity">>, Captured) =:= Build,
                      implementation_build_changed),
    ensure_validation(maps:get(<<"build_manifest_sha256">>, Captured) =:=
                      maps:get(sha256, Snapshot),
                      implementation_build_manifest_changed),
    add_code_paths(),
    finalize(OraclePath, ImplementationPath, OracleReportPath, Identity,
             Snapshot, Captured, CapturedBytes, CapturedDigest).

self_test() ->
    add_code_paths(),
    ensure(decode_hex(<<"00ff7f">>, 3, true) =:= <<0, 255, 127>>,
           self_test_hex_round_trip),
    expect_validation(invalid_hex,
                      fun() -> decode_hex(<<"0x">>, 1, true) end),
    expect_validation(noncanonical_hex,
                      fun() -> decode_hex(<<"7F">>, 1, true) end),
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
    Implementation = implementation_transcript(
        maps:get(<<"oracle_run_id">>, Valid), maps:get(<<"oracle">>, Valid)),
    Summary = validate_transcript(Implementation, <<"http3-to-pylsqpack">>),
    ensure(maps:get(blocked_cases, Summary) >= 2,
           self_test_blocked_coverage),
    qpack_adversarial_self_test(Valid),
    safe_emit(standard_io, <<"QPACK differential self-test Ready\n">>),
    ok.

minimal_transcript() ->
    #{<<"schema">> => ?SCHEMA,
      <<"direction">> => <<"http3-to-pylsqpack">>,
      <<"oracle">> => oracle_identity_fixture(),
      <<"oracle_run_id">> => binary:copy(<<"01">>, ?RUN_ID_BYTES),
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
    Prefix = decode_hex(required(Document, <<"encoder_stream_prefix">>),
                        ?MAX_PREFIX_BYTES, true),
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
    ensure(maps:get(fields, Summary) =:= maps:get(fields, Validation),
           oracle_field_count_drift),
    ensure(maps:get(blocked_cases, Summary) =:=
           maps:get(blocked_cases, Validation),
           oracle_blocked_count_drift),
    ensure(maps:get(blocked_cases, Summary) >= 2,
           oracle_blocked_coverage_missing),
    Summary.

exercise_oracle_step(Step, {Decoder0, Summary0}) ->
    StreamId = maps:get(<<"stream_id">>, Step),
    Delivery = maps:get(<<"delivery">>, Step),
    EncoderBytes = decode_hex(maps:get(<<"encoder_stream">>, Step),
                              ?MAX_STEP_BYTES, true),
    Section = decode_hex(maps:get(<<"field_section">>, Step),
                         ?MAX_STEP_BYTES, false),
    Expected = headers_from_json(maps:get(<<"headers">>, Step)),
    PreviousEncoderInstructions = maps:get(encoder_instructions, Summary0),
    {Decoder1, Headers, BlockedCase, EncoderInstructions} =
        case Delivery of
            <<"header_first">> ->
                {ok, {blocked, BlockedState, _Required}} =
                    call(?DECODER, decode, [Decoder0, StreamId, Section]),
                {ReadyState, Parsed} =
                    apply_encoder_bytes(BlockedState, EncoderBytes,
                                        PreviousEncoderInstructions),
                {ok, {decoded, DecodedState, DecodedHeaders}} =
                    call(?DECODER, retry_blocked, [ReadyState, StreamId]),
                {DecodedState, DecodedHeaders, 1, Parsed};
            <<"header_before_encoder_unblocked">> ->
                {ok, {decoded, HeaderState, DecodedHeaders}} =
                    call(?DECODER, decode, [Decoder0, StreamId, Section]),
                {DecodedState, Parsed} =
                    apply_encoder_bytes(HeaderState, EncoderBytes,
                                        PreviousEncoderInstructions),
                {DecodedState, DecodedHeaders, 0, Parsed};
            <<"encoder_first">> ->
                {ReadyState, Parsed} =
                    apply_encoder_bytes(Decoder0, EncoderBytes,
                                        PreviousEncoderInstructions),
                {ok, {decoded, DecodedState, DecodedHeaders}} =
                    call(?DECODER, decode, [ReadyState, StreamId, Section]),
                {DecodedState, DecodedHeaders, 0, Parsed}
        end,
    ensure(Headers =:= Expected,
           {oracle_header_difference, length(Expected), length(Headers)}),
    OracleFeedback = decode_hex(maps:get(<<"decoder_stream">>, Step),
                                ?MAX_STEP_BYTES, true),
    {OracleFeedbackCount, OracleFeedbackInstructions} =
        decode_decoder_bytes(OracleFeedback, 0, []),
    {Decoder, Feedback} = call(?DECODER, take_instructions, [Decoder1]),
    ensure(feedback_stream_actions(Feedback) =:=
           feedback_stream_actions(OracleFeedbackInstructions),
           decoder_feedback_action_drift),
    FeedbackBytes = encode_decoder_instructions(Feedback),
    FeedbackInstructions = maps:get(feedback_instructions, Summary0)
        + length(Feedback) + OracleFeedbackCount,
    ensure(FeedbackInstructions =< ?MAX_INSTRUCTIONS,
           decoder_instruction_count_limit),
    FeedbackByteCount = maps:get(feedback_bytes, Summary0)
        + byte_size(FeedbackBytes) + byte_size(OracleFeedback),
    ensure(FeedbackByteCount =< ?MAX_TOTAL_ENCODED_BYTES,
           decoder_feedback_byte_limit),
    {Decoder,
     Summary0#{cases := maps:get(cases, Summary0) + 1,
               fields := maps:get(fields, Summary0) + length(Headers),
               blocked_cases := maps:get(blocked_cases, Summary0) + BlockedCase,
               encoder_instructions := EncoderInstructions,
               feedback_instructions := FeedbackInstructions,
               feedback_bytes := FeedbackByteCount}}.

apply_encoder_bytes(State, <<>>, Count) -> {State, Count};
apply_encoder_bytes(State0, Bytes, Count) ->
    ensure(Count < ?MAX_INSTRUCTIONS, encoder_instruction_count_limit),
    case call(?INSTRUCTION, decode_encoder,
              [Bytes, call(?INSTRUCTION, default_limits, [])]) of
        {ok, {Incoming, Rest}} ->
            ensure(byte_size(Rest) < byte_size(Bytes),
                   encoder_instruction_made_no_progress),
            {ok, State} = call(?DECODER, apply_encoder_instruction,
                               [State0, Incoming]),
            apply_encoder_bytes(State, Rest, Count + 1);
        {error, _Error} ->
            erlang:error(oracle_encoder_stream_rejected)
    end.

count_decoder_bytes(Bytes, Count) ->
    {FinalCount, _Instructions} = decode_decoder_bytes(Bytes, Count, []),
    FinalCount.

decode_decoder_bytes(<<>>, Count, Reversed) ->
    {Count, lists:reverse(Reversed)};
decode_decoder_bytes(Bytes, Count, Reversed) ->
    ensure(Count < ?MAX_INSTRUCTIONS, decoder_instruction_count_limit),
    case call(?INSTRUCTION, decode_decoder, [Bytes]) of
        {ok, {Incoming, Rest}} ->
            ensure(byte_size(Rest) < byte_size(Bytes),
                   decoder_instruction_made_no_progress),
            decode_decoder_bytes(Rest, Count + 1, [Incoming | Reversed]);
        {error, _Error} ->
            erlang:error(oracle_decoder_stream_rejected)
    end.

feedback_stream_actions(Instructions) when is_list(Instructions) ->
    feedback_stream_actions(Instructions, []);
feedback_stream_actions(_Instructions) ->
    erlang:error(invalid_decoder_instruction_list).

feedback_stream_actions([], Reversed) -> lists:reverse(Reversed);
feedback_stream_actions([{insert_count_increment, Increment} | Rest], Reversed)
  when is_integer(Increment), Increment > 0 ->
    feedback_stream_actions(Rest, Reversed);
feedback_stream_actions([{section_acknowledgement, StreamId} = Instruction | Rest],
                        Reversed)
  when is_integer(StreamId), StreamId >= 0, StreamId =< 4611686018427387903 ->
    feedback_stream_actions(Rest, [Instruction | Reversed]);
feedback_stream_actions([{stream_cancellation, StreamId} = Instruction | Rest],
                        Reversed)
  when is_integer(StreamId), StreamId >= 0, StreamId =< 4611686018427387903 ->
    feedback_stream_actions(Rest, [Instruction | Reversed]);
feedback_stream_actions(_Instructions, _Reversed) ->
    erlang:error(invalid_decoder_instruction).

implementation_transcript(OracleRunId, OracleIdentity) ->
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
    #{<<"schema">> => ?SCHEMA,
      <<"direction">> => <<"http3-to-pylsqpack">>,
      <<"oracle">> => OracleIdentity,
      <<"oracle_run_id">> => OracleRunId,
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
    EncoderBytes = encode_encoder_instructions(Instructions, PreferHuffman),
    {State, Section} = case call(?ENCODER, encode,
                                 [State2, StreamId, Headers,
                                  AllowBlocking, PreferHuffman]) of
        {ok, {EncodedState, EncodedSection}} when is_binary(EncodedSection) ->
            {EncodedState, EncodedSection};
        _ -> erlang:error(field_section_encode_failed)
    end,
    ensure(byte_size(EncoderBytes) + byte_size(Section) =< ?MAX_STEP_BYTES,
           implementation_step_byte_limit),
    {State,
     #{<<"id">> => Id,
       <<"stream_id">> => StreamId,
       <<"delivery">> => Delivery,
       <<"encoder_stream">> => encode_hex(EncoderBytes),
       <<"field_section">> => encode_hex(Section),
       <<"headers">> => headers_to_json(Headers)}}.

encode_encoder_instructions(Instructions, PreferHuffman)
  when is_list(Instructions), is_boolean(PreferHuffman) ->
    ensure(length(Instructions) =< ?MAX_INSTRUCTIONS,
           encoder_instruction_count_limit),
    {Reversed, _Size} = lists:foldl(fun(Instruction, {Parts, Size}) ->
        Bytes = case call(?INSTRUCTION, encode_encoder,
                          [Instruction, PreferHuffman]) of
            {ok, Encoded} when is_binary(Encoded) -> Encoded;
            _ -> erlang:error(encoder_instruction_encode_failed)
        end,
        NextSize = Size + byte_size(Bytes),
        ensure(NextSize =< ?MAX_STEP_BYTES,
               encoder_instruction_byte_limit),
        {[Bytes | Parts], NextSize}
    end, {[], 0}, Instructions),
    iolist_to_binary(lists:reverse(Reversed));
encode_encoder_instructions(_Instructions, _PreferHuffman) ->
    erlang:error(invalid_encoder_instruction_list).

encode_decoder_instructions(Instructions) when is_list(Instructions) ->
    ensure(length(Instructions) =< ?MAX_INSTRUCTIONS,
           decoder_instruction_count_limit),
    {Reversed, _Size} = lists:foldl(fun(Instruction, {Parts, Size}) ->
        Bytes = case call(?INSTRUCTION, encode_decoder, [Instruction]) of
            {ok, Encoded} when is_binary(Encoded) -> Encoded;
            _ -> erlang:error(decoder_instruction_encode_failed)
        end,
        NextSize = Size + byte_size(Bytes),
        ensure(NextSize =< ?MAX_STEP_BYTES,
               decoder_instruction_byte_limit),
        {[Bytes | Parts], NextSize}
    end, {[], 0}, Instructions),
    iolist_to_binary(lists:reverse(Reversed));
encode_decoder_instructions(_Instructions) ->
    erlang:error(invalid_decoder_instruction_list).

headers_to_json(Headers) ->
    [#{<<"name">> => encode_hex(Name), <<"value">> => encode_hex(Value)}
     || {header, Name, Value, _Never} <- Headers].

headers_from_json(Headers) ->
    [{header,
      decode_hex(required(Header, <<"name">>), ?MAX_HEADER_NAME_BYTES, false),
      decode_hex(required(Header, <<"value">>), ?MAX_HEADER_VALUE_BYTES, true),
      false}
     || Header <- Headers].

validate_transcript(Document, ExpectedDirection) when is_map(Document) ->
    DocumentKeys = case ExpectedDirection of
        <<"pylsqpack-to-http3">> ->
            [<<"schema">>, <<"direction">>, <<"oracle">>,
             <<"oracle_run_id">>, <<"configuration">>,
             <<"encoder_stream_prefix">>, <<"steps">>];
        <<"http3-to-pylsqpack">> ->
            [<<"schema">>, <<"direction">>, <<"oracle">>,
             <<"oracle_run_id">>, <<"configuration">>, <<"steps">>];
        _ -> validation(invalid_expected_direction)
    end,
    exact_keys(Document, DocumentKeys, invalid_document_fields),
    ensure_validation(required(Document, <<"schema">>) =:= ?SCHEMA,
                      invalid_schema),
    ensure_validation(required(Document, <<"direction">>) =:= ExpectedDirection,
                      invalid_direction),
    Oracle = required(Document, <<"oracle">>),
    validate_oracle_identity(Oracle),
    validate_run_id(required(Document, <<"oracle_run_id">>)),
    Configuration = required(Document, <<"configuration">>),
    ensure_validation(is_map(Configuration), invalid_configuration),
    exact_keys(Configuration,
               [<<"maximum_table_capacity">>, <<"maximum_blocked_streams">>],
               invalid_configuration_fields),
    ensure_validation(required(Configuration,
                               <<"maximum_table_capacity">>) =:= ?CAPACITY,
                      capacity_drift),
    ensure_validation(required(Configuration,
                               <<"maximum_blocked_streams">>) =:=
                      ?BLOCKED_STREAMS, blocked_stream_drift),
    PrefixBytes = case ExpectedDirection of
        <<"pylsqpack-to-http3">> ->
            byte_size(decode_hex(required(Document,
                                          <<"encoder_stream_prefix">>),
                                 ?MAX_PREFIX_BYTES, true));
        <<"http3-to-pylsqpack">> -> 0
    end,
    Steps = required(Document, <<"steps">>),
    ensure_validation(is_list(Steps) andalso length(Steps) > 0
                      andalso length(Steps) =< ?MAX_STEPS, invalid_steps),
    Summary = lists:foldl(
        fun(Step, Acc) -> validate_step(Step, ExpectedDirection, Acc) end,
        #{streams => #{}, cases => 0, fields => 0, blocked_cases => 0,
          encoded_bytes => PrefixBytes}, Steps),
    maps:remove(streams, Summary);
validate_transcript(_Document, _ExpectedDirection) ->
    validation(invalid_document).

validate_step(Step, Direction, Summary) ->
    ensure_validation(is_map(Step), invalid_step),
    StepKeys = case Direction of
        <<"pylsqpack-to-http3">> ->
            [<<"id">>, <<"stream_id">>, <<"delivery">>,
             <<"encoder_stream">>, <<"field_section">>,
             <<"decoder_stream">>, <<"headers">>];
        <<"http3-to-pylsqpack">> ->
            [<<"id">>, <<"stream_id">>, <<"delivery">>,
             <<"encoder_stream">>, <<"field_section">>, <<"headers">>]
    end,
    exact_keys(Step, StepKeys, invalid_step_fields),
    Id = required(Step, <<"id">>),
    ensure_validation(is_binary(Id) andalso byte_size(Id) > 0
                      andalso byte_size(Id) =< ?MAX_STEP_ID_BYTES,
                      invalid_step_id),
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
    EncoderBytes = decode_hex(required(Step, <<"encoder_stream">>),
                              ?MAX_STEP_BYTES, true),
    Section = decode_hex(required(Step, <<"field_section">>),
                         ?MAX_STEP_BYTES, false),
    Headers = required(Step, <<"headers">>),
    ensure_validation(is_list(Headers) andalso length(Headers) > 0
                      andalso length(Headers) =< ?MAX_HEADERS,
                      invalid_headers),
    HeaderBytes = lists:sum([validate_header_json(Header)
                             || Header <- Headers]),
    DecoderBytes = case Direction of
        <<"pylsqpack-to-http3">> ->
            decode_hex(required(Step, <<"decoder_stream">>),
                       ?MAX_STEP_BYTES, true);
        <<"http3-to-pylsqpack">> -> <<>>
    end,
    Encoded = byte_size(EncoderBytes) + byte_size(Section)
              + byte_size(DecoderBytes),
    ensure_validation(Encoded =< ?MAX_STEP_BYTES, step_too_large),
    Fields = maps:get(fields, Summary) + length(Headers),
    TotalEncoded = maps:get(encoded_bytes, Summary) + Encoded + HeaderBytes,
    ensure_validation(Fields =< ?MAX_TOTAL_FIELDS, field_count_limit),
    ensure_validation(TotalEncoded =< ?MAX_TOTAL_ENCODED_BYTES,
                      transcript_byte_limit),
    Summary#{streams := Streams#{StreamId => true},
             cases := maps:get(cases, Summary) + 1,
             fields := Fields,
             blocked_cases := maps:get(blocked_cases, Summary)
                 + case Delivery of <<"header_first">> -> 1; _ -> 0 end,
             encoded_bytes := TotalEncoded}.

validate_header_json(Header) ->
    ensure_validation(is_map(Header), invalid_header),
    exact_keys(Header, [<<"name">>, <<"value">>], invalid_header_fields),
    Name = decode_hex(required(Header, <<"name">>),
                      ?MAX_HEADER_NAME_BYTES, false),
    Value = decode_hex(required(Header, <<"value">>),
                       ?MAX_HEADER_VALUE_BYTES, true),
    byte_size(Name) + byte_size(Value).

finalize(OraclePath, ImplementationPath, OracleReportPath, Identity, Snapshot,
         Captured, CapturedBytes, CapturedDigest) ->
    Build = maps:get(report, Snapshot),
    {Oracle, OracleBytes, OracleDigest} = read_json(OraclePath),
    OracleSummary = validate_transcript(Oracle, <<"pylsqpack-to-http3">>),
    ok = validate_oracle_lock(Oracle),
    {Implementation, ImplementationBytes, ImplementationDigest} =
        read_json(ImplementationPath),
    ImplementationSummary = validate_transcript(
        Implementation, <<"http3-to-pylsqpack">>),
    {OracleReport, OracleReportBytes, OracleReportDigest} =
        read_json(OracleReportPath),
    exact_keys(OracleReport,
        [<<"schema">>, <<"status">>, <<"direction">>, <<"oracle">>,
         <<"oracle_run_id">>, <<"cases">>, <<"fields">>,
         <<"blocked_cases">>, <<"decoder_control_bytes">>,
         <<"implementation_bytes">>, <<"implementation_sha256">>],
        invalid_oracle_report_fields),
    ensure_validation(required(OracleReport, <<"schema">>) =:= ?SCHEMA,
                      invalid_oracle_report_schema),
    ensure_validation(required(OracleReport, <<"status">>) =:= <<"Ready">>,
                      oracle_report_not_ready),
    ensure_validation(required(OracleReport, <<"direction">>) =:=
                      <<"http3-to-pylsqpack">>, invalid_oracle_report_direction),
    OracleIdentity = required(Oracle, <<"oracle">>),
    OracleRunId = required(Oracle, <<"oracle_run_id">>),
    validate_campaign_bindings(OracleIdentity, OracleRunId,
                               Implementation, OracleReport),
    ensure_validation(required(OracleReport, <<"cases">>) =:=
                      maps:get(cases, ImplementationSummary),
                      oracle_report_case_drift),
    ensure_validation(required(OracleReport, <<"fields">>) =:=
                      maps:get(fields, ImplementationSummary),
                      oracle_report_field_drift),
    ensure_validation(required(OracleReport, <<"blocked_cases">>) =:=
                      maps:get(blocked_cases, ImplementationSummary),
                      oracle_report_blocked_drift),
    validate_bounded_integer(required(OracleReport,
                                     <<"decoder_control_bytes">>),
                             0, ?MAX_TOTAL_ENCODED_BYTES,
                             invalid_oracle_control_bytes),
    ensure_validation(required(OracleReport, <<"implementation_bytes">>) =:=
                      byte_size(ImplementationBytes),
                      oracle_report_size_drift),
    ensure_validation(required(OracleReport, <<"implementation_sha256">>) =:=
                      ImplementationDigest, oracle_report_digest_drift),
    validate_capture(Captured, OracleDigest, byte_size(OracleBytes),
                     ImplementationDigest, byte_size(ImplementationBytes),
                     OracleRunId, OracleIdentity, Build,
                     maps:get(sha256, Snapshot), OracleSummary),
    SourceDigest = source_digest(),
    Report =
        #{schema => ?SCHEMA,
          status => <<"Ready">>,
          family => <<"qpack-rfc9204-differential">>,
          shareable => true,
          replay_command => <<"mise run qpack-differential">>,
          oracle => OracleIdentity,
          oracle_run_id => OracleRunId,
          directions =>
              [summary_json(<<"pylsqpack-to-http3">>, OracleSummary),
               summary_json(<<"http3-to-pylsqpack">>,
                            ImplementationSummary)],
          oracle_execution => required(Captured, <<"oracle_execution">>),
          oracle_corpus_bytes => byte_size(OracleBytes),
          oracle_corpus_sha256 => OracleDigest,
          implementation_corpus_bytes => byte_size(ImplementationBytes),
          implementation_corpus_sha256 => ImplementationDigest,
          implementation_identity_bytes => byte_size(CapturedBytes),
          implementation_identity_sha256 => CapturedDigest,
          oracle_report_bytes => byte_size(OracleReportBytes),
          oracle_report_sha256 => OracleReportDigest,
          source_sha256 => SourceDigest,
          build_identity => Build,
          build_manifest_sha256 => maps:get(sha256, Snapshot)},
    FinalSnapshot = fresh_verify_locked("http3"),
    Build = maps:get(report, FinalSnapshot),
    true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
    Completed = evidence_complete(Report, Identity),
    _Published = write_json(?OUTPUT, Completed),
    try
        qpack_require_unchanged_input(OraclePath, OracleBytes, OracleDigest),
        qpack_require_unchanged_input(ImplementationPath, ImplementationBytes,
                                      ImplementationDigest),
        qpack_require_unchanged_input(ImplementationPath ++ ".identity.json",
                                      CapturedBytes, CapturedDigest),
        qpack_require_unchanged_input(OracleReportPath, OracleReportBytes,
                                      OracleReportDigest),
        SourceDigest = source_digest(),
        case evidence_identity() of
            Identity -> ok;
            _OtherIdentity -> erlang:error(source_changed_after_publication)
        end
    catch
        _:_ ->
            qpack_invalidate(?OUTPUT),
            erlang:error(evidence_changed_after_publication)
    end,
    ok.

qpack_require_unchanged_input(Path, ExpectedBytes, ExpectedDigest) ->
    Current = qpack_read(Path, ?MAX_INPUT_BYTES, false),
    ensure_validation(Current =:= ExpectedBytes andalso
                      digest_bytes(Current) =:= ExpectedDigest,
                      input_changed_after_verification).

summary_json(Direction, Summary) ->
    #{direction => Direction,
      cases => maps:get(cases, Summary),
      fields => maps:get(fields, Summary),
      blocked_cases => maps:get(blocked_cases, Summary),
      encoded_bytes => maps:get(encoded_bytes, Summary)}.

source_digest() ->
    Paths = ["scripts/qpack_differential.escript",
             "packages/http3/test/interop/qpack_oracle.py",
             "packages/http3/test/interop/qpack_oracle_contract_test.py",
             "packages/http3/test/interop/requirements.txt",
             "packages/http3/src/http3/internal/qpack/decoder.gleam",
             "packages/http3/src/http3/internal/qpack/encoder.gleam",
             "packages/http3/src/http3/internal/qpack/field_section.gleam",
             "packages/http3/src/http3/internal/qpack/instruction.gleam",
             "packages/http3/src/http3/internal/qpack/instruction_stream.gleam"],
    Frames = [begin
        Name = unicode:characters_to_binary(Path),
        Bytes = qpack_read(Path, ?MAX_INPUT_BYTES, false),
        <<(byte_size(Name)):64/unsigned-big, Name/binary,
          (byte_size(Bytes)):64/unsigned-big,
          (crypto:hash(sha256, Bytes))/binary>>
    end || Path <- Paths],
    hex(crypto:hash(sha256,
                    [<<"http3-qpack-source-v2", 0,
                       (length(Paths)):64/unsigned-big>> | Frames])).

validate_oracle_lock(Document) ->
    Oracle = required(Document, <<"oracle">>),
    Path = binary_to_list(required(Oracle, <<"requirements_lock">>)),
    Expected = required(Oracle, <<"requirements_lock_sha256">>),
    ensure_validation(Path =:=
                      "packages/http3/test/interop/requirements.txt",
                      oracle_lock_path_drift),
    Lock = qpack_read(Path, ?MAX_INPUT_BYTES, false),
    ensure_validation(binary:match(Lock, <<"pylsqpack==1.0.0">>) =/=
                      nomatch, oracle_version_not_pinned),
    ensure_validation(digest_bytes(Lock) =:= Expected,
                      oracle_lock_digest_drift).

read_json(Path) ->
    Bytes = qpack_read(Path, ?MAX_INPUT_BYTES, false),
    qpack_json_preflight(Bytes),
    try evidence_json_decode(Bytes) of
        Value ->
            qpack_validate_json_shape(Value),
            {Value, Bytes, digest_bytes(Bytes)}
    catch
        _:_ -> validation(invalid_json)
    end.

qpack_json_preflight(Bytes) when is_binary(Bytes) ->
    qpack_json_preflight(Bytes, false, false, 0, 0, 0).

qpack_json_preflight(<<>>, _InString, _Escaped, _Depth, _Nodes,
                     _IntegerBytes) -> ok;
qpack_json_preflight(<<_Byte, Rest/binary>>, true, true, Depth, Nodes,
                     IntegerBytes) ->
    qpack_json_preflight(Rest, true, false, Depth, Nodes, IntegerBytes);
qpack_json_preflight(<<$\\, Rest/binary>>, true, false, Depth, Nodes,
                     IntegerBytes) ->
    qpack_json_preflight(Rest, true, true, Depth, Nodes, IntegerBytes);
qpack_json_preflight(<<$", Rest/binary>>, true, false, Depth, Nodes,
                     IntegerBytes) ->
    qpack_json_preflight(Rest, false, false, Depth, Nodes, IntegerBytes);
qpack_json_preflight(<<_Byte, Rest/binary>>, true, false, Depth, Nodes,
                     IntegerBytes) ->
    qpack_json_preflight(Rest, true, false, Depth, Nodes, IntegerBytes);
qpack_json_preflight(<<$", Rest/binary>>, false, _Escaped, Depth, Nodes,
                     _IntegerBytes) ->
    qpack_json_preflight(Rest, true, false, Depth, Nodes, 0);
qpack_json_preflight(<<Byte, Rest/binary>>, false, _Escaped, Depth, Nodes,
                     _IntegerBytes) when Byte =:= ${; Byte =:= $[ ->
    NextDepth = Depth + 1,
    NextNodes = Nodes + 1,
    ensure_validation(NextDepth =< ?MAX_JSON_DEPTH + 1,
                      json_depth_limit),
    ensure_validation(NextNodes =< ?MAX_JSON_NODES, json_node_limit),
    qpack_json_preflight(Rest, false, false, NextDepth, NextNodes, 0);
qpack_json_preflight(<<Byte, Rest/binary>>, false, _Escaped, Depth, Nodes,
                     _IntegerBytes) when Byte =:= $}; Byte =:= $] ->
    ensure_validation(Depth > 0, invalid_json),
    qpack_json_preflight(Rest, false, false, Depth - 1, Nodes, 0);
qpack_json_preflight(<<$,, Rest/binary>>, false, _Escaped, Depth, Nodes,
                     _IntegerBytes) ->
    NextNodes = Nodes + 1,
    ensure_validation(NextNodes =< ?MAX_JSON_NODES, json_node_limit),
    qpack_json_preflight(Rest, false, false, Depth, NextNodes, 0);
qpack_json_preflight(<<Byte, Rest/binary>>, false, _Escaped, Depth, Nodes,
                     IntegerBytes) ->
    case qpack_json_integer_character(Byte) of
        true ->
            NextIntegerBytes = IntegerBytes + 1,
            ensure_validation(
                NextIntegerBytes =< ?MAX_JSON_INTEGER_TOKEN_BYTES,
                json_integer_token_limit),
            qpack_json_preflight(Rest, false, false, Depth, Nodes,
                                NextIntegerBytes);
        false -> qpack_json_preflight(Rest, false, false, Depth, Nodes, 0)
    end.

qpack_json_integer_character(Byte) when Byte >= $0, Byte =< $9 -> true;
qpack_json_integer_character($-) -> true;
qpack_json_integer_character($+) -> true;
qpack_json_integer_character($.) -> true;
qpack_json_integer_character($e) -> true;
qpack_json_integer_character($E) -> true;
qpack_json_integer_character(_) -> false.

write_json(Path, Value) ->
    qpack_validate_json_shape(Value),
    Bytes = iolist_to_binary([json:encode(Value), <<"\n">>]),
    ensure_validation(byte_size(Bytes) > 0 andalso
                      byte_size(Bytes) =< ?MAX_OUTPUT_BYTES,
                      output_byte_limit),
    ok = evidence_publish_new(Path, Bytes, ?MAX_OUTPUT_BYTES),
    Bytes = qpack_read(Path, ?MAX_OUTPUT_BYTES, true),
    #{bytes => Bytes, size => byte_size(Bytes), sha256 => digest_bytes(Bytes)}.

qpack_read(Path, Maximum, AllowHeldLock) ->
    ensure_validation(is_list(Path) andalso Path =/= [], invalid_path),
    ensure_validation(is_integer(Maximum) andalso Maximum > 0 andalso
                      Maximum =< ?MAX_INPUT_BYTES, invalid_read_limit),
    case AllowHeldLock of
        true -> ok;
        false -> ensure_lock_absent(Path)
    end,
    try evidence_publication_read(Path, Maximum) of
        Bytes ->
            case AllowHeldLock of
                true -> ok;
                false -> ensure_lock_absent(Path)
            end,
            Bytes
    catch
        _:_ -> validation(input_read_rejected)
    end.

digest_bytes(Bytes) -> hex(crypto:hash(sha256, Bytes)).

encode_hex(Bytes) ->
    list_to_binary(string:lowercase(binary_to_list(binary:encode_hex(Bytes)))).

decode_hex(Value, MaximumBytes, AllowEmpty)
  when is_binary(Value), is_integer(MaximumBytes), MaximumBytes >= 0,
       is_boolean(AllowEmpty), byte_size(Value) rem 2 =:= 0,
       byte_size(Value) =< MaximumBytes * 2 ->
    ensure_validation(AllowEmpty orelse byte_size(Value) > 0, invalid_hex),
    ensure_validation(lists:all(fun is_lower_hex/1, binary_to_list(Value)),
                      invalid_hex_digit),
    try binary:decode_hex(Value) of
        Bytes -> Bytes
    catch _:_ -> validation(invalid_hex) end;
decode_hex(_Value, _MaximumBytes, _AllowEmpty) -> validation(invalid_hex).

is_lower_hex(Value) when Value >= $0, Value =< $9 -> true;
is_lower_hex(Value) when Value >= $a, Value =< $f -> true;
is_lower_hex(_) -> false.

exact_keys(Map, Keys, Reason) when is_map(Map), is_list(Keys) ->
    ensure_validation(lists:sort(maps:keys(Map)) =:= lists:sort(Keys), Reason);
exact_keys(_Map, _Keys, Reason) -> validation(Reason).

validate_oracle_identity(Oracle) ->
    ensure_validation(is_map(Oracle), invalid_oracle),
    exact_keys(Oracle,
        [<<"name">>, <<"version">>, <<"requirements_lock">>,
         <<"requirements_lock_sha256">>, <<"driver_sha256">>,
         <<"python_runtime">>, <<"module_files">>], invalid_oracle_fields),
    ensure_validation(required(Oracle, <<"name">>) =:= <<"pylsqpack">>,
                      invalid_oracle_name),
    ensure_validation(required(Oracle, <<"version">>) =:= ?VERSION,
                      invalid_oracle_version),
    ensure_validation(required(Oracle, <<"requirements_lock">>) =:=
                      <<"packages/http3/test/interop/requirements.txt">>,
                      invalid_oracle_lock_path),
    LockDigest = required(Oracle, <<"requirements_lock_sha256">>),
    DriverDigest = required(Oracle, <<"driver_sha256">>),
    validate_digest(LockDigest, invalid_oracle_lock_digest),
    validate_digest(DriverDigest, invalid_oracle_driver_digest),
    CurrentLock = qpack_read(
        "packages/http3/test/interop/requirements.txt",
        ?MAX_INPUT_BYTES, false),
    CurrentDriver = qpack_read(
        "packages/http3/test/interop/qpack_oracle.py",
        ?MAX_INPUT_BYTES, false),
    ensure_validation(LockDigest =:= digest_bytes(CurrentLock),
                      stale_oracle_lock_identity),
    ensure_validation(DriverDigest =:= digest_bytes(CurrentDriver),
                      stale_oracle_driver_identity),
    validate_python_runtime_identity(required(Oracle, <<"python_runtime">>)),
    Modules = required(Oracle, <<"module_files">>),
    ensure_validation(is_list(Modules) andalso length(Modules) >= 1 andalso
                      length(Modules) =< 4, invalid_oracle_modules),
    Roles = [validate_oracle_module(Module) || Module <- Modules],
    ensure_validation(length(Roles) =:= length(lists:usort(Roles)),
                      duplicate_oracle_module_role),
    ok.

validate_python_runtime_identity(Runtime) ->
    ensure_validation(is_map(Runtime), invalid_python_runtime_identity),
    exact_keys(Runtime, [<<"implementation">>, <<"version">>, <<"cache_tag">>],
               invalid_python_runtime_fields),
    ensure_validation(required(Runtime, <<"implementation">>) =:= <<"cpython">>,
                      invalid_python_implementation),
    PythonVersion = required(Runtime, <<"version">>),
    ensure_validation(is_binary(PythonVersion) andalso
                      byte_size(PythonVersion) > 0 andalso
                      byte_size(PythonVersion) =< 32 andalso
                      re:run(PythonVersion,
                             <<"^[0-9]{1,8}(?:\\.[0-9]{1,8}){2}$">>,
                             [{capture, none}]) =:= match,
                      invalid_python_version),
    CacheTag = required(Runtime, <<"cache_tag">>),
    ensure_validation(is_binary(CacheTag) andalso byte_size(CacheTag) > 0 andalso
                      byte_size(CacheTag) =< 64 andalso
                      re:run(CacheTag, <<"^[a-z0-9_-]+$">>,
                             [{capture, none}]) =:= match,
                      invalid_python_cache_tag),
    ok.

validate_oracle_module(Module) ->
    ensure_validation(is_map(Module), invalid_oracle_module),
    exact_keys(Module, [<<"role">>, <<"sha256">>, <<"bytes">>],
               invalid_oracle_module_fields),
    Role = required(Module, <<"role">>),
    ensure_validation(is_binary(Role) andalso byte_size(Role) > 0 andalso
                      byte_size(Role) =< 32 andalso
                      lists:all(fun is_role_character/1,
                                binary_to_list(Role)),
                      invalid_oracle_module_role),
    validate_digest(required(Module, <<"sha256">>),
                    invalid_oracle_module_digest),
    validate_bounded_integer(required(Module, <<"bytes">>), 1,
                             ?MAX_INPUT_BYTES, invalid_oracle_module_size),
    Role.

is_role_character(Value) when Value >= $a, Value =< $z -> true;
is_role_character($-) -> true;
is_role_character($_) -> true;
is_role_character(_) -> false.

validate_digest(Value, Reason) ->
    ensure_validation(is_binary(Value) andalso byte_size(Value) =:= 64,
                      Reason),
    _ = decode_hex(Value, 32, false),
    ok.

validate_run_id(Value) ->
    ensure_validation(is_binary(Value) andalso
                      byte_size(Value) =:= ?RUN_ID_BYTES * 2,
                      invalid_oracle_run_id),
    _ = decode_hex(Value, ?RUN_ID_BYTES, false),
    ok.

validate_bounded_integer(Value, Minimum, Maximum, Reason) ->
    ensure_validation(is_integer(Value) andalso Value >= Minimum andalso
                      Value =< Maximum, Reason).

oracle_identity_fixture() ->
    Driver = qpack_read("packages/http3/test/interop/qpack_oracle.py",
                        ?MAX_INPUT_BYTES, false),
    Lock = qpack_read("packages/http3/test/interop/requirements.txt",
                      ?MAX_INPUT_BYTES, false),
    #{<<"name">> => <<"pylsqpack">>,
      <<"version">> => ?VERSION,
      <<"requirements_lock">> =>
          <<"packages/http3/test/interop/requirements.txt">>,
      <<"requirements_lock_sha256">> => digest_bytes(Lock),
      <<"driver_sha256">> => digest_bytes(Driver),
      <<"python_runtime">> =>
          #{<<"implementation">> => <<"cpython">>,
            <<"version">> => <<"3.12.0">>,
            <<"cache_tag">> => <<"cpython-312">>},
      <<"module_files">> =>
          [#{<<"role">> => <<"binding">>,
             <<"sha256">> => binary:copy(<<"00">>, 32),
             <<"bytes">> => 1}]}.

validate_campaign_bindings(OracleIdentity, OracleRunId, Implementation,
                           OracleReport) ->
    ensure_validation(required(Implementation, <<"oracle">>) =:=
                      OracleIdentity, implementation_oracle_identity_drift),
    ensure_validation(required(OracleReport, <<"oracle">>) =:=
                      OracleIdentity, oracle_report_identity_drift),
    ensure_validation(required(Implementation, <<"oracle_run_id">>) =:=
                      OracleRunId, implementation_oracle_run_drift),
    ensure_validation(required(OracleReport, <<"oracle_run_id">>) =:=
                      OracleRunId, oracle_report_run_drift),
    ok.

validate_capture(Captured, OracleDigest, OracleBytes, ImplementationDigest,
                 ImplementationBytes, OracleRunId, OracleIdentity, Build,
                 ManifestDigest, OracleSummary) ->
    ensure_validation(is_map(Captured), invalid_implementation_capture),
    exact_keys(Captured,
        [<<"artifact_sha256">>, <<"artifact_bytes">>,
         <<"oracle_corpus_sha256">>, <<"oracle_corpus_bytes">>,
         <<"oracle_run_id">>, <<"oracle_identity">>,
         <<"oracle_execution">>,
         <<"build_identity">>, <<"build_manifest_sha256">>,
         <<"evidence_identity">>, <<"execution_environment">>],
        invalid_implementation_capture_fields),
    ensure_validation(required(Captured, <<"artifact_sha256">>) =:=
                      ImplementationDigest, implementation_capture_changed),
    ensure_validation(required(Captured, <<"artifact_bytes">>) =:=
                      ImplementationBytes, implementation_capture_size_changed),
    ensure_validation(required(Captured, <<"oracle_corpus_sha256">>) =:=
                      OracleDigest, oracle_capture_changed),
    ensure_validation(required(Captured, <<"oracle_corpus_bytes">>) =:=
                      OracleBytes, oracle_capture_size_changed),
    ensure_validation(required(Captured, <<"oracle_run_id">>) =:= OracleRunId,
                      oracle_capture_run_changed),
    ensure_validation(required(Captured, <<"oracle_identity">>) =:=
                      OracleIdentity, oracle_capture_identity_changed),
    validate_oracle_execution(required(Captured, <<"oracle_execution">>),
                              OracleSummary),
    ensure_validation(required(Captured, <<"build_identity">>) =:= Build,
                      implementation_capture_build_changed),
    ensure_validation(required(Captured, <<"build_manifest_sha256">>) =:=
                      ManifestDigest, implementation_capture_manifest_changed),
    ok.

oracle_execution_summary(Summary) ->
    #{cases => maps:get(cases, Summary),
      fields => maps:get(fields, Summary),
      blocked_cases => maps:get(blocked_cases, Summary),
      encoder_instructions => maps:get(encoder_instructions, Summary),
      feedback_instructions => maps:get(feedback_instructions, Summary),
      feedback_bytes => maps:get(feedback_bytes, Summary),
      feedback_actions_verified => true}.

validate_oracle_execution(Execution, OracleSummary) ->
    ensure_validation(is_map(Execution), invalid_oracle_execution),
    exact_keys(Execution,
        [<<"cases">>, <<"fields">>, <<"blocked_cases">>,
         <<"encoder_instructions">>, <<"feedback_instructions">>,
         <<"feedback_bytes">>, <<"feedback_actions_verified">>],
        invalid_oracle_execution_fields),
    validate_bounded_integer(required(Execution, <<"cases">>), 1,
                             ?MAX_STEPS, invalid_oracle_execution_cases),
    validate_bounded_integer(required(Execution, <<"fields">>), 1,
                             ?MAX_TOTAL_FIELDS,
                             invalid_oracle_execution_fields_count),
    validate_bounded_integer(required(Execution, <<"blocked_cases">>), 0,
                             ?MAX_STEPS,
                             invalid_oracle_execution_blocked_cases),
    validate_bounded_integer(required(Execution, <<"encoder_instructions">>),
                             0, ?MAX_INSTRUCTIONS,
                             invalid_oracle_execution_encoder_instructions),
    validate_bounded_integer(required(Execution, <<"feedback_instructions">>),
                             0, ?MAX_INSTRUCTIONS,
                             invalid_oracle_execution_feedback_instructions),
    validate_bounded_integer(required(Execution, <<"feedback_bytes">>), 0,
                             ?MAX_TOTAL_ENCODED_BYTES,
                             invalid_oracle_execution_feedback_bytes),
    ensure_validation(required(Execution, <<"feedback_actions_verified">>)
                      =:= true,
                      oracle_feedback_actions_not_verified),
    ensure_validation(required(Execution, <<"cases">>) =:=
                      maps:get(cases, OracleSummary),
                      oracle_execution_case_drift),
    ensure_validation(required(Execution, <<"fields">>) =:=
                      maps:get(fields, OracleSummary),
                      oracle_execution_field_drift),
    ensure_validation(required(Execution, <<"blocked_cases">>) =:=
                      maps:get(blocked_cases, OracleSummary),
                      oracle_execution_blocked_drift),
    ok.

qpack_validate_json_shape(Value) ->
    qpack_validate_json_shape([{Value, 0}], 0).

qpack_validate_json_shape([], _Count) -> ok;
qpack_validate_json_shape([{Value, Depth} | Rest], Count0) ->
    Count = Count0 + 1,
    ensure_validation(Count =< ?MAX_JSON_NODES, json_node_limit),
    ensure_validation(Depth =< ?MAX_JSON_DEPTH, json_depth_limit),
    Pending = case Value of
        Map when is_map(Map) ->
            ensure_validation(map_size(Map) =< ?MAX_CONTAINER_ITEMS,
                              json_object_limit),
            lists:foreach(fun(Key) ->
                ensure_validation((is_binary(Key) andalso byte_size(Key) =< 256)
                                  orelse is_atom(Key), invalid_json_key)
            end, maps:keys(Map)),
            [{Member, Depth + 1} || {_Key, Member} <- maps:to_list(Map)];
        List when is_list(List) ->
            ensure_validation(length(List) =< ?MAX_CONTAINER_ITEMS,
                              json_array_limit),
            [{Member, Depth + 1} || Member <- List];
        Binary when is_binary(Binary) ->
            ensure_validation(byte_size(Binary) =< ?MAX_INPUT_BYTES,
                              json_string_limit), [];
        Integer when is_integer(Integer) ->
            ensure_validation(Integer >= -9223372036854775808 andalso
                              Integer =< 9223372036854775807,
                              json_integer_limit), [];
        true -> [];
        false -> [];
        null -> [];
        _ -> validation(invalid_json_scalar)
    end,
    qpack_validate_json_shape(lists:reverse(Pending, Rest), Count).

qpack_adversarial_self_test(Valid) ->
    ValidSummary = validate_transcript(Valid, <<"http3-to-pylsqpack">>),
    [Step] = maps:get(<<"steps">>, Valid),
    expect_validation(extra_document_key, fun() ->
        validate_transcript(Valid#{<<"unexpected">> => true},
                            <<"http3-to-pylsqpack">>)
    end),
    TooManyHeaders = Valid#{<<"steps">> :=
        [Step#{<<"headers">> := lists:duplicate(?MAX_HEADERS + 1,
                                                hd(maps:get(<<"headers">>, Step)))}]},
    expect_validation(header_count_limit, fun() ->
        validate_transcript(TooManyHeaders, <<"http3-to-pylsqpack">>)
    end),
    OversizedHex = binary:copy(<<"00">>, ?MAX_STEP_BYTES + 1),
    expect_validation(hex_size_limit, fun() ->
        validate_transcript(Valid#{<<"steps">> :=
            [Step#{<<"field_section">> := OversizedHex}]},
            <<"http3-to-pylsqpack">>)
    end),
    expect_validation(json_depth_limit, fun() ->
        qpack_validate_json_shape(deep_json(?MAX_JSON_DEPTH + 1, null))
    end),
    NodeBomb = [lists:duplicate(?MAX_CONTAINER_ITEMS, null)
                || _ <- lists:seq(1, 25)],
    expect_validation(json_node_limit, fun() ->
        qpack_validate_json_shape(NodeBomb)
    end),
    DeepJson = iolist_to_binary([
        binary:copy(<<"[">>, ?MAX_JSON_DEPTH + 2), <<"0">>,
        binary:copy(<<"]">>, ?MAX_JSON_DEPTH + 2)]),
    expect_validation(json_text_depth_limit, fun() ->
        qpack_json_preflight(DeepJson)
    end),
    NodeJson = iolist_to_binary([
        <<"[">>, lists:join(<<",">>,
            lists:duplicate(?MAX_JSON_NODES + 1, <<"0">>)), <<"]">>]),
    expect_validation(json_text_node_limit, fun() ->
        qpack_json_preflight(NodeJson)
    end),
    IntegerJson = binary:copy(<<"9">>, ?MAX_JSON_INTEGER_TOKEN_BYTES + 1),
    expect_validation(json_integer_text_limit, fun() ->
        qpack_json_preflight(IntegerJson)
    end),
    expect_any_failure(encoder_instruction_total_limit, fun() ->
        apply_encoder_bytes(undefined, <<0>>, ?MAX_INSTRUCTIONS)
    end),
    expect_any_failure(decoder_instruction_total_limit, fun() ->
        count_decoder_bytes(<<0>>, ?MAX_INSTRUCTIONS)
    end),
    expect_any_failure(encoder_instruction_output_count_limit, fun() ->
        encode_encoder_instructions(
            lists:duplicate(?MAX_INSTRUCTIONS + 1, invalid), false)
    end),
    expect_any_failure(decoder_instruction_output_count_limit, fun() ->
        encode_decoder_instructions(
            lists:duplicate(?MAX_INSTRUCTIONS + 1, invalid))
    end),
    ensure(feedback_stream_actions(
        [{insert_count_increment, 1}, {section_acknowledgement, 4}]) =:=
        feedback_stream_actions([{section_acknowledgement, 4}]),
        feedback_increment_normalization_failed),
    expect_any_failure(feedback_action_drift, fun() ->
        ensure(feedback_stream_actions([{section_acknowledgement, 4}]) =:=
               feedback_stream_actions([{section_acknowledgement, 8}]),
               decoder_feedback_action_drift)
    end),
    Identity = maps:get(<<"oracle">>, Valid),
    RunId = maps:get(<<"oracle_run_id">>, Valid),
    MinimalReport = #{<<"oracle">> => Identity,
                      <<"oracle_run_id">> => RunId},
    expect_validation(stale_run, fun() ->
        validate_campaign_bindings(Identity, RunId,
            Valid#{<<"oracle_run_id">> := binary:copy(<<"02">>,
                                                      ?RUN_ID_BYTES)},
            MinimalReport)
    end),
    expect_validation(stale_report_run, fun() ->
        validate_campaign_bindings(Identity, RunId, Valid,
            MinimalReport#{<<"oracle_run_id">> :=
                binary:copy(<<"03">>, ?RUN_ID_BYTES)})
    end),
    StaleIdentity = Identity#{<<"driver_sha256">> :=
                              binary:copy(<<"00">>, 32)},
    expect_validation(stale_identity, fun() ->
        validate_oracle_identity(StaleIdentity)
    end),
    PythonRuntime = maps:get(<<"python_runtime">>, Identity),
    expect_validation(invalid_python_runtime, fun() ->
        validate_oracle_identity(Identity#{<<"python_runtime">> :=
            PythonRuntime#{<<"version">> := <<"unverified">>}})
    end),
    ArtifactDigest = binary:copy(<<"11">>, 32),
    OracleDigest = binary:copy(<<"22">>, 32),
    ManifestDigest = binary:copy(<<"33">>, 32),
    Build = #{<<"package">> => <<"http3">>},
    OracleExecution =
        #{<<"cases">> => maps:get(cases, ValidSummary),
          <<"fields">> => maps:get(fields, ValidSummary),
          <<"blocked_cases">> => maps:get(blocked_cases, ValidSummary),
          <<"encoder_instructions">> => 0,
          <<"feedback_instructions">> => 0,
          <<"feedback_bytes">> => 0,
          <<"feedback_actions_verified">> => true},
    Capture = #{<<"artifact_sha256">> => ArtifactDigest,
                <<"artifact_bytes">> => 10,
                <<"oracle_corpus_sha256">> => OracleDigest,
                <<"oracle_corpus_bytes">> => 20,
                <<"oracle_run_id">> => RunId,
                <<"oracle_identity">> => Identity,
                <<"oracle_execution">> => OracleExecution,
                <<"build_identity">> => Build,
                <<"build_manifest_sha256">> => ManifestDigest,
                <<"evidence_identity">> => #{},
                <<"execution_environment">> => #{}},
    ok = validate_capture(Capture, OracleDigest, 20, ArtifactDigest, 10,
                          RunId, Identity, Build, ManifestDigest,
                          ValidSummary),
    expect_validation(stale_capture, fun() ->
        validate_capture(Capture#{<<"artifact_sha256">> :=
                                     binary:copy(<<"44">>, 32)},
                         OracleDigest, 20, ArtifactDigest, 10, RunId,
                         Identity, Build, ManifestDigest, ValidSummary)
    end),
    expect_validation(unverified_feedback_capture, fun() ->
        validate_capture(Capture#{<<"oracle_execution">> :=
            OracleExecution#{<<"feedback_actions_verified">> := false}},
            OracleDigest, 20, ArtifactDigest, 10, RunId, Identity, Build,
            ManifestDigest, ValidSummary)
    end),
    qpack_file_boundary_self_test(),
    qpack_broken_sink_self_test(),
    ok.

deep_json(0, Value) -> Value;
deep_json(Depth, Value) -> deep_json(Depth - 1, [Value]).

qpack_file_boundary_self_test() ->
    Root = filename:join("build/qpack-differential",
        "self-test-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(16), lowercase))),
    _ = evidence_publication_ensure_directory(Root),
    Plain = filename:join(Root, "plain.json"),
    Linked = filename:join(Root, "linked.json"),
    Oversized = filename:join(Root, "oversized.json"),
    Target = filename:join(Root, "published.json"),
    LateOutput = filename:join(Root, "late-output.json"),
    LateIdentity = filename:join(Root, "late-output.json.identity.json"),
    RetainedOutput = filename:join(Root, "retained-output.json"),
    RetainedLock = RetainedOutput ++ ?LOCK_SUFFIX,
    RetainedOwner = filename:join(RetainedLock, ?LOCK_OWNER),
    ChangedInput = filename:join(Root, "changed-input.json"),
    try
        ok = evidence_publish_new(Plain, <<"{}\n">>, ?MAX_INPUT_BYTES),
        ok = file:make_link(Plain, Linked),
        expect_validation(hardlink_input, fun() ->
            qpack_read(Plain, ?MAX_INPUT_BYTES, false)
        end),
        ok = file:delete(Linked),
        <<"{}\n">> = qpack_read(Plain, ?MAX_INPUT_BYTES, false),
        ok = evidence_publication_write_temporary(
            Oversized, binary:copy(<<"x">>, ?MAX_INPUT_BYTES + 1)),
        expect_validation(oversized_input, fun() ->
            qpack_read(Oversized, ?MAX_INPUT_BYTES, false)
        end),
        expect_validation(special_input, fun() ->
            qpack_read(Root, ?MAX_INPUT_BYTES, false)
        end),
        with_qpack_lock(Target, fun() ->
            expect_validation(lock_contention, fun() ->
                with_qpack_lock(Target, fun() -> ok end)
            end),
            ok = evidence_publish_new(Target, <<"old\n">>, ?MAX_OUTPUT_BYTES),
            expect_validation(held_lock_input, fun() ->
                qpack_read(Target, ?MAX_OUTPUT_BYTES, false)
            end),
            expect_any_failure(publication_collision, fun() ->
                write_json(Target, #{schema => 1})
            end),
            <<"old\n">> = qpack_read(Target, ?MAX_OUTPUT_BYTES, true),
            qpack_invalidate(Target)
        end),
        expect_any_failure(late_publication_cleanup, fun() ->
            qpack_publication_transaction([LateOutput, LateIdentity], fun() ->
                _ = write_json(LateOutput, #{schema => 1}),
                _ = write_json(LateIdentity, #{schema => 1}),
                erlang:error(late_publication_failure)
            end)
        end),
        ensure(qpack_path_absent(LateOutput),
               late_publication_output_survived),
        ensure(qpack_path_absent(LateIdentity),
               late_publication_identity_survived),
        expect_any_failure(unsafe_cleanup_retains_lock, fun() ->
            with_qpack_lock(RetainedOutput, fun() ->
                ok = file:make_dir(RetainedOutput),
                erlang:error(forced_late_failure)
            end)
        end),
        ensure(not qpack_path_absent(RetainedLock),
               failed_cleanup_released_lock),
        {ok, [?LOCK_OWNER]} = file:list_dir(RetainedLock),
        ok = evidence_publish_new(ChangedInput, <<"old\n">>, ?MAX_INPUT_BYTES),
        OriginalInput = qpack_read(ChangedInput, ?MAX_INPUT_BYTES, false),
        OriginalDigest = digest_bytes(OriginalInput),
        ok = file:write_file(ChangedInput, <<"new\n">>, [binary]),
        expect_validation(changed_verified_input, fun() ->
            qpack_require_unchanged_input(ChangedInput, OriginalInput,
                                          OriginalDigest)
        end),
        ok
    after
        qpack_delete_fixture(Linked),
        qpack_delete_fixture(Plain),
        qpack_delete_fixture(Oversized),
        qpack_delete_fixture(Target),
        qpack_delete_fixture(LateOutput),
        qpack_delete_fixture(LateIdentity),
        qpack_delete_fixture(RetainedOwner),
        qpack_delete_directory(RetainedLock),
        qpack_delete_directory(RetainedOutput),
        qpack_delete_fixture(ChangedInput),
        case file:del_dir(Root) of
            ok -> ok;
            {error, enoent} -> ok;
            {error, _} -> erlang:error(qpack_self_test_cleanup_failed)
        end
    end.

qpack_delete_fixture(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(qpack_self_test_cleanup_failed)
    end.

qpack_delete_directory(Path) ->
    case file:del_dir(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(qpack_self_test_cleanup_failed)
    end.

qpack_broken_sink_self_test() ->
    Sink = spawn(fun broken_sink_loop/0),
    Started = erlang:monotonic_time(millisecond),
    try
        safe_emit(Sink, <<"QPACK differential failed\n">>)
    after
        exit(Sink, kill)
    end,
    ensure(erlang:monotonic_time(millisecond) - Started < 1000,
           broken_sink_deadline_exceeded).

broken_sink_loop() ->
    receive _ -> broken_sink_loop() end.

expect_any_failure(Name, Fun) ->
    try Fun() of
        _ -> erlang:error({self_test_expected_failure, Name})
    catch
        error:{self_test_expected_failure, Name} ->
            erlang:error({self_test_expected_failure, Name});
        _:_ -> ok
    end.

qpack_evidence_begin(Path) ->
    qpack_invalidate(Path),
    evidence_identity().

qpack_publication_transaction(Paths, Function)
  when is_list(Paths), is_function(Function, 0) ->
    try Function()
    catch
        Class:Reason:Stacktrace ->
            qpack_cleanup_failed_publication(Paths),
            erlang:raise(Class, Reason, Stacktrace)
    end.

qpack_cleanup_failed_publication(Paths) ->
    lists:foreach(fun(Path) ->
        qpack_invalidate(Path),
        ensure_validation(qpack_path_absent(Path),
                          failed_publication_cleanup)
    end, Paths).

qpack_invalidate(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, _} ->
            _ = qpack_read(Path, ?MAX_OUTPUT_BYTES, true),
            case file:delete(Path) of
                ok -> ok;
                {error, _} -> validation(prior_output_invalidation_failed)
            end,
            ensure_validation(qpack_path_absent(Path),
                              prior_output_invalidation_failed);
        {error, _} -> validation(prior_output_inspection_failed)
    end.

with_qpack_lock(Path0, Function) when is_function(Function, 0) ->
    Path = filename:absname(Path0),
    Parent = filename:dirname(Path),
    _ = evidence_publication_ensure_directory(Parent),
    Lock = Path ++ ?LOCK_SUFFIX,
    case file:make_dir(Lock) of
        ok -> ok;
        {error, eexist} ->
            qpack_invalidate(Path),
            validation(active_or_abandoned_publication);
        {error, _} -> validation(publication_lock_failed)
    end,
    Token = binary:encode_hex(crypto:strong_rand_bytes(32), lowercase),
    Owner = filename:join(Lock, ?LOCK_OWNER),
    OwnerBytes = iolist_to_binary([json:encode(
        #{schema => 1, kind => <<"qpack-oracle-publication">>,
          status => <<"Writing">>, token => Token}), <<"\n">>]),
    ok = evidence_publication_write_temporary(Owner, OwnerBytes),
    OwnerBytes = evidence_publication_read(Owner, 4096),
    try Function() of
        Result ->
            release_qpack_lock(Lock, Owner, OwnerBytes),
            Result
    catch
        Class:Reason:Stacktrace ->
            case qpack_try_invalidate(Path) of
                ok ->
                    release_qpack_lock(Lock, Owner, OwnerBytes),
                    erlang:raise(Class, Reason, Stacktrace);
                retained ->
                    erlang:error(publication_lock_retained)
            end
    end.

qpack_try_invalidate(Path) ->
    try
        qpack_invalidate(Path),
        ensure_validation(qpack_path_absent(Path),
                          failed_publication_cleanup),
        ok
    catch _:_ -> retained end.

release_qpack_lock(Lock, Owner, Expected) ->
    try
        Expected = evidence_publication_read(Owner, 4096),
        {ok, Names} = file:list_dir(Lock),
        [?LOCK_OWNER] = lists:sort(Names),
        ok = file:delete(Owner),
        ok = file:del_dir(Lock),
        true = qpack_path_absent(Lock),
        ok
    catch _:_ -> erlang:error(publication_lock_release_failed) end.

ensure_lock_absent(Path) ->
    ensure_validation(qpack_path_absent(filename:absname(Path) ++ ?LOCK_SUFFIX),
                      active_or_abandoned_publication).

qpack_path_absent(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> true;
        _ -> false
    end.

safe_emit(Device, Bytes) when is_binary(Bytes), byte_size(Bytes) =< 4096 ->
    {Pid, Monitor} = spawn_monitor(fun() ->
        try io:put_chars(Device, Bytes) catch _:_ -> ok end
    end),
    receive
        {'DOWN', Monitor, process, Pid, _} -> ok
    after 100 ->
        exit(Pid, kill),
        receive {'DOWN', Monitor, process, Pid, _} -> ok after 100 -> ok end
    end.

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
