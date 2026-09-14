#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include_lib("kernel/include/file.hrl").

-define(MAX_TRACES, 256).
-define(MAX_TRACE_BYTES, 16777216).
-define(MAX_TOTAL_BYTES, 134217728).
-define(MAX_RECORDS_PER_TRACE, 200000).
-define(MAX_TOTAL_RECORDS, 1000000).
-define(OUTPUT_RELATIVE, "build/diagnostics/qlog-failures").
-define(PROFILE_RELATIVE, "standards/qlog-profile.json").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "qlog preservation failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["capture", SourceDirectory, ArtifactName]) ->
    capture(SourceDirectory, ArtifactName);
run(["verify", ArtifactName]) ->
    verify(ArtifactName);
run(["--self-test"]) ->
    self_test();
run(_) ->
    erlang:error(
      {usage,
       "capture SOURCE_DIRECTORY ARTIFACT_NAME | verify ARTIFACT_NAME | "
       "--self-test"}).

capture(SourceDirectory0, ArtifactName) ->
    ensure(valid_artifact_name(ArtifactName),
           {invalid_artifact_name, ArtifactName}),
    Root = repository_root(),
    SourceDirectory = filename:absname(SourceDirectory0),
    validate_source_directory(SourceDirectory),
    OutputBase = filename:join(Root, ?OUTPUT_RELATIVE),
    TargetDirectory = filename:join(OutputBase, ArtifactName),
    ensure(filename:dirname(TargetDirectory) =:= OutputBase,
           {unsafe_artifact_directory, TargetDirectory}),
    ensure(not filelib:is_file(TargetDirectory),
           {artifact_already_exists, TargetDirectory}),
    ArtifactRelative = filename:join(?OUTPUT_RELATIVE, ArtifactName),
    Provenance = provenance(Root),
    Entries = read_source_traces(SourceDirectory, ArtifactRelative),
    Manifest = build_manifest(SourceDirectory, ArtifactRelative,
                              Provenance, Entries),
    write_artifact(TargetDirectory, Entries, Manifest),
    verify_artifact(TargetDirectory, list_to_binary(ArtifactRelative)),
    ManifestPath = filename:join(TargetDirectory, "manifest.json"),
    ManifestDigest = sha256(read(ManifestPath)),
    io:format("preserved ~B payload-free qlog traces (~B bytes, ~B events) "
              "at ~s; manifest sha256 ~s~n",
              [length(Entries), manifest_total_bytes(Manifest),
               manifest_total_events(Manifest), ArtifactRelative,
               ManifestDigest]),
    ok.

verify(ArtifactName) ->
    ensure(valid_artifact_name(ArtifactName),
           {invalid_artifact_name, ArtifactName}),
    Root = repository_root(),
    ArtifactRelative = filename:join(?OUTPUT_RELATIVE, ArtifactName),
    TargetDirectory = filename:join(Root, ArtifactRelative),
    verify_artifact(TargetDirectory, list_to_binary(ArtifactRelative)),
    Manifest = decode_json_file(filename:join(TargetDirectory,
                                               "manifest.json")),
    io:format("verified ~B payload-free qlog traces at ~s; trace-set "
              "sha256 ~s~n",
              [length(maps:get(<<"traces">>, Manifest)), ArtifactRelative,
               maps:get(<<"trace_set_sha256">>, Manifest)]),
    ok.

repository_root() ->
    Script = filename:absname(escript:script_name()),
    filename:dirname(filename:dirname(Script)).

provenance(Root) ->
    ToolPath = filename:join(Root, "scripts/qlog_preserve.escript"),
    ProfilePath = filename:join(Root, ?PROFILE_RELATIVE),
    #{<<"tool">> => <<"scripts/qlog_preserve.escript">>,
      <<"tool_sha256">> => sha256(read(ToolPath)),
      <<"qlog_profile">> => list_to_binary(?PROFILE_RELATIVE),
      <<"qlog_profile_sha256">> => sha256(read(ProfilePath))}.

valid_artifact_name(Name) ->
    length(Name) >= 1 andalso length(Name) =< 96 andalso
    Name =/= "." andalso Name =/= ".." andalso
    string:find(Name, "..") =:= nomatch andalso
    re:run(Name, "^[a-z0-9][a-z0-9._-]*$", [{capture, none}]) =:= match.

validate_source_directory(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = directory}} -> ok;
        {ok, #file_info{type = Type}} ->
            erlang:error({source_is_not_plain_directory, Path, Type});
        {error, Reason} ->
            erlang:error({cannot_inspect_source_directory, Path, Reason})
    end.

read_source_traces(SourceDirectory, ArtifactRelative) ->
    {ok, Names0} = file:list_dir(SourceDirectory),
    Names = lists:sort(Names0),
    ensure(Names =/= [], {empty_qlog_source_directory, SourceDirectory}),
    ensure(length(Names) =< ?MAX_TRACES,
           {too_many_source_entries, length(Names), ?MAX_TRACES}),
    lists:foreach(fun validate_qlog_filename/1, Names),
    Entries = read_source_traces(Names, SourceDirectory, ArtifactRelative,
                                 [], 0, 0),
    ensure(length(Entries) >= 1, no_qlog_traces),
    lists:reverse(Entries).

read_source_traces([], _Source, _Artifact, Entries, _Bytes, _Records) ->
    Entries;
read_source_traces([Name | Rest], Source, Artifact, Entries,
                   TotalBytes0, TotalRecords0) ->
    SourcePath = filename:join(Source, Name),
    validate_plain_trace(SourcePath),
    Bytes = read_bounded_trace(SourcePath),
    TotalBytes = TotalBytes0 + byte_size(Bytes),
    ensure(TotalBytes =< ?MAX_TOTAL_BYTES,
           {qlog_source_too_large, TotalBytes, ?MAX_TOTAL_BYTES}),
    ArtifactPath = filename:join([Artifact, "traces", Name]),
    Summary = summarize_trace(Name, ArtifactPath, Bytes),
    TotalRecords = TotalRecords0 + maps:get(<<"records">>, Summary),
    ensure(TotalRecords =< ?MAX_TOTAL_RECORDS,
           {too_many_qlog_records, TotalRecords, ?MAX_TOTAL_RECORDS}),
    Entry = #{name => Name, bytes => Bytes, summary => Summary},
    read_source_traces(Rest, Source, Artifact, [Entry | Entries],
                       TotalBytes, TotalRecords).

validate_qlog_filename(Name) ->
    Valid = length(Name) >= 6 andalso length(Name) =< 128 andalso
        filename:extension(Name) =:= ".qlog" andalso
        re:run(Name, "^[A-Za-z0-9][A-Za-z0-9._-]*[.]qlog$",
               [{capture, none}]) =:= match,
    ensure(Valid, {unexpected_qlog_source_entry, Name}).

validate_plain_trace(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = regular, size = Size}}
                when Size > 0, Size =< ?MAX_TRACE_BYTES -> ok;
        {ok, #file_info{type = regular, size = Size}} ->
            erlang:error({invalid_qlog_trace_size, Path, Size,
                          ?MAX_TRACE_BYTES});
        {ok, #file_info{type = Type}} ->
            erlang:error({qlog_trace_is_not_plain_file, Path, Type});
        {error, Reason} ->
            erlang:error({cannot_inspect_qlog_trace, Path, Reason})
    end.

read_bounded_trace(Path) ->
    Bytes = read(Path),
    ensure(byte_size(Bytes) =< ?MAX_TRACE_BYTES,
           {qlog_trace_grew_while_reading, Path, byte_size(Bytes),
            ?MAX_TRACE_BYTES}),
    Bytes.

summarize_trace(Name, ArtifactPath, Bytes) ->
    Records = decode_sequence(Bytes),
    ensure(length(Records) =< ?MAX_RECORDS_PER_TRACE,
           {too_many_trace_records, Name, length(Records),
            ?MAX_RECORDS_PER_TRACE}),
    [Header | Events] = Records,
    VantagePoint = validate_header(Header),
    validate_events(Events),
    ensure(Events =/= [], {qlog_without_events, Name}),
    First = hd(Events),
    Last = lists:last(Events),
    FirstTime = maps:get(<<"time">>, First),
    LastTime = maps:get(<<"time">>, Last),
    Times = [maps:get(<<"time">>, Event) || Event <- Events],
    LastReceive = last_activity_time(Events, receive_event_names()),
    LastSend = last_activity_time(Events, send_event_names()),
    LastHttp3 = last_http3_time(Events),
    #{<<"artifact">> => list_to_binary(ArtifactPath),
      <<"sha256">> => sha256(Bytes),
      <<"bytes">> => byte_size(Bytes),
      <<"records">> => length(Records),
      <<"events">> => length(Events),
      <<"vantage_point">> => VantagePoint,
      <<"first_event">> => maps:get(<<"name">>, First),
      <<"first_time_ms">> => FirstTime,
      <<"last_event">> => maps:get(<<"name">>, Last),
      <<"last_time_ms">> => LastTime,
      <<"minimum_time_ms">> => lists:min(Times),
      <<"maximum_time_ms">> => lists:max(Times),
      <<"duration_ms">> => lists:max(Times) - lists:min(Times),
      <<"last_receive_time_ms">> => LastReceive,
      <<"last_send_time_ms">> => LastSend,
      <<"last_http3_time_ms">> => LastHttp3,
      <<"quiet_before_close_ms">> => optional_difference(LastTime,
                                                         LastReceive),
      <<"event_counts">> => event_counts(Events),
      <<"event_timing">> => event_timing(Events),
      <<"sequence_findings">> => sequence_findings(Events),
      <<"maximum_event_gap">> => maximum_event_gap(Events)}.

decode_sequence(Bytes) ->
    ensure(byte_size(Bytes) > 0, empty_qlog),
    ensure(binary:first(Bytes) =:= 16#1e,
           missing_initial_record_separator),
    [<<>> | Chunks] = binary:split(Bytes, <<16#1e>>, [global]),
    ensure(Chunks =/= [] andalso
           lists:all(fun(Chunk) -> byte_size(Chunk) > 0 end, Chunks),
           empty_qlog_record),
    [decode_record(Chunk) || Chunk <- Chunks].

decode_record(Chunk) ->
    ensure(binary:last(Chunk) =:= $\n, record_without_line_feed),
    Json = binary:part(Chunk, 0, byte_size(Chunk) - 1),
    ensure(byte_size(Json) > 0 andalso
           binary:match(Json, <<"\n">>) =:= nomatch andalso
           binary:match(Json, <<"\r">>) =:= nomatch,
           qlog_record_must_be_single_line),
    Decoders =
        #{object_start => fun(_OldAccumulator) -> #{} end,
          object_push => fun unique_object_push/3,
          object_finish =>
              fun(Object, OldAccumulator) -> {Object, OldAccumulator} end},
    try json:decode(Json, ok, Decoders) of
        {Value, ok, <<>>} when is_map(Value) -> Value;
        {_Value, ok, <<>>} -> erlang:error(qlog_record_not_an_object);
        _ -> erlang:error(invalid_qlog_json)
    catch
        error:{duplicate_json_object_key, _Key} = Reason ->
            erlang:error(Reason);
        error:qlog_record_not_an_object ->
            erlang:error(qlog_record_not_an_object);
        _:_ -> erlang:error(invalid_qlog_json)
    end.

unique_object_push(Key, Value, Object) ->
    ensure(not maps:is_key(Key, Object), {duplicate_json_object_key, Key}),
    maps:put(Key, Value, Object).

validate_header(Header) ->
    exact_keys(Header,
               [<<"description">>, <<"file_schema">>,
                <<"serialization_format">>, <<"title">>, <<"trace">>],
               unexpected_qlog_header_keys),
    ensure(maps:get(<<"file_schema">>, Header) =:=
               <<"urn:ietf:params:qlog:file:sequential">>,
           invalid_qlog_file_schema),
    ensure(maps:get(<<"serialization_format">>, Header) =:=
               <<"application/qlog+json-seq">>,
           invalid_qlog_serialization),
    ensure(maps:get(<<"title">>, Header) =:=
               <<"quic_core HTTP/3 diagnostics">>,
           invalid_qlog_title),
    ensure(maps:get(<<"description">>, Header) =:=
               <<"draft-ietf-quic-qlog-main-schema-14; privacy=strict">>,
           invalid_qlog_privacy_profile),
    Trace = maps:get(<<"trace">>, Header),
    exact_keys(Trace,
               [<<"common_fields">>, <<"event_schemas">>,
                <<"vantage_point">>],
               unexpected_qlog_trace_header_keys),
    Common = maps:get(<<"common_fields">>, Trace),
    exact_keys(Common, [<<"reference_time">>, <<"time_format">>],
               unexpected_qlog_common_field_keys),
    ensure(maps:get(<<"time_format">>, Common) =:=
               <<"relative_to_epoch">>, invalid_qlog_time_format),
    Reference = maps:get(<<"reference_time">>, Common),
    exact_keys(Reference, [<<"clock_type">>, <<"epoch">>],
               unexpected_qlog_reference_time_keys),
    ensure(Reference =:= #{<<"clock_type">> => <<"monotonic">>,
                           <<"epoch">> => <<"unknown">>},
           invalid_qlog_reference_time),
    ensure(maps:get(<<"event_schemas">>, Trace) =:= event_schemas(),
           invalid_qlog_event_schemas),
    Vantage = maps:get(<<"vantage_point">>, Trace),
    exact_keys(Vantage, [<<"name">>, <<"type">>],
               unexpected_qlog_vantage_point_keys),
    ensure(maps:get(<<"name">>, Vantage) =:= <<"quic_core">>,
           invalid_qlog_vantage_point_name),
    Role = maps:get(<<"type">>, Vantage),
    ensure(lists:member(Role, [<<"client">>, <<"server">>]),
           invalid_qlog_vantage_point_type),
    Role.

event_schemas() ->
    [<<"urn:ietf:params:qlog:events:quic-13">>,
     <<"urn:ietf:params:qlog:events:http3-13">>,
     <<"urn:ietf:params:qlog:events:loglevel">>].

validate_events(Events) ->
    lists:foreach(
          fun(Event) ->
              exact_keys(Event, [<<"data">>, <<"name">>, <<"time">>],
                         unexpected_qlog_event_keys),
              Time = maps:get(<<"time">>, Event),
              bounded_integer(Time, 0, 9223372036854775807,
                              invalid_qlog_event_time),
              Name = maps:get(<<"name">>, Event),
              ensure(is_binary(Name), invalid_qlog_event_name),
              validate_event_data(Name, maps:get(<<"data">>, Event))
          end,
          Events),
    ok.

validate_event_data(<<"quic:connection_started">>, Data) ->
    exact_keys(Data, [<<"local">>, <<"remote">>],
               unexpected_connection_started_keys),
    ensure(maps:get(<<"local">>, Data) =:= #{} andalso
           maps:get(<<"remote">>, Data) =:= #{},
           endpoint_identity_not_redacted);
validate_event_data(Name, Data)
        when Name =:= <<"quic:udp_datagrams_received">>;
             Name =:= <<"quic:udp_datagrams_sent">> ->
    exact_optional_keys(Data, [<<"count">>], [<<"raw">>],
                        unexpected_datagram_event_keys),
    bounded_integer(maps:get(<<"count">>, Data), 1, 65535,
                    invalid_datagram_count),
    case maps:find(<<"raw">>, Data) of
        error -> ok;
        {ok, Raw} -> validate_datagram_raw(Raw)
    end;
validate_event_data(<<"quic:migration_state_updated">>, Data) ->
    exact_keys(Data, [<<"new">>], unexpected_migration_event_keys),
    ensure(lists:member(maps:get(<<"new">>, Data),
                        [<<"migration_started">>,
                         <<"migration_abandoned">>,
                         <<"migration_complete">>]),
           invalid_migration_state);
validate_event_data(<<"quic:connection_closed">>, Data) ->
    exact_keys(Data, [<<"initiator">>, <<"trigger">>],
               unexpected_connection_closed_keys),
    ensure(Data =:= #{<<"initiator">> => <<"local">>,
                      <<"trigger">> => <<"application">>},
           invalid_connection_close);
validate_event_data(Name, Data)
        when Name =:= <<"quic:packet_received">>;
             Name =:= <<"quic:packet_sent">> ->
    exact_optional_keys(Data, [<<"header">>], [<<"raw">>],
                        unexpected_packet_event_keys),
    Header = maps:get(<<"header">>, Data),
    exact_keys(Header, [<<"packet_type">>],
               unexpected_packet_header_keys),
    ensure(lists:member(maps:get(<<"packet_type">>, Header),
                        [<<"initial">>, <<"handshake">>, <<"0RTT">>,
                         <<"1RTT">>, <<"retry">>,
                         <<"version_negotiation">>,
                         <<"stateless_reset">>, <<"unknown">>]),
           invalid_packet_type),
    validate_optional_length(Data);
validate_event_data(Name, Data)
        when Name =:= <<"quic:key_updated">>;
             Name =:= <<"quic:key_discarded">> ->
    exact_keys(Data, [<<"key_type">>, <<"trigger">>],
               unexpected_key_event_keys),
    ensure(maps:get(<<"trigger">>, Data) =:= <<"tls">>,
           invalid_key_trigger),
    ensure(lists:member(maps:get(<<"key_type">>, Data), key_types()),
           invalid_key_type);
validate_event_data(<<"quic:recovery_metrics_updated">>, Data) ->
    exact_keys(Data, [<<"bytes_in_flight">>, <<"congestion_window">>],
               unexpected_recovery_metric_keys),
    bounded_integer(maps:get(<<"bytes_in_flight">>, Data), 0,
                    9223372036854775807, invalid_bytes_in_flight),
    bounded_integer(maps:get(<<"congestion_window">>, Data), 0,
                    9223372036854775807, invalid_congestion_window);
validate_event_data(<<"quic:congestion_state_updated">>, Data) ->
    exact_optional_keys(Data, [<<"new">>], [<<"trigger">>],
                        unexpected_congestion_state_keys),
    ensure(lists:member(maps:get(<<"new">>, Data),
                        [<<"slow_start">>, <<"congestion_avoidance">>,
                         <<"recovery">>, <<"application_limited">>]),
           invalid_congestion_state),
    case maps:find(<<"trigger">>, Data) of
        error -> ok;
        {ok, Trigger} ->
            ensure(lists:member(Trigger,
                                [<<"packet_loss">>, <<"ecn_ce">>,
                                 <<"persistent_congestion">>]),
                   invalid_congestion_trigger)
    end;
validate_event_data(<<"http3:parameters_set">>, Data) ->
    exact_keys(Data, [<<"initiator">>],
               unexpected_http3_parameter_keys),
    validate_initiator(maps:get(<<"initiator">>, Data));
validate_event_data(<<"http3:stream_type_set">>, Data) ->
    exact_keys(Data,
               [<<"initiator">>, <<"stream_id">>, <<"stream_type">>],
               unexpected_http3_stream_type_keys),
    validate_initiator(maps:get(<<"initiator">>, Data)),
    bounded_integer(maps:get(<<"stream_id">>, Data), 0,
                    4611686018427387903, invalid_http3_stream_id),
    ensure(lists:member(maps:get(<<"stream_type">>, Data),
                        [<<"request">>, <<"control">>, <<"push">>,
                         <<"reserved">>, <<"unknown">>,
                         <<"qpack_encode">>, <<"qpack_decode">>]),
           invalid_http3_stream_type);
validate_event_data(Name, Data)
        when Name =:= <<"http3:frame_created">>;
             Name =:= <<"http3:frame_parsed">> ->
    exact_keys(Data, [<<"frame">>, <<"stream_id">>],
               unexpected_http3_frame_event_keys),
    bounded_integer(maps:get(<<"stream_id">>, Data), 0,
                    4611686018427387903, invalid_http3_frame_stream_id),
    validate_frame(maps:get(<<"frame">>, Data));
validate_event_data(<<"loglevel:error">>, Data) ->
    exact_keys(Data, [<<"code">>], unexpected_loglevel_error_keys),
    bounded_integer(maps:get(<<"code">>, Data), 0, 2147483647,
                    invalid_application_diagnostic_code);
validate_event_data(Name, _Data) ->
    erlang:error({unsupported_qlog_event_for_payload_free_capture, Name}).

validate_datagram_raw(Raw) ->
    ensure(is_list(Raw) andalso Raw =/= [] andalso length(Raw) =< 65535,
           invalid_datagram_raw_summary),
    lists:foreach(
      fun(Info) ->
          exact_keys(Info, [<<"length">>],
                     unexpected_datagram_raw_keys),
          bounded_integer(maps:get(<<"length">>, Info), 1,
                          9223372036854775807,
                          invalid_datagram_raw_length)
      end,
      Raw).

validate_optional_length(Data) ->
    case maps:find(<<"raw">>, Data) of
        error -> ok;
        {ok, Raw} ->
            exact_keys(Raw, [<<"length">>], unexpected_raw_info_keys),
            bounded_integer(maps:get(<<"length">>, Raw), 1,
                            9223372036854775807, invalid_raw_length)
    end.

key_types() ->
    [<<"server_initial_secret">>, <<"client_initial_secret">>,
     <<"server_handshake_secret">>, <<"client_handshake_secret">>,
     <<"server_0rtt_secret">>, <<"client_0rtt_secret">>,
     <<"server_1rtt_secret">>, <<"client_1rtt_secret">>].

validate_initiator(Initiator) ->
    ensure(lists:member(Initiator, [<<"local">>, <<"remote">>]),
           invalid_http3_initiator).

validate_frame(Frame) ->
    ensure(is_map(Frame), invalid_http3_frame),
    FrameType = maps:get(<<"frame_type">>, Frame, undefined),
    {Required, Optional} = frame_keys(FrameType),
    exact_optional_keys(Frame, [<<"frame_type">> | Required],
                        [<<"raw">> | Optional],
                        unexpected_http3_frame_keys),
    validate_frame_redacted_fields(FrameType, Frame),
    validate_optional_length(Frame).

frame_keys(<<"data">>) -> {[], []};
frame_keys(<<"headers">>) -> {[<<"headers">>], []};
frame_keys(<<"cancel_push">>) -> {[<<"push_id">>], []};
frame_keys(<<"settings">>) -> {[<<"settings">>], []};
frame_keys(<<"push_promise">>) ->
    {[<<"headers">>, <<"push_id">>], []};
frame_keys(<<"goaway">>) -> {[<<"id">>], []};
frame_keys(<<"max_push_id">>) -> {[<<"push_id">>], []};
frame_keys(<<"unknown">>) -> {[<<"frame_type_bytes">>], []};
frame_keys(Other) -> erlang:error({invalid_http3_frame_type, Other}).

validate_frame_redacted_fields(<<"headers">>, Frame) ->
    ensure(maps:get(<<"headers">>, Frame) =:= [],
           http3_headers_not_redacted);
validate_frame_redacted_fields(<<"settings">>, Frame) ->
    ensure(maps:get(<<"settings">>, Frame) =:= [],
           http3_settings_not_redacted);
validate_frame_redacted_fields(<<"push_promise">>, Frame) ->
    ensure(maps:get(<<"headers">>, Frame) =:= [],
           http3_headers_not_redacted),
    ensure(maps:get(<<"push_id">>, Frame) =:= 0,
           http3_push_id_not_redacted);
validate_frame_redacted_fields(<<"cancel_push">>, Frame) ->
    ensure(maps:get(<<"push_id">>, Frame) =:= 0,
           http3_push_id_not_redacted);
validate_frame_redacted_fields(<<"max_push_id">>, Frame) ->
    ensure(maps:get(<<"push_id">>, Frame) =:= 0,
           http3_push_id_not_redacted);
validate_frame_redacted_fields(<<"goaway">>, Frame) ->
    ensure(maps:get(<<"id">>, Frame) =:= 0,
           http3_identifier_not_redacted);
validate_frame_redacted_fields(<<"unknown">>, Frame) ->
    ensure(maps:get(<<"frame_type_bytes">>, Frame) =:= 0,
           http3_unknown_frame_type_not_redacted);
validate_frame_redacted_fields(<<"data">>, _Frame) -> ok.

exact_keys(Value, Expected, Reason) ->
    ensure(is_map(Value), {expected_qlog_object, Reason}),
    Actual = lists:sort(maps:keys(Value)),
    ensure(Actual =:= lists:sort(Expected), {Reason, Actual}).

exact_optional_keys(Value, Required, Optional, Reason) ->
    ensure(is_map(Value), {expected_qlog_object, Reason}),
    Actual = lists:sort(maps:keys(Value)),
    ensure(lists:all(fun(Key) -> lists:member(Key, Actual) end, Required)
           andalso
           lists:all(fun(Key) -> lists:member(Key, Required ++ Optional) end,
                     Actual),
           {Reason, Actual}).

bounded_integer(Value, Minimum, Maximum, Reason) ->
    ensure(is_integer(Value) andalso Value >= Minimum andalso Value =< Maximum,
           {Reason, Value}).

event_counts(Events) ->
    lists:foldl(
      fun(Event, Counts) ->
          Name = maps:get(<<"name">>, Event),
          maps:update_with(Name, fun(Count) -> Count + 1 end, 1, Counts)
      end,
      #{},
      Events).

event_timing(Events) ->
    lists:foldl(
      fun(Event, Timings) ->
          Name = maps:get(<<"name">>, Event),
          Time = maps:get(<<"time">>, Event),
          case maps:find(Name, Timings) of
              error ->
                  maps:put(Name,
                           #{<<"count">> => 1,
                             <<"first_time_ms">> => Time,
                             <<"last_time_ms">> => Time},
                           Timings);
              {ok, Timing} ->
                  maps:put(Name,
                           Timing#{<<"count">> :=
                                       maps:get(<<"count">>, Timing) + 1,
                                   <<"last_time_ms">> := Time},
                           Timings)
          end
      end,
      #{},
      Events).

receive_event_names() ->
    [<<"quic:udp_datagrams_received">>, <<"quic:packet_received">>].

send_event_names() ->
    [<<"quic:udp_datagrams_sent">>, <<"quic:packet_sent">>].

last_activity_time(Events, Names) ->
    matching_last_time(Events,
                       fun(Name) -> lists:member(Name, Names) end).

last_http3_time(Events) ->
    matching_last_time(Events,
                       fun(Name) ->
                           binary:match(Name, <<"http3:">>) =:= {0, 6}
                       end).

matching_last_time(Events, Predicate) ->
    lists:foldl(
      fun(Event, Last) ->
          case Predicate(maps:get(<<"name">>, Event)) of
              true -> maps:get(<<"time">>, Event);
              false -> Last
          end
      end,
      null,
      Events).

optional_difference(_Last, null) -> null;
optional_difference(Last, Earlier) -> Last - Earlier.

maximum_event_gap([First | Rest]) ->
    maximum_event_gap(Rest, First,
                      #{<<"milliseconds">> => 0,
                        <<"from_event">> => maps:get(<<"name">>, First),
                        <<"from_time_ms">> => maps:get(<<"time">>, First),
                        <<"to_event">> => maps:get(<<"name">>, First),
                        <<"to_time_ms">> => maps:get(<<"time">>, First)}).

maximum_event_gap([], _Previous, Maximum) -> Maximum;
maximum_event_gap([Event | Rest], Previous, Maximum0) ->
    Gap = maps:get(<<"time">>, Event) - maps:get(<<"time">>, Previous),
    Maximum = case Gap > maps:get(<<"milliseconds">>, Maximum0) of
        true ->
            #{<<"milliseconds">> => Gap,
              <<"from_event">> => maps:get(<<"name">>, Previous),
              <<"from_time_ms">> => maps:get(<<"time">>, Previous),
              <<"to_event">> => maps:get(<<"name">>, Event),
              <<"to_time_ms">> => maps:get(<<"time">>, Event)};
        false -> Maximum0
    end,
    maximum_event_gap(Rest, Event, Maximum).

sequence_findings([First | Rest] = Events) ->
    FirstName = maps:get(<<"name">>, First),
    LastName = maps:get(<<"name">>, lists:last(Events)),
    Timestamp = timestamp_regressions(Rest, First, 2, 0, 0, null),
    Timestamp#{
      <<"starts_with_connection_started">> =>
          FirstName =:= <<"quic:connection_started">>,
      <<"ends_with_connection_closed">> =>
          LastName =:= <<"quic:connection_closed">>}.

timestamp_regressions([], _Previous, _Index, Count, Maximum, First) ->
    #{<<"timestamp_regressions">> => Count,
      <<"maximum_timestamp_regression_ms">> => Maximum,
      <<"first_timestamp_regression">> => First};
timestamp_regressions([Event | Rest], Previous, Index,
                      Count0, Maximum0, First0) ->
    PreviousTime = maps:get(<<"time">>, Previous),
    Time = maps:get(<<"time">>, Event),
    case Time < PreviousTime of
        true ->
            Regression = PreviousTime - Time,
            Finding = #{<<"record_index">> => Index,
                        <<"previous_event">> =>
                            maps:get(<<"name">>, Previous),
                        <<"previous_time_ms">> => PreviousTime,
                        <<"event">> => maps:get(<<"name">>, Event),
                        <<"time_ms">> => Time,
                        <<"regression_ms">> => Regression},
            First = case First0 of null -> Finding; _ -> First0 end,
            timestamp_regressions(Rest, Event, Index + 1, Count0 + 1,
                                  erlang:max(Maximum0, Regression), First);
        false ->
            timestamp_regressions(Rest, Event, Index + 1, Count0,
                                  Maximum0, First0)
    end.

build_manifest(SourceDirectory, ArtifactRelative, Provenance, Entries) ->
    Traces = [maps:get(summary, Entry) || Entry <- Entries],
    TotalBytes = lists:sum([maps:get(<<"bytes">>, Trace) || Trace <- Traces]),
    TotalRecords = lists:sum([maps:get(<<"records">>, Trace)
                              || Trace <- Traces]),
    ensure(TotalBytes =< ?MAX_TOTAL_BYTES, invalid_manifest_total_bytes),
    ensure(TotalRecords =< ?MAX_TOTAL_RECORDS,
           invalid_manifest_total_records),
    #{<<"schema">> => 1,
      <<"status">> => <<"Captured">>,
      <<"classification">> => classification(),
      <<"source_directory">> => list_to_binary(SourceDirectory),
      <<"artifact_directory">> => list_to_binary(ArtifactRelative),
      <<"limits">> => limits(),
      <<"provenance">> => Provenance,
      <<"trace_set_sha256">> => trace_set_digest(Traces),
      <<"summary">> => aggregate_summary(Traces),
      <<"traces">> => Traces}.

classification() ->
    #{<<"manifest_payload_free">> => true,
      <<"raw_traces_payload_free">> => true,
      <<"raw_traces_retained">> => true,
      <<"raw_traces_shareable">> => false,
      <<"application_headers_retained">> => false,
      <<"application_payloads_retained">> => false,
      <<"cryptographic_material_retained">> => false,
      <<"endpoint_identity_retained">> => false}.

limits() ->
    #{<<"maximum_traces">> => ?MAX_TRACES,
      <<"maximum_trace_bytes">> => ?MAX_TRACE_BYTES,
      <<"maximum_total_bytes">> => ?MAX_TOTAL_BYTES,
      <<"maximum_records_per_trace">> => ?MAX_RECORDS_PER_TRACE,
      <<"maximum_total_records">> => ?MAX_TOTAL_RECORDS}.

aggregate_summary(Traces) ->
    Durations = [maps:get(<<"duration_ms">>, Trace) || Trace <- Traces],
    #{<<"trace_count">> => length(Traces),
      <<"total_bytes">> =>
          lists:sum([maps:get(<<"bytes">>, Trace) || Trace <- Traces]),
      <<"total_records">> =>
          lists:sum([maps:get(<<"records">>, Trace) || Trace <- Traces]),
      <<"total_events">> =>
          lists:sum([maps:get(<<"events">>, Trace) || Trace <- Traces]),
      <<"vantage_points">> => aggregate_vantage_points(Traces),
      <<"event_counts">> => aggregate_event_counts(Traces),
      <<"sequence_findings">> => aggregate_sequence_findings(Traces),
      <<"duration_ms">> => distribution(Durations),
      <<"slowest_trace">> => maximum_trace_field(Traces,
                                                   <<"duration_ms">>),
      <<"largest_event_gap">> => maximum_nested_trace_field(
                                      Traces, <<"maximum_event_gap">>,
                                      <<"milliseconds">>),
      <<"longest_quiet_before_close">> => maximum_optional_trace_field(
                                               Traces,
                                               <<"quiet_before_close_ms">>)}.

aggregate_vantage_points(Traces) ->
    lists:foldl(
      fun(Trace, Counts) ->
          Role = maps:get(<<"vantage_point">>, Trace),
          maps:update_with(Role, fun(Count) -> Count + 1 end, 1, Counts)
      end,
      #{},
      Traces).

aggregate_event_counts(Traces) ->
    lists:foldl(
      fun(Trace, Aggregate) ->
          maps:fold(
            fun(Name, Count, Counts) ->
                maps:update_with(Name, fun(Value) -> Value + Count end,
                                 Count, Counts)
            end,
            Aggregate,
            maps:get(<<"event_counts">>, Trace))
      end,
      #{},
      Traces).

aggregate_sequence_findings(Traces) ->
    Nonconforming =
        [#{<<"artifact">> => maps:get(<<"artifact">>, Trace),
           <<"findings">> => maps:get(<<"sequence_findings">>, Trace)}
         || Trace <- Traces,
            trace_has_sequence_finding(Trace)],
    #{<<"timestamp_regressions">> =>
          lists:sum(
            [maps:get(<<"timestamp_regressions">>,
                      maps:get(<<"sequence_findings">>, Trace))
             || Trace <- Traces]),
      <<"traces_with_findings">> => length(Nonconforming),
      <<"nonconforming_traces">> => Nonconforming}.

trace_has_sequence_finding(Trace) ->
    Findings = maps:get(<<"sequence_findings">>, Trace),
    maps:get(<<"timestamp_regressions">>, Findings) > 0 orelse
    not maps:get(<<"starts_with_connection_started">>, Findings) orelse
    not maps:get(<<"ends_with_connection_closed">>, Findings).

distribution(Values) ->
    Sorted = lists:sort(Values),
    #{<<"minimum">> => hd(Sorted),
      <<"p50">> => nearest_rank(Sorted, 50),
      <<"p95">> => nearest_rank(Sorted, 95),
      <<"p99">> => nearest_rank(Sorted, 99),
      <<"maximum">> => lists:last(Sorted)}.

nearest_rank(Sorted, Percentile) ->
    Rank = (Percentile * length(Sorted) + 99) div 100,
    lists:nth(Rank, Sorted).

maximum_trace_field(Traces, Field) ->
    Trace = select_maximum(Traces,
                           fun(Item) -> maps:get(Field, Item) end),
    #{<<"artifact">> => maps:get(<<"artifact">>, Trace),
      <<"milliseconds">> => maps:get(Field, Trace)}.

maximum_nested_trace_field(Traces, Container, Field) ->
    Trace = select_maximum(
              Traces,
              fun(Item) -> maps:get(Field, maps:get(Container, Item)) end),
    Value = maps:get(Container, Trace),
    Value#{<<"artifact">> => maps:get(<<"artifact">>, Trace)}.

maximum_optional_trace_field(Traces, Field) ->
    Candidates = [Trace || Trace <- Traces,
                           is_integer(maps:get(Field, Trace))],
    case Candidates of
        [] -> null;
        _ ->
            Trace = select_maximum(Candidates,
                                   fun(Item) -> maps:get(Field, Item) end),
            #{<<"artifact">> => maps:get(<<"artifact">>, Trace),
              <<"milliseconds">> => maps:get(Field, Trace)}
    end.

select_maximum([First | Rest], Value) ->
    lists:foldl(
      fun(Item, Maximum) ->
          ItemValue = Value(Item),
          MaximumValue = Value(Maximum),
          ItemPath = maps:get(<<"artifact">>, Item),
          MaximumPath = maps:get(<<"artifact">>, Maximum),
          case ItemValue > MaximumValue orelse
               (ItemValue =:= MaximumValue andalso ItemPath < MaximumPath) of
              true -> Item;
              false -> Maximum
          end
      end,
      First,
      Rest).

trace_set_digest(Traces) ->
    Sorted = lists:sort(
               fun(Left, Right) ->
                   maps:get(<<"artifact">>, Left) <
                       maps:get(<<"artifact">>, Right)
               end,
               Traces),
    Material =
        [[maps:get(<<"artifact">>, Trace), <<0>>,
          maps:get(<<"sha256">>, Trace), <<0>>,
          integer_to_binary(maps:get(<<"bytes">>, Trace)), <<0>>,
          integer_to_binary(maps:get(<<"records">>, Trace)), <<"\n">>]
         || Trace <- Sorted],
    sha256(iolist_to_binary(Material)).

write_artifact(TargetDirectory, Entries, Manifest) ->
    ok = filelib:ensure_dir(filename:join(filename:dirname(TargetDirectory),
                                          ".directory")),
    case file:make_dir(TargetDirectory) of
        ok -> ok;
        {error, eexist} ->
            erlang:error({artifact_already_exists, TargetDirectory});
        {error, Reason} ->
            erlang:error({cannot_create_artifact_directory,
                          TargetDirectory, Reason})
    end,
    TraceDirectory = filename:join(TargetDirectory, "traces"),
    ok = file:make_dir(TraceDirectory),
    lists:foreach(
      fun(Entry) ->
          Path = filename:join(TraceDirectory, maps:get(name, Entry)),
          ok = write_exclusive(Path, maps:get(bytes, Entry))
      end,
      Entries),
    ManifestPath = filename:join(TargetDirectory, "manifest.json"),
    ok = write_exclusive(ManifestPath,
                         iolist_to_binary([json:encode(Manifest), <<"\n">>])),
    ok.

write_exclusive(Path, Bytes) ->
    case file:write_file(Path, Bytes, [binary, exclusive]) of
        ok -> ok;
        {error, Reason} -> erlang:error({cannot_write_artifact, Path, Reason})
    end.

verify_artifact(TargetDirectory, ExpectedArtifact) ->
    validate_source_directory(TargetDirectory),
    ManifestPath = filename:join(TargetDirectory, "manifest.json"),
    Manifest = decode_json_file(ManifestPath),
    validate_manifest(Manifest, ExpectedArtifact),
    TraceDirectory = filename:join(TargetDirectory, "traces"),
    validate_source_directory(TraceDirectory),
    StoredTraces = maps:get(<<"traces">>, Manifest),
    ExpectedNames = [filename:basename(binary_to_list(
                         maps:get(<<"artifact">>, Trace)))
                     || Trace <- StoredTraces],
    {ok, ActualNames0} = file:list_dir(TraceDirectory),
    ActualNames = lists:sort(ActualNames0),
    ensure(ActualNames =:= lists:sort(ExpectedNames),
           {artifact_trace_inventory_mismatch, ExpectedNames, ActualNames}),
    VerifiedTraces =
        [begin
             validate_qlog_filename(Name),
             Path = filename:join(TraceDirectory, Name),
             validate_plain_trace(Path),
             Stored = find_stored_trace(Name, StoredTraces),
             ArtifactPath = binary_to_list(maps:get(<<"artifact">>, Stored)),
             summarize_trace(Name, ArtifactPath, read_bounded_trace(Path))
         end || Name <- ActualNames],
    ensure(VerifiedTraces =:= StoredTraces,
           artifact_trace_summary_mismatch),
    ensure(trace_set_digest(VerifiedTraces) =:=
               maps:get(<<"trace_set_sha256">>, Manifest),
           artifact_trace_set_digest_mismatch),
    ensure(aggregate_summary(VerifiedTraces) =:=
               maps:get(<<"summary">>, Manifest),
           artifact_aggregate_summary_mismatch),
    ok.

validate_manifest(Manifest, ExpectedArtifact) ->
    exact_keys(Manifest,
               [<<"artifact_directory">>, <<"classification">>,
                <<"limits">>, <<"provenance">>, <<"schema">>,
                <<"source_directory">>, <<"status">>, <<"summary">>,
                <<"trace_set_sha256">>, <<"traces">>],
               unexpected_qlog_manifest_keys),
    ensure(maps:get(<<"schema">>, Manifest) =:= 1,
           invalid_qlog_manifest_schema),
    ensure(maps:get(<<"status">>, Manifest) =:= <<"Captured">>,
           invalid_qlog_manifest_status),
    ensure(maps:get(<<"artifact_directory">>, Manifest) =:=
               ExpectedArtifact, invalid_qlog_artifact_directory),
    ensure(maps:get(<<"classification">>, Manifest) =:= classification(),
           invalid_qlog_artifact_classification),
    ensure(maps:get(<<"limits">>, Manifest) =:= limits(),
           invalid_qlog_artifact_limits),
    ensure(valid_sha256(maps:get(<<"trace_set_sha256">>, Manifest)),
           invalid_qlog_trace_set_digest),
    Source = maps:get(<<"source_directory">>, Manifest),
    ensure(is_binary(Source) andalso byte_size(Source) > 0,
           invalid_qlog_source_directory),
    validate_provenance(maps:get(<<"provenance">>, Manifest)),
    Traces = maps:get(<<"traces">>, Manifest),
    ensure(is_list(Traces) andalso length(Traces) >= 1 andalso
           length(Traces) =< ?MAX_TRACES,
           invalid_qlog_manifest_traces),
    ok.

validate_provenance(Provenance) ->
    exact_keys(Provenance,
               [<<"qlog_profile">>, <<"qlog_profile_sha256">>,
                <<"tool">>, <<"tool_sha256">>],
               unexpected_qlog_provenance_keys),
    ensure(maps:get(<<"tool">>, Provenance) =:=
               <<"scripts/qlog_preserve.escript">>,
           invalid_qlog_provenance_tool),
    ensure(maps:get(<<"qlog_profile">>, Provenance) =:=
               list_to_binary(?PROFILE_RELATIVE),
           invalid_qlog_provenance_profile),
    ensure(valid_sha256(maps:get(<<"tool_sha256">>, Provenance)),
           invalid_qlog_provenance_tool_digest),
    ensure(valid_sha256(maps:get(<<"qlog_profile_sha256">>, Provenance)),
           invalid_qlog_provenance_profile_digest).

find_stored_trace(Name, Traces) ->
    Matches = [Trace || Trace <- Traces,
                        filename:basename(binary_to_list(
                            maps:get(<<"artifact">>, Trace))) =:= Name],
    case Matches of
        [Trace] -> Trace;
        _ -> erlang:error({invalid_stored_trace_name, Name, length(Matches)})
    end.

manifest_total_bytes(Manifest) ->
    maps:get(<<"total_bytes">>, maps:get(<<"summary">>, Manifest)).

manifest_total_events(Manifest) ->
    maps:get(<<"total_events">>, maps:get(<<"summary">>, Manifest)).

decode_json_file(Path) ->
    Bytes = read(Path),
    try json:decode(Bytes) of
        Value when is_map(Value) -> Value;
        _ -> erlang:error({json_file_not_an_object, Path})
    catch
        error:{json_file_not_an_object, Path} = Reason ->
            erlang:error(Reason);
        _:_ -> erlang:error({invalid_json_file, Path})
    end.

self_test() ->
    Temporary = temporary_directory(),
    Source = filename:join(Temporary, "source"),
    Target = filename:join(Temporary, "artifact"),
    ok = file:make_dir(Temporary),
    ok = file:make_dir(Source),
    try
        Client = fixture_trace(<<"client">>, 40),
        Server = fixture_trace(<<"server">>, 10020),
        ok = file:write_file(filename:join(Source, "client-1.qlog"), Client),
        ok = file:write_file(filename:join(Source, "server-1.qlog"), Server),
        Artifact = <<"build/diagnostics/qlog-failures/self-test">>,
        Entries = read_source_traces(Source, binary_to_list(Artifact)),
        Provenance =
            #{<<"tool">> => <<"scripts/qlog_preserve.escript">>,
              <<"tool_sha256">> => binary:copy(<<"a">>, 64),
              <<"qlog_profile">> => list_to_binary(?PROFILE_RELATIVE),
              <<"qlog_profile_sha256">> => binary:copy(<<"b">>, 64)},
        Manifest = build_manifest(Source, binary_to_list(Artifact),
                                  Provenance, Entries),
        Summary = maps:get(<<"summary">>, Manifest),
        ensure(maps:get(<<"trace_count">>, Summary) =:= 2,
               self_test_wrong_trace_count),
        ensure(maps:get(<<"total_events">>, Summary) =:= 10,
               self_test_wrong_event_count),
        LongestQuiet = maps:get(<<"longest_quiet_before_close">>, Summary),
        ensure(maps:get(<<"milliseconds">>, LongestQuiet) =:= 10000,
               self_test_wrong_quiet_interval),
        write_artifact(Target, Entries, Manifest),
        verify_artifact(Target, Artifact),
        expect_error_tag(
          unsupported_qlog_event_for_payload_free_capture,
          fun() -> validate_event_data(<<"http3:payload">>,
                                       #{<<"body">> => <<"secret">>}) end),
        expect_error_tag(
          unexpected_http3_frame_keys,
          fun() -> validate_frame(
                     #{<<"frame_type">> => <<"headers">>,
                       <<"headers">> => [],
                       <<"authorization">> => <<"secret">>}) end),
        expect_error_tag(
          duplicate_json_object_key,
          fun() -> decode_record(
                     <<"{\"name\":\"safe\",\"name\":\"payload\"}\n">>)
          end),
        RegressionRecords = decode_sequence(Server),
        [RegressionHeader, RegressionStart, RegressionDatagram,
         RegressionPacket, RegressionFrame0, RegressionClose] =
            RegressionRecords,
        RegressionFrame = RegressionFrame0#{<<"time">> := 19},
        RegressionBytes = encode_sequence(
                            [RegressionHeader, RegressionStart,
                             RegressionDatagram, RegressionPacket,
                             RegressionFrame, RegressionClose]),
        RegressionSummary = summarize_trace(
                              "regression.qlog",
                              "build/diagnostics/qlog-failures/self-test/"
                              "traces/regression.qlog",
                              RegressionBytes),
        RegressionFindings = maps:get(<<"sequence_findings">>,
                                      RegressionSummary),
        ensure(maps:get(<<"timestamp_regressions">>, RegressionFindings)
                   =:= 1,
               self_test_timestamp_regression_not_recorded),
        ensure(valid_artifact_name("failure-20260903"),
               self_test_valid_artifact_name_rejected),
        ensure(not valid_artifact_name("../failure"),
               self_test_unsafe_artifact_name_accepted),
        TamperedPath = filename:join([Target, "traces", "server-1.qlog"]),
        ok = file:write_file(TamperedPath, fixture_trace(<<"server">>, 9040)),
        expect_error_tag(artifact_trace_summary_mismatch,
                         fun() -> verify_artifact(Target, Artifact) end),
        ensure(trace_set_digest([maps:get(summary, Entry)
                                 || Entry <- Entries]) =:=
               trace_set_digest([maps:get(summary, Entry)
                                 || Entry <- lists:reverse(Entries)]),
               self_test_nondeterministic_trace_set_digest),
        io:format("qlog preservation self-test ok (bounded copy/verify, "
                  "deterministic digest, sequence findings, duplicate-key "
                  "and payload rejection)~n",
                  []),
        ok
    after
        cleanup_temporary_directory(Temporary)
    end.

fixture_trace(Role, CloseTime) ->
    Header =
        #{<<"file_schema">> =>
              <<"urn:ietf:params:qlog:file:sequential">>,
          <<"serialization_format">> =>
              <<"application/qlog+json-seq">>,
          <<"title">> => <<"quic_core HTTP/3 diagnostics">>,
          <<"description">> =>
              <<"draft-ietf-quic-qlog-main-schema-14; privacy=strict">>,
          <<"trace">> =>
              #{<<"common_fields">> =>
                    #{<<"time_format">> => <<"relative_to_epoch">>,
                      <<"reference_time">> =>
                          #{<<"clock_type">> => <<"monotonic">>,
                            <<"epoch">> => <<"unknown">>}},
                <<"vantage_point">> =>
                    #{<<"name">> => <<"quic_core">>, <<"type">> => Role},
                <<"event_schemas">> => event_schemas()}},
    Events =
        [fixture_event(0, <<"quic:connection_started">>,
                       #{<<"local">> => #{}, <<"remote">> => #{}}),
         fixture_event(10, <<"quic:udp_datagrams_received">>,
                       #{<<"count">> => 1,
                         <<"raw">> => [#{<<"length">> => 1200}]}),
         fixture_event(20, <<"quic:packet_received">>,
                       #{<<"header">> => #{<<"packet_type">> => <<"1RTT">>},
                         <<"raw">> => #{<<"length">> => 80}}),
         fixture_event(30, <<"http3:frame_parsed">>,
                       #{<<"stream_id">> => 0,
                         <<"frame">> => #{<<"frame_type">> => <<"headers">>,
                                           <<"headers">> => []}}),
         fixture_event(CloseTime, <<"quic:connection_closed">>,
                       #{<<"initiator">> => <<"local">>,
                         <<"trigger">> => <<"application">>})],
    encode_sequence([Header | Events]).

fixture_event(Time, Name, Data) ->
    #{<<"time">> => Time, <<"name">> => Name, <<"data">> => Data}.

encode_sequence(Records) ->
    iolist_to_binary([[<<16#1e>>, json:encode(Record), <<"\n">>]
                      || Record <- Records]).

temporary_directory() ->
    Base = case os:getenv("TMPDIR") of
        false -> "/tmp";
        [] -> "/tmp";
        Value -> Value
    end,
    filename:join(filename:absname(Base),
                  "http3-qlog-preserve-self-test-" ++
                  integer_to_list(erlang:unique_integer([positive,
                                                         monotonic]))).

cleanup_temporary_directory(Path) ->
    ensure(lists:prefix("http3-qlog-preserve-self-test-",
                        filename:basename(Path)),
           {unsafe_self_test_cleanup, Path}),
    delete_tree(Path).

delete_tree(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, #file_info{type = directory}} ->
            {ok, Names} = file:list_dir(Path),
            lists:foreach(fun(Name) -> delete_tree(filename:join(Path, Name)) end,
                          Names),
            ok = file:del_dir(Path);
        {ok, _Info} -> ok = file:delete(Path)
    end.

expect_error_tag(Expected, Run) ->
    try Run() of
        _ -> erlang:error({self_test_expected_failure, Expected})
    catch
        error:Reason ->
            ensure(reason_tag(Reason) =:= Expected,
                   {self_test_wrong_failure, Expected, Reason})
    end.

reason_tag(Value) when is_atom(Value) -> Value;
reason_tag(Value) when is_tuple(Value), tuple_size(Value) >= 1 ->
    element(1, Value);
reason_tag(Value) -> Value.

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

sha256(Bytes) ->
    hex(crypto:hash(sha256, Bytes)).

valid_sha256(Digest) when is_binary(Digest) ->
    re:run(Digest, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
valid_sha256(_Digest) -> false.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0b", [Byte])
                      || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
