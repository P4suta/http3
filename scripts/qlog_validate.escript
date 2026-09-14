#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(PROFILE, "standards/qlog-profile.json").
-define(OUTPUT, "build/qlog").

main([]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            case filelib:is_regular(filename:join(?OUTPUT, "report.json")) of
                true -> ok;
                false ->
                    _ = write_report(#{status => <<"Blocked">>,
                                       reason => printable(Reason)})
            end,
            io:format(standard_error,
                      "qlog validation failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(["--self-test"]) ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "qlog validator self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(_) ->
    io:format(standard_error,
              "usage: qlog_validate.escript [--self-test]~n", []),
    halt(2).

run() ->
    Profile = decode_file(?PROFILE),
    validate_profile(Profile),
    TracePaths = trace_paths(),
    Traces = [read_trace(Path, Profile) || Path <- TracePaths],
    VantagePoints = lists:usort(
        [maps:get(vantage_point, Trace) || Trace <- Traces]
    ),
    ensure(VantagePoints =:= [<<"client">>, <<"server">>],
           {incomplete_live_vantage_points, VantagePoints}),
    Names = lists:usort(lists:append(
        [maps:get(event_names, Trace) || Trace <- Traces]
    )),
    MissingFamilies = missing_families(Profile, Names),
    MissingTraceFamilies = missing_trace_families(Profile, Traces),
    Status = case {MissingFamilies, MissingTraceFamilies} of
                 {[], []} -> <<"Ready">>;
                 _ -> <<"Blocked">>
             end,
    RuntimeDigest = aggregate_trace_digest(Traces),
    RuntimeReport = #{status => Status,
                      evidence_kind => <<"ephemeral-live-qlog">>,
                      profile => list_to_binary(?PROFILE),
                      records => lists:sum(
                          [maps:get(records, Trace) || Trace <- Traces]
                      ),
                      trace_sha256 => RuntimeDigest,
                      traces => Traces},
    ok = write_json(filename:join(?OUTPUT, "runtime-evidence.json"),
                    RuntimeReport),
    TraceSummaries = lists:sort([trace_summary(Trace) || Trace <- Traces]),
    SemanticDigest = semantic_trace_digest(TraceSummaries),
    Report = #{status => Status,
               profile => list_to_binary(?PROFILE),
               profile_sha256 => hex(crypto:hash(sha256, read(?PROFILE))),
               trace => <<"live-public-http3">>,
               trace_semantic_sha256 => SemanticDigest,
               runtime_evidence => <<"build/qlog/runtime-evidence.json">>,
               traces => TraceSummaries,
               event_names => Names,
               missing_live_families => MissingFamilies,
               missing_per_trace_families => MissingTraceFamilies},
    ok = write_report(Report),
    case {MissingFamilies, MissingTraceFamilies} of
        {[], []} ->
            io:format("qlog JSON-SEQ, pinned profile, and live event breadth ok "
                      "(~B traces, ~s)~n",
                      [length(Traces), RuntimeDigest]),
            ok;
        _ ->
            erlang:error({missing_live_qlog_event_families,
                          MissingFamilies,
                          MissingTraceFamilies})
    end.

validate_profile(Profile) ->
    ensure(maps:get(<<"schema">>, Profile) =:= 1, invalid_profile_schema),
    ensure(maps:get(<<"baseline_date">>, Profile) =:= <<"2026-08-30">>,
           stale_qlog_baseline),
    Documents = maps:get(<<"documents">>, Profile),
    ensure(length(Documents) =:= 3, incomplete_qlog_document_pin),
    lists:foreach(fun validate_document_pin/1, Documents),
    ensure(maps:get(<<"file_schema">>, Profile) =:=
               <<"urn:ietf:params:qlog:file:sequential">>,
           invalid_file_schema_pin),
    ensure(maps:get(<<"serialization_format">>, Profile) =:=
               <<"application/qlog+json-seq">>,
           invalid_serialization_pin).

validate_document_pin(Document) ->
    Id = maps:get(<<"id">>, Document),
    Url = maps:get(<<"url">>, Document),
    Digest = maps:get(<<"sha256">>, Document),
    ensure(byte_size(Id) > 0, empty_qlog_document_id),
    ensure(binary:match(Url, <<"https://www.ietf.org/archive/id/">>) =:=
               {0, byte_size(<<"https://www.ietf.org/archive/id/">>)},
           {untrusted_qlog_document_url, Url}),
    ensure(re:run(Digest, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match,
           {invalid_qlog_document_digest, Id}).

trace_paths() ->
    Expected = filename:join(filename:absname("build"), "qlog"),
    case filename:absname(?OUTPUT) of
        Expected -> ok;
        Unsafe -> erlang:error({unsafe_qlog_output, Unsafe})
    end,
    Paths = lists:sort(filelib:wildcard(filename:join(?OUTPUT, "*.qlog"))),
    ensure(valid_live_trace_count(length(Paths)),
           {unexpected_live_qlog_trace_count, length(Paths)}),
    lists:foreach(fun(Path) ->
        ensure(filelib:is_regular(Path), {invalid_qlog_path, Path})
    end, Paths),
    Paths.

%% One public round trip owns exactly one client and one server connection.
%% Accepting extras would let a duplicated transport/application writer pass
%% while splitting causal evidence across unrelated trace files.
valid_live_trace_count(Count) -> Count =:= 2.

read_trace(Path, Profile) ->
    {ok, TraceBytes} = file:read_file(Path),
    Records = decode_sequence(TraceBytes),
    validate_records(Records, Profile),
    [Header | _] = Records,
    Trace = maps:get(<<"trace">>, Header),
    Vantage = maps:get(<<"vantage_point">>, Trace),
    #{path => list_to_binary(Path),
      vantage_point => maps:get(<<"type">>, Vantage),
      sha256 => hex(crypto:hash(sha256, TraceBytes)),
      records => length(Records),
      event_names => event_names(Records)}.

aggregate_trace_digest(Traces) ->
    Material = [[maps:get(path, Trace), <<0>>, maps:get(sha256, Trace), <<"\n">>]
                || Trace <- Traces],
    hex(crypto:hash(sha256, iolist_to_binary(Material))).

trace_summary(Trace) ->
    #{vantage_point => maps:get(vantage_point, Trace),
      event_names => lists:usort(maps:get(event_names, Trace))}.

semantic_trace_digest(TraceSummaries) ->
    Material = [[maps:get(vantage_point, Trace), <<0>>,
                 [[Name, <<"\n">>] || Name <- maps:get(event_names, Trace)]]
                || Trace <- TraceSummaries],
    hex(crypto:hash(sha256, iolist_to_binary(Material))).

decode_sequence(Bytes) ->
    ensure(byte_size(Bytes) > 0, empty_qlog),
    ensure(binary:first(Bytes) =:= 16#1e, missing_initial_record_separator),
    Chunks = binary:split(Bytes, <<16#1e>>, [global]),
    Records = [decode_record(Chunk) || Chunk <- Chunks, byte_size(Chunk) > 0],
    ensure(length(Records) >= 2, qlog_without_events),
    Records.

decode_record(Chunk) ->
    ensure(binary:last(Chunk) =:= $\n, record_without_line_feed),
    Json = binary:part(Chunk, 0, byte_size(Chunk) - 1),
    try json:decode(Json) of
        Value when is_map(Value) -> Value;
        _ -> erlang:error(qlog_record_not_an_object)
    catch
        _:_ -> erlang:error(invalid_qlog_json)
    end.

validate_records([Header | Events], Profile) ->
    ensure(maps:get(<<"file_schema">>, Header) =:=
               maps:get(<<"file_schema">>, Profile),
           qlog_file_schema_drift),
    ensure(maps:get(<<"serialization_format">>, Header) =:=
               maps:get(<<"serialization_format">>, Profile),
           qlog_serialization_drift),
    Trace = maps:get(<<"trace">>, Header),
    ensure(maps:get(<<"event_schemas">>, Trace) =:=
               maps:get(<<"event_schemas">>, Profile),
           qlog_event_schema_drift),
    Common = maps:get(<<"common_fields">>, Trace),
    ensure(not maps:is_key(<<"protocol_type">>, Common),
           obsolete_qlog_protocol_type),
    ensure(maps:get(<<"time_format">>, Common) =:=
               <<"relative_to_epoch">>, invalid_qlog_time_format),
    Reference = maps:get(<<"reference_time">>, Common),
    ensure(Reference =:= #{<<"clock_type">> => <<"monotonic">>,
                          <<"epoch">> => <<"unknown">>},
           invalid_qlog_reference_time),
    Vantage = maps:get(<<"vantage_point">>, Trace),
    ensure(lists:member(maps:get(<<"type">>, Vantage),
                        [<<"client">>, <<"server">>]),
           invalid_qlog_vantage_point),
    validate_events(Events, -1),
    Names = event_names([Header | Events]),
    ensure(hd(Names) =:= <<"quic:connection_started">>,
           qvis_connection_start_missing),
    ensure(lists:last(Names) =:= <<"quic:connection_closed">>,
           qvis_connection_close_missing),
    ensure(lists:any(fun(Name) ->
                         Name =:= <<"quic:udp_datagrams_received">> orelse
                         Name =:= <<"quic:udp_datagrams_sent">>
                     end, Names),
           qvis_transport_activity_missing),
    ensure(no_sensitive_material(Header, Events), sensitive_qlog_material).

validate_events([], _PreviousTime) -> ok;
validate_events([Event | Rest], PreviousTime) ->
    Time = maps:get(<<"time">>, Event),
    Name = maps:get(<<"name">>, Event),
    Data = maps:get(<<"data">>, Event),
    ensure(is_number(Time) andalso Time >= PreviousTime,
           {non_monotonic_qlog_time, Time}),
    ensure(is_binary(Name) andalso binary:match(Name, <<":">>) =/= nomatch,
           {invalid_qlog_event_name, Name}),
    ensure(is_map(Data), {invalid_qlog_event_data, Name}),
    validate_event_data(Name, Data),
    validate_events(Rest, Time).

validate_event_data(<<"quic:connection_started">>, Data) ->
    ensure(is_map(maps:get(<<"local">>, Data)), missing_local_endpoint),
    ensure(is_map(maps:get(<<"remote">>, Data)), missing_remote_endpoint);
validate_event_data(Name, Data)
        when Name =:= <<"quic:udp_datagrams_received">>;
             Name =:= <<"quic:udp_datagrams_sent">> ->
    Count = maps:get(<<"count">>, Data, 0),
    ensure(is_integer(Count) andalso Count > 0 andalso Count =< 65535,
           {invalid_datagram_count, Count}),
    case maps:find(<<"raw">>, Data) of
        {ok, Raw} ->
            ensure(is_list(Raw) andalso Raw =/= [], invalid_raw_datagrams),
            lists:foreach(fun(Info) ->
                Length = maps:get(<<"length">>, Info),
                ensure(is_integer(Length) andalso Length > 0,
                       invalid_raw_datagram_length)
            end, Raw);
        error -> ok
    end;
validate_event_data(Name, Data)
        when Name =:= <<"quic:packet_received">>;
             Name =:= <<"quic:packet_sent">> ->
    Header = maps:get(<<"header">>, Data),
    ensure(is_map(Header), missing_packet_header),
    ensure(lists:member(maps:get(<<"packet_type">>, Header),
                        [<<"initial">>, <<"handshake">>, <<"0RTT">>,
                         <<"1RTT">>, <<"retry">>,
                         <<"version_negotiation">>, <<"stateless_reset">>,
                         <<"unknown">>]),
           invalid_packet_type),
    ensure(not maps:is_key(<<"dcid">>, Header) andalso
           not maps:is_key(<<"scid">>, Header) andalso
           not maps:is_key(<<"token">>, Header),
           packet_identifier_not_redacted),
    validate_optional_raw(Data);
validate_event_data(Name, Data)
        when Name =:= <<"quic:key_updated">>;
             Name =:= <<"quic:key_discarded">> ->
    ensure(lists:member(maps:get(<<"key_type">>, Data),
                        [<<"server_initial_secret">>,
                         <<"client_initial_secret">>,
                         <<"server_handshake_secret">>,
                         <<"client_handshake_secret">>,
                         <<"server_0rtt_secret">>,
                         <<"client_0rtt_secret">>,
                         <<"server_1rtt_secret">>,
                         <<"client_1rtt_secret">>]),
           invalid_key_type),
    ensure(maps:get(<<"trigger">>, Data) =:= <<"tls">>,
           invalid_key_trigger),
    ensure(not maps:is_key(<<"old">>, Data) andalso
           not maps:is_key(<<"new">>, Data) andalso
           not maps:is_key(<<"key">>, Data),
           key_material_not_redacted);
validate_event_data(<<"quic:recovery_metrics_updated">>, Data) ->
    Window = maps:get(<<"congestion_window">>, Data),
    Flight = maps:get(<<"bytes_in_flight">>, Data),
    ensure(is_integer(Window) andalso Window >= 0,
           invalid_congestion_window),
    ensure(is_integer(Flight) andalso Flight >= 0,
           invalid_bytes_in_flight);
validate_event_data(<<"quic:congestion_state_updated">>, Data) ->
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
validate_event_data(<<"quic:migration_state_updated">>, Data) ->
    ensure(lists:member(maps:get(<<"new">>, Data),
                        [<<"migration_started">>,
                         <<"migration_abandoned">>,
                         <<"migration_complete">>]),
           invalid_migration_state);
validate_event_data(<<"http3:parameters_set">>, Data) ->
    ensure(lists:member(maps:get(<<"initiator">>, Data),
                        [<<"local">>, <<"remote">>]),
           invalid_http3_parameter_initiator);
validate_event_data(<<"http3:stream_type_set">>, Data) ->
    StreamId = maps:get(<<"stream_id">>, Data),
    ensure(is_integer(StreamId) andalso StreamId >= 0,
           invalid_http3_stream_id),
    ensure(lists:member(maps:get(<<"stream_type">>, Data),
                        [<<"request">>, <<"control">>, <<"push">>,
                         <<"reserved">>, <<"unknown">>,
                         <<"qpack_encode">>, <<"qpack_decode">>]),
           invalid_http3_stream_type);
validate_event_data(Name, Data)
        when Name =:= <<"http3:frame_created">>;
             Name =:= <<"http3:frame_parsed">> ->
    StreamId = maps:get(<<"stream_id">>, Data),
    Frame = maps:get(<<"frame">>, Data),
    ensure(is_integer(StreamId) andalso StreamId >= 0,
           invalid_http3_frame_stream_id),
    ensure(is_map(Frame), invalid_http3_frame),
    ensure(lists:member(maps:get(<<"frame_type">>, Frame),
                        [<<"data">>, <<"headers">>, <<"cancel_push">>,
                         <<"settings">>, <<"push_promise">>, <<"goaway">>,
                         <<"max_push_id">>, <<"unknown">>]),
           invalid_http3_frame_type),
    case maps:find(<<"headers">>, Frame) of
        {ok, []} -> ok;
        {ok, _} -> erlang:error(http3_header_values_not_redacted);
        error -> ok
    end,
    validate_optional_raw(Frame);
validate_event_data(<<"loglevel:error">>, Data) ->
    Code = maps:get(<<"code">>, Data),
    ensure(is_integer(Code) andalso Code >= 0 andalso Code =< 2147483647,
           invalid_application_diagnostic_code),
    ensure(not maps:is_key(<<"message">>, Data),
           application_diagnostic_message_not_redacted),
    ensure(map_size(Data) =:= 1, application_diagnostic_payload_not_redacted);
validate_event_data(<<"quic:connection_closed">>, Data) ->
    ensure(maps:get(<<"initiator">>, Data) =:= <<"local">>,
           invalid_close_initiator),
    ensure(maps:get(<<"trigger">>, Data) =:= <<"application">>,
           invalid_close_trigger);
validate_event_data(_Name, _Data) -> ok.

validate_optional_raw(Data) ->
    case maps:find(<<"raw">>, Data) of
        {ok, Raw} ->
            ensure(is_map(Raw), invalid_raw_info),
            Length = maps:get(<<"length">>, Raw),
            ensure(is_integer(Length) andalso Length > 0,
                   invalid_raw_length),
            ensure(not maps:is_key(<<"data">>, Raw), raw_data_not_redacted);
        error -> ok
    end.

no_sensitive_material(Header, Events) ->
    Encoded = iolist_to_binary(json:encode([Header | Events])),
    Markers = [<<"PRIVATE KEY">>, <<"traffic_secret">>,
               <<"authorization">>, <<"cookie">>, <<"set-cookie">>,
               <<"request_body">>, <<"response_body">>],
    not lists:any(fun(Marker) ->
                      binary:match(string:lowercase(Encoded),
                                   string:lowercase(Marker)) =/= nomatch
                  end, Markers).

event_names([_Header | Events]) ->
    [maps:get(<<"name">>, Event) || Event <- Events].

missing_families(Profile, Names) ->
    Families = maps:get(<<"required_live_families">>, Profile),
    maps:fold(fun(Family, Required, Missing) ->
        case lists:all(fun(Name) -> lists:member(Name, Names) end, Required) of
            true -> Missing;
            false -> [Family | Missing]
        end
    end, [], Families).

missing_trace_families(Profile, Traces) ->
    Families = maps:get(<<"required_per_trace_families">>, Profile),
    lists:filtermap(fun(Trace) ->
        Names = maps:get(event_names, Trace),
        Missing = maps:fold(fun(Family, Required, Acc) ->
            case lists:all(fun(Name) -> lists:member(Name, Names) end,
                           Required) of
                true -> Acc;
                false -> [Family | Acc]
            end
        end, [], Families),
        case Missing of
            [] -> false;
            _ -> {true, #{vantage_point => maps:get(vantage_point, Trace),
                           missing => lists:sort(Missing)}}
        end
    end, Traces).

self_test() ->
    true = valid_live_trace_count(2),
    false = valid_live_trace_count(1),
    false = valid_live_trace_count(3),
    RS = 16#1e,
    Valid = <<RS, "{}\n", RS, "{\"value\":1}\n">>,
    ensure(length(decode_sequence(Valid)) =:= 2,
           self_test_valid_sequence_rejected),
    Consecutive = <<RS, RS, "{}\n", RS, "{}\n">>,
    ensure(length(decode_sequence(Consecutive)) =:= 2,
           self_test_consecutive_rs_rejected),
    expect_decode_error(missing_initial_record_separator,
                        fun() -> decode_sequence(<<"{}\n">>) end),
    expect_decode_error(record_without_line_feed,
                        fun() -> decode_sequence(
                            <<RS, "{}", RS, "{}\n">>)
                        end),
    expect_decode_error(invalid_qlog_json,
                        fun() -> decode_sequence(
                            <<RS, "{broken}\n", RS, "{}\n">>)
                        end),
    expect_decode_error(qlog_record_not_an_object,
                        fun() -> decode_sequence(
                            <<RS, "123\n", RS, "{}\n">>)
                        end),
    expect_decode_error(invalid_congestion_trigger,
                        fun() -> validate_event_data(
                            <<"quic:congestion_state_updated">>,
                            #{<<"new">> => <<"slow_start">>,
                              <<"trigger">> => <<"peer_payload">>})
                        end),
    Earlier = #{<<"time">> => 2,
                <<"name">> => <<"quic:migration_state_updated">>,
                <<"data">> => #{<<"new">> => <<"migration_started">>}},
    Regressed = #{<<"time">> => 1,
                  <<"name">> => <<"quic:migration_state_updated">>,
                  <<"data">> => #{<<"new">> => <<"migration_abandoned">>}},
    expect_decode_error({non_monotonic_qlog_time, 1},
                        fun() -> validate_events([Earlier, Regressed], -1) end),
    io:format("qlog JSON-SEQ validator self-test ok (exact live cardinality "
              "plus 6 adversarial sequence/event/time cases)~n", []),
    ok.

expect_decode_error(Expected, Run) ->
    try Run() of
        _ -> erlang:error({self_test_expected_failure, Expected})
    catch
        error:Expected -> ok;
        error:Other -> erlang:error({self_test_wrong_failure,
                                     Expected, Other})
    end.

decode_file(Path) ->
    {ok, Bytes} = file:read_file(Path),
    try json:decode(Bytes) of
        Value when is_map(Value) -> Value
    catch
        _:_ -> erlang:error({invalid_json_file, Path})
    end.

write_report(Report) ->
    write_json(filename:join(?OUTPUT, "report.json"), Report).

write_json(Path, Report) ->
    ok = filelib:ensure_dir(Path),
    file:write_file(Path,
                    [json:encode(Report), <<"\n">>]).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0b", [Byte])
                      || <<Byte>> <= Binary]).

printable(Value) ->
    iolist_to_binary(io_lib:format("~0tp", [Value])).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
