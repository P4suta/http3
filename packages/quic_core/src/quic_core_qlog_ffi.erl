-module(quic_core_qlog_ffi).

-export([close/1, event/5, frame_event/6, open/3, stats/1,
         validate_directory/1]).

-define(MAX_DIRECTORY_BYTES, 4096).
-define(CALL_TIMEOUT_MILLISECONDS, 5000).

-record(writer_state, {
    owner_monitor,
    device_writer,
    device_writer_monitor,
    events,
    busy = false,
    failed = false,
    closing = false,
    close_sent = false,
    close_waiters = [],
    maximum_events,
    last_event_time = 0,
    dropped = 0,
    write_errors = 0
}).

-spec open(binary(), 1 | 2, pos_integer()) -> {ok, pid()} | {error, 1 | 2 | 3}.
open(Directory, Vantage, MaximumEvents)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES,
         (Vantage =:= 1 orelse Vantage =:= 2),
         is_integer(MaximumEvents), MaximumEvents > 0,
         MaximumEvents =< 2147483647 ->
    case binary:match(Directory, <<0>>) of
        nomatch -> open_valid_directory(Directory, Vantage, MaximumEvents);
        _ -> {error, 1}
    end;
open(_Directory, _Vantage, _MaximumEvents) ->
    {error, 1}.

-spec validate_directory(binary()) -> {ok, nil} | {error, 1 | 2}.
validate_directory(Directory)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES ->
    case binary:match(Directory, <<0>>) of
        nomatch -> validate_writable_directory(Directory);
        _ -> {error, 1}
    end;
validate_directory(_Directory) ->
    {error, 1}.

-spec event(pid(), integer(), integer(), integer(), integer()) ->
    {ok, nil} | {error, 1 | 3 | 4}.
event(Writer, Event, Time, Value, Auxiliary)
    when is_pid(Writer), is_integer(Event), Event >= 1, Event =< 18,
         is_integer(Time), Time >= 0,
         is_integer(Value), Value >= 0,
         is_integer(Auxiliary), Auxiliary >= 0 ->
    case valid_event(Event, Value, Auxiliary) of
        true ->
            Metadata = {scalar, Event, Time, Value, Auxiliary},
            writer_call(Writer, {event, Metadata}, {error, 3});
        false ->
            {error, 1}
    end;
event(_Writer, _Event, _Time, _Value, _Auxiliary) ->
    {error, 1}.

-spec frame_event(pid(), 12 | 13, non_neg_integer(), non_neg_integer(),
                  1..8, non_neg_integer()) ->
    {ok, nil} | {error, 1 | 3 | 4}.
frame_event(Writer, Event, Time, StreamId, FrameType, PayloadBytes)
    when is_pid(Writer) ->
    case valid_frame_event(
        Event, Time, StreamId, FrameType, PayloadBytes
    ) of
        true ->
            Metadata = {frame, Event, Time, StreamId, FrameType, PayloadBytes},
            writer_call(Writer, {event, Metadata}, {error, 3});
        false ->
            {error, 1}
    end;
frame_event(_Writer, _Event, _Time, _StreamId, _FrameType, _PayloadBytes) ->
    {error, 1}.

-spec stats(pid()) ->
    {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}}
    | {error, 1 | 3}.
stats(Writer) when is_pid(Writer) ->
    writer_call(Writer, stats, {error, 3});
stats(_Writer) ->
    {error, 1}.

-spec close(pid()) -> {ok, nil} | {error, 1 | 3}.
close(Writer) when is_pid(Writer) ->
    %% Treat an already-terminated diagnostic writer as closed. This keeps
    %% connection teardown idempotent even after a filesystem failure.
    writer_call(Writer, close, {ok, nil});
close(_Writer) ->
    {error, 1}.

open_valid_directory(Directory, Vantage, MaximumEvents) ->
    case ensure_directory(Directory) of
        {ok, DirectoryList} ->
            open_unique(DirectoryList, Vantage, MaximumEvents, 0);
        {error, _} = Error -> Error
    end.

validate_writable_directory(Directory) ->
    case ensure_directory(Directory) of
        {ok, DirectoryList} -> validate_writable_unique(DirectoryList, 0);
        {error, _} = Error -> Error
    end.

ensure_directory(Directory) ->
    DirectoryList = unicode:characters_to_list(Directory, utf8),
    case is_list(DirectoryList) of
        false -> {error, 1};
        true ->
            Placeholder = filename:join(DirectoryList, ".http3-qlog-dir"),
            case filelib:ensure_dir(Placeholder) of
                ok -> {ok, DirectoryList};
                {error, _Reason} -> {error, 2}
            end
    end.

validate_writable_unique(_Directory, Attempts) when Attempts >= 8 ->
    {error, 2};
validate_writable_unique(Directory, Attempts) ->
    Unique = erlang:unique_integer([positive, monotonic]),
    Filename = lists:flatten(io_lib:format(".http3-qlog-probe-~B", [Unique])),
    Path = filename:join(Directory, Filename),
    case file:open(Path, [write, exclusive, binary]) of
        {ok, Device} ->
            Close = file:close(Device),
            Delete = file:delete(Path),
            case Close =:= ok andalso Delete =:= ok of
                true -> {ok, nil};
                false -> {error, 2}
            end;
        {error, eexist} -> validate_writable_unique(Directory, Attempts + 1);
        {error, _Reason} -> {error, 2}
    end.

open_unique(_Directory, _Vantage, _MaximumEvents, Attempts) when Attempts >= 8 ->
    {error, 2};
open_unique(Directory, Vantage, MaximumEvents, Attempts) ->
    Unique = erlang:unique_integer([positive, monotonic]),
    Role = role(Vantage),
    Filename = lists:flatten(io_lib:format("http3-~s-~B.qlog", [Role, Unique])),
    Path = filename:join(Directory, Filename),
    case file:open(Path, [write, exclusive, binary]) of
        {ok, Device} ->
            case write_record(Device, header(Vantage)) of
                {ok, nil} ->
                    Owner = self(),
                    Writer = spawn(fun() ->
                        nil = quic_core_process_label_ffi:set_role(7),
                        writer_admission(Owner, Device, MaximumEvents)
                    end),
                    {ok, Writer};
                {error, _} = Error ->
                    _ = file:close(Device),
                    _ = file:delete(Path),
                    Error
            end;
        {error, eexist} ->
            open_unique(Directory, Vantage, MaximumEvents, Attempts + 1);
        {error, _Reason} -> {error, 2}
    end.

writer_admission(Owner, Device, MaximumEvents) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    Admission = self(),
    {DeviceWriter, DeviceWriterMonitor} = spawn_monitor(
        fun() ->
            nil = quic_core_process_label_ffi:set_role(7),
            device_writer_loop(Admission, Device)
        end
    ),
    writer_admission_loop(#writer_state{
        owner_monitor = OwnerMonitor,
        device_writer = DeviceWriter,
        device_writer_monitor = DeviceWriterMonitor,
        events = queue:new(),
        maximum_events = MaximumEvents
    }).

writer_admission_loop(State) ->
    receive
        {qlog_call, From, Ref, close}
            when State#writer_state.failed,
                 State#writer_state.device_writer =:= undefined ->
            reply(From, Ref, {error, 3}),
            erlang:demonitor(State#writer_state.owner_monitor, [flush]),
            ok;
        {qlog_call, From, Ref, close} when State#writer_state.failed ->
            State#writer_state.device_writer ! qlog_close,
            writer_admission_loop(State#writer_state{
                closing = true,
                close_sent = true,
                close_waiters = [{From, Ref} | State#writer_state.close_waiters]
            });
        {qlog_call, From, Ref, {event, _Metadata}}
            when State#writer_state.closing ->
            reply(From, Ref, {error, 3}),
            writer_admission_loop(State);
        {qlog_call, From, Ref, {event, _Metadata}}
            when State#writer_state.failed ->
            reply(From, Ref, {error, 3}),
            writer_admission_loop(State#writer_state{
                dropped = State#writer_state.dropped + 1
            });
        {qlog_call, From, Ref, {event, Metadata}} ->
            InFlight = case State#writer_state.busy of
                true -> 1;
                false -> 0
            end,
            case queue:len(State#writer_state.events) + InFlight >=
                 State#writer_state.maximum_events of
                true ->
                    reply(From, Ref, {error, 4}),
                    writer_admission_loop(State#writer_state{
                        dropped = State#writer_state.dropped + 1
                    });
                false ->
                    case normalize_event(
                        Metadata,
                        State#writer_state.last_event_time
                    ) of
                        {ok, Time, Json} ->
                            reply(From, Ref, {ok, nil}),
                            continue_writer(State#writer_state{
                                events = queue:in(Json, State#writer_state.events),
                                last_event_time = Time
                            });
                        error ->
                            reply(From, Ref, {error, 1}),
                            writer_admission_loop(State)
                    end
            end;
        {qlog_call, From, Ref, stats} ->
            InFlight = case State#writer_state.busy of
                true -> 1;
                false -> 0
            end,
            reply(From, Ref, {ok, {
                State#writer_state.dropped,
                State#writer_state.write_errors,
                queue:len(State#writer_state.events) + InFlight
            }}),
            writer_admission_loop(State);
        {qlog_call, From, Ref, close} ->
            continue_writer(State#writer_state{
                closing = true,
                close_waiters = [{From, Ref} | State#writer_state.close_waiters]
            });
        {qlog_device_written, DeviceWriter, {ok, nil}}
            when DeviceWriter =:= State#writer_state.device_writer ->
            continue_writer(State#writer_state{busy = false});
        {qlog_device_written, DeviceWriter, {error, 3}}
            when DeviceWriter =:= State#writer_state.device_writer ->
            Queued = queue:len(State#writer_state.events),
            continue_writer(State#writer_state{
                events = queue:new(),
                busy = false,
                failed = true,
                dropped = State#writer_state.dropped + Queued,
                write_errors = State#writer_state.write_errors + 1
            });
        {qlog_device_closed, DeviceWriter, Result}
            when DeviceWriter =:= State#writer_state.device_writer ->
            reply_waiters(State#writer_state.close_waiters, Result),
            erlang:demonitor(State#writer_state.owner_monitor, [flush]),
            erlang:demonitor(State#writer_state.device_writer_monitor, [flush]),
            ok;
        {'DOWN', Monitor, process, _Owner, _Reason}
            when Monitor =:= State#writer_state.owner_monitor ->
            continue_writer(State#writer_state{closing = true});
        {'DOWN', Monitor, process, _Writer, _Reason}
            when Monitor =:= State#writer_state.device_writer_monitor ->
            Queued = queue:len(State#writer_state.events),
            InFlight = case State#writer_state.busy of
                true -> 1;
                false -> 0
            end,
            writer_admission_loop(State#writer_state{
                device_writer = undefined,
                device_writer_monitor = undefined,
                events = queue:new(),
                busy = false,
                failed = true,
                dropped = State#writer_state.dropped + Queued + InFlight,
                write_errors = State#writer_state.write_errors + 1
            });
        _Other ->
            writer_admission_loop(State)
    end.

continue_writer(State0) ->
    State1 = dispatch_next_event(State0),
    State2 = maybe_close_device(State1),
    writer_admission_loop(State2).

dispatch_next_event(State = #writer_state{busy = true}) ->
    State;
dispatch_next_event(State = #writer_state{failed = true}) ->
    State;
dispatch_next_event(State) ->
    case queue:out(State#writer_state.events) of
        {empty, _} -> State;
        {{value, Json}, Remaining} ->
            State#writer_state.device_writer ! {qlog_write, Json},
            State#writer_state{events = Remaining, busy = true}
    end.

maybe_close_device(State = #writer_state{closing = false}) ->
    State;
maybe_close_device(State = #writer_state{close_sent = true}) ->
    State;
maybe_close_device(State = #writer_state{busy = true}) ->
    State;
maybe_close_device(State) ->
    case queue:is_empty(State#writer_state.events) of
        false -> State;
        true ->
            State#writer_state.device_writer ! qlog_close,
            State#writer_state{close_sent = true}
    end.

device_writer_loop(Admission, Device) ->
    receive
        {qlog_write, Json} ->
            Admission ! {qlog_device_written, self(), write_record(Device, Json)},
            device_writer_loop(Admission, Device);
        qlog_close ->
            Result = close_device(Device),
            Admission ! {qlog_device_closed, self(), Result},
            ok
    end.

writer_call(Writer, Request, DownResult) ->
    Ref = make_ref(),
    Monitor = erlang:monitor(process, Writer),
    Writer ! {qlog_call, self(), Ref, Request},
    receive
        {qlog_reply, Ref, Reply} ->
            erlang:demonitor(Monitor, [flush]),
            Reply;
        {'DOWN', Monitor, process, Writer, _Reason} ->
            DownResult
    after ?CALL_TIMEOUT_MILLISECONDS ->
        erlang:demonitor(Monitor, [flush]),
        DownResult
    end.

reply(To, Ref, Value) ->
    To ! {qlog_reply, Ref, Value}.

reply_waiters(Waiters, Value) ->
    lists:foreach(fun({To, Ref}) -> reply(To, Ref, Value) end, Waiters).

%% The admission process is the only cross-producer ordering point. Keep one
%% scalar watermark and clamp an accepted event to it before JSON construction;
%% no timestamp history or producer identity is retained.
normalize_event({scalar, Event, Time0, Value, Auxiliary}, LastTime)
    when is_integer(Time0), Time0 >= 0 ->
    case valid_event(Event, Value, Auxiliary) of
        true ->
            Time = erlang:max(Time0, LastTime),
            case event_json(Event, Time, Value, Auxiliary) of
                {ok, Json} -> {ok, Time, Json};
                error -> error
            end;
        false ->
            error
    end;
normalize_event(
    {frame, Event, Time0, StreamId, FrameType, PayloadBytes},
    LastTime
) ->
    case valid_frame_event(
        Event, Time0, StreamId, FrameType, PayloadBytes
    ) of
        true ->
            Time = erlang:max(Time0, LastTime),
            case frame_event_json(Event, Time, StreamId, FrameType, PayloadBytes) of
                {ok, Json} -> {ok, Time, Json};
                error -> error
            end;
        false ->
            error
    end;
normalize_event(_Metadata, _LastTime) ->
    error.

valid_event(Event, Value, Auxiliary)
    when Event =:= 1 orelse Event =:= 4 orelse Event =:= 5 orelse
         Event =:= 10 orelse Event =:= 16 orelse Event =:= 17 ->
    is_integer(Value) andalso Value >= 0 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(Event, Count, Bytes) when Event =:= 2 orelse Event =:= 3 ->
    is_integer(Count) andalso Count > 0 andalso Count =< 65535 andalso
        is_integer(Bytes) andalso Bytes >= 0;
valid_event(Event, PacketType, Bytes) when Event =:= 6 orelse Event =:= 7 ->
    is_integer(PacketType) andalso PacketType >= 1 andalso PacketType =< 8 andalso
        is_integer(Bytes) andalso Bytes >= 0;
valid_event(Event, KeyType, Auxiliary) when Event =:= 8 orelse Event =:= 9 ->
    is_integer(KeyType) andalso KeyType >= 1 andalso KeyType =< 8 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(11, State, Auxiliary) ->
    is_integer(State) andalso State >= 1 andalso State =< 4 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(12, State, Trigger) ->
    is_integer(State) andalso State >= 1 andalso State =< 4 andalso
        is_integer(Trigger) andalso Trigger >= 1 andalso Trigger =< 3;
valid_event(14, Initiator, Auxiliary) ->
    is_integer(Initiator) andalso Initiator >= 1 andalso Initiator =< 2 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(15, StreamId, StreamType) ->
    is_integer(StreamId) andalso StreamId >= 0 andalso
        is_integer(StreamType) andalso StreamType >= 1 andalso StreamType =< 7;
valid_event(18, Code, Auxiliary) ->
    is_integer(Code) andalso Code >= 0 andalso Code =< 2147483647 andalso
        is_integer(Auxiliary) andalso Auxiliary >= 0;
valid_event(_Event, _Value, _Auxiliary) ->
    false.

valid_frame_event(Event, Time, StreamId, FrameType, PayloadBytes) ->
    is_integer(Event) andalso (Event =:= 12 orelse Event =:= 13) andalso
        is_integer(Time) andalso Time >= 0 andalso
        is_integer(StreamId) andalso StreamId >= 0 andalso
        is_integer(FrameType) andalso FrameType >= 1 andalso FrameType =< 8 andalso
        is_integer(PayloadBytes) andalso PayloadBytes >= 0.

header(Vantage) ->
    Role = role(Vantage),
    iolist_to_binary([
        <<"{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," >>,
        <<"\"serialization_format\":\"application/qlog+json-seq\"," >>,
        <<"\"title\":\"quic_core HTTP/3 diagnostics\"," >>,
        <<"\"description\":\"draft-ietf-quic-qlog-main-schema-14; privacy=strict\"," >>,
        <<"\"trace\":{" >>,
        <<"\"common_fields\":{" >>,
        <<"\"time_format\":\"relative_to_epoch\"," >>,
        <<"\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}}," >>,
        <<"\"vantage_point\":{\"name\":\"quic_core\",\"type\":\"" >>,
        Role,
        <<"\"},\"event_schemas\":[" >>,
        <<"\"urn:ietf:params:qlog:events:quic-13\"," >>,
        <<"\"urn:ietf:params:qlog:events:http3-13\"," >>,
        <<"\"urn:ietf:params:qlog:events:loglevel\"]}}" >>
    ]).

event_json(1, Time, _Value, _Auxiliary) ->
    %% The draft-13 event schema requires both endpoint objects.  Their
    %% members are optional, so empty objects preserve the strict diagnostic
    %% privacy profile without fabricating or retaining addresses.
    event_with_data(
        Time,
        <<"quic:connection_started">>,
        <<"{\"local\":{},\"remote\":{}}">>
    );
event_json(2, Time, Count, Bytes) ->
    event_with_datagrams(Time, <<"quic:udp_datagrams_received">>, Count, Bytes);
event_json(3, Time, Count, Bytes) ->
    event_with_datagrams(Time, <<"quic:udp_datagrams_sent">>, Count, Bytes);
event_json(4, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_complete\"}">>
    );
event_json(5, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:connection_closed">>,
        <<"{\"initiator\":\"local\",\"trigger\":\"application\"}">>
    );
event_json(6, Time, PacketType, Bytes) ->
    event_with_packet(Time, <<"quic:packet_received">>, PacketType, Bytes);
event_json(7, Time, PacketType, Bytes) ->
    event_with_packet(Time, <<"quic:packet_sent">>, PacketType, Bytes);
event_json(8, Time, KeyType, _Auxiliary) ->
    event_with_key(Time, <<"quic:key_updated">>, KeyType);
event_json(9, Time, KeyType, _Auxiliary) ->
    event_with_key(Time, <<"quic:key_discarded">>, KeyType);
event_json(10, Time, CongestionWindow, BytesInFlight) ->
    event_with_data(
        Time,
        <<"quic:recovery_metrics_updated">>,
        iolist_to_binary(io_lib:format(
            "{\"congestion_window\":~B,\"bytes_in_flight\":~B}",
            [CongestionWindow, BytesInFlight]
        ))
    );
event_json(11, Time, State, _Auxiliary) ->
    case congestion_state(State) of
        error -> error;
        Name -> event_with_data(
            Time,
            <<"quic:congestion_state_updated">>,
            iolist_to_binary([<<"{\"new\":\"">>, Name, <<"\"}">>])
        )
    end;
event_json(12, Time, State, Trigger) ->
    case {congestion_state(State), congestion_trigger(Trigger)} of
        {error, _} -> error;
        {_, error} -> error;
        {Name, Cause} -> event_with_data(
            Time,
            <<"quic:congestion_state_updated">>,
            iolist_to_binary([
                <<"{\"new\":\"">>, Name,
                <<"\",\"trigger\":\"">>, Cause, <<"\"}">>
            ])
        )
    end;
event_json(14, Time, Initiator, _Auxiliary) ->
    case initiator(Initiator) of
        error -> error;
        Name -> event_with_data(
            Time,
            <<"http3:parameters_set">>,
            iolist_to_binary([<<"{\"initiator\":\"">>, Name, <<"\"}">>])
        )
    end;
event_json(15, Time, StreamId, StreamType) ->
    case stream_type(StreamType) of
        error -> error;
        Name -> event_with_data(
            Time,
            <<"http3:stream_type_set">>,
            iolist_to_binary(io_lib:format(
                "{\"initiator\":\"local\",\"stream_id\":~B,"
                "\"stream_type\":\"~s\"}",
                [StreamId, Name]
            ))
        )
    end;
event_json(16, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_started\"}">>
    );
event_json(17, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_abandoned\"}">>
    );
event_json(18, Time, Code, _Auxiliary) when Code =< 2147483647 ->
    %% The main-schema loglevel:error event permits a numeric code without a
    %% message. Deliberately emit only that bounded code: the public bridge
    %% has no text or arbitrary-data parameter that could retain a payload.
    event_with_data(
        Time,
        <<"loglevel:error">>,
        iolist_to_binary(io_lib:format("{\"code\":~B}", [Code]))
    );
event_json(_Event, _Time, _Value, _Auxiliary) ->
    error.

frame_event_json(Event, Time, StreamId, FrameType, PayloadBytes) ->
    Name = frame_event_name(Event),
    case frame_json(FrameType, PayloadBytes) of
        error -> error;
        Frame ->
            event_with_data(
                Time,
                Name,
                iolist_to_binary([
                    <<"{\"stream_id\":" >>,
                    integer_to_binary(StreamId),
                    <<",\"frame\":" >>,
                    Frame,
                    <<"}">>
                ])
            )
    end.

frame_event_name(12) -> <<"http3:frame_created">>;
frame_event_name(13) -> <<"http3:frame_parsed">>.

frame_json(FrameType, PayloadBytes) ->
    case frame_type(FrameType) of
        error -> error;
        {Name, Required} ->
            Raw = case PayloadBytes of
                0 -> <<>>;
                _ -> iolist_to_binary(io_lib:format(
                    ",\"raw\":{\"length\":~B}", [PayloadBytes]
                ))
            end,
            iolist_to_binary([
                <<"{\"frame_type\":\"">>, Name, <<"\"">>, Required, Raw,
                <<"}">>
            ])
    end.

frame_type(1) -> {<<"data">>, <<>>};
frame_type(2) -> {<<"headers">>, <<",\"headers\":[]">>};
frame_type(3) -> {<<"cancel_push">>, <<",\"push_id\":0">>};
frame_type(4) -> {<<"settings">>, <<",\"settings\":[]">>};
frame_type(5) ->
    {<<"push_promise">>, <<",\"push_id\":0,\"headers\":[]">>};
frame_type(6) -> {<<"goaway">>, <<",\"id\":0">>};
frame_type(7) -> {<<"max_push_id">>, <<",\"push_id\":0">>};
frame_type(8) -> {<<"unknown">>, <<",\"frame_type_bytes\":0">>};
frame_type(_) -> error.

event_with_packet(Time, Name, PacketType, Bytes) ->
    case packet_type(PacketType) of
        error -> error;
        Type ->
            Raw = case Bytes of
                0 -> <<>>;
                _ -> iolist_to_binary(io_lib:format(
                    ",\"raw\":{\"length\":~B}", [Bytes]
                ))
            end,
            event_with_data(
                Time,
                Name,
                iolist_to_binary([
                    <<"{\"header\":{\"packet_type\":\"">>,
                    Type,
                    <<"\"}">>,
                    Raw,
                    <<"}">>
                ])
            )
    end.

event_with_key(Time, Name, KeyType) ->
    case key_type(KeyType) of
        error -> error;
        Type -> event_with_data(
            Time,
            Name,
            iolist_to_binary([
                <<"{\"key_type\":\"">>, Type,
                <<"\",\"trigger\":\"tls\"}">>
            ])
        )
    end.

packet_type(1) -> <<"initial">>;
packet_type(2) -> <<"handshake">>;
packet_type(3) -> <<"0RTT">>;
packet_type(4) -> <<"1RTT">>;
packet_type(5) -> <<"retry">>;
packet_type(6) -> <<"version_negotiation">>;
packet_type(7) -> <<"stateless_reset">>;
packet_type(8) -> <<"unknown">>;
packet_type(_) -> error.

key_type(1) -> <<"server_initial_secret">>;
key_type(2) -> <<"client_initial_secret">>;
key_type(3) -> <<"server_handshake_secret">>;
key_type(4) -> <<"client_handshake_secret">>;
key_type(5) -> <<"server_0rtt_secret">>;
key_type(6) -> <<"client_0rtt_secret">>;
key_type(7) -> <<"server_1rtt_secret">>;
key_type(8) -> <<"client_1rtt_secret">>;
key_type(_) -> error.

congestion_state(1) -> <<"slow_start">>;
congestion_state(2) -> <<"congestion_avoidance">>;
congestion_state(3) -> <<"recovery">>;
congestion_state(4) -> <<"application_limited">>;
congestion_state(_) -> error.

congestion_trigger(1) -> <<"packet_loss">>;
congestion_trigger(2) -> <<"ecn_ce">>;
congestion_trigger(3) -> <<"persistent_congestion">>;
congestion_trigger(_) -> error.

initiator(1) -> <<"local">>;
initiator(2) -> <<"remote">>;
initiator(_) -> error.

stream_type(1) -> <<"request">>;
stream_type(2) -> <<"control">>;
stream_type(3) -> <<"push">>;
stream_type(4) -> <<"reserved">>;
stream_type(5) -> <<"unknown">>;
stream_type(6) -> <<"qpack_encode">>;
stream_type(7) -> <<"qpack_decode">>;
stream_type(_) -> error.

event_with_datagrams(Time, Name, 1, Bytes) when Bytes > 0 ->
    event_with_data(
        Time,
        Name,
        iolist_to_binary(
            io_lib:format("{\"count\":1,\"raw\":[{\"length\":~B}]}", [Bytes])
        )
    );
event_with_datagrams(Time, Name, Count, _Bytes) when Count > 0, Count =< 65535 ->
    event_with_data(
        Time,
        Name,
        iolist_to_binary(io_lib:format("{\"count\":~B}", [Count]))
    );
event_with_datagrams(_Time, _Name, _Count, _Bytes) ->
    error.

event_with_data(Time, Name, Data) ->
    {ok, iolist_to_binary([
        <<"{\"time\":" >>,
        integer_to_binary(Time),
        <<",\"name\":\"" >>,
        Name,
        <<"\",\"data\":" >>,
        Data,
        <<"}">>
    ])}.

write_record(Device, Json) ->
    try file:write(Device, [<<16#1e>>, Json, <<"\n">>]) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, 3}
    catch
        _Class:_Reason -> {error, 3}
    end.

close_device(Device) ->
    try file:close(Device) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, 3}
    catch
        _Class:_Reason -> {error, 3}
    end.

role(1) -> <<"client">>;
role(2) -> <<"server">>.
