-module(gleam_quic_qlog_ffi).

-export([close/1, event/5, open/3, stats/1, validate_directory/1]).

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
    when is_pid(Writer), is_integer(Event), Event >= 1, Event =< 5,
         is_integer(Time), Time >= 0,
         is_integer(Value), Value >= 0,
         is_integer(Auxiliary), Auxiliary >= 0 ->
    case event_json(Event, Time, Value, Auxiliary) of
        {ok, Json} -> writer_call(Writer, {event, Json}, {error, 3});
        error -> {error, 1}
    end;
event(_Writer, _Event, _Time, _Value, _Auxiliary) ->
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
                        nil = gleam_quic_process_label_ffi:set_role(7),
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
            nil = gleam_quic_process_label_ffi:set_role(7),
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
        {qlog_call, From, Ref, {event, _Json}} when State#writer_state.closing ->
            reply(From, Ref, {error, 3}),
            writer_admission_loop(State);
        {qlog_call, From, Ref, {event, _Json}} when State#writer_state.failed ->
            reply(From, Ref, {error, 3}),
            writer_admission_loop(State#writer_state{
                dropped = State#writer_state.dropped + 1
            });
        {qlog_call, From, Ref, {event, Json}} ->
            case queue:len(State#writer_state.events) >=
                 State#writer_state.maximum_events of
                true ->
                    reply(From, Ref, {error, 4}),
                    writer_admission_loop(State#writer_state{
                        dropped = State#writer_state.dropped + 1
                    });
                false ->
                    reply(From, Ref, {ok, nil}),
                    continue_writer(State#writer_state{
                        events = queue:in(Json, State#writer_state.events)
                    })
            end;
        {qlog_call, From, Ref, stats} ->
            InFlight = case State#writer_state.busy of true -> 1; false -> 0 end,
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
            InFlight = case State#writer_state.busy of true -> 1; false -> 0 end,
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

header(Vantage) ->
    Role = role(Vantage),
    iolist_to_binary([
        <<"{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," >>,
        <<"\"serialization_format\":\"application/qlog+json-seq\"," >>,
        <<"\"title\":\"gleam_quic HTTP/3 diagnostics\"," >>,
        <<"\"description\":\"draft-ietf-quic-qlog-main-schema-14; privacy=strict\"," >>,
        <<"\"trace\":{" >>,
        <<"\"common_fields\":{\"protocol_type\":[\"QUIC\",\"HTTP/3\"]," >>,
        <<"\"time_format\":\"relative_to_epoch\"," >>,
        <<"\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}}," >>,
        <<"\"vantage_point\":{\"name\":\"gleam_quic\",\"type\":\"" >>,
        Role,
        <<"\"},\"event_schemas\":[" >>,
        <<"\"urn:ietf:params:qlog:events:quic-13\"," >>,
        <<"\"urn:ietf:params:qlog:events:http3-13\"]}}" >>
    ]).

event_json(1, Time, _Value, _Auxiliary) ->
    event_with_data(Time, <<"quic:connection_started">>, <<"{}">>);
event_json(2, Time, Count, Bytes) ->
    event_with_datagrams(Time, <<"quic:udp_datagrams_received">>, Count, Bytes);
event_json(3, Time, Count, Bytes) ->
    event_with_datagrams(Time, <<"quic:udp_datagrams_sent">>, Count, Bytes);
event_json(4, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:migration_state_updated">>,
        <<"{\"new\":\"migration_completed\"}">>
    );
event_json(5, Time, _Value, _Auxiliary) ->
    event_with_data(
        Time,
        <<"quic:connection_closed">>,
        <<"{\"initiator\":\"local\",\"trigger\":\"application\"}">>
    );
event_json(_Event, _Time, _Value, _Auxiliary) ->
    error.

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
