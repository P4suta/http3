-module(gleam_quic_qlog_ffi).

-export([close/1, event/5, open/2, validate_directory/1]).

-define(MAX_DIRECTORY_BYTES, 4096).

-spec open(binary(), 1 | 2) -> {ok, pid()} | {error, 1 | 2 | 3}.
open(Directory, Vantage)
    when is_binary(Directory), byte_size(Directory) > 0,
         byte_size(Directory) =< ?MAX_DIRECTORY_BYTES,
         (Vantage =:= 1 orelse Vantage =:= 2) ->
    case binary:match(Directory, <<0>>) of
        nomatch -> open_valid_directory(Directory, Vantage);
        _ -> {error, 1}
    end;
open(_Directory, _Vantage) ->
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
    {ok, nil} | {error, 1 | 3}.
event(Device, Event, Time, Value, Auxiliary)
    when is_pid(Device), is_integer(Event), Event >= 1, Event =< 5,
         is_integer(Time), Time >= 0,
         is_integer(Value), Value >= 0,
         is_integer(Auxiliary), Auxiliary >= 0 ->
    case event_json(Event, Time, Value, Auxiliary) of
        {ok, Json} -> write_record(Device, Json);
        error -> {error, 1}
    end;
event(_Device, _Event, _Time, _Value, _Auxiliary) ->
    {error, 1}.

-spec close(pid()) -> {ok, nil} | {error, 1 | 3}.
close(Device) when is_pid(Device) ->
    try file:close(Device) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, 3}
    catch
        _Class:_Reason -> {error, 3}
    end;
close(_Device) ->
    {error, 1}.

open_valid_directory(Directory, Vantage) ->
    case ensure_directory(Directory) of
        {ok, DirectoryList} -> open_unique(DirectoryList, Vantage, 0);
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

open_unique(_Directory, _Vantage, Attempts) when Attempts >= 8 ->
    {error, 2};
open_unique(Directory, Vantage, Attempts) ->
    Unique = erlang:unique_integer([positive, monotonic]),
    Role = role(Vantage),
    Filename = lists:flatten(io_lib:format("http3-~s-~B.qlog", [Role, Unique])),
    Path = filename:join(Directory, Filename),
    case file:open(Path, [write, exclusive, binary]) of
        {ok, Device} ->
            case write_record(Device, header(Vantage)) of
                {ok, nil} -> {ok, Device};
                {error, _} = Error ->
                    _ = file:close(Device),
                    _ = file:delete(Path),
                    Error
            end;
        {error, eexist} -> open_unique(Directory, Vantage, Attempts + 1);
        {error, _Reason} -> {error, 2}
    end.

header(Vantage) ->
    Role = role(Vantage),
    iolist_to_binary([
        <<"{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," >>,
        <<"\"serialization_format\":\"application/qlog+json-seq\"," >>,
        <<"\"title\":\"gleam_quic native HTTP/3\",\"trace\":{" >>,
        <<"\"common_fields\":{\"protocol_type\":[\"QUIC\"]," >>,
        <<"\"time_format\":\"relative_to_epoch\"," >>,
        <<"\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}}," >>,
        <<"\"vantage_point\":{\"name\":\"gleam_quic\",\"type\":\"" >>,
        Role,
        <<"\"},\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-13\"]}}" >>
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

role(1) -> <<"client">>;
role(2) -> <<"server">>.
