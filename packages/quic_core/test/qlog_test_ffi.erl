-module(qlog_test_ffi).

-export([
    fail_device_writer/1,
    file_contains/2,
    file_event_times/1,
    files_are_rfc7464_sequences/1,
    with_directory/1,
    with_suspended_device_writer/2,
    with_temp_override/1,
    with_tmpdir_override/1,
    write_two_producer_interleaving/1,
    write_probe_file/1
]).

%% Drive two independent producers in a deterministic admission order. Their
%% local timestamps are 0, 2, 1, 3, exposing any missing writer-wide watermark
%% without depending on scheduler timing.
-spec write_two_producer_interleaving(tuple()) -> {ok, nil} | {error, nil}.
write_two_producer_interleaving({writer, Admission, _Epoch})
    when is_pid(Admission) ->
    Controller = self(),
    ProducerA = spawn(fun() -> timestamp_producer(Admission, Controller) end),
    ProducerB = spawn(fun() -> timestamp_producer(Admission, Controller) end),
    try
        ok = emit_and_wait(ProducerA, scalar, 0),
        ok = emit_and_wait(ProducerB, frame, 2),
        ok = emit_and_wait(ProducerA, frame, 1),
        ok = emit_and_wait(ProducerB, scalar, 3),
        {ok, nil}
    catch
        _:_ -> {error, nil}
    after
        ProducerA ! stop,
        ProducerB ! stop
    end;
write_two_producer_interleaving(_Writer) ->
    {error, nil}.

timestamp_producer(Admission, Controller) ->
    receive
        {emit, Token, Kind, Time} ->
            Result = case Kind of
                scalar ->
                    quic_core_qlog_ffi:event(Admission, 3, Time, 1, 1200);
                frame ->
                    quic_core_qlog_ffi:frame_event(
                        Admission, 12, Time, 0, 1, 1200
                    )
            end,
            Controller ! {emitted, self(), Token, Result},
            timestamp_producer(Admission, Controller);
        stop ->
            ok
    end.

emit_and_wait(Producer, Kind, Time) ->
    Token = make_ref(),
    Producer ! {emit, Token, Kind, Time},
    receive
        {emitted, Producer, Token, {ok, nil}} -> ok;
        {emitted, Producer, Token, _Error} -> error
    after 5000 ->
        error
    end.

-spec fail_device_writer(tuple()) -> {ok, nil} | {error, nil}.
fail_device_writer({writer, Admission, _Epoch}) when is_pid(Admission) ->
    case find_device_writer(Admission, 100) of
        {ok, DeviceWriter} ->
            exit(DeviceWriter, kill),
            {ok, nil};
        {error, nil} = Error -> Error
    end;
fail_device_writer(_Writer) ->
    {error, nil}.

%% Freeze the filesystem worker while a test exercises admission. This turns
%% an otherwise scheduler-dependent in-flight boundary into deterministic
%% evidence, and always resumes the worker before returning or raising.
-spec with_suspended_device_writer(tuple(), fun(() -> term())) ->
    {ok, term()} | {error, nil}.
with_suspended_device_writer({writer, Admission, _Epoch}, Fun)
    when is_pid(Admission), is_function(Fun, 0) ->
    case find_device_writer(Admission, 100) of
        {ok, DeviceWriter} ->
            true = erlang:suspend_process(DeviceWriter),
            try {ok, Fun()}
            after
                true = erlang:resume_process(DeviceWriter)
            end;
        {error, nil} = Error -> Error
    end;
with_suspended_device_writer(_Writer, _Fun) ->
    {error, nil}.

find_device_writer(Admission, Remaining) ->
    case process_info(Admission, monitors) of
        {monitors, Monitors} ->
            Candidates = [
                Pid
             || {process, Pid} <- Monitors,
                is_pid(Pid),
                is_device_writer(Pid)
            ],
            case Candidates of
                [DeviceWriter] -> {ok, DeviceWriter};
                _ when Remaining > 0 ->
                    receive after 1 ->
                        find_device_writer(Admission, Remaining - 1)
                    end;
                _ ->
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

is_device_writer(Pid) ->
    case process_info(Pid, current_function) of
        {current_function, {quic_core_qlog_ffi, device_writer_loop, 2}} -> true;
        _ -> false
    end.

%% Runs Fun with the path of a uniquely named scratch directory and deletes
%% that directory afterwards, whether or not Fun created it.
-spec with_directory(fun((binary()) -> term())) -> term().
with_directory(Fun) when is_function(Fun, 1) ->
    Directory = unique_scratch_path("gleam-quic-qlog-test-"),
    try Fun(list_to_binary(Directory))
    after
        _ = file:del_dir_r(Directory)
    end.

%% Points TMPDIR at a fresh scratch directory for the duration of Fun, then
%% restores the previous environment and deletes the directory.
-spec with_tmpdir_override(fun((binary()) -> term())) -> term().
with_tmpdir_override(Fun) when is_function(Fun, 1) ->
    with_environment_override("TMPDIR", "gleam-quic-tmpdir-test-", Fun).

%% Unsets TMPDIR and points TEMP at a fresh scratch directory, exercising the
%% documented TEMP fallback of temporary_root/0.
-spec with_temp_override(fun((binary()) -> term())) -> term().
with_temp_override(Fun) when is_function(Fun, 1) ->
    with_environment_override("TEMP", "gleam-quic-temp-test-", Fun).

%% Mutates the process-global environment, so it relies on gleeunit running
%% test modules sequentially; every variable it touches is restored afterwards.
-spec with_environment_override(
    string(), string(), fun((binary()) -> term())
) -> term().
with_environment_override(Name, Prefix, Fun) ->
    Root = unique_scratch_path(Prefix),
    ok = filelib:ensure_path(Root),
    Previous = [
        {Candidate, os:getenv(Candidate)}
     || Candidate <- ["TMPDIR", "TEMP", "TMP"]
    ],
    lists:foreach(fun({Candidate, _}) -> os:unsetenv(Candidate) end, Previous),
    true = os:putenv(Name, Root),
    try Fun(list_to_binary(Root))
    after
        lists:foreach(
            fun({Candidate, Value}) -> restore_environment(Candidate, Value) end,
            Previous
        ),
        _ = file:del_dir_r(Root)
    end.

%% Creates Directory, writes one file inside it, and reports whether that file
%% exists, proving the fixture root is writable.
-spec write_probe_file(binary()) -> boolean().
write_probe_file(Directory) when is_binary(Directory) ->
    Path = filename:join(binary_to_list(Directory), "probe.txt"),
    ok =:= filelib:ensure_dir(Path)
        andalso ok =:= file:write_file(Path, <<"probe">>)
        andalso filelib:is_regular(Path).

%% Returns a unique, not-yet-created path under the OS temporary directory.
-spec unique_scratch_path(string()) -> string().
unique_scratch_path(Prefix) ->
    Suffix = integer_to_list(erlang:unique_integer([positive, monotonic])),
    filename:join(temporary_root(), Prefix ++ Suffix).

%% First non-empty of TMPDIR, TEMP, and TMP, falling back to "/tmp", so the
%% fixtures also work where /tmp is read-only or absent, such as on Windows.
-spec temporary_root() -> string().
temporary_root() ->
    first_environment_value(["TMPDIR", "TEMP", "TMP"], "/tmp").

-spec first_environment_value([string()], string()) -> string().
first_environment_value([], Default) ->
    Default;
first_environment_value([Name | Rest], Default) ->
    case os:getenv(Name) of
        [_ | _] = Value -> Value;
        _ -> first_environment_value(Rest, Default)
    end.

-spec restore_environment(string(), string() | false) -> ok.
restore_environment(Name, false) ->
    _ = os:unsetenv(Name),
    ok;
restore_environment(Name, Value) ->
    _ = os:putenv(Name, Value),
    ok.

-spec file_contains(binary(), binary()) -> boolean().
file_contains(Directory, Text)
    when is_binary(Directory), is_binary(Text) ->
    Files = filelib:wildcard(filename:join(binary_to_list(Directory), "*.qlog")),
    Files =/= [] andalso lists:all(fun(Path) ->
        case file:read_file(Path) of
            {ok, Contents} -> binary:match(Contents, Text) =/= nomatch;
            {error, _Reason} -> false
        end
    end, Files).

%% Return event timestamps from the fixture's sole trace, excluding its header.
-spec file_event_times(binary()) -> {ok, [non_neg_integer()]} | {error, nil}.
file_event_times(Directory) when is_binary(Directory) ->
    Files = filelib:wildcard(filename:join(binary_to_list(Directory), "*.qlog")),
    case Files of
        [Path] ->
            try
                {ok, Bytes} = file:read_file(Path),
                [<<>>, _Header | Events] = binary:split(Bytes, <<16#1e>>, [global]),
                {ok, [event_time(Event) || Event <- Events]}
            catch
                _:_ -> {error, nil}
            end;
        _ ->
            {error, nil}
    end;
file_event_times(_Directory) ->
    {error, nil}.

event_time(Record) when byte_size(Record) >= 2 ->
    Json = binary:part(Record, 0, byte_size(Record) - 1),
    #{<<"time">> := Time} = json:decode(Json),
    true = is_integer(Time) andalso Time >= 0,
    Time.

%% Checks the writer output as bytes, independently of the qlog semantic
%% validator. RFC 7464 requires UTF-8 records framed as RS JSON-text LF.
-spec files_are_rfc7464_sequences(binary()) -> boolean().
files_are_rfc7464_sequences(Directory) when is_binary(Directory) ->
    Files = filelib:wildcard(filename:join(binary_to_list(Directory), "*.qlog")),
    Files =/= [] andalso lists:all(fun is_rfc7464_file/1, Files).

is_rfc7464_file(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} when byte_size(Bytes) > 0 ->
            is_utf8(Bytes) andalso
                binary:first(Bytes) =:= 16#1e andalso
                is_rfc7464_records(binary:split(Bytes, <<16#1e>>, [global]));
        _ ->
            false
    end.

is_rfc7464_records([<<>> | Records]) when Records =/= [] ->
    lists:all(fun is_rfc7464_record/1, Records);
is_rfc7464_records(_Records) ->
    false.

is_rfc7464_record(Record) when byte_size(Record) >= 2 ->
    case binary:last(Record) of
        $\n ->
            Json = binary:part(Record, 0, byte_size(Record) - 1),
            try json:decode(Json) of
                _Value -> true
            catch
                _:_ -> false
            end;
        _ ->
            false
    end;
is_rfc7464_record(_Record) ->
    false.

is_utf8(Bytes) ->
    try unicode:characters_to_binary(Bytes, utf8, utf8) of
        Converted -> is_binary(Converted) andalso Converted =:= Bytes
    catch
        _:_ -> false
    end.
