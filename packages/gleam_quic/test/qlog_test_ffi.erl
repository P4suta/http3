-module(qlog_test_ffi).

-export([fail_device_writer/1, file_contains/2, with_directory/1]).

-spec fail_device_writer(tuple()) -> {ok, nil} | {error, nil}.
fail_device_writer({writer, Admission, _Epoch}) when is_pid(Admission) ->
    fail_device_writer(Admission, 100);
fail_device_writer(_Writer) ->
    {error, nil}.

fail_device_writer(Admission, Remaining) ->
    case process_info(Admission, monitors) of
        {monitors, Monitors} ->
            Candidates = [
                Pid
             || {process, Pid} <- Monitors,
                is_pid(Pid),
                is_device_writer(Pid)
            ],
            case Candidates of
                [DeviceWriter] ->
                    exit(DeviceWriter, kill),
                    {ok, nil};
                _ when Remaining > 0 ->
                    receive after 1 ->
                        fail_device_writer(Admission, Remaining - 1)
                    end;
                _ ->
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

is_device_writer(Pid) ->
    case process_info(Pid, current_function) of
        {current_function, {gleam_quic_qlog_ffi, device_writer_loop, 2}} -> true;
        _ -> false
    end.

-spec with_directory(fun((binary()) -> term())) -> term().
with_directory(Fun) when is_function(Fun, 1) ->
    Suffix = integer_to_list(erlang:unique_integer([positive, monotonic])),
    Directory = filename:join("/tmp", "gleam-quic-qlog-test-" ++ Suffix),
    try Fun(list_to_binary(Directory))
    after
        _ = file:del_dir_r(Directory)
    end.

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
