-module(qlog_test_ffi).

-export([
    fail_device_writer/1,
    file_contains/2,
    with_directory/1,
    with_temp_override/1,
    with_tmpdir_override/1,
    write_probe_file/1
]).

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
