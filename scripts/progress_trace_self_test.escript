#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(TRACE_ENVIRONMENT, "HTTP3_BENCHMARK_TRACE_DIR").
-define(MARKER, <<"trace-payload-marker-5f17c9">>).
-define(CSV_HEADER,
        <<"schema,mode,iteration,warmup,workers,requests_per_worker,elapsed_ms,"
          "server_completed,client_completed,client_min_completed,"
          "client_p10_completed,client_p50_completed,client_p90_completed,"
          "client_max_completed,client_completion_spread,active_clients,"
          "client_phase_connect_open_or_send,"
          "client_phase_awaiting_response,client_phase_response,"
          "client_phase_completed,stalled_clients,server_minus_client_completed,"
          "server_completed_since_previous,client_completed_since_previous,"
          "beam_processes,beam_memory_bytes,mailbox_messages,vm_census_age_ms,"
          "vm_census_collection_microseconds,run_queue,"
          "runtime_ms_since_previous,reductions_since_previous,"
          "progress_collection_microseconds,sample_collection_microseconds">>).

main([]) ->
    guarded_self_test();
main(_) ->
    io:format(standard_error, "usage: progress_trace_self_test.escript~n", []),
    halt(1).

guarded_self_test() ->
    try self_test() of
        ok ->
            io:format("HTTP/3 benchmark progress trace self-test passed~n", [])
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "progress trace self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

self_test() ->
    load_trace_module(),
    PreviousEnvironment = os:getenv(?TRACE_ENVIRONMENT),
    true = os:unsetenv(?TRACE_ENVIRONMENT),
    disabled = http3_benchmark_trace_ffi:start_progress_trace(
                 <<"load">>, 1, false, 2, 2),
    Directory = temporary_directory(),
    ok = file:make_dir(Directory),
    Parent = self(),
    {SensitiveProcess, SensitiveMonitor} = spawn_monitor(fun() ->
        sensitive_process(Parent)
    end),
    receive
        {sensitive_process_ready, SensitiveProcess} -> ok
    after 5000 -> erlang:error(sensitive_process_start_timeout)
    end,
    lists:foreach(fun(_Index) -> SensitiveProcess ! {retained, ?MARKER} end,
                  lists:seq(1, 128)),
    true = os:putenv(?TRACE_ENVIRONMENT, Directory),
    try
        run_enabled_trace_test(Directory, SensitiveProcess)
    after
        SensitiveProcess ! stop_sensitive_process,
        await_sensitive_process(SensitiveProcess, SensitiveMonitor),
        restore_environment(PreviousEnvironment),
        cleanup_directory(Directory)
    end.

run_enabled_trace_test(Directory, SensitiveProcess) ->
    Trace = http3_benchmark_trace_ffi:start_progress_trace(
              <<"load">>, 1, false, 2, 2),
    nil = http3_benchmark_trace_ffi:trace_client_progress(Trace, 0, 1, 2),
    nil = http3_benchmark_trace_ffi:trace_server_progress(Trace, 0),
    timer:sleep(6200),
    nil = http3_benchmark_trace_ffi:stop_progress_trace(Trace),
    CsvPath = filename:join(Directory, "load-measured-1.csv"),
    {ok, Csv} = file:read_file(CsvPath),
    verify_csv(Csv),
    [SnapshotPath] =
        filelib:wildcard(filename:join(Directory,
                                       "load-measured-1-stall-*.json")),
    {ok, SnapshotBytes} = file:read_file(SnapshotPath),
    nomatch = binary:match(SnapshotBytes, ?MARKER),
    verify_snapshot(json:decode(SnapshotBytes), SensitiveProcess),
    ok.

verify_csv(Csv) ->
    [Header | Rows] = [Line || Line <- binary:split(Csv, <<"\n">>, [global]),
                               Line =/= <<>>],
    ensure(Header =:= ?CSV_HEADER, invalid_progress_trace_header),
    ensure(length(Rows) >= 6, {insufficient_progress_trace_rows, length(Rows)}),
    lists:foreach(
      fun(Row) ->
          Fields = binary:split(Row, <<",">>, [global]),
          ensure(length(Fields) =:= 34,
                 {invalid_progress_trace_row_width, length(Fields), Row})
      end,
      Rows),
    ok.

verify_snapshot(Snapshot, SensitiveProcess) ->
    ensure(maps:get(<<"schema">>, Snapshot) =:= 1,
           invalid_progress_snapshot_schema),
    ensure(maps:get(<<"shareable">>, Snapshot) =:= false,
           progress_snapshot_must_not_be_shareable),
    ensure(maps:get(<<"payload_free">>, Snapshot) =:= true,
           progress_snapshot_must_be_payload_free),
    Processes = maps:get(<<"processes">>, Snapshot),
    Ports = maps:get(<<"ports">>, Snapshot),
    ensure(length(Processes) =< 64, unbounded_progress_snapshot_processes),
    ensure(length(Ports) =< 64, unbounded_progress_snapshot_ports),
    SensitivePid = list_to_binary(pid_to_list(SensitiveProcess)),
    ensure(lists:any(fun(Process) ->
                         maps:get(<<"pid">>, Process) =:= SensitivePid
                     end,
                     Processes),
           sensitive_fixture_missing_from_bounded_snapshot),
    lists:foreach(fun verify_process_snapshot/1, Processes),
    lists:foreach(fun verify_port_snapshot/1, Ports),
    Redaction = maps:get(<<"redaction">>, Snapshot),
    ExpectedRedactionKeys =
        [<<"function_arguments">>, <<"message_payloads">>,
         <<"process_dictionaries">>, <<"socket_endpoints">>],
    ensure(lists:sort(maps:keys(Redaction)) =:= ExpectedRedactionKeys,
           invalid_progress_snapshot_redaction),
    ok.

verify_process_snapshot(Process) ->
    ExpectedKeys =
        [<<"current_mfa">>, <<"initial_mfa">>, <<"memory_bytes">>,
         <<"message_queue_len">>, <<"pid">>, <<"reductions">>,
         <<"stack_mfas">>, <<"status">>],
    ensure(lists:sort(maps:keys(Process)) =:= ExpectedKeys,
           {unexpected_process_snapshot_fields, maps:keys(Process)}),
    verify_mfa(maps:get(<<"current_mfa">>, Process)),
    verify_mfa(maps:get(<<"initial_mfa">>, Process)),
    lists:foreach(fun verify_mfa/1, maps:get(<<"stack_mfas">>, Process)).

verify_mfa(null) ->
    ok;
verify_mfa(Mfa) ->
    ensure(lists:sort(maps:keys(Mfa)) =:=
               [<<"arity">>, <<"function">>, <<"module">>],
           {unexpected_mfa_snapshot_fields, maps:keys(Mfa)}),
    ensure(is_integer(maps:get(<<"arity">>, Mfa)), invalid_mfa_arity).

verify_port_snapshot(Port) ->
    ExpectedKeys =
        [<<"connected">>, <<"id">>, <<"input_bytes">>, <<"memory_bytes">>,
         <<"name">>, <<"output_bytes">>, <<"queue_size">>],
    ensure(lists:sort(maps:keys(Port)) =:= ExpectedKeys,
           {unexpected_port_snapshot_fields, maps:keys(Port)}).

sensitive_process(Parent) ->
    put(trace_fixture_value, ?MARKER),
    Parent ! {sensitive_process_ready, self()},
    receive
        stop_sensitive_process -> ok
    end.

await_sensitive_process(Process, Monitor) ->
    receive
        {'DOWN', Monitor, process, Process, normal} -> ok;
        {'DOWN', Monitor, process, Process, Reason} ->
            erlang:error({sensitive_process_failed, Reason})
    after 5000 ->
        exit(Process, kill),
        receive
            {'DOWN', Monitor, process, Process, _Reason} -> ok
        after 5000 -> ok
        end
    end.

load_trace_module() ->
    Script = filename:absname(escript:script_name()),
    Root = filename:dirname(filename:dirname(Script)),
    EbinPattern = filename:join(
                    [Root, "packages", "http3", "build", "dev", "erlang",
                     "*", "ebin"]),
    EbinDirectories = filelib:wildcard(EbinPattern),
    ensure(EbinDirectories =/= [], {missing_http3_build, EbinPattern}),
    lists:foreach(fun(Directory) -> true = code:add_patha(Directory) end,
                  EbinDirectories),
    {module, http3_benchmark_trace_ffi} =
        code:ensure_loaded(http3_benchmark_trace_ffi),
    ok.

temporary_directory() ->
    Base = case os:getenv("TMPDIR") of
        false -> "/tmp";
        [] -> "/tmp";
        Value -> Value
    end,
    filename:join(
      filename:absname(Base),
      "http3-progress-trace-self-test-"
      ++ integer_to_list(erlang:unique_integer([positive, monotonic]))).

restore_environment(false) ->
    true = os:unsetenv(?TRACE_ENVIRONMENT),
    ok;
restore_environment(Value) ->
    true = os:putenv(?TRACE_ENVIRONMENT, Value),
    ok.

cleanup_directory(Directory) ->
    lists:foreach(fun(Path) -> ok = file:delete(Path) end,
                  filelib:wildcard(filename:join(Directory, "*"))),
    ok = file:del_dir(Directory).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
