%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(ffi_analysis_child).
-export([run/5]).

%% This VM performs compiler-graph analysis only. Ordinary application/test
%% VMs retain process_runner's 256 MiB policy. PLT construction and loading both
%% exceeded that limit on OTP 29; their measured largest actor was 390 MB.
run(Phase, Plt, Files, Path, Nonce) ->
    Heap = #{size => 134217728, kill => true, error_logger => false,
             include_shared_binaries => true},
    erlang:system_flag(max_heap_size, Heap),
    process_flag(max_heap_size, Heap),
    erlang:system_flag(schedulers_online, erlang:min(2, erlang:system_info(schedulers_online))),
    Observation = observe(),
    Parent = self(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Result = try analyze(Phase, Plt, Files)
                 catch _:_ -> failed(analysis_failed) end,
        Parent ! {analysis_result, self(), Result}
    end),
    Result = receive
        {analysis_result, Worker, Value} ->
            receive
                {'DOWN', Monitor, process, Worker, normal} -> Value;
                {'DOWN', Monitor, process, Worker, _} -> failed(analysis_worker_failed)
            end;
        {'DOWN', Monitor, process, Worker, killed} -> failed(analysis_worker_killed);
        {'DOWN', Monitor, process, Worker, _} -> failed(analysis_worker_failed)
    end,
    Memory = stop_observer(Observation),
    Report = Result#{schema => 1, phase => Phase, nonce => Nonce, memory => Memory},
    Bytes = json:encode(Report),
    true = iolist_size(Bytes) =< 2097152,
    ok = file:write_file(Path, Bytes, [exclusive]),
    erlang:halt(case maps:get(passed, Result) andalso maps:get(joined, Memory) of
        true -> 0; false -> 1
    end).

analyze(plt, Plt, []) ->
    [] = dialyzer:run([{analysis_type, plt_build}, {apps, applications()},
                      {output_plt, Plt}, {get_warnings, false}]),
    passed(0);
analyze(analyze, Plt, Files) ->
    {Warnings, Modules} = dialyzer:run_report_modules_analyzed([
        {analysis_type, succ_typings}, {init_plt, Plt}, {check_plt, false},
        {files, Files}]),
    Expected = lists:sort([list_to_atom(filename:basename(P, ".beam")) || P <- Files]),
    true = lists:sort(Modules) =:= Expected,
    true = length(Warnings) =< 4096,
    Rows = [warning(W, Expected) || W <- Warnings],
    (passed(length(Modules)))#{passed => Warnings =:= [],
        warning_count => length(Warnings), warnings => Rows,
        failure => case Warnings of [] -> none; _ -> type_findings end};
%% Private adversarial controls are reachable only from the runner self-test.
analyze(control_policy, _, _) ->
    #{size := 134217728, kill := true, error_logger := false,
      include_shared_binaries := true} = element(2, process_info(self(), max_heap_size)),
    passed(0);
analyze(control_private, _, _) -> error({private_input, <<"ffi-private-control">>});
analyze(control_timeout, _, _) -> receive never -> passed(0) end;
analyze(control_flood, _, _) -> flood();
analyze(control_killed, _, _) -> exit(self(), kill).

applications() -> [erts, kernel, stdlib, crypto, asn1, public_key, ssl, compiler,
                   syntax_tools, parsetools, inets, runtime_tools, mnesia].
passed(Count) -> #{passed => true, failure => none, module_count => Count,
                   warning_count => 0, warnings => []}.
failed(Kind) -> (passed(0))#{passed => false, failure => Kind}.
flood() -> io:put_chars(binary:copy(<<"ffi-private-output">>, 4096)), flood().

warning({Tag, {File, Location, _}, {Kind, _}}, Expected) ->
    warning_row(Tag, File, Location, Kind, Expected);
warning({Tag, {File, Location}, {Kind, _}}, Expected) ->
    warning_row(Tag, File, Location, Kind, Expected).
warning_row(Tag, File, Location, Kind, Expected) ->
    Name = filename:basename(File, ".erl"),
    true = lists:member(Name, [atom_to_list(M) || M <- Expected]),
    {Line, Column} = case Location of {L, C} -> {L, C}; L -> {L, 0} end,
    true = is_integer(Line) andalso Line > 0 andalso Line =< 1000000,
    true = is_integer(Column) andalso Column >= 0 andalso Column =< 1000000,
    #{module => list_to_binary(Name), line => Line, column => Column,
      category => bounded_symbol(Tag), kind => bounded_symbol(Kind)}.
bounded_symbol(Atom) when is_atom(Atom) ->
    Bytes = atom_to_binary(Atom), true = byte_size(Bytes) =< 128, Bytes.

observe() ->
    Cells = atomics:new(4, [{signed, false}]), Parent = self(),
    {Pid, Ref} = spawn_opt(fun() ->
        Monitor = monitor(process, Parent), sample(Cells, Monitor)
    end, [monitor, {max_heap_size, #{size => 1048576, kill => true,
        error_logger => false, include_shared_binaries => true}}]),
    {Pid, Ref, Cells}.
sample(Cells, Monitor) ->
    Processes = processes(),
    Sizes = [N || P <- Processes, {memory, N} <- [process_info(P, memory)]],
    atomics:put(Cells, 1, max(atomics:get(Cells, 1), erlang:memory(total))),
    atomics:put(Cells, 2, max(atomics:get(Cells, 2), lists:max([0 | Sizes]))),
    atomics:put(Cells, 3, max(atomics:get(Cells, 3), length(Processes))),
    atomics:add(Cells, 4, 1),
    receive stop -> ok; {'DOWN', Monitor, process, _, _} -> ok
    after 200 -> sample(Cells, Monitor) end.
stop_observer({Pid, Ref, Cells}) ->
    Pid ! stop,
    Joined = receive {'DOWN', Ref, process, Pid, normal} -> true;
                     {'DOWN', Ref, process, Pid, _} -> false
             after 2000 -> exit(Pid, kill),
                 receive {'DOWN', Ref, process, Pid, _} -> false
                 after 1000 -> false end
             end,
    #{sampled => true, interval_ms => 200, samples => atomics:get(Cells, 4),
      vm_total_peak_bytes => atomics:get(Cells, 1),
      largest_process_peak_bytes => atomics:get(Cells, 2),
      process_count_peak => atomics:get(Cells, 3), joined => Joined}.
