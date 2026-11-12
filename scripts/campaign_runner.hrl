%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("process_runner.hrl").
-include("campaign_child_evidence.hrl").

generated_execute(Mode, Shard, Shards, Seed, Cases, Scope) ->
    Path = generated_report_path(Mode, Shard, Scope),
    Identity = evidence_begin(Path),
    Initial = #{schema => 2, status => <<"Failed">>, mode => list_to_binary(Mode),
        shard => Shard, shards => Shards, seed => Seed, requested_cases => Cases,
        scope => atom_to_binary(Scope), shareable => true, evidence_identity => Identity,
        replay_command => generated_replay(Mode, Shard, Shards, Seed, Cases, Scope),
        executions => []},
    generated_write_reports(Path, Initial, Mode, Shards, Scope),
    try generated_execute_ready(Mode, Shard, Shards, Seed, Cases, Scope, Path, Identity, Initial)
    catch Class:Reason:Stack ->
        %% Keep completed siblings even when final source/build validation fails.
        Previous = generated_read(Path),
        Failed = Previous#{<<"status">> => <<"Failed">>,
            <<"failure">> => diagnostic_failure_details(Class, Reason, Stack)},
        generated_write_reports(Path, Failed, Mode, Shards, Scope),
        erlang:raise(Class, Reason, Stack)
    end.

generated_execute_ready(Mode, Shard, Shards, Seed, Cases, Scope, Path, Identity, Initial) ->
    Targets = case Mode of "model" -> ["core"]; _ -> ["http", "http3", "core"] end,
    fresh_with_verified_builds(Targets, fun(Snapshots) ->
        generated_execute_locked(Mode, Shard, Shards, Seed, Cases, Scope,
            Path, Identity, Initial, Targets, Snapshots)
    end).

generated_execute_locked(Mode, Shard, Shards, Seed, Cases, Scope, Path,
                         Identity, Initial, Targets, Snapshots) ->
    Builds = generated_snapshot_builds(Snapshots), Runtime = execution_runtime(),
    Compiled = generated_compile_runner(), Digest = generated_runner_digest(Compiled),
    Requests = generated_requests(Mode, Seed, Cases),
    Base = Initial#{build_identities => Builds, execution_environment => Runtime,
        runner_sha256 => Digest, configured_families => length(Requests)},
    Runs = lists:foldl(fun(Request, Previous) ->
        Execution = try generated_run_child(Request, Compiled, Digest, Runtime, 600000)
            catch Class:Reason:Stack -> #{request => Request, child => #{},
                failure => diagnostic_failure_details(Class, Reason, Stack)} end,
        All = Previous ++ [Execution],
        generated_write_reports(Path, Base#{executions => All}, Mode, Shards, Scope), All
    end, [], Requests),
    Completed = lists:sum([maps:get(<<"completed_cases">>, maps:get(child, E), 0) || E <- Runs]),
    Report = Base#{executions => Runs, completed_cases => Completed},
    generated_write_reports(Path, Report, Mode, Shards, Scope),
    true = lists:all(fun({Execution, Request}) -> generated_execution_valid(generated_json(Execution),
        generated_json(Request), Runtime, Digest) end, lists:zip(Runs, Requests)),
    Nonces = [maps:get(nonce, Run) || Run <- Runs],
    true = length(Nonces) =:= length(lists:usort(Nonces)),
    FinalSnapshots = [fresh_verify_locked(Target) || Target <- Targets],
    Builds = generated_snapshot_builds(FinalSnapshots),
    true = [maps:get(sha256, Snapshot) || Snapshot <- Snapshots] =:=
        [maps:get(sha256, Snapshot) || Snapshot <- FinalSnapshots],
    Status = case Scope of qualification -> <<"Ready">>; diagnostic -> <<"DiagnosticPassed">> end,
    Final = evidence_complete(Report#{status => Status}, Identity),
    generated_write_reports(Path, Final, Mode, Shards, Scope),
    io:format("~s shard ~B/~B: ~B completed cases in ~B joined child VMs~n",
        [Mode, Shard, Shards, Completed, length(Runs)]), ok.

generated_run_child(Request, Compiled, Digest, Runtime, Deadline) ->
    generated_run_child(Request, Compiled, Digest, Runtime, Deadline,
        generated_runtime_roots(Request)).

%% A family uses its own built package closure. Searching all three closures
%% both changes module precedence and repeats filesystem work during VM boot.
generated_runtime_roots(#{family := <<"http-masque">>}) -> ["build/dev/erlang"];
generated_runtime_roots(#{family := <<"http3-wire">>}) -> ["packages/http3/build/dev/erlang"];
generated_runtime_roots(#{family := Family})
    when Family =:= <<"quic-core-wire">>; Family =:= <<"quic-cubic-rfc9438-rfc9406">> ->
    ["packages/quic_core/build/dev/erlang"].

generated_run_child(Request, Compiled, Digest, Runtime, Deadline, Roots) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16)),
    Directory = filename:absname(filename:join("build/campaign/runner", binary_to_list(Nonce))),
    Path = filename:join(Directory, "child.json"),
    ok = filelib:ensure_dir(Path),
    lists:foreach(fun({Module, Bytes}) ->
        ok = file:write_file(filename:join(Directory, atom_to_list(Module) ++ ".beam"), Bytes)
    end, Compiled),
    Paths = [Directory | lists:usort([filename:absname(P) || Root <- Roots,
        P <- filelib:wildcard(filename:join(Root, "*/ebin"))])],
    Loads = [io_lib:format(
        "begin {ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),"
        "{module,~p}=code:load_binary(~p,~0tp,B) end,",
        [filename:join(Directory, atom_to_list(Module) ++ ".beam"),
         crypto:hash(sha256, Bytes), Module, Module, atom_to_list(Module) ++ ".beam"])
        || {Module, Bytes} <- Compiled],
    %% Fun scope gives every verified load fresh Erlang variable bindings.
    ScopedLoads = [["(fun()->", string:trim(lists:flatten(Load), trailing, ","), " end)(),"] || Load <- Loads],
    Eval = [ScopedLoads, io_lib:format("campaign_child:run(~0tp,~0tp,~0tp,nil).", [Request, Path, Nonce])],
    {Exit, Output} = run_child_evaluation(filename:absname("."), Paths, lists:flatten(Eval), Deadline),
    Child = generated_read_child(Path),
    Valid = generated_child_valid(Child, generated_json(Request), Nonce, Runtime),
    Safe = case Valid of true -> Child; false -> #{invalid_child_schema => true} end,
    #{request => Request, nonce => Nonce, deadline_ms => Deadline, runner_sha256 => Digest,
      exit_status => Exit, process => maps:without([tail, output_sha256], Output),
      child => Safe, child_sha256 => generated_json_digest(generated_json(Safe))}.

generated_builds(Targets) ->
    Snapshots = fresh_with_verified_builds(Targets,
        fun(Verified) -> Verified end),
    generated_snapshot_builds(Snapshots).

generated_snapshot_builds(Snapshots) ->
    maps:from_list([{list_to_binary(maps:get(target, Snapshot)),
        maps:get(report, Snapshot)} || Snapshot <- Snapshots]).
generated_json(Term) -> json:decode(iolist_to_binary(json:encode(Term))).
generated_read(Path) -> evidence_json_decode(runtime_matrix_read(Path, 1048576)).
generated_read_child(Path) ->
    %% A child stopped during checkpoint replacement can leave the complete
    %% pending document; validate that document with the same nonce and schema.
    try evidence_json_decode(runtime_matrix_read(Path, 65536))
    catch _:_ -> try evidence_json_decode(runtime_matrix_read(Path ++ ".pending", 65536))
                 catch _:_ -> #{} end end.
generated_report_path("model", _, diagnostic) -> "build/model/diagnostic-replay.json";
generated_report_path("model", Shard, qualification) ->
    filename:join("build/model", "shard-" ++ integer_to_list(Shard) ++ ".json");
generated_report_path(Mode, Shard, qualification) ->
    filename:join(["build/campaign", Mode, "shard-" ++ integer_to_list(Shard) ++ ".json"]).
generated_write_reports(Path, Report, Mode, Shards, Scope) ->
    ok = filelib:ensure_dir(Path),
    Bytes = [json:encode(Report), $\n], ok = file:write_file(Path, Bytes),
    case Shards =:= 1 andalso Mode =/= "model" andalso Scope =:= qualification of
        true -> file:write_file(filename:join("build/campaign", Mode ++ ".json"), Bytes);
        false -> ok
    end.
