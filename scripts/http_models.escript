#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("http_model_evidence.hrl").

main(Arguments) ->
    ok = file:set_cwd(filename:dirname(filename:dirname(filename:absname(escript:script_name())))),
    try run(Arguments) of ok -> ok
    catch Class:Reason:Stack ->
        io:format(standard_error, "HTTP models failed: ~s~n",
                  [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

run(["--self-test"]) -> self_test();
run([]) -> campaign(982451653, 1000);
run(["--seed", Seed, "--cases", Cases]) ->
    campaign(integer(Seed, 0, 2147483646), integer(Cases, 1, 10000));
run(["replay", Domain, Seed, Steps]) ->
    Name = list_to_binary(Domain),
    ensure(lists:member(Name, domains()), invalid_model_domain),
    execute(replay, [Name], integer(Seed, 0, 2147483646), integer(Steps, 1, 32));
run(_) -> erlang:error(invalid_http_model_arguments).

campaign(Seed, Cases) -> execute(campaign, domains(), Seed, Cases).
domains() -> [<<"http1">>, <<"http2">>, <<"hpack">>, <<"pool">>, <<"cancellation">>, <<"drain">>].

execute(Mode, Domains, Seed, Count) ->
    Path = report_path(Mode),
    Identity = evidence_begin(Path),
    ok = filelib:ensure_dir(Path),
    try execute_run(Mode, Domains, Seed, Count, Path, Identity)
    catch Class:Reason:Stack ->
        case filelib:is_regular(Path) of
            true ->
                Previous = evidence_json_decode(fresh_read(Path)),
                Failed = Previous#{<<"status">> => <<"Failed">>,
                    <<"failure">> => diagnostic_failure_details(Class, Reason, Stack)},
                ok = file:write_file(Path, [json:encode(Failed), $\n]);
            false ->
                Failure = #{schema => 1, family => <<"http-state-models">>, status => <<"Failed">>,
                            mode => atom_to_binary(Mode), seed => Seed,
                            requested_cases_or_steps => Count, shareable => true,
                            evidence_identity => Identity,
                            failure => diagnostic_failure_details(Class, Reason, Stack)},
                ok = file:write_file(Path, [json:encode(Failure), $\n])
        end,
        erlang:raise(Class, Reason, Stack)
    end.

execute_run(Mode, Domains, Seed, Count, Path, Identity) ->
    fresh_with_verified_build("http", fun(Snapshot) ->
        execute_run_verified(Mode, Domains, Seed, Count, Path, Identity,
                             Snapshot)
    end).

execute_run_verified(Mode, Domains, Seed, Count, Path, Identity, Snapshot) ->
    ChildPath = filename:absname("build/http-model/child.json"),
    remove_report(ChildPath),
    BuildIdentity = maps:get(report, Snapshot),
    Runner = compile_runner(),
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Paths = [Runner | [filename:absname(P) || P <- filelib:wildcard("build/dev/erlang/*/ebin")]],
    Evaluation = case Mode of
        campaign -> io_lib:format("http_model_child:run(~0tp,~B,~B,~0tp,~0tp).",
                                  [Domains, Seed, Count, ChildPath, Nonce]);
        replay -> io_lib:format("http_model_child:replay(~0tp,~B,~B,~0tp,~0tp,nil).",
                                [hd(Domains), Seed, Count, ChildPath, Nonce])
    end,
    {Status, Output} = run_child_evaluation(filename:absname("."), Paths,
                                           lists:flatten(Evaluation), 600000),
    Child = read_child(ChildPath),
    Valid = http_model_valid_child(Child, Mode, Domains, Seed, Count, Nonce),
    Complete = process_status_verified(Status, 0, Output) andalso Valid andalso
               maps:get(<<"status">>, Child, <<>>) =:= <<"Passed">> andalso
               process_vm_output_empty(Output),
    EvidenceStatus = case {Complete, Mode} of
        {true, campaign} -> <<"Ready">>;
        {true, replay} -> <<"DiagnosticPassed">>;
        _ -> <<"Failed">>
    end,
    SafeChild = case Valid of true -> Child; false -> #{invalid_child_schema => true} end,
    Report = #{schema => 1, family => <<"http-state-models">>, status => EvidenceStatus,
               mode => atom_to_binary(Mode), seed => Seed, requested_cases_or_steps => Count,
               execution_environment => execution_runtime(), shareable => true,
               build_identity => BuildIdentity,
               runner_sha256 => hex(crypto:hash(sha256, fresh_read(
                   filename:join(Runner, "http_model_child.beam")))),
               replay_command => replay_command(Mode, Domains, Seed, Count),
               model => SafeChild, runner_exit => Status,
               runner_output => safe_runner_output(Output)},
    %% A source-stable BEAM replacement during the child run also invalidates
    %% evidence; checking source identity alone cannot detect that mismatch.
    ok = file:write_file(Path, [json:encode(Report#{status => <<"Failed">>, evidence_identity => Identity}), $\n]),
    FinalSnapshot = fresh_verify_locked("http"),
    BuildIdentity = maps:get(report, FinalSnapshot),
    true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
    ok = file:write_file(Path, [json:encode(evidence_complete(Report, Identity)), $\n]),
    io:format("HTTP models ~s: ~B domains, seed ~B, count ~B~n",
              [EvidenceStatus, length(Domains), Seed, Count]),
    ensure(Complete, http_model_campaign_failed).

report_path(campaign) -> "build/http-model/result.json";
report_path(replay) -> "build/http-model/replay.json".

replay_command(campaign, _Domains, Seed, Count) ->
    iolist_to_binary(io_lib:format("escript scripts/http_models.escript --seed ~B --cases ~B", [Seed, Count]));
replay_command(replay, [Domain], Seed, Count) ->
    iolist_to_binary(io_lib:format("escript scripts/http_models.escript replay ~s ~B ~B", [Domain, Seed, Count])).

safe_runner_output(Output) -> maps:without([tail, output_sha256], Output).

compile_runner() ->
    Directory = filename:absname("build/http-model/runner"),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    case compile:file("scripts/http_model_child.erl", [binary, return_errors, return_warnings]) of
        {ok, Module, Binary, []} ->
            ok = file:write_file(filename:join(Directory, atom_to_list(Module) ++ ".beam"), Binary), Directory;
        _ -> erlang:error(http_model_child_compile_failed)
    end.
read_child(Path) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, File} ->
            Read = file:read(File, 65537),
            ok = file:close(File),
            case Read of
                {ok, Bytes} when byte_size(Bytes) =< 65536 ->
                    try evidence_json_decode(Bytes) catch _:_ -> #{} end;
                _ -> #{}
            end;
        _ -> #{}
    end.
remove_report(Path) ->
    case file:delete(Path) of ok -> ok; {error, enoent} -> ok; _ -> erlang:error(stale_model_report_not_removed) end.
integer(Text, Minimum, Maximum) ->
    Number = list_to_integer(Text),
    ensure(http_model_bounded(Number, Minimum, Maximum), invalid_model_number), Number.
ensure(true, _) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
hex(Binary) -> iolist_to_binary([io_lib:format("~2.16.0b", [Byte]) || <<Byte>> <= Binary]).

self_test() ->
    _ = compile_runner(),
    ensure(output_tail(new_output()) =:= <<>>, initial_child_output_empty),
    PrivateOutput = #{tail => <<"private-marker">>, output_sha256 => <<"guessable-marker-digest">>, output_bytes => 14},
    ensure(safe_runner_output(PrivateOutput) =:= #{output_bytes => 14}, private_output_and_digest_removed),
    Nonce = <<"current-run">>,
    Row = #{<<"domain">> => <<"http1">>, <<"seed">> => 7, <<"cases">> => 1,
            <<"transitions">> => 8, <<"sha256">> => binary:copy(<<"a">>, 64), <<"status">> => <<"Passed">>},
    Child = #{<<"schema">> => 1, <<"nonce">> => Nonce, <<"mode">> => <<"campaign">>,
              <<"status">> => <<"Passed">>, <<"domains">> => [Row]},
    Good = fun(Value) -> http_model_valid_child(Value, campaign, [<<"http1">>], 7, 1, Nonce) end,
    ensure(Good(Child), valid_model_fixture),
    Hostile = [Child#{<<"payload">> => <<"private-marker">>}, Child#{<<"nonce">> => <<"stale">>},
               Child#{<<"domains">> => []}, Child#{<<"domains">> => [Row, Row]},
               Child#{<<"domains">> => [Row#{<<"cases">> => 0}]},
               Child#{<<"domains">> => [Row#{<<"transitions">> => 0}]},
               Child#{<<"domains">> => [Row#{<<"sha256">> => <<"bad">>}]},
               Child#{<<"domains">> => [Row#{<<"extra">> => <<"private-marker">>}]}],
    ensure(lists:all(fun(Value) -> not Good(Value) end, Hostile), hostile_model_schema_rejected),
    io:format("HTTP model harness self-test: strict schema, nonce, nonzero cases, counts and digest verified~n").
