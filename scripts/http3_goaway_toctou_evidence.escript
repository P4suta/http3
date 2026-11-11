#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("command_capture.hrl").

main(["green"]) ->
    try run("green", "none") of
        ok -> ok
    catch
        Class:Reason:_Stack ->
            io:format(standard_error,
                "http3_goaway_toctou_evidence status=failed class=~p reason=~p~n",
                [Class, safe_reason(Reason)]),
            halt(1)
    end;
main(["red", Mutation])
  when Mutation =:= "routing-disabled"; Mutation =:= "alt-used-leak" ->
    try run("red", Mutation) of
        ok -> ok
    catch
        Class:Reason:_Stack ->
            io:format(standard_error,
                "http3_goaway_toctou_evidence status=failed class=~p reason=~p~n",
                [Class, safe_reason(Reason)]),
            halt(1)
    end;
main(_) -> halt(2).

run(Expectation, Mutation) ->
    Root = filename:absname("."),
    Gleam = required_executable("HTTP_GLEAM_EXECUTABLE"),
    Rebar = required_executable("HTTP_REBAR_EXECUTABLE"),
    Supervisor = required_executable("HTTP_PROCESS_SUPERVISOR_PYTHON"),
    Paths = ["src/http/client.gleam",
             "src/http/internal/http3/client.gleam",
             "src/http/server.gleam",
             "src/http_client_ffi.erl",
             "packages/http3/src/http3/client.gleam",
             "packages/http3/src/http3/server.gleam",
             "test/http3_goaway_toctou_test.gleam",
             "scripts/http3_goaway_toctou_evidence.escript",
             "gleam.toml", "manifest.toml",
             "packages/http3/gleam.toml",
             "packages/quic_core/gleam.toml"],
    SourceSha = source_sha256(Root, Paths),
    GleamSha = file_sha256(Gleam),
    RebarSha = file_sha256(Rebar),
    SupervisorSha = file_sha256(Supervisor),
    Environment = otp_environment(),
    Result = command_capture(
        Gleam, ["run", "-m", "http3_goaway_toctou_test"], Root,
        120000, 1048576, Environment),
    {Outcome, Proof} = capture_outcome(Result),
    true = source_sha256(Root, Paths) =:= SourceSha,
    Expected = case Expectation of
        "red" -> failed;
        "green" -> ready
    end,
    true = Outcome =:= Expected,
    true = proof_complete(Proof),
    Evidence = #{
        schema => 1,
        generated_unix_seconds => erlang:system_time(second),
        status => case Outcome of ready -> <<"Ready">>;
                                  failed -> <<"ExpectedRed">> end,
        expectation => list_to_binary(Expectation),
        source_sha256 => SourceSha,
        source_stable_during_run => true,
        source_files => length(Paths),
        source_paths => [unicode:characters_to_binary(Path) || Path <- Paths],
        test_module => <<"http3_goaway_toctou_test">>,
        test_functions => [
            <<"pooled_http3_goaway_refusal_reroutes_one_nonreplayable_body_test">>,
            <<"pooled_http3_goaway_reroute_to_tcp_omits_alt_used_test">>
        ],
        scenarios => [
            <<"pooled_h3_refusal_reroutes_to_current_h3_alt_svc">>,
            <<"pooled_h3_refusal_reroutes_to_h2_tls_origin">>
        ],
        planned_tests => 2,
        completed_tests => completed_tests(Outcome, Mutation),
        failed_tests => case Outcome of ready -> 0; failed -> 1 end,
        not_run_tests => not_run_tests(Outcome, Mutation),
        expected_mutation => list_to_binary(Mutation),
        failure_classification =>
            case Outcome of ready -> <<"none">>;
                            failed -> <<"expected_regression_detected">> end,
        deadline_milliseconds => 120000,
        output_limit_bytes => 1048576,
        peers => [
            #{implementation => <<"in_tree_http3_server">>,
              version => <<"0.1.0">>,
              role => <<"origin_and_alt_svc_alternate">>, instances => 2},
            #{implementation => <<"in_tree_http2_tls_server">>,
              version => <<"0.1.0">>,
              role => <<"origin_tcp_fallback">>, instances => 1}
        ],
        fixture => #{pool_connections => 1, retries => 0,
                     probe_sequences => [[false, true, false], [false, true]],
                     request_body => <<"nonreplayable_single_pull">>},
        wire_assertions => [
            <<"replacement_h3_alt_used_matches_current_endpoint">>,
            <<"replacement_h2_tls_origin_omits_alt_used">>
        ],
        otp_release => list_to_binary(erlang:system_info(otp_release)),
        gleam_version => <<"1.18.1">>,
        gleam_sha256 => GleamSha,
        rebar_version => <<"3.27.0">>,
        rebar_sha256 => RebarSha,
        process_supervisor_sha256 => SupervisorSha,
        child_exit_status => maps:get(exit_status, Proof),
        process => safe_proof(Proof),
        rerun_command => iolist_to_binary([
            "escript scripts/http3_goaway_toctou_evidence.escript ",
            Expectation, case Mutation of "none" -> ""; _ -> " " ++ Mutation end
        ])
    },
    true = evidence_complete(Evidence),
    false = evidence_complete(maps:remove(test_functions, Evidence)),
    false = evidence_complete(Evidence#{completed_tests => -1}),
    false = evidence_complete(Evidence#{wire_assertions => []}),
    false = evidence_complete(Evidence#{source_stable_during_run => false}),
    Path = evidence_path(Root, Expectation, Mutation),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Evidence), $\n]),
    io:format(
        "http3_goaway_toctou_evidence status=~s expectation=~s mutation=~s "
        "source_sha256=~s otp=~s child_exit=~p tree_empty=true "
        "console_isolated=true report=~s~n",
        [maps:get(status, Evidence), Expectation, Mutation, SourceSha,
         erlang:system_info(otp_release), maps:get(exit_status, Proof), Path]),
    ok.

completed_tests(ready, "none") -> 2;
completed_tests(failed, "routing-disabled") -> 0;
completed_tests(failed, "alt-used-leak") -> 1.

not_run_tests(ready, "none") -> 0;
not_run_tests(failed, "routing-disabled") -> 1;
not_run_tests(failed, "alt-used-leak") -> 0.

evidence_complete(Evidence) ->
    case {maps:find(test_functions, Evidence),
          maps:find(scenarios, Evidence),
          maps:find(wire_assertions, Evidence),
          maps:find(peers, Evidence),
          maps:find(planned_tests, Evidence),
          maps:find(completed_tests, Evidence),
          maps:find(failed_tests, Evidence),
          maps:find(not_run_tests, Evidence)} of
        {{ok, Tests}, {ok, Scenarios}, {ok, Wire}, {ok, Peers},
         {ok, Planned}, {ok, Completed}, {ok, Failed}, {ok, NotRun}} ->
            Planned =:= 2 andalso length(Tests) =:= Planned andalso
            length(Scenarios) =:= Planned andalso length(Wire) =:= Planned andalso
            length(Peers) =:= 2 andalso
            Completed + Failed + NotRun =:= Planned andalso
            maps:get(source_stable_during_run, Evidence, false) =:= true;
        _ -> false
    end.

capture_outcome({ok, _Output, Proof}) -> {ready, Proof};
capture_outcome({error, Proof}) when is_map(Proof) -> {failed, Proof};
capture_outcome({error, _Projection, Proof}) -> {failed, Proof}.

proof_complete(Proof) ->
    maps:get(child_exit_observed, Proof, false) =:= true andalso
    maps:get(native_tree_empty, Proof, false) =:= true andalso
    maps:get(native_console_isolated, Proof, false) =:= true andalso
    maps:get(process_supervisor_protocol_valid, Proof, false) =:= true andalso
    maps:get(native_descendant_outlived, Proof, true) =:= false.

safe_proof(Proof) ->
    maps:with([outcome, exit_status, child_exit_observed,
               process_supervisor_protocol_valid,
               process_supervisor_failure_code,
               process_supervisor_attestation_failure,
               native_tree_empty, native_console_isolated,
               native_descendant_outlived,
               native_termination_requested,
               elapsed_milliseconds, output_bytes], Proof).

required_executable(Name) ->
    case os:getenv(Name) of
        Path when is_list(Path), Path =/= [] ->
            Absolute = filename:absname(Path),
            true = filelib:is_regular(Absolute),
            Absolute;
        _ -> erlang:error(missing_pinned_executable)
    end.

otp_environment() ->
    Separator = case os:type() of {win32, _} -> ";"; _ -> ":" end,
    OtpBin = filename:join(code:root_dir(), "bin"),
    Existing = case os:getenv("PATH") of false -> ""; Value -> Value end,
    [{"PATH", OtpBin ++ Separator ++ Existing},
     {"ERL_AFLAGS", false}, {"ERL_FLAGS", false}, {"ERL_ZFLAGS", false}].

source_sha256(Root, Paths) ->
    Context = lists:foldl(fun(Path, Acc) ->
        {ok, Bytes} = file:read_file(filename:join(Root, Path)),
        crypto:hash_update(Acc, [unicode:characters_to_binary(Path), 0,
                                 Bytes, 0])
    end, crypto:hash_init(sha256), Paths),
    binary:encode_hex(crypto:hash_final(Context), lowercase).

file_sha256(Path) ->
    {ok, Bytes} = file:read_file(Path),
    true = byte_size(Bytes) =< 134217728,
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

evidence_path(Root, Expectation, Mutation) ->
    Suffix = case Mutation of "none" -> ""; _ -> "-" ++ Mutation end,
    filename:join([Root, "build", "evidence",
        "http3-goaway-toctou-" ++ Expectation ++ Suffix ++ "-otp" ++
        erlang:system_info(otp_release) ++ ".json"]).

safe_reason(badmatch) -> badmatch;
safe_reason(missing_pinned_executable) -> missing_pinned_executable;
safe_reason(_) -> evidence_contract_failed.
