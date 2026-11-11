%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qualification_eunit_listener).
-behaviour(eunit_listener).
-export([run/3, run_attested/6, run_invocation/7, run_same_vm/3,
         run_descriptors/4, run_same_vm_descriptors/4,
         run_units/4, run_units_attested/7, run_same_vm_units/4,
         start/1, init/1, handle_begin/3, handle_end/3, handle_cancel/3, terminate/2]).
-include("diagnostic_failure.hrl").
-include("suite_evidence.hrl").
-include("json_evidence.hrl").
-include("execution_beam_identity.hrl").

run(Units, Path, Nonce) ->
    Result = run_same_vm(Units, Path, Nonce),
    erlang:halt(case Result of ok -> 0; error -> 1 end).

run_attested(Units, Path, Nonce, RunnerSha, BuildRoot, ExpectedInventory) ->
    Tests = [descriptor(Unit) || Unit <- Units],
    Result = run_local_attested(Units, Tests, Path, Nonce, 10,
        RunnerSha, BuildRoot, ExpectedInventory),
    erlang:halt(case Result of ok -> 0; error -> 1 end).

%% This is the only entry point used by an attested child evaluation.  It
%% validates a data-only canonical ETF envelope and all parent-provided
%% identity bindings before selecting one of the two fixed runner operations.
%% No atom or function name from the wire is passed to apply/3.
run_invocation(InvocationBytes, ExpectedInvocationSha, ExpectedInvocationNonce,
               ExpectedLeaseNonce, ExpectedSourceSha, ExpectedRunnerSha,
               ExpectedInventorySha) ->
    true = execution_beam_digest(ExpectedInvocationSha, 64),
    true = execution_beam_digest(ExpectedInvocationNonce, 32),
    true = execution_beam_digest(ExpectedLeaseNonce, 32),
    true = execution_beam_digest(ExpectedSourceSha, 64),
    true = execution_beam_digest(ExpectedRunnerSha, 64),
    true = execution_beam_digest(ExpectedInventorySha, 64),
    ExpectedInvocationSha = binary:encode_hex(
        crypto:hash(sha256, InvocationBytes), lowercase),
    {ok, Invocation} = canonical_etf_decode(
        InvocationBytes, 16777216, 64, 2000000),
    {execution_beam_invocation_v2,
     ExpectedInvocationNonce, ExpectedLeaseNonce, ExpectedSourceSha,
     ExpectedRunnerSha, ExpectedInventorySha, Dispatch} = Invocation,
    case Dispatch of
        {run_attested, Units, Path, RunNonce, BuildRoot, Inventory} ->
            ExpectedInventorySha = maps:get(sha256, Inventory),
            run_attested(Units, Path, RunNonce, ExpectedRunnerSha,
                         BuildRoot, Inventory);
        {run_units_attested, Units, Path, RunNonce, Seconds, BuildRoot,
         Inventory} ->
            ExpectedInventorySha = maps:get(sha256, Inventory),
            run_units_attested(Units, Path, RunNonce, Seconds,
                               ExpectedRunnerSha, BuildRoot, Inventory)
    end.

%% Keep cover's instrumented modules and counters in the caller's VM. EUnit
%% joins its listeners before returning; report publication alone is not exit.
run_same_vm(Units, Path, Nonce) ->
    Tests = [descriptor(Unit) || Unit <- Units],
    run_local(Units, Tests, Path, Nonce, 10).

%% The same finite ceiling covers each unit and its ordinary/generator leaves.
%% A group timeout alone does not replace EUnit's independent 5 s leaf default.
run_units(Units, Path, Nonce, Seconds) ->
    Result = run_same_vm_units(Units, Path, Nonce, Seconds),
    erlang:halt(case Result of ok -> 0; error -> 1 end).

run_units_attested(Units, Path, Nonce, Seconds, RunnerSha, BuildRoot,
                   ExpectedInventory)
  when is_integer(Seconds), Seconds >= 5, Seconds =< 3600,
       Seconds rem 5 =:= 0 ->
    Tests = [{timeout, 5, descriptor(Unit)} || Unit <- Units],
    Result = run_local_attested(Units, Tests, Path, Nonce, Seconds div 5,
        RunnerSha, BuildRoot, ExpectedInventory),
    erlang:halt(case Result of ok -> 0; error -> 1 end).

run_same_vm_units(Units, Path, Nonce, Seconds)
  when is_integer(Seconds), Seconds >= 5, Seconds =< 3600,
       Seconds rem 5 =:= 0 ->
    Tests = [{timeout, 5, descriptor(Unit)} || Unit <- Units],
    run_local(Units, Tests, Path, Nonce, Seconds div 5).

%% Explicit descriptors retain literal caller-supplied timeout values.
run_descriptors(Units, Descriptors, Path, Nonce) ->
    Result = run_same_vm_descriptors(Units, Descriptors, Path, Nonce),
    erlang:halt(case Result of ok -> 0; error -> 1 end).

run_same_vm_descriptors(Units, Descriptors, Path, Nonce) ->
    run_local(Units, Descriptors, Path, Nonce, 1).

run_local(Units, Descriptors, Path, Nonce, Scale) ->
    run_local_mode(Units, Descriptors, Path, Nonce, Scale, unattested).

run_local_attested(Units, Descriptors, Path, Nonce, Scale,
                   RunnerSha, BuildRoot, ExpectedInventory) ->
    true = execution_beam_digest(RunnerSha, 64),
    ExpectedDigest = execution_beam_inventory_digest(
        maps:get(entries, ExpectedInventory)),
    ExpectedDigest = maps:get(sha256, ExpectedInventory),
    run_local_mode(Units, Descriptors, Path, Nonce, Scale,
        #{runner_sha256 => RunnerSha, build_root => BuildRoot,
          inventory => ExpectedInventory,
          inventory_sha256 => ExpectedDigest}).

run_local_mode(Units, Descriptors, Path, Nonce, Scale, BeamIdentity) ->
    Written = make_ref(),
    Result = eunit:test(Descriptors, [no_tty, {scale_timeouts, Scale},
        {report, {?MODULE, [{units, Units}, {path, Path}, {nonce, Nonce},
                           {execution_beam_identity, BeamIdentity},
                           {report_owner, self()}, {report_reference, Written}]}}]),
    Published = receive {Written, Outcome} -> Outcome after 1000 -> error end,
    case Result =:= ok andalso Published =:= ok andalso
         valid_completion(Units, Path, Nonce, BeamIdentity) of
        true -> ok;
        false -> error
    end.

valid_completion(Units, Path, Nonce, unattested) ->
    try
        true = Units =/= [] andalso length(Units) =< 10000,
        Report = bounded_report(Path),
        suite_child_valid(Report, Units, Nonce) andalso suite_completed_tests(Report) > 0
    catch _:_ -> false end;
valid_completion(Units, Path, Nonce,
                 #{runner_sha256 := RunnerSha,
                   inventory_sha256 := InventorySha}) ->
    try
        true = Units =/= [] andalso length(Units) =< 10000,
        Report = bounded_report(Path),
        suite_attested_child_valid(Report, Units, Nonce,
            RunnerSha, InventorySha) andalso suite_completed_tests(Report) > 0
    catch _:_ -> false end.

bounded_report(Path) ->
    evidence_json_decode(execution_beam_read(Path, 8388608)).

descriptor(#{module := Module, function := Function, kind := Kind}) ->
    Tag = case Kind of <<"test">> -> test; <<"generator">> -> generator end,
    %% A described group prevents EUnit from flattening a generator's leaves
    %% into the sibling unit list. Its first id component remains the ordinal.
    {<<"qualification unit">>,
     {inorder, [{Tag, binary_to_existing_atom(Module, utf8),
                      binary_to_existing_atom(Function, utf8)}]}}.

start(Options) -> eunit_listener:start(?MODULE, Options).

init(Options) ->
    #{path => proplists:get_value(path, Options),
      nonce => proplists:get_value(nonce, Options),
      expected => proplists:get_value(units, Options),
      execution_beam_identity => proplists:get_value(
          execution_beam_identity, Options, unattested),
      report_owner => proplists:get_value(report_owner, Options),
      report_reference => proplists:get_value(report_reference, Options),
      rows => #{}, failures => [], failure_count => 0,
      unexpected_events => 0}.

handle_begin(test, Data, State) -> count(started, Data, State);
handle_begin(group, _Data, State) -> State.

handle_end(test, Data, State0) ->
    State1 = count(completed, Data, State0),
    case proplists:get_value(status, Data) of
        ok -> count(passed, Data, State1);
        {skipped, _} -> fail(skipped, <<"skipped">>, [], Data, State1);
        {error, {Class, Reason, Stack}} ->
            Details = diagnostic_failure_details(Class, Reason, Stack),
            fail(failed, maps:get(exception_reason, Details),
                 json:decode(maps:get(stacktrace, Details)), Data, State1);
        _ -> fail(failed, <<"invalid_test_status">>, [], Data, State1)
    end;
handle_end(group, _Data, State) -> State.

handle_cancel(_Kind, Data, State) ->
    %% Cancellation reasons may contain raw exceptions, messages, or sockets.
    {Classification, Stack} = cancellation(proplists:get_value(reason, Data)),
    fail(cancelled, Classification, Stack, Data, State).

cancellation(timeout) -> {<<"deadline_exceeded">>, []};
cancellation({timeout, #{stacktrace := Stack}}) ->
    {<<"deadline_exceeded">>, diagnostic_stack(Stack)};
cancellation({exit, killed}) -> {<<"worker_killed">>, []};
cancellation({exit, _}) -> {<<"worker_exit">>, []};
cancellation({blame, _}) -> {<<"dependency_cancelled">>, []};
cancellation({abort, _}) -> {<<"execution_aborted">>, []};
cancellation({startup, _}) -> {<<"startup_failed">>, []};
cancellation(_) -> {<<"cancelled">>, []}.

count(Key, Data, #{rows := Rows, expected := Units} = State) ->
    case unit_id(Data, length(Units)) of
        invalid -> unexpected(State);
        Id ->
            Row = maps:get(Id, Rows, empty_row()),
            State#{rows => Rows#{Id => Row#{Key => maps:get(Key, Row) + 1}}}
    end.

empty_row() -> #{started => 0, completed => 0, passed => 0,
                 failed => 0, skipped => 0, cancelled => 0}.

unit_id(Data, Count) ->
    case proplists:get_value(id, Data) of
        [Id | _] when is_integer(Id), Id > 0, Id =< Count -> Id;
        _ -> invalid
    end.

unexpected(#{unexpected_events := Count} = State) ->
    State#{unexpected_events => erlang:min(2147483647, Count + 1)}.

fail(Key, Classification, Stack, Data,
     #{failures := Failures, failure_count := Count, expected := Units} = State) ->
    Id = unit_id(Data, length(Units)),
    Failure = #{unit => case Id of invalid -> 0; _ -> Id end,
                classification => Classification, stack => Stack},
    Bounded = case Count < 64 of
        true -> [Failure | Failures];
        false -> Failures
    end,
    count(Key, Data, State#{failures => Bounded,
                            failure_count => erlang:min(2147483647, Count + 1)}).

terminate(Result, #{path := Path, nonce := Nonce, expected := Units, rows := Rows,
                    report_owner := Owner, report_reference := Reference,
                    execution_beam_identity := BeamIdentity,
                    failures := Failures, failure_count := FailureCount,
                    unexpected_events := Unexpected}) ->
    Indexed = lists:zip(lists:seq(1, length(Units)), Units),
    Report0 = #{run_nonce => Nonce, listener_completed => true,
               eunit_completed => case Result of {ok, _} -> true; _ -> false end,
               unexpected_events => Unexpected,
               units => [Unit#{ordinal => Id, counts => maps:get(Id, Rows, empty_row())}
                         || {Id, Unit} <- Indexed],
               failure_count => FailureCount,
               failures => lists:reverse(Failures),
               failures_dropped => erlang:max(0, FailureCount - 64)},
    Report = case BeamIdentity of
        unattested -> Report0#{schema => 1};
        #{runner_sha256 := RunnerSha, build_root := BuildRoot,
          inventory := ExpectedInventory} ->
            RequiredModules = lists:usort([
                maps:get(module, Unit) || Unit <- Units]),
            Attestation0 = execution_beam_loaded_attestation(
                ExpectedInventory, BuildRoot, RequiredModules),
            RunnerVerified = execution_beam_runner_loaded(RunnerSha),
            BeamsVerified = maps:get(loaded_beams_verified, Attestation0),
            Report0#{schema => 2, execution_beam_identity =>
                Attestation0#{runner_sha256 => RunnerSha,
                              loaded_beams_verified =>
                                  RunnerVerified andalso BeamsVerified}}
    end,
    ReportBytes = iolist_to_binary([json:encode(Report), $\n]),
    Written = try execution_beam_publish_new(Path, ReportBytes, 8388608) of
        ok -> ok
    catch _:_ -> error end,
    case is_pid(Owner) andalso is_reference(Reference) of
        true -> Owner ! {Reference, Written}, ok;
        false -> ok
    end.
