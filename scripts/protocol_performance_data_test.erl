%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(protocol_performance_data_test).
-export([contracts/0]).
-compile(nowarn_unused_function).
-include_lib("eunit/include/eunit.hrl").
-include("protocol_performance_data.hrl").

contracts() -> [fun public_sample_retains_all_latencies_and_unknown_connection_count/0,
    fun private_nested_failure_is_projected_before_publication/0,
    fun primary_and_cleanup_stages_survive_projection/0,
    fun sample_rejects_extra_connections_and_impossible_elapsed_sums/0,
    fun child_rejects_unknown_fields_and_preserves_exact_nonce/0,
    fun child_rejects_incomplete_counts_and_impossible_work_windows/0,
    fun summary_uses_all_measured_latencies_and_median_trial_rate/0,
    fun failure_projection_has_finite_depth_and_strict_keys/0,
    fun retry_evidence_is_projected_only_from_fixed_atoms/0,
    fun six_trials_execute_sequentially_in_one_owned_vm/0,
    fun skipped_global_deadline_rows_are_not_completed_trials/0,
    fun native_callback_secrets_never_enter_child_rows/0,
    fun a_failed_but_converged_trial_does_not_skip_later_trials/0,
    fun native_dns_services_are_primed_before_the_observed_work/0].

public_sample_retains_all_latencies_and_unknown_connection_count() ->
    Input = {sample,3,100,1024,100,0,none,1000000,
        lists:duplicate(100,{latency,100,200})},
    Actual = pp_sample(Input),
    ?assertMatch({ok,_},Actual),
    {ok,Safe}=Actual,
    ?assertEqual(null,maps:get(accepted_connections,Safe)),
    ?assertEqual(100,length(maps:get(latencies,Safe))).

private_nested_failure_is_projected_before_publication() ->
    Secret = <<"private-protocol-child-marker">>,
    Actual=pp_failure({operation,7,{error_value,{body,{too_large,Secret}}}}),
    ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(Actual)),Secret)),
    ?assertEqual(<<"invalid_result">>,maps:get(kind,Actual)).

primary_and_cleanup_stages_survive_projection() ->
    Actual=pp_failure({cleanup_failed,{some,{operation,6,{error_value,{timeout,total}}}},
        {operation,13,{error_value,cancelled}}}),
    ?assertEqual(<<"cleanup">>,maps:get(kind,Actual)),
    ?assertEqual(6,maps:get(stage,maps:get(primary,Actual))),
    ?assertEqual(<<"timeout_total">>,maps:get(error,maps:get(primary,Actual))),
    ?assertEqual(13,maps:get(stage,maps:get(cleanup,Actual))).

sample_rejects_extra_connections_and_impossible_elapsed_sums()->
    {ok,Sample}=pp_sample(native_sample(1)),
    ?assertNot(pp_sample_valid(Sample#{accepted_connections:=2},1)),
    ?assertNot(pp_sample_valid(Sample#{elapsed_microseconds:=999},1)),
    ?assertNot(pp_sample_valid(Sample#{latencies:=lists:duplicate(101,#{headers_microseconds=>1,complete_microseconds=>2})},1)),
    ?assertNot(pp_sample_valid(Sample#{private=><<"secret">>},1)).

child_rejects_unknown_fields_and_preserves_exact_nonce()->
    Child=fixture_child(1),Nonce=maps:get(nonce,Child),
    ?assert(pp_child_valid(Child,1,Nonce)),
    ?assert(pp_child_valid(json:decode(iolist_to_binary(json:encode(Child))),1,Nonce)),
    ?assertNot(pp_child_valid(Child#{private=><<"secret">>},1,Nonce)),
    ?assertNot(pp_child_valid(Child,1,<<"abcdef0123456789abcdef0123456789">>)),
    ?assertNot(pp_child_valid(Child,2,Nonce)).

child_rejects_incomplete_counts_and_impossible_work_windows()->
    Child=fixture_child(1),Nonce=maps:get(nonce,Child),
    ?assertNot(pp_child_valid(Child#{completed_trials:=5},1,Nonce)),
    ?assertNot(pp_child_valid(Child#{elapsed_ms:=1},1,Nonce)),
    [First|Rest]=maps:get(rows,Child),Sample=maps:get(sample,First),
    Long=Sample#{elapsed_microseconds:=60000000},
    ?assertNot(pp_child_valid(Child#{rows:=[First#{sample:=Long}|Rest]},1,Nonce)),
    Observation=maps:get(observation,First),
    Overlong=First#{observation:=Observation#{work_elapsed_us:=61000000,work_elapsed_ms:=61000}},
    ?assertNot(pp_child_valid(Child#{rows:=[Overlong|Rest],elapsed_ms:=70000},1,Nonce)),
    ?assertNot(pp_child_valid(Child#{rows:=[First#{observation:=Observation#{sampler_mode:=<<"injected">>}}|Rest]},1,Nonce)).

summary_uses_all_measured_latencies_and_median_trial_rate()->
    Child=fixture_child(1),[Warmup|Measured]=maps:get(rows,Child),
    Rates=[1000,2000,4000,5000,10000],
    Rows=[begin
        S=maps:get(sample,Row),
        L=[#{headers_microseconds=>I,complete_microseconds=>I}||I<-lists:seq(1,100)],
        Row#{sample:=S#{elapsed_microseconds:=Elapsed,latencies:=L}}
    end||{Row,Elapsed}<-lists:zip(Measured,Rates)],
    %% Each trial needs at least the sequential latency sum5050; choose larger
    %% elapsed intervals with distinct rates, and sufficiently long Work scopes.
    Corrected=[Row#{sample:=(maps:get(sample,Row))#{elapsed_microseconds:=E*10}}
        ||{Row,E}<-lists:zip(Rows,Rates)],
    Expanded=Child#{rows:=[Warmup|Corrected]},
    Safe=expand_work_windows(Expanded,1000000),
    ?assert(pp_child_passed(Safe)),
    [Summary,Missing2,Missing3]=pp_summary([Safe]),
    ?assertEqual(500,maps:get(requests,Summary)),
    ?assertEqual(50,maps:get(headers_p50_microseconds,Summary)),
    ?assertEqual(95,maps:get(complete_p95_microseconds,Summary)),
    ?assertEqual(99,maps:get(complete_p99_microseconds,Summary)),
    ?assertEqual(2500.0,maps:get(median_trial_requests_per_second,Summary)),
    ?assertEqual(500000000/220000,maps:get(requests_per_second,Summary)),
    ?assertEqual(<<"Failed">>,maps:get(status,Missing2)),
    ?assertEqual(<<"Failed">>,maps:get(status,Missing3)).

failure_projection_has_finite_depth_and_strict_keys()->
    Deep=lists:foldl(fun(_,Acc)->{cleanup_failed,{some,Acc},Acc} end,
        {operation,8,{error_value,{body,{too_large,42}}}},lists:seq(1,12)),
    Safe=pp_failure(Deep),?assert(pp_failure_valid(Safe)),
    ?assert(byte_size(iolist_to_binary(json:encode(Safe)))<10000),
    ?assertNot(pp_failure_valid(Safe#{secret=><<"private">>})),
    ?assertNot(pp_failure_valid((pp_failure_leaf(<<"operation">>))#{error:=<<"private">>})).

retry_evidence_is_projected_only_from_fixed_atoms()->
    Safe=pp_failure({operation,7,{error_value,{protocol,http3},peer_guaranteed_unprocessed}}),
    ?assertEqual(<<"http3">>,maps:get(error,Safe)),
    Secret=<<"private-retry-evidence">>,
    Rejected=pp_failure({operation,7,{error_value,{protocol,http3},Secret}}),
    ?assertEqual(<<"invalid_result">>,maps:get(kind,Rejected)),
    ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(Rejected)),Secret)).

six_trials_execute_sequentially_in_one_owned_vm()->
    Counter=atomics:new(1,[]),
    Child=protocol_performance_child:collect_with(1,nonce(),fun()->
        atomics:add(Counter,1,1),receive after 40->ok end,{ok,native_sample(1)}
    end,30000),
    ?assertEqual(6,atomics:get(Counter,1)),
    ?assertEqual(6,maps:get(completed_trials,Child)),
    ?assert(pp_child_passed(Child)).

skipped_global_deadline_rows_are_not_completed_trials()->
    Counter=atomics:new(1,[]),
    Child=protocol_performance_child:collect_with(1,nonce(),fun()->
        atomics:add(Counter,1,1),{ok,native_sample(1)} end,100),
    ?assertEqual(0,atomics:get(Counter,1)),
    ?assertEqual(0,maps:get(completed_trials,Child)),
    ?assertEqual(6,length(maps:get(rows,Child))),
    ?assert(pp_child_valid(Child,1,nonce())),?assertNot(pp_child_passed(Child)).

native_callback_secrets_never_enter_child_rows()->
    Secret = <<"private-protocol-callback-value">>,
    lists:foreach(fun(Work)->
        Child=protocol_performance_child:collect_with(1,nonce(),Work,30000),
        ?assert(pp_child_valid(Child,1,nonce())),?assertNot(pp_child_passed(Child)),
        ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(Child)),Secret))
    end,[fun()->throw({Secret,self()}) end,
        fun()->{ok,#{private=>Secret}} end,
        fun()->{error,{operation,6,{error_value,{body,{too_large,Secret}}}}} end]).

a_failed_but_converged_trial_does_not_skip_later_trials()->
    Counter=atomics:new(1,[]),
    Child=protocol_performance_child:collect_with(1,nonce(),fun()->
        Count=atomics:add_get(Counter,1,1),receive after 40->ok end,
        case Count of 1->{error,{cleanup_failed,{some,{invalid,7}},{invalid,13}}};
            _->{ok,native_sample(1)} end
    end,30000),
    ?assertEqual(6,atomics:get(Counter,1)),?assertEqual(6,maps:get(completed_trials,Child)),
    ?assert(pp_child_valid(Child,1,nonce())),?assertNot(pp_child_passed(Child)),
    [First|Rest]=maps:get(rows,Child),
    ?assertEqual(<<"cleanup">>,maps:get(kind,maps:get(failure,First))),
    ?assert(lists:all(fun(Row)->maps:get(status,Row)=:=<<"Passed">> end,Rest)).

native_dns_services_are_primed_before_the_observed_work()->
    ok=protocol_performance_child:prime_dns(),
    Report=http_protocol_observer:measure(fun()->
        _=inet:getaddrs("localhost",inet6),_=inet:getaddrs("localhost",inet),
        receive after 40->ok end
    end,fun()->ok end,#{deadline_ms=>erlang:monotonic_time(millisecond)+2000,
        convergence_timeout_ms=>100}),
    ?assertEqual(true,maps:get(converged,Report)),
    ?assertEqual(0,maps:get(project_processes,maps:get(final,Report))),
    ?assertEqual(0,maps:get(tcp_ports,maps:get(final,Report))),
    ?assertEqual(0,maps:get(udp_ports,maps:get(final,Report))),
    ?assert(http_protocol_observer:valid_report(Report)).

native_sample(P)->{sample,P,100,1024,100,0,case P of 3->none;_->{some,1} end,
    10000,lists:duplicate(100,{latency,5,10})}.
nonce()-><<"ABCDEF0123456789ABCDEF0123456789">>.
fixture_child(P)->
    Observation=http_protocol_observer:measure(fun()->receive after 40->ok end end,fun()->ok end,
        #{deadline_ms=>erlang:monotonic_time(millisecond)+1000}),
    ?assertEqual(<<"ok">>,maps:get(status,Observation)),
    {ok,Sample}=pp_sample(native_sample(P)),
    #{schema=>1,status=><<"Passed">>,nonce=>nonce(),protocol=>P,configured_trials=>6,
      completed_trials=>6,requests=>100,payload_bytes=>1024,elapsed_ms=>1000,
      global_timeout_ms=>270000,row_timeout_ms=>60000,failure=>null,
      rows=>[#{trial=>I,status=><<"Passed">>,sample=>Sample,failure=>null,
          observation=>Observation}||I<-lists:seq(0,5)]}.
expand_work_windows(Child,Us)->
    Child#{elapsed_ms:=Us*6 div 1000,rows:=[begin O=maps:get(observation,Row),
        Row#{observation:=O#{work_elapsed_us:=Us,work_elapsed_ms:=Us div 1000}}
    end||Row<-maps:get(rows,Child)]}.
