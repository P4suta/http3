%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_protocol_benchmark_test).
-include_lib("eunit/include/eunit.hrl").

cleanup_retains_primary_and_runs_once_test() ->
    Calls=atomics:new(2,[]),
    Work=fun()->atomics:add(Calls,1,1),{error,{invalid,12}} end,
    Cleanup=fun()->atomics:add(Calls,2,1),{error,{invalid,13}} end,
    Result=http_protocol_benchmark_ffi:finally(Work,Cleanup),
    ?assertEqual({error,{cleanup_failed,{some,{invalid,12}},{invalid,13}}},Result),
    ?assertEqual({1,1},{atomics:get(Calls,1),atomics:get(Calls,2)}).

cleanup_projects_exceptions_before_publication_test() ->
    Private=fun()->erlang:error({private_marker,<<"private-benchmark-marker">>,self()}) end,
    Actual=http_protocol_benchmark_ffi:finally(Private,Private),
    Safe=Actual=:={error,{cleanup_failed,{some,{invalid,20}},{invalid,21}}},
    ?assert(Safe).

cleanup_preserves_success_and_cleanup_only_failure_test() ->
    ?assertEqual({ok,17},http_protocol_benchmark_ffi:finally(
        fun()->{ok,17} end,fun()->{ok,nil} end)),
    ?assertEqual({error,{cleanup_failed,none,{invalid,14}}},
        http_protocol_benchmark_ffi:finally(fun()->{ok,17} end,fun()->{error,{invalid,14}} end)).

cleanup_rejects_untyped_callback_values_test() ->
    ?assertEqual({error,{cleanup_failed,{some,{invalid,22}},{invalid,23}}},
        http_protocol_benchmark_ffi:finally(fun()->invalid end,fun()->invalid end)).
