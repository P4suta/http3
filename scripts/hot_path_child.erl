%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(hot_path_child).
-export([run/3]).
-include("diagnostic_failure.hrl").
-include("performance_failure.hrl").
run(Profile, Path, Nonce) ->
    Result = try hot_path_profile:measure(Profile) of
        {nil, Signals} -> #{status => <<"Passed">>, signals => Signals, failure => null};
        {{'EXIT',{Reason,Stack}},Signals} when is_list(Stack) ->
            #{status => <<"Failed">>, signals => Signals, failure => failure(error,Reason,Stack)};
        {{'EXIT',Reason},Signals} ->
            #{status => <<"Failed">>, signals => Signals, failure => failure(exit,Reason,[])};
        {_Other, Signals} -> #{status => <<"Failed">>, signals => Signals,
            failure => #{exception_class => <<"error">>, classification => <<"invalid_result">>,
                phase => 0, results => [], counters => [], code_lines => [0, 0]}}
    catch Class:Reason:Stack ->
        #{status => <<"Failed">>, signals => [], failure => failure(Class,Reason,Stack)}
    end,
    ok = file:write_file(Path, [json:encode(Result#{schema => 1, nonce => Nonce}), $\n], [exclusive]),
    halt(case maps:get(status, Result) of <<"Passed">> -> 0; _ -> 1 end).

%% OTP tprof uses catch inside its workload process and returns the captured
%% exit as a value. Project it here exactly as a directly raised exception;
%% neither a raw exit reason nor a stack crosses the child evidence boundary.
failure(Class,Reason,Stack) ->
    Details = diagnostic_failure_details(Class,Reason,[]),
    maps:merge(performance_failure(Reason),
        #{exception_class => maps:get(exception_class,Details),
            classification => maps:get(exception_reason,Details),
            code_lines => performance_stack_lines(Stack)}).
