%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_child).
-export([run/3]).
-include("diagnostic_failure.hrl").
-include("performance_failure.hrl").
run(Mode, Path, Nonce) ->
    Start = performance_host:capture(<<"start">>),
    Result = try http3_benchmark:run([Mode]) of
        nil -> #{status => <<"Passed">>, failure => null};
        _ -> #{status => <<"Failed">>, failure => #{exception_class => <<"error">>, classification => <<"invalid_result">>, phase => 0, results => [], counters => [], code_lines => [0, 0]}}
    catch Class:Reason:Stack ->
        Details = diagnostic_failure_details(Class, Reason, []),
        Failure = maps:merge(performance_failure(Reason), #{exception_class => maps:get(exception_class, Details),
                                              classification => maps:get(exception_reason, Details),
                                              code_lines => performance_stack_lines(Stack)}),
        #{status => <<"Failed">>, failure => Failure}
    end,
    End = performance_host:capture(<<"end">>),
    ok = file:write_file(Path, [json:encode(Result#{schema => 1, mode => Mode, nonce => Nonce,
        host_start => Start, host_end => End}), $\n]),
    halt(case maps:get(status, Result) of <<"Passed">> -> 0; _ -> 1 end).
