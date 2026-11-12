-module(http_tls_log_test_ffi).

-export([capture/1]).

%% The filter runs in the logging process. It counts fixed TLS alert classes
%% and stops the test's synthetic certificate names before any handler sees
%% them. No report, exception, endpoint, or certificate is retained.
capture(Run) ->
    Counter = atomics:new(3, []),
    Filter = fun(Event, Counts) ->
        case Event of
            #{msg := {report, #{alert := _, role := _} = Report}} ->
                capture_report(Report, Counts),
                stop;
            #{meta := #{domain := [otp, ssl | _]}, msg := {report, Report}} ->
                capture_report(Report, Counts),
                stop;
            _ -> ignore
        end
    end,
    ok = logger:add_primary_filter(http_tls_privacy_test, {Filter, Counter}),
    try
        logger:notice(#{http_tls_privacy_probe => true}, #{domain => [otp, ssl]}),
        Result = Run(),
        {Result, atomics:get(Counter, 1), atomics:get(Counter, 2),
            atomics:get(Counter, 3) =:= 1}
    after
        ok = logger:remove_primary_filter(http_tls_privacy_test)
    end.

capture_report(#{http_tls_privacy_probe := true}, Counter) ->
    atomics:add(Counter, 3, 1);
capture_report(#{role := client}, Counter) ->
    atomics:add(Counter, 1, 1);
capture_report(#{role := server}, Counter) ->
    atomics:add(Counter, 2, 1);
capture_report(_, _Counter) -> ok.
