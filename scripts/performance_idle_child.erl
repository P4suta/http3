%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_idle_child).
-export([run/2]).
-include("diagnostic_failure.hrl").
-include("performance_idle_evidence.hrl").
-compile({nowarn_unused_function, [{idw_observer_complete, 1}, {idw_diagnostics_complete, 1}]}).

run(Path, Nonce) ->
    %% The private VM never publishes logger messages or exception arguments.
    %% Only the bounded runner observes its output volume and actual exit.
    _ = logger:set_primary_config(level, none),
    put({?MODULE, phase}, instrumentation_read),
    erase({?MODULE, metadata}),
    erase({?MODULE, fixture}),
    {Status, Failure, Fixture, Instrumentation} = try
        {gleam_erlang_ffi, Original, _} = code:get_object_code(gleam_erlang_ffi),
        put({?MODULE, phase}, instrumentation_controls),
        ok = performance_idle_instrumentation:self_test(Original),
        put({?MODULE, phase}, instrumentation_prepare),
        {ok, Instrumented, Metadata} = performance_idle_instrumentation:prepare(Original),
        put({?MODULE, metadata}, Metadata),
        put({?MODULE, phase}, instrumentation_load),
        _ = code:purge(gleam_erlang_ffi),
        {module, gleam_erlang_ffi} = code:load_binary(gleam_erlang_ffi,
            "verified-idle-select", Instrumented),
        try
            put({?MODULE, phase}, fixture),
            nil = http3_idle_wakeup:main(),
            put({?MODULE, phase}, evidence),
            Evidence = http3_idle_wakeup_ffi:take_evidence(),
            put({?MODULE, fixture}, safe_fixture_value(Evidence)),
            {<<"Passed">>, null, Evidence, Metadata}
        after
            Previous = get({?MODULE, phase}),
            put({?MODULE, phase}, instrumentation_restore),
            _ = code:purge(gleam_erlang_ffi),
            {module, gleam_erlang_ffi} = code:load_binary(gleam_erlang_ffi,
                "original-idle-select", Original),
            put({?MODULE, phase}, Previous)
        end
    catch Class:Reason ->
        Details = diagnostic_failure_details(Class, Reason, []),
        {<<"Failed">>, #{exception_class => maps:get(exception_class, Details),
            classification => maps:get(exception_reason, Details),
            phase => failure_phase(), cause => failure_cause(Reason)},
            safe_fixture(), stored_metadata()}
    end,
    Report = #{schema => 2, nonce => Nonce, status => Status, failure => Failure,
        fixture => Fixture, instrumentation => Instrumentation, diagnostics => safe_diagnostics()},
    ok = file:write_file(Path, [json:encode(Report), $\n]),
    erlang:halt(case Status of <<"Passed">> -> 0; _ -> 1 end).

failure_phase() ->
    case get({?MODULE, phase}) of
        instrumentation_read -> <<"instrumentation_read">>;
        instrumentation_controls -> <<"instrumentation_controls">>;
        instrumentation_prepare -> <<"instrumentation_prepare">>;
        instrumentation_load -> <<"instrumentation_load">>;
        instrumentation_restore -> <<"instrumentation_restore">>;
        fixture -> <<"fixture">>;
        evidence -> <<"evidence">>;
        _ -> <<"unknown">>
    end.

failure_cause({http3_idle_wakeup_failed, <<"transport did not reach bounded quiescence">>}) -> <<"quiescence">>;
failure_cause({http3_idle_wakeup_failed, <<"idle client closed early">>}) -> <<"client_closed_early">>;
failure_cause({http3_idle_wakeup_failed, <<"idle server stopped early">>}) -> <<"server_stopped_early">>;
failure_cause({http3_idle_wakeup_failed, <<"idle periodic wakeup qualification failed">>}) -> <<"periodic_wakeup">>;
failure_cause({http3_idle_wakeup_failed, {<<"idle client cleanup failed">>, _}}) -> <<"client_cleanup">>;
failure_cause({http3_idle_wakeup_failed, {<<"idle server cleanup failed">>, _}}) -> <<"server_cleanup">>;
failure_cause({http3_idle_wakeup_failed, {<<"idle fixture operation failed">>, _}}) -> <<"fixture_operation">>;
failure_cause({http3_idle_wakeup_failed, {<<"idle trace operation failed">>, _}}) -> <<"trace_operation">>;
failure_cause(_) -> <<"unknown">>.

safe_fixture() ->
    try
        case erase({?MODULE, fixture}) of
            undefined -> safe_fixture_value(http3_idle_wakeup_ffi:take_evidence());
            Value -> safe_fixture_value(Value)
        end
    catch _:_ -> null end.

safe_fixture_value(Value) ->
    try
        Fixture = json:decode(iolist_to_binary(json:encode(Value))),
        case idw_fixture_shape(Fixture) of true -> Fixture; false -> null end
    catch _:_ -> null end.

stored_metadata() ->
    case get({?MODULE, metadata}) of undefined -> null; Value -> Value end.

safe_diagnostics() ->
    try
        D = json:decode(iolist_to_binary(json:encode(http3_idle_wakeup_ffi:take_diagnostics()))),
        case idw_diagnostics_shape(D) of true -> D; false -> null end
    catch _:_ -> null end.
