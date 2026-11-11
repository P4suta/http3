%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(qlog_primitive_failure_tests).
-include_lib("eunit/include/eunit.hrl").

pre_guardian_primitive_failure_is_typed_and_resource_free_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Faults = [
            startup_alias,
            startup_atomics,
            startup_reference,
            startup_guardian_spawn
        ],
        ?assert(lists:all(fun(Fault) ->
            {Result, Ticket} = quic_core_qlog_ffi:open_accounted_with_fault(
                Directory, 1, 2, Fault
            ),
            failed(Result) andalso
                quic_core_qlog_ffi:cleanup_state(Ticket) =:= released andalso
                quic_core_qlog_ffi:cleanup_owners(Ticket) =:= [] andalso
                qlog_files_empty(Directory)
        end, Faults))
    end) end}.

guardian_setup_failure_marks_its_empty_cleanup_ticket_released_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        ?assert(lists:all(fun(Fault) ->
            {Result, Ticket} = quic_core_qlog_ffi:open_accounted_with_fault(
                Directory, 1, 2, Fault
            ),
            failed(Result) andalso await_released(Ticket) andalso
                owners_dead(Ticket) andalso qlog_files_empty(Directory)
        end, [startup_owner_monitor, startup_worker_spawn]))
    end) end}.

post_open_primitive_failure_joins_children_and_removes_partial_file_test_() ->
    {timeout, 40, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Faults = [
            startup_admission_spawn,
            admission_owner_monitor,
            admission_file_monitor,
            admission_device_writer_monitor,
            admission_guardian_monitor
        ],
        ?assert(lists:all(fun(Fault) ->
            {Result, Ticket} = quic_core_qlog_ffi:open_accounted_with_fault(
                Directory, 1, 2, Fault
            ),
            failed(Result) andalso await_released(Ticket) andalso
                owners_dead(Ticket) andalso qlog_files_empty(Directory)
        end, Faults))
    end) end}.

writer_call_setup_failure_does_not_dispatch_or_stop_writer_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        {Writer, Ticket} = open_writer(Directory, []),
        try
            Faults = [
                writer_call_reference,
                writer_call_alias,
                writer_call_monitor
            ],
            ?assert(lists:all(fun(Fault) ->
                quic_core_qlog_ffi:writer_call_with_fault(Writer, Fault)
                    =:= {error, 3}
                    andalso writer_healthy(Writer)
            end, Faults))
        after
            _ = quic_core_qlog_ffi:close(Writer)
        end,
        ?assert(await_released(Ticket)),
        ?assert(owners_dead(Ticket))
    end) end}.

event_budget_primitive_failure_is_local_to_diagnostics_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Faults = [
            event_budget_reference,
            event_budget_alias,
            event_budget_monitor
        ],
        ?assert(lists:all(fun(Fault) ->
            {Writer, Ticket} = open_writer(Directory, Fault),
            Subject = {subject, self(), make_ref()},
            Bound = quic_core_qlog_ffi:bind_budget(
                Writer, Subject, <<1>>, 1
            ) =:= {ok, nil},
            Refused = quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1)
                =:= {error, 3},
            Healthy = writer_healthy(Writer),
            _ = quic_core_qlog_ffi:close(Writer),
            Bound andalso Refused andalso Healthy andalso
                await_released(Ticket) andalso owners_dead(Ticket)
        end, Faults))
    end) end}.

owner_binding_monitor_failure_closes_a_valid_trace_without_crashing_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Faults = [
            admission_bind_reference,
            admission_bind_monitor,
            guardian_bind_monitor
        ],
        ?assert(lists:all(fun(Fault) ->
            {Writer, Ticket} = open_writer(Directory, Fault),
            Refused = quic_core_qlog_ffi:bind_owner(Writer, self())
                =:= {error, 3},
            _ = quic_core_qlog_ffi:close(Writer),
            Refused andalso await_released(Ticket) andalso owners_dead(Ticket)
        end, Faults))
    end) end}.

monitor_free_join_fallback_proves_cleanup_before_release_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        {Writer, Ticket} = open_writer(Directory, join_monitor),
        ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil}),
        ?assert(await_released(Ticket)),
        ?assert(owners_dead(Ticket))
    end) end}.

cancel_monitor_failure_uses_the_same_bounded_join_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        {Result, Ticket} = quic_core_qlog_ffi:open_accounted_with_fault(
            Directory, 1, 2, [startup_admission_spawn, cancel_monitor]
        ),
        ?assert(failed(Result)),
        ?assert(await_released(Ticket)),
        ?assert(owners_dead(Ticket)),
        ?assert(qlog_files_empty(Directory))
    end) end}.

discovery_probe_primitive_mutation_control_test() ->
    ?assert(lists:all(fun(Fault) ->
        quic_core_qlog_ffi:primitive_probe_with_fault(Fault)
            =:= unavailable
    end, [startup_probe_reference, startup_probe_spawn])).

open_writer(Directory, Faults) ->
    {Result, Ticket} = quic_core_qlog_ffi:open_accounted_with_fault(
        Directory, 1, 2, Faults
    ),
    case Result of
        {ok, Writer} when is_pid(Writer) -> {Writer, Ticket};
        _ -> erlang:error(qlog_fault_fixture_unavailable)
    end.

failed({error, 3}) -> true;
failed(_) -> false.

writer_healthy(Writer) ->
    case quic_core_qlog_ffi:stats(Writer) of
        {ok, {Dropped, Errors, Queued}} ->
            is_integer(Dropped) andalso is_integer(Errors) andalso
                is_integer(Queued);
        _ -> false
    end.

qlog_files_empty(Directory) ->
    filelib:wildcard(
        filename:join(binary_to_list(Directory), "*.qlog")
    ) =:= [].

owners_dead(Ticket) ->
    lists:all(fun(Pid) -> not is_process_alive(Pid) end,
        quic_core_qlog_ffi:cleanup_owners(Ticket)).

await_released(Ticket) ->
    await_released(
        Ticket, erlang:monotonic_time(millisecond) + 1500
    ).

await_released(Ticket, Deadline) ->
    Released = quic_core_qlog_ffi:cleanup_state(Ticket) =:= released,
    case Released orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Released;
        false ->
            receive after 1 -> await_released(Ticket, Deadline) end
    end.
