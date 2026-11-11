%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_cleanup_ticket_tests).
-include_lib("eunit/include/eunit.hrl").

live_writer_is_pending_until_close_and_both_owners_exit_test_() ->
    {timeout, 10, fun() -> with_writer(fun(Writer, Ticket) ->
        Owners = quic_core_qlog_ffi:cleanup_owners(Ticket),
        ?assert(length(Owners) =:= 2),
        ?assert(length(lists:usort(Owners)) =:= 2),
        ?assert(lists:all(fun is_process_alive/1, Owners)),
        ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending),
        ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil}),
        ?assert(await_released(Ticket)),
        ?assert(lists:all(fun dead/1, Owners)),
        {message_queue_len, Before} = process_info(self(), message_queue_len),
        ?assert(lists:all(fun(_) -> quic_core_qlog_ffi:cleanup_state(Ticket) =:= released end,
                         lists:seq(1, 1000))),
        ?assert(process_info(self(), message_queue_len) =:= {message_queue_len, Before})
    end) end}.

pure_input_rejection_has_no_pending_resources_test() ->
    {Result, Ticket} = quic_core_qlog_ffi:open_accounted(<<>>, 1, 2),
    ?assert(Result =:= {error, 1}),
    ?assert(quic_core_qlog_ffi:cleanup_owners(Ticket) =:= []),
    ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= released).

unexecuted_open_stays_pending_even_after_a_late_device_exits_test_() ->
    {timeout, 20, fun() -> qlog_startup_tests:barrier_case(open, accounted,
        fun(Token, _, {entered, _Caller, Requester, _, Proxy}) ->
            {Result, Ticket} = result(Token),
            ?assert(Result =:= {error, 3}),
            ?assert(dead(Requester)),
            Owners = quic_core_qlog_ffi:cleanup_owners(Ticket),
            ?assert(length(Owners) =:= 1),
            ?assert(lists:all(fun dead/1, Owners)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending),
            Proxy ! {startup_release, Token},
            Late = receive {startup_late_open, Token, File} -> {opened, File}
                   after 1500 -> missing end,
            ?assert(is_tuple(Late) andalso element(1, Late) =:= opened),
            ?assert(dead(element(2, Late))),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending)
        end) end}.

registered_header_timeout_releases_only_after_actual_child_exit_test_() ->
    {timeout, 20, fun() -> qlog_startup_tests:barrier_case(header, accounted,
        fun(Token, _, {entered, _Caller, Requester, Device, _Proxy}) ->
            {Result, Ticket} = result(Token),
            ?assert(Result =:= {error, 3}),
            ?assert(dead(Requester)),
            ?assert(dead(Device)),
            ?assert(length(quic_core_qlog_ffi:cleanup_owners(Ticket)) =:= 1),
            ?assert(await_released(Ticket))
        end) end}.

admission_exit_releases_its_confirmed_cleanup_ticket_test_() ->
    {timeout, 10, fun() -> with_writer(fun(Writer, Ticket) ->
        exit(Writer, kill),
        ?assert(dead(Writer)),
        ?assert(await_released(Ticket)),
        ?assert(lists:all(fun dead/1, quic_core_qlog_ffi:cleanup_owners(Ticket)))
    end) end}.

close_timeout_does_not_release_a_live_admission_test_() ->
    {timeout, 15, fun() -> with_writer(fun(Writer, Ticket) ->
        true = erlang:suspend_process(Writer),
        try
            ?assert(quic_core_qlog_ffi:close(Writer) =:= {error, 3}),
            ?assert(is_process_alive(Writer)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending)
        after true = erlang:resume_process(Writer) end,
        ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil}),
        ?assert(await_released(Ticket))
    end) end}.

unknown_ticket_cannot_forge_release_test() ->
    ?assert(quic_core_qlog_ffi:cleanup_state({forged, <<"private-value">>}) =:= pending),
    ?assert(quic_core_qlog_ffi:cleanup_owners({forged, <<"private-value">>}) =:= []).

with_writer(Action) ->
    qlog_test_ffi:with_directory(fun(Directory) ->
        Open = quic_core_qlog_ffi:open_accounted(Directory, 1, 2),
        ?assert(is_tuple(Open) andalso tuple_size(Open) =:= 2),
        {Result, Ticket} = Open,
        ?assert(is_tuple(Result) andalso element(1, Result) =:= ok),
        {ok, Writer} = Result,
        try Action(Writer, Ticket)
        after _ = quic_core_qlog_ffi:close(Writer), ?assert(dead(Writer)) end
    end).

result(Token) ->
    Value = receive {startup_result, Token, Reply} -> Reply after 6500 -> missing end,
    ?assert(is_tuple(Value) andalso tuple_size(Value) =:= 2),
    Value.

dead(Pid) ->
    Monitor = erlang:monitor(process, Pid),
    try receive {'DOWN', Monitor, process, Pid, _} -> true after 1000 -> false end
    after erlang:demonitor(Monitor, [flush]) end.

await_released(Ticket) -> await_released(Ticket, erlang:monotonic_time(millisecond) + 1000).
await_released(Ticket, Deadline) ->
    Released = quic_core_qlog_ffi:cleanup_state(Ticket) =:= released,
    case Released orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Released;
        false -> receive after 1 -> await_released(Ticket, Deadline) end
    end.
