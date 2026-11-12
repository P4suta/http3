%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_cleanup_owner_tests).
-include_lib("eunit/include/eunit.hrl").

guardian_exit_alone_cannot_release_a_suspended_admission_test_() ->
    {timeout, 20, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        {{ok, Writer}, Ticket} = quic_core_qlog_ffi:open_accounted(Directory, 1, 2),
        Owners = quic_core_qlog_ffi:cleanup_owners(Ticket),
        ?assert(length(Owners) =:= 2),
        [Guardian] = [P || P <- Owners, P =/= Writer],
        true = erlang:suspend_process(Guardian),
        Controller = self(), Token = make_ref(),
        {Closer, Monitor} = spawn_monitor(fun() ->
            Result = quic_core_qlog_ffi:close(Writer),
            Controller ! {closed, Token, Result}
        end),
        try
            ?assert(await_release_request(Guardian, Writer,
                                         erlang:monotonic_time(millisecond) + 1000)),
            true = erlang:suspend_process(Writer),
            true = erlang:resume_process(Guardian),
            ?assert(dead(Guardian)),
            ?assert(is_process_alive(Writer)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= pending),
            true = erlang:resume_process(Writer),
            Closed = receive {closed, Token, Reply} -> Reply after 1500 -> missing end,
            ?assert(Closed =:= {ok, nil}),
            ?assert(dead(Writer)),
            ?assert(quic_core_qlog_ffi:cleanup_state(Ticket) =:= released)
        after
            resume(Writer), resume(Guardian),
            _ = quic_core_qlog_ffi:close(Writer),
            exit(Closer, kill),
            ?assert(join(Closer, Monitor)),
            ?assert(dead(Writer)),
            ?assert(dead(Guardian))
        end
    end) end}.

resume(Pid) ->
    try true = erlang:resume_process(Pid), ok catch error:badarg -> ok end.

join(Pid, Monitor) ->
    try receive {'DOWN', Monitor, process, Pid, _} -> true after 1000 -> false end
    after erlang:demonitor(Monitor, [flush]) end.

dead(Pid) -> join(Pid, erlang:monitor(process, Pid)).

await_release_request(Guardian, Writer, Deadline) ->
    Queued = case process_info(Guardian, messages) of
        {messages, Messages} -> lists:member({qlog_guardian_release, Writer}, Messages);
        _ -> false
    end,
    case Queued orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Queued;
        false -> receive after 1 -> await_release_request(Guardian, Writer, Deadline) end
    end.
