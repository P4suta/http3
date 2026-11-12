%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_budget_tests).
-include_lib("eunit/include/eunit.hrl").

auxiliary_and_writer_reservations_share_one_atomic_budget_test() ->
    Identity = quic_core_qlog_admission_ffi:new(),
    Auxiliary = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
        Identity, 16384, 1064960)),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {16384,0}),
    Writer = required(quic_core_qlog_admission_ffi:reserve(
        Identity, 1048576, 1064960, 1)),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1064960,1}),
    ?assert(quic_core_qlog_admission_ffi:reserve_auxiliary(
        Identity, 1, 1064960) =:= {error,1}),
    ?assert(quic_core_qlog_admission_ffi:reserve(
        Identity, 1, 1064960, 1) =:= {error,2}),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Auxiliary) =:= {ok,nil}),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Writer) =:= {ok,nil}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Auxiliary),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1048576,1}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Writer),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}).

auxiliary_reservation_lifecycle_is_idempotent_test() ->
    Identity = quic_core_qlog_admission_ffi:new(),
    Unused = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
        Identity, 16384, 32768)),
    nil = quic_core_qlog_admission_ffi:release_unused(Unused),
    nil = quic_core_qlog_admission_ffi:release_unused(Unused),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Unused) =:= {error,nil}),
    Active = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
        Identity, 16384, 32768)),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Active) =:= {ok,nil}),
    nil = quic_core_qlog_admission_ffi:release_unused(Active),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {16384,0}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Active),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Active),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}).

auxiliary_preflight_prioritises_a_full_shared_connection_slot_test() ->
    Identity = quic_core_qlog_admission_ffi:new(), Maximum = 1048576,
    Writer = required(quic_core_qlog_admission_ffi:reserve(
        Identity, Maximum, Maximum, 1)),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Writer) =:= {ok,nil}),
    %% Both dimensions are exhausted. The existing connection is the earlier
    %% cause, and the byte-only contender must not debit either dimension.
    ?assert(quic_core_qlog_admission_ffi:reserve_auxiliary(
        Identity, 1, Maximum, 1) =:= {error,2}),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {Maximum,1}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Writer),
    Auxiliary = required(quic_core_qlog_admission_ffi:reserve_auxiliary(
        Identity, 1, Maximum, 1)),
    nil = quic_core_qlog_admission_ffi:release_unused(Auxiliary),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}).

parallel_auxiliary_reservations_never_overcommit_test() ->
    Identity = quic_core_qlog_admission_ffi:new(), Parent = self(), Ref = make_ref(),
    Workers = [spawn_monitor(fun() -> receive {Ref,start} ->
        Parent ! {Ref, quic_core_qlog_admission_ffi:reserve_auxiliary(
            Identity, 16384, 32768)}
    end end) || _ <- lists:seq(1,16)],
    try
        lists:foreach(fun({Pid,_}) -> Pid ! {Ref,start} end, Workers),
        Results = [receive {Ref,Result} -> Result after 2000 -> ?assert(false) end
            || _ <- Workers],
        Tokens = [Token || {ok,Token} <- Results],
        ?assert(length(Tokens) =:= 2),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {32768,0}),
        lists:foreach(fun quic_core_qlog_admission_ffi:release_unused/1, Tokens),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0})
    after
        lists:foreach(fun({Pid,Monitor}) ->
            receive {'DOWN',Monitor,process,Pid,_} -> ok
            after 2000 -> exit(Pid,kill),
                receive {'DOWN',Monitor,process,Pid,_} -> ok
                after 1000 -> ?assert(false) end
            end
        end, Workers)
    end.

diagnostic_packed_counter_preserves_maximum_supported_charge_test() ->
    Identity = quic_core_qlog_admission_ffi:new(), Maximum = 2147483647,
    Token = required(quic_core_qlog_admission_ffi:reserve(Identity,Maximum,Maximum,Maximum)),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {Maximum,1}),
    ?assert(quic_core_qlog_admission_ffi:reserve(Identity,1,Maximum,Maximum) =:= {error,1}),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Token) =:= {ok,nil}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Token),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Token),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}),
    Again = required(quic_core_qlog_admission_ffi:reserve(Identity,Maximum,Maximum,Maximum)),
    nil = quic_core_qlog_admission_ffi:release_unused(Again),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}).

dynamic_event_budget_refuses_without_waiting_and_resumes_after_release_test() ->
    Identity = quic_core_qlog_admission_ffi:new(), Base = 1048576,
    Event = 16384, Maximum = Base * 2 + Event,
    First = required(quic_core_qlog_admission_ffi:reserve(
        Identity, Base, Maximum, 2)),
    Second = required(quic_core_qlog_admission_ffi:reserve(
        Identity, Base, Maximum, 2)),
    ?assert(quic_core_qlog_admission_ffi:begin_open(First) =:= {ok,nil}),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Second) =:= {ok,nil}),
    Started = erlang:monotonic_time(millisecond),
    ?assert(quic_core_qlog_admission_ffi:reserve_event(First, Event) =:= {ok,nil}),
    ?assert(quic_core_qlog_admission_ffi:reserve_event(Second, Event) =:= {error,1}),
    ?assert(erlang:monotonic_time(millisecond) - Started < 1000),
    ?assert(quic_core_qlog_admission_ffi:event_snapshot(Identity) =:= {2,1,1,0,1}),
    nil = quic_core_qlog_admission_ffi:release_events(First, Event, 1),
    ?assert(quic_core_qlog_admission_ffi:reserve_event(Second, Event) =:= {ok,nil}),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {Maximum,2}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(First),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Second),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}),
    ?assert(quic_core_qlog_admission_ffi:event_snapshot(Identity) =:= {3,2,1,2,0}).

dynamic_admission_sync_points_are_linearizable_test_() ->
    {timeout, 10, fun() ->
        lists:foreach(fun(_) ->
            closing_excludes_an_active_reservation(),
            active_registration_rollback_finishes_an_exhausted_collection(),
            closing_collects_a_committed_reservation(),
            last_active_operation_finishes_an_exhausted_collection(),
            closing_waits_for_an_active_release(),
            exactly_one_confirmed_collector_settles()
        end, lists:seq(1, 8))
    end}.

closing_excludes_an_active_reservation() ->
    {Identity, Token} = open_dynamic_token(),
    Reserve = start_probe(active_registered, fun() ->
        quic_core_qlog_admission_ffi:reserve_event(Token, 16384)
    end),
    Close = start_probe(closing, fun() ->
        quic_core_qlog_admission_ffi:release_confirmed(Token)
    end),
    finish_probe(Reserve, {error,2}),
    finish_probe(Close, nil),
    assert_released(Identity, Token, {1,0,1,0,0}).

active_registration_rollback_finishes_an_exhausted_collection() ->
    {Identity, Token} = open_dynamic_token(),
    Reserve = start_probe(active_registered, fun() ->
        quic_core_qlog_admission_ffi:reserve_event(Token, 16384)
    end),
    Parent = self(), Ref = make_ref(),
    {Closer, Monitor} = spawn_monitor(fun() ->
        Result = quic_core_qlog_admission_ffi:release_confirmed(Token),
        Parent ! {Ref,result,Result}
    end),
    receive {Ref,result,nil} -> ok after 2000 -> ?assert(false) end,
    receive {'DOWN',Monitor,process,Closer,normal} -> ok
    after 1000 -> ?assert(false) end,
    ?assert(quic_core_qlog_admission_ffi:reservation_snapshot(Token) =:=
        {2,1,0,16384}),
    %% The lifecycle recheck rejects this event. Its rollback is the last
    %% active leave and must settle the already confirmed token by itself.
    finish_probe(Reserve, {error,2}),
    assert_released(Identity, Token, {1,0,1,0,0}).

closing_collects_a_committed_reservation() ->
    {Identity, Token} = open_dynamic_token(),
    Reserve = start_probe(dynamic_debited, fun() ->
        quic_core_qlog_admission_ffi:reserve_event(Token, 16384)
    end),
    Close = start_probe(closing, fun() ->
        quic_core_qlog_admission_ffi:release_confirmed(Token)
    end),
    finish_probe(Reserve, {ok,nil}),
    finish_probe(Close, nil),
    assert_released(Identity, Token, {1,1,0,1,0}).

last_active_operation_finishes_an_exhausted_collection() ->
    {Identity, Token} = open_dynamic_token(),
    Reserve = start_probe(dynamic_debited, fun() ->
        quic_core_qlog_admission_ffi:reserve_event(Token, 16384)
    end),
    Parent = self(), Ref = make_ref(),
    {Closer, Monitor} = spawn_monitor(fun() ->
        Result = quic_core_qlog_admission_ffi:release_confirmed(Token),
        Parent ! {Ref,result,Result}
    end),
    receive {Ref,result,nil} -> ok after 2000 -> ?assert(false) end,
    receive {'DOWN',Monitor,process,Closer,normal} -> ok
    after 1000 -> ?assert(false) end,
    ?assert(quic_core_qlog_admission_ffi:reservation_snapshot(Token) =:=
        {2,1,0,16384}),
    %% Do not call release_confirmed again: the final active leave must notice
    %% Closing and perform the one permitted settlement itself.
    finish_probe(Reserve, {ok,nil}),
    assert_released(Identity, Token, {1,1,0,1,0}).

closing_waits_for_an_active_release() ->
    {Identity, Token} = open_dynamic_token(),
    ?assert(quic_core_qlog_admission_ffi:reserve_event(Token, 16384) =:= {ok,nil}),
    Release = start_probe(events_claimed, fun() ->
        quic_core_qlog_admission_ffi:release_events(Token, 16384, 1)
    end),
    Close = start_probe(closing, fun() ->
        quic_core_qlog_admission_ffi:release_confirmed(Token)
    end),
    finish_probe(Release, nil),
    finish_probe(Close, nil),
    assert_released(Identity, Token, {1,1,0,1,0}).

exactly_one_confirmed_collector_settles() ->
    {Identity, Token} = open_dynamic_token(),
    ?assert(quic_core_qlog_admission_ffi:reserve_event(Token, 16384) =:= {ok,nil}),
    First = start_probe(settlement_claimed, fun() ->
        quic_core_qlog_admission_ffi:release_confirmed(Token)
    end),
    Parent = self(), Ref = make_ref(),
    {Second, Monitor} = spawn_monitor(fun() ->
        Result = quic_core_qlog_admission_ffi:release_confirmed(Token),
        Parent ! {Ref,result,Result}
    end),
    receive {Ref,result,nil} -> ok after 1000 -> ?assert(false) end,
    receive {'DOWN',Monitor,process,Second,normal} -> ok
    after 1000 -> ?assert(false) end,
    ?assert(quic_core_qlog_admission_ffi:reservation_snapshot(Token) =:=
        {3,0,1,16384}),
    finish_probe(First, nil),
    assert_released(Identity, Token, {1,1,0,1,0}).

open_dynamic_token() ->
    Identity = quic_core_qlog_admission_ffi:new(),
    Token = required(quic_core_qlog_admission_ffi:reserve(
        Identity, 1048576, 1064960, 1)),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Token) =:= {ok,nil}),
    ?assert(quic_core_qlog_admission_ffi:bind_writer(Token, 16384)),
    {Identity, Token}.

start_probe(Stage, Run) ->
    Parent = self(), Ref = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        _ = erlang:put(
            {quic_core_qlog_admission_ffi,test_probe},
            {Parent,Ref,Stage}
        ),
        Result = Run(),
        Parent ! {Ref,result,Result}
    end),
    receive {Ref,Stage} -> ok after 1000 -> ?assert(false) end,
    {Worker, Monitor, Ref}.

finish_probe({Worker, Monitor, Ref}, Expected) ->
    Worker ! {Ref,continue},
    receive {Ref,result,Result} -> ?assert(Result =:= Expected)
    after 1000 -> ?assert(false) end,
    receive {'DOWN',Monitor,process,Worker,normal} -> ok
    after 1000 -> ?assert(false) end.

assert_released(Identity, Token, EventSnapshot) ->
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}),
    ?assert(quic_core_qlog_admission_ffi:event_snapshot(Identity) =:= EventSnapshot),
    ?assert(quic_core_qlog_admission_ffi:reservation_snapshot(Token) =:=
        {4,0,0,16384}).

qlog_writer_charges_and_releases_dynamic_client_token_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Identity = quic_core_qlog_admission_ffi:new(), Base = 1048576,
        Event = 16384, Token = required(quic_core_qlog_admission_ffi:reserve(
            Identity, Base, Base + Event, 1)),
        ?assert(quic_core_qlog_admission_ffi:begin_open(Token) =:= {ok,nil}),
        Writer = required('quic_core@internal@qlog':open(Directory,client,0,8)),
        try
            ?assert('quic_core@internal@qlog':bind_admission(
                Writer,Token,Event) =:= {ok,nil}),
            {ok,ok} = qlog_test_ffi:with_suspended_device_writer(Writer,fun() ->
                {writer,Handle,_} = Writer,
                ?assert(quic_core_qlog_ffi:event(Handle,3,0,1,1) =:= {ok,nil}),
                ?assert(quic_core_qlog_ffi:event(Handle,3,0,1,1) =:= {error,4}),
                ?assert(quic_core_qlog_admission_ffi:event_snapshot(Identity) =:=
                    {2,1,1,0,1}),
                ok
            end),
            await(fun() -> quic_core_qlog_admission_ffi:event_snapshot(Identity) =:=
                {2,1,1,1,0} end),
            ?assert('quic_core@internal@qlog':close(Writer) =:= {ok,nil})
        after
            _ = 'quic_core@internal@qlog':close(Writer),
            nil = quic_core_qlog_admission_ffi:release_confirmed(Token)
        end,
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0})
    end) end}.

client_handshake_failure_returns_unstarted_diagnostic_reservation_test_() ->
    {timeout, 20, fun() -> with_endpoint(false, 8388608, 4,
        fun(Listener, Client0, Directory) ->
        Client = required('quic_core@client':with_qlog(
            'quic_core@client':with_limits(Client0, limits(1114112)), Directory)),
        Wrong = required('quic_core@client':with_application_protocols(Client, [<<"not-offered">>])),
        Failed = 'quic_core@client':connect(Wrong),
        ?assert(case Failed of {error,{failure,_}} -> true; _ -> false end),
        ?assert(trace_count(Directory) =:= 0),
        Again = required('quic_core@client':connect(Client)),
        try _ = required('quic_core@server':accept(Listener))
        after close_attempt({ok,Again}) end
    end) end}.

client_changed_limits_preserve_unproved_startup_quarantine_test_() ->
    {timeout, 30, fun() -> with_endpoint(false, 8388608, 4,
        fun(Listener, Client0, Directory) ->
        Small = 'quic_core@client':with_limits(
            Client0, limits_at(1114112, changed_limits_config)),
        Client = required_at(
            'quic_core@client':with_qlog(Small, Directory), changed_qlog_config),
        ?assert(file:write_file(Directory, <<>>, [exclusive]) =:= ok),
        try
            ?assert('quic_core@client':connect(Client) =:=
                {error,{failure,{socket,write_file}}}),
            ?assert(file:delete(Directory) =:= ok),
            ?assert(file:make_dir(Directory) =:= ok),
            %% No native file device was discovered, so no later process join
            %% can prove this startup safe to release. Keep this one charge
            %% quarantined while independently confirmed closes still recover.
            ?assert(diagnostic_allocation(Client) =:= {1048576, 1}),
            Larger = 'quic_core@client':with_limits(Client, limits(2162688)),
            lists:foreach(fun(_) ->
                Connection = required_connect_at(Larger, changed_larger_connect),
                try
                    _ = required_at('quic_core@server':accept(Listener), changed_larger_accept),
                    Reduced = 'quic_core@client':with_limits(Larger, limits(1114112)),
                    ?assert('quic_core@client':connect(Reduced) =:=
                        {error,{failure,{limit,endpoint_memory,1114112}}})
                after close_attempt({ok,Connection}) end,
                ?assert(await_diagnostic_allocation(
                    Client, {1048576, 1}, 7000)),
                ?assert('quic_core@client':connect(Client) =:=
                    {error,{failure,{limit,endpoint_memory,1114112}}})
            end, lists:seq(1,2))
        after case file:delete(Directory) of ok -> ok; _ -> ok end end
    end) end}.

client_owner_cleanup_returns_confirmed_diagnostic_charge_test_() ->
    {timeout, 20, fun() -> with_endpoint(false, 8388608, 4,
        fun(Listener, Client0, Directory) ->
        Client = required_at('quic_core@client':with_qlog(
            'quic_core@client':with_limits(
                Client0, limits_at(1114112, owner_limits_config)), Directory),
            owner_qlog_config),
        Parent = self(), Token = make_ref(),
        {Owner, Monitor} = spawn_monitor(fun() ->
            Connection = required_at('quic_core@client':connect(Client), owner_initial_connect),
            Parent ! {Token,Connection}, receive finish -> ok end
        end),
        try
            Connection = receive {Token,Value} -> Value
                after 5000 -> ?assert(false) end,
            _ = required_at('quic_core@server':accept(Listener), owner_initial_accept),
            Actor = required_at(
                quic_core_test_ffi:labelled_pid(Connection, <<"quic_core.client">>),
                owner_actor_lookup),
            ActorMonitor = erlang:monitor(process, Actor),
            Owner ! finish,
            receive {'DOWN',Monitor,process,Owner,_} -> ok after 1000 -> ?assert(false) end,
            receive {'DOWN',ActorMonitor,process,Actor,_} -> ok after 7000 -> ?assert(false) end,
            ?assert(await_diagnostic_allocation(Client, {0, 0}, 7000)),
            Again = required_connect_at(Client, owner_retry_connect),
            try _ = required_at('quic_core@server':accept(Listener), owner_retry_accept)
            after close_attempt({ok,Again}) end
        after exit(Owner,kill), erlang:demonitor(Monitor,[flush]) end
    end) end}.

diagnostic_atomic_reservation_returns_at_most_once_test() ->
    Identity = quic_core_qlog_admission_ffi:new(),
    Token = required(quic_core_qlog_admission_ffi:reserve(Identity, 1048576, 2097152, 2)),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Token) =:= {ok,nil}),
    nil = quic_core_qlog_admission_ffi:release_unused(Token),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {1048576,1}),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Token),
    nil = quic_core_qlog_admission_ffi:release_confirmed(Token),
    nil = quic_core_qlog_admission_ffi:release_unused(Token),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}).

diagnostic_returned_unused_token_cannot_open_late_test() ->
    Identity = quic_core_qlog_admission_ffi:new(),
    Token = required(quic_core_qlog_admission_ffi:reserve(Identity, 1048576, 2097152, 2)),
    nil = quic_core_qlog_admission_ffi:release_unused(Token),
    ?assert(quic_core_qlog_admission_ffi:begin_open(Token) =:= {error,nil}),
    ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0}).

diagnostic_parallel_reservation_never_overcommits_test() ->
    Identity = quic_core_qlog_admission_ffi:new(),
    Parent = self(), Ref = make_ref(),
    Workers = [spawn_monitor(fun() -> receive {Ref,start} ->
        Parent ! {Ref, quic_core_qlog_admission_ffi:reserve(Identity,1048576,2097152,2)}
    end end) || _ <- lists:seq(1,16)],
    try
        lists:foreach(fun({Pid,_}) -> Pid ! {Ref,start} end, Workers),
        Results = [receive {Ref,Result} -> Result after 2000 -> ?assert(false) end
            || _ <- Workers],
        Tokens = [Token || {ok,Token} <- Results],
        ?assert(length(Tokens) =:= 2),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {2097152,2}),
        lists:foreach(fun quic_core_qlog_admission_ffi:release_unused/1, Tokens),
        ?assert(quic_core_qlog_admission_ffi:snapshot(Identity) =:= {0,0})
    after
        lists:foreach(fun({Pid,Monitor}) ->
            receive {'DOWN',Monitor,process,Pid,_} -> ok
            after 2000 -> exit(Pid,kill),
                receive {'DOWN',Monitor,process,Pid,_} -> ok after 1000 -> ?assert(false) end
            end
        end, Workers)
    end.

client_unconfirmed_start_keeps_memory_across_retry_test_() ->
    {timeout, 20, fun() -> with_endpoint(false, fun(_Listener, Client0, Directory) ->
        Client1 = 'quic_core@client':with_limits(
            Client0, limits_at(1114112, live_limits_config)),
        Client = required_at(
            'quic_core@client':with_qlog(Client1, Directory), live_qlog_config),
        ?assert(file:write_file(Directory, <<>>, [exclusive]) =:= ok),
        try
            ?assert('quic_core@client':connect(Client) =:=
                {error,{failure,{socket,write_file}}}),
            %% A now-writable destination does not prove that the previous
            %% opening has no outstanding filesystem ownership.
            ?assert(file:delete(Directory) =:= ok),
            ?assert(file:make_dir(Directory) =:= ok),
            Retry = 'quic_core@client':connect(Client),
            try
                ?assert(Retry =:= {error,{failure,{limit,endpoint_memory,1114112}}}),
                ?assert(trace_count(Directory) =:= 0)
            after close_attempt(Retry) end
        after
            case file:delete(Directory) of ok -> ok; _ -> ok end
        end
    end) end}.

client_unconfirmed_start_keeps_slot_across_setters_and_callers_test_() ->
    {timeout, 20, fun() -> with_endpoint(false, fun(_Listener, Client0, Directory) ->
        Limits = required('quic_core@config':with_limit(limits(8388608), connections, 1)),
        Client1 = 'quic_core@client':with_limits(Client0, Limits),
        Client = required('quic_core@client':with_qlog(Client1, Directory)),
        ?assert(file:write_file(Directory, <<>>, [exclusive]) =:= ok),
        try
            ?assert('quic_core@client':connect(Client) =:=
                {error,{failure,{socket,write_file}}}),
            ?assert(file:delete(Directory) =:= ok),
            ?assert(file:make_dir(Directory) =:= ok),
            Disabled = required('quic_core@client':with_qlog(Client, <<>>)),
            Derived = required('quic_core@client':with_qlog(
                'quic_core@client':with_limits(Disabled, Limits), Directory)),
            Parent = self(), Token = make_ref(),
            {Caller, Monitor} = spawn_monitor(fun() ->
                Attempt = 'quic_core@client':connect(Derived),
                Parent ! {Token, Attempt =:= {error,{failure,{overload,connections}}}},
                close_attempt(Attempt)
            end),
            try
                receive {Token, Refused} -> ?assert(Refused)
                after 5000 -> ?assert(false) end,
                receive {'DOWN',Monitor,process,Caller,_} -> ok
                after 2000 -> ?assert(false) end,
                ?assert(trace_count(Directory) =:= 0)
            after exit(Caller,kill), erlang:demonitor(Monitor,[flush]) end
        after case file:delete(Directory) of ok -> ok; _ -> ok end end
    end) end}.

client_live_qlog_reservation_is_shared_until_confirmed_close_test_() ->
    {timeout, 20, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client1 = 'quic_core@client':with_limits(Client0, limits(1114112)),
        Client = required('quic_core@client':with_qlog(Client1, Directory)),
        First = required_at('quic_core@client':connect(Client), live_first_connect),
        _ = required_at('quic_core@server':accept(Listener), live_first_accept),
        try
            Retry = 'quic_core@client':connect(Client),
            try ?assert(Retry =:= {error,{failure,{limit,endpoint_memory,1114112}}})
            after close_attempt(Retry) end
        after close_attempt({ok,First}) end,
        ?assert(await_diagnostic_allocation(Client, {0, 0}, 7000)),
        Second = required_connect_at(Client, live_second_connect),
        try
            _ = required_at('quic_core@server':accept(Listener), live_second_accept),
            ?assert(trace_count(Directory) =:= 2)
        after close_attempt({ok,Second}) end
    end) end}.

client_close_joins_diagnostic_children_before_success_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client = required('quic_core@client':with_qlog(Client0, Directory)),
        Connection = required('quic_core@client':connect(Client)),
        _ = required('quic_core@server':accept(Listener)),
        {Writer, Children} = client_diagnostic_children(Connection),
        ?assert(length(Children) =:= 3),
        ?assert('quic_core@client':close(Connection) =:= {ok,closed}),
        ?assert(lists:all(fun(P) -> not is_process_alive(P) end, [Writer|Children]))
    end) end}.

client_close_does_not_invent_flush_after_writer_failure_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client = required('quic_core@client':with_qlog(Client0, Directory)),
        Connection = required('quic_core@client':connect(Client)),
        _ = required('quic_core@server':accept(Listener)),
        {Writer, Children} = client_diagnostic_children(Connection),
        exit(Writer,kill),
        await(fun() -> lists:all(fun(P) -> not is_process_alive(P) end, [Writer|Children]) end),
        ?assert('quic_core@client':close(Connection) =:=
            {error,{failure,{socket,write_file}}})
    end) end}.

client_close_caller_death_cannot_orphan_taken_diagnostics_test_() ->
    {timeout, 15, fun() -> held_client_close(fun(Connection, Closer, Monitor, All) ->
        %% The transport actor continues answering while its API caller is
        %% blocked in qlog IO; a synchronous close in that actor fails here.
        ?assert('quic_core@client':phase(Connection) =:=
            {error,{failure,{closed,peer,none}}}),
        exit(Closer, kill),
        receive {'DOWN',Monitor,process,Closer,_} -> ok after 1000 -> ?assert(false) end,
        %% Keep the original connection owner alive. Only the original
        %% guardian and fixed transport closing deadline can finish cleanup.
        await(fun() -> lists:all(fun(P) -> not is_process_alive(P) end, All) end,
            erlang:monotonic_time(millisecond) + 6500)
    end) end}.

client_close_recipient_death_before_flush_still_reaps_diagnostics_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client = required('quic_core@client':with_qlog(Client0, Directory)),
        Connection = required('quic_core@client':connect(Client)),
        _ = required('quic_core@server':accept(Listener)),
        {Writer, Children} = client_diagnostic_children(Connection),
        Devices = [P || P <- Children, role(P,device_writer_loop)],
        ?assert(length(Devices) =:= 1),
        Device = hd(Devices),
        true = erlang:suspend_process(Device),
        {connection,{connection,Commands,_,_,_,_}} = Connection,
        Parent = self(), Token = make_ref(),
        {Recipient, Monitor} = spawn_monitor(fun() ->
            Reply = 'gleam@erlang@process':new_subject(),
            Deadline = 'quic_core@diagnostics':monotonic_milliseconds() + 6500,
            'gleam@erlang@process':send(Commands, {close,0,Deadline,Reply}),
            Parent ! {Token,command_sent},
            %% Deliberately die while the affine completion worker owns qlog.
            receive stop -> ok end
        end),
        try
            receive {Token,command_sent} -> ok after 2000 -> ?assert(false) end,
            exit(Recipient,kill),
            receive {'DOWN',Monitor,process,Recipient,_} -> ok after 1000 -> ?assert(false) end,
            true = erlang:resume_process(Device),
            await(fun() -> lists:all(fun(P) -> not is_process_alive(P) end, [Writer|Children]) end,
                erlang:monotonic_time(millisecond) + 6500)
        after
            exit(Recipient,kill), erlang:demonitor(Monitor,[flush]),
            try erlang:resume_process(Device) catch error:badarg -> ok end,
            close_attempt({ok,Connection})
        end
    end) end}.

simultaneous_client_close_does_not_claim_pending_cleanup_test_() ->
    {timeout, 15, fun() -> held_client_close(fun(Connection, Closer, Monitor, _All) ->
        ?assertEqual({error,{failure,{timeout,operation}}},
            'quic_core@client':close(Connection)),
        exit(Closer, kill),
        receive {'DOWN',Monitor,process,Closer,_} -> ok after 1000 -> ?assert(false) end
    end) end}.

held_client_close(Run) ->
    with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client = required('quic_core@client':with_qlog(Client0, Directory)),
        Connection = required('quic_core@client':connect(Client)),
        _ = required('quic_core@server':accept(Listener)),
        {Writer, Children} = client_diagnostic_children(Connection),
        Devices = [P || P <- Children, role(P,device_writer_loop)],
        ?assert(length(Devices) =:= 1),
        Device = hd(Devices),
        true = erlang:suspend_process(Device),
        {Closer, Monitor} = spawn_monitor(fun() ->
            _ = 'quic_core@client':close(Connection)
        end),
        try
            await(fun() -> client_close_completion_blocked(Connection) end),
            Run(Connection, Closer, Monitor, [Writer|Children])
        after
            exit(Closer,kill),
            receive {'DOWN',Monitor,process,Closer,_} -> ok after 100 -> ok end,
            try erlang:resume_process(Device) catch error:badarg -> ok end,
            close_attempt({ok,Connection}),
            await(fun() -> lists:all(fun(P) -> not is_process_alive(P) end, [Writer|Children]) end,
                erlang:monotonic_time(millisecond) + 6500)
        end
    end).

client_close_completion_blocked(Connection) ->
    Actor = required(quic_core_test_ffi:labelled_pid(
        Connection, <<"quic_core.client">>
    )),
    case process_info(Actor, monitored_by) of
        {monitored_by, Watchers} ->
            lists:any(fun(Pid) -> role(Pid, writer_call_until) end, Watchers);
        undefined -> false
    end.

client_diagnostic_children(Connection) ->
    Actor = required(quic_core_test_ffi:labelled_pid(Connection, <<"quic_core.client">>)),
    {monitored_by, Watchers} = process_info(Actor, monitored_by),
    Writers = [P || P <- Watchers, role(P, writer_receive) orelse role(P, writer_admission_loop)],
    ?assert(length(Writers) =:= 1),
    Writer = hd(Writers),
    {monitors, Monitors} = process_info(Writer, monitors),
    Children = lists:usort([P || {process,P} <- Monitors, is_pid(P), P =/= Actor]),
    {Writer, Children}.

client_qlog_configuration_has_no_filesystem_side_effect_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Path = <<Directory/binary, "/not-created">>,
        Client = required('quic_core@client':new(<<"localhost">>, 443, <<"qlog-budget">>)),
        _ = required('quic_core@client':with_qlog(Client, Path)),
        ?assert(not filelib:is_dir(binary_to_list(Path)))
    end) end}.

server_qlog_configuration_has_no_filesystem_side_effect_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Path = <<Directory/binary, "/not-created">>,
        _ = required('quic_core@server':with_qlog(server_configuration(), Path)),
        ?assert(not filelib:is_dir(binary_to_list(Path)))
    end) end}.

idle_listener_does_not_open_unfunded_qlog_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Path = <<Directory/binary, "/not-created">>,
        Server = required('quic_core@server':with_qlog(server_configuration(), Path)),
        %% Keep the assertion focused on listener startup even on the old
        %% implementation, whose setter already created the empty directory.
        case file:del_dir(Path) of ok -> ok; {error,enoent} -> ok end,
        Listener = required('quic_core@server':start(Server)),
        try ?assert(not filelib:is_dir(binary_to_list(Path)))
        after _ = 'quic_core@server':stop(Listener) end
    end) end}.

server_configuration() ->
    Cert = required(quic_core_test_ffi:fixture(<<"server.pem">>)),
    Key = required(quic_core_test_ffi:fixture(<<"server-key.pem">>)),
    'quic_core@server':with_address_family(
        required('quic_core@server':new(Cert, Key, <<"qlog-budget">>)), ipv4).

client_qlog_requires_budget_before_open_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client1 = 'quic_core@client':with_limits(Client0, limits(65536)),
        Client = required('quic_core@client':with_qlog(Client1, Directory)),
        Result = 'quic_core@client':connect(Client),
        try
            ?assert(Result =:= {error, {failure, {limit, endpoint_memory, 65536}}}),
            ?assert(trace_count(Directory) =:= 0),
            ?assert('quic_core@server':accept(Listener) =:=
                {error, {failure, {timeout, operation}}})
        after close_attempt(Result) end
    end) end}.

server_qlog_requires_budget_before_open_test_() ->
    {timeout, 15, fun() -> with_endpoint(true, fun(_Listener, Client, Directory) ->
        Result = 'quic_core@client':connect(Client),
        try
            ?assert(Result =:= {error, {failure, {quic, peer, {some, 2}}}}),
            ?assert(trace_count(Directory) =:= 0)
        after close_attempt(Result) end
    end) end}.

disabled_qlog_retains_existing_minimum_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client = 'quic_core@client':with_limits(Client0, limits(65536)),
        Connection = required('quic_core@client':connect(Client)),
        try
            Peer = required('quic_core@server':accept(Listener)),
            ?assert('quic_core@server':phase(Peer) =:= {ok, established}),
            ?assert(trace_count(Directory) =:= 0)
        after close_attempt({ok, Connection}) end
    end) end}.

client_diagnostic_admission_has_an_exact_quantized_boundary_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, 8388608, 4,
        fun(Listener, Client0, Directory) ->
        Client = required('quic_core@client':with_qlog(Client0, Directory)),
        TooSmall = 'quic_core@client':with_limits(Client, limits(1114111)),
        ?assert('quic_core@client':connect(TooSmall) =:=
            {error,{failure,{limit,endpoint_memory,1114111}}}),
        ?assert(trace_count(Directory) =:= 0),
        Exact = 'quic_core@client':with_limits(Client, limits(1114112)),
        Connection = required('quic_core@client':connect(Exact)),
        try
            _ = required('quic_core@server':accept(Listener)),
            ?assert(trace_count(Directory) =:= 1)
        after close_attempt({ok,Connection}) end
    end) end}.

large_telemetry_limit_uses_dynamic_budget_instead_of_preallocation_test_() ->
    {timeout, 15, fun() -> with_endpoint(false, fun(Listener, Client0, Directory) ->
        Client1 = required('quic_core@client':with_qlog(Client0, Directory)),
        Limits = required('quic_core@config':with_limit(limits(1114112), telemetry, 2147483647)),
        Client = 'quic_core@client':with_limits(Client1, Limits),
        Connection = required('quic_core@client':connect(Client)),
        try
            _ = required('quic_core@server':accept(Listener)),
            ?assert(trace_count(Directory) =:= 1)
        after close_attempt({ok,Connection}) end
    end) end}.

listener_stop_does_not_wait_on_its_own_qlog_budget_test_() ->
    {timeout, 15, fun() -> with_endpoint(true, 8388608, 1, 1,
        fun(Listener, Client, Directory) ->
        Connection = required('quic_core@client':connect(Client)),
        try
            Peer = required('quic_core@server':accept(Listener)),
            {Writer, WriterMonitor, Stop} =
                quic_core_test_ffi:with_quiescent_connection(Peer,
                    fun(_Actor, Release) ->
                        {Writer0, Device} = server_diagnostic_writer(Listener, Peer),
                        await(fun() ->
                            writer_is_empty(Writer0)
                                andalso element(5, admission_stats(Listener)) =:= 0
                        end),
                        {ok,{DroppedBefore,ErrorsBefore,0}} =
                            quic_core_qlog_ffi:stats(Writer0),
                        WriterMonitor0 = erlang:monitor(process, Writer0),
                        true = erlang:suspend_process(Device),
                        Stop0 = try
                            %% Occupy the complete ordinary queue and its one
                            %% dynamic event charge. The terminal observation
                            %% has a separate prepaid slot, so listener-led
                            %% shutdown never calls back into the synchronously
                            %% blocked listener.
                            ?assert(quic_core_qlog_ffi:event(
                                Writer0,3,0,1,1) =:= {ok,nil}),
                            await(fun() ->
                                element(5, admission_stats(Listener)) =:= 1
                            end),
                            StopStarted = erlang:monotonic_time(millisecond),
                            StopProcess = start_stop(Listener),
                            ok = Release(),
                            await_equal({ok,{2,0}}, fun() ->
                                quic_core_qlog_ffi:terminal_snapshot(Writer0)
                            end),
                            {ok,{DroppedAfter,ErrorsBefore,2}} =
                                quic_core_qlog_ffi:stats(Writer0),
                            ?assert(DroppedAfter >= DroppedBefore),
                            {StopProcess, StopStarted}
                        after
                            _ = Release(),
                            try erlang:resume_process(Device)
                            catch error:badarg -> ok end
                        end,
                        {Writer0, WriterMonitor0, Stop0}
                    end),
            {{Stopper, StopMonitor, StopRef}, StartedAt} = Stop,
            receive {StopRef, result, StopResult} ->
                ?assert(StopResult =:= {ok,stopped})
            after 2000 -> ?assert(false) end,
            receive {'DOWN',StopMonitor,process,Stopper,normal} -> ok
            after 1000 -> ?assert(false) end,
            StopFinished = erlang:monotonic_time(millisecond),
            %% The fixture's 1.5 s operation deadline is the outer bound. A
            %% callback to the blocked listener would instead consume the
            %% writer's five-second budget deadline and fail this stop.
            ?assert(StopFinished - StartedAt < 1500),
            receive {'DOWN',WriterMonitor,process,Writer,_} -> ok
            after 1000 -> ?assert(false) end,
            %% A successful stop now means its final qlog reconciliation saw
            %% every static and dynamic reservation at exact zero.
            ?assert(trace_event_count(Directory,
                <<"\"name\":\"quic:connection_closed\"">>) =:= 1)
        after close_attempt({ok,Connection}) end
    end) end}.

server_terminal_qlog_event_is_exactly_once_test_() ->
    {timeout, 15, fun() -> with_endpoint(true, 8388608, 1, 1,
        fun(Listener, Client, Directory) ->
        Connection = required('quic_core@client':connect(Client)),
        try
            Peer = required('quic_core@server':accept(Listener)),
            quic_core_test_ffi:with_quiescent_connection(
                Peer, fun(_Actor, _Release) ->
                {Writer, Device} = server_diagnostic_writer(Listener, Peer),
                await(fun() ->
                    writer_is_empty(Writer)
                        andalso element(5, admission_stats(Listener)) =:= 0
                end),
                {ok,{DroppedBefore,ErrorsBefore,0}} = quic_core_qlog_ffi:stats(Writer),
                true = erlang:suspend_process(Device),
                try
                    ?assert(quic_core_qlog_ffi:event(Writer,3,0,1,1) =:= {ok,nil}),
                    ?assert(quic_core_qlog_ffi:event(Writer,5,1,0,0) =:= {ok,nil}),
                    ?assert(quic_core_qlog_ffi:event(Writer,5,2,0,0) =:= {error,5}),
                    ?assert(quic_core_qlog_ffi:terminal_snapshot(Writer) =:= {ok,{2,1}}),
                    ?assertEqual(
                        {ok,{DroppedBefore + 1,ErrorsBefore,2}},
                        quic_core_qlog_ffi:stats(Writer)
                    )
                after
                    try erlang:resume_process(Device) catch error:badarg -> ok end
                end,
                await_equal(0, fun() ->
                    element(5, admission_stats(Listener))
                end)
                end),
            ?assertEqual({ok,stopped}, 'quic_core@server':stop(Listener)),
            ?assert(trace_event_count(Directory,
                <<"\"name\":\"quic:connection_closed\"">>) =:= 1)
        after close_attempt({ok,Connection}) end
    end) end}.

server_stop_does_not_turn_terminal_device_failure_into_success_test_() ->
    {timeout, 15, fun() -> with_endpoint(true, 8388608, 1, 1,
        fun(Listener, Client, _Directory) ->
        Connection = required('quic_core@client':connect(Client)),
        try
            Peer = required('quic_core@server':accept(Listener)),
            quic_core_test_ffi:with_quiescent_connection(
                Peer, fun(_Actor, Release) ->
                    {Writer, Device} = server_diagnostic_writer(Listener, Peer),
                    await(fun() -> writer_is_empty(Writer) end),
                    true = erlang:suspend_process(Device),
                    try
                        {Stopper, StopMonitor, StopRef} = start_stop(Listener),
                        ok = Release(),
                        await_equal({ok,{2,0}}, fun() ->
                            quic_core_qlog_ffi:terminal_snapshot(Writer)
                        end),
                        %% The terminal record is now the sole in-flight device
                        %% write. Its writer loss must reach the listener's typed
                        %% stop result.
                        exit(Device, kill),
                        receive {StopRef, result, StopResult} ->
                            ?assertEqual(
                                {error,{failure,{socket,write_file}}},
                                StopResult
                            )
                        after 2000 -> ?assert(false) end,
                        receive {'DOWN',StopMonitor,process,Stopper,normal} -> ok
                        after 1000 -> ?assert(false) end
                    after
                        _ = Release(),
                        try erlang:resume_process(Device)
                        catch error:badarg -> ok end
                    end
                end)
        after close_attempt({ok,Connection}) end
    end) end}.

start_stop(Listener) ->
    Parent = self(), Ref = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Result = 'quic_core@server':stop(Listener),
        Parent ! {Ref,result,Result}
    end),
    {Worker, Monitor, Ref}.

writer_is_empty(Writer) ->
    case quic_core_qlog_ffi:stats(Writer) of
        {ok,{_,0,0}} -> true;
        _ -> false
    end.

server_qlog_event_pressure_is_typed_observable_and_recoverable_test_() ->
    {timeout, 20, fun() -> with_endpoint(true, 2097152, 1,
        fun(Listener, Client, _Directory) ->
        Connection = required('quic_core@client':connect(Client)),
        try
            Peer = required('quic_core@server':accept(Listener)),
            quic_core_test_ffi:with_quiescent_connection(
                Peer, fun(_Actor, _Release) ->
                {Writer, Device} = server_diagnostic_writer(Listener, Peer),
                await_equal(0, fun() ->
                    element(5, admission_stats(Listener))
                end),
                Before = admission_stats(Listener),
                true = erlang:suspend_process(Device),
                try
                    Started = erlang:monotonic_time(millisecond),
                    {Accepted, Classification} = fill_qlog_until_refused(Writer, 128, 0),
                    Elapsed = erlang:monotonic_time(millisecond) - Started,
                    ?assert(Accepted > 0 andalso Accepted < 128),
                    ?assert(Classification =:= resource_refused),
                    ?assert(Elapsed < 3000),
                    During = admission_stats(Listener),
                    ?assertEqual(Accepted + 1,
                        element(1,During) - element(1,Before)),
                    ?assertEqual(Accepted,
                        element(2,During) - element(2,Before)),
                    ?assertEqual(1, element(3,During) - element(3,Before)),
                    ?assertEqual(Accepted, element(5,During)),
                    ?assertEqual(Accepted * 16384, element(6,During))
                after try erlang:resume_process(Device) catch error:badarg -> ok end end,
                await_equal(0, fun() ->
                    element(5, admission_stats(Listener))
                end),
                ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok,nil}),
                await_equal(0, fun() ->
                    element(5, admission_stats(Listener))
                end)
                end)
        after close_attempt({ok,Connection}) end
    end) end}.

diagnostic_charge_survives_connection_death_until_children_join_test_() ->
    {timeout, 20, fun() -> with_endpoint(true, 8388608, 1,
        fun(Listener, Client, Directory) ->
        Connection = required('quic_core@client':connect(Client)),
        try
            Peer = required('quic_core@server':accept(Listener)),
            quic_core_test_ffi:with_quiescent_connection(
                Peer, fun(Actor, _Release) ->
                ListenerActor = required(quic_core_test_ffi:labelled_pid(Listener, <<"quic_core.listener">>)),
                {monitored_by, Watchers} = process_info(ListenerActor, monitored_by),
                Writers = [P || P <- Watchers, role(P, writer_receive) orelse role(P, writer_admission_loop)],
                ?assertEqual(1, length(Writers)),
                Writer = hd(Writers),
                {monitors, Monitors} = process_info(Writer, monitors),
                Devices = [P || {process,P} <- Monitors, is_pid(P), role(P, device_writer_loop)],
                ?assertEqual(1, length(Devices)),
                Device = hd(Devices),
                await(fun() ->
                    writer_is_empty(Writer)
                        andalso element(5, admission_stats(Listener)) =:= 0
                end),
                Before = budget_stats(Listener),
                ?assert(element(1, Before) >= 1048576 + 65536),
                ?assert(element(2, Before) =:= 1 andalso element(3, Before) =:= 4),
                true = erlang:suspend_process(Device),
                try
                    ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok,nil}),
                    exit(Actor, kill),
                    await(fun() ->
                        quic_core_qlog_ffi:terminal_snapshot(Writer) =:= {ok,{2,0}}
                    end),
                    await(fun() -> 'quic_core@server':connection_id_stats(Listener) =:=
                        {ok,{listener_connection_id_stats,0,0}} end),
                    %% The route and transport grant have gone, but the deliberately
                    %% blocked qlog child still owns its complete diagnostic charge.
                    ?assertEqual({1064960,1,4}, budget_stats(Listener))
                after try erlang:resume_process(Device) catch error:badarg -> ok end end,
                await(fun() -> budget_stats(Listener) =:= {0,0,0} end),
                ?assert(trace_event_count(Directory,
                    <<"\"name\":\"quic:connection_closed\"">>) =:= 1)
                end),
            Again = required('quic_core@client':connect(Client)),
            try
                _ = required('quic_core@server':accept(Listener)),
                ?assert(element(2, budget_stats(Listener)) =:= 1)
            after close_attempt({ok,Again}) end,
            await(fun() -> budget_stats(Listener) =:= {0,0,0} end),
            ?assert(budget_stats(Listener) =:= {0,0,0})
        after close_attempt({ok,Connection}) end
    end) end}.

unconfirmed_start_keeps_a_finite_slot_and_truthful_stop_test_() ->
    {timeout, 20, fun() -> with_endpoint(true, 8388608, 1,
        fun(Listener, Client, Directory) ->
        %% Create the fixture directory explicitly: configuration is pure.
        %% Replace it with a file so startup fails before device registration.
        ?assert(file:make_dir(Directory) =:= ok),
        ?assert(file:del_dir(Directory) =:= ok),
        ?assert(file:write_file(Directory, <<>>, [exclusive]) =:= ok),
        try
            lists:foreach(fun(_) ->
                Result = 'quic_core@client':connect(Client),
                try
                    ?assert(budget_stats(Listener) =:= {1048576,1,4}),
                    ?assert(Result =:= {error,{failure,{quic,peer,{some,2}}}})
                after close_attempt(Result) end
            end, lists:seq(1,3)),
            %% Stopping communication must not describe unconfirmed diagnostic
            %% ownership as a successfully released reservation.
            ?assert('quic_core@server':stop(Listener) =:=
                {error,{failure,{socket,write_file}}})
        after
            ?assert(file:delete(Directory) =:= ok),
            ?assert(file:make_dir(Directory) =:= ok)
        end
    end) end}.

budget_stats({listener, NativeListener}) ->
    required('quic_core@internal@runtime@server_worker':qlog_budget_stats(NativeListener)).

admission_stats({listener, NativeListener}) ->
    required('quic_core@internal@runtime@server_worker':qlog_admission_stats(NativeListener)).

server_diagnostic_writer(Listener, _Peer) ->
    ListenerResult = quic_core_test_ffi:labelled_pid(Listener, <<"quic_core.listener">>),
    ?assert(is_tuple(ListenerResult) andalso tuple_size(ListenerResult) =:= 2
        andalso element(1,ListenerResult) =:= ok
        andalso is_pid(element(2,ListenerResult))),
    {ok,ListenerActor} = ListenerResult,
    {monitored_by, Watchers} = process_info(ListenerActor, monitored_by),
    Writers = [P || P <- Watchers,
        role(P,writer_receive) orelse role(P,writer_admission_loop)],
    ?assertEqual(1, length(Writers)),
    Writer = hd(Writers),
    {monitors, Monitors} = process_info(Writer, monitors),
    Devices = [P || {process,P} <- Monitors, is_pid(P), role(P,device_writer_loop)],
    ?assertEqual(1, length(Devices)),
    {Writer,hd(Devices)}.

fill_qlog_until_refused(_Writer, 0, Accepted) -> {Accepted,not_refused};
fill_qlog_until_refused(Writer, Remaining, Accepted) ->
    case quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) of
        {ok,nil} -> fill_qlog_until_refused(Writer, Remaining - 1, Accepted + 1);
        {error,4} -> {Accepted,resource_refused};
        _ -> {Accepted,diagnostic_unavailable}
    end.

role(Pid, Function) ->
    case process_info(Pid, current_stacktrace) of
        {current_stacktrace, Stack} -> lists:any(fun
            ({quic_core_qlog_ffi,F,_,_}) -> F =:= Function;
            (_) -> false
        end, Stack);
        _ -> false
    end.

await(Check) -> await(Check, erlang:monotonic_time(millisecond) + 7000).
await(Check, Deadline) ->
    case Check() of
        true -> ok;
        false ->
            ?assert(erlang:monotonic_time(millisecond) < Deadline),
            receive after 1 -> await(Check, Deadline) end
    end.

await_equal(Expected, Observe) ->
    await_equal(Expected, Observe,
        erlang:monotonic_time(millisecond) + 7000).

await_equal(Expected, Observe, Deadline) ->
    Actual = Observe(),
    case Actual =:= Expected of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    receive after 1 ->
                        await_equal(Expected, Observe, Deadline)
                    end;
                false -> ?assertEqual(Expected, Actual)
            end
    end.

with_endpoint(ServerQlog, Run) ->
    with_endpoint(ServerQlog, 65536, 1024, Run).

with_endpoint(ServerQlog, Budget, Connections, Run) ->
    with_endpoint(ServerQlog, Budget, Connections, undefined, Run).

with_endpoint(ServerQlog, Budget, Connections, Telemetry, Run) ->
    qlog_test_ffi:with_directory(fun(Directory) ->
        Cert = required(quic_core_test_ffi:fixture(<<"server.pem">>)),
        Key = required(quic_core_test_ffi:fixture(<<"server-key.pem">>)),
        Ca = required(quic_core_test_ffi:fixture(<<"ca.pem">>)),
        Deadlines = lists:foldl(fun(Phase, D) ->
            required('quic_core@config':with_deadline(D, Phase, 1500))
        end, 'quic_core@config':default_deadlines(), [connect, handshake, operation]),
        Config0 = required('quic_core@server':new(Cert, Key, <<"qlog-budget">>)),
        Config1 = 'quic_core@server':with_address_family(Config0, ipv4),
        Config2 = 'quic_core@server':with_deadlines(Config1, Deadlines),
        ConnectionLimits = required('quic_core@config':with_limit(
            limits(Budget), connections, Connections)),
        Limits = case Telemetry of
            undefined -> ConnectionLimits;
            _ -> required('quic_core@config':with_limit(
                ConnectionLimits, telemetry, Telemetry))
        end,
        Config3 = 'quic_core@server':with_limits(Config2, Limits),
        Config = case ServerQlog of
            true -> required('quic_core@server':with_qlog(Config3, Directory));
            false -> Config3
        end,
        Listener = required('quic_core@server':start(Config)),
        Port = required('quic_core@server':port(Listener)),
        Client0 = required('quic_core@client':new(
            <<"localhost">>, Port, <<"qlog-budget">>)),
        Client1 = 'quic_core@client':with_address_family(Client0, ipv4),
        Client2 = required('quic_core@client':with_ca_certificates(Client1, Ca)),
        Client = 'quic_core@client':with_deadlines(Client2, Deadlines),
        try Run(Listener, Client, Directory) of
            Value ->
                Stop = 'quic_core@server':stop(Listener),
                ?assert(Stop =:= {ok, stopped}
                    orelse Stop =:= {ok, already_stopped}),
                Value
        catch Class:Reason:Stack ->
            %% Failed assertions may deliberately leave an unconfirmed ticket.
            %% Close communication, then preserve that original causal failure;
            %% the cleanup error must not replace it in ordinary EUnit output.
            _ = 'quic_core@server':stop(Listener),
            erlang:raise(Class, Reason, Stack)
        end
    end).

limits(Bytes) ->
    required('quic_core@config':with_limit('quic_core@config':default_limits(),
        endpoint_memory, Bytes)).

limits_at(Bytes, Stage) ->
    required_at('quic_core@config':with_limit(
        'quic_core@config':default_limits(), endpoint_memory, Bytes), Stage).

required(Result) ->
    ?assert(is_tuple(Result) andalso tuple_size(Result) =:= 2 andalso element(1, Result) =:= ok),
    element(2, Result).

%% Preserve only a fixed stage label and a typed failure class.  In particular,
%% never put a raw path, endpoint, process identifier, socket or exception into
%% an assertion term that the EUnit listener may retain or print.
required_at({ok, Value}, _Stage) -> Value;
required_at(Result, Stage) ->
    erlang:error({required_failed, Stage, safe_result_class(Result)}).

safe_result_class({error,{failure,{limit,endpoint_memory,_}}}) -> endpoint_memory;
safe_result_class({error,{failure,{overload,connections}}}) -> connections;
safe_result_class({error,{failure,{socket,write_file}}}) -> write_file;
safe_result_class({error,{failure,{tls,_}}}) -> tls;
safe_result_class({error,{failure,{quic,_,_}}}) -> quic;
safe_result_class({error,{failure,{closed,_,_}}}) -> closed;
safe_result_class({error,_}) -> other_error;
safe_result_class(_) -> malformed_result.

required_connect_at(Client, Stage) ->
    case 'quic_core@client':connect(Client) of
        {ok, Connection} -> Connection;
        Result ->
            {Bytes, Connections} = diagnostic_allocation(Client),
            erlang:error({diagnostic_connect_failed, Stage,
                safe_result_class(Result), Bytes, Connections})
    end.

diagnostic_allocation(Client) ->
    case 'quic_core@client':client_diagnostic_budget_allocation(Client) of
        {diagnostic_budget_allocation, Bytes, Connections}
          when is_integer(Bytes), Bytes >= 0, Bytes =< 2147483647,
               is_integer(Connections), Connections >= 0,
               Connections =< 2147483647 -> {Bytes, Connections};
        _ -> erlang:error(invalid_diagnostic_allocation)
    end.

await_diagnostic_allocation(Client, Expected, Milliseconds) ->
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    await_diagnostic_allocation_until(Client, Expected, Deadline).

await_diagnostic_allocation_until(Client, Expected, Deadline) ->
    Current = diagnostic_allocation(Client),
    Expired = erlang:monotonic_time(millisecond) >= Deadline,
    case {Current =:= Expected, Expired} of
        {true, _} -> true;
        {false, true} ->
            {Bytes, Connections} = Current,
            {diagnostic_reconciliation_stats, Attempts, Admitted, Refused,
                Recovered, ExpiredCount, Retained} =
                'quic_core@client':client_diagnostic_reconciliation_stats(Client),
            erlang:error({diagnostic_recovery_timeout,
                Bytes, Connections, Attempts, Admitted, Refused,
                Recovered, ExpiredCount, Retained});
        {false, false} -> receive after 1 ->
            await_diagnostic_allocation_until(Client, Expected, Deadline)
        end
    end.

close_attempt({ok, Connection}) -> _ = 'quic_core@client':close(Connection), ok;
close_attempt(_) -> ok.

trace_count(Directory) ->
    length(filelib:wildcard(filename:join(binary_to_list(Directory), "*.qlog"))).

trace_event_count(Directory, Needle) ->
    lists:sum([case file:read_file(Path) of
        {ok, Bytes} -> length(binary:matches(Bytes, Needle));
        {error, _} -> 0
    end || Path <- filelib:wildcard(
        filename:join(binary_to_list(Directory), "*.qlog"))]).
