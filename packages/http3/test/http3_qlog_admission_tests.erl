%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_qlog_admission_tests).
-include_lib("eunit/include/eunit.hrl").

stable_reusable_retry_keeps_unconfirmed_qlog_slot_test_() ->
    {timeout,20,fun() -> with_directory(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca), block(Directory),
            try
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{socket,write_file}}}),
                restore(Directory),
                Again = 'http3@client':connect(Client,<<"localhost">>,Port),
                try ?assert(Again =:= {error,{failure,{overload,connections}}})
                after close_attempt(Again) end
            after ensure_restored(Directory) end
        end)
    end) end}.

stable_buffered_retry_keeps_slot_across_configuration_changes_test_() ->
    {timeout,20,fun() -> with_directory(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca), Request = outbound(Port),
            block(Directory),
            try
                ?assert('http3@client':send(Client,Request) =:=
                    {error,{failure,{socket,write_file}}}),
                restore(Directory),
                Derived = required('http3@client':with_timeout(
                    'http3@client':with_limits(Client, limits()), 3000)),
                ?assert('http3@client':send(Derived,Request) =:=
                    {error,{failure,{overload,connections}}})
            after ensure_restored(Directory) end
        end)
    end) end}.

stable_client_keeps_qlog_slot_across_distinct_origins_test_() ->
    {timeout,20,fun() -> with_directory(fun(Directory) ->
        with_server(fun(FirstPort,Ca) -> with_server(fun(SecondPort,_Ca) ->
            ?assert(FirstPort =/= SecondPort),
            Client = configured(Directory,Ca), block(Directory),
            try
                ?assert('http3@client':connect(Client,<<"localhost">>,FirstPort) =:=
                    {error,{failure,{socket,write_file}}}),
                restore(Directory),
                Again = 'http3@client':connect(Client,<<"localhost">>,SecondPort),
                try ?assert(Again =:= {error,{failure,{overload,connections}}})
                after close_attempt(Again) end
            after ensure_restored(Directory) end
        end) end)
    end) end}.

stable_live_slot_returns_only_after_confirmed_close_test_() ->
    {timeout,20,fun() -> with_traces(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca),
            First = required('http3@client':connect(Client,<<"localhost">>,Port)),
            try
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{overload,connections}}})
            after ?assert('http3@client':close(First) =:= {ok,closed}) end,
            Second = required('http3@client':connect(Client,<<"localhost">>,Port)),
            ?assert('http3@client':close(First) =:= {ok,already_closed}),
            try
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{overload,connections}}})
            after ?assert('http3@client':close(Second) =:= {ok,closed}) end
        end)
    end,2) end}.

connection_slot_refusal_does_not_leak_auxiliary_memory_test_() ->
    {timeout,20,fun() -> with_traces(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Base = configured(Directory,Ca),
            OneSlot = required('http3@config':with_limit(
                limits(),connections,1)),
            %% One live writer plus one transient HTTP/3 slice exactly fits
            %% the shared diagnostic ceiling. If a refused contender marks
            %% that slice active before core admission, the next refusal is
            %% incorrectly reported as EndpointMemory and this test fails.
            Tight = required('http3@config':with_limit(
                OneSlot,endpoint_memory,1146880)),
            Client = 'http3@client':with_limits(Base,Tight),
            Live = required('http3@client':connect(Client,<<"localhost">>,Port)),
            try
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{overload,connections}}}),
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{overload,connections}}})
            after ?assert('http3@client':close(Live) =:= {ok,closed}) end,
            Again = required('http3@client':connect(Client,<<"localhost">>,Port)),
            ?assert('http3@client':close(Again) =:= {ok,closed})
        end)
    end,2) end}.

stable_failed_owner_keeps_the_shared_slot_test_() ->
    {timeout,20,fun() -> with_directory(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca), Parent = self(), Tag = make_ref(),
            block(Directory),
            try
                {Child,Monitor} = spawn_monitor(fun() ->
                    Outcome = 'http3@client':connect(Client,<<"localhost">>,Port),
                    Parent ! {Tag,Outcome =:= {error,{failure,{socket,write_file}}}}
                end),
                try
                    receive {Tag,ExpectedFailure} -> ?assert(ExpectedFailure)
                    after 5000 -> ?assert(false) end,
                    receive {'DOWN',Monitor,process,Child,Reason} -> ?assert(Reason =:= normal)
                    after 5000 -> ?assert(false) end
                after exit(Child,kill), joined(Monitor,Child) end,
                restore(Directory),
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{overload,connections}}})
            after ensure_restored(Directory) end
        end)
    end) end}.

stable_buffered_success_returns_diagnostic_slice_test_() ->
    {timeout,20,fun() -> with_traces(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca), Request = outbound(Port),
            ?assertMatch({ok,_},'http3@client':send(Client,Request)),
            ?assertMatch({ok,_},'http3@client':send(Client,Request))
        end)
    end,2) end}.

stable_derived_limits_keep_existing_memory_charge_test_() ->
    {timeout,20,fun() -> with_traces(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca), block(Directory),
            try
                ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                    {error,{failure,{socket,write_file}}}),
                restore(Directory),
                %% One quarantined core qlog working set fills this exact
                %% dynamic-budget boundary even though HTTP/3 scalar tokens
                %% themselves now cost only one 16 KiB quantum.
                Low = 1114112,
                MoreSlots = required('http3@config':with_limit(limits(),connections,2)),
                Small = 'http3@client':with_limits(Client,required(
                    'http3@config':with_limit(MoreSlots,endpoint_memory,Low))),
                ?assert('http3@client':connect(Small,<<"localhost">>,Port) =:=
                    {error,{failure,{limit,endpoint_memory,Low}}}),
                Larger = 'http3@client':with_limits(Client,MoreSlots),
                Live = required('http3@client':connect(Larger,<<"localhost">>,Port)),
                try
                    ?assert('http3@client':connect(Client,<<"localhost">>,Port) =:=
                        {error,{failure,{overload,connections}}})
                after ?assert('http3@client':close(Live) =:= {ok,closed}) end,
                ?assert('http3@client':connect(Small,<<"localhost">>,Port) =:=
                    {error,{failure,{limit,endpoint_memory,Low}}})
            after ensure_restored(Directory) end
        end)
    end,1) end}.

stable_validation_failure_does_not_consume_a_slot_test_() ->
    {timeout,20,fun() -> with_traces(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca),
            ?assert('http3@client':connect(Client,<<"localhost">>,0) =:=
                {error,{invalid_port,0}}),
            Connected = required('http3@client':connect(Client,<<"localhost">>,Port)),
            ?assert('http3@client':close(Connected) =:= {ok,closed})
        end)
    end,1) end}.

stable_memory_refusal_precedes_core_connection_work_test_() ->
    {timeout,20,fun() -> with_directory(fun(Directory) ->
        with_server(fun(Port,Ca) ->
            Client = configured(Directory,Ca),
            Maximum = 1114111,
            Small = 'http3@client':with_limits(Client,required(
                'http3@config':with_limit(limits(),endpoint_memory,Maximum))),
            ?assert('http3@client':connect(Small,<<"localhost">>,Port) =:=
                {error,{failure,{limit,endpoint_memory,Maximum}}}),
            ?assert('http3@client':send(Small,outbound(Port)) =:=
                {error,{failure,{limit,endpoint_memory,Maximum}}})
        end)
    end) end}.

diagnostic_returned_unused_slice_cannot_open_late_test_() ->
    {timeout,5,fun() ->
        Identity = 'http3@internal@qlog_admission':new(),
        Exact = required('http3@config':with_limit(limits(),endpoint_memory,81920)),
        {some,Token} = required('http3@internal@qlog_admission':reserve(
            Identity,<<"unused-config-only">>,Exact)),
        nil = 'http3@internal@qlog_admission':release_unused({some,Token}),
        nil = 'http3@internal@qlog_admission':release_unused({some,Token}),
        ?assert('http3@internal@qlog_admission':begin_open({some,Token}) =:= {error,nil}),
        ?assert('http3@internal@qlog_admission':snapshot(Identity) =:= {0,0})
    end}.

limits() ->
    L0 = required('http3@config':with_limit('http3@config':default_limits(),endpoint_memory,8388608)),
    required('http3@config':with_limit(L0,connections,1)).

configured(Directory,Ca) ->
    C0 = required('http3@client':with_ca_certificate('http3@client':new(),Ca)),
    C1 = 'http3@client':with_address_family(C0,ipv4),
    C2 = 'http3@client':with_limits(C1,limits()),
    C3 = 'http3@client':with_qlog(C2,required('http3@transport':qlog(Directory))),
    required('http3@client':with_timeout(C3,3000)).

outbound(Port) ->
    required('gleam@http@request':to(
        <<"https://localhost:",(integer_to_binary(Port))/binary,"/echo">>)).

with_directory(Run) ->
    {_,Count} = http3_test_ffi:with_qlog_directory(Run), ?assert(Count =:= 0).

with_traces(Run,Expected) ->
    {_,Count} = http3_test_ffi:with_qlog_directory(Run), ?assert(Count =:= Expected).

with_server(Run) ->
    Result = http3_test_support:with_ipv4_server_timeout(3000,fun(Port,Ca) ->
        try {completed,Run(Port,Ca)} catch C:R:S -> {failed,C,R,S} end
    end),
    case Result of {completed,Value} -> Value; {failed,C,R,S} -> erlang:raise(C,R,S) end.

block(Directory) ->
    ?assert(file:del_dir(Directory) =:= ok),
    ?assert(file:write_file(Directory,<<>>,[exclusive]) =:= ok).
restore(Directory) ->
    ?assert(file:delete(Directory) =:= ok), ?assert(file:make_dir(Directory) =:= ok).
ensure_restored(Directory) ->
    case filelib:is_regular(Directory) of true -> restore(Directory); false -> ok end.
close_attempt({ok,Connection}) -> _ = 'http3@client':close(Connection), ok;
close_attempt(_) -> ok.
required(Result) ->
    ?assert(is_tuple(Result) andalso tuple_size(Result) =:= 2 andalso element(1,Result) =:= ok),
    element(2,Result).

joined(Monitor,Pid) ->
    case is_process_alive(Pid) of
        false -> erlang:demonitor(Monitor,[flush]), ok;
        true -> receive {'DOWN',Monitor,process,Pid,_} -> ok
                after 1000 -> ?assert(false) end
    end.
