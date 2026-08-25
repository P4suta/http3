#!/usr/bin/env escript

-define(MAXIMUM_RELATIVE_NS, 120000000000).

main([Path]) ->
    try
        Events = read_events(Path),
        ok = validate_clock_domain(Events),
        ok = validate_actor_identity(Events),
        ok = validate_warmup_noise(Events),
        Labels = lists:usort([
            Label
         || Event <- Events,
            Label <- [logical_label(Event)],
            Label =/= <<>>
        ]),
        io:format("clock_domain=node-local-monotonic~n"),
        io:format("relative_timing=enabled~n"),
        io:format("event_count=~B~n", [length(Events)]),
        io:format("logical_labels=~s~n", [join_binaries(Labels)]),
        halt(0)
    catch
        Class:Reason ->
            io:format(standard_error,
                      "clock_self_check=failed class=~p reason=~0p~n",
                      [Class, Reason]),
            halt(1)
    end;
main(_) ->
    io:format(standard_error, "usage: check_trace.escript TRACE.jsonl~n", []),
    halt(2).

read_events(Path) ->
    {ok, Contents} = file:read_file(Path),
    Lines = [Line || Line <- binary:split(Contents, <<"\n">>, [global]),
                     Line =/= <<>>],
    true = Lines =/= [],
    [json:decode(Line) || Line <- Lines].

validate_clock_domain(Events) ->
    Roots = [timestamp(Event) || Event <- Events,
                                 event_kind(Event) =:= <<"root">>],
    [RootAt] = Roots,
    Sends = [Event || Event <- Events, event_kind(Event) =:= <<"send">>],
    Receives = [Event || Event <- Events,
                         event_kind(Event) =:= <<"receive">>],
    true = Sends =/= [],
    true = Receives =/= [],
    Causal = [Event || Event <- Events,
                       lists:member(event_kind(Event),
                                    [<<"root">>, <<"send">>, <<"receive">>])],
    Nodes = lists:usort([maps:get(<<"node">>, Event) || Event <- Causal]),
    [_SingleNode] = Nodes,
    true = lists:all(fun(Event) ->
        At = timestamp(Event),
        is_integer(At) andalso At >= RootAt andalso
            At - RootAt =< ?MAXIMUM_RELATIVE_NS
    end, Causal),
    ok.

validate_actor_identity(Events) ->
    Labels = [logical_label(Event) || Event <- Events],
    true = lists:all(fun(Label) -> lists:member(Label, Labels) end, [
        <<"http3.client">>,
        <<"http3.listener">>,
        <<"http3.connect_candidate">>
    ]),
    true = lists:any(fun(Label) ->
        binary:match(Label, <<"gleam_quic.">>) =/= nomatch
    end, Labels),
    RoleEvents = length([
        Label
     || Label <- Labels,
        binary:match(Label, <<"http3.">>) =/= nomatch orelse
            binary:match(Label, <<"gleam_quic.">>) =/= nomatch
    ]),
    GenericInitEvents = length([
        Label || Label <- Labels, Label =:= <<"proc_lib:init_p/3">>
    ]),
    true = RoleEvents > GenericInitEvents,
    ok.

validate_warmup_noise(Events) ->
    CodeServerEvents = length([
        Event
     || Event <- Events,
        binary:match(logical_label(Event), <<"code_server">>) =/= nomatch
    ]),
    true = CodeServerEvents * 2 =< length(Events),
    ok.

timestamp(Event) ->
    maps:get(<<"local_timestamp_ns">>, Event).

event_kind(Event) ->
    maps:get(<<"kind">>, maps:get(<<"event">>, Event)).

logical_label(Event) ->
    Process = maps:get(<<"process">>, Event, #{}),
    case maps:get(<<"logical">>, Process, null) of
        Logical when is_map(Logical) -> maps:get(<<"label">>, Logical, <<>>);
        _Absent -> <<>>
    end.

join_binaries(Values) ->
    unicode:characters_to_list(lists:join(<<",">>, Values), utf8).
