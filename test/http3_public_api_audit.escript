#!/usr/bin/env escript

main([Path]) ->
    {ok, Interface} = file:read_file(Path),
    Forbidden = [
        <<"\"client_connection\":{">>,
        <<"\"client_stream\":{">>,
        <<"\"server_stream\":{">>,
        <<"\"ticket_handle\":{">>,
        <<"ConnectionHandle">>,
        <<"StreamHandle">>,
        <<"RequestHandle">>,
        <<"ResumptionTicketHandle">>,
        <<"http3/internal/">>
    ],
    Required = [
        <<"\"connection_transport\":{">>,
        <<"\"stream_transport\":{">>,
        <<"\"request_transport\":{">>,
        <<"\"capabilities\":{">>,
        <<"\"resumption_ticket\":{">>
    ],
    assert_absent(Interface, Forbidden),
    assert_present(Interface, Required),
    io:format("public API boundary ok~n");
main(_) ->
    erlang:error(public_api_audit_usage).

assert_absent(_Interface, []) ->
    ok;
assert_absent(Interface, [Pattern | Rest]) ->
    case binary:match(Interface, Pattern) of
        nomatch -> assert_absent(Interface, Rest);
        _ -> erlang:error({public_api_leaks_internal_value, Pattern})
    end.

assert_present(_Interface, []) ->
    ok;
assert_present(Interface, [Pattern | Rest]) ->
    case binary:match(Interface, Pattern) of
        nomatch -> erlang:error({public_api_missing_expected_value, Pattern});
        _ -> assert_present(Interface, Rest)
    end.
