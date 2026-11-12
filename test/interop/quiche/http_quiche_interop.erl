%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% The native endpoints use only the unified public HTTP API.
-module(http_quiche_interop).
-define(INTEROP_NOTICE_READ_ONLY, true).
-export([run/2]).
-define(FIXTURES, "packages/quic_core/test/fixtures").
-define(MAX_BODY, 131072).
-include("../../interop_notice.hrl").

run(Role, Argument) ->
    try with_reporter(fun(Reporter) -> run_role(Role, Argument, Reporter) end)
    catch Class:_Reason:_Stack ->
        %% This peer output is retained by interoperability jobs.  Report only
        %% fixed classifications; exception values and stack data can contain
        %% endpoints, process identifiers, handles, or application bytes.
        Details = #{exception_class => safe_exception_class(Class),
                    exception_reason => <<"validation_failed">>},
        io:format("native peer failed: ~s~n", [json:encode(Details)]),
        {error, nil}
    end.

safe_exception_class(error) -> <<"error">>;
safe_exception_class(exit) -> <<"exit">>;
safe_exception_class(throw) -> <<"throw">>;
safe_exception_class(_) -> <<"unknown">>.

with_reporter(Action) ->
    {ok, Reporter} = http@diagnostics:start(256, 1000, fun(Observation) ->
        io:format("NATIVE_OBSERVATION=~tp~n", [Observation]), {ok, nil}
    end),
    try Action(Reporter)
    after
        {ok, nil} = http@diagnostics:stop(Reporter),
        io:format("NATIVE_DIAGNOSTICS=~tp~n", [http@diagnostics:snapshot(Reporter)])
    end.

run_role(client, Port, Reporter) ->
    {ok, Pem} = file:read_file(filename:join(?FIXTURES, "ecdsa-p256-server.pem")),
    [{'Certificate', Ca, not_encrypted}] = public_key:pem_decode(Pem),
    Configuration0 = http@client:with_ca_certificates(
        http@client:without_retries(http@client:defaults()), [Ca]),
    Configuration1 = http@client:with_https_record_resolver(Configuration0,
        fun(_, _, _) -> {ok, [{https_record, [<<"h3">>], Port, true, 60000}]} end),
    Configuration = http@client:with_diagnostics(Configuration1, Reporter),
    {ok, Client} = http@client:start(Configuration),
    try
        <<"quiche-independent-server">> = receive_response(Client, Port, <<"/small">>, 200),
        Large = large_body(),
        Large = receive_response(Client, Port, <<"/large">>, 200),
        _ = receive_response(Client, Port, <<"/missing">>, 404),
        io:put_chars("native client quiche contract verified\n"), ok
    after
        {ok, nil} = http@client:close(Client)
    end;
run_role(server, StopPath, Reporter) ->
    {ok, Certificate} = file:read_file(filename:join(?FIXTURES, "ecdsa-p256-server.pem")),
    {ok, PrivateKey} = file:read_file(filename:join(?FIXTURES, "ecdsa-p256-server-key.pem")),
    ServerConfig = http@server:with_diagnostics(http@server:defaults(), Reporter),
    {ok, Server} = http@server:start(ServerConfig, fun handle/2),
    try
        {ok, Config} = http@server:http3_defaults(Certificate, PrivateKey, <<"localhost">>),
        {ok, Listener} = http@server:listen_http3(Server, <<127, 0, 0, 1>>, 0, Config),
        try
            {endpoint, _, Port} = http@server:listener_endpoint(Listener),
            io:format("PORT=~B~n", [Port]),
            ok = await_stop(StopPath, erlang:monotonic_time(millisecond) + 120000),
            {ok, nil} = http@server:drain_listener(Listener)
        after
            {ok, nil} = http@server:stop_listener(Listener)
        end
    after
        {ok, nil} = http@server:stop(Server)
    end,
    io:put_chars("native server quiche contract verified\n").

receive_response(Client, Port, Path, Status) ->
    Request = {request, get, [], http@body:empty(), https, <<"localhost">>, {some, Port}, Path, none},
    {ok, Exchange} = http@client:exchange(Client, Request),
    http3 = http@client:selected_protocol(Exchange),
    {response, Status, _, Body} = http@client:response(Exchange),
    {ok, {Bytes, _Trailers}} = http@body:read_all(Body, ?MAX_BODY),
    Bytes.

await_stop(Path, Deadline) ->
    case interop_read_notice(Path,32) of
        {ok, <<"complete">>} -> ok;
        {error, enoent} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> receive after 25 -> await_stop(Path, Deadline) end;
                false -> erlang:error(native_fixture_deadline)
            end;
        _ -> erlang:error(invalid_native_completion)
    end.

handle({request, get, _, _, _, _, _, <<"/large">>, _}, _) ->
    response(large_body());
handle({request, post, _, Body, _, _, _, <<"/echo">>, _}, _) ->
    case http@body:read_all(Body, ?MAX_BODY) of
        {ok, {Bytes, []}} -> response(Bytes);
        _ -> erlang:error(request_body_not_received)
    end;
handle(_, _) -> erlang:error(unexpected_interop_request).

response(Bytes) ->
    Body = http@body:from_bytes_with_trailers(Bytes, [{<<"x-response-finished">>, <<"yes">>}]),
    {ok, {response, 200, [{<<"content-type">>, <<"application/octet-stream">>}], Body}}.

large_body() -> binary:copy(<<"quiche-flow-">>, 6000).
