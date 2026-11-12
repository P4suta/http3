%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Public-API endpoints only; HTTP/2 parsing belongs to independent nghttp2.
-module(http_nghttp2_interop).
-define(INTEROP_NOTICE_READ_ONLY, true).
-export([run_client/1, run_server/1]).

-define(FIXTURES, "packages/http3/test/fixtures").
-define(MAX_BODY, 131072).
-include("../../interop_notice.hrl").

run_client(Port) ->
    {ok, Pem} = file:read_file(filename:join(?FIXTURES, "ca.pem")),
    [{'Certificate', Ca, not_encrypted}] = public_key:pem_decode(Pem),
    Configuration = http@client:with_ca_certificates(
        http@client:without_retries(http@client:defaults()), [Ca]),
    {ok, Client} = http@client:start(Configuration),
    try
        Small = <<"nghttp2-independent-server">>,
        Small = receive_response(Client, request(get, Port, <<"/small">>, http@body:empty()), 200),
        Large = large_body(),
        Large = receive_response(Client, request(get, Port, <<"/large">>, http@body:empty()), 200),
        Upload = http@body:from_bytes_with_trailers(Large,
            [{<<"x-upload-finished">>, <<"yes">>}]),
        Large = receive_response(Client, request(post, Port, <<"/echo">>, Upload), 200),
        _ = receive_response(Client, request(get, Port, <<"/missing">>, http@body:empty()), 404),
        io:put_chars("native client nghttp2 contract verified\n"),
        ok
    after
        {ok, nil} = http@client:close(Client)
    end.

request(Method, Port, Path, Body) ->
    {request, Method, [], Body, https, <<"localhost">>, {some, Port}, Path, none}.

receive_response(Client, Request, Status) ->
    {ok, Exchange} = http@client:exchange(Client, Request),
    http2 = http@client:selected_protocol(Exchange),
    {response, Status, _Headers, Body} = http@client:response(Exchange),
    {ok, {Bytes, Trailers}} = http@body:read_all(Body, ?MAX_BODY),
    true = lists:member({<<"x-response-finished">>, <<"yes">>}, Trailers),
    Bytes.

run_server(StopPath) ->
    {ok, Certificate} = file:read_file(filename:join(?FIXTURES, "server.pem")),
    {ok, PrivateKey} = file:read_file(filename:join(?FIXTURES, "server-key.pem")),
    {ok, Server} = http@server:start(http@server:defaults(), fun handle/2),
    try
        {ok, Listener} = http@server:listen_http2_tls(Server, <<127, 0, 0, 1>>, 0,
            http@server:http2_defaults(), Certificate, PrivateKey, <<"localhost">>),
        try
            {endpoint, _, Port} = http@server:listener_endpoint(Listener),
            io:format("PORT=~B~n", [Port]),
            ok = await_stop(StopPath, erlang:monotonic_time(millisecond) + 90000),
            {ok, nil} = http@server:drain_listener(Listener)
        after
            {ok, nil} = http@server:stop_listener(Listener)
        end
    after
        {ok, nil} = http@server:stop(Server)
    end,
    io:put_chars("native server nghttp2 contract verified\n").

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
        {ok, {Bytes, [{<<"x-upload-finished">>, <<"yes">>}]}} -> response(Bytes);
        _ -> erlang:error(request_trailers_not_received)
    end;
handle(_, _) -> erlang:error(unexpected_interop_request).

response(Bytes) ->
    Body = http@body:from_bytes_with_trailers(Bytes,
        [{<<"x-response-finished">>, <<"yes">>}]),
    {ok, {response, 200, [{<<"content-type">>, <<"application/octet-stream">>}], Body}}.

large_body() -> binary:copy(<<"nghttp2-flow-">>, 6000).
