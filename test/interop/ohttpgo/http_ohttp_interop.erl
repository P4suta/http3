%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Public http OHTTP/BHTTP APIs and authenticated HTTP only.
-module(http_ohttp_interop).
-define(INTEROP_NOTICE_READ_ONLY, true).
-export([run_client/3, run_server/1]).

-define(FIXTURES, "packages/http3/test/fixtures").
-define(MAX, 131072).
-include("../../interop_notice.hrl").

limits() -> {limits, ?MAX, 16, 4096, 70000, 8, 128}.
body() -> binary:copy(<<"ohttp-flow-">>, 6000).

new_client() ->
    {ok, Pem} = file:read_file(filename:join(?FIXTURES, "ca.pem")),
    [{'Certificate', Ca, not_encrypted}] = public_key:pem_decode(Pem),
    Configuration = http@client:with_ca_certificates(
        http@client:without_retries(http@client:defaults()), [Ca]),
    http@client:start(Configuration).

run_client(Port, ConfigPort, Algorithm) ->
    {ok, Client} = new_client(),
    try
        ConfigPath = case Port =:= ConfigPort of
            true -> <<"/config">>;
            false -> <<"/config/", (integer_to_binary(Algorithm))/binary>>
        end,
        {200, <<"application/ohttp-keys">>, ConfigBytes} =
            exchange(Client, get, ConfigPort, ConfigPath, <<>>, <<>>, []),
        {ok, [Configuration]} = http@ohttp:decode_key_configurations(ConfigBytes, 1),
        {key_configuration, 1, 16#20, _, [{symmetric_algorithm, 1, Algorithm}]} = Configuration,
        {ok, Ohttp} = http@ohttp:client(Configuration, limits(), ?MAX),
        Request = {request, <<"POST">>, <<"https">>, <<"target.example">>, <<"/submit">>,
            [{field, <<"x-request">>, <<"yes">>}], [body()],
            [{field, <<"x-request-finished">>, <<"yes">>}], 128},
        {ok, {Wire, Context}} = http@ohttp:seal_request(Ohttp, Request, known_length),
        Markers = [{<<"x-client-marker">>, <<"must-not-reach-gateway">>},
                   {<<"cookie">>, <<"private-fixture-marker">>}],
        {200, <<"message/ohttp-res">>, Encrypted} =
            exchange(Client, post, Port, <<"/gateway">>, <<"message/ohttp-req">>, Wire, Markers),
        {ok, {response, [], 201, [{field, <<"x-response">>, <<"yes">>}], [Body],
            [{field, <<"x-response-finished">>, <<"yes">>}], 0}} = http@ohttp:open_response(Context, Encrypted),
        Body = body(),
        Size = byte_size(Wire) - 1,
        <<Prefix:Size/binary, Last>> = Wire,
        Tampered = <<Prefix/binary, (Last bxor 1)>>,
        {400, _, <<>>} = exchange(Client, post, Port, <<"/gateway">>, <<"message/ohttp-req">>, Tampered, Markers),
        {415, _, <<>>} = exchange(Client, post, Port, <<"/gateway">>, <<"application/octet-stream">>, Tampered, Markers),
        io:put_chars("native OHTTP client contract verified\n")
    after
        {ok, nil} = http@client:close(Client)
    end.

exchange(Client, Method, Port, Path, Media, Bytes, Extra) ->
    Headers = case Media of <<>> -> Extra; _ -> [{<<"content-type">>, Media} | Extra] end,
    Request = {request, Method, Headers, http@body:from_bytes(Bytes),
        https, <<"localhost">>, {some, Port}, Path, none},
    {ok, Exchange} = http@client:exchange(Client, Request),
    {response, Status, ResponseHeaders, ResponseBody} = http@client:response(Exchange),
    {ok, {Content, []}} = http@body:read_all(ResponseBody, ?MAX),
    {Status, proplists:get_value(<<"content-type">>, ResponseHeaders, <<>>), Content}.

run_server(StopPath) ->
    {ok, Certificate} = file:read_file(filename:join(?FIXTURES, "server.pem")),
    {ok, PrivateKey} = file:read_file(filename:join(?FIXTURES, "server-key.pem")),
    Keys = [{Algorithm, key(Algorithm)} || Algorithm <- [1, 3]],
    {ok, Server} = http@server:start(http@server:defaults(), fun(Request, _) -> handle(Request, Keys) end),
    try
        {ok, Listener} = http@server:listen_http1_tls(Server, <<127, 0, 0, 1>>, 0,
            http@server:http1_defaults(), Certificate, PrivateKey, <<"localhost">>),
        try
            {endpoint, _, Port} = http@server:listener_endpoint(Listener),
            io:format("PORT=~B~n", [Port]),
            ok = await_stop(StopPath, erlang:monotonic_time(millisecond) + 110000),
            {ok, nil} = http@server:drain_listener(Listener)
        after
            {ok, nil} = http@server:stop_listener(Listener)
        end
    after
        {ok, nil} = http@server:stop(Server)
    end,
    io:put_chars("native OHTTP gateway and relay contract verified\n").

key(Algorithm) ->
    %% A fresh fixture key is never logged or retained in interoperability reports.
    {ok, Key} = http@ohttp:gateway_key(1, crypto:strong_rand_bytes(32), [{symmetric_algorithm, 1, Algorithm}]),
    Key.

handle({request, get, _, _, _, _, _, <<"/config/", Digit>>, _}, Keys) ->
    Key = proplists:get_value(Digit - $0, Keys),
    {ok, Configuration} = http@ohttp:encode_key_configurations([http@ohttp:key_configuration(Key)]),
    response(200, <<"application/ohttp-keys">>, Configuration);
handle({request, post, Headers, Body, _, _, _, <<"/relay/", Digit>>, _}, Keys) ->
    {ok, {Bytes, []}} = http@body:read_all(Body, ?MAX),
    {ok, Relay} = http@ohttp:relay(<<"https://gateway.example/ohttp">>, ?MAX),
    case http@ohttp:forward_request(Relay, proplists:get_value(<<"content-type">>, Headers, <<>>), Bytes) of
        {ok, {relay_forward, <<"https://gateway.example/ohttp">>, <<"message/ohttp-req">>, Bytes}} ->
            gateway_response(proplists:get_value(Digit - $0, Keys), Bytes);
        {error, invalid_media_type} -> response(415, <<>>, <<>>)
    end;
handle({request, post, Headers, Body, _, _, _, <<"/gateway/", Digit>>, _}, Keys) ->
    false = lists:keymember(<<"cookie">>, 1, Headers),
    false = lists:keymember(<<"x-client-marker">>, 1, Headers),
    {ok, {Bytes, []}} = http@body:read_all(Body, ?MAX),
    case proplists:get_value(<<"content-type">>, Headers, <<>>) of
        <<"message/ohttp-req">> -> gateway_response(proplists:get_value(Digit - $0, Keys), Bytes);
        _ -> response(415, <<>>, <<>>)
    end;
handle(_, _) -> erlang:error(unexpected_ohttp_interop_request).

gateway_response(Key, Bytes) ->
    {ok, Gateway} = http@ohttp:gateway(Key, [<<"target.example">>], limits(), ?MAX),
    {ok, ReplayStore} = http@ohttp:replay_store(4),
    case http@ohttp:open_request(Gateway, ReplayStore, Bytes) of
        {ok, {{request, <<"POST">>, <<"https">>, <<"target.example">>, <<"/submit">>,
            [{field, <<"x-request">>, <<"yes">>}], [Content],
            [{field, <<"x-request-finished">>, <<"yes">>}], Padding}, Context, _}} ->
            true = Padding =:= 0 orelse Padding =:= 128,
            Content = body(),
            Inner = {response, [], 201, [{field, <<"x-response">>, <<"yes">>}], [Content],
                [{field, <<"x-response-finished">>, <<"yes">>}], 0},
            {ok, Wire} = http@ohttp:seal_response(Context, Inner, known_length),
            {ok, Wire} = http@ohttp:forward_response(<<"message/ohttp-res">>, Wire, ?MAX),
            response(200, <<"message/ohttp-res">>, Wire);
        {error, decryption_failed} -> response(400, <<>>, <<>>)
    end.

response(Status, Media, Bytes) ->
    Headers = case Media of <<>> -> []; _ -> [{<<"content-type">>, Media}] end,
    {ok, {response, Status, Headers, http@body:from_bytes(Bytes)}}.

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
