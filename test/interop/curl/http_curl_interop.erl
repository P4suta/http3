%% An independent-peer interoperability endpoint for curl.
%%
%% This module owns no protocol logic. It starts the package's own HTTP/1.1 and
%% HTTP/2 TLS listeners through their public API, publishes the ports it was
%% given, and answers a fixed set of routes so that an external client can be
%% the one deciding whether the wire behaviour is correct.
-module(http_curl_interop).

-export([run/2]).

%% The listeners hold one request body at a time and the harness sends kilobytes,
%% so a fixed 64 KiB ceiling is far above the workload and still finite.
-define(BODY_LIMIT, 65536).
%% An abandoned harness must not leave a listening endpoint behind.
-define(LIFETIME_MILLISECONDS, 120000).

-define(FIXTURES, "packages/http3/test/fixtures").

run(Http1Port, Http2Port) ->
    {ok, Certificate} = file:read_file(filename:join(?FIXTURES, "server.pem")),
    {ok, PrivateKey} = file:read_file(filename:join(?FIXTURES, "server-key.pem")),
    Multiplex = spawn_link(fun multiplex_barrier/0),
    {ok, Server} = http@server:start(http@server:defaults(),
        fun(Request, Context) -> handle(Request, Context, Multiplex) end),
    {ok, Http1} = http@server:listen_http1_tls(
        Server,
        <<127, 0, 0, 1>>,
        Http1Port,
        http@server:http1_defaults(),
        Certificate,
        PrivateKey,
        <<"localhost">>
    ),
    {ok, Http2} = http@server:listen_http2_tls(
        Server,
        <<127, 0, 0, 1>>,
        Http2Port,
        http@server:http2_defaults(),
        Certificate,
        PrivateKey,
        <<"localhost">>
    ),
    {endpoint, _, BoundHttp1} = http@server:listener_endpoint(Http1),
    {endpoint, _, BoundHttp2} = http@server:listener_endpoint(Http2),
    io:format("h1_port=~B~n", [BoundHttp1]),
    io:format("h2_port=~B~n", [BoundHttp2]),
    io:format("ready=1~n"),
    receive
    after ?LIFETIME_MILLISECONDS -> ok
    end.

handle(Request, Context, Multiplex) ->
    {request, Method, _Headers, Body, _Scheme, _Host, _Port, Path, _Query} =
        Request,
    case {Method, Path} of
        {get, <<"/hello">>} -> text(200, <<"curl-interop">>);
        {head, <<"/hello">>} -> text(200, <<"curl-interop">>);
        {get, <<"/teapot">>} -> text(418, <<"teapot">>);
        {post, <<"/echo">>} -> echo(Body);
        {get, <<"/multiplex">>} ->
            case http@context:protocol(Context) of
                http2 ->
                    Multiplex ! {await, self(), http@context:peer_endpoint(Context)},
                    receive overlap_ready -> text(200, <<"overlap-verified">>)
                    after 5000 -> text(500, <<"overlap-not-observed">>)
                    end;
                _ -> text(400, <<"requires-http2">>)
            end;
        _ -> text(404, <<"not found">>)
    end.

%% Both handlers must be live on the same TCP connection before either can
%% return. Two sequential URLs, or two independent sockets, cannot satisfy it.
multiplex_barrier() ->
    receive
        {await, First, Peer} ->
            receive
                {await, Second, Peer} when First =/= Second ->
                    First ! overlap_ready,
                    Second ! overlap_ready
            after 5000 -> ok
            end
    after ?LIFETIME_MILLISECONDS -> ok
    end.

echo(Body) ->
    case http@body:read_all(Body, ?BODY_LIMIT) of
        {ok, {Bytes, _Trailers}} -> text(200, Bytes);
        {error, _} -> text(413, <<"too large">>)
    end.

text(Status, Bytes) ->
    Headers = [
        {<<"content-type">>, <<"text/plain; charset=utf-8">>},
        {<<"x-interop-peer">>, <<"http-curl-interop">>}
    ],
    {ok, {response, Status, Headers, http@body:from_bytes(Bytes)}}.
