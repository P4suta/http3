%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% The browser supplies an independent HTTP client; these are public server APIs.
-module(http_browser_interop).
-export([run/3, run/5]).
-include_lib("public_key/include/public_key.hrl").
-include("../../interop_notice.hrl").

run(Protocol,ReadyPath,StopPath) ->
    case perform(Protocol,ReadyPath,StopPath) of
        {ok,_}->ok;
        _->{error,browser_fixture}
    end.

run(Protocol,ReadyPath,StopPath,ResultPath,Nonce)
  when is_binary(Nonce),byte_size(Nonce)=:=32 ->
    true=lists:all(fun(Byte)->
        (Byte>=$0 andalso Byte=<$9) orelse (Byte>=$a andalso Byte=<$f)
    end,binary_to_list(Nonce)),
    Outcome=perform(Protocol,ReadyPath,StopPath),
    case Outcome of
        {ok,Record}->
            ok=file:write_file(ResultPath,json:encode(Record#{schema=>1,nonce=>Nonce}),[exclusive]),
            ok;
        {error,Phase}->
            ok=file:write_file(ResultPath,json:encode(#{schema=>1,nonce=>Nonce,failure_phase=>Phase}),[exclusive]),
            {error,browser_fixture}
    end.

perform(Protocol,ReadyPath,StopPath) ->
    try
        put(browser_phase,1),
        {Certificate,Key}=credentials(),
        Counts=atomics:new(8,[]),Owner=self(),
        {ok,Server}=http@server:start(http@server:defaults(),
            fun(Request,Context)->handle(Request,Context,Counts,Owner) end),
        try
            put(browser_phase,2),
            {ok,Listener}=listen(Server,Protocol,Certificate,Key),
            try
                put(browser_phase,3),
                {endpoint,_,Port}=http@server:listener_endpoint(Listener),
                ok=interop_publish_notice(ReadyPath,iolist_to_binary(json:encode(#{port=>Port}))),
                {Mode,PullDown}=await_stop(StopPath,Counts,none,false,
                    erlang:monotonic_time(millisecond)+40000),
                put(browser_phase,4),
                Record=observations(Protocol,Counts,PullDown),
                ok=validate_work(Mode,Record),
                {ok,nil}=http@server:drain_listener(Listener),
                {ok,Record#{stopped=>true}}
            after {ok,nil}=http@server:stop_listener(Listener) end
        after {ok,nil}=http@server:stop(Server) end
    catch _:_ -> {error,get(browser_phase)}
    after erase(browser_phase) end.

%% NSS rejects the Ed25519 fixture CA. Keep normal browser verification and
%% issue a distinct end-entity certificate from the existing ECDSA test CA.
credentials() ->
    Root="packages/quic_core/test/fixtures/",
    {ok,Certificate}=file:read_file(Root++"ecdsa-p256-server.pem"),
    {ok,Key}=file:read_file(Root++"ecdsa-p256-server-key.pem"),
    [{'Certificate',Der,not_encrypted}]=public_key:pem_decode(Certificate),
    [PemKey]=public_key:pem_decode(Key),
    SigningKey=public_key:pem_entry_decode(PemKey),
    #'OTPCertificate'{tbsCertificate=CaTbs}=public_key:pkix_decode_cert(Der,otp),
    LeafTbs=CaTbs#'OTPTBSCertificate'{
        serialNumber=CaTbs#'OTPTBSCertificate'.serialNumber+2,
        subject={rdnSequence,[[#'AttributeTypeAndValue'{
            type=?'id-at-commonName',value={utf8String,<<"localhost">>}}]]},
        extensions=[leaf_extension(Extension)
            || Extension <- CaTbs#'OTPTBSCertificate'.extensions]},
    Leaf=public_key:pkix_sign(LeafTbs,SigningKey),
    {public_key:pem_encode([{'Certificate',Leaf,not_encrypted}]),Key}.

leaf_extension(Extension=#'Extension'{extnID=?'id-ce-basicConstraints'}) ->
    Extension#'Extension'{extnValue=#'BasicConstraints'{cA=false}};
leaf_extension(Extension=#'Extension'{extnID=?'id-ce-keyUsage'}) ->
    Extension#'Extension'{extnValue=[digitalSignature]};
leaf_extension(Extension) -> Extension.

listen(Server,1,Certificate,Key) ->
    http@server:listen_http1_tls(Server,<<127,0,0,1>>,0,http@server:http1_defaults(),Certificate,Key,<<"localhost">>);
listen(Server,2,Certificate,Key) ->
    http@server:listen_http2_tls(Server,<<127,0,0,1>>,0,http@server:http2_defaults(),Certificate,Key,<<"localhost">>);
listen(Server,3,Certificate,Key) ->
    {ok,Configuration}=http@server:http3_defaults(Certificate,Key,<<"localhost">>),
    http@server:listen_http3(Server,<<127,0,0,1>>,0,Configuration).

handle({request,get,_,_,_,_,_,<<"/">>,_},_,Counts,_) ->
    count(Counts,1),
    reply(200,<<"text/html; charset=utf-8">>,<<"<!doctype html><meta charset=utf-8><link rel=icon href=data:,><title>HTTP browser contract</title>">>);
handle({request,get,_,_,_,_,_,<<"/body">>,_},_,Counts,_) ->
    count(Counts,2),
    Bytes=binary:copy(<<"browser-protocol-">>,4250),
    {ok,Body}=http@body:from_pull(byte_source(Bytes,Counts),{some,byte_size(Bytes)},none,
        fun()->count(Counts,5),nil end),
    response(201,<<"application/octet-stream">>,Body);
handle({request,get,_,_,_,_,_,<<"/abort">>,_},_,Counts,Owner) ->
    count(Counts,6),
    Next=http@body:pull(fun(_)->
        Owner!{browser_abort_pull,self()},
        count(Counts,7),
        receive after 20000->{error,http@error:new({timeout,operation})} end
    end),
    First=http@body:pull(fun(_)->{ok,{pull_data,binary:copy(<<16#5a>>,64),Next}} end),
    {ok,Body}=http@body:from_pull(First,none,none,
        fun()->count(Counts,8),nil end),
    response(200,<<"application/octet-stream">>,Body);
handle({request,get,_,_,_,_,_,<<"/abort-ready">>,_},_,Counts,_) ->
    ok=await_pull(Counts,erlang:monotonic_time(millisecond)+2000),
    reply(204,<<"text/plain">>,<<>>);
handle(_,_,_,_) -> reply(404,<<"text/plain">>,<<>>).

byte_source(<<>>,Counts)->http@body:pull(fun(_)->count(Counts,4),{ok,{pull_end,[]}} end);
byte_source(Bytes,Counts)->http@body:pull(fun(Maximum)->
    Size=min(Maximum,byte_size(Bytes)),
    <<Chunk:Size/binary,Rest/binary>>=Bytes,
    Total=atomics:add_get(Counts,3,Size),true=Total=<72250,
    {ok,{pull_data,Chunk,byte_source(Rest,Counts)}}
end).

count(Counts,Index)->true=atomics:add_get(Counts,Index,1)=<16,ok.

await_pull(Counts,Deadline)->
    case atomics:get(Counts,7) of
        1->ok;
        0->true=erlang:monotonic_time(millisecond)<Deadline,
           receive after 5->await_pull(Counts,Deadline) end;
        _->error(unexpected_pull_count)
    end.

reply(Status,Media,Bytes) ->
    response(Status,Media,http@body:from_bytes(Bytes)).

response(Status,Media,Body) ->
    {ok,{response,Status,[{<<"content-type">>,Media},{<<"cache-control">>,<<"no-store">>}],Body}}.

await_stop(Path,Counts,Monitor,Down,Deadline) ->
    true=erlang:monotonic_time(millisecond)<Deadline,
    receive
        {browser_abort_pull,Pid} when Monitor=:=none->
            await_stop(Path,Counts,monitor(process,Pid),Down,Deadline);
        {'DOWN',Monitor,process,_,_} when Monitor=/=none->
            await_stop(Path,Counts,Monitor,true,Deadline)
    after 10->check_stop(Path,Counts,Monitor,Down,Deadline)
    end.

check_stop(Path,Counts,Monitor,Down,Deadline) ->
    case read_stop(Path) of
        {ok,<<"untrusted-complete">>}->{untrusted,Down};
        {ok,<<"trusted-complete">>} when Down->
            case atomics:get(Counts,5)=:=1 andalso atomics:get(Counts,8)=:=1 of
                true->{trusted,Down};
                false->await_stop(Path,Counts,Monitor,Down,Deadline)
            end;
        {ok,<<"trusted-complete">>}->await_stop(Path,Counts,Monitor,Down,Deadline);
        {error,enoent}->await_stop(Path,Counts,Monitor,Down,Deadline);
        _ -> error(completion)
    end.

read_stop(Path)->
    interop_read_notice(Path,32).

observations(Protocol,Counts,Down)->
    #{protocol=>Protocol,document_requests=>atomics:get(Counts,1),
      body_requests=>atomics:get(Counts,2),body_bytes_pulled=>atomics:get(Counts,3),
      body_eof=>atomics:get(Counts,4),body_cleanup=>atomics:get(Counts,5),
      abort_requests=>atomics:get(Counts,6),abort_source_entered=>atomics:get(Counts,7),
      abort_source_cancelled=>atomics:get(Counts,8),abort_pull_down=>Down}.

validate_work(untrusted,Record)->
    false=maps:get(abort_pull_down,Record),
    true=lists:all(fun(Key)->maps:get(Key,Record)=:=0 end,
        [document_requests,body_requests,body_bytes_pulled,body_eof,body_cleanup,
         abort_requests,abort_source_entered,abort_source_cancelled]),ok;
validate_work(trusted,Record)->
    #{document_requests:=1,body_requests:=1,body_bytes_pulled:=72250,body_eof:=1,
      body_cleanup:=1,abort_requests:=1,abort_source_entered:=1,
      abort_source_cancelled:=1,abort_pull_down:=true}=Record,ok.
