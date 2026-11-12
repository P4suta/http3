%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_alpn_test_ffi).
-export([probe/4,credentials/1]).
-include_lib("public_key/include/public_key.hrl").

%% Ed25519 is used by the QUIC/TLS 1.3 matrix. TLS 1.2 needs a certificate
%% compatible with its selected cipher suite. Derive a distinct end-entity
%% certificate from the existing public ECDSA test CA: the trust anchor itself
%% is not an end-entity certificate accepted by OTP's TLS 1.2 validation path.
credentials(12) ->
    Root="packages/quic_core/test/fixtures/",
    {ok,Certificate}=file:read_file(Root++"ecdsa-p256-server.pem"),
    {ok,Key}=file:read_file(Root++"ecdsa-p256-server-key.pem"),
    [{'Certificate',Der,not_encrypted}]=public_key:pem_decode(Certificate),
    [PemKey]=public_key:pem_decode(Key),
    SigningKey=public_key:pem_entry_decode(PemKey),
    #'OTPCertificate'{tbsCertificate=CaTbs}=public_key:pkix_decode_cert(Der,otp),
    LeafTbs=CaTbs#'OTPTBSCertificate'{
        serialNumber=CaTbs#'OTPTBSCertificate'.serialNumber+1,
        subject={rdnSequence,[[#'AttributeTypeAndValue'{
            type=?'id-at-commonName',value={utf8String,<<"localhost">>}}]]},
        extensions=[leaf_extension(Extension)
            || Extension <- CaTbs#'OTPTBSCertificate'.extensions]},
    Leaf=public_key:pkix_sign(LeafTbs,SigningKey),
    {public_key:pem_encode([{'Certificate',Leaf,not_encrypted}]),Key,Der};
credentials(13) -> http_test_ffi:server_credentials().

leaf_extension(Extension=#'Extension'{extnID=?'id-ce-basicConstraints'}) ->
    Extension#'Extension'{extnValue=#'BasicConstraints'{cA=false}};
leaf_extension(Extension=#'Extension'{extnID=?'id-ce-keyUsage'}) ->
    Extension#'Extension'{extnValue=[digitalSignature]};
leaf_extension(Extension) -> Extension.

%% An independent TLS peer deliberately omits the ALPN extension. Only the
%% fixed outcome code crosses this fixture boundary; TLS terms never do.
probe(Port, Ca, Protocols, Version) ->
    {ok,_}=application:ensure_all_started(ssl),
    Deadline=erlang:monotonic_time(millisecond)+10000,
    Alpn=case Protocols of []->[];_->[{alpn_advertised_protocols,Protocols}] end,
    Options=[{verify,verify_peer},{cacerts,[Ca]},
        {server_name_indication,"localhost"},
        {customize_hostname_check,[{match_fun,public_key:pkix_verify_hostname_match_fun(https)}]},
        {versions,[case Version of 12->'tlsv1.2';13->'tlsv1.3' end]},
        {log_level,none},{active,false},binary|Alpn],
    try ssl:connect({127,0,0,1},Port,Options,remaining(Deadline)) of
        {error,Failure}->connect_failure(Failure);
        {ok,Socket}->
            try
                case {Protocols,ssl:negotiated_protocol(Socket)} of
                    {[],{error,protocol_not_negotiated}}->exchange(Socket,Deadline);
                    {[<<"http/1.1">>],{ok,<<"http/1.1">>}}->exchange(Socket,Deadline);
                    _->6
                end
            after ssl:close(Socket) end
    catch _:_ ->7 end.

connect_failure({tls_alert,{no_application_protocol,_}})->8;
connect_failure({tls_alert,{handshake_failure,_}})->9;
connect_failure({tls_alert,{unknown_ca,_}})->10;
connect_failure({tls_alert,{certificate_expired,_}})->13;
connect_failure({tls_alert,{unsupported_certificate,_}})->14;
connect_failure({tls_alert,{bad_certificate,_}})->15;
connect_failure({tls_alert,{decode_error,_}})->16;
connect_failure({tls_alert,{illegal_parameter,_}})->17;
connect_failure({tls_alert,{decrypt_error,_}})->18;
connect_failure({tls_alert,{insufficient_security,_}})->19;
connect_failure({tls_alert,{_,_}})->20;
connect_failure({options,_})->21;
connect_failure(closed)->11;
connect_failure(timeout)->12;
connect_failure(_)->1.

exchange(Socket,Deadline)->
    case ssl:send(Socket,<<"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n">>) of
        ok->read(Socket,Deadline,<<>>);
        {error,_}->2
    end.
read(Socket,Deadline,Buffer) when byte_size(Buffer)=<4096 ->
    case binary:match(Buffer,<<"\r\n\r\n">>) of
        {_,_}->case Buffer of <<"HTTP/1.1 204 ",_/binary>>->0;_->5 end;
        nomatch->case ssl:recv(Socket,0,remaining(Deadline)) of
            {ok,Bytes} when byte_size(Buffer)+byte_size(Bytes)=<4096 ->
                read(Socket,Deadline,<<Buffer/binary,Bytes/binary>>);
            {ok,_}->5;
            {error,timeout}->4;
            {error,_}->3
        end
    end.
remaining(Deadline)->max(0,Deadline-erlang:monotonic_time(millisecond)).
