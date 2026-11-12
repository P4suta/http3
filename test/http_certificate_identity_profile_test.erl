%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_certificate_identity_profile_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

-define(MAX_DOCUMENT_BYTES, 65536).
-define(MAX_SOURCE_BYTES, 1048576).

contracts() ->
    [{"current_public_profile", fun current_public_profile/0},
     {"removed_identifier_statement_is_rejected",
      fun removed_identifier_statement_is_rejected/0},
     {"removed_provider_mapping_is_rejected",
      fun removed_provider_mapping_is_rejected/0},
     {"removed_root_documentation_link_is_rejected",
      fun removed_root_documentation_link_is_rejected/0},
     {"removed_profile_documentation_link_is_rejected",
      fun removed_profile_documentation_link_is_rejected/0}].

current_public_profile() ->
    ?assert(valid_profile(inputs())).

removed_identifier_statement_is_rejected() ->
    Inputs = inputs(),
    Profile = maps:get(profile, Inputs),
    Marker = <<"SRV-ID and URI-ID are unsupported">>,
    Mutated = Inputs#{profile => binary:replace(Profile, Marker, <<>>)},
    ?assertNot(valid_profile(Mutated)).

removed_provider_mapping_is_rejected() ->
    Inputs = inputs(),
    QuicTls = maps:get(quic_tls, Inputs),
    Marker = <<"{dns_id, Host}">>,
    Mutated = Inputs#{quic_tls => binary:replace(QuicTls, Marker, <<>>)},
    ?assertNot(valid_profile(Mutated)).

removed_root_documentation_link_is_rejected() ->
    Inputs = inputs(),
    Document = maps:get(root_readme, Inputs),
    Mutated = Inputs#{root_readme => binary:replace(
        Document, <<"(docs/README.md)">>, <<>>)},
    ?assertNot(valid_profile(Mutated)).

removed_profile_documentation_link_is_rejected() ->
    Inputs = inputs(),
    Document = maps:get(documentation_index, Inputs),
    Mutated = Inputs#{documentation_index => binary:replace(
        Document, <<"(CERTIFICATE_IDENTITY.md)">>, <<>>)},
    ?assertNot(valid_profile(Mutated)).

inputs() ->
    #{profile => read_bounded("docs/CERTIFICATE_IDENTITY.md", ?MAX_DOCUMENT_BYTES),
      root_readme => read_bounded("README.md", ?MAX_DOCUMENT_BYTES),
      documentation_index => read_bounded("docs/README.md", ?MAX_DOCUMENT_BYTES),
      http3_readme => read_bounded("packages/http3/README.md", ?MAX_DOCUMENT_BYTES),
      quic_readme => read_bounded("packages/quic_core/README.md", ?MAX_DOCUMENT_BYTES),
      quic_client => read_bounded(
          "packages/quic_core/src/quic_core/client.gleam", ?MAX_SOURCE_BYTES),
      quic_tls => read_bounded(
          "packages/quic_core/src/quic_core_tls_ffi.erl", ?MAX_SOURCE_BYTES),
      tcp_tls => read_bounded("src/http_transport_ffi.erl", ?MAX_SOURCE_BYTES),
      http3_client => read_bounded(
          "packages/http3/src/http3/client.gleam", ?MAX_SOURCE_BYTES)}.

valid_profile(Inputs) ->
    all_present(maps:get(profile, Inputs),
        [<<"DNS-ID and IP-ID are mandatory to implement">>,
         <<"SRV-ID and URI-ID are unsupported">>,
         <<"authenticated origin and the connect target">>,
         <<"TLS SNI">>, <<"HTTP authority">>, <<"connection pool key">>,
         <<"resumption ticket">>, <<"whole left-most label">>,
         <<"Unicode U-label">>, <<"canonical ASCII A-label">>,
         <<"remains an open release gate">>])
    andalso readmes_publish_profile(Inputs)
    andalso all_present(maps:get(quic_client, Inputs),
        [<<"with_connect_address">>, <<"with_connect_port">>,
         <<"ticket_origin(handle) == #(client.hostname, client.port)">>])
    andalso all_present(maps:get(quic_tls, Inputs),
        [<<"verify_service_identity">>, <<"{ip, Address}">>,
         <<"{dns_id, Host}">>, <<"{cn, _CommonName}">>])
    andalso all_present(maps:get(tcp_tls, Inputs),
        [<<"server_name_indication">>,
         <<"pkix_verify_hostname_match_fun(https)">>])
    andalso all_present(maps:get(http3_client, Inputs),
        [<<"with_connect_address">>, <<"origin host, TLS SNI">>,
         <<"authority and resumption identity retain their original values">>]).

readmes_publish_profile(Inputs) ->
    Marker1 = <<"DNS-ID and IP-ID are mandatory to implement">>,
    Marker2 = <<"SRV-ID and URI-ID are unsupported">>,
    all_present(maps:get(root_readme, Inputs), [<<"(docs/README.md)">>])
    andalso all_present(maps:get(documentation_index, Inputs),
        [<<"(CERTIFICATE_IDENTITY.md)">>])
    andalso lists:all(fun(Document) -> all_present(Document, [Marker1, Marker2]) end,
        [maps:get(http3_readme, Inputs), maps:get(quic_readme, Inputs)]).

all_present(Bytes, Markers) ->
    lists:all(fun(Marker) -> binary:match(Bytes, Marker) =/= nomatch end, Markers).

read_bounded(Path, Maximum) ->
    {ok, Handle} = file:open(Path, [read, raw, binary]),
    try
        case file:read(Handle, Maximum + 1) of
            {ok, Bytes} when byte_size(Bytes) =< Maximum ->
                eof = file:read(Handle, 1),
                Bytes;
            _ ->
                error(profile_input_invalid)
        end
    after
        ok = file:close(Handle)
    end.
