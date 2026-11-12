-module(quic_core_tls_policy_tests).

-include_lib("eunit/include/eunit.hrl").

rsa_server_certificate_modulus_boundary_test() ->
    Weak = certificate_chain("weak-rsa1024-server.pem"),
    Accepted = certificate_chain("rsa-pss-server.pem"),
    Ed25519 = certificate_chain("server.pem"),
    ?assertEqual(
        {ok, false},
        quic_core_tls_ffi:server_certificate_public_key_secure(Weak)
    ),
    ?assertEqual(
        {ok, true},
        quic_core_tls_ffi:server_certificate_public_key_secure(Accepted)
    ),
    ?assertEqual(
        {ok, true},
        quic_core_tls_ffi:server_certificate_public_key_secure(Ed25519)
    ),
    ?assertEqual(
        {error, 1},
        quic_core_tls_ffi:server_certificate_public_key_secure([])
    ).

certificate_chain(Name) ->
    Path = filename:join(["test", "fixtures", Name]),
    {ok, Pem} = file:read_file(Path),
    {ok, Chain} = quic_core_tls_ffi:certificate_chain_from_pem(Pem),
    Chain.
