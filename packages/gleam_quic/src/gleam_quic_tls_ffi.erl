-module(gleam_quic_tls_ffi).

-export([
    certificate_chain_from_pem/1,
    constant_time_equal/2,
    is_ip_address/1,
    sign/3,
    signing_key_from_pem/1,
    signing_key_scheme/1,
    system_trust_store/0,
    trust_store_from_der/1,
    trust_store_from_pem/1,
    validate_server_certificate/3,
    verify/4
]).

-spec is_ip_address(binary()) -> boolean().
is_ip_address(Hostname) when is_binary(Hostname) ->
    case inet:parse_address(binary_to_list(Hostname)) of
        {ok, _Address} -> true;
        {error, _Reason} -> false
    end;
is_ip_address(_Hostname) ->
    false.

-define(ID_ED25519, {1, 3, 101, 112}).
-define(ID_ED448, {1, 3, 101, 113}).
-define(ID_EC_PUBLIC_KEY, {1, 2, 840, 10045, 2, 1}).
-define(ID_RSA_ENCRYPTION, {1, 2, 840, 113549, 1, 1, 1}).
-define(ID_RSA_PSS, {1, 2, 840, 113549, 1, 1, 10}).
-define(SECP256R1, {1, 2, 840, 10045, 3, 1, 7}).
-define(SECP384R1, {1, 3, 132, 0, 34}).
-define(SECP521R1, {1, 3, 132, 0, 35}).

-spec trust_store_from_pem(binary()) -> {ok, tuple()} | {error, 2 | 3}.
trust_store_from_pem(Pem) when is_binary(Pem) ->
    case decode_pem_certificates(Pem) of
        {ok, Certificates} -> {ok, {gleam_quic_trust_store, Certificates}};
        Error -> Error
    end;
trust_store_from_pem(_Pem) ->
    {error, 3}.

-spec trust_store_from_der([binary()]) -> {ok, tuple()} | {error, 2 | 3}.
trust_store_from_der(Certificates) when is_list(Certificates), Certificates =/= [] ->
    case ensure_public_key() of
        ok ->
            try
                lists:foreach(
                    fun(Der) when is_binary(Der) ->
                        public_key:pkix_decode_cert(Der, otp)
                    end,
                    Certificates
                ),
                {ok, {gleam_quic_trust_store, Certificates}}
            catch
                _Class:_Reason -> {error, 3}
            end;
        error ->
            {error, 2}
    end;
trust_store_from_der(_Certificates) ->
    {error, 3}.

-spec system_trust_store() -> {ok, tuple()} | {error, 2 | 3}.
system_trust_store() ->
    case ensure_public_key() of
        ok ->
            try public_key:cacerts_get() of
                [] -> {error, 3};
                Certificates when is_list(Certificates) ->
                    {ok, {gleam_quic_trust_store, Certificates}}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end.

-spec certificate_chain_from_pem(binary()) ->
    {ok, [binary()]} | {error, 2 | 3}.
certificate_chain_from_pem(Pem) when is_binary(Pem) ->
    decode_pem_certificates(Pem);
certificate_chain_from_pem(_Pem) ->
    {error, 3}.

-spec validate_server_certificate([binary()], tuple(), binary()) ->
    {ok, tuple()} | {error, 1 | 2 | 3 | 5 | 6}.
validate_server_certificate(
    CertificateChain,
    {gleam_quic_trust_store, TrustAnchors},
    Hostname
) when is_list(CertificateChain), CertificateChain =/= [],
       is_list(TrustAnchors), TrustAnchors =/= [],
       is_binary(Hostname), byte_size(Hostname) > 0 ->
    case ensure_public_key() of
        ok -> validate_chain_and_identity(CertificateChain, TrustAnchors, Hostname);
        error -> {error, 2}
    end;
validate_server_certificate(_CertificateChain, _TrustStore, _Hostname) ->
    {error, 1}.

-spec signing_key_from_pem(binary()) -> {ok, tuple()} | {error, 2 | 3}.
signing_key_from_pem(Pem) when is_binary(Pem) ->
    case ensure_public_key() of
        ok ->
            try private_key_entries(public_key:pem_decode(Pem)) of
                [Entry] -> {ok, {gleam_quic_signing_key, public_key:pem_entry_decode(Entry)}};
                _Entries -> {error, 3}
            catch
                _Class:_Reason -> {error, 3}
            end;
        error ->
            {error, 2}
    end;
signing_key_from_pem(_Pem) ->
    {error, 3}.

-spec signing_key_scheme(tuple()) -> {ok, integer()} | {error, 1 | 8}.
signing_key_scheme({gleam_quic_signing_key, Key}) ->
    case private_key_scheme(Key) of
        {ok, Scheme} -> {ok, Scheme};
        error -> {error, 8}
    end;
signing_key_scheme(_Key) ->
    {error, 1}.

-spec sign(tuple(), integer(), binary()) -> {ok, binary()} | {error, 1 | 2 | 8}.
sign({gleam_quic_signing_key, Key}, Scheme, Content)
    when is_integer(Scheme), is_binary(Content) ->
    case signature_parameters(Scheme) of
        {ok, Digest, Options} ->
            case ensure_public_key() of
                ok ->
                    try public_key:sign(Content, Digest, Key, Options) of
                        Signature when is_binary(Signature), byte_size(Signature) > 0 ->
                            {ok, Signature};
                        _Other ->
                            {error, 8}
                    catch
                        _Class:_Reason -> {error, 8}
                    end;
                error ->
                    {error, 2}
            end;
        error ->
            {error, 8}
    end;
sign(_Key, _Scheme, _Content) ->
    {error, 1}.

-spec verify(tuple(), integer(), binary(), binary()) ->
    {ok, nil} | {error, 1 | 2 | 7 | 8}.
verify(
    {gleam_quic_verified_peer, _LeafCertificate, PublicKeyInfo},
    Scheme,
    Content,
    Signature
) when is_integer(Scheme), is_binary(Content), is_binary(Signature),
       byte_size(Signature) > 0 ->
    case verification_parameters(Scheme, PublicKeyInfo) of
        {ok, Digest, PublicKey, Options} ->
            case ensure_public_key() of
                ok ->
                    try public_key:verify(Content, Digest, Signature, PublicKey, Options) of
                        true -> {ok, nil};
                        false -> {error, 7}
                    catch
                        _Class:_Reason -> {error, 7}
                    end;
                error ->
                    {error, 2}
            end;
        error ->
            {error, 8}
    end;
verify(_Peer, _Scheme, _Content, _Signature) ->
    {error, 1}.

-spec constant_time_equal(binary(), binary()) -> {ok, boolean()} | {error, 1 | 2}.
constant_time_equal(Left, Right) when is_binary(Left), is_binary(Right) ->
    case byte_size(Left) =:= byte_size(Right) of
        false -> {ok, false};
        true ->
            case application:ensure_all_started(crypto) of
                {ok, _Applications} ->
                    try crypto:hash_equals(Left, Right) of
                        Equal when is_boolean(Equal) -> {ok, Equal}
                    catch
                        _Class:_Reason -> {error, 2}
                    end;
                {error, _Reason} ->
                    {error, 2}
            end
    end;
constant_time_equal(_Left, _Right) ->
    {error, 1}.

-spec decode_pem_certificates(binary()) -> {ok, [binary()]} | {error, 2 | 3}.
decode_pem_certificates(Pem) ->
    case ensure_public_key() of
        ok ->
            try
                Certificates = [
                    Der
                 || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem),
                    is_binary(Der)
                ],
                case Certificates of
                    [] -> {error, 3};
                    _ ->
                        lists:foreach(
                            fun(Der) -> public_key:pkix_decode_cert(Der, otp) end,
                            Certificates
                        ),
                        {ok, Certificates}
                end
            catch
                _Class:_Reason -> {error, 3}
            end;
        error ->
            {error, 2}
    end.

-spec validate_chain_and_identity([binary()], [binary()], binary()) ->
    {ok, tuple()} | {error, 3 | 5 | 6}.
validate_chain_and_identity(CertificateChain, TrustAnchors, Hostname) ->
    try
        lists:foreach(
            fun(Der) -> public_key:pkix_decode_cert(Der, otp) end,
            CertificateChain
        ),
        LeafDer = hd(CertificateChain),
        Leaf = public_key:pkix_decode_cert(LeafDer, otp),
        case find_valid_path(TrustAnchors, CertificateChain) of
            {ok, PublicKeyInfo} ->
                case verify_service_identity(Leaf, Hostname) of
                    true -> {ok, {gleam_quic_verified_peer, Leaf, PublicKeyInfo}};
                    false -> {error, 6}
                end;
            error ->
                {error, 5}
        end
    catch
        _Class:_Reason -> {error, 3}
    end.

-spec find_valid_path([binary()], [binary()]) -> {ok, tuple()} | error.
find_valid_path([], _CertificateChain) ->
    error;
find_valid_path([TrustAnchor | Rest], CertificateChain) ->
    Chain = trim_trust_anchor(CertificateChain, TrustAnchor),
    case public_key:pkix_path_validation(TrustAnchor, Chain, []) of
        {ok, {PublicKeyInfo, _PolicyTree}} -> {ok, PublicKeyInfo};
        {error, _Reason} -> find_valid_path(Rest, CertificateChain)
    end.

-spec trim_trust_anchor([binary()], binary()) -> [binary()].
trim_trust_anchor(CertificateChain, TrustAnchor) ->
    case lists:last(CertificateChain) =:= TrustAnchor of
        true -> lists:droplast(CertificateChain);
        false -> CertificateChain
    end.

-spec verify_service_identity(tuple(), binary()) -> boolean().
verify_service_identity(Leaf, Hostname) ->
    Host = binary_to_list(Hostname),
    ReferenceId = case inet:parse_address(Host) of
        {ok, Address} -> {ip, Address};
        {error, einval} -> {dns_id, Host}
    end,
    NoCommonNameFallback = fun
        (_Reference, {cn, _CommonName}) -> false;
        (_Reference, _Presented) -> default
    end,
    public_key:pkix_verify_hostname(
        Leaf,
        [ReferenceId],
        [{match_fun, NoCommonNameFallback}]
    ).

-spec private_key_entries([tuple()]) -> [tuple()].
private_key_entries(Entries) ->
    [
        Entry
     || Entry <- Entries,
        is_private_key_entry(Entry)
    ].

-spec is_private_key_entry(tuple()) -> boolean().
is_private_key_entry({'PrivateKeyInfo', _Der, not_encrypted}) -> true;
is_private_key_entry({'OneAsymmetricKey', _Der, not_encrypted}) -> true;
is_private_key_entry({'ECPrivateKey', _Der, not_encrypted}) -> true;
is_private_key_entry({'RSAPrivateKey', _Der, not_encrypted}) -> true;
is_private_key_entry(_Entry) -> false.

-spec private_key_scheme(term()) -> {ok, integer()} | error.
private_key_scheme({'ECPrivateKey', _Version, _Private, {namedCurve, ?ID_ED25519}, _Public, _Attrs}) ->
    {ok, 16#0807};
private_key_scheme({'ECPrivateKey', _Version, _Private, {namedCurve, ?ID_ED448}, _Public, _Attrs}) ->
    {ok, 16#0808};
private_key_scheme({'ECPrivateKey', _Version, _Private, {namedCurve, ?SECP256R1}, _Public, _Attrs}) ->
    {ok, 16#0403};
private_key_scheme({'ECPrivateKey', _Version, _Private, {namedCurve, ?SECP384R1}, _Public, _Attrs}) ->
    {ok, 16#0503};
private_key_scheme({'ECPrivateKey', _Version, _Private, {namedCurve, ?SECP521R1}, _Public, _Attrs}) ->
    {ok, 16#0603};
private_key_scheme({'RSAPrivateKey', _Version, _Modulus, _PublicExponent, _PrivateExponent,
                    _Prime1, _Prime2, _Exponent1, _Exponent2, _Coefficient, _OtherPrimeInfos}) ->
    {ok, 16#0804};
private_key_scheme(_Key) ->
    error.

-spec verification_parameters(integer(), tuple()) ->
    {ok, atom(), term(), list()} | error.
verification_parameters(Scheme, {Oid, Key, Parameters}) ->
    case scheme_matches_key(Scheme, Oid, Parameters) of
        true ->
            case signature_parameters(Scheme) of
                {ok, Digest, Options} ->
                    {ok, Digest, public_key_value(Oid, Key, Parameters), Options};
                error -> error
            end;
        false ->
            error
    end;
verification_parameters(_Scheme, _PublicKeyInfo) ->
    error.

-spec signature_parameters(integer()) -> {ok, atom(), list()} | error.
signature_parameters(16#0403) -> {ok, sha256, []};
signature_parameters(16#0503) -> {ok, sha384, []};
signature_parameters(16#0603) -> {ok, sha512, []};
signature_parameters(16#0804) -> {ok, sha256, rsa_pss_options(sha256, 32)};
signature_parameters(16#0805) -> {ok, sha384, rsa_pss_options(sha384, 48)};
signature_parameters(16#0806) -> {ok, sha512, rsa_pss_options(sha512, 64)};
signature_parameters(16#0807) -> {ok, none, []};
signature_parameters(16#0808) -> {ok, none, []};
signature_parameters(16#0809) -> {ok, sha256, rsa_pss_options(sha256, 32)};
signature_parameters(16#080A) -> {ok, sha384, rsa_pss_options(sha384, 48)};
signature_parameters(16#080B) -> {ok, sha512, rsa_pss_options(sha512, 64)};
signature_parameters(_Scheme) -> error.

-spec rsa_pss_options(atom(), integer()) -> list().
rsa_pss_options(Digest, SaltLength) ->
    [
        {rsa_padding, rsa_pkcs1_pss_padding},
        {rsa_pss_saltlen, SaltLength},
        {rsa_mgf1_md, Digest}
    ].

-spec scheme_matches_key(integer(), tuple(), term()) -> boolean().
scheme_matches_key(16#0403, ?ID_EC_PUBLIC_KEY, {namedCurve, ?SECP256R1}) -> true;
scheme_matches_key(16#0503, ?ID_EC_PUBLIC_KEY, {namedCurve, ?SECP384R1}) -> true;
scheme_matches_key(16#0603, ?ID_EC_PUBLIC_KEY, {namedCurve, ?SECP521R1}) -> true;
scheme_matches_key(Scheme, ?ID_RSA_ENCRYPTION, _Parameters)
    when Scheme >= 16#0804, Scheme =< 16#0806 -> true;
scheme_matches_key(Scheme, ?ID_RSA_PSS, _Parameters)
    when Scheme >= 16#0809, Scheme =< 16#080B -> true;
scheme_matches_key(16#0807, ?ID_ED25519, _Parameters) -> true;
scheme_matches_key(16#0808, ?ID_ED448, _Parameters) -> true;
scheme_matches_key(_Scheme, _Oid, _Parameters) -> false.

-spec public_key_value(tuple(), term(), term()) -> term().
public_key_value(?ID_RSA_ENCRYPTION, Key, _Parameters) -> Key;
public_key_value(_Oid, Key, Parameters) -> {Key, Parameters}.

-spec ensure_public_key() -> ok | error.
ensure_public_key() ->
    case application:ensure_all_started(public_key) of
        {ok, _Applications} -> ok;
        {error, _Reason} -> error
    end.
