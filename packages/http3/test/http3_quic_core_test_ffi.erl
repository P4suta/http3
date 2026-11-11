-module(http3_quic_core_test_ffi).

-export([fixture/1, without_system_roots/1]).

%% Isolate the real OS-root loader for one sequential contract and restore its
%% application configuration and previously cached anchors even after failure.
-spec without_system_roots(fun(() -> A)) -> A.
without_system_roots(Run) ->
    {ok, _} = application:ensure_all_started(public_key),
    PreviousPath = application:get_env(public_key, cacerts_path),
    PreviousCache = persistent_term:get(pubkey_os_cacerts, not_loaded),
    Missing = filename:join(filename:dirname(code:which(?MODULE)),
        "missing-system-roots-" ++ integer_to_list(erlang:unique_integer([positive]))),
    false = filelib:is_file(Missing),
    ok = application:set_env(public_key, cacerts_path, Missing),
    _ = public_key:cacerts_clear(),
    try
        case quic_core_tls_ffi:system_trust_store() of
            {error, _} -> Run();
            {ok, _} -> erlang:error(system_roots_fixture_failed)
        end
    after
        case PreviousPath of
            {ok, Path} -> application:set_env(public_key, cacerts_path, Path);
            undefined -> application:unset_env(public_key, cacerts_path)
        end,
        case PreviousCache of
            not_loaded -> public_key:cacerts_clear();
            Cache -> persistent_term:put(pubkey_os_cacerts, Cache)
        end
    end.

-spec fixture(binary()) -> {ok, binary()} | {error, nil}.
fixture(Name) when Name =:= <<"ca.pem">>;
                   Name =:= <<"client.pem">>;
                   Name =:= <<"client-key.pem">>;
                   Name =:= <<"server.pem">>;
                   Name =:= <<"server-key.pem">> ->
    read_fixture(Name, [
        <<"../../test/fixtures/">>,
        <<"test/fixtures/">>
    ]);
fixture(_Name) ->
    {error, nil}.

-spec read_fixture(binary(), [binary()]) -> {ok, binary()} | {error, nil}.
read_fixture(_Name, []) ->
    {error, nil};
read_fixture(Name, [Prefix | Rest]) ->
    case file:read_file(<<Prefix/binary, Name/binary>>) of
        {ok, Bytes} -> {ok, Bytes};
        {error, _Reason} -> read_fixture(Name, Rest)
    end.
