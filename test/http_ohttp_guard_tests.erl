%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(http_ohttp_guard_tests).

-include_lib("eunit/include/eunit.hrl").

-export([fixture_request/1]).

-define(AES_128_GCM, 1).
-define(KDF_SHA256, 1).
-define(KEM_X25519, 16#0020).
-define(TEST_MAXIMUM, 4096).

context_claim_is_one_shot_test() ->
    Claim = http_ohttp_ffi:new_context_claim(),
    ?assertEqual(true, http_ohttp_ffi:claim_context(Claim)),
    ?assertEqual(false, http_ohttp_ffi:claim_context(Claim)).

concurrent_context_claim_has_one_winner_test() ->
    Claim = http_ohttp_ffi:new_context_claim(),
    Parent = self(),
    Workers = [spawn_monitor(fun() ->
        Parent ! {claim_result, http_ohttp_ffi:claim_context(Claim)}
    end) || _ <- lists:seq(1, 32)],
    Results = receive_results(32, []),
    lists:foreach(fun({Pid, Monitor}) ->
        receive {'DOWN', Monitor, process, Pid, normal} -> ok
        after 1000 -> erlang:error(worker_join_timeout)
        end
    end, Workers),
    ?assertEqual(1, length([true || true <- Results])),
    ?assertEqual(31, length([false || false <- Results])).

nonzero_low_order_x25519_input_fails_closed_test() ->
    Private = binary:decode_hex(
        <<"3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a">>
    ),
    LowOrder = <<1, 0:248>>,
    ?assertEqual(rejected,
                 crypto_outcome(http_ohttp_ffi:x25519_shared(Private, LowOrder))).

replay_store_reservation_capacity_abort_and_late_lease_test() ->
    Store = require_store(http_ohttp_ffi:new_replay_store_for_test(1, 100, 10, 0)),
    FirstEnc = <<1:256>>,
    SecondEnc = <<2:256>>,
    FirstLease = require_lease(http_ohttp_ffi:replay_reserve(Store, FirstEnc)),
    ?assertEqual(capacity,
                 reserve_outcome(http_ohttp_ffi:replay_reserve(Store, SecondEnc))),
    ?assertEqual(true, http_ohttp_ffi:replay_abort(Store, FirstLease)),
    SecondLease = require_lease(http_ohttp_ffi:replay_reserve(Store, SecondEnc)),
    ?assertEqual(false, http_ohttp_ffi:replay_commit(Store, FirstLease)),
    ?assertEqual(true, http_ohttp_ffi:replay_commit(Store, SecondLease)),
    ?assertEqual(replay,
                 reserve_outcome(http_ohttp_ffi:replay_reserve(Store, SecondEnc))),
    ?assertEqual(capacity,
                 reserve_outcome(http_ohttp_ffi:replay_reserve(Store, <<7:256>>))),
    ?assertEqual(true, http_ohttp_ffi:close_replay_store(Store)),
    ?assertEqual(true, http_ohttp_ffi:close_replay_store(Store)).

replay_store_lease_is_bound_to_reserving_caller_test() ->
    Store = require_store(http_ohttp_ffi:new_replay_store_for_test(1, 100, 10, 0)),
    Lease = require_lease(http_ohttp_ffi:replay_reserve(Store, <<8:256>>)),
    Parent = self(),
    {_Caller, CallerMonitor} = spawn_monitor(fun() ->
        Parent ! {foreign_commit, http_ohttp_ffi:replay_commit(Store, Lease)}
    end),
    receive {foreign_commit, ForeignResult} ->
        ?assertEqual(false, ForeignResult)
    after 1000 ->
        erlang:error(foreign_commit_timeout)
    end,
    receive {'DOWN', CallerMonitor, process, _Pid, normal} -> ok
    after 1000 -> erlang:error(foreign_commit_join_timeout)
    end,
    ?assertEqual(true, http_ohttp_ffi:replay_commit(Store, Lease)),
    ?assertEqual(true, http_ohttp_ffi:close_replay_store(Store)).

replay_store_pending_and_committed_expiry_use_injected_clock_test() ->
    Store = require_store(http_ohttp_ffi:new_replay_store_for_test(1, 100, 10, 0)),
    Enc = <<3:256>>,
    ExpiredLease = require_lease(http_ohttp_ffi:replay_reserve(Store, Enc)),
    ?assertEqual(true, http_ohttp_ffi:replay_store_advance_for_test(Store, 10)),
    CurrentLease = require_lease(http_ohttp_ffi:replay_reserve(Store, Enc)),
    ?assertEqual(false, http_ohttp_ffi:replay_commit(Store, ExpiredLease)),
    ?assertEqual(true, http_ohttp_ffi:replay_commit(Store, CurrentLease)),
    ?assertEqual(replay,
                 reserve_outcome(http_ohttp_ffi:replay_reserve(Store, Enc))),
    ?assertEqual(true, http_ohttp_ffi:replay_store_advance_for_test(Store, 99)),
    ?assertEqual(replay,
                 reserve_outcome(http_ohttp_ffi:replay_reserve(Store, Enc))),
    ?assertEqual(true, http_ohttp_ffi:replay_store_advance_for_test(Store, 1)),
    FinalLease = require_lease(http_ohttp_ffi:replay_reserve(Store, Enc)),
    ?assertEqual(true, http_ohttp_ffi:replay_abort(Store, FinalLease)),
    ?assertEqual(true, http_ohttp_ffi:close_replay_store(Store)).

replay_store_reclaims_pending_reservation_when_caller_dies_test() ->
    Store = require_store(http_ohttp_ffi:new_replay_store_for_test(1, 100, 100, 0)),
    Parent = self(),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Parent ! {reserved, http_ohttp_ffi:replay_reserve(Store, <<4:256>>)},
        receive stop -> ok end
    end),
    receive {reserved, {ok, _Lease}} -> ok after 1000 -> erlang:error(reserve_timeout) end,
    exit(Caller, kill),
    receive {'DOWN', CallerMonitor, process, Caller, killed} -> ok
    after 1000 -> erlang:error(caller_join_timeout)
    end,
    Replacement = require_lease(http_ohttp_ffi:replay_reserve(Store, <<5:256>>)),
    ?assertEqual(true, http_ohttp_ffi:replay_abort(Store, Replacement)),
    ?assertEqual(true, http_ohttp_ffi:close_replay_store(Store)).

replay_store_owner_death_is_fail_closed_test() ->
    Parent = self(),
    {Owner, OwnerMonitor} = spawn_monitor(fun() ->
        Store = require_store(
            http_ohttp_ffi:new_replay_store_for_test(1, 100, 10, 0)
        ),
        Parent ! {store, Store},
        receive stop -> ok end
    end),
    Store = receive {store, Value} -> Value
    after 1000 -> erlang:error(store_start_timeout)
    end,
    exit(Owner, kill),
    receive {'DOWN', OwnerMonitor, process, Owner, killed} -> ok
    after 1000 -> erlang:error(owner_join_timeout)
    end,
    ?assertEqual(unavailable,
                 reserve_outcome(http_ohttp_ffi:replay_reserve(Store, <<6:256>>))),
    ?assertEqual(true, http_ohttp_ffi:close_replay_store(Store)).

crypto_outcome({ok, _}) -> accepted;
crypto_outcome({error, _}) -> rejected;
crypto_outcome(_) -> invalid.

reserve_outcome({ok, _}) -> accepted;
reserve_outcome({error, 1}) -> replay;
reserve_outcome({error, 2}) -> capacity;
reserve_outcome({error, 3}) -> unavailable;
reserve_outcome(_) -> invalid.

require_store({ok, Store}) -> Store;
require_store(_) -> erlang:error(replay_store_setup_failed).

require_lease({ok, Lease}) -> Lease;
require_lease(_) -> erlang:error(replay_lease_setup_failed).

receive_results(0, Results) -> Results;
receive_results(Remaining, Results) ->
    receive
        {claim_result, Result} when is_boolean(Result) ->
            receive_results(Remaining - 1, [Result | Results])
    after 1000 ->
        erlang:error(result_deadline)
    end.

%% Test-only deterministic sender fixture. This function is intentionally kept
%% in the test tree; the published module never accepts caller-selected HPKE
%% request keys or response nonces.
fixture_request(Plaintext) when is_binary(Plaintext) ->
    _ = application:ensure_all_started(crypto),
    EphemeralPrivate = binary:decode_hex(
        <<"bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73">>
    ),
    GatewayPublic = binary:decode_hex(
        <<"31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155">>
    ),
    {EphemeralPublic, _} = crypto:generate_key(ecdh, x25519, EphemeralPrivate),
    Shared = crypto:compute_key(ecdh, GatewayPublic, EphemeralPrivate, x25519),
    Header = <<1, ?KEM_X25519:16, ?KDF_SHA256:16, ?AES_128_GCM:16>>,
    KemSuite = <<"KEM", ?KEM_X25519:16>>,
    EaePrk = labeled_extract(<<>>, KemSuite, <<"eae_prk">>, Shared),
    SharedSecret = labeled_expand(
        EaePrk,
        KemSuite,
        <<"shared_secret">>,
        <<EphemeralPublic/binary, GatewayPublic/binary>>,
        32
    ),
    Suite = <<"HPKE", ?KEM_X25519:16, ?KDF_SHA256:16, ?AES_128_GCM:16>>,
    PskIdHash = labeled_extract(<<>>, Suite, <<"psk_id_hash">>, <<>>),
    Info = <<"message/bhttp request", 0, Header/binary>>,
    InfoHash = labeled_extract(<<>>, Suite, <<"info_hash">>, Info),
    KeyScheduleContext = <<0, PskIdHash/binary, InfoHash/binary>>,
    Secret = labeled_extract(SharedSecret, Suite, <<"secret">>, <<>>),
    Key = labeled_expand(Secret, Suite, <<"key">>, KeyScheduleContext, 16),
    Nonce = labeled_expand(Secret, Suite, <<"base_nonce">>, KeyScheduleContext, 12),
    ExporterSecret = labeled_expand(Secret, Suite, <<"exp">>, KeyScheduleContext, 32),
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_128_gcm, Key, Nonce, Plaintext, <<>>, 16, true
    ),
    Limits = {limits, 16777216, 4096, 1048576, 16777216, 4096, 1048576},
    Context = {
        crypto_context,
        ExporterSecret,
        EphemeralPublic,
        {symmetric_algorithm, ?KDF_SHA256, ?AES_128_GCM},
        Limits,
        ?TEST_MAXIMUM
    },
    {
        <<Header/binary, EphemeralPublic/binary, Ciphertext/binary, Tag/binary>>,
        {client_context, Context, http_ohttp_ffi:new_context_claim()}
    }.

labeled_extract(Salt, Suite, Label, Input) ->
    EffectiveSalt = case Salt of
        <<>> -> <<0:256>>;
        _ -> Salt
    end,
    crypto:mac(
        hmac,
        sha256,
        EffectiveSalt,
        <<"HPKE-v1", Suite/binary, Label/binary, Input/binary>>
    ).

labeled_expand(Prk, Suite, Label, Info, Length) ->
    ExpandedInfo = <<Length:16, "HPKE-v1", Suite/binary, Label/binary, Info/binary>>,
    Material = crypto:mac(hmac, sha256, Prk, <<ExpandedInfo/binary, 1>>),
    binary:part(Material, 0, Length).
