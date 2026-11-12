-module(http_ohttp_ffi).

-export([
    x25519_public/1,
    x25519_shared/2,
    new_context_claim/0,
    claim_context/1,
    random_bytes/1,
    hkdf_extract/2,
    hkdf_expand/3,
    aead_seal/4,
    aead_open/4,
    sha256/1,
    new_replay_store/2,
    new_replay_store_for_test/4,
    replay_reserve/2,
    replay_commit/2,
    replay_abort/2,
    replay_store_advance_for_test/2,
    close_replay_store/1
]).

-define(HASH_SIZE, 32).
-define(TAG_SIZE, 16).
-define(REPLAY_CALL_TIMEOUT, 5000).
-define(REPLAY_PENDING_MILLISECONDS, 5000).
-define(REPLAY_MAXIMUM, 1000000).
-define(REPLAY_MAXIMUM_QUEUE, 4096).

-spec new_context_claim() -> atomics:atomics_ref().
new_context_claim() ->
    atomics:new(1, [{signed, false}]).

-spec claim_context(term()) -> boolean().
claim_context(Claim) ->
    try atomics:compare_exchange(Claim, 1, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec new_replay_store(pos_integer(), integer()) ->
    {ok, term()} | {error, nil}.
new_replay_store(Maximum, Retention)
    when is_integer(Maximum), Maximum > 0, Maximum =< ?REPLAY_MAXIMUM,
         is_integer(Retention), Retention =/= 0, Retention >= -1 ->
    start_replay_store(Maximum, Retention, ?REPLAY_PENDING_MILLISECONDS,
                       monotonic);
new_replay_store(_, _) ->
    {error, nil}.

-spec new_replay_store_for_test(pos_integer(), pos_integer(), pos_integer(),
                                non_neg_integer()) ->
    {ok, term()} | {error, nil}.
new_replay_store_for_test(Maximum, Retention, PendingMilliseconds, Now)
    when is_integer(Maximum), Maximum > 0, Maximum =< ?REPLAY_MAXIMUM,
         is_integer(Retention), Retention > 0,
         is_integer(PendingMilliseconds), PendingMilliseconds > 0,
         is_integer(Now), Now >= 0 ->
    start_replay_store(Maximum, Retention, PendingMilliseconds, {manual, Now});
new_replay_store_for_test(_, _, _, _) ->
    {error, nil}.

-spec replay_reserve(term(), binary()) ->
    {ok, reference()} | {error, 1 | 2 | 3}.
replay_reserve(Store, EncapsulatedKey)
    when is_binary(EncapsulatedKey), byte_size(EncapsulatedKey) =:= 32 ->
    case replay_call(Store, {reserve, EncapsulatedKey}) of
        {ok, Reply} -> Reply;
        unavailable -> {error, 3}
    end;
replay_reserve(_, _) ->
    {error, 3}.

-spec replay_commit(term(), term()) -> boolean().
replay_commit(Store, Lease) when is_reference(Lease) ->
    case replay_call(Store, {commit, Lease}) of
        {ok, Reply} when is_boolean(Reply) -> Reply;
        _ -> false
    end;
replay_commit(_, _) ->
    false.

-spec replay_abort(term(), term()) -> boolean().
replay_abort(Store, Lease) when is_reference(Lease) ->
    case replay_call(Store, {abort, Lease}) of
        {ok, Reply} when is_boolean(Reply) -> Reply;
        _ -> false
    end;
replay_abort(_, _) ->
    false.

-spec replay_store_advance_for_test(term(), non_neg_integer()) -> boolean().
replay_store_advance_for_test(Store, Milliseconds)
    when is_integer(Milliseconds), Milliseconds >= 0 ->
    case replay_call(Store, {advance, Milliseconds}) of
        {ok, Reply} when is_boolean(Reply) -> Reply;
        _ -> false
    end;
replay_store_advance_for_test(_, _) ->
    false.

-spec close_replay_store(term()) -> boolean().
close_replay_store(Store) ->
    case replay_call(Store, close) of
        {ok, true} -> true;
        _ -> true
    end.

start_replay_store(Maximum, Retention, PendingMilliseconds, Clock) ->
    Owner = self(),
    Token = make_ref(),
    Credits = atomics:new(2, [{signed, false}]),
    atomics:put(Credits, 1, 1),
    QueueMaximum = erlang:min(?REPLAY_MAXIMUM_QUEUE, Maximum + 32),
    Pid = spawn(fun() ->
        OwnerMonitor = erlang:monitor(process, Owner),
        State = #{
            token => Token,
            owner => Owner,
            owner_monitor => OwnerMonitor,
            maximum => Maximum,
            retention => Retention,
            pending_milliseconds => PendingMilliseconds,
            clock => Clock,
            entries => #{},
            leases => #{},
            credits => Credits
        },
        try replay_store_loop(State)
        after atomics:put(Credits, 1, 0)
        end
    end),
    {ok, {ohttp_replay_store, Pid, Token, Credits, QueueMaximum}}.

replay_call({ohttp_replay_store, Pid, Token, Credits, QueueMaximum}, Request)
    when is_pid(Pid), is_reference(Token),
         is_integer(QueueMaximum), QueueMaximum > 0 ->
    try replay_call_valid(Pid, Token, Credits, QueueMaximum, Request)
    catch
        _:_ -> unavailable
    end;
replay_call(_, _) ->
    unavailable.

replay_call_valid(Pid, Token, Credits, QueueMaximum, Request) ->
    Alias = erlang:alias([reply]),
    try
        Monitor = erlang:monitor(process, Pid),
        try
            case acquire_replay_call_credit(Credits, QueueMaximum) of
                false -> unavailable;
                true -> replay_call_admitted(
                    Pid, Token, Credits, Alias, Monitor, Request
                )
            end
        after
            erlang:demonitor(Monitor, [flush])
        end
    after
        erlang:unalias(Alias)
    end.

replay_call_admitted(Pid, Token, _Credits, Alias, Monitor, Request) ->
    Reference = make_ref(),
    Deadline = erlang:monotonic_time(millisecond) + ?REPLAY_CALL_TIMEOUT,
    Pid ! {replay_call, Token, self(), Alias, Reference, Deadline, Request},
    Wait = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
    Result = receive
        {replay_reply, Reference, Reply} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true -> {ok, Reply};
                false -> unavailable
            end;
        {'DOWN', Monitor, process, Pid, _} ->
            unavailable
    after Wait ->
        unavailable
    end,
    case Result of
        unavailable ->
            Pid ! {replay_cancel, Token, self(), Reference},
            unavailable;
        _ -> Result
    end.

acquire_replay_call_credit(Credits, Maximum) ->
    case atomics:get(Credits, 1) of
        1 -> acquire_replay_call_credit(Credits, Maximum, atomics:get(Credits, 2));
        _ -> false
    end.

acquire_replay_call_credit(_Credits, Maximum, Current) when Current >= Maximum ->
    false;
acquire_replay_call_credit(Credits, Maximum, Current) ->
    case atomics:compare_exchange(Credits, 2, Current, Current + 1) of
        ok -> true;
        Actual -> acquire_replay_call_credit(Credits, Maximum, Actual)
    end.

release_replay_call_credit(Credits) ->
    Current = atomics:get(Credits, 2),
    case Current of
        0 -> ok;
        _ ->
            case atomics:compare_exchange(Credits, 2, Current, Current - 1) of
                ok -> ok;
                Actual -> release_replay_call_credit(Credits, Actual)
            end
    end.

release_replay_call_credit(_Credits, 0) -> ok;
release_replay_call_credit(Credits, Current) ->
    case atomics:compare_exchange(Credits, 2, Current, Current - 1) of
        ok -> ok;
        Actual -> release_replay_call_credit(Credits, Actual)
    end.

replay_store_loop(State = #{token := Token, owner := Owner,
                             owner_monitor := OwnerMonitor,
                             credits := Credits}) ->
    receive
        {replay_call, Token, From, ReplyTo, Reference, Deadline, Request}
            when is_pid(From), is_reference(ReplyTo), is_reference(Reference),
                 is_integer(Deadline) ->
            release_replay_call_credit(Credits),
            case is_process_alive(Owner) of
                true ->
                    case erlang:monotonic_time(millisecond) < Deadline of
                        true ->
                            Swept = replay_sweep(State),
                            case replay_store_request(Request, From, Reference,
                                                      Swept) of
                                {reply, Reply, Next} ->
                                    ReplyTo ! {replay_reply, Reference, Reply},
                                    replay_store_loop(Next);
                                {stop, Reply, Final} ->
                                    atomics:put(Credits, 1, 0),
                                    ReplyTo ! {replay_reply, Reference, Reply},
                                    replay_cleanup(Final)
                            end;
                        false ->
                            ReplyTo ! {replay_reply, Reference, {error, 3}},
                            replay_store_loop(State)
                    end;
                false ->
                    ReplyTo ! {replay_reply, Reference, {error, 3}},
                    replay_cleanup(State)
            end;
        {replay_cancel, Token, From, Reference} ->
            replay_store_loop(replay_cancel_reservation(From, Reference, State));
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            replay_cleanup(State);
        {'DOWN', Monitor, process, _Caller, _} ->
            replay_store_loop(replay_remove_monitor(Monitor, State));
        _ ->
            replay_store_loop(State)
    end.

replay_store_request({reserve, EncapsulatedKey}, From, CallReference,
                     State = #{entries := Entries, maximum := Maximum,
                               pending_milliseconds := PendingMilliseconds,
                               leases := Leases}) ->
    case maps:is_key(EncapsulatedKey, Entries) of
        true -> {reply, {error, 1}, State};
        false when map_size(Entries) >= Maximum ->
            {reply, {error, 2}, State};
        false ->
            Lease = make_ref(),
            Monitor = erlang:monitor(process, From),
            Expires = replay_now(State) + PendingMilliseconds,
            Entry = {pending, Lease, From, Monitor, Expires, CallReference},
            Next = State#{
                entries := Entries#{EncapsulatedKey => Entry},
                leases := Leases#{Lease => EncapsulatedKey}
            },
            {reply, {ok, Lease}, Next}
    end;
replay_store_request({commit, Lease}, From, _CallReference,
                     State = #{entries := Entries, leases := Leases,
                               retention := Retention}) ->
    case maps:find(Lease, Leases) of
        {ok, EncapsulatedKey} ->
            case maps:find(EncapsulatedKey, Entries) of
                {ok, {pending, Lease, From, Monitor, _Expires, _ReserveCall}} ->
                    erlang:demonitor(Monitor, [flush]),
                    Expires = case Retention of
                        -1 -> infinity;
                        _ -> replay_now(State) + Retention
                    end,
                    Committed = {committed, Expires},
                    Next = State#{
                        entries := Entries#{EncapsulatedKey := Committed},
                        leases := maps:remove(Lease, Leases)
                    },
                    {reply, true, Next};
                _ -> {reply, false, State}
            end;
        error -> {reply, false, State}
    end;
replay_store_request({abort, Lease}, From, _CallReference,
                     State = #{entries := Entries, leases := Leases}) ->
    case maps:find(Lease, Leases) of
        {ok, EncapsulatedKey} ->
            case maps:find(EncapsulatedKey, Entries) of
                {ok, {pending, Lease, From, Monitor, _Expires, _ReserveCall}} ->
                    erlang:demonitor(Monitor, [flush]),
                    Next = State#{
                        entries := maps:remove(EncapsulatedKey, Entries),
                        leases := maps:remove(Lease, Leases)
                    },
                    {reply, true, Next};
                _ -> {reply, false, State}
            end;
        error -> {reply, false, State}
    end;
replay_store_request({advance, Milliseconds}, _From, _CallReference,
                     State = #{clock := {manual, Now}})
    when is_integer(Milliseconds), Milliseconds >= 0 ->
    Next = replay_sweep(State#{clock := {manual, Now + Milliseconds}}),
    {reply, true, Next};
replay_store_request({advance, _}, _From, _CallReference, State) ->
    {reply, false, State};
replay_store_request(close, _From, _CallReference, State) ->
    {stop, true, State};
replay_store_request(_, _From, _CallReference, State) ->
    {reply, {error, 3}, State}.

replay_now(#{clock := monotonic}) ->
    erlang:monotonic_time(millisecond);
replay_now(#{clock := {manual, Now}}) ->
    Now.

replay_sweep(State = #{entries := Entries}) ->
    Now = replay_now(State),
    {KeptEntries, KeptLeases} = maps:fold(
        fun(Key, Entry, {EntryAccumulator, LeaseAccumulator}) ->
            case replay_entry_live(Entry, Now) of
                true ->
                    NextLeases = case Entry of
                        {pending, Lease, _, _, _, _} ->
                            LeaseAccumulator#{Lease => Key};
                        {committed, _} -> LeaseAccumulator
                    end,
                    {EntryAccumulator#{Key => Entry}, NextLeases};
                false ->
                    replay_demonitor_entry(Entry),
                    {EntryAccumulator, LeaseAccumulator}
            end
        end,
        {#{}, #{}},
        Entries
    ),
    State#{entries := KeptEntries, leases := KeptLeases}.

replay_entry_live({pending, _Lease, Caller, _Monitor, Expires, _CallReference},
                  Now) ->
    Expires > Now andalso is_process_alive(Caller);
replay_entry_live({committed, infinity}, _Now) ->
    true;
replay_entry_live({committed, Expires}, Now) ->
    Expires > Now.

replay_demonitor_entry({pending, _Lease, _Caller, Monitor, _Expires,
                        _CallReference}) ->
    erlang:demonitor(Monitor, [flush]);
replay_demonitor_entry({committed, _Expires}) ->
    ok.

replay_remove_monitor(Monitor, State = #{entries := Entries}) ->
    Kept = maps:filter(
        fun(_Key, Entry) ->
            case Entry of
                {pending, _Lease, _Caller, EntryMonitor, _Expires, _CallReference} ->
                    EntryMonitor =/= Monitor;
                {committed, _Expires} -> true
            end
        end,
        Entries
    ),
    replay_rebuild_leases(State#{entries := Kept}).

replay_cancel_reservation(From, CallReference,
                          State = #{entries := Entries}) ->
    Kept = maps:filter(
        fun(_Key, Entry) ->
            case Entry of
                {pending, _Lease, From, Monitor, _Expires, CallReference} ->
                    erlang:demonitor(Monitor, [flush]),
                    false;
                _ -> true
            end
        end,
        Entries
    ),
    replay_rebuild_leases(State#{entries := Kept}).

replay_rebuild_leases(State = #{entries := Entries}) ->
    Leases = maps:fold(
        fun(Key, Entry, Accumulator) ->
            case Entry of
                {pending, Lease, _Caller, _Monitor, _Expires, _CallReference} ->
                    Accumulator#{Lease => Key};
                {committed, _Expires} -> Accumulator
            end
        end,
        #{},
        Entries
    ),
    State#{leases := Leases}.

replay_cleanup(#{entries := Entries, credits := Credits}) ->
    atomics:put(Credits, 1, 0),
    maps:foreach(fun(_Key, Entry) -> replay_demonitor_entry(Entry) end, Entries),
    ok.

-spec x25519_public(binary()) -> {ok, binary()} | {error, nil}.
x25519_public(PrivateKey)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    with_crypto(fun() ->
        case crypto:generate_key(ecdh, x25519, PrivateKey) of
            {PublicKey, _}
                when is_binary(PublicKey), byte_size(PublicKey) =:= 32 ->
                PublicKey
        end
    end);
x25519_public(_) ->
    {error, nil}.

-spec x25519_shared(binary(), binary()) -> {ok, binary()} | {error, nil}.
x25519_shared(PrivateKey, <<0:256>>)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    {error, nil};
x25519_shared(PrivateKey, <<1, 0:248>>)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    {error, nil};
x25519_shared(PrivateKey, PeerPublicKey)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32,
         is_binary(PeerPublicKey), byte_size(PeerPublicKey) =:= 32 ->
    with_crypto(fun() ->
        case crypto:compute_key(ecdh, PeerPublicKey, PrivateKey, x25519) of
            <<0:256>> -> erlang:error(invalid_shared_secret);
            Shared when is_binary(Shared), byte_size(Shared) =:= 32 -> Shared
        end
    end);
x25519_shared(_, _) ->
    {error, nil}.

-spec random_bytes(integer()) -> {ok, binary()} | {error, nil}.
random_bytes(Count) when is_integer(Count), Count > 0, Count =< 65536 ->
    with_crypto(fun() -> crypto:strong_rand_bytes(Count) end);
random_bytes(_) ->
    {error, nil}.

-spec hkdf_extract(binary(), binary()) -> {ok, binary()} | {error, nil}.
hkdf_extract(Salt, InputKeyMaterial)
    when is_binary(Salt), is_binary(InputKeyMaterial) ->
    with_crypto(fun() ->
        EffectiveSalt = case Salt of
            <<>> -> <<0:(?HASH_SIZE * 8)>>;
            _ -> Salt
        end,
        crypto:mac(hmac, sha256, EffectiveSalt, InputKeyMaterial)
    end);
hkdf_extract(_, _) ->
    {error, nil}.

-spec hkdf_expand(binary(), binary(), integer()) ->
    {ok, binary()} | {error, nil}.
hkdf_expand(PseudorandomKey, Info, Length)
    when is_binary(PseudorandomKey), is_binary(Info),
         is_integer(Length), Length >= 0, Length =< 255 * ?HASH_SIZE ->
    with_crypto(fun() ->
        Blocks = (Length + ?HASH_SIZE - 1) div ?HASH_SIZE,
        Material = hkdf_blocks(PseudorandomKey, Info, Blocks, 1, <<>>, []),
        binary:part(iolist_to_binary(lists:reverse(Material)), 0, Length)
    end);
hkdf_expand(_, _, _) ->
    {error, nil}.

-spec hkdf_blocks(binary(), binary(), non_neg_integer(), pos_integer(), binary(),
                  [binary()]) -> [binary()].
hkdf_blocks(_Key, _Info, 0, _Index, _Previous, Accumulator) ->
    Accumulator;
hkdf_blocks(Key, Info, Remaining, Index, Previous, Accumulator) ->
    Block = crypto:mac(hmac, sha256, Key, <<Previous/binary, Info/binary, Index:8>>),
    hkdf_blocks(Key, Info, Remaining - 1, Index + 1, Block,
                [Block | Accumulator]).

-spec aead_seal(integer(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, nil}.
aead_seal(Algorithm, Key, Nonce, Plaintext)
    when is_integer(Algorithm), is_binary(Key), is_binary(Nonce),
         is_binary(Plaintext) ->
    case cipher(Algorithm, Key, Nonce) of
        {ok, Cipher} ->
            with_crypto(fun() ->
                {Ciphertext, Tag} = crypto:crypto_one_time_aead(
                    Cipher, Key, Nonce, Plaintext, <<>>, ?TAG_SIZE, true
                ),
                <<Ciphertext/binary, Tag/binary>>
            end);
        error ->
            {error, nil}
    end;
aead_seal(_, _, _, _) ->
    {error, nil}.

-spec aead_open(integer(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, nil}.
aead_open(Algorithm, Key, Nonce, Protected)
    when is_integer(Algorithm), is_binary(Key), is_binary(Nonce),
         is_binary(Protected), byte_size(Protected) >= ?TAG_SIZE ->
    case cipher(Algorithm, Key, Nonce) of
        {ok, Cipher} ->
            CiphertextSize = byte_size(Protected) - ?TAG_SIZE,
            <<Ciphertext:CiphertextSize/binary, Tag:?TAG_SIZE/binary>> = Protected,
            with_crypto(fun() ->
                case crypto:crypto_one_time_aead(
                    Cipher, Key, Nonce, Ciphertext, <<>>, Tag, false
                ) of
                    Plaintext when is_binary(Plaintext) -> Plaintext;
                    error -> erlang:error(authentication_failed)
                end
            end);
        error ->
            {error, nil}
    end;
aead_open(_, _, _, _) ->
    {error, nil}.

-spec sha256(binary()) -> {ok, binary()} | {error, nil}.
sha256(Input) when is_binary(Input) ->
    with_crypto(fun() -> crypto:hash(sha256, Input) end);
sha256(_) ->
    {error, nil}.

-spec cipher(integer(), binary(), binary()) ->
    {ok, aes_128_gcm | chacha20_poly1305} | error.
cipher(1, Key, Nonce) when byte_size(Key) =:= 16, byte_size(Nonce) =:= 12 ->
    {ok, aes_128_gcm};
cipher(3, Key, Nonce) when byte_size(Key) =:= 32, byte_size(Nonce) =:= 12 ->
    {ok, chacha20_poly1305};
cipher(_, _, _) ->
    error.

-spec with_crypto(fun(() -> binary())) -> {ok, binary()} | {error, nil}.
with_crypto(Operation) ->
    case application:ensure_all_started(crypto) of
        {ok, _} ->
            try Operation() of
                Value when is_binary(Value) -> {ok, Value}
            catch
                _:_ -> {error, nil}
            end;
        {error, _} ->
            {error, nil}
    end.
