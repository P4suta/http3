# OHTTP and HPKE current-source requirements audit

This memo reviews every RFC 9180 and RFC 9458 requirement ID currently pinned in `standards/requirements.json`.
It does not change that canonical inventory.
The review is against the OHTTP implementation at base commit `c24f8b1a256eb50e65998b5e782b2a1f04ec0c30` plus the working-tree changes listed below, on 2026-09-12.

The authoritative source documents are [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) and [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458).
The downloaded text used to check the pinned source locations had SHA-256 digests `f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6` and `55f13cb7b3501e29f9edbbbbd9c8a3e13b84799d609d0e01443f543effa99350`.
The canonical inventory had digest `cfbce9084299d36b0da9c2be00900b8cf9bd7a069a0e50aebc5117256f0aeae0` when reviewed.

The implementation and test digests at review time were:

| Path | SHA-256 |
| --- | --- |
| `src/http/ohttp.gleam` | `e0ec8d8d54963c572f8ce08a577169d490d5c9e90afa59023f262e2dc93fcea7` |
| `src/http_ohttp_ffi.erl` | `3323303c895c642ed24b0c86ae26f7e0c684d89d7f41be8099a2a0a0e32acbdf` |
| `test/ohttp_test.gleam` | `452e29741158a0c2a9c298f962a7fb85eee8d851a411aa049e673d4e298dc920` |
| `test/http_ohttp_guard_tests.erl` | `7a753c95e0670cd09576312749e410d0f0f95476c22bc61b2ad3b968658bb276` |

`Implemented` means that the current source owns the required behavior and has an executable evidence candidate.
The OHTTP candidates in this memo have the current passing attestation recorded below.
`N-A` means the clause applies to an HPKE mode,
algorithm family, extension, or operation that the exported OHTTP profile does not implement.
`Open` means a required behavior or integration boundary is absent or cannot yet be proved.
A final `Ready` decision must replace every candidate added in future work with a current-source, source-closure-stable execution report.

The source-closure-stable exact run is `Ready` in `build/supervised-gleam/http-exact-reports/d4abe46c8da015a5bcc9b72765bc618f8444defcfda0acc8d5ec0b0e09e2d179-08468c06b12687612c6e27b81c17f6b5.json`.
It records source digest `d4abe46c8da015a5bcc9b72765bc618f8444defcfda0acc8d5ec0b0e09e2d179`,
2 configured modules, 26 configured and completed units, zero failures, 1,109 attested artifact files, OTP 29, Gleam 1.18.1, a verified child exit status of zero, an empty native process tree, console isolation, no surviving descendant,
no deadline, and no output-limit event.
The rerun command is `escript scripts/supervised_gleam.escript --http-ohttp-exact-test`.

## Reference anchors

Implementation anchors keep the per-requirement table readable while retaining symbol-level traceability.

| Anchor | Current implementation |
| --- | --- |
| `I-CFG` | `src/http/ohttp.gleam`: `decode_key_configuration`, `decode_key_configurations`, `validate_configuration`, `select_algorithm` |
| `I-SEAL` | `src/http/ohttp.gleam`: `client`, `seal_request`, `seal_request_bytes`, `seal_request_bytes_unchecked` |
| `I-OPEN` | `src/http/ohttp.gleam`: `gateway`, `open_request_detailed`, `open_request_bytes_detailed`, `open_reserved_request` |
| `I-HPKE` | `src/http/ohttp.gleam`: `setup_hpke`, `labeled_extract`, `labeled_expand`, `hpke_export`, `protect_response` |
| `I-KEM` | `src/http_ohttp_ffi.erl`: `x25519_public/1`, `x25519_shared/2`; `src/http/ohttp.gleam`: `crypto_result` |
| `I-AEAD` | `src/http_ohttp_ffi.erl`: `aead_seal/4`, `aead_open/4`; `src/http/ohttp.gleam`: `aead_parameters` |
| `I-CTX` | `src/http/ohttp.gleam`: opaque `ClientContext`, opaque `GatewayContext`, `claim_context_once`; `src/http_ohttp_ffi.erl`: atomic context claim |
| `I-PROTECT` | `src/http/ohttp.gleam`: `GatewayOpen`, `ProtectedRequestFailure`, `GatewayAdmission`, `seal_protected_failure`, `admit_request`, `seal_response`, `open_response` |
| `I-EXPECT` | `src/http/ohttp.gleam`: `reject_continue_expectation`, `parse_expectation_members` and its finite RFC 9110 grammar helpers |
| `I-POLICY` | `src/http/ohttp.gleam`: `authorize_request`, exact `Gateway.allowed_authorities` |
| `I-RELAY` | `src/http/ohttp.gleam`: closed `RelayForward`, `relay`, `forward_request`, `forward_response` |
| `I-REPLAY` | `src/http/ohttp.gleam`: `ReplayStore`, `reserve_replay`; `src/http_ohttp_ffi.erl`: owner process and reserve/commit/abort state machine |
| `I-LIMIT` | `src/http/ohttp.gleam`: `validate_message_bytes`, bounded key collection, algorithm count, authority list, and replay capacity checks |

Evidence anchors name executable tests, not prose assertions.

| Anchor | Candidate executable evidence |
| --- | --- |
| `T-CFG` | `test/ohttp_test.gleam::rfc9458_key_configuration_vector_and_strict_collection_test` |
| `T-VECTOR` | `test/ohttp_test.gleam::rfc9458_request_and_response_crypto_vectors_test` |
| `T-CLAIM` | the two 32-caller response-context tests in `test/ohttp_test.gleam`, plus the context-claim EUnit tests in `test/http_ohttp_guard_tests.erl` |
| `T-FRESH` | `test/ohttp_test.gleam::rfc9458_production_client_uses_fresh_request_contexts_test` |
| `T-AUTH` | `test/ohttp_test.gleam::rfc9458_failed_response_authentication_consumes_context_test` and the fixed response vector |
| `T-EXPECT` | `test/ohttp_test.gleam::rfc9458_expect_100_continue_is_rejected_at_both_boundaries_test` and `rfc9110_expect_grammar_handles_values_parameters_and_quoted_commas_test` |
| `T-PROTECT` | `test/ohttp_test.gleam::rfc9458_post_decryption_failures_keep_context_and_are_protected_test` |
| `T-REPLAY` | `test/ohttp_test.gleam::replay_identity_is_enc_and_shared_store_serializes_32_callers_test` and all replay-store EUnit actor tests |
| `T-LOW` | `test/ohttp_test.gleam::rfc9180_low_order_x25519_inputs_abort_before_key_schedule_test` and `test/http_ohttp_guard_tests.erl::nonzero_low_order_x25519_input_fails_closed_test/0` |
| `T-ALG` | `test/ohttp_test.gleam::rfc9180_unsupported_kem_kdf_and_aead_are_rejected_independently_test` |
| `T-POLICY` | `test/ohttp_test.gleam::bhttp_padding_tamper_and_target_policy_fail_closed_test` |
| `T-RELAY` | `test/ohttp_test.gleam::relay_forwards_only_ohttp_content_and_fixed_gateway_identity_test` |

## RFC 9180 requirements

The exported profile is HPKE base mode, DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and either AES-128-GCM or ChaCha20-Poly1305.
It is deliberately a single-shot OHTTP API.
PSK, Auth, AuthPSK, P-curve, X448, general multi-message HPKE contexts, user-defined KEMs, and user-defined KDFs are outside this API.

| Requirement ID | Status | Implementation | Evidence | Remaining gap or N-A basis |
| --- | --- | --- | --- | --- |
| `RFC9180-4-001-SHOULD` | N-A | `I-SEAL` | `T-FRESH` | Clause governs entropy supplied to `DeriveKeyPair`; no deterministic `DeriveKeyPair(ikm)` API is exported. Production request keys come directly from the OS CSPRNG. |
| `RFC9180-4-002-MUST` | Implemented | `I-HPKE` | `T-VECTOR` | DHKEM labeled operations use the `KEM` prefix followed by the two-byte identifier `0x0020`; current exact-run attestation remains pending. |
| `RFC9180-5.1-MUST-BIND-MODE-AND-SUITE-TO-KEY-SCHEDULE` | Implemented | `I-HPKE` | `T-VECTOR`, `T-ALG` | The pinned occurrence requires the non-KEM suite identifier to start with `HPKE` and identify KEM/KDF/AEAD; the historical ID is broader than the atomic clause. |
| `RFC9180-4-1-004-MUST` | Implemented | `I-HPKE` | `T-VECTOR` | DHKEM and HPKE use the correct HKDF-SHA256 constants and separately labeled calls. |
| `RFC9180-4-1-005-MUST` | Implemented | `I-CFG`, `I-KEM` | `T-LOW`, `T-ALG` | Input lengths, suite IDs, supported algorithms, provider failures, and all-zero DH outputs fail closed. |
| `RFC9180-5-006-MUST` | N-A | — | — | Obligation is on future KEM specifications to declare supported modes; this library defines no new KEM. |
| `RFC9180-5-1-007-MUST` | Implemented | `I-CFG`, `I-KEM` | `T-LOW`, `T-ALG` | Repeated KEM input/output validation requirement is owned by the same closed profile checks. |
| `RFC9180-5.1.2-MUST-VERIFY-PSK-INPUT-CONSISTENCY` | N-A | `I-HPKE` | `T-VECTOR` | Base mode fixes both PSK inputs to empty and exposes neither input to callers. |
| `RFC9180-5-1-009-MUST` | N-A | `I-HPKE` | `T-VECTOR` | This is the second atomic occurrence of the paired PSK/PSK-ID rule; PSK modes are unavailable. |
| `RFC9180-5-1-2-010-MUST` | N-A | — | — | Minimum PSK entropy applies only to PSK mode. |
| `RFC9180-5-1-2-011-SHOULD` | N-A | — | — | Recommended PSK length applies only to PSK mode. |
| `RFC9180-5-1-4-012-MUST` | N-A | — | — | Minimum PSK entropy applies only to AuthPSK mode. |
| `RFC9180-5-1-4-013-SHOULD` | N-A | — | — | Recommended PSK length applies only to AuthPSK mode. |
| `RFC9180-5-2-014-MUST` | N-A | `I-SEAL`, `I-OPEN` | `T-VECTOR` | The public OHTTP request context performs exactly one seal/open at sequence zero; no incrementable sequence exists. |
| `RFC9180-5-2-015-MUST-NOT` | Implemented | `I-CTX`, `I-PROTECT` | `T-CLAIM`, `T-VECTOR` | Sender and recipient capabilities are separate opaque types; no sender-context decrypt operation exists. |
| `RFC9180-5-2-016-MUST-NOT` | Implemented | `I-CTX`, `I-PROTECT` | `T-CLAIM`, `T-VECTOR` | No recipient-context encrypt operation exists; OHTTP response roles are separately derived and typed. |
| `RFC9180-5-2-017-MUST` | N-A | `I-SEAL`, `I-OPEN` | `T-VECTOR` | Sequence overflow is unreachable in the single-shot, sequence-zero profile. |
| `RFC9180-5.3-MUST-DOMAIN-SEPARATE-EXPORT` | N-A | `I-HPKE` | `T-VECTOR` | The pinned clause at RFC line 857 requires *future KDF specifications* to bound variable-length inputs. The ID and existing inventory summary incorrectly describe it as exporter domain separation. No new KDF is defined here. |
| `RFC9180-7-1-1-019-MUST` | Implemented | `I-CFG`, `I-KEM` | `T-LOW` | Deserialized X25519 public inputs reach validation before key schedule output can be used. |
| `RFC9180-7-1-2-020-MUST` | N-A | — | — | P-256/P-384/P-521 private-key reduction is outside the X25519-only profile. |
| `RFC9180-7-1-2-021-MUST` | Open | `I-KEM` | Candidate provider-conformance test is absent | Private bytes are delegated to OTP/OpenSSL X25519 operations. No executable evidence yet proves the required clamping for the effective private-key import/serialization boundary. |
| `RFC9180-7-1-2-022-MUST` | Open | `I-KEM` | Candidate provider-conformance test is absent | The provider is expected to clamp X25519 scalar input, but the current suite does not prove unclamped inputs produce RFC 7748-equivalent results. |
| `RFC9180-7-1-2-023-SHOULD` | N-A | `I-KEM` | `T-LOW` | RFC 9180 states the nonzero-mod-order check is structurally true for X25519 after clamping; no other DH group is exposed. |
| `RFC9180-7-1-3-024-SHOULD` | N-A | — | — | `DeriveKeyPair(ikm)` is not exported. |
| `RFC9180-7-1-3-025-SHOULD` | N-A | — | — | `DeriveKeyPair(ikm)` is not exported; production uses direct CSPRNG material. |
| `RFC9180-7-1-4-026-MUST` | Implemented | `I-CFG`, `I-KEM` | `T-LOW` | Sender validates the recipient X25519 input and rejects invalid/all-zero exchange results. |
| `RFC9180-7-1-4-027-MUST` | Implemented | `I-OPEN`, `I-KEM` | `T-LOW` | Recipient validates the ephemeral X25519 input and rejects invalid/all-zero exchange results. |
| `RFC9180-7-1-4-028-MUST` | N-A | — | — | Static sender public-key validation applies only to authenticated HPKE modes. |
| `RFC9180-7-1-4-029-MUST` | N-A | — | — | Partial public-key validation applies to P-256/P-384/P-521, which are unsupported. |
| `RFC9180-7-1-4-030-MUST` | N-A | — | — | P-curve coordinate, infinity, and shared-secret checks are outside the X25519-only profile. |
| `RFC9180-7-1-4-031-MUST` | Implemented | `I-KEM` | `T-LOW` | X25519 provider errors and all-zero DH output abort before the key schedule. |
| `RFC9180-4-MUST-ABORT-INVALID-X25519-DH` | Implemented | `I-KEM` | `T-LOW` | Zero and a distinct nonzero low-order encoding are covered without exposing the raw input in assertion output. |
| `RFC9180-7-1-5-033-MUST` | N-A | — | — | Obligation is on future KEM specifications to state Auth/AuthPSK support; this library defines no new KEM. |
| `RFC9180-7-1-5-034-MUST` | N-A | — | — | Obligation is on a future KEM with multiple encodings; the fixed X25519 encoding is used unchanged. |
| `RFC9180-7-2-1-035-MUST` | N-A | — | — | Obligation is on future KDF specifications to define parameter bounds; no new KDF is defined. |
| `RFC9180-7-2-1-036-RECOMMENDED` | Implemented | `I-HPKE`, `I-LIMIT` | `T-VECTOR` | All KDF variable inputs in the fixed OHTTP profile are at most 64 bytes; callers cannot inject an unbounded HPKE info, PSK, PSK-ID, or exporter context. |
| `RFC9180-9-1-1-037-SHOULD` | N-A | — | — | OHTTP base mode does not claim sender authentication or key-compromise-impersonation resistance. |
| `RFC9180-9-2-038-MUST` | Implemented | `I-KEM`, `I-HPKE` | `T-VECTOR`, `T-LOW` | Uses the standardized DHKEM(X25519, HKDF-SHA256) construction rather than a private KEM. |
| `RFC9180-9-2-039-MUST` | Implemented | `I-HPKE` | `T-VECTOR` | DH output is passed through DHKEM ExtractAndExpand to the fixed 32-byte shared secret. |
| `RFC9180-9-2-3-040-MUST-NOT` | N-A | — | — | The clause forbids reuse of `DeriveKeyPair` input material; that operation and input are absent. |
| `RFC9180-5.2-MUST-NOT-REUSE-NONCE-WITH-KEY` | Implemented | `I-SEAL`, `I-HPKE` | `T-FRESH`, `T-CLAIM` | The pinned source clause concerns reuse of Encap randomness. Each production seal draws fresh OS randomness; deterministic production entry points have been removed. Context claims also prevent response key/nonce reuse. |
| `RFC9180-9-3-042-SHOULD` | Implemented | `I-HPKE` | `T-VECTOR`, `T-ALG` | HKDF-SHA256 is fixed alongside the approximately 128-bit X25519 profile. |
| `RFC9180-9-3-043-SHOULD` | Implemented | `I-HPKE` | `T-VECTOR`, `T-ALG` | HKDF-SHA256 meets the selected KEM security level. |
| `RFC9180-9-3-044-SHOULD` | N-A | — | — | The repeated comparison with PSK security does not apply in base mode. |
| `RFC9180-5.2-MUST-AUTHENTICATE-CIPHERTEXT` | Implemented | `I-AEAD`, `I-PROTECT` | `T-AUTH`, `T-VECTOR` | AES-128-GCM and ChaCha20-Poly1305 open only authenticated ciphertext; failure is collapsed to `DecryptionFailed` and consumes a response context. |
| `RFC9180-9-5-046-MUST` | N-A | — | — | Minimum PSK entropy applies only to PSK/AuthPSK modes. |
| `RFC9180-9-5-047-SHOULD` | N-A | — | — | Recommended PSK length applies only to PSK/AuthPSK modes. |
| `RFC9180-9-6-048-MUST` | N-A | `I-HPKE` | `T-VECTOR` | Obligation is explicitly on future KEM instantiations. The selected registered DHKEM already uses the RFC labels. |
| `RFC9180-9-6-049-MUST` | N-A | `I-HPKE` | `T-VECTOR` | Obligation is explicitly on future KEM instantiations that directly reuse underlying hash/HMAC calls. |
| `RFC9180-9-7-1-050-MUST` | Implemented | `I-CTX` | `T-CLAIM`, `T-VECTOR` | RFC 9180 states ordering is trivial for the single-shot API; there is exactly one request ciphertext per context. |
| `RFC9180-9-7-1-051-MUST` | N-A | — | — | No context permits multiple `Seal` or `Open` calls. |
| `RFC9180-9-7-1-052-SHOULD` | N-A | — | — | Ordering metadata in AAD is a recommendation for multi-message contexts, which are absent. |
| `RFC9180-9-7-1-053-MUST` | Open | `I-CTX` | Candidate integrated transport-loss test is absent | The cryptographic primitive does not own a transport and cannot detect a lost OHTTP response. The future HTTP integration must classify terminal loss. |
| `RFC9180-9-7-1-054-MUST` | Open | `I-CTX` | Candidate integrated transport-loss/cancel test is absent | Opaque one-shot contexts can be dropped, but no integrated exchange currently proves that unrecoverable loss discards all copies and supervised work. |

## RFC 9458 requirements

The current module owns binary HTTP encoding, OHTTP cryptography, gateway admission policy, a minimal relay value, finite limits, and exact `enc` replay serialization.
It does not yet own the complete client-to-relay,
relay-to-gateway, or gateway-to-target HTTP exchanges.
Requirements covering those HTTP envelopes remain open even when a lower-level primitive helps an application satisfy them.

| Requirement ID | Status | Implementation | Evidence | Remaining gap or N-A basis |
| --- | --- | --- | --- | --- |
| `RFC9458-3-MUST-AUTHENTICATE-KEY-CONFIGURATION` | Open | `I-CFG` | `T-CFG` proves syntax only | `Client` accepts a bare valid configuration without authenticated acquisition evidence, gateway identity, or integrity provenance. |
| `RFC9458-3.2-MUST-DISCARD-MALFORMED-CONFIGURATION-COLLECTION` | Implemented | `I-CFG`, `I-LIMIT` | `T-CFG` | Collection decoding is atomic: any malformed or excess member rejects the complete collection. |
| `RFC9458-5-MUST-KEEP-ADDITIONAL-CLIENT-FIELDS-INDEPENDENT` | Open | `I-SEAL` | Candidate outer-request integration test is absent | The module returns ciphertext but does not build the client-to-relay POST or constrain its additional fields. |
| `RFC9458-5-MUST-REMOVE-ADDITIONAL-CLIENT-FIELDS` | Open | `I-RELAY` | `T-RELAY` proves the closed relay value only | No integrated pair proves that every field added by the client is removed before relay forwarding. |
| `RFC9458-5-MUST-NOT-ADD-UNAWARE-RELAY-INFORMATION` | Implemented | `I-RELAY` | `T-RELAY` | `RelayForward` can contain only the fixed gateway URI, fixed media type, and unchanged encrypted body. |
| `RFC9458-5-MUST-ENCAPSULATE-GATEWAY-FORWARDED-RESPONSE-INFORMATION` | Open | `I-PROTECT`, `I-RELAY` | `T-PROTECT`, `T-VECTOR` prove protected primitives | There is no target execution/outer-response adapter proving every target result and target failure stays inside the Encapsulated Response. |
| `RFC9458-5-MUST-LIMIT-SUCCESS-RESPONSE-ENVELOPE` | Open | `I-RELAY` | Candidate gateway outer-response test is absent | `forward_response` validates media type and size but does not own status 200 or the complete outer header set. |
| `RFC9458-5.1-MUST-NOT-SEND-EXPECT-100-CONTINUE` | Implemented | `I-SEAL`, `I-EXPECT` | `T-EXPECT` | Typed and byte-oriented request sealing both reject 100-continue before deriving a production request key. |
| `RFC9458-5.1-MUST-ERROR-ON-EXPECT-100-CONTINUE` | Implemented | `I-OPEN`, `I-EXPECT`, `I-PROTECT` | `T-EXPECT`, `T-PROTECT` | After authenticated opening, the integration admission API emits a canonical protected 417 response. |
| `RFC9458-5.2-MUST-RETURN-4XX-FOR-INVALID-OUTER-MESSAGE` | Open | `I-OPEN`, `I-RELAY` | Candidate HTTP-server adapter test is absent | Pre-decapsulation media, framing, key, size, and authentication errors are typed, but no server adapter maps all of them to finite outer 4xx responses. |
| `RFC9458-5.2-MUST-ENCAPSULATE-POST-DECAPSULATION-ERRORS` | Open | `I-PROTECT` | `T-PROTECT` covers malformed request, Expect, and target policy | The repaired admission boundary preserves `GatewayContext` and protects canonical 400/417/403. Target execution failures, timeouts, and every target-produced error still need an integrated adapter and proof. |
| `RFC9458-6-MUST-USE-HTTPS-ON-BOTH-RELAY-HOPS` | Open | `I-RELAY` | `T-RELAY` proves only HTTPS syntax for the gateway URI | The client-to-relay resource and both authenticated transport executions are outside this module. Accepted text is not proof of the endpoint actually contacted. |
| `RFC9458-6.1-MUST-AUTHORIZE-GATEWAY-FOR-TARGET` | Open | `I-POLICY` | `T-POLICY` proves gateway-side target admission only | `Client` binds no gateway identity to an allowed target set, so it cannot prove client authorization of that gateway for the sealed target. |
| `RFC9458-6.1-MUST-USE-AUTHENTICATED-GATEWAY-KEY` | Open | `I-CFG` | `T-CFG` proves syntax only | `KeyConfiguration` lacks authenticated origin/provenance; this repeats the Section 3 acquisition gap. |
| `RFC9458-6.1-MUST-USE-FRESH-HPKE-CONTEXT-PER-REQUEST` | Implemented | `I-SEAL`, `I-CTX` | `T-FRESH`, `T-CLAIM` | Every production seal obtains new OS CSPRNG X25519 material. There is no public deterministic client or reusable response nonce hook. |
| `RFC9458-6.1-MUST-NOT-SEND-IDENTIFYING-OUTER-FIELDS` | Open | `I-SEAL` | Candidate client outer-request test is absent | The module does not build the outer relay request or accept a typed relay-removal trust policy. |
| `RFC9458-6.2-MUST-FOLLOW-HTTP-FORWARDING-RULES` | Open | `I-RELAY` | `T-RELAY` proves only the narrow value | No actual intermediary exchange removes hop-by-hop fields, processes gateway status, or demonstrates RFC 9110 Section 7.6 forwarding behavior. |
| `RFC9458-6.2-SHOULD-NOT-FORWARD-UNKNOWN-FIELDS` | Implemented | `I-RELAY` | `T-RELAY` | The closed primitive accepts no inbound header collection, so an unknown field cannot enter `RelayForward`. Full intermediary integration remains separately open above. |
| `RFC9458-6.2-MUST-NOT-ADD-CLIENT-IDENTIFYING-INFORMATION` | Implemented | `I-RELAY` | `T-RELAY` | Client address, credentials, connection metadata, and free-form headers are unrepresentable in the relay value. |
| `RFC9458-6.2.1-MUST-NOT-ADD-UNIQUE-PERSISTENT-IDENTIFIER` | Implemented | `I-RELAY` | `T-RELAY` | No persistent or pseudonymous client identifier field is representable. |
| `RFC9458-6-2-3-021-SHOULD` | N-A | `I-RELAY` | `T-RELAY` | The relay primitive has no delay feature, timer, or batching option; therefore it cannot add a delay without client awareness. |
| `RFC9458-6.3-SHOULD-CONSTRAIN-GATEWAY-TARGETS` | Implemented | `I-POLICY` | `T-POLICY`, `T-PROTECT` | Gateway admission uses an exact authority allowlist; an empty list denies all targets, and rejection is protected after decapsulation. |
| `RFC9458-6.3-SHOULD-NOT-USE-INSECURE-CROSS-ORIGIN-TARGET` | Implemented | `I-POLICY` | `T-POLICY` | Admission requires `https` for every target, which is stricter than permitting same-origin HTTP. The later target transport still needs end-to-end integration evidence. |
| `RFC9458-6.4-MUST-ISOLATE-OHTTP-PRIVATE-KEYS` | Open | `I-CFG` | Candidate cross-protocol-key-misuse test is absent | `gateway_key` imports raw reusable X25519 private bytes without a purpose-bound or non-exportable handle. The same bytes can be supplied to another protocol using the OHTTP label. |
| `RFC9458-6.5-MUST-NOT-AUTOMATICALLY-RETRY-AMBIGUOUS-FAILURE` | Open | — | Candidate supervised exchange/retry model is absent | No OHTTP exchange state machine classifies positive non-processing signals versus ambiguous connection failure. Applications currently own retry decisions without a library oracle. |
| `RFC9458-6.5.1-SHOULD-INCLUDE-DATE-FOR-ANTI-REPLAY` | Open | `I-REPLAY` | `T-REPLAY` proves exact-`enc` replay handling only | Request authoring has no Date policy, injectable clock, gateway capability, or inclusion/omission tests. The replay store is complementary and is not a Date substitute. |
| `RFC9458-6.5.1-MUST-NOT-TREAT-DATE-WINDOW-AS-SECRET` | N-A | — | — | The gateway implements no Date acceptance window and makes no secrecy decision about one. |
| `RFC9458-6.5.2-MUST-REENCRYPT-DATE-RETRY-WITH-FRESH-CONTEXT` | Open | `I-SEAL` | `T-FRESH` proves ordinary seals only | Every call to seal is fresh, but there is no typed Date-correction retry transition proving mutation followed by one new context. |
| `RFC9458-6.5.2-MUST-NOT-RETRY-ADJUSTED-DATE-MORE-THAN-ONCE` | Open | — | Candidate Date-retry model is absent | No scoped retry token or finite attempt counter prevents a caller from performing multiple adjusted-Date retries. |
| `RFC9458-6.5.2-SHOULD-PREVENT-CACHING-DATE-CONDITIONED-ERROR` | N-A | — | — | No Date-conditioned outer gateway response exists. This becomes applicable with that feature and must then prove `no-store` or `Vary: date`. |
| `RFC9458-6.5.2-MUST-NOT-REUSE-GATEWAY-DATE` | Open | — | Candidate one-shot gateway-Date capability test is absent | No typed, resource-scoped, single-use Date value exists; a caller can retain and reuse ordinary text without detection. |
| `RFC9458-6.10-RECOMMENDED-USE-HTTPS-TO-SEPARATE-TARGET` | Implemented | `I-POLICY` | `T-POLICY` | Gateway admission accepts only `https` target schemes. A future gateway-to-target adapter must additionally attest certificate verification and the contacted endpoint. |
| `RFC9458-7-MUST-MITIGATE-UNIQUE-CLIENT-CONFIGURATIONS` | Open | `I-CFG` | `T-CFG` proves wire consistency only | A bare caller-selected configuration carries no anonymity-set, consistency, authenticated distribution, or gateway/relay identity evidence. |

## Replay extension and diagnostic invariants

The shared replay store is an additional defense; RFC 9458 does not let it replace the Date requirements.
Its identity is the exact 32-byte HPKE encapsulated key (`enc`), so changing ciphertext under the same request context cannot evade admission.
Reservation occurs before AEAD work, pending entries count against the finite capacity, authentication failure aborts a reservation,
and successful authentication commits it before binary HTTP or target-policy processing.
Consequently, malformed authenticated requests remain replayed even when their protected error is 400, 417, or 403.

The actor binds each lease to its caller, monitors pending callers, uses a finite call deadline and queue budget, rejects late/stale leases, reclaims a pending entry when the caller dies, and becomes unavailable when its owner dies.
It never replaces a dead store with an empty store.
The test-only manual monotonic clock makes pending and committed expiry deterministic.
The public compatibility `replay_store` retains committed identities indefinitely; the explicit `replay_store_with_retention` documents that expiry permits an old identity to be admitted again.

The OHTTP tests convert errors and outcomes to finite categories before assertion.
The low-order input, private keys, raw ciphertext, target authority,
process identifiers, references, sockets, and exceptions are not assertion payloads or shared diagnostics.
Concurrent tests report only counts and fixed categories.
Fixed request and response vectors use a sender fixture confined to the test tree.

## Stale deterministic references

The following current-tree references describe production APIs that have been removed and must be corrected by their owning files before a conformance map or API snapshot can be accepted:

| Location | Stale content | Required correction |
| --- | --- | --- |
| `gleam.toml:132` | Comment says deterministic entry points exist for vectors. | State that deterministic sender construction is test-tree-only and production sealing always uses the OS CSPRNG. |
| `api/http.snapshot:226` | Exposes `http/ohttp/deterministic_client`. | Regenerate the compiler-derived API snapshot from current source. |
| `standards/requirements.json` entry `RFC9180-5.2-MUST-NOT-REUSE-NONCE-WITH-KEY` | References `deterministic_client`, `claim_deterministic_key/1`, and removed deterministic tests. | Replace with `seal_request_bytes_unchecked`, context claims, `T-FRESH`, and the current 32-caller tests after this audit is adopted. |
| `standards/requirements.json` entry `RFC9458-6.1-MUST-USE-FRESH-HPKE-CONTEXT-PER-REQUEST` | Its reason and implementation still treat `deterministic_client` as public. | Mark the repaired production path only after a current exact-run report is attached. |
| `standards/requirements.json` entry `RFC9458-6.5.2-MUST-REENCRYPT-DATE-RETRY-WITH-FRESH-CONTEXT` | Uses removed `deterministic_client` as the stated defect. | Keep the requirement Open for the missing typed Date retry state machine, not for a production deterministic key path that no longer exists. |

References in `scripts/ohttp_distribution_audit.escript` are intentional negative controls: the distribution audit must reject any source, snapshot, or archive that reintroduces these names.
Historical comments in `test/ohttp_test.gleam` and `docs/MIGRATION.md` intentionally explain their removal.
They are not stale API claims.

## Red-to-Green diagnostic trail and remaining adoption work

The original current-source Red report is `build/supervised-gleam/http-exact-reports/ecae8ce16dc6d66b80d5b89e342ffd9e8b7c302fd47c3e29711941610c39822e-fcfc53894391a02affd5a6beabd583eb.json`.
It completed all 22 then-configured units and safely classified one pattern mismatch in the combined Expect boundary test.
The diagnostic split retained three independently named client, gateway/replay, and extension-token units.
Its first complete Red report,
`build/supervised-gleam/http-exact-reports/ee4e18f23db136fd42217a851da4d0af927acb2c5a675352d94dc006a1964622-8545842c9130aeca9c7c2993cee9496f.json`,
proved the gateway and extension paths passed and isolated the client path.
The next split report,
`build/supervised-gleam/http-exact-reports/8101dab6b6cd5ecd1934858783084220ec4f8acf91c8f9e797d88ecacf65ae1b-575649a68503fbb49fba21d8d06d5697.json`,
completed all 26 units and isolated the mismatch to the bare-obs-text fixture.

The fixture expected `bhttp.encode` to accept the field, but its value ended in HTAB.
That violates the public `bhttp.Field` contract, which forbids boundary SP/HTAB, so the actual finite result was `InvalidField` before OHTTP parsing.
Removing only the trailing HTAB preserved the interior invalid obs-text and allowed the test to prove that the OHTTP Expect parser returns `InvalidMessage` without deriving a request key.
The final `Ready` report named above executes the retained 26-unit suite.
An intermediate compiler-rejected report caused by a missing terminal `Nil` during test splitting is retained at `build/supervised-gleam/http-exact-reports/d29afb9ab90f612c5fc911c4787fe90387e26c60abaa05a3eff178e372ea9d86-86916911e90a71d19dda13b9c3b2f9ea.json` and is not conformance evidence.

The exact suite covers Gleam compilation, the OHTTP test module, EUnit actor/claim tests, both 32-caller races, fixed request and response vectors, and the zero and nonzero low-order X25519 cases.
The Open rows in this memo still need their stated implementation and integration evidence.
The stale generated API snapshot and canonical requirement entries must be refreshed by their owners.
Independent interoperability and audit remain separate external evidence.
