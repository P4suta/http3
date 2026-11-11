# Compression Dictionary Transport requirement inventory

Reviewed 2026-09-11.
The RFC 9842 requirement map is complete for the shipped capability boundary.
This document inventories its requirements and the algorithms imported by its string-valued URLPattern profile.
It records implemented helpers, executable checks, and conditional behavior that is outside the integrated HTTP client/server because neither endpoint advertises or negotiates compression-dictionary transport.
This map does not claim that automatic HTTP negotiation exists and does not change the repository-wide readiness result.
The machine-readable counterpart is [requirements.json](requirements.json), under `RFC9842`.

## Sources and the meaning of completion

The primary document is [RFC 9842](https://www.rfc-editor.org/rfc/rfc9842.html).
The [official text](https://www.rfc-editor.org/rfc/rfc9842.txt) has SHA-256 `27944690358430e7885edc3a7a0c6b12eae23076b11adb38fcb5bc865f31c0de`.
The [all-status errata search](https://errata.rfc-editor.org/search/?rfc_number=9842) returned no entries on the review date.
Absence of errata does not resolve differences between separately versioned referenced algorithms.

There are 26 atomic uppercase obligations: 22 `MUST` and four `MUST NOT`.
The single selection obligation in Section 2.2.3 is split into its three ordered rules.
The keyword legend is excluded, as are `MAY` permissions.
No uppercase advisory obligation occurs outside the legend.
This is the existing manifest's `BCP14Uppercase` counting convention, not a claim that formats, algorithms, or imported specifications have no other constraints.

The tables below also inventory those other constraints.
Their `D` and `P` identifiers are review identifiers, not additional BCP 14 clauses or invented keyword levels.
Every RFC section is accounted for, including informative examples, optional facilities, registrations, and security guidance.

`Implemented` below names the specific helper or codec property with executable evidence.
`NotApplicable` identifies a conditional protocol state that no library-owned HTTP path can enter, and states the exact boundary instead of silently treating absent automatic negotiation as success.
The actor column identifies the RFC participant that bears each obligation when an application chooses to implement that role.

The [requirements auditor](../scripts/requirements_audit.escript) checks source pins, declared counts, dispositions, and resolvable implementation/test symbols.
It does not infer normative completeness from prose, execute the referenced tests, or turn a passing diagnostic into current-source qualification.
In particular, this RFC's `map_complete` is true while the repository-wide `inventory_complete` remains false for unrelated unfinished maps.

## The 26 uppercase obligations

The `RFC9842-` prefix is omitted from IDs.
Linked test names are executable entrypoints, ordinary EUnit generators, or case functions called by those generators (notably the native window cases).

| ID / level | RFC actor | Disposition | Implementation / executable test | Scope or gap |
| --- | --- | --- | --- | --- |
| `2.1.1-MUST-NOT-INVALID-URL-PATTERN` / MUST NOT | Client | Implemented | [compression.valid_pattern](../src/http/compression.gleam); [url_pattern_profile_test](../test/url_pattern_profile_test.gleam), [dictionary_url_context_test](../test/dictionary_url_context_test.gleam) | The source-bound 270-case step matrix, 517 independent Node/Chromium cases, direct regressions, regexp refusal, same-origin selection, and finite work failures cover the reachable string-pattern profile. |
| `2.1.1-MUST-REQUIRED-MATCH` / MUST | Client | Implemented | [compression.parse_directive_members](../src/http/compression.gleam); [dictionary_store_contract_test.unknown_dictionary_types_and_missing_match_are_rejected_test](../test/dictionary_store_contract_test.gleam) | Required member/type rejection and complete field compatibility are exercised. |
| `2.1.2-MUST-EMPTY-DESTINATION-LIST` / MUST | Client | Implemented | [compression.destination_matches](../src/http/compression.gleam); [dictionary_store_contract_test.empty_destination_matches_all_destinations_test](../test/dictionary_store_contract_test.gleam) | Empty destination list matches all request destinations. |
| `2.1.2-MUST-UNSUPPORTED-DESTINATIONS` / MUST | Client | Implemented | [compression.select_dictionary_for_request](../src/http/compression.gleam); [dictionary_capability_test.unsupported_destinations_ignore_restrictive_match_lists_test](../test/dictionary_capability_test.gleam) | Unsupported capability also removes destination-specific selection precedence. |
| `2.1.3-MUST-ECHO-NONEMPTY-ID` / MUST | Client | NotApplicable | No library-owned request emitter. | The integrated client never sends `Available-Dictionary`, `Dictionary-ID`, `dcb`, or `dcz`; field serializers do not own requests. |
| `2.1.3-MUST-OPAQUE-ID` / MUST | Client | Implemented | [compression.parse_dictionary_id](../src/http/compression.gleam); [dictionary_field_contract_test](../test/dictionary_field_contract_test.gleam) | Helper parsing/serialization covers empty, escaped, and 1,024/1,025 decoded-character boundaries without interpreting identifier content. |
| `2.1.3-MUST-NOT-ID-AS-CONTENT-PROOF` / MUST NOT | Server | Implemented | [compression.open_dictionary_header](../src/http/compression.gleam), [dictionary_policy.encode](../src/http/internal/dictionary_policy.gleam); [dictionary_request_policy_test](../test/dictionary_request_policy_test.gleam) | Codecs take bytes rather than an ID; encode/decode derive or compare the content hash, and the explicit selected-record policy rejects identifier-only and stale-ID substitutions. |
| `2.1.3-MUST-VALIDATE-DICTIONARY-HASH` / MUST | Server and decoder | Implemented | [compression.open_dictionary_header](../src/http/compression.gleam), [dictionary_policy.encode](../src/http/internal/dictionary_policy.gleam); [dictionary_request_policy_test](../test/dictionary_request_policy_test.gleam), [compression_test.rfc9842_dictionary_headers_hash_and_round_trip_test](../test/compression_test.gleam) | DCB/DCZ decode validates the wire hash before codec use; selected-record encode recomputes bytes and checks stored and advertised hashes before encoding. |
| `2.1.4-MUST-NOT-UNKNOWN-DICTIONARY-TYPE` / MUST NOT | Client | Implemented | [compression.insert_dictionary](../src/http/compression.gleam); [dictionary_store_contract_test.unknown_dictionary_types_and_missing_match_are_rejected_test](../test/dictionary_store_contract_test.gleam) | Unknown type is rejected before insertion/use. |
| `2.2-MUST-ONE-AVAILABLE-DICTIONARY` / MUST | Client | NotApplicable | No library-owned request emitter. | The integrated client never emits the conditional header; the one-hash serializer returns one field value and does not mutate an HTTP request. |
| `2.2.1-MUST-FRESH-DICTIONARY` / MUST | Client | Implemented | [compression.select_entry](../src/http/compression.gleam); [dictionary_selection_time_test](../test/dictionary_selection_time_test.gleam), [dictionary_store_contract_test.dictionary_expires_at_its_exact_freshness_deadline_test](../test/dictionary_store_contract_test.gleam) | The Store intentionally selects fresh entries only, using a bounded caller-supplied cache deadline and the inclusive-fetch/exclusive-expiry interval. Not supporting the separately permitted serve-stale branch is a stricter valid policy. |
| `2.2.3-MUST-DESTINATION-PRECEDENCE` / MUST | Client | Implemented | [compression.preferred](../src/http/compression.gleam); [dictionary_store_contract_test.dictionary_selection_uses_all_three_precedence_rules_test](../test/dictionary_store_contract_test.gleam) | Destination specificity precedes match length only when supported. |
| `2.2.3-MUST-MATCH-LENGTH-PRECEDENCE` / MUST | Client | Implemented | [compression.preferred](../src/http/compression.gleam); [dictionary_store_contract_test.dictionary_selection_uses_all_three_precedence_rules_test](../test/dictionary_store_contract_test.gleam) | Original match-string length breaks equal destination rank. |
| `2.2.3-MUST-FETCH-TIME-PRECEDENCE` / MUST | Client | Implemented | [compression.preferred](../src/http/compression.gleam); [dictionary_store_contract_test.dictionary_selection_uses_all_three_precedence_rules_test](../test/dictionary_store_contract_test.gleam) | Newest fetch time breaks equal destination/length rank. |
| `2.3-MUST-ECHO-STORED-ID` / MUST | Client | NotApplicable | No library-owned request emitter. | The integrated client never selects the standalone Store or emits `Dictionary-ID`; an application composing `Available-Dictionary` owns this conditional header. |
| `2.3-MUST-IDENTICAL-DECODED-ID` / MUST | Client | NotApplicable | No library-owned request emitter. | The parser/serializer preserves opaque decoded values, but there is no library-generated outgoing identifier. |
| `4-MUST-ADVERTISED-DCB-WINDOW` / MUST | Client | Implemented | [compression.decode](../src/http/compression.gleam); [http_dictionary_window_test.dcb_window_case](../test/http_dictionary_window_test.erl) | Required 16 MiB codec capability exercised; automatic advertisement is not claimed. |
| `5-MUST-ADVERTISED-DCZ-WINDOW` / MUST | Client | Implemented | [compression.decode](../src/http/compression.gleam); [http_dictionary_window_test.dcz_window_case](../test/http_dictionary_window_test.erl) | Dictionary-dependent 8–128 MiB codec capability exercised; automatic advertisement is not claimed. |
| `5-MUST-DCZ-ENCODED-WINDOW` / MUST | Encoder/server | Implemented | [compression.encode](../src/http/compression.gleam); [http_dictionary_window_test.dcz_encoder_window_case](../test/http_dictionary_window_test.erl) | Actual encoder frames are inspected against the strict dictionary-dependent limit. |
| `6.1-MUST-NOT-NO-DICTIONARY-NO-ADVERTISEMENT` / MUST NOT | Client | NotApplicable | No automatic dictionary content negotiation. | The integrated client never advertises dictionary-aware codings, with or without a standalone Store, so the forbidden library-owned state is unreachable. |
| `6.2-MUST-CACHEABLE-VARY` / MUST | Server | NotApplicable | No automatic dictionary response production. | The dispatcher has no dictionary registry or coding policy; the byte codec does not create HTTP responses. Applications composing one own `Content-Encoding` and `Vary`. |
| `8-MUST-SECURE-CONTEXT` / MUST | Client and server | NotApplicable | No integrated dictionary transport path. | The Store accepts only canonical HTTPS origins, while transport authentication for an application-composed exchange remains application policy. |
| `9.3-MUST-MITIGATION-FAILURE-ERROR` / MUST | Client | NotApplicable | No automatic dictionary response decode. | The integrated client has no CDT mitigation pipeline or partial decoded response. Standalone selection and codec failures are typed and atomic. |
| `9.3.2-MUST-RESPONSE-READABILITY-PROTECTION` / MUST | Protected client | NotApplicable | No browser readability model. | The general HTTP client has no browsing context, Fetch response tainting, CORS readability policy, or automatic CDT negotiation. |
| `9.3.2-MUST-BOTH-RESOURCES-READABLE` / MUST | Protected client | NotApplicable | No browser readability model. | The RFC's conditional protected-client case cannot occur in the library-owned client; an application adding such a model must gate both resources. |
| `10-MUST-COOKIE-EQUIVALENT-LIFETIME` / MUST | Client | NotApplicable | No client-owned dictionary store. | `http.Client` neither owns nor consults `compression.Store` and never advertises a dictionary. The immutable Store is application-owned and exposes explicit clearing scopes. |

Hash validation is independent of the opaque ID.
`open_dictionary_header` compares the decoded DCB/DCZ header hash to the supplied dictionary before codec use.
The explicit selected-record policy recomputes the actual bytes and checks both the cached and advertised hashes before encoding.
Its regressions detect wrong bytes under an unchanged ID, a stale ID mapping, a forged cached hash, and wrong, missing, or multiple advertisements.

## Formats, procedures, and imported requirements

| Review ID / source | Required behavior or defined scope | Implementation and executable evidence | Remaining work or applicability |
| --- | --- | --- | --- |
| D01 / §§1–1.2 | Dictionary negotiation applies independently of HTTP version; examples illustrate use cases. Typed Structured Fields, HTTP semantics, and cache semantics supply terminology and parsing rules. | `compression` provides protocol-independent helpers. H1/H2/H3 ordinary tests elsewhere do not exercise an automatic dictionary exchange. | Automatic cross-protocol negotiation is outside the current endpoint capability. Examples and the BCP 14 legend add no separate runtime obligation. |
| D02 / §2.1 | `Use-As-Dictionary` is a Structured Field Dictionary. Known members have their prescribed types; `match` is required, `match-dest` defaults empty, `id` defaults empty, and `type` defaults `raw`. | `parse_use_as_dictionary`, `parse_directive_members`, `serialize_use_as_dictionary`; [dictionary_field_contract_test](../test/dictionary_field_contract_test.gleam), `dictionary_store_contract_test.unknown_dictionary_types_and_missing_match_are_rejected_test`. | Ordinary controls cover last-member-wins semantics, fully parsed/ignored known-member parameters, preserved unknown members, malformed earlier duplicates, exact types/defaults, and the supported 256-parameter boundary. This field proof does not qualify every generic Structured Fields parser branch or actual HTTP negotiation. |
| D03 / §§2.1.1, 2.1.5 | Validate the match string through URLPattern creation using the dictionary request URL; reject arbitrary regexp groups. Match encoded URL components. Prefix/version examples are consequences of matching. | `insert_dictionary_from_url`, `pattern.compile`, component parser; the source-bound P01–P23 step matrix, pathname WPT generator and full-pattern tests. | The shipped string-pattern profile is covered. Admission does not replace the independent origin comparison at selection. Header-only syntax parsing uses a synthetic base and is not the final contextual admission check. |
| D04 / §2.1.2 | Parse a list of Fetch destination strings; the empty list and unsupported-destination capability have distinct representations but both disable destination filtering. | `parse_destinations`, `destination_matches`, `DestinationCapability`; `dictionary_capability_test`, including the supported empty Fetch destination; `dictionary_field_contract_test` covers repeated entries and list/item parameters. | Automatic request-destination acquisition is absent. The application must provide the actual capability and destination; an empty supported destination must not be mistaken for unsupported capability. The local 64-entry limit remains a resource policy, not a uniqueness requirement. |
| D05 / §§2.1.3, 2.3 | The ID is an opaque Structured Field String, up to 1,024 decoded characters, and is echoed for the selected dictionary without changing its decoded value. | `parse_dictionary_id`, `serialize_dictionary_id`, `validate_directive`; `dictionary_field_contract_test` exercises exact 1,024/1,025 decoded ASCII boundaries, doubled wire escapes, empty ID, and semantic round trips. | The integrated client does not emit the conditional request header. Applications composing it must use the returned decoded value unchanged. |
| D06 / §2.1.4 | `raw` supplies unformatted dictionary bytes; an unknown type is unusable. | `parse_dictionary_type`, `insert_dictionary_from_url`; unknown-type refusal and raw-prefix codec tests. | General serialized Shared Brotli dictionaries are outside this raw subset; see [BROTLI.md](BROTLI.md). Unknown types must remain unusable even when parsable as an extension token. |
| D07 / §2.2 | `Available-Dictionary` is one Structured Field Byte Sequence containing the SHA-256 of one selected dictionary's contents. | `dictionary_hash`, `parse_available_dictionary`, `serialize_available_dictionary`; `dictionary_field_contract_test` covers 31/32/33-byte values, non-byte-aligned serialization, Item parameters, wrong types, malformed encoding, and multiple-item rejection. `dictionary_policy.encode` validates selected bytes against the single field. | The integrated client does not mutate a request. Applications that elect to send this conditional header own header-list uniqueness. |
| D08 / §2.2.1 | A usable entry is fresh or explicitly permitted stale by cache policy. | The store adopts the stricter fresh-only choice and checks one signed 64-bit caller-clock domain with `fetched_at <= now < fresh_until`; five ordinary clock/origin/partition cases supplement the expiry regression. | Callers derive `fresh_until` from their cache metadata. The Store never serves stale, so no stale-permission branch is required for its advertised capability. |
| D09 / §2.2.2 steps 1–7 | Apply destination filtering; compare dictionary-request origin with outbound-request origin; compile the stored match with the **outbound URL** as base; match that canonical outbound URL. | `select_dictionary_for_url`, `destination_matches`, `pattern_matches`; public `full_url_api_resolves_match_against_the_outgoing_url_test`, cross-origin, query/fragment, canonical host/port, and unrelated-IPv6 regressions. | This procedural seam is implemented and exercised. Any future automatic request path must preserve it: compiling once against the dictionary path changes the RFC algorithm. |
| D10 / §2.2.3 | Choose one candidate by destination specificity, then original match-string length, then newest fetch time. | `preferred`; `dictionary_selection_uses_all_three_precedence_rules_test` and unsupported-capability precedence tests. | Wire `match` is an ASCII Structured Field String; internal Unicode-pattern helper support is broader and does not redefine this comparison's wire input. The integrated client does not emit the selected result. |
| D11 / §3 | The `compression-dictionary` link relation permits prefetching; the fetched response still uses ordinary dictionary advertisement and cache headers. | No automatic prefetch consumer. | Optional prefetch is not needed to send dictionaries received normally. If implemented, test that a link alone does not admit bytes without the response checks. |
| D12 / §4 | DCB consists of `ff 44 43 42`, a 32-byte dictionary hash, and a Shared Brotli stream using the external raw dictionary. Support the required 16 MiB decoder window. | `encode` framing branches, `open_dictionary_header`, Brotli raw-prefix codec; framing, independent raw-prefix, and `dictionary_window_test` native cases. | The codec window obligation is tested; this does not assert automatic `Accept-Encoding: dcb` or close unrelated RFC 9841 formats. Malformed/truncated framing remains codec error handling. |
| D13 / §5 | DCZ consists of the eight-byte skippable-frame prefix `5e 2a 4d 18 20 00 00 00`, the 32-byte dictionary hash, and the Zstandard stream. | Same framing helpers plus `http_compression_ffi`; framing/hash and independent dictionary-window cases. | Selected-record encoding and decode both validate content hashes. The prefix's 32-byte payload length is not a normal Zstandard content frame. |
| D14 / §5 | Decoder capacity is `min(128 MiB, max(8 MiB, 1.25 × dictionary_size))`; the encoded window must be strictly smaller than the resulting limit. Oversized encoded windows may be refused. | Independent backward-reference fixtures and public encoder frame-window inspection in `http_dictionary_window_test.erl`, discovered by `dictionary_window_test.gleam`. | Preserve the strict encoder inequality. Decoder acceptance at a capability limit does not license encoding at that limit. See the reference/compiler/native-lifetime evidence in [BROTLI.md](BROTLI.md). |
| D15 / §§6–6.2 | Normal content negotiation selects the coding; the advertised dictionary selects compatible dictionary bytes. Opt-out/no-match omits dictionary advertisement. Cacheable dictionary-coded responses vary on both negotiation fields. | Helpers expose coding and field values; no automatic client/server policy connects them. | Conditional wire obligations are NotApplicable to library-owned behavior because neither endpoint advertises or serves CDT. An application implementing that feature owns q-values, header uniqueness, cacheability, `Vary`, and fallback. |
| D16 / §§7–7.3 | Register `dcb`, `dcz`, the three field names, and the link relation. | Names/framing are present in helpers; registry provenance is maintained separately by the standards manifest. | IANA publication instructions are not an implementation operation. No registration, network publication, or third-party update is required here. |
| D17 / §8 | Restrict dictionary use to authenticated HTTPS contexts. | Explicit store APIs reject insecure URL contexts; public isolation/secure-context tests. | The byte codec has no transport semantics, and neither integrated endpoint performs CDT. Applications composing transport must gate it on the authenticated connection, not merely a URL string. |
| D18 / §§9–9.2 | Account for inherited codec risks, dictionary/content integrity, and compression disclosures when attacker-controlled and confidential inputs can interact. | Bounded codec failures, content-hash validation, and store partitioning are relevant controls. | Application data provenance and confidentiality policy remain application responsibilities; the public API does not claim to infer them. |
| D19 / §§9.3–9.3.2 | Mitigation failure discards the response and produces an error. Protect both dictionary and compressed response under a protected client's cross-origin/readability model. | Canonical same-origin checks and atomic typed codec failures exist. No Fetch/CORS response-readability model is connected to the general HTTP client. | The integrated client does not perform CDT, and it has no browser response-tainting boundary; the conditional protected-client duties are NotApplicable. |
| D20 / §9.3.3 | Evaluate server request context: missing `Sec-Fetch-Site`, same-origin, missing mode, navigate/same-origin mode, then CORS response/origin permissions; otherwise the algorithm returns false. Consider avoiding dictionary compression for false contexts and uncontrolled content. | No server dictionary-compression policy consumes these fields. | This lower-case mitigation guidance is not an additional BCP 14 row. An application adding CDT can adopt the algorithm at its response boundary. |
| D21 / §10 | Dictionary retention/partitioning/clearing follows the client's cookie privacy policy, with equal or stricter partitioning. | `clear_dictionaries` scopes plus `dictionary_capability_test`; byte-accounting/old-value lifetime in `dictionary_memory_test`. | `http.Client` owns no dictionary state. The standalone immutable Store is application-owned; callers that compose CDT must replace it when their cookie policy clears and discard old values they no longer need. |
| D22 / §11 | Normative references are Fetch, RFC 8792 example line folding, HTTP (RFC 9110), HTTP caching (RFC 9111), BCP 14 (RFC 2119/8174), SHA-256 (RFC 6234), Shared Brotli (RFC 9841), Structured Fields (RFC 9651), URI syntax (RFC 3986), URLPattern, Web Linking (RFC 8288), and Zstandard (RFC 8878). | Separate requirement maps and the explicitly pinned profile below provide ownership boundaries. RFC 8792 folding applies to displayed examples, not literal field bytes sent on the wire. | RFC 5861, RFC 6265, RFC 7457 and RFC 7932 are listed by this RFC as informative references. Their classification does not remove the direct freshness, cookie-equivalence or DCB obligations stated in RFC 9842 itself. This document inventories the imported seams; it does not close every referenced specification. |

## Adopted URLPattern and URL profile

| Input to the profile | Exact authority | Use and limitation |
| --- | --- | --- |
| URLPattern | [RFC-referenced snapshot `696b4029d52e5854044bac6b72cdb198cb962ed0`](https://urlpattern.spec.whatwg.org/commit-snapshots/696b4029d52e5854044bac6b72cdb198cb962ed0/), captured HTML SHA-256 `e93fd5310a762a3835f256aa6c1b076634f57c1ef5bd170fb9a8ffabc7fea936` | String constructor, eight component patterns, create/match/has-regexp operations. |
| Callback corrections | [Snapshot `aeb2019cf3aa1fb31af134a682c0255302a41297`](https://urlpattern.spec.whatwg.org/commit-snapshots/aeb2019cf3aa1fb31af134a682c0255302a41297/), HTML SHA-256 `f2392c3bad5ccb3b253cfcebdb98f16abb12c4669c578396dd7ab518957a9d87` | Explicitly adopted June 2026 URL setter/callback corrections. This is a documented combined profile; it is not silently treated as the original RFC snapshot. |
| URL algorithms used by callbacks and parsed inputs | [URL snapshot `8e14777cfa145b08a9fb735fe580ec0c366564c3`](https://url.spec.whatwg.org/commit-snapshots/8e14777cfa145b08a9fb735fe580ec0c366564c3/), HTML SHA-256 `8e2eef304c23375141e1ac38268d5b5a54eff934c14c3175b323aab419b0dfbe` | Special HTTP(S) URL parsing, state overrides, origin serialization, host processing. RFC 9842's separately named `[URL]` reference is RFC 3986; this WHATWG dependency enters through URLPattern and is identified separately. |
| Unicode | Unicode 16.0.0 identifier properties and UTS #46/NFC data; exact input hashes in `scripts/urlpattern_reference.mjs` and `scripts/url_host_tables.py` | Nontransitional mapping, contextual joiners, domain-wide Bidi, bounded pure host processing. See [URL_HOST_CANONICALIZATION.md](../docs/URL_HOST_CANONICALIZATION.md). Newer Unicode data in a runtime is not substituted. |
| Fetch destinations/readability | [RFC-referenced Fetch snapshot `5a9680638ebfc2b3b7f4efb2bef0b579a2663951`](https://fetch.spec.whatwg.org/commit-snapshots/5a9680638ebfc2b3b7f4efb2bef0b579a2663951/) | Destination capability is explicit; full Fetch/readability behavior is not implemented by the dictionary helper. |
| Independent observations | Node 26.8.2 and Chromium 153.0.8010.36, exact binaries/script/input identities in [urlpattern-full-independent.json](../test/fixtures/urlpattern-full-independent.json) | Agreement is supporting evidence, not normative authority. Node uses newer Unicode data than this host profile. |

The RFC field takes a String, not a JavaScript `URLPatternInit` object.
The implementation still applies the init-processing semantics needed after parsing that string and inheriting its base.
Arbitrary regexp parts are rejected; the canonical segment/full wildcard forms allowed by the specification's has-regexp test remain usable.
Matching is case-sensitive unless a component's canonicalization already removes the distinction.
No public JavaScript class,
constructor overload, capture-object API, pattern-string getter, comparison API,
or user-selected `ignoreCase` option is claimed.
Their absence is not a missing RFC String-to-boolean operation.
Semantics that those algorithms contribute to compilation and matching are still in scope.

### Constructor, component, and callback inventory

All implementation paths in this table are under [`src/http/internal/url_pattern/`](../src/http/internal/url_pattern/).
`full` means [url_pattern_full_test.gleam](../test/url_pattern_full_test.gleam),
`constructor` means [url_pattern_constructor_test.gleam](../test/url_pattern_constructor_test.gleam),
`encoding` means [url_pattern_encoding_test.gleam](../test/url_pattern_encoding_test.gleam),
and `path` means [dictionary_url_pattern_test.gleam](../test/dictionary_url_pattern_test.gleam).
The source-bound profile and its ordinary tests record the exact semantic steps claimed for this RFC consumer.
They do not claim a general JavaScript `URLPattern` API, regexp engine, capture API, or runtime-selected Unicode data.

| ID / imported algorithm | Implementation seam | Executable checks or precise remaining proof |
| --- | --- | --- |
| P01 / §1.3 structs; §1.4 create, match, has-regexp | `pattern.compile`, `pattern.matches`, eight compiled components | `full.absolute_patterns_match_all_url_components_test`, `arbitrary_regexp_groups_are_rejected_in_every_component_test`; canonical wildcard checks in `path`. The RFC consumes boolean matching, not capture results. |
| P02 / §1.5 special-scheme predicate | `pattern.special_scheme`, compiled protocol tested against the six special schemes | `constructor.special_scheme_pattern_controls_authority_and_default_path_test`; step-indexed cases for all six schemes, optional patterns and opaque selection; `full` 517-case corpus. |
| P03 / §1.5 IPv6-pattern detection, absolute pathname, dummy URL | `pattern.options` IPv6-prefix detection, `absolute_path`, encoding helpers | `constructor.named_hostname_and_bracketed_address_do_not_create_a_port_test`, `encoding.ipv6_pattern_pieces_are_not_complete_address_parses_test`, relative/base full tests. Fully parsed candidate IPv6 and pattern fixed-piece syntax are separate contracts. |
| P04 / §1.6 initial, protocol, authority and host states | `constructor.parse_with_work` and its token/state traversal | The finite matrix assigns EOF/rewind, protocol/authority and host-EOF steps explicit maps; absolute/default-port, named hostname, special-scheme, and constructor WPT cases add breadth. |
| P05 / §1.6 username, password, port states | Same constructor FSM, IPv6 bracket depth, credential separators | Matrix cases cover credentials, repeated `@`, escaped `:`, empty/end ports and IPv6 brackets; direct constructor and full-pattern cases preserve the boundaries. |
| P06 / §1.6 path, search, hash, group/modifier transitions | Constructor token boundaries and missing-versus-empty components | `relative_search_and_hash_preserve_missing_fields_test`, `named_optional_modifier_is_not_a_search_boundary_test`, `escaped_delimiters_and_group_contents_follow_token_boundaries_test`. |
| P07 / §§2.1.1–2.1.2 tokenization | `component` strict/lenient lexer and `unicode` identifier tables | `path.unicode_identifiers_obey_start_and_continue_properties_test`, missing-name/dangling-escape, nested-group and escaped-syntax checks; constructor tests exercise lenient delimiters. Invalid regexp-token recognition must remain distinct from permitted primitive wildcards. |
| P08 / §§2.1.3–2.1.5 parts, options, add-part and names | Component parser, duplicate-name set, pending fixed text, normalization | `path.duplicate_capture_names_are_invalid_test`, optional/repeated/named segment cases; `full` fixed-group path/IPv4/NFC regressions detect encoding before adjacent fixed-text merge. |
| P09 / §2.2 matching semantics | Bounded Thompson automaton replaces generated JavaScript regexp execution | The 180-case cross product covers every admitted literal/segment/full part, four modifiers, three actual separator/prefix options and five candidate shapes; prefix/suffix repetition, pathname 136-case and full 517-case generators supplement it. |
| P10 / §2.3 pattern-string conversion | No exposed getter or textual regexp; raw parsed components and normalized parts feed compilation | Getter/capture rendering is outside the RFC surface. Any conversion property used internally, notably default-port removal and fixed-text escaping, remains covered by P11/P12 and must not be dismissed as an API-only detail. |
| P11 / §3.2 init processing and base inheritance | `pattern.apply_base`, `inherit`, `escape`, `absolute_path` | Full relative-directory, search/hash-only, inherited metacharacters and maximum escaped-path tests. Public `dictionary_url_context_test` verifies the fetched-base versus outbound-base distinction. |
| P12 / §1.4 default-port handling; §3.1 port callback | `pattern.remove_default_port`, `encoding.port` | The matrix separates protocol-dependent complete URL default removal from the port-only callback's empty/numeric-prefix/range behavior; direct full and encoding tests retain both contracts. |
| P13 / §3.1 protocol callback | `encoding.protocol` | `encoding.protocol_case_and_empty_value_are_canonical_test`; constructor scheme controls. |
| P14 / §3.1 username/password callbacks | `encoding.encode(Userinfo)` | `encoding.credentials_percent_encode_reserved_and_utf8_bytes_test`, full credentials and URL-parser multiple-`@` checks. |
| P15 / §3.1 hostname callback | `pattern.hostname_piece`, host-state preprocessing and `host.canonicalize` | Matrix and direct full tests cover nonempty preprocessing, strict empty-prefix rejection, delimiters, port-inside-piece, and the separate complete-host behavior; the recorded reference divergence remains explicit below. |
| P16 / §3.1 IPv6 hostname callback | `encoding.encode(Ipv6Pattern)` / `ipv6_piece`, ASCII hex/bracket/colon fixed-piece rule | `encoding.ipv6_pattern_pieces_are_not_complete_address_parses_test`; unrelated IPv6/domain must be a clean non-match after canonical input parsing. |
| P17 / §3.1 hierarchical pathname callback | `pathname`, component fixed-piece callback, retained variable boundaries | Pathname WPT, fixed-group dot-segment tests, trailing wildcard and inherited path tests. Variable parts cannot be deleted by normalizing a following `..`. |
| P18 / §3.1 opaque pathname callback | `encoding.encode(OpaquePath)` | Matrix and direct tests retain dots/slashes, `?`/`#` transitions and terminal-space behavior, explicitly separating the pinned callback from observed runtime setter behavior. |
| P19 / §3.1 search and hash callbacks | `encoding.encode(Search/Hash)` | Encode-set tests, full query apostrophe and independent query/fragment tests; empty query/hash distinct from absent in URL-parser tests. |
| P20 / canonical input processing for §1.4 match | `url.parse`, `component.matches_canonical`, `pattern.match_parts` | `url_pattern_url_test`, `full.ipv6_pattern_against_a_domain_is_a_clean_non_match_test`, public unrelated-IPv6 control. A canonical candidate must not run through a pattern's fixed-piece callback again. |
| P21 / imported host/Unicode algorithms | `host`, `host_ip`, `host_idna`, `host_nfc`, `host_punycode`, generated tables | `url_pattern_host_test` and ordinary reference generator cover fixed hosts, UTS #46, NFC, hex overflow, joiner/Bidi and expansion; the profile explicitly pins Unicode 16.0.0 rather than substituting a runtime version. |
| P22 / bounded operation policy | Constructor work, input/output byte limits, pre-admitted component graph, shared selection work | Full negative-credit, expanded-graph, inherited-maximum-path, construction/matching budget tests; `path.matching_work_exhaustion_is_an_error_test`. Exhaustion is an error, not proof a normative pattern is invalid or a clean non-match. |
| P23 / integration surface | Explicit full fetched/outgoing URL APIs, origin equality, partition/destination/freshness before matching | Fifteen public context tests plus capability/store tests cover the consumer seam. Automatic HTTP collection and header policy are outside the library-owned CDT boundary. |

### Explicit profile differences and resource limits

The reference generator retains 13 hostname-object controls separately from the 517 full-string cases.
For an empty hostname prefix before `/`, `?`, or `#`,
Chromium constructs an empty hostname while Node rejects it.
The current callback follows the pinned special-host empty-buffer rejection.
Nonempty prefixes terminate at those delimiters; they are a different case.
Complete host inputs keep their strict delimiter rules.
The full-string 517-case agreement does not erase these three object-callback differences.

Query apostrophes follow the special-query percent-encode set.
Opaque pathname callbacks follow the adopted URL state transitions for `?` and `#`; observed component setters in a reference runtime can differ.
Unicode 16 host data also has retained disagreements with Node's newer Unicode data and Bidi behavior.
These are profile decisions to validate, not convenient selections of whichever runtime accepts an input.

The bounded profile admits 2,048-byte authored patterns, 10,240-byte complete URL input/output, 8,192-byte canonical component input/output, 24,576-byte derived escaped components, and at most 16,384 automaton states before graph construction.
Selection shares 8,388,608 work units across candidates.
Complete host input/output is bounded at 2,048 bytes, with mapping/decomposition expansion explicitly bounded; details and actual measurements are in [URL_HOST_CANONICALIZATION.md](../docs/URL_HOST_CANONICALIZATION.md).
These local resource refusals must remain distinct from invalid syntax and ordinary non-match.
They are not added limits in the WHATWG standard.

## Executed evidence and its boundary

The retained staged diagnostic summary is `build/diagnostics/urlpattern-reference/summary.json`.
The full matcher result is 569 ordinary leaves: 517 independent full-string cases, 33 selected WPT constructor cases, and 19 direct regressions.
Separate results cover 15 public context tests, 176 related dictionary tests, and seven encoding tests; they are separate suites and their counts must not be added as if disjoint.
Ten intentional mutations were detected across 12 child VMs.

The 569-leaf proof is `build/diagnostics/urlpattern-reference/proof-8a0af3411a673e5065e2d6246152ec85/execution.json` with zero child output, exit status zero, observed child exit, and unchanged captured runtime.
The retained phase-wide HTTP result was 1,856 passes, also with observed exit and zero output.
Both are explicitly diagnostic: other authored sources changed, and the latest unrelated qlog source was not freshly built in that captured runtime.
This document neither reruns nor promotes them to a current-source report.

Reproduction sources are [urlpattern_reference.mjs](../scripts/urlpattern_reference.mjs),
[urlpattern_full_reference.py](../scripts/urlpattern_full_reference.py), and the ordinary generators in the linked test modules.
Codec window proof includes 17 ordinary native controls, independent reference fixtures, encoder-window inspection and native context lifetime checks as described in [BROTLI.md](BROTLI.md).
A source reference proves discoverability; a retained execution proves only its own captured inputs.

The field contract follows [RFC 9651 §§2.3, 3.1, 3.2 and 4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html): Item and Inner List parameters remain part of parsing, duplicate dictionary keys use their last parsed value, and ordered lists may repeat entries.
RFC 9842 adds member types and the ID/hash constraints; it does not prohibit these parameters or repeated destinations.
Known-member parameters are ignored only after complete parsing; unknown members retain their values and parameters.
Malformed syntax still invalidates the entire field.

[dictionary_field_contract_test](../test/dictionary_field_contract_test.gleam) has 21 ordinary controls.
Against the original implementation, 12 passed and nine exposed parameter/repeated-destination refusals.
The minimal correction made all 21 pass; final related execution completed 100 cases.
Seven isolated BEAM mutations were detected: three parameter restrictions, repeated-destination rejection, relaxed hash/ID lengths, and discarded extensions.
The retained summary is `build/diagnostics/dictionary-requirements/field-summary.json`.
Each test VM had an absolute deadline, the unchanged 256 MiB per-process guard,
zero output, and observed exit; captured source and base/overlay runtime bytes were checked before and after.
These are scoped diagnostics from fresh isolated builds, not a current repository qualification.
Server pre-use hash validation has separate selected-record and H1/H2/H3 application-policy evidence; automatic wire selection/echo remains outside the integrated HTTP boundary.

The same final isolated build also completed all 1,877 HTTP cases from 883 configured entrypoints, with exit zero, zero output and unchanged captured inputs.
The 21 new field cases and 100 related cases overlap that full suite;
these counts are not additive.

### Combined-profile input contract and finite step matrix

[urlpattern-profile.json](../test/fixtures/urlpattern-profile.json) now assigns all P01–P23 rows to the pinned authority, an algorithm anchor, named semantic steps, and explicit case IDs or an existing/out-of-surface scope.
Its [270-case matrix](../test/fixtures/urlpattern-profile-cases.json) is generated from explicit examples and primitive-language rules by [url_pattern_profile_fixture.py](../scripts/url_pattern_profile_fixture.py).
These semantic step names identify the decisions required by the shipped string/create/match/regexp-refusal consumer.
The matrix is paired with the broad independent corpus; it does not expose or claim unrelated getter/capture APIs.

| New matrix family | Cases | Observation |
| --- | ---: | --- |
| Constructor transitions | 21 | Missing versus empty component maps, EOF rewinds, authority/credential/port boundaries, group/modifier boundaries, six special schemes and opaque selection. |
| Component languages | 189 | 180 combinations of literal/segment/full parts, four modifiers, three actual separator/prefix options and five candidate strings; four prefix/suffix repetition cases and five rejection/name controls. |
| Encoding callbacks | 19 | Protocol, userinfo, port, IPv6 fixed pieces, opaque path, query and fragment outcomes, including the adopted query/opaque corrections. |
| Full compilation/matching | 24 | Base escaping, inheritance, default-port order, three IPv6 prefixes, split-group refusal, hostname state, merged fixed text, variable boundaries and canonical input. |
| Complete host distinction | 2 | A complete host rejects a delimiter that terminates a nonempty hostname callback piece. |
| Resource contracts | 15 | Negative/zero/sufficient work, no credit replenishment, authored/derived/candidate/encoded-byte boundaries and pre-admitted graph size. |

The shared [fixture validator](../test/url_pattern_profile.hrl) binds the exact profile pins, source generators and Unicode tables, row/step/case inventory,
reference outcomes and 13 hostname-object records.
It rejects duplicate JSON keys and uses bounded reads and parsing.
Its [ordinary wrapper](../test/url_pattern_profile_test.gleam) executes 12 input controls and the 270 matrix cases.
The existing 517-case generator now calls this validator before returning test descriptors.
The [command-line check](../scripts/url_pattern_profile.escript) validates static inputs only; it never certifies that a test or reference runtime executed.

The initial four rejection Reds used an explicitly marked new-contract TDD stub, not a duplicate model presented as an existing-consumer failure.
After implementation, the actual 517-case generator accepted the valid fixture and rejected duplicate IDs, a missing specification row, an old callback pin,
incorrect hostname divergence metadata, a missing matrix case and changed generator source.
Restoring only the old generator entrypoint defeated all six rejections and was detected.
Eight additional isolated BEAM mutations were detected by ordinary cases: accepting every profile, wrong constructor EOF state, skipped default-port removal, repeated candidate canonicalization,
changed query encoding, skipped opaque transitions, and replenished compile or match work.

One initial matrix expectation was corrected before final proof: a group containing only `[` does not update the constructor's top-level IPv6 bracket depth.
The pinned constructor's group handling and Node 26.8.2 both reject that split form.
A group containing the whole IPv6 hostname succeeds.
Both outcomes are now separate cases; no production change was justified by that initial failure.

The retained summary is `build/diagnostics/url-pattern-profile/summary.json`.
The final isolated build passed 1,089 related cases and all 2,159 HTTP cases from 885 entrypoints.
These counts include overlapping existing suites and must not be added to the 270-case matrix or the 517 reference cases.
Test and consumer VMs retained zero output, finite deadlines, the unchanged 256 MiB per-process limit, observed exits and unchanged captured source/runtime bytes.
This retained evidence is a scoped diagnostic from a coherent private copy and does not qualify the current whole repository or replay Node/Chromium.
The ordinary test suite executes the bound profile and 270 matrix cases.
Three hostname differences are resolved by the recorded normative decision, and the Unicode input is pinned rather than selected from the runtime.
Together these close the RFC consumer's invalid-pattern requirement without claiming a general URLPattern implementation.

### Selected dictionary validation before encoding

The new internal [dictionary policy](../src/http/internal/dictionary_policy.gleam) accepts the selected record, every `Available-Dictionary` field line, an explicit clock and the existing codec limits.
It requires one valid advertised hash and recomputes SHA-256 from the selected immutable bytes before calling the codec.
Both the advertisement and the record's cached hash must match.
The identifier is not content authority.
Missing, multiple, malformed and mismatching inputs produce the existing typed compression failures; no public API was added.

The record policy also checks signed 64-bit clocks, valid record chronology,
the raw dictionary type and freshness at the exact deadline.
Fresh-only is a conservative local policy, not a new RFC server obligation: RFC 9842 §2.2.1 also permits a client to use a resource it may legitimately serve stale.
This helper does not implement that cache decision, origin/readability/security checks or coding negotiation, and does not take ownership of a Body.

[Sixteen ordinary cases](../test/dictionary_request_policy_test.gleam) first ran against an explicitly documented new-contract TDD baseline that delegated straight to the raw encoder: four passed and twelve failed at the intended assertions.
All sixteen pass after validation.
This is evidence for a missing internal contract, not a defect in the existing advertisement-free raw codec.

[Three public-wire cases](../test/dictionary_request_wire_test.gleam) each perform thirteen requests through verified TLS H1, H2 or H3.
Their application handler composes the existing public field parser, hash function and encoder,
and compares its bounded result with the internal policy.
Cases cover wrong hash, missing/multiple fields, expired records, changed bytes with an unchanged ID/hash, an unrelated ID with matching bytes, and successful DCB/DCZ responses.
The client checks status, selected protocol, coding and decoded bytes; successful requests after refusals confirm continued service.
Fixed typed observations confirm each response source's single cancellation callback and bounded incoming Body cleanup after response transfer.
These are thirty-nine application-policy exchanges, not an automatic negotiation or full security/caching proof.

The initial H2/H3 wire attempts cancelled the incoming Body inside the handler before returning a response.
Fixed stage observations showed that this correctly cancelled the active exchange.
Moving that fixture's cleanup after response transfer made all three pass; no protocol production fix was inferred from the fixture failure.
The related suite completed 91 cases.
Eight private BEAM mutations were detected: omitting the advertised hash comparison, trusting only the cached hash, omitting the cached-hash consistency comparison, accepting no advertisement or multiple lines, relaxing expiry, skipping time validation and bypassing validation in the actual public-primitives application handler.
Retained execution and input identities are summarized in `build/diagnostics/dictionary-request/summary.json`.
The same private fresh build completed all 2,178 HTTP cases from 904 entrypoints,
with zero output, exit zero, observed VM exit and unchanged captured inputs.
The 91 related cases include the sixteen policy cases and three wire cases;
these counts overlap the full suite.
The private copy reuses a coherent prior dependency snapshot and does not qualify all current repository sources.

The common server dispatcher does not call this internal policy because it has no dictionary registry, request advertisement selector, or dictionary-aware content-negotiation feature.
Raw encoders and arbitrary application handlers remain explicit primitives.
If an automatic server CDT feature is added later,
its compulsory boundary must pass every matching field line and the exact selected bytes independently of an ID lookup, retain typed fallback and Body ownership, and resist bypass.
That future feature boundary is not inferred from the application-policy fixture.

### Existing selection contract and automatic-integration boundary

The current public surface declares explicit compression primitives and a dictionary Store.
It does not declare automatic dictionary response production:
`compression.encode` returns bytes, `body.from_bytes` does not retain the selected dictionary's identity, and `server.Handler` returns an arbitrary response Body and headers.
`server.Config` has no dictionary registry or compression policy.
The common `server.run_adopted_worker` dispatches the response, but cannot recover the dictionary bytes used by an arbitrary already-encoded Body.
A `Content-Encoding` or dictionary-hash header is not such provenance.

The generic `server.with_middlewares` hook can run application policy, but it does not make a dictionary registry or validated response production compulsory.
The preceding public-wire fixture therefore remains optional application proof.
No new server setter or public API is introduced here.
Any later declaration must bind dictionary bytes, codec limits and request selection at one compulsory production boundary, including responses that short-circuit middleware.
Server lookup must use the client's advertised hash: applying the client's best-match ranking to every dictionary on the server could select a newer dictionary the client has never obtained.
The opaque Store currently has no hash-lookup API.

The existing selection path did have an independent defect: a record with a future `fetched_at` could be selected, and its recency could displace a record already available to the caller.
Selection also accepted out-of-range clocks even though record admission bounded them.
The five [ordinary regression cases](../test/dictionary_selection_time_test.gleam) produced three intended failures against the unchanged implementation; exact clock endpoints/expiry and canonical origin/partition controls already passed.
The minimal fix validates the selection clock and excludes records before their fetch time.
This is a conservative local interval contract, not a claim that RFC 9842 adds a particular integer range or clock representation.

The same private fresh build passed 109 related cases and all 2,183 HTTP cases from 909 entrypoints.
Six isolated mutations were detected by the five ordinary cases: removing the fetch-time guard, making the fetch boundary exclusive,
removing the clock range, making expiry inclusive, or removing origin or partition equality.
Every case completed with bounded VM execution, zero output and observed VM exit, and the captured sources and base BEAMs remained unchanged.
The retained `build/diagnostics/dictionary-selection/summary.json` binds each run and mutation to its exact inputs.
The related/new counts overlap the full suite, and this coherent prior-dependency copy is a scoped diagnostic,
not current-repository qualification or an actual automatic negotiation run.

[RFC 9842 §2.2.1](https://www.rfc-editor.org/rfc/rfc9842.html#section-2.2.1) permits a resource that is fresh or allowed stale.
This Store adopts the stricter fresh-only alternative.
Applications compute `fresh_until` from their cache metadata; selection then enforces the caller's signed clock and excludes future and expired records.
The separate general HTTP cache helper remains unconnected because the integrated client never advertises this Store.

The inventory has fifteen Implemented properties and eleven precise NotApplicable conditional protocol duties.
`RFC9842.map_complete` is true.
The classification is intentionally narrower than automatic CDT support: adding that feature later would make the corresponding request emission, Vary,
authenticated transport, protected-client readability, and cookie-lifecycle conditions applicable and require new executable evidence.

## Future automatic CDT feature work

| Feature extension | Required design before declaring it | Decisive executable acceptance check |
| --- | --- | --- |
| Automatic client request negotiation | Bind cache-derived admission, destination capability, one selected hash and optional ID to request generation. | H1/H2/H3 observe one consistent selected hash/ID, no dcb/dcz on opt-out or no-match, redirects and changed cache age, with a non-replayable body consumed once. |
| Automatic server response production | Bind request advertisement, exact dictionary bytes, coding negotiation, cacheability and Body ownership in one compulsory boundary. | Wrong bytes/hash/ID and missing or duplicate advertisements cannot bypass validation; cacheable coded responses merge both required `Vary` members and fallback stays uncoded. |
| Browser-style protected client | Add an explicit browsing context, response-taint/CORS policy and atomic drop outcome for dictionary and response resources. | Every readable/unreadable pair, redirect, mitigation rejection and CORS branch returns the specified response or a typed error without partial output. |
| Client-owned dictionary persistence | Make Client own the authoritative dictionary state and bind its isolation and invalidation to the cookie policy. | Cookie clearing removes advertisements in every affected scope, preserves unrelated scopes, and cannot restore cleared state through an internal stale holder. |

These extensions improve product scope but are absent today.
Their conditional RFC duties are mapped as NotApplicable to the current library-owned HTTP paths,
so this completed map does not turn absence into an automatic-CDT claim.
