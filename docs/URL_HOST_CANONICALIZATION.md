# URL host canonicalization

The private `http/internal/url_pattern/host.canonicalize` function parses a complete special URL host and returns its canonical ASCII spelling, including brackets for IPv6.
Its input and output limits are each 2048 UTF-8 bytes.
It performs no DNS lookup, socket operation, subprocess execution, or runtime table loading.
Hostname pattern fragments use separate callbacks; they are not complete hosts.

The implementation pins [WHATWG URL snapshot 8e14777](https://url.spec.whatwg.org/commit-snapshots/8e14777cfa145b08a9fb735fe580ec0c366564c3/) and Unicode 16.0.0 data for UTS #46, NFC, bidi and joining properties.
Entirely ASCII domains follow that URL snapshot's relaxed lowercase rule, including ASCII A-labels.
Non-ASCII domains apply nontransitional processing with CheckBidi and CheckJoiners enabled; DNS length, STD3 and hyphen restrictions are disabled as required for the special-host parser.
Forbidden domain bytes are checked after mapping and canonical composition.

The checked generator permits at most 18 mapped scalars per input scalar and at most 4 scalars per canonical decomposition.
Thus a 2048-byte input has a conservative 147456-scalar intermediate bound; algorithmic Hangul decomposition has width at most 3. The maximum-mapping regression executes 682 copies of U+FDFA (2046 bytes) and observes 12276 normalized scalars before the host rejects the oversized/forbidden result.
Table lookups are binary searches; canonical reordering uses stable sorting.
Punycode additionally bounds its arithmetic to nonnegative values up to 2^31−1 and emitted output to 2048 units.
IPv4 syntax recognition is independent of its 32-bit value bound, so oversized hexadecimal integers are rejected as IPv4 rather than accepted as domains.

`scripts/url_host_tables.py` regenerates the tables offline from five digest-pinned Unicode inputs and a digest-pinned Gleam 1.18.1 formatter.
`scripts/url_host_reference.mjs` uses the pinned Node 26.8.2 executable plus official Unicode 16 test files.
Ordinary tests cover 479 fixed domain/IP cases, 6387 well-formed UTS #46 cases, and all 19965 NFC rows (five normalization relations per row).
Ill-formed UTF-16 rows are explicitly counted and excluded because Gleam input is a Unicode scalar string.
Separate ordinary tests cover malformed percent-decoded UTF-8, byte limits, expansion, and overflow-hex rejection.
Every assertion publishes only a fixed test name, scalar index, or Boolean result.

The fixture also retains 7926 Node differential observations.
Node 26.8.2 uses Unicode 17.0, and its bidi behavior differs from the RFC 5893 domain-wide checks in some cases.
Those observations are diagnostic comparisons, not substitutes for normative Unicode 16 assertions.
This profile does not claim Unicode 17 host conformance or complete URLPattern conformance.
The surrounding URLPattern constructor and matcher have their own qualification scope.

Generation examples (input files are downloaded separately from their official URLs and checked against the generator's pinned hashes):

```text
python scripts/url_host_tables.py --formatter /usr/local/bin/gleam --check INPUT_DIRECTORY
node scripts/url_host_reference.mjs --check INPUT_DIRECTORY
```
