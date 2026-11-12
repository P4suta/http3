param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ReviewedOn = '2026-09-12'
$OutputLabel = 'build/requirements-fragments/rfc9325-closure-review.json'
$InventoryLabel = 'standards/requirements.json'
$RfcLabel = 'build/standards/rfc9325.txt'
$GeneratorLabel = 'scripts/rfc9325_closure_review.ps1'
$OutputPath = Join-Path $RepositoryRoot ($OutputLabel -replace '/', [IO.Path]::DirectorySeparatorChar)
$InventoryPath = Join-Path $RepositoryRoot ($InventoryLabel -replace '/', [IO.Path]::DirectorySeparatorChar)
$RfcPath = Join-Path $RepositoryRoot ($RfcLabel -replace '/', [IO.Path]::DirectorySeparatorChar)
$GeneratorPath = Join-Path $RepositoryRoot ($GeneratorLabel -replace '/', [IO.Path]::DirectorySeparatorChar)
$PinnedRfcBytes = 96608
$PinnedRfcSha256 = 'e3475381d056bde1eed65252954cce68250168454387f6799b38660806f215bc'

function Get-Sha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([Convert]::ToHexString($sha.ComputeHash($Bytes))).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    Get-Sha256Bytes ([IO.File]::ReadAllBytes($Path))
}

function Relative-Path {
    param([Parameter(Mandatory = $true)][string]$Path)
    $root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes repository root: $Path"
    }
    $full.Substring($root.Length).Replace([IO.Path]::DirectorySeparatorChar, '/')
}

function Repo-Path {
    param([Parameter(Mandatory = $true)][string]$Label)
    Join-Path $RepositoryRoot ($Label -replace '/', [IO.Path]::DirectorySeparatorChar)
}

function Evidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Symbol,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][ValidateSet('direct', 'applicable-boundary', 'out-of-scope-comparison')][string]$Relevance
    )
    [ordered]@{ path = $Path; symbol = $Symbol; needle = $Needle; relevance = $Relevance }
}

$EvidenceCatalog = [ordered]@{
    'otp-client-options' = Evidence 'src/http_transport_ffi.erl' 'client_tls_options/3' 'client_tls_options(ServerName, TrustedCertificates, AlpnProtocols) ->' 'direct'
    'otp-server-options' = Evidence 'src/http_transport_ffi.erl' 'server_tls_options/2' 'server_tls_options(CertsKeys, AlpnProtocols) ->' 'direct'
    'otp-tls-version' = Evidence 'src/http_transport_ffi.erl' 'tls_version/1' 'tls_version(Socket) ->' 'direct'
    'otp-client-upgrade' = Evidence 'src/http_transport_ffi.erl' 'upgrade_client_tls/5' 'upgrade_client_tls(' 'applicable-boundary'
    'otp-server-upgrade' = Evidence 'src/http_transport_ffi.erl' 'upgrade_server_tls/5' 'upgrade_server_tls(' 'applicable-boundary'
    'otp-server-credentials' = Evidence 'src/http_transport_ffi.erl' 'server_credentials/2' 'server_credentials(CertificatePem, PrivateKeyPem) ->' 'applicable-boundary'
    'transport-client-upgrade' = Evidence 'src/http/internal/transport.gleam' 'upgrade_client_tls' 'pub fn upgrade_client_tls(' 'direct'
    'h1-prepare' = Evidence 'src/http/internal/http1/exchange.gleam' 'prepare' 'fn prepare(' 'direct'
    'h1-secure-transport' = Evidence 'src/http/internal/http1/exchange.gleam' 'secure_transport' 'fn secure_transport(' 'direct'
    'h2-prepare' = Evidence 'src/http/internal/http2/exchange.gleam' 'prepare' 'fn prepare(outgoing:' 'direct'
    'h2-dial' = Evidence 'src/http/internal/http2/exchange.gleam' 'dial' 'fn dial(' 'direct'
    'h2-negotiate-transport' = Evidence 'src/http/internal/http2/exchange.gleam' 'negotiate_transport' 'fn negotiate_transport(' 'direct'
    'hsts-parse' = Evidence 'src/http/internal/hsts.gleam' 'parse' 'pub fn parse(' 'direct'
    'hsts-applies' = Evidence 'src/http/internal/hsts.gleam' 'applies' 'pub fn applies(' 'direct'
    'hsts-upgrade-port' = Evidence 'src/http/internal/hsts.gleam' 'upgrade_port' 'pub fn upgrade_port(' 'direct'
    'client-hsts-policy' = Evidence 'src/http/client.gleam' 'with_hsts_policy' 'pub fn with_hsts_policy(' 'direct'
    'client-without-hsts' = Evidence 'src/http/client.gleam' 'without_hsts' 'pub fn without_hsts(' 'direct'
    'quic-require-client-tls13' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'require_client_tls13' 'fn require_client_tls13(' 'direct'
    'quic-require-server-tls13' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'require_server_tls13' 'fn require_server_tls13(' 'direct'
    'quic-client-groups' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'client_supported_groups' 'fn client_supported_groups(' 'out-of-scope-comparison'
    'quic-generate-key-pair' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'generate_key_pair' 'fn generate_key_pair(' 'out-of-scope-comparison'
    'quic-cipher-suites' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'supported_cipher_suites' 'fn supported_cipher_suites()' 'out-of-scope-comparison'
    'quic-select-client-alpn' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'select_client_alpn' 'fn select_client_alpn(' 'direct'
    'quic-selected-server-alpn' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'selected_server_alpn' 'fn selected_server_alpn(' 'direct'
    'quic-ticket-issue' = Evidence 'packages/quic_core/src/quic_core/internal/tls/session_ticket.gleam' 'issue' 'pub fn issue(' 'out-of-scope-comparison'
    'quic-ticket-policy' = Evidence 'packages/quic_core/src/quic_core/internal/tls/resumption.gleam' 'server_policy_with_keys' 'pub fn server_policy_with_keys(' 'out-of-scope-comparison'
    'quic-psk-dhe' = Evidence 'packages/quic_core/src/quic_core/internal/tls/engine.gleam' 'client_extensions' 'fn client_extensions(' 'out-of-scope-comparison'
    'quic-aead-limits' = Evidence 'packages/quic_core/src/quic_core/internal/aead_usage.gleam' 'limits' 'pub fn limits(' 'out-of-scope-comparison'
    'quic-aead-update' = Evidence 'packages/quic_core/src/quic_core/internal/aead_usage.gleam' 'needs_key_update' 'pub fn needs_key_update(' 'out-of-scope-comparison'
    'quic-cert-validate' = Evidence 'packages/quic_core/src/quic_core/internal/tls/authentication.gleam' 'validate_server_certificate' 'pub fn validate_server_certificate(' 'direct'
    'quic-rsa-policy' = Evidence 'packages/quic_core/src/quic_core/internal/tls/authentication.gleam' 'server_certificate_public_key_secure' 'pub fn server_certificate_public_key_secure(' 'out-of-scope-comparison'
    'quic-rsa-server-gate' = Evidence 'packages/quic_core/src/quic_core/server.gleam' 'require_secure_server_certificate' 'fn require_secure_server_certificate(' 'out-of-scope-comparison'
    'quic-server-alt-cert' = Evidence 'packages/quic_core/src/quic_core/server.gleam' 'with_certificate' 'pub fn with_certificate(' 'out-of-scope-comparison'
    'h3-connect-to' = Evidence 'packages/http3/src/http3/client.gleam' 'connect_to' 'pub fn connect_to(' 'direct'

    'test-http1-versions' = Evidence 'test/http_alpn_test.gleam' 'http1_tls_accepts_an_explicit_http1_protocol_test' 'pub fn http1_tls_accepts_an_explicit_http1_protocol_test()' 'direct'
    'test-http1-no-alpn' = Evidence 'test/http_alpn_test.gleam' 'http1_tls_accepts_peers_without_an_alpn_extension_test' 'pub fn http1_tls_accepts_peers_without_an_alpn_extension_test()' 'direct'
    'test-http1-alpn-reject' = Evidence 'test/http_alpn_test.gleam' 'http1_tls_rejects_an_incompatible_nonempty_protocol_test' 'pub fn http1_tls_rejects_an_incompatible_nonempty_protocol_test()' 'direct'
    'test-tls13-roundtrip' = Evidence 'test/tls_transport_test.gleam' 'authenticated_tls13_alpn_and_active_once_data_round_trip_test' 'pub fn authenticated_tls13_alpn_and_active_once_data_round_trip_test()' 'direct'
    'test-hostname-mismatch' = Evidence 'test/tls_transport_test.gleam' 'hostname_mismatch_fails_closed_with_a_typed_error_test' 'pub fn hostname_mismatch_fails_closed_with_a_typed_error_test()' 'direct'
    'test-hsts-upgrade' = Evidence 'test/client_test.gleam' 'verified_hsts_policy_upgrades_a_later_cleartext_uri_test' 'pub fn verified_hsts_policy_upgrades_a_later_cleartext_uri_test()' 'direct'
    'test-hsts-auth' = Evidence 'test/client_test.gleam' 'hsts_upgrade_never_bypasses_tls_authentication_failure_test' 'pub fn hsts_upgrade_never_bypasses_tls_authentication_failure_test()' 'direct'
    'test-quic-tls13' = Evidence 'packages/quic_core/test/tls_engine_test.gleam' 'completes_authenticated_client_server_handshake_test' 'pub fn completes_authenticated_client_server_handshake_test()' 'direct'
    'test-quic-version-extension' = Evidence 'packages/quic_core/test/tls_extension_value_test.gleam' 'round_trips_sni_alpn_and_versions_test' 'pub fn round_trips_sni_alpn_and_versions_test()' 'direct'
    'test-quic-alpn-reject' = Evidence 'packages/quic_core/test/tls_engine_test.gleam' 'rejects_alpn_mismatch_and_tampered_finished_test' 'pub fn rejects_alpn_mismatch_and_tampered_finished_test()' 'direct'
    'test-quic-alpn-preference' = Evidence 'packages/quic_core/test/tls_engine_test.gleam' 'rfc7301_server_alpn_preference_is_authoritative_test' 'pub fn rfc7301_server_alpn_preference_is_authoritative_test()' 'direct'
    'test-quic-psk-dhe' = Evidence 'packages/quic_core/test/tls_engine_test.gleam' 'fresh_client_advertises_psk_dhe_for_future_tickets_test' 'pub fn fresh_client_advertises_psk_dhe_for_future_tickets_test()' 'out-of-scope-comparison'
    'test-quic-ticket' = Evidence 'packages/quic_core/test/tls_session_ticket_test.gleam' 'protects_and_restores_bound_resumption_ticket_test' 'pub fn protects_and_restores_bound_resumption_ticket_test()' 'out-of-scope-comparison'
    'test-quic-ticket-rotation' = Evidence 'packages/quic_core/test/tls_resumption_test.gleam' 'previous_ticket_key_resumes_during_bounded_rotation_window_test' 'pub fn previous_ticket_key_resumes_during_bounded_rotation_window_test()' 'out-of-scope-comparison'
    'test-quic-key-limits' = Evidence 'packages/quic_core/test/aead_usage_test.gleam' 'enforces_rfc9001_aead_usage_limits_test' 'pub fn enforces_rfc9001_aead_usage_limits_test()' 'out-of-scope-comparison'
    'test-quic-p256' = Evidence 'packages/quic_core/test/tls_engine_test.gleam' 'completes_p256_key_exchange_in_first_client_hello_test' 'pub fn completes_p256_key_exchange_in_first_client_hello_test()' 'out-of-scope-comparison'
    'test-quic-rsa-small' = Evidence 'packages/quic_core/test/public_api_test.gleam' 'server_rejects_rsa_certificate_below_2048_bits_test' 'pub fn server_rejects_rsa_certificate_below_2048_bits_test()' 'out-of-scope-comparison'
    'test-quic-rsa-live' = Evidence 'packages/quic_core/test/public_loopback_test.gleam' 'rsa_pss_certificate_live_round_trip_test' 'pub fn rsa_pss_certificate_live_round_trip_test()' 'out-of-scope-comparison'
    'test-h3-origin-name' = Evidence 'packages/http3/test/client_endpoint_test.gleam' 'explicit_rootless_anchors_still_verify_the_original_service_name_test' 'pub fn explicit_rootless_anchors_still_verify_the_original_service_name_test()' 'direct'
    'test-h3-origin-destination' = Evidence 'packages/http3/test/client_endpoint_test.gleam' 'explicit_destination_keeps_certificate_identity_verification_test' 'pub fn explicit_destination_keeps_certificate_identity_verification_test()' 'direct'
}

$TaskCatalog = [ordered]@{
    'VERIFY-VERSION-PREFERENCE-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'One independent dual-version TLS peer fixture and focused client/server tests; no public API change.'
        acceptance = @('Offer TLS 1.2 and 1.3 simultaneously to each library-owned OTP endpoint direction.', 'Assert TLS 1.3 is selected and the test fails if either option builder is reordered or constrained to TLS 1.2.')
    }
    'VERIFY-TLS12-AGGREGATE-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'One generated aggregate gate over the RFC 9325 TLS 1.2 rows.'
        acceptance = @('List every applicable TLS 1.2 row transitively required by occurrence 8.', 'Refuse closure while any listed row is Open or lacks current-source executable evidence.')
    }
    'VERIFY-COMPRESSION-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'One TLS 1.2 wire probe plus one OTP-version capability assertion.'
        acceptance = @('Show that the client offers only null compression and the server rejects a non-null-only offer.', 'Fail on OTP 28 and 29 if TLS compression becomes negotiable.')
    }
    'VERIFY-RESUMPTION-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'Focused OTP TLS 1.2/1.3 session and ticket probes; no QUIC claim and no broad performance suite.'
        acceptance = @('Determine separately whether client and server OTP paths resume sessions or issue/use tickets under the exact configured options.', 'If resumption is reachable, prove authentication, encryption, lifetime, key rotation/destruction, and PSK-DHE behavior; otherwise prove it remains disabled.', 'Promote any observed ungoverned behavior to an implementation task instead of treating absence of evidence as compliance.')
    }
    'VERIFY-RENEGOTIATION-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'Focused TLS 1.2 ClientHello/renegotiation/extended-master-secret peer probes on OTP 28 and 29.'
        acceptance = @('Assert renegotiation_info and extended_master_secret behavior in both endpoint roles.', 'Assert a client-side fatal failure for a peer that omits the required renegotiation acknowledgement.', 'Record negotiated extensions without retaining raw handshake secrets.')
    }
    'VERIFY-ALPN-CLIENT-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'One malicious TLS peer fixture and one forged custom-TLS ServerHello test.'
        acceptance = @('Select an ALPN identifier the client did not offer.', 'Assert both OTP HTTP and custom HTTP/3 clients fail before any request bytes are sent.')
    }
    'VERIFY-ECDSA-PROVIDER-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'A provider-bound signing probe and a short policy note; no replacement cryptography.'
        acceptance = @('Identify the OTP/OpenSSL ECDSA nonce strategy for every supported runtime.', 'If signatures are not RFC 6979 deterministic, record a clause-specific documented deviation with the provider security rationale.')
    }
    'VERIFY-POINT-FORMAT-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'One TLS 1.2 ClientHello/ServerHello extension probe on OTP 28 and 29.'
        acceptance = @('Capture only the ec_point_formats identifiers.', 'Assert the extension is absent or its list is exactly uncompressed.')
    }
    'VERIFY-TLS-KEY-LIMITS-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'Version-pinned OTP source/capability evidence and focused boundary tests; do not attempt a 2^24.5-record campaign.'
        acceptance = @('Establish the confidentiality and integrity limits used by OTP TLS 1.2 and 1.3 for configured suites.', 'Prove key rotation or finite connection close occurs before the applicable limit.', 'Keep QUIC RFC 9001 counters as comparison-only evidence.')
    }
    'VERIFY-GCM-NONCE-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'Version-pinned OTP implementation evidence plus a bounded TLS 1.2 record-sequence probe.'
        acceptance = @('Show that TLS 1.2 AES-GCM nonce_explicit derives from the 64-bit record sequence number.', 'Run on OTP 28 and 29 and reject an unknown provider implementation.')
    }
    'VERIFY-ECDH-REUSE-01' = [ordered]@{
        kind = 'verification'
        maximum_scope = 'A repeated-handshake key-share probe and provider-source identity for OTP 28 and 29.'
        acceptance = @('Show whether the OTP server reuses ECDH ephemeral keys across connections.', 'If reuse occurs, prove X25519 or required peer-point validation; otherwise prove distinct shares across a bounded sample.')
    }
    'IMP-SNI-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'HTTP/1.1 and HTTP/2 OTP server credential selection plus focused TLS tests; no QUIC changes.'
        acceptance = @('Add a bounded exact/wildcard SNI credential selector without exposing certificate contents in diagnostics.', 'Reject an unrecognized presented name and emit the fatal unrecognized_name alert.', 'Test recognized, absent-policy, unrecognized, malformed, timeout, and cleanup paths on TLS 1.2 and 1.3.')
    }
    'IMP-CIPHER-PROFILE-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'One shared explicit OTP TLS 1.2 cipher allowlist/order function and adversarial negotiation tests.'
        acceptance = @('Permit only the four RFC 9325 ECDHE AES-GCM suites, or record a clause-specific documented deviation for an additional equally strong suite.', 'Exclude NULL, RC4, export, sub-128-bit, static RSA, static DH/ECDH, CBC, and TLS_DHE suites.', 'Pin client order and server preference and assert the negotiated suite against hostile offers on OTP 28 and 29.')
    }
    'IMP-GROUP-PROFILE-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'Explicit OTP supported-groups policy plus focused TLS 1.2 negotiation tests.'
        acceptance = @('Offer X25519 and P-256 and no curve below 224 bits.', 'Disable finite-field DHE so short, static, and reused finite-field parameters are unreachable.', 'Assert negotiated group and negative offers on OTP 28 and 29.')
    }
    'IMP-CERT-POLICY-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'A transport-layer credential/signature policy reused by HTTP/1.1 and HTTP/2, with focused certificate fixtures.'
        acceptance = @('Apply the existing RSA 2048-bit boundary to every TCP TLS server credential before listening.', 'Reject SHA-1 and MD5 authentication signatures and explicitly request SHA-256-or-stronger TLS 1.2 signature algorithms.', 'Exercise RSA 2047/2048 boundaries, SHA-1/MD5 rejection, and supported ECDSA/RSA success without importing upper-package types.')
    }
    'IMP-TRUNC-HMAC-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'One explicit TLS 1.2 extension/cipher policy assertion and a negative peer test.'
        acceptance = @('Make Truncated HMAC negotiation unreachable on both OTP endpoint roles.', 'Reject a peer path that attempts to require the extension and retain only fixed diagnostic codes.')
    }
    'IMP-REVOCATION-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'A typed finite revocation policy at both client certificate-validation boundaries, with deterministic local fixtures.'
        acceptance = @('Support a bounded CRL, OCSP, or caller-supplied revocation decision with explicit hard/soft-fail policy.', 'Reject a revoked leaf and intermediate, define stale/unreachable responder behavior, and never log certificate bytes or target names.', 'Cover cancellation, timeout, callback exit, saturation, and cleanup.')
    }
    'IMP-OCSP-STAPLING-01' = [ordered]@{
        kind = 'implementation'
        maximum_scope = 'OTP HTTP server OCSP/status_request configuration and focused peer tests.'
        acceptance = @('Expose bounded OCSP stapling configuration for TLS 1.2 and 1.3 server credentials.', 'Prove a valid staple is sent, stale/malformed staples fail closed according to policy, and disabled mode is explicit.', 'Avoid network-dependent tests by using deterministic local OCSP fixtures.')
    }
}

$script:Decisions = [Collections.Generic.List[object]]::new()
function Add-Decision {
    param(
        [int]$Occurrence,
        [string]$Obligation,
        [ValidateSet('Implemented', 'NotApplicable', 'DocumentedDeviation', 'Open')][string]$Disposition,
        [string]$FindingClass,
        [string]$Reason,
        [string[]]$ImplementationKeys,
        [string[]]$TestKeys,
        [AllowEmptyString()][string]$TaskId,
        [AllowEmptyString()][string]$AcceptanceFocus
    )
    $script:Decisions.Add([ordered]@{
        source_occurrence = $Occurrence
        obligation = $Obligation
        proposed_disposition = $Disposition
        finding_class = $FindingClass
        reason = $Reason
        implementation_keys = @($ImplementationKeys)
        test_keys = @($TestKeys)
        task_id = $TaskId
        acceptance_focus = $AcceptanceFocus
    })
}

function Add-Implemented { param($N,$O,$R,[string[]]$I,[string[]]$T) Add-Decision $N $O 'Implemented' 'ConfirmedImplemented' $R $I $T '' '' }
function Add-NA { param($N,$O,$R,$Class='ConditionalOutOfScope') Add-Decision $N $O 'NotApplicable' $Class $R @() @() '' '' }
function Add-EvidenceGap { param($N,$O,$R,[string[]]$I,[string[]]$T,$Task,$Focus) Add-Decision $N $O 'Open' 'InsufficientEvidence' $R $I $T $Task $Focus }
function Add-Missing { param($N,$O,$R,[string[]]$I,[string[]]$T,$Task,$Focus) Add-Decision $N $O 'Open' 'MissingImplementation' $R $I $T $Task $Focus }
function Add-Aggregate { param($N,$O,$R,[string[]]$I,[string[]]$T,$Task,$Focus) Add-Decision $N $O 'Open' 'BlockedAggregate' $R $I $T $Task $Focus }

$VersionImpl = @('otp-client-options','otp-server-options','otp-tls-version')
$VersionTests = @('test-http1-versions','test-tls13-roundtrip')
$OtpBoundary = @('otp-client-options','otp-server-options')
$ResumptionComparison = @('otp-server-options','quic-ticket-issue','quic-ticket-policy','quic-psk-dhe')
$ResumptionTests = @('test-quic-ticket','test-quic-ticket-rotation','test-quic-psk-dhe')
$CipherComparison = @('otp-client-options','otp-server-options','quic-cipher-suites')
$GroupComparison = @('otp-client-options','otp-server-options','quic-client-groups','quic-generate-key-pair')

Add-Implemented 1 'Do not negotiate SSLv2.' 'Both OTP option builders allow only TLS 1.3 and TLS 1.2, and the post-handshake version decoder rejects anything else. Live tests exercise both permitted versions, so SSLv2 is unreachable on the applicable HTTP/1.1 and HTTP/2 TLS paths.' $VersionImpl $VersionTests
Add-Implemented 2 'Do not negotiate SSLv3.' 'The exact allowlist and post-handshake decoder admit only TLS 1.2 or 1.3. The live permitted-version matrix makes SSLv3 unreachable on both OTP endpoint roles.' $VersionImpl $VersionTests
Add-Implemented 3 'Do not negotiate TLS 1.0.' 'The client and server configure only TLS 1.3 and 1.2, and reject any other negotiated version before exposing the stream. Existing live tests cover each allowed version.' $VersionImpl $VersionTests
Add-Implemented 4 'Do not negotiate TLS 1.1.' 'The client and server configure only TLS 1.3 and 1.2, and reject any other negotiated version before exposing the stream. Existing live tests cover each allowed version.' $VersionImpl $VersionTests
Add-Implemented 5 'Support TLS 1.2.' 'Both OTP endpoint roles explicitly include TLS 1.2, and the independent HTTP/1.1 ALPN fixture completes TLS 1.2 handshakes and exchanges an authenticated request.' $VersionImpl @('test-http1-versions')
Add-Implemented 6 'Support TLS 1.3.' 'Both OTP endpoint roles explicitly include TLS 1.3, and independent transport and HTTP/1.1 fixtures complete authenticated TLS 1.3 handshakes.' $VersionImpl @('test-http1-versions','test-tls13-roundtrip')
Add-EvidenceGap 7 'Prefer TLS 1.3 over earlier TLS versions when TLS 1.3 is implemented.' 'The option lists place TLS 1.3 first, but no existing test offers TLS 1.2 and 1.3 simultaneously and observes the selected version in both endpoint roles. OTP negotiation semantics are therefore assumed rather than current-source evidenced.' $OtpBoundary $VersionTests 'VERIFY-VERSION-PREFERENCE-01' 'Prove TLS 1.3 wins a simultaneous TLS 1.2/1.3 offer in both endpoint directions.'
Add-Aggregate 8 'When TLS 1.2 is supported, follow every RFC 9325 recommendation that applies to TLS 1.2.' 'This is an aggregate obligation. Cipher policy, compression, resumption, renegotiation, record limits, nonce construction, key groups, revocation, and stapling still contain Open findings, so this row cannot close independently.' $OtpBoundary @('test-http1-versions') 'VERIFY-TLS12-AGGREGATE-01' 'Close only after every applicable TLS 1.2 child row is non-Open with current evidence.'
Add-Implemented 9 'A new transport protocol integrating TLS must use only TLS 1.3.' 'This occurrence expressly covers new TLS-integrating transports. The QUIC core emits and accepts only the TLS 1.3 SupportedVersions value, rejects any other server selection, and has authenticated handshake tests.' @('quic-require-client-tls13','quic-require-server-tls13') @('test-quic-version-extension','test-quic-tls13')
Add-NA 10 'A newly designed application protocol layered on TLS must integrate TLS 1.2 and TLS 1.3.' 'The repository implements standardized HTTP/1.1, HTTP/2, and HTTP/3; it does not define a new application protocol. Existing HTTP version support is governed by those protocol specifications, so this protocol-designer duty has no library-owned triggering state.' 'ProtocolDesignerRole'
Add-NA 11 'Do not negotiate DTLS 1.0.' 'No public client or server API provides DTLS. UDP transport is QUIC, whose TLS 1.3 handshake is expressly outside the RFC 9325 DTLS profile.'
Add-NA 12 'Support DTLS 1.2.' 'No public client or server API provides DTLS, so this positive DTLS capability is outside the declared product surface.'
Add-NA 13 'Support DTLS 1.3.' 'No public client or server API provides DTLS, so this advisory DTLS capability is outside the declared product surface.'
Add-NA 14 'Prefer DTLS 1.3 when DTLS 1.3 is implemented.' 'The antecedent is false because the library implements no DTLS endpoint.'
Add-Implemented 15 'A TLS 1.2 client must not fall back to an earlier TLS version.' 'The client performs one OTP TLS handshake with an allowlist containing only TLS 1.3 and 1.2; it has no retry path that widens the version set. The post-handshake decoder also rejects older versions.' @('otp-client-upgrade','otp-client-options','otp-tls-version') @('test-http1-versions')
Add-NA 16 'If a protocol defines both dynamic TLS upgrade and a separate TLS-only method, implementations must support the TLS-only method.' 'HTTP in this repository uses cleartext and dedicated TLS listeners/connect paths and exposes no STARTTLS-style in-band upgrade. The conditional protocol shape does not occur.'
Add-NA 17 'Administrators must prefer the separate TLS-only method over dynamic upgrade.' 'This is an administrator deployment choice and the library exposes no dynamic-upgrade mode to choose.' 'ExternalOperatorRole'
Add-NA 18 'If a protocol has only dynamic TLS upgrade, implementations must expose a strict no-plaintext policy.' 'The library implements no protocol whose only protection mechanism is an in-band TLS upgrade, so the antecedent is false.'
Add-NA 19 'Administrators must enable the strict no-plaintext policy for an upgrade-only protocol.' 'This is an external administrator duty and there is no upgrade-only protocol mode in the public API.' 'ExternalOperatorRole'
Add-Implemented 20 'HTTP clients and servers intended for the Web must support HSTS.' 'The integrated client parses, bounds, persists, expires, applies, and can explicitly configure HSTS. Server responses accept arbitrary header fields, including Strict-Transport-Security. Tests prove verified learning, URI upgrade, and that an upgrade never bypasses certificate authentication.' @('hsts-parse','hsts-applies','hsts-upgrade-port','client-hsts-policy','client-without-hsts') @('test-hsts-upgrade','test-hsts-auth')
Add-NA 21 'A deployed web server should send HSTS unless doing so would weaken security.' 'Whether a particular deployment should emit Strict-Transport-Security depends on its certificate and topology. Applications own response headers, while the library already permits the field; automatic emission would invent operator policy.' 'ExternalOperatorRole'
Add-EvidenceGap 22 'TLS 1.2 implementations and deployments should not negotiate TLS-level compression unless the application is proven safe.' 'Neither OTP option builder requests compression, but no repository test or pinned OTP capability evidence proves that a non-null TLS 1.2 compression offer is impossible on OTP 28 and 29.' $OtpBoundary @() 'VERIFY-COMPRESSION-01' 'Prove null-only TLS compression behavior for both client and server roles.'
Add-EvidenceGap 23 'When session resumption is used, authenticate and encrypt the resumption information.' 'The HTTP server disables legacy session reuse, but the exact TLS 1.2 client cache and TLS 1.3 ticket behavior of the configured OTP versions is not tested. QUIC tickets are authenticated and encrypted, but RFC 9325 Section 5 makes that comparison insufficient for the applicable OTP paths.' $ResumptionComparison $ResumptionTests 'VERIFY-RESUMPTION-01' 'Determine reachability first; if reachable, prove authenticated and encrypted resumption state.'
Add-EvidenceGap 24 'Use a ticket-encryption cipher at least as strong as the main TLS cipher.' 'The custom QUIC ticket uses AES-256-GCM, but QUIC is out of scope here. Current tests do not establish whether applicable OTP TLS emits tickets or which protection it uses.' $ResumptionComparison @('test-quic-ticket') 'VERIFY-RESUMPTION-01' 'Prove tickets are disabled or identify and verify their protection strength on OTP TLS.'
Add-EvidenceGap 25 'Rotate ticket-encryption keys regularly.' 'The custom QUIC API has an explicit current/previous key ring, but no current-source test establishes applicable OTP TLS ticket issuance or rotation. It is unsafe to infer compliance from the unrelated QUIC key ring.' $ResumptionComparison @('test-quic-ticket-rotation') 'VERIFY-RESUMPTION-01' 'Prove OTP tickets are disabled or demonstrate a finite, observable rotation schedule.'
Add-EvidenceGap 26 'Destroy old ticket-encryption keys at the end of their validity period.' 'A QUIC previous-key window is bounded, but applicable OTP TLS key retirement is not configured or observed. The current source cannot prove destruction semantics.' $ResumptionComparison @('test-quic-ticket-rotation') 'VERIFY-RESUMPTION-01' 'Prove OTP tickets are disabled or that expired key generations can no longer resume.'
Add-EvidenceGap 27 'Limit session-ticket validity to a reasonable duration.' 'The QUIC ticket implementation caps lifetime at seven days, but no applicable OTP TLS ticket lifetime is pinned or tested. The conditional obligation cannot be closed until ticket reachability is known.' $ResumptionComparison @('test-quic-ticket') 'VERIFY-RESUMPTION-01' 'Prove OTP tickets are disabled or assert a finite configured lifetime and expiry rejection.'
Add-EvidenceGap 28 'A TLS 1.2 server should not resume sessions that are too old.' 'The server passes reuse_sessions=false, which appears stronger than the recommendation, but there is no adversarial TLS 1.2 resumption probe proving that no server-side resumption remains reachable under OTP 28 and 29.' @('otp-server-options','otp-server-upgrade') @('test-http1-versions') 'VERIFY-RESUMPTION-01' 'Attempt old and fresh TLS 1.2 resumption and prove both are disabled or the old session is rejected.'
Add-EvidenceGap 29 'A TLS 1.3 client resuming a session should send key_share.' 'The QUIC client always advertises PSK-DHE and key_share, but QUIC is comparison-only. No test inspects the applicable OTP TLS 1.3 resumption ClientHello.' @('otp-client-options','quic-psk-dhe','quic-generate-key-pair') @('test-quic-psk-dhe') 'VERIFY-RESUMPTION-01' 'Inspect an OTP TLS 1.3 resumption ClientHello and require key_share when resumption occurs.'
Add-EvidenceGap 30 'A TLS 1.3 server should select psk_dhe_ke and answer with key_share during resumption.' 'The custom QUIC engine enforces PSK-DHE, but RFC 9325 excludes QUIC from this profile. Applicable OTP TLS 1.3 server resumption mode and ServerHello extensions are unobserved.' @('otp-server-options','quic-psk-dhe','quic-ticket-policy') @('test-quic-psk-dhe','test-quic-ticket') 'VERIFY-RESUMPTION-01' 'Inspect an OTP TLS 1.3 resumed handshake and require PSK-DHE plus server key_share.'
Add-EvidenceGap 31 'TLS 1.2 clients and servers must implement renegotiation_info.' 'TLS 1.2 handshakes succeed, but the repository neither pins OTP secure-renegotiation options nor records the extension in both roles. Provider behavior is assumed.' $OtpBoundary @('test-http1-versions') 'VERIFY-RENEGOTIATION-01' 'Prove renegotiation_info support in both OTP roles.'
Add-EvidenceGap 32 'A TLS 1.2 client must send renegotiation_info in ClientHello.' 'No existing wire-level client test observes renegotiation_info. Successful TLS 1.2 negotiation alone does not prove the exact ClientHello extension.' @('otp-client-options') @('test-http1-versions') 'VERIFY-RENEGOTIATION-01' 'Capture the TLS 1.2 ClientHello and assert renegotiation_info is present.'
Add-EvidenceGap 33 'A TLS 1.2 client must send a fatal handshake_failure if the server does not acknowledge renegotiation_info.' 'No hostile server fixture omits the acknowledgement, so the required alert and pre-request termination are unproven.' @('otp-client-upgrade','otp-client-options') @() 'VERIFY-RENEGOTIATION-01' 'Omit the server acknowledgement and assert the client emits/fails with fatal handshake_failure before HTTP bytes.'
Add-EvidenceGap 34 'TLS 1.2 implementations must support extended_master_secret.' 'No option or existing test pins the OTP extended_master_secret extension for either endpoint role. This delegated provider behavior needs direct evidence.' $OtpBoundary @('test-http1-versions') 'VERIFY-RENEGOTIATION-01' 'Observe and require extended_master_secret in both TLS 1.2 endpoint roles.'
Add-NA 35 'Multiplexed protocols should follow RFC 9113 advice for post-handshake authentication.' 'The occurrence addresses protocol design. This repository implements the already standardized HTTP/2 and HTTP/3 protocols and exposes no TLS post-handshake client-authentication operation; its HTTP/2 conformance is tracked under RFC 9113.' 'ProtocolDesignerRole'
Add-Missing 36 'TLS clients and servers for HTTPS must support SNI.' 'The OTP client sends SNI, and the HTTP/3 server has name-indexed credentials, but HTTP/1.1 and HTTP/2 server APIs accept only one certificate and do not expose an SNI selector. The server half of the applicable capability is incomplete.' @('otp-client-options','otp-server-options','quic-server-alt-cert') @('test-hostname-mismatch') 'IMP-SNI-01' 'Provide bounded name-based credential selection on both OTP HTTP server paths.'
Add-Missing 37 'A server that does not recognize the presented SNI should not continue the handshake.' 'The HTTP/1.1 and HTTP/2 OTP server options do not compare presented SNI with the configured service identity and can continue with the sole certificate. No explicit documented deviation exists.' @('otp-server-options','quic-server-alt-cert') @() 'IMP-SNI-01' 'Reject an unrecognized SNI before application dispatch on TLS 1.2 and 1.3.'
Add-Missing 38 'An unrecognized SNI should produce a fatal unrecognized_name alert.' 'No OTP server SNI callback is configured, so the library cannot deliberately emit unrecognized_name for an unknown name. Certificate mismatch observed later by a client is not the required server alert.' @('otp-server-options') @() 'IMP-SNI-01' 'Emit and independently observe fatal unrecognized_name for an unknown presented name.'
Add-NA 39 'Quoted RFC 6066 text says a server may continue or abort for an unknown SNI.' 'This uppercase SHOULD occurs inside an explicitly quoted rule that RFC 9325 immediately updates and replaces with occurrences 37 and 38. It is not an independent RFC 9325 obligation.' 'InventoryFalsePositive'
Add-Implemented 40 'A client should abort if an SNI-acknowledging server presents a certificate for a different hostname.' 'The OTP client enables peer verification and HTTPS hostname matching against the original server name. The custom HTTP/3 certificate validator does the same. Independent tests force wrong-origin certificates and observe a typed TLS failure.' @('otp-client-options','quic-cert-validate','h3-connect-to') @('test-hostname-mismatch','test-h3-origin-name','test-h3-origin-destination')
Add-Implemented 41 'TLS clients and servers must support ALPN.' 'Both OTP roles configure ALPN and all HTTP/3 handshakes require ALPN. Tests cover TLS 1.2, TLS 1.3, matching offers, and custom server preference.' @('otp-client-options','otp-server-options','quic-select-client-alpn','quic-selected-server-alpn') @('test-http1-versions','test-quic-alpn-preference')
Add-Implemented 42 'A server with no mutually supported ALPN must send a fatal no_application_protocol alert.' 'OTP servers are configured with preferred protocols and an independent peer observes rejection for a non-overlapping offer on TLS 1.2 and 1.3. The custom TLS server returns NoApplicationProtocol for the same condition.' @('otp-server-options','quic-select-client-alpn') @('test-http1-alpn-reject','test-quic-alpn-reject')
Add-EvidenceGap 43 'A client should abort if the server selects an ALPN value outside the client offer.' 'HTTP/1.1, HTTP/2, and custom TLS code contain explicit selected-value membership checks, but no existing hostile peer test returns an unoffered server selection and proves that request bytes remain unsent.' @('h1-secure-transport','h2-negotiate-transport','quic-selected-server-alpn','otp-client-options') @('test-quic-alpn-reject') 'VERIFY-ALPN-CLIENT-01' 'Directly exercise a server-selected, unoffered ALPN in every client protocol path.'
Add-NA 44 'Providers with multiple protocols on one domain should deploy ALPN.' 'This is a service-provider topology obligation. The library exposes ALPN on every secure protocol, but it cannot determine or configure all services deployed for a domain.' 'ExternalOperatorRole'
Add-NA 45 'Providers should give multiple same-domain services equivalent security levels.' 'Equivalent security across independently deployed services is controlled by operators outside one library process.' 'ExternalOperatorRole'
Add-NA 46 'Cross-service safeguards should include coordinated TLS configuration and credential protection.' 'This clause concerns organization-wide server configuration and credential custody. The library neither inventories external services nor owns their secret-storage controls.' 'ExternalOperatorRole'
Add-NA 47 'Providers should give all servers for one service equivalent TLS security.' 'Fleet-wide configuration equivalence and traffic steering are deployment responsibilities outside the public client/server API.' 'ExternalOperatorRole'
Add-NA 48 'Applications other than HTTP or QUIC must avoid 0-RTT unless an explicit protocol specification defines safe use.' 'The normative sentence expressly applies to other protocols. This repository implements HTTP, for which the preceding text points to RFC 8470, and QUIC, for which it points to RFC 9001; no generic application protocol API exists.'
Add-Missing 49 'Do not negotiate NULL-encryption cipher suites.' 'Applicable OTP TLS paths do not set an explicit cipher allowlist, so the guarantee varies with OTP defaults. The custom QUIC allowlist excludes NULL but is out of scope under RFC 9325 Section 5.' $CipherComparison @('test-quic-tls13') 'IMP-CIPHER-PROFILE-01' 'Pin an OTP allowlist and reject a NULL-only peer offer.'
Add-Missing 50 'Do not negotiate RC4 cipher suites.' 'No explicit OTP cipher profile makes RC4 unrepresentable across supported runtimes; relying on provider defaults is not a stable library contract.' $CipherComparison @() 'IMP-CIPHER-PROFILE-01' 'Reject an RC4-only peer offer on OTP 28 and 29.'
Add-Missing 51 'Do not negotiate export or any cipher suite below 112-bit security.' 'The HTTP TLS option builders omit ciphers entirely. Current behavior may be safe in a given OTP release, but the repository does not own or test this mandatory floor.' $CipherComparison @() 'IMP-CIPHER-PROFILE-01' 'Allow only explicitly enumerated suites meeting the security floor and reject export offers.'
Add-Missing 52 'Prefer not to negotiate cipher algorithms below 128-bit security.' 'No explicit suite list or order encodes the advisory 128-bit floor for OTP TLS 1.2.' $CipherComparison @() 'IMP-CIPHER-PROFILE-01' 'Exclude every sub-128-bit suite from the configured OTP profile.'
Add-Missing 53 'Prefer not to negotiate static-RSA key-transport suites.' 'The server honors its cipher order but supplies no cipher list, and the client also inherits OTP defaults. Static RSA is not excluded by repository-owned configuration.' $CipherComparison @() 'IMP-CIPHER-PROFILE-01' 'Reject TLS_RSA_* offers and prove ECDHE succeeds.'
Add-Missing 54 'Prefer not to negotiate static finite-field DH suites.' 'The applicable OTP TLS paths do not pin an ECDHE-only suite profile; custom QUIC uses ephemeral ECDH but cannot close the HTTP-over-TLS obligation.' $GroupComparison @('test-quic-p256') 'IMP-CIPHER-PROFILE-01' 'Remove TLS_DH_* suites from both endpoint profiles.'
Add-Missing 55 'Prefer not to negotiate static elliptic-curve DH suites.' 'No repository-owned OTP cipher allowlist excludes TLS_ECDH_* suites. The QUIC ephemeral-key implementation is outside the applicability boundary.' $GroupComparison @('test-quic-p256') 'IMP-CIPHER-PROFILE-01' 'Remove TLS_ECDH_* suites and prove only ephemeral ECDHE negotiates.'
Add-Missing 56 'Support and prefer cipher suites that provide forward secrecy.' 'The existing Implemented evidence covers only custom QUIC, which RFC 9325 Section 5 declares out of scope. HTTP/1.1 and HTTP/2 rely on unpinned OTP cipher defaults, so the whole-library disposition must return to Open.' @('otp-client-options','otp-server-options','quic-client-groups','quic-generate-key-pair') @('test-quic-p256','test-quic-tls13') 'IMP-CIPHER-PROFILE-01' 'Pin and negotiate only forward-secret ECDHE suites on the applicable OTP paths.'
Add-Missing 57 'TLS 1.2 implementations should not negotiate ephemeral finite-field DHE suites.' 'The applicable option builders do not exclude TLS_DHE_* suites. Custom QUIC supports only ECDH but is comparison-only.' $GroupComparison @('test-quic-p256') 'IMP-CIPHER-PROFILE-01' 'Exclude all TLS_DHE_* suites on TLS 1.2.'
Add-Missing 58 'Implement and deploy the four recommended TLS 1.2 ECDHE AES-GCM suites.' 'No explicit OTP cipher list guarantees support for the four named suites or records a reasoned exception; existing tests complete TLS 1.2 without asserting the negotiated suite.' $CipherComparison @('test-http1-versions') 'IMP-CIPHER-PROFILE-01' 'Assert support and negotiated identifiers for each applicable RSA/ECDSA AES-128/256-GCM suite.'
Add-Missing 59 'Do not use a CBC suite unless encrypt_then_mac is successfully negotiated.' 'The library neither excludes CBC explicitly nor observes encrypt_then_mac. An AEAD-only allowlist is the bounded way to make the conditional failure state unreachable.' $OtpBoundary @() 'IMP-CIPHER-PROFILE-01' 'Exclude CBC suites and reject a CBC-only offer.'
Add-Missing 60 'When ECDSA authenticates a TLS peer, prefer the P-256 curve.' 'Server credentials are accepted as PEM without an algorithm/curve policy, and client peer algorithms are delegated to OTP. No clause-specific deviation documents why another curve would be preferred.' @('otp-client-options','otp-server-credentials','quic-rsa-policy') @('test-quic-p256') 'IMP-CERT-POLICY-01' 'Define and test the applicable credential/signature curve policy, preferring P-256 or documenting a precise exception.'
Add-EvidenceGap 61 'ECDSA implementations should use deterministic ECDSA.' 'Nonce generation occurs inside the OTP/OpenSSL provider and is neither selected nor verified by repository code. The custom TLS signer also delegates to that provider. There is no current evidence or documented deviation.' @('otp-client-options','otp-server-options') @() 'VERIFY-ECDSA-PROVIDER-01' 'Identify and evidence provider nonce generation, then document any justified non-deterministic strategy.'
Add-Missing 62 'A TLS 1.2 client should propose TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 first.' 'The client does not configure its cipher list or order, so this exact first proposal is controlled by OTP defaults.' @('otp-client-options') @('test-http1-versions') 'IMP-CIPHER-PROFILE-01' 'Capture ClientHello and assert the named suite is the first TLS 1.2 proposal.'
Add-Missing 63 'A TLS 1.2 server must prefer TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 over weaker offered suites.' 'honor_cipher_order is enabled, but no server cipher order is supplied. The mandatory relative preference is therefore not a repository-owned invariant.' @('otp-server-options') @('test-http1-versions') 'IMP-CIPHER-PROFILE-01' 'Offer the named suite after weaker candidates and assert it wins.'
Add-Missing 64 'A TLS 1.2 server should prefer a stronger offered suite such as AES-256 absent a compelling reason.' 'The server has no explicit suite order and no documented performance exception, so the stronger-suite preference is neither implemented nor intentionally deviated from.' @('otp-server-options') @() 'IMP-CIPHER-PROFILE-01' 'Offer AES-128 and AES-256 recommended suites and assert the declared stronger preference.'
Add-Missing 65 'Prefer not to support TLS_RSA_WITH_AES_128_CBC_SHA.' 'The applicable TLS option builders inherit provider defaults and do not explicitly remove the obsolete static-RSA CBC suite.' $OtpBoundary @() 'IMP-CIPHER-PROFILE-01' 'Reject a peer offering only TLS_RSA_WITH_AES_128_CBC_SHA.'
Add-Missing 66 'TLS 1.2 clients and servers should include the Supported Groups extension.' 'The HTTP TLS paths do not configure supported_groups and no existing wire test observes the extension. Provider defaults are not a stable public contract.' $GroupComparison @('test-quic-version-extension') 'IMP-GROUP-PROFILE-01' 'Pin supported_groups in both OTP roles and observe the extension.'
Add-Missing 67 'TLS 1.2 clients and servers should support P-256 and X25519.' 'Custom QUIC supports both groups, but applicable OTP TLS has no explicit group list or negotiation matrix.' $GroupComparison @('test-quic-p256') 'IMP-GROUP-PROFILE-01' 'Negotiate P-256 and X25519 independently on OTP 28 and 29.'
Add-EvidenceGap 68 'If ec_point_formats is sent, its list must contain only uncompressed.' 'The extension encoding is owned by OTP for HTTP TLS, and no current wire test proves absence or the required singleton value. QUIC TLS 1.3 does not supply applicable TLS 1.2 evidence.' $OtpBoundary @() 'VERIFY-POINT-FORMAT-01' 'Observe both endpoint hellos and require absent-or-uncompressed-only ec_point_formats.'
Add-EvidenceGap 69 'A sender approaching its AEAD confidentiality limit should rotate the session key.' 'QUIC has explicit RFC 9001 packet counters and key updates, but RFC 9325 excludes QUIC. OTP TLS record-limit and KeyUpdate behavior is opaque to the current source and tests.' @('otp-client-options','otp-server-options','quic-aead-limits','quic-aead-update') @('test-quic-key-limits') 'VERIFY-TLS-KEY-LIMITS-01' 'Establish the applicable OTP sender limit and prove rotation or closure before it.'
Add-EvidenceGap 70 'A receiver reaching its AEAD integrity limit should close the connection.' 'The custom QUIC integrity counter is comparison-only. No repository evidence establishes the OTP TLS receiver limit or close behavior.' @('otp-client-options','otp-server-options','quic-aead-limits') @('test-quic-key-limits') 'VERIFY-TLS-KEY-LIMITS-01' 'Establish the OTP integrity limit and finite close behavior.'
Add-EvidenceGap 71 'Use a 2^24.5-record confidentiality limit for recommended TLS 1.2 AES-GCM suites.' 'The library cannot inspect or configure OTP TLS record counters, and no pinned provider evidence proves this limit. QUIC uses different RFC 9001 packet limits.' $OtpBoundary @() 'VERIFY-TLS-KEY-LIMITS-01' 'Pin provider evidence for the exact TLS 1.2 AES-GCM limit and fail unsupported runtimes.'
Add-Missing 72 'Require at least 2048-bit finite-field DHE keys.' 'The applicable OTP profile does not constrain DHE groups or exclude DHE suites. Disabling all finite-field DHE is the simpler bounded conformance path.' $GroupComparison @() 'IMP-GROUP-PROFILE-01' 'Make sub-2048-bit DHE unreachable, preferably by disabling finite-field DHE.'
Add-Missing 73 'Do not use elliptic curves below 224 bits.' 'The applicable OTP paths do not pin supported groups. Custom QUIC selects only X25519 and P-256 but cannot establish the HTTP-over-TLS guarantee.' $GroupComparison @('test-quic-p256') 'IMP-GROUP-PROFILE-01' 'Allow only X25519, P-256, and any explicitly reviewed group of at least 224 bits.'
Add-Missing 74 'An RSA-authenticating server must use a certificate with a modulus of at least 2048 bits.' 'The new check correctly protects custom QUIC servers, but HTTP/1.1 and HTTP/2 server_credentials accepts decoded RSA certificates without the modulus gate. The existing whole-row Implemented disposition therefore overstates coverage.' @('otp-server-credentials','quic-rsa-policy','quic-rsa-server-gate') @('test-quic-rsa-small','test-quic-rsa-live') 'IMP-CERT-POLICY-01' 'Apply the RSA modulus boundary before every OTP TLS listener starts.'
Add-Missing 75 'Prefer SHA-256 for RSA authentication.' 'Neither TCP server credential loading nor the TLS 1.2 signature-algorithm configuration expresses this preference. Custom QUIC supports SHA-256-or-stronger PSS but is out of scope.' @('otp-server-credentials','otp-client-options','quic-rsa-policy') @('test-quic-rsa-live') 'IMP-CERT-POLICY-01' 'Pin SHA-256-or-stronger RSA authentication and test negotiated signature identifiers.'
Add-Missing 76 'Do not use SHA-1 or MD5 for RSA authentication.' 'The repository does not reject a TCP server credential or peer chain solely because its authentication signature uses SHA-1 or MD5, and it does not pin signature algorithms in OTP options.' @('otp-client-options','otp-server-credentials','quic-rsa-policy') @() 'IMP-CERT-POLICY-01' 'Reject SHA-1/MD5 fixtures in both owned-credential and peer-validation paths.'
Add-Missing 77 'A TLS 1.2 client must request SHA-256 with Signature Algorithms.' 'The OTP client options omit signature_algs and no ClientHello test observes a SHA-256 request. Custom QUIC TLS 1.3 evidence does not satisfy the TLS 1.2 clause.' @('otp-client-options') @() 'IMP-CERT-POLICY-01' 'Configure and observe SHA-256-or-stronger TLS 1.2 signature algorithms.'
Add-Missing 78 'Do not use the Truncated HMAC extension.' 'No explicit OTP TLS policy or negative test makes Truncated HMAC negotiation unreachable. Relying on current provider defaults leaves the mandatory behavior unowned.' $OtpBoundary @() 'IMP-TRUNC-HMAC-01' 'Prove both endpoint roles cannot negotiate Truncated HMAC.'
Add-Implemented 79 'Do not use an insecurely and indirectly discovered hostname as the certificate reference identifier.' 'HTTP/1.1 keeps the request origin host separate from proxy/connect destination, HTTP/2 keys and authenticates the prepared origin, and HTTP/3 connect_to explicitly changes only the UDP destination. Wrong-origin tests prove the original service name remains the certificate identity.' @('h1-prepare','h1-secure-transport','h2-prepare','h2-dial','h3-connect-to') @('test-h3-origin-name','test-h3-origin-destination','test-hostname-mismatch')
Add-EvidenceGap 80 'TLS 1.2 AES-GCM should derive nonce_explicit from the 64-bit record sequence number.' 'TLS record construction is delegated to OTP and no current-source artifact identifies or probes its nonce construction on either supported runtime.' $OtpBoundary @() 'VERIFY-GCM-NONCE-01' 'Pin and test the OTP 28/29 TLS 1.2 AES-GCM nonce construction.'
Add-Missing 81 'Prefer not to use static finite-field DH keys.' 'The library does not pin an ECDHE-only OTP cipher/group profile, so static finite-field DH is not excluded by repository-owned configuration.' $GroupComparison @() 'IMP-GROUP-PROFILE-01' 'Disable finite-field DH suites in both endpoint roles.'
Add-Missing 82 'Prefer not to reuse ephemeral finite-field DH keys across connections.' 'No repository-owned group policy excludes finite-field DHE or controls OTP exponent reuse. Removing DHE is the bounded way to satisfy the advisory without depending on provider internals.' $GroupComparison @() 'IMP-GROUP-PROFILE-01' 'Disable finite-field DHE and prove repeated handshakes negotiate ECDHE instead.'
Add-EvidenceGap 83 'A server reusing ECDH keys should use a safe curve or validate received points.' 'Custom QUIC generates fresh X25519/P-256 pairs and validates shared secrets, but it is out of scope. Whether OTP HTTP servers reuse ECDH keys and what checks occur is not evidenced.' @('otp-server-options','quic-generate-key-pair','quic-client-groups') @('test-quic-p256') 'VERIFY-ECDH-REUSE-01' 'Prove no OTP reuse, or prove safe-curve/point-validation behavior when reuse occurs.'
Add-Missing 84 'TLS implementations must implement a strategy to distrust revoked certificates.' 'Both HTTP TLS validation paths perform chain and identity checks, but neither configures CRLs, OCSP, a revocation callback, or a documented alternative strategy. This is a confirmed capability gap.' @('otp-client-options','quic-cert-validate') @('test-hostname-mismatch','test-h3-origin-destination') 'IMP-REVOCATION-01' 'Add a typed finite revocation policy and deterministic revoked-certificate tests.'
Add-Missing 85 'Public-certificate TLS servers should support OCSP and OCSP stapling.' 'The OTP server options expose no status_request or staple configuration, and the custom TLS CertificateEntry path has no public stapling input. No clause-specific deviation exists.' @('otp-server-options','otp-server-credentials') @() 'IMP-OCSP-STAPLING-01' 'Expose and verify bounded OCSP stapling for TLS 1.2 and 1.3 servers.'

$AppendixMentions = [ordered]@{
    86 = 'a historical SHOULD NOT level for TLS 1.0 and 1.1'
    87 = 'the replacement MUST NOT level for TLS 1.0 and 1.1'
    88 = 'the added SHOULD level for TLS 1.3'
    89 = 'a MUST-level ALPN implementation requirement'
    90 = 'SHOULD-level ALPN and SNI guidance'
    91 = 'MUST-level strict-TLS recommendations'
    92 = 'the RSA-certificate MUST-level change'
    93 = 'the superseded RSA-certificate SHOULD level'
    94 = 'SHOULD-level AES-GCM nonce guidance'
    95 = 'the SHOULD NOT finite-field DH summary'
    96 = 'the SHOULD NOT finite-field DH reuse summary'
    97 = 'the SHOULD NOT static ECDH summary'
    98 = 'the 2048-bit DH MUST summary'
    99 = 'the extended_master_secret MUST summary'
    100 = 'the ticket-validity MUST summary'
    101 = 'the superseded ticket-validity SHOULD level'
    102 = 'the SHOULD-level session-duration summary'
    103 = 'the SHOULD NOT old-cipher summary'
    104 = 'the SHOULD-level TLS 1.3 resumption summary'
    105 = 'the generic MUST-level 0-RTT summary'
}
foreach ($entry in $AppendixMentions.GetEnumerator()) {
    Add-NA ([int]$entry.Key) "No independent obligation; Appendix A mentions $($entry.Value)." "Appendix A is an informative change log. This uppercase token labels or summarizes a substantive rule elsewhere and does not create a second independently testable requirement." 'InventoryFalsePositive'
}

function Resolve-Evidence {
    param([string[]]$Keys)
    $resolved = @()
    foreach ($key in $Keys) {
        if (-not $EvidenceCatalog.Contains($key)) { throw "Unknown evidence key: $key" }
        $item = $EvidenceCatalog[$key]
        $resolved += [ordered]@{ path = $item.path; symbol = $item.symbol; relevance = $item.relevance }
    }
    @($resolved)
}

$InventoryBytes = [IO.File]::ReadAllBytes($InventoryPath)
$InventorySha256 = Get-Sha256Bytes $InventoryBytes
$Inventory = [Text.Encoding]::UTF8.GetString($InventoryBytes) | ConvertFrom-Json
$Rfc = @($Inventory.standards | Where-Object id -eq 'RFC9325')
if ($Rfc.Count -ne 1) { throw 'RFC9325 inventory entry is missing or duplicated.' }
$InventoryRequirements = @($Rfc[0].requirements | Sort-Object { [int]$_.source_occurrence })

function Build-Reviews {
    $reviews = @()
    foreach ($decision in @($script:Decisions | Sort-Object { [int]$_.source_occurrence })) {
        $matches = @($InventoryRequirements | Where-Object source_occurrence -eq $decision.source_occurrence)
        if ($matches.Count -ne 1) { throw "No unique inventory row for occurrence $($decision.source_occurrence)." }
        $row = $matches[0]
        $canonicalSummary = ([string]$row.summary) -replace '^Reviewed obligation: ', ''
        if ($row.disposition -cne $decision.proposed_disposition -or
            $canonicalSummary -cne $decision.obligation -or
            $row.reason -cne $decision.reason -or
            $row.finding_class -cne $decision.finding_class) {
            throw "Canonical RFC9325 review drift for occurrence $($decision.source_occurrence)."
        }
        $implementationTask = $null
        $verificationTask = $null
        if ($decision.finding_class -eq 'MissingImplementation') {
            $implementationTask = [ordered]@{ id = $decision.task_id; acceptance_focus = $decision.acceptance_focus }
        }
        elseif ($decision.finding_class -in @('InsufficientEvidence','BlockedAggregate')) {
            $verificationTask = [ordered]@{ id = $decision.task_id; acceptance_focus = $decision.acceptance_focus }
        }
        $resolvedImplementation = @(Resolve-Evidence $decision.implementation_keys)
        $resolvedTests = @(Resolve-Evidence $decision.test_keys)
        $canonicalImplementation = if ($row.PSObject.Properties.Name -contains 'implementation') { @($row.implementation | ForEach-Object { "$($_.path)|$($_.symbol)" }) } else { @() }
        $canonicalTests = if ($row.PSObject.Properties.Name -contains 'tests') { @($row.tests | ForEach-Object { "$($_.path)|$($_.symbol)" }) } else { @() }
        $reviewImplementation = @($resolvedImplementation | ForEach-Object { "$($_.path)|$($_.symbol)" })
        $reviewTests = @($resolvedTests | ForEach-Object { "$($_.path)|$($_.symbol)" })
        if (@($canonicalImplementation | Where-Object { $_ -cnotin $reviewImplementation }).Count -ne 0 -or
            @($canonicalTests | Where-Object { $_ -cnotin $reviewTests }).Count -ne 0) {
            throw "Canonical RFC9325 evidence drift for occurrence $($decision.source_occurrence)."
        }
        $canonicalTaskProperty = if ($null -ne $implementationTask) { 'bounded_implementation_task' } elseif ($null -ne $verificationTask) { 'bounded_verification_task' } else { '' }
        if ($canonicalTaskProperty -ne '') {
            if (-not ($row.PSObject.Properties.Name -contains $canonicalTaskProperty)) { throw "Canonical RFC9325 task missing for occurrence $($decision.source_occurrence)." }
            $canonicalTask = $row.$canonicalTaskProperty
            $reviewTask = if ($null -ne $implementationTask) { $implementationTask } else { $verificationTask }
            if ($canonicalTask.id -cne $reviewTask.id -or $canonicalTask.acceptance_focus -cne $reviewTask.acceptance_focus) { throw "Canonical RFC9325 task drift for occurrence $($decision.source_occurrence)." }
        }
        $reviews += [ordered]@{
            id = $row.id
            section = $row.section
            source_line = $row.source_line
            source_column = $row.source_column
            source_occurrence = $row.source_occurrence
            source_clause_sha256 = $row.source_clause_sha256
            level = $row.level
            roles = @($row.roles)
            exact_obligation = $decision.obligation
            current_disposition = $row.disposition
            proposed_disposition = $decision.proposed_disposition
            finding_class = $decision.finding_class
            reason = $decision.reason
            implementation = $resolvedImplementation
            tests = $resolvedTests
            bounded_implementation_task = $implementationTask
            bounded_verification_task = $verificationTask
        }
    }
    @($reviews)
}

function Count-Values {
    param([object[]]$Rows, [string]$Property)
    $counts = [ordered]@{}
    foreach ($value in @('Implemented','NotApplicable','DocumentedDeviation','Open')) {
        $counts[$value] = @($Rows | Where-Object { $_.$Property -eq $value }).Count
    }
    $counts
}

function Build-Artifact {
    $reviews = @(Build-Reviews)
    $referencedLabels = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($label in @($InventoryLabel,$RfcLabel,$GeneratorLabel)) { [void]$referencedLabels.Add($label) }
    foreach ($review in $reviews) {
        foreach ($evidence in @($review.implementation) + @($review.tests)) { [void]$referencedLabels.Add($evidence.path) }
    }
    $inputFiles = @()
    foreach ($label in @($referencedLabels | Sort-Object)) {
        $path = Repo-Path $label
        $inputFiles += [ordered]@{ path = $label; bytes = ([IO.File]::ReadAllBytes($path)).Length; sha256 = Get-FileSha256 $path }
    }
    $currentCounts = Count-Values $reviews 'current_disposition'
    $proposedCounts = Count-Values $reviews 'proposed_disposition'
    $findingCounts = [ordered]@{}
    foreach ($class in @('ConfirmedImplemented','ConditionalOutOfScope','ExternalOperatorRole','ProtocolDesignerRole','InventoryFalsePositive','MissingImplementation','InsufficientEvidence','BlockedAggregate')) {
        $findingCounts[$class] = @($reviews | Where-Object finding_class -eq $class).Count
    }
    [ordered]@{
        schema = 1
        reviewed_on = $ReviewedOn
        standard = 'RFC9325'
        purpose = 'Independent current-source retention review of the 55 RFC 9325 requirements that remain Open in standards/requirements.json; this artifact never mutates the canonical manifest.'
        input = [ordered]@{
            inventory = [ordered]@{ path = $InventoryLabel; bytes = $InventoryBytes.Length; sha256 = $InventorySha256 }
            canonical_rfc = [ordered]@{ path = $RfcLabel; url = 'https://www.rfc-editor.org/rfc/rfc9325.txt'; bytes = $PinnedRfcBytes; sha256 = $PinnedRfcSha256 }
            files = $inputFiles
        }
        scope = [ordered]@{
            applicable_tls_paths = @('HTTP/1.1 over OTP ssl','HTTP/2 over OTP ssl')
            quic_rule = 'RFC 9325 Section 5 excludes QUIC except where a source occurrence expressly addresses new TLS-integrating transports or delegates to RFC 9001. QUIC symbols elsewhere are comparison-only and never close an OTP TLS duty.'
            role_rule = 'Library-owned client/server behavior is applicable. Administrator, fleet operator, and new-protocol designer duties are NotApplicable unless a public API owns the triggering decision.'
            evidence_rule = 'Implemented requires a direct source invariant and existing executable evidence. Provider behavior that is plausible but untested remains Open as InsufficientEvidence. Absence of a stable library-owned control is MissingImplementation.'
            deviation_rule = 'DocumentedDeviation requires an existing clause-specific public rationale and tests for the alternate behavior; no reviewed occurrence qualified.'
        }
        summary = [ordered]@{
            total = $reviews.Count
            open_rows_reviewed = @($reviews | Where-Object current_disposition -eq 'Open').Count
            true_missing_implementation_rows = @($reviews | Where-Object finding_class -eq 'MissingImplementation').Count
            insufficient_evidence_rows = @($reviews | Where-Object finding_class -eq 'InsufficientEvidence').Count
            blocked_aggregate_rows = @($reviews | Where-Object finding_class -eq 'BlockedAggregate').Count
            current_dispositions = $currentCounts
            proposed_dispositions = $proposedCounts
            finding_classes = $findingCounts
            reclassifications = [ordered]@{
                open_to_implemented = @($reviews | Where-Object { $_.current_disposition -eq 'Open' -and $_.proposed_disposition -eq 'Implemented' }).Count
                open_to_not_applicable = @($reviews | Where-Object { $_.current_disposition -eq 'Open' -and $_.proposed_disposition -eq 'NotApplicable' }).Count
                open_remaining_open = @($reviews | Where-Object { $_.current_disposition -eq 'Open' -and $_.proposed_disposition -eq 'Open' }).Count
                implemented_remaining_implemented = @($reviews | Where-Object { $_.current_disposition -eq 'Implemented' -and $_.proposed_disposition -eq 'Implemented' }).Count
                implemented_to_open = @($reviews | Where-Object { $_.current_disposition -eq 'Implemented' -and $_.proposed_disposition -eq 'Open' }).Count
            }
        }
        task_catalog = $TaskCatalog
        reviews = $reviews
        limitations = @(
            'This is a static current-source and existing-test audit of the canonical retained dispositions; it does not claim that an Open requirement has been closed.',
            'No full suite or external interoperability peer was run for this review.',
            'OTP-internal compression, resumption, renegotiation, ECDSA nonce, TLS record-limit, nonce, point-format, and ECDH-reuse behavior remains Open until version-pinned executable evidence exists.',
            'Twenty Appendix A scanner hits are retained and explicitly classified as inventory false positives rather than silently dropped.',
            'Independent audit and release signing remain external conditions.'
        )
        verification = [ordered]@{
            generator = $GeneratorLabel
            output_encoding = 'UTF-8 without BOM, LF line endings, final LF'
            deterministic_double_generation = 'passed'
            adversarial_self_check = 'passed'
            adversarial_controls = @(
                'missing-review','duplicate-id','reordered-reviews','coordinate-drift','source-fingerprint-drift',
                'current-count-drift','proposed-count-drift','implemented-without-test','missing-gap-without-task',
                'evidence-gap-without-task','not-applicable-with-task','unknown-task','missing-evidence-path',
                'missing-evidence-symbol','qlog-evidence-path','stale-inventory-digest','stale-rfc-digest',
                'undocumented-deviation','secret-marker','encoding-claim-drift'
            )
            public_secret_scan = 'passed'
            qlog_files_referenced = 0
        }
    }
}

function Assert-Artifact {
    param([Parameter(Mandatory = $true)]$Artifact)
    if ($Artifact.schema -ne 1 -or $Artifact.standard -ne 'RFC9325') { throw 'Artifact identity mismatch.' }
    if ($Artifact.input.inventory.sha256 -ne $InventorySha256 -or $Artifact.input.inventory.bytes -ne $InventoryBytes.Length) { throw 'Inventory identity mismatch.' }
    if ($Artifact.input.canonical_rfc.sha256 -ne $PinnedRfcSha256 -or $Artifact.input.canonical_rfc.bytes -ne $PinnedRfcBytes) { throw 'RFC pin mismatch.' }
    $actualRfcBytes = [IO.File]::ReadAllBytes($RfcPath)
    if ($actualRfcBytes.Length -ne $PinnedRfcBytes -or (Get-Sha256Bytes $actualRfcBytes) -ne $PinnedRfcSha256) { throw 'Canonical RFC bytes drifted.' }
    $rows = @($Artifact.reviews)
    if ($rows.Count -ne 105) { throw "Expected 105 reviews, found $($rows.Count)." }
    if (@($script:Decisions).Count -ne 105) { throw 'Decision table is incomplete.' }
    if (@($rows.id | Sort-Object -Unique).Count -ne 105) { throw 'Review ids are duplicated.' }
    if (@($rows.source_occurrence | Sort-Object -Unique).Count -ne 105) { throw 'Source occurrences are duplicated.' }
    for ($index = 0; $index -lt 105; $index++) {
        $row = $rows[$index]
        $source = $InventoryRequirements[$index]
        if ($row.source_occurrence -ne ($index + 1)) { throw "Review ordering is not source-contiguous: index=$index observed=$($row.source_occurrence)." }
        foreach ($property in @('id','section','source_line','source_column','source_occurrence','source_clause_sha256','level','current_disposition')) {
            $sourceProperty = if ($property -eq 'current_disposition') { 'disposition' } else { $property }
            if ([string]$row.$property -cne [string]$source.$sourceProperty) { throw "Source mapping drift for $($row.id): $property" }
        }
        if ([string]::IsNullOrWhiteSpace($row.exact_obligation) -or [string]::IsNullOrWhiteSpace($row.reason)) { throw "Empty review explanation: $($row.id)" }
        $impl = @($row.implementation)
        $tests = @($row.tests)
        $allEvidence = @($impl) + @($tests)
        $pairs = @($allEvidence | ForEach-Object { "$($_.path)|$($_.symbol)" })
        if (@($pairs | Sort-Object -Unique).Count -ne $pairs.Count) { throw "Duplicate evidence reference: $($row.id)" }
        foreach ($evidence in $allEvidence) {
            if ($evidence.path -match '(?i)qlog') { throw "qlog evidence is forbidden: $($row.id)" }
            $catalogMatch = @($EvidenceCatalog.Values | Where-Object { $_.path -ceq $evidence.path -and $_.symbol -ceq $evidence.symbol -and $_.relevance -ceq $evidence.relevance })
            if ($catalogMatch.Count -ne 1) { throw "Unknown evidence reference: $($row.id) $($evidence.path) $($evidence.symbol)" }
            $path = Repo-Path $evidence.path
            if (-not [IO.File]::Exists($path)) { throw "Evidence path missing: $($evidence.path)" }
            $text = [IO.File]::ReadAllText($path)
            if (-not $text.Contains($catalogMatch[0].needle, [StringComparison]::Ordinal)) { throw "Evidence symbol missing: $($evidence.path) $($evidence.symbol)" }
        }
        $implementationTask = $row.bounded_implementation_task
        $verificationTask = $row.bounded_verification_task
        switch ($row.finding_class) {
            'ConfirmedImplemented' {
                if ($row.proposed_disposition -ne 'Implemented' -or $impl.Count -eq 0 -or $tests.Count -eq 0 -or $null -ne $implementationTask -or $null -ne $verificationTask) { throw "Invalid Implemented evidence: $($row.id)" }
            }
            'MissingImplementation' {
                if ($row.proposed_disposition -ne 'Open' -or $null -eq $implementationTask -or $null -ne $verificationTask) { throw "Invalid implementation gap: $($row.id)" }
            }
            { $_ -in @('InsufficientEvidence','BlockedAggregate') } {
                if ($row.proposed_disposition -ne 'Open' -or $null -eq $verificationTask -or $null -ne $implementationTask) { throw "Invalid evidence gap: $($row.id)" }
            }
            { $_ -in @('ConditionalOutOfScope','ExternalOperatorRole','ProtocolDesignerRole','InventoryFalsePositive') } {
                if ($row.proposed_disposition -ne 'NotApplicable' -or $null -ne $implementationTask -or $null -ne $verificationTask) { throw "Invalid NotApplicable row: $($row.id)" }
            }
            'DocumentedDeviation' {
                if ($row.proposed_disposition -ne 'DocumentedDeviation' -or -not ($row.PSObject.Properties.Name -contains 'deviation_document') -or [string]::IsNullOrWhiteSpace($row.deviation_document)) { throw "Undocumented deviation: $($row.id)" }
            }
            default { throw "Unknown finding class: $($row.finding_class)" }
        }
        foreach ($task in @($implementationTask,$verificationTask)) {
            if ($null -eq $task) { continue }
            if (-not $TaskCatalog.Contains([string]$task.id) -or [string]::IsNullOrWhiteSpace($task.acceptance_focus)) { throw "Unknown or unbounded task: $($row.id)" }
        }
    }
    $current = Count-Values $rows 'current_disposition'
    $proposed = Count-Values $rows 'proposed_disposition'
    if ($current.Open -ne 55 -or $current.Implemented -ne 13 -or $current.NotApplicable -ne 37 -or $current.DocumentedDeviation -ne 0) { throw 'Current inventory counts drifted.' }
    if ($proposed.Implemented -ne 13 -or $proposed.NotApplicable -ne 37 -or $proposed.DocumentedDeviation -ne 0 -or $proposed.Open -ne 55) { throw 'Proposed disposition counts drifted.' }
    foreach ($name in @('Implemented','NotApplicable','DocumentedDeviation','Open')) {
        if ($Artifact.summary.current_dispositions.$name -ne $current.$name -or $Artifact.summary.proposed_dispositions.$name -ne $proposed.$name) { throw "Summary drift: $name" }
    }
    if ($Artifact.summary.open_rows_reviewed -ne 55 -or $Artifact.summary.true_missing_implementation_rows -ne 32 -or $Artifact.summary.insufficient_evidence_rows -ne 22 -or $Artifact.summary.blocked_aggregate_rows -ne 1) { throw 'Open-review counts drifted.' }
    if ($Artifact.summary.reclassifications.open_to_implemented -ne 0 -or $Artifact.summary.reclassifications.open_to_not_applicable -ne 0 -or $Artifact.summary.reclassifications.open_remaining_open -ne 55 -or $Artifact.summary.reclassifications.implemented_remaining_implemented -ne 13 -or $Artifact.summary.reclassifications.implemented_to_open -ne 0) { throw 'Reclassification counts drifted.' }
    if (@($Artifact.verification.adversarial_controls).Count -ne 20 -or @($Artifact.verification.adversarial_controls | Sort-Object -Unique).Count -ne 20) { throw 'Adversarial control inventory drifted.' }
    if ($Artifact.verification.output_encoding -ne 'UTF-8 without BOM, LF line endings, final LF') { throw 'Encoding claim drifted.' }
    if ($Artifact.verification.qlog_files_referenced -ne 0) { throw 'qlog reference count drifted.' }
    foreach ($inputFile in @($Artifact.input.files)) {
        $path = Repo-Path $inputFile.path
        if (-not [IO.File]::Exists($path) -or ([IO.File]::ReadAllBytes($path)).Length -ne $inputFile.bytes -or (Get-FileSha256 $path) -ne $inputFile.sha256) { throw "Deterministic input drift: $($inputFile.path)" }
    }
    $serialized = $Artifact | ConvertTo-Json -Depth 100
    if ($serialized -match '-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|(?i)authorization\s*[:=]\s*[^,}\r\n]+|(?i)bearer\s+[A-Za-z0-9._~-]{12,}|(?i)(?:api[_-]?key|secret|password)\s*[:=]\s*[A-Za-z0-9+/=_-]{8,}') { throw 'Secret marker detected.' }
}

function Clone-Artifact { param($Artifact) ($Artifact | ConvertTo-Json -Depth 100) | ConvertFrom-Json }
function Assert-AdversarialReject {
    param([string]$Name, [scriptblock]$Mutation, $Base)
    $clone = Clone-Artifact $Base
    $null = $Mutation.Invoke($clone)
    $rejected = $false
    try { Assert-Artifact $clone } catch { $rejected = $true }
    if (-not $rejected) { throw "Adversarial mutation was accepted: $Name" }
}

$Base = Build-Artifact
Assert-Artifact $Base
Assert-AdversarialReject 'missing-review' { param($x) $x.reviews = @($x.reviews | Select-Object -Skip 1) } $Base
Assert-AdversarialReject 'duplicate-id' { param($x) $x.reviews[1].id = $x.reviews[0].id } $Base
Assert-AdversarialReject 'reordered-reviews' { param($x) $tmp=$x.reviews[0];$x.reviews[0]=$x.reviews[1];$x.reviews[1]=$tmp } $Base
Assert-AdversarialReject 'coordinate-drift' { param($x) $x.reviews[0].source_line++ } $Base
Assert-AdversarialReject 'source-fingerprint-drift' { param($x) $x.reviews[0].source_clause_sha256 = ('0' * 64) } $Base
Assert-AdversarialReject 'current-count-drift' { param($x) $x.reviews[6].current_disposition = 'Implemented' } $Base
Assert-AdversarialReject 'proposed-count-drift' { param($x) $x.reviews[6].proposed_disposition = 'Implemented' } $Base
Assert-AdversarialReject 'implemented-without-test' { param($x) $x.reviews[0].tests = @() } $Base
Assert-AdversarialReject 'missing-gap-without-task' { param($x) $x.reviews[35].bounded_implementation_task = $null } $Base
Assert-AdversarialReject 'evidence-gap-without-task' { param($x) $x.reviews[6].bounded_verification_task = $null } $Base
Assert-AdversarialReject 'not-applicable-with-task' { param($x) $x.reviews[9].bounded_verification_task = [pscustomobject]@{id='VERIFY-VERSION-PREFERENCE-01';acceptance_focus='invalid'} } $Base
Assert-AdversarialReject 'unknown-task' { param($x) $x.reviews[6].bounded_verification_task.id = 'UNKNOWN' } $Base
Assert-AdversarialReject 'missing-evidence-path' { param($x) $x.reviews[0].implementation[0].path = 'missing.gleam' } $Base
Assert-AdversarialReject 'missing-evidence-symbol' { param($x) $x.reviews[0].implementation[0].symbol = 'missing' } $Base
Assert-AdversarialReject 'qlog-evidence-path' { param($x) $x.reviews[0].implementation[0].path = 'packages/quic_core/src/quic_core/internal/qlog.gleam' } $Base
Assert-AdversarialReject 'stale-inventory-digest' { param($x) $x.input.inventory.sha256 = ('0' * 64) } $Base
Assert-AdversarialReject 'stale-rfc-digest' { param($x) $x.input.canonical_rfc.sha256 = ('0' * 64) } $Base
Assert-AdversarialReject 'undocumented-deviation' { param($x) $x.reviews[0].finding_class='DocumentedDeviation';$x.reviews[0].proposed_disposition='DocumentedDeviation' } $Base
Assert-AdversarialReject 'secret-marker' { param($x) $x.reviews[0].reason = '-----BEGIN PRIVATE KEY-----' } $Base
Assert-AdversarialReject 'encoding-claim-drift' { param($x) $x.verification.output_encoding = 'UTF-16' } $Base

$First = Build-Artifact
$Second = Build-Artifact
Assert-Artifact $First
Assert-Artifact $Second
$FirstText = ($First | ConvertTo-Json -Depth 100) -replace "`r`n", "`n"
$SecondText = ($Second | ConvertTo-Json -Depth 100) -replace "`r`n", "`n"
if ($FirstText -cne $SecondText) { throw 'Double generation was not deterministic.' }
$OutputBytes = [Text.UTF8Encoding]::new($false).GetBytes($FirstText + "`n")

if ($Check) {
    if (-not [IO.File]::Exists($OutputPath)) { throw "Generated output is missing: $OutputLabel" }
    $Existing = [IO.File]::ReadAllBytes($OutputPath)
    if ((Get-Sha256Bytes $Existing) -ne (Get-Sha256Bytes $OutputBytes)) { throw "Generated output is stale: $OutputLabel" }
    if ($Existing.Length -lt 1 -or $Existing[0] -eq 0xEF -or $Existing[-1] -ne 0x0A) { throw 'Output encoding contract failed.' }
    [Console]::WriteLine("checked $OutputLabel sha256=$(Get-Sha256Bytes $Existing)")
    exit 0
}

[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($OutputPath)) | Out-Null
[IO.File]::WriteAllBytes($OutputPath, $OutputBytes)
[Console]::WriteLine("generated $OutputLabel sha256=$(Get-Sha256Bytes $OutputBytes)")
