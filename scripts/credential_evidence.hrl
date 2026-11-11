%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("runtime_matrix_evidence.hrl").
-include("artifact_merge_evidence.hrl").

%% Every symbol is an actual zero-arity compiler-exported EUnit unit. A source
%% comment matching a regular expression cannot satisfy a credential role.
credential_required_units() ->
    [credential_requirement(<<"rsa_pss_certificate_live">>, <<"core">>, <<"public_loopback_test">>,
                            <<"rsa_pss_certificate_live_round_trip_test">>),
     credential_requirement(<<"ecdsa_p256_certificate_live">>, <<"core">>, <<"public_loopback_test">>,
                            <<"ecdsa_p256_certificate_live_round_trip_test">>),
     credential_requirement(<<"ecdsa_p384_certificate_live">>, <<"core">>, <<"public_loopback_test">>,
                            <<"ecdsa_p384_certificate_live_round_trip_test">>),
     credential_requirement(<<"ed25519_mtls_live">>, <<"core">>, <<"public_loopback_test">>,
                            <<"public_mtls_required_and_optional_round_trip_test">>),
     credential_requirement(<<"mtls_optional_anonymous">>, <<"core">>, <<"tls_engine_test">>,
                            <<"optional_client_certificate_accepts_anonymous_client_test">>),
     credential_requirement(<<"mtls_required_refusal">>, <<"core">>, <<"tls_engine_test">>,
                            <<"required_client_certificate_rejects_anonymous_client_test">>),
     credential_requirement(<<"authenticated_direct_handshake">>, <<"core">>, <<"tls_engine_test">>,
                            <<"completes_authenticated_client_server_handshake_test">>),
     credential_requirement(<<"hello_retry_request">>, <<"core">>, <<"tls_engine_test">>,
                            <<"completes_one_hello_retry_request_and_discards_initial_keys_test">>),
     credential_requirement(<<"certificate_rotation">>, <<"http3">>, <<"server_test">>,
                            <<"certificate_reload_is_atomic_and_preserves_existing_connections_test">>),
     credential_requirement(<<"resumption_and_zero_rtt">>, <<"core">>, <<"tls_engine_test">>,
                            <<"completes_psk_resumption_and_accepts_replay_checked_early_data_test">>),
     credential_requirement(<<"replay_guard_fallback">>, <<"http3">>, <<"transport_test">>,
                            <<"external_replay_guard_failure_falls_back_to_one_rtt_test">>),
     credential_requirement(<<"ticket_expiry_and_origin_rejection">>, <<"core">>, <<"tls_session_ticket_test">>,
                            <<"rejects_tampered_expired_or_cross_origin_tickets_test">>),
     credential_requirement(<<"hostname_chain_and_scheme_rejection">>, <<"core">>, <<"tls_authentication_test">>,
                            <<"rejects_wrong_hostname_untrusted_chain_and_mismatched_scheme_test">>),
     credential_requirement(<<"native_tls_failure_secrecy">>, <<"http">>, <<"tls_transport_test">>,
                            <<"rejected_tls_identity_never_logs_native_certificate_or_hostname_reports_test">>)].

credential_requirement(Role, Target, Module, Function) ->
    #{role => Role, target => Target, unit => #{module => Module, function => Function, kind => <<"test">>}}.

credential_contract_valid(Catalogs) ->
    lists:all(fun(#{target := Target, unit := Unit}) ->
        lists:member(Unit, maps:get(units, maps:get(Target, Catalogs)))
    end, credential_required_units()).

credential_matrix_summary(Rows, Catalogs, Identity) ->
    Complete = runtime_matrix_rows_valid(Rows) andalso credential_contract_valid(Catalogs),
    Platforms = [{Os, Otp} || Os <- [<<"ubuntu-24.04">>, <<"macos-15">>, <<"windows-2025">>], Otp <- [28, 29]],
    PlatformRows = [credential_platform_row(Os, Otp, Rows, Catalogs) || {Os, Otp} <- Platforms],
    #{schema => 2, status => case Complete of true -> <<"Ready">>; false -> <<"Blocked">> end,
      evidence_identity => Identity, evidence_source => <<"verified complete runtime package suites">>,
      expected_platforms => 6, expected_roles_per_platform => length(credential_required_units()),
      completed_platforms => length([ok || #{status := <<"Ready">>} <- PlatformRows]),
      platforms => PlatformRows}.

credential_platform_row(Os, Otp, Rows, Catalogs) ->
    Selected = [Row || Row <- Rows, maps:get(os, Row) =:= Os, maps:get(otp, Row) =:= Otp],
    Complete = length(Selected) =:= 3 andalso credential_contract_valid(Catalogs) andalso
        lists:sort([maps:get(target, R) || R <- Selected]) =:= [<<"core">>, <<"http">>, <<"http3">>] andalso
        lists:all(fun(Row) -> maps:get(status, Row) =:= <<"Ready">> end, Selected),
    Base = #{platform => Os, otp => Otp, status => case Complete of true -> <<"Ready">>; false -> <<"Blocked">> end},
    case Complete of
        false -> Base#{failure => <<"incomplete_or_invalid_runtime_evidence">>};
        true -> Base#{roles => [Requirement#{package_report_sha256 =>
                    maps:get(report_sha256, hd([R || R <- Selected,
                        maps:get(target, R) =:= maps:get(target, Requirement)]))}
                || Requirement <- credential_required_units()],
            package_runs => Selected}
    end.

credential_matrix_capture(Identity) ->
    Catalogs = runtime_matrix_catalog(),
    Rows = runtime_matrix_rows("verified", Catalogs, Identity),
    credential_matrix_summary(Rows, Catalogs, Identity).

credential_matrix_verify(Report) ->
    Current = credential_matrix_capture(evidence_identity()),
    runtime_matrix_ensure(maps:get(status, Current) =:= <<"Ready">> andalso
        runtime_matrix_inventory_valid("verified"), incomplete_credential_matrix),
    runtime_matrix_ensure(Report =:= runtime_matrix_json(Current), stale_or_invalid_credential_matrix).

credential_matrix_self_test() ->
    Identity = #{<<"schema">> => 2, <<"source_sha256">> => binary:copy(<<"A">>, 64), <<"files">> => 10},
    Catalogs = maps:from_list([{Target, #{units => [maps:get(unit, Requirement)
        || Requirement <- credential_required_units(), maps:get(target, Requirement) =:= Target]}}
        || Target <- [<<"core">>, <<"http3">>, <<"http">>]]),
    Rows = [Row#{status => <<"Ready">>, report_sha256 => binary:copy(<<"B">>, 64), run_nonce => integer_to_binary(Id)}
            || {Id, Row} <- lists:zip(lists:seq(1, 18), runtime_matrix_expected())],
    #{status := <<"Ready">>, completed_platforms := 6} = credential_matrix_summary(Rows, Catalogs, Identity),
    lists:foreach(fun(Bad) ->
        #{status := <<"Blocked">>} = credential_matrix_summary(Bad, Catalogs, Identity)
    end, [tl(Rows), [hd(Rows) | tl(tl(Rows))] ++ [hd(Rows)],
          [(hd(Rows))#{status => <<"Failed">>} | tl(Rows)]]),
    Core = maps:get(<<"core">>, Catalogs),
    MissingUnit = Catalogs#{<<"core">> => Core#{units => tl(maps:get(units, Core))}},
    #{status := <<"Blocked">>} = credential_matrix_summary(Rows, MissingUnit, Identity),
    io:put_chars("credential evidence: exact executed symbols, all six platforms and no duplicate runs verified\n").
