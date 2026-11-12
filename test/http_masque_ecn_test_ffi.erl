-module(http_masque_ecn_test_ffi).

-export([
    unsupported_options_preserve_explicit_unobserved_default_case/0,
    accepted_option_without_readback_is_unobserved_case/0,
    observed_socket_default_is_distinct_from_wire_evidence_case/0,
    observed_nonzero_ecn_never_claims_not_ect_case/0,
    option_exceptions_are_redacted_as_unobserved_case/0
]).

unsupported_options_preserve_explicit_unobserved_default_case() ->
    require(http_masque_udp_ffi:not_ect_configuration(
        fun() -> {error, enotsup} end,
        fun() -> {error, enotsup} end) =:= 1,
        unsupported_options_were_not_explicit).

accepted_option_without_readback_is_unobserved_case() ->
    require(http_masque_udp_ffi:not_ect_configuration(
        fun() -> ok end,
        fun() -> {error, enotsup} end) =:= 2,
        configured_and_unobserved_were_conflated).

observed_socket_default_is_distinct_from_wire_evidence_case() ->
    require(http_masque_udp_ffi:not_ect_configuration(
        fun() -> {error, einval} end,
        fun() -> {ok, [{tos, 0}]} end) =:= 3,
        socket_option_observation_was_not_retained).

observed_nonzero_ecn_never_claims_not_ect_case() ->
    require(http_masque_udp_ffi:not_ect_configuration(
        fun() -> ok end,
        fun() -> {ok, [{tclass, 3}]} end) =:= 0,
        nonzero_ecn_was_falsely_reported_as_not_ect).

option_exceptions_are_redacted_as_unobserved_case() ->
    require(http_masque_udp_ffi:not_ect_configuration(
        fun() -> erlang:error({private_backend, <<"sentinel">>}) end,
        fun() -> erlang:error({private_backend, <<"sentinel">>}) end) =:= 1,
        callback_exception_was_not_redacted).

require(true, _) -> ok;
require(false, Reason) -> erlang:error(Reason).
