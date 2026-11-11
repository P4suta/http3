import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import http3/internal/native/header_semantics
import http3/internal/qpack/header

fn field(name: BitArray, value: BitArray) -> header.Header {
  header.Header(name, value, False)
}

fn custom_request(
  scheme: BitArray,
  authority: Option(BitArray),
  host: Option(BitArray),
) -> List(header.Header) {
  let pseudo_fields = case authority {
    None -> [
      field(<<":method">>, <<"GET">>),
      field(<<":scheme">>, scheme),
      field(<<":path">>, <<"resource">>),
    ]
    Some(value) -> [
      field(<<":method">>, <<"GET">>),
      field(<<":scheme">>, scheme),
      field(<<":authority">>, value),
      field(<<":path">>, <<"resource">>),
    ]
  }
  case host {
    None -> pseudo_fields
    Some(value) -> list.append(pseudo_fields, [field(<<"host">>, value)])
  }
}

fn add_optional_policies(
  policies: header_semantics.AuthorityPolicies,
  next: Int,
  remaining: Int,
) -> Result(
  header_semantics.AuthorityPolicies,
  header_semantics.AuthorityPolicyError,
) {
  case remaining {
    0 -> Ok(policies)
    _ ->
      case
        header_semantics.with_custom_scheme_authority_policy(
          policies,
          "x" <> int.to_string(next),
          header_semantics.OptionalAuthority,
        )
      {
        Error(error) -> Error(error)
        Ok(policies) -> add_optional_policies(policies, next + 1, remaining - 1)
      }
  }
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn custom_scheme_authority_policies_are_enforced_test() -> Nil {
  let mandatory =
    header_semantics.authority_policies()
    |> header_semantics.with_custom_scheme_authority_policy(
      "Repo+Sync",
      header_semantics.MandatoryAuthority,
    )
  let assert Ok(mandatory) = mandatory
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(mandatory_control),
    [],
    None,
  )) =
    header_semantics.validate_with_authority_policies(
      custom_request(<<"REPO+SYNC">>, Some(<<"store.example">>), None),
      header_semantics.RequestSection,
      False,
      mandatory,
    )
  assert mandatory_control.scheme == Some(<<"repo+sync">>)
  assert header_semantics.validate_with_authority_policies(
      custom_request(<<"repo+sync">>, None, None),
      header_semantics.RequestSection,
      False,
      mandatory,
    )
    == Error(header_semantics.MissingPseudoHeader(<<":authority">>))

  let assert Ok(optional) =
    header_semantics.authority_policies()
    |> header_semantics.with_custom_scheme_authority_policy(
      "urn+transport",
      header_semantics.OptionalAuthority,
    )
  let assert Ok(_) =
    header_semantics.validate_with_authority_policies(
      custom_request(<<"urn+transport">>, None, None),
      header_semantics.RequestSection,
      False,
      optional,
    )
  let assert Ok(_) =
    header_semantics.validate_with_authority_policies(
      custom_request(
        <<"urn+transport">>,
        Some(<<"registry.example">>),
        Some(<<"registry.example">>),
      ),
      header_semantics.RequestSection,
      False,
      optional,
    )

  let assert Ok(no_authority) =
    header_semantics.authority_policies()
    |> header_semantics.with_custom_scheme_authority_policy(
      "local",
      header_semantics.NoAuthority,
    )
  let assert Ok(_) =
    header_semantics.validate_with_authority_policies(
      custom_request(<<"local">>, None, None),
      header_semantics.RequestSection,
      False,
      no_authority,
    )
  assert header_semantics.validate_with_authority_policies(
      custom_request(<<"local">>, Some(<<"forbidden">>), None),
      header_semantics.RequestSection,
      False,
      no_authority,
    )
    == Error(header_semantics.InvalidAuthority)
  assert header_semantics.validate_with_authority_policies(
      custom_request(<<"local">>, None, Some(<<"forbidden">>)),
      header_semantics.RequestSection,
      False,
      no_authority,
    )
    == Error(header_semantics.InvalidAuthority)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn custom_scheme_policy_is_fail_closed_normalized_and_bounded_test() -> Nil {
  let empty = header_semantics.authority_policies()
  assert header_semantics.validate_with_authority_policies(
      custom_request(<<"unknown">>, None, None),
      header_semantics.RequestSection,
      False,
      empty,
    )
    == Error(header_semantics.InvalidScheme)
  assert header_semantics.with_custom_scheme_authority_policy(
      empty,
      "HTTP",
      header_semantics.OptionalAuthority,
    )
    == Error(header_semantics.ReservedAuthorityScheme)
  assert header_semantics.with_custom_scheme_authority_policy(
      empty,
      "https",
      header_semantics.NoAuthority,
    )
    == Error(header_semantics.ReservedAuthorityScheme)
  assert header_semantics.with_custom_scheme_authority_policy(
      empty,
      "1invalid",
      header_semantics.OptionalAuthority,
    )
    == Error(header_semantics.InvalidAuthorityScheme)
  assert header_semantics.with_custom_scheme_authority_policy(
      empty,
      "",
      header_semantics.OptionalAuthority,
    )
    == Error(header_semantics.InvalidAuthorityScheme)
  assert header_semantics.with_custom_scheme_authority_policy(
      empty,
      "schéme",
      header_semantics.OptionalAuthority,
    )
    == Error(header_semantics.InvalidAuthorityScheme)
  assert header_semantics.with_custom_scheme_authority_policy(
      empty,
      string.repeat("a", 65),
      header_semantics.OptionalAuthority,
    )
    == Error(header_semantics.AuthoritySchemeTooLong(64))
  let assert Ok(one) =
    header_semantics.with_custom_scheme_authority_policy(
      empty,
      "Case-Safe",
      header_semantics.OptionalAuthority,
    )
  assert header_semantics.with_custom_scheme_authority_policy(
      one,
      "case-safe",
      header_semantics.MandatoryAuthority,
    )
    == Error(header_semantics.DuplicateAuthorityScheme)
  let assert Ok(full) = add_optional_policies(empty, 0, 32)
  assert header_semantics.with_custom_scheme_authority_policy(
      full,
      "overflow",
      header_semantics.OptionalAuthority,
    )
    == Error(header_semantics.AuthorityPolicyLimitExceeded(32))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_request_control_fields_and_content_length_test() -> Nil {
  let fields = [
    field(<<":method">>, <<"POST">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":authority">>, <<"example.com">>),
    field(<<":path">>, <<"/upload">>),
    field(<<"host">>, <<"example.com">>),
    field(<<"content-length">>, <<"5, 5">>),
    field(<<"te">>, <<"trailers">>),
  ]
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    regular,
    Some(5),
  )) = header_semantics.validate(fields, header_semantics.RequestSection, False)
  assert control.method == <<"POST">>
  assert control.scheme == Some(<<"https">>)
  assert control.authority == Some(<<"example.com">>)
  assert control.path == Some(<<"/upload">>)
  assert control.protocol == None
  assert regular
    == [
      field(<<"host">>, <<"example.com">>),
      field(<<"content-length">>, <<"5, 5">>),
      field(<<"te">>, <<"trailers">>),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_connect_and_negotiated_extended_connect_test() -> Nil {
  let connect = [
    field(<<":method">>, <<"CONNECT">>),
    field(<<":authority">>, <<"example.com:443">>),
  ]
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    [],
    None,
  )) =
    header_semantics.validate(connect, header_semantics.RequestSection, False)
  assert control.scheme == None
  assert control.path == None

  let extended = [
    field(<<":method">>, <<"CONNECT">>),
    field(<<":protocol">>, <<"websocket">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":authority">>, <<"example.com">>),
    field(<<":path">>, <<"/chat">>),
  ]
  assert header_semantics.validate(
      extended,
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.ExtendedConnectNotEnabled)
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    [],
    None,
  )) =
    header_semantics.validate(extended, header_semantics.RequestSection, True)
  assert control.protocol == Some(<<"websocket">>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_pseudo_header_order_duplicates_and_missing_values_test() -> Nil {
  assert header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<"accept">>, <<"*/*">>),
        field(<<":scheme">>, <<"https">>),
      ],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.PseudoHeaderAfterRegular)
  assert header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<":method">>, <<"POST">>),
      ],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.DuplicatePseudoHeader(<<":method">>))
  assert header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<":scheme">>, <<"https">>),
        field(<<":path">>, <<"/">>),
      ],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.MissingPseudoHeader(<<":authority">>))
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(host_control),
    [host],
    None,
  )) =
    header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<":scheme">>, <<"https">>),
        field(<<":path">>, <<"/">>),
        field(<<"host">>, <<"example.com">>),
      ],
      header_semantics.RequestSection,
      False,
    )
  assert host_control.authority == Some(<<"example.com">>)
  assert host == field(<<"host">>, <<"example.com">>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ordinary_requests_require_exactly_one_method_scheme_and_path_test() -> Nil {
  let authority = field(<<":authority">>, <<"example.com">>)
  let method = field(<<":method">>, <<"GET">>)
  let scheme = field(<<":scheme">>, <<"https">>)
  let path = field(<<":path">>, <<"/">>)
  assert header_semantics.validate(
      [scheme, authority, path],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.MissingPseudoHeader(<<":method">>))
  assert header_semantics.validate(
      [method, authority, path],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.MissingPseudoHeader(<<":scheme">>))
  assert header_semantics.validate(
      [method, scheme, authority],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.MissingPseudoHeader(<<":path">>))
  assert header_semantics.validate(
      [method, scheme, scheme, authority, path],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.DuplicatePseudoHeader(<<":scheme">>))
  assert header_semantics.validate(
      [method, scheme, authority, path, path],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.DuplicatePseudoHeader(<<":path">>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authority_and_host_are_nonempty_and_identical_when_both_exist_test() -> Nil {
  let prefix = [
    field(<<":method">>, <<"GET">>),
    field(<<":scheme">>, <<"https">>),
  ]
  let path = field(<<":path">>, <<"/">>)
  assert header_semantics.validate(
      list.append(prefix, [field(<<":authority">>, <<>>), path]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.InvalidAuthority)
  assert header_semantics.validate(
      list.append(prefix, [
        field(<<":authority">>, <<"example.com">>),
        path,
        field(<<"host">>, <<>>),
      ]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.InvalidAuthority)
  assert header_semantics.validate(
      list.append(prefix, [
        field(<<":authority">>, <<"example.com">>),
        path,
        field(<<"host">>, <<"other.example">>),
      ]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.AuthorityHostMismatch)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn mandatory_scheme_accepts_host_as_the_effective_authority_test() -> Nil {
  let fields = [
    field(<<":method">>, <<"GET">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":path">>, <<"/">>),
    field(<<"host">>, <<"example.com">>),
  ]
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    [host],
    None,
  )) = header_semantics.validate(fields, header_semantics.RequestSection, False)
  assert control.authority == Some(<<"example.com">>)
  assert host == field(<<"host">>, <<"example.com">>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn scheme_without_target_authority_rejects_authority_and_host_test() -> Nil {
  let assert Ok(policies) =
    header_semantics.authority_policies()
    |> header_semantics.with_custom_scheme_authority_policy(
      "local",
      header_semantics.NoAuthority,
    )
  assert header_semantics.validate_with_authority_policies(
      custom_request(<<"local">>, Some(<<"forbidden">>), None),
      header_semantics.RequestSection,
      False,
      policies,
    )
    == Error(header_semantics.InvalidAuthority)
  assert header_semantics.validate_with_authority_policies(
      custom_request(<<"local">>, None, Some(<<"forbidden">>)),
      header_semantics.RequestSection,
      False,
      policies,
    )
    == Error(header_semantics.InvalidAuthority)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_smuggling_prone_regular_fields_test() -> Nil {
  let base = [
    field(<<":method">>, <<"GET">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":authority">>, <<"example.com">>),
    field(<<":path">>, <<"/">>),
  ]
  assert header_semantics.validate(
      list.append(base, [field(<<"Connection">>, <<"close">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.UppercaseFieldName)
  assert header_semantics.validate(
      list.append(base, [field(<<"transfer-encoding">>, <<"chunked">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.ConnectionSpecificField(<<"transfer-encoding">>))
  assert header_semantics.validate(
      list.append(base, [field(<<"te">>, <<"gzip">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.InvalidTeField)
  assert header_semantics.validate(
      list.append(base, [
        field(<<"content-length">>, <<"4">>),
        field(<<"content-length">>, <<"5">>),
      ]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.ConflictingContentLength)
  assert header_semantics.validate(
      list.append(base, [field(<<"x">>, <<"bad\r\nvalue">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.InvalidFieldValue)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_response_status_and_rejects_http_upgrade_test() -> Nil {
  let assert Ok(header_semantics.Validated(
    header_semantics.ResponseControlData(103),
    [regular],
    None,
  )) =
    header_semantics.validate(
      [field(<<":status">>, <<"103">>), field(<<"link">>, <<"</a>">>)],
      header_semantics.ResponseSection,
      False,
    )
  assert regular == field(<<"link">>, <<"</a>">>)
  assert header_semantics.is_informational_status(103)
  assert !header_semantics.is_informational_status(200)
  assert header_semantics.validate(
      [field(<<":status">>, <<"101">>)],
      header_semantics.ResponseSection,
      False,
    )
    == Error(header_semantics.SwitchingProtocolsForbidden)
  assert header_semantics.validate(
      [field(<<":method">>, <<"GET">>)],
      header_semantics.ResponseSection,
      False,
    )
    == Error(header_semantics.UnexpectedPseudoHeader(<<":method">>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn trailers_forbid_pseudo_and_framing_fields_test() -> Nil {
  let assert Ok(header_semantics.Validated(
    header_semantics.TrailerControlData,
    [decoded],
    None,
  )) =
    header_semantics.validate(
      [field(<<"checksum">>, <<"ok">>)],
      header_semantics.TrailerSection,
      False,
    )
  assert decoded == field(<<"checksum">>, <<"ok">>)
  assert header_semantics.validate(
      [field(<<":status">>, <<"200">>)],
      header_semantics.TrailerSection,
      False,
    )
    == Error(header_semantics.PseudoHeaderInTrailers)
  assert header_semantics.validate(
      [field(<<"content-length">>, <<"0">>)],
      header_semantics.TrailerSection,
      False,
    )
    == Error(header_semantics.ForbiddenTrailerField(<<"content-length">>))
}
