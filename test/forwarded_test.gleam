import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import http/forwarded

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn a_single_element_round_trips_through_its_field_value_test() -> Nil {
  let assert Ok([element]) =
    forwarded.parse("for=192.0.2.43", forwarded.default_limits())
  assert element.for == Some(forwarded.Ipv4(<<192, 0, 2, 43>>, None))
  assert element.by == None
  assert element.host == None
  assert element.proto == None
  assert element.extensions == []
  assert forwarded.to_field_value([element]) == "for=192.0.2.43"
}

pub fn a_repeated_parameter_in_one_element_is_refused_test() -> Nil {
  assert forwarded.parse(
      "for=192.0.2.43;for=198.51.100.17",
      forwarded.default_limits(),
    )
    == Error(forwarded.DuplicateParameter("for"))
}

pub fn an_obfuscated_identifier_requires_its_leading_underscore_test() -> Nil {
  assert forwarded.obfuscated_node("_hidden") |> result.is_ok
  assert forwarded.obfuscated_node("hidden") == Error(forwarded.InvalidNode)
  assert forwarded.obfuscated_node("_bad!") == Error(forwarded.InvalidNode)
  assert forwarded.obfuscated_node("_") == Error(forwarded.InvalidNode)
}

pub fn an_ipv6_node_is_bracketed_and_quoted_on_the_wire_test() -> Nil {
  // RFC 7239 section 6: ":" is not a token character, so an IPv6 address and
  // any nodename carrying a port have to be quoted.
  let assert Ok([element]) =
    forwarded.parse(
      "for=\"[2001:db8:cafe::17]:47011\"",
      forwarded.default_limits(),
    )
  let assert Some(forwarded.Ipv6(address, Some(forwarded.Port(47_011)))) =
    element.for
  assert address
    == <<0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17>>
  assert forwarded.to_field_value([element])
    == "for=\"[2001:db8:cafe::17]:47011\""
}

pub fn an_ipv6_literal_is_rendered_the_way_rfc_5952_asks_test() -> Nil {
  // Lowercase, no leading zeroes in a group, and the longest run of at least
  // two zero groups compressed exactly once.
  let assert Ok(node) =
    forwarded.with_port(
      forwarded.Ipv6(
        <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
        None,
      ),
      None,
    )
  let element =
    forwarded.Element(
      by: None,
      for: Some(node),
      host: None,
      proto: None,
      extensions: [],
    )
  assert forwarded.to_field_value([element]) == "for=\"[2001:db8::1]\""
}

pub fn each_proxy_appends_its_own_element_in_order_test() -> Nil {
  let assert Ok(elements) =
    forwarded.parse(
      "for=192.0.2.43, for=198.51.100.17",
      forwarded.default_limits(),
    )
  assert list.length(elements) == 2
  let assert Ok(hidden) = forwarded.obfuscated_node("_gateway")
  let appended =
    forwarded.append(
      elements,
      forwarded.Element(
        by: Some(hidden),
        for: None,
        host: None,
        proto: None,
        extensions: [],
      ),
    )
  assert forwarded.to_field_value(appended)
    == "for=192.0.2.43, for=198.51.100.17, by=_gateway"
}

pub fn a_generated_identifier_is_obfuscated_and_fresh_per_request_test() -> Nil {
  // Sections 6.3 and 8.3 both ask for identifiers generated per request, which
  // is what stops the field becoming a stable client identifier.
  let assert Ok(first) = forwarded.generate_obfuscated_node()
  let assert Ok(second) = forwarded.generate_obfuscated_node()
  let assert forwarded.Obfuscated(first_name, None) = first
  let assert forwarded.Obfuscated(second_name, None) = second
  assert first_name != second_name
  assert forwarded.obfuscated_node(first_name) == Ok(first)

  let assert Ok(generated_port) = forwarded.generate_obfuscated_port()
  let assert forwarded.ObfuscatedPort(port_name) = generated_port
  assert forwarded.obfuscated_port(port_name) == Ok(generated_port)

  let assert Ok(element) = forwarded.obfuscated_element()
  let assert Some(forwarded.Obfuscated(by_name, None)) = element.by
  let assert Some(forwarded.Obfuscated(for_name, None)) = element.for
  assert by_name != for_name
}

pub fn an_obfuscated_port_carries_its_own_leading_underscore_test() -> Nil {
  assert forwarded.obfuscated_port("47011") == Error(forwarded.InvalidNode)
  let assert Ok(port) = forwarded.obfuscated_port("_hidden")
  let assert Ok(node) = forwarded.with_port(forwarded.Unknown(None), Some(port))
  let element =
    forwarded.Element(
      by: Some(node),
      for: None,
      host: None,
      proto: None,
      extensions: [],
    )
  assert forwarded.to_field_value([element]) == "by=\"unknown:_hidden\""
}

pub fn a_host_outside_the_host_abnf_is_refused_test() -> Nil {
  let limits = forwarded.default_limits()
  // `:` is not a token character, so an authority carrying a port has to
  // arrive quoted; the bare form is a malformed pair rather than a bad host.
  assert forwarded.parse("host=example.com:8443", limits)
    == Error(forwarded.InvalidParameter)
  let assert Ok([element]) =
    forwarded.parse("host=\"example.com:8443\"", limits)
  assert element.host == Some("example.com:8443")
  assert forwarded.to_field_value([element]) == "host=\"example.com:8443\""
  assert forwarded.parse("host=\"exa mple.com\"", limits)
    == Error(forwarded.InvalidHost)
  assert forwarded.parse("host=\"[2001:db8::1]:443\"", limits)
    |> result.is_ok
}

pub fn a_protocol_outside_the_scheme_production_is_refused_test() -> Nil {
  let limits = forwarded.default_limits()
  let assert Ok([element]) = forwarded.parse("proto=HTTPS", limits)
  assert element.proto == Some("https")
  assert forwarded.parse("proto=1http", limits)
    == Error(forwarded.InvalidProtocol)
}

pub fn an_unregistered_parameter_is_retained_without_interpretation_test() -> Nil {
  // Section 9 admits extension parameters that conform to forwarded-pair; this
  // module forwards them rather than inventing semantics for them.
  let assert Ok([element]) =
    forwarded.parse("for=unknown;secret=\"a b\"", forwarded.default_limits())
  assert element.for == Some(forwarded.Unknown(None))
  assert element.extensions == [forwarded.Parameter("secret", "a b")]
  assert forwarded.to_field_value([element]) == "for=unknown;secret=\"a b\""
}

pub fn every_ceiling_is_finite_and_enforced_test() -> Nil {
  let assert Ok(tight) = forwarded.with_limits(4096, 2, 2)
  assert forwarded.parse("for=unknown, for=unknown, for=unknown", tight)
    == Error(forwarded.TooManyElements)
  assert forwarded.parse("a=1;b=2;c=3", tight)
    == Error(forwarded.TooManyParameters)
  let assert Ok(small) = forwarded.with_limits(8, 2, 2)
  assert forwarded.parse("for=192.0.2.43", small)
    == Error(forwarded.InputTooLarge)
  assert forwarded.with_limits(0, 2, 2) == Error(forwarded.InvalidParameter)
  assert forwarded.with_limits(4096, 0, 2) == Error(forwarded.InvalidParameter)
  assert forwarded.with_limits(4096, 2, 0) == Error(forwarded.InvalidParameter)
}

pub fn a_malformed_node_or_pair_is_refused_test() -> Nil {
  let limits = forwarded.default_limits()
  assert forwarded.parse("for=192.0.2.999", limits)
    == Error(forwarded.InvalidNode)
  assert forwarded.parse("for=192.0.2.043", limits)
    == Error(forwarded.InvalidNode)
  assert forwarded.parse("for=\"[2001:db8::1::2]\"", limits)
    == Error(forwarded.InvalidNode)
  assert forwarded.parse("for=\"unknown:0\"", limits)
    == Error(forwarded.InvalidNode)
  assert forwarded.parse("for", limits) == Error(forwarded.InvalidParameter)
}
