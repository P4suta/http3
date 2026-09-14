import http3/address

pub fn ipv4_literal_and_endpoint_round_trip_test() -> Nil {
  let assert Ok(parsed) = address.parse("127.0.0.1")
  assert address.family(parsed) == address.Ipv4
  assert address.to_string(parsed) == "127.0.0.1"

  let assert Ok(endpoint) = address.endpoint(parsed, 443)
  assert address.endpoint_address(endpoint) == parsed
  assert address.port(endpoint) == 443
  assert address.endpoint_to_string(endpoint) == "127.0.0.1:443"
  assert address.parse_endpoint("127.0.0.1:443") == Ok(endpoint)
}

pub fn ipv6_literal_and_endpoint_round_trip_test() -> Nil {
  let assert Ok(parsed) = address.parse("2001:db8::1")
  assert address.family(parsed) == address.Ipv6
  assert address.to_string(parsed) == "2001:db8::1"

  let assert Ok(endpoint) = address.endpoint(parsed, 8443)
  assert address.endpoint_to_string(endpoint) == "[2001:db8::1]:8443"
  assert address.parse_endpoint("[2001:db8::1]:8443") == Ok(endpoint)
}

pub fn address_parser_rejects_names_and_invalid_ports_test() -> Nil {
  assert address.parse("localhost")
    == Error(address.InvalidAddress("localhost"))
  assert address.parse_endpoint("2001:db8::1:443")
    == Error(address.InvalidEndpoint("2001:db8::1:443"))
  assert address.parse_endpoint("[127.0.0.1]:443")
    == Error(address.InvalidEndpoint("[127.0.0.1]:443"))
  let assert Ok(loopback) = address.parse("127.0.0.1")
  assert address.endpoint(loopback, 65_536)
    == Error(address.InvalidPort(65_536))
}
