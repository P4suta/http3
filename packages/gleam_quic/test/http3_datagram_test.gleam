import gleam_quic/internal/http3/capsule
import gleam_quic/internal/http3/datagram

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn binds_unreliable_datagrams_to_negotiated_extension_requests_test() -> Nil {
  let assert Ok(state) = datagram.new(True, True, 2, 8)
  let assert Ok(extension) = datagram.extension(<<"websocket">>)
  let assert Ok(state) =
    datagram.associate(state, 4, extension, datagram.UnreliableAndCapsules)
  let assert Ok(encoded) = datagram.encode_unreliable(state, 4, <<"hi">>)
  assert encoded == <<1, "hi">>
  assert datagram.decode_unreliable(state, encoded)
    == Ok(datagram.Received(4, extension, <<"hi">>))
  assert datagram.decode_unreliable(state, <<2, "unknown">>)
    == Error(datagram.UnknownAssociation(8))
  assert datagram.associate(state, 3, extension, datagram.Capsules)
    == Error(datagram.InvalidRequestStream(3))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn capsule_delivery_uses_the_enclosing_request_association_test() -> Nil {
  let assert Ok(state) = datagram.new(False, False, 1, 3)
  let assert Ok(extension) = datagram.extension(<<"connect-udp">>)
  let assert Ok(state) =
    datagram.associate(state, 0, extension, datagram.Capsules)
  assert datagram.encode_capsule(state, 0, <<"udp">>) == Ok(<<0, 3, "udp">>)
  assert datagram.receive_capsule(state, 0, capsule.Datagram(<<"udp">>))
    == Ok(datagram.DatagramReceived(datagram.Received(0, extension, <<"udp">>)))
  assert datagram.receive_capsule(state, 0, capsule.Unknown(0x21, <<"x">>))
    == Ok(datagram.ExtensionCapsule(0, extension, 0x21, <<"x">>))
  assert datagram.encode_unreliable(state, 0, <<>>)
    == Error(datagram.UnreliableDatagramNotNegotiated)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn requires_both_quic_and_http_datagram_negotiation_and_bounds_test() -> Nil {
  let assert Ok(extension) = datagram.extension(<<"connect-ip">>)
  let assert Ok(state) = datagram.new(True, False, 1, 2)
  assert datagram.associate(state, 0, extension, datagram.Unreliable)
    == Error(datagram.UnreliableDatagramNotNegotiated)
  let assert Ok(state) = datagram.new(True, True, 1, 2)
  let assert Ok(state) =
    datagram.associate(state, 0, extension, datagram.Unreliable)
  assert datagram.encode_unreliable(state, 0, <<1, 2, 3>>)
    == Error(datagram.PayloadLimitExceeded(2))
  assert datagram.extension(<<>>) == Error(datagram.InvalidExtension)
}
