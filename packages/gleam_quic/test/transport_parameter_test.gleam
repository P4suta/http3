import gleam_quic/transport_parameter
import gleam_quic/version

const reset_token = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_standard_server_parameters_test() -> Nil {
  let preferred =
    transport_parameter.PreferredAddress(
      ipv4_address: <<127, 0, 0, 1>>,
      ipv4_port: 443,
      ipv6_address: <<0:128>>,
      ipv6_port: 0,
      connection_id: <<1, 2, 3, 4>>,
      stateless_reset_token: reset_token,
    )
  let parameters = [
    transport_parameter.OriginalDestinationConnectionId(<<1, 2>>),
    transport_parameter.MaxIdleTimeout(30_000),
    transport_parameter.StatelessResetToken(reset_token),
    transport_parameter.MaxUdpPayloadSize(1472),
    transport_parameter.InitialMaxData(1_000_000),
    transport_parameter.InitialMaxStreamDataBidiLocal(10_000),
    transport_parameter.InitialMaxStreamDataBidiRemote(20_000),
    transport_parameter.InitialMaxStreamDataUni(30_000),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(50),
    transport_parameter.AckDelayExponent(3),
    transport_parameter.MaxAckDelay(25),
    transport_parameter.DisableActiveMigration,
    transport_parameter.PreferredAddressParameter(preferred),
    transport_parameter.ActiveConnectionIdLimit(4),
    transport_parameter.InitialSourceConnectionId(<<3, 4>>),
    transport_parameter.RetrySourceConnectionId(<<5, 6>>),
    transport_parameter.VersionInformation(version.Version2, [
      version.Version2,
      version.Version1,
    ]),
    transport_parameter.MaxDatagramFrameSize(1200),
    transport_parameter.GreaseQuicBit,
    transport_parameter.Unknown(0x173e, <<9, 8, 7>>),
  ]

  let assert Ok(encoded) =
    transport_parameter.encode_all(parameters, transport_parameter.Server)
  assert transport_parameter.decode_all(
      encoded,
      transport_parameter.Server,
      transport_parameter.default_limits(),
    )
    == Ok(parameters)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn accepts_non_minimal_integer_and_preserves_unknown_test() -> Nil {
  let encoded = <<0x01, 0x02, 0x40, 0x25, 0x1f, 0x02, 1, 2>>
  assert transport_parameter.decode_all(
      encoded,
      transport_parameter.Client,
      transport_parameter.default_limits(),
    )
    == Ok([
      transport_parameter.MaxIdleTimeout(37),
      transport_parameter.Unknown(0x1f, <<1, 2>>),
    ])
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_duplicates_roles_and_invalid_values_test() -> Nil {
  let limits = transport_parameter.default_limits()
  assert transport_parameter.decode_all(
      <<1, 1, 0, 1, 1, 0>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.DuplicateParameter(1))
  assert transport_parameter.decode_all(
      <<0, 0>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.ForbiddenForClient(0))
  assert transport_parameter.decode_all(
      <<3, 2, 0x44, 0xaf>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.InvalidParameter(3))
  assert transport_parameter.decode_all(
      <<0x0a, 1, 21>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.InvalidParameter(0x0a))
  assert transport_parameter.decode_all(
      <<0x0b, 4, 0x80, 0x00, 0x40, 0x00>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.InvalidParameter(0x0b))
  assert transport_parameter.decode_all(
      <<0x0e, 1, 1>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.InvalidParameter(0x0e))
  assert transport_parameter.decode_all(
      <<0x0c, 1, 0>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.InvalidParameter(0x0c))
  assert transport_parameter.decode_all(
      <<0x11, 4, 0, 0, 0, 1>>,
      transport_parameter.Client,
      limits,
    )
    == Error(transport_parameter.InvalidParameter(0x11))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_non_byte_aligned_values_without_vm_exception_test() -> Nil {
  let bits = <<1:size(1)>>
  assert transport_parameter.encode_all(
      [transport_parameter.InitialSourceConnectionId(bits)],
      transport_parameter.Client,
    )
    == Error(transport_parameter.NonByteAligned)
  assert transport_parameter.encode_all(
      [transport_parameter.StatelessResetToken(bits)],
      transport_parameter.Server,
    )
    == Error(transport_parameter.NonByteAligned)
  assert transport_parameter.encode_all(
      [transport_parameter.Unknown(0x1f, bits)],
      transport_parameter.Client,
    )
    == Error(transport_parameter.NonByteAligned)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_parameter_resource_limits_test() -> Nil {
  assert transport_parameter.decode_all(
      <<0x1f, 4, 1, 2, 3, 4>>,
      transport_parameter.Client,
      transport_parameter.Limits(10, 3),
    )
    == Error(transport_parameter.ValueLimitExceeded(3))
  assert transport_parameter.decode_all(
      <<0x1f, 0, 0x20, 0>>,
      transport_parameter.Client,
      transport_parameter.Limits(1, 10),
    )
    == Error(transport_parameter.ParameterLimitExceeded(1))
  assert transport_parameter.decode_all(
      <<1>>,
      transport_parameter.Client,
      transport_parameter.Limits(0, 10),
    )
    == Error(transport_parameter.InvalidLimits)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_handshake_required_parameters_test() -> Nil {
  assert transport_parameter.validate_handshake(
      [transport_parameter.InitialSourceConnectionId(<<1>>)],
      transport_parameter.Client,
      retried: False,
    )
    == Ok(Nil)
  assert transport_parameter.validate_handshake(
      [],
      transport_parameter.Client,
      retried: False,
    )
    == Error(transport_parameter.MissingRequiredParameter(0x0f))
  assert transport_parameter.validate_handshake(
      [transport_parameter.InitialSourceConnectionId(<<1>>)],
      transport_parameter.Server,
      retried: True,
    )
    == Error(transport_parameter.MissingRequiredParameter(0x00))
}
