import gleam_quic/internal/tls/extension

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_ordered_tls_extensions_test() -> Nil {
  let extensions = [
    extension.Extension(extension.ServerName, <<0, 0>>),
    extension.Extension(extension.SupportedVersions, <<2, 3, 4>>),
    extension.Extension(extension.QuicTransportParameters, <<1, 0>>),
    extension.Extension(extension.Unknown(0xaaaa), <<9, 8, 7>>),
    extension.Extension(extension.PreSharedKey, <<0, 1, 0, 0>>),
  ]
  let limits = extension.default_limits()
  let assert Ok(encoded) =
    extension.encode_all(extensions, extension.ClientHelloExtensions, limits)
  assert extension.decode_all(encoded, extension.ClientHelloExtensions, limits)
    == Ok(extensions)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_duplicate_and_misordered_tls_extensions_test() -> Nil {
  let limits = extension.default_limits()
  assert extension.decode_all(
      <<0, 43, 0, 0, 0, 43, 0, 0>>,
      extension.OtherExtensions,
      limits,
    )
    == Error(extension.DuplicateExtension(43))
  assert extension.decode_all(
      <<0, 41, 0, 0, 0, 43, 0, 0>>,
      extension.ClientHelloExtensions,
      limits,
    )
    == Error(extension.PreSharedKeyNotLast)
  assert extension.encode_all(
      [
        extension.Extension(extension.PreSharedKey, <<>>),
        extension.Extension(extension.SupportedVersions, <<>>),
      ],
      extension.ClientHelloExtensions,
      limits,
    )
    == Error(extension.PreSharedKeyNotLast)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_tls_extension_resource_limits_test() -> Nil {
  assert extension.decode_all(
      <<1:size(1)>>,
      extension.OtherExtensions,
      extension.default_limits(),
    )
    == Error(extension.NonByteAligned)
  assert extension.decode_all(
      <<0, 43, 0>>,
      extension.OtherExtensions,
      extension.default_limits(),
    )
    == Error(extension.Truncated)
  assert extension.decode_all(
      <<0, 43, 0, 2, 1>>,
      extension.OtherExtensions,
      extension.default_limits(),
    )
    == Error(extension.Truncated)
  assert extension.decode_all(
      <<0, 43, 0, 2, 1, 2>>,
      extension.OtherExtensions,
      extension.Limits(10, 1, 100),
    )
    == Error(extension.DataTooLarge(2))
  assert extension.decode_all(
      <<0, 43, 0, 0, 0, 51, 0, 0>>,
      extension.OtherExtensions,
      extension.Limits(1, 10, 100),
    )
    == Error(extension.ExtensionLimitExceeded(1))
  assert extension.decode_all(
      <<0:88>>,
      extension.OtherExtensions,
      extension.Limits(10, 10, 10),
    )
    == Error(extension.TotalTooLarge(11))
  assert extension.encode_all(
      [extension.Extension(extension.Unknown(43), <<>>)],
      extension.OtherExtensions,
      extension.default_limits(),
    )
    == Error(extension.InvalidKind(43))
}
