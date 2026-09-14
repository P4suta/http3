//// Pure RFC 9368 version policy shared by packet routing and TLS.
////
//// Keeping this decision surface free of sockets, actors, and cryptographic
//// state makes downgrade behavior exhaustively testable. The caller still
//// authenticates the selected version through TLS Version Information.

import gleam/list
import gleam/result
import quic_core/version.{type Version}

/// A Version Negotiation packet offered no eligible version that has not
/// already been attempted for this logical connection sequence.
pub type Error {
  NoMutualVersion
}

/// Versions implemented by this package, in local preference order.
pub fn supported_versions() -> List(Version) {
  [version.Version2, version.Version1]
}

/// Versions emitted in an incompatible Version Negotiation packet.
pub fn offered_versions() -> List(Version) {
  supported_versions()
}

/// Versions authenticated in server-sent Version Information.
///
/// The current package has one immutable deployment set. If runtime version
/// rollout is added, this function must become a bounded listener snapshot
/// and follow RFC 9368's MSL rollout sequencing.
pub fn fully_deployed_versions() -> List(Version) {
  supported_versions()
}

/// Compatibility explicitly published for the implemented version pair.
/// Identity is handled without negotiation and is intentionally false here.
pub fn compatible(first: Version, second: Version) -> Bool {
  case first, second {
    version.Version1, version.Version2 | version.Version2, version.Version1 ->
      True
    _, _ -> False
  }
}

/// Select a mutually supported incompatible version without retrying the
/// current or any earlier attempted version.
pub fn select_incompatible(
  current: Version,
  offered: List(Version),
  attempted: List(Version),
) -> Result(Version, Error) {
  supported_versions()
  |> list.find(fn(candidate) {
    candidate != current
    && list.contains(offered, candidate)
    && !list.contains(attempted, candidate)
  })
  |> result.replace_error(NoMutualVersion)
}

/// Build client-sent Available Versions while preserving Chosen Version.
pub fn available_versions(
  selected: Version,
  advertise_compatible_versions: Bool,
) -> List(Version) {
  case advertise_compatible_versions {
    True -> supported_versions()
    False -> [selected]
  }
}
