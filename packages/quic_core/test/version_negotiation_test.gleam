import quic_core/internal/version_negotiation
import quic_core/version

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn centralizes_supported_offered_and_fully_deployed_versions_test() -> Nil {
  let expected = [version.Version2, version.Version1]
  assert version_negotiation.supported_versions() == expected
  assert version_negotiation.offered_versions() == expected
  assert version_negotiation.fully_deployed_versions() == expected
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn selects_only_an_offered_unattempted_mutual_version_test() -> Nil {
  assert version_negotiation.select_incompatible(
      version.Version1,
      [version.Unknown(7), version.Version2],
      [],
    )
    == Ok(version.Version2)
  assert version_negotiation.select_incompatible(
      version.Version2,
      [version.Version2, version.Version1],
      [version.Version1],
    )
    == Error(version_negotiation.NoMutualVersion)
  assert version_negotiation.select_incompatible(
      version.Version1,
      [version.Version1],
      [],
    )
    == Error(version_negotiation.NoMutualVersion)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn assumes_only_the_published_v1_v2_compatibility_test() -> Nil {
  assert version_negotiation.compatible(version.Version1, version.Version2)
  assert version_negotiation.compatible(version.Version2, version.Version1)
  assert !version_negotiation.compatible(version.Version1, version.Version1)
  assert !version_negotiation.compatible(
    version.Version1,
    version.Unknown(0xface_b00c),
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn advertises_compatible_versions_only_when_enabled_test() -> Nil {
  assert version_negotiation.available_versions(version.Version1, True)
    == [version.Version2, version.Version1]
  assert version_negotiation.available_versions(version.Version2, False)
    == [version.Version2]
}
