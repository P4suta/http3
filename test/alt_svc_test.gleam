import gleam/option.{None, Some}
import gleeunit/should
import http/internal/alt_svc

pub fn default_freshness_is_twenty_four_hours_test() -> Nil {
  let entry =
    case alt_svc.parse("h3=\":443\"", "EXAMPLE.com", 443, 10) {
      Some(entry) -> Ok(entry)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert entry.origin_host == "example.com"
  assert entry.origin_port == 443
  assert entry.alternative_port == 443
  assert entry.expires_at == 86_400_010
}

pub fn response_age_reduces_freshness_without_underflow_test() -> Nil {
  let fresh =
    case
      alt_svc.parse_with_age("h3=\":8443\"; ma=60", "example.com", 443, 100, 7)
    {
      Some(fresh) -> Ok(fresh)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert fresh.expires_at == 53_100

  let stale =
    case
      alt_svc.parse_with_age("h3=\":8443\"; ma=60", "example.com", 443, 100, 70)
    {
      Some(stale) -> Ok(stale)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert stale.expires_at == 100
}

pub fn quoted_pair_and_unknown_parameters_are_processed_test() -> Nil {
  let entry =
    case
      alt_svc.parse(
        "h3=\"\\:8443\"; extension=ignored; persist=invalid; ma=90",
        "example.com",
        443,
        0,
      )
    {
      Some(entry) -> Ok(entry)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert entry.alternative_port == 8443
  assert entry.expires_at == 90_000
}

pub fn clear_is_case_sensitive_and_cross_host_authorities_are_rejected_test() -> Nil {
  let cleared =
    case alt_svc.parse("clear", "example.com", 443, 77) {
      Some(cleared) -> Ok(cleared)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert cleared.expires_at == 77
  assert alt_svc.parse("CLEAR", "example.com", 443, 77) == None
  assert alt_svc.parse("h3=\"other.example:443\"", "example.com", 443, 77)
    == None
}

pub fn first_supported_alternative_retains_server_preference_test() -> Nil {
  let entry =
    case
      alt_svc.parse(
        "h2=\":7443\"; ma=60, h3=\":8443\"; ma=60, h3=\":9443\"; ma=60",
        "example.com",
        443,
        0,
      )
    {
      Some(entry) -> Ok(entry)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert entry.alternative_port == 8443
}
