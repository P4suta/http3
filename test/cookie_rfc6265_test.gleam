import gleam/http
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import gleeunit/should
import http/internal/cookie

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn cookie_date_verified_and_reported_errata_test() -> Nil {
  let now = 12_345
  let parsed =
    case
      cookie.parse_with_unix_seconds(
        "sid=future; Expires=Fri, 02 JAN 1970 00:00:00 GMT; Path=/",
        http.Https,
        "example.com",
        "/",
        now,
        0,
      )
    {
      Some(parsed) -> Ok(parsed)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok

  assert parsed.expires_at == now + 86_400_000

  let with_suffixes =
    case
      cookie.parse_with_unix_seconds(
        "sid=suffixed; Expires=00:00:00x 02x JANx 1970x; Path=/",
        http.Https,
        "example.com",
        "/",
        now,
        0,
      )
    {
      Some(with_suffixes) -> Ok(with_suffixes)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert with_suffixes.expires_at == now + 86_400_000
}

pub fn invalid_path_uses_default_and_empty_domain_is_ignored_test() -> Nil {
  let parsed =
    case
      cookie.parse(
        "sid=kept; Path=relative; Domain=; Max-Age=60",
        http.Https,
        "example.com",
        "/account/login",
        1000,
      )
    {
      Some(parsed) -> Ok(parsed)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok

  assert parsed.path == "/account"
  assert parsed.domain == "example.com"
  assert parsed.host_only
}

pub fn cookie_domains_use_canonical_idna_and_label_boundaries_test() -> Nil {
  let parsed =
    case
      cookie.parse(
        "sid=idna; Domain=bücher.example; Path=/; Max-Age=60",
        http.Https,
        "BÜCHER.EXAMPLE",
        "/",
        1000,
      )
    {
      Some(parsed) -> Ok(parsed)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok

  assert parsed.domain == "xn--bcher-kva.example"
  assert cookie.request_header(
      [parsed],
      http.Https,
      "shop.bücher.example",
      "/",
      2000,
    )
    == Some("sid=idna")
  assert cookie.request_header(
      [parsed],
      http.Https,
      "notbücher.example",
      "/",
      2000,
    )
    == None
}

pub fn cookie_paths_match_exact_octets_without_uri_normalization_test() -> Nil {
  let parsed =
    case
      cookie.parse(
        "sid=exact; Path=/%7euser; Max-Age=60",
        http.Https,
        "example.com",
        "/%7euser",
        1000,
      )
    {
      Some(parsed) -> Ok(parsed)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert cookie.request_header(
      [parsed],
      http.Https,
      "example.com",
      "/%7euser/profile",
      2000,
    )
    == Some("sid=exact")
  assert cookie.request_header(
      [parsed],
      http.Https,
      "example.com",
      "/%7Euser/profile",
      2000,
    )
    == None
}

pub fn cookie_header_sorts_longer_paths_before_shorter_paths_test() -> Nil {
  let root =
    case
      cookie.parse(
        "root=first; Path=/; Max-Age=60",
        http.Https,
        "example.com",
        "/",
        1000,
      )
    {
      Some(root) -> Ok(root)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let account =
    case
      cookie.parse(
        "account=second; Path=/account; Max-Age=60",
        http.Https,
        "example.com",
        "/account",
        2000,
      )
    {
      Some(account) -> Ok(account)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok

  assert cookie.request_header(
      [root, account],
      http.Https,
      "example.com",
      "/account/view",
      3000,
    )
    == Some("account=second; root=first")

  let older =
    case
      cookie.parse(
        "older=first; Path=/same; Max-Age=60",
        http.Https,
        "example.com",
        "/same",
        1000,
      )
    {
      Some(older) -> Ok(older)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let newer =
    case
      cookie.parse(
        "newer=second; Path=/same; Max-Age=60",
        http.Https,
        "example.com",
        "/same",
        2000,
      )
    {
      Some(newer) -> Ok(newer)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert cookie.request_header(
      [newer, older],
      http.Https,
      "example.com",
      "/same",
      3000,
    )
    == Some("older=first; newer=second")
}

pub fn secure_httponly_and_replacement_metadata_are_retained_test() -> Nil {
  let original =
    case
      cookie.parse(
        "sid=old; Path=/; Secure; HttpOnly; Max-Age=60",
        http.Https,
        "example.com",
        "/",
        1000,
      )
    {
      Some(original) -> Ok(original)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert original.secure
  assert original.http_only
  assert original.persistent
  assert cookie.request_header([original], http.Http, "example.com", "/", 2000)
    == None
  assert cookie.request_header(
      [original],
      http.Https,
      "sub.example.com",
      "/",
      2000,
    )
    == None

  let replacement =
    case
      cookie.parse(
        "sid=new; Path=/; Max-Age=60",
        http.Https,
        "example.com",
        "/",
        3000,
      )
    {
      Some(replacement) -> Ok(replacement)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let replacement =
    cookie.with_creation(replacement, original.creation_milliseconds)
  assert replacement.creation_milliseconds == 1000
  assert replacement.value == "new"
}

pub fn max_age_is_strict_and_the_last_valid_attribute_wins_test() -> Nil {
  let now = 1000
  let parsed =
    case
      cookie.parse(
        "sid=bounded; Max-Age=10; Max-Age=invalid; Max-Age=20",
        http.Https,
        "example.com",
        "/",
        now,
      )
    {
      Some(parsed) -> Ok(parsed)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert parsed.expires_at == now + 20_000

  let invalid =
    case
      cookie.parse(
        "sid=session; Max-Age=+20",
        http.Https,
        "example.com",
        "/",
        now,
      )
    {
      Some(invalid) -> Ok(invalid)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert invalid.expires_at == now + 86_400_000
}

pub fn cookie_parser_rejects_input_beyond_its_finite_budget_test() -> Nil {
  let oversized = "sid=value; extension=" <> string.repeat("a", times: 8192)
  assert cookie.parse(oversized, http.Https, "example.com", "/", 1000) == None

  let excessive_attributes =
    "sid=value" <> string.repeat("; extension=value", times: 65)
  assert cookie.parse(
      excessive_attributes,
      http.Https,
      "example.com",
      "/",
      1000,
    )
    == None

  assert cookie.parse(
      "sid=unsafe\u{0007}value; Path=/",
      http.Https,
      "example.com",
      "/",
      1000,
    )
    == None

  let wsp_only =
    case
      cookie.parse(
        "\t sid \t=\t value \t; Path=/",
        http.Https,
        "example.com",
        "/",
        1000,
      )
    {
      Some(wsp_only) -> Ok(wsp_only)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert wsp_only.name == "sid"
  assert wsp_only.value == "value"
}

pub fn quoted_cookie_pair_is_preserved_without_attribute_leakage_test() -> Nil {
  let parsed =
    case
      cookie.parse_with_unix_seconds(
        "quoted=\"hello\"; Path=/; SameSite=None; Max-Age=60",
        http.Https,
        "example.com",
        "/",
        1000,
        0,
      )
    {
      Some(parsed) -> Ok(parsed)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok

  assert parsed.value == "\"hello\""
  assert cookie.request_header([parsed], http.Https, "example.com", "/", 2000)
    == Some("quoted=\"hello\"")
}

pub fn far_future_expiry_is_bounded_without_integer_overflow_test() -> Nil {
  let now = 1000
  let maximum_age =
    case
      cookie.parse_with_unix_seconds(
        "sid=max-age; Max-Age=999999999999999999999999999999999999",
        http.Https,
        "example.com",
        "/",
        now,
        0,
      )
    {
      Some(maximum_age) -> Ok(maximum_age)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert maximum_age.persistent
  assert maximum_age.expires_at == now + 63_072_000_000

  let expires =
    case
      cookie.parse_with_unix_seconds(
        "sid=expires; Expires=Fri, 31 Dec 9999 23:59:59 GMT",
        http.Https,
        "example.com",
        "/",
        now,
        0,
      )
    {
      Some(expires) -> Ok(expires)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert expires.persistent
  assert expires.expires_at == now + 63_072_000_000
}
