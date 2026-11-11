//// Constructor boundaries use pinned WHATWG rules and Node 26.8.2 controls.

import gleam/dict
import gleam/result
import http/internal/url_pattern/component
import http/internal/url_pattern/constructor

pub fn absolute_origin_defaults_only_the_port_test() -> Nil {
  assert constructor.parse("https://example.com")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "https"),
        #(constructor.Hostname, "example.com"),
        #(constructor.Port, ""),
      ]),
    )
}

pub fn relative_search_and_hash_preserve_missing_fields_test() -> Nil {
  assert constructor.parse("?version=2#top")
    == Ok(
      dict.from_list([
        #(constructor.Search, "version=2"),
        #(constructor.Hash, "top"),
      ]),
    )
  assert constructor.parse("#top")
    == Ok(
      dict.from_list([
        #(constructor.Hash, "top"),
      ]),
    )
  assert constructor.parse("")
    == Ok(
      dict.from_list([
        #(constructor.Pathname, ""),
      ]),
    )
}

pub fn named_optional_modifier_is_not_a_search_boundary_test() -> Nil {
  assert constructor.parse("/app/:file?version=2#top")
    == Ok(
      dict.from_list([
        #(constructor.Pathname, "/app/:file?version=2"),
        #(constructor.Search, ""),
        #(constructor.Hash, "top"),
      ]),
    )
  assert constructor.parse("/app/file?version=2")
    == Ok(
      dict.from_list([
        #(constructor.Pathname, "/app/file"),
        #(constructor.Search, "version=2"),
      ]),
    )
}

pub fn named_hostname_and_bracketed_address_do_not_create_a_port_test() -> Nil {
  assert constructor.parse("https://:name.example.com:8443/path")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "https"),
        #(constructor.Hostname, ":name.example.com"),
        #(constructor.Port, "8443"),
        #(constructor.Pathname, "/path"),
      ]),
    )
  assert constructor.parse("https://[\\:\\:1]:8443/path")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "https"),
        #(constructor.Hostname, "[\\:\\:1]"),
        #(constructor.Port, "8443"),
        #(constructor.Pathname, "/path"),
      ]),
    )
}

pub fn escaped_delimiters_and_group_contents_follow_token_boundaries_test() -> Nil {
  assert constructor.parse("https\\://example.com/{foo?bar}/tail")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "https"),
        #(constructor.Hostname, "example.com"),
        #(constructor.Port, ""),
        #(constructor.Pathname, "/{foo?bar}/tail"),
      ]),
    )
  assert constructor.parse("/a/(.*)?more#end")
    == Ok(
      dict.from_list([
        #(constructor.Pathname, "/a/(.*)?more"),
        #(constructor.Search, ""),
        #(constructor.Hash, "end"),
      ]),
    )
}

pub fn credentials_default_path_and_search_are_explicit_test() -> Nil {
  assert constructor.parse("https://user\\:pass@example.com#end")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "https"),
        #(constructor.Username, "user"),
        #(constructor.Password, "pass"),
        #(constructor.Hostname, "example.com"),
        #(constructor.Port, ""),
        #(constructor.Pathname, "/"),
        #(constructor.Search, ""),
        #(constructor.Hash, "end"),
      ]),
    )
  assert constructor.parse("data\\:opaque?query")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "data"),
        #(constructor.Hostname, ""),
        #(constructor.Port, ""),
        #(constructor.Pathname, "opaque"),
        #(constructor.Search, "query"),
      ]),
    )
}

pub fn special_scheme_pattern_controls_authority_and_default_path_test() -> Nil {
  assert constructor.parse("https{test}?\\:example.com#end")
    == Ok(
      dict.from_list([
        #(constructor.Protocol, "https{test}?"),
        #(constructor.Hostname, "example.com"),
        #(constructor.Port, ""),
        #(constructor.Pathname, "/"),
        #(constructor.Search, ""),
        #(constructor.Hash, "end"),
      ]),
    )
}

pub fn constructor_input_and_protocol_work_are_bounded_test() -> Nil {
  let result = constructor.parse(repeat("a", 2049)) |> result.replace(Nil)
  assert result == Error(component.WorkLimitExceeded)
}

fn repeat(value: String, count: Int) -> String {
  case count {
    0 -> ""
    _ -> value <> repeat(value, count - 1)
  }
}
