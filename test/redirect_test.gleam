import gleam/http.{Get, Https, Post, Put}
import gleam/http/request
import gleam/option.{None, Some}
import gleeunit/should
import http/body
import http/error
import http/internal/redirect

pub fn see_other_rewrites_post_to_get_and_removes_representation_headers_test() -> Nil {
  let outgoing =
    request.Request(
      method: Post,
      headers: [
        #("authorization", "Bearer same-origin"),
        #("content-length", "3"),
        #("content-type", "text/plain"),
        #("transfer-encoding", "chunked"),
      ],
      body: body.from_text("abc"),
      scheme: Https,
      host: "example.com",
      port: None,
      path: "/old",
      query: None,
    )

  let next = redirect.follow(outgoing, 303, "/next") |> should.be_ok

  assert next.method == Get
  assert next.path == "/next"
  assert request.get_header(next, "authorization") == Ok("Bearer same-origin")
  assert request.get_header(next, "content-length") == Error(Nil)
  assert request.get_header(next, "content-type") == Error(Nil)
  assert request.get_header(next, "transfer-encoding") == Error(Nil)
  assert body.read_all(next.body, 0) == Ok(#(<<>>, []))
}

pub fn temporary_redirect_replays_the_body_and_preserves_the_method_test() -> Nil {
  let outgoing =
    request.Request(
      method: Put,
      headers: [#("content-length", "3")],
      body: body.from_text("abc"),
      scheme: Https,
      host: "example.com",
      port: None,
      path: "/old",
      query: None,
    )

  let next = redirect.follow(outgoing, 307, "/next") |> should.be_ok

  assert next.method == Put
  assert body.read_all(next.body, 3) == Ok(#(<<"abc":utf8>>, []))
}

pub fn temporary_redirect_rejects_a_non_replayable_body_test() -> Nil {
  let source = body.pull(fn(_) { Ok(body.PullEnd([])) })
  let outgoing_body =
    body.from_pull(source, Some(0), None, fn() { Nil }) |> should.be_ok
  let outgoing =
    request.Request(
      method: Put,
      headers: [],
      body: outgoing_body,
      scheme: Https,
      host: "example.com",
      port: None,
      path: "/old",
      query: None,
    )

  let failure = redirect.follow(outgoing, 308, "/next") |> should.be_error

  assert error.kind(failure) == error.Body(error.NotReplayable)
}

pub fn cross_origin_redirect_strips_credentials_and_does_not_inherit_port_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [
        #("authorization", "Bearer secret"),
        #("proxy-authorization", "Basic secret"),
        #("cookie", "sid=secret"),
        #("x-public", "kept"),
      ],
      body: body.empty(),
      scheme: Https,
      host: "example.com",
      port: Some(8443),
      path: "/old",
      query: None,
    )

  let next =
    redirect.follow(outgoing, 301, "https://other.example/next")
    |> should.be_ok

  assert next.host == "other.example"
  assert next.port == None
  assert request.get_header(next, "authorization") == Error(Nil)
  assert request.get_header(next, "proxy-authorization") == Error(Nil)
  assert request.get_header(next, "cookie") == Error(Nil)
  assert request.get_header(next, "x-public") == Ok("kept")
}

pub fn same_origin_compares_hosts_case_insensitively_and_normalises_ports_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [#("authorization", "Bearer retained")],
      body: body.empty(),
      scheme: Https,
      host: "EXAMPLE.com",
      port: None,
      path: "/old",
      query: None,
    )

  let next =
    redirect.follow(outgoing, 301, "https://example.COM:443/next")
    |> should.be_ok

  assert request.get_header(next, "authorization") == Ok("Bearer retained")
}

pub fn relative_location_is_merged_and_fragment_is_not_forwarded_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [],
      body: body.empty(),
      scheme: Https,
      host: "example.com",
      port: None,
      path: "/a/b/old",
      query: Some("old=1"),
    )

  let next =
    redirect.follow(outgoing, 302, "../next?new=2#client-only")
    |> should.be_ok

  assert next.path == "/a/next"
  assert next.query == Some("new=2")
}

pub fn downgrade_userinfo_and_non_http_locations_are_rejected_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [],
      body: body.empty(),
      scheme: Https,
      host: "example.com",
      port: None,
      path: "/old",
      query: None,
    )

  let downgrade =
    redirect.follow(outgoing, 302, "http://example.com/insecure")
    |> should.be_error
  let userinfo =
    redirect.follow(outgoing, 302, "https://user@example.com/secret")
    |> should.be_error
  let non_http =
    redirect.follow(outgoing, 302, "ftp://example.com/archive")
    |> should.be_error

  assert error.kind(downgrade) == error.Policy(error.RedirectPolicy)
  assert error.kind(userinfo) == error.Policy(error.RedirectPolicy)
  assert error.kind(non_http) == error.Policy(error.RedirectPolicy)
}

pub fn uri_scheme_is_case_insensitive_and_normalized_for_redirects_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [],
      body: body.empty(),
      scheme: Https,
      host: "source.example",
      port: None,
      path: "/old",
      query: None,
    )

  let next =
    redirect.follow(outgoing, 302, "hTtPs://EXAMPLE.com:443/next")
    |> should.be_ok

  assert next.scheme == Https
  assert next.host == "example.com"
  assert next.port == Some(443)
  assert next.path == "/next"
}

pub fn rfc3986_relative_reference_and_dot_segment_vectors_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [],
      body: body.empty(),
      scheme: Https,
      host: "a",
      port: None,
      path: "/b/c/d;p",
      query: Some("q"),
    )

  let sibling = redirect.follow(outgoing, 302, "g?y#s") |> should.be_ok
  assert sibling.host == "a"
  assert sibling.path == "/b/c/g"
  assert sibling.query == Some("y")

  let network_path =
    redirect.follow(outgoing, 302, "//Other.Example/g") |> should.be_ok
  assert network_path.host == "other.example"
  assert network_path.path == "/g"

  let query_only = redirect.follow(outgoing, 302, "?y") |> should.be_ok
  assert query_only.path == "/b/c/d;p"
  assert query_only.query == Some("y")

  let above_root =
    redirect.follow(outgoing, 302, "../../../../../g") |> should.be_ok
  assert above_root.path == "/g"
}

pub fn malformed_uri_references_fail_before_redirect_dispatch_test() -> Nil {
  let outgoing =
    request.Request(
      method: Get,
      headers: [],
      body: body.empty(),
      scheme: Https,
      host: "example.com",
      port: None,
      path: "/old",
      query: None,
    )

  let _trailing_percent =
    redirect.follow(outgoing, 302, "/bad%") |> should.be_error
  let _short_percent =
    redirect.follow(outgoing, 302, "/bad%2") |> should.be_error
  let _non_hex_percent =
    redirect.follow(outgoing, 302, "/bad%GG") |> should.be_error
  let _backslash =
    redirect.follow(outgoing, 302, "/back\\slash") |> should.be_error
  let _authority_space =
    redirect.follow(outgoing, 302, "https://exa mple/") |> should.be_error
  let _unterminated_ipv6 =
    redirect.follow(outgoing, 302, "https://[::1") |> should.be_error
  Nil
}
