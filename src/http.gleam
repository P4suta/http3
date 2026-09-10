//// Unified HTTP capability entry point for the Erlang target.

import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/result
import http/body
import http/client
import http/error
import http3

/// Execute one bounded request and return a detached standard response.
///
/// A temporary safe-default client is always closed before this function
/// returns. The response body has already been collected under the configured
/// one-shot limit and can be replayed independently, including its trailers.
pub fn fetch(
  outgoing: Request(BitArray),
) -> Result(Response(body.Body), error.Error) {
  use temporary <- result.try(client.start(client.defaults()))
  let outcome = client.fetch(temporary, outgoing)
  let _close_result = client.close(temporary)
  outcome
}

/// Return whether this runtime can use the repository-owned HTTP/3 stack.
///
/// HTTP/1.1 and HTTP/2 do not require this QUIC capability.
pub fn supports_http3() -> Bool {
  http3.is_supported()
}
