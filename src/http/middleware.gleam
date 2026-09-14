//// Ordered protocol-neutral request middleware.

import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import http/body
import http/context
import http/error

/// The stable application handler contract.
pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

/// The remaining middleware chain. Its constructor is private so middleware
/// can only continue through `next`.
pub opaque type Next {
  Next(handler: Handler)
}

/// One middleware layer. Returning without calling `next` short-circuits the
/// remainder of the chain.
pub type Middleware =
  fn(Request(body.Body), context.Context, Next) ->
    Result(Response(body.Body), error.Error)

/// Continue with the next middleware layer or terminal handler.
pub fn next(
  continuation: Next,
  request: Request(body.Body),
  context: context.Context,
) -> Result(Response(body.Body), error.Error) {
  let Next(handler) = continuation
  handler(request, context)
}

/// Execute middleware in declaration order around one terminal handler.
pub fn run(
  middlewares: List(Middleware),
  handler: Handler,
  request: Request(body.Body),
  context: context.Context,
) -> Result(Response(body.Body), error.Error) {
  stack(middlewares, handler)(request, context)
}

/// Compile an ordered middleware list into one handler.
pub fn stack(middlewares: List(Middleware), handler: Handler) -> Handler {
  case middlewares {
    [] -> handler
    [middleware, ..rest] -> {
      let continuation = Next(stack(rest, handler))
      fn(request, context) { middleware(request, context, continuation) }
    }
  }
}
