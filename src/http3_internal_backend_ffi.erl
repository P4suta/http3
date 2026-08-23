-module(http3_internal_backend_ffi).

-export([is_supported/0]).

-spec is_supported() -> boolean().
is_supported() ->
    quic:is_available().
