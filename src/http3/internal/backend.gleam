//// The boundary between the public HTTP/3 API and the current QUIC backend.
////
//// Backend-specific handles, atoms, maps, and messages must not cross this
//// module boundary into public types.

@external(erlang, "http3_internal_backend_ffi", "is_supported")
pub fn is_supported() -> Bool
