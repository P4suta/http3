//// Lazy diagnostic sampling primitives.
////
//// A disabled diagnostic must be observationally free: in particular, its
//// snapshot closure may perform an actor call and therefore must never be
//// evaluated merely to pass a value into a no-op recorder.

import gleam/option.{type Option, None, Some}

/// Capture one snapshot only when its diagnostic consumer is enabled.
pub fn when_enabled(enabled: Bool, capture: fn() -> value) -> Option(value) {
  case enabled {
    False -> None
    True -> Some(capture())
  }
}
