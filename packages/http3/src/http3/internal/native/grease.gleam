//// Deterministic HTTP/3 GREASE decisions from an injected scalar sample.

import gleam/option.{type Option, None, Some}
import http3/internal/native/frame
import http3/internal/varint

const reserved_base = 0x21

const reserved_step = 0x1f

const no_error = 0x100

const no_error_grease_denominator = 8

@external(erlang, "http3_grease_ffi", "sample")
fn secure_sample() -> Result(Int, Nil)

/// Obtain one production decision sample without making the pure GREASE selection functions depend on clocks or process state.
/// Failure stays finite and falls back to the caller-provided injected value.
pub fn runtime_sample(fallback: Int) -> Int {
  case secure_sample() {
    Ok(sample) -> sample
    Error(Nil) -> fallback
  }
}

/// Select one reserved SETTINGS identifier and bounded arbitrary value.
/// Disabling GREASE is explicit; an enabled endpoint always advertises one.
pub fn setting(enabled: Bool, sample: Int) -> Option(frame.Setting) {
  case enabled {
    False -> None
    True -> {
      let normalized = positive_remainder(sample, maximum_reserved_index() + 1)
      let identifier = reserved_base + reserved_step * normalized
      let value = positive_remainder(sample / reserved_step, varint.maximum + 1)
      Some(frame.Setting(identifier, value))
    }
  }
}

/// Select a reserved error code for one eighth of injected samples.
/// Other samples preserve the registered H3_NO_ERROR wire value.
pub fn no_error_code(sample: Int) -> Int {
  let normalized = positive_remainder(sample, no_error_grease_denominator)
  case normalized {
    0 -> {
      let selection = sample / no_error_grease_denominator
      reserved_base
      + reserved_step
      * positive_remainder(selection, maximum_reserved_index() + 1)
    }
    _ -> no_error
  }
}

/// Identify values from the RFC 9114 reserved error/setting space.
pub fn is_reserved(value: Int) -> Bool {
  value >= reserved_base
  && value <= varint.maximum
  && { value - reserved_base } % reserved_step == 0
}

fn maximum_reserved_index() -> Int {
  { varint.maximum - reserved_base } / reserved_step
}

fn positive_remainder(value: Int, modulus: Int) -> Int {
  let remainder = value % modulus
  case remainder < 0 {
    True -> remainder + modulus
    False -> remainder
  }
}
