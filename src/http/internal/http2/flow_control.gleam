//// HTTP/2 connection and stream flow-control window arithmetic.

const maximum_window = 0x7fff_ffff

/// A private signed window. SETTINGS reductions may make a stream window
/// negative until WINDOW_UPDATE restores credit.
pub opaque type Window {
  Window(available: Int)
}

/// A flow-control arithmetic or protocol failure.
pub type Error {
  InvalidLimit
  InvalidIncrement
  InvalidConsumption
  FlowControlExceeded
  WindowOverflow
}

/// Construct a window from a valid HTTP/2 initial size.
pub fn new(initial: Int) -> Result(Window, Error) {
  case valid_initial_size(initial) {
    True -> Ok(Window(initial))
    False -> Error(InvalidLimit)
  }
}

/// Return current credit. Stream credit may be negative after SETTINGS.
pub fn available(window: Window) -> Int {
  window.available
}

/// Consume DATA flow-control octets without allowing credit to underflow.
pub fn consume(window: Window, octets: Int) -> Result(Window, Error) {
  case octets {
    value if value < 0 -> Error(InvalidConsumption)
    0 -> Ok(window)
    value if value > window.available -> Error(FlowControlExceeded)
    value -> Ok(Window(window.available - value))
  }
}

/// Apply one non-zero 31-bit WINDOW_UPDATE increment.
pub fn increase(window: Window, increment: Int) -> Result(Window, Error) {
  case increment > 0 && increment <= maximum_window {
    False -> Error(InvalidIncrement)
    True -> checked_window(window.available + increment)
  }
}

/// Apply the delta caused by SETTINGS_INITIAL_WINDOW_SIZE to one stream.
///
/// A reduction is allowed to make the stream window negative. An increase
/// beyond the 31-bit maximum is a flow-control error.
pub fn apply_initial_window_size(
  window: Window,
  previous: Int,
  replacement: Int,
) -> Result(Window, Error) {
  case valid_initial_size(previous) && valid_initial_size(replacement) {
    False -> Error(InvalidLimit)
    True -> checked_window(window.available + replacement - previous)
  }
}

fn checked_window(value: Int) -> Result(Window, Error) {
  case value > maximum_window {
    True -> Error(WindowOverflow)
    False -> Ok(Window(value))
  }
}

fn valid_initial_size(value: Int) -> Bool {
  value >= 0 && value <= maximum_window
}
