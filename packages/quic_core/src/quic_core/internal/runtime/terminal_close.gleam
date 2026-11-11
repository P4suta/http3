//// One fixed atomic word per connection preserves its first authenticated terminal kind and code after the actor releases all runtime resources.
//// No process, endpoint, reason text, payload, or exception is retained.

pub type TerminalClose

pub type Kind {
  Application
  Transport
  LocalTransport
}

pub type Snapshot {
  Pending
  Closed(kind: Kind, code: Int)
}

const maximum_code = 4_611_686_018_427_387_903

const code_space = 4_611_686_018_427_387_904

@external(erlang, "quic_core_terminal_close_ffi", "new")
pub fn new() -> TerminalClose

@external(erlang, "quic_core_terminal_close_ffi", "publish")
fn publish_encoded(close: TerminalClose, value: Int) -> Bool

@external(erlang, "quic_core_terminal_close_ffi", "read")
fn read_encoded(close: TerminalClose) -> Int

pub fn publish(
  close close: TerminalClose,
  kind kind: Kind,
  code code: Int,
) -> Bool {
  case code < 0 || code > maximum_code {
    True -> False
    False -> {
      let value = case kind {
        Application -> code + 1
        Transport -> code_space + code + 1
        LocalTransport -> 2 * code_space + code + 1
      }
      publish_encoded(close, value)
    }
  }
}

pub fn snapshot(close: TerminalClose) -> Snapshot {
  case read_encoded(close) {
    0 -> Pending
    value if value <= code_space -> Closed(Application, value - 1)
    value if value <= 2 * code_space -> Closed(Transport, value - code_space - 1)
    value -> Closed(LocalTransport, value - 2 * code_space - 1)
  }
}
