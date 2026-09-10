//// Runtime capability boundary for the repository-owned QUIC core.

import quic_core

pub fn is_supported() -> Bool {
  quic_core.is_supported()
}
