//// Runtime capability boundary for the repository-owned QUIC core.

import gleam_quic

pub fn is_supported() -> Bool {
  gleam_quic.is_supported()
}
