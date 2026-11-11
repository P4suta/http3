// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Fixed roles for the global resource census.
/// Set a role before publishing readiness, accepting ownership, or executing an application callback.
pub type Role {
  ServerExecutor
  RequestHandler
  UploadReader
  DiagnosticGuardian
  DiagnosticSink
  Http3ConnectionOwner
  Http3RequestReaper
  Http3RequestWorker
  Http3IoWorker
  Http3Listener
  Http3Acceptor
  Http3ResponseSupervisor
  Http3ResponseTerminal
  Http3ResponseWork
  Http3ResponseCleanup
  ClientRaceGuardian
  ClientConnectionCandidate
}

@external(erlang, "proc_lib", "set_label")
fn set_label(label: String) -> Nil

pub fn set(role: Role) -> Nil {
  let label = case role {
    ServerExecutor -> "http.server_executor"
    RequestHandler -> "http.request_handler"
    UploadReader -> "http.upload_reader"
    DiagnosticGuardian -> "http.diagnostic_guardian"
    DiagnosticSink -> "http.diagnostic_sink"
    Http3ConnectionOwner -> "http.http3_connection_owner"
    Http3RequestReaper -> "http.http3_request_reaper"
    Http3RequestWorker -> "http.http3_request_worker"
    Http3IoWorker -> "http.http3_io_worker"
    Http3Listener -> "http.http3_listener"
    Http3Acceptor -> "http.http3_acceptor"
    Http3ResponseSupervisor -> "http.http3_response_supervisor"
    Http3ResponseTerminal -> "http.http3_response_terminal"
    Http3ResponseWork -> "http.http3_response_work"
    Http3ResponseCleanup -> "http.http3_response_cleanup"
    ClientRaceGuardian -> "http.client_race_guardian"
    ClientConnectionCandidate -> "http.client_connection_candidate"
  }
  set_label(label)
}
