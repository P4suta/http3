//// Stable Client copies retain a finite diagnostic slice across origins and attempts.
//// Creating the identity holds no actor, global table, directory or endpoint value.
//// A pending core cleanup may later use its bounded observer.

import gleam/option.{type Option, None, Some}
import gleam/result
import http3/config
import http3/failure
import quic_core/client as core_client

pub opaque type Identity {
  Identity(core_budget: core_client.DiagnosticBudget)
}

pub opaque type Reservation {
  Reservation(
    memory: core_client.DiagnosticReservation,
    core_budget: core_client.DiagnosticBudget,
  )
}

/// Allocation-only identity shared by copies of the public HTTP/3 Client.
pub fn new() -> Identity {
  Identity(core_client.new_diagnostic_budget())
}

/// Reserve the HTTP/3 adapter's finite scalar references before core work.
/// The qlog writer working set and accepted events use the associated shared core diagnostic budget, so queue capacity is charged only as it is used.
/// A full shared writer set wins classification before transient byte pressure;
/// the scalar preflight never claims the core-owned connection slot itself.
pub fn reserve(
  identity identity: Identity,
  directory directory: String,
  limits limits: config.Limits,
) -> Result(Option(Reservation), failure.Failure) {
  case directory {
    "" -> Ok(None)
    _ -> {
      let Identity(core_budget) = identity
      let maximum = config.limit(limits, failure.EndpointMemory)
      core_client.reserve_diagnostic_memory(
        core_budget,
        16_384,
        maximum - 65_536,
        config.limit(limits, failure.Connections),
      )
      |> result.map(fn(memory) { Some(Reservation(memory, core_budget)) })
      |> result.map_error(fn(code) {
        case code {
          2 -> failure.Overload(failure.Connections)
          _ -> failure.Limit(failure.EndpointMemory, maximum)
        }
      })
    }
  }
}

/// A returned unused token cannot subsequently start any core connection.
pub fn begin_open(reservation: Option(Reservation)) -> Result(Nil, Nil) {
  case reservation {
    None -> Ok(Nil)
    Some(Reservation(memory, _)) -> core_client.begin_diagnostic_memory(memory)
  }
}

pub fn release_unused(reservation: Option(Reservation)) -> Nil {
  case reservation {
    None -> Nil
    Some(Reservation(memory, _)) ->
      core_client.release_unused_diagnostic_memory(memory)
  }
}

/// A successful public core close confirms diagnostic cleanup.
/// The linked core reservation can also settle this slice after a later confirmed owner join.
/// An unproved or expired cleanup remains charged.
/// This says nothing about the transport's subsequent QUIC Closing lifetime.
pub fn release_confirmed(reservation: Option(Reservation)) -> Nil {
  case reservation {
    None -> Nil
    Some(Reservation(memory, _)) ->
      core_client.release_confirmed_diagnostic_memory(memory)
  }
}

/// Core qlog admission shared by every connection derived from the stable parent Client.
/// Disabled qlog carries no budget into the core layer.
pub fn core_budget(
  reservation: Option(Reservation),
) -> Option(core_client.DiagnosticBudget) {
  case reservation {
    None -> None
    Some(Reservation(memory, budget)) ->
      Some(core_client.link_diagnostic_reservation(budget, memory))
  }
}

/// Scalar HTTP/3 adapter reservations, as `#(bytes, connections)`.
pub fn snapshot(identity: Identity) -> #(Int, Int) {
  let Identity(core_budget) = identity
  let core_client.DiagnosticBudgetAllocation(bytes, connections) =
    core_client.diagnostic_budget_allocation(core_budget)
  #(bytes, connections)
}
