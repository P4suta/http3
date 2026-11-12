import quic_core
import quic_core/client
import quic_core/config
import quic_core/failure

@external(erlang, "quic_bootstrap_join_test_ffi", "timeout_join")
fn timeout_join(prepare: fn(Int) -> fn() -> Bool) -> #(Bool, Bool, Bool)

// nolint: unused_exports, thrown_away_error -- EUnit entrypoint reduces unexpected private failures to a fixed boolean.
pub fn public_connect_timeout_waits_for_the_establishment_supervisor_to_exit_test() -> Nil {
  let assert Ok(deadlines) =
    config.default_deadlines()
    |> config.with_deadline(failure.Total, 2000)
  let outcome =
    timeout_join(fn(port) {
      let assert Ok(configured) = client.new("localhost", port, "bootstrap")
      fn() {
        let result =
          configured
          |> client.with_address_family(quic_core.Ipv4)
          |> client.with_deadlines(deadlines)
          |> client.connect
        case result {
          Error(client.Failure(failure.Timeout(failure.Total))) -> True
          Ok(connection) -> {
            let _closed = client.close(connection)
            False
          }
          Error(_unexpected_failure) -> False
        }
      }
    })
  assert outcome == #(False, True, True)
}
