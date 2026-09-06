import gleam/bit_array
import gleam/result
import gleeunit
import http/internal/transport

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn active_once_tcp_reads_never_exceed_the_requested_chunk_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(server) = transport.accept(listener, 1000)

  let assert Ok(Nil) = transport.send(client, <<"abcdefghij":utf8>>)
  let assert Ok(#(server, received)) = read_exact(server, 10, 4, <<>>)
  assert received == <<"abcdefghij":utf8>>

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(transport.ReadEnd(server)) = transport.read(server, 4, 1000)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.stop(listener)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn accept_timeout_is_finite_and_does_not_destroy_the_listener_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  assert transport.accept(listener, 5) == Error(transport.Timeout)

  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(server) = transport.accept(listener, 1000)
  let assert Ok(Nil) = transport.close(client)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn read_timeout_closes_the_socket_to_avoid_late_mailbox_data_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(server) = transport.accept(listener, 1000)

  assert transport.read(server, 16, 5) == Error(transport.Timeout)
  assert transport.read(server, 16, 5) == Ok(transport.ReadEnd(server))

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn invalid_addresses_ports_deadlines_and_payloads_are_typed_test() -> Nil {
  assert transport.listen(<<127, 0, 0>>, 0, 8, 1000)
    == Error(transport.InvalidInput)
  assert transport.listen(<<127, 0, 0, 1>>, 65_536, 8, 1000)
    == Error(transport.InvalidInput)
  assert transport.connect("", 443, 1000, 1000) == Error(transport.InvalidInput)
  assert transport.connect("example.test", 443, 0, 1000)
    == Error(transport.InvalidInput)
  assert transport.connect_with_timeouts("example.test", 443, 0, 1000, 1000)
    == Error(transport.InvalidInput)
  assert transport.connect_with_timeouts("example.test", 443, 1000, 0, 1000)
    == Error(transport.InvalidInput)

  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  assert transport.local_endpoint(listener) != Error(transport.InvalidInput)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

fn read_exact(
  socket: transport.Socket,
  wanted: Int,
  maximum_chunk: Int,
  collected: BitArray,
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  case bit_array.byte_size(collected) == wanted {
    True -> Ok(#(socket, collected))
    False -> {
      use outcome <- result.try(transport.read(socket, maximum_chunk, 1000))
      case outcome {
        transport.ReadData(bytes, socket) -> {
          assert bit_array.byte_size(bytes) > 0
          assert bit_array.byte_size(bytes) <= maximum_chunk
          read_exact(
            socket,
            wanted,
            maximum_chunk,
            bit_array.append(collected, bytes),
          )
        }
        transport.ReadEnd(_) -> Error(transport.Closed)
      }
    }
  }
}
