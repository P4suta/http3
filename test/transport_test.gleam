import gleam/bit_array
import gleam/result
import gleeunit
import http/internal/transport
import http_test_support

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

pub fn a_stalled_first_candidate_does_not_consume_the_connect_deadline_test() -> Nil {
  use host <- http_test_support.with_blackhole_first_host

  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)

  let mailbox_before = http_test_support.message_queue_length()
  let started = transport.monotonic_millisecond()
  let connected = transport.connect(host, port, 2000, 1000)
  let elapsed = transport.monotonic_millisecond() - started

  let assert Ok(client) = connected
  let assert Ok(server) = transport.accept(listener, 1000)

  // The first resolved address is unroutable, so a connect path that hands one
  // candidate the whole budget never reaches loopback, and one that abandons
  // the list on a stall never tries it. Bounding each attempt by the RFC 8305
  // Connection Attempt Delay reaches it one delay in.
  assert elapsed < 1000

  // Abandoning an attempt leaves nothing behind for the caller to receive, so
  // the connect path adds no message to its owner's mailbox.
  assert http_test_support.message_queue_length() == mailbox_before

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn resolved_addresses_are_ordered_by_rfc6724_destination_selection_test() -> Nil {
  // RFC 8305 section 4 requires the resolved addresses to be sorted by RFC 6724
  // section 6 Destination Address Selection before any of them is attempted.
  // The vectors are that document's own worked examples from section 10.2, each
  // naming the source address the algorithm selects for each destination; source
  // selection itself is the kernel's here, so what is pinned is the destination
  // ordering given those sources.
  let order = http_test_support.sorted_destination_order

  // Rule 2, prefer matching scope: the global source goes with the global
  // destination and the link-local one with the IPv4 destination it reaches.
  assert order([
      #("2001:db8:1::1", "2001:db8:1::2"),
      #("198.51.100.121", "169.254.13.78"),
    ])
    == ["2001:db8:1::1", "198.51.100.121"]
  assert order([
      #("2001:db8:1::1", "fe80::1"),
      #("198.51.100.121", "198.51.100.117"),
    ])
    == ["198.51.100.121", "2001:db8:1::1"]

  // Rule 6, prefer higher precedence: the default policy table puts ::/0 above
  // the IPv4-mapped prefix, so IPv6 leads when the scopes match. The reversed
  // input is the one that isolates the rule, because with the document's own
  // order rule 10 would have produced the same answer.
  assert order([#("2001:db8:1::1", "2001:db8:1::2"), #("10.1.2.3", "10.1.2.4")])
    == ["2001:db8:1::1", "10.1.2.3"]
  assert order([#("10.1.2.3", "10.1.2.4"), #("2001:db8:1::1", "2001:db8:1::2")])
    == ["2001:db8:1::1", "10.1.2.3"]

  // Rule 8, prefer smaller scope.
  assert order([#("2001:db8:1::1", "2001:db8:1::2"), #("fe80::1", "fe80::2")])
    == ["fe80::1", "2001:db8:1::1"]

  // Rule 9, longest matching prefix, capped at the length of the source prefix,
  // again with the reversed input that isolates it from rule 10.
  assert order([
      #("2001:db8:1::1", "2001:db8:1::2"),
      #("2001:db8:3ffe::1", "2001:db8:3f44::2"),
    ])
    == ["2001:db8:1::1", "2001:db8:3ffe::1"]
  assert order([
      #("2001:db8:3ffe::1", "2001:db8:3f44::2"),
      #("2001:db8:1::1", "2001:db8:1::2"),
    ])
    == ["2001:db8:1::1", "2001:db8:3ffe::1"]

  // Rule 5, prefer matching label: both destinations are reached from a 6to4
  // source, and only the 6to4 destination shares its label. Reversed, the rule
  // has to outrank rule 6, which would have preferred the other one.
  assert order([
      #("2002:c633:6401::1", "2002:c633:6401::2"),
      #("2001:db8:1::1", "2002:c633:6401::2"),
    ])
    == ["2002:c633:6401::1", "2001:db8:1::1"]
  assert order([
      #("2001:db8:1::1", "2002:c633:6401::2"),
      #("2002:c633:6401::1", "2002:c633:6401::2"),
    ])
    == ["2002:c633:6401::1", "2001:db8:1::1"]

  // Rule 7, prefer native transport: the two destinations tie on scope, on
  // label -- neither source matches its destination's -- and on precedence, so
  // what separates them is that the first is reached from a 6to4 source and the
  // second from a unique local one.
  assert order([
      #("2001:db8:1::1", "2002:c633:6401::2"),
      #("2001:db8:2::1", "fd00::2"),
    ])
    == ["2001:db8:2::1", "2001:db8:1::1"]

  // Rule 6 again, and it outranks the label match of the preceding vector.
  assert order([
      #("2002:c633:6401::1", "2002:c633:6401::2"),
      #("2001:db8:1::1", "2001:db8:1::2"),
    ])
    == ["2001:db8:1::1", "2002:c633:6401::1"]

  // Rule 1, avoid unusable destinations: one with no source sorts last whatever
  // the rules after it would have said.
  assert order([#("2001:db8:1::1", ""), #("198.51.100.121", "198.51.100.117")])
    == ["198.51.100.121", "2001:db8:1::1"]

  // Rule 10, otherwise leave the order unchanged: two destinations that tie
  // every rule keep the order they arrived in, in both directions.
  assert order([
      #("2001:db8:1::1", "2001:db8:1::2"),
      #("2001:db8:1::2", "2001:db8:1::2"),
    ])
    == ["2001:db8:1::1", "2001:db8:1::2"]
  assert order([
      #("2001:db8:1::2", "2001:db8:1::2"),
      #("2001:db8:1::1", "2001:db8:1::2"),
    ])
    == ["2001:db8:1::2", "2001:db8:1::1"]
}

pub fn resolved_addresses_interleave_the_two_families_test() -> Nil {
  // RFC 8305 section 4: whichever family leads the sorted list is followed by an
  // address of the other family, so a family whose connectivity is impaired
  // costs one attempt rather than a run of them. What is left when one family
  // runs out follows in its sorted order.
  let interleave = http_test_support.interleaved_destination_order

  assert interleave([
      "2001:db8::1", "2001:db8::2", "2001:db8::3", "198.51.100.1",
      "198.51.100.2",
    ])
    == [
      "2001:db8::1", "198.51.100.1", "2001:db8::2", "198.51.100.2",
      "2001:db8::3",
    ]

  // The leading family is whichever one sorted first, not IPv6 by fiat.
  assert interleave(["198.51.100.1", "2001:db8::1", "198.51.100.2"])
    == ["198.51.100.1", "2001:db8::1", "198.51.100.2"]

  // One family alone keeps its order, and an empty list stays empty.
  assert interleave(["2001:db8::1", "2001:db8::2"])
    == ["2001:db8::1", "2001:db8::2"]
  assert interleave([]) == []
}

pub fn both_address_families_are_asked_for_at_once_test() -> Nil {
  // RFC 8305 section 3: the two queries are issued as close together as
  // possible and resolution is asynchronous, so neither family waits on the
  // other's answer. The first answer starts the Resolution Delay of section 8,
  // and a straggler is waited for only until that runs out.
  //
  // The delays here are far apart on purpose: two seconds against fifty
  // milliseconds, so the assertions hold with a wide margin on a loaded host
  // rather than resting on the clock.
  let trace = http_test_support.family_resolution_trace

  // Both answer at once: nothing is delayed, and both are present.
  let #(elapsed, six, four) = trace(0, 0, 0)
  assert six
  assert four
  assert elapsed < 500

  // The AAAA answer never arrives. Sequential lookups would have cost the whole
  // two seconds before the A answer was even asked for; here the A answer is
  // already in and the wait ends with the Resolution Delay.
  let #(elapsed, six, four) = trace(2000, 0, 0)
  assert !six
  assert four
  assert elapsed < 500

  // The same in the other direction, which is the case that matters least but
  // must not behave differently.
  let #(elapsed, six, four) = trace(0, 2000, 0)
  assert six
  assert !four
  assert elapsed < 500

  // A straggler inside the Resolution Delay is still taken.
  let #(_, six, four) = trace(10, 0, 0)
  assert six
  assert four

  // A query that dies without answering counts as answering nothing and does
  // not hold the other family, which still answers in full.
  let #(elapsed, six, four) = trace(-1, 0, 0)
  assert !six
  assert four
  assert elapsed < 500

  // Both dying leaves nothing, and returns rather than waiting.
  let #(elapsed, six, four) = trace(-1, -1, 0)
  assert !six
  assert !four
  assert elapsed < 500
}

pub fn a_resolved_name_is_sorted_and_interleaved_before_it_is_attempted_test() -> Nil {
  // The production resolution path, not the two steps on their own: both
  // families are gathered, ordered by RFC 6724, and then interleaved. The
  // concurrency of the two queries is pinned separately, in
  // both_address_families_are_asked_for_at_once_test, because the timing of a
  // real resolver is not something a host file can control.
  //
  // The vectors hold whether or not the host has IPv6 connectivity. 3ffe::/16
  // carries precedence 1 in the default policy table, below the IPv4-mapped
  // prefix, so it sorts after an IPv4 address on a host that can reach it; on a
  // host that cannot, rule 1 puts it last for want of a source. Either way it
  // does not lead, which the unsorted concatenation of the two families would
  // have had it do.
  assert http_test_support.resolved_host_order(
      "http-order-one.test",
      ["127.0.0.2", "127.0.0.3"],
      ["3ffe::1"],
    )
    == ["127.0.0.2", "3ffe::1", "127.0.0.3"]

  // The IPv6 loopback carries precedence 50, the highest in the table, so here
  // IPv6 leads and the interleave pulls the single IPv4 address to second.
  assert http_test_support.resolved_host_order(
      "http-order-two.test",
      ["127.0.0.2"],
      ["::1", "3ffe::1"],
    )
    == ["::1", "127.0.0.2", "3ffe::1"]
}
