//// Strict, bounded RFC 7239 `Forwarded` parsing and serialization.
////
//// The field carries what a proxy knows and the next hop cannot see: who the
//// request came from, which interface it arrived on, and which scheme carried
//// it. RFC 7239 section 8.2 is explicit that this is sensitive, so nothing
//// here emits a real address unless a caller asks for one: the obfuscated
//// node is the one this module can generate, and the literal ones have to be
//// supplied.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

const default_maximum_bytes = 8192

const default_maximum_elements = 32

const default_maximum_parameters = 32

/// Bytes of randomness behind a generated obfuscated identifier. Sixteen is
/// past birthday collision for any number of requests a single proxy answers,
/// and short enough that a chain of them stays inside the field's own ceiling.
const obfuscated_random_bytes = 16

/// Finite parser ceilings.
pub type Limits {
  Limits(maximum_bytes: Int, maximum_elements: Int, maximum_parameters: Int)
}

/// The port half of a node identifier, RFC 7239 section 6.
pub type NodePort {
  /// A real port number, 1 to 65535.
  Port(number: Int)
  /// A generated token standing in for one, which section 6 requires to carry
  /// a leading underscore so it cannot be read as a port.
  ObfuscatedPort(name: String)
}

/// One node identifier, RFC 7239 section 6.
pub type Node {
  /// Four address bytes.
  Ipv4(address: BitArray, port: Option(NodePort))
  /// Sixteen address bytes. Serialization brackets and quotes these, which
  /// section 6 requires because `:` is not a token character.
  Ipv6(address: BitArray, port: Option(NodePort))
  /// A generated token with a leading underscore.
  Obfuscated(name: String, port: Option(NodePort))
  /// The address is not known to the proxy.
  Unknown(port: Option(NodePort))
}

/// One forwarded-element: the parameters one proxy added.
pub type Element {
  Element(
    by: Option(Node),
    for: Option(Node),
    host: Option(String),
    proto: Option(String),
    extensions: List(Parameter),
  )
}

/// One registered or extension forwarded-pair this module does not interpret.
pub type Parameter {
  Parameter(name: String, value: String)
}

/// Why a field value, node, or generated identifier was refused.
pub type Error {
  /// Section 4: a parameter occurred more than once in one element.
  DuplicateParameter(name: String)
  InvalidNode
  InvalidHost
  InvalidProtocol
  InvalidParameter
  InputTooLarge
  TooManyElements
  TooManyParameters
  RandomnessUnavailable
}

/// Ceilings a proxy can answer with without tuning: eight kibibytes of field,
/// thirty-two elements, thirty-two parameters in any one of them.
pub fn default_limits() -> Limits {
  Limits(
    maximum_bytes: default_maximum_bytes,
    maximum_elements: default_maximum_elements,
    maximum_parameters: default_maximum_parameters,
  )
}

/// Replace the ceilings. Every value stays finite and positive.
pub fn with_limits(
  maximum_bytes maximum_bytes: Int,
  maximum_elements maximum_elements: Int,
  maximum_parameters maximum_parameters: Int,
) -> Result(Limits, Error) {
  case
    maximum_bytes > 0
    && maximum_bytes <= 1_048_576
    && maximum_elements > 0
    && maximum_elements <= 1024
    && maximum_parameters > 0
    && maximum_parameters <= 1024
  {
    False -> Error(InvalidParameter)
    True ->
      Ok(Limits(
        maximum_bytes: maximum_bytes,
        maximum_elements: maximum_elements,
        maximum_parameters: maximum_parameters,
      ))
  }
}

/// Build an obfuscated node from a caller's identifier.
///
/// Section 6.3 requires the leading underscore that tells it from a real name
/// and restricts the rest to ALPHA, DIGIT, ".", "_" and "-".
pub fn obfuscated_node(name: String) -> Result(Node, Error) {
  case valid_obfuscated(name) {
    False -> Error(InvalidNode)
    True -> Ok(Obfuscated(name: name, port: None))
  }
}

/// Build an obfuscated port under the same rule, which section 6 states
/// separately so an `obfport` cannot be read as a port number.
pub fn obfuscated_port(name: String) -> Result(NodePort, Error) {
  case valid_obfuscated(name) {
    False -> Error(InvalidNode)
    True -> Ok(ObfuscatedPort(name: name))
  }
}

/// Attach a port to a node, or remove it with `None`.
pub fn with_port(
  node node: Node,
  port port: Option(NodePort),
) -> Result(Node, Error) {
  case port {
    Some(Port(number)) if number < 1 || number > 65_535 -> Error(InvalidNode)
    _ ->
      Ok(case node {
        Ipv4(address, _) -> Ipv4(address, port)
        Ipv6(address, _) -> Ipv6(address, port)
        Obfuscated(name, _) -> Obfuscated(name, port)
        Unknown(_) -> Unknown(port)
      })
  }
}

/// Generate a fresh obfuscated node from strong randomness.
///
/// Sections 6.3 and 8.3 both ask for identifiers that are random per request,
/// which is what keeps the field from becoming a stable client identifier.
pub fn generate_obfuscated_node() -> Result(Node, Error) {
  use name <- result.try(generate_obfuscated_name())
  Ok(Obfuscated(name: name, port: None))
}

/// The same generator for a port, for a proxy that wants its interface
/// traceable without disclosing it.
pub fn generate_obfuscated_port() -> Result(NodePort, Error) {
  use name <- result.try(generate_obfuscated_name())
  Ok(ObfuscatedPort(name: name))
}

/// An element carrying only generated obfuscated identifiers.
///
/// Sections 5.1, 5.2 and 8.3 all say the default configuration should
/// obfuscate `by` and `for`, so this is what a proxy adds unless it has been
/// configured to disclose something.
pub fn obfuscated_element() -> Result(Element, Error) {
  use by <- result.try(generate_obfuscated_node())
  use for <- result.try(generate_obfuscated_node())
  Ok(
    Element(
      by: Some(by),
      for: Some(for),
      host: None,
      proto: None,
      extensions: [],
    ),
  )
}

/// Parse one `Forwarded` field value into its elements, left to right.
pub fn parse(
  value value: String,
  limits limits: Limits,
) -> Result(List(Element), Error) {
  case string.byte_size(value) > limits.maximum_bytes {
    True -> Error(InputTooLarge)
    False ->
      parse_elements(split_elements(value), limits, [], 0)
      |> result.map(list.reverse)
  }
}

/// Serialize elements back into one field value.
pub fn to_field_value(elements: List(Element)) -> String {
  elements
  |> list.map(element_to_string)
  |> string.join(", ")
}

/// Append one element after the elements a request already carries, which is
/// the order section 4 gives: the first element is the first proxy.
pub fn append(
  elements elements: List(Element),
  element element: Element,
) -> List(Element) {
  list.append(elements, [element])
}

fn split_elements(value: String) -> List(String) {
  string.split(value, ",")
}

fn parse_elements(
  raw: List(String),
  limits: Limits,
  parsed: List(Element),
  count: Int,
) -> Result(List(Element), Error) {
  case raw {
    [] -> Ok(parsed)
    [head, ..rest] ->
      case count >= limits.maximum_elements {
        True -> Error(TooManyElements)
        False -> {
          use element <- result.try(parse_element(head, limits))
          parse_elements(rest, limits, [element, ..parsed], count + 1)
        }
      }
  }
}

fn parse_element(raw: String, limits: Limits) -> Result(Element, Error) {
  let empty =
    Element(by: None, for: None, host: None, proto: None, extensions: [])
  use pairs <- result.try(parse_pairs(string.split(raw, ";"), limits, [], 0))
  apply_pairs(pairs, empty, [])
}

fn parse_pairs(
  raw: List(String),
  limits: Limits,
  parsed: List(#(String, String)),
  count: Int,
) -> Result(List(#(String, String)), Error) {
  case raw {
    [] -> Ok(list.reverse(parsed))
    [head, ..rest] ->
      case string.trim(head) {
        // The ABNF makes the pair optional in every position, so an empty one
        // is well formed and carries nothing.
        "" -> parse_pairs(rest, limits, parsed, count)
        trimmed ->
          case count >= limits.maximum_parameters {
            True -> Error(TooManyParameters)
            False -> {
              use pair <- result.try(parse_pair(trimmed))
              parse_pairs(rest, limits, [pair, ..parsed], count + 1)
            }
          }
      }
  }
}

fn parse_pair(raw: String) -> Result(#(String, String), Error) {
  case string.split_once(raw, "=") {
    Error(Nil) -> Error(InvalidParameter)
    Ok(#(name, value)) -> {
      let name = string.lowercase(string.trim(name))
      use value <- result.try(parse_value(string.trim(value)))
      case valid_token(name) {
        False -> Error(InvalidParameter)
        True -> Ok(#(name, value))
      }
    }
  }
}

fn parse_value(raw: String) -> Result(String, Error) {
  case string.starts_with(raw, "\"") {
    False ->
      case valid_token(raw) {
        False -> Error(InvalidParameter)
        True -> Ok(raw)
      }
    True -> unquote(raw)
  }
}

fn unquote(raw: String) -> Result(String, Error) {
  case string.ends_with(raw, "\"") && string.byte_size(raw) >= 2 {
    False -> Error(InvalidParameter)
    True -> {
      let inner = string.slice(raw, 1, string.length(raw) - 2)
      case string.contains(inner, "\"") {
        True -> Error(InvalidParameter)
        False -> Ok(string.replace(inner, "\\", ""))
      }
    }
  }
}

fn apply_pairs(
  pairs: List(#(String, String)),
  element: Element,
  seen: List(String),
) -> Result(Element, Error) {
  case pairs {
    [] -> Ok(Element(..element, extensions: list.reverse(element.extensions)))
    [#(name, value), ..rest] ->
      case list.contains(seen, name) {
        True -> Error(DuplicateParameter(name))
        False -> {
          use element <- result.try(apply_pair(element, name, value))
          apply_pairs(rest, element, [name, ..seen])
        }
      }
  }
}

fn apply_pair(
  element: Element,
  name: String,
  value: String,
) -> Result(Element, Error) {
  case name {
    "by" -> {
      use node <- result.try(parse_node(value))
      Ok(Element(..element, by: Some(node)))
    }
    "for" -> {
      use node <- result.try(parse_node(value))
      Ok(Element(..element, for: Some(node)))
    }
    "host" ->
      case valid_host(value) {
        False -> Error(InvalidHost)
        True -> Ok(Element(..element, host: Some(value)))
      }
    "proto" ->
      case valid_scheme(value) {
        False -> Error(InvalidProtocol)
        True -> Ok(Element(..element, proto: Some(string.lowercase(value))))
      }
    _ ->
      Ok(
        Element(..element, extensions: [
          Parameter(name: name, value: value),
          ..element.extensions
        ]),
      )
  }
}

fn parse_node(value: String) -> Result(Node, Error) {
  case string.starts_with(value, "[") {
    True -> parse_bracketed_ipv6(value)
    False ->
      case string.split_once(value, ":") {
        Ok(#(name, port)) -> {
          use port <- result.try(parse_node_port(port))
          parse_nodename(name, Some(port))
        }
        Error(Nil) -> parse_nodename(value, None)
      }
  }
}

fn parse_bracketed_ipv6(value: String) -> Result(Node, Error) {
  use #(bracketed, remainder) <- result.try(
    string.split_once(value, "]") |> result.replace_error(InvalidNode),
  )
  use address <- result.try(parse_ipv6(string.drop_start(bracketed, 1)))
  use port <- result.try(parse_trailing_port(remainder))
  Ok(Ipv6(address: address, port: port))
}

/// What may follow a bracketed literal: nothing, or a colon and one port.
fn parse_trailing_port(remainder: String) -> Result(Option(NodePort), Error) {
  case remainder {
    "" -> Ok(None)
    _ ->
      case string.starts_with(remainder, ":") {
        False -> Error(InvalidNode)
        True ->
          parse_node_port(string.drop_start(remainder, 1))
          |> result.map(Some)
      }
  }
}

fn parse_nodename(name: String, port: Option(NodePort)) -> Result(Node, Error) {
  case name {
    "unknown" -> Ok(Unknown(port: port))
    _ ->
      case string.starts_with(name, "_") {
        True ->
          case valid_obfuscated(name) {
            False -> Error(InvalidNode)
            True -> Ok(Obfuscated(name: name, port: port))
          }
        False -> {
          use address <- result.try(parse_ipv4(name))
          Ok(Ipv4(address: address, port: port))
        }
      }
  }
}

fn parse_node_port(raw: String) -> Result(NodePort, Error) {
  case string.starts_with(raw, "_") {
    True ->
      case valid_obfuscated(raw) {
        False -> Error(InvalidNode)
        True -> Ok(ObfuscatedPort(name: raw))
      }
    False ->
      case int.parse(raw) {
        Error(Nil) -> Error(InvalidNode)
        Ok(number) ->
          case number >= 1 && number <= 65_535 && string.byte_size(raw) <= 5 {
            False -> Error(InvalidNode)
            True -> Ok(Port(number: number))
          }
      }
  }
}

fn parse_ipv4(literal: String) -> Result(BitArray, Error) {
  case string.split(literal, ".") {
    [a, b, c, d] -> {
      use a <- result.try(parse_octet(a))
      use b <- result.try(parse_octet(b))
      use c <- result.try(parse_octet(c))
      use d <- result.try(parse_octet(d))
      Ok(<<a, b, c, d>>)
    }
    _ -> Error(InvalidNode)
  }
}

fn parse_octet(raw: String) -> Result(Int, Error) {
  // A leading zero would let "010" and "10" name the same octet, which is what
  // RFC 3986 section 3.2.2 excludes by writing the decimal forms out.
  case int.parse(raw) {
    Error(Nil) -> Error(InvalidNode)
    Ok(value) ->
      case
        value >= 0
        && value <= 255
        && string.byte_size(raw) == string.byte_size(int.to_string(value))
      {
        False -> Error(InvalidNode)
        True -> Ok(value)
      }
  }
}

fn parse_ipv6(literal: String) -> Result(BitArray, Error) {
  case string.split(literal, "::") {
    [single] -> {
      use groups <- result.try(ipv6_groups(string.split(single, ":"), []))
      case list.length(groups) == 8 {
        False -> Error(InvalidNode)
        True -> Ok(ipv6_bytes(groups))
      }
    }
    [head, tail] -> {
      use leading <- result.try(ipv6_side(head))
      use trailing <- result.try(ipv6_side(tail))
      let filled = list.length(leading) + list.length(trailing)
      case filled < 8 {
        False -> Error(InvalidNode)
        True ->
          Ok(
            ipv6_bytes(
              list.flatten([
                leading,
                list.repeat(0, 8 - filled),
                trailing,
              ]),
            ),
          )
      }
    }
    _ -> Error(InvalidNode)
  }
}

fn ipv6_side(raw: String) -> Result(List(Int), Error) {
  case raw {
    "" -> Ok([])
    _ -> ipv6_groups(string.split(raw, ":"), [])
  }
}

fn ipv6_groups(
  raw: List(String),
  parsed: List(Int),
) -> Result(List(Int), Error) {
  case raw {
    [] -> Ok(list.reverse(parsed))
    [head, ..rest] ->
      case int.base_parse(head, 16) {
        Error(Nil) -> Error(InvalidNode)
        Ok(value) ->
          case
            value >= 0
            && value <= 65_535
            && string.byte_size(head) >= 1
            && string.byte_size(head) <= 4
          {
            False -> Error(InvalidNode)
            True -> ipv6_groups(rest, [value, ..parsed])
          }
      }
  }
}

fn ipv6_bytes(groups: List(Int)) -> BitArray {
  list.fold(groups, <<>>, fn(bytes, group) {
    bit_array.append(bytes, <<group:16>>)
  })
}

fn element_to_string(element: Element) -> String {
  [
    optional_pair("by", element.by |> option.map(node_to_string)),
    optional_pair("for", element.for |> option.map(node_to_string)),
    optional_pair("host", element.host |> option.map(quote_if_needed)),
    optional_pair("proto", element.proto),
    ..list.map(element.extensions, fn(parameter) {
      Some(parameter.name <> "=" <> quote_if_needed(parameter.value))
    })
  ]
  |> list.filter_map(fn(pair) { option.to_result(pair, Nil) })
  |> string.join(";")
}

fn optional_pair(name: String, value: Option(String)) -> Option(String) {
  option.map(value, fn(value) { name <> "=" <> value })
}

fn node_to_string(node: Node) -> String {
  let rendered = case node {
    Ipv4(address, port) -> ipv4_to_string(address) <> port_suffix(port)
    // Section 6 requires the brackets and, with them, the quoting: ":" and "["
    // are not token characters.
    Ipv6(address, port) ->
      "[" <> ipv6_to_string(address) <> "]" <> port_suffix(port)
    Obfuscated(name, port) -> name <> port_suffix(port)
    Unknown(port) -> "unknown" <> port_suffix(port)
  }
  quote_if_needed(rendered)
}

fn port_suffix(port: Option(NodePort)) -> String {
  case port {
    None -> ""
    Some(Port(number)) -> ":" <> int.to_string(number)
    Some(ObfuscatedPort(name)) -> ":" <> name
  }
}

fn ipv4_to_string(address: BitArray) -> String {
  case address {
    <<a, b, c, d>> ->
      [a, b, c, d]
      |> list.map(int.to_string)
      |> string.join(".")
    _ -> "unknown"
  }
}

/// RFC 5952: lowercase hexadecimal, no leading zeroes in a group, and the
/// longest run of at least two zero groups compressed to "::".
fn ipv6_to_string(address: BitArray) -> String {
  case ipv6_group_list(address, []) {
    [] -> "unknown"
    groups -> compress_ipv6(groups)
  }
}

fn ipv6_group_list(address: BitArray, parsed: List(Int)) -> List(Int) {
  case address {
    <<group:16, rest:bytes>> -> ipv6_group_list(rest, [group, ..parsed])
    <<>> ->
      case list.length(parsed) == 8 {
        True -> list.reverse(parsed)
        False -> []
      }
    _ -> []
  }
}

fn compress_ipv6(groups: List(Int)) -> String {
  let #(start, length) = longest_zero_run(groups, 0, -1, 0, -1, 0)
  case length >= 2 {
    False ->
      groups
      |> list.map(hexadecimal)
      |> string.join(":")
    True -> {
      let leading =
        groups
        |> list.take(start)
        |> list.map(hexadecimal)
        |> string.join(":")
      let trailing =
        groups
        |> list.drop(start + length)
        |> list.map(hexadecimal)
        |> string.join(":")
      leading <> "::" <> trailing
    }
  }
}

fn longest_zero_run(
  groups: List(Int),
  index: Int,
  run_start: Int,
  run_length: Int,
  best_start: Int,
  best_length: Int,
) -> #(Int, Int) {
  case groups {
    [] -> {
      case run_length > best_length {
        True -> #(run_start, run_length)
        False -> #(best_start, best_length)
      }
    }
    [0, ..rest] -> {
      let start = case run_length {
        0 -> index
        _ -> run_start
      }
      longest_zero_run(
        rest,
        index + 1,
        start,
        run_length + 1,
        best_start,
        best_length,
      )
    }
    [_, ..rest] -> {
      let #(best_start, best_length) = case run_length > best_length {
        True -> #(run_start, run_length)
        False -> #(best_start, best_length)
      }
      longest_zero_run(rest, index + 1, -1, 0, best_start, best_length)
    }
  }
}

fn hexadecimal(group: Int) -> String {
  string.lowercase(int.to_base16(group))
}

fn quote_if_needed(value: String) -> String {
  case valid_token(value) {
    True -> value
    False -> "\"" <> string.replace(value, "\"", "\\\"") <> "\""
  }
}

fn valid_token(value: String) -> Bool {
  case string.byte_size(value) {
    0 -> False
    _ ->
      value
      |> string.to_utf_codepoints
      |> list.all(fn(codepoint) {
        is_token_byte(string.utf_codepoint_to_int(codepoint))
      })
  }
}

fn is_token_byte(byte: Int) -> Bool {
  case byte {
    0x21 -> True
    b if b >= 0x23 && b <= 0x27 -> True
    0x2a | 0x2b | 0x2d | 0x2e -> True
    b if b >= 0x30 && b <= 0x39 -> True
    b if b >= 0x41 && b <= 0x5a -> True
    0x5e | 0x5f | 0x60 -> True
    b if b >= 0x61 && b <= 0x7a -> True
    0x7c | 0x7e -> True
    _ -> False
  }
}

/// Section 6.3: a leading underscore and then ALPHA, DIGIT, ".", "_", "-".
fn valid_obfuscated(name: String) -> Bool {
  case string.pop_grapheme(name) {
    Error(Nil) -> False
    Ok(#("_", rest)) ->
      string.byte_size(rest) > 0
      && rest
      |> string.to_utf_codepoints
      |> list.all(fn(codepoint) {
        is_obfuscated_byte(string.utf_codepoint_to_int(codepoint))
      })
    Ok(_) -> False
  }
}

fn is_obfuscated_byte(byte: Int) -> Bool {
  case byte {
    0x2d | 0x2e | 0x5f -> True
    b if b >= 0x30 && b <= 0x39 -> True
    b if b >= 0x41 && b <= 0x5a -> True
    b if b >= 0x61 && b <= 0x7a -> True
    _ -> False
  }
}

/// Section 5.3 defers to the Host ABNF: a registered name, an IPv4 literal or
/// a bracketed IPv6 literal, each with an optional port.
fn valid_host(value: String) -> Bool {
  let #(authority, port) = case string.starts_with(value, "[") {
    True ->
      case string.split_once(value, "]") {
        Ok(#(bracketed, remainder)) -> #(bracketed <> "]", remainder)
        Error(Nil) -> #(value, "")
      }
    False ->
      case string.split_once(value, ":") {
        Ok(#(name, port)) -> #(name, ":" <> port)
        Error(Nil) -> #(value, "")
      }
  }
  valid_host_authority(authority) && valid_host_port(port)
}

fn valid_host_authority(authority: String) -> Bool {
  case string.starts_with(authority, "[") {
    True ->
      string.ends_with(authority, "]")
      && result.is_ok(parse_ipv6(
        authority
        |> string.drop_start(1)
        |> string.drop_end(1),
      ))
    False ->
      string.byte_size(authority) > 0
      && authority
      |> string.to_utf_codepoints
      |> list.all(fn(codepoint) {
        is_registered_name_byte(string.utf_codepoint_to_int(codepoint))
      })
  }
}

fn valid_host_port(port: String) -> Bool {
  case port {
    "" -> True
    _ ->
      string.starts_with(port, ":")
      && case int.parse(string.drop_start(port, 1)) {
        Error(Nil) -> False
        Ok(number) -> number >= 1 && number <= 65_535
      }
  }
}

fn is_registered_name_byte(byte: Int) -> Bool {
  case byte {
    0x21 | 0x24 -> True
    b if b >= 0x26 && b <= 0x2e -> True
    b if b >= 0x30 && b <= 0x39 -> True
    0x3b | 0x3d -> True
    b if b >= 0x41 && b <= 0x5a -> True
    0x5f -> True
    b if b >= 0x61 && b <= 0x7a -> True
    0x7e -> True
    _ -> False
  }
}

/// Section 5.4 defers to the RFC 3986 scheme production.
fn valid_scheme(value: String) -> Bool {
  case string.pop_grapheme(value) {
    Error(Nil) -> False
    Ok(#(first, rest)) ->
      is_alpha(first)
      && rest
      |> string.to_utf_codepoints
      |> list.all(fn(codepoint) {
        is_scheme_byte(string.utf_codepoint_to_int(codepoint))
      })
  }
}

fn is_alpha(grapheme: String) -> Bool {
  case string.to_utf_codepoints(grapheme) {
    [codepoint] -> {
      let byte = string.utf_codepoint_to_int(codepoint)
      { byte >= 0x41 && byte <= 0x5a } || { byte >= 0x61 && byte <= 0x7a }
    }
    _ -> False
  }
}

fn is_scheme_byte(byte: Int) -> Bool {
  case byte {
    0x2b | 0x2d | 0x2e -> True
    b if b >= 0x30 && b <= 0x39 -> True
    b if b >= 0x41 && b <= 0x5a -> True
    b if b >= 0x61 && b <= 0x7a -> True
    _ -> False
  }
}

fn generate_obfuscated_name() -> Result(String, Error) {
  case random_bytes(obfuscated_random_bytes) {
    Error(Nil) -> Error(RandomnessUnavailable)
    Ok(bytes) -> Ok("_" <> base16_lowercase(bytes))
  }
}

fn base16_lowercase(bytes: BitArray) -> String {
  string.lowercase(bit_array.base16_encode(bytes))
}

/// Strong randomness from the same bounded primitive the OHTTP runtime uses;
/// this module adds no Erlang module of its own for sixteen bytes.
@external(erlang, "http_ohttp_ffi", "random_bytes")
fn random_bytes(count: Int) -> Result(BitArray, Nil)
