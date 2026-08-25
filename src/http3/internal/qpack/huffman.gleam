//// RFC 7541 Appendix B Huffman codec used by QPACK.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result

type Code {
  Code(symbol: Int, bits: Int, length: Int)
}

/// Invalid alignment, code, EOS use, padding, or decoded-size bound.
pub type Error {
  NonByteAligned
  InvalidCode
  EosSymbol
  InvalidPadding
  OutputLimitExceeded(Int)
}

/// Huffman-encode bytes and pad the final octet with the EOS prefix (ones).
pub fn encode(bytes: BitArray) -> Result(BitArray, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> encode_bytes(bytes, <<>>)
  }
}

/// Strictly decode a bounded Huffman string, rejecting EOS and invalid
/// trailing padding.
pub fn decode(
  bytes: BitArray,
  maximum_output_bytes: Int,
) -> Result(BitArray, Error) {
  case bit_array.bit_size(bytes) % 8, maximum_output_bytes >= 0 {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, False -> Error(OutputLimitExceeded(maximum_output_bytes))
    0, True -> decode_bits(bytes, 0, 0, <<>>, maximum_output_bytes)
    _, True -> Error(NonByteAligned)
  }
}

/// Return encoded byte size without allocating the encoding.
pub fn encoded_size(bytes: BitArray) -> Result(Int, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      use bits <- result.try(encoded_bits(bytes, 0))
      Ok({ bits + 7 } / 8)
    }
  }
}

fn encode_bytes(
  bytes: BitArray,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case bytes {
    <<>> -> pad_encoding(accumulator)
    <<byte, rest:bits>> ->
      case find_symbol(codes(), byte) {
        Some(Code(_, bits, length)) ->
          encode_bytes(rest, <<accumulator:bits, bits:size(length)>>)
        None -> Error(InvalidCode)
      }
    _ -> Error(NonByteAligned)
  }
}

fn pad_encoding(encoded: BitArray) -> Result(BitArray, Error) {
  let remainder = bit_array.bit_size(encoded) % 8
  case remainder {
    0 -> Ok(encoded)
    _ -> {
      let padding_length = 8 - remainder
      let padding = int.bitwise_shift_left(1, padding_length) - 1
      Ok(<<encoded:bits, padding:size(padding_length)>>)
    }
  }
}

fn encoded_bits(bytes: BitArray, total: Int) -> Result(Int, Error) {
  case bytes {
    <<>> -> Ok(total)
    <<byte, rest:bits>> ->
      case find_symbol(codes(), byte) {
        Some(Code(_, _, length)) -> encoded_bits(rest, total + length)
        None -> Error(InvalidCode)
      }
    _ -> Error(NonByteAligned)
  }
}

fn decode_bits(
  bits: BitArray,
  current: Int,
  current_length: Int,
  output: BitArray,
  maximum_output_bytes: Int,
) -> Result(BitArray, Error) {
  case bits {
    <<>> -> validate_padding(current, current_length, output)
    <<bit:1, rest:bits>> -> {
      let current = int.bitwise_or(int.bitwise_shift_left(current, 1), bit)
      let current_length = current_length + 1
      decode_symbol_or_prefix(
        rest,
        current,
        current_length,
        output,
        maximum_output_bytes,
      )
    }
    _ -> Error(NonByteAligned)
  }
}

fn decode_symbol_or_prefix(
  rest: BitArray,
  current: Int,
  current_length: Int,
  output: BitArray,
  maximum_output_bytes: Int,
) -> Result(BitArray, Error) {
  case find_code(codes(), current, current_length) {
    Some(Code(256, _, _)) -> Error(EosSymbol)
    Some(Code(symbol, _, _)) ->
      case bit_array.byte_size(output) >= maximum_output_bytes {
        True -> Error(OutputLimitExceeded(maximum_output_bytes))
        False ->
          decode_bits(rest, 0, 0, <<output:bits, symbol>>, maximum_output_bytes)
      }
    None ->
      case current_length < 30 && has_prefix(codes(), current, current_length) {
        True ->
          decode_bits(
            rest,
            current,
            current_length,
            output,
            maximum_output_bytes,
          )
        False -> Error(InvalidCode)
      }
  }
}

fn validate_padding(
  current: Int,
  current_length: Int,
  output: BitArray,
) -> Result(BitArray, Error) {
  case current_length {
    0 -> Ok(output)
    length if length <= 7 -> {
      let expected = int.bitwise_shift_left(1, length) - 1
      case current == expected {
        True -> Ok(output)
        False -> Error(InvalidPadding)
      }
    }
    _ -> Error(InvalidPadding)
  }
}

fn find_symbol(table: List(Code), symbol: Int) -> Option(Code) {
  case table {
    [] -> None
    [Code(current, _, _) as entry, ..rest] ->
      case current == symbol {
        True -> Some(entry)
        False -> find_symbol(rest, symbol)
      }
  }
}

fn find_code(table: List(Code), bits: Int, length: Int) -> Option(Code) {
  case table {
    [] -> None
    [Code(_, current, current_length) as entry, ..rest] ->
      case current == bits && current_length == length {
        True -> Some(entry)
        False -> find_code(rest, bits, length)
      }
  }
}

fn has_prefix(table: List(Code), bits: Int, length: Int) -> Bool {
  case table {
    [] -> False
    [Code(_, current, current_length), ..rest] ->
      case
        current_length > length
        && int.bitwise_shift_right(current, current_length - length) == bits
      {
        True -> True
        False -> has_prefix(rest, bits, length)
      }
  }
}

fn codes() -> List(Code) {
  [
    Code(0, 0x1ff8, 13),
    Code(1, 0x7fffd8, 23),
    Code(2, 0xfffffe2, 28),
    Code(3, 0xfffffe3, 28),
    Code(4, 0xfffffe4, 28),
    Code(5, 0xfffffe5, 28),
    Code(6, 0xfffffe6, 28),
    Code(7, 0xfffffe7, 28),
    Code(8, 0xfffffe8, 28),
    Code(9, 0xffffea, 24),
    Code(10, 0x3ffffffc, 30),
    Code(11, 0xfffffe9, 28),
    Code(12, 0xfffffea, 28),
    Code(13, 0x3ffffffd, 30),
    Code(14, 0xfffffeb, 28),
    Code(15, 0xfffffec, 28),
    Code(16, 0xfffffed, 28),
    Code(17, 0xfffffee, 28),
    Code(18, 0xfffffef, 28),
    Code(19, 0xffffff0, 28),
    Code(20, 0xffffff1, 28),
    Code(21, 0xffffff2, 28),
    Code(22, 0x3ffffffe, 30),
    Code(23, 0xffffff3, 28),
    Code(24, 0xffffff4, 28),
    Code(25, 0xffffff5, 28),
    Code(26, 0xffffff6, 28),
    Code(27, 0xffffff7, 28),
    Code(28, 0xffffff8, 28),
    Code(29, 0xffffff9, 28),
    Code(30, 0xffffffa, 28),
    Code(31, 0xffffffb, 28),
    Code(32, 0x14, 6),
    Code(33, 0x3f8, 10),
    Code(34, 0x3f9, 10),
    Code(35, 0xffa, 12),
    Code(36, 0x1ff9, 13),
    Code(37, 0x15, 6),
    Code(38, 0xf8, 8),
    Code(39, 0x7fa, 11),
    Code(40, 0x3fa, 10),
    Code(41, 0x3fb, 10),
    Code(42, 0xf9, 8),
    Code(43, 0x7fb, 11),
    Code(44, 0xfa, 8),
    Code(45, 0x16, 6),
    Code(46, 0x17, 6),
    Code(47, 0x18, 6),
    Code(48, 0x0, 5),
    Code(49, 0x1, 5),
    Code(50, 0x2, 5),
    Code(51, 0x19, 6),
    Code(52, 0x1a, 6),
    Code(53, 0x1b, 6),
    Code(54, 0x1c, 6),
    Code(55, 0x1d, 6),
    Code(56, 0x1e, 6),
    Code(57, 0x1f, 6),
    Code(58, 0x5c, 7),
    Code(59, 0xfb, 8),
    Code(60, 0x7ffc, 15),
    Code(61, 0x20, 6),
    Code(62, 0xffb, 12),
    Code(63, 0x3fc, 10),
    Code(64, 0x1ffa, 13),
    Code(65, 0x21, 6),
    Code(66, 0x5d, 7),
    Code(67, 0x5e, 7),
    Code(68, 0x5f, 7),
    Code(69, 0x60, 7),
    Code(70, 0x61, 7),
    Code(71, 0x62, 7),
    Code(72, 0x63, 7),
    Code(73, 0x64, 7),
    Code(74, 0x65, 7),
    Code(75, 0x66, 7),
    Code(76, 0x67, 7),
    Code(77, 0x68, 7),
    Code(78, 0x69, 7),
    Code(79, 0x6a, 7),
    Code(80, 0x6b, 7),
    Code(81, 0x6c, 7),
    Code(82, 0x6d, 7),
    Code(83, 0x6e, 7),
    Code(84, 0x6f, 7),
    Code(85, 0x70, 7),
    Code(86, 0x71, 7),
    Code(87, 0x72, 7),
    Code(88, 0xfc, 8),
    Code(89, 0x73, 7),
    Code(90, 0xfd, 8),
    Code(91, 0x1ffb, 13),
    Code(92, 0x7fff0, 19),
    Code(93, 0x1ffc, 13),
    Code(94, 0x3ffc, 14),
    Code(95, 0x22, 6),
    Code(96, 0x7ffd, 15),
    Code(97, 0x3, 5),
    Code(98, 0x23, 6),
    Code(99, 0x4, 5),
    Code(100, 0x24, 6),
    Code(101, 0x5, 5),
    Code(102, 0x25, 6),
    Code(103, 0x26, 6),
    Code(104, 0x27, 6),
    Code(105, 0x6, 5),
    Code(106, 0x74, 7),
    Code(107, 0x75, 7),
    Code(108, 0x28, 6),
    Code(109, 0x29, 6),
    Code(110, 0x2a, 6),
    Code(111, 0x7, 5),
    Code(112, 0x2b, 6),
    Code(113, 0x76, 7),
    Code(114, 0x2c, 6),
    Code(115, 0x8, 5),
    Code(116, 0x9, 5),
    Code(117, 0x2d, 6),
    Code(118, 0x77, 7),
    Code(119, 0x78, 7),
    Code(120, 0x79, 7),
    Code(121, 0x7a, 7),
    Code(122, 0x7b, 7),
    Code(123, 0x7ffe, 15),
    Code(124, 0x7fc, 11),
    Code(125, 0x3ffd, 14),
    Code(126, 0x1ffd, 13),
    Code(127, 0xffffffc, 28),
    Code(128, 0xfffe6, 20),
    Code(129, 0x3fffd2, 22),
    Code(130, 0xfffe7, 20),
    Code(131, 0xfffe8, 20),
    Code(132, 0x3fffd3, 22),
    Code(133, 0x3fffd4, 22),
    Code(134, 0x3fffd5, 22),
    Code(135, 0x7fffd9, 23),
    Code(136, 0x3fffd6, 22),
    Code(137, 0x7fffda, 23),
    Code(138, 0x7fffdb, 23),
    Code(139, 0x7fffdc, 23),
    Code(140, 0x7fffdd, 23),
    Code(141, 0x7fffde, 23),
    Code(142, 0xffffeb, 24),
    Code(143, 0x7fffdf, 23),
    Code(144, 0xffffec, 24),
    Code(145, 0xffffed, 24),
    Code(146, 0x3fffd7, 22),
    Code(147, 0x7fffe0, 23),
    Code(148, 0xffffee, 24),
    Code(149, 0x7fffe1, 23),
    Code(150, 0x7fffe2, 23),
    Code(151, 0x7fffe3, 23),
    Code(152, 0x7fffe4, 23),
    Code(153, 0x1fffdc, 21),
    Code(154, 0x3fffd8, 22),
    Code(155, 0x7fffe5, 23),
    Code(156, 0x3fffd9, 22),
    Code(157, 0x7fffe6, 23),
    Code(158, 0x7fffe7, 23),
    Code(159, 0xffffef, 24),
    Code(160, 0x3fffda, 22),
    Code(161, 0x1fffdd, 21),
    Code(162, 0xfffe9, 20),
    Code(163, 0x3fffdb, 22),
    Code(164, 0x3fffdc, 22),
    Code(165, 0x7fffe8, 23),
    Code(166, 0x7fffe9, 23),
    Code(167, 0x1fffde, 21),
    Code(168, 0x7fffea, 23),
    Code(169, 0x3fffdd, 22),
    Code(170, 0x3fffde, 22),
    Code(171, 0xfffff0, 24),
    Code(172, 0x1fffdf, 21),
    Code(173, 0x3fffdf, 22),
    Code(174, 0x7fffeb, 23),
    Code(175, 0x7fffec, 23),
    Code(176, 0x1fffe0, 21),
    Code(177, 0x1fffe1, 21),
    Code(178, 0x3fffe0, 22),
    Code(179, 0x1fffe2, 21),
    Code(180, 0x7fffed, 23),
    Code(181, 0x3fffe1, 22),
    Code(182, 0x7fffee, 23),
    Code(183, 0x7fffef, 23),
    Code(184, 0xfffea, 20),
    Code(185, 0x3fffe2, 22),
    Code(186, 0x3fffe3, 22),
    Code(187, 0x3fffe4, 22),
    Code(188, 0x7ffff0, 23),
    Code(189, 0x3fffe5, 22),
    Code(190, 0x3fffe6, 22),
    Code(191, 0x7ffff1, 23),
    Code(192, 0x3ffffe0, 26),
    Code(193, 0x3ffffe1, 26),
    Code(194, 0xfffeb, 20),
    Code(195, 0x7fff1, 19),
    Code(196, 0x3fffe7, 22),
    Code(197, 0x7ffff2, 23),
    Code(198, 0x3fffe8, 22),
    Code(199, 0x1ffffec, 25),
    Code(200, 0x3ffffe2, 26),
    Code(201, 0x3ffffe3, 26),
    Code(202, 0x3ffffe4, 26),
    Code(203, 0x7ffffde, 27),
    Code(204, 0x7ffffdf, 27),
    Code(205, 0x3ffffe5, 26),
    Code(206, 0xfffff1, 24),
    Code(207, 0x1ffffed, 25),
    Code(208, 0x7fff2, 19),
    Code(209, 0x1fffe3, 21),
    Code(210, 0x3ffffe6, 26),
    Code(211, 0x7ffffe0, 27),
    Code(212, 0x7ffffe1, 27),
    Code(213, 0x3ffffe7, 26),
    Code(214, 0x7ffffe2, 27),
    Code(215, 0xfffff2, 24),
    Code(216, 0x1fffe4, 21),
    Code(217, 0x1fffe5, 21),
    Code(218, 0x3ffffe8, 26),
    Code(219, 0x3ffffe9, 26),
    Code(220, 0xffffffd, 28),
    Code(221, 0x7ffffe3, 27),
    Code(222, 0x7ffffe4, 27),
    Code(223, 0x7ffffe5, 27),
    Code(224, 0xfffec, 20),
    Code(225, 0xfffff3, 24),
    Code(226, 0xfffed, 20),
    Code(227, 0x1fffe6, 21),
    Code(228, 0x3fffe9, 22),
    Code(229, 0x1fffe7, 21),
    Code(230, 0x1fffe8, 21),
    Code(231, 0x7ffff3, 23),
    Code(232, 0x3fffea, 22),
    Code(233, 0x3fffeb, 22),
    Code(234, 0x1ffffee, 25),
    Code(235, 0x1ffffef, 25),
    Code(236, 0xfffff4, 24),
    Code(237, 0xfffff5, 24),
    Code(238, 0x3ffffea, 26),
    Code(239, 0x7ffff4, 23),
    Code(240, 0x3ffffeb, 26),
    Code(241, 0x7ffffe6, 27),
    Code(242, 0x3ffffec, 26),
    Code(243, 0x3ffffed, 26),
    Code(244, 0x7ffffe7, 27),
    Code(245, 0x7ffffe8, 27),
    Code(246, 0x7ffffe9, 27),
    Code(247, 0x7ffffea, 27),
    Code(248, 0x7ffffeb, 27),
    Code(249, 0xffffffe, 28),
    Code(250, 0x7ffffec, 27),
    Code(251, 0x7ffffed, 27),
    Code(252, 0x7ffffee, 27),
    Code(253, 0x7ffffef, 27),
    Code(254, 0x7fffff0, 27),
    Code(255, 0x3ffffee, 26),
    Code(256, 0x3fffffff, 30),
  ]
}
