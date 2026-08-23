//// RFC 9002 packet- and time-threshold loss classification.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam_quic/internal/rtt
import gleam_quic/varint

const packet_threshold = 3

/// Metadata retained for one unacknowledged packet.
pub type SentPacket {
  SentPacket(
    packet_number: Int,
    time_sent_milliseconds: Int,
    ack_eliciting: Bool,
    in_flight: Bool,
    sent_bytes: Int,
  )
}

/// Newly lost packets, survivors, and the next time-threshold deadline.
pub type Detection {
  Detection(
    lost: List(SentPacket),
    remaining: List(SentPacket),
    next_loss_time_milliseconds: Option(Int),
  )
}

/// Invalid packet number, time, size, or timer granularity.
pub type Error {
  InvalidInput
}

/// Detect losses after a later packet in the same number space was acknowledged.
pub fn detect(
  sent_packets: List(SentPacket),
  largest_acknowledged: Int,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  timer_granularity_milliseconds: Int,
) -> Result(Detection, Error) {
  case
    largest_acknowledged >= 0
    && largest_acknowledged <= varint.maximum
    && now_milliseconds >= 0
    && timer_granularity_milliseconds > 0
    && valid_packets(sent_packets, now_milliseconds)
  {
    False -> Error(InvalidInput)
    True -> {
      let delay = rtt.loss_delay(estimator, timer_granularity_milliseconds)
      Ok(classify(
        sent_packets,
        largest_acknowledged,
        now_milliseconds,
        delay,
        [],
        [],
        None,
      ))
    }
  }
}

fn classify(
  packets: List(SentPacket),
  largest_acknowledged: Int,
  now_milliseconds: Int,
  delay: Int,
  lost_reversed: List(SentPacket),
  remaining_reversed: List(SentPacket),
  next_loss_time: Option(Int),
) -> Detection {
  case packets {
    [] ->
      Detection(
        list.reverse(lost_reversed),
        list.reverse(remaining_reversed),
        next_loss_time,
      )
    [packet, ..rest] ->
      case is_lost(packet, largest_acknowledged, now_milliseconds, delay) {
        True ->
          classify(
            rest,
            largest_acknowledged,
            now_milliseconds,
            delay,
            [packet, ..lost_reversed],
            remaining_reversed,
            next_loss_time,
          )
        False ->
          classify(
            rest,
            largest_acknowledged,
            now_milliseconds,
            delay,
            lost_reversed,
            [packet, ..remaining_reversed],
            earlier_deadline(
              next_loss_time,
              packet,
              largest_acknowledged,
              delay,
            ),
          )
      }
  }
}

fn is_lost(
  packet: SentPacket,
  largest_acknowledged: Int,
  now_milliseconds: Int,
  delay: Int,
) -> Bool {
  packet.packet_number <= largest_acknowledged
  && {
    packet.time_sent_milliseconds <= now_milliseconds - delay
    || largest_acknowledged >= packet.packet_number + packet_threshold
  }
}

fn earlier_deadline(
  current: Option(Int),
  packet: SentPacket,
  largest_acknowledged: Int,
  delay: Int,
) -> Option(Int) {
  case packet.packet_number <= largest_acknowledged {
    False -> current
    True -> {
      let candidate = packet.time_sent_milliseconds + delay
      case current {
        None -> Some(candidate)
        Some(existing) if candidate < existing -> Some(candidate)
        Some(_) -> current
      }
    }
  }
}

fn valid_packets(packets: List(SentPacket), now_milliseconds: Int) -> Bool {
  list.all(packets, fn(packet) {
    packet.packet_number >= 0
    && packet.packet_number <= varint.maximum
    && packet.time_sent_milliseconds >= 0
    && packet.time_sent_milliseconds <= now_milliseconds
    && packet.sent_bytes >= 0
  })
}
