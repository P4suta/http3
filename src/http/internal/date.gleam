//// The Date response field, in the one format RFC 9110 section 5.6.7 prefers.
////
//// Section 6.6.1 requires a Date in every 2xx, 3xx, and 4xx response from an
//// origin server that has a clock, and this one always has. The three server
//// protocols share this module so that a response carries the same field
//// whichever of them wrote it, and so that the wall clock is read in one place.

import gleam/int
import gleam/list
import gleam/string
import http/internal/transport

/// Add a Date field to a response's fields when the status calls for one and
/// the handler did not send its own.
///
/// A handler that set a Date keeps it: the field is the resource's to state
/// when the resource has something to say about it. The name is lowercase
/// because HTTP/2 and HTTP/3 require that of every field, and HTTP/1.1 compares
/// field names without regard to case.
pub fn with_date(
  status status: Int,
  headers headers: List(#(String, String)),
) -> List(#(String, String)) {
  case status >= 200 && status < 500, present(headers, "date") {
    True, False -> [#("date", now()), ..headers]
    _, _ -> headers
  }
}

fn now() -> String {
  imf_fixdate(transport.unix_millisecond() / 1000)
}

fn present(headers: List(#(String, String)), name: String) -> Bool {
  list.any(headers, fn(field) { string.lowercase(field.0) == name })
}

/// Render seconds since the epoch as the fixed-length format section 5.6.7
/// prefers: `Sun, 06 Nov 1994 08:49:37 GMT`, always twenty-nine characters.
fn imf_fixdate(seconds: Int) -> String {
  let days = floor_divide(seconds, 86_400)
  let remainder = seconds - days * 86_400
  let #(year, month, day) = civil_from_days(days)
  day_name(days)
  <> ", "
  <> two_digits(day)
  <> " "
  <> month_name(month)
  <> " "
  <> int.to_string(year)
  <> " "
  <> two_digits(remainder / 3600)
  <> ":"
  <> two_digits(remainder % 3600 / 60)
  <> ":"
  <> two_digits(remainder % 60)
  <> " GMT"
}

fn floor_divide(value: Int, divisor: Int) -> Int {
  case value < 0 && value % divisor != 0 {
    True -> value / divisor - 1
    False -> value / divisor
  }
}

fn two_digits(value: Int) -> String {
  case value < 10 {
    True -> "0" <> int.to_string(value)
    False -> int.to_string(value)
  }
}

/// The first of January 1970 was a Thursday, which fixes the whole cycle.
fn day_name(days: Int) -> String {
  case { days + 4 } % 7 {
    0 -> "Sun"
    1 -> "Mon"
    2 -> "Tue"
    3 -> "Wed"
    4 -> "Thu"
    5 -> "Fri"
    _ -> "Sat"
  }
}

fn month_name(month: Int) -> String {
  case month {
    1 -> "Jan"
    2 -> "Feb"
    3 -> "Mar"
    4 -> "Apr"
    5 -> "May"
    6 -> "Jun"
    7 -> "Jul"
    8 -> "Aug"
    9 -> "Sep"
    10 -> "Oct"
    11 -> "Nov"
    _ -> "Dec"
  }
}

/// Days since the epoch to a civil date, by Howard Hinnant's algorithm: the
/// year is shifted to start in March so that the leap day falls last and the
/// month lengths repeat on a five-month cycle.
fn civil_from_days(days: Int) -> #(Int, Int, Int) {
  let shifted = days + 719_468
  let era = floor_divide(shifted, 146_097)
  let day_of_era = shifted - era * 146_097
  let year_of_era =
    {
      day_of_era
      - day_of_era
      / 1460
      + day_of_era
      / 36_524
      - day_of_era
      / 146_096
    }
    / 365
  let year = year_of_era + era * 400
  let day_of_year =
    day_of_era - { 365 * year_of_era + year_of_era / 4 - year_of_era / 100 }
  let shifted_month = { 5 * day_of_year + 2 } / 153
  let day = day_of_year - { 153 * shifted_month + 2 } / 5 + 1
  let month = case shifted_month < 10 {
    True -> shifted_month + 3
    False -> shifted_month - 9
  }
  case month <= 2 {
    True -> #(year + 1, month, day)
    False -> #(year, month, day)
  }
}
