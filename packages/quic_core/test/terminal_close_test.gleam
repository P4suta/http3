import gleam/erlang/process
import gleam/int
import gleam/list
import gleeunit/should
import quic_core/internal/runtime/terminal_close

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn terminal_close_word_validates_codes_and_preserves_first_kind_test() -> Nil {
  [
    terminal_close.Application,
    terminal_close.Transport,
    terminal_close.LocalTransport,
  ]
  |> list.each(fn(kind) {
    [0, 0x106, 4_611_686_018_427_387_903]
    |> list.each(fn(code) {
      let close = terminal_close.new()
      assert terminal_close.snapshot(close) == terminal_close.Pending
      assert !terminal_close.publish(close:, kind:, code: -1)
      assert !terminal_close.publish(
        close:,
        kind:,
        code: 4_611_686_018_427_387_904,
      )
      assert terminal_close.snapshot(close) == terminal_close.Pending
      assert terminal_close.publish(close:, kind:, code:)
      assert !terminal_close.publish(
        close:,
        kind: terminal_close.Application,
        code: 7,
      )
      assert !terminal_close.publish(
        close:,
        kind: terminal_close.Transport,
        code: 8,
      )
      assert terminal_close.snapshot(close) == terminal_close.Closed(kind, code)
    })
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn competing_close_publishers_have_exactly_one_terminal_winner_test() -> Nil {
  let close = terminal_close.new()
  let replies = process.new_subject()
  let codes = int.range(1, 32, with: [], run: fn(acc, code) { [code, ..acc] })
  codes
  |> list.each(fn(code) {
    let _publisher =
      process.spawn_unlinked(fn() {
        let won =
          terminal_close.publish(close:, kind: terminal_close.Transport, code:)
        process.send(replies, #(code, won))
      })
  })
  let results =
    codes
    |> list.map(fn(_) { process.receive(replies, within: 1000) |> should.be_ok })
  let winners =
    list.filter_map(results, fn(result) {
      case result {
        #(code, True) -> Ok(code)
        _ -> Error(Nil)
      }
    })
  assert list.length(winners) == 1
  let winner = list.fold(winners, 0, int.max)
  assert terminal_close.snapshot(close)
    == terminal_close.Closed(terminal_close.Transport, winner)
}
