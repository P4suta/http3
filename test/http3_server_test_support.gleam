import gleam/result
import gleam/string
import http3/client

pub fn default_response_head(
  outcome outcome: Result(client.ResponseEvent, client.Error),
  status expected_status: Int,
) -> Bool {
  result.map(outcome, fn(event) {
    case event {
      client.Response(status, [#("date", value)]) ->
        status == expected_status
        && string.byte_size(value) == 29
        && string.ends_with(value, " GMT")
      _ -> False
    }
  })
  |> result.unwrap(False)
}
