import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/peer_settings
import http/internal/http2/settings

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn defaults_match_the_http2_initial_values_test() -> Nil {
  let state = peer_settings.defaults()
  assert peer_settings.header_table_size(state) == 4096
  assert peer_settings.push_enabled(state)
  assert peer_settings.maximum_concurrent_streams(state) == None
  assert peer_settings.initial_window_size(state) == 65_535
  assert peer_settings.maximum_frame_size(state) == 16_384
  assert peer_settings.maximum_header_list_size(state) == None
  assert !peer_settings.extended_connect_enabled(state)
  assert !peer_settings.rfc7540_priorities_disabled(state)
}

pub fn ordered_updates_use_the_last_value_and_report_window_delta_test() -> Nil {
  let state = peer_settings.defaults()
  let assert Ok(peer_settings.Applied(state, delta)) =
    peer_settings.apply(
      state,
      [
        settings.InitialWindowSize(60_000),
        settings.InitialWindowSize(70_000),
        settings.MaxConcurrentStreams(10),
        settings.MaxHeaderListSize(8192),
        settings.HeaderTableSize(1024),
        settings.EnableConnectProtocol(True),
        settings.NoRfc7540Priorities(True),
        settings.Unknown(99, 7),
      ],
      peer_settings.Server,
    )

  assert delta == 4465
  assert peer_settings.initial_window_size(state) == 70_000
  assert peer_settings.maximum_concurrent_streams(state) == Some(10)
  assert peer_settings.maximum_header_list_size(state) == Some(8192)
  assert peer_settings.header_table_size(state) == 1024
  assert peer_settings.extended_connect_enabled(state)
  assert peer_settings.rfc7540_priorities_disabled(state)
}

pub fn clients_reject_enable_push_sent_by_a_server_test() -> Nil {
  let state = peer_settings.defaults()
  assert peer_settings.apply(
      state,
      [settings.EnablePush(False)],
      peer_settings.Client,
    )
    == Error(peer_settings.EnablePushForbidden)

  let assert Ok(peer_settings.Applied(state, 0)) =
    peer_settings.apply(
      state,
      [settings.EnablePush(False)],
      peer_settings.Server,
    )
  assert !peer_settings.push_enabled(state)
}

pub fn rfc8441_enable_connect_protocol_cannot_be_disabled_test() -> Nil {
  let defaults = peer_settings.defaults()
  let assert Ok(peer_settings.Applied(enabled, 0)) =
    peer_settings.apply(
      defaults,
      [settings.EnableConnectProtocol(True)],
      peer_settings.Client,
    )
  assert peer_settings.apply(
      enabled,
      [settings.EnableConnectProtocol(False)],
      peer_settings.Client,
    )
    == Error(peer_settings.InvalidSetting(settings.InvalidValue(8)))
  assert peer_settings.apply(
      defaults,
      [
        settings.EnableConnectProtocol(True),
        settings.EnableConnectProtocol(False),
      ],
      peer_settings.Client,
    )
    == Error(peer_settings.InvalidSetting(settings.InvalidValue(8)))
}
