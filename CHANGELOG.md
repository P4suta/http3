# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.1.0 - 2026-08-23

### Added

- An Erlang-target Gleam package with `quic` 1.8.1 as the minimum backend.
- The `http3.is_supported()` backend capability probe.
- A private Gleam adapter and Erlang FFI boundary around `quic:is_available/0`.
- Architecture, roadmap, security, contribution, licence, and release
  documentation.
- Reproducible development tools, a complete local check task, and hardened CI
  definitions for OTP and operating-system compatibility.
