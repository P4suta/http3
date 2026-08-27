# SPDX-FileCopyrightText: 2026 the http3 contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

defmodule Http3.MixProject do
  use Mix.Project

  def project do
    [
      app: :http3,
      version: "0.1.0",
      elixir: "~> 1.17",
      archives: [mix_gleam: "== 0.6.2"],
      compilers: [:gleam | Mix.compilers()],
      aliases: ["deps.get": ["deps.get", "gleam.deps.get"]],
      erlc_paths: [
        "build/dev/erlang/http3/_gleam_artefacts",
        "build/dev/erlang/http3/build",
        "src"
      ],
      erlc_include_path: "build/dev/erlang/http3/include",
      prune_code_paths: false,
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:crypto, :public_key]]
  end

  defp deps do
    [
      {:gleam_erlang, "== 1.3.0"},
      {:gleam_http, "== 4.3.0"},
      {:gleam_quic, path: "packages/gleam_quic"},
      {:gleam_stdlib, "== 1.0.5"}
    ]
  end
end
