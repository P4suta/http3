#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main([]) ->
    assert_manifest("gleam.toml", <<"http">>),
    assert_manifest("packages/http3/gleam.toml", <<"http3">>),
    assert_manifest("packages/quic_core/gleam.toml", <<"quic_core">>),
    assert_path("src/http.gleam"),
    assert_path("packages/http3/src/http3.gleam"),
    assert_path("packages/quic_core/src/quic_core.gleam"),
    assert_path("README.md"),
    assert_path("packages/http3/README.md"),
    assert_path("packages/quic_core/README.md"),
    assert_path("LICENSE"),
    assert_path("packages/http3/LICENSE"),
    assert_path("packages/quic_core/LICENSE"),
    assert_path("docs/CONFORMANCE.md"),
    assert_path("docs/SECURITY_REVIEW.md"),
    assert_path("docs/V1.md"),
    assert_absent_path("packages/gleam_quic"),
    Http3 = read("packages/http3/gleam.toml"),
    assert_contains(
        "packages/http3/gleam.toml",
        Http3,
        <<"quic_core = { path = \"../quic_core\" }">>
    ),
    Root = read("gleam.toml"),
    assert_contains(
        "gleam.toml",
        Root,
        <<"http3 = { path = \"packages/http3\" }">>
    ),
    io:format("three-package layout ok~n");
main(_) ->
    erlang:error(package_layout_audit_usage).

assert_manifest(Path, Name) ->
    Contents = read(Path),
    Expected = <<"name = \"", Name/binary, "\"">>,
    assert_contains(Path, Contents, Expected).

assert_contains(Path, Contents, Expected) ->
    case binary:match(Contents, Expected) of
        nomatch -> erlang:error({missing_manifest_contract, Path, Expected});
        _ -> ok
    end.

assert_path(Path) ->
    case filelib:is_regular(Path) of
        true -> ok;
        false -> erlang:error({missing_package_path, Path})
    end.

assert_absent_path(Path) ->
    case filelib:is_dir(Path) orelse filelib:is_regular(Path) of
        false -> ok;
        true -> erlang:error({obsolete_package_path, Path})
    end.

read(Path) ->
    case file:read_file(Path) of
        {ok, Contents} -> Contents;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.
