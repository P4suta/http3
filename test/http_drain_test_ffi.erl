%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_drain_test_ffi).
-export([shorten_native_timeout/2]).

%% Shorten only drain. Shortening native idle/operation as well races the
%% forced-drain result against an ordinary stream or connection timeout,
%% particularly when cover instrumentation changes scheduling.
shorten_native_timeout(Configuration, Milliseconds) ->
    'http@server':with_http3_drain_timeout(
        Configuration, Milliseconds
    ).
