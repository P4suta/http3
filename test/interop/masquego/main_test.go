// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func fixtureOptions() options {
	root := filepath.Join("..", "..", "..", "packages", "http3", "test", "fixtures")
	return options{ca: filepath.Join(root, "ca.pem"), certificate: filepath.Join(root, "server.pem"),
		key: filepath.Join(root, "server-key.pem")}
}

func TestAuthenticationAndFixedInput(t *testing.T) {
	config, err := tlsClient(fixtureOptions().ca)
	if err != nil || config.InsecureSkipVerify || config.ServerName != "localhost" ||
		config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		len(config.NextProtos) != 1 || config.NextProtos[0] != "h3" || config.RootCAs == nil {
		t.Fatal("authentication contract")
	}
	for _, port := range []int{-1, 0, 65536} {
		if _, err := loopback(port); err == nil {
			t.Fatal("invalid port accepted")
		}
		if _, err := proxyTemplate(port); err == nil {
			t.Fatal("invalid template accepted")
		}
	}
	if len(packet(0, 0)) != 64 || bytes.Equal(packet(0, 0), packet(1, 0)) ||
		bytes.Equal(packet(0, 0), packet(0, 1)) {
		t.Fatal("datagram association oracle")
	}
}

func TestTerminalSuccessRequiresLiveDeadline(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, release := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer release()
	for name, state := range map[string]struct {
		ctx  context.Context
		live bool
	}{"active": {context.Background(), true}, "cancelled": {cancelled, false},
		"expired": {expired, false}} {
		t.Run(name, func(t *testing.T) {
			if successfulCompletion(state.ctx, nil) != state.live ||
				successfulCompletion(state.ctx, errContract) {
				t.Fatal("terminal success escaped cancellation, deadline, or failure")
			}
		})
	}
}

func TestTwoLiveFlowsAndDeniedTarget(t *testing.T) {
	log.SetOutput(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := make(chan [2]int, 1)
	server := make(chan error, 1)
	o := fixtureOptions()
	go func() { server <- serveProxy(ctx, o, func(port, target int) { ready <- [2]int{port, target} }) }()
	select {
	case ports := <-ready:
		o.endpoint, o.target = strconv.Itoa(ports[0]), ports[1]
	case <-ctx.Done():
		t.Fatal("proxy readiness deadline")
	}
	clientResult := runClient(ctx, o)
	if clientResult != nil {
		t.Errorf("client phase=%d", safePhase(clientResult))
		cancel()
	}
	passed, joined := awaitFixture(ctx, server, func() {})
	if clientResult != nil || !passed || !joined {
		t.Fatal("client/proxy contract or disposal deadline")
	}
}

func awaitFixture(ctx context.Context, done <-chan error, cancelling func()) (bool, bool) {
	select {
	case result := <-done:
		return ctx.Err() == nil && result == nil, true
	case <-ctx.Done():
		cancelling()
		select {
		case <-done:
			return false, true
		case <-time.After(2 * time.Second):
			return false, false
		}
	}
}

func TestLateServerResultCannotPassAfterDeadline(t *testing.T) {
	for name, terminal := range map[string]error{"late-success": nil, "late-failure": errContract} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done, entered, exited := make(chan error), make(chan struct{}), make(chan struct{})
			go func() { defer close(exited); <-entered; done <- terminal }()
			passed, joined := awaitFixture(ctx, done, func() { close(entered) })
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				t.Fatal("controlled server did not exit")
			}
			if passed || !joined {
				t.Fatal("late success/failure disposal must join and fail")
			}
		})
	}
}

func TestMalformedDatagramCannotCountAsCompletedEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("echo setup")
	}
	defer socket.Close()
	done := make(chan error, 1)
	go func() { done <- echoPackets(ctx, socket) }()
	client, err := net.DialUDP("udp4", nil, socket.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal("echo sender setup")
	}
	defer client.Close()
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal("echo send")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid echo accepted")
		}
	case <-ctx.Done():
		t.Fatal("echo deadline")
	}
}
