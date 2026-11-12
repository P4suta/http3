// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const packetsPerFlow = 8

var errContract = errors.New("MASQUE contract failed")

type contractPhase uint8

func (contractPhase) Error() string { return "MASQUE contract failed" }

func safePhase(err error) uint8 {
	if phase, ok := err.(contractPhase); ok && phase <= 32 {
		return uint8(phase)
	}
	return 0
}

type options struct {
	role, endpoint, ca, certificate, key string
	target                               int
}

func main() {
	var o options
	flag.StringVar(&o.role, "role", "", "client or proxy")
	flag.StringVar(&o.endpoint, "endpoint", "", "loopback proxy port")
	flag.StringVar(&o.ca, "ca", "", "explicit fixture trust anchor")
	flag.StringVar(&o.certificate, "certificate", "", "proxy certificate")
	flag.StringVar(&o.key, "key", "", "proxy private key")
	flag.IntVar(&o.target, "target", 0, "loopback target port")
	flag.Parse()
	// Upstream diagnostics can contain datagrams, addresses, or raw errors.
	// Only our fixed terminal result and readiness port reach the supervisor.
	log.SetOutput(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- run(ctx, o) }()
	select {
	case err := <-finished:
		if successfulCompletion(ctx, err) {
			fmt.Println("MASQUE CONNECT-UDP contract verified")
			return
		}
		fmt.Fprintln(os.Stderr, "MASQUE contract failed")
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "MASQUE contract deadline")
	}
	os.Exit(1)
}

func successfulCompletion(ctx context.Context, err error) bool {
	// Both select cases may be ready.
	// A late nil result is still incomplete.
	return err == nil && ctx.Err() == nil
}

func run(ctx context.Context, o options) error {
	switch o.role {
	case "client":
		return runClient(ctx, o)
	case "proxy":
		return runProxy(ctx, o)
	default:
		return errContract
	}
}

func loopback(port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", errContract
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
}

func proxyTemplate(port int) (*uritemplate.Template, error) {
	if _, err := loopback(port); err != nil {
		return nil, err
	}
	return uritemplate.New("https://localhost:" + strconv.Itoa(port) + "/.well-known/masque/udp/{target_host}/{target_port}/")
}

func tlsClient(path string) (*tls.Config, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, errContract
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errContract
	}
	return &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 5 * time.Second,
		HandshakeIdleTimeout: 3 * time.Second, MaxIncomingStreams: 4,
		InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 65536,
		InitialConnectionReceiveWindow: 262144, MaxConnectionReceiveWindow: 262144}
}

func packet(flow, sequence int) []byte {
	return append([]byte{byte(flow), byte(sequence)}, bytes.Repeat([]byte{0x5a}, 62)...)
}

func runClient(ctx context.Context, o options) (outcome error) {
	phase := contractPhase(1)
	defer func() {
		if outcome != nil {
			outcome = phase
		}
	}()
	port, err := strconv.Atoi(o.endpoint)
	if err != nil {
		return errContract
	}
	address, err := loopback(port)
	if err != nil {
		return err
	}
	target, err := loopback(o.target)
	if err != nil {
		return err
	}
	template, err := proxyTemplate(port)
	if err != nil {
		return errContract
	}
	tlsConfig, err := tlsClient(o.ca)
	if err != nil {
		return err
	}
	phase = 2
	conn, err := quic.DialAddr(ctx, address, tlsConfig, quicConfig())
	if err != nil {
		return errContract
	}
	defer conn.CloseWithError(0, "")
	if conn.ConnectionState().TLS.NegotiatedProtocol != http3.NextProtoH3 {
		return errContract
	}
	phase = 3
	transport := &masque.Transport{}
	client, err := transport.NewClientConn(conn)
	if err != nil {
		return errContract
	}
	flows := make([]*masque.Conn, 0, 2)
	defer func() {
		for _, flow := range flows {
			if err := flow.Close(); err != nil && outcome == nil {
				outcome = errContract
			}
		}
	}()
	for i := 0; i < 2; i++ {
		phase = 4
		req, err := masque.NewRequest(ctx, template, target)
		if err != nil {
			return errContract
		}
		flow, rsp, err := client.Dial(req)
		if err != nil || rsp == nil {
			phase = 9
			if rsp != nil {
				switch rsp.StatusCode {
				case 400:
					phase = 10
				case 502:
					phase = 11
				}
			}
			return errContract
		}
		flows = append(flows, flow)
		if rsp.StatusCode != 200 || rsp.Header.Get("Capsule-Protocol") != "?1" {
			phase = 12
			return errContract
		}
	}
	// Both contexts remain live on one authenticated connection.
	// Interleaving distinct payloads exposes accidental datagram association across streams.
	for sequence := 0; sequence < packetsPerFlow; sequence++ {
		phase = 5
		for id, flow := range flows {
			phase = 6
			payload := packet(id, sequence)
			if n, err := flow.WriteTo(payload, nil); err != nil || n != len(payload) {
				return errContract
			}
		}
		for id, flow := range flows {
			if err := flow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return errContract
			}
			buffer := make([]byte, 65)
			n, _, err := flow.ReadFrom(buffer)
			if err != nil || !bytes.Equal(buffer[:n], packet(id, sequence)) {
				return errContract
			}
		}
	}
	phase = 7
	denied, err := masque.NewRequest(ctx, template, "127.0.0.2:"+strconv.Itoa(o.target))
	if err != nil {
		return errContract
	}
	flow, rsp, err := client.Dial(denied)
	if flow != nil || err == nil || rsp == nil || rsp.StatusCode != 502 {
		return errContract
	}
	if rsp.Body != nil {
		_ = rsp.Body.Close()
	}
	phase = 8
	return nil
}

func runProxy(ctx context.Context, o options) error {
	return serveProxy(ctx, o, func(port, target int) {
		fmt.Printf("PORT=%d\nTARGET=%d\n", port, target)
	})
}

func serveProxy(ctx context.Context, o options, ready func(int, int)) (outcome error) {
	certificate, err := tls.LoadX509KeyPair(o.certificate, o.key)
	if err != nil {
		return errContract
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errContract
	}
	defer echo.Close()
	echoDone := make(chan error, 1)
	go func() { echoDone <- echoPackets(ctx, echo) }()
	defer func() {
		_ = echo.Close()
		if err := <-echoDone; err != nil && outcome == nil {
			outcome = errContract
		}
	}()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errContract
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	template, err := proxyTemplate(port)
	if err != nil {
		return errContract
	}
	target := echo.LocalAddr().String()
	proxy := &masque.Proxy{}
	defer func() {
		if err := proxy.Close(); err != nil && outcome == nil {
			outcome = errContract
		}
	}()
	var accepted, rejected, connections atomic.Int32
	requests := make(chan bool, 3)
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate},
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		QUICConfig: quicConfig(), EnableDatagrams: true, MaxHeaderBytes: 8192,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			connections.Add(1)
			return ctx
		}}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parsed, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			w.WriteHeader(400)
			requests <- false
			return
		}
		if parsed.Target != target {
			rejected.Add(1)
			w.Header().Set("Proxy-Status", "fixture;error=destination_ip_prohibited")
			w.WriteHeader(502)
			requests <- true
			return
		}
		if accepted.Add(1) > 2 {
			w.WriteHeader(503)
			requests <- false
			return
		}
		// quic-go flushes headers when masque-go obtains HTTPStream.
		// Supply this application header before the documented Proxy call boundary.
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
		err = proxy.Proxy(w, parsed)
		requests <- err == nil
	})
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(udp) }()
	defer func() {
		closeErr := server.Close()
		serveErr := <-serving
		if outcome == nil && (closeErr != nil ||
			(serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed))) {
			outcome = errContract
		}
	}()
	ready(port, echo.LocalAddr().(*net.UDPAddr).Port)
	for i := 0; i < 3; i++ {
		select {
		case ok := <-requests:
			if !ok {
				return errContract
			}
		case <-ctx.Done():
			return errContract
		}
	}
	if accepted.Load() != 2 || rejected.Load() != 1 || connections.Load() != 1 {
		return errContract
	}
	return nil
}

func echoPackets(ctx context.Context, socket *net.UDPConn) error {
	buffer := make([]byte, 65)
	for count := 0; count < 2*packetsPerFlow; count++ {
		deadline, ok := ctx.Deadline()
		if !ok || socket.SetReadDeadline(deadline) != nil {
			return errContract
		}
		n, peer, err := socket.ReadFromUDP(buffer)
		if err != nil || n != 64 {
			return errContract
		}
		if _, err := socket.WriteToUDP(buffer[:n], peer); err != nil {
			return errContract
		}
	}
	return nil
}
