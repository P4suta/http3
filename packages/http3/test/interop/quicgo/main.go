package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
)

const peerName = "quic-go-v0.61.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "quic-go interop: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: interop server CERT KEY | interop client CA PORT")
	}

	switch args[0] {
	case "server":
		if len(args) < 3 || len(args) > 4 {
			return errors.New("server mode requires certificate and private-key paths, then optional v1 or v2")
		}
		version, err := requestedVersion(args[3:])
		if err != nil {
			return err
		}
		return runServer(args[1], args[2], version)
	case "client":
		if len(args) < 3 || len(args) > 4 {
			return errors.New("client mode requires CA path and UDP port, then optional v1 or v2")
		}
		version, err := requestedVersion(args[3:])
		if err != nil {
			return err
		}
		return runClient(args[1], args[2], version)
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
}

func requestedVersion(args []string) (quic.Version, error) {
	if len(args) == 0 || args[0] == "v1" {
		return quic.Version1, nil
	}
	if args[0] == "v2" {
		return quic.Version2, nil
	}
	return 0, fmt.Errorf("unknown QUIC version %q", args[0])
}

func runServer(certPath, keyPath string, version quic.Version) error {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load server credential: %w", err)
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer packetConn.Close()

	requestResult := make(chan error, 1)
	var requestOnce sync.Once
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       10 * time.Second,
			Tracer:               qlog.DefaultConnectionTracer,
			Versions:             []quic.Version{version},
		},
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			body, readErr := io.ReadAll(io.LimitReader(request.Body, 1025))
			result := validateNativeRequest(request, body, readErr)
			if result != nil {
				http.Error(response, result.Error(), http.StatusBadRequest)
			} else {
				response.Header().Set("x-interop-peer", peerName)
				response.WriteHeader(http.StatusCreated)
				_, result = response.Write([]byte("quic-go-response"))
			}
			requestOnce.Do(func() { requestResult <- result })
		}),
	}

	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(packetConn) }()
	port := packetConn.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("PORT=%d\n", port)

	select {
	case err = <-requestResult:
		if err != nil {
			_ = server.Close()
			return err
		}
	case err = <-serveResult:
		return fmt.Errorf("serve before request completed: %w", err)
	case <-time.After(15 * time.Second):
		_ = server.Close()
		return errors.New("timed out waiting for native request")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err = <-serveResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	fmt.Println("quic-go server interop ok")
	return nil
}

func validateNativeRequest(request *http.Request, body []byte, readErr error) error {
	if readErr != nil {
		return fmt.Errorf("read request body: %w", readErr)
	}
	if request.Method != http.MethodPost {
		return fmt.Errorf("method = %q, want POST", request.Method)
	}
	if request.URL.Path != "/quicgo" {
		return fmt.Errorf("path = %q, want /quicgo", request.URL.Path)
	}
	if string(body) != "native-request" {
		return fmt.Errorf("body = %q, want native-request", body)
	}
	return nil
}

func runClient(caPath, portText string, version quic.Version) error {
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", portText)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("parse CA certificate")
	}

	udpTarget := net.JoinHostPort("127.0.0.1", portText)
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       10 * time.Second,
			Tracer:               qlog.DefaultConnectionTracer,
			Versions:             []quic.Version{version},
		},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpTarget, tlsConfig, config)
		},
	}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://localhost:%d/native", port)
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader("quic-go-request"))
	if err != nil {
		return fmt.Errorf("construct request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("status = %d, want 201", response.StatusCode)
	}
	if response.Header.Get("x-interop-peer") != "gleam-native" {
		return fmt.Errorf("x-interop-peer = %q, want gleam-native", response.Header.Get("x-interop-peer"))
	}
	if string(body) != "native-response" {
		return fmt.Errorf("body = %q, want native-response", body)
	}
	fmt.Println("quic-go client interop ok")
	return nil
}
