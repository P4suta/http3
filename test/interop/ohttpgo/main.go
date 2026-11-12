// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Independent RFC 9458 oracle.
// Failures expose a fixed phase only.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	ohttp "github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
)

const maximumBytes = 131072

// Only this private type carries fixed source-authored phase names.
// Native library panics and errors never enter diagnostic output.
type contractFailure string

func require(ok bool, phase string) {
	if !ok {
		panic(contractFailure(phase))
	}
}

func readBounded(reader io.Reader) []byte {
	data, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	require(err == nil && len(data) <= maximumBytes, "bounded_read")
	return data
}

func body() []byte { return bytes.Repeat([]byte("ohttp-flow-"), 6000) }

func requestPlaintext(padding int) []byte {
	request, err := http.NewRequest("POST", "https://target.example/submit", bytes.NewReader(body()))
	require(err == nil, "inner_request")
	request.Header.Set("X-Request", "yes")
	request.Trailer = http.Header{"X-Request-Finished": {"yes"}}
	binaryRequest := ohttp.BinaryRequest(*request)
	plaintext, err := binaryRequest.Marshal()
	require(err == nil, "bhttp_request_encode")
	return append(plaintext, make([]byte, padding)...)
}

func client(ca string, advertiseALPN bool) *http.Client {
	pem, err := os.ReadFile(ca)
	require(err == nil, "ca_read")
	roots := x509.NewCertPool()
	require(roots.AppendCertsFromPEM(pem), "ca_parse")
	tlsConfiguration := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if advertiseALPN {
		tlsConfiguration.NextProtos = []string{"http/1.1"}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig:    tlsConfiguration,
		DisableCompression: true, MaxConnsPerHost: 1,
		ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 8192,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func exchange(c *http.Client, method, uri, media string, data []byte, marker bool) (int, string, []byte) {
	request, err := http.NewRequest(method, uri, bytes.NewReader(data))
	require(err == nil, "request_create")
	if media != "" {
		request.Header.Set("Content-Type", media)
	}
	if marker {
		request.Header.Set("X-Client-Marker", "must-not-reach-gateway")
		request.Header.Set("Cookie", "private-fixture-marker")
	}
	response, err := c.Do(request)
	if err != nil {
		var certificateFailure *tls.CertificateVerificationError
		var outer *url.Error
		var network net.Error
		switch {
		case errors.As(err, &certificateFailure):
			panic(contractFailure("outer_certificate"))
		case errors.As(err, &network) && network.Timeout():
			panic(contractFailure("outer_timeout"))
		case errors.As(err, &outer) && errors.Is(outer.Err, io.EOF):
			panic(contractFailure("outer_eof"))
		}
	}
	require(err == nil, "outer_exchange")
	defer response.Body.Close()
	return response.StatusCode, response.Header.Get("Content-Type"), readBounded(response.Body)
}

func runClient(endpoint, ca string, algorithm int, advertiseALPN bool) {
	c := client(ca, advertiseALPN)
	defer c.CloseIdleConnections()
	status, media, configuration := exchange(c, "GET", endpoint+"/config/"+strconv.Itoa(algorithm), "", nil, false)
	require(status == 200 && media == "application/ohttp-keys", "configuration_response")
	require(len(configuration) > 2 && int(binary.BigEndian.Uint16(configuration[:2])) == len(configuration)-2, "configuration_collection")
	config, err := ohttp.UnmarshalPublicConfig(configuration[2:])
	require(err == nil && config.KEMID == hpke.KEM_X25519_HKDF_SHA256 && len(config.Suites) == 1 &&
		int(config.Suites[0].AEADID) == algorithm && config.Suites[0].KDFID == hpke.KDF_HKDF_SHA256, "configuration_decode")
	sealed, responseContext, err := ohttp.NewDefaultClient(config).EncapsulateRequest(requestPlaintext(0))
	require(err == nil, "request_seal")
	wire := sealed.Marshal()
	uri := endpoint + "/relay/" + strconv.Itoa(algorithm)
	status, media, ciphertext := exchange(c, "POST", uri, "message/ohttp-req", wire, true)
	require(status == 200 && media == "message/ohttp-res", "encapsulated_response")
	response, err := ohttp.UnmarshalEncapsulatedResponse(ciphertext)
	require(err == nil, "response_decode")
	opened, err := responseContext.DecapsulateResponse(response)
	require(err == nil, "response_open")
	inner, err := ohttp.UnmarshalBinaryResponse(opened)
	require(err == nil && inner.StatusCode == 201 && len(inner.Header["x-response"]) == 1 && inner.Header["x-response"][0] == "yes" &&
		len(inner.Trailer["x-response-finished"]) == 1 && inner.Trailer["x-response-finished"][0] == "yes" && bytes.Equal(readBounded(inner.Body), body()), "inner_response_oracle")
	inner.Body.Close()
	wire[len(wire)-1] ^= 1
	status, _, _ = exchange(c, "POST", uri, "message/ohttp-req", wire, true)
	require(status == 400, "tamper_rejected")
	status, _, _ = exchange(c, "POST", uri, "application/octet-stream", wire, true)
	require(status == 415, "media_rejected")
}

func gateway(algorithm int) (ohttp.Gateway, []byte) {
	configuration, err := ohttp.NewConfig(1, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD(algorithm))
	require(err == nil, "gateway_configuration")
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{configuration})
	return gateway, gateway.MarshalConfigs()
}

func openAndRespond(gateway ohttp.Gateway, wire []byte) (int, []byte) {
	request, err := ohttp.UnmarshalEncapsulatedRequest(wire)
	if err != nil {
		return 400, nil
	}
	opened, responseContext, err := gateway.DecapsulateRequest(request)
	if err != nil {
		return 400, nil
	}
	// The pinned reference request decoder writes trailers into a nil map.
	// Its independent encoder still provides an exact wire oracle, including request headers, the large content, trailers and RFC 9292 zero padding.
	require(bytes.Equal(opened, requestPlaintext(128)), "inner_request_oracle")
	response := ohttp.BinaryResponse(http.Response{StatusCode: 201,
		Header: http.Header{"X-Response": {"yes"}}, Body: io.NopCloser(bytes.NewReader(body())),
		Trailer: http.Header{"X-Response-Finished": {"yes"}}})
	plaintext, err := response.Marshal()
	require(err == nil, "bhttp_response_encode")
	sealed, err := responseContext.EncapsulateResponse(plaintext)
	require(err == nil, "response_seal")
	return 200, sealed.Marshal()
}

func serve(role, endpoint, ca, certificate, key string, algorithm int) {
	gateway, configuration := gateway(algorithm)
	c := client(ca, true)
	defer c.CloseIdleConnections()
	complete := make(chan struct{}, 1)
	var mutex sync.Mutex
	count := 0
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192,
		ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Exactly one bounded scenario is accepted; redirects and arbitrary targets are absent.
			mutex.Lock()
			defer mutex.Unlock()
			if r.Method == "GET" && r.URL.Path == "/config" && role == "gateway" {
				w.Header().Set("Content-Type", "application/ohttp-keys")
				_, err := w.Write(configuration)
				require(err == nil, "config_write")
				return
			}
			require(r.Method == "POST" && r.URL.Path == "/gateway" && count < 3, "outer_request_oracle")
			wire := readBounded(r.Body)
			r.Body.Close()
			status, payload := 415, []byte(nil)
			if r.Header.Get("Content-Type") == "message/ohttp-req" {
				if role == "gateway" {
					status, payload = openAndRespond(gateway, wire)
				} else {
					var media string
					// Deliberately rebuild the outer request from only its opaque body and media type.
					status, media, payload = exchange(c, "POST", endpoint+"/gateway/"+strconv.Itoa(algorithm), "message/ohttp-req", wire, false)
					require(status != 200 || media == "message/ohttp-res", "relay_response_media")
				}
			}
			expected := []int{200, 400, 415}
			require(status == expected[count], "outer_status_oracle")
			if status == 200 {
				w.Header().Set("Content-Type", "message/ohttp-res")
			}
			w.WriteHeader(status)
			_, err := w.Write(payload)
			require(err == nil, "response_write")
			count++
			if count == 3 {
				complete <- struct{}{}
			}
		})}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require(err == nil, "listener_bind")
	fmt.Printf("PORT=%d\n", listener.Addr().(*net.TCPAddr).Port)
	finished := make(chan error, 1)
	go func() { finished <- server.ServeTLS(listener, certificate, key) }()
	select {
	case <-complete:
	case <-finished:
		panic("server_early_exit")
	case <-time.After(45 * time.Second):
		panic("server_deadline")
	}
	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require(server.Shutdown(deadline) == nil, "server_shutdown")
	require(<-finished == http.ErrServerClosed, "server_join")
}

func main() {
	defer func() {
		if failure := recover(); failure != nil {
			if phase, ok := failure.(contractFailure); ok {
				fmt.Fprintln(os.Stderr, "ohttp peer phase:", phase)
			} else {
				fmt.Fprintln(os.Stderr, "ohttp peer contract failed")
			}
			os.Exit(1)
		}
	}()
	role := flag.String("role", "", "client, relay, gateway")
	algorithm := flag.Int("aead", 0, "1 or 3")
	alpn := flag.Bool("alpn", true, "advertise HTTP/1.1 on outer TLS")
	endpoint := flag.String("endpoint", "", "fixed native TLS endpoint")
	ca := flag.String("ca", "", "test CA")
	certificate := flag.String("certificate", "", "test certificate")
	key := flag.String("key", "", "test key")
	flag.Parse()
	require(flag.NArg() == 0 && (*algorithm == 1 || *algorithm == 3), "arguments")
	switch *role {
	case "client":
		runClient(*endpoint, *ca, *algorithm, *alpn)
	case "relay", "gateway":
		serve(*role, *endpoint, *ca, *certificate, *key, *algorithm)
	default:
		panic("role")
	}
	fmt.Println("ohttp independent contract verified")
}
