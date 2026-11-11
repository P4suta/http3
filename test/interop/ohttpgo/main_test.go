// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
package main

import (
	"bytes"
	"testing"

	ohttp "github.com/chris-wood/ohttp-go"
)

func mustPanic(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected bounded oracle rejection")
		}
	}()
	run()
}

func TestIndependentEncodersAndBothAeads(t *testing.T) {
	for _, algorithm := range []int{1, 3} {
		g, configurations := gateway(algorithm)
		configuration, err := ohttp.UnmarshalPublicConfig(configurations[2:])
		if err != nil {
			t.Fatal("configuration failed")
		}
		request, context, err := ohttp.NewDefaultClient(configuration).EncapsulateRequest(requestPlaintext(128))
		if err != nil {
			t.Fatal("seal failed")
		}
		status, response := openAndRespond(g, request.Marshal())
		if status != 200 {
			t.Fatal("valid request rejected")
		}
		sealedResponse, err := ohttp.UnmarshalEncapsulatedResponse(response)
		if err != nil {
			t.Fatal("response parse failed")
		}
		opened, err := context.DecapsulateResponse(sealedResponse)
		if err != nil {
			t.Fatal("response authentication failed")
		}
		message, err := ohttp.UnmarshalBinaryResponse(opened)
		if err != nil || message.StatusCode != 201 || !bytes.Equal(readBounded(message.Body), body()) {
			t.Fatal("body or status mismatch")
		}
		wire := request.Marshal()
		wire[len(wire)-1] ^= 1
		if rejected, _ := openAndRespond(g, wire); rejected != 400 {
			t.Fatal("tamper accepted")
		}
	}
}

func TestOracleRejectsOneByteMutationAfterValidAuthentication(t *testing.T) {
	g, configurations := gateway(1)
	configuration, _ := ohttp.UnmarshalPublicConfig(configurations[2:])
	plaintext := requestPlaintext(128)
	plaintext[len(plaintext)-1] = 1
	request, _, err := ohttp.NewDefaultClient(configuration).EncapsulateRequest(plaintext)
	if err != nil {
		t.Fatal("seal failed")
	}
	mustPanic(t, func() { openAndRespond(g, request.Marshal()) })
}

func TestReadCeilingRejectsExactlyOneByteAboveLimit(t *testing.T) {
	if len(readBounded(bytes.NewReader(make([]byte, maximumBytes)))) != maximumBytes {
		t.Fatal("boundary rejected")
	}
	mustPanic(t, func() { readBounded(bytes.NewReader(make([]byte, maximumBytes+1))) })
}
