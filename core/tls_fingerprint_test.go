package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestComputeTLSFingerprintsFromClientHello(t *testing.T) {
	record := buildTestClientHello(t)
	got := computeTLSFingerprintsFromClientHello(record)
	if got.JA4 == "" {
		t.Fatal("expected JA4 fingerprint")
	}
	if got.JA3 == "" {
		t.Fatal("expected JA3 fingerprint")
	}
	if got.Family != "ja4" || got.Version != "ja4" {
		t.Fatalf("expected JA4-first metadata, got family=%q version=%q", got.Family, got.Version)
	}
	if !strings.HasPrefix(got.JA4, "t13d0406h2_") {
		t.Fatalf("unexpected JA4 prefix: %s", got.JA4)
	}

	expectedCipherHash := hash12("002f,0035,1301,1302")
	expectedExtHash := hash12("000a,000b,000d,002b_0403,0804")
	expected := fmt.Sprintf("t13d0406h2_%s_%s", expectedCipherHash, expectedExtHash)
	if got.JA4 != expected {
		t.Fatalf("unexpected JA4 fingerprint: got %s want %s", got.JA4, expected)
	}
}

func TestComputeTLSFingerprintsMalformedClientHello(t *testing.T) {
	got := computeTLSFingerprintsFromClientHello([]byte{0x16, 0x03, 0x01, 0x00})
	if got.JA4 != "" || got.JA3 != "" {
		t.Fatalf("expected empty fingerprints for malformed record, got %+v", got)
	}
}

func buildTestClientHello(t *testing.T) []byte {
	t.Helper()

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0)

	ciphers := []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
	}
	_ = binary.Write(&body, binary.BigEndian, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		_ = binary.Write(&body, binary.BigEndian, c)
	}

	body.WriteByte(1)
	body.WriteByte(0)

	exts := bytes.Buffer{}
	writeExtension(&exts, 0x0000, buildSNIExtension("example.com"))
	writeExtension(&exts, 0x0010, buildALPNExtension("h2"))
	writeExtension(&exts, 0x002b, []byte{4, 0x03, 0x04, 0x03, 0x03})
	writeExtension(&exts, 0x000d, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04})
	writeExtension(&exts, 0x000a, []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})
	writeExtension(&exts, 0x000b, []byte{0x01, 0x00})
	_ = binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())

	helloBody := body.Bytes()
	var handshake bytes.Buffer
	handshake.WriteByte(0x01)
	handshake.Write([]byte{byte(len(helloBody) >> 16), byte(len(helloBody) >> 8), byte(len(helloBody))})
	handshake.Write(helloBody)

	record := handshake.Bytes()
	var tlsRecord bytes.Buffer
	tlsRecord.Write([]byte{0x16, 0x03, 0x03, byte(len(record) >> 8), byte(len(record))})
	tlsRecord.Write(record)
	return tlsRecord.Bytes()
}

func writeExtension(buf *bytes.Buffer, typ uint16, payload []byte) {
	_ = binary.Write(buf, binary.BigEndian, typ)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)
}

func buildSNIExtension(host string) []byte {
	name := []byte(host)
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.BigEndian, uint16(3+len(name)))
	payload.WriteByte(0)
	_ = binary.Write(&payload, binary.BigEndian, uint16(len(name)))
	payload.Write(name)
	return payload.Bytes()
}

func buildALPNExtension(value string) []byte {
	name := []byte(value)
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.BigEndian, uint16(1+len(name)))
	payload.WriteByte(byte(len(name)))
	payload.Write(name)
	return payload.Bytes()
}
