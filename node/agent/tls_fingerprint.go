package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type tlsFingerprints struct {
	JA4        string
	JA3        string
	Family     string
	Version    string
	Confidence int
}

type parsedClientHello struct {
	legacyVersion     uint16
	supportedVersions []uint16
	hasSNI            bool
	ciphers           []uint16
	extensions        []uint16
	signatureAlgs     []uint16
	firstALPN         []byte
	groups            []uint16
	ecPoints          []uint8
}

func normalizeJA4(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func seedJA4BlacklistFromConfig() {
	if ja4Blacklist == nil {
		return
	}
	ja4Mu.Lock()
	for k := range ja4Blacklist {
		delete(ja4Blacklist, k)
	}
	for _, v := range config.Security.JA4Blacklist {
		key := normalizeJA4(v)
		if key == "" {
			continue
		}
		ja4Blacklist[key] = time.Now().Add(3650 * 24 * time.Hour)
	}
	ja4Mu.Unlock()
}

func ja4LabelFor(value string) string {
	norm := normalizeJA4(value)
	if norm == "" {
		return ""
	}
	labels := config.Security.JA4Labels
	if len(labels) == 0 {
		return ""
	}
	if v, ok := labels[norm]; ok {
		return v
	}
	for k, v := range labels {
		if normalizeJA4(k) == norm {
			return v
		}
	}
	return ""
}

func computeTLSFingerprintsFromClientHello(data []byte) tlsFingerprints {
	hello, err := parseClientHello(data)
	if err != nil {
		return tlsFingerprints{}
	}

	ja3 := buildJA3FromParsed(hello)
	ja4 := buildJA4FromParsed(hello)
	out := tlsFingerprints{
		JA4:        ja4,
		JA3:        ja3,
		Confidence: 100,
	}
	switch {
	case ja4 != "":
		out.Family = "ja4"
		out.Version = "ja4"
	case ja3 != "":
		out.Family = "ja3"
		out.Version = "ja3"
		out.Confidence = 70
	}
	return out
}

func parseClientHello(data []byte) (*parsedClientHello, error) {
	if len(data) < 5 || data[0] != 0x16 {
		return nil, fmt.Errorf("not a tls handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return nil, fmt.Errorf("truncated tls record")
	}
	hs := data[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, fmt.Errorf("not a clienthello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil, fmt.Errorf("truncated clienthello")
	}
	body := hs[4 : 4+hsLen]
	if len(body) < 34 {
		return nil, fmt.Errorf("clienthello too short")
	}

	out := &parsedClientHello{
		legacyVersion: binary.BigEndian.Uint16(body[0:2]),
	}

	offset := 2 + 32
	if offset >= len(body) {
		return nil, fmt.Errorf("missing session id")
	}
	sessLen := int(body[offset])
	offset++
	if offset+sessLen > len(body) {
		return nil, fmt.Errorf("bad session id")
	}
	offset += sessLen
	if offset+2 > len(body) {
		return nil, fmt.Errorf("missing cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+csLen > len(body) || csLen%2 != 0 {
		return nil, fmt.Errorf("bad cipher suite list")
	}
	for i := 0; i+1 < csLen; i += 2 {
		v := binary.BigEndian.Uint16(body[offset+i : offset+i+2])
		if isGreaseValue(v) {
			continue
		}
		out.ciphers = append(out.ciphers, v)
	}
	offset += csLen
	if offset >= len(body) {
		return out, nil
	}
	compLen := int(body[offset])
	offset++
	if offset+compLen > len(body) {
		return nil, fmt.Errorf("bad compression methods")
	}
	offset += compLen
	if offset+2 > len(body) {
		return out, nil
	}
	extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extLen > len(body) {
		return nil, fmt.Errorf("bad extension list")
	}
	exts := body[offset : offset+extLen]
	for len(exts) >= 4 {
		et := binary.BigEndian.Uint16(exts[0:2])
		elen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if elen > len(exts) {
			return nil, fmt.Errorf("bad extension payload")
		}
		edata := exts[:elen]
		exts = exts[elen:]
		if isGreaseValue(et) {
			continue
		}
		out.extensions = append(out.extensions, et)
		switch et {
		case 0: // SNI
			out.hasSNI = true
		case 10: // supported_groups
			if len(edata) < 2 {
				continue
			}
			l := int(binary.BigEndian.Uint16(edata[0:2]))
			if l+2 > len(edata) || l%2 != 0 {
				continue
			}
			for i := 0; i+1 < l; i += 2 {
				v := binary.BigEndian.Uint16(edata[2+i : 2+i+2])
				if isGreaseValue(v) {
					continue
				}
				out.groups = append(out.groups, v)
			}
		case 11: // ec_point_formats
			if len(edata) < 1 {
				continue
			}
			l := int(edata[0])
			if l+1 > len(edata) {
				continue
			}
			out.ecPoints = append(out.ecPoints, edata[1:1+l]...)
		case 13: // signature_algorithms
			if len(edata) < 2 {
				continue
			}
			l := int(binary.BigEndian.Uint16(edata[0:2]))
			if l+2 > len(edata) || l%2 != 0 {
				continue
			}
			for i := 0; i+1 < l; i += 2 {
				out.signatureAlgs = append(out.signatureAlgs, binary.BigEndian.Uint16(edata[2+i:2+i+2]))
			}
		case 16: // ALPN
			if len(edata) < 2 {
				continue
			}
			total := int(binary.BigEndian.Uint16(edata[0:2]))
			if total+2 > len(edata) || total == 0 {
				continue
			}
			values := edata[2 : 2+total]
			if len(values) == 0 {
				continue
			}
			firstLen := int(values[0])
			if firstLen == 0 || 1+firstLen > len(values) {
				continue
			}
			out.firstALPN = append([]byte(nil), values[1:1+firstLen]...)
		case 43: // supported_versions
			if len(edata) < 1 {
				continue
			}
			l := int(edata[0])
			if l+1 > len(edata) || l%2 != 0 {
				continue
			}
			for i := 0; i+1 < l; i += 2 {
				v := binary.BigEndian.Uint16(edata[1+i : 1+i+2])
				if isGreaseValue(v) {
					continue
				}
				out.supportedVersions = append(out.supportedVersions, v)
			}
		}
	}
	return out, nil
}

func buildJA3FromParsed(hello *parsedClientHello) string {
	if hello == nil {
		return ""
	}
	ciphers := make([]string, 0, len(hello.ciphers))
	for _, v := range hello.ciphers {
		ciphers = append(ciphers, strconvUint16(v))
	}
	exts := make([]string, 0, len(hello.extensions))
	for _, v := range hello.extensions {
		exts = append(exts, strconvUint16(v))
	}
	groups := make([]string, 0, len(hello.groups))
	for _, v := range hello.groups {
		groups = append(groups, strconvUint16(v))
	}
	points := make([]string, 0, len(hello.ecPoints))
	for _, v := range hello.ecPoints {
		points = append(points, strconvUint8(v))
	}
	return ja3HashFromString(buildJA3String(hello.legacyVersion, ciphers, exts, groups, points))
}

func buildJA4FromParsed(hello *parsedClientHello) string {
	if hello == nil {
		return ""
	}

	version := tlsVersionCode(hello)
	sni := "i"
	if hello.hasSNI {
		sni = "d"
	}
	alpn := ja4ALPNCode(hello.firstALPN)

	cipherList := make([]string, 0, len(hello.ciphers))
	for _, v := range hello.ciphers {
		cipherList = append(cipherList, fmt.Sprintf("%04x", v))
	}
	sort.Strings(cipherList)

	extList := make([]string, 0, len(hello.extensions))
	for _, v := range hello.extensions {
		if v == 0 || v == 16 {
			continue
		}
		extList = append(extList, fmt.Sprintf("%04x", v))
	}
	sort.Strings(extList)

	sigList := make([]string, 0, len(hello.signatureAlgs))
	for _, v := range hello.signatureAlgs {
		sigList = append(sigList, fmt.Sprintf("%04x", v))
	}

	ja4b := "000000000000"
	if len(cipherList) > 0 {
		ja4b = hash12(strings.Join(cipherList, ","))
	}

	ja4c := "000000000000"
	if len(extList) > 0 {
		base := strings.Join(extList, ",")
		if len(sigList) > 0 {
			base += "_" + strings.Join(sigList, ",")
		}
		ja4c = hash12(base)
	}

	return fmt.Sprintf("t%s%s%s%s%s_%s_%s",
		version,
		sni,
		twoDigitCount(len(cipherList)),
		twoDigitCount(len(hello.extensions)),
		alpn,
		ja4b,
		ja4c,
	)
}

func tlsVersionCode(hello *parsedClientHello) string {
	v := hello.legacyVersion
	for _, sv := range hello.supportedVersions {
		if sv > v {
			v = sv
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func twoDigitCount(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func ja4ALPNCode(v []byte) string {
	if len(v) == 0 {
		return "00"
	}
	first := v[0]
	last := v[len(v)-1]
	if isASCIIAlphaNum(first) && isASCIIAlphaNum(last) {
		if len(v) == 1 {
			return string([]byte{first, first})
		}
		return string([]byte{first, last})
	}
	hexValue := hex.EncodeToString(v)
	if len(hexValue) == 1 {
		return hexValue + hexValue
	}
	return string([]byte{hexValue[0], hexValue[len(hexValue)-1]})
}

func isASCIIAlphaNum(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	default:
		return false
	}
}

func hash12(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:12]
}
