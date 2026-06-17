//go:build reality_oracle_clienthello_shape

// This oracle is intentionally invoked with:
//   go run -tags reality_oracle_clienthello_shape ./tools/reality-oracle/clienthello_shape.go
//
// It emits a normalized, deterministic uTLS ClientHello shape. The output is
// used by Rust tests as an oracle for shaped-rustls fingerprint compatibility.

package main

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"

	utls "github.com/refraction-networking/utls"
)

const (
	serverName = "example.com"

	clientHelloHandshakeType = byte(0x01)

	extensionServerName             = uint16(0x0000)
	extensionStatusRequest          = uint16(0x0005)
	extensionSupportedGroups        = uint16(0x000a)
	extensionECPointFormats         = uint16(0x000b)
	extensionSignatureAlgorithms    = uint16(0x000d)
	extensionALPN                   = uint16(0x0010)
	extensionSCT                    = uint16(0x0012)
	extensionPadding                = uint16(0x0015)
	extensionExtendedMasterSecret   = uint16(0x0017)
	extensionCompressCertificate    = uint16(0x001b)
	extensionSessionTicket          = uint16(0x0023)
	extensionSupportedVersions      = uint16(0x002b)
	extensionPSKKeyExchangeModes    = uint16(0x002d)
	extensionKeyShare               = uint16(0x0033)
	extensionApplicationSettings    = uint16(0x4469)
	extensionApplicationSettingsNew = uint16(0x44cd)
	extensionEncryptedClientHello   = uint16(0xfe0d)
	extensionRenegotiationInfo      = uint16(0xff01)
)

type deterministicReader struct{}

func (r *deterministicReader) Read(out []byte) (int, error) {
	for i := range out {
		out[i] = byte(i)
	}
	return len(out), nil
}

type zeroReader struct{}

func (zeroReader) Read(out []byte) (int, error) {
	clear(out)
	return len(out), nil
}

type clientHelloShape struct {
	Fingerprint                      string            `json:"fingerprint"`
	UTLSID                           string            `json:"utls_id"`
	ServerName                       string            `json:"server_name"`
	HandshakeLength                  int               `json:"handshake_length"`
	LegacyVersion                    string            `json:"legacy_version"`
	CipherSuites                     []string          `json:"cipher_suites"`
	CompressionMethods               []string          `json:"compression_methods"`
	ExtensionOrder                   []string          `json:"extension_order"`
	Extensions                       []extensionShape  `json:"extensions"`
	SupportedVersions                []string          `json:"supported_versions,omitempty"`
	SupportedGroups                  []string          `json:"supported_groups,omitempty"`
	ECPointFormats                   []string          `json:"ec_point_formats,omitempty"`
	SignatureAlgorithms              []string          `json:"signature_algorithms,omitempty"`
	ALPNProtocols                    []string          `json:"alpn_protocols,omitempty"`
	KeyShares                        []keyShareShape   `json:"key_shares,omitempty"`
	PSKKeyExchangeModes              []string          `json:"psk_key_exchange_modes,omitempty"`
	CertificateCompressionAlgorithms []string          `json:"certificate_compression_algorithms,omitempty"`
	ApplicationSettings              []applicationALPS `json:"application_settings,omitempty"`
	PaddingLength                    *int              `json:"padding_length,omitempty"`
	EncryptedClientHelloLength       *int              `json:"encrypted_client_hello_length,omitempty"`
}

type extensionShape struct {
	Type   string `json:"type"`
	Length int    `json:"length"`
}

type keyShareShape struct {
	Group             string `json:"group"`
	KeyExchangeLength int    `json:"key_exchange_length"`
}

type applicationALPS struct {
	Type      string   `json:"type"`
	Protocols []string `json:"protocols"`
}

func main() {
	fingerprint := flag.String("fingerprint", "hellochrome_100", "uTLS fingerprint to shape")
	checkPath := flag.String("check", "", "compare generated shape with a committed JSON file")
	flag.Parse()

	shape, err := buildShape(*fingerprint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build shape: %v\n", err)
		os.Exit(1)
	}

	generated, err := json.MarshalIndent(shape, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal shape: %v\n", err)
		os.Exit(1)
	}
	generated = append(generated, '\n')

	if *checkPath == "" {
		_, _ = os.Stdout.Write(generated)
		return
	}

	expected, err := os.ReadFile(*checkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(expected, generated) {
		fmt.Fprintf(os.Stderr, "fixture mismatch: %s\n", *checkPath)
		os.Exit(1)
	}
}

func buildShape(fingerprint string) (clientHelloShape, error) {
	id, err := clientHelloID(fingerprint)
	if err != nil {
		return clientHelloShape{}, err
	}

	previousRand := cryptoRand.Reader
	cryptoRand.Reader = zeroReader{}
	defer func() { cryptoRand.Reader = previousRand }()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := &utls.Config{
		ServerName:   serverName,
		Rand:         &deterministicReader{},
		OmitEmptyPsk: true,
	}
	uConn := utls.UClient(clientConn, config, id)
	if err := uConn.BuildHandshakeState(); err != nil {
		return clientHelloShape{}, err
	}

	hello := uConn.HandshakeState.Hello
	if hello == nil {
		return clientHelloShape{}, errors.New("uTLS did not build a ClientHello")
	}
	return parseClientHelloShape(fingerprint, id.Str(), hello.Raw)
}

func clientHelloID(fingerprint string) (utls.ClientHelloID, error) {
	switch fingerprint {
	case "chrome", "hellochrome_auto":
		return utls.HelloChrome_Auto, nil
	case "firefox", "hellofirefox_auto":
		return utls.HelloFirefox_Auto, nil
	case "safari", "hellosafari_auto":
		return utls.HelloSafari_Auto, nil
	case "ios", "helloios_auto":
		return utls.HelloIOS_Auto, nil
	case "android", "helloandroid_11_okhttp":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge", "helloedge_auto":
		return utls.HelloEdge_Auto, nil
	case "360", "hello360_auto":
		return utls.Hello360_Auto, nil
	case "qq", "helloqq_auto":
		return utls.HelloQQ_Auto, nil
	case "random", "randomized", "hellorandomized":
		return utls.HelloRandomized, nil
	case "randomizednoalpn", "hellorandomizednoalpn":
		return utls.HelloRandomizedNoALPN, nil
	case "hellorandomizedalpn":
		return utls.HelloRandomizedALPN, nil
	case "hellofirefox_55":
		return utls.HelloFirefox_55, nil
	case "hellofirefox_56":
		return utls.HelloFirefox_56, nil
	case "hellofirefox_63":
		return utls.HelloFirefox_63, nil
	case "hellofirefox_65":
		return utls.HelloFirefox_65, nil
	case "hellofirefox_99":
		return utls.HelloFirefox_99, nil
	case "hellofirefox_102":
		return utls.HelloFirefox_102, nil
	case "hellofirefox_105":
		return utls.HelloFirefox_105, nil
	case "hellofirefox_120":
		return utls.HelloFirefox_120, nil
	case "hellofirefox_148":
		return utls.HelloFirefox_148, nil
	case "hellochrome_58":
		return utls.HelloChrome_58, nil
	case "hellochrome_62":
		return utls.HelloChrome_62, nil
	case "hellochrome_70":
		return utls.HelloChrome_70, nil
	case "hellochrome_72":
		return utls.HelloChrome_72, nil
	case "hellochrome_83":
		return utls.HelloChrome_83, nil
	case "hellochrome_87":
		return utls.HelloChrome_87, nil
	case "hellochrome_96":
		return utls.HelloChrome_96, nil
	case "hellochrome_100":
		return utls.HelloChrome_100, nil
	case "hellochrome_102":
		return utls.HelloChrome_102, nil
	case "hellochrome_106_shuffle":
		return utls.HelloChrome_106_Shuffle, nil
	case "hellochrome_100_psk":
		return utls.HelloChrome_100_PSK, nil
	case "hellochrome_112_psk_shuf":
		return utls.HelloChrome_112_PSK_Shuf, nil
	case "hellochrome_114_padding_psk_shuf":
		return utls.HelloChrome_114_Padding_PSK_Shuf, nil
	case "hellochrome_115_pq":
		return utls.HelloChrome_115_PQ, nil
	case "hellochrome_115_pq_psk":
		return utls.HelloChrome_115_PQ_PSK, nil
	case "hellochrome_120":
		return utls.HelloChrome_120, nil
	case "hellochrome_120_pq":
		return utls.HelloChrome_120_PQ, nil
	case "hellochrome_131":
		return utls.HelloChrome_131, nil
	case "hellochrome_133":
		return utls.HelloChrome_133, nil
	case "helloios_11_1":
		return utls.HelloIOS_11_1, nil
	case "helloios_12_1":
		return utls.HelloIOS_12_1, nil
	case "helloios_13":
		return utls.HelloIOS_13, nil
	case "helloios_14":
		return utls.HelloIOS_14, nil
	case "helloedge_85":
		return utls.HelloEdge_85, nil
	case "helloedge_106":
		return utls.HelloEdge_106, nil
	case "hellosafari_16_0":
		return utls.HelloSafari_16_0, nil
	case "hellosafari_26_3":
		return utls.HelloSafari_26_3, nil
	case "hello360_7_5":
		return utls.Hello360_7_5, nil
	case "hello360_11_0":
		return utls.Hello360_11_0, nil
	case "helloqq_11_1":
		return utls.HelloQQ_11_1, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported fingerprint fixture: %s", fingerprint)
	}
}

func parseClientHelloShape(fingerprint string, utlsID string, raw []byte) (clientHelloShape, error) {
	cursor := byteCursor{raw: raw}
	handshakeType, err := cursor.readU8("missing handshake type")
	if err != nil {
		return clientHelloShape{}, err
	}
	if handshakeType != int(clientHelloHandshakeType) {
		return clientHelloShape{}, fmt.Errorf("not a ClientHello handshake: 0x%02x", handshakeType)
	}
	handshakeLen, err := cursor.readU24("missing handshake length")
	if err != nil {
		return clientHelloShape{}, err
	}
	if handshakeLen != len(raw)-4 {
		return clientHelloShape{}, fmt.Errorf("handshake length mismatch: header=%d raw=%d", handshakeLen, len(raw)-4)
	}

	legacyVersion, err := cursor.readU16("missing legacy version")
	if err != nil {
		return clientHelloShape{}, err
	}
	if _, err := cursor.take(32, "missing ClientHello random"); err != nil {
		return clientHelloShape{}, err
	}
	sessionIDLen, err := cursor.readU8("missing legacy session id length")
	if err != nil {
		return clientHelloShape{}, err
	}
	if _, err := cursor.take(sessionIDLen, "truncated legacy session id"); err != nil {
		return clientHelloShape{}, err
	}

	cipherSuites, err := cursor.readU16List("missing cipher suites")
	if err != nil {
		return clientHelloShape{}, err
	}

	compressionMethodsLen, err := cursor.readU8("missing compression methods length")
	if err != nil {
		return clientHelloShape{}, err
	}
	compressionMethodsBytes, err := cursor.take(compressionMethodsLen, "truncated compression methods")
	if err != nil {
		return clientHelloShape{}, err
	}
	compressionMethods := make([]string, 0, len(compressionMethodsBytes))
	for _, method := range compressionMethodsBytes {
		compressionMethods = append(compressionMethods, formatU8(method))
	}

	extensionsLen, err := cursor.readU16("missing extensions length")
	if err != nil {
		return clientHelloShape{}, err
	}
	extensionsEnd, err := cursor.checkedEnd(extensionsLen, "truncated extensions")
	if err != nil {
		return clientHelloShape{}, err
	}
	if extensionsEnd != len(raw) {
		return clientHelloShape{}, fmt.Errorf("extensions length mismatch: ended at %d expected raw length %d", extensionsEnd, len(raw))
	}

	shape := clientHelloShape{
		Fingerprint:        fingerprint,
		UTLSID:             utlsID,
		ServerName:         serverName,
		HandshakeLength:    len(raw),
		LegacyVersion:      formatU16(uint16(legacyVersion)),
		CipherSuites:       formatU16s(cipherSuites),
		CompressionMethods: compressionMethods,
	}

	for cursor.offset < extensionsEnd {
		extensionType, err := cursor.readU16("missing extension type")
		if err != nil {
			return clientHelloShape{}, err
		}
		extensionLen, err := cursor.readU16("missing extension length")
		if err != nil {
			return clientHelloShape{}, err
		}
		extensionData, err := cursor.take(extensionLen, "truncated extension data")
		if err != nil {
			return clientHelloShape{}, err
		}

		extensionTypeU16 := uint16(extensionType)
		shape.ExtensionOrder = append(shape.ExtensionOrder, formatU16(extensionTypeU16))
		shape.Extensions = append(shape.Extensions, extensionShape{
			Type:   formatU16(extensionTypeU16),
			Length: extensionLen,
		})

		if err := parseExtensionShape(extensionTypeU16, extensionData, &shape); err != nil {
			return clientHelloShape{}, fmt.Errorf("extension %s: %w", formatU16(extensionTypeU16), err)
		}
	}
	if cursor.offset != extensionsEnd {
		return clientHelloShape{}, fmt.Errorf("extensions length mismatch: ended at %d expected %d", cursor.offset, extensionsEnd)
	}

	return shape, nil
}

func parseExtensionShape(extensionType uint16, data []byte, shape *clientHelloShape) error {
	cursor := byteCursor{raw: data}
	parsedPayload := true
	switch extensionType {
	case extensionSupportedVersions:
		values, err := cursor.readU8LengthPrefixedU16List("missing supported_versions")
		if err != nil {
			return err
		}
		shape.SupportedVersions = formatU16s(values)
	case extensionSupportedGroups:
		values, err := cursor.readU16List("missing supported_groups")
		if err != nil {
			return err
		}
		shape.SupportedGroups = formatU16s(values)
	case extensionECPointFormats:
		values, err := cursor.readU8List("missing ec_point_formats")
		if err != nil {
			return err
		}
		shape.ECPointFormats = formatU8s(values)
	case extensionSignatureAlgorithms:
		values, err := cursor.readU16List("missing signature_algorithms")
		if err != nil {
			return err
		}
		shape.SignatureAlgorithms = formatU16s(values)
	case extensionALPN:
		values, err := cursor.readProtocolNameList("missing ALPN protocols")
		if err != nil {
			return err
		}
		shape.ALPNProtocols = values
	case extensionKeyShare:
		keyShares, err := parseKeyShares(data)
		if err != nil {
			return err
		}
		shape.KeyShares = keyShares
		cursor.offset = len(data)
	case extensionPSKKeyExchangeModes:
		values, err := cursor.readU8List("missing psk_key_exchange_modes")
		if err != nil {
			return err
		}
		shape.PSKKeyExchangeModes = formatU8s(values)
	case extensionCompressCertificate:
		values, err := cursor.readU8LengthPrefixedU16List("missing compress_certificate algorithms")
		if err != nil {
			return err
		}
		shape.CertificateCompressionAlgorithms = formatU16s(values)
	case extensionApplicationSettings, extensionApplicationSettingsNew:
		protocols, err := cursor.readProtocolNameList("missing application_settings protocols")
		if err != nil {
			return err
		}
		shape.ApplicationSettings = append(shape.ApplicationSettings, applicationALPS{
			Type:      formatU16(extensionType),
			Protocols: protocols,
		})
	case extensionPadding:
		paddingLen := len(data)
		shape.PaddingLength = &paddingLen
		parsedPayload = false
	case extensionEncryptedClientHello:
		echLen := len(data)
		shape.EncryptedClientHelloLength = &echLen
		parsedPayload = false
	case extensionServerName,
		extensionStatusRequest,
		extensionSCT,
		extensionExtendedMasterSecret,
		extensionSessionTicket,
		extensionRenegotiationInfo:
		// Presence and payload length are captured in the generic extension list.
		parsedPayload = false
	default:
		// Unknown and GREASE extensions are intentionally represented only by
		// type and payload length. GREASE values are normalized by formatU16.
		parsedPayload = false
	}

	if parsedPayload && cursor.offset != len(data) {
		return fmt.Errorf("trailing extension data: parsed=%d length=%d", cursor.offset, len(data))
	}
	return nil
}

func parseKeyShares(data []byte) ([]keyShareShape, error) {
	cursor := byteCursor{raw: data}
	sharesLen, err := cursor.readU16("missing key_share client_shares length")
	if err != nil {
		return nil, err
	}
	sharesEnd, err := cursor.checkedEnd(sharesLen, "truncated key_share client_shares")
	if err != nil {
		return nil, err
	}
	if sharesEnd != len(data) {
		return nil, fmt.Errorf("key_share client_shares length mismatch: end=%d len=%d", sharesEnd, len(data))
	}

	var shares []keyShareShape
	for cursor.offset < sharesEnd {
		group, err := cursor.readU16("missing key_share group")
		if err != nil {
			return nil, err
		}
		keyExchangeLen, err := cursor.readU16("missing key_exchange length")
		if err != nil {
			return nil, err
		}
		if _, err := cursor.take(keyExchangeLen, "truncated key_exchange"); err != nil {
			return nil, err
		}
		shares = append(shares, keyShareShape{
			Group:             formatU16(uint16(group)),
			KeyExchangeLength: keyExchangeLen,
		})
	}
	return shares, nil
}

func formatU16s(values []uint16) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, formatU16(value))
	}
	return out
}

func formatU8s(values []byte) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, formatU8(value))
	}
	return out
}

func formatU16(value uint16) string {
	if isGREASE(value) {
		return "GREASE"
	}
	return fmt.Sprintf("0x%04x", value)
}

func formatU8(value byte) string {
	return fmt.Sprintf("0x%02x", value)
}

func isGREASE(value uint16) bool {
	high := byte(value >> 8)
	low := byte(value)
	return high == low && high&0x0f == 0x0a
}

type byteCursor struct {
	raw    []byte
	offset int
	base   int
}

func (c byteCursor) absoluteOffset() int {
	return c.base + c.offset
}

func (c byteCursor) checkedEnd(length int, message string) (int, error) {
	if length < 0 || c.offset+length > len(c.raw) {
		return 0, fmt.Errorf("%s: need %d bytes at offset %d, have %d", message, length, c.absoluteOffset(), len(c.raw)-c.offset)
	}
	return c.offset + length, nil
}

func (c *byteCursor) take(length int, message string) ([]byte, error) {
	end, err := c.checkedEnd(length, message)
	if err != nil {
		return nil, err
	}
	out := c.raw[c.offset:end]
	c.offset = end
	return out, nil
}

func (c *byteCursor) readU8(message string) (int, error) {
	bytes, err := c.take(1, message)
	if err != nil {
		return 0, err
	}
	return int(bytes[0]), nil
}

func (c *byteCursor) readU16(message string) (int, error) {
	bytes, err := c.take(2, message)
	if err != nil {
		return 0, err
	}
	return int(bytes[0])<<8 | int(bytes[1]), nil
}

func (c *byteCursor) readU24(message string) (int, error) {
	bytes, err := c.take(3, message)
	if err != nil {
		return 0, err
	}
	return int(bytes[0])<<16 | int(bytes[1])<<8 | int(bytes[2]), nil
}

func (c *byteCursor) readU16List(message string) ([]uint16, error) {
	length, err := c.readU16(message + " length")
	if err != nil {
		return nil, err
	}
	if length%2 != 0 {
		return nil, fmt.Errorf("%s length is odd: %d", message, length)
	}
	end, err := c.checkedEnd(length, "truncated "+message)
	if err != nil {
		return nil, err
	}

	values := make([]uint16, 0, length/2)
	for c.offset < end {
		value, err := c.readU16("missing " + message + " value")
		if err != nil {
			return nil, err
		}
		values = append(values, uint16(value))
	}
	return values, nil
}

func (c *byteCursor) readU8List(message string) ([]byte, error) {
	length, err := c.readU8(message + " length")
	if err != nil {
		return nil, err
	}
	values, err := c.take(length, "truncated "+message)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), values...), nil
}

func (c *byteCursor) readU8LengthPrefixedU16List(message string) ([]uint16, error) {
	length, err := c.readU8(message + " length")
	if err != nil {
		return nil, err
	}
	if length%2 != 0 {
		return nil, fmt.Errorf("%s length is odd: %d", message, length)
	}
	end, err := c.checkedEnd(length, "truncated "+message)
	if err != nil {
		return nil, err
	}

	values := make([]uint16, 0, length/2)
	for c.offset < end {
		value, err := c.readU16("missing " + message + " value")
		if err != nil {
			return nil, err
		}
		values = append(values, uint16(value))
	}
	return values, nil
}

func (c *byteCursor) readProtocolNameList(message string) ([]string, error) {
	length, err := c.readU16(message + " length")
	if err != nil {
		return nil, err
	}
	end, err := c.checkedEnd(length, "truncated "+message)
	if err != nil {
		return nil, err
	}

	var protocols []string
	for c.offset < end {
		protocolLen, err := c.readU8("missing protocol name length")
		if err != nil {
			return nil, err
		}
		protocol, err := c.take(protocolLen, "truncated protocol name")
		if err != nil {
			return nil, err
		}
		protocols = append(protocols, string(protocol))
	}
	return protocols, nil
}
