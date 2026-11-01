package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/infra/conf"
	ss "github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// Classic Shadowsocks AEAD ("AEAD-2017") client fixtures. Salts are drawn
// from a fixed crypto/rand source and recorded from the emitted wire; key
// derivation, chunk framing, nonce sequence and the accepted method strings
// all come from the pinned Xray-core module.
type discardLog struct{}

func (discardLog) Handle(xlog.Message) {}

func ssAeadMethodClass(method string) string {
	config, err := (&conf.ShadowsocksClientConfig{
		Address:  &conf.Address{Address: net.ParseAddress("192.0.2.1")},
		Port:     8388,
		Cipher:   method,
		Password: "synthetic-password",
	}).Build()
	if err != nil {
		return "rejected"
	}
	if _, ok := config.(*ss2022.ClientConfig); ok {
		return "shadowsocks2022"
	}
	account, err := config.(*ss.ClientConfig).Server.User.Account.GetInstance()
	must(err)
	return account.(*ss.Account).CipherType.String()
}

func ssAeadUser(cipher ss.CipherType, password string) *protocol.MemoryUser {
	account, err := (&ss.Account{CipherType: cipher, Password: password}).AsAccount()
	must(err)
	return &protocol.MemoryUser{Account: account}
}

func ssAeadFixtures() map[string]any {
	// The config builder logs a deprecation warning to stdout, which carries
	// this generator's JSON output.
	xlog.RegisterHandler(discardLog{})
	methods := []map[string]any{}
	for _, method := range []string{
		"aes-128-gcm", "AES-128-GCM", "aead_aes_128_gcm",
		"aes-256-gcm", "aead_aes_256_gcm",
		"chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305", "ChaCha20-IETF-Poly1305",
		"xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305",
		"none", "plain", "", "rc4-md5", "aes-128-cfb", "aes-192-gcm", "chacha20-ietf",
		"2022-blake3-aes-128-gcm", " aes-128-gcm",
	} {
		methods = append(methods, map[string]any{"method": method, "class": ssAeadMethodClass(method)})
	}
	if _, err := (&conf.ShadowsocksClientConfig{
		Address: &conf.Address{Address: net.ParseAddress("192.0.2.1")},
		Port:    8388, Cipher: "aes-128-gcm",
	}).Build(); err == nil {
		panic("empty Shadowsocks password accepted")
	}

	// Salts come from crypto/rand; a fixed source keeps the fixture stable.
	saved := crand.Reader
	defer func() { crand.Reader = saved }()
	cases := []map[string]any{}
	for _, cipher := range []ss.CipherType{ss.CipherType_AES_128_GCM, ss.CipherType_AES_256_GCM, ss.CipherType_CHACHA20_POLY1305, ss.CipherType_XCHACHA20_POLY1305} {
		for _, password := range []string{"synthetic-ss-aead-password", "пароль-🔑:with:colons"} {
			crand.Reader = bytes.NewReader(bytes.Repeat([]byte{byte(0x10 + len(cases))}, 4096))
			user := ssAeadUser(cipher, password)
			account := user.Account.(*ss.MemoryAccount)
			ivLen := int(account.Cipher.IVSize())
			destination := net.TCPDestination(net.DomainAddress("example.test"), 443)

			var tcp bytes.Buffer
			writer, err := ss.WriteTCPRequest(&protocol.RequestHeader{
				Version: ss.Version, Command: protocol.RequestCommandTCP,
				Address: destination.Address, Port: destination.Port, User: user,
			}, &tcp)
			must(err)
			request := append([]byte(nil), tcp.Bytes()...)
			tcp.Reset()
			next := buf.New()
			next.Write([]byte("after-header"))
			must(writer.WriteMultiBuffer(buf.MultiBuffer{next}))
			nextRecord := append([]byte(nil), tcp.Bytes()...)
			// One 20000-byte write shows the writer's chunk boundaries.
			tcp.Reset()
			large := buf.MergeBytes(nil, bytes.Repeat([]byte{0x5a}, 20000))
			must(writer.WriteMultiBuffer(large))
			largeDigest := sha256.Sum256(tcp.Bytes())
			largeLen := tcp.Len()

			// Server-to-client stream: one payload record, then the empty
			// record that Xray's reader treats as end of stream, followed by
			// bytes that must never be read.
			var response bytes.Buffer
			serverWriter, err := ss.WriteTCPResponse(&protocol.RequestHeader{User: user}, &response)
			must(err)
			payload := buf.New()
			payload.Write([]byte("server payload"))
			must(serverWriter.WriteMultiBuffer(buf.MultiBuffer{payload}))
			must(serverWriter.WriteMultiBuffer(buf.MultiBuffer{}))
			response.Write([]byte("trailing bytes after end of stream"))
			reader, err := ss.ReadTCPResponse(user, bytes.NewReader(response.Bytes()))
			must(err)
			decoded, err := reader.ReadMultiBuffer()
			must(err)
			if decoded.String() != "server payload" {
				panic("Shadowsocks AEAD response oracle")
			}
			buf.ReleaseMulti(decoded)
			if _, err := reader.ReadMultiBuffer(); err != io.EOF {
				panic("empty Shadowsocks AEAD record is not end of stream")
			}

			udpDestination := net.UDPDestination(net.DomainAddress("example.test"), 443)
			udpRequest := &protocol.RequestHeader{
				Version: ss.Version, Command: protocol.RequestCommandUDP,
				Address: udpDestination.Address, Port: udpDestination.Port, User: user,
			}
			packet, err := ss.EncodeUDPPacket(udpRequest, []byte("udp-payload"))
			must(err)
			udpWire := append([]byte(nil), packet.Bytes()...)
			packet.Release()

			// A reply whose address type carries high bits. Xray masks the
			// type with 0x0F when decoding UDP packets.
			reply := buf.New()
			reply.Write(udpWire[:ivLen])
			reply.Write([]byte{0x11, 192, 0, 2, 8, 0, 53})
			reply.Write([]byte("reply"))
			must(account.Cipher.EncodePacket(account.Key, reply))
			maskedReply := append([]byte(nil), reply.Bytes()...)
			validator := new(ss.Validator)
			must(validator.Add(user))
			header, decodedReply, err := ss.DecodeUDPPacket(validator, reply)
			must(err)
			if header.Address.String() != "192.0.2.8" || header.Port != 53 || string(decodedReply.Bytes()) != "reply" {
				panic("Shadowsocks AEAD UDP oracle")
			}
			reply.Release()

			cases = append(cases, map[string]any{
				"cipher": cipher.String(), "method": strings.ReplaceAll(strings.ToLower(cipher.String()), "_", "-"), "password": password,
				"key": hex.EncodeToString(account.Key), "saltLength": ivLen, "address": "example.test", "port": 443,
				"request": hex.EncodeToString(request), "nextRecord": hex.EncodeToString(nextRecord),
				"largeWriteLength": largeLen, "largeWriteSha256": hex.EncodeToString(largeDigest[:]),
				"response":   hex.EncodeToString(response.Bytes()),
				"udpPayload": hex.EncodeToString([]byte("udp-payload")), "udpWire": hex.EncodeToString(udpWire),
				"udpMaskedReply": hex.EncodeToString(maskedReply),
			})
		}
	}
	return map[string]any{"methods": methods, "cases": cases}
}
