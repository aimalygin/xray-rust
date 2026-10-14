package main

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/hex"
	"github.com/xtls/xray-core/common/buf"
	xc "github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	va "github.com/xtls/xray-core/proxy/vmess/aead"
	ve "github.com/xtls/xray-core/proxy/vmess/encoding"
	"golang.org/x/crypto/chacha20poly1305"
)

func vmessFixtures() map[string]any {
	saved := crand.Reader
	defer func() { crand.Reader = saved }()
	id, err := uuid.ParseString("00112233-4455-6677-8899-aabbccddeeff")
	must(err)
	commandKey := protocol.NewID(id).CmdKey()
	crand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x33}, 128))
	auth := va.CreateAuthID(commandKey, 1700000000)
	nonce := bytes.Repeat([]byte{0x44}, 8)
	kd := []map[string]any{}
	for _, path := range [][]string{{"AES Auth ID Encryption"}, {"auth_len"}, {"VMess Header AEAD Key", string(auth[:]), string(nonce)}, {"VMess Header AEAD Nonce_Length", string(auth[:]), string(nonce)}} {
		parts := []string{}
		for _, p := range path {
			parts = append(parts, hex.EncodeToString([]byte(p)))
		}
		kd = append(kd, map[string]any{"path": parts, "output": hex.EncodeToString(va.KDF(commandKey, path...))})
	}
	records := []map[string]any{}
	key := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		makeCipher := func(key []byte) cipher.AEAD {
			if method == "aes-128-gcm" {
				return xc.NewAesGcm(key)
			}
			c, err := chacha20poly1305.New(ve.GenerateChacha20Poly1305Key(key))
			must(err)
			return c
		}
		for _, authenticated := range []bool{false, true} {
			mask := ve.NewShakeSizeParser(iv)
			normalizer := ve.NewShakeSizeParser(iv)
			var length xc.ChunkSizeEncoder = mask
			if authenticated {
				length = ve.NewAEADSizeParser(&xc.AEADAuthenticator{AEAD: makeCipher(va.KDF16(key, "auth_len")), NonceGenerator: ve.GenerateChunkNonce(iv, 12)})
			}
			var wire bytes.Buffer
			writer := xc.NewAuthenticationWriter(&xc.AEADAuthenticator{AEAD: makeCipher(key), NonceGenerator: ve.GenerateChunkNonce(iv, 12)}, length, &wire, protocol.TransferTypeStream, mask)
			chunks := []map[string]any{}
			for _, payload := range [][]byte{[]byte("VMess AEAD body"), bytes.Repeat([]byte{0x5a}, 1000), nil} {
				crand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x55}, 128))
				if len(payload) == 0 {
					must(writer.WriteMultiBuffer(nil))
				} else {
					b := buf.New()
					_, err := b.Write(payload)
					must(err)
					must(writer.WriteMultiBuffer(buf.MultiBuffer{b}))
				}
				padding := int(normalizer.NextPaddingLen())
				if !authenticated {
					normalizer.Encode(0, make([]byte, 2))
				}
				data := append([]byte(nil), wire.Bytes()...)
				clear(data[len(data)-padding:])
				chunks = append(chunks, map[string]any{"payload": hex.EncodeToString(payload), "wire": hex.EncodeToString(data), "padding": padding})
				wire.Reset()
			}
			records = append(records, map[string]any{"method": method, "authenticatedLength": authenticated, "key": hex.EncodeToString(key), "iv": hex.EncodeToString(iv), "chunks": chunks})
		}
	}
	return map[string]any{"id": id.String(), "commandKey": hex.EncodeToString(commandKey), "authId": hex.EncodeToString(auth[:]), "kdf": kd, "records": records}
}
