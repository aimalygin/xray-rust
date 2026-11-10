The Client Initial test vectors are from [RFC 9369 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9369.html#appendix-A.2) (`rfc9369-client-initial.hex`, QUIC v2), copyright 2023 IETF Trust and the identified authors, and [RFC 9001 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2) (`rfc9001-client-initial.hex`, QUIC v1), copyright 2021 IETF Trust and the identified authors. Extracted code components are covered by the Revised BSD License in section 4.e of the [IETF Trust Legal Provisions](https://trustee.ietf.org/license-info). The vector is provided without warranty.

`xray-chrome-parrot-client-initials.hex` holds the first four datagrams, one
hexadecimal datagram per line, that Xray-core v26.11.9 (`676eaf66`, Go 1.27.3)
sent as a Hysteria 2 client to an unanswering local UDP port on 2026-11-03. Its
default ChromeParrot QUIC stack splits the ClientHello for
`chrome-parrot.example` over the first two 1250-byte datagrams; the last two
are its retransmission 200 ms later. The handshake was never answered, so the
datagrams carry only ephemeral key shares and no Hysteria credentials.
