use super::table::{Index, Table};
use super::{huffman, Header};

use bytes::{BufMut, BytesMut};
use http::header::{HeaderName, HeaderValue};

const DEFAULT_MAX_ALLOWED_SIZE: usize = 4 * 1024;

#[derive(Debug)]
pub struct Encoder {
    table: Table,
    max_allowed_size: usize,
    size_update: Option<SizeUpdate>,
    /// Reusable buffer for the encoded header block of a single frame.
    ///
    /// A header block only has to live until it is copied into the
    /// connection write buffer, so the buffer that holds it can be reused
    /// across frames instead of being allocated and freed per frame. See
    /// `take_scratch` / `return_scratch`.
    scratch: BytesMut,
    /// xray-rust: whether `:authority` follows `:method` in request header
    /// blocks, the order Chrome and Go's HTTP/2 writers use.
    authority_first: bool,
    /// xray-rust: whether representations are picked as Go's `hpack`
    /// encoder picks them.
    go_choices: bool,
    /// xray-rust: whether request pseudo-headers take the order of Go's
    /// `net/http` HTTP/2 client: `:authority`, `:method`, `:path`,
    /// `:scheme`.
    go_pseudo_order: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SizeUpdate {
    One(usize),
    Two(usize, usize), // min, max
}

impl Encoder {
    pub fn new(max_size: usize, capacity: usize) -> Encoder {
        let max_size = max_size.min(DEFAULT_MAX_ALLOWED_SIZE);

        Encoder {
            table: Table::new(max_size, capacity),
            max_allowed_size: DEFAULT_MAX_ALLOWED_SIZE,
            size_update: None,
            scratch: BytesMut::new(),
            authority_first: false,
            go_choices: false,
            go_pseudo_order: false,
        }
    }

    /// Caps the dynamic table at `max` bytes whatever the peer allows; a
    /// smaller table is announced at the start of the next header block.
    /// xray-rust: also Go's `Encoder.SetMaxDynamicTableSizeLimit`.
    pub(crate) fn set_max_allowed_size(&mut self, max: usize) {
        self.max_allowed_size = max;

        if self.table.max_size() > max {
            self.update_max_size(max);
        }
    }

    /// xray-rust: puts `:authority` right after `:method` in request header
    /// blocks, instead of after `:scheme`.
    pub(crate) fn set_authority_first(&mut self, enabled: bool) {
        self.authority_first = enabled;
    }

    /// xray-rust: whether `:authority` follows `:method`.
    pub(crate) fn authority_first(&self) -> bool {
        self.authority_first
    }

    /// xray-rust: writes request pseudo-headers in the order of Go's
    /// `net/http` HTTP/2 client, `:authority`, `:method`, `:path`,
    /// `:scheme`; it takes precedence over `set_authority_first`.
    pub(crate) fn set_go_pseudo_order(&mut self, enabled: bool) {
        self.go_pseudo_order = enabled;
    }

    /// xray-rust: whether request pseudo-headers take Go's order.
    pub(crate) fn go_pseudo_order(&self) -> bool {
        self.go_pseudo_order
    }

    /// xray-rust: picks representations as Go's `hpack.Encoder` does: a
    /// string in Huffman code only when that is shorter, a name's last
    /// static table entry, where upstream takes its first, and a field
    /// indexed whenever it fits the table.
    pub(crate) fn set_go_choices(&mut self, enabled: bool) {
        self.go_choices = enabled;
        self.table.set_go_indexing(enabled);
    }

    /// The static index a name is referenced by: Go's `byName` keeps a
    /// name's last entry.
    fn name_index(&self, idx: usize) -> usize {
        match idx {
            2 | 4 | 6 if self.go_choices => idx + 1,
            8 if self.go_choices => 14,
            _ => idx,
        }
    }

    /// Takes the reusable buffer for one header-block encode.
    ///
    /// The buffer is returned by `return_scratch` once the encoded block has
    /// been copied into the write buffer. If it is not returned - the
    /// CONTINUATION path keeps it, since the remainder is still needed - the
    /// next call simply starts from a fresh buffer.
    pub(crate) fn take_scratch(&mut self) -> BytesMut {
        std::mem::take(&mut self.scratch)
    }

    /// Returns a fully-written header block buffer for reuse.
    pub(crate) fn return_scratch(&mut self, scratch: BytesMut) {
        self.scratch = scratch;
    }

    /// Queues a max size update.
    ///
    /// The next call to `encode` will include a dynamic size update frame.
    pub fn update_max_size(&mut self, val: usize) {
        let val = val.min(self.max_allowed_size);

        match self.size_update {
            Some(SizeUpdate::One(old)) => {
                if val > old {
                    if old > self.table.max_size() {
                        self.size_update = Some(SizeUpdate::One(val));
                    } else {
                        self.size_update = Some(SizeUpdate::Two(old, val));
                    }
                } else {
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
            Some(SizeUpdate::Two(min, _)) => {
                if val < min {
                    self.size_update = Some(SizeUpdate::One(val));
                } else {
                    self.size_update = Some(SizeUpdate::Two(min, val));
                }
            }
            None => {
                if val != self.table.max_size() {
                    // Don't bother writing a frame if the value already matches
                    // the table's max size.
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
        }
    }

    /// Encode a set of headers into the provide buffer
    pub fn encode<I>(&mut self, headers: I, dst: &mut BytesMut)
    where
        I: IntoIterator<Item = Header<Option<HeaderName>>>,
    {
        let span = tracing::trace_span!("hpack::encode");
        let _e = span.enter();

        self.encode_size_updates(dst);

        let mut last_index = None;

        for header in headers {
            match header.reify() {
                // The header has an associated name. In which case, try to
                // index it in the table.
                Ok(header) => {
                    let index = self.table.index(header);
                    self.encode_header(&index, dst);

                    last_index = Some(index);
                }
                // The header does not have an associated name. This means that
                // the name is the same as the previously yielded header. In
                // which case, we skip table lookup and just use the same index
                // as the previous entry.
                Err(value) => {
                    self.encode_header_without_name(
                        last_index.as_ref().unwrap_or_else(|| {
                            panic!("encoding header without name, but no previous index to use for name");
                        }),
                        &value,
                        dst,
                    );
                }
            }
        }
    }

    fn encode_size_updates(&mut self, dst: &mut BytesMut) {
        match self.size_update.take() {
            Some(SizeUpdate::One(val)) => {
                self.table.resize(val);
                encode_size_update(val, dst);
            }
            Some(SizeUpdate::Two(min, max)) => {
                self.table.resize(min);
                self.table.resize(max);
                encode_size_update(min, dst);
                encode_size_update(max, dst);
            }
            None => {}
        }
    }

    fn encode_header(&mut self, index: &Index, dst: &mut BytesMut) {
        match *index {
            Index::Indexed(idx, _) => {
                encode_int(idx, 7, 0x80, dst);
            }
            Index::Name(idx, _) => {
                let header = self.table.resolve(index);

                encode_not_indexed(
                    self.name_index(idx),
                    header.value_slice(),
                    header.is_sensitive(),
                    self.go_choices,
                    dst,
                );
            }
            Index::Inserted(_) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                dst.put_u8(0b0100_0000);

                encode_str(header.name().as_slice(), self.go_choices, dst);
                encode_str(header.value_slice(), self.go_choices, dst);
            }
            Index::InsertedValue(idx, _) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                encode_int(self.name_index(idx), 6, 0b0100_0000, dst);
                encode_str(header.value_slice(), self.go_choices, dst);
            }
            Index::NotIndexed(_) => {
                let header = self.table.resolve(index);

                encode_not_indexed2(
                    header.name().as_slice(),
                    header.value_slice(),
                    header.is_sensitive(),
                    self.go_choices,
                    dst,
                );
            }
        }
    }

    fn encode_header_without_name(
        &mut self,
        last: &Index,
        value: &HeaderValue,
        dst: &mut BytesMut,
    ) {
        match *last {
            Index::Indexed(..)
            | Index::Name(..)
            | Index::Inserted(..)
            | Index::InsertedValue(..) => {
                let idx = self.table.resolve_idx(last);

                encode_not_indexed(
                    self.name_index(idx),
                    value.as_ref(),
                    value.is_sensitive(),
                    self.go_choices,
                    dst,
                );
            }
            Index::NotIndexed(_) => {
                let last = self.table.resolve(last);

                encode_not_indexed2(
                    last.name().as_slice(),
                    value.as_ref(),
                    value.is_sensitive(),
                    self.go_choices,
                    dst,
                );
            }
        }
    }
}

impl Default for Encoder {
    fn default() -> Encoder {
        Encoder::new(4096, 0)
    }
}

fn encode_size_update(val: usize, dst: &mut BytesMut) {
    encode_int(val, 5, 0b0010_0000, dst)
}

fn encode_not_indexed(name: usize, value: &[u8], sensitive: bool, go: bool, dst: &mut BytesMut) {
    if sensitive {
        encode_int(name, 4, 0b10000, dst);
    } else {
        encode_int(name, 4, 0, dst);
    }

    encode_str(value, go, dst);
}

fn encode_not_indexed2(
    name: &[u8],
    value: &[u8],
    sensitive: bool,
    go: bool,
    dst: &mut BytesMut,
) {
    if sensitive {
        dst.put_u8(0b10000);
    } else {
        dst.put_u8(0);
    }

    encode_str(name, go, dst);
    encode_str(value, go, dst);
}

/// Encodes a string literal; `go` keeps it raw unless Huffman code is
/// shorter, as Go's `appendHpackString` does.
fn encode_str(val: &[u8], go: bool, dst: &mut BytesMut) {
    if !val.is_empty() {
        let idx = position(dst);

        // Push a placeholder byte for the length header
        dst.put_u8(0);

        // Encode with huffman
        huffman::encode(val, dst);

        let huff_len = position(dst) - (idx + 1);

        if go && huff_len >= val.len() {
            dst.truncate(idx);
            encode_int(val.len(), 7, 0, dst);
            dst.put_slice(val);
            return;
        }

        if encode_int_one_byte(huff_len, 7) {
            // Write the string head
            dst[idx] = 0x80 | huff_len as u8;
        } else {
            // Write the head to a placeholder
            const PLACEHOLDER_LEN: usize = 8;
            let mut buf = [0u8; PLACEHOLDER_LEN];

            let head_len = {
                let mut head_dst = &mut buf[..];
                encode_int(huff_len, 7, 0x80, &mut head_dst);
                PLACEHOLDER_LEN - head_dst.remaining_mut()
            };

            // This is just done to reserve space in the destination
            dst.put_slice(&buf[1..head_len]);

            // Shift the header forward
            for i in 0..huff_len {
                let src_i = idx + 1 + (huff_len - (i + 1));
                let dst_i = idx + head_len + (huff_len - (i + 1));
                dst[dst_i] = dst[src_i];
            }

            // Copy in the head
            for i in 0..head_len {
                dst[idx + i] = buf[i];
            }
        }
    } else {
        // Write an empty string
        dst.put_u8(0);
    }
}

/// Encode an integer into the given destination buffer
fn encode_int<B: BufMut>(
    mut value: usize,   // The integer to encode
    prefix_bits: usize, // The number of bits in the prefix
    first_byte: u8,     // The base upon which to start encoding the int
    dst: &mut B,
) {
    if encode_int_one_byte(value, prefix_bits) {
        dst.put_u8(first_byte | value as u8);
        return;
    }

    let low = (1 << prefix_bits) - 1;

    value -= low;

    dst.put_u8(first_byte | low as u8);

    while value >= 128 {
        dst.put_u8(0b1000_0000 | value as u8);

        value >>= 7;
    }

    dst.put_u8(value as u8);
}

/// Returns true if the in the int can be fully encoded in the first byte.
fn encode_int_one_byte(value: usize, prefix_bits: usize) -> bool {
    value < (1 << prefix_bits) - 1
}

fn position(buf: &BytesMut) -> usize {
    buf.len()
}

#[cfg(test)]
mod test {
    use super::*;
    use http::*;

    #[test]
    fn test_encode_method_get() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_post() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("POST")]);
        assert_eq!(*res, [0x80 | 3]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_patch() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(res[0], 0b01000000 | 2); // Incremental indexing w/ name pulled from table
        assert_eq!(res[1], 0x80 | 5); // header value w/ huffman coding

        assert_eq!("PATCH", huff_decode(&res[2..7]));
        assert_eq!(encoder.table.len(), 1);

        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(1 << 7 | 62, res[0]);
        assert_eq!(1, res.len());
    }

    #[test]
    fn test_encode_indexed_name_literal_value() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-language", "foo")]);

        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 2); // header value w/ huffman coding

        assert_eq!("foo", huff_decode(&res[2..4]));

        // Same name, new value should still use incremental
        let res = encode(&mut encoder, vec![header("content-language", "bar")]);
        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 3); // header value w/ huffman coding
        assert_eq!("bar", huff_decode(&res[2..5]));
    }

    #[test]
    fn test_repeated_headers_are_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("foo", "hello")]);

        assert_eq!(&[0b01000000, 0x80 | 2], &res[0..2]);
        assert_eq!("foo", huff_decode(&res[2..4]));
        assert_eq!(0x80 | 4, res[4]);
        assert_eq!("hello", huff_decode(&res[5..]));
        assert_eq!(9, res.len());

        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "hello")]);
        assert_eq!([0x80 | 62], *res);

        assert_eq!(encoder.table.len(), 1);
    }

    #[test]
    fn test_evicting_headers() {
        let mut encoder = Encoder::default();

        // Fill the table
        for i in 0..64 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
            assert_eq!(key, huff_decode(&res[2..14]));
            assert_eq!(0x80 | 12, res[14]);
            assert_eq!(key, huff_decode(&res[15..]));
            assert_eq!(27, res.len());

            // Make sure the header can be found...
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            // Only check that it is found
            assert_eq!(0x80, res[0] & 0x80);
        }

        assert_eq!(4096, encoder.table.size());
        assert_eq!(64, encoder.table.len());

        // Find existing headers
        for i in 0..64 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80, res[0] & 0x80);
        }

        // Insert a new header
        let key = "x-hello-world-64";
        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
        assert_eq!(key, huff_decode(&res[2..14]));
        assert_eq!(0x80 | 12, res[14]);
        assert_eq!(key, huff_decode(&res[15..]));
        assert_eq!(27, res.len());

        assert_eq!(64, encoder.table.len());

        // Now try encoding entries that should exist in the table
        for i in 1..65 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80 | (61 + (65 - i)), res[0]);
        }
    }

    #[test]
    fn test_large_headers_are_not_indexed() {
        let mut encoder = Encoder::new(128, 0);
        let key = "hello-world-hello-world-HELLO-zzz";

        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0, 0x80 | 25], &res[..2]);

        assert_eq!(0, encoder.table.len());
        assert_eq!(0, encoder.table.size());
    }

    #[test]
    fn test_sensitive_headers_are_never_indexed() {
        use http::header::HeaderValue;

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        // Now, try to encode the sensitive header

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b10000, 0x80 | 8], &res[..2]);
        assert_eq!("my-password", huff_decode(&res[2..10]));
        assert_eq!(0x80 | 4, res[10]);
        assert_eq!("12345", huff_decode(&res[11..]));

        // Now, try to encode a sensitive header w/ a name in the static table
        let name = "authorization".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 8], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!("12345", huff_decode(&res[3..]));

        // Using the name component of a previously indexed header (without
        // sensitive flag set)

        let _ = encode(
            &mut encoder,
            vec![self::header("my-password", "not-so-secret")],
        );

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 47], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!("12345", huff_decode(&res[3..]));
    }

    #[test]
    fn test_content_length_value_not_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-length", "1234")]);

        assert_eq!(&[15, 13, 0x80 | 3], &res[0..3]);
        assert_eq!("1234", huff_decode(&res[3..]));
        assert_eq!(6, res.len());
    }

    #[test]
    fn test_encoding_headers_with_same_name() {
        let mut encoder = Encoder::default();
        let name = "hello";

        // Encode first one
        let _ = encode(&mut encoder, vec![header(name, "one")]);

        // Encode second one
        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x40 | 62, 0x80 | 3], &res[0..2]);
        assert_eq!("two", huff_decode(&res[2..]));
        assert_eq!(5, res.len());

        // Encode the first one again
        let res = encode(&mut encoder, vec![header(name, "one")]);
        assert_eq!(&[0x80 | 63], &res[..]);

        // Now the second one
        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x80 | 62], &res[..]);
    }

    #[test]
    fn test_evicting_headers_when_multiple_of_same_name_are_in_table() {
        // The encoder only has space for 2 headers
        let mut encoder = Encoder::new(76, 0);

        let _ = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(1, encoder.table.len());

        let _ = encode(&mut encoder, vec![header("bar", "foo")]);
        assert_eq!(2, encoder.table.len());

        // This will evict the first header, while still referencing the header
        // name
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x40 | 63, 0, 0x80 | 3], &res[..3]);
        assert_eq!(2, encoder.table.len());

        // Try adding the same header again
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x80 | 62], &res[..]);
        assert_eq!(2, encoder.table.len());
    }

    #[test]
    fn test_max_size_zero() {
        // Static table only
        let mut encoder = Encoder::new(0, 0);
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[0, 0x80 | 2], &res[..2]);
        assert_eq!("foo", huff_decode(&res[2..4]));
        assert_eq!(0x80 | 3, res[4]);
        assert_eq!("bar", huff_decode(&res[5..8]));
        assert_eq!(0, encoder.table.len());

        // Encode a custom value
        let res = encode(&mut encoder, vec![header("transfer-encoding", "chunked")]);
        assert_eq!(&[15, 42, 0x80 | 6], &res[..3]);
        assert_eq!("chunked", huff_decode(&res[3..]));
    }

    #[test]
    fn test_update_max_size_combos() {
        let mut encoder = Encoder::default();
        assert!(encoder.size_update.is_none());
        assert_eq!(4096, encoder.table.max_size());

        encoder.update_max_size(4096); // Default size
        assert!(encoder.size_update.is_none());

        encoder.update_max_size(0);
        assert_eq!(Some(SizeUpdate::One(0)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::Two(0, 100)), encoder.size_update);

        let mut encoder = Encoder::default();
        encoder.set_max_allowed_size(8000);
        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::One(8000)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::One(100)), encoder.size_update);

        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::Two(100, 8000)), encoder.size_update);

        encoder.update_max_size(4000);
        assert_eq!(Some(SizeUpdate::Two(100, 4000)), encoder.size_update);

        encoder.update_max_size(50);
        assert_eq!(Some(SizeUpdate::One(50)), encoder.size_update);
    }

    #[test]
    fn test_resizing_table() {
        let mut encoder = Encoder::default();

        // Add a header
        let _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(1);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(&[32 | 1, 0x80 | 2], &res[..]);
        assert_eq!(0, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(0, res[0]);

        encoder.update_max_size(100);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 64], &res[..3]);

        encoder.update_max_size(0);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32, 0], &res[..2]);
    }

    #[test]
    fn test_decreasing_table_size_without_eviction() {
        let mut encoder = Encoder::default();

        // Add a header
        let _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(100);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 0x80 | 62], &res[..]);
    }

    #[test]
    fn test_nameless_header() {
        let mut encoder = Encoder::default();

        let res = encode(
            &mut encoder,
            vec![
                Header::Field {
                    name: Some("hello".parse().unwrap()),
                    value: HeaderValue::from_bytes(b"world").unwrap(),
                },
                Header::Field {
                    name: None,
                    value: HeaderValue::from_bytes(b"zomg").unwrap(),
                },
            ],
        );

        assert_eq!(&[0x40, 0x80 | 4], &res[0..2]);
        assert_eq!("hello", huff_decode(&res[2..6]));
        assert_eq!(0x80 | 4, res[6]);
        assert_eq!("world", huff_decode(&res[7..11]));

        // Next is not indexed
        assert_eq!(&[15, 47, 0x80 | 3], &res[11..14]);
        assert_eq!("zomg", huff_decode(&res[14..]));
    }

    #[test]
    fn test_large_size_update() {
        let mut encoder = Encoder::default();
        encoder.set_max_allowed_size(usize::MAX);

        encoder.update_max_size(1912930560);
        assert_eq!(Some(SizeUpdate::One(1912930560)), encoder.size_update);

        let mut dst = BytesMut::with_capacity(6);
        encoder.encode_size_updates(&mut dst);
        assert_eq!([63, 225, 129, 148, 144, 7], &dst[..]);
    }

    #[test]
    fn test_large_size_update_is_capped() {
        let mut encoder = Encoder::new(0, 0);

        encoder.update_max_size(1912930560);
        assert_eq!(
            Some(SizeUpdate::One(DEFAULT_MAX_ALLOWED_SIZE)),
            encoder.size_update
        );

        let mut dst = BytesMut::with_capacity(3);
        encoder.encode_size_updates(&mut dst);
        assert_eq!([63, 225, 31], &dst[..]);
        assert_eq!(DEFAULT_MAX_ALLOWED_SIZE, encoder.table.max_size());
    }

    #[test]
    #[ignore]
    fn test_evicted_overflow() {
        // Not sure what the best way to do this is.
    }

    #[test]
    fn a_zero_table_limit_announces_itself_and_indexes_nothing() {
        let mut encoder = Encoder::default();
        encoder.set_max_allowed_size(0);
        // The server allowing a table changes nothing.
        encoder.update_max_size(4096);
        // A size update to zero, then a literal without indexing.
        let first = encode(&mut encoder, vec![header("x-custom", "1")]);
        assert_eq!([0x20, 0x00], first[..2]);
        // A static name is referenced, its value still not indexed.
        let method = encode(&mut encoder, vec![method("CONNECT")]);
        assert_eq!(0x02, method[0]);
        // Nothing was added to the table: the same literal again.
        let again = encode(&mut encoder, vec![header("x-custom", "1")]);
        assert_eq!(first[1..], again[..]);
        assert_eq!(0, encoder.table.size());
    }

    #[test]
    fn go_choices_pick_raw_strings_and_last_static_names() {
        use crate::hpack::BytesStr;

        let mut encoder = Encoder::default();
        encoder.set_max_allowed_size(0);
        encoder.set_go_choices(true);
        let res = encode(
            &mut encoder,
            vec![method("CONNECT"), header("capsule-protocol", "?1")],
        );
        // `:method` by its last static entry, POST, and CONNECT raw: its
        // Huffman code is no shorter.
        assert_eq!([0x20, 0x03, 0x07], res[..3]);
        assert_eq!(b"CONNECT", &res[3..10]);
        // A Huffman name, then `?1` raw.
        assert_eq!(0x00, res[10]);
        assert_eq!(0x80, res[11] & 0x80);
        assert_eq!([0x02, b'?', b'1'], res[res.len() - 3..]);
        // `:path` by its last entry, a long value in Huffman code.
        let path = encode(
            &mut encoder,
            vec![Header::Path(BytesStr::from_static("/masque/ip/"))],
        );
        assert_eq!(0x05, path[0]);
        assert_eq!(0x80, path[1] & 0x80);
        // Upstream keeps the first entry and Huffman code throughout.
        let mut upstream = Encoder::default();
        upstream.set_max_allowed_size(0);
        let res = encode(&mut upstream, vec![method("CONNECT")]);
        assert_eq!([0x20, 0x02, 0x80 | 7], res[..3]);
    }

    #[test]
    fn go_choices_index_every_field_that_fits() {
        use crate::hpack::BytesStr;

        let mut encoder = Encoder::default();
        encoder.set_go_choices(true);
        let first = encode(
            &mut encoder,
            vec![
                Header::Path(BytesStr::from_static("/v1/object")),
                header("authorization", "Bearer t"),
                header("content-length", "4"),
            ],
        );
        // `:path` with incremental indexing by its last static entry, then
        // `authorization` (23) and `content-length` (28), as Go writes them.
        assert_eq!(0x45, first[0]);
        let auth = 1 + 1 + usize::from(first[1] & 0x7f);
        assert_eq!(0x40 | 23, first[auth]);
        let length = auth + 1 + 1 + usize::from(first[auth + 1] & 0x7f);
        assert_eq!(0x40 | 28, first[length]);
        // The same `:path` again is the oldest dynamic entry: 62 + 2.
        let again = encode(&mut encoder, vec![Header::Path(BytesStr::from_static("/v1/object"))]);
        assert_eq!([0x80 | 64], again[..]);
        // Upstream never indexes `:path`.
        let mut upstream = Encoder::default();
        let path = encode(&mut upstream, vec![Header::Path(BytesStr::from_static("/v1/object"))]);
        assert_eq!(0x04, path[0]);
    }

    fn encode(e: &mut Encoder, hdrs: Vec<Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(hdrs, &mut dst);
        dst
    }

    fn method(s: &str) -> Header<Option<HeaderName>> {
        Header::Method(Method::from_bytes(s.as_bytes()).unwrap())
    }

    fn header(name: &str, val: &str) -> Header<Option<HeaderName>> {
        let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(val.as_bytes()).unwrap();

        Header::Field {
            name: Some(name),
            value,
        }
    }

    fn huff_decode(src: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        huffman::decode(src, &mut buf).unwrap()
    }
}
