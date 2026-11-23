//! The BLAKE3 context key of a byte string.
//!
//! BLAKE3's key derivation hashes its context into a context key, then hashes
//! the key material under that key. The `blake3` crate takes the context as
//! `&str`. Xray's Go client passes binary values there: an IV, a key-exchange
//! message, a record's ciphertext. This module hashes such a context itself
//! and `blake3::hazmat::HasherExt::new_from_context_key` takes the result, so
//! the key material, the secret half, is still hashed by the `blake3` crate.
//!
//! It is the BLAKE3 hash in its `DERIVE_KEY_CONTEXT` mode, written for a
//! complete, short input: one compression at a time. Every context is a value
//! that crossed the wire, so nothing here is wiped.

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MESSAGE_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The context key `blake3::Hasher::new_derive_key` computes for a context
/// string made of these bytes.
pub(crate) fn context_key(context: &[u8]) -> [u8; 32] {
    let words = subtree(context, 0).compress(ROOT);
    let mut key = [0; 32];
    for (bytes, word) in key.chunks_exact_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    key
}

/// The last compression of a chunk or of a parent node, not yet performed:
/// the root's takes the `ROOT` flag, any other yields a chaining value.
struct Node {
    chaining_value: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Node {
    /// The root is chunk 0 or a parent, whose counter is 0 either way: the
    /// counter of the first output block.
    fn compress(&self, extra_flags: u32) -> [u32; 8] {
        compress(
            &self.chaining_value,
            &self.block,
            self.counter,
            self.block_len,
            self.flags | extra_flags,
        )
    }
}

fn subtree(input: &[u8], chunk_counter: u64) -> Node {
    if input.len() <= CHUNK_LEN {
        return chunk(input, chunk_counter);
    }
    // The left subtree takes the largest power-of-two number of chunks that
    // leaves the right one at least a byte.
    let left_chunks = 1 << ((input.len() - 1) / CHUNK_LEN).ilog2();
    let (left, right) = input.split_at(left_chunks * CHUNK_LEN);
    let mut block = [0; 16];
    block[..8].copy_from_slice(&subtree(left, chunk_counter).compress(0));
    block[8..].copy_from_slice(&subtree(right, chunk_counter + left_chunks as u64).compress(0));
    Node {
        chaining_value: IV,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | DERIVE_KEY_CONTEXT,
    }
}

fn chunk(input: &[u8], chunk_counter: u64) -> Node {
    // Every block but the last goes into the chaining value. The last one is
    // never empty, except in the only chunk of an empty input.
    let head_len = input.len().saturating_sub(1) / BLOCK_LEN * BLOCK_LEN;
    let (head, last) = input.split_at(head_len);
    let mut chaining_value = IV;
    let mut flags = DERIVE_KEY_CONTEXT | CHUNK_START;
    for block in head.chunks_exact(BLOCK_LEN) {
        chaining_value = compress(
            &chaining_value,
            &words(block),
            chunk_counter,
            BLOCK_LEN as u32,
            flags,
        );
        flags = DERIVE_KEY_CONTEXT;
    }
    Node {
        chaining_value,
        block: words(last),
        counter: chunk_counter,
        block_len: last.len() as u32,
        flags: flags | CHUNK_END,
    }
}

/// A block as little-endian words, padded with zeros.
fn words(block: &[u8]) -> [u32; 16] {
    let mut padded = [0; BLOCK_LEN];
    padded[..block.len()].copy_from_slice(block);
    let mut words = [0; 16];
    for (word, bytes) in words.iter_mut().zip(padded.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    words
}

/// The compression function, down to the eight words that make a chaining
/// value or the first 32 bytes of the root's output.
fn compress(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 8] {
    let mut state = [0; 16];
    state[..8].copy_from_slice(chaining_value);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;
    let mut message = *block;
    for round in 0..7 {
        if round != 0 {
            message = MESSAGE_PERMUTATION.map(|from| message[from]);
        }
        // Columns, then diagonals.
        mix(&mut state, [0, 4, 8, 12], message[0], message[1]);
        mix(&mut state, [1, 5, 9, 13], message[2], message[3]);
        mix(&mut state, [2, 6, 10, 14], message[4], message[5]);
        mix(&mut state, [3, 7, 11, 15], message[6], message[7]);
        mix(&mut state, [0, 5, 10, 15], message[8], message[9]);
        mix(&mut state, [1, 6, 11, 12], message[10], message[11]);
        mix(&mut state, [2, 7, 8, 13], message[12], message[13]);
        mix(&mut state, [3, 4, 9, 14], message[14], message[15]);
    }
    std::array::from_fn(|index| state[index] ^ state[index + 8])
}

fn mix(state: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[cfg(test)]
mod tests {
    use super::context_key;

    /// A text context of `len` bytes that differs from block to block and
    /// from chunk to chunk.
    fn text(len: usize) -> String {
        (0..len)
            .map(|index| char::from(b' ' + ((index * 7 + index / 64 + index / 1024) % 95) as u8))
            .collect()
    }

    fn assert_matches_blake3(len: usize) {
        let context = text(len);
        assert_eq!(context.len(), len);
        assert_eq!(
            context_key(context.as_bytes()),
            blake3::hazmat::hash_derive_key_context(&context),
            "context of {len} bytes"
        );
    }

    #[test]
    fn matches_blake3_at_every_length_through_four_chunks() {
        for len in 0..=4 * 1024 + 1 {
            assert_matches_blake3(len);
        }
    }

    #[test]
    fn matches_blake3_around_every_subtree_boundary_of_a_deep_tree() {
        // Powers of two and their neighbours change which chunks pair up;
        // 67 chunks make a tree whose right edge is five levels of unequal
        // subtrees.
        for chunks in [5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 67] {
            for offset in [-1_isize, 0, 1] {
                assert_matches_blake3((chunks * 1024_isize + offset) as usize);
            }
        }
    }
}
