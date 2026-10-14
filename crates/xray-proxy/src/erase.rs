//! Erase delivered plaintext with zeroize's volatile stores and compiler fences.
use zeroize::Zeroize;

pub(crate) fn erase(bytes: &mut [u8]) {
    // SAFETY: u64 has no invalid bit patterns or padding. align_to_mut returns
    // disjoint slices covering exactly the original exclusive byte slice, with
    // correct alignment for the middle. No reference escapes this function.
    // Keep using Zeroize for every part so stores cannot be elided by the
    // optimizer. Word stores avoid a volatile instruction for every byte.
    let (prefix, words, suffix) = unsafe { bytes.align_to_mut::<u64>() };
    prefix.zeroize();
    words.zeroize();
    suffix.zeroize();
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_alignment_and_partial_length_is_erased_without_touching_neighbors() {
        for start in 0..32 {
            for len in 0..260 {
                let mut bytes = vec![0xa5; start + len + 32];
                super::erase(&mut bytes[start..start + len]);
                assert!(bytes[..start].iter().all(|&b| b == 0xa5));
                assert!(bytes[start..start + len].iter().all(|&b| b == 0));
                assert!(bytes[start + len..].iter().all(|&b| b == 0xa5));
            }
        }
    }
}
