// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::fmt;
use zeroize::Zeroizing;

/// Owned preshared key, redacted in Debug and zeroized before deallocation.
///
/// The heap allocation keeps key bytes at a stable address during ownership
/// transfers. Cloning creates an independent zeroizing owner. Explicit byte
/// access is only for the Noise KDF and authorized configuration export.
pub struct PresharedKey(Box<Zeroizing<[u8; 32]>>);

impl PresharedKey {
    /// Copy a key into zeroizing storage. The caller owns its input's lifetime.
    pub fn new(bytes: &[u8; 32]) -> Self {
        let mut key = Box::new(Zeroizing::new([0; 32]));
        key.copy_from_slice(bytes);
        Self(key)
    }

    /// Borrow secret bytes. Do not log them or retain unprotected copies.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for PresharedKey {
    fn clone(&self) -> Self {
        Self::new(self.as_bytes())
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[test]
    fn ownership_moves_without_moving_bytes_and_clones_wipe_independently() {
        fn zeroizing_owner<T: ZeroizeOnDrop>(_: &T) {}
        let first = PresharedKey::new(&[0xa5; 32]);
        zeroizing_owner(&*first.0);
        let address = first.as_bytes().as_ptr();
        let mut moved = Some(first);
        assert_eq!(moved.as_ref().unwrap().as_bytes().as_ptr(), address);
        let copy = moved.as_ref().unwrap().clone();
        assert_ne!(copy.as_bytes().as_ptr(), address);
        moved.as_mut().unwrap().0.zeroize();
        assert_eq!(moved.as_ref().unwrap().as_bytes(), &[0; 32]);
        assert_eq!(copy.as_bytes(), &[0xa5; 32]);
        assert_eq!(format!("{copy:?}"), "PresharedKey(<redacted>)");
    }
}
