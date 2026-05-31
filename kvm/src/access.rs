//! Native, arch-neutral memory-access permission flags.

use bitflags::bitflags;

bitflags! {
    /// Per-GFN access permission bits, mirroring the KVM VMI access mask.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct MemAccess: u8 {
        /// Read permitted.
        const R = kvm_sys::KVM_VMI_ACCESS_R as u8;

        /// Write permitted.
        const W = kvm_sys::KVM_VMI_ACCESS_W as u8;

        /// Execute permitted.
        const X = kvm_sys::KVM_VMI_ACCESS_X as u8;

        /// Page-walk writes trapped while leaving R/W/X as set.
        const PW = kvm_sys::KVM_VMI_ACCESS_PW as u8;
    }
}

impl std::fmt::Display for MemAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut result = [b'-'; 3];
        if self.contains(MemAccess::R) {
            result[0] = b'r';
        }
        if self.contains(MemAccess::W) {
            result[1] = b'w';
        }
        if self.contains(MemAccess::X) {
            result[2] = b'x';
        }
        // SAFETY: The `result` array is always valid UTF-8.
        f.write_str(unsafe { std::str::from_utf8_unchecked(&result) })
    }
}

#[cfg(test)]
mod tests {
    use super::MemAccess;

    #[test]
    fn display_renders_rwx() {
        assert_eq!(MemAccess::empty().to_string(), "---");
        assert_eq!(MemAccess::R.to_string(), "r--");
        assert_eq!((MemAccess::R | MemAccess::X).to_string(), "r-x");
        assert_eq!(
            (MemAccess::R | MemAccess::W | MemAccess::X).to_string(),
            "rwx"
        );
    }

    #[test]
    fn bits_match_uapi() {
        assert_eq!(MemAccess::R.bits(), kvm_sys::KVM_VMI_ACCESS_R as u8);
        assert_eq!(MemAccess::PW.bits(), kvm_sys::KVM_VMI_ACCESS_PW as u8);
    }
}
