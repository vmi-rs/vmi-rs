//! Fault-based guest-memory mapping over the `vmi_fd`.

use std::os::fd::{AsRawFd, BorrowedFd};

use crate::error::KvmError;

/// Page size used for fixed-size vmi_fd mappings (the per-vCPU event ring).
pub const PAGE_SIZE: usize = 4096;

/// Returns the running host's page size, the granule the vmi_fd mmap interface
/// works in. The kernel rejects an mmap offset that is not a multiple of it,
/// and the vmi_fd fault handler reads `pgoff = offset >> host_page_shift` as a
/// KVM gfn, whose frame size is this host page size.
pub fn host_page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) is always valid and returns a positive
    // power-of-two page size on every supported host.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    size as usize
}

/// One mmap'd guest page. Unmaps on drop.
///
/// On a host whose page size exceeds the guest page (for example a 16K-page
/// arm64 host introspecting a 4K-page guest) the underlying mmap covers the
/// enclosing host page. For an ordinary guest gfn the slice exposed to callers
/// is the guest page window inside that host page. For a shadow gfn (a
/// host-page kernel allocation) the slice is the full host page, so callers can
/// read and write all of the shadow that replaces the enclosing host frame.
pub struct KvmMappedPage {
    /// Start of the underlying mmap (host-page aligned), for munmap.
    base: *mut u8,

    /// Length of the underlying mmap in bytes, for munmap.
    base_len: usize,

    /// Start of the guest page window inside the mapping.
    ptr: *mut u8,

    /// Length of the guest page window in bytes.
    len: usize,
}

impl KvmMappedPage {
    /// Returns the guest page bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr/len address the guest page window inside the mapping.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Returns the guest page bytes mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see as_slice; mapping is MAP_SHARED with PROT_WRITE.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

// SAFETY: KvmMappedPage exclusively owns its mmap region and unmaps it once on
// drop. Moving it across threads is safe.
unsafe impl Send for KvmMappedPage {}

impl Drop for KvmMappedPage {
    fn drop(&mut self) {
        // SAFETY: base/base_len came from mmap and are unmapped exactly once.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.base_len);
        }
    }
}

/// Maps guest pages on demand via `mmap` on the vmi_fd, translating a gfn into
/// the host-page-aligned offset the kernel fault handler expects.
pub struct KvmGuestMemory;

impl KvmGuestMemory {
    /// Maps a single guest page identified by `gfn`. `write` selects
    /// PROT_READ|PROT_WRITE vs PROT_READ.
    pub fn map_page(
        vmi_fd: BorrowedFd,
        gfn: u64,
        page_shift: u8,
        write: bool,
    ) -> Result<KvmMappedPage, KvmError> {
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        // The caller asks for the guest page identified by `gfn` in its own
        // granule (`1 << page_shift`). The vmi_fd mmap interface, however,
        // works in host pages: the offset must be host-page aligned or the
        // kernel returns EINVAL, and the fault handler reads `gfn = vmf->pgoff
        // = offset >> host_page_shift` as the KVM gfn to resolve.
        let guest_page = 1usize << page_shift;
        let host_page = host_page_size();
        let host_shift = host_page.trailing_zeros();

        // A shadow gfn returned by `alloc_gfn` is already a host-page gfn in the
        // kernel's `shadow_pages` xarray, keyed verbatim by `vmf->pgoff`. The
        // guest-to-host page-unit conversion below must not be applied to it, or
        // `pgoff` no longer matches the xarray key and the fault handler raises
        // SIGBUS. Place it at `offset = shadow_gfn << host_shift` so the kernel
        // recovers the exact key, and expose a guest-page window at the start of
        // the host page. On a host whose page size equals the guest granule both
        // branches coincide.
        let shadow = gfn >= kvm_sys::KVM_VMI_SHADOW_GFN_BASE;
        let (aligned, sub) = if shadow {
            (gfn << host_shift, 0usize)
        } else {
            // Align the guest PA down to the enclosing host page and expose the
            // guest page window inside it.
            let guest_pa = gfn << page_shift;
            let aligned = guest_pa & !(host_page as u64 - 1);
            let sub = (guest_pa - aligned) as usize;
            (aligned, sub)
        };

        // A shadow gfn replaces a whole host frame, so expose the full host page
        // and let callers read and write all of it. An ordinary guest gfn
        // exposes only its guest page window. On a host whose page size equals
        // the guest granule both windows are identical.
        let window = if shadow { host_page } else { guest_page };
        let base_len = (sub + window).next_multiple_of(host_page);

        // SAFETY: standard mmap; null addr lets the kernel choose.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                base_len,
                prot,
                libc::MAP_SHARED,
                vmi_fd.as_raw_fd(),
                aligned as libc::off_t,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(KvmError::last_os_error());
        }
        Ok(KvmMappedPage {
            base: base as *mut u8,
            base_len,
            // SAFETY: sub < base_len, so this stays inside the mapping.
            ptr: unsafe { (base as *mut u8).add(sub) },
            len: window,
        })
    }
}
