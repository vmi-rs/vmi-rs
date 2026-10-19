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

/// One mmap'd host page. Unmaps on drop.
///
/// The vmi_fd mmap interface works in host pages, so the mapping always covers
/// a whole host frame. Callers that want a smaller guest-page window narrow it
/// at a higher layer (see [`VmiMappedPage::window`] in `vmi-core`).
pub struct KvmMappedPage {
    /// Start of the underlying mmap (host-page aligned), for munmap.
    base: *mut u8,

    /// Length of the underlying mmap in bytes, for munmap.
    base_len: usize,

    /// Start of the exposed bytes (equal to `base`).
    ptr: *mut u8,

    /// Length of the exposed bytes in bytes (one host page).
    len: usize,
}

impl KvmMappedPage {
    /// Returns the host page bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr/len address the host page mapping.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Returns the host page bytes mutably.
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

/// Maps host pages on demand via `mmap` on the vmi_fd, placing a host frame at
/// the host-page-aligned offset the kernel fault handler expects.
pub struct KvmGuestMemory;

impl KvmGuestMemory {
    /// Maps a single host page identified by `hfn`. `write` selects
    /// PROT_READ|PROT_WRITE vs PROT_READ.
    pub fn map_page(
        vmi_fd: BorrowedFd,
        hfn: u64,
        write: bool,
    ) -> Result<KvmMappedPage, KvmError> {
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        // The vmi_fd mmap interface works in host pages: `hfn` names the host
        // frame, the offset must be host-page aligned, and the fault handler
        // reads `gfn = vmf->pgoff = offset >> host_page_shift`. A shadow gfn from
        // alloc_gfn is already a host-page key, and a normal host frame derived
        // from a guest gfn is too, so both place at `hfn << host_shift`.
        let host_page = host_page_size();
        let host_shift = host_page.trailing_zeros();
        let aligned = hfn << host_shift;

        // SAFETY: standard mmap; null addr lets the kernel choose.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                host_page,
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
            base_len: host_page,
            ptr: base as *mut u8,
            len: host_page,
        })
    }
}
