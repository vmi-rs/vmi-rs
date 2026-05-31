//! Fault-based guest-memory mapping over the `vmi_fd`.

use std::os::fd::{AsRawFd, BorrowedFd};

use crate::error::KvmError;

/// Page size used for guest-memory mappings.
pub const PAGE_SIZE: usize = 4096;

/// One mmap'd guest page. Unmaps on drop.
pub struct KvmMappedPage {
    /// Start of the mapping.
    ptr: *mut u8,

    /// Length of the mapping in bytes.
    len: usize,
}

impl KvmMappedPage {
    /// Returns the page bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr/len come from a successful mmap of len bytes.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Returns the page bytes mutably.
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
        // SAFETY: ptr/len came from mmap and are unmapped exactly once.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

/// Maps guest pages on demand via `mmap(vmi_fd, offset = gfn << shift)`.
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
        let offset = (gfn << page_shift) as libc::off_t;
        // SAFETY: standard mmap; null addr lets the kernel choose.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                prot,
                libc::MAP_SHARED,
                vmi_fd.as_raw_fd(),
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(KvmError::last_os_error());
        }
        Ok(KvmMappedPage {
            ptr: ptr as *mut u8,
            len: PAGE_SIZE,
        })
    }
}
