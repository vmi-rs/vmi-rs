//! Guest physical memory mapping.

use std::ops::{Deref, DerefMut};
use std::os::fd::RawFd;

use crate::consts::PAGE_SIZE;
use crate::error::KvmError;

bitflags::bitflags! {
    /// Memory access permissions.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryAccess: u8 {
        const READ = kvm_sys::KVM_VMI_ACCESS_R as u8;
        const WRITE = kvm_sys::KVM_VMI_ACCESS_W as u8;
        const EXECUTE = kvm_sys::KVM_VMI_ACCESS_X as u8;
    }
}

/// A mapped guest physical page. Unmapped on drop.
///
/// On hosts with page sizes larger than 4KB (e.g., 16KB on Apple Silicon),
/// we map the containing host page and expose only the 4KB guest page
/// within it.
pub struct KvmMappedPage {
    /// Pointer to the start of the 4KB guest page within the mapping.
    ptr: *mut u8,
    /// Size of the guest page (always 4KB).
    len: usize,
    /// Pointer to the start of the mmap'd region (host-page-aligned).
    mmap_ptr: *mut u8,
    /// Size of the mmap'd region (host page size).
    mmap_len: usize,
}

unsafe impl Send for KvmMappedPage {}

impl KvmMappedPage {
    /// Map a guest physical page via the vmi_fd.
    ///
    /// The mmap offset must be aligned to the host page size. When the
    /// host page size exceeds the guest page size (4KB), we map the
    /// containing host page and return a view into the correct 4KB
    /// sub-page.
    pub fn new(vmi_fd: RawFd, gfn: u64, writable: bool) -> Result<Self, KvmError> {
        let guest_offset = gfn * PAGE_SIZE;
        let host_page_size = host_page_size() as u64;

        // Align down to host page boundary.
        let mmap_offset = guest_offset & !(host_page_size - 1);
        let sub_page_offset = (guest_offset - mmap_offset) as usize;
        let mmap_len = host_page_size as usize;

        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_len,
                prot,
                libc::MAP_SHARED,
                vmi_fd,
                mmap_offset as libc::off_t,
            )
        };

        if mmap_ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }

        let ptr = unsafe { (mmap_ptr as *mut u8).add(sub_page_offset) };

        Ok(Self {
            ptr,
            len: PAGE_SIZE as usize,
            mmap_ptr: mmap_ptr as *mut u8,
            mmap_len,
        })
    }
}

/// Returns the host page size (cached after first call).
fn host_page_size() -> usize {
    static HOST_PAGE_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *HOST_PAGE_SIZE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize })
}

impl Drop for KvmMappedPage {
    fn drop(&mut self) {
        if !self.mmap_ptr.is_null() {
            unsafe { libc::munmap(self.mmap_ptr as _, self.mmap_len) };
        }
    }
}

impl Deref for KvmMappedPage {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl DerefMut for KvmMappedPage {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl AsRef<[u8]> for KvmMappedPage {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for KvmMappedPage {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}
