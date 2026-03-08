//! Guest physical memory mapping.

use std::ops::{Deref, DerefMut};
use std::os::fd::RawFd;

use crate::consts::{self, PAGE_SIZE};
use crate::error::KvmError;

bitflags::bitflags! {
    /// Memory access permissions.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryAccess: u8 {
        const READ = consts::KVM_VMI_ACCESS_R;
        const WRITE = consts::KVM_VMI_ACCESS_W;
        const EXECUTE = consts::KVM_VMI_ACCESS_X;
    }
}

/// A mapped guest physical page. Unmapped on drop.
pub struct KvmMappedPage {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for KvmMappedPage {}

impl KvmMappedPage {
    /// Map a guest physical page via the vmi_fd.
    pub fn new(vmi_fd: RawFd, gfn: u64, writable: bool) -> Result<Self, KvmError> {
        let offset = gfn * PAGE_SIZE;
        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE as usize,
                prot,
                libc::MAP_SHARED,
                vmi_fd,
                offset as libc::off_t,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            len: PAGE_SIZE as usize,
        })
    }
}

impl Drop for KvmMappedPage {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { libc::munmap(self.ptr as _, self.len) };
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
