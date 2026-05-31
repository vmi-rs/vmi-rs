//! A duplicated KVM vCPU fd, used for standard register ioctls.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::{
    core::{ioctl_with_mut_ref, ioctl_with_ref},
    error::KvmError,
};

/// Wraps one duplicated vCPU fd. Register ioctls work because a paused vCPU
/// has released `vcpu->mutex`.
pub struct KvmVcpu {
    /// The owned vCPU fd.
    fd: OwnedFd,
}

impl KvmVcpu {
    /// Wraps an already-duplicated vCPU fd.
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Borrows the underlying fd.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Reads general-purpose registers via `KVM_GET_REGS`.
    pub fn get_regs(&self) -> Result<kvm_sys::kvm_regs, KvmError> {
        let mut regs = kvm_sys::kvm_regs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_REGS, &mut regs)?;
        Ok(regs)
    }

    /// Writes general-purpose registers via `KVM_SET_REGS`.
    pub fn set_regs(&self, regs: &kvm_sys::kvm_regs) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_REGS, regs)?;
        Ok(())
    }

    /// Reads special registers via `KVM_GET_SREGS`.
    pub fn get_sregs(&self) -> Result<kvm_sys::kvm_sregs, KvmError> {
        let mut sregs = kvm_sys::kvm_sregs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_SREGS, &mut sregs)?;
        Ok(sregs)
    }

    /// Writes special registers via `KVM_SET_SREGS`.
    pub fn set_sregs(&self, sregs: &kvm_sys::kvm_sregs) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_SREGS, sregs)?;
        Ok(())
    }

    /// Reads debug registers via `KVM_GET_DEBUGREGS`.
    pub fn get_debugregs(&self) -> Result<kvm_sys::kvm_debugregs, KvmError> {
        let mut dregs = kvm_sys::kvm_debugregs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_DEBUGREGS, &mut dregs)?;
        Ok(dregs)
    }

    /// Reads the given MSRs. `entries` is filled with index/data pairs. The
    /// data fields are populated on return.
    pub fn get_msrs(&self, entries: &mut [kvm_sys::kvm_msr_entry]) -> Result<(), KvmError> {
        // kvm_msrs is a flexible-array struct: header + entries[]. Build a byte
        // buffer of the right size.
        let nmsrs = entries.len();
        let header = std::mem::size_of::<kvm_sys::kvm_msrs>();
        let nwords = (header + std::mem::size_of_val(entries)).div_ceil(8);
        let mut buf = vec![0u64; nwords];
        // SAFETY: buf is aligned to 8 bytes (Vec<u64>) and large enough for the header.
        let msrs = buf.as_mut_ptr() as *mut kvm_sys::kvm_msrs;
        unsafe {
            (*msrs).nmsrs = nmsrs as u32;
            let dst = (*msrs).__bindgen_anon_1.entries.as_mut_ptr();
            std::ptr::copy_nonoverlapping(entries.as_ptr(), dst, nmsrs);
            let ret = libc::ioctl(self.fd().as_raw_fd(), kvm_sys::KVM_GET_MSRS as _, msrs);
            if ret < 0 {
                return Err(KvmError::last_os_error());
            }
            std::ptr::copy_nonoverlapping(
                (*msrs).__bindgen_anon_1.entries.as_ptr(),
                entries.as_mut_ptr(),
                nmsrs,
            );
        }
        Ok(())
    }
}
