//! KVM VMI session management.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;

use crate::consts;
use crate::error::KvmError;

/// Raw ioctl helper. Returns `Err(io::Error)` on failure.
pub(crate) unsafe fn kvm_ioctl(
    fd: RawFd,
    request: libc::c_ulong,
    arg: u64,
) -> std::io::Result<i32> {
    let ret = unsafe { libc::ioctl(fd, request, arg) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Owned vmi_fd handle. Closes the fd on drop.
#[derive(Debug)]
pub(crate) struct KvmVmiHandle {
    fd: OwnedFd,
}

impl KvmVmiHandle {
    fn new(vm_fd: RawFd) -> Result<Self, KvmError> {
        let vmi_fd = unsafe { kvm_ioctl(vm_fd, consts::KVM_CREATE_VMI, 0)? };
        let fd = unsafe { OwnedFd::from_raw_fd(vmi_fd) };
        tracing::trace!(vmi_fd, "created KVM VMI session");
        Ok(Self { fd })
    }
}

/// KVM VMI session.
///
/// Reference-counted wrapper around the `vmi_fd`. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct KvmVmiSession {
    pub(crate) handle: Rc<KvmVmiHandle>,
}

impl KvmVmiSession {
    /// Open a VMI session on the given KVM VM file descriptor.
    pub fn new(vm_fd: RawFd) -> Result<Self, KvmError> {
        Ok(Self {
            handle: Rc::new(KvmVmiHandle::new(vm_fd)?),
        })
    }

    /// Returns the raw vmi_fd for ioctl calls.
    pub fn fd(&self) -> RawFd {
        self.handle.fd.as_raw_fd()
    }

    /// Pause all vCPUs.
    pub fn pause_vm(&self) -> Result<(), KvmError> {
        unsafe { kvm_ioctl(self.fd(), consts::KVM_VMI_PAUSE_VM, 0)? };
        Ok(())
    }

    /// Unpause all vCPUs.
    pub fn unpause_vm(&self) -> Result<(), KvmError> {
        unsafe { kvm_ioctl(self.fd(), consts::KVM_VMI_UNPAUSE_VM, 0)? };
        Ok(())
    }

    /// Pause a specific vCPU.
    pub fn pause_vcpu(&self, vcpu_id: u32) -> Result<(), KvmError> {
        let vcpu = kvm_sys::kvm_vmi_vcpu {
            vcpu_id,
            ..Default::default()
        };
        unsafe {
            kvm_ioctl(
                self.fd(),
                consts::KVM_VMI_PAUSE_VCPU,
                &vcpu as *const _ as u64,
            )?;
        }
        Ok(())
    }

    /// Unpause a specific vCPU.
    pub fn unpause_vcpu(&self, vcpu_id: u32) -> Result<(), KvmError> {
        let vcpu = kvm_sys::kvm_vmi_vcpu {
            vcpu_id,
            ..Default::default()
        };
        unsafe {
            kvm_ioctl(
                self.fd(),
                consts::KVM_VMI_UNPAUSE_VCPU,
                &vcpu as *const _ as u64,
            )?;
        }
        Ok(())
    }

    /// Allocate a shadow GFN from the kernel's pool.
    pub fn alloc_gfn(&self) -> Result<u64, KvmError> {
        let mut alloc = kvm_sys::kvm_vmi_alloc_gfn::default();
        unsafe {
            kvm_ioctl(
                self.fd(),
                consts::KVM_VMI_ALLOC_GFN,
                &mut alloc as *mut _ as u64,
            )?;
        }
        Ok(alloc.gfn)
    }

    /// Free a shadow GFN.
    pub fn free_gfn(&self, gfn: u64) -> Result<(), KvmError> {
        let free = kvm_sys::kvm_vmi_free_gfn { gfn };
        unsafe {
            kvm_ioctl(
                self.fd(),
                consts::KVM_VMI_FREE_GFN,
                &free as *const _ as u64,
            )?;
        }
        Ok(())
    }

    /// Enable or disable singlestepping for a vCPU.
    pub fn singlestep(&self, vcpu_id: u32, enable: bool) -> Result<(), KvmError> {
        let ss = kvm_sys::kvm_vmi_singlestep {
            vcpu_id,
            enable: u32::from(enable),
        };
        unsafe {
            kvm_ioctl(
                self.fd(),
                consts::KVM_VMI_SINGLESTEP,
                &ss as *const _ as u64,
            )?;
        }
        Ok(())
    }

    /// Inject an event into a vCPU.
    pub fn inject_event(
        &self,
        vcpu_id: u32,
        vector: u8,
        typ: u8,
        error_code: u32,
        has_error: bool,
        cr2: u64,
    ) -> Result<(), KvmError> {
        let inject = kvm_sys::kvm_vmi_inject_event {
            vcpu_id,
            vector,
            type_: typ,
            padding: 0,
            error_code,
            has_error: u32::from(has_error),
            cr2,
        };
        unsafe {
            kvm_ioctl(
                self.fd(),
                consts::KVM_VMI_INJECT_EVENT,
                &inject as *const _ as u64,
            )?;
        }
        Ok(())
    }
}
