//! Alternate memory view management.

use crate::consts;
use crate::error::KvmError;
use crate::session::{KvmVmiSession, kvm_ioctl};

/// An alternate memory view. Destroyed on drop.
pub struct KvmVmiView {
    session: KvmVmiSession,
    view_id: u32,
}

impl KvmVmiView {
    /// Create a new alternate memory view with the given default access.
    pub fn new(session: KvmVmiSession, default_access: u8) -> Result<Self, KvmError> {
        let mut view = kvm_sys::kvm_vmi_view {
            view_id: 0,
            flags: 0,
            default_access,
            ..Default::default()
        };

        unsafe {
            kvm_ioctl(
                session.fd(),
                consts::KVM_VMI_CREATE_VIEW,
                &mut view as *mut _ as u64,
            )?;
        }

        tracing::trace!(view_id = view.view_id, "created VMI view");
        Ok(Self {
            session,
            view_id: view.view_id,
        })
    }

    /// The view identifier assigned by the kernel.
    pub fn id(&self) -> u32 {
        self.view_id
    }

    /// Switch a vCPU to this view.
    pub fn switch(&self, vcpu_id: u32) -> Result<(), KvmError> {
        let sw = kvm_sys::kvm_vmi_switch_view {
            vcpu_id,
            view_id: self.view_id,
        };
        unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_SWITCH_VIEW,
                &sw as *const _ as u64,
            )?;
        }
        Ok(())
    }

    /// Query the access permissions for a GFN in this view.
    pub fn get_mem_access(&self, gfn: u64) -> Result<u8, KvmError> {
        let mut ma = kvm_sys::kvm_vmi_mem_access {
            view_id: self.view_id,
            nr: 1,
            gfn,
            ..Default::default()
        };
        unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_GET_MEM_ACCESS,
                &mut ma as *mut _ as u64,
            )?;
        }
        Ok(ma.access)
    }

    /// Set the access permissions for a GFN in this view.
    pub fn set_mem_access(&self, gfn: u64, access: u8) -> Result<(), KvmError> {
        let ma = kvm_sys::kvm_vmi_mem_access {
            view_id: self.view_id,
            nr: 1,
            access,
            gfn,
            ..Default::default()
        };
        unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_SET_MEM_ACCESS,
                &ma as *const _ as u64,
            )?;
        }
        Ok(())
    }

    /// Remap a GFN to point to a different backing page in this view.
    pub fn change_gfn(&self, old_gfn: u64, new_gfn: u64) -> Result<(), KvmError> {
        let change = kvm_sys::kvm_vmi_change_gfn {
            view_id: self.view_id,
            pad: 0,
            old_gfn,
            new_gfn,
        };
        unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_CHANGE_GFN,
                &change as *const _ as u64,
            )?;
        }
        Ok(())
    }
}

impl Drop for KvmVmiView {
    fn drop(&mut self) {
        tracing::trace!(view_id = self.view_id, "destroying VMI view");
        let view = kvm_sys::kvm_vmi_view {
            view_id: self.view_id,
            ..Default::default()
        };
        let _ = unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_DESTROY_VIEW,
                &view as *const _ as u64,
            )
        };
    }
}
