//! The VMI session: owns the `vmi_fd` and wraps every vmi_fd ioctl.

use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::{
    access::MemAccess,
    core::{ViewId, ioctl_none, ioctl_with_mut_ref, ioctl_with_ref},
    error::KvmError,
};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::{KvmControl, KvmInjectEvent};

#[cfg(target_arch = "aarch64")]
use crate::arch::arm64::{KvmControl, KvmInjectEvent};

/// A VMI session created from a KVM VM fd via `KVM_CREATE_VMI`.
pub struct KvmVmi {
    /// The owned `vmi_fd`.
    fd: OwnedFd,
}

impl KvmVmi {
    /// Creates a session by issuing `KVM_CREATE_VMI` on the given VM fd.
    pub fn create(vm_fd: BorrowedFd) -> Result<Self, KvmError> {
        let ret = ioctl_none(vm_fd, kvm_sys::KVM_CREATE_VMI)?;
        // SAFETY: a successful KVM_CREATE_VMI returns a fresh owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(ret) };
        Ok(Self { fd })
    }

    /// Returns a borrow of the underlying `vmi_fd`, for mmap and ring setup.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Pauses all vCPUs (synchronous: all are out of guest mode on return).
    pub fn pause_vm(&self) -> Result<(), KvmError> {
        ioctl_none(self.fd(), kvm_sys::KVM_VMI_PAUSE_VM)?;
        Ok(())
    }

    /// Unpauses all vCPUs (refcounted).
    pub fn unpause_vm(&self) -> Result<(), KvmError> {
        ioctl_none(self.fd(), kvm_sys::KVM_VMI_UNPAUSE_VM)?;
        Ok(())
    }

    /// Pauses a single vCPU.
    pub fn pause_vcpu(&self, vcpu_id: u32) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_vcpu {
            vcpu_id,
            ..Default::default()
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_PAUSE_VCPU, &arg)?;
        Ok(())
    }

    /// Unpauses a single vCPU.
    pub fn unpause_vcpu(&self, vcpu_id: u32) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_vcpu {
            vcpu_id,
            ..Default::default()
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_UNPAUSE_VCPU, &arg)?;
        Ok(())
    }

    /// Acknowledges a delivered event so the blocked vCPU resumes.
    pub fn ack_event(&self, vcpu_id: u32) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_vcpu {
            vcpu_id,
            ..Default::default()
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_ACK_EVENT, &arg)?;
        Ok(())
    }

    /// Enables or disables an event monitor.
    pub fn control_event(&self, control: KvmControl, enable: bool) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_control_event {
            event: control.event_id(),
            enable: enable as u32,
            arch: control.arch_data(),
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_CONTROL_EVENT, &arg)?;
        Ok(())
    }

    /// Creates an alternate view, returning its kernel-assigned id.
    pub fn create_view(&self, default_access: MemAccess) -> Result<ViewId, KvmError> {
        let mut arg = kvm_sys::kvm_vmi_view {
            default_access: default_access.bits(),
            ..Default::default()
        };
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_VMI_CREATE_VIEW, &mut arg)?;
        Ok(ViewId(arg.view_id))
    }

    /// Destroys an alternate view.
    pub fn destroy_view(&self, view: ViewId) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_view {
            view_id: view.0,
            ..Default::default()
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_DESTROY_VIEW, &arg)?;
        Ok(())
    }

    /// Switches all vCPUs to a view.
    pub fn switch_view(&self, view: ViewId) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_switch_view {
            view_id: view.0,
            ..Default::default()
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_SWITCH_VIEW, &arg)?;
        Ok(())
    }

    /// Sets per-GFN access in a view (single GFN).
    pub fn set_mem_access(
        &self,
        view: ViewId,
        gfn: u64,
        access: MemAccess,
    ) -> Result<(), KvmError> {
        let mut arg = kvm_sys::kvm_vmi_mem_access {
            view_id: view.0,
            nr: 1,
            ..Default::default()
        };
        // Writing the single-GFN arm of the union (nr == 1 selects it) is safe.
        arg.__bindgen_anon_1.__bindgen_anon_1.gfn = gfn;
        arg.__bindgen_anon_1.__bindgen_anon_1.access = access.bits();
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_SET_MEM_ACCESS, &arg)?;
        Ok(())
    }

    /// Queries per-GFN access in a view (single GFN).
    pub fn get_mem_access(&self, view: ViewId, gfn: u64) -> Result<MemAccess, KvmError> {
        let mut arg = kvm_sys::kvm_vmi_mem_access {
            view_id: view.0,
            nr: 1,
            ..Default::default()
        };
        // Writing the single-GFN arm of the union is safe.
        arg.__bindgen_anon_1.__bindgen_anon_1.gfn = gfn;
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_VMI_GET_MEM_ACCESS, &mut arg)?;
        // SAFETY: kernel filled the single-GFN arm.
        let bits = unsafe { arg.__bindgen_anon_1.__bindgen_anon_1.access };
        Ok(MemAccess::from_bits_truncate(bits))
    }

    /// Remaps `old_gfn` to `new_gfn` in a view.
    pub fn change_gfn(&self, view: ViewId, old_gfn: u64, new_gfn: u64) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_change_gfn {
            view_id: view.0,
            old_gfn,
            new_gfn,
            ..Default::default()
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_CHANGE_GFN, &arg)?;
        Ok(())
    }

    /// Allocates a shadow GFN, returning it.
    pub fn alloc_gfn(&self) -> Result<u64, KvmError> {
        let mut arg = kvm_sys::kvm_vmi_alloc_gfn::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_VMI_ALLOC_GFN, &mut arg)?;
        Ok(arg.gfn)
    }

    /// Frees a shadow GFN.
    pub fn free_gfn(&self, gfn: u64) -> Result<(), KvmError> {
        let arg = kvm_sys::kvm_vmi_free_gfn { gfn };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_FREE_GFN, &arg)?;
        Ok(())
    }

    /// Injects an exception/interrupt/NMI into a vCPU.
    pub fn inject_event(&self, event: KvmInjectEvent) -> Result<(), KvmError> {
        let arg = event.to_sys();
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_INJECT_EVENT, &arg)?;
        Ok(())
    }

    /// Sets up a vCPU ring, returning the ring fd (OUT). `event_fd`/`ack_fd`
    /// are agent-created eventfds passed in.
    pub fn setup_ring(
        &self,
        vcpu_id: u32,
        event_fd: i32,
        ack_fd: i32,
    ) -> Result<OwnedFd, KvmError> {
        let mut arg = kvm_sys::kvm_vmi_setup_ring {
            vcpu_id,
            event_fd,
            ack_fd,
            ring_fd: -1,
            ..Default::default()
        };
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_VMI_SETUP_RING, &mut arg)?;
        // SAFETY: kernel returned a fresh owned ring fd.
        Ok(unsafe { OwnedFd::from_raw_fd(arg.ring_fd) })
    }

    /// Tears down a vCPU ring.
    pub fn teardown_ring(&self, vcpu_id: u32) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_VMI_TEARDOWN_RING, &vcpu_id)?;
        Ok(())
    }
}
