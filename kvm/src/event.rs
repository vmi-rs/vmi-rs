//! Native, decoded VMI event types (arch-neutral envelope).

use crate::{
    access::MemAccess,
    arch::x86::{KvmEventReasonX86, KvmVmiRegsX86},
};

/// In-event register snapshot, arch-split like `xen::ctrl::VmEventRegs`.
#[derive(Debug, Clone, Copy)]
pub enum KvmVmiRegs {
    /// x86 register snapshot.
    X86(KvmVmiRegsX86),
}

/// Arch-neutral memory-access event payload.
#[derive(Debug, Clone, Copy)]
pub struct KvmMemAccessEvent {
    /// Faulting guest-physical address.
    pub gpa: u64,

    /// Access that was attempted.
    pub access: MemAccess,
}

/// Arch-neutral single-step event payload.
#[derive(Debug, Clone, Copy)]
pub struct KvmSinglestepEvent {
    /// Guest-physical address of the stepped instruction.
    pub gpa: u64,
}

/// Reason an event was delivered. Arch-neutral reasons are direct variants and
/// arch-specific ones nest under `Arch`.
#[derive(Debug, Clone, Copy)]
pub enum KvmEventReason {
    /// EPT/access-permission violation.
    MemAccess(KvmMemAccessEvent),

    /// Single-step trap.
    Singlestep(KvmSinglestepEvent),

    /// Guest hypercall (VMCALL).
    Hypercall,

    /// Architecture-specific reason.
    Arch(KvmEventReasonX86),
}

/// One decoded VMI event read off a ring slot.
#[derive(Debug, Clone, Copy)]
pub struct KvmVmiEvent {
    /// vCPU that produced the event.
    pub vcpu_id: u32,

    /// View the vCPU was in.
    pub view_id: u32,

    /// Faulting-instruction length, when the event carries one.
    pub insn_len: u8,

    /// Register snapshot embedded in the event.
    pub regs: KvmVmiRegs,

    /// Why the event fired.
    pub reason: KvmEventReason,
}

/// What the agent tells the kernel to do when the vCPU resumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmResponseAction {
    /// Resume normally.
    Continue,

    /// Suppress the faulting operation.
    Deny,

    /// Emulate the faulting instruction.
    Emulate,

    /// Reinject the original interrupt/exception.
    Reinject,

    /// Single-step one instruction.
    Singlestep,

    /// Single-step then switch view atomically.
    FastSinglestep,
}

/// The agent's response to one event, written back into the slot on `respond`.
#[derive(Debug, Clone, Copy)]
pub struct KvmVmiResponse {
    /// Action to apply on resume.
    pub action: KvmResponseAction,

    /// Replacement register values, when registers were modified.
    pub regs: Option<KvmVmiRegs>,

    /// View to switch to on resume, when a switch was requested.
    pub view_id: Option<u32>,
}

impl KvmVmiResponse {
    /// Composes the raw `KVM_VMI_RESPONSE_*` flag word for this response.
    pub(crate) fn flags(&self) -> u32 {
        let mut flags = kvm_sys::KVM_VMI_RESPONSE_CONTINUE;
        match self.action {
            KvmResponseAction::Continue => {}
            KvmResponseAction::Deny => flags |= kvm_sys::KVM_VMI_RESPONSE_DENY,
            KvmResponseAction::Emulate => flags |= kvm_sys::KVM_VMI_RESPONSE_EMULATE,
            KvmResponseAction::Reinject => flags |= kvm_sys::KVM_VMI_RESPONSE_REINJECT,
            KvmResponseAction::Singlestep => flags |= kvm_sys::KVM_VMI_RESPONSE_SINGLESTEP,
            KvmResponseAction::FastSinglestep => flags |= kvm_sys::KVM_VMI_RESPONSE_SINGLESTEP_FAST,
        }
        if self.regs.is_some() {
            flags |= kvm_sys::KVM_VMI_RESPONSE_SET_REGS;
        }
        if self.view_id.is_some() {
            flags |= kvm_sys::KVM_VMI_RESPONSE_SWITCH_VIEW;
        }
        flags
    }
}
