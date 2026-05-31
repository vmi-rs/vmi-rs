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
