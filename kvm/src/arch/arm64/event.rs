//! arm64 in-event register and event types, plus the ring-slot union decode.

use crate::{
    access::MemAccess,
    error::KvmError,
    event::{KvmEventReason, KvmMemAccessEvent, KvmSinglestepEvent, KvmVmiEvent, KvmVmiRegs},
};

/// In-event register snapshot for arm64 (mirrors `kvm_vmi_regs`). Field names
/// match the uAPI struct so `From` is a direct copy.
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmVmiRegsArm64 {
    /// General-purpose registers x0-x30.
    pub regs: [u64; 31],

    /// Stack pointer at EL0.
    pub sp_el0: u64,

    /// Stack pointer at EL1.
    pub sp_el1: u64,

    /// Program counter.
    pub pc: u64,

    /// Processor state.
    pub pstate: u64,

    /// Translation table base register 0 at EL1.
    pub ttbr0_el1: u64,

    /// Translation table base register 1 at EL1.
    pub ttbr1_el1: u64,

    /// Translation control register at EL1.
    pub tcr_el1: u64,

    /// System control register at EL1.
    pub sctlr_el1: u64,

    /// Memory attribute indirection register at EL1.
    pub mair_el1: u64,

    /// Vector base address register at EL1.
    pub vbar_el1: u64,

    /// Context ID register at EL1.
    pub contextidr_el1: u64,

    /// Exception link register at EL1.
    pub elr_el1: u64,

    /// Saved program status register at EL1.
    pub spsr_el1: u64,

    /// Exception syndrome register at EL1.
    pub esr_el1: u64,

    /// Fault address register at EL1.
    pub far_el1: u64,

    /// Thread ID register (EL0 read/write).
    pub tpidr_el0: u64,

    /// Thread ID register at EL1.
    pub tpidr_el1: u64,

    /// Thread ID register (EL0 read-only).
    pub tpidrro_el0: u64,
}

impl From<&kvm_sys::kvm_vmi_regs> for KvmVmiRegsArm64 {
    fn from(value: &kvm_sys::kvm_vmi_regs) -> Self {
        Self {
            regs: value.regs,
            sp_el0: value.sp_el0,
            sp_el1: value.sp_el1,
            pc: value.pc,
            pstate: value.pstate,
            ttbr0_el1: value.ttbr0_el1,
            ttbr1_el1: value.ttbr1_el1,
            tcr_el1: value.tcr_el1,
            sctlr_el1: value.sctlr_el1,
            mair_el1: value.mair_el1,
            vbar_el1: value.vbar_el1,
            contextidr_el1: value.contextidr_el1,
            elr_el1: value.elr_el1,
            spsr_el1: value.spsr_el1,
            esr_el1: value.esr_el1,
            far_el1: value.far_el1,
            tpidr_el0: value.tpidr_el0,
            tpidr_el1: value.tpidr_el1,
            tpidrro_el0: value.tpidrro_el0,
        }
    }
}

impl From<&KvmVmiRegsArm64> for kvm_sys::kvm_vmi_regs {
    fn from(value: &KvmVmiRegsArm64) -> Self {
        Self {
            regs: value.regs,
            sp_el0: value.sp_el0,
            sp_el1: value.sp_el1,
            pc: value.pc,
            pstate: value.pstate,
            ttbr0_el1: value.ttbr0_el1,
            ttbr1_el1: value.ttbr1_el1,
            tcr_el1: value.tcr_el1,
            sctlr_el1: value.sctlr_el1,
            mair_el1: value.mair_el1,
            vbar_el1: value.vbar_el1,
            contextidr_el1: value.contextidr_el1,
            elr_el1: value.elr_el1,
            spsr_el1: value.spsr_el1,
            esr_el1: value.esr_el1,
            far_el1: value.far_el1,
            tpidr_el0: value.tpidr_el0,
            tpidr_el1: value.tpidr_el1,
            tpidrro_el0: value.tpidrro_el0,
        }
    }
}

/// Payload of a sysreg-write event.
#[derive(Debug, Clone, Copy)]
pub struct KvmSysregEvent {
    /// Encoded system register id (`KVM_VMI_SYSREG_*`).
    pub reg: u64,

    /// Register value before the (deferred) write.
    pub old_value: u64,

    /// Value the guest is writing (observe-only).
    pub new_value: u64,
}

/// Payload of a software breakpoint event.
#[derive(Debug, Clone, Copy)]
pub struct KvmBreakpointEvent {
    /// Guest-physical address of the breakpoint.
    pub gpa: u64,
}

/// arm64-specific event reasons, nested under `KvmEventReason::Arch`.
#[derive(Debug, Clone, Copy)]
pub enum KvmEventReasonArm64 {
    /// System-register access.
    Sysreg(KvmSysregEvent),

    /// Software breakpoint.
    Breakpoint(KvmBreakpointEvent),
}

/// Decodes one ring-slot record into a native event. This is the only place the
/// `kvm_vmi_ring_event` union is read and every arm is gated by `type_`.
pub(crate) fn decode_event(slot: &kvm_sys::kvm_vmi_ring_event) -> Result<KvmVmiEvent, KvmError> {
    let regs = KvmVmiRegs::Arm64(KvmVmiRegsArm64::from(&slot.regs));
    let kind = slot.type_;
    let insn_len = slot.insn_len;

    let reason = if kind == kvm_sys::KVM_VMI_EVENT_MEM_ACCESS {
        // SAFETY: type_ selects the mem_access arm.
        let m = unsafe { slot.__bindgen_anon_1.mem_access };
        KvmEventReason::MemAccess(KvmMemAccessEvent {
            gpa: m.gpa,
            access: MemAccess::from_bits_truncate(m.access as u8),
        })
    } else if kind == kvm_sys::KVM_VMI_EVENT_SINGLESTEP {
        // SAFETY: type_ selects the singlestep arm.
        let ss = unsafe { slot.__bindgen_anon_1.singlestep };
        KvmEventReason::Singlestep(KvmSinglestepEvent { gpa: ss.gpa })
    } else if kind == kvm_sys::KVM_VMI_EVENT_HYPERCALL {
        KvmEventReason::Hypercall
    } else if kind == kvm_sys::KVM_VMI_EVENT_BREAKPOINT {
        // SAFETY: type_ selects the arch.breakpoint arm. The arm64 payload
        // names the faulting guest-physical address `ipa`.
        let bp = unsafe { slot.__bindgen_anon_1.arch.breakpoint };
        KvmEventReason::Arch(KvmEventReasonArm64::Breakpoint(KvmBreakpointEvent {
            gpa: bp.ipa,
        }))
    } else if kind == kvm_sys::KVM_VMI_EVENT_SYSREG {
        // SAFETY: type_ selects the arch.sysreg arm.
        let sr = unsafe { slot.__bindgen_anon_1.arch.sysreg };
        KvmEventReason::Arch(KvmEventReasonArm64::Sysreg(KvmSysregEvent {
            reg: u64::from(sr.reg),
            old_value: sr.old_value,
            new_value: sr.new_value,
        }))
    } else {
        return Err(KvmError::Other("unknown event type"));
    };

    Ok(KvmVmiEvent {
        vcpu_id: slot.vcpu_id,
        view_id: slot.view_id,
        insn_len,
        regs,
        reason,
    })
}

#[cfg(test)]
mod decode_tests {
    use super::*;
    use crate::event::{KvmEventReason, KvmVmiRegs};

    fn empty_slot() -> kvm_sys::kvm_vmi_ring_event {
        kvm_sys::kvm_vmi_ring_event::default()
    }

    #[test]
    fn decodes_mem_access() {
        let mut slot = empty_slot();
        slot.type_ = kvm_sys::KVM_VMI_EVENT_MEM_ACCESS;
        slot.__bindgen_anon_1.mem_access = kvm_sys::kvm_vmi_event_mem_access {
            gpa: 0xdead000,
            access: kvm_sys::KVM_VMI_ACCESS_R | kvm_sys::KVM_VMI_ACCESS_X,
            pad: 0,
        };
        match decode_event(&slot).unwrap().reason {
            KvmEventReason::MemAccess(m) => {
                assert_eq!(m.gpa, 0xdead000);
                assert!(m.access.contains(crate::MemAccess::R | crate::MemAccess::X));
            }
            other => panic!("wrong reason: {other:?}"),
        }
    }

    #[test]
    fn decodes_breakpoint() {
        let mut slot = empty_slot();
        slot.type_ = kvm_sys::KVM_VMI_EVENT_BREAKPOINT;
        slot.__bindgen_anon_1.arch.breakpoint = kvm_sys::kvm_vmi_event_breakpoint {
            ipa: 0xcafe000,
            imm: 0,
            pad: 0,
        };
        match decode_event(&slot).unwrap().reason {
            KvmEventReason::Arch(KvmEventReasonArm64::Breakpoint(bp)) => {
                assert_eq!(bp.gpa, 0xcafe000);
            }
            other => panic!("wrong reason: {other:?}"),
        }
    }

    #[test]
    fn decodes_sysreg() {
        let mut slot = empty_slot();
        slot.type_ = kvm_sys::KVM_VMI_EVENT_SYSREG;
        slot.__bindgen_anon_1.arch.sysreg = kvm_sys::kvm_vmi_event_sysreg {
            reg: kvm_sys::KVM_VMI_SYSREG_TTBR0_EL1,
            pad: 0,
            old_value: 0x1000,
            new_value: 0x2000,
        };
        match decode_event(&slot).unwrap().reason {
            KvmEventReason::Arch(KvmEventReasonArm64::Sysreg(sr)) => {
                assert_eq!(sr.reg, u64::from(kvm_sys::KVM_VMI_SYSREG_TTBR0_EL1));
                assert_eq!(sr.old_value, 0x1000);
                assert_eq!(sr.new_value, 0x2000);
            }
            other => panic!("wrong reason: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_errors() {
        let mut slot = empty_slot();
        slot.type_ = 0xffff_ffff;
        assert!(decode_event(&slot).is_err());
    }

    #[test]
    fn regs_round_trip() {
        let mut sys = kvm_sys::kvm_vmi_regs::default();
        sys.regs[0] = 0x1122_3344;
        sys.pc = 0xdead_beef;
        sys.ttbr0_el1 = 0x5000;
        let native = KvmVmiRegsArm64::from(&sys);
        assert_eq!(native.regs[0], 0x1122_3344);
        assert_eq!(native.pc, 0xdead_beef);
        assert_eq!(native.ttbr0_el1, 0x5000);
        let back = kvm_sys::kvm_vmi_regs::from(&native);
        assert_eq!(back.regs[0], sys.regs[0]);
        assert_eq!(back.pc, sys.pc);
        assert_eq!(back.ttbr0_el1, sys.ttbr0_el1);
    }

    #[test]
    fn decodes_singlestep() {
        let mut slot = empty_slot();
        slot.type_ = kvm_sys::KVM_VMI_EVENT_SINGLESTEP;
        slot.__bindgen_anon_1.singlestep = kvm_sys::kvm_vmi_event_singlestep { gpa: 0xc000 };
        let ev = decode_event(&slot).unwrap();
        assert!(matches!(ev.regs, KvmVmiRegs::Arm64(_)));
        match ev.reason {
            KvmEventReason::Singlestep(ss) => assert_eq!(ss.gpa, 0xc000),
            other => panic!("wrong reason: {other:?}"),
        }
    }
}
