//! x86 in-event register and event types, plus the ring-slot union decode.

use crate::{
    access::MemAccess,
    error::KvmError,
    event::{KvmEventReason, KvmMemAccessEvent, KvmSinglestepEvent, KvmVmiEvent, KvmVmiRegs},
};

/// One x86 segment in the packed in-event layout (mirrors
/// `kvm_vmi_regs__bindgen_ty_1`: base, limit, selector, VMX AR word).
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmSegmentX86 {
    /// Segment base.
    pub base: u64,

    /// Segment limit.
    pub limit: u32,

    /// Segment selector.
    pub selector: u16,

    /// VMX access-rights word.
    pub ar: u16,
}

/// In-event register snapshot (mirrors `kvm_vmi_regs`). Field names match the
/// uAPI struct so `From` is a direct copy.
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmVmiRegsX86 {
    /// RAX.
    pub rax: u64,

    /// RBX.
    pub rbx: u64,

    /// RCX.
    pub rcx: u64,

    /// RDX.
    pub rdx: u64,

    /// RSI.
    pub rsi: u64,

    /// RDI.
    pub rdi: u64,

    /// RBP.
    pub rbp: u64,

    /// RSP.
    pub rsp: u64,

    /// R8.
    pub r8: u64,

    /// R9.
    pub r9: u64,

    /// R10.
    pub r10: u64,

    /// R11.
    pub r11: u64,

    /// R12.
    pub r12: u64,

    /// R13.
    pub r13: u64,

    /// R14.
    pub r14: u64,

    /// R15.
    pub r15: u64,

    /// Instruction pointer.
    pub rip: u64,

    /// RFLAGS.
    pub rflags: u64,

    /// CR0.
    pub cr0: u64,

    /// CR3.
    pub cr3: u64,

    /// CR4.
    pub cr4: u64,

    /// XCR0.
    pub xcr0: u64,

    /// CS segment.
    pub cs: KvmSegmentX86,

    /// SS segment.
    pub ss: KvmSegmentX86,

    /// DS segment.
    pub ds: KvmSegmentX86,

    /// ES segment.
    pub es: KvmSegmentX86,

    /// FS segment.
    pub fs: KvmSegmentX86,

    /// GS segment.
    pub gs: KvmSegmentX86,

    /// `IA32_SYSENTER_CS`.
    pub sysenter_cs: u64,

    /// `IA32_SYSENTER_ESP`.
    pub sysenter_esp: u64,

    /// `IA32_SYSENTER_EIP`.
    pub sysenter_eip: u64,

    /// `IA32_EFER`.
    pub msr_efer: u64,

    /// `IA32_STAR`.
    pub msr_star: u64,

    /// `IA32_LSTAR`.
    pub msr_lstar: u64,

    /// `IA32_CSTAR`.
    pub msr_cstar: u64,

    /// `IA32_FMASK` (syscall flag mask).
    pub msr_syscall_mask: u64,

    /// `IA32_KERNEL_GS_BASE` (the swapped-out GS base).
    pub msr_kernel_gs_base: u64,

    /// `IA32_TSC_AUX`.
    pub msr_tsc_aux: u64,
}

impl From<&kvm_sys::kvm_vmi_regs> for KvmVmiRegsX86 {
    fn from(value: &kvm_sys::kvm_vmi_regs) -> Self {
        /// Copies one packed in-event segment into `KvmSegmentX86`.
        fn seg(s: &kvm_sys::kvm_vmi_regs__bindgen_ty_1) -> KvmSegmentX86 {
            KvmSegmentX86 {
                base: s.base,
                limit: s.limit,
                selector: s.selector,
                ar: s.ar,
            }
        }

        Self {
            rax: value.rax,
            rbx: value.rbx,
            rcx: value.rcx,
            rdx: value.rdx,
            rsi: value.rsi,
            rdi: value.rdi,
            rbp: value.rbp,
            rsp: value.rsp,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rip: value.rip,
            rflags: value.rflags,
            cr0: value.cr0,
            cr3: value.cr3,
            cr4: value.cr4,
            xcr0: value.xcr0,
            cs: seg(&value.cs),
            ss: seg(&value.ss),
            ds: seg(&value.ds),
            es: seg(&value.es),
            fs: seg(&value.fs),
            gs: seg(&value.gs),
            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            msr_efer: value.msr_efer,
            msr_star: value.msr_star,
            msr_lstar: value.msr_lstar,
            msr_cstar: value.msr_cstar,
            msr_syscall_mask: value.msr_syscall_mask,
            msr_kernel_gs_base: value.msr_kernel_gs_base,
            msr_tsc_aux: value.msr_tsc_aux,
        }
    }
}

impl From<&KvmVmiRegsX86> for kvm_sys::kvm_vmi_regs {
    fn from(value: &KvmVmiRegsX86) -> Self {
        /// Packs one `KvmSegmentX86` back into the in-event segment layout.
        fn unseg(s: &KvmSegmentX86) -> kvm_sys::kvm_vmi_regs__bindgen_ty_1 {
            kvm_sys::kvm_vmi_regs__bindgen_ty_1 {
                base: s.base,
                limit: s.limit,
                selector: s.selector,
                ar: s.ar,
            }
        }

        Self {
            rax: value.rax,
            rbx: value.rbx,
            rcx: value.rcx,
            rdx: value.rdx,
            rsi: value.rsi,
            rdi: value.rdi,
            rbp: value.rbp,
            rsp: value.rsp,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rip: value.rip,
            rflags: value.rflags,
            cr0: value.cr0,
            cr3: value.cr3,
            cr4: value.cr4,
            xcr0: value.xcr0,
            cs: unseg(&value.cs),
            ss: unseg(&value.ss),
            ds: unseg(&value.ds),
            es: unseg(&value.es),
            fs: unseg(&value.fs),
            gs: unseg(&value.gs),
            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            msr_efer: value.msr_efer,
            msr_star: value.msr_star,
            msr_lstar: value.msr_lstar,
            msr_cstar: value.msr_cstar,
            msr_syscall_mask: value.msr_syscall_mask,
            msr_kernel_gs_base: value.msr_kernel_gs_base,
            msr_tsc_aux: value.msr_tsc_aux,
        }
    }
}

/// Which control register a CR write event targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmCr {
    /// CR0.
    Cr0,

    /// CR3.
    Cr3,

    /// CR4.
    Cr4,

    /// XCR0.
    Xcr0,
}

/// Payload of a CR write event.
#[derive(Debug, Clone, Copy)]
pub struct KvmCrEvent {
    /// Control register written.
    pub index: KvmCr,

    /// Value before the write.
    pub old: u64,

    /// Value the guest attempted to write.
    pub new: u64,
}

/// Payload of an MSR write event.
#[derive(Debug, Clone, Copy)]
pub struct KvmMsrEvent {
    /// MSR index written.
    pub index: u32,

    /// Value before the write.
    pub old: u64,

    /// Value the guest attempted to write.
    pub new: u64,
}

/// Payload of a CPUID event.
#[derive(Debug, Clone, Copy)]
pub struct KvmCpuidEvent {
    /// Leaf (EAX) requested.
    pub leaf: u32,

    /// Subleaf (ECX) requested.
    pub subleaf: u32,
}

/// Payload of a software breakpoint event.
#[derive(Debug, Clone, Copy)]
pub struct KvmBreakpointEvent {
    /// Guest-physical address of the breakpoint.
    pub gpa: u64,
}

/// Payload of a debug-exception event.
#[derive(Debug, Clone, Copy)]
pub struct KvmDebugEvent {
    /// Guest-physical address of the faulting instruction.
    pub gpa: u64,

    /// Pending debug-exception bits.
    pub pending_dbg: u64,
}

/// Payload of an I/O-instruction event.
#[derive(Debug, Clone, Copy)]
pub struct KvmIoEvent {
    /// I/O port accessed.
    pub port: u16,

    /// Access width in bytes.
    pub bytes: u8,

    /// True for IN, false for OUT.
    pub in_: bool,

    /// True for a string (REP) I/O instruction.
    pub string: bool,
}

/// x86-specific event reasons, nested under `KvmEventReason::Arch`.
#[derive(Debug, Clone, Copy)]
pub enum KvmEventReasonX86 {
    /// MOV to CR0/CR3/CR4 or XSETBV to XCR0.
    WriteCr(KvmCrEvent),

    /// WRMSR to a monitored MSR.
    WriteMsr(KvmMsrEvent),

    /// CPUID execution.
    CpuId(KvmCpuidEvent),

    /// Software breakpoint (INT3).
    Breakpoint(KvmBreakpointEvent),

    /// Debug exception.
    Debug(KvmDebugEvent),

    /// I/O instruction (IN/OUT).
    Io(KvmIoEvent),
}

/// Maps the KVM CR index constant to `KvmCr`.
// Wired into the ring read path by the event-loop migration; until then it is
// exercised only by `decode_event` and the decode tests.
#[allow(dead_code)]
fn cr_from_index(index: u32) -> Option<KvmCr> {
    match index {
        x if x == kvm_sys::KVM_VMI_CR0 => Some(KvmCr::Cr0),
        x if x == kvm_sys::KVM_VMI_CR3 => Some(KvmCr::Cr3),
        x if x == kvm_sys::KVM_VMI_CR4 => Some(KvmCr::Cr4),
        x if x == kvm_sys::KVM_VMI_XCR0 => Some(KvmCr::Xcr0),
        _ => None,
    }
}

/// Decodes one ring-slot record into a native event. This is the only place the
/// `kvm_vmi_ring_event` union is read and every arm is gated by `type_`.
// The ring read path consumes this in the event-loop migration. For now it is
// covered by the decode tests below.
#[allow(dead_code)]
pub(crate) fn decode_event(slot: &kvm_sys::kvm_vmi_ring_event) -> Result<KvmVmiEvent, KvmError> {
    let regs = KvmVmiRegs::X86(KvmVmiRegsX86::from(&slot.regs));
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
    } else if kind == kvm_sys::KVM_VMI_EVENT_CR {
        // SAFETY: type_ selects the arch.cr arm.
        let cr = unsafe { slot.__bindgen_anon_1.arch.cr };
        let index = match cr_from_index(cr.index) {
            Some(index) => index,
            None => return Err(KvmError::Other("unknown CR index in event")),
        };
        KvmEventReason::Arch(KvmEventReasonX86::WriteCr(KvmCrEvent {
            index,
            old: cr.old_value,
            new: cr.new_value,
        }))
    } else if kind == kvm_sys::KVM_VMI_EVENT_MSR {
        // SAFETY: type_ selects the arch.msr arm.
        let msr = unsafe { slot.__bindgen_anon_1.arch.msr };
        KvmEventReason::Arch(KvmEventReasonX86::WriteMsr(KvmMsrEvent {
            index: msr.index,
            old: msr.old_value,
            new: msr.new_value,
        }))
    } else if kind == kvm_sys::KVM_VMI_EVENT_CPUID {
        // SAFETY: type_ selects the arch.cpuid arm.
        let c = unsafe { slot.__bindgen_anon_1.arch.cpuid };
        KvmEventReason::Arch(KvmEventReasonX86::CpuId(KvmCpuidEvent {
            leaf: c.leaf,
            subleaf: c.subleaf,
        }))
    } else if kind == kvm_sys::KVM_VMI_EVENT_BREAKPOINT {
        // SAFETY: type_ selects the arch.breakpoint arm.
        let bp = unsafe { slot.__bindgen_anon_1.arch.breakpoint };
        KvmEventReason::Arch(KvmEventReasonX86::Breakpoint(KvmBreakpointEvent {
            gpa: bp.gpa,
        }))
    } else if kind == kvm_sys::KVM_VMI_EVENT_DEBUG {
        // SAFETY: type_ selects the arch.debug arm.
        let d = unsafe { slot.__bindgen_anon_1.arch.debug };
        KvmEventReason::Arch(KvmEventReasonX86::Debug(KvmDebugEvent {
            gpa: d.gpa,
            pending_dbg: d.pending_dbg,
        }))
    } else if kind == kvm_sys::KVM_VMI_EVENT_IO {
        // SAFETY: type_ selects the arch.io arm.
        let io = unsafe { slot.__bindgen_anon_1.arch.io };
        KvmEventReason::Arch(KvmEventReasonX86::Io(KvmIoEvent {
            port: io.port,
            bytes: io.bytes,
            in_: io.in_ != 0,
            string: io.string != 0,
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
    fn decodes_cr_write() {
        let mut slot = empty_slot();
        slot.type_ = kvm_sys::KVM_VMI_EVENT_CR;
        slot.vcpu_id = 2;
        slot.__bindgen_anon_1.arch.cr = kvm_sys::kvm_vmi_event_cr {
            index: kvm_sys::KVM_VMI_CR3,
            pad: 0,
            old_value: 0x1000,
            new_value: 0x2000,
        };
        let ev = decode_event(&slot).unwrap();
        assert_eq!(ev.vcpu_id, 2);
        assert!(matches!(ev.regs, KvmVmiRegs::X86(_)));
        match ev.reason {
            KvmEventReason::Arch(KvmEventReasonX86::WriteCr(cr)) => {
                assert_eq!(cr.index, KvmCr::Cr3);
                assert_eq!(cr.old, 0x1000);
                assert_eq!(cr.new, 0x2000);
            }
            other => panic!("wrong reason: {other:?}"),
        }
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
    fn unknown_type_errors() {
        let mut slot = empty_slot();
        slot.type_ = 0xffff_ffff;
        assert!(decode_event(&slot).is_err());
    }

    #[test]
    fn regs_round_trip() {
        let sys = kvm_sys::kvm_vmi_regs {
            rax: 0x1122_3344,
            rip: 0xdead_beef,
            cr3: 0x5000,
            xcr0: 0x7,
            msr_lstar: 0xffff_8000_0000_0000,
            cs: kvm_sys::kvm_vmi_regs__bindgen_ty_1 {
                base: 0,
                limit: 0xfffff,
                selector: 0x10,
                ar: 0xa09b,
            },
            ..Default::default()
        };
        let native = KvmVmiRegsX86::from(&sys);
        assert_eq!(native.rax, 0x1122_3344);
        assert_eq!(native.rip, 0xdead_beef);
        assert_eq!(native.cr3, 0x5000);
        assert_eq!(native.xcr0, 0x7);
        assert_eq!(native.msr_lstar, 0xffff_8000_0000_0000);
        assert_eq!(native.cs.ar, 0xa09b);
        let back = kvm_sys::kvm_vmi_regs::from(&native);
        assert_eq!(back.rax, sys.rax);
        assert_eq!(back.rip, sys.rip);
        assert_eq!(back.cr3, sys.cr3);
        assert_eq!(back.xcr0, sys.xcr0);
        assert_eq!(back.msr_lstar, sys.msr_lstar);
        assert_eq!(back.cs.limit, sys.cs.limit);
        assert_eq!(back.cs.selector, sys.cs.selector);
        assert_eq!(back.cs.ar, sys.cs.ar);
    }
}
