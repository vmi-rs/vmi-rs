//! Safe event types converted from ring event data.

/// Event reason extracted from a ring event.
#[derive(Debug, Clone, Copy)]
pub enum KvmVmiEventReason {
    /// EPT violation with VMI permissions.
    MemoryAccess { gpa: u64, access: u32 },
    /// Control register write.
    Cr { index: u32, old_value: u64, new_value: u64 },
    /// MSR write.
    Msr { index: u32, old_value: u64, new_value: u64 },
    /// CPUID instruction.
    Cpuid { leaf: u32, subleaf: u32 },
    /// Software breakpoint (INT3).
    Breakpoint { gpa: u64, insn_len: u32 },
    /// MTF single-step completed.
    Singlestep { gpa: u64 },
    /// Debug exception (DR access).
    Debug { pending_dbg: u64 },
    /// Descriptor table register access.
    DescAccess { descriptor: u8, is_write: bool },
    /// Interrupt injection.
    Interrupt { vector: u32, error_code: u32, cr2: u64 },
    /// I/O port access.
    Io { port: u16, bytes: u8, direction: u8, string: bool },
}

/// A VMI event extracted from a ring event.
#[derive(Debug, Clone, Copy)]
pub struct KvmVmiEvent {
    /// The reason/type of event.
    pub reason: KvmVmiEventReason,
    /// The vCPU that generated this event.
    pub vcpu_id: u32,
    /// The view the vCPU was in when the event occurred.
    pub view_id: u32,
}

impl KvmVmiEvent {
    /// Parse a ring event into a safe `KvmVmiEvent`.
    ///
    /// # Safety
    ///
    /// The `raw` event must have been produced by the kernel and have a
    /// valid `type_` field. Accessing union fields requires matching on
    /// the correct variant.
    pub unsafe fn from_raw(raw: &kvm_sys::kvm_vmi_ring_event) -> Option<Self> {
        let reason = unsafe {
            match raw.type_ {
                kvm_sys::KVM_VMI_EVENT_MEM_ACCESS => {
                    let d = &raw.u.mem_access;
                    KvmVmiEventReason::MemoryAccess {
                        gpa: d.gpa,
                        access: d.access,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_CR => {
                    let d = &raw.u.cr;
                    KvmVmiEventReason::Cr {
                        index: d.index,
                        old_value: d.old_value,
                        new_value: d.new_value,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_MSR => {
                    let d = &raw.u.msr;
                    KvmVmiEventReason::Msr {
                        index: d.index,
                        old_value: d.old_value,
                        new_value: d.new_value,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_CPUID => {
                    let d = &raw.u.cpuid;
                    KvmVmiEventReason::Cpuid {
                        leaf: d.leaf,
                        subleaf: d.subleaf,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_BREAKPOINT => {
                    let d = &raw.u.breakpoint;
                    KvmVmiEventReason::Breakpoint {
                        gpa: d.gpa,
                        insn_len: d.insn_len,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_SINGLESTEP => {
                    let d = &raw.u.singlestep;
                    KvmVmiEventReason::Singlestep { gpa: d.gpa }
                }
                kvm_sys::KVM_VMI_EVENT_DEBUG => {
                    let d = &raw.u.debug;
                    KvmVmiEventReason::Debug {
                        pending_dbg: d.pending_dbg,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_DESC_ACCESS => {
                    let d = &raw.u.desc_access;
                    KvmVmiEventReason::DescAccess {
                        descriptor: d.descriptor,
                        is_write: d.is_write != 0,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_INTERRUPT => {
                    let d = &raw.u.interrupt;
                    KvmVmiEventReason::Interrupt {
                        vector: d.vector,
                        error_code: d.error_code,
                        cr2: d.cr2,
                    }
                }
                kvm_sys::KVM_VMI_EVENT_IO => {
                    let d = &raw.u.io;
                    KvmVmiEventReason::Io {
                        port: d.port,
                        bytes: d.bytes,
                        direction: d.in_,
                        string: d.string != 0,
                    }
                }
                _ => return None,
            }
        };

        Some(Self {
            reason,
            vcpu_id: raw.vcpu_id,
            view_id: raw.view_id,
        })
    }
}
