//! x86 native monitor-control and event-injection parameters.

use crate::arch::x86::KvmCr;

impl KvmCr {
    /// Returns the `KVM_VMI_CR*`/`XCR0` index constant for this register.
    pub(crate) fn index(self) -> u32 {
        match self {
            KvmCr::Cr0 => kvm_sys::KVM_VMI_CR0,
            KvmCr::Cr3 => kvm_sys::KVM_VMI_CR3,
            KvmCr::Cr4 => kvm_sys::KVM_VMI_CR4,
            KvmCr::Xcr0 => kvm_sys::KVM_VMI_XCR0,
        }
    }
}

/// A monitor-control request: which event to enable/disable plus its params.
#[derive(Debug, Clone, Copy)]
pub enum KvmControl {
    /// Control-register write monitoring.
    Cr {
        /// Which control register.
        reg: KvmCr,

        /// Only report writes that change the value.
        on_change_only: bool,
    },

    /// MSR write monitoring for one MSR index.
    Msr(u32),

    /// CPUID interception.
    CpuId,

    /// I/O instruction interception.
    Io,

    /// Software breakpoint (INT3) interception.
    Breakpoint,

    /// Debug exception interception.
    Debug,

    /// Single-step trap interception.
    Singlestep,

    /// Guest hypercall interception.
    Hypercall,
}

impl KvmControl {
    /// Returns the `KVM_VMI_EVENT_*` id this control targets.
    pub(crate) fn event_id(&self) -> u32 {
        match self {
            KvmControl::Cr { .. } => kvm_sys::KVM_VMI_EVENT_CR,
            KvmControl::Msr(_) => kvm_sys::KVM_VMI_EVENT_MSR,
            KvmControl::CpuId => kvm_sys::KVM_VMI_EVENT_CPUID,
            KvmControl::Io => kvm_sys::KVM_VMI_EVENT_IO,
            KvmControl::Breakpoint => kvm_sys::KVM_VMI_EVENT_BREAKPOINT,
            KvmControl::Debug => kvm_sys::KVM_VMI_EVENT_DEBUG,
            KvmControl::Singlestep => kvm_sys::KVM_VMI_EVENT_SINGLESTEP,
            KvmControl::Hypercall => kvm_sys::KVM_VMI_EVENT_HYPERCALL,
        }
    }

    /// Returns the arch control-data union for this control.
    pub(crate) fn arch_data(&self) -> kvm_sys::kvm_vmi_arch_control_data {
        let mut arch = kvm_sys::kvm_vmi_arch_control_data::default();
        match self {
            KvmControl::Cr {
                reg,
                on_change_only,
            } => {
                arch.cr.index = reg.index() as u8;
                arch.cr.onchangeonly = u8::from(*on_change_only);
            }
            KvmControl::Msr(msr) => {
                arch.msr.msr = *msr;
            }
            KvmControl::CpuId
            | KvmControl::Io
            | KvmControl::Breakpoint
            | KvmControl::Debug
            | KvmControl::Singlestep
            | KvmControl::Hypercall => {}
        }
        arch
    }
}

/// VMCS interruption-type encoding for event injection.
#[derive(Debug, Clone, Copy)]
pub enum KvmInjectType {
    /// External interrupt.
    ExtInt,

    /// Non-maskable interrupt.
    Nmi,

    /// Hardware exception.
    HwExcept,

    /// Software interrupt.
    SwInt,

    /// Privileged software exception (ICEBP).
    PrivSwInt,

    /// Software exception (INT3/INTO).
    SwExcept,
}

impl KvmInjectType {
    /// Returns the VMCS interruption-type encoding for this type.
    pub(crate) fn encode(self) -> u8 {
        let value = match self {
            KvmInjectType::ExtInt => kvm_sys::KVM_VMI_EVENT_TYPE_EXT_INT,
            KvmInjectType::Nmi => kvm_sys::KVM_VMI_EVENT_TYPE_NMI,
            KvmInjectType::HwExcept => kvm_sys::KVM_VMI_EVENT_TYPE_HW_EXCEPT,
            KvmInjectType::SwInt => kvm_sys::KVM_VMI_EVENT_TYPE_SW_INT,
            KvmInjectType::PrivSwInt => kvm_sys::KVM_VMI_EVENT_TYPE_PRIV_SW_INT,
            KvmInjectType::SwExcept => kvm_sys::KVM_VMI_EVENT_TYPE_SW_EXCEPT,
        };
        value as u8
    }
}

/// An event to inject into a vCPU (exception/interrupt/NMI).
#[derive(Debug, Clone, Copy)]
pub struct KvmInjectEvent {
    /// Target vCPU.
    pub vcpu_id: u32,

    /// Interrupt/exception vector.
    pub vector: u8,

    /// VMCS event-type encoding.
    pub type_: KvmInjectType,

    /// Faulting-instruction length (for software events).
    pub insn_len: u8,

    /// Error code, when the vector pushes one.
    pub error_code: Option<u32>,

    /// CR2 value for page-fault injection.
    pub cr2: u64,
}

impl KvmInjectEvent {
    /// Lowers to the uAPI inject-event struct.
    pub(crate) fn to_sys(self) -> kvm_sys::kvm_vmi_inject_event {
        kvm_sys::kvm_vmi_inject_event {
            vcpu_id: self.vcpu_id,
            vector: self.vector,
            type_: self.type_.encode(),
            insn_len: self.insn_len,
            pad: 0,
            error_code: self.error_code.unwrap_or(0),
            has_error: u32::from(self.error_code.is_some()),
            cr2: self.cr2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_control_sets_index_and_onchange() {
        for (reg, expected) in [
            (KvmCr::Cr0, kvm_sys::KVM_VMI_CR0),
            (KvmCr::Cr3, kvm_sys::KVM_VMI_CR3),
            (KvmCr::Cr4, kvm_sys::KVM_VMI_CR4),
            (KvmCr::Xcr0, kvm_sys::KVM_VMI_XCR0),
        ] {
            let c = KvmControl::Cr {
                reg,
                on_change_only: true,
            };
            assert_eq!(c.event_id(), kvm_sys::KVM_VMI_EVENT_CR);
            let arch = c.arch_data();
            // SAFETY: cr arm just written.
            unsafe {
                assert_eq!(arch.cr.index as u32, expected);
                assert_eq!(arch.cr.onchangeonly, 1);
            }
        }
    }

    #[test]
    fn inject_without_error_code_clears_has_error() {
        let e = KvmInjectEvent {
            vcpu_id: 1,
            vector: 3,
            type_: KvmInjectType::SwExcept,
            insn_len: 1,
            error_code: None,
            cr2: 0,
        };
        let sys = e.to_sys();
        assert_eq!(sys.has_error, 0);
        assert_eq!(sys.error_code, 0);
    }

    #[test]
    fn inject_with_error_code_sets_has_error() {
        let e = KvmInjectEvent {
            vcpu_id: 0,
            vector: 14,
            type_: KvmInjectType::HwExcept,
            insn_len: 0,
            error_code: Some(6),
            cr2: 0xdead_0000,
        };
        let sys = e.to_sys();
        assert_eq!(sys.has_error, 1);
        assert_eq!(sys.error_code, 6);
        assert_eq!(sys.cr2, 0xdead_0000);
    }
}
