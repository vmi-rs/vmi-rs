//! arm64 native monitor-control and event-injection parameters.

/// A monitor-control request for arm64: which event to enable/disable.
///
/// The arm64 uAPI defines a `kvm_vmi_arch_control_data` union for arch-specific
/// parameters. Only `Sysreg` carries such data, the others use the zeroed
/// control data.
#[derive(Debug, Clone, Copy)]
pub enum KvmControl {
    /// Single-step trap interception.
    Singlestep,

    /// Guest hypercall interception.
    Hypercall,

    /// Memory-access (stage-2 fault) interception.
    MemAccess,

    /// Software-breakpoint (`BRK`) interception.
    Breakpoint,

    /// System-register write interception (e.g. `TTBR0_EL1`).
    Sysreg {
        /// `KVM_VMI_SYSREG_*` register index.
        reg: u32,

        /// Deliver only when the value changes.
        onchangeonly: bool,

        /// Fire only when `((old ^ new) & bitmask) != 0`. A `0` mask fires on
        /// any change.
        bitmask: u64,
    },
}

impl KvmControl {
    /// Returns the `KVM_VMI_EVENT_*` id this control targets.
    pub(crate) fn event_id(&self) -> u32 {
        match self {
            KvmControl::Singlestep => kvm_sys::KVM_VMI_EVENT_SINGLESTEP,
            KvmControl::Hypercall => kvm_sys::KVM_VMI_EVENT_HYPERCALL,
            KvmControl::MemAccess => kvm_sys::KVM_VMI_EVENT_MEM_ACCESS,
            KvmControl::Breakpoint => kvm_sys::KVM_VMI_EVENT_BREAKPOINT,
            KvmControl::Sysreg { .. } => kvm_sys::KVM_VMI_EVENT_SYSREG,
        }
    }

    /// Returns the arch control-data union for this control.
    ///
    /// Only `Sysreg` carries arch-specific data, so every other control returns
    /// the zeroed default.
    pub(crate) fn arch_data(&self) -> kvm_sys::kvm_vmi_arch_control_data {
        match self {
            KvmControl::Sysreg {
                reg,
                onchangeonly,
                bitmask,
            } => kvm_sys::kvm_vmi_arch_control_data {
                sysreg: kvm_sys::kvm_vmi_arch_control_data__bindgen_ty_1 {
                    reg: *reg as u8,
                    onchangeonly: u8::from(*onchangeonly),
                    pad: [0; 6],
                    bitmask: *bitmask,
                },
            },
            _ => kvm_sys::kvm_vmi_arch_control_data::default(),
        }
    }
}

/// arm64 inject-event type: SError or synchronous abort.
#[derive(Debug, Clone, Copy)]
pub enum KvmInjectType {
    /// SError interrupt (`KVM_VMI_INJECT_SERROR`).
    Serror,

    /// Synchronous abort (`KVM_VMI_INJECT_ABORT`).
    Abort,
}

impl KvmInjectType {
    /// Returns the `KVM_VMI_INJECT_*` encoding for this type.
    pub(crate) fn encode(self) -> u32 {
        match self {
            KvmInjectType::Serror => kvm_sys::KVM_VMI_INJECT_SERROR,
            KvmInjectType::Abort => kvm_sys::KVM_VMI_INJECT_ABORT,
        }
    }
}

/// An event to inject into a vCPU (SError or synchronous abort).
#[derive(Debug, Clone, Copy)]
pub struct KvmInjectEvent {
    /// Target vCPU.
    pub vcpu_id: u32,

    /// Injection type.
    pub type_: KvmInjectType,

    /// Fault address for synchronous aborts.
    pub addr: u64,

    /// Exception syndrome register value.
    pub esr: u64,

    /// True for instruction aborts.
    pub iabt: bool,

    /// True when `esr` is valid.
    pub has_esr: bool,

    /// Fault status code.
    pub fsc: u8,

    /// True for write faults.
    pub write: bool,
}

impl KvmInjectEvent {
    /// Lowers to the uAPI inject-event struct.
    pub(crate) fn to_sys(self) -> kvm_sys::kvm_vmi_inject_event {
        kvm_sys::kvm_vmi_inject_event {
            vcpu_id: self.vcpu_id,
            type_: self.type_.encode(),
            addr: self.addr,
            esr: self.esr,
            iabt: u8::from(self.iabt),
            has_esr: u8::from(self.has_esr),
            fsc: self.fsc,
            write: u8::from(self.write),
            pad: [0; 4],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_control_targets_breakpoint_event() {
        assert_eq!(
            KvmControl::Breakpoint.event_id(),
            kvm_sys::KVM_VMI_EVENT_BREAKPOINT
        );
    }

    #[test]
    fn sysreg_control_targets_sysreg_event() {
        let c = KvmControl::Sysreg {
            reg: kvm_sys::KVM_VMI_SYSREG_TTBR0_EL1,
            onchangeonly: true,
            bitmask: 0,
        };
        assert_eq!(c.event_id(), kvm_sys::KVM_VMI_EVENT_SYSREG);
        // SAFETY: single-member union.
        let s = unsafe { c.arch_data().sysreg };
        assert_eq!(u32::from(s.reg), kvm_sys::KVM_VMI_SYSREG_TTBR0_EL1);
        assert_eq!(s.onchangeonly, 1);
    }

    #[test]
    fn inject_serror_encodes_type() {
        let e = KvmInjectEvent {
            vcpu_id: 0,
            type_: KvmInjectType::Serror,
            addr: 0,
            esr: 0,
            iabt: false,
            has_esr: false,
            fsc: 0,
            write: false,
        };
        let sys = e.to_sys();
        assert_eq!(sys.type_, kvm_sys::KVM_VMI_INJECT_SERROR);
        assert_eq!(sys.has_esr, 0);
    }

    #[test]
    fn inject_abort_with_esr() {
        let e = KvmInjectEvent {
            vcpu_id: 1,
            type_: KvmInjectType::Abort,
            addr: 0xdead_0000,
            esr: 0x9200_0007,
            iabt: false,
            has_esr: true,
            fsc: 7,
            write: true,
        };
        let sys = e.to_sys();
        assert_eq!(sys.type_, kvm_sys::KVM_VMI_INJECT_ABORT);
        assert_eq!(sys.addr, 0xdead_0000);
        assert_eq!(sys.esr, 0x9200_0007);
        assert_eq!(sys.has_esr, 1);
        assert_eq!(sys.fsc, 7);
        assert_eq!(sys.write, 1);
    }
}
