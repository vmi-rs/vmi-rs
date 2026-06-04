//! arm64 native monitor-control and event-injection parameters.

/// A monitor-control request for arm64: which event to enable/disable.
///
/// The arm64 uAPI defines a `kvm_vmi_arch_control_data` union for future
/// arch-specific parameters. None of the variants implemented here carry
/// arch-specific data, so all use the zeroed control data.
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
}

impl KvmControl {
    /// Returns the `KVM_VMI_EVENT_*` id this control targets.
    pub(crate) fn event_id(&self) -> u32 {
        match self {
            KvmControl::Singlestep => kvm_sys::KVM_VMI_EVENT_SINGLESTEP,
            KvmControl::Hypercall => kvm_sys::KVM_VMI_EVENT_HYPERCALL,
            KvmControl::MemAccess => kvm_sys::KVM_VMI_EVENT_MEM_ACCESS,
            KvmControl::Breakpoint => kvm_sys::KVM_VMI_EVENT_BREAKPOINT,
        }
    }

    /// Returns the arch control-data union for this control.
    ///
    /// None of the implemented controls carries arch-specific data, so this
    /// returns the zeroed default.
    pub(crate) fn arch_data(&self) -> kvm_sys::kvm_vmi_arch_control_data {
        kvm_sys::kvm_vmi_arch_control_data::default()
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
