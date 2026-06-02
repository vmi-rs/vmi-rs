//! arm64 native register and event types for the KVM VMI bindings.

mod control;
mod event;
mod regs;

pub use self::{
    control::{KvmControl, KvmInjectEvent, KvmInjectType},
    event::{KvmBreakpointEvent, KvmEventReasonArm64, KvmSysregEvent, KvmVmiRegsArm64},
    regs::{CoreReg, Registers, core_reg_id, sysreg_id},
};

pub use self::regs::{
    CONTEXTIDR_EL1, ESR_EL1, FAR_EL1, MAIR_EL1, SCTLR_EL1, TCR_EL1, TPIDR_EL0, TPIDR_EL1,
    TPIDRRO_EL0, TTBR0_EL1, TTBR1_EL1, VBAR_EL1,
};

pub(crate) use self::event::decode_event;
