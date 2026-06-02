//! arm64 register access for KVM_GET_ONE_REG.

/// Base bits shared by every 64-bit arm64 register id.
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;

/// Size field marking a 64-bit register value.
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;

/// Coprocessor field selecting the core-register block.
const KVM_REG_ARM_CORE: u64 = 0x0000_0000_0010_0000;

/// Coprocessor field selecting the system-register block.
const KVM_REG_ARM64_SYSREG: u64 = 0x0000_0000_0013_0000;

/// One addressable core register in `struct kvm_regs`.
#[derive(Debug, Clone, Copy)]
pub enum CoreReg {
    /// General-purpose register `x<n>`, n in 0..=30.
    X(u8),

    /// Stack pointer at EL0 (`regs.sp`).
    Sp,

    /// Program counter (`regs.pc`).
    Pc,

    /// Processor state (`regs.pstate`).
    Pstate,

    /// Holds the EL1 banked stack pointer in the kvm_regs CORE block.
    SpEl1,

    /// Holds the EL1 exception link register in the kvm_regs CORE block.
    ElrEl1,

    /// Holds the EL1 saved program status register in the kvm_regs CORE block.
    SpsrEl1,
}

/// Returns the `kvm_one_reg` id for a core register.
pub fn core_reg_id(reg: CoreReg) -> u64 {
    // Field index = offsetof(struct kvm_regs, field) / sizeof(u32).
    let index = match reg {
        CoreReg::X(n) => (n as u64) * 2,
        CoreReg::Sp => 62,
        CoreReg::Pc => 64,
        CoreReg::Pstate => 66,
        CoreReg::SpEl1 => 68,
        CoreReg::ElrEl1 => 70,
        CoreReg::SpsrEl1 => 72,
    };
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | index
}

/// Returns the `kvm_one_reg` id for a system register by its encoding.
pub const fn sysreg_id(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG
        | ((op0 << 14) & 0xc000)
        | ((op1 << 11) & 0x3800)
        | ((crn << 7) & 0x780)
        | ((crm << 3) & 0x78)
        | (op2 & 0x7)
}

/// `KVM_ONE_REG` id for `TTBR0_EL1`.
pub const TTBR0_EL1: u64 = sysreg_id(3, 0, 2, 0, 0);

/// `KVM_ONE_REG` id for `TTBR1_EL1`.
pub const TTBR1_EL1: u64 = sysreg_id(3, 0, 2, 0, 1);

/// `KVM_ONE_REG` id for `TCR_EL1`.
pub const TCR_EL1: u64 = sysreg_id(3, 0, 2, 0, 2);

/// `KVM_ONE_REG` id for `SCTLR_EL1`.
pub const SCTLR_EL1: u64 = sysreg_id(3, 0, 1, 0, 0);

/// `KVM_ONE_REG` id for `VBAR_EL1`.
pub const VBAR_EL1: u64 = sysreg_id(3, 0, 12, 0, 0);

/// `KVM_ONE_REG` id for `MAIR_EL1`.
pub const MAIR_EL1: u64 = sysreg_id(3, 0, 10, 2, 0);

/// `KVM_ONE_REG` id for `CONTEXTIDR_EL1`.
pub const CONTEXTIDR_EL1: u64 = sysreg_id(3, 0, 13, 0, 1);

/// `KVM_ONE_REG` id for `ESR_EL1`.
pub const ESR_EL1: u64 = sysreg_id(3, 0, 5, 2, 0);

/// `KVM_ONE_REG` id for `FAR_EL1`.
pub const FAR_EL1: u64 = sysreg_id(3, 0, 6, 0, 0);

/// `KVM_ONE_REG` id for `TPIDR_EL0`.
pub const TPIDR_EL0: u64 = sysreg_id(3, 3, 13, 0, 2);

/// `KVM_ONE_REG` id for `TPIDR_EL1`.
pub const TPIDR_EL1: u64 = sysreg_id(3, 0, 13, 0, 4);

/// `KVM_ONE_REG` id for `TPIDRRO_EL0`.
pub const TPIDRRO_EL0: u64 = sysreg_id(3, 3, 13, 0, 3);

/// Full vCPU register context read via `KVM_GET_ONE_REG`. A flat native
/// bundle the driver maps to `vmi_core::Registers`, mirroring
/// `kvm_vmi_regs`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_reg_ids() {
        assert_eq!(core_reg_id(CoreReg::X(0)), 0x6030000000100000);
        assert_eq!(core_reg_id(CoreReg::X(30)), 0x603000000010003c);
        assert_eq!(core_reg_id(CoreReg::Sp), 0x603000000010003e);
        assert_eq!(core_reg_id(CoreReg::Pc), 0x6030000000100040);
        assert_eq!(core_reg_id(CoreReg::Pstate), 0x6030000000100042);
        assert_eq!(core_reg_id(CoreReg::SpEl1), 0x6030000000100044);
        assert_eq!(core_reg_id(CoreReg::ElrEl1), 0x6030000000100046);
        assert_eq!(core_reg_id(CoreReg::SpsrEl1), 0x6030000000100048);
    }

    #[test]
    fn sysreg_ids() {
        assert_eq!(sysreg_id(3, 0, 2, 0, 0), 0x603000000013c100); // TTBR0_EL1
        assert_eq!(sysreg_id(3, 0, 12, 0, 0), 0x603000000013c600); // VBAR_EL1
        assert_eq!(sysreg_id(3, 3, 13, 0, 2), 0x603000000013de82); // TPIDR_EL0
    }
}
