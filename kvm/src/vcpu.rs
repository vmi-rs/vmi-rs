//! A duplicated KVM vCPU fd, used for standard register ioctls.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[cfg(target_arch = "x86_64")]
use std::os::fd::AsRawFd;

use crate::{core::ioctl_with_ref, error::KvmError};

#[cfg(target_arch = "x86_64")]
use crate::core::ioctl_with_mut_ref;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::{KvmDtable, KvmSegment, Registers};

#[cfg(target_arch = "aarch64")]
use crate::arch::arm64::Registers;

/// `IA32_SYSENTER_CS`.
#[cfg(target_arch = "x86_64")]
const MSR_IA32_SYSENTER_CS: u32 = 0x0000_0174;

/// `IA32_SYSENTER_ESP`.
#[cfg(target_arch = "x86_64")]
const MSR_IA32_SYSENTER_ESP: u32 = 0x0000_0175;

/// `IA32_SYSENTER_EIP`.
#[cfg(target_arch = "x86_64")]
const MSR_IA32_SYSENTER_EIP: u32 = 0x0000_0176;

/// `IA32_EFER`.
#[cfg(target_arch = "x86_64")]
const MSR_EFER: u32 = 0xc000_0080;

/// `IA32_STAR`.
#[cfg(target_arch = "x86_64")]
const MSR_STAR: u32 = 0xc000_0081;

/// `IA32_LSTAR`.
#[cfg(target_arch = "x86_64")]
const MSR_LSTAR: u32 = 0xc000_0082;

/// `IA32_CSTAR`.
#[cfg(target_arch = "x86_64")]
const MSR_CSTAR: u32 = 0xc000_0083;

/// `IA32_FMASK` (syscall flag mask).
#[cfg(target_arch = "x86_64")]
const MSR_FMASK: u32 = 0xc000_0084;

/// `IA32_KERNEL_GS_BASE` (the swapped-out GS base).
#[cfg(target_arch = "x86_64")]
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// `IA32_TSC_AUX`.
#[cfg(target_arch = "x86_64")]
const MSR_TSC_AUX: u32 = 0xc000_0103;

/// The subset of MSRs read alongside the GP and special registers.
#[cfg(target_arch = "x86_64")]
#[derive(Default)]
struct Msrs {
    /// `IA32_EFER`.
    efer: u64,

    /// `IA32_STAR`.
    star: u64,

    /// `IA32_LSTAR`.
    lstar: u64,

    /// `IA32_CSTAR`.
    cstar: u64,

    /// `IA32_FMASK` (syscall flag mask).
    sfmask: u64,

    /// `IA32_KERNEL_GS_BASE` (the swapped-out GS base).
    kernel_gs_base: u64,

    /// `IA32_SYSENTER_CS`.
    sysenter_cs: u64,

    /// `IA32_SYSENTER_ESP`.
    sysenter_esp: u64,

    /// `IA32_SYSENTER_EIP`.
    sysenter_eip: u64,

    /// `IA32_TSC_AUX`.
    tsc_aux: u64,
}

/// Wraps one duplicated vCPU fd. Register ioctls work because a paused vCPU
/// has released `vcpu->mutex`.
pub struct KvmVcpu {
    /// The owned vCPU fd.
    fd: OwnedFd,
}

impl KvmVcpu {
    /// Wraps an already-duplicated vCPU fd.
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Borrows the underlying fd.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Reads general-purpose registers via `KVM_GET_REGS`.
    #[cfg(target_arch = "x86_64")]
    fn get_regs(&self) -> Result<kvm_sys::kvm_regs, KvmError> {
        let mut regs = kvm_sys::kvm_regs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_REGS, &mut regs)?;
        Ok(regs)
    }

    /// Writes general-purpose registers via `KVM_SET_REGS`.
    #[cfg(target_arch = "x86_64")]
    fn set_regs(&self, regs: &kvm_sys::kvm_regs) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_REGS, regs)?;
        Ok(())
    }

    /// Reads special registers via `KVM_GET_SREGS`.
    #[cfg(target_arch = "x86_64")]
    fn get_sregs(&self) -> Result<kvm_sys::kvm_sregs, KvmError> {
        let mut sregs = kvm_sys::kvm_sregs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_SREGS, &mut sregs)?;
        Ok(sregs)
    }

    /// Writes special registers via `KVM_SET_SREGS`.
    #[cfg(target_arch = "x86_64")]
    fn set_sregs(&self, sregs: &kvm_sys::kvm_sregs) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_SREGS, sregs)?;
        Ok(())
    }

    /// Reads debug registers via `KVM_GET_DEBUGREGS`.
    #[cfg(target_arch = "x86_64")]
    fn get_debugregs(&self) -> Result<kvm_sys::kvm_debugregs, KvmError> {
        let mut dregs = kvm_sys::kvm_debugregs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_DEBUGREGS, &mut dregs)?;
        Ok(dregs)
    }

    /// Reads the given MSRs. `entries` is filled with index/data pairs. The
    /// data fields are populated on return.
    #[cfg(target_arch = "x86_64")]
    fn get_msrs(&self, entries: &mut [kvm_sys::kvm_msr_entry]) -> Result<(), KvmError> {
        // kvm_msrs is a flexible-array struct: header + entries[]. Build a byte
        // buffer of the right size.
        let nmsrs = entries.len();
        let header = std::mem::size_of::<kvm_sys::kvm_msrs>();
        let nwords = (header + std::mem::size_of_val(entries)).div_ceil(8);
        let mut buf = vec![0u64; nwords];
        // SAFETY: buf is aligned to 8 bytes (Vec<u64>) and large enough for the header.
        let msrs = buf.as_mut_ptr() as *mut kvm_sys::kvm_msrs;
        unsafe {
            (*msrs).nmsrs = nmsrs as u32;
            let dst = (*msrs).__bindgen_anon_1.entries.as_mut_ptr();
            std::ptr::copy_nonoverlapping(entries.as_ptr(), dst, nmsrs);
            let ret = libc::ioctl(self.fd().as_raw_fd(), kvm_sys::KVM_GET_MSRS as _, msrs);
            if ret < 0 {
                return Err(KvmError::last_os_error());
            }
            std::ptr::copy_nonoverlapping(
                (*msrs).__bindgen_anon_1.entries.as_ptr(),
                entries.as_mut_ptr(),
                nmsrs,
            );
        }
        Ok(())
    }

    /// Reads the MSRs carried in the full register context into a named bundle.
    #[cfg(target_arch = "x86_64")]
    fn read_tracked_msrs(&self) -> Result<Msrs, KvmError> {
        let indices = [
            MSR_EFER,
            MSR_STAR,
            MSR_LSTAR,
            MSR_CSTAR,
            MSR_FMASK,
            MSR_KERNEL_GS_BASE,
            MSR_IA32_SYSENTER_CS,
            MSR_IA32_SYSENTER_ESP,
            MSR_IA32_SYSENTER_EIP,
            MSR_TSC_AUX,
        ];

        let mut entries = indices
            .iter()
            .map(|msr| kvm_sys::kvm_msr_entry {
                index: *msr,
                ..Default::default()
            })
            .collect::<Vec<_>>();

        self.get_msrs(&mut entries)?;

        Ok(Msrs {
            efer: entries[0].data,
            star: entries[1].data,
            lstar: entries[2].data,
            cstar: entries[3].data,
            sfmask: entries[4].data,
            kernel_gs_base: entries[5].data,
            sysenter_cs: entries[6].data,
            sysenter_esp: entries[7].data,
            sysenter_eip: entries[8].data,
            tsc_aux: entries[9].data,
        })
    }

    /// Reads the full register context via `KVM_GET_REGS`, `KVM_GET_SREGS`,
    /// `KVM_GET_DEBUGREGS`, and `KVM_GET_MSRS` and flattens it into `Registers`.
    #[cfg(target_arch = "x86_64")]
    pub fn get_registers(&self) -> Result<Registers, KvmError> {
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let dregs = self.get_debugregs()?;
        let msrs = self.read_tracked_msrs()?;

        let seg = |s: &kvm_sys::kvm_segment| KvmSegment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
        };

        Ok(Registers {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,

            cr0: sregs.cr0,
            cr2: sregs.cr2,
            cr3: sregs.cr3,
            cr4: sregs.cr4,

            cs: seg(&sregs.cs),
            ds: seg(&sregs.ds),
            es: seg(&sregs.es),
            fs: seg(&sregs.fs),
            gs: seg(&sregs.gs),
            ss: seg(&sregs.ss),
            tr: seg(&sregs.tr),
            ldt: seg(&sregs.ldt),

            gdt: KvmDtable {
                base: sregs.gdt.base,
                limit: sregs.gdt.limit,
            },
            idt: KvmDtable {
                base: sregs.idt.base,
                limit: sregs.idt.limit,
            },

            db: dregs.db,
            dr6: dregs.dr6,
            dr7: dregs.dr7,

            efer: msrs.efer,
            star: msrs.star,
            lstar: msrs.lstar,
            cstar: msrs.cstar,
            sfmask: msrs.sfmask,
            kernel_gs_base: msrs.kernel_gs_base,
            sysenter_cs: msrs.sysenter_cs,
            sysenter_esp: msrs.sysenter_esp,
            sysenter_eip: msrs.sysenter_eip,
            tsc_aux: msrs.tsc_aux,
        })
    }

    /// Writes the general-purpose and special registers from `regs` via
    /// `KVM_SET_REGS` and `KVM_SET_SREGS`. `efer` is written as part of
    /// `KVM_SET_SREGS`. Debug registers and the remaining MSRs (STAR, LSTAR,
    /// CSTAR, SFMASK, KERNEL_GS_BASE, SYSENTER_*, TSC_AUX) are not written back.
    #[cfg(target_arch = "x86_64")]
    pub fn set_registers(&self, regs: &Registers) -> Result<(), KvmError> {
        let unseg = |s: &KvmSegment| kvm_sys::kvm_segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            ..Default::default()
        };

        let gp = kvm_sys::kvm_regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        };

        let sregs = kvm_sys::kvm_sregs {
            cs: unseg(&regs.cs),
            ds: unseg(&regs.ds),
            es: unseg(&regs.es),
            fs: unseg(&regs.fs),
            gs: unseg(&regs.gs),
            ss: unseg(&regs.ss),
            tr: unseg(&regs.tr),
            ldt: unseg(&regs.ldt),
            gdt: kvm_sys::kvm_dtable {
                base: regs.gdt.base,
                limit: regs.gdt.limit,
                ..Default::default()
            },
            idt: kvm_sys::kvm_dtable {
                base: regs.idt.base,
                limit: regs.idt.limit,
                ..Default::default()
            },
            cr0: regs.cr0,
            cr2: regs.cr2,
            cr3: regs.cr3,
            cr4: regs.cr4,
            efer: regs.efer,
            ..Default::default()
        };

        self.set_regs(&gp)?;
        self.set_sregs(&sregs)?;
        Ok(())
    }

    /// Reads one register by id via `KVM_GET_ONE_REG`.
    #[cfg(target_arch = "aarch64")]
    fn get_one_reg(&self, id: u64) -> Result<u64, KvmError> {
        let mut val = 0u64;
        let reg = kvm_sys::kvm_one_reg {
            id,
            // Sound: `val` outlives the synchronous ioctl and the pointer is exclusively owned for its duration.
            addr: &mut val as *mut u64 as u64,
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_GET_ONE_REG, &reg)?;
        Ok(val)
    }

    /// Writes one register by id via `KVM_SET_ONE_REG`.
    #[cfg(target_arch = "aarch64")]
    fn set_one_reg(&self, id: u64, val: u64) -> Result<(), KvmError> {
        let reg = kvm_sys::kvm_one_reg {
            id,
            // Sound: `val` outlives the synchronous ioctl and the pointer is exclusively owned for its duration.
            addr: &val as *const u64 as u64,
        };
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_ONE_REG, &reg)?;
        Ok(())
    }

    /// Reads the full register context via `KVM_GET_ONE_REG` (one ioctl per
    /// register) and assembles it into `Registers`.
    #[cfg(target_arch = "aarch64")]
    pub fn get_registers(&self) -> Result<Registers, KvmError> {
        use crate::arch::arm64::{
            CONTEXTIDR_EL1, CoreReg, ESR_EL1, FAR_EL1, MAIR_EL1, SCTLR_EL1, TCR_EL1, TPIDR_EL0,
            TPIDR_EL1, TPIDRRO_EL0, TTBR0_EL1, TTBR1_EL1, VBAR_EL1, core_reg_id,
        };

        let mut regs = [0u64; 31];
        for n in 0u8..31 {
            regs[n as usize] = self.get_one_reg(core_reg_id(CoreReg::X(n)))?;
        }

        Ok(Registers {
            regs,
            sp_el0: self.get_one_reg(core_reg_id(CoreReg::Sp))?,
            sp_el1: self.get_one_reg(core_reg_id(CoreReg::SpEl1))?,
            pc: self.get_one_reg(core_reg_id(CoreReg::Pc))?,
            pstate: self.get_one_reg(core_reg_id(CoreReg::Pstate))?,
            ttbr0_el1: self.get_one_reg(TTBR0_EL1)?,
            ttbr1_el1: self.get_one_reg(TTBR1_EL1)?,
            tcr_el1: self.get_one_reg(TCR_EL1)?,
            sctlr_el1: self.get_one_reg(SCTLR_EL1)?,
            mair_el1: self.get_one_reg(MAIR_EL1)?,
            vbar_el1: self.get_one_reg(VBAR_EL1)?,
            contextidr_el1: self.get_one_reg(CONTEXTIDR_EL1)?,
            elr_el1: self.get_one_reg(core_reg_id(CoreReg::ElrEl1))?,
            spsr_el1: self.get_one_reg(core_reg_id(CoreReg::SpsrEl1))?,
            esr_el1: self.get_one_reg(ESR_EL1)?,
            far_el1: self.get_one_reg(FAR_EL1)?,
            tpidr_el0: self.get_one_reg(TPIDR_EL0)?,
            tpidr_el1: self.get_one_reg(TPIDR_EL1)?,
            tpidrro_el0: self.get_one_reg(TPIDRRO_EL0)?,
        })
    }

    /// Writes the writable registers via `KVM_SET_ONE_REG`. `sp_el1`,
    /// `elr_el1`, and `spsr_el1` are written via CORE-block ONE_REG ids,
    /// matching how they are read in `get_registers`. `TPIDRRO_EL0` is
    /// read-only for the guest but writable by the hypervisor via
    /// `KVM_SET_ONE_REG`, so it is written back.
    #[cfg(target_arch = "aarch64")]
    pub fn set_registers(&self, regs: &Registers) -> Result<(), KvmError> {
        use crate::arch::arm64::{
            CONTEXTIDR_EL1, CoreReg, ESR_EL1, FAR_EL1, MAIR_EL1, SCTLR_EL1, TCR_EL1, TPIDR_EL0,
            TPIDR_EL1, TPIDRRO_EL0, TTBR0_EL1, TTBR1_EL1, VBAR_EL1, core_reg_id,
        };

        for n in 0u8..31 {
            self.set_one_reg(core_reg_id(CoreReg::X(n)), regs.regs[n as usize])?;
        }
        self.set_one_reg(core_reg_id(CoreReg::Sp), regs.sp_el0)?;
        self.set_one_reg(core_reg_id(CoreReg::SpEl1), regs.sp_el1)?;
        self.set_one_reg(core_reg_id(CoreReg::Pc), regs.pc)?;
        self.set_one_reg(core_reg_id(CoreReg::Pstate), regs.pstate)?;
        self.set_one_reg(TTBR0_EL1, regs.ttbr0_el1)?;
        self.set_one_reg(TTBR1_EL1, regs.ttbr1_el1)?;
        self.set_one_reg(TCR_EL1, regs.tcr_el1)?;
        self.set_one_reg(SCTLR_EL1, regs.sctlr_el1)?;
        self.set_one_reg(MAIR_EL1, regs.mair_el1)?;
        self.set_one_reg(VBAR_EL1, regs.vbar_el1)?;
        self.set_one_reg(CONTEXTIDR_EL1, regs.contextidr_el1)?;
        self.set_one_reg(core_reg_id(CoreReg::ElrEl1), regs.elr_el1)?;
        self.set_one_reg(core_reg_id(CoreReg::SpsrEl1), regs.spsr_el1)?;
        self.set_one_reg(ESR_EL1, regs.esr_el1)?;
        self.set_one_reg(FAR_EL1, regs.far_el1)?;
        self.set_one_reg(TPIDR_EL0, regs.tpidr_el0)?;
        self.set_one_reg(TPIDR_EL1, regs.tpidr_el1)?;
        self.set_one_reg(TPIDRRO_EL0, regs.tpidrro_el0)?;
        Ok(())
    }
}
