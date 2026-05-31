//! A duplicated KVM vCPU fd, used for standard register ioctls.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::{
    arch::x86::{KvmDtable, KvmSegment, Registers},
    core::{ioctl_with_mut_ref, ioctl_with_ref},
    error::KvmError,
};

/// `IA32_SYSENTER_CS`.
const MSR_IA32_SYSENTER_CS: u32 = 0x0000_0174;

/// `IA32_SYSENTER_ESP`.
const MSR_IA32_SYSENTER_ESP: u32 = 0x0000_0175;

/// `IA32_SYSENTER_EIP`.
const MSR_IA32_SYSENTER_EIP: u32 = 0x0000_0176;

/// `IA32_EFER`.
const MSR_EFER: u32 = 0xc000_0080;

/// `IA32_STAR`.
const MSR_STAR: u32 = 0xc000_0081;

/// `IA32_LSTAR`.
const MSR_LSTAR: u32 = 0xc000_0082;

/// `IA32_CSTAR`.
const MSR_CSTAR: u32 = 0xc000_0083;

/// `IA32_FMASK` (syscall flag mask).
const MSR_FMASK: u32 = 0xc000_0084;

/// `IA32_KERNEL_GS_BASE` (the swapped-out GS base).
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// `IA32_TSC_AUX`.
const MSR_TSC_AUX: u32 = 0xc000_0103;

/// The subset of MSRs read alongside the GP and special registers.
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
    fn get_regs(&self) -> Result<kvm_sys::kvm_regs, KvmError> {
        let mut regs = kvm_sys::kvm_regs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_REGS, &mut regs)?;
        Ok(regs)
    }

    /// Writes general-purpose registers via `KVM_SET_REGS`.
    fn set_regs(&self, regs: &kvm_sys::kvm_regs) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_REGS, regs)?;
        Ok(())
    }

    /// Reads special registers via `KVM_GET_SREGS`.
    fn get_sregs(&self) -> Result<kvm_sys::kvm_sregs, KvmError> {
        let mut sregs = kvm_sys::kvm_sregs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_SREGS, &mut sregs)?;
        Ok(sregs)
    }

    /// Writes special registers via `KVM_SET_SREGS`.
    fn set_sregs(&self, sregs: &kvm_sys::kvm_sregs) -> Result<(), KvmError> {
        ioctl_with_ref(self.fd(), kvm_sys::KVM_SET_SREGS, sregs)?;
        Ok(())
    }

    /// Reads debug registers via `KVM_GET_DEBUGREGS`.
    fn get_debugregs(&self) -> Result<kvm_sys::kvm_debugregs, KvmError> {
        let mut dregs = kvm_sys::kvm_debugregs::default();
        ioctl_with_mut_ref(self.fd(), kvm_sys::KVM_GET_DEBUGREGS, &mut dregs)?;
        Ok(dregs)
    }

    /// Reads the given MSRs. `entries` is filled with index/data pairs. The
    /// data fields are populated on return.
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
}
