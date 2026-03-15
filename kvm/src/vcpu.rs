//! vCPU register access via KVM ioctls.
//!
//! These functions operate on raw vCPU file descriptors (obtained by
//! duplicating QEMU's vCPU fds via `/proc/pid/fd` or `pidfd_getfd()`).

use std::os::fd::RawFd;

use crate::consts;
use crate::error::KvmError;
use crate::session::kvm_ioctl;

/// Well-known x86 MSR indices.
pub mod msr {
    pub const IA32_SYSENTER_CS: u32 = 0x174;
    pub const IA32_SYSENTER_ESP: u32 = 0x175;
    pub const IA32_SYSENTER_EIP: u32 = 0x176;
    pub const EFER: u32 = 0xC000_0080;
    pub const STAR: u32 = 0xC000_0081;
    pub const LSTAR: u32 = 0xC000_0082;
    pub const CSTAR: u32 = 0xC000_0083;
    pub const SYSCALL_MASK: u32 = 0xC000_0084;
    pub const FS_BASE: u32 = 0xC000_0100;
    pub const GS_BASE: u32 = 0xC000_0101;
    pub const KERNEL_GS_BASE: u32 = 0xC000_0102;
    pub const TSC_AUX: u32 = 0xC000_0103;
}

/// Maximum number of MSRs we read at once.
const MAX_MSRS: usize = 16;

/// Buffer for `KVM_GET_MSRS` / `KVM_SET_MSRS` ioctls.
///
/// `struct kvm_msrs` has a flexible array member, so we define a
/// fixed-capacity version that can be passed to the kernel.
#[repr(C)]
struct MsrBuffer {
    nmsrs: u32,
    pad: u32,
    entries: [kvm_sys::kvm_msr_entry; MAX_MSRS],
}

impl MsrBuffer {
    fn new(indices: &[u32]) -> Self {
        assert!(indices.len() <= MAX_MSRS);
        let mut buf = Self {
            nmsrs: indices.len() as u32,
            pad: 0,
            entries: [kvm_sys::kvm_msr_entry::default(); MAX_MSRS],
        };
        for (i, &idx) in indices.iter().enumerate() {
            buf.entries[i].index = idx;
        }
        buf
    }

    fn get(&self, index: u32) -> Option<u64> {
        for i in 0..self.nmsrs as usize {
            if self.entries[i].index == index {
                return Some(self.entries[i].data);
            }
        }
        None
    }
}

/// Read general-purpose registers from a vCPU fd.
pub fn get_regs(vcpu_fd: RawFd) -> Result<kvm_sys::kvm_regs, KvmError> {
    let mut regs = kvm_sys::kvm_regs::default();
    unsafe {
        kvm_ioctl(
            vcpu_fd,
            consts::KVM_GET_REGS,
            &mut regs as *mut _ as u64,
        )?;
    }
    Ok(regs)
}

/// Read system registers from a vCPU fd.
pub fn get_sregs(vcpu_fd: RawFd) -> Result<kvm_sys::kvm_sregs, KvmError> {
    let mut sregs = kvm_sys::kvm_sregs::default();
    unsafe {
        kvm_ioctl(
            vcpu_fd,
            consts::KVM_GET_SREGS,
            &mut sregs as *mut _ as u64,
        )?;
    }
    Ok(sregs)
}

/// Read a set of MSRs from a vCPU fd.
///
/// Returns the buffer with filled-in `data` fields. The kernel sets
/// `nmsrs` to the number of MSRs successfully read.
fn get_msrs(vcpu_fd: RawFd, indices: &[u32]) -> Result<MsrBuffer, KvmError> {
    let mut buf = MsrBuffer::new(indices);
    unsafe {
        kvm_ioctl(
            vcpu_fd,
            consts::KVM_GET_MSRS,
            &mut buf as *mut _ as u64,
        )?;
    }
    Ok(buf)
}

/// MSR values read from a vCPU.
#[derive(Debug, Default)]
pub struct MsrValues {
    pub efer: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub syscall_mask: u64,
    pub tsc_aux: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
}

/// The set of MSR indices we read for VMI register state.
const VMI_MSR_INDICES: &[u32] = &[
    msr::EFER,
    msr::STAR,
    msr::LSTAR,
    msr::CSTAR,
    msr::SYSCALL_MASK,
    msr::TSC_AUX,
    msr::KERNEL_GS_BASE,
    msr::IA32_SYSENTER_CS,
    msr::IA32_SYSENTER_ESP,
    msr::IA32_SYSENTER_EIP,
];

/// Read the VMI-relevant MSRs from a vCPU fd.
pub fn get_vmi_msrs(vcpu_fd: RawFd) -> Result<MsrValues, KvmError> {
    let buf = get_msrs(vcpu_fd, VMI_MSR_INDICES)?;
    Ok(MsrValues {
        efer: buf.get(msr::EFER).unwrap_or(0),
        star: buf.get(msr::STAR).unwrap_or(0),
        lstar: buf.get(msr::LSTAR).unwrap_or(0),
        cstar: buf.get(msr::CSTAR).unwrap_or(0),
        syscall_mask: buf.get(msr::SYSCALL_MASK).unwrap_or(0),
        tsc_aux: buf.get(msr::TSC_AUX).unwrap_or(0),
        kernel_gs_base: buf.get(msr::KERNEL_GS_BASE).unwrap_or(0),
        sysenter_cs: buf.get(msr::IA32_SYSENTER_CS).unwrap_or(0),
        sysenter_esp: buf.get(msr::IA32_SYSENTER_ESP).unwrap_or(0),
        sysenter_eip: buf.get(msr::IA32_SYSENTER_EIP).unwrap_or(0),
    })
}
