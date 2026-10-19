//! x86 full-context register types read via the standard KVM ioctls.

/// One x86 segment in the standard KVM bitfield layout (mirrors `kvm_segment`).
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmSegment {
    /// Segment base address.
    pub base: u64,

    /// Segment limit.
    pub limit: u32,

    /// Segment selector.
    pub selector: u16,

    /// Segment type bits.
    pub type_: u8,

    /// Present bit.
    pub present: u8,

    /// Descriptor privilege level.
    pub dpl: u8,

    /// Default/big bit.
    pub db: u8,

    /// Descriptor type bit (1 = code/data, 0 = system).
    pub s: u8,

    /// 64-bit code segment bit.
    pub l: u8,

    /// Granularity bit.
    pub g: u8,

    /// Available-for-software bit.
    pub avl: u8,
}

/// One x86 descriptor-table register (mirrors `kvm_dtable`).
#[derive(Debug, Default, Clone, Copy)]
pub struct KvmDtable {
    /// Descriptor-table base address.
    pub base: u64,

    /// Descriptor-table limit.
    pub limit: u16,
}

/// Full vCPU register context read via the standard KVM ioctls. A flat native
/// bundle the driver maps to `vmi_core::Registers`, mirroring
/// `xen::arch::x86::Registers`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Registers {
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

    /// RSP.
    pub rsp: u64,

    /// RBP.
    pub rbp: u64,

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

    /// CR2.
    pub cr2: u64,

    /// CR3.
    pub cr3: u64,

    /// CR4.
    pub cr4: u64,

    /// CS segment.
    pub cs: KvmSegment,

    /// DS segment.
    pub ds: KvmSegment,

    /// ES segment.
    pub es: KvmSegment,

    /// FS segment.
    pub fs: KvmSegment,

    /// GS segment.
    pub gs: KvmSegment,

    /// SS segment.
    pub ss: KvmSegment,

    /// Task register.
    pub tr: KvmSegment,

    /// Local descriptor table register.
    pub ldt: KvmSegment,

    /// Global descriptor table register.
    pub gdt: KvmDtable,

    /// Interrupt descriptor table register.
    pub idt: KvmDtable,

    /// Debug address registers DR0-DR3.
    pub db: [u64; 4],

    /// Debug status register DR6.
    pub dr6: u64,

    /// Debug control register DR7.
    pub dr7: u64,

    /// `IA32_EFER`.
    pub efer: u64,

    /// `IA32_STAR`.
    pub star: u64,

    /// `IA32_LSTAR`.
    pub lstar: u64,

    /// `IA32_CSTAR`.
    pub cstar: u64,

    /// `IA32_FMASK` (syscall flag mask).
    pub sfmask: u64,

    /// `IA32_KERNEL_GS_BASE` (the swapped-out GS base).
    pub kernel_gs_base: u64,

    /// `IA32_SYSENTER_CS`.
    pub sysenter_cs: u64,

    /// `IA32_SYSENTER_ESP`.
    pub sysenter_esp: u64,

    /// `IA32_SYSENTER_EIP`.
    pub sysenter_eip: u64,

    /// `IA32_TSC_AUX`.
    pub tsc_aux: u64,
}

#[cfg(test)]
mod tests {
    use super::{KvmSegment, Registers};

    #[test]
    fn registers_default_is_zeroed() {
        let r = Registers::default();
        assert_eq!(r.rip, 0);
        assert_eq!(r.cs.base, 0);
    }

    #[test]
    fn segment_maps_to_kvm_segment() {
        let s = KvmSegment {
            base: 0xffff,
            limit: 0xabcd,
            selector: 0x10,
            type_: 0xb,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,
            g: 1,
            avl: 0,
        };
        let k = kvm_sys::kvm_segment {
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
        assert_eq!(k.base, s.base);
        assert_eq!(k.l, s.l);
        assert_eq!(k.type_, s.type_);
    }
}
