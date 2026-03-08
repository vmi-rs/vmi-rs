//! KVM VMI constants, ioctl numbers, and helpers.
//!
//! bindgen processes `#define` constants for simple values but not for
//! ioctl macros (`_IO`, `_IOW`, `_IOR`, `_IOWR`) since those are CPP
//! macros with sizeof expressions. We define them here manually.

/// Page size (4 KiB).
pub const PAGE_SIZE: u64 = 0x1000;

/// Page shift (12 bits).
pub const PAGE_SHIFT: u64 = 12;

/// Invalid GFN sentinel (revert to host mapping).
pub const INVALID_GFN: u64 = !0u64;

/// Shadow GFN base address.
pub const SHADOW_GFN_BASE: u64 = 0xFFFFFE000000;

// ---------------------------------------------------------------------------
// ioctl helpers
// ---------------------------------------------------------------------------

const KVMIO: u32 = 0xAE;

pub(crate) const fn _io(nr: u32) -> libc::c_ulong {
    ((KVMIO << 8) | nr) as libc::c_ulong
}

pub(crate) const fn _iow<T>(nr: u32) -> libc::c_ulong {
    let size = std::mem::size_of::<T>() as u32;
    ((1u32) << 30 | (size << 16) | (KVMIO << 8) | nr) as libc::c_ulong
}

pub(crate) const fn _ior<T>(nr: u32) -> libc::c_ulong {
    let size = std::mem::size_of::<T>() as u32;
    ((2u32) << 30 | (size << 16) | (KVMIO << 8) | nr) as libc::c_ulong
}

pub(crate) const fn _iowr<T>(nr: u32) -> libc::c_ulong {
    let size = std::mem::size_of::<T>() as u32;
    ((3u32) << 30 | (size << 16) | (KVMIO << 8) | nr) as libc::c_ulong
}

// ---------------------------------------------------------------------------
// VM-level ioctl
// ---------------------------------------------------------------------------

pub const KVM_CREATE_VMI: libc::c_ulong = _io(0xef);

// ---------------------------------------------------------------------------
// vCPU-level ioctls (for register access on duplicated vCPU fds)
// ---------------------------------------------------------------------------

// KVM_GET_REGS: _IOR(KVMIO, 0x81, struct kvm_regs) -- struct kvm_regs is 144 bytes
pub const KVM_GET_REGS: libc::c_ulong =
    ((2u32 << 30) | (144u32 << 16) | (KVMIO << 8) | 0x81) as libc::c_ulong;
pub const KVM_SET_REGS: libc::c_ulong =
    ((1u32 << 30) | (144u32 << 16) | (KVMIO << 8) | 0x82) as libc::c_ulong;

// KVM_GET_SREGS: _IOR(KVMIO, 0x83, struct kvm_sregs) -- struct kvm_sregs is 312 bytes
pub const KVM_GET_SREGS: libc::c_ulong =
    ((2u32 << 30) | (312u32 << 16) | (KVMIO << 8) | 0x83) as libc::c_ulong;
pub const KVM_SET_SREGS: libc::c_ulong =
    ((1u32 << 30) | (312u32 << 16) | (KVMIO << 8) | 0x84) as libc::c_ulong;

pub const KVM_CHECK_EXTENSION: libc::c_ulong = _io(0x04);

// ---------------------------------------------------------------------------
// vmi_fd ioctls -- use bindgen-generated struct types for size computation
// ---------------------------------------------------------------------------

pub const KVM_VMI_CONTROL_EVENT: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_control_event>(0xd6);
pub const KVM_VMI_ACK_EVENT: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_vcpu>(0xd7);
pub const KVM_VMI_SETUP_RING: libc::c_ulong =
    _iowr::<kvm_sys::kvm_vmi_setup_ring>(0xd8);
pub const KVM_VMI_TEARDOWN_RING: libc::c_ulong =
    _iow::<u32>(0xd9);
pub const KVM_VMI_CREATE_VIEW: libc::c_ulong =
    _iowr::<kvm_sys::kvm_vmi_view>(0xda);
pub const KVM_VMI_DESTROY_VIEW: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_view>(0xdb);
pub const KVM_VMI_SWITCH_VIEW: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_switch_view>(0xdc);
pub const KVM_VMI_GET_MEM_ACCESS: libc::c_ulong =
    _iowr::<kvm_sys::kvm_vmi_mem_access>(0xdd);
pub const KVM_VMI_SET_MEM_ACCESS: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_mem_access>(0xde);
pub const KVM_VMI_PAUSE_VM: libc::c_ulong = _io(0xdf);
pub const KVM_VMI_UNPAUSE_VM: libc::c_ulong = _io(0xe0);
pub const KVM_VMI_PAUSE_VCPU: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_vcpu>(0xe1);
pub const KVM_VMI_UNPAUSE_VCPU: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_vcpu>(0xe2);
pub const KVM_VMI_INJECT_EVENT: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_inject_event>(0xe3);
pub const KVM_VMI_SINGLESTEP: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_singlestep>(0xe4);
pub const KVM_VMI_ALLOC_GFN: libc::c_ulong =
    _iowr::<kvm_sys::kvm_vmi_alloc_gfn>(0xe5);
pub const KVM_VMI_FREE_GFN: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_free_gfn>(0xe6);
pub const KVM_VMI_CHANGE_GFN: libc::c_ulong =
    _iow::<kvm_sys::kvm_vmi_change_gfn>(0xe7);

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

pub const KVM_CAP_VMI: u32 = 248;
pub const KVM_CAP_VMI_RING: u32 = 260;
pub const KVM_CAP_VMI_GUEST_MMAP: u32 = 261;
pub const KVM_CAP_VMI_PAUSE: u32 = 262;
pub const KVM_CAP_VMI_INJECT: u32 = 263;
pub const KVM_CAP_VMI_ALLOC_GFN: u32 = 264;
pub const KVM_CAP_NR_VCPUS: u32 = 9;
pub const KVM_CAP_MAX_VCPUS: u32 = 66;
pub const KVM_CAP_NR_MEMSLOTS: u32 = 10;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

pub const KVM_VMI_EVENT_MEM_ACCESS: u32 = 0;
pub const KVM_VMI_EVENT_CR: u32 = 1;
pub const KVM_VMI_EVENT_MSR: u32 = 2;
pub const KVM_VMI_EVENT_CPUID: u32 = 3;
pub const KVM_VMI_EVENT_BREAKPOINT: u32 = 4;
pub const KVM_VMI_EVENT_SINGLESTEP: u32 = 5;
pub const KVM_VMI_EVENT_DEBUG: u32 = 6;
pub const KVM_VMI_EVENT_DESC_ACCESS: u32 = 7;
pub const KVM_VMI_EVENT_INTERRUPT: u32 = 8;
pub const KVM_VMI_EVENT_IO: u32 = 9;
pub const KVM_VMI_NUM_EVENTS: u32 = 10;

// ---------------------------------------------------------------------------
// Memory access flags
// ---------------------------------------------------------------------------

pub const KVM_VMI_ACCESS_R: u8 = 1 << 0;
pub const KVM_VMI_ACCESS_W: u8 = 1 << 1;
pub const KVM_VMI_ACCESS_X: u8 = 1 << 2;
pub const KVM_VMI_ACCESS_RWX: u8 = KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_W | KVM_VMI_ACCESS_X;
pub const KVM_VMI_ACCESS_DEFAULT: u8 = 0xff;

// ---------------------------------------------------------------------------
// CR indices
// ---------------------------------------------------------------------------

pub const KVM_VMI_CR0: u8 = 0;
pub const KVM_VMI_CR3: u8 = 3;
pub const KVM_VMI_CR4: u8 = 4;
pub const KVM_VMI_XCR0: u8 = 64;

// ---------------------------------------------------------------------------
// Descriptor types
// ---------------------------------------------------------------------------

pub const KVM_VMI_DESC_GDTR: u8 = 0;
pub const KVM_VMI_DESC_IDTR: u8 = 1;
pub const KVM_VMI_DESC_LDTR: u8 = 2;
pub const KVM_VMI_DESC_TR: u8 = 3;

// ---------------------------------------------------------------------------
// Response flags
// ---------------------------------------------------------------------------

pub const KVM_VMI_RESPONSE_ALLOW: u32 = 0;
pub const KVM_VMI_RESPONSE_DENY: u32 = 1 << 0;
pub const KVM_VMI_RESPONSE_SET_REGS: u32 = 1 << 1;
pub const KVM_VMI_RESPONSE_SINGLESTEP: u32 = 1 << 2;
pub const KVM_VMI_RESPONSE_SINGLESTEP_FAST: u32 = 1 << 3;
pub const KVM_VMI_RESPONSE_SWITCH_VIEW: u32 = 1 << 4;
pub const KVM_VMI_RESPONSE_EMULATE: u32 = 1 << 5;
pub const KVM_VMI_RESPONSE_REINJECT: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// Event control flags
// ---------------------------------------------------------------------------

pub const KVM_VMI_EVENT_ENABLE: u32 = 1 << 0;
pub const KVM_VMI_SINGLESTEP_START: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Event injection types
// ---------------------------------------------------------------------------

pub const KVM_VMI_EVENT_TYPE_EXT_INT: u8 = 0;
pub const KVM_VMI_EVENT_TYPE_NMI: u8 = 2;
pub const KVM_VMI_EVENT_TYPE_HW_EXCEPT: u8 = 3;
pub const KVM_VMI_EVENT_TYPE_SW_INT: u8 = 4;
pub const KVM_VMI_EVENT_TYPE_PRIV_SW_INT: u8 = 5;
pub const KVM_VMI_EVENT_TYPE_SW_EXCEPT: u8 = 6;
