//! Safe bindings for the KVM VMI uAPI.

pub mod access;
pub mod arch;
pub mod attach;
pub mod core;
pub mod error;
pub mod event;
pub mod memory;
pub mod ring;
pub mod session;
pub mod vcpu;

pub use kvm_sys as sys;

/// GFN sentinel that reverts a view's GFN remap to its host mapping
/// (`KVM_VMI_INVALID_GFN`, all ones).
pub const INVALID_GFN: u64 = kvm_sys::KVM_VMI_INVALID_GFN as u64;

pub use self::{
    access::MemAccess,
    attach::{KvmFds, from_pid},
    core::ViewId,
    error::KvmError,
    event::{
        KvmEventReason, KvmMemAccessEvent, KvmResponseAction, KvmSinglestepEvent, KvmVmiEvent,
        KvmVmiRegs, KvmVmiResponse,
    },
    memory::{KvmGuestMemory, KvmMappedPage},
    ring::KvmVmiRing,
    session::KvmVmi,
    vcpu::KvmVcpu,
};
