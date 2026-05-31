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

pub use self::{
    access::MemAccess,
    attach::{KvmFds, from_pid},
    core::ViewId,
    error::KvmError,
    event::{KvmEventReason, KvmMemAccessEvent, KvmSinglestepEvent, KvmVmiEvent, KvmVmiRegs},
    memory::{KvmGuestMemory, KvmMappedPage},
    ring::KvmVmiRing,
    session::KvmVmi,
    vcpu::KvmVcpu,
};
