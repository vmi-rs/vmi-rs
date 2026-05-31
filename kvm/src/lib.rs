//! Safe bindings for the KVM VMI uAPI.

pub mod attach;
pub mod core;
pub mod error;
pub mod memory;
pub mod ring;
pub mod session;
pub mod vcpu;

pub use kvm_sys as sys;

pub use self::{
    attach::{KvmFds, from_pid},
    core::ViewId,
    error::KvmError,
    memory::{KvmGuestMemory, KvmMappedPage},
    ring::KvmVmiRing,
    session::KvmVmi,
    vcpu::KvmVcpu,
};
