pub mod consts;
pub mod error;
pub mod event;
pub mod memory;
pub mod monitor;
pub mod ring;
pub mod session;
pub mod view;

#[cfg(target_arch = "x86_64")]
pub mod vcpu;

pub use kvm_sys as sys;

pub use self::{
    error::KvmError,
    event::{KvmVmiEvent, KvmVmiEventReason},
    memory::{KvmMappedPage, MemoryAccess},
    monitor::KvmVmiMonitor,
    ring::KvmVmiRing,
    session::KvmVmiSession,
    view::KvmVmiView,
};

#[cfg(target_arch = "x86_64")]
pub use self::vcpu::MsrValues;
