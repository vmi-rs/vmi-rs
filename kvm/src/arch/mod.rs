//! Architecture-specific native register types for the KVM VMI bindings.

#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod arm64;
