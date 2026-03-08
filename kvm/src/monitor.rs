//! Event monitoring control.

use crate::consts;
use crate::error::KvmError;
use crate::session::{KvmVmiSession, kvm_ioctl};

/// Controls event monitoring for a VMI session.
pub struct KvmVmiMonitor {
    session: KvmVmiSession,
}

impl KvmVmiMonitor {
    /// Create a new monitor control handle.
    pub fn new(session: KvmVmiSession) -> Self {
        Self { session }
    }

    /// Send a control event command (enable/disable monitoring).
    pub fn control_event(
        &self,
        ctrl: &kvm_sys::kvm_vmi_control_event,
    ) -> Result<(), KvmError> {
        unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_CONTROL_EVENT,
                ctrl as *const _ as u64,
            )?;
        }
        Ok(())
    }
}
