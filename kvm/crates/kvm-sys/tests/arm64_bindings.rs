//! Smoke test: arm64 VMI uapi types are present and correctly sized.
#![cfg(target_arch = "aarch64")]

use std::mem::{offset_of, size_of};

use kvm_sys;

#[test]
fn kvm_vmi_regs_layout() {
    let r = kvm_sys::kvm_vmi_regs::default();
    assert_eq!(r.regs.len(), 31);
    assert_eq!(size_of::<kvm_sys::kvm_vmi_regs>(), 392);
    let _ = offset_of!(kvm_sys::kvm_vmi_regs, ttbr0_el1);
    let _ = offset_of!(kvm_sys::kvm_vmi_regs, vbar_el1);
}

#[test]
fn kvm_vmi_inject_event_present() {
    let e = kvm_sys::kvm_vmi_inject_event::default();
    assert_eq!(e.type_, 0);
    let _ = offset_of!(kvm_sys::kvm_vmi_inject_event, fsc);
}

#[test]
fn one_reg_ioctl_present() {
    let _id: u64 = kvm_sys::KVM_GET_ONE_REG;
    let _r = kvm_sys::kvm_one_reg::default();
}
