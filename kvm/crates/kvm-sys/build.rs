use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=KVM_SYS_HEADERS");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_bindings = out_dir.join("bindings.rs");

    let headers = env::var("KVM_SYS_HEADERS")
        .unwrap_or_else(|_| "/root/vmi-dev/project/linux/usr/include".to_string());
    let headers_path = PathBuf::from(&headers);

    let committed = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("bindings")
        .join("kvm-vmi.rs");

    let use_committed = env::var("DOCS_RS").is_ok()
        || !headers_path.join("linux/kvm_vmi.h").exists();

    if use_committed {
        std::fs::copy(&committed, &out_bindings)
            .expect("committed bindings/kvm-vmi.rs must exist as a fallback");
        return;
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{headers}"))
        .allowlist_item("kvm_vmi.*")
        .allowlist_item("KVM_VMI.*")
        .allowlist_item("KVM_CAP_VMI.*")
        .allowlist_item("KVM_CREATE_VMI")
        .allowlist_item("kvm_regs")
        .allowlist_item("kvm_sregs")
        .allowlist_item("kvm_segment")
        .allowlist_item("kvm_dtable")
        .allowlist_item("kvm_msrs")
        .allowlist_item("kvm_msr_entry")
        .allowlist_item("kvm_debugregs")
        .allowlist_item("KVM_GET_REGS")
        .allowlist_item("KVM_SET_REGS")
        .allowlist_item("KVM_GET_SREGS")
        .allowlist_item("KVM_SET_SREGS")
        .allowlist_item("KVM_GET_MSRS")
        .allowlist_item("KVM_SET_MSRS")
        .allowlist_item("KVM_GET_DEBUGREGS")
        .allowlist_item("KVM_SET_DEBUGREGS")
        .allowlist_item("kvm_sys_.*")
        .derive_default(true)
        .generate()
        .expect("failed to generate KVM bindings");

    bindings
        .write_to_file(&out_bindings)
        .expect("failed to write bindings");

    // Refresh the committed fallback so it tracks the headers.
    let _ = std::fs::create_dir_all(committed.parent().unwrap());
    let _ = bindings.write_to_file(&committed);
}
