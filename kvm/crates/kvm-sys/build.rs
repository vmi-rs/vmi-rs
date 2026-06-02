use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=KVM_SYS_HEADERS");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_bindings = out_dir.join("bindings.rs");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let headers =
        env::var("KVM_SYS_HEADERS").unwrap_or_else(|_| "/opt/linux/usr/include".to_string());
    let headers_path = PathBuf::from(&headers);

    let fallback = if target_arch == "aarch64" {
        "kvm-vmi-arm64.rs"
    } else {
        "kvm-vmi.rs"
    };
    let committed = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("bindings")
        .join(fallback);

    let use_committed =
        env::var("DOCS_RS").is_ok() || !headers_path.join("linux/kvm_vmi.h").exists();

    if use_committed {
        std::fs::copy(&committed, &out_bindings).expect("committed bindings fallback must exist");
        return;
    }

    let builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{headers}"))
        .allowlist_item("kvm_vmi.*")
        .allowlist_item("KVM_VMI.*")
        .allowlist_item("KVM_CAP_VMI.*")
        .allowlist_item("KVM_CREATE_VMI")
        .allowlist_item("kvm_sys_.*")
        .derive_default(true);

    let builder = if target_arch == "aarch64" {
        builder.allowlist_item("kvm_one_reg")
    } else {
        builder
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
    };

    let bindings = builder.generate().expect("failed to generate KVM bindings");

    bindings
        .write_to_file(&out_bindings)
        .expect("failed to write bindings");

    // Refresh the committed fallback so it tracks the headers.
    let _ = std::fs::create_dir_all(committed.parent().unwrap());
    let _ = bindings.write_to_file(&committed);
}
