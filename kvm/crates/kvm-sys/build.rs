use std::{env, fs, path::PathBuf};

fn main() {
    let out_path = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR not set"),
    );

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // Use pre-generated bindings if requested or on docs.rs.
    if env::var("DOCS_RS").is_ok() || env::var("KVM_SYS_USE_BINDINGS").is_ok() {
        let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let bindings_file = match target_arch.as_str() {
            "aarch64" => "bindings/kvm-vmi-aarch64.rs",
            _ => "bindings/kvm-vmi-x86_64.rs",
        };
        fs::copy(
            src.join(bindings_file),
            out_path.join("bindings.rs"),
        )
        .expect("Failed to copy pre-generated bindings");
        return;
    }

    // Find kernel headers directory.
    let headers_dir = env::var("KVM_HEADERS_DIR").unwrap_or_else(|_| {
        let project_headers = PathBuf::from("/root/linux/usr/include");
        if project_headers.join("linux/kvm_vmi.h").exists() {
            return project_headers.to_string_lossy().into_owned();
        }
        "/usr/include".to_string()
    });

    println!("cargo::rerun-if-env-changed=KVM_HEADERS_DIR");
    println!("cargo::rerun-if-changed=wrapper.h");

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{headers_dir}"))
        .derive_debug(true)
        .derive_default(true)
        .wrap_unsafe_ops(true)
        // Only generate VMI types/constants and our ioctl evaluator constants.
        // Without allowlists, including linux/kvm.h would flood the output
        // with all of KVM's types and ioctls.
        //
        // Types: all kvm_vmi_* structs and unions
        .allowlist_type("kvm_vmi_.*")
        // Constants: KVM_VMI_* defines (event types, access flags, response
        // flags, etc.) and KVM_CAP_VMI* capabilities
        .allowlist_var("KVM_VMI_.*")
        .allowlist_var("KVM_CAP_VMI.*")
        .allowlist_var("KVM_CAP_NR_VCPUS")
        .allowlist_var("KVM_CAP_MAX_VCPUS")
        .allowlist_var("KVM_CAP_NR_MEMSLOTS")
        // Ioctl numbers: our static const evaluators from wrapper.h
        .allowlist_var("KVM_CREATE_VMI_IOCTL")
        .allowlist_var("KVM_CHECK_EXTENSION_IOCTL");

    match target_arch.as_str() {
        "aarch64" => {
            // arm64-specific event evaluations
            builder = builder
                .allowlist_var("KVM_VMI_EVENT_BREAKPOINT_EVAL")
                .allowlist_var("KVM_VMI_EVENT_SYSREG_EVAL")
                .allowlist_var("KVM_VMI_NUM_EVENTS_EVAL")
                // arm64 vCPU ioctls
                .allowlist_var("KVM_GET_ONE_REG_IOCTL")
                .allowlist_type("kvm_one_reg");
        }
        _ => {
            // x86_64-specific types
            builder = builder
                .allowlist_type("kvm_regs")
                .allowlist_type("kvm_sregs")
                .allowlist_type("kvm_segment")
                .allowlist_type("kvm_dtable")
                .allowlist_type("kvm_msr_entry")
                // x86 event evaluations
                .allowlist_var("KVM_VMI_EVENT_CR_EVAL")
                .allowlist_var("KVM_VMI_EVENT_MSR_EVAL")
                .allowlist_var("KVM_VMI_EVENT_CPUID_EVAL")
                .allowlist_var("KVM_VMI_EVENT_BREAKPOINT_EVAL")
                .allowlist_var("KVM_VMI_EVENT_DEBUG_EVAL")
                .allowlist_var("KVM_VMI_EVENT_DESC_ACCESS_EVAL")
                .allowlist_var("KVM_VMI_EVENT_IO_EVAL")
                .allowlist_var("KVM_VMI_NUM_EVENTS_EVAL")
                // x86 vCPU ioctls
                .allowlist_var("KVM_GET_REGS_IOCTL")
                .allowlist_var("KVM_SET_REGS_IOCTL")
                .allowlist_var("KVM_GET_SREGS_IOCTL")
                .allowlist_var("KVM_SET_SREGS_IOCTL")
                .allowlist_var("KVM_GET_MSRS_IOCTL")
                .allowlist_var("KVM_SET_MSRS_IOCTL");
        }
    }

    let bindings = builder
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
