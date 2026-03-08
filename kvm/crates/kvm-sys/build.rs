use std::{env, fs, path::PathBuf};

fn main() {
    let out_path = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR not set"),
    );

    // Use pre-generated bindings if requested or on docs.rs.
    if env::var("DOCS_RS").is_ok() || env::var("KVM_SYS_USE_BINDINGS").is_ok() {
        let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        fs::copy(
            src.join("bindings/kvm-vmi.rs"),
            out_path.join("bindings.rs"),
        )
        .expect("Failed to copy pre-generated bindings");
        return;
    }

    // Find kernel headers directory.
    let headers_dir = env::var("KVM_HEADERS_DIR").unwrap_or_else(|_| {
        let project_headers = PathBuf::from("/root/vmi-dev-claude/project/linux/usr/include");
        if project_headers.join("linux/kvm_vmi.h").exists() {
            return project_headers.to_string_lossy().into_owned();
        }
        "/usr/include".to_string()
    });

    println!("cargo::rerun-if-env-changed=KVM_HEADERS_DIR");
    println!("cargo::rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{headers_dir}"))
        .derive_debug(true)
        .derive_default(true)
        .wrap_unsafe_ops(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
