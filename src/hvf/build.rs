fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=Hypervisor");
        cc::Build::new().file("src/simd.c").compile("hvf_simd");
        println!("cargo:rerun-if-changed=src/simd.c");
    }
}
