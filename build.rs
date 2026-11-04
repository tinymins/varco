fn main() {
    // Double-clicking the exe raises UAC; a virtual NIC needs administrator rights.
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};
        let manifest =
            new_manifest("varco").requested_execution_level(ExecutionLevel::RequireAdministrator);
        embed_manifest(manifest).expect("embedding the Windows manifest");
        // The icon Explorer shows for the exe.
        embed_resource::compile("assets/icon/varco.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("embedding the Windows icon");
    }
    #[cfg(feature = "gui")]
    {
        // One fixed style, so the window looks the same on every platform.
        let config = slint_build::CompilerConfiguration::new().with_style("fluent-light".into());
        slint_build::compile_with_config("ui/app.slint", config).expect("compiling the UI");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
