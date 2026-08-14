fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/branding/logo.ico");
        res.set(
            "FileDescription",
            "Zyphora Reversing — professional reverse engineering workstation",
        );
        res.set("ProductName", "Zyphora Reversing");
        res.set("FileVersion", "0.1.0.0");
        res.set("ProductVersion", "0.1.0.0");
        res.set("LegalCopyright", "2026 Zyphora Reversing Dev Team");
        if let Err(e) = res.compile() {
            eprintln!("Warning: Windows resource compilation failed: {e}");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/");
    println!("cargo:rerun-if-changed=assets/branding/logo.ico");
}
