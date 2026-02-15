use std::process::Command;

fn main() {
    let ver = std::env::var("VERSION").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=VERSION={}", ver);

    let commit = std::env::var("COMMIT").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=COMMIT={}", commit);

    let date = std::env::var("DATE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=DATE={}", date);

    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=OS={}", os);

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=ARCH={}", arch);

    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().into())
        .unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_version);
}
