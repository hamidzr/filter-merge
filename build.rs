use std::process::Command;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let mut git_paths = vec!["HEAD".to_string()];
    if let Ok(output) = Command::new("git")
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .output()
    {
        if output.status.success() {
            git_paths.push(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }
    for path in git_paths {
        if let Ok(output) = Command::new("git")
            .args(["rev-parse", "--git-path", &path])
            .output()
        {
            if output.status.success() {
                println!(
                    "cargo:rerun-if-changed={}",
                    String::from_utf8_lossy(&output.stdout).trim()
                );
            }
        }
    }
    let revision = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|v| v.status.success())
        .and_then(|v| String::from_utf8(v.stdout).ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=BUILD_REVISION={}", revision.trim());
    let epoch = std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    });
    println!("cargo:rustc-env=BUILD_EPOCH={epoch}");
    let mut date = Command::new("date");
    date.arg("-u");
    if cfg!(target_os = "macos") {
        date.args(["-r", &epoch]);
    } else {
        date.args(["-d", &format!("@{epoch}")]);
    }
    let built = date
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
        .ok()
        .filter(|v| v.status.success())
        .and_then(|v| String::from_utf8(v.stdout).ok())
        .unwrap_or(epoch);
    println!("cargo:rustc-env=BUILD_DATE={}", built.trim());
}
