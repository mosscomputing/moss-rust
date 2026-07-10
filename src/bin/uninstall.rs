//! MOSS Uninstall Helper for moss-rust (moss-sdk).
//!
//! Usage:
//!     cargo run --bin uninstall [--dry-run]
//!
//! Checklist-only: prints the manual-cleanup checklist and exits 0. Makes no
//! network calls and mutates no files.

use std::process::exit;

fn main() {
    let dry_run = std::env::args().skip(1).any(|arg| arg == "--dry-run");

    println!("MOSS Uninstall Helper for moss-rust");
    println!("----------------------------------------");
    if dry_run {
        println!("[DRY-RUN MODE]");
    }
    print!(
        r#"
MANUAL CLEANUP CHECKLIST

[ ] Revoke/rotate MOSS credentials in the MOSS console (API keys / agent capability tokens)
[ ] Remove the moss-sdk dependency:
      cargo remove moss-sdk
[ ] Remove `use moss_sdk::...;` imports from your .rs files
[ ] Remove config files: rm -f .moss.yml moss_config.json moss.config.js
[ ] Unset MOSS_* environment variables
[ ] CI/CD: remove MOSS_* secrets and setup steps from GitHub Actions / CI
[ ] Docker: remove MOSS_* ENV lines and the MOSS dependency from Dockerfiles
[ ] Docs: update README / setup guides that reference MOSS
"#
    );
    println!("\nChecklist printed. Complete the steps above manually.");
    exit(0);
}
