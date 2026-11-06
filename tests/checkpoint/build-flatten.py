#!/usr/bin/env python3
"""Build a test CLI around BoxLite's existing Qcow2Helper, without editing BoxLite.

Usage: python3 tests/checkpoint/build-flatten.py /path/to/boxlite
This copies only the existing module and its constants into an ignored harness,
then applies the adjacent compatibility patch. It contains no second flatten
implementation. The Disk stub replaces unrelated RAII ownership in this CLI.
"""
import hashlib
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[2]
source = Path(sys.argv[1]).resolve() / "src/boxlite/src/disk"
work = repo / "target/checkpoint-flatten"
(work / "src").mkdir(parents=True, exist_ok=True)
for name in ("qcow2.rs", "constants.rs"):
    data = (source / name).read_bytes()
    print(f"{source / name}: sha256={hashlib.sha256(data).hexdigest()}", flush=True)
    (work / "src" / name).write_bytes(data)
subprocess.run(["patch", str(work / "src/qcow2.rs"),
                str(repo / "patches/boxlite-flatten-tail-and-zero-clusters.patch")], check=True)
(work / "Cargo.toml").write_text("""[package]
name = "checkpoint-flatten"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
qcow2-rs = "0.1.6"
tracing = "0.1"

[dev-dependencies]
tempfile = "3"
""")
(work / "src/main.rs").write_text('''#![allow(dead_code)]
// The implementation is BoxLite plus the adjacent compatibility patch. These
// types replace only unrelated Disk ownership and error wrappers in this CLI.
extern crate self as boxlite_shared;
pub mod errors {
 #[derive(Debug)] pub enum BoxliteError { Storage(String) }
 pub type BoxliteResult<T> = Result<T, BoxliteError>;
 impl std::fmt::Display for BoxliteError { fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {write!(f,"{self:?}")} }
 impl std::error::Error for BoxliteError {}
}
mod constants;
mod qcow2;
pub enum DiskFormat { Qcow2 }
pub struct Disk;
impl Disk { pub fn new(_:std::path::PathBuf,_:DiskFormat,_:bool)->Self {Self} pub fn leak(self) {} }
fn main() {
 let args: Vec<_> = std::env::args_os().collect();
 assert_eq!(args.len(),4);
 let src=std::path::Path::new(&args[2]); let dst=std::path::Path::new(&args[3]);
 if args[1] == "overlay" {
  qcow2::Qcow2Helper::create_cow_child_disk(src,qcow2::BackingFormat::Raw,dst,std::fs::metadata(src).unwrap().len()).unwrap();
 } else {
  assert_eq!(args[1],"flatten");
  qcow2::Qcow2Helper::flatten(src,dst).unwrap();
 }
}
''')
subprocess.run(["cargo", "test", "test_flatten"], cwd=work, check=True)
subprocess.run(["cargo", "build", "--release"], cwd=work, check=True)
print(f"Set KRUN_TEST_FLATTEN={work / 'target/release/checkpoint-flatten'}")
