// SPDX-License-Identifier: Apache-2.0

//! Shared descriptor fixture for device-only continuation tests. Its inactive
//! 1 MiB disk is byte-equivalent across captures; active block I/O uses its own fixture.
use super::*;
use crate::snapshot_vm::checkpoint::{ExportMetadata, ImportBindings};
use devices::virtio::block::ImageType;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) fn attach_disk(vm: &mut RamSnapshotVm) {
    let path = std::env::temp_dir().join(format!("v9-disk-{}-{}", std::process::id(), rand_id()));
    assert!(std::process::Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&path)
        .arg("1M")
        .status()
        .unwrap()
        .success());
    vm.attach_disk(&path, ImageType::Qcow2, false, false)
        .unwrap();
    fs::remove_file(path).unwrap();
}

pub(crate) trait DescriptorFixture: Sized {
    fn export_test(&mut self, path: &Path) -> Result<()>;
    fn import_test(path: &Path, resources: RestoreResources) -> Result<Self>;
    fn export_test_write_failure(&mut self) -> Result<()>;
}
impl DescriptorFixture for RamSnapshotVm {
    fn export_test(&mut self, path: &Path) -> Result<()> {
        self.prepare_checkpoint()?;
        let memory = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let disk = path.with_extension("qcow2");
        let status = std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2"])
            .arg(&disk)
            .arg("1M")
            .status()?;
        assert!(status.success());
        let qcow2 = OpenOptions::new().read(true).write(true).open(&disk)?;
        let result = self.export_fd(
            memory,
            qcow2,
            ExportMetadata {
                application_schema: 1,
                application: serde_json::Value::Null,
                objects: vec![],
            },
        );
        if result.is_err() {
            fs::remove_file(path)?;
            fs::remove_file(disk)?;
        }
        result
    }
    fn export_test_write_failure(&mut self) -> Result<()> {
        use std::os::fd::FromRawFd;
        self.prepare_checkpoint()?;
        let fd = unsafe {
            libc::memfd_create(
                c"snapshot-failed-writer".as_ptr(),
                libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let memory = unsafe { File::from_raw_fd(fd) };
        let path =
            std::env::temp_dir().join(format!("v9-failure-{}-{}", std::process::id(), rand_id()));
        assert!(std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2"])
            .arg(&path)
            .arg("1M")
            .status()?
            .success());
        let disk = OpenOptions::new().read(true).write(true).open(&path)?;
        fs::remove_file(path)?;
        let result = super::tests::with_failed_payload_write(17, || {
            self.export_fd(
                memory.try_clone()?,
                disk,
                ExportMetadata {
                    application_schema: 1,
                    application: serde_json::Value::Null,
                    objects: vec![],
                },
            )
        });
        assert!(result
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("injected mid-copy write failure"));
        use std::os::unix::fs::FileExt;
        let mut partial = vec![0; memory.metadata()?.len() as usize];
        memory.read_exact_at(&mut partial, 0)?;
        let mut metadata =
            serde_json::Deserializer::from_slice(&partial[160..]).into_iter::<serde_json::Value>();
        metadata.next().unwrap().unwrap();
        assert_eq!(
            partial.len(),
            160 + metadata.byte_offset() + 17,
            "failure did not occur after exactly 17 RAM bytes"
        );
        assert!(
            crate::ram_snapshot::full::inspect(&memory).is_err(),
            "failed writer sealed a valid image"
        );
        result
    }
    fn import_test(path: &Path, resources: RestoreResources) -> Result<Self> {
        let disk = path.with_extension("qcow2");
        let owned = path.with_extension(format!("owned-{}", rand_id()));
        fs::copy(disk, &owned)?;
        let qcow2 = OpenOptions::new().read(true).write(true).open(&owned)?;
        Self::import_fd(
            File::open(path)?,
            ImportBindings {
                disks: vec![qcow2],
                shares: vec![],
            },
            resources,
        )
    }
}
fn rand_id() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
