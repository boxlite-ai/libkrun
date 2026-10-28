#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    pub shared_dir: String,
    pub shm_size: Option<usize>,
    pub allow_root_dir_delete: bool,
    pub read_only: bool,
    /// libkrun created `shared_dir` for this VM alone (the temporary boot
    /// root of `krun_set_root_disk_remount`), unlike a caller's directory.
    /// The ordinary VMM ignores it; a checkpointing VM keeps that directory
    /// until the VM ends and then removes it.
    pub vm_owned: bool,
}
