use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use imago::{
    file::File as ImagoFile, qcow2::Qcow2, DynStorage, FormatAccess, Storage, SyncFormatAccess,
};
use utils::eventfd::EventFd;

pub(crate) type Image = SyncFormatAccess<Box<dyn DynStorage>>;
type QcowImage = Qcow2<Box<dyn DynStorage>, Arc<FormatAccess<Box<dyn DynStorage>>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

impl FileIdentity {
    pub fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Phase {
    Absent = 0,
    Fenced = 1,
    Installed = 2,
    Committed = 3,
    Aborted = 4,
}

fn errno(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

#[derive(Default)]
pub struct SnapshotHandle {
    pub(crate) disk: Mutex<Option<Arc<SnapshotDisk>>>,
}

impl SnapshotHandle {
    pub fn disk(&self) -> io::Result<Arc<SnapshotDisk>> {
        self.disk
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| errno(libc::ENODEV))
    }
}

struct SnapshotState {
    image: FileIdentity,
    transaction: String,
    phase: Phase,
}

pub struct SnapshotDisk {
    path: PathBuf,
    image: Arc<Mutex<Image>>,
    state: Mutex<SnapshotState>,
    // Serialize acceptance of one descriptor against flush and backend replacement.
    queue_boundary: Mutex<()>,
    fenced: AtomicBool,
    queue_kick: Mutex<Option<EventFd>>,
}

impl SnapshotDisk {
    pub(crate) fn new(path: PathBuf, image: Arc<Mutex<Image>>, identity: FileIdentity) -> Self {
        Self {
            path,
            image,
            state: Mutex::new(SnapshotState {
                image: identity,
                transaction: String::new(),
                phase: Phase::Absent,
            }),
            queue_boundary: Mutex::new(()),
            fenced: AtomicBool::new(false),
            queue_kick: Mutex::new(None),
        }
    }

    pub(crate) fn set_queue(&self, event: Option<EventFd>) {
        *self.queue_kick.lock().unwrap() = event;
    }

    pub(crate) fn fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }

    pub(crate) fn accept_descriptor(&self) -> Option<MutexGuard<'_, ()>> {
        let guard = self.queue_boundary.lock().unwrap();
        (!self.fenced()).then_some(guard)
    }

    pub fn status(&self, transaction: &str) -> io::Result<Phase> {
        let state = self.state.lock().unwrap();
        if state.transaction == transaction {
            Ok(state.phase)
        } else if self.fenced() {
            Err(errno(libc::EBUSY))
        } else {
            Ok(Phase::Absent)
        }
    }

    pub fn fence(&self, transaction: &str, source: FileIdentity) -> io::Result<Phase> {
        let mut state = self.state.lock().unwrap();
        if state.transaction == transaction {
            return Ok(state.phase);
        }
        if self.fenced() {
            return Err(errno(libc::EBUSY));
        }
        if state.image != source {
            return Err(errno(libc::ESTALE));
        }

        self.fenced.store(true, Ordering::Release);
        let _boundary = self.queue_boundary.lock().unwrap();
        let result = {
            let image = self.image.lock().unwrap();
            image.flush().and_then(|()| image.sync())
        };
        if let Err(error) = result {
            self.unfence();
            return Err(error);
        }
        state.transaction = transaction.to_owned();
        state.phase = Phase::Fenced;
        Ok(Phase::Fenced)
    }

    pub fn install(
        &self,
        transaction: &str,
        overlay: FileIdentity,
        backing_path: &Path,
        backing: FileIdentity,
    ) -> io::Result<Phase> {
        let mut state = self.state.lock().unwrap();
        Self::check_transaction(&state, transaction)?;
        if state.phase == Phase::Installed && state.image == overlay {
            return Ok(Phase::Installed);
        }
        if state.phase != Phase::Fenced || state.image != backing {
            return Err(errno(libc::EINVAL));
        }

        let mut child = open_verified(&self.path, true, overlay)?;
        if child.implicit_backing_file().map(Path::new) != Some(backing_path) {
            return Err(errno(libc::EINVAL));
        }
        let mut base = open_verified(backing_path, false, backing)?;
        base.open_implicit_dependencies_sync()?;
        child.set_backing(Some(Arc::new(FormatAccess::new(base))));
        child.open_implicit_dependencies_sync()?;
        self.replace(SyncFormatAccess::new(child)?)?;
        state.image = overlay;
        state.phase = Phase::Installed;
        Ok(Phase::Installed)
    }

    pub fn release(&self, transaction: &str, overlay: FileIdentity) -> io::Result<Phase> {
        let mut state = self.state.lock().unwrap();
        Self::check_transaction(&state, transaction)?;
        if !matches!(state.phase, Phase::Installed | Phase::Committed) || state.image != overlay {
            return Err(errno(libc::EINVAL));
        }
        state.phase = Phase::Committed;
        self.unfence();
        Ok(Phase::Committed)
    }

    pub fn abort(&self, transaction: &str, source: FileIdentity) -> io::Result<Phase> {
        let mut state = self.state.lock().unwrap();
        Self::check_transaction(&state, transaction)?;
        if !matches!(
            state.phase,
            Phase::Fenced | Phase::Installed | Phase::Aborted
        ) {
            return Err(errno(libc::EINVAL));
        }
        if state.image != source {
            let mut original = open_verified(&self.path, true, source)?;
            original.open_implicit_dependencies_sync()?;
            self.replace(SyncFormatAccess::new(original)?)?;
            state.image = source;
        }
        state.phase = Phase::Aborted;
        self.unfence();
        Ok(Phase::Aborted)
    }

    fn check_transaction(state: &SnapshotState, transaction: &str) -> io::Result<()> {
        if state.transaction != transaction {
            return Err(errno(libc::ENOENT));
        }
        Ok(())
    }

    fn replace(&self, replacement: Image) -> io::Result<()> {
        let mut image = self.image.lock().unwrap();
        if replacement.size() != image.size() {
            return Err(errno(libc::EINVAL));
        }
        *image = replacement;
        Ok(())
    }

    fn unfence(&self) {
        self.fenced.store(false, Ordering::Release);
        if let Some(queue) = self.queue_kick.lock().unwrap().as_ref() {
            if let Err(error) = queue.write(1) {
                // EAGAIN means an existing notification already wakes the queue.
                if error.kind() != io::ErrorKind::WouldBlock {
                    log::error!("failed to wake the virtio-blk queue: {error}");
                }
            }
        }
    }
}

fn open_verified(path: &Path, writable: bool, identity: FileIdentity) -> io::Result<QcowImage> {
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if FileIdentity::of(&file)? != identity {
        return Err(errno(libc::ESTALE));
    }
    let storage: Box<dyn DynStorage> = Box::new(ImagoFile::try_from(file)?);
    let qcow = Qcow2::open_image_sync(storage, writable)?;
    if qcow.requires_external_data_file() {
        return Err(errno(libc::ENOTSUP));
    }
    Ok(qcow)
}

pub(crate) fn open_initial(file: File) -> io::Result<Option<(Image, FileIdentity, usize)>> {
    let identity = FileIdentity::of(&file)?;
    let storage = ImagoFile::try_from(file)?;
    let discard_alignment = storage.discard_align();
    let mut qcow: QcowImage =
        Qcow2::open_image_sync(Box::new(storage) as Box<dyn DynStorage>, true)?;
    if qcow.requires_external_data_file()
        || qcow
            .implicit_backing_file()
            .is_some_and(|path| Path::new(path).is_relative())
    {
        return Ok(None);
    }
    qcow.open_implicit_dependencies_sync()?;
    Ok(Some((
        SyncFormatAccess::new(qcow)?,
        identity,
        discard_alignment,
    )))
}
