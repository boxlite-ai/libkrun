//! Disk backend abstraction for virtio-blk.
//!
//! Provides a `DiskBackend` trait to abstract block device I/O,
//! with implementations for raw files and qcow2 images.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::super::super::error::{Result, WkrunError};
/// Disk format: raw file passthrough.
pub const DISK_FORMAT_RAW: u32 = 0;
/// Disk format: qcow2 image.
pub const DISK_FORMAT_QCOW2: u32 = 1;

/// Abstract block device I/O.
///
/// Backends translate guest sector reads/writes to the underlying
/// storage format (raw file, qcow2 image, etc.).
pub trait DiskBackend: Send {
    /// Read `buf.len()` bytes starting at `offset` into `buf`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Write `buf` starting at `offset`.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Flush pending writes to stable storage.
    fn flush(&mut self) -> Result<()>;

    /// Virtual disk size in bytes.
    fn capacity_bytes(&self) -> u64;
}

// ---------------------------------------------------------------------------
// Raw disk backend
// ---------------------------------------------------------------------------

/// Raw file-backed disk — direct passthrough to the host file.
pub struct RawDiskBackend {
    file: File,
    capacity: u64,
}

impl RawDiskBackend {
    /// Wrap an open file as a raw disk backend.
    ///
    /// The file size must be > 0 (i.e., the file must not be empty).
    pub fn new(file: File) -> Result<Self> {
        let metadata = file
            .metadata()
            .map_err(|e| WkrunError::Device(format!("failed to get disk metadata: {}", e)))?;
        let capacity = metadata.len();
        if capacity == 0 {
            return Err(WkrunError::Device("disk file is empty".into()));
        }
        Ok(RawDiskBackend { file, capacity })
    }
}

impl DiskBackend for RawDiskBackend {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| WkrunError::Device(format!("disk seek failed: {}", e)))?;
        self.file
            .read_exact(buf)
            .map_err(|e| WkrunError::Device(format!("disk read failed: {}", e)))?;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| WkrunError::Device(format!("disk seek failed: {}", e)))?;
        self.file
            .write_all(buf)
            .map_err(|e| WkrunError::Device(format!("disk write failed: {}", e)))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| WkrunError::Device(format!("disk flush failed: {}", e)))?;
        Ok(())
    }

    fn capacity_bytes(&self) -> u64 {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// qcow2 disk backend
// ---------------------------------------------------------------------------

/// qcow2 magic number: 'Q', 'F', 'I', 0xFB.
const QCOW2_MAGIC: u32 = 0x514649FB;

/// Mask to extract the cluster-aligned file offset from an L1 or L2 entry.
/// Bits 55:9 — zeroes out the top flag bits and the sub-cluster offset.
const L2_OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;

/// Parsed qcow2 header (fields common to v2 and v3).
#[derive(Debug)]
struct Qcow2Header {
    #[allow(dead_code)]
    version: u32,
    backing_file_offset: u64, // File offset of the backing file path (0 = none).
    backing_file_size: u32,   // Length of the backing file path in bytes.
    cluster_bits: u32,
    size: u64,            // Virtual disk size in bytes.
    l1_size: u32,         // Number of entries in the L1 table.
    l1_table_offset: u64, // File offset of the L1 table.
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    refcount_order: u32, // log2(refcount bits); 4 means 16-bit refcounts.
}

impl Qcow2Header {
    /// Parse a qcow2 header from the first 104 bytes of the file.
    fn parse(buf: &[u8; 104]) -> Result<Self> {
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != QCOW2_MAGIC {
            return Err(WkrunError::Device(format!(
                "not a qcow2 image: bad magic 0x{:08X}",
                magic
            )));
        }

        let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != 2 && version != 3 {
            return Err(WkrunError::Device(format!(
                "unsupported qcow2 version: {}",
                version
            )));
        }

        // Backing file offset and size (parsed but not validated here —
        // the backend's open() method handles backing file resolution).
        let backing_file_offset = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let backing_file_size = u32::from_be_bytes(buf[16..20].try_into().unwrap());

        let cluster_bits = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        if !(9..=21).contains(&cluster_bits) {
            return Err(WkrunError::Device(format!(
                "invalid qcow2 cluster_bits: {}",
                cluster_bits
            )));
        }

        let size = u64::from_be_bytes(buf[24..32].try_into().unwrap());
        let crypt_method = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        if crypt_method != 0 {
            return Err(WkrunError::Device(
                "qcow2 encryption is not supported".into(),
            ));
        }

        let l1_size = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let l1_table_offset = u64::from_be_bytes(buf[40..48].try_into().unwrap());
        let refcount_table_offset = u64::from_be_bytes(buf[48..56].try_into().unwrap());
        let refcount_table_clusters = u32::from_be_bytes([buf[56], buf[57], buf[58], buf[59]]);

        let nb_snapshots = u32::from_be_bytes([buf[60], buf[61], buf[62], buf[63]]);
        if nb_snapshots != 0 {
            return Err(WkrunError::Device(
                "qcow2 snapshots are not supported".into(),
            ));
        }

        // v3 has refcount_order at offset 96; v2 defaults to 4 (16-bit).
        let refcount_order = if version >= 3 {
            u32::from_be_bytes([buf[96], buf[97], buf[98], buf[99]])
        } else {
            4
        };

        Ok(Qcow2Header {
            version,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            size,
            l1_size,
            l1_table_offset,
            refcount_table_offset,
            refcount_table_clusters,
            refcount_order,
        })
    }
}

/// Detect disk format by checking for QCOW2 magic bytes.
fn detect_disk_format(path: &Path) -> Result<u32> {
    let mut f = File::open(path).map_err(|e| {
        WkrunError::Device(format!(
            "failed to open '{}' for format detection: {}",
            path.display(),
            e
        ))
    })?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).map_err(|e| {
        WkrunError::Device(format!(
            "failed to read magic from '{}': {}",
            path.display(),
            e
        ))
    })?;
    if u32::from_be_bytes(magic) == QCOW2_MAGIC {
        Ok(DISK_FORMAT_QCOW2)
    } else {
        Ok(DISK_FORMAT_RAW)
    }
}

/// qcow2 image backend with two-level L1/L2 table navigation.
///
/// Supports reading and writing existing qcow2 images. New clusters
/// are allocated by appending to the end of the file (append-only).
/// Unallocated clusters delegate to an optional backing file.
/// No compression, encryption, or snapshot support.
struct Qcow2DiskBackend {
    file: File,
    header: Qcow2Header,
    cluster_size: u64,
    l2_entries_per_table: u64,
    l1_table: Vec<u64>,
    refcount_table: Vec<u64>,
    next_free_cluster: u64,
    read_only: bool,
    backing: Option<Box<dyn DiskBackend>>,
}

impl Qcow2DiskBackend {
    /// Open a qcow2 image file and parse its metadata.
    fn open(path: &Path, read_only: bool) -> Result<Self> {
        let mut file = File::options()
            .read(true)
            .write(!read_only)
            .open(path)
            .map_err(|e| {
                WkrunError::Device(format!(
                    "failed to open qcow2 disk '{}': {}",
                    path.display(),
                    e
                ))
            })?;

        // Read header.
        let mut header_buf = [0u8; 104];
        file.read_exact(&mut header_buf)
            .map_err(|e| WkrunError::Device(format!("failed to read qcow2 header: {}", e)))?;
        let header = Qcow2Header::parse(&header_buf)?;

        let cluster_size = 1u64 << header.cluster_bits;
        let l2_entries_per_table = cluster_size / 8;

        // Read L1 table.
        let l1_byte_len = (header.l1_size as usize) * 8;
        let mut l1_bytes = vec![0u8; l1_byte_len];
        file.seek(SeekFrom::Start(header.l1_table_offset))
            .map_err(|e| WkrunError::Device(format!("failed to seek to L1 table: {}", e)))?;
        file.read_exact(&mut l1_bytes)
            .map_err(|e| WkrunError::Device(format!("failed to read L1 table: {}", e)))?;
        let l1_table: Vec<u64> = l1_bytes
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect();

        // Read refcount table.
        let refcount_entries = (header.refcount_table_clusters as u64 * cluster_size / 8) as usize;
        let mut refcount_bytes = vec![0u8; refcount_entries * 8];
        file.seek(SeekFrom::Start(header.refcount_table_offset))
            .map_err(|e| WkrunError::Device(format!("failed to seek to refcount table: {}", e)))?;
        file.read_exact(&mut refcount_bytes)
            .map_err(|e| WkrunError::Device(format!("failed to read refcount table: {}", e)))?;
        let refcount_table: Vec<u64> = refcount_bytes
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect();

        // Determine next free cluster: end of file rounded up to cluster boundary.
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| WkrunError::Device(format!("failed to get qcow2 file size: {}", e)))?;
        let next_free_cluster = file_len.div_ceil(cluster_size) * cluster_size;

        // Open backing file if referenced in the header.
        let backing = if header.backing_file_offset != 0 && header.backing_file_size > 0 {
            file.seek(SeekFrom::Start(header.backing_file_offset))
                .map_err(|e| {
                    WkrunError::Device(format!("failed to seek to backing file path: {}", e))
                })?;
            let mut path_buf = vec![0u8; header.backing_file_size as usize];
            file.read_exact(&mut path_buf).map_err(|e| {
                WkrunError::Device(format!("failed to read backing file path: {}", e))
            })?;
            let backing_path_str = String::from_utf8(path_buf).map_err(|e| {
                WkrunError::Device(format!("invalid UTF-8 in backing file path: {}", e))
            })?;

            // Resolve relative paths against the parent directory of this qcow2 file.
            let backing_path = {
                let p = PathBuf::from(&backing_path_str);
                if p.is_absolute() {
                    p
                } else {
                    path.parent().unwrap_or_else(|| Path::new(".")).join(&p)
                }
            };

            let backing_format = detect_disk_format(&backing_path)?;
            let backend = open_disk_backend(&backing_path, backing_format, true)?;
            Some(backend)
        } else {
            None
        };

        Ok(Qcow2DiskBackend {
            file,
            header,
            cluster_size,
            l2_entries_per_table,
            l1_table,
            refcount_table,
            next_free_cluster,
            read_only,
            backing,
        })
    }

    /// Resolve a guest byte offset to a host file offset.
    /// Returns `None` if the cluster is unallocated.
    fn resolve_offset(&mut self, guest_offset: u64) -> Result<Option<u64>> {
        let l1_index = (guest_offset / self.cluster_size / self.l2_entries_per_table) as usize;
        let l2_index = ((guest_offset / self.cluster_size) % self.l2_entries_per_table) as usize;
        let offset_in_cluster = guest_offset % self.cluster_size;

        if l1_index >= self.l1_table.len() {
            return Ok(None);
        }

        let l1_entry = self.l1_table[l1_index];
        let l2_table_offset = l1_entry & L2_OFFSET_MASK;
        if l2_table_offset == 0 {
            return Ok(None);
        }

        // Read the L2 entry.
        let l2_entry_file_offset = l2_table_offset + (l2_index as u64) * 8;
        self.file
            .seek(SeekFrom::Start(l2_entry_file_offset))
            .map_err(|e| WkrunError::Device(format!("qcow2: failed to seek L2 entry: {}", e)))?;
        let mut entry_buf = [0u8; 8];
        self.file
            .read_exact(&mut entry_buf)
            .map_err(|e| WkrunError::Device(format!("qcow2: failed to read L2 entry: {}", e)))?;
        let l2_entry = u64::from_be_bytes(entry_buf);

        let data_cluster_offset = l2_entry & L2_OFFSET_MASK;
        if data_cluster_offset == 0 {
            return Ok(None);
        }

        Ok(Some(data_cluster_offset + offset_in_cluster))
    }

    /// Allocate a new cluster by appending to the file.
    /// Updates refcount for the new cluster.
    fn allocate_cluster(&mut self) -> Result<u64> {
        let offset = self.allocate_raw_cluster()?;
        self.set_refcount(offset, 1)?;
        Ok(offset)
    }

    /// Allocate a new cluster without updating refcounts.
    /// Used internally to break recursion when allocating refcount blocks.
    fn allocate_raw_cluster(&mut self) -> Result<u64> {
        let offset = self.next_free_cluster;
        let zeros = vec![0u8; self.cluster_size as usize];
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| WkrunError::Device(format!("qcow2: seek for alloc failed: {}", e)))?;
        self.file
            .write_all(&zeros)
            .map_err(|e| WkrunError::Device(format!("qcow2: cluster alloc write failed: {}", e)))?;
        self.next_free_cluster = offset + self.cluster_size;
        Ok(offset)
    }

    /// Set the refcount for a cluster at the given file offset.
    ///
    /// Navigates the two-level refcount table. If the refcount block
    /// is missing, allocates one (using raw allocation to avoid recursion).
    fn set_refcount(&mut self, cluster_offset: u64, count: u16) -> Result<()> {
        let cluster_index = cluster_offset / self.cluster_size;
        let refcount_bits = 1u32 << self.header.refcount_order;
        let entries_per_block = self.cluster_size * 8 / refcount_bits as u64;

        let refcount_table_index = (cluster_index / entries_per_block) as usize;
        let block_index = cluster_index % entries_per_block;

        if refcount_table_index >= self.refcount_table.len() {
            // Refcount table too small — skip for now (append-only images
            // with limited allocations rarely hit this).
            return Ok(());
        }

        let mut block_offset = self.refcount_table[refcount_table_index];
        if block_offset == 0 {
            // Allocate a new refcount block (raw — no recursive refcount update).
            block_offset = self.allocate_raw_cluster()?;
            self.refcount_table[refcount_table_index] = block_offset;
            // Write updated refcount table entry back to disk.
            let rt_entry_offset =
                self.header.refcount_table_offset + (refcount_table_index as u64) * 8;
            self.file
                .seek(SeekFrom::Start(rt_entry_offset))
                .map_err(|e| {
                    WkrunError::Device(format!("qcow2: seek refcount table entry: {}", e))
                })?;
            self.file
                .write_all(&block_offset.to_be_bytes())
                .map_err(|e| {
                    WkrunError::Device(format!("qcow2: write refcount table entry: {}", e))
                })?;
        }

        // Write the 16-bit refcount entry.
        let entry_offset = block_offset + block_index * (refcount_bits as u64 / 8);
        self.file
            .seek(SeekFrom::Start(entry_offset))
            .map_err(|e| WkrunError::Device(format!("qcow2: seek refcount entry: {}", e)))?;
        self.file
            .write_all(&count.to_be_bytes())
            .map_err(|e| WkrunError::Device(format!("qcow2: write refcount entry: {}", e)))?;

        Ok(())
    }

    /// Ensure an L2 table exists for the given L1 index. Allocates if needed.
    /// Returns the file offset of the L2 table.
    fn ensure_l2_table(&mut self, l1_index: usize) -> Result<u64> {
        let l1_entry = self.l1_table[l1_index];
        let l2_offset = l1_entry & L2_OFFSET_MASK;
        if l2_offset != 0 {
            return Ok(l2_offset);
        }

        // Allocate a new L2 table cluster.
        let new_l2_offset = self.allocate_cluster()?;

        // Update in-memory L1 table.
        self.l1_table[l1_index] = new_l2_offset;

        // Write L1 entry back to disk.
        let l1_entry_file_offset = self.header.l1_table_offset + (l1_index as u64) * 8;
        self.file
            .seek(SeekFrom::Start(l1_entry_file_offset))
            .map_err(|e| WkrunError::Device(format!("qcow2: seek L1 entry: {}", e)))?;
        self.file
            .write_all(&new_l2_offset.to_be_bytes())
            .map_err(|e| WkrunError::Device(format!("qcow2: write L1 entry: {}", e)))?;

        Ok(new_l2_offset)
    }

    /// Ensure a data cluster exists for the given guest offset.
    /// Allocates L2 table and/or data cluster if needed.
    /// Returns the host file offset for the data.
    fn ensure_data_cluster(&mut self, guest_offset: u64) -> Result<u64> {
        let l1_index = (guest_offset / self.cluster_size / self.l2_entries_per_table) as usize;
        let l2_index = ((guest_offset / self.cluster_size) % self.l2_entries_per_table) as usize;
        let offset_in_cluster = guest_offset % self.cluster_size;

        if l1_index >= self.l1_table.len() {
            return Err(WkrunError::Device(format!(
                "qcow2: guest offset {} exceeds virtual size",
                guest_offset
            )));
        }

        let l2_table_offset = self.ensure_l2_table(l1_index)?;

        // Read the L2 entry.
        let l2_entry_file_offset = l2_table_offset + (l2_index as u64) * 8;
        self.file
            .seek(SeekFrom::Start(l2_entry_file_offset))
            .map_err(|e| WkrunError::Device(format!("qcow2: seek L2 entry: {}", e)))?;
        let mut entry_buf = [0u8; 8];
        self.file
            .read_exact(&mut entry_buf)
            .map_err(|e| WkrunError::Device(format!("qcow2: read L2 entry: {}", e)))?;
        let l2_entry = u64::from_be_bytes(entry_buf);
        let data_offset = l2_entry & L2_OFFSET_MASK;

        if data_offset != 0 {
            return Ok(data_offset + offset_in_cluster);
        }

        // Allocate a new data cluster.
        let new_data_offset = self.allocate_cluster()?;

        // Write L2 entry back to disk.
        self.file
            .seek(SeekFrom::Start(l2_entry_file_offset))
            .map_err(|e| WkrunError::Device(format!("qcow2: seek L2 entry for write: {}", e)))?;
        self.file
            .write_all(&new_data_offset.to_be_bytes())
            .map_err(|e| WkrunError::Device(format!("qcow2: write L2 entry: {}", e)))?;

        Ok(new_data_offset + offset_in_cluster)
    }
}

impl DiskBackend for Qcow2DiskBackend {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut pos = 0usize;
        let mut guest_offset = offset;

        while pos < buf.len() {
            let offset_in_cluster = guest_offset % self.cluster_size;
            let remaining_in_cluster = (self.cluster_size - offset_in_cluster) as usize;
            let chunk_len = remaining_in_cluster.min(buf.len() - pos);

            match self.resolve_offset(guest_offset)? {
                Some(host_offset) => {
                    self.file.seek(SeekFrom::Start(host_offset)).map_err(|e| {
                        WkrunError::Device(format!("qcow2: read seek failed: {}", e))
                    })?;
                    self.file
                        .read_exact(&mut buf[pos..pos + chunk_len])
                        .map_err(|e| WkrunError::Device(format!("qcow2: read failed: {}", e)))?;
                }
                None => {
                    // Unallocated cluster — read from backing file or return zeros.
                    match self.backing {
                        Some(ref mut b) => {
                            b.read_at(guest_offset, &mut buf[pos..pos + chunk_len])?
                        }
                        None => buf[pos..pos + chunk_len].fill(0),
                    }
                }
            }

            pos += chunk_len;
            guest_offset += chunk_len as u64;
        }

        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(WkrunError::Device(
                "qcow2: write rejected on read-only disk".into(),
            ));
        }

        let mut pos = 0usize;
        let mut guest_offset = offset;

        while pos < buf.len() {
            let offset_in_cluster = guest_offset % self.cluster_size;
            let remaining_in_cluster = (self.cluster_size - offset_in_cluster) as usize;
            let chunk_len = remaining_in_cluster.min(buf.len() - pos);

            let host_offset = self.ensure_data_cluster(guest_offset)?;

            self.file
                .seek(SeekFrom::Start(host_offset))
                .map_err(|e| WkrunError::Device(format!("qcow2: write seek failed: {}", e)))?;
            self.file
                .write_all(&buf[pos..pos + chunk_len])
                .map_err(|e| WkrunError::Device(format!("qcow2: write failed: {}", e)))?;

            pos += chunk_len;
            guest_offset += chunk_len as u64;
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| WkrunError::Device(format!("qcow2: flush failed: {}", e)))?;
        Ok(())
    }

    fn capacity_bytes(&self) -> u64 {
        self.header.size
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Open a disk backend based on the specified format.
///
/// - `DISK_FORMAT_RAW` (0): raw file passthrough
/// - `DISK_FORMAT_QCOW2` (1): qcow2 image with copy-on-write
pub fn open_disk_backend(
    path: &Path,
    format: u32,
    read_only: bool,
) -> Result<Box<dyn DiskBackend>> {
    match format {
        DISK_FORMAT_RAW => {
            let file = File::options()
                .read(true)
                .write(!read_only)
                .open(path)
                .map_err(|e| {
                    WkrunError::Device(format!("failed to open disk '{}': {}", path.display(), e))
                })?;
            Ok(Box::new(RawDiskBackend::new(file)?))
        }
        DISK_FORMAT_QCOW2 => {
            let backend = Qcow2DiskBackend::open(path, read_only)?;
            Ok(Box::new(backend))
        }
        _ => Err(WkrunError::Device(format!(
            "unsupported disk format: {}",
            format
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;

    fn create_raw_file(size: usize) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; size]).unwrap();
        f.flush().unwrap();
        f
    }

    fn create_raw_file_with_pattern(sectors: u64) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for sector in 0..sectors {
            let pattern = vec![(sector & 0xFF) as u8; 512];
            f.write_all(&pattern).unwrap();
        }
        f.flush().unwrap();
        f
    }

    // --- RawDiskBackend ---

    #[test]
    fn test_raw_backend_capacity() {
        let tmp = create_raw_file(4096);
        let file = File::open(tmp.path()).unwrap();
        let backend = RawDiskBackend::new(file).unwrap();
        assert_eq!(backend.capacity_bytes(), 4096);
    }

    #[test]
    fn test_raw_backend_empty_file_error() {
        let tmp = NamedTempFile::new().unwrap();
        let file = File::open(tmp.path()).unwrap();
        assert!(RawDiskBackend::new(file).is_err());
    }

    #[test]
    fn test_raw_backend_read_at() {
        let tmp = create_raw_file_with_pattern(4);
        let file = File::options()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        let mut backend = RawDiskBackend::new(file).unwrap();

        let mut buf = [0u8; 512];
        backend.read_at(512 * 2, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x02));
    }

    #[test]
    fn test_raw_backend_write_at() {
        let tmp = create_raw_file(2048);
        let file = File::options()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        let mut backend = RawDiskBackend::new(file).unwrap();

        let data = vec![0xABu8; 512];
        backend.write_at(512, &data).unwrap();

        let mut buf = [0u8; 512];
        backend.read_at(512, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_raw_backend_flush() {
        let tmp = create_raw_file(512);
        let file = File::options()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        let mut backend = RawDiskBackend::new(file).unwrap();
        backend.flush().unwrap();
    }

    // --- open_disk_backend factory ---

    #[test]
    fn test_factory_raw_format() {
        let tmp = create_raw_file(1024);
        let backend = open_disk_backend(tmp.path(), DISK_FORMAT_RAW, false).unwrap();
        assert_eq!(backend.capacity_bytes(), 1024);
    }

    #[test]
    fn test_factory_invalid_format() {
        let tmp = create_raw_file(1024);
        let result = open_disk_backend(tmp.path(), 99, false);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // qcow2 test helpers
    // -----------------------------------------------------------------------

    /// Create a minimal qcow2 v2 image programmatically.
    ///
    /// Layout (cluster_size = 512 for small tests):
    ///   Cluster 0: header
    ///   Cluster 1: refcount table (1 entry pointing to cluster 2)
    ///   Cluster 2: refcount block (refcounts for clusters 0..N)
    ///   Cluster 3: L1 table
    ///   [Cluster 4+: optional pre-allocated L2 + data]
    ///
    /// `preallocated` is a list of (guest_byte_offset, data) pairs to
    /// write into the image at construction time.
    fn create_test_qcow2(
        virtual_size: u64,
        cluster_bits: u32,
        preallocated: &[(u64, &[u8])],
    ) -> NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 8;

        // Calculate L1 table size.
        let l1_entries = virtual_size.div_ceil(cluster_size * l2_entries) as u32;

        // Fixed layout:
        // Cluster 0: header
        // Cluster 1: refcount table
        // Cluster 2: refcount block
        // Cluster 3: L1 table (may span multiple clusters but 1 for small tests)
        let refcount_table_offset = cluster_size;
        let refcount_block_offset = cluster_size * 2;
        let l1_table_offset = cluster_size * 3;
        let mut next_cluster = cluster_size * 4; // First free cluster.

        // Collect allocations needed for preallocated data.
        struct PreallocInfo {
            l2_idx: usize,
            l2_cluster: u64,
            data_cluster: u64,
            data: Vec<u8>,
            data_offset_in_cluster: u64,
        }

        let mut l2_clusters: std::collections::HashMap<usize, u64> =
            std::collections::HashMap::new();
        let mut allocs = Vec::new();

        for &(guest_offset, data) in preallocated {
            let l1_idx = (guest_offset / cluster_size / l2_entries) as usize;
            let l2_idx = ((guest_offset / cluster_size) % l2_entries) as usize;
            let offset_in_cluster = guest_offset % cluster_size;

            let l2_cluster = *l2_clusters.entry(l1_idx).or_insert_with(|| {
                let c = next_cluster;
                next_cluster += cluster_size;
                c
            });

            let data_cluster = next_cluster;
            next_cluster += cluster_size;

            allocs.push(PreallocInfo {
                l2_idx,
                l2_cluster,
                data_cluster,
                data: data.to_vec(),
                data_offset_in_cluster: offset_in_cluster,
            });
        }

        let total_clusters = next_cluster / cluster_size;
        let file_size = next_cluster;

        // Build the file.
        let mut f = NamedTempFile::new().unwrap();
        let mut image = vec![0u8; file_size as usize];

        // --- Header (cluster 0) ---
        // Magic.
        image[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        // Version = 2.
        image[4..8].copy_from_slice(&2u32.to_be_bytes());
        // Backing file offset = 0.
        image[8..16].copy_from_slice(&0u64.to_be_bytes());
        // Backing file size = 0.
        image[16..20].copy_from_slice(&0u32.to_be_bytes());
        // Cluster bits.
        image[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
        // Virtual size.
        image[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        // Crypt method = 0.
        image[32..36].copy_from_slice(&0u32.to_be_bytes());
        // L1 size.
        image[36..40].copy_from_slice(&l1_entries.to_be_bytes());
        // L1 table offset.
        image[40..48].copy_from_slice(&l1_table_offset.to_be_bytes());
        // Refcount table offset.
        image[48..56].copy_from_slice(&refcount_table_offset.to_be_bytes());
        // Refcount table clusters = 1.
        image[56..60].copy_from_slice(&1u32.to_be_bytes());
        // Nb snapshots = 0.
        image[60..64].copy_from_slice(&0u32.to_be_bytes());

        // --- Refcount table (cluster 1) ---
        // Single entry pointing to refcount block at cluster 2.
        let rt_off = refcount_table_offset as usize;
        image[rt_off..rt_off + 8].copy_from_slice(&refcount_block_offset.to_be_bytes());

        // --- Refcount block (cluster 2) ---
        // Set refcount=1 for all allocated clusters (16-bit BE entries).
        let rb_off = refcount_block_offset as usize;
        for i in 0..total_clusters {
            let entry_off = rb_off + (i as usize) * 2;
            image[entry_off..entry_off + 2].copy_from_slice(&1u16.to_be_bytes());
        }

        // --- L1 table (cluster 3) ---
        for (&l1_idx, &l2_cluster) in &l2_clusters {
            let entry_off = l1_table_offset as usize + l1_idx * 8;
            image[entry_off..entry_off + 8].copy_from_slice(&l2_cluster.to_be_bytes());
        }

        // --- L2 tables + data clusters ---
        for alloc in &allocs {
            // Write L2 entry.
            let l2_entry_off = alloc.l2_cluster as usize + alloc.l2_idx * 8;
            image[l2_entry_off..l2_entry_off + 8]
                .copy_from_slice(&alloc.data_cluster.to_be_bytes());

            // Write data.
            let data_off = alloc.data_cluster as usize + alloc.data_offset_in_cluster as usize;
            let end = data_off + alloc.data.len();
            image[data_off..end].copy_from_slice(&alloc.data);
        }

        f.write_all(&image).unwrap();
        f.flush().unwrap();
        f
    }

    // -----------------------------------------------------------------------
    // qcow2 header parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_qcow2_header_valid_v2() {
        let tmp = create_test_qcow2(1024 * 1024, 16, &[]);
        let backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();
        assert_eq!(backend.header.version, 2);
        assert_eq!(backend.header.cluster_bits, 16);
        assert_eq!(backend.capacity_bytes(), 1024 * 1024);
    }

    #[test]
    fn test_qcow2_header_bad_magic() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let err = Qcow2DiskBackend::open(tmp.path(), false).err().unwrap();
        assert!(err.to_string().contains("bad magic"), "error was: {}", err);
    }

    #[test]
    fn test_qcow2_header_bad_version() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&1u32.to_be_bytes()); // Version 1.
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let err = Qcow2DiskBackend::open(tmp.path(), false).err().unwrap();
        assert!(err.to_string().contains("version"), "error was: {}", err);
    }

    #[test]
    fn test_qcow2_header_backing_file_parsed() {
        // Verify that header parsing accepts backing_file_offset != 0.
        let mut buf = [0u8; 104];
        buf[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&2u32.to_be_bytes());
        buf[8..16].copy_from_slice(&100u64.to_be_bytes()); // Backing file offset.
        buf[16..20].copy_from_slice(&10u32.to_be_bytes()); // Backing file size.
        buf[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits.
        buf[24..32].copy_from_slice(&(1024u64 * 1024).to_be_bytes()); // size.
        buf[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size.
        buf[40..48].copy_from_slice(&(65536u64).to_be_bytes()); // l1_table_offset.
        buf[48..56].copy_from_slice(&(65536u64).to_be_bytes()); // refcount_table_offset.
        buf[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters.

        let header = Qcow2Header::parse(&buf).unwrap();
        assert_eq!(header.backing_file_offset, 100);
        assert_eq!(header.backing_file_size, 10);
    }

    #[test]
    fn test_qcow2_header_encryption_rejected() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&2u32.to_be_bytes());
        data[8..16].copy_from_slice(&0u64.to_be_bytes()); // No backing.
        data[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits.
        data[24..32].copy_from_slice(&(1024u64 * 1024).to_be_bytes());
        data[32..36].copy_from_slice(&1u32.to_be_bytes()); // Encrypted!
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let err = Qcow2DiskBackend::open(tmp.path(), false).err().unwrap();
        assert!(err.to_string().contains("encryption"), "error was: {}", err);
    }

    // -----------------------------------------------------------------------
    // qcow2 reads
    // -----------------------------------------------------------------------

    #[test]
    fn test_qcow2_read_unallocated_returns_zeros() {
        // 1MB image with no preallocated data, cluster_bits=9 (512B clusters).
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        let mut buf = [0xFFu8; 512];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_qcow2_read_allocated_cluster() {
        let pattern = vec![0xABu8; 128];
        let tmp = create_test_qcow2(1024 * 1024, 9, &[(512, &pattern)]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        let mut buf = [0u8; 128];
        backend.read_at(512, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_qcow2_read_cross_cluster_boundary() {
        // Two adjacent clusters with different data.
        let data0 = vec![0x11u8; 512];
        let data1 = vec![0x22u8; 512];
        let tmp = create_test_qcow2(1024 * 1024, 9, &[(0, &data0), (512, &data1)]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        // Read 256 bytes spanning the boundary (last 128 of cluster 0 + first 128 of cluster 1).
        let mut buf = [0u8; 256];
        backend.read_at(384, &mut buf).unwrap();
        assert!(buf[..128].iter().all(|&b| b == 0x11));
        assert!(buf[128..].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn test_qcow2_capacity() {
        let tmp = create_test_qcow2(2 * 1024 * 1024, 16, &[]);
        let backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();
        assert_eq!(backend.capacity_bytes(), 2 * 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // qcow2 writes
    // -----------------------------------------------------------------------

    #[test]
    fn test_qcow2_write_allocates_cluster() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        let data = vec![0xCDu8; 256];
        backend.write_at(0, &data).unwrap();

        let mut buf = [0u8; 256];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn test_qcow2_write_read_roundtrip() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        // Write different patterns at different offsets.
        backend.write_at(0, &[0x11; 512]).unwrap();
        backend.write_at(512, &[0x22; 512]).unwrap();
        backend.write_at(1024, &[0x33; 512]).unwrap();

        let mut buf0 = [0u8; 512];
        let mut buf1 = [0u8; 512];
        let mut buf2 = [0u8; 512];
        backend.read_at(0, &mut buf0).unwrap();
        backend.read_at(512, &mut buf1).unwrap();
        backend.read_at(1024, &mut buf2).unwrap();

        assert!(buf0.iter().all(|&b| b == 0x11));
        assert!(buf1.iter().all(|&b| b == 0x22));
        assert!(buf2.iter().all(|&b| b == 0x33));
    }

    #[test]
    fn test_qcow2_write_partial_cluster() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        // Write 100 bytes in the middle of cluster 0.
        backend.write_at(200, &[0xBB; 100]).unwrap();

        // Verify: first 200 bytes = zeros, next 100 = 0xBB, rest = zeros.
        let mut buf = [0u8; 512];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf[..200].iter().all(|&b| b == 0x00));
        assert!(buf[200..300].iter().all(|&b| b == 0xBB));
        assert!(buf[300..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_qcow2_write_cross_cluster_boundary() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        // Write 256 bytes spanning cluster boundary (cluster_size=512).
        let data = vec![0xEE; 256];
        backend.write_at(384, &data).unwrap();

        let mut buf = [0u8; 256];
        backend.read_at(384, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xEE));

        // Verify untouched parts.
        let mut before = [0u8; 384];
        backend.read_at(0, &mut before).unwrap();
        assert!(before.iter().all(|&b| b == 0x00));

        let mut after = [0u8; 128];
        backend.read_at(640, &mut after).unwrap();
        assert!(after.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_qcow2_write_same_cluster_no_realloc() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        backend.write_at(0, &[0x11; 256]).unwrap();
        let free_before = backend.next_free_cluster;

        // Write again to the same cluster — should not allocate new clusters.
        backend.write_at(256, &[0x22; 256]).unwrap();
        assert_eq!(backend.next_free_cluster, free_before);

        // Verify both writes persisted.
        let mut buf = [0u8; 512];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf[..256].iter().all(|&b| b == 0x11));
        assert!(buf[256..].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn test_qcow2_l2_table_allocation() {
        // Use cluster_bits=9 (512B), virtual_size=1MB.
        // L2 entries per table = 512/8 = 64.
        // So each L1 entry covers 64*512 = 32768 bytes.
        // Writing at offset 32768 requires L1 index=1 (new L2 table).
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();

        let data = vec![0xAA; 512];
        backend.write_at(32768, &data).unwrap();

        let mut buf = [0u8; 512];
        backend.read_at(32768, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_qcow2_read_only_rejects_writes() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), true).unwrap();

        let result = backend.write_at(0, &[0x11; 512]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("read-only"), "error was: {}", err);
    }

    #[test]
    fn test_qcow2_flush() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = Qcow2DiskBackend::open(tmp.path(), false).unwrap();
        backend.write_at(0, &[0x42; 512]).unwrap();
        backend.flush().unwrap();
    }

    // -----------------------------------------------------------------------
    // Factory: qcow2 dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_factory_qcow2_format() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let mut backend = open_disk_backend(tmp.path(), DISK_FORMAT_QCOW2, false).unwrap();
        assert_eq!(backend.capacity_bytes(), 1024 * 1024);

        // Write + read through the factory-created backend.
        backend.write_at(0, &[0x99; 512]).unwrap();
        let mut buf = [0u8; 512];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x99));
    }

    // -----------------------------------------------------------------------
    // Backing file support
    // -----------------------------------------------------------------------

    /// Create a minimal qcow2 v2 image with a backing file reference.
    ///
    /// Layout (cluster_size = 512):
    ///   Cluster 0: header + backing file path
    ///   Cluster 1: refcount table
    ///   Cluster 2: refcount block
    ///   Cluster 3: L1 table (all zeros — everything reads from backing)
    fn create_test_qcow2_with_backing(
        virtual_size: u64,
        cluster_bits: u32,
        backing_path: &Path,
    ) -> NamedTempFile {
        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 8;
        let l1_entries = virtual_size.div_ceil(cluster_size * l2_entries) as u32;

        let backing_path_bytes = backing_path.to_string_lossy().as_bytes().to_vec();
        let backing_path_len = backing_path_bytes.len() as u32;
        // Store backing path right after the 104-byte header.
        let backing_file_offset: u64 = 104;

        let refcount_table_offset = cluster_size;
        let refcount_block_offset = cluster_size * 2;
        let l1_table_offset = cluster_size * 3;
        let total_clusters = 4u64;
        let file_size = cluster_size * total_clusters;

        let mut f = NamedTempFile::new().unwrap();
        let mut image = vec![0u8; file_size as usize];

        // --- Header (cluster 0) ---
        image[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        image[4..8].copy_from_slice(&2u32.to_be_bytes()); // version
        image[8..16].copy_from_slice(&backing_file_offset.to_be_bytes());
        image[16..20].copy_from_slice(&backing_path_len.to_be_bytes());
        image[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
        image[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        image[32..36].copy_from_slice(&0u32.to_be_bytes()); // crypt_method
        image[36..40].copy_from_slice(&l1_entries.to_be_bytes());
        image[40..48].copy_from_slice(&l1_table_offset.to_be_bytes());
        image[48..56].copy_from_slice(&refcount_table_offset.to_be_bytes());
        image[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters
        image[60..64].copy_from_slice(&0u32.to_be_bytes()); // nb_snapshots

        // Backing file path (after header).
        let start = backing_file_offset as usize;
        image[start..start + backing_path_bytes.len()].copy_from_slice(&backing_path_bytes);

        // --- Refcount table (cluster 1) ---
        let rt_off = refcount_table_offset as usize;
        image[rt_off..rt_off + 8].copy_from_slice(&refcount_block_offset.to_be_bytes());

        // --- Refcount block (cluster 2) ---
        let rb_off = refcount_block_offset as usize;
        for i in 0..total_clusters {
            let entry_off = rb_off + (i as usize) * 2;
            image[entry_off..entry_off + 2].copy_from_slice(&1u16.to_be_bytes());
        }

        // L1 table (cluster 3) — all zeros (everything unallocated → backing).

        f.write_all(&image).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_qcow2_backing_file_read() {
        // Create a raw base disk with a known pattern.
        let base = create_raw_file_with_pattern(8); // 8 sectors = 4096 bytes
        let base_path = base.path().to_path_buf();

        // Create a QCOW2 child that references the base as backing.
        let child = create_test_qcow2_with_backing(4096, 9, &base_path);

        let mut backend = Qcow2DiskBackend::open(child.path(), false).unwrap();

        // Read sector 0 — should come from backing (pattern byte = 0x00).
        let mut buf = [0u8; 512];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x00));

        // Read sector 3 — should come from backing (pattern byte = 0x03).
        backend.read_at(512 * 3, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x03));

        // Read sector 7 — should come from backing (pattern byte = 0x07).
        backend.read_at(512 * 7, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x07));
    }

    #[test]
    fn test_qcow2_backing_file_cow_write() {
        // Create a raw base disk with pattern.
        let base = create_raw_file_with_pattern(8);
        let base_path = base.path().to_path_buf();

        let child = create_test_qcow2_with_backing(4096, 9, &base_path);
        let mut backend = Qcow2DiskBackend::open(child.path(), false).unwrap();

        // Write to sector 2 in the child.
        backend.write_at(512 * 2, &[0xFF; 512]).unwrap();

        // Read sector 2 — should reflect the child write (0xFF).
        let mut buf = [0u8; 512];
        backend.read_at(512 * 2, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xFF));

        // Read sector 3 — should still come from backing (0x03).
        backend.read_at(512 * 3, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x03));

        // Read sector 0 — should still come from backing (0x00).
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_qcow2_backing_file_missing_errors() {
        let missing_path = Path::new("/nonexistent/backing/file.raw");
        let child = create_test_qcow2_with_backing(4096, 9, missing_path);

        let result = Qcow2DiskBackend::open(child.path(), false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent") || err.contains("No such file"),
            "error was: {}",
            err
        );
    }

    #[test]
    fn test_detect_disk_format_raw() {
        let tmp = create_raw_file(1024);
        let fmt = detect_disk_format(tmp.path()).unwrap();
        assert_eq!(fmt, DISK_FORMAT_RAW);
    }

    #[test]
    fn test_detect_disk_format_qcow2() {
        let tmp = create_test_qcow2(1024 * 1024, 9, &[]);
        let fmt = detect_disk_format(tmp.path()).unwrap();
        assert_eq!(fmt, DISK_FORMAT_QCOW2);
    }
}
