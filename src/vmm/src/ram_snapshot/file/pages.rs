// SPDX-License-Identifier: Apache-2.0

use std::io;

pub(super) fn allocated(address: usize, len: usize, page_size: usize) -> io::Result<Vec<bool>> {
    if !address.is_multiple_of(page_size) {
        return Err(io::Error::other("unaligned RAM mapping"));
    }
    query(address, len.div_ceil(page_size), page_size)
}

#[cfg(target_os = "linux")]
fn query(address: usize, count: usize, page_size: usize) -> io::Result<Vec<bool>> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::open("/proc/self/pagemap")?;
    let mut entries = vec![0; count * 8];
    file.read_exact_at(&mut entries, (address / page_size) as u64 * 8)?;
    Ok(entries
        .chunks_exact(8)
        .map(|bytes| {
            let entry = u64::from_ne_bytes(bytes.try_into().unwrap());
            // Present OR swapped: neither a swapped-out page nor a resident zero
            // page is omitted. PFNs are not needed (and may be hidden by the kernel).
            entry & ((1 << 63) | (1 << 62)) != 0
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn query(address: usize, count: usize, page_size: usize) -> io::Result<Vec<bool>> {
    unsafe extern "C" {
        fn mach_vm_page_range_query(
            task: libc::mach_port_t,
            address: u64,
            size: u64,
            dispositions: u64,
            dispositions_count: *mut u64,
        ) -> libc::kern_return_t;
    }
    let mut dispositions = vec![0i32; count];
    let mut returned = count as u64;
    // SAFETY: the caller owns this live, page-aligned region; the output buffer
    // holds count integers and remains alive for the synchronous Mach call.
    #[allow(deprecated)]
    let status = unsafe {
        mach_vm_page_range_query(
            libc::mach_task_self(),
            address as u64,
            (count * page_size) as u64,
            dispositions.as_mut_ptr() as u64,
            &mut returned,
        )
    };
    if status != libc::KERN_SUCCESS || returned != count as u64 {
        return Err(io::Error::other(format!(
            "RAM page query failed: {status}, count={returned}"
        )));
    }
    // In particular retain PAGE_PAGED_OUT: XNU uses it for compressor/swap
    // contents. Only an entirely empty disposition is treated as unallocated.
    Ok(dispositions.into_iter().map(|flags| flags != 0).collect())
}
