#![warn(missing_docs)]

//! Memory management utilities for POSIX systems.
//!
//! This is mostly a wrapper around functions found in `<sys/mman.h>`. For
//! first-hand documentation, see [sys_mman.h(0P)].
//!
//! [sys_mman.h(0P)]: http://man7.org/linux/man-pages/man2/mlock.2.html


extern crate libc;


use std::mem;
use std::convert::From;
use std::io;


/// Representation of an arbitrary memory region.
///
/// This can safely point to invalid memory, it does not provide any access
/// (even read-only) and is merely a placeholder to support memory management
/// operation. These operations will just fail with an ENOMEM (invalid address
/// range).
pub struct MemoryView {
    ptr: *const u8,
    len: usize,
    pad: usize,
}


impl<'a, T: 'a + ?Sized> From<&'a T> for MemoryView {
    fn from(val: &'a T) -> MemoryView {
        MemoryView::from_raw_parts(
            unsafe { mem::transmute_copy(&val) },
            mem::size_of_val(val),
        )
    }
}


impl MemoryView {
    /// Construct a memory view from a pointer and a length. This is safe
    /// because the pointer will never be used to read or write the memory.
    pub fn from_raw_parts(ptr: *const u8, len: usize) -> Self {
        let pgs = page_size();
        let pad = ptr as usize & (pgs - 1);
        MemoryView {
            ptr: ptr.offset(-(pad as isize)),
            len: (len + pad + pgs - 1) & -pgs,
        }
    }
    
    /// Length of the memory region.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Pointer to the beginning of the region.
    pub fn ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Lock the memory region. Pages containing a part of the region are
    /// guaranteed to be resident in memory after a sucessful call and until
    /// they are unlocked, unmaped, otherwise freed or the process exits.
    ///
    /// Use with caution: will safe, locking too much memory can cause
    /// other processes (including the kernel) to starve.
    ///
    /// See [mlock(2)].
    ///
    /// [mlock(2)]: http://man7.org/linux/man-pages/man2/mlock.2.html
    pub fn lock(&self) -> io::Result<()> {
        unsafe {
            check(libc::mlock(
                self.ptr.offset(-(self.pad as isize)) as *const libc::c_void,
                (self.len + self.pad) as libc::size_t))
        }
    }

    /// Unlock the memory region. This will enable concerned pages to be swapped
    /// out if needed.
    ///
    /// See [mlock(2)].
    ///
    /// [mlock(2)]: http://man7.org/linux/man-pages/man2/mlock.2.html
    pub fn unlock(&self) -> io::Result<()> {
        unsafe {
            check(libc::munlock(
                self.ptr.offset(-(self.pad as isize)) as *const libc::c_void,
                (self.len + self.pad) as libc::size_t))
        }
    }

    /// Check residency information. Returns a boolean for each page containing
    /// a part of the memory region.
    ///
    /// See [mincore(2)].
    ///
    /// [mincore(2)]: http://man7.org/linux/man-pages/man2/mincore.2.html
    pub fn is_resident(&self) -> io::Result<Vec<bool>> {
        let pgs = page_size();
        let n_pages = (self.len + self.pad + pgs - 1) / pgs;
        let mut v = vec![0u8; n_pages];

        unsafe {
            check(libc::mincore(
                self.ptr.offset(-(self.pad as isize)) as *mut libc::c_void,
                (self.len + self.pad) as libc::size_t,
                v.as_mut_ptr() as *mut libc::c_uchar))?;
        }

        Ok(v.iter().map(|&b| b & 1 == 1).collect())
    }
}


/// Get the default memory page size in bytes.
pub fn page_size() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_PAGESIZE) as usize
    }
}


fn check(ret: libc::c_int) -> io::Result<()> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
