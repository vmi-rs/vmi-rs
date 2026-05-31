//! Small shared types and the raw-ioctl helper.

use std::os::fd::{AsRawFd, BorrowedFd};

use crate::error::KvmError;

/// Identifier of an alternate memory view. View 0 is the default view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ViewId(pub u32);

/// Issues an ioctl with a typed argument pointer, mapping a negative return
/// to the last OS error.
pub(crate) fn ioctl_with_ref<T>(fd: BorrowedFd, request: u64, arg: &T) -> Result<i32, KvmError> {
    // SAFETY: `arg` outlives the call and `request` matches `T` by construction
    // at every call site.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), request as _, arg as *const T) };
    if ret < 0 {
        return Err(KvmError::last_os_error());
    }
    Ok(ret)
}

/// Issues an ioctl with a mutable argument pointer (for OUT fields).
pub(crate) fn ioctl_with_mut_ref<T>(
    fd: BorrowedFd,
    request: u64,
    arg: &mut T,
) -> Result<i32, KvmError> {
    // SAFETY: see `ioctl_with_ref`.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), request as _, arg as *mut T) };
    if ret < 0 {
        return Err(KvmError::last_os_error());
    }
    Ok(ret)
}

/// Issues an ioctl with no argument.
pub(crate) fn ioctl_none(fd: BorrowedFd, request: u64) -> Result<i32, KvmError> {
    // SAFETY: `request` is an argless ioctl by construction at the call site.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), request as _) };
    if ret < 0 {
        return Err(KvmError::last_os_error());
    }
    Ok(ret)
}
