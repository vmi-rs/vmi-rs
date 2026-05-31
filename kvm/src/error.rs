//! Error type for the KVM VMI bindings.

/// An error from a KVM VMI operation.
#[derive(thiserror::Error, Debug)]
pub enum KvmError {
    /// An OS-level failure from an ioctl, mmap, or syscall.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A failure that does not map to an OS error.
    #[error("{0}")]
    Other(&'static str),
}

impl KvmError {
    /// Returns the last OS error, for use after a failed libc call.
    pub(crate) fn last_os_error() -> Self {
        Self::Io(std::io::Error::last_os_error())
    }
}
