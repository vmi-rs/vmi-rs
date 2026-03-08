/// Errors from KVM VMI operations.
#[derive(thiserror::Error, Debug)]
pub enum KvmError {
    /// An I/O error from a KVM ioctl or syscall.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The operation is not supported.
    #[error("{0}")]
    Other(&'static str),
}
