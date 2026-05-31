//! Turns a QEMU pid into duplicated VM and vCPU fds via pidfd_getfd.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::KvmError;

/// The fds an agent needs to drive a VM: the VM fd and one fd per vCPU.
pub struct KvmFds {
    /// The duplicated KVM VM fd.
    pub vm: OwnedFd,

    /// Duplicated vCPU fds, indexed by vCPU id (ascending /proc fd order).
    pub vcpus: Vec<OwnedFd>,
}

/// Kind of KVM anon-inode behind a `/proc/<pid>/fd` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FdKind {
    /// A `kvm-vm` anon-inode.
    Vm,

    /// A `kvm-vcpu` anon-inode.
    Vcpu,
}

impl FdKind {
    /// Classifies a resolved `/proc/<pid>/fd/<n>` symlink target.
    pub(crate) fn classify(target: &str) -> Option<FdKind> {
        if target.contains("kvm-vm") {
            return Some(FdKind::Vm);
        }
        if target.contains("kvm-vcpu") {
            return Some(FdKind::Vcpu);
        }
        None
    }
}

/// Opens a pidfd for `pid`.
fn pidfd_open(pid: i32) -> Result<OwnedFd, KvmError> {
    // SAFETY: pidfd_open is a plain syscall returning a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(KvmError::last_os_error());
    }
    // SAFETY: fd is a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Duplicates `target_fd` from `pidfd`'s process into ours.
fn pidfd_getfd(pidfd: &OwnedFd, target_fd: i32) -> Result<OwnedFd, KvmError> {
    // SAFETY: pidfd_getfd returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target_fd, 0) };
    if fd < 0 {
        return Err(KvmError::last_os_error());
    }
    // SAFETY: fd is a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Resolves the QEMU process's KVM fds and duplicates them into this process.
/// vCPU fds are returned in ascending source-fd order, which is QEMU's
/// vCPU-creation order (vcpu 0..n).
pub fn from_pid(pid: i32) -> Result<KvmFds, KvmError> {
    let pidfd = pidfd_open(pid)?;

    let dir = format!("/proc/{pid}/fd");
    let entries = std::fs::read_dir(&dir).map_err(KvmError::Io)?;

    let mut found = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_err) => continue,
        };
        let path = entry.path();
        let target = match std::fs::read_link(&path) {
            Ok(target) => target,
            Err(_err) => continue,
        };
        let target = target.to_string_lossy();
        let kind = match FdKind::classify(&target) {
            Some(kind) => kind,
            None => continue,
        };
        let num = match entry.file_name().to_string_lossy().parse::<i32>() {
            Ok(num) => num,
            Err(_err) => continue,
        };
        found.push((num, kind));
    }

    found.sort_by_key(|(num, _)| *num);

    let mut vm = None;
    let mut vcpus = Vec::new();
    for (num, kind) in found {
        let dup = pidfd_getfd(&pidfd, num)?;
        match kind {
            FdKind::Vm => vm = Some(dup),
            FdKind::Vcpu => vcpus.push(dup),
        }
    }

    let vm = match vm {
        Some(vm) => vm,
        None => return Err(KvmError::Other("no kvm-vm fd found in target process")),
    };
    if vcpus.is_empty() {
        return Err(KvmError::Other("no kvm-vcpu fds found in target process"));
    }

    Ok(KvmFds { vm, vcpus })
}

#[cfg(test)]
mod tests {
    use super::FdKind;

    #[test]
    fn classifies_links() {
        assert_eq!(FdKind::classify("anon_inode:[kvm-vm]"), Some(FdKind::Vm));
        assert_eq!(FdKind::classify("anon_inode:kvm-vm"), Some(FdKind::Vm));
        assert_eq!(
            FdKind::classify("anon_inode:[kvm-vcpu:3]"),
            Some(FdKind::Vcpu)
        );
        assert_eq!(FdKind::classify("anon_inode:kvm-vcpu"), Some(FdKind::Vcpu));
        assert_eq!(FdKind::classify("/dev/null"), None);
    }
}
