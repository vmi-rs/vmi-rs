//! Per-vCPU event ring: ring_fd mmap plus event/ack eventfds.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::{error::KvmError, memory::PAGE_SIZE};

/// Computes the slot index for a producer/consumer cursor.
pub(crate) fn slot_index(cursor: u32, num_slots: u32) -> u32 {
    cursor % num_slots
}

/// One vCPU's event ring.
pub struct KvmVmiRing {
    /// The vCPU this ring belongs to.
    vcpu_id: u32,

    /// Start of the mmap'd ring page.
    ring: *mut u8,

    /// eventfd signaled by the kernel when an event is produced.
    event_fd: OwnedFd,

    /// eventfd signaled by the agent to ack a consumed event.
    ack_fd: OwnedFd,

    /// The owned ring fd backing the mmap.
    _ring_fd: OwnedFd,

    /// The agent's private consumer cursor.
    local_cons: u32,
}

impl KvmVmiRing {
    /// Maps a ring page and takes ownership of the eventfds.
    pub fn new(
        vcpu_id: u32,
        ring_fd: OwnedFd,
        event_fd: OwnedFd,
        ack_fd: OwnedFd,
    ) -> Result<Self, KvmError> {
        // SAFETY: ring page is one page at offset 0.
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                ring_fd.as_raw_fd(),
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            return Err(KvmError::last_os_error());
        }
        Ok(Self {
            vcpu_id,
            ring: ring as *mut u8,
            event_fd,
            ack_fd,
            _ring_fd: ring_fd,
            local_cons: 0,
        })
    }

    /// Returns the vCPU id this ring belongs to.
    pub fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// Borrows the event_fd for polling.
    pub fn event_fd(&self) -> BorrowedFd<'_> {
        self.event_fd.as_fd()
    }

    /// Borrows the ack_fd for signaling.
    pub fn ack_fd(&self) -> BorrowedFd<'_> {
        self.ack_fd.as_fd()
    }

    /// Returns the ring header by shared read.
    fn header(&self) -> &kvm_sys::kvm_vmi_ring_header {
        // SAFETY: header sits at offset 0 of the ring page.
        unsafe { &*(self.ring as *const kvm_sys::kvm_vmi_ring_header) }
    }

    /// Returns true if an unconsumed event is queued.
    pub fn has_pending(&self) -> bool {
        // SAFETY: req_prod is a live shared field at offset 0.
        let prod = unsafe { std::ptr::read_volatile(&self.header().req_prod) };
        prod != self.local_cons
    }

    /// Returns a mutable pointer to the current consumer slot, or None if empty.
    pub fn current_slot(&mut self) -> Option<*mut kvm_sys::kvm_vmi_ring_event> {
        let hdr = self.header();
        // SAFETY: req_prod is a live shared field.
        let prod = unsafe { std::ptr::read_volatile(&hdr.req_prod) };
        if prod == self.local_cons {
            return None;
        }
        let num_slots = unsafe { std::ptr::read_volatile(&hdr.num_slots) };
        let idx = slot_index(self.local_cons, num_slots) as usize;
        // Slots begin after the ring header.
        // SAFETY: the ring page holds a header followed by event slots.
        let base = unsafe {
            self.ring
                .add(std::mem::size_of::<kvm_sys::kvm_vmi_ring_header>())
        };
        // SAFETY: idx < num_slots by construction of slot_index.
        let slot = unsafe {
            base.add(idx * std::mem::size_of::<kvm_sys::kvm_vmi_ring_event>())
                as *mut kvm_sys::kvm_vmi_ring_event
        };
        Some(slot)
    }

    /// Blocks on the event_fd until an event arrives or the timeout elapses.
    /// Returns true if an event is ready.
    pub fn wait(&self, timeout_ms: i32) -> Result<bool, KvmError> {
        let mut pfd = libc::pollfd {
            fd: self.event_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single valid pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret < 0 {
            return Err(KvmError::last_os_error());
        }
        if ret == 0 {
            return Ok(false);
        }
        let mut val = 0u64;
        // SAFETY: eventfd read of 8 bytes.
        let n = unsafe {
            libc::read(
                self.event_fd.as_raw_fd(),
                &mut val as *mut u64 as *mut libc::c_void,
                8,
            )
        };
        if n != 8 {
            return Err(KvmError::last_os_error());
        }
        Ok(true)
    }

    /// Advances the agent cursor after a slot has been handled and the kernel
    /// has been acked. The kernel advances req_cons on ack. The agent tracks
    /// its own cursor here.
    pub fn advance(&mut self) {
        self.local_cons = self.local_cons.wrapping_add(1);
    }
}

// SAFETY: KvmVmiRing exclusively owns its mmap region and fds. No shared
// references to the ring pointer escape, so it is safe to move across threads.
unsafe impl Send for KvmVmiRing {}

impl Drop for KvmVmiRing {
    fn drop(&mut self) {
        // SAFETY: ring came from mmap of one page.
        unsafe {
            libc::munmap(self.ring as *mut libc::c_void, PAGE_SIZE);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn slot_index_wraps() {
        assert_eq!(super::slot_index(0, 4), 0);
        assert_eq!(super::slot_index(5, 4), 1);
        assert_eq!(super::slot_index(8, 4), 0);
    }
}
