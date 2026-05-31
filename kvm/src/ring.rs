//! Per-vCPU event ring: ring_fd mmap plus event/ack eventfds.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::{
    arch::x86::decode_event,
    error::KvmError,
    event::{KvmVmiEvent, KvmVmiRegs, KvmVmiResponse},
    memory::PAGE_SIZE,
};

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

    /// eventfd signaled by the kernel when an event is produced. `None` only
    /// for a test ring built over an externally-owned buffer.
    event_fd: Option<OwnedFd>,

    /// eventfd signaled by the agent to ack a consumed event. `None` only for a
    /// test ring built over an externally-owned buffer.
    ack_fd: Option<OwnedFd>,

    /// The owned ring fd backing the mmap. `None` only for a test ring whose
    /// buffer is owned elsewhere, in which case `Drop` must not munmap.
    _ring_fd: Option<OwnedFd>,

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
            event_fd: Some(event_fd),
            ack_fd: Some(ack_fd),
            _ring_fd: Some(ring_fd),
            local_cons: 0,
        })
    }

    /// Returns the vCPU id this ring belongs to.
    pub fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// Borrows the event_fd for polling.
    pub fn event_fd(&self) -> BorrowedFd<'_> {
        self.event_fd
            .as_ref()
            .expect("called event_fd() on a test ring that has no fds")
            .as_fd()
    }

    /// Borrows the ack_fd for signaling.
    pub fn ack_fd(&self) -> BorrowedFd<'_> {
        self.ack_fd
            .as_ref()
            .expect("called ack_fd() on a test ring that has no fds")
            .as_fd()
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

    /// Returns the current consumer slot index, or `None` when the ring is
    /// empty. Reads the shared producer cursor by volatile load.
    fn current_index(&self) -> Option<usize> {
        let hdr = self.header();
        // SAFETY: req_prod is a live shared field.
        let prod = unsafe { std::ptr::read_volatile(&hdr.req_prod) };
        if prod == self.local_cons {
            return None;
        }
        // SAFETY: num_slots is a live shared field.
        let num_slots = unsafe { std::ptr::read_volatile(&hdr.num_slots) };
        Some(slot_index(self.local_cons, num_slots) as usize)
    }

    /// Returns a pointer to slot `idx`. Slots begin right after the header.
    fn slot_ptr(&self, idx: usize) -> *mut kvm_sys::kvm_vmi_ring_event {
        // SAFETY: the ring page holds a header followed by event slots, and
        // idx < num_slots by construction of `current_index`.
        unsafe {
            self.ring
                .add(std::mem::size_of::<kvm_sys::kvm_vmi_ring_header>())
                .add(idx * std::mem::size_of::<kvm_sys::kvm_vmi_ring_event>())
                as *mut kvm_sys::kvm_vmi_ring_event
        }
    }

    /// Peeks the current consumer slot, decoding it into a native event, or
    /// returns `None` when no event is queued. Does not advance the cursor.
    pub fn next_event(&self) -> Option<KvmVmiEvent> {
        let idx = self.current_index()?;
        let slot_ptr = self.slot_ptr(idx);
        // SAFETY: slot_ptr points into the mapped ring page at a slot the
        // kernel has finished writing (producer cursor passed it) and will not
        // touch again until ack. Copy it out by value so no pointer escapes.
        let slot = unsafe { std::ptr::read_volatile(slot_ptr) };
        decode_event(&slot).ok()
    }

    /// Writes `resp` back into the current consumer slot, to be consumed by the
    /// kernel on ack. Does nothing when no event is queued.
    pub fn respond(&mut self, resp: KvmVmiResponse) {
        let idx = match self.current_index() {
            Some(idx) => idx,
            None => return,
        };
        let slot_ptr = self.slot_ptr(idx);
        // SAFETY: slot_ptr points into the mapped ring page at the current
        // slot. The kernel does not touch this slot until the agent acks, and
        // idx < num_slots, so these writes are exclusive and in bounds. The
        // writes are volatile because the slot is shared MAP_SHARED memory the
        // kernel reads on ack, matching the volatile read in `next_event`.
        unsafe {
            std::ptr::write_volatile(&mut (*slot_ptr).response, resp.flags());
            if let Some(view_id) = resp.view_id {
                std::ptr::write_volatile(&mut (*slot_ptr).view_id, view_id);
            }
            if let Some(KvmVmiRegs::X86(regs)) = resp.regs {
                std::ptr::write_volatile(&mut (*slot_ptr).regs, kvm_sys::kvm_vmi_regs::from(&regs));
            }
        }
    }

    /// Blocks on the event_fd until an event arrives or the timeout elapses.
    /// Returns true if an event is ready.
    pub fn wait(&self, timeout_ms: i32) -> Result<bool, KvmError> {
        let mut pfd = libc::pollfd {
            fd: self.event_fd().as_raw_fd(),
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
                self.event_fd().as_raw_fd(),
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
        // Only the production ring owns the mapping. A test ring built over an
        // externally-owned buffer has no ring_fd and must not munmap.
        if self._ring_fd.is_some() {
            // SAFETY: ring came from mmap of one page.
            unsafe {
                libc::munmap(self.ring as *mut libc::c_void, PAGE_SIZE);
            }
        }
    }
}

#[cfg(test)]
impl KvmVmiRing {
    /// Wraps an externally-owned ring buffer with no fds. `Drop` does not
    /// munmap, so the caller keeps ownership of the backing storage.
    pub(crate) fn from_raw_for_test(ring: *mut u8, vcpu_id: u32) -> Self {
        Self {
            vcpu_id,
            ring,
            event_fd: None,
            ack_fd: None,
            _ring_fd: None,
            local_cons: 0,
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

#[cfg(test)]
mod ring_tests {
    use crate::arch::x86::KvmEventReasonX86;
    use crate::event::{KvmEventReason, KvmResponseAction, KvmVmiResponse};

    fn page() -> Vec<u64> {
        let bytes = std::mem::size_of::<kvm_sys::kvm_vmi_ring_header>()
            + std::mem::size_of::<kvm_sys::kvm_vmi_ring_event>();
        vec![0u64; bytes.div_ceil(8)]
    }

    #[test]
    fn reads_decodes_and_responds() {
        let mut buf = page();
        let base = buf.as_mut_ptr() as *mut u8;
        let hdr = base as *mut kvm_sys::kvm_vmi_ring_header;
        let slot0 = unsafe {
            base.add(std::mem::size_of::<kvm_sys::kvm_vmi_ring_header>())
                as *mut kvm_sys::kvm_vmi_ring_event
        };
        unsafe {
            (*hdr).num_slots = 1;
            (*hdr).req_prod = 1;
            (*slot0) = kvm_sys::kvm_vmi_ring_event::default();
            (*slot0).type_ = kvm_sys::KVM_VMI_EVENT_BREAKPOINT;
            (*slot0).vcpu_id = 0;
            (*slot0).__bindgen_anon_1.arch.breakpoint =
                kvm_sys::kvm_vmi_event_breakpoint { gpa: 0x4000 };
        }
        let mut ring = super::KvmVmiRing::from_raw_for_test(base, 0);
        let ev = ring.next_event().expect("event queued");
        match ev.reason {
            KvmEventReason::Arch(KvmEventReasonX86::Breakpoint(bp)) => assert_eq!(bp.gpa, 0x4000),
            other => panic!("wrong reason: {other:?}"),
        }
        ring.respond(KvmVmiResponse {
            action: KvmResponseAction::Deny,
            regs: None,
            view_id: Some(7),
        });
        unsafe {
            assert_eq!((*slot0).view_id, 7);
            assert_ne!((*slot0).response & kvm_sys::KVM_VMI_RESPONSE_DENY, 0);
        }
    }
}
