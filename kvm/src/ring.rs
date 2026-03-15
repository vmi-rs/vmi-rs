//! Per-vCPU event ring buffer.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::consts::{self, PAGE_SIZE};
use crate::error::KvmError;
use crate::session::{KvmVmiSession, kvm_ioctl};

/// Per-vCPU ring buffer wrapping the mmap'd shared page and eventfds.
pub struct KvmVmiRing {
    session: KvmVmiSession,
    vcpu_id: u32,
    _ring_fd: OwnedFd,
    event_fd: OwnedFd,
    ack_fd: OwnedFd,
    mmap_ptr: *mut u8,
}

unsafe impl Send for KvmVmiRing {}

impl KvmVmiRing {
    /// Set up a ring buffer for a vCPU.
    pub fn new(session: KvmVmiSession, vcpu_id: u32) -> Result<Self, KvmError> {
        let event_fd = Self::create_eventfd()?;
        let ack_fd = Self::create_eventfd()?;

        let mut setup = kvm_sys::kvm_vmi_setup_ring {
            vcpu_id,
            flags: 0,
            event_fd: event_fd.as_raw_fd(),
            ack_fd: ack_fd.as_raw_fd(),
            ring_fd: -1,
            pad: 0,
        };

        unsafe {
            kvm_ioctl(
                session.fd(),
                consts::KVM_VMI_SETUP_RING,
                &mut setup as *mut _ as u64,
            )?;
        }

        let ring_fd = unsafe { OwnedFd::from_raw_fd(setup.ring_fd) };

        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                ring_fd.as_raw_fd(),
                0,
            )
        };
        if mmap_ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }

        tracing::trace!(vcpu_id, "set up VMI ring");

        Ok(Self {
            session,
            vcpu_id,
            _ring_fd: ring_fd,
            event_fd,
            ack_fd,
            mmap_ptr: mmap_ptr as *mut u8,
        })
    }

    fn create_eventfd() -> Result<OwnedFd, KvmError> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// The vCPU ID this ring belongs to.
    pub fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// The eventfd the kernel signals when a new event is available.
    pub fn event_fd(&self) -> RawFd {
        self.event_fd.as_raw_fd()
    }

    fn header(&self) -> &kvm_sys::kvm_vmi_ring_header {
        unsafe { &*(self.mmap_ptr as *const kvm_sys::kvm_vmi_ring_header) }
    }

    /// Number of events waiting to be consumed.
    pub fn unconsumed_requests(&self) -> u32 {
        let h = self.header();
        let prod = unsafe { std::ptr::read_volatile(&h.req_prod) };
        let cons = unsafe { std::ptr::read_volatile(&h.req_cons) };
        prod.wrapping_sub(cons)
    }

    /// Whether there are events waiting.
    pub fn has_unconsumed_requests(&self) -> bool {
        self.unconsumed_requests() > 0
    }

    /// Get a mutable reference to the current event slot.
    ///
    /// # Safety
    ///
    /// Caller must ensure `has_unconsumed_requests()` is true.
    #[allow(clippy::mut_from_ref)] // mmap region is shared memory; &self wraps a raw *mut pointer
    pub unsafe fn current_event(&self) -> &mut kvm_sys::kvm_vmi_ring_event {
        let h = self.header();
        let cons = unsafe { std::ptr::read_volatile(&h.req_cons) };
        let slot = cons % h.num_slots;

        let header_size = std::mem::size_of::<kvm_sys::kvm_vmi_ring_header>();
        let event_size = std::mem::size_of::<kvm_sys::kvm_vmi_ring_event>();
        let ptr = unsafe { self.mmap_ptr.add(header_size + slot as usize * event_size) };

        unsafe { &mut *(ptr as *mut kvm_sys::kvm_vmi_ring_event) }
    }

    /// Advance the consumer index past the current event.
    pub fn advance_consumer(&self) {
        // Use the raw mmap pointer to compute the address of req_cons,
        // avoiding the creation of a shared reference that we then cast
        // to *mut (which is UB).
        let req_cons_ptr = unsafe {
            self.mmap_ptr
                .add(std::mem::offset_of!(kvm_sys::kvm_vmi_ring_header, req_cons))
                as *mut u32
        };
        let cons = unsafe { std::ptr::read_volatile(req_cons_ptr) };
        unsafe {
            std::ptr::write_volatile(req_cons_ptr, cons.wrapping_add(1));
        }
    }

    /// Drain the eventfd counter (acknowledge kernel notification).
    pub fn drain_eventfd(&self) {
        let mut buf = [0u8; 8];
        let _ = unsafe {
            libc::read(self.event_fd.as_raw_fd(), buf.as_mut_ptr() as _, 8)
        };
    }

    /// Signal the ack_fd to tell the kernel the response is ready.
    pub fn signal_ack(&self) {
        let val: u64 = 1;
        let _ = unsafe {
            libc::write(self.ack_fd.as_raw_fd(), &val as *const _ as _, 8)
        };
    }

    /// Acknowledge an event via ioctl - advances req_cons in kernel and wakes vCPU.
    pub fn ack_event_ioctl(&self) -> Result<(), KvmError> {
        let mut vcpu = kvm_sys::kvm_vmi_vcpu {
            vcpu_id: self.vcpu_id,
            pad: 0,
        };
        unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_ACK_EVENT,
                &mut vcpu as *mut _ as u64,
            )?;
        }
        Ok(())
    }
}

impl Drop for KvmVmiRing {
    fn drop(&mut self) {
        tracing::trace!(vcpu_id = self.vcpu_id, "tearing down VMI ring");
        let _ = unsafe {
            kvm_ioctl(
                self.session.fd(),
                consts::KVM_VMI_TEARDOWN_RING,
                &self.vcpu_id as *const u32 as u64,
            )
        };
        if !self.mmap_ptr.is_null() {
            unsafe { libc::munmap(self.mmap_ptr as _, PAGE_SIZE as usize) };
        }
    }
}
