//! x86 native register and event types for the KVM VMI bindings.

mod event;
mod regs;

pub use self::{
    event::{
        KvmBreakpointEvent, KvmCpuidEvent, KvmCr, KvmCrEvent, KvmDebugEvent, KvmEventReasonX86,
        KvmIoEvent, KvmMsrEvent, KvmSegmentX86, KvmVmiRegsX86,
    },
    regs::{KvmDtable, KvmSegment, Registers},
};

#[allow(unused_imports)]
pub(crate) use self::event::decode_event;
