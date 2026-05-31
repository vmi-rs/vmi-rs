#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <linux/kvm_vmi_events.h>
#include <asm/kvm_vmi.h>

/* Force ioctl constants to be visible to bindgen. */
static const unsigned long kvm_sys_KVM_CREATE_VMI = KVM_CREATE_VMI;
static const unsigned long kvm_sys_KVM_VMI_SETUP_RING = KVM_VMI_SETUP_RING;
static const unsigned long kvm_sys_KVM_VMI_TEARDOWN_RING = KVM_VMI_TEARDOWN_RING;
static const unsigned long kvm_sys_KVM_VMI_ACK_EVENT = KVM_VMI_ACK_EVENT;
static const unsigned long kvm_sys_KVM_VMI_CONTROL_EVENT = KVM_VMI_CONTROL_EVENT;
static const unsigned long kvm_sys_KVM_VMI_PAUSE_VM = KVM_VMI_PAUSE_VM;
static const unsigned long kvm_sys_KVM_VMI_UNPAUSE_VM = KVM_VMI_UNPAUSE_VM;
static const unsigned long kvm_sys_KVM_VMI_PAUSE_VCPU = KVM_VMI_PAUSE_VCPU;
static const unsigned long kvm_sys_KVM_VMI_UNPAUSE_VCPU = KVM_VMI_UNPAUSE_VCPU;
static const unsigned long kvm_sys_KVM_VMI_INJECT_EVENT = KVM_VMI_INJECT_EVENT;
static const unsigned long kvm_sys_KVM_VMI_CREATE_VIEW = KVM_VMI_CREATE_VIEW;
static const unsigned long kvm_sys_KVM_VMI_DESTROY_VIEW = KVM_VMI_DESTROY_VIEW;
static const unsigned long kvm_sys_KVM_VMI_SWITCH_VIEW = KVM_VMI_SWITCH_VIEW;
static const unsigned long kvm_sys_KVM_VMI_GET_MEM_ACCESS = KVM_VMI_GET_MEM_ACCESS;
static const unsigned long kvm_sys_KVM_VMI_SET_MEM_ACCESS = KVM_VMI_SET_MEM_ACCESS;
static const unsigned long kvm_sys_KVM_VMI_ALLOC_GFN = KVM_VMI_ALLOC_GFN;
static const unsigned long kvm_sys_KVM_VMI_FREE_GFN = KVM_VMI_FREE_GFN;
static const unsigned long kvm_sys_KVM_VMI_CHANGE_GFN = KVM_VMI_CHANGE_GFN;
static const unsigned long kvm_sys_KVM_GET_REGS = KVM_GET_REGS;
static const unsigned long kvm_sys_KVM_SET_REGS = KVM_SET_REGS;
static const unsigned long kvm_sys_KVM_GET_SREGS = KVM_GET_SREGS;
static const unsigned long kvm_sys_KVM_SET_SREGS = KVM_SET_SREGS;
static const unsigned long kvm_sys_KVM_GET_MSRS = KVM_GET_MSRS;
static const unsigned long kvm_sys_KVM_SET_MSRS = KVM_SET_MSRS;
static const unsigned long kvm_sys_KVM_GET_DEBUGREGS = KVM_GET_DEBUGREGS;
static const unsigned long kvm_sys_KVM_SET_DEBUGREGS = KVM_SET_DEBUGREGS;

/* Force arch event ids and invalid-gfn (function-like / cast macros) visible. */
static const unsigned kvm_sys_KVM_VMI_EVENT_CR = KVM_VMI_EVENT_CR;
static const unsigned kvm_sys_KVM_VMI_EVENT_MSR = KVM_VMI_EVENT_MSR;
static const unsigned kvm_sys_KVM_VMI_EVENT_CPUID = KVM_VMI_EVENT_CPUID;
static const unsigned kvm_sys_KVM_VMI_EVENT_BREAKPOINT = KVM_VMI_EVENT_BREAKPOINT;
static const unsigned kvm_sys_KVM_VMI_EVENT_DEBUG = KVM_VMI_EVENT_DEBUG;
static const unsigned kvm_sys_KVM_VMI_EVENT_DESC_ACCESS = KVM_VMI_EVENT_DESC_ACCESS;
static const unsigned kvm_sys_KVM_VMI_EVENT_IO = KVM_VMI_EVENT_IO;
/*
 * KVM_VMI_INVALID_GFN is `~(__u64)0`, which bindgen cannot constant-fold as an
 * unsigned 64-bit static (the value exceeds i64 and falls back to a linkage
 * symbol). Casting to a signed long long folds to -1, which bindgen emits as a
 * `pub const`; callers recover the sentinel with `as u64`. The value still
 * comes from the kernel header macro.
 */
static const long long kvm_sys_KVM_VMI_INVALID_GFN = (long long)(KVM_VMI_INVALID_GFN);
