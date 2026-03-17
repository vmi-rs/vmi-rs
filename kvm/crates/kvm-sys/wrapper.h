/* KVM VMI uAPI bindings */

/* static_assert is not supported by libclang in all configurations */
#define static_assert(...)

/*
 * Include ioctl encoding macros (_IO/_IOW/_IOR/_IOWR) and the main
 * KVM header (for KVMIO, capability constants, KVM_CREATE_VMI, and
 * register ioctl definitions).  kvm_vmi.h provides VMI-specific
 * structs, constants, and ioctl definitions.
 */
#include <linux/ioctl.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>

/*
 * Force bindgen to evaluate ioctl numbers.
 *
 * bindgen cannot evaluate #define macros that contain sizeof()
 * (e.g. _IOW(KVMIO, 0xd6, struct kvm_vmi_control_event)), but it
 * CAN evaluate static const initialisers because libclang resolves
 * sizeof() at the AST level.
 *
 * We use a _IOCTL suffix to avoid name collisions with the original
 * #define macros (the preprocessor would expand the name otherwise).
 */

/* VM-level ioctl (on VM fd) */
static const unsigned long KVM_CREATE_VMI_IOCTL              = KVM_CREATE_VMI;

/* vmi_fd ioctls */
static const unsigned long KVM_VMI_CONTROL_EVENT_IOCTL       = KVM_VMI_CONTROL_EVENT;
static const unsigned long KVM_VMI_ACK_EVENT_IOCTL           = KVM_VMI_ACK_EVENT;
static const unsigned long KVM_VMI_SETUP_RING_IOCTL          = KVM_VMI_SETUP_RING;
static const unsigned long KVM_VMI_TEARDOWN_RING_IOCTL       = KVM_VMI_TEARDOWN_RING;
static const unsigned long KVM_VMI_CREATE_VIEW_IOCTL         = KVM_VMI_CREATE_VIEW;
static const unsigned long KVM_VMI_DESTROY_VIEW_IOCTL        = KVM_VMI_DESTROY_VIEW;
static const unsigned long KVM_VMI_SWITCH_VIEW_IOCTL         = KVM_VMI_SWITCH_VIEW;
static const unsigned long KVM_VMI_GET_MEM_ACCESS_IOCTL      = KVM_VMI_GET_MEM_ACCESS;
static const unsigned long KVM_VMI_SET_MEM_ACCESS_IOCTL      = KVM_VMI_SET_MEM_ACCESS;
static const unsigned long KVM_VMI_PAUSE_VM_IOCTL            = KVM_VMI_PAUSE_VM;
static const unsigned long KVM_VMI_UNPAUSE_VM_IOCTL          = KVM_VMI_UNPAUSE_VM;
static const unsigned long KVM_VMI_PAUSE_VCPU_IOCTL          = KVM_VMI_PAUSE_VCPU;
static const unsigned long KVM_VMI_UNPAUSE_VCPU_IOCTL        = KVM_VMI_UNPAUSE_VCPU;
static const unsigned long KVM_VMI_INJECT_EVENT_IOCTL        = KVM_VMI_INJECT_EVENT;
static const unsigned long KVM_VMI_ALLOC_GFN_IOCTL           = KVM_VMI_ALLOC_GFN;
static const unsigned long KVM_VMI_FREE_GFN_IOCTL            = KVM_VMI_FREE_GFN;
static const unsigned long KVM_VMI_CHANGE_GFN_IOCTL          = KVM_VMI_CHANGE_GFN;

/*
 * Arch event IDs use KVM_VMI_ARCH_EVENT() macro which bindgen can't
 * evaluate directly. Force evaluation via static const.
 */
static const unsigned int KVM_VMI_EVENT_BREAKPOINT_EVAL      = KVM_VMI_EVENT_BREAKPOINT;
static const unsigned int KVM_VMI_NUM_EVENTS_EVAL            = KVM_VMI_NUM_EVENTS;

#if defined(__x86_64__)

/* x86-specific arch event evaluations */
static const unsigned int KVM_VMI_EVENT_CR_EVAL              = KVM_VMI_EVENT_CR;
static const unsigned int KVM_VMI_EVENT_MSR_EVAL             = KVM_VMI_EVENT_MSR;
static const unsigned int KVM_VMI_EVENT_CPUID_EVAL           = KVM_VMI_EVENT_CPUID;
static const unsigned int KVM_VMI_EVENT_DEBUG_EVAL           = KVM_VMI_EVENT_DEBUG;
static const unsigned int KVM_VMI_EVENT_DESC_ACCESS_EVAL     = KVM_VMI_EVENT_DESC_ACCESS;
static const unsigned int KVM_VMI_EVENT_IO_EVAL              = KVM_VMI_EVENT_IO;

/* x86 vCPU ioctls (register access via duplicated vCPU fds) */
static const unsigned long KVM_GET_REGS_IOCTL                = KVM_GET_REGS;
static const unsigned long KVM_SET_REGS_IOCTL                = KVM_SET_REGS;
static const unsigned long KVM_GET_SREGS_IOCTL               = KVM_GET_SREGS;
static const unsigned long KVM_SET_SREGS_IOCTL               = KVM_SET_SREGS;
static const unsigned long KVM_GET_MSRS_IOCTL                = KVM_GET_MSRS;
static const unsigned long KVM_SET_MSRS_IOCTL                = KVM_SET_MSRS;

#endif /* __x86_64__ */

#if defined(__aarch64__)

/* arm64-specific arch event evaluations */
static const unsigned int KVM_VMI_EVENT_SYSREG_EVAL          = KVM_VMI_EVENT_SYSREG;

/* arm64 vCPU ioctls (register access via KVM_GET_ONE_REG) */
static const unsigned long KVM_GET_ONE_REG_IOCTL             = KVM_GET_ONE_REG;

#endif /* __aarch64__ */

static const unsigned long KVM_CHECK_EXTENSION_IOCTL         = KVM_CHECK_EXTENSION;
