/* KVM VMI uAPI bindings */

/* static_assert is not supported by libclang in all configurations */
#define static_assert(...)

#include <linux/kvm_vmi.h>
