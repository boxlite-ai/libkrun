// SPDX-License-Identifier: Apache-2.0
#include <Hypervisor/Hypervisor.h>
#include <string.h>
// Rust u128 is passed in integer registers; Apple's vector argument uses q0.
hv_return_t krun_hvf_set_simd(hv_vcpu_t cpu, uint32_t reg, const unsigned char *bytes) {
    hv_simd_fp_uchar16_t value;
    memcpy(&value, bytes, sizeof(value));
    return hv_vcpu_set_simd_fp_reg(cpu, reg, value);
}
