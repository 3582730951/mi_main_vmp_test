#include "../platform_adapter.h"

static uint32_t g_windows_init_state;

static const uint32_t k_platform_init_seed = 0x56575057u;

int vmp_platform_init(void) {
  g_windows_init_state = k_platform_init_seed ^ 0x10203040u;
  return 0;
}

VmpPlatformProbe vmp_platform_probe(void) {
  VmpPlatformProbe probe;
  probe.platform = VMP_PLATFORM_WINDOWS;
  probe.abi_version = 1;
  probe.pointer_bits = (uint32_t)(sizeof(void *) * 8u);
  probe.init_state = g_windows_init_state;
  probe.reserved = 0;
  return probe;
}
