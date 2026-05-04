#include "../platform_adapter.h"

static uint32_t g_ios_init_state;

__attribute__((constructor)) static void vmp_ios_constructor(void) {
  g_ios_init_state = 0x494f5331u;
}

int vmp_platform_init(void) {
  if (g_ios_init_state == 0u) {
    g_ios_init_state = 0x494f5331u;
  }
  return 0;
}

VmpPlatformProbe vmp_platform_probe(void) {
  VmpPlatformProbe probe;
  probe.platform = VMP_PLATFORM_IOS;
  probe.abi_version = 1;
  probe.pointer_bits = (uint32_t)(sizeof(void *) * 8u);
  probe.init_state = g_ios_init_state;
  probe.reserved = 0;
  return probe;
}
