#include "../platform_adapter.h"

static uint32_t g_linux_init_state;

__attribute__((constructor)) static void mi_linux_ctor(void) {
  g_linux_init_state = 0x4c494e58u;
}

int vmp_platform_init(void) {
  if (g_linux_init_state == 0u) {
    g_linux_init_state = 0x4c494e58u;
  }
  return 0;
}

VmpPlatformProbe vmp_platform_probe(void) {
  VmpPlatformProbe probe;
  probe.platform = VMP_PLATFORM_LINUX;
  probe.abi_version = 1;
  probe.pointer_bits = (uint32_t)(sizeof(void *) * 8u);
  probe.init_state = g_linux_init_state;
  probe.reserved = 0;
  return probe;
}
