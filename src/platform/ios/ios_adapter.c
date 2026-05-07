#include "../platform_adapter.h"

int vmp_platform_init(void) {
  return 0;
}

VmpPlatformProbe vmp_platform_probe(void) {
  VmpPlatformProbe probe;
  probe.platform = VMP_PLATFORM_IOS;
  probe.abi_version = 1;
  probe.pointer_bits = (uint32_t)(sizeof(void *) * 8u);
  probe.init_state = 0x494f5331u;
  probe.reserved = 0;
  return probe;
}
