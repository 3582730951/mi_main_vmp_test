#include "../platform_adapter.h"

static uint32_t g_windows_init_state;

#ifdef _MSC_VER
#pragma section(".vmp$init", read)
__declspec(allocate(".vmp$init")) static const uint32_t k_vmp_section_marker = 0x56575057u;
#else
static const uint32_t k_vmp_section_marker __attribute__((used)) = 0x56575057u;
#endif

int vmp_platform_init(void) {
  g_windows_init_state = k_vmp_section_marker ^ 0x10203040u;
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
