#include "../platform_adapter.h"

#include <stdio.h>

int main(void) {
  VmpPlatformProbe probe;
  if (vmp_platform_init() != 0) {
    return 10;
  }
  probe = vmp_platform_probe();
  if (probe.platform != VMP_PLATFORM_WINDOWS || probe.pointer_bits != 64u) {
    return 11;
  }
  if (vmp_platform_protected_add(40, 2) != 42) {
    return 12;
  }
  puts("windows platform smoke passed");
  return 0;
}
