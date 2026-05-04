#ifndef VMP_PLATFORM_ADAPTER_H
#define VMP_PLATFORM_ADAPTER_H

#include <stdint.h>

#ifdef _WIN32
#define VMP_EXPORT __declspec(dllexport)
#else
#define VMP_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum VmpPlatformKind {
  VMP_PLATFORM_WINDOWS = 1,
  VMP_PLATFORM_LINUX = 2,
  VMP_PLATFORM_ANDROID = 3,
  VMP_PLATFORM_IOS = 4
} VmpPlatformKind;

typedef struct VmpPlatformProbe {
  VmpPlatformKind platform;
  uint32_t abi_version;
  uint32_t pointer_bits;
  uint32_t init_state;
  uint32_t reserved;
} VmpPlatformProbe;

VMP_EXPORT int vmp_platform_init(void);
VMP_EXPORT VmpPlatformProbe vmp_platform_probe(void);
VMP_EXPORT int vmp_platform_protected_add(int lhs, int rhs);
VMP_EXPORT uint32_t vmp_platform_hash_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif
