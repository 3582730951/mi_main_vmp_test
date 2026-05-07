#ifndef VMP_PLATFORM_ADAPTER_H
#define VMP_PLATFORM_ADAPTER_H

#include <stdint.h>

#ifdef VMP_PLATFORM_NO_EXPORTS
#define VMP_EXPORT
#elif defined(_WIN32)
#ifdef VMP_PLATFORM_EXPORT_WINDOWS_ABI
#define VMP_EXPORT __declspec(dllexport)
#else
#define VMP_EXPORT
#endif
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

#define MI_PLATFORM_INIT_SYMBOL "mi_p0"
#define MI_PLATFORM_PROBE_SYMBOL "mi_p1"
#define MI_PLATFORM_ADD_SYMBOL "mi_p2"
#define MI_PLATFORM_HASH_SYMBOL "mi_p3"

VMP_EXPORT int mi_p0(void);
VMP_EXPORT VmpPlatformProbe mi_p1(void);
VMP_EXPORT int mi_p2(int lhs, int rhs);
VMP_EXPORT uint32_t mi_p3(const char *name);

#ifndef VMP_PLATFORM_DISABLE_COMPAT_NAMES
#define vmp_platform_init mi_p0
#define vmp_platform_probe mi_p1
#define vmp_platform_protected_add mi_p2
#define vmp_platform_hash_name mi_p3
#endif

#ifdef __cplusplus
}
#endif

#endif
