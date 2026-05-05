#include "../platform_adapter.h"

#ifdef __ANDROID__
#include <jni.h>
#endif

static uint32_t g_android_init_state;

__attribute__((constructor)) static void mi_android_ctor(void) {
  g_android_init_state = 0x414e4452u;
}

int vmp_platform_init(void) {
  if (g_android_init_state == 0u) {
    g_android_init_state = 0x414e4452u;
  }
  return 0;
}

VmpPlatformProbe vmp_platform_probe(void) {
  VmpPlatformProbe probe;
  probe.platform = VMP_PLATFORM_ANDROID;
  probe.abi_version = 1;
  probe.pointer_bits = (uint32_t)(sizeof(void *) * 8u);
  probe.init_state = g_android_init_state;
  probe.reserved = 0;
  return probe;
}

#ifdef __ANDROID__
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)vm;
  (void)reserved;
  vmp_platform_init();
  return JNI_VERSION_1_6;
}
#endif
