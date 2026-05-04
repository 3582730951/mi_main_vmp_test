#include "../../src/platform/platform_adapter.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef int (*init_fn)(void);
typedef VmpPlatformProbe (*probe_fn)(void);
typedef int (*add_fn)(int, int);
typedef int (*jni_on_load_fn)(void *, void *);

int main(int argc, char **argv) {
  const char *library_path = argc > 1 ? argv[1] : "./libvmp_platform.so";
  void *handle = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
  init_fn init;
  probe_fn probe;
  add_fn add;
  jni_on_load_fn jni_on_load;
  VmpPlatformProbe platform_probe;
  int jni_version;

  if (handle == NULL) {
    printf("dlopen_error=%s\n", dlerror());
    return 30;
  }

  init = (init_fn)dlsym(handle, "vmp_platform_init");
  probe = (probe_fn)dlsym(handle, "vmp_platform_probe");
  add = (add_fn)dlsym(handle, "vmp_platform_protected_add");
  jni_on_load = (jni_on_load_fn)dlsym(handle, "JNI_OnLoad");
  if (init == NULL || probe == NULL || add == NULL || jni_on_load == NULL) {
    puts("missing_required_symbol=1");
    dlclose(handle);
    return 31;
  }

  if (init() != 0) {
    puts("init_failed=1");
    dlclose(handle);
    return 32;
  }

  platform_probe = probe();
  printf("platform=%u\n", (uint32_t)platform_probe.platform);
  printf("pointer_bits=%u\n", platform_probe.pointer_bits);
  printf("init_state=%u\n", platform_probe.init_state);
  printf("add_20_22=%d\n", add(20, 22));

  jni_version = jni_on_load(NULL, NULL);
  printf("jni_on_load=%d\n", jni_version);

  if (platform_probe.platform != VMP_PLATFORM_ANDROID ||
      platform_probe.pointer_bits != 64u ||
      add(20, 22) != 42 ||
      jni_version == 0) {
    dlclose(handle);
    return 33;
  }

  dlclose(handle);
  puts("android native smoke passed");
  return 0;
}
