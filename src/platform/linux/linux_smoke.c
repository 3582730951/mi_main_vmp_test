#include "../platform_adapter.h"

#include <dlfcn.h>
#include <stdio.h>

typedef int (*add_fn)(int, int);

int main(int argc, char **argv) {
  if (vmp_platform_init() != 0) {
    return 20;
  }
  if (vmp_platform_probe().platform != VMP_PLATFORM_LINUX) {
    return 21;
  }
  if (vmp_platform_protected_add(7, 35) != 42) {
    return 22;
  }
  if (argc > 1) {
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    add_fn add;
    if (handle == NULL) {
      puts(dlerror());
      return 23;
    }
    add = (add_fn)dlsym(handle, "vmp_platform_protected_add");
    if (add == NULL || add(20, 22) != 42) {
      return 24;
    }
    dlclose(handle);
  }
  puts("linux platform smoke passed");
  return 0;
}
