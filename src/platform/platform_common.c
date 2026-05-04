#include "platform_adapter.h"

#include <stddef.h>

uint32_t vmp_platform_hash_name(const char *name) {
  uint32_t hash = 2166136261u;
  if (name == NULL) {
    return hash;
  }
  while (*name != '\0') {
    hash ^= (unsigned char)*name++;
    hash *= 16777619u;
  }
  return hash;
}

int vmp_platform_protected_add(int lhs, int rhs) {
  return lhs + rhs;
}
