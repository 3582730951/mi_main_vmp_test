# Linux Platform Adapter

## Batch Coverage

- T100: `src/platform/linux/linux_adapter.c` exposes the x64/arm64-neutral ABI probe.
- T101: CMake emits an executable and shared object.
- T102: Dynamic symbol resolution is reserved for hashed lookup through the platform hash helper.
- T103: Runtime initialization uses `.init_array` via a constructor.
- T104: CI builds with PIE/RELRO linker flags.
- T105: The smoke test keeps required exports and allows stripping policy checks later.
- T106: `tests/platform/linux_smoke.sh` validates executable and `.so` load behavior.

## Acceptance

Run:

```bash
tests/platform/linux_smoke.sh
```

The script builds release artifacts, executes the ELF smoke binary, loads the `.so` through `dlopen`, verifies ELF metadata with `readelf`, and checks for forbidden credential markers.
