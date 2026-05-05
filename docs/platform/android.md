# Android Platform Plan

## Batch Coverage

- T110: `src/platform/android/android_adapter.c` is an NDK-oriented shared-library adapter for `arm64-v8a` and `x86_64`.
- T111: `JNI_OnLoad` initializes the native runtime before Java/Kotlin calls reach protected code.
- T112: JNI/API string protection is a policy requirement for the core protector; exported JNI names should be minimized and bridges should use registration where possible.
- T113: Packaging places protected `.so` files under APK ABI directories.
- T114: DEX obfuscation is peripheral only; core secrets stay in native code.
- T115: Emulator execution is wired through `.github/workflows/platform-android-plan.yml` and `tests/platform/android_ci_emulator_smoke.sh`.
- T116/T117: Normal emulator smoke and hostile-environment checks are separate gates to keep false-positive analysis explicit. `tests/platform/android_hostile_trigger_report.sh` records baseline and hostile-device root, hook-framework, and Frida probes and remains blocked until all required hostile trigger classes are observed.

## Emulator Acceptance Plan

1. Build native libraries with the Android NDK CMake toolchain for `arm64-v8a` and `x86_64`.
2. Package protected libraries into the APK under `lib/<abi>/`.
3. Boot an x86_64 emulator on CI or a self-hosted runner.
4. Install the APK, run JNI smoke tests, and compare protected/unprotected core logic outputs. The current smoke APK embeds the generated protected VM payload inside `libmi_bridge.so` instead of loading it as an APK asset.
5. Run hostile-environment checks for root, XP-family frameworks, and hook tooling in a separate job profile.

The Android hostile report is allowed to pass only when the same authorized hostile test device or image produces all required trigger classes under CI with `ANDROID_HOSTILE_PROFILE_AUTHORIZED=true` and a non-empty `ANDROID_HOSTILE_PROFILE_ID`:

- root evidence from `su`/Magisk paths, `su -c id`, insecure build properties, verified-boot state, root-manager packages/processes, or Magisk/Zygisk mounts;
- Xposed-family evidence from Xposed, LSPosed, EdXposed, or Zygisk packages/processes/properties/known module paths;
- Frida/hook evidence from Frida process/package names, Frida/Gum Unix sockets, or default Frida TCP listener ports.

The report includes device build metadata and raw probe summaries so imported artifacts can be reviewed without treating a normal emulator absence, or root-only emulator baseline, as complete hostile-trigger evidence.

`tests/platform/android_ci_emulator_smoke.sh` installs the required Android SDK packages, creates the x86_64 AVD when needed, starts the emulator, runs the native `.so` smoke and APK/JNI smoke, and always stops `adb`/the emulator on exit. The APK signing path uses `ANDROID_KEYSTORE_B64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD` from GitHub Secrets when present; otherwise it falls back to a local test-release keystore and reports that scope. GitHub-hosted Android emulator jobs can be slow; if stability is poor, use a self-hosted runner with hardware acceleration.

References:

- Android NDK CMake: https://developer.android.com/ndk/guides/cmake
- Android NDK ABI list: https://developer.android.com/ndk/guides/abis
- Android 64-bit native-library folders: https://developer.android.com/google/play/requirements/64-bit
