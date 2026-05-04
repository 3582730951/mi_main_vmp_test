# Official Source List

The plan requires primary sources for platform and CI decisions. These are the baseline references used for this phase.

| Area | Official Source | Use |
|---|---|---|
| LLVM New Pass Manager | https://llvm.org/docs/NewPassManager.html | Pass plugin architecture and pipeline placement |
| LLVM Writing Passes | https://llvm.org/docs/WritingAnLLVMNewPMPass.html | New PM pass skeleton and registration |
| Microsoft PE/COFF | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format | PE/COFF format, sections, imports, TLS considerations |
| Microsoft x64 ABI | https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention | Windows x64 calling convention for runtime bridges |
| Android NDK | https://developer.android.com/ndk/guides | Android native build and ABI guidance |
| Android JNI Tips | https://developer.android.com/training/articles/perf-jni | JNI naming, registration, and runtime behavior |
| GitHub Actions Secrets | https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions | Encrypted secret usage and log hygiene |
| GitHub-hosted Runners | https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners | Windows/macOS/Linux runner capabilities |
| Apple Mach-O Runtime | https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachORuntime/ | Mach-O structure and runtime loading background |
| Apple Code Signing | https://developer.apple.com/support/code-signing/ | iOS/macOS signing model and certificate workflow |
| Apple App Review Guidelines | https://developer.apple.com/app-store/review/guidelines/ | Platform policy constraints relevant to no-JIT design |
| Linux `dlopen`/`dlsym` | https://man7.org/linux/man-pages/man3/dlopen.3.html | Dynamic loading behavior for ELF adapter design |

## Source Use Rules

- Prefer current official documentation, platform specifications, standards, and measured CI output.
- Use blogs or forums only as debugging clues, not as architectural authority.
- Record any platform behavior that diverges from documentation in QA reports with command output.
