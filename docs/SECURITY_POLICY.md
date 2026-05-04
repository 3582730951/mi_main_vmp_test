# Security Policy

This project is for protecting software that the operator owns or has explicit authorization to protect. It must not be used to hide malware, bypass third-party security controls, evade lawfully installed monitoring, or access systems without authorization.

## Allowed Use

- Protecting proprietary native code from casual static analysis.
- Reducing exposure of sensitive business strings, API names, JNI names, URLs, and license-field names in release artifacts.
- Detecting unsupported or hostile runtime environments and choosing a local integrity policy response.
- Measuring behavior consistency, string exposure, platform compatibility, and performance overhead.

## Prohibited Use

- Persistence, covert installation, or unauthorized auto-start behavior.
- Kernel rootkits, kernel-mode hiding, bootkits, or firmware manipulation.
- Disabling, bypassing, or tampering with EDR, antivirus, MDM, platform security, or audit products.
- Credential theft, data exfiltration, lateral movement, exploit delivery, or unauthorized access.
- Instructions or code intended to bypass third-party DRM, licensing, or platform policy outside an authorized test.

## Anti-Analysis Boundary

Anti-debug, anti-injection, hook, root, and tamper checks are implemented as defensive signals. They may:

- report a suspicious condition;
- fail closed for protected sample code;
- reduce sensitive behavior in an authorized application;
- emit test telemetry that proves the detection path executed.

They must not:

- hide processes, files, modules, or network connections from the operating system;
- patch security tools;
- exploit vulnerabilities;
- persist beyond the protected process lifetime;
- attack analysis tools or the host environment.

## Credential Handling

`passwd.txt` is treated only as a local migration source. Its contents must never be printed, committed, copied into generated files, embedded into workflows, or logged by tests. CI credentials must be stored in GitHub Encrypted Secrets and referenced only through `${{ secrets.NAME }}` syntax.

## Reporting Security Issues

For this workspace, report security concerns by opening an issue in the private project tracker or sending the maintainer a private message through the approved internal channel. Do not paste credentials, proprietary bytecode, protected samples, or crash dumps containing sensitive strings into public systems.

## Release Gate

A release artifact cannot be considered accepted until automated checks show:

- behavior consistency for protected samples;
- zero configured critical plaintext strings in release protected artifacts;
- secret hygiene across docs/scripts/workflows;
- platform-specific gates for the target platform;
- three consecutive automated audit passes.
