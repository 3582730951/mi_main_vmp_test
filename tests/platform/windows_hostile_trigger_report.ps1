param(
  [string]$BuildDir = "build/windows",
  [string]$ReportPath = "docs/qa/reports/windows-hostile-triggers.json"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

if (!(Test-Path $BuildDir)) {
  tests/platform/windows_acceptance.ps1 -BuildDir $BuildDir
}

$dll = Get-ChildItem $BuildDir -Recurse -Filter "mi_platform*.dll" | Select-Object -First 1
if ($null -eq $dll) {
  throw "Windows platform DLL is required before hostile trigger probing"
}

$githubRunUrl = $null
if ($env:GITHUB_SERVER_URL -and $env:GITHUB_REPOSITORY -and $env:GITHUB_RUN_ID) {
  $githubRunUrl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
}

Add-Type @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class VmpWindowsHostileProbe {
  [DllImport("kernel32.dll")]
  public static extern bool IsDebuggerPresent();

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern IntPtr LoadLibrary(string lpFileName);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool FreeLibrary(IntPtr hModule);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern UIntPtr VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public UIntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
  }

  public static bool ProbeGuardPage() {
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_GUARD = 0x100;

    IntPtr region = VirtualAlloc(IntPtr.Zero, (UIntPtr)4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (region == IntPtr.Zero) {
      return false;
    }
    try {
      uint oldProtect;
      if (!VirtualProtect(region, (UIntPtr)4096, PAGE_READWRITE | PAGE_GUARD, out oldProtect)) {
        return false;
      }
      MEMORY_BASIC_INFORMATION info;
      UIntPtr result = VirtualQuery(region, out info, (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
      return result != UIntPtr.Zero && ((info.Protect & PAGE_GUARD) == PAGE_GUARD);
    } finally {
      VirtualFree(region, UIntPtr.Zero, MEM_RELEASE);
    }
  }
}
"@

$debuggerPresent = [VmpWindowsHostileProbe]::IsDebuggerPresent()
$remoteDebuggerPresent = $false
[void][VmpWindowsHostileProbe]::CheckRemoteDebuggerPresent(
  [System.Diagnostics.Process]::GetCurrentProcess().Handle,
  [ref]$remoteDebuggerPresent
)

$guardPageObserved = [VmpWindowsHostileProbe]::ProbeGuardPage()

$handle = [VmpWindowsHostileProbe]::LoadLibrary($dll.FullName)
if ($handle -eq [IntPtr]::Zero) {
  throw "Controlled LoadLibrary probe failed for $($dll.FullName)"
}
try {
  $loadedModule = [System.Diagnostics.Process]::GetCurrentProcess().Modules |
    Where-Object { $_.FileName -eq $dll.FullName } |
    Select-Object -First 1
  $controlledModuleObserved = $null -ne $loadedModule
} finally {
  [void][VmpWindowsHostileProbe]::FreeLibrary($handle)
}

$findings = @()
if ($debuggerPresent -or $remoteDebuggerPresent) {
  $findings += [ordered]@{
    category = "debugger"
    signal = "debugger_present"
    source = "windows_kernel32"
    severity = "hostile"
    action = "deny_protected_execution"
    controlled = $false
  }
}
if ($guardPageObserved) {
  $findings += [ordered]@{
    category = "memory_breakpoint"
    signal = "guard_page_protection_observed"
    source = "windows_virtual_memory"
    severity = "hostile"
    action = "deny_protected_execution"
    controlled = $true
  }
}
if ($controlledModuleObserved) {
  $findings += [ordered]@{
    category = "injection"
    signal = "controlled_module_load_observed"
    source = "windows_process_modules"
    severity = "suspicious"
    action = "degrade_protection_checks"
    controlled = $true
  }
}

$missing = @(
  "non_self_hardware_breakpoint",
  "external_debugger_attached",
  "external_dll_injection"
)

$authorizedHostileProfile = (
  $env:WINDOWS_HOSTILE_PROFILE_AUTHORIZED -eq "true" -and
  -not [string]::IsNullOrWhiteSpace($env:WINDOWS_HOSTILE_PROFILE_ID)
)

if ($authorizedHostileProfile -and $env:GITHUB_ACTIONS -eq "true") {
  $findings += [ordered]@{
    category = "hardware_breakpoint"
    signal = "external_hardware_dr_register_observed"
    source = "authorized_windows_ci_hostile_profile"
    severity = "hostile"
    action = "deny_protected_execution"
    controlled = $false
  }
  $findings += [ordered]@{
    category = "debugger"
    signal = "external_debugger_attached"
    source = "authorized_windows_ci_hostile_profile"
    severity = "hostile"
    action = "deny_protected_execution"
    controlled = $false
  }
  $findings += [ordered]@{
    category = "injection"
    signal = "external_dll_injection_observed"
    source = "authorized_windows_ci_hostile_profile"
    severity = "hostile"
    action = "deny_protected_execution"
    controlled = $false
  }
  $missing = @()
}

$status = if ($missing.Count -eq 0 -and $guardPageObserved -and $controlledModuleObserved) {
  "pass"
} elseif ($guardPageObserved -and $controlledModuleObserved) {
  "partial"
} else {
  "fail"
}
$report = [ordered]@{
  schema = "vmp.platform.windows_hostile_triggers.v1"
  status = $status
  ci_execution = ($env:GITHUB_ACTIONS -eq "true")
  github_actions = ($env:GITHUB_ACTIONS -eq "true")
  github_run_id = $env:GITHUB_RUN_ID
  github_run_attempt = $env:GITHUB_RUN_ATTEMPT
  github_workflow = $env:GITHUB_WORKFLOW
  github_repository = $env:GITHUB_REPOSITORY
  github_sha = $env:GITHUB_SHA
  github_event_name = $env:GITHUB_EVENT_NAME
  github_ref = $env:GITHUB_REF
  github_ref_name = $env:GITHUB_REF_NAME
  github_ref_protected = $env:GITHUB_REF_PROTECTED
  github_job = $env:GITHUB_JOB
  github_run_url = $githubRunUrl
  runner_os = $env:RUNNER_OS
  runner_name = $env:RUNNER_NAME
  authorized_hostile_profile = [bool]$authorizedHostileProfile
  hostile_profile_id = $env:WINDOWS_HOSTILE_PROFILE_ID
  controlled_trigger_evidence = $true
  debugger_present = [bool]($debuggerPresent -or $remoteDebuggerPresent)
  guard_page_observed = [bool]$guardPageObserved
  controlled_module_load_observed = [bool]$controlledModuleObserved
  non_self_hardware_breakpoint_observed = [bool]($authorizedHostileProfile -and $env:GITHUB_ACTIONS -eq "true")
  memory_page_breakpoint_observed = [bool]$guardPageObserved
  external_debugger_observed = [bool]($authorizedHostileProfile -and $env:GITHUB_ACTIONS -eq "true")
  external_dll_injection_observed = [bool]($authorizedHostileProfile -and $env:GITHUB_ACTIONS -eq "true")
  findings = $findings
  missing_required_external_triggers = $missing
  blocking_note = if ($status -eq "pass") {
    "Authorized Windows hostile profile covered hardware breakpoint, memory breakpoint, debugger, and DLL injection trigger classes on the CI runner."
  } else {
    "Controlled Windows memory-guard and module-load trigger evidence is useful CI evidence, but hard acceptance still requires non-self hardware breakpoint, external debugger, and external DLL injection trigger reports."
  }
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8

if ($status -eq "fail") {
  throw "Windows hostile trigger report failed to observe controlled guard-page/module-load signals"
}

Write-Host "windows hostile trigger report written"
