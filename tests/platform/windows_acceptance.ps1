param(
  [string]$BuildDir = "build/windows",
  [string]$ReportPath = "docs/qa/reports/windows-acceptance.json"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

cmake -S src/platform -B $BuildDir -DPLATFORM_ADAPTER_TARGET=windows -DCMAKE_BUILD_TYPE=Release
cmake --build $BuildDir --config Release

$exe = Join-Path $BuildDir "Release/vmp_platform_smoke.exe"
if (!(Test-Path $exe)) {
  $exe = Join-Path $BuildDir "vmp_platform_smoke.exe"
}
& $exe
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

$dll = Get-ChildItem $BuildDir -Recurse -Filter "vmp_platform*.dll" | Select-Object -First 1
if ($null -eq $dll) {
  throw "Windows DLL artifact was not produced"
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeLoader {
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern IntPtr LoadLibrary(string lpFileName);
  [DllImport("kernel32", SetLastError = true)]
  public static extern bool FreeLibrary(IntPtr hModule);
}
"@

$handle = [NativeLoader]::LoadLibrary($dll.FullName)
if ($handle -eq [IntPtr]::Zero) {
  throw "Windows DLL artifact could not be loaded: $($dll.FullName)"
}
[void][NativeLoader]::FreeLibrary($handle)

$forbidden = @(
  "passwd.txt",
  "GITHUB_PAT",
  "REMOTE_PAT",
  "CRITICAL_AUTHZ_TOKEN_SAMPLE",
  "https://license.sample.invalid"
)
$artifacts = @((Get-Item $exe), $dll)
foreach ($artifact in $artifacts) {
  $bytes = [System.IO.File]::ReadAllBytes($artifact.FullName)
  $text = [System.Text.Encoding]::ASCII.GetString($bytes)
  foreach ($needle in $forbidden) {
    if ($text.Contains($needle)) {
      throw "Forbidden marker found in Windows artifact $($artifact.FullName): $needle"
    }
  }
}

$reportArtifacts = @()
foreach ($artifact in $artifacts) {
  $kind = if ($artifact.Extension -eq ".dll") { "dll" } else { "exe" }
  $reportArtifacts += [ordered]@{
    path = $artifact.FullName
    kind = $kind
    bytes = $artifact.Length
    sha256 = (Get-FileHash -Algorithm SHA256 -Path $artifact.FullName).Hash.ToLowerInvariant()
  }
}

$githubRunUrl = $null
if ($env:GITHUB_SERVER_URL -and $env:GITHUB_REPOSITORY -and $env:GITHUB_RUN_ID) {
  $githubRunUrl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
}

$report = [ordered]@{
  schema = "vmp.platform.windows_acceptance.v1"
  status = "pass"
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
  github_head_ref = $env:GITHUB_HEAD_REF
  github_base_ref = $env:GITHUB_BASE_REF
  github_job = $env:GITHUB_JOB
  github_run_url = $githubRunUrl
  runner_os = $env:RUNNER_OS
  runner_name = $env:RUNNER_NAME
  smoke_exe_executed = $true
  dll_load_executed = $true
  artifacts = $reportArtifacts
  forbidden_plaintext_hits = @()
  scope_note = "This is Windows .exe execution and .dll load evidence. It satisfies the Windows CI gate only when produced on a GitHub Actions Windows runner."
}
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "windows acceptance passed"
