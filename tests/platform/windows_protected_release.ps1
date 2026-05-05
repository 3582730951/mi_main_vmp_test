param(
  [string]$BuildDir = "build/windows-protected",
  [string]$ReportPath = "docs/qa/reports/windows-protected-release.json"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

$sampleOut = "samples/protected_chain/out"
if (Test-Path $sampleOut) {
  Remove-Item -Recurse -Force $sampleOut
}
New-Item -ItemType Directory -Force -Path $sampleOut | Out-Null
$sample = "samples/protected_chain/out/protected_sample.vmp"
$builder = Join-Path $BuildDir "protected_sample_builder.exe"
$builderSources = @(
  "tools/vmp/protected_sample.cpp",
  "src/core/Deterministic.cpp",
  "src/core/OpcodeMap.cpp",
  "src/core/ProtectionConfig.cpp",
  "src/core/Bytecode.cpp",
  "src/core/IRLoweringSkeleton.cpp",
  "src/runtime/VMRuntime.cpp"
)
if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
  & cl.exe /nologo /std:c++17 /EHsc /O2 /W4 /WX /I src $builderSources /Fe:$builder
} elseif (Get-Command g++ -ErrorAction SilentlyContinue) {
  & g++ -std=c++17 -Wall -Wextra -Werror -I src $builderSources -o $builder
} else {
  throw "No supported Windows C++ compiler found for protected sample builder"
}
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

& $builder build $sampleOut
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
& $builder verify $sample
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
& $builder report $sample $sampleOut
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

$header = Join-Path $BuildDir "protected_sample_blob.h"
@'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
items = ", ".join(f"0x{byte:02x}" for byte in data)
pathlib.Path(sys.argv[2]).write_text(
    "#pragma once\n"
    "#include <cstddef>\n"
    "#include <cstdint>\n"
    f"static constexpr std::uint8_t kProtectedSampleBlob[] = {{{items}}};\n"
    f"static constexpr std::size_t kProtectedSampleBlobSize = {len(data)};\n",
    encoding="utf-8",
)
'@ | python3 - $sample $header

$sourceList = @(
  "tools/vmp/protected_release_main.cpp"
)

$exe = Join-Path $BuildDir "protected_release_sample.exe"
if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
  & cl.exe /nologo /std:c++17 /EHsc /O2 /DVMP_DISABLE_RUNTIME_ENTRY_EXPORTS=1 /Gy /Gw /I $BuildDir /I src $sourceList /link /OPT:REF /OPT:ICF /OUT:$exe
} elseif (Get-Command g++ -ErrorAction SilentlyContinue) {
  & g++ -std=c++17 -O2 -DVMP_DISABLE_RUNTIME_ENTRY_EXPORTS=1 -fvisibility=hidden -fdata-sections -ffunction-sections -I $BuildDir -I src $sourceList -Wl,--gc-sections -o $exe
} else {
  throw "No supported Windows C++ compiler found"
}
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

& $exe
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

$forbidden = @(
  "protected-sample-seed-v1",
  "authorized_sample_behavior",
  "CRITICAL_AUTHZ_TOKEN_SAMPLE",
  "https://license.sample.invalid",
  "Authorization:",
  "Bearer ",
  "JNI_OnLoad",
  "Java_",
  "dlopen",
  "dlsym",
  "VMPBC",
  "VMPSAM",
  "VMPIRL",
  "OLLVM"
)
$bytes = [System.IO.File]::ReadAllBytes($exe)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
$hits = @()
foreach ($needle in $forbidden) {
  if ($text.Contains($needle)) {
    $hits += $needle
  }
}
if ($hits.Count -gt 0) {
  throw "Forbidden marker found in Windows protected release sample: $($hits -join ', ')"
}

$githubRunUrl = $null
if ($env:GITHUB_SERVER_URL -and $env:GITHUB_REPOSITORY -and $env:GITHUB_RUN_ID) {
  $githubRunUrl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
}

$report = [ordered]@{
  schema = "vmp.platform.windows_protected_release.v1"
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
  artifact = $exe
  artifact_bytes = (Get-Item $exe).Length
  artifact_sha256 = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLowerInvariant()
  behavior_cases_passed = 4
  forbidden_plaintext_hits = $hits
  scope_note = "Windows runner builds and executes the local protected release sample. This is CI execution evidence when produced by GitHub Actions."
}
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "windows protected release passed"
