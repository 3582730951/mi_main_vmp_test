#!/usr/bin/env bash
set -euo pipefail

MODE="ci"
TOOLS_DIR="${TOOLS_DIR:-/tmp}"
INSTALL_ANGR="${INSTALL_ANGR:-1}"
INSTALL_FLOSS="${INSTALL_FLOSS:-1}"
INSTALL_RADARE2="${INSTALL_RADARE2:-1}"
INSTALL_RIZIN="${INSTALL_RIZIN:-1}"
INSTALL_GHIDRA="${INSTALL_GHIDRA:-0}"

usage() {
  cat <<'EOF'
usage: scripts/audit/install_reverse_tooling.sh [--ci|--local] [--with-ghidra] [--without-angr] [--without-floss] [--without-radare2] [--without-rizin]

Installs best-effort GitHub-hosted reverse-analysis tooling used by the
automated QA sidecars. Missing optional tools are reported by the audits as
unavailable; installation failures here are intentionally non-fatal.

Environment:
  TOOLS_DIR       directory for cloned rules or optional downloads (default: /tmp)
  INSTALL_ANGR   set to 0 to skip angr (default: 1)
  INSTALL_FLOSS  set to 0 to skip Mandiant FLOSS (default: 1)
  INSTALL_RADARE2 set to 0 to skip GitHub radare2 release install (default: 1)
  INSTALL_RIZIN  set to 0 to skip GitHub rizin release install (default: 1)
  INSTALL_GHIDRA set to 1 to attempt a Ghidra release install (default: 0)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci)
      MODE="ci"
      ;;
    --local)
      MODE="local"
      ;;
    --with-ghidra)
      INSTALL_GHIDRA="1"
      ;;
    --without-angr)
      INSTALL_ANGR="0"
      ;;
    --without-floss)
      INSTALL_FLOSS="0"
      ;;
    --without-radare2)
      INSTALL_RADARE2="0"
      ;;
    --without-rizin)
      INSTALL_RIZIN="0"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

run_optional() {
  local label="$1"
  shift
  echo "==> ${label}"
  if "$@"; then
    echo "ok: ${label}"
  else
    echo "optional tool unavailable after attempted install: ${label}" >&2
  fi
}

python_pip_optional() {
  local seconds="$1"
  shift
  timeout "${seconds}" python3 -m pip install --user --break-system-packages --disable-pip-version-check "$@" || true
}

publish_tool_dir() {
  local tool_dir="$1"
  shift
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "${tool_dir}" >> "${GITHUB_PATH}"
  fi
  mkdir -p "$HOME/.local/bin"
  local tool
  for tool in "$@"; do
    if [[ -x "${tool_dir}/${tool}" ]]; then
      ln -sf "${tool_dir}/${tool}" "$HOME/.local/bin/${tool}"
    fi
  done
}

install_apt_tools() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get unavailable; skipping distro packages"
    return 0
  fi

  local apt_prefix=()
  if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      apt_prefix=(sudo)
    else
      echo "not root and sudo unavailable; skipping distro packages"
      return 0
    fi
  fi

  "${apt_prefix[@]}" apt-get update
  "${apt_prefix[@]}" apt-get install -y \
    binutils \
    clang-14 \
    g++-mingw-w64-x86-64 \
    git \
    llvm-14-dev \
    llvm-14-tools \
    unzip \
    zip
  "${apt_prefix[@]}" apt-get install -y binutils-mingw-w64-x86-64 || true
  "${apt_prefix[@]}" apt-get install -y radare2 || true
  "${apt_prefix[@]}" apt-get install -y rizin || true
  "${apt_prefix[@]}" apt-get install -y default-jre-headless || true
}

install_python_tools() {
  python_pip_optional 120s --only-binary=:all: lief
  python_pip_optional 180s flare-capa
  if [[ "${INSTALL_FLOSS}" == "1" ]]; then
    python_pip_optional 180s flare-floss
  fi
  python_pip_optional 60s r2pipe
  python_pip_optional 60s rzpipe
  if [[ "${INSTALL_ANGR}" == "1" ]]; then
    python_pip_optional 240s --only-binary=:all: angr
  fi
}

install_capa_rules() {
  mkdir -p "${TOOLS_DIR}"
  if [[ -d "${TOOLS_DIR}/capa-rules/.git" ]]; then
    git -C "${TOOLS_DIR}/capa-rules" pull --ff-only || true
  else
    rm -rf "${TOOLS_DIR}/capa-rules"
    timeout 90s git clone --depth 1 https://github.com/mandiant/capa-rules.git "${TOOLS_DIR}/capa-rules" || true
  fi
}

github_release_asset_url() {
  local repo="$1"
  local pattern="$2"
  python3 - "$repo" "$pattern" <<'PY'
import fnmatch
import json
import sys
import urllib.request

repo = sys.argv[1]
pattern = sys.argv[2]
api = f"https://api.github.com/repos/{repo}/releases/latest"
try:
    with urllib.request.urlopen(api, timeout=30) as response:
        data = json.load(response)
except Exception:
    sys.exit(1)

for asset in data.get("assets", []):
    name = str(asset.get("name", ""))
    url = str(asset.get("browser_download_url", ""))
    if fnmatch.fnmatch(name, pattern) and url:
        print(url)
        sys.exit(0)
sys.exit(1)
PY
}

ghidra_release_url() {
  github_release_asset_url "NationalSecurityAgency/ghidra" "ghidra_*_PUBLIC_*.zip"
}

install_radare2_release() {
  if [[ "${INSTALL_RADARE2}" != "1" ]]; then
    echo "radare2 GitHub release install disabled"
    return 0
  fi
  if command -v r2 >/dev/null 2>&1 || command -v radare2 >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get unavailable; skipping radare2 GitHub .deb install"
    return 0
  fi

  local apt_prefix=()
  if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      apt_prefix=(sudo)
    else
      echo "not root and sudo unavailable; skipping radare2 GitHub .deb install"
      return 0
    fi
  fi

  mkdir -p "${TOOLS_DIR}"
  local url
  url="$(github_release_asset_url "radareorg/radare2" "radare2_[0-9]*_amd64.deb")" || return 0
  local package="${TOOLS_DIR}/$(basename "${url}")"
  timeout 180s python3 - <<PY || return 0
import urllib.request
urllib.request.urlretrieve("${url}", "${package}")
PY
  DEBIAN_FRONTEND=noninteractive "${apt_prefix[@]}" apt-get install -y "${package}" || true
}

install_rizin_release() {
  if [[ "${INSTALL_RIZIN}" != "1" ]]; then
    echo "rizin GitHub release install disabled"
    return 0
  fi
  if command -v rizin >/dev/null 2>&1 || command -v rz >/dev/null 2>&1; then
    return 0
  fi

  mkdir -p "${TOOLS_DIR}"
  local url
  url="$(github_release_asset_url "rizinorg/rizin" "rizin-v*-static-x86_64.tar.xz")" || return 0
  local archive="${TOOLS_DIR}/$(basename "${url}")"
  local extract_dir="${TOOLS_DIR}/rizin-release"
  timeout 180s python3 - <<PY || return 0
import urllib.request
urllib.request.urlretrieve("${url}", "${archive}")
PY
  rm -rf "${extract_dir}"
  mkdir -p "${extract_dir}"
  tar -xf "${archive}" -C "${extract_dir}" || return 0
  local rizin_bin
  rizin_bin="$(find "${extract_dir}" -type f \( -name rizin -o -name rz \) -perm -u+x | head -n 1)"
  if [[ -n "${rizin_bin}" ]]; then
    publish_tool_dir "$(dirname "${rizin_bin}")" rizin rz
  fi
}

install_ghidra() {
  if [[ "${INSTALL_GHIDRA}" != "1" ]]; then
    echo "Ghidra download disabled; set INSTALL_GHIDRA=1 or pass --with-ghidra to enable it"
    return 0
  fi
  if command -v analyzeHeadless >/dev/null 2>&1; then
    return 0
  fi

  mkdir -p "${TOOLS_DIR}"
  local url
  url="$(ghidra_release_url)" || return 0
  local archive="${TOOLS_DIR}/$(basename "${url}")"
  timeout 300s python3 - <<PY || return 0
import urllib.request
urllib.request.urlretrieve("${url}", "${archive}")
PY
  unzip -q -o "${archive}" -d "${TOOLS_DIR}" || return 0
  local headless
  headless="$(find "${TOOLS_DIR}" -maxdepth 3 -path "*/support/analyzeHeadless" -type f | head -n 1)"
  if [[ -n "${headless}" && -n "${GITHUB_PATH:-}" ]]; then
    dirname "${headless}" >> "${GITHUB_PATH}"
  fi
}

main() {
  if [[ "${MODE}" == "ci" || "${MODE}" == "local" ]]; then
    run_optional "distro reverse-analysis packages" install_apt_tools
    run_optional "Python reverse-analysis packages" install_python_tools
    run_optional "Mandiant capa-rules clone" install_capa_rules
    run_optional "radare2 GitHub release backend" install_radare2_release
    run_optional "rizin GitHub release backend" install_rizin_release
    run_optional "Ghidra optional headless backend" install_ghidra
  fi

  cat <<EOF
Reverse tooling bootstrap complete.
Suggested environment:
  export PATH="\$HOME/.local/bin:\$PATH"
  export CAPA_RULES="${TOOLS_DIR}/capa-rules"
EOF
}

main "$@"
