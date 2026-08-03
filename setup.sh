#!/usr/bin/env bash
#
# setup.sh - Install the Zscaler root CA certificate into a JDK's trust
#            store (cacerts), npm's cafile config, and pip's cert config,
#            so Java, npm and pip work behind the Zscaler TLS-inspecting
#            proxy. Works on native Windows (Git Bash/MSYS), WSL Ubuntu/
#            Debian, Linux and macOS.
#
# Usage:
#   ./setup.sh [options]
#
# Options:
#   -j, --java-home <path>   JAVA_HOME to target (default: $JAVA_HOME, then
#                             auto-detected from `java`/`javac` on PATH,
#                             then auto-detected from common JDK install
#                             locations such as scoop, Program Files,
#                             sdkman, jenv, asdf, apt's /usr/lib/jvm, etc.)
#   -c, --cert <path>        Path to the Zscaler root CA cert (.crt/.pem/.cer).
#                             If omitted, the script looks for a local
#                             zscaler*.crt/.pem/.cer file, then falls back
#                             to exporting it from the Windows "Root" cert
#                             store, then falls back to grabbing it live
#                             from an HTTPS handshake (Zscaler MITM).
#   -a, --alias <name>       Alias to use in the truststore (default: zscaler-root-ca)
#   -p, --storepass <pass>   cacerts store password (default: changeit)
#   -H, --host <host:port>   Host used for the live TLS fallback (default: www.google.com:443)
#   -N, --skip-npm            Skip configuring npm's cafile
#   -P, --skip-pip            Skip configuring pip's cert
#   -S, --skip-system-ca      Skip installing into the OS trust store (apt/curl/wget/git)
#   -r, --remove             Remove the alias instead of installing it
#   -l, --list                List whether the alias is currently installed
#   -h, --help                Show this help
#
# Auto-detection:
#   npm and pip are located the same way as the JDK: first on PATH, then by
#   scanning common per-user/system install locations (scoop, Program
#   Files, nvm, nodeenv, pyenv, virtualenvs, Python launcher installs,
#   Homebrew, apt/dpkg's /usr/lib, /usr/bin) so the script works even when
#   nothing is on PATH in the current shell.
#
# WSL / Ubuntu notes:
#   Under WSL (or plain Ubuntu/Debian), apt-installed JDKs live under
#   /usr/lib/jvm and their cacerts file is usually owned by root
#   (mode 644). If cacerts isn't writable by the current user, the script
#   automatically retries the write with `sudo` (only for the actual
#   import/delete calls, never for read-only listing). Running under WSL
#   also auto-detects a mounted Windows drive (/mnt/c) so JDKs/npm/pip
#   installed on the Windows side are still found if that's what you use.
#
# System CA / apt support (Debian, Ubuntu, WSL, RHEL, Fedora):
#   This is what fixes `sudo apt update`/`apt upgrade` (and curl, wget,
#   git, pip's default verifier, etc.) failing with certificate errors
#   behind Zscaler. The cert is copied (using sudo, or directly if already
#   root) to /usr/local/share/ca-certificates/<alias>.crt on Debian/Ubuntu
#   and `update-ca-certificates` is run, or to
#   /etc/pki/ca-trust/source/anchors/<alias>.crt with `update-ca-trust
#   extract` on RHEL/Fedora. --remove deletes that file and refreshes the
#   store. --list shows whether it's currently installed. Skip with -S.
#   No-op (with a log message) if neither ca-certificates nor ca-trust
#   tooling is present (e.g. plain Windows/macOS).
#
# npm support:
#   The cert is converted to PEM and copied to
#   ~/.zscaler-certs/zscaler-root-ca.pem, then `npm config set cafile`
#   points there. --remove clears that npm config (only if it still points
#   at our managed file) and deletes the persisted PEM. --list also shows
#   npm's current cafile setting. Skip with -N.
#
# pip support:
#   The cert is converted to PEM and copied to
#   ~/.zscaler-certs/zscaler-root-ca.pem (shared with npm), then
#   `pip config set global.cert` points there. --remove clears that pip
#   config (only if it still points at our managed file). --list also
#   shows pip's current global.cert setting. Skip with -P.
#
# Rerunning / updating:
#   This script is fully idempotent and safe to re-run at any time (e.g.
#   whenever the corporate Zscaler cert rotates): it always re-detects the
#   current cert, replaces the old truststore alias, and rewrites the
#   npm/pip/system-CA config to point at the freshly captured cert.
#
# Examples:
#   ./setup.sh
#   ./setup.sh -j "/c/Program Files/Java/jdk-17" -c ./ZscalerRootCA.crt
#   ./setup.sh --remove
#
set -euo pipefail

# Safe fallbacks so auto-detection never crashes on set -u in stripped-down
# environments (HOME/USER are usually set, but not guaranteed everywhere).
HOME="${HOME:-${USERPROFILE:-/tmp}}"
USER="${USER:-${USERNAME:-unknown}}"
SCOOP="${SCOOP:-$HOME/scoop}"

ALIAS="zscaler-root-ca"
STOREPASS="changeit"
CERT_FILE=""
JAVA_HOME_OVERRIDE=""
TLS_HOST="www.google.com:443"
ACTION="install"
SKIP_NPM=""
SKIP_PIP=""
SKIP_SYSTEM_CA=""
PERSIST_DIR="${HOME:-/tmp}/.zscaler-certs"
PERSIST_PEM="$PERSIST_DIR/zscaler-root-ca.pem"

log()  { printf '[setup] %s\n' "$*"; }
err()  { printf '[setup] ERROR: %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
  sed -n '2,82p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    -j|--java-home) JAVA_HOME_OVERRIDE="$2"; shift 2 ;;
    -c|--cert)       CERT_FILE="$2"; shift 2 ;;
    -a|--alias)      ALIAS="$2"; shift 2 ;;
    -p|--storepass)  STOREPASS="$2"; shift 2 ;;
    -H|--host)       TLS_HOST="$2"; shift 2 ;;
    -N|--skip-npm)   SKIP_NPM="1"; shift ;;
    -P|--skip-pip)   SKIP_PIP="1"; shift ;;
    -S|--skip-system-ca) SKIP_SYSTEM_CA="1"; shift ;;
    -r|--remove)     ACTION="remove"; shift ;;
    -l|--list)       ACTION="list"; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) die "Unknown option: $1 (use -h for help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Detect WSL and a mounted Windows drive, so Windows-side installs (scoop,
# Program Files, ...) are still found when this runs inside WSL Ubuntu.
# ---------------------------------------------------------------------------
IS_WSL=""
if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null \
   || [ -n "${WSL_DISTRO_NAME:-}" ] || [ -n "${WSL_INTEROP:-}" ]; then
  IS_WSL="1"
fi

WIN_MOUNT=""
for m in /mnt/c /c; do
  [ -d "$m/Windows" ] && { WIN_MOUNT="$m"; break; }
done

# ---------------------------------------------------------------------------
# Locate JAVA_HOME
# ---------------------------------------------------------------------------
java_home_from_bin() {
  java_bin="$1"
  [ -x "$java_bin" ] || return 1
  if command -v readlink >/dev/null 2>&1; then
    resolved="$(readlink -f "$java_bin" 2>/dev/null || true)"
    [ -n "$resolved" ] && java_bin="$resolved"
  fi
  # java_bin is .../<JAVA_HOME>/bin/java(.exe)
  dirname_bin="$(dirname "$java_bin")"
  echo "$(dirname "$dirname_bin")"
}

# Common locations JDKs get installed to outside of PATH: scoop, Program
# Files, sdkman, jenv/asdf, apt's /usr/lib/jvm, and the usual macOS spots.
scan_java_home_candidates() {
  bases=(
    "$SCOOP/apps"
    "$HOME/.sdkman/candidates/java"
    "$HOME/.jenv/versions"
    "$HOME/.asdf/installs/java"
    "/usr/lib/jvm"
    "/opt/homebrew/opt"
    "/usr/local/opt"
    "/Library/Java/JavaVirtualMachines"
  )
  if [ -n "$WIN_MOUNT" ]; then
    bases+=(
      "$WIN_MOUNT/Program Files/Java"
      "$WIN_MOUNT/Program Files (x86)/Java"
      "$WIN_MOUNT/Program Files/Eclipse Adoptium"
      "$WIN_MOUNT/Program Files/Zulu"
    )
  fi
  for base in "${bases[@]}"; do
    [ -d "$base" ] || continue
    for dir in "$base"/*; do
      [ -d "$dir" ] || continue
      candidate="$dir"
      [ -d "$dir/current" ] && candidate="$dir/current"
      [ -d "$dir/Contents/Home" ] && candidate="$dir/Contents/Home"
      if [ -x "$candidate/bin/java" ] || [ -x "$candidate/bin/java.exe" ]; then
        echo "$candidate"
      fi
    done
  done
}

resolve_java_home() {
  if [ -n "$JAVA_HOME_OVERRIDE" ]; then
    echo "$JAVA_HOME_OVERRIDE"
    return 0
  fi
  if [ -n "${JAVA_HOME:-}" ]; then
    echo "$JAVA_HOME"
    return 0
  fi
  if command -v java >/dev/null 2>&1; then
    home="$(java_home_from_bin "$(command -v java)" || true)"
    [ -n "$home" ] && { echo "$home"; return 0; }
  fi
  candidate="$(scan_java_home_candidates | head -n 1)"
  [ -n "$candidate" ] && { echo "$candidate"; return 0; }
  return 1
}

HAVE_JDK=""
JAVA_HOME_RESOLVED="$(resolve_java_home || true)"
if [ -n "$JAVA_HOME_OVERRIDE" ] && [ ! -d "$JAVA_HOME_OVERRIDE" ]; then
  die "JAVA_HOME does not exist: $JAVA_HOME_OVERRIDE"
fi
if [ -n "$JAVA_HOME_RESOLVED" ] && [ -d "$JAVA_HOME_RESOLVED" ]; then
  KEYTOOL="$JAVA_HOME_RESOLVED/bin/keytool"
  [ -x "$KEYTOOL" ] || KEYTOOL="$JAVA_HOME_RESOLVED/bin/keytool.exe"
  if [ ! -x "$KEYTOOL" ] && command -v keytool >/dev/null 2>&1; then
    KEYTOOL="$(command -v keytool)"
  fi
  # JDK 9+ ships cacerts under lib/security; older JDKs under jre/lib/security.
  if [ -x "$KEYTOOL" ] && [ -f "$JAVA_HOME_RESOLVED/lib/security/cacerts" ]; then
    CACERTS="$JAVA_HOME_RESOLVED/lib/security/cacerts"
  elif [ -x "$KEYTOOL" ] && [ -f "$JAVA_HOME_RESOLVED/jre/lib/security/cacerts" ]; then
    CACERTS="$JAVA_HOME_RESOLVED/jre/lib/security/cacerts"
  fi
  if [ -x "$KEYTOOL" ] && [ -n "${CACERTS:-}" ]; then
    HAVE_JDK="1"
    log "Using JAVA_HOME: $JAVA_HOME_RESOLVED"
    log "Using cacerts: $CACERTS"
  else
    log "JAVA_HOME resolved to $JAVA_HOME_RESOLVED but keytool/cacerts not found there; skipping Java truststore setup"
  fi
else
  log "No JDK found (JAVA_HOME unset and no 'java' on PATH); skipping Java truststore setup. Pass -j/--java-home to target one."
fi

# On apt-installed JDKs (common under WSL/Ubuntu/Debian) cacerts is usually
# owned by root (mode 644): writes need sudo, reads don't.
CACERTS_SUDO=""
if [ -n "$HAVE_JDK" ] && [ ! -w "$CACERTS" ]; then
  if command -v sudo >/dev/null 2>&1; then
    log "cacerts at $CACERTS is not writable by the current user; will use sudo for the import/delete"
    CACERTS_SUDO="1"
  else
    log "cacerts at $CACERTS is not writable and sudo is unavailable; skipping Java truststore setup"
    HAVE_JDK=""
  fi
fi

run_keytool_write() {
  if [ -n "$CACERTS_SUDO" ]; then
    sudo "$KEYTOOL" "$@"
  else
    "$KEYTOOL" "$@"
  fi
}

# ---------------------------------------------------------------------------
# Locate npm / pip beyond PATH (scoop, Program Files, nvm, pyenv, etc.)
# ---------------------------------------------------------------------------
scan_command_candidates() {
    cmd_name="$1"
    bases=(
      "$SCOOP/apps"
      "$HOME/AppData/Roaming/nvm"
      "$HOME/.nvm/versions/node"
      "$HOME/.pyenv/versions"
      "$HOME/AppData/Local/Programs/Python"
    )
    if [ -n "$WIN_MOUNT" ]; then
      bases+=(
        "$WIN_MOUNT/Program Files/nodejs"
        "$WIN_MOUNT/Program Files (x86)/nodejs"
      )
      for pydir in "$WIN_MOUNT"/Python*; do
        [ -d "$pydir" ] && bases+=("$pydir")
      done
    fi
    bases+=(
      "/opt/homebrew/opt"
      "/usr/local/opt"
    )
    for glob_base in "${bases[@]}"; do
      for dir in "$glob_base"/*; do
        [ -d "$dir" ] || continue
        for sub in "$dir" "$dir/current" "$dir/bin" "$dir/current/bin" "$dir/Scripts"; do
          [ -x "$sub/$cmd_name" ] && { echo "$sub/$cmd_name"; continue; }
          [ -x "$sub/$cmd_name.cmd" ] && { echo "$sub/$cmd_name.cmd"; continue; }
          [ -x "$sub/$cmd_name.exe" ] && { echo "$sub/$cmd_name.exe"; continue; }
        done
      done
    done
  }

resolve_command() {
  cmd_name="$1"
  if command -v "$cmd_name" >/dev/null 2>&1; then
    command -v "$cmd_name"
    return 0
  fi
  candidate="$(scan_command_candidates "$cmd_name" | head -n 1)"
  [ -n "$candidate" ] && { echo "$candidate"; return 0; }
  return 1
}

HAVE_NPM=""
NPM_BIN="$(resolve_command npm || true)"
if [ -n "$NPM_BIN" ]; then
  HAVE_NPM="1"
  log "Using npm: $NPM_BIN"
fi

HAVE_PIP=""
PIP_BIN="$(resolve_command pip || true)"
[ -z "$PIP_BIN" ] && PIP_BIN="$(resolve_command pip3 || true)"
if [ -n "$PIP_BIN" ]; then
  HAVE_PIP="1"
  log "Using pip: $PIP_BIN"
fi

# ---------------------------------------------------------------------------
# Detect the OS trust store tooling (this is what apt/curl/wget/git use).
# Debian/Ubuntu/WSL: ca-certificates + update-ca-certificates.
# RHEL/Fedora:       ca-certificates + update-ca-trust.
# Gated on an actual Linux kernel: MSYS2/Git Bash on Windows ships its own
# unrelated update-ca-trust/update-ca-certificates shims under /mingw64,
# which manage MSYS's bundled bundle, not the OS trust store.
# ---------------------------------------------------------------------------
IS_LINUX=""
case "$(uname -s 2>/dev/null || true)" in
  Linux*) IS_LINUX="1" ;;
esac

AM_ROOT=""
[ "$(id -u 2>/dev/null || echo 1)" = "0" ] && AM_ROOT="1"

HAVE_SUDO=""
command -v sudo >/dev/null 2>&1 && HAVE_SUDO="1"

HAVE_SYSTEM_CA=""
SYSTEM_CA_KIND=""
SYSTEM_CA_FILE=""
SYSTEM_CA_UPDATE=""
if [ -n "$IS_LINUX" ]; then
  if command -v update-ca-certificates >/dev/null 2>&1; then
    SYSTEM_CA_KIND="debian"
    SYSTEM_CA_FILE="/usr/local/share/ca-certificates/${ALIAS}.crt"
    SYSTEM_CA_UPDATE="update-ca-certificates"
  elif command -v update-ca-trust >/dev/null 2>&1; then
    SYSTEM_CA_KIND="rhel"
    SYSTEM_CA_FILE="/etc/pki/ca-trust/source/anchors/${ALIAS}.crt"
    SYSTEM_CA_UPDATE="update-ca-trust"
  fi
fi
if [ -n "$SYSTEM_CA_KIND" ]; then
  if [ -n "$AM_ROOT" ] || [ -n "$HAVE_SUDO" ]; then
    HAVE_SYSTEM_CA="1"
    log "Using system CA store ($SYSTEM_CA_KIND): $SYSTEM_CA_FILE"
  else
    log "Found $SYSTEM_CA_UPDATE but no sudo/root available; skipping system CA store (apt/curl/wget/git)"
  fi
elif [ -n "$IS_LINUX" ]; then
  log "No system CA store tooling found (update-ca-certificates/update-ca-trust); skipping apt/curl/wget/git trust setup"
fi

run_system_ca_write() {
  if [ -n "$AM_ROOT" ]; then
    "$@"
  else
    sudo "$@"
  fi
}

system_ca_configure() {
  pem_path="$1"
  [ -n "$HAVE_SYSTEM_CA" ] || { log "System CA store not available, skipping apt/curl/wget/git config"; return 0; }
  run_system_ca_write cp "$pem_path" "$SYSTEM_CA_FILE"
  if [ "$SYSTEM_CA_KIND" = "debian" ]; then
    run_system_ca_write update-ca-certificates >/dev/null
  else
    run_system_ca_write update-ca-trust extract >/dev/null
  fi
  log "Installed into system CA store -> $SYSTEM_CA_FILE (apt/curl/wget/git now trust it)"
}

system_ca_unconfigure() {
  [ -n "$HAVE_SYSTEM_CA" ] || { log "System CA store not available, skipping apt/curl/wget/git cleanup"; return 0; }
  if [ -f "$SYSTEM_CA_FILE" ]; then
    run_system_ca_write rm -f "$SYSTEM_CA_FILE"
    if [ "$SYSTEM_CA_KIND" = "debian" ]; then
      run_system_ca_write update-ca-certificates >/dev/null
    else
      run_system_ca_write update-ca-trust extract >/dev/null
    fi
    log "Removed from system CA store: $SYSTEM_CA_FILE"
  else
    log "$SYSTEM_CA_FILE not present, nothing to remove from system CA store"
  fi
}

system_ca_list() {
  if [ -z "$SYSTEM_CA_KIND" ]; then
    log "System CA store tooling not found (no apt/curl/wget/git trust to check)"
    return 0
  fi
  if [ -f "$SYSTEM_CA_FILE" ]; then
    log "System CA store: $SYSTEM_CA_FILE IS installed"
  else
    log "System CA store: $SYSTEM_CA_FILE is NOT installed"
  fi
}

if [ -z "$HAVE_JDK" ] \
   && { [ -n "$SKIP_NPM" ] || [ -z "$HAVE_NPM" ]; } \
   && { [ -n "$SKIP_PIP" ] || [ -z "$HAVE_PIP" ]; } \
   && { [ -n "$SKIP_SYSTEM_CA" ] || [ -z "$HAVE_SYSTEM_CA" ]; }; then
  die "Nothing to do: no JDK, npm, pip or system CA store found (or all skipped). Install one of them, or pass -j/--java-home."
fi

# ---------------------------------------------------------------------------
# npm helpers
# ---------------------------------------------------------------------------
normalize_path() {
  p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    p="$(cygpath -w "$p" 2>/dev/null || printf '%s' "$p")"
  else
    case "$p" in
      /?/*)
        drive="$(printf '%s' "${p#/}" | cut -c1 | tr 'a-z' 'A-Z')"
        rest="${p#/?}"
        p="${drive}:${rest}"
        ;;
    esac
  fi
  printf '%s' "$p" | tr '\\' '/' | tr 'A-Z' 'a-z'
}

npm_configure() {
  pem_path="$1"
  [ -n "$HAVE_NPM" ] || { log "npm not found, skipping npm config"; return 0; }
  mkdir -p "$PERSIST_DIR"
  cp "$pem_path" "$PERSIST_PEM"
  "$NPM_BIN" config set cafile "$PERSIST_PEM" >/dev/null 2>&1 \
    && log "Configured npm cafile -> $PERSIST_PEM" \
    || err "Failed to run 'npm config set cafile'"
}

npm_unconfigure() {
  [ -n "$HAVE_NPM" ] || { log "npm not found, skipping npm cleanup"; return 0; }
  current="$("$NPM_BIN" config get cafile 2>/dev/null || true)"
  if [ "$(normalize_path "$current")" = "$(normalize_path "$PERSIST_PEM")" ]; then
    "$NPM_BIN" config delete cafile >/dev/null 2>&1 && log "Cleared npm cafile config"
  else
    log "npm cafile not managed by this script, leaving as-is"
  fi
}

npm_list() {
  [ -n "$HAVE_NPM" ] || { log "npm not found"; return 0; }
  current="$("$NPM_BIN" config get cafile 2>/dev/null || true)"
  if [ -n "$current" ] && [ "$current" != "null" ]; then
    log "npm cafile is set to: $current"
  else
    log "npm cafile is NOT set"
  fi
}

pip_configure() {
  pem_path="$1"
  [ -n "$HAVE_PIP" ] || { log "pip not found, skipping pip config"; return 0; }
  mkdir -p "$PERSIST_DIR"
  cp "$pem_path" "$PERSIST_PEM"
  "$PIP_BIN" config set global.cert "$PERSIST_PEM" >/dev/null 2>&1 \
    && log "Configured pip global.cert -> $PERSIST_PEM" \
    || err "Failed to run 'pip config set global.cert'"
}

pip_unconfigure() {
  [ -n "$HAVE_PIP" ] || { log "pip not found, skipping pip cleanup"; return 0; }
  current="$("$PIP_BIN" config get global.cert 2>/dev/null || true)"
  if [ "$(normalize_path "$current")" = "$(normalize_path "$PERSIST_PEM")" ]; then
    "$PIP_BIN" config unset global.cert >/dev/null 2>&1 && log "Cleared pip global.cert config"
  else
    log "pip global.cert not managed by this script, leaving as-is"
  fi
}

pip_list() {
  [ -n "$HAVE_PIP" ] || { log "pip not found"; return 0; }
  current="$("$PIP_BIN" config get global.cert 2>/dev/null || true)"
  if [ -n "$current" ]; then
    log "pip global.cert is set to: $current"
  else
    log "pip global.cert is NOT set"
  fi
}

# Ensure a certificate (PEM, DER/.cer, whatever keytool/openssl accept) ends
# up as a plain PEM file at $out, for npm's cafile.
ensure_pem() {
  in="$1"; out="$2"
  if command -v openssl >/dev/null 2>&1; then
    if openssl x509 -in "$in" -inform PEM -out "$out" 2>/dev/null; then return 0; fi
    if openssl x509 -in "$in" -inform DER -out "$out" 2>/dev/null; then return 0; fi
  fi
  if [ -n "$HAVE_JDK" ] && "$KEYTOOL" -printcert -rfc -file "$in" > "$out" 2>/dev/null && [ -s "$out" ]; then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# list / remove actions don't need a certificate file
# ---------------------------------------------------------------------------
if [ "$ACTION" = "list" ]; then
  if [ -n "$HAVE_JDK" ]; then
    if "$KEYTOOL" -list -keystore "$CACERTS" -storepass "$STOREPASS" -alias "$ALIAS" >/dev/null 2>&1; then
      log "Alias '$ALIAS' IS installed in $CACERTS"
      "$KEYTOOL" -list -v -keystore "$CACERTS" -storepass "$STOREPASS" -alias "$ALIAS" | grep -E 'Owner|Valid|SHA256'
    else
      log "Alias '$ALIAS' is NOT installed in $CACERTS"
    fi
  else
    log "No JDK truststore to check (no JDK found)"
  fi
  [ -n "$SKIP_NPM" ] || npm_list
  [ -n "$SKIP_PIP" ] || pip_list
  [ -n "$SKIP_SYSTEM_CA" ] || system_ca_list
  exit 0
fi

if [ "$ACTION" = "remove" ]; then
  if [ -n "$HAVE_JDK" ]; then
    if "$KEYTOOL" -list -keystore "$CACERTS" -storepass "$STOREPASS" -alias "$ALIAS" >/dev/null 2>&1; then
      run_keytool_write -delete -keystore "$CACERTS" -storepass "$STOREPASS" -alias "$ALIAS"
      log "Removed alias '$ALIAS' from $CACERTS"
    else
      log "Alias '$ALIAS' not present, nothing to remove"
    fi
  else
    log "No JDK truststore to clean up (no JDK found)"
  fi
  [ -n "$SKIP_NPM" ] || npm_unconfigure
  [ -n "$SKIP_PIP" ] || pip_unconfigure
  [ -n "$SKIP_SYSTEM_CA" ] || system_ca_unconfigure
  rm -f "$PERSIST_PEM"
  exit 0
fi

# ---------------------------------------------------------------------------
# Locate (or obtain) the Zscaler root certificate
# ---------------------------------------------------------------------------
find_local_cert() {
  for f in ./zscaler*.crt ./zscaler*.pem ./zscaler*.cer ./ZScaler*.crt ./ZScaler*.pem ./ZScaler*.cer; do
    [ -f "$f" ] && { echo "$f"; return 0; }
  done
  return 1
}

export_from_windows_store() {
  certutil_bin=""
  if command -v certutil.exe >/dev/null 2>&1; then
    certutil_bin="certutil.exe"
  elif [ -n "$WIN_MOUNT" ] && [ -x "$WIN_MOUNT/Windows/System32/certutil.exe" ]; then
    certutil_bin="$WIN_MOUNT/Windows/System32/certutil.exe"
  fi
  [ -n "$certutil_bin" ] || return 1
  out="$TMP_DIR/zscaler-from-store.cer"
  if "$certutil_bin" -store root "Zscaler" "$out" >/dev/null 2>&1 || \
     "$certutil_bin" -store root "ZScaler" "$out" >/dev/null 2>&1; then
    [ -s "$out" ] && { echo "$out"; return 0; }
  fi
  return 1
}

fetch_from_live_tls() {
  command -v openssl >/dev/null 2>&1 || return 1
  host="${TLS_HOST%%:*}"
  port="${TLS_HOST##*:}"
  out="$TMP_DIR/zscaler-from-tls.pem"
  # Grab the LAST certificate in the chain served during the handshake;
  # behind Zscaler this is the injected root/intermediate CA.
  if ! echo | openssl s_client -connect "$TLS_HOST" -servername "$host" -showcerts 2>/dev/null \
        > "$TMP_DIR/chain.txt"; then
    return 1
  fi
  awk '/-----BEGIN CERTIFICATE-----/{c=""} {c=c $0 "\n"} /-----END CERTIFICATE-----/{last=c} END{printf "%s", last}' \
    "$TMP_DIR/chain.txt" > "$out"
  [ -s "$out" ] || return 1
  echo "$out"
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [ -z "$CERT_FILE" ]; then
  CERT_FILE="$(find_local_cert || true)"
  [ -n "$CERT_FILE" ] && log "Found local certificate: $CERT_FILE"
fi

if [ -z "$CERT_FILE" ]; then
  log "No local cert given, trying to export from the Windows Root store..."
  CERT_FILE="$(export_from_windows_store || true)"
  [ -n "$CERT_FILE" ] && log "Exported certificate via certutil: $CERT_FILE"
fi

if [ -z "$CERT_FILE" ]; then
  log "Trying to fetch the injected root CA live via TLS to $TLS_HOST ..."
  CERT_FILE="$(fetch_from_live_tls || true)"
  [ -n "$CERT_FILE" ] && log "Captured certificate from TLS handshake: $CERT_FILE"
fi

[ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ] || die "Could not locate a Zscaler root certificate. Pass one explicitly with -c/--cert."

# ---------------------------------------------------------------------------
# Import into cacerts
# ---------------------------------------------------------------------------
if [ -n "$HAVE_JDK" ]; then
  if "$KEYTOOL" -list -keystore "$CACERTS" -storepass "$STOREPASS" -alias "$ALIAS" >/dev/null 2>&1; then
    log "Alias '$ALIAS' already exists, removing old entry first..."
    run_keytool_write -delete -keystore "$CACERTS" -storepass "$STOREPASS" -alias "$ALIAS"
  fi

  log "Importing $CERT_FILE into $CACERTS as alias '$ALIAS'..."
  run_keytool_write -importcert \
    -trustcacerts \
    -noprompt \
    -alias "$ALIAS" \
    -file "$CERT_FILE" \
    -keystore "$CACERTS" \
    -storepass "$STOREPASS"
else
  log "Skipping Java truststore import (no JDK found)"
fi

# ---------------------------------------------------------------------------
# Configure npm / pip / system CA store (best-effort)
# ---------------------------------------------------------------------------
if [ -z "$SKIP_NPM" ] || [ -z "$SKIP_PIP" ] || [ -z "$SKIP_SYSTEM_CA" ]; then
  SHARED_PEM="$TMP_DIR/zscaler-shared.pem"
  if ensure_pem "$CERT_FILE" "$SHARED_PEM"; then
    [ -n "$SKIP_NPM" ] || npm_configure "$SHARED_PEM"
    [ -n "$SKIP_PIP" ] || pip_configure "$SHARED_PEM"
    [ -n "$SKIP_SYSTEM_CA" ] || system_ca_configure "$SHARED_PEM"
  else
    err "Could not convert $CERT_FILE to PEM; skipping npm/pip/system-CA config"
  fi
fi

if [ -n "$HAVE_JDK" ]; then
  log "Done. Verify with: ./setup.sh -j \"$JAVA_HOME_RESOLVED\" --list"
else
  log "Done. Verify with: ./setup.sh --list"
fi
