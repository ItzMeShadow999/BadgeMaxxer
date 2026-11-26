#!/bin/sh
set -eu

OWNER="ItzMeShadow999"
REPO="badgemaxxer"
TAG="${BADGEMAXXER_TAG:-}"
RELEASES="https://github.com/$OWNER/$REPO/releases"
DIR="$HOME/BadgeMaxxer"
FILES="BadgeMaxxer.py lib/secret_store.py Watcher/stream_watcher.py Watcher/watcher_voice.py Watcher/watcher_common.py Streamer/Streamer.js"
PACKAGES="websockets davey cryptography"

if [ -t 1 ]; then
    YELLOW="$(printf '\033[33m')"; GREEN="$(printf '\033[32m')"; RED="$(printf '\033[31m')"; RESET="$(printf '\033[0m')"
else
    YELLOW=""; GREEN=""; RED=""; RESET=""
fi

step() { printf '  %s%s%s\n' "$YELLOW" "$1" "$RESET"; }
ok()   { printf '  %s%s%s\n' "$GREEN" "$1" "$RESET"; }
bad()  { printf '  %s%s%s\n' "$RED" "$1" "$RESET" >&2; }

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -H "User-Agent: BadgeMaxxer-installer" -o "$2" "$1"
    else
        wget -q --header="User-Agent: BadgeMaxxer-installer" -O "$2" "$1"
    fi
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

find_python() {
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_tag() {
    if [ -n "$TAG" ]; then
        echo "$TAG"
        return 0
    fi
    fetch "https://api.github.com/repos/$OWNER/$REPO/releases/latest" "$1"
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$1" | head -n 1
}

ensure_system_packages() {
    command -v apt-get >/dev/null 2>&1 || return 0
    need=""
    if ! command -v python3 >/dev/null 2>&1; then
        need="$need python3 python3-venv"
    elif ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
        need="$need python3-venv"
    fi
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        need="$need curl"
    fi
    if ! command -v node >/dev/null 2>&1; then
        need="$need nodejs"
    fi
    if ! command -v npm >/dev/null 2>&1; then
        need="$need npm"
    fi
    if ! command -v ffmpeg >/dev/null 2>&1; then
        need="$need ffmpeg"
    fi
    if [ -n "$need" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            sudo_cmd=""
        elif command -v sudo >/dev/null 2>&1; then
            sudo_cmd="sudo"
        else
            bad "Missing system packages:$need. Run as root: apt-get install$need"
            return 0
        fi
        step "Installing system packages:$need ..."
        if ! $sudo_cmd apt-get update -qq || ! $sudo_cmd apt-get install -y -qq $need; then
            bad "apt could not install:$need. Install them yourself: sudo apt install$need"
            return 0
        fi
        ok "System packages installed:$need"
    fi
    if command -v node >/dev/null 2>&1; then
        node_major="$(node --version 2>/dev/null | sed 's/^v//; s/\..*//')"
        case "$node_major" in
            ""|*[!0-9]*) ;;
            *) if [ "$node_major" -lt 18 ]; then
                   bad "Node.js $(node --version) is too old, the Streamer needs Node.js 18 or newer (use NodeSource or nvm)"
               fi ;;
        esac
    fi
}

install_badgemaxxer() {
    echo
    printf '  %sBadgeMaxxer installer%s\n' "$YELLOW" "$RESET"
    echo

    ensure_system_packages

    sums="$(mktemp)"
    trap 'rm -f "$sums"' EXIT
    ref="$(resolve_tag "$sums" 2>/dev/null)" || ref=""
    case "$ref" in
        "")
            bad "Could not load release checksums, nothing was installed: could not find the latest release (set BADGEMAXXER_TAG to pick one)"
            return 1
            ;;
        *[!A-Za-z0-9._-]*)
            bad "Could not load release checksums, nothing was installed: invalid release tag '$ref'"
            return 1
            ;;
    esac
    base="https://raw.githubusercontent.com/$OWNER/$REPO/$ref"
    step "Release $ref, fetching SHA256SUMS ..."
    if ! fetch "$RELEASES/download/$ref/SHA256SUMS" "$sums" || ! grep -Eq '^[0-9a-fA-F]{64}[[:space:]]' "$sums"; then
        bad "Could not load release checksums, nothing was installed: SHA256SUMS is empty or unreadable"
        return 1
    fi

    if ! py="$(find_python)"; then
        bad "Python 3.9 or newer is required. Install it with your package manager (for example: sudo pacman -S python, or sudo apt install python3 python3-venv), then run this again."
        return 1
    fi

    if ! mkdir -p "$DIR/Watcher" "$DIR/lib" "$DIR/Streamer"; then
        bad "Could not create $DIR"
        return 1
    fi

    for file in $FILES; do
        target="$DIR/$file"
        temp="$target.download"
        step "Fetching $file ...."
        mkdir -p "$(dirname "$target")"
        if ! fetch "$base/$file" "$temp"; then
            rm -f "$temp"
            bad "Could not install $file : download failed"
            return 1
        fi
        expected=""
        cr="$(printf '\r')"
        while read -r hash name || [ -n "$hash" ]; do
            name="${name%"$cr"}"
            if [ "${name#\*}" = "$file" ]; then
                expected="$(printf '%s' "$hash" | tr 'A-F' 'a-f')"
                break
            fi
        done < "$sums"
        actual="$(sha256 "$temp")"
        if [ -z "$expected" ]; then
            rm -f "$temp"
            bad "Could not install $file : no checksum listed for $file in SHA256SUMS"
            return 1
        fi
        if [ "$actual" != "$expected" ]; then
            rm -f "$temp"
            bad "Could not install $file : checksum mismatch (expected $expected, got $actual)"
            return 1
        fi
        ok "Verified $file (sha256 $(printf '%.16s' "$actual")...)"
        mv -f "$temp" "$target"
    done
    rm -f "$sums"
    ok "Files saved to $DIR (your session.json is never touched)"

    if ! "$DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1 && ! "$py" -m venv --clear "$DIR/.venv"; then
        bad "Could not create a virtual environment in $DIR/.venv. On Debian or Ubuntu install python3-venv, then run this again."
        return 1
    fi
    missing=""
    for pkg in $PACKAGES; do
        if ! "$DIR/.venv/bin/python" -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('$pkg') is None)" >/dev/null 2>&1; then
            missing="$missing $pkg"
        fi
    done
    if [ -z "$missing" ]; then
        ok "Python packages already installed: $PACKAGES"
    else
        step "Installing missing Python packages:$missing ..."
        if ! "$DIR/.venv/bin/python" -m pip install --quiet --disable-pip-version-check $missing; then
            bad "pip could not install every package, BadgeMaxxer will try again when it needs them."
        fi
    fi

    ok "Starting BadgeMaxxer"
    echo
    cd "$DIR"
    if (exec </dev/tty) 2>/dev/null; then
        exec "$DIR/.venv/bin/python" "$DIR/BadgeMaxxer.py" </dev/tty
    fi
    exec "$DIR/.venv/bin/python" "$DIR/BadgeMaxxer.py"
}

install_badgemaxxer
