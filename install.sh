#!/usr/bin/env bash
# Desisherlock installer - no root/sudo required, ever.
# Port scanning uses TCP connect scanning only, so nothing here needs elevated
# privileges. Do not add sudo to this script.
#
# Run it as: bash install.sh   (works even if the executable bit got lost
# in transit, e.g. a GitHub web upload instead of a real git push/clone).
#
# When run in an interactive terminal, this script drops you into a fresh
# shell at the end with PATH already set - so "Desisherlock" works
# immediately, with no manual "source ~/.bashrc" or new-terminal step.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Desisherlock installer"
echo "======================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found. Install Python 3.8+ and re-run." >&2
    exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="$(echo "$PY_VERSION" | cut -d. -f1)"
PY_MINOR="$(echo "$PY_VERSION" | cut -d. -f2)"

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo "Error: Python 3.8+ required, found $PY_VERSION." >&2
    exit 1
fi
echo "Found Python $PY_VERSION"

if ! python3 -m pip --version >/dev/null 2>&1; then
    echo "Error: pip not found for python3. Install pip and re-run." >&2
    exit 1
fi
echo "Found pip"

echo "Installing Desisherlock (user site, no sudo)..."
# --ignore-installed forces pip to install our own copy of every dependency
# into user site-packages, even if a same-named package already exists
# system-wide. Without this, pip treats an existing system package as
# "already satisfied" and skips it - which silently breaks Desisherlock if
# that system copy is broken, outdated, or incompatible (this bit us for
# real with a broken system `cryptography` package during testing).
if python3 -m pip install --user --upgrade --ignore-installed . --break-system-packages >/tmp/desisherlock_install.log 2>&1; then
    echo "Install succeeded."
else
    echo "Retrying without --break-system-packages (older pip may not support it)..."
    if ! python3 -m pip install --user --upgrade --ignore-installed . >>/tmp/desisherlock_install.log 2>&1; then
        echo "Error: pip install failed. Full log:" >&2
        cat /tmp/desisherlock_install.log >&2
        exit 1
    fi
fi

USER_BIN="$(python3 -m site --user-base)/bin"
MARKER="# Added by Desisherlock installer"
PATH_LINE="export PATH=\"$USER_BIN:\$PATH\""

# Persist the PATH fix for every future new terminal, regardless of shell.
for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$RC" ] || [ "$RC" = "$HOME/.profile" ]; then
        touch "$RC"
        if ! grep -Fxq "$PATH_LINE" "$RC" 2>/dev/null; then
            { echo ""; echo "$MARKER"; echo "$PATH_LINE"; } >> "$RC"
        fi
    fi
done

echo ""
echo "Done. Desisherlock is installed."

case ":$PATH:" in
    *":$USER_BIN:"*)
        # Already on PATH in this very shell - nothing more to do.
        echo "Try: Desisherlock --version"
        ;;
    *)
        if [ -t 0 ] && [ -t 1 ] && [ -n "${SHELL:-}" ]; then
            echo "Switching you into a shell with the right PATH now..."
            echo ""
            exec env PATH="$USER_BIN:$PATH" "$SHELL"
        else
            # No terminal attached (e.g. piped into this script, or run from
            # a non-interactive build step) - can't hand control to a new
            # shell, so fall back to telling the user what to do.
            echo ""
            echo "NOTE: $USER_BIN is not on your PATH in this session."
            echo "Run this now, or just open a new terminal:"
            echo "  source ~/.bashrc"
        fi
        ;;
esac
