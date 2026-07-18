#!/usr/bin/env bash
# Desisherlock uninstaller - no root/sudo required.
set -euo pipefail

echo "Uninstalling Desisherlock..."
python3 -m pip uninstall -y desisherlock

echo "Done. Config and reports under ~/.desisherlock were left in place;"
echo "remove that directory manually if you want a full clean-up."
