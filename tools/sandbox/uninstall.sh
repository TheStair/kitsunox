#!/bin/bash
# Undo tools/sandbox/setup.sh: stop and remove the timer, runner and config, and the sandbox's
# images and podman store. Results already imported into Kitsunox stay in data/sandbox/.
# Docker itself and the KITSUNOX_SANDBOX_RESULTS line in .env are left; remove them by hand
# (sudo apt-get remove docker.io; delete the line) if you want them gone too.
#
#     sudo bash tools/sandbox/uninstall.sh
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 2
fi
systemctl disable --now kitsunox-sandbox.timer 2>/dev/null || true
rm -f /etc/systemd/system/kitsunox-sandbox.service /etc/systemd/system/kitsunox-sandbox.timer
systemctl daemon-reload
rm -f /usr/local/sbin/kitsunox-sandbox-run /etc/kitsunox-sandbox.json
rm -rf /srv/kitsunox-sandbox
if command -v docker >/dev/null; then
    docker image rm -f gcr.io/ossf-malware-analysis/dynamic-analysis:rel-38 >/dev/null 2>&1 || true
    docker image ls --format '{{.Repository}}@{{.Digest}}' \
        | grep '^gcr.io/ossf-malware-analysis/' | xargs -r docker image rm -f >/dev/null 2>&1 || true
fi
echo "Removed the Kitsunox sandbox runner, timer, config, store and images."
