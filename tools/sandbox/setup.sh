#!/bin/bash
# Kitsunox Stage 5, local Docker sandbox: one-time setup. Run once, as root:
#
#     sudo bash tools/sandbox/setup.sh
#
# What it does (docs/stages/sandbox.md, "Local Docker sandbox"; decision 0014, addendum
# 2026-11-01):
#   1. installs Docker (Ubuntu's docker.io). Your user is NOT added to the docker group: that
#      group is root-equivalent, and only root's timer talks to Docker;
#   2. pulls package-analysis rel-38's analysis image by digest into Docker, and has its podman
#      pull the dynamic-analysis sandbox image by digest (the pins in docs/stages/sandbox.md)
#      into a podman store of its own, /srv/kitsunox-sandbox/store, never the host's
#      /var/lib/containers;
#   3. installs a root-owned copy of the runner (/usr/local/sbin/kitsunox-sandbox-run), its
#      config (/etc/kitsunox-sandbox.json) and an hourly root timer (kitsunox-sandbox.timer);
#   4. points Kitsunox at the results root (KITSUNOX_SANDBOX_RESULTS in .env, which it also
#      makes readable by you only), so each tick exports jobs and imports results;
#   5. runs an inert test package through the whole chain and keeps its result for review. It
#      does not enable the timer: decision 0014's review gate says no real sample runs before
#      the owner has looked at a benign result. After that, one more command turns it on:
#          sudo systemctl enable --now kitsunox-sandbox.timer
# Re-running it is safe: every step checks what is already there.
set -euo pipefail

ANALYSIS_DIGEST="sha256:1f3104f3f0cfddeaf62f0952d663e129cb5efe38486766e676fb926fa84c4c27"
SANDBOX_DIGEST="sha256:d90cdfac786491580614b9cefd0d12223131528c476de331842336c145bef5a7"
ANALYSIS_IMAGE="gcr.io/ossf-malware-analysis/analysis"
SANDBOX_IMAGE="gcr.io/ossf-malware-analysis/dynamic-analysis"
RELEASE="rel-38"
ROOT_DIR="/srv/kitsunox-sandbox"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 2
fi
OWNER="${SUDO_USER:-}"
if [[ -z "$OWNER" || "$OWNER" == "root" ]]; then
    echo "Run through sudo from the Kitsunox user's account, so the owner is known." >&2
    exit 2
fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA="$REPO/data"
ENV_FILE="$REPO/.env"
if [[ ! -d "$DATA" || ! -f "$REPO/pyproject.toml" ]]; then
    echo "Can't find the Kitsunox checkout and data/ next to this script ($REPO)." >&2
    exit 2
fi
OWNER_UID="$(id -u "$OWNER")"
OWNER_GID="$(id -g "$OWNER")"
step() { printf '\n== %s\n' "$*"; }

step "1/6 Docker"
if ! command -v docker >/dev/null; then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io
fi
systemctl enable --now docker >/dev/null
if id -nG "$OWNER" | tr ' ' '\n' | grep -qx docker; then
    echo "WARNING: $OWNER is in the docker group, which is root-equivalent." \
        "Remove it with: sudo gpasswd -d $OWNER docker" >&2
fi
docker version --format 'Docker {{.Server.Version}}'

step "2/6 Analysis image, pinned by digest"
docker pull -q "$ANALYSIS_IMAGE@$ANALYSIS_DIGEST"

step "3/6 Directories"
install -d -m 0755 -o root -g root "$ROOT_DIR"
install -d -m 0700 -o root -g root "$ROOT_DIR/store" "$ROOT_DIR/work"
install -d -m 0750 -o "$OWNER_UID" -g "$OWNER_GID" "$ROOT_DIR/results"

step "4/6 Sandbox image into the sandbox's own podman store"
# The analysis container's podman pulls the sandbox image itself, by digest, as package-analysis
# does. (Copying it from Docker with `docker save | podman load` broke on Docker 29: podman
# loaded its OCI archive as localhost/rel-38 and the expected name never existed.) This setup
# container has the network; the runner's never do.
in_analysis() {
    docker run --rm --privileged --cgroupns=host --network "$NET" \
        -v "$ROOT_DIR/store:/var/lib/containers" "$ANALYSIS_IMAGE@$ANALYSIS_DIGEST" "$@"
}
show_store() {
    echo "What the sandbox's podman store holds now:" >&2
    NET=none in_analysis podman images --all --digests >&2 || true
}
trap show_store ERR
NET=bridge in_analysis podman pull -q "$SANDBOX_IMAGE@$SANDBOX_DIGEST"
NET=none in_analysis podman tag "$SANDBOX_IMAGE@$SANDBOX_DIGEST" "$SANDBOX_IMAGE:$RELEASE"
# A name left by an earlier, failed setup (docker save | podman load), if any.
NET=none in_analysis podman untag localhost/rel-38:latest >/dev/null 2>&1 || true
SANDBOX_ID="$(NET=none in_analysis \
    podman image inspect --format '{{.Id}}' "$SANDBOX_IMAGE:$RELEASE")"
trap - ERR
echo "sandbox image in the store: $SANDBOX_ID"

step "5/6 Runner, config, timer, Kitsunox setting"
install -m 0755 -o root -g root "$REPO/tools/sandbox/kitsunox_sandbox_run.py" \
    /usr/local/sbin/kitsunox-sandbox-run
umask 077
cat > /etc/kitsunox-sandbox.json <<EOF
{
  "export_dir": "$DATA/sandbox/export",
  "results_dir": "$ROOT_DIR/results",
  "work_dir": "$ROOT_DIR/work",
  "store_dir": "$ROOT_DIR/store",
  "owner_uid": $OWNER_UID,
  "owner_gid": $OWNER_GID,
  "analysis_digest": "$ANALYSIS_DIGEST",
  "sandbox_image_id": "$SANDBOX_ID",
  "memory": "6g",
  "cpus": "2",
  "pids": 4096,
  "timeout_s": 1200
}
EOF
chmod 0644 /etc/kitsunox-sandbox.json
umask 022
cat > /etc/systemd/system/kitsunox-sandbox.service <<'EOF'
[Unit]
Description=Kitsunox Stage 5: run exported package-analysis jobs in Docker (no network)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/kitsunox-sandbox-run
Nice=15
IOSchedulingClass=idle
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
TimeoutStartSec=6h
EOF
cat > /etc/systemd/system/kitsunox-sandbox.timer <<'EOF'
[Unit]
Description=Kitsunox Stage 5 sandbox runs, hourly at :25 (Kitsunox ticks start near :55-:15)

[Timer]
OnCalendar=*-*-* *:25:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
touch "$ENV_FILE"
chown "$OWNER_UID:$OWNER_GID" "$ENV_FILE"
chmod 0600 "$ENV_FILE"
if ! grep -q '^KITSUNOX_SANDBOX_RESULTS=' "$ENV_FILE"; then
    printf 'KITSUNOX_SANDBOX_RESULTS=%s\n' "$ROOT_DIR/results" >> "$ENV_FILE"
fi
echo "runner: /usr/local/sbin/kitsunox-sandbox-run; results root: $ROOT_DIR/results"

step "6/6 Smoke test: an inert package through the whole chain (a few minutes)"
if /usr/local/sbin/kitsunox-sandbox-run --smoke --keep "$ROOT_DIR/smoke-result"; then
    echo
    echo "The chain works. The timer is NOT enabled yet: decision 0014's review gate says no"
    echo "real sample runs before you have looked at a benign result. The test package's"
    echo "result is in $ROOT_DIR/smoke-result (ask Claude to read it with you). Then turn on"
    echo "the hourly runs with:"
    echo
    echo "    sudo systemctl enable --now kitsunox-sandbox.timer"
else
    echo
    echo "The smoke test failed (output above), so nothing will run. Send the output to" >&2
    echo "Claude; re-running this script after a fix is safe." >&2
    exit 1
fi
