#!/usr/bin/env bash
# Runs inside the build VM: guest agent, cloud-init, updates.
set -euxo pipefail
cloud-init status --wait || true
. /etc/os-release
case "$ID" in
  rocky|almalinux|rhel|centos)
    dnf -y upgrade
    dnf -y install qemu-guest-agent cloud-init cloud-utils-growpart python3 dnf-utils
    ;;
  debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get -y -o Dpkg::Options::=--force-confold dist-upgrade
    apt-get -y install qemu-guest-agent cloud-init cloud-guest-utils python3 needrestart
    ;;
  *) echo "unsupported distro $ID" >&2; exit 1 ;;
esac
systemctl enable qemu-guest-agent
