#!/usr/bin/env bash
# Make the template generic: no host identity, no build key, fresh cloud-init on first boot.
set -euxo pipefail
. /etc/os-release
case "$ID" in
  rocky|almalinux|rhel|centos) dnf -y clean all ;;
  debian|ubuntu) apt-get -y autoremove --purge; apt-get clean ;;
esac
rm -f /etc/ssh/ssh_host_*
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id && ln -sf /etc/machine-id /var/lib/dbus/machine-id || true
cloud-init clean --logs --seed
for h in /root /home/*; do rm -f "$h/.ssh/authorized_keys" "$h/.bash_history"; done
find /var/log -type f -exec truncate -s 0 {} \;
rm -rf /tmp/* /var/tmp/*
fstrim -av || true   # hand freed blocks back to thin storage: a smaller template
sync
