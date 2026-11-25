#!/usr/bin/env bash
# Runs inside the build VM: guest agent, cloud-init, updates, SSH hardening, automatic updates.
# HM_SSHD_HARDENING (1/0) and HM_UNATTENDED_UPDATES (distro|security|off) come from the Packer variables.
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

if [ "${HM_SSHD_HARDENING:-1}" = 1 ]; then
  # sshd takes the first value it reads: 01- comes before the image's and cloud-init's 50-*.conf
  install -d -m 755 /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/01-homelab.conf <<'EOF'
# homelab-infrastructure template: key-only logins (Packer variable sshd_hardening)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
  chmod 644 /etc/ssh/sshd_config.d/01-homelab.conf
  grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  sshd -t
fi

case "${HM_UNATTENDED_UPDATES:-distro}:$ID" in
  security:rocky|security:almalinux|security:rhel|security:centos)
    dnf -y install dnf-automatic
    sed -i -e 's/^upgrade_type *=.*/upgrade_type = security/' -e 's/^apply_updates *=.*/apply_updates = yes/' \
      /etc/dnf/automatic.conf
    systemctl enable dnf-automatic.timer
    ;;
  security:debian|security:ubuntu)
    apt-get -y install unattended-upgrades
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
      > /etc/apt/apt.conf.d/20auto-upgrades
    ;;
  off:rocky|off:almalinux|off:rhel|off:centos)
    systemctl disable dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null || true
    ;;
  off:debian|off:ubuntu)
    printf 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n' \
      > /etc/apt/apt.conf.d/20auto-upgrades
    ;;
esac
