#!/usr/bin/env bash
set -eu
cp -R "$(dirname "$0")/files/." .
git init -qb main
git remote add origin ssh://git@gitlab.example.com:2222/marek/homelab-infrastructure.git
