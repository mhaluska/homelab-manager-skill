#!/usr/bin/env bash
set -eu
cp -R "$(dirname "$0")/files/." .
git init -qb main
git remote add origin git@github.com:example/homelab-infrastructure.git
