#!/usr/bin/env bash
set -euo pipefail

cd /opt/docker-stacks/netops-v4
python3 -m py_compile netops-app/app/main.py
sudo docker compose up -d --build --force-recreate netops-v4
sleep 3
./scripts/check.sh
