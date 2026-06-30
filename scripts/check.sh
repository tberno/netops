#!/usr/bin/env bash
set -euo pipefail

APP="/opt/docker-stacks/netops-v4/netops-app/app"

python3 -m py_compile "$APP/main.py"
python3 -m py_compile "$APP/routes/tools.py"
python3 -m py_compile "$APP/routes/reports.py"
python3 -m py_compile "$APP/routes/device.py"

find "$APP/services" -name '*.py' -print0 | xargs -0 -n1 python3 -m py_compile

curl -s -o /dev/null -w "v4 health: %{http_code}\n" \
  http://127.0.0.1:8056/health

curl -s -o /dev/null -w "stats: %{http_code}\n" \
  "http://127.0.0.1:8056/reports/interface-statistics?limit=25"

curl -s -o /dev/null -w "lookup hub: %{http_code}\n" \
  "http://127.0.0.1:8056/tools/lookup"

curl -s -o /dev/null -w "interface lookup: %{http_code}\n" \
  "http://127.0.0.1:8056/tools/lookup/interfaces?q=acme&limit=25"

curl -k -s -o /dev/null -w "v4 external: %{http_code}\n" \
  "https://raccoon.middlebury.edu/netops-v4/tools/lookup"

curl -k -s -o /dev/null -w "v3 still live: %{http_code}\n" \
  "https://raccoon.middlebury.edu/netops/reports/interface-statistics"
