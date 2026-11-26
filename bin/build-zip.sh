#!/usr/bin/env bash
# Builds dist/bee-monitor-<version>.zip using .distignore.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(grep -m1 -E '^\s*\*\s*Version:' bee-monitor.php | awk '{print $NF}')
STABLE=$(grep -m1 -E '^Stable tag:' readme.txt | awk '{print $NF}')
CONST=$(grep -m1 "BEE_MONITOR_VERSION'" bee-monitor.php | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
if [ "$VERSION" != "$STABLE" ] || [ "$VERSION" != "$CONST" ]; then
	echo "Version mismatch: header=$VERSION stable=$STABLE constant=$CONST" >&2
	exit 1
fi
rm -rf dist && mkdir -p dist/bee-monitor
rsync -a --exclude-from=.distignore ./ dist/bee-monitor/
(cd dist && zip -qr "bee-monitor-$VERSION.zip" bee-monitor)
echo "Built dist/bee-monitor-$VERSION.zip"
