#!/bin/sh
# Runs on the host: build Network Manager and put it in the share of the VM
# that ../gxwi/dev/boot.sh started, with its icon for the base theme and its
# declaration for the catalogue. GXWI's dev service puts them where a package
# would, and its dev loop restarts on a new one.
#
# The rename makes the new binary appear whole, never half-written.
set -eu
cd "$(dirname "$0")/.."
. dev/env.sh
[ -d ../gxwi/target/vmshare ] || { echo "no ../gxwi/target/vmshare: boot the VM from ../gxwi first" >&2; exit 1; }
share=$(cd ../gxwi/target/vmshare && pwd)
cargo build --release
mkdir -p "$share/icons/base"
cp gxwi-network-manager.svg "$share/icons/base/dev.peios.gxwi-network-manager.svg"
mkdir -p "$share/apps"
cp dev.peios.gxwi-network-manager.toml "$share/apps/dev.peios.gxwi-network-manager.toml"
cp target/release/gxwi-network-manager "$share/gxwi-network-manager.new"
mv "$share/gxwi-network-manager.new" "$share/gxwi-network-manager"
