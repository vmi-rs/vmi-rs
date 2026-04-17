#!/usr/bin/env bash
set -euo pipefail

VMI_RS_DIR="$(realpath "$(dirname "${0}")/..")"
MAKE_README="scripts/make-readme.sh"

pushd "${VMI_RS_DIR}" > /dev/null

"${MAKE_README}" "isr"
"${MAKE_README}" "isr/crates/isr-cache"
"${MAKE_README}" "isr/crates/isr-core"
"${MAKE_README}" "isr/crates/isr-dl-linux"
"${MAKE_README}" "isr/crates/isr-dl-windows"
"${MAKE_README}" "isr/crates/isr-dwarf"
"${MAKE_README}" "isr/crates/isr-macros"
"${MAKE_README}" "isr/crates/isr-pdb"
cp "isr/crates/isr-cache/README.md" "isr/docs/isr-cache.md"
cp "isr/crates/isr-core/README.md" "isr/docs/isr-core.md"
cp "isr/crates/isr-dl/README.md" "isr/docs/isr-dl.md"
cp "isr/crates/isr-dl-linux/README.md" "isr/docs/isr-dl-linux.md"
cp "isr/crates/isr-dl-windows/README.md" "isr/docs/isr-dl-windows.md"
cp "isr/crates/isr-dwarf/README.md" "isr/docs/isr-dwarf.md"
cp "isr/crates/isr-macros/README.md" "isr/docs/isr-macros.md"
cp "isr/crates/isr-pdb/README.md" "isr/docs/isr-pdb.md"

"${MAKE_README}" "vmi"
"${MAKE_README}" "vmi/crates/vmi-arch-amd64"
"${MAKE_README}" "vmi/crates/vmi-core"
"${MAKE_README}" "vmi/crates/vmi-driver-xen"
# "${MAKE_README}" "vmi/crates/vmi-macros"
"${MAKE_README}" "vmi/crates/vmi-os-linux"
"${MAKE_README}" "vmi/crates/vmi-os-windows"
"${MAKE_README}" "vmi/crates/vmi-utils"
cp "vmi/crates/vmi-arch-amd64/README.md" "vmi/docs/vmi-arch-amd64.md"
cp "vmi/crates/vmi-core/README.md" "vmi/docs/vmi-core.md"
cp "vmi/crates/vmi-core/docs/arch.md" "vmi/docs/vmi-core-arch.md"
cp "vmi/crates/vmi-core/docs/os.md" "vmi/docs/vmi-core-os.md"
cp "vmi/crates/vmi-driver-kdmp/README.md" "vmi/docs/vmi-driver-kdmp.md"
cp "vmi/crates/vmi-driver-xen/README.md" "vmi/docs/vmi-driver-xen.md"
cp "vmi/crates/vmi-driver-xen-core-dump/README.md" "vmi/docs/vmi-driver-xen-core-dump.md"
# cp "vmi/crates/vmi-macros/README.md" "vmi/docs/vmi-macros.md"
cp "vmi/crates/vmi-os-linux/README.md" "vmi/docs/vmi-os-linux.md"
cp "vmi/crates/vmi-os-windows/README.md" "vmi/docs/vmi-os-windows.md"
cp "vmi/crates/vmi-utils/README.md" "vmi/docs/vmi-utils.md"

popd > /dev/null
