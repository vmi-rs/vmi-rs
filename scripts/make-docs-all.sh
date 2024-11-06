#!/usr/bin/env bash

# Get path to the make-docs.sh script in the same directory as this script
MAKE_DOCS="$(dirname "${0}")/make-docs.sh"

"${MAKE_DOCS}" "isr"
"${MAKE_DOCS}" "isr/crates/isr-cache"
"${MAKE_DOCS}" "isr/crates/isr-core"
"${MAKE_DOCS}" "isr/crates/isr-dl-linux"
"${MAKE_DOCS}" "isr/crates/isr-dl-pdb"
"${MAKE_DOCS}" "isr/crates/isr-dwarf"
"${MAKE_DOCS}" "isr/crates/isr-macros"
"${MAKE_DOCS}" "isr/crates/isr-pdb"
cp "isr/crates/isr-cache/README.md" "isr/docs/isr-cache.md"
cp "isr/crates/isr-core/README.md" "isr/docs/isr-core.md"
cp "isr/crates/isr-dl-linux/README.md" "isr/docs/isr-dl-linux.md"
cp "isr/crates/isr-dl-pdb/README.md" "isr/docs/isr-dl-pdb.md"
cp "isr/crates/isr-dwarf/README.md" "isr/docs/isr-dwarf.md"
cp "isr/crates/isr-macros/README.md" "isr/docs/isr-macros.md"
cp "isr/crates/isr-pdb/README.md" "isr/docs/isr-pdb.md"

"${MAKE_DOCS}" "vmi"
"${MAKE_DOCS}" "vmi/crates/vmi-arch-amd64"
"${MAKE_DOCS}" "vmi/crates/vmi-core"
"${MAKE_DOCS}" "vmi/crates/vmi-driver-xen"
# "${MAKE_DOCS}" "vmi/crates/vmi-macros"
"${MAKE_DOCS}" "vmi/crates/vmi-os-linux"
"${MAKE_DOCS}" "vmi/crates/vmi-os-windows"
"${MAKE_DOCS}" "vmi/crates/vmi-utils"
cp "vmi/crates/vmi-arch-amd64/README.md" "vmi/docs/vmi-arch-amd64.md"
cp "vmi/crates/vmi-core/README.md" "vmi/docs/vmi-core.md"
cp "vmi/crates/vmi-core/docs/arch.md" "vmi/docs/vmi-core-arch.md"
cp "vmi/crates/vmi-core/docs/os.md" "vmi/docs/vmi-core-os.md"
cp "vmi/crates/vmi-driver-xen/README.md" "vmi/docs/vmi-driver-xen.md"
# cp "vmi/crates/vmi-macros/README.md" "vmi/docs/vmi-macros.md"
cp "vmi/crates/vmi-os-linux/README.md" "vmi/docs/vmi-os-linux.md"
cp "vmi/crates/vmi-os-windows/README.md" "vmi/docs/vmi-os-windows.md"
cp "vmi/crates/vmi-utils/README.md" "vmi/docs/vmi-utils.md"