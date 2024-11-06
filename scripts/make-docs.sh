#!/usr/bin/env bash

echo "Generating README.md for ${1}"

# Read the template file up to the {{readme}} line
sed -n '/{{readme}}/q;p' "${1}/README.tpl" > "${1}/README.md"

# Append the output of the cargo readme command
cargo readme -r "${1}" --no-indent-headings             \
                       --no-template                    \
                       --no-title                       \
                       --no-license                     \
    | sed -E '/^(\[[a-zA-Z0-9_.:!()`]+\]: .*)$/d'       \
    | sed -E '/^[ ]*#$/d'                               \
    | sed -E '/^[ ]+# .*/d'                             \
    | sed -E 's/```rust(,[a-z_]+)?$/```rust,ignore/'    \
    >> "${1}/README.md"

# Append the rest of the template file
sed -n '/{{readme}}/,$p' "${1}/README.tpl" | tail -n +2 >> "${1}/README.md"
