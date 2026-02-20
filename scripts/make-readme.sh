#!/bin/bash
#
# Assemble a README.md from its template and the module-level rustdoc in
# src/lib.rs. The rustdoc is extracted, transformed to markdown, and
# inserted between <!-- readme --> markers.
#
# Usage: make-readme.sh <crate-directory>
#

set -euo pipefail

LIB_RS="${1}/src/lib.rs"
README_MD="${1}/README.md"
README_TMP="${README_MD}.tmp"

trap 'rm -f "${README_TMP}"' EXIT

echo "Generating README.md for ${1}"

# Extract and transform module-level rustdoc into GitHub-flavored markdown.
extract_readme() {
    # Extract //! lines, stripping the "//! " or "//!" prefix.
    sed -n '/^\/\/!/{s/^\/\/! \{0,1\}//;p;}' "${LIB_RS}" |

    # Strip trailing whitespace.
    sed 's/[[:space:]]*$//' |

    # Transform code fences, remove hidden doc lines and link defs.
    awk '
        # Track code fences to distinguish code blocks from prose.
        /^[[:space:]]*```/ {
            if (in_code) {
                in_code = 0
            } else {
                in_code = 1
                # Normalize rustdoc code fence annotations to ```rust,ignore
                # (```rust, ```rust,no_run, ```no_run, ```ignore are
                # rustdoc-only and not valid on GitHub)
                sub(/```(rust(,no_run)?|no_run|ignore)$/, "```rust,ignore")
            }
            print
            next
        }

        # Strip hidden doc lines inside code blocks.
        # Rustdoc hides lines starting with "# " (or bare "#") in
        # code examples; these must be removed for plain markdown.
        in_code && /^[[:space:]]*#( |$)/ { next }

        # Strip link reference definitions.
        # The template (README.tpl) provides all link targets with
        # proper URLs; the rustdoc versions use crate::, ::, or
        # relative paths that do not resolve on GitHub.
        !in_code && /^\[.*\]: / { next }

        { print }
    ' |

    # Collapse consecutive blank lines.
    cat -s |

    # Strip trailing blank lines left over after link-def removal.
    sed -e :a -e '/^[[:space:]]*$/{$d;N;ba;}'
}

#
# Assemble the final README.
#
# Supports two marker formats:
#   <!-- readme -->               (initial placeholder, replaced on first run)
#   <!-- readme start -->...<!-- readme end -->  (updated in place on re-runs)
#

{
    if grep -q '^<!-- readme start -->$' "${README_MD}"; then
        # Update mode: replace content between start/end markers.
        sed '/^<!-- readme start -->$/,$d' "${README_MD}"
        echo '<!-- readme start -->'
        extract_readme
        echo '<!-- readme end -->'
        sed '0,/^<!-- readme end -->$/d' "${README_MD}"

    elif grep -q '^<!-- readme -->$' "${README_MD}"; then
        # Initial mode: replace single marker with start/end pair.
        sed '/^<!-- readme -->$/,$d' "${README_MD}"
        echo '<!-- readme start -->'
        extract_readme
        echo '<!-- readme end -->'
        sed '0,/^<!-- readme -->$/d' "${README_MD}"

    else
        echo "error: no <!-- readme --> marker found in ${README_MD}" >&2
        exit 1
    fi
} > "${README_TMP}"

mv "${README_TMP}" "${README_MD}"
trap - EXIT
