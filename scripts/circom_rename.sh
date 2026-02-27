#!/bin/bash
# This script is designed to be idempotent, so it can be run again without changing anything.

if [ $# -ne 2 ]; then
    echo "Usage: $0 <folder> <prefix>"
    exit 1
fi

FOLDER="$1"
PREFIX="$2"

# Find all files we need to modify
CIRCUITS=$(find circuits/circom-ecdsa-p256/ -type f -name "*.circom")

# Collect all symbols that need to be renamed (might be over-renaming signal names, but that isn't really an issue if done everywhere).
SYMBOLS=$(cat $CIRCUITS | grep -oP '^(template|function)\s+\K(?!'"$PREFIX"')[A-Za-z0-9_]+\b')

# We could also only rename conflicts. Would be preferrable but also more complex.

# For performance: Build the sed expression and only run sed once per file
# xxxxxxxx is unlikely to occur/cause problems, it simplifies regex building and
# it means we don't get issues if we don't need to replace any symbols.
SYM_REGEX="xxxxxxxx"
for sym in $SYMBOLS; do
    SYM_REGEX="$SYM_REGEX|$sym"
done

# We also need to replace includes into node_modules
SED_EXPR="
    s=^include \".*/node_modules/circomlib=include \"circomlib=g;
    /^include/! s/\b($SYM_REGEX)\b/$PREFIX\\1/g;
"

# Do the renaming
for file in $CIRCUITS; do
    sed -Ei "$SED_EXPR" "$file"
done

