set -e
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

R1CS_FILE=$1
OUT=$2
BASE=$(dirname "$R1CS_FILE")
CURVE=$(basename "$BASE")
CURVE=${CURVE//[_.-]/}
CIRCUIT=$(basename "$R1CS_FILE")
CIRCUIT=${CIRCUIT%.*}
CIRCUIT_SANITIZED=${CIRCUIT//[_.-]/}
WASM="$BASE/${CIRCUIT}_js/${CIRCUIT}.wasm"
WASM_RENAMED="$BUILD_DIR/${CURVE}${CIRCUIT_SANITIZED}.wasm"

# w2c2 takes the filename and uses it for prefixing.
# We want the prefix to include the curve, so we create a copy of the wasm file.
cp "$WASM" "$WASM_RENAMED"

# p: Pretty formatting, m: function prefixes, f 1: One file per function.
# rust-witness uses -f 1 to separate the files and remove some code (motly static data).
# I've decided to try kepeing that in for simplicity => no -f 1.
target/w2c2 -pm "$WASM_RENAMED" "$OUT"

# make the data constants static to prevent duplicate symbol errors.
sed -e "s/const U8 d/static const U8 d/g" -i "$OUT"

# Append circuit specific code that improves debugging and logging.
# Unfortunately the prefix cannot contain "_" if done via wasm renaming.
sed -e "s/XXXX/${CURVE}$CIRCUIT_SANITIZED/g; s/YYYY/${CURVE}$CIRCUIT/g" \
    templates/w2c2_circuit_specific.c \
    >> "$OUT"

