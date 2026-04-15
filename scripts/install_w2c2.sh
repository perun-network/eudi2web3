set -e
BUILD_DIR=$(mktemp -d)
OUT=$PWD/target
trap 'rm -rf "$BUILD_DIR"' EXIT

git clone --recursive https://github.com/vivianjeng/w2c2 $BUILD_DIR
cd $BUILD_DIR

cmake -B build
cmake --build build

cp build/w2c2/w2c2 "$OUT/w2c2"
cp w2c2/w2c2_base.h "$OUT/w2c2_includes/w2c2_base.h"
# cp w2c2/*.h "$OUT/w2c2_includes/"

chmod u+x "$OUT/w2c2"

