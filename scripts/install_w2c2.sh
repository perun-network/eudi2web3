set -e
BUILD_DIR=$(mktemp -d)
OUT=$PWD/target
trap 'rm -rf "$BUILD_DIR"' EXIT

cd $BUILD_DIR
if [ -z "$W2C2_REV" ]; then
    git clone --recursive https://github.com/vivianjeng/w2c2 .
else
    git init
    git remote add origin https://github.com/vivianjeng/w2c2
    git fetch --depth 1 origin "$W2C2_REV"
    git checkout FETCH_HEAD
    git submodule update --init --depth 1
fi

cmake -B build
cmake --build build

cp build/w2c2/w2c2 "$OUT/w2c2"
cp w2c2/w2c2_base.h "$OUT/w2c2_includes/w2c2_base.h"
# cp w2c2/*.h "$OUT/w2c2_includes/"

chmod u+x "$OUT/w2c2"

