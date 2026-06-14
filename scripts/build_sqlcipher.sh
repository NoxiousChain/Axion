#!/bin/bash
# Build SQLCipher from source into vendor/sqlcipher/ using Apple CommonCrypto.
# No Homebrew or system package manager required.
# Usage: bash scripts/build_sqlcipher.sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor/sqlcipher"
VERSION="4.6.1"
TARBALL="/tmp/sqlcipher-${VERSION}.tar.gz"
SRC="/tmp/sqlcipher-${VERSION}"

echo "==> Building SQLCipher $VERSION into $VENDOR"

# Download source if not already present
if [ ! -f "$TARBALL" ]; then
  echo "Downloading SQLCipher $VERSION..."
  curl -fsSL "https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v${VERSION}.tar.gz" \
    -o "$TARBALL"
fi

# Extract
rm -rf "$SRC"
tar xzf "$TARBALL" -C /tmp

SDK=$(xcrun --show-sdk-path)
CC=$(xcrun -f clang)

cd "$SRC"
./configure \
  CC="$CC" \
  CFLAGS="-isysroot $SDK -DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2" \
  LDFLAGS="-isysroot $SDK -framework Security -framework Foundation" \
  --enable-tempstore=yes \
  --with-crypto-lib=commoncrypto \
  --prefix="$VENDOR"

make -j"$(sysctl -n hw.logicalcpu)"
make install

echo ""
echo "==> SQLCipher built at $VENDOR"
echo ""
echo "Now install the Python binding:"
echo "  source venv/bin/activate"
echo "  CPATH=\"$VENDOR/include\" LIBRARY_PATH=\"$VENDOR/lib\" pip install sqlcipher3==0.5.3"
