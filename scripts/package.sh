#!/usr/bin/env bash
# Builds release artifacts into dist/. Needs: cargo-xwin, Homebrew llvm, Docker.
# Usage: scripts/package.sh [windows] [macos] [linux]   (default: all)
set -euo pipefail
cd "$(dirname "$0")/.."
TARGETS=("$@"); [ ${#TARGETS[@]} = 0 ] && TARGETS=(windows macos linux)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
mkdir -p dist

notices() { # destination directory
  cp assets/fonts/OFL-LICENSE.txt "$1/NotoSansSC-OFL.txt"
  cp vendor/wintun/LICENSE.txt "$1/Wintun-LICENSE.txt"
}

windows() {
  # lld-link embeds the UAC manifest through a tool named mt.exe.
  local llvm; llvm=$(brew --prefix llvm)/bin
  mkdir -p target/mt-shim
  ln -sf "$llvm/llvm-mt" target/mt-shim/mt.exe
  for pair in "x86_64-pc-windows-msvc:x64" "aarch64-pc-windows-msvc:arm64"; do
    local target=${pair%%:*} arch=${pair##*:}
    # ring's arm64 assembly is built with plain clang, which needs xwin's clang flags.
    local cross=clang-cl; [ "$arch" = arm64 ] && cross=clang
    XWIN_CROSS_COMPILER=$cross PATH="$PWD/target/mt-shim:$llvm:$PATH" cargo xwin build --release --features gui --target "$target"
    cp "target/$target/release/varco.exe" "dist/varco-$VERSION-windows-$arch.exe"
  done
}

macos() {
  for pair in "aarch64-apple-darwin:arm64" "x86_64-apple-darwin:x64"; do
    local target=${pair%%:*} arch=${pair##*:}
    cargo build --release --features gui --target "$target"
    local app="dist/varco-$VERSION-macos-$arch/varco.app"
    rm -rf "dist/varco-$VERSION-macos-$arch"
    mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
    cp "target/$target/release/varco" "$app/Contents/MacOS/varco"
    sed "s/@VERSION@/${VERSION%%-*}/" deploy/Info.plist > "$app/Contents/Info.plist"
    notices "$app/Contents/Resources"
    # Ad-hoc signature: Apple Silicon refuses to run unsigned code at all.
    codesign --force --deep --sign - "$app"
    (cd "dist/varco-$VERSION-macos-$arch" && zip -qry "../varco-$VERSION-macos-$arch.zip" varco.app)
    rm -rf "dist/varco-$VERSION-macos-$arch"
  done
}

linux() {
  # Static, no GUI: the server, and the client on headless machines.
  for pair in "linux/amd64:x86_64-unknown-linux-musl:x64" "linux/arm64:aarch64-unknown-linux-musl:arm64"; do
    IFS=: read -r platform target arch <<<"$pair"
    docker run --rm --platform "$platform" -v "$PWD:/src" -w /src \
      -v "varco-cargo-$arch:/usr/local/cargo/registry" -e "CARGO_TARGET_DIR=/src/target/docker-$arch" \
      rust:1-alpine sh -c "apk add -q musl-dev && cargo build --locked --release --target $target"
    cp "target/docker-$arch/$target/release/varco" "dist/varco-$VERSION-linux-$arch"
  done
}

for t in "${TARGETS[@]}"; do "$t"; done
ls -la dist
