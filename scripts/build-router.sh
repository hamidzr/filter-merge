#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-"$project_dir/target"}
export CARGO_TARGET_DIR="$target_dir"
mkdir -p "$target_dir/toolchain"

# use installed Rust sources and Zig's musl toolchain without changing shell setup
command -v cargo >/dev/null
if [[ ! -x "$target_dir/toolchain/zig/zig" ]]; then
  [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || {
    echo 'this toolchain bootstrap supports macOS ARM64' >&2
    exit 1
  }
  archive="$target_dir/toolchain/zig-0.15.2.tar.xz"
  curl -fL --retry 2 --max-time 120 \
    https://ziglang.org/download/0.15.2/zig-aarch64-macos-0.15.2.tar.xz -o "$archive"
  echo "3cc2bab367e185cdfb27501c4b30b1b0653c28d9f73df8dc91488e66ece5fa6b  $archive" | shasum -a 256 -c -
  tar -xJf "$archive" -C "$target_dir/toolchain"
  mv "$target_dir/toolchain/zig-aarch64-macos-0.15.2" "$target_dir/toolchain/zig"
  rm "$archive"
fi
cat >"$target_dir/toolchain/zig-cc" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/zig/zig" cc -target aarch64-linux-musl "$@"
EOF
cat >"$target_dir/toolchain/zig-ar" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/zig/zig" ar "$@"
EOF
chmod 755 "$target_dir/toolchain/zig-cc" "$target_dir/toolchain/zig-ar"
# prime musl archives, then let LLD accept Rust's ARM erratum flag
"$target_dir/toolchain/zig/zig" c++ -target aarch64-linux-musl -static -O2 -v \
  -x c++ - -o "$target_dir/toolchain/probe" 2>"$target_dir/toolchain/probe-link.txt" <<'EOF'
int main(void) { return 0; }
EOF
cp "$project_dir/scripts/zig-linker.py" "$target_dir/toolchain/zig-linker.py"
chmod 755 "$target_dir/toolchain/zig-linker.py"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$target_dir/toolchain/zig-linker.py"
export CC_aarch64_unknown_linux_musl="$target_dir/toolchain/zig-cc"
export AR_aarch64_unknown_linux_musl="$target_dir/toolchain/zig-ar"

cd "$project_dir"
if rustc --print target-libdir --target aarch64-unknown-linux-musl | xargs test -d; then
  cargo build --locked --release --target aarch64-unknown-linux-musl
else
  # Homebrew Rust includes rust-src but no Linux standard library
  RUSTC_BOOTSTRAP=1 cargo build --locked --release --target aarch64-unknown-linux-musl \
    -Z build-std=std,panic_abort -Z build-std-features=optimize_for_size
fi
file "$target_dir/aarch64-unknown-linux-musl/release/filter-merge"
ls -lh "$target_dir/aarch64-unknown-linux-musl/release/filter-merge"
