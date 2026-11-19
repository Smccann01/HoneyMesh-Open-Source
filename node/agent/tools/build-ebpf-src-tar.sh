#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

version_line="$(rg -n 'const Version = ' "$ROOT_DIR/main.go" | head -n 1 || true)"
if [[ -z "$version_line" ]]; then
  echo "ERROR: unable to determine version from main.go" >&2
  exit 1
fi

VERSION="$(printf "%s" "$version_line" | sed -E 's/.*const Version = "([^"]+)".*/\1/')"
if [[ -z "$VERSION" ]]; then
  echo "ERROR: version parsed empty" >&2
  exit 1
fi

OUTDIR="${OUTDIR:-$ROOT_DIR/dist}"
OUTNAME="honeymesh-ebpf-src-${VERSION}.tar.gz"
TMPDIR="$(mktemp -d)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct -- . 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

mkdir -p "$OUTDIR"
mkdir -p "$TMPDIR/honeymesh-${VERSION}/bpf/src"

shopt -s nullglob
c_files=("$ROOT_DIR/bpf/"*.c)
if [[ ${#c_files[@]} -eq 0 ]]; then
  echo "ERROR: no .c files found under $ROOT_DIR/bpf" >&2
  rm -rf "$TMPDIR"
  exit 1
fi

cp "$ROOT_DIR/bpf/LICENSE" "$TMPDIR/honeymesh-${VERSION}/bpf/"
cp "${c_files[@]}" "$TMPDIR/honeymesh-${VERSION}/bpf/src/"

# Keep ordering, ownership and timestamps stable across build directories.
( cd "$TMPDIR" && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - "honeymesh-${VERSION}" | gzip -n > "$OUTDIR/$OUTNAME" )

rm -rf "$TMPDIR"

echo "Wrote: $OUTDIR/$OUTNAME"
