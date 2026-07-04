#!/bin/sh
set -eu
cd "$(dirname "$0")"
while IFS=$(printf '\t') read -r name version url sha; do
  [ -n "$name" ] || continue
  [ -f "$name.zip" ] || curl -fsSL "$url" -o "$name.zip"
  echo "$sha  $name.zip" | sha256sum -c -
done < manifest.tsv
