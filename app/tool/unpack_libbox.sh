#!/usr/bin/env bash
#
# Unpack Libbox.xcframework where the extension target links it from.
#
# One definition, two callers -- the `ios` and `ios_project` jobs in
# .github/workflows/app.yml -- for the reason scripts/check.sh is the single
# definition of validity: an assertion that exists twice is an assertion that
# drifts, and both checks below are load-bearing. The build steps around it are
# deliberately spelled out in each job, because one builds the committed project
# and the other builds the generated one and that difference must stay visible.
set -euo pipefail

app="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The path FRAMEWORK_SEARCH_PATHS names and the path the file reference in
# Runner.xcodeproj resolves to. Both come from tool/ios_project.rb; this is the
# third spelling and the one that puts the bytes there.
dir="$app/packages/singbox_tunnel/ios/Frameworks"
tarball="$dir/Libbox.xcframework.tar.gz"

[ -f "$tarball" ] || {
  echo "error: no $tarball" >&2
  echo "The libbox_apple job's artifact did not land in $dir." >&2
  exit 1
}

tar -xzf "$tarball" -C "$dir"
rm -f "$tarball"

# An .xcframework IS its root Info.plist: that file is what lists the available
# libraries, so a directory without one is not one. Checked here as well as in
# libbox_apple, because a truncated download is a different failure from a
# truncated build and only one of them is that job's.
test -s "$dir/Libbox.xcframework/Info.plist"

# Every Libbox.framework inside is in the VERSIONED layout: a real Versions/A,
# with Current, Headers, Modules and the binary as symlinks into it (gomobile
# bind_iosapp.go:194-205 and :285). Zero symlinks means the artifact round trip
# flattened the bundle, which is silent -- the directory still looks like a
# framework, and Xcode rejects it much later and says something else.
links=$(find "$dir/Libbox.xcframework" -type l | wc -l)
[ "$links" -gt 0 ] || {
  echo "error: no symlinks under $dir/Libbox.xcframework -- the bundle was flattened in transit" >&2
  exit 1
}
echo "$links symlinks intact"

# The slice directories are gomobile's to choose. Print them rather than pin them.
ls "$dir/Libbox.xcframework"
