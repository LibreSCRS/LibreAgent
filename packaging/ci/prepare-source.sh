#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs in a work copy, on the host, before any container starts. Places the
# fetch-time dependencies the release tarball carries, so the package build
# itself never reaches the network.
#
# The QCBOR pin is read from cmake/FetchQCBOR.cmake -- the same file the build
# would otherwise fetch with -- so the two cannot drift. FETCHCONTENT_SOURCE_DIR
# overrides GIT_TAG silently, and a drift would compile a different codec than
# the sources say.
set -euo pipefail

sha="$(awk '/GIT_TAG/{print $2; exit}' cmake/FetchQCBOR.cmake)"
[ -n "$sha" ] || { echo "prepare-source: cannot read the QCBOR pin" >&2; exit 1; }

mkdir -p thirdparty
rm -rf thirdparty/QCBOR

cache="${QCBOR_CACHE:-/var/tmp/p4b/cache/QCBOR}"
if [ -d "$cache/.git" ] && git -C "$cache" rev-parse HEAD | grep -q "^$sha"; then
  cp -a "$cache" thirdparty/QCBOR
else
  git clone --quiet https://github.com/laurencelundblade/QCBOR.git thirdparty/QCBOR
  git -C thirdparty/QCBOR checkout --quiet "$sha"
fi
rm -rf thirdparty/QCBOR/.git
test -f thirdparty/QCBOR/CMakeLists.txt
echo "prepare-source: QCBOR staged at $sha"
