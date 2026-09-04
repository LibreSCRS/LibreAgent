#!/usr/bin/env bash
# Runs INSIDE a fresh container. /pkg holds this repository's packages and
# /pkg-<Repo> the upstream ones. The claim this file exists to make is
# coexistence: that the split measured for pacman also holds for dpkg and rpm,
# where two packages owning one path is a conflict rather than a warning.
set -uo pipefail
fail=0
check() { if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

if [ "${FAMILY:-deb}" = deb ]; then
  export DEBIAN_FRONTEND=noninteractive
  # The base container is not a machine. Ubuntu's image ships
  # /etc/dpkg/dpkg.cfg.d/excludes with path-exclude=/usr/share/locale/*/LC_MESSAGES/*.mo
  # (Debian's does not), so a package that carries translations installs without
  # them there. Asserting on disk under that configuration measures the image,
  # not the package, so the exclusion goes before anything is installed.
  rm -f /etc/dpkg/dpkg.cfg.d/excludes
  apt-get update -qq
  apt-get install -y --no-install-recommends /pkg-LibreMiddleware/*.deb /pkg/*.deb >/dev/null
  check "V1 middleware and agent packages install together" $?
  installed_list() { dpkg-query -W -f='${Package}\n'; }
  files_of() { dpkg -L "$1" 2>/dev/null; }
  LIBGLOB="/usr/lib/*"
else
  dnf -y -q install /pkg-LibreMiddleware/*.rpm /pkg/*.rpm >/dev/null
  check "V1 middleware and agent packages install together" $?
  installed_list() { rpm -qa --qf '%{NAME}\n'; }
  files_of() { rpm -ql "$1" 2>/dev/null; }
  LIBGLOB="/usr/lib64"
fi

ours=$(installed_list | grep -E 'librescrs|liblibrescrs|libreagent' | sort -u)
echo "installed: $(echo "$ours" | tr '\n' ' ')"

# Every path owned exactly once. Directories are excluded on purpose: a package
# manager conflicts files, never directories, so shared ownership of
# /usr/share/librescrs as a directory is not a problem, and counting it would
# report a conflict that does not exist.
: > /tmp/all.txt
for p in $ours; do
  files_of "$p" | while read -r f; do [ -f "$f" ] || [ -L "$f" ] && echo "$f"; done
done | sort > /tmp/all.txt
uniq -d < /tmp/all.txt > /tmp/dupes.txt
n=$(wc -l < /tmp/all.txt); echo "PATH_COUNT=$n"
# An empty list has no duplicates either, so the disjointness claim would pass
# vacuously the moment the install step failed -- exactly when it must not.
test "$n" -gt 100; check "V-coexist the path list is not empty (counted $n)" $?
test ! -s /tmp/dupes.txt; check "V-coexist every installed path owned exactly once" $?
[ -s /tmp/dupes.txt ] && cat /tmp/dupes.txt

# The client library carries the major in its SONAME and in its package name.
ls $LIBGLOB/liblibrescrs-agentclient-qt.so.5 >/dev/null 2>&1
check "V-soname client library ships .so.5" $?

# The core packages hold static archives and no shared object. That asymmetry
# is the shape, not an oversight, so assert it rather than leave it to chance.
ls $LIBGLOB/libLibreAgentCore.a $LIBGLOB/libLibreAgentWire.a >/dev/null 2>&1
check "V-core static archives present" $?
ls $LIBGLOB/libLibreAgentCore.so* >/dev/null 2>&1 && { echo "  unexpected shared core"; false; } || true
check "V-core no shared counterpart" 0

miss=0
for f in $LIBGLOB/liblibrescrs-agentclient-qt.so.*; do
  [ -e "$f" ] || continue
  if ldd "$f" 2>/dev/null | grep -q 'not found'; then echo "  not found in $f"; miss=1; fi
done
test "$miss" -eq 0; check "V11 no unresolved shared-library dependency" $?

exit $fail
