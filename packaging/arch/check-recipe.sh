#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-recipe.sh
#
# The Arch recipe must build THIS project's signed release tag, and must say
# true things about it. Every arm prints what it measured, because a silent
# pass is a vacuum and not a pass.
#
#   1  source= holds exactly one entry for this project's own source, and it is
#      git+https://github.com/LibreSCRS/<this repository>.git#tag=$pkgver?signed
#      -- this repository, the unprefixed tag every release in this stack
#      carries, and makepkg's signature check switched on. GitHub's
#      auto-generated archive/refs/tags tarball is refused: its bytes are not
#      ours to assert and nothing signs them.
#   2  pkgver equals the first line of VERSION, and so does the RPM spec's
#      Version:. pkgver only labels the package; the installed CMake version
#      file is generated from VERSION, so a bump that misses one of them ships
#      a package whose own metadata disagrees.
#   3  every submodule gitlink is pinned verbatim in the recipe; and a
#      FetchContent pin carried by the recipe equals the pin in the cmake module
#      the build would otherwise fetch with.
#   4  the trust the recipe declares: validpgpkeys is exactly the primary key
#      of this repository's KEYS file, the signed source's checksum is SKIP (a
#      VCS source has none; makepkg refuses anything else), and every other
#      source -- an upstream archive at a fixed commit -- carries a real
#      sha256. This holds before the tag exists and after it, so the release
#      needs no follow-up edit of the recipe and there is no arm that waits
#      for a tag.
#
# Threat model. This reads the recipe as TEXT rather than sourcing it, so it
# guards against the honest regression: someone edits source=, bumps a version
# or refreshes a pin in the shapes this repository actually writes, and gets one
# of them wrong. It does not resist a recipe written to conceal intent: a URL
# assembled from variables other than $pkgver/$_srcname, an architecture array
# (source_x86_64=()) instead of source=, a source=( or its closing ) not at
# column 0, a pin that appears in the recipe only inside a comment. Code
# review, not this gate, is what catches a recipe written to mislead.
#
# Exit codes: 0 green, 1 an arm failed, 2 cannot judge (no recipe, no gpg to
# read KEYS).
set -u

[ "$#" -eq 0 ] || { echo "usage: check-recipe.sh" >&2; exit 2; }

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
recipe="$here/PKGBUILD"

rc=0
note() { printf '%-6s %s\n' "$1" "$2"; }
bad()  { note FAIL "$1"; rc=1; }

[ -f "$recipe" ] || { note FAIL "no PKGBUILD next to this script ($recipe)"; exit 2; }

pkgver=$(sed -nE 's/^pkgver=([^[:space:]#]+).*/\1/p' "$recipe" | head -1)
[ -n "$pkgver" ] || bad "no pkgver= in $recipe"

# --- arm 1 -----------------------------------------------------------------
reponame=$(basename "$root")
block=$(sed -n '/^source=(/,/^)/p' "$recipe")
own_url="git+https://github.com/LibreSCRS/$reponame.git#tag="
if [ -z "$block" ]; then
  bad "arm1: no 'source=(' ... ')' array in the recipe -- the pattern matches nothing, which is a vacuum and not a pass"
else
  mapfile -t entries < <(printf '%s\n' "$block" | sed -e '1d' -e '$d' \
                          | grep -vE '^[[:space:]]*(#|$)')
  n=${#entries[@]}
  own=0
  if [ "$n" -eq 0 ]; then
    bad "arm1: the source=() array holds no entries"
  fi
  for e in "${entries[@]}"; do
    url=${e##*::}; url=${url%\"}; url=${url#\"}
    case "$url" in
      *archive/refs/tags*)
        bad "arm1: fetches GitHub's auto-generated archive, whose bytes this project does not produce and nothing signs: $url" ;;
    esac
    case "$url" in
      *github.com/LibreSCRS/*)
        rest=${url#*github.com/LibreSCRS/}
        erepo=${rest%%[/.#]*}
        [ "$erepo" = "$reponame" ] || { bad "arm1: fetches LibreSCRS/$erepo while this repository is $reponame -- a recipe copied between siblings builds the other one's sources"; continue; }
        own=$((own + 1))
        case "$url" in
          "${own_url}\$pkgver?signed"|"${own_url}\${pkgver}?signed") : ;;
          *'#tag=v'*) bad "arm1: asks for a v-prefixed tag; every tag this project publishes is unprefixed: $url" ;;
          *'#tag='*) case "$url" in
                       *'?signed') bad "arm1: the tag is not \$pkgver: $url" ;;
                       *) bad "arm1: the tag is fetched without ?signed, so makepkg never checks its signature: $url" ;;
                     esac ;;
          git+*) bad "arm1: fetches a branch or commit, not the release tag: $url" ;;
          *) bad "arm1: fetches something other than the signed release tag ($url); the recipe builds ${own_url}\$pkgver?signed" ;;
        esac ;;
    esac
  done
  printf 'arm1: %d source entr%s, %d for this repository\n' \
    "$n" "$([ "$n" -eq 1 ] && echo y || echo ies)" "$own"
  [ "$own" -eq 1 ] || bad "arm1: expected exactly one source entry for LibreSCRS/$reponame, found $own"
fi

# --- arm 2 -----------------------------------------------------------------
vf="$root/VERSION"
if [ ! -f "$vf" ]; then
  bad "arm2: $vf is missing -- pkgver cannot be shown to agree with anything"
else
  declared=$(sed -n '1p' "$vf" | tr -d '[:space:]'); declared=${declared#v}
  if [ -z "$declared" ]; then
    bad "arm2: first line of VERSION is empty"
  elif [ "$declared" != "$pkgver" ]; then
    bad "arm2: version drift -- VERSION says $declared, the recipe says pkgver=$pkgver"
  else
    printf 'arm2: pkgver=%s equals the first line of VERSION\n' "$pkgver"
  fi
fi

spec="$root/packaging/rpm/libreagent.spec"
if [ ! -f "$spec" ]; then
  printf 'arm2c: no packaging/rpm/libreagent.spec -- nothing to compare against VERSION\n'
else
  specver=$(sed -nE 's/^Version:[[:space:]]+([^[:space:]]+).*/\1/p' "$spec" | head -1)
  if [ -z "$specver" ]; then
    bad "arm2c: no 'Version:' line in $spec"
  elif [ "$specver" != "$declared" ]; then
    bad "arm2c: version drift -- VERSION says $declared, $spec says Version: $specver"
  else
    printf 'arm2c: %s Version: %s matches VERSION\n' "$(basename "$spec")" "$specver"
  fi
fi

# --- arm 3 -----------------------------------------------------------------
# Read from the index, not from HEAD: the gate judges the tree it is run over.
gl=0; ok=0
while read -r mode sha _stage path; do
  [ "$mode" = 160000 ] || continue
  gl=$((gl + 1))
  if grep -q "$sha" "$recipe"; then ok=$((ok + 1))
  else bad "arm3: submodule $path is pinned at $sha, which appears nowhere in the recipe"; fi
done < <(git -C "$root" ls-files -s 2>/dev/null)
printf 'arm3: %d submodule gitlink(s), %d pinned in the recipe\n' "$gl" "$ok"

fm="$root/cmake/FetchQCBOR.cmake"
rp=$(sed -nE 's/^_qcbor_commit=([0-9a-f]{40}).*/\1/p' "$recipe" | head -1)
if [ -n "$rp" ] && [ ! -f "$fm" ]; then
  bad "arm3b: the recipe pins _qcbor_commit=$rp but $fm is missing -- nothing to keep it in lockstep with"
elif [ -n "$rp" ]; then
  mapfile -t decl < <(sed -nE 's/^[[:space:]]*GIT_TAG[[:space:]]+([0-9a-f]{40})[[:space:]]*$/\1/p' "$fm")
  if [ "${#decl[@]}" -ne 1 ]; then
    bad "arm3b: cmake/FetchQCBOR.cmake must hold exactly one 'GIT_TAG <40-hex>' line; found ${#decl[@]}"
  elif [ "${decl[0]}" != "$rp" ]; then
    bad "arm3b: QCBOR pin drift -- cmake says ${decl[0]}, the recipe says $rp"
  else
    printf 'arm3b: QCBOR pin %s matches cmake/FetchQCBOR.cmake\n' "$rp"
  fi
else
  printf 'arm3b: the recipe carries no _qcbor_commit -- nothing to keep in lockstep\n'
fi

# --- arm 4 -----------------------------------------------------------------
keys="$root/KEYS"
if ! command -v gpg >/dev/null 2>&1; then
  note FAIL "arm4: gpg is not on PATH -- the fingerprint in KEYS cannot be read"
  exit 2
fi
if [ ! -f "$keys" ]; then
  bad "arm4: $keys is missing -- the recipe's validpgpkeys cannot be shown to name the release key"
else
  gh_home=$(mktemp -d "${TMPDIR:-/var/tmp}/check-recipe-gpg.XXXXXX") || exit 2
  primaries=$(GNUPGHOME="$gh_home" gpg --batch --show-keys --with-colons "$keys" 2>/dev/null \
              | awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }' \
              | sort -u)
  rm -rf "$gh_home"
  if [ -z "$primaries" ]; then
    bad "arm4: no primary key could be read out of KEYS"
  else
    declared=$(sed -n '/^validpgpkeys=(/,/)/p' "$recipe" | sed 's/#.*//' \
               | grep -oE "'[^']*'|\"[^\"]*\"" | tr -d "'\"" | sort -u)
    if [ -z "$declared" ]; then
      bad "arm4: the recipe declares no validpgpkeys, so makepkg would trust any key it happens to have"
    elif [ "$declared" != "$primaries" ]; then
      bad "arm4: validpgpkeys ($(echo $declared)) is not the primary key of KEYS ($(echo $primaries))"
    else
      printf 'arm4: validpgpkeys is the primary key of KEYS (%s)\n' "$(echo $primaries)"
    fi
  fi
fi
mapfile -t vals < <(sed -n '/^sha256sums=(/,/)/p' "$recipe" | sed 's/#.*//' \
                    | grep -oE "'[^']*'|\"[^\"]*\"" | tr -d "'\"")
if [ "${#vals[@]}" -eq 0 ]; then
  bad "arm4: no sha256sums entries found -- the pattern matches nothing, which is a vacuum and not a pass"
elif [ "${#vals[@]}" -ne "${n:-0}" ]; then
  bad "arm4: ${#vals[@]} sha256sums entr$([ "${#vals[@]}" -eq 1 ] && echo y || echo ies) for ${n:-0} sources -- makepkg pairs them by position"
else
  k=0 n_bad=0
  for e in "${entries[@]}"; do
    v=${vals[$k]}; k=$((k + 1))
    case "$e" in
      *'::git+'*|git+*)
        [ "$v" = SKIP ] || { bad "arm4: source $k is a VCS source, whose checksum makepkg requires to be SKIP, not '$v'"; n_bad=$((n_bad + 1)); } ;;
      *)
        if [ "${#v}" -ne 64 ] || [ -n "${v//[0-9a-f]/}" ]; then
          bad "arm4: source $k is an archive at a fixed revision and carries '$v', not a sha256 -- its bytes exist, so its sum can be written now"
          n_bad=$((n_bad + 1))
        fi ;;
    esac
  done
  [ "$n_bad" -ne 0 ] || printf 'arm4: %d sha256sums entr%s, SKIP only for the signed tag\n' \
    "${#vals[@]}" "$([ "${#vals[@]}" -eq 1 ] && echo y || echo ies)"
fi

echo "check-recipe: $([ $rc -eq 0 ] && echo GREEN || echo RED)"
exit "$rc"
