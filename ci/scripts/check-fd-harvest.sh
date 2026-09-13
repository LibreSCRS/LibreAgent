#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-fd-harvest.sh — the SCM_RIGHTS vocabulary lives in one file.
#
# cmsg_len describes what the SENDER attached. On a truncated control message
# XNU keeps reporting that number while msg_controllen shrinks to what actually
# arrived (bsd/kern/uipc_syscalls.c, copyout_control: the cmsg header is copied
# out verbatim, only *controllen is corrected), so `cmsg_len - CMSG_LEN(0)`
# walks off the receiver's stack buffer and every int past the end is handed to
# fcntl() and then owned. Linux hides this (scm_detach_fds rewrites cmsg_len to
# what it delivered), which is why no Linux runtime test can see it and why this
# is a source-shape gate.
#
# What this measures is STRUCTURE, not spelling.
#
#   Rule 1. Exactly ONE read of cmsg_len in the helper -- src/wire/FdHarvest.h,
#           plus src/wire/FdHarvest.cpp when the helper is split. That read is
#           the clamp. Zero means the clamp is gone; two means somebody computes
#           a second length beside it. Reads are counted as OCCURRENCES, not as
#           lines or statements that contain one, so putting the second read on
#           the clamp's own line does not hide it.
#
#   Rule 2. In every production source -- every tracked file this repository
#           compiles that is not under one of the test roots below -- none of
#           the ancillary-message vocabulary may appear at all, except in the
#           helper: recvmsg, recvmmsg, SYS_recvmsg, sendmsg, sendmmsg, msghdr,
#           cmsghdr, CMSG_FIRSTHDR, CMSG_NXTHDR, CMSG_DATA, CMSG_LEN,
#           CMSG_SPACE, SCM_RIGHTS, msg_control, msg_controllen, cmsg_len,
#           cmsg_level, cmsg_type.
#
#   Rule 3. A production source outside the helper may not spell those names by
#           TOKEN PASTING: no `##` (or `%:%:`), and no call to a macro that this
#           tree defines with one. `CAT(msg, hdr)` types no banned name and
#           expands to one, so a rule that only reads the source text is a
#           spelling rule again unless the paste route is closed with it.
#
#   Rule 4. The helper's own shape is pinned: one receive walk and one send
#           assembly, one recvmsg and one sendmsg. Rule 2 is silent inside the
#           helper by construction and rule 1 counts only reads, so a SECOND
#           walk in there -- one that takes its count from what the peer
#           announced and never reads cmsg_len at all -- would move neither.
#           It moves this one, again by occurrence and not by line.
#           Changing the helper's shape on purpose means changing the expected
#           counts here, in the same commit, on purpose.
#
#   Rule 5. Nothing under a test root is named by a CMake file outside the test
#           roots. The rule-2 exemption for tests is keyed on the PATH, so a
#           translation unit parked under a test root and listed in a production
#           target's source list would ship inside the library with the
#           vocabulary rule silent. A .cpp needs no #include to be compiled, so
#           only its build-system reference can give it away.
#
# Rule 2 replaces three earlier attempts to tell a receive-side harvest from a
# send-side assembly by looking at what the code around it said or did -- first
# the token `sendmsg` anywhere in the region, then the three header assignments,
# then a statement-level write/read classification. Each was refuted the same
# way: a harvest was respelled until it no longer matched, passed with rc=0, and
# left the counter of measured loops unchanged, so the pass looked like the
# absence of a harvest rather than the amnesty it was. A classifier that has to
# recognise C++ statements will always lose that race. Confining the vocabulary
# is a much narrower claim -- to adopt a descriptor from a control message a
# caller must build a msghdr, ask the kernel to fill it and step through it --
# but it is a claim about NAMES, so it is only as good as the reading of the
# source that finds them, and as good as the SET of files it reads. Both have
# been wrong here before, and both are measured:
#
#   * a line continuation. `msg\<newline>hdr` is one token to the compiler and
#     two lines to a line-at-a-time reader, so continued lines are spliced
#     before anything else looks at them;
#   * a digit separator. `1'000` opens no character literal, but a reader that
#     assumes it does discards the rest of the line -- and this repository
#     writes `60'000ms`, so the shape is not hypothetical. A quote opens a
#     literal here only when one closes on the same line and the character
#     before it is not part of an identifier or number;
#   * a paste (rule 3);
#   * an extension nobody thought of. The file set used to come from a list of
#     C/C++ extensions, and a harvest in a tracked .c++, .cppm, .C, .inc or a
#     file with no extension at all was invisible to the walk AND to the git
#     cross-check that exists to catch a narrowed walk, because both were handed
#     that same list. The set is now the INVERSE: every tracked file is in scope
#     unless its extension is on the list of things this repository is known to
#     keep in a non-compiled form (below). An extension nobody thought of is
#     therefore scanned rather than skipped, and a `.cpp.in` template is scanned
#     as the .cpp it configures into.
#
# Both rules read the source with string literals and comments -- `//` AND
# `/* */` -- removed. A helper named in prose has not been called, and a
# subtraction parked in a block comment is a subtraction again the moment the
# comment markers move. So SCM_RIGHTS in a sentence is not a harvest.
#
# Threat model. This gate catches an honest regression: a change written in
# the shapes this codebase uses today -- CMSG_FIRSTHDR/CMSG_NXTHDR/CMSG_DATA,
# a subtraction against CMSG_LEN(0), a stray #include of a test header -- that
# forgets the clamp or lets a second, unmeasured harvest back into the tree. It
# reads source text with comments and literals stripped, so it cannot see
# intent and does not try to: a harvest that never spells the libc interface,
# that reaches the vocabulary through a macro this tree does not define, or
# that is built by hand inside the helper without calling any of the macros
# rule 4 counts is out of scope here and belongs to code review. Known doors,
# each measured on a git-archive copy:
#
#   * a second, unclamped walk built entirely inside the helper's own body
#     with hand-computed pointer arithmetic -- no CMSG_FIRSTHDR, CMSG_NXTHDR or
#     CMSG_DATA, and no second read of cmsg_len. Rule 1 counts only reads of
#     cmsg_len, rule 4 counts only the four named macros, and rule 2 is silent
#     inside the helper by construction, so none of the three moves and the
#     gate still prints the same OK line. Measured: a second adoption loop
#     added to receiveWithFds() that takes `msg.msg_control` as a raw
#     `std::uint8_t*`, walks it with a hard-coded offset instead of
#     CMSG_DATA(), and trusts a count it invents instead of reading cmsg_len,
#     leaves rc=0. Nothing here measures the helper's OWN body beyond the four
#     counted macros and the one counted read;
#   * a receive that never names the libc interface -- io_uring's
#     IORING_OP_RECVMSG rings, a raw syscall(SYS_recvmsg, ...) spelled with the
#     bare number 47, or inline assembly. `SYS_recvmsg` is banned as a token so
#     the ordinary spelling of that route is caught; the numeric one is not,
#     and neither is a ring. Nothing in this component uses either today, and
#     adding one would be a reviewable change of transport, not a respelling;
#   * a paste macro that comes from OUTSIDE this tree. Rule 3 derives the paste
#     macros it bans from this repository's own #define lines, so a macro
#     supplied by a third-party header could still assemble a banned name out
#     of fragments. Pulling one in for that purpose is, again, a visible change
#     and not a respelling of a loop;
#   * a file kept in one of the non-compiled forms below that is nonetheless
#     fed to the compiler. The list is short and every entry on it is a form
#     this repository actually uses for documentation, packaging or data;
#     moving code into one of them would show up as a build-system change.
#
# The test roots are deliberately outside rule 2: tests build msghdr/cmsghdr
# pairs by hand on purpose -- FdHarvestTest hand-forges the truncated control
# message Linux cannot produce, and tests/spike/ScmRightsSpikeTest.cpp
# reproduces the raw kernel behaviour -- and a rule that banned that would ban
# the falsification of the clamp itself. The roots are NAMED here rather than
# matched by directory name anywhere in the tree: a directory called tests/ in
# the middle of src/ used to inherit the exemption, which made
# src/wire/tests/Harvest.cpp a production translation unit the gate never
# opened. Each named root must exist, so deleting one is a red rather than a
# silently wider scope, and rule 5 covers what a path-keyed exemption cannot.
#
# Cost, because a gate that quietly becomes its job's whole runtime is a
# surprise nobody decided on: this scans every file in scope once, in one awk
# pass, and the selftest below repeats the whole gate on a fresh copy of the
# tree per case. On an 8-core desktop that is ~1,4 s for the gate and ~85 s for
# the selftest at 232 sources and 36 cases -- it was 5,9 s and 168 s when each
# file went through two awk processes, twice. The cost is the product of files
# and cases, so re-time it whenever BANNED, NON_SOURCE_EXTS or the case list
# grows, and keep it inside the format-check job's timeout with room to spare.
#
# Usage:   ci/scripts/check-fd-harvest.sh [repo-root]
# Exit:    0 = the vocabulary is confined and the clamp is read exactly once
#          1 = a banned name outside the helper, a paste that could spell one,
#              the wrong number of reads, or a helper that changed shape
#          2 = this gate could not run (bad root, no scratch space): NOT a red,
#              and a harness that records rc must not read it as one
set -uo pipefail
export LC_ALL=C

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
HELPER="src/wire/FdHarvest.h"
HELPER_SPLIT="src/wire/FdHarvest.cpp"

# Upstream OASIS PKCS#11 headers, imported verbatim. They define __PASTE, which
# is why rule 3's ban on the paste operator itself cannot apply to them; the ban
# on CALLING a paste macro from another file still does, so nothing outside this
# directory can use what it defines.
VENDORED_RE='^include/LibreSCRS/Agent/pkcs11/oasis/'

# The exemption of rule 2, by explicit path. Not "any directory called tests".
TEST_ROOTS=(tests client/qt/tests)

# The forms this repository keeps that the compiler never sees. Everything else
# is scanned, so a C++ extension nobody listed fails loudly instead of vanishing.
# `.in` and `.template` are peeled off first: Foo.cpp.in configures into a .cpp.
NON_SOURCE_EXTS=(
    md markdown rst adoc txt text log
    yml yaml json json5 toml ini cfg conf desktop service policy
    cmake sh bash zsh py pl rb awk sed
    html htm css js jsx ts tsx map
    png jpg jpeg gif ico svg pdf bin dat
    tsv csv cddl spec publicapi files install symbols in
    patch diff lock qrc ui qm mo po pot
    gitignore gitattributes clang-format clang-tidy editorconfig
)

BANNED=(
    recvmsg recvmmsg SYS_recvmsg sendmsg sendmmsg
    msghdr cmsghdr
    CMSG_FIRSTHDR CMSG_NXTHDR CMSG_DATA CMSG_LEN CMSG_SPACE
    SCM_RIGHTS
    msg_control msg_controllen
    cmsg_len cmsg_level cmsg_type
)

# The helper's pinned shape (rule 4), measured on the stripped source.
declare -A HELPER_SHAPE=(
    [CMSG_FIRSTHDR]=2   # one receive walk, one send assembly
    [CMSG_NXTHDR]=1     # the receive walk is the only iteration
    [recvmsg]=1
    [sendmsg]=1
)

if ! cd "$ROOT" 2>/dev/null; then
    echo "FAIL: cannot enter '$ROOT' -- this gate did not run, and this is not a red." >&2
    exit 2
fi
fail=0

STRIPDIR="$(mktemp -d "${TMPDIR:-/var/tmp}/fdharvest.XXXXXX")" || {
    echo "FAIL: no scratch directory -- this gate did not run." >&2
    exit 2
}
trap 'rm -rf "$STRIPDIR"' EXIT

# --- scope --------------------------------------------------------------------
# Build and install trees are pruned by directory name, because they are
# generated copies of what is already measured here. When the tree is a
# checkout, git knows the truth and the two are compared below.
walk() { printf '%s\n' "$WALKED"; }

walk_uncached() {
    find . \
        \( -name .git -o -name '_deps' -o -name 'build' -o -name 'build-*' \
           -o -name 'install-*' -o -name '.qtcreator' \) -prune -o \
        -type f -print |
        sed 's|^\./||'
}

# Drop the forms the compiler never sees. Reads paths, writes paths.
compiled_only() {
    awk -v deny="${NON_SOURCE_EXTS[*]}" '
    BEGIN { n = split(deny, D, " "); for (i = 1; i <= n; i++) deny_[tolower(D[i])] = 1 }
    {
        base = $0
        sub(/.*\//, "", base)
        if (base ~ /^\./) next                       # .clang-format and friends
        while (base ~ /\.(in|template)$/) { sub(/\.(in|template)$/, "", base) }
        if (base ~ /\./) {
            ext = base
            sub(/.*\./, "", ext)
            if (tolower(ext) in deny_) next
        }
        print
    }'
}

WALKED="$(walk_uncached)"

TEST_ROOT_RE="^($(IFS='|'; printf '%s' "${TEST_ROOTS[*]}"))/"

production_only() { grep -v -E "$TEST_ROOT_RE"; }

mapfile -t sources < <(walk | compiled_only | production_only | sort)
mapfile -t everything < <(walk | compiled_only | sort)

for root in "${TEST_ROOTS[@]}"; do
    if [[ ! -d "$root" ]]; then
        echo "FAIL: the test root '$root' does not exist." >&2
        echo "      Rule 2 exempts exactly these paths; a root that moved without this" >&2
        echo "      list moving with it either exempts nothing or exempts the wrong tree." >&2
        fail=1
    fi
done

if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    missed="$(comm -13 \
        <(printf '%s\n' "${sources[@]}") \
        <(git -C "$ROOT" ls-files | compiled_only | production_only | sort))"
    if [[ -n "$missed" ]]; then
        echo "FAIL: tracked production sources the scan did not reach:" >&2
        printf '%s\n' "$missed" | sed 's/^/        /' >&2
        echo "      Widen walk() -- a pruned directory is an unmeasured one." >&2
        fail=1
    fi
fi

# The scope may not collapse to the one file the ban exempts: a walk that
# reached nothing but the helper would report the vocabulary confined to it and
# mean nothing by it.
scanned=0
for f in "${sources[@]}"; do
    [[ "$f" == "$HELPER" || "$f" == "$HELPER_SPLIT" ]] && continue
    scanned=$((scanned + 1))
done
if [[ $scanned -eq 0 ]]; then
    echo "FAIL: the scan reached no production source outside the helper;" >&2
    echo "      this gate cannot pass vacuously -- check the scope." >&2
    exit 1
fi
if [[ ! -f "$HELPER" ]]; then
    echo "FAIL: $HELPER does not exist, so there is nothing this gate confines" >&2
    echo "      the SCM_RIGHTS vocabulary TO." >&2
    exit 1
fi

helpers=("$HELPER")
[[ -f "$HELPER_SPLIT" ]] && helpers+=("$HELPER_SPLIT")

is_helper() {
    local f="$1" h
    for h in "${helpers[@]}"; do
        [[ "$f" == "$h" ]] && return 0
    done
    return 1
}

# --- stripping ----------------------------------------------------------------
# Every file in scope is stripped ONCE, in a single pass, into $STRIPDIR: the
# continued lines spliced, then string literals, character literals, // comments
# and /* */ comments removed. One output line per input line, so line numbers
# survive: a spliced statement is reported at its LAST line. (One pass because
# two awk processes per file, over every file, twice, made this gate the longest
# step of its CI job by two orders of magnitude.)
stripped_path() {
    local p="$1"
    printf '%s/%s' "$STRIPDIR" "${p//\//%}"
}

strip_all() {
    local f
    for f in "$@"; do
        : > "$(stripped_path "$f")" || return 1
    done
    awk -v out="$STRIPDIR" '
    function identish(c) { return (c ~ /[A-Za-z0-9_]/) }
    # Where does the literal opened by q at position i close, on this line?
    # 0 when it does not -- and a quote that closes nothing is not a literal: an
    # apostrophe between digits is a separator, and reading it as an opener used
    # to discard every banned name after it on the line.
    function closes(s, i, q, n,   j, c) {
        j = i + 1
        while (j <= n) {
            c = substr(s, j, 1)
            if (c == "\\") { j += 2; continue }
            if (c == q) return j
            j++
        }
        return 0
    }
    function stripline(s,   n, o, i, ch, two, prev, end) {
        # Nothing on this line can open a literal or a comment, and no block
        # comment is open: the line is already stripped.
        if (!inblock && s !~ /["'"'"'\/*]/) { return s }
        n = length(s); o = ""; i = 1
        while (i <= n) {
            ch = substr(s, i, 1); two = substr(s, i, 2)
            if (inblock) {
                if (two == "*/") { inblock = 0; i += 2 } else { i++ }
                continue
            }
            if (two == "/*") { inblock = 1; i += 2; continue }
            if (two == "//") { break }
            if (ch == dq || ch == sq) {
                prev = (i > 1) ? substr(s, i - 1, 1) : ""
                if (ch == sq && identish(prev)) { o = o ch; i++; continue }
                end = closes(s, i, ch, n)
                if (end == 0) { o = o ch; i++; continue }
                i = end + 1
                continue
            }
            o = o ch; i++
        }
        return o
    }
    BEGIN { dq = sprintf("%c", 34); sq = sprintf("%c", 39); inblock = 0; cur = "" }
    FNR == 1 {
        if (cur != "") { if (buf != "") print stripline(buf) > cur; close(cur) }
        p = FILENAME; gsub(/\//, "%", p)
        cur = out "/" p; buf = ""; inblock = 0
    }
    {
        line = $0
        if (line ~ /\\$/) { sub(/\\$/, "", line); buf = buf line; print "" > cur; next }
        print stripline(buf line) > cur; buf = ""
    }
    END { if (cur != "") { if (buf != "") print stripline(buf) > cur; close(cur) } }
    ' "$@"
}

if ! strip_all "${everything[@]}"; then
    echo "FAIL: could not strip the sources -- this gate did not run." >&2
    exit 2
fi
stripped=()
for f in "${everything[@]}"; do
    stripped+=("$(stripped_path "$f")")
done

# --- Rule 3, first half: what pastes in this tree, and where it is defined ----
# A macro whose body concatenates is a way to write any name at all, so its own
# name joins the banned vocabulary everywhere except the file that defines it.
declare -A pasteMacro=()
while IFS=: read -r pf pname; do
    [[ -z "$pname" ]] && continue
    pasteMacro["$pname"]="$pf"
done < <(
    # One pass over the stripped copies; FILENAME carries the mangled path back.
    awk '
    /^[ \t]*#[ \t]*define[ \t]+[A-Za-z_][A-Za-z0-9_]*/ {
        if (index($0, "##") == 0 && index($0, "%:%:") == 0) next
        line = $0
        sub(/^[ \t]*#[ \t]*define[ \t]+/, "", line)
        sub(/[^A-Za-z0-9_].*$/, "", line)
        if (line == "") next
        f = FILENAME
        sub(/.*\//, "", f)
        gsub(/%/, "/", f)
        print f ":" line
    }' "${stripped[@]}"
)

# --- Rule 2: the vocabulary appears only in the helper -----------------------
# mode "first": at most one hit per token per line, which is enough to report.
# mode "all": every occurrence, because rule 4 COUNTS them and a second walk
# crammed onto the line of the first one used to move no counter at all.
banned_hits() {
    awk -v toks="$2" -v mode="${3:-first}" '
    function boundary(line, at, tok,   before, after) {
        before = (at > 1) ? substr(line, at - 1, 1) : ""
        after = substr(line, at + length(tok), 1)
        return (before !~ /[A-Za-z0-9_]/) && (after !~ /[A-Za-z0-9_]/)
    }
    BEGIN { n = split(toks, T, " ") }
    {
        for (i = 1; i <= n; i++) {
            off = 0
            while (1) {
                k = index(substr($0, off + 1), T[i])
                if (k == 0) break
                at = off + k
                if (boundary($0, at, T[i])) {
                    print NR ":" T[i]
                    if (mode != "all") break
                }
                off = at + length(T[i]) - 1
            }
        }
    }' "$1"
}

found=0
prodstripped=()
for f in "${sources[@]}"; do
    is_helper "$f" && continue
    prodstripped+=("$(stripped_path "$f")")
done

pastemap=""
for m in "${!pasteMacro[@]}"; do
    pastemap+="$m=${pasteMacro[$m]};"
done

# One pass over every stripped production source. Three findings share it:
# a banned name (rule 2), the paste operator (rule 3) and a call to a macro
# this tree defines by pasting (rule 3). Per-file awk invocations made this
# gate the longest step of its CI job; the work is the same, the processes
# are not.
while IFS=: read -r kind f ln token; do
    [[ -z "$kind" ]] && continue
    case "$kind" in
    B)
        echo "FAIL: $f:$ln names '$token'." >&2
        echo "      The ancillary-message vocabulary belongs in $HELPER alone:" >&2
        echo "      call receiveWithFds()/sendWithFds() instead of building a msghdr here." >&2
        ;;
    P)
        echo "FAIL: $f:$ln uses the token-paste operator." >&2
        echo "      A pasted name is a name this gate cannot read: CAT(msg, hdr) types" >&2
        echo "      none of the banned words and expands to one of them." >&2
        ;;
    M)
        echo "FAIL: $f:$ln calls '$token', which ${pasteMacro[$token]} defines by pasting." >&2
        echo "      A macro that concatenates can spell any of the banned names out of" >&2
        echo "      fragments, so it stays in the file that defines it." >&2
        ;;
    esac
    found=$((found + 1))
    fail=1
done < <(
    if [[ ${#prodstripped[@]} -gt 0 ]]; then
        awk -v banned="${BANNED[*]}" -v pastemap="$pastemap" -v vre="$VENDORED_RE" '
        function boundary(line, at, tok,   before, after) {
            before = (at > 1) ? substr(line, at - 1, 1) : ""
            after = substr(line, at + length(tok), 1)
            return (before !~ /[A-Za-z0-9_]/) && (after !~ /[A-Za-z0-9_]/)
        }
        function hits(line, tok, kind, only,   off, k, at) {
            off = 0
            while (1) {
                k = index(substr(line, off + 1), tok)
                if (k == 0) return
                at = off + k
                if (boundary(line, at, tok)) {
                    print kind ":" src ":" FNR ":" tok
                    if (only) return
                }
                off = at + length(tok) - 1
            }
        }
        BEGIN {
            nb = split(banned, B, " ")
            np = split(pastemap, PM, ";")
            for (i = 1; i <= np; i++) {
                if (PM[i] == "") continue
                eq = index(PM[i], "=")
                pname[i] = substr(PM[i], 1, eq - 1)
                pfile[i] = substr(PM[i], eq + 1)
            }
        }
        FNR == 1 {
            src = FILENAME
            sub(/.*\//, "", src)
            gsub(/%/, "/", src)
            vendored = (src ~ vre)
        }
        {
            for (i = 1; i <= nb; i++) hits($0, B[i], "B", 1)
            if (!vendored && (index($0, "##") > 0 || index($0, "%:%:") > 0)) {
                print "P:" src ":" FNR ":"
            }
            for (i = 1; i <= np; i++) {
                if (pname[i] == "" || pfile[i] == src) continue
                hits($0, pname[i], "M", 1)
            }
        }' "${prodstripped[@]}"
    fi
)

# The exemption is a path, so production code must not reach under a root.
while IFS=: read -r f ln inc; do
    [[ -z "$ln" ]] && continue
    echo "FAIL: $f:$ln includes '$inc', which is under a test root." >&2
    echo "      The test roots are exempt from the vocabulary rule because tests forge" >&2
    echo "      control messages on purpose; production code that includes one is" >&2
    echo "      production code that the exemption would cover." >&2
    found=$((found + 1))
    fail=1
done < <(
    grep -n -H -E '^[[:space:]]*#[[:space:]]*include[[:space:]]*["<][^">]*(^|/)?tests/' \
        "${sources[@]}" /dev/null |
        sed -E 's/^([^:]+):([0-9]+):[[:space:]]*#[[:space:]]*include[[:space:]]*["<]([^">]*)[">].*/\1:\2:\3/'
)

# --- Rule 5: no production target compiles anything under a test root --------
# A .cpp is compiled because a CMake file names it, not because anything
# includes it, so the build system is the only place this shows.
while IFS=: read -r cf ln ref; do
    [[ -z "$ln" ]] && continue
    echo "FAIL: $cf:$ln names '$ref', which is under a test root." >&2
    echo "      A translation unit under a test root is exempt from the vocabulary rule;" >&2
    echo "      one that a CMake file outside the test roots compiles is production code" >&2
    echo "      wearing a test path. Move the file, or move the target under the root." >&2
    fail=1
done < <(
    mapfile -t cmakes < <(walk | grep -E '(^|/)(CMakeLists\.txt|[^/]+\.cmake)$' |
        grep -v -E "$TEST_ROOT_RE" | sort)
    if [[ ${#cmakes[@]} -gt 0 ]]; then
        awk -v re="(^|[^A-Za-z0-9_.])($(IFS='|'; printf '%s' "${TEST_ROOTS[*]}"))/" '
        { line = $0; sub(/#.*$/, "", line) }
        line ~ re {
            hit = line
            sub(/^.*[^A-Za-z0-9_.\/-]/, "", hit)
            sub(/[^A-Za-z0-9_.\/-].*$/, "", hit)
            print FILENAME ":" FNR ":" hit
        }' "${cmakes[@]}"
    fi
)

# --- Rule 1: the peer-supplied length is read exactly once, in the helper ----
# Lines are joined into statements first, and a statement ends at the next `;`,
# `{` or `}` WHEREVER it falls -- mid-line included, because a splitter that
# flushed a whole line at a time counted `const auto a = c->cmsg_len; g = c->cmsg_len;`
# as one read. A write consumes the token it is written with: the send side
# filling the header in before sendmsg is not a read of anything the peer chose.
# What is counted is occurrences of the surviving token, so two reads inside one
# statement are two.
reads=()
for h in "${helpers[@]}"; do
    mapfile -t hreads < <(
        awk -v f="$h" '
        function emit(ln, s,   t) {
            t = s
            gsub(/cmsg_len[ \t]*=[ \t]*[^=]/, " ", t)
            gsub(/cmsg_len[ \t]*=[ \t]*$/, " ", t)
            while (index(t, "cmsg_len") > 0) {
                print f ":" ln
                sub(/cmsg_len/, " ", t)
            }
        }
        {
            line = $0
            while (match(line, /[;{}]/)) {
                if (buf == "") start = NR
                emit(start, buf " " substr(line, 1, RSTART))
                buf = ""
                line = substr(line, RSTART + 1)
            }
            if (line !~ /^[ \t]*$/) {
                if (buf == "") start = NR
                buf = buf " " line
            }
        }
        END { if (buf != "") emit(start, buf) }' "$(stripped_path "$h")"
    )
    reads+=("${hreads[@]}")
done

if [[ ${#reads[@]} -ne 1 ]]; then
    echo "FAIL: the helper reads the peer-supplied cmsg_len ${#reads[@]} time(s); it must read it once." >&2
    if [[ ${#reads[@]} -eq 0 ]]; then
        echo "      With no read there is no clamp: the count of descriptors then comes" >&2
        echo "      from somewhere other than what the kernel said it delivered." >&2
    else
        echo "      Sites: ${reads[*]}. One read, into a local, and every bound computed" >&2
        echo "      from that local -- a second read is a second, unclamped length." >&2
    fi
    fail=1
fi

# --- Rule 4: the helper's shape ----------------------------------------------
HELPER_STRIPPED="$STRIPDIR/.helper"
: > "$HELPER_STRIPPED"
for h in "${helpers[@]}"; do
    cat "$(stripped_path "$h")" >> "$HELPER_STRIPPED"
done
for tok in "${!HELPER_SHAPE[@]}"; do
    seen="$(banned_hits "$HELPER_STRIPPED" "$tok" all | wc -l)"
    want="${HELPER_SHAPE[$tok]}"
    if [[ "$seen" -ne "$want" ]]; then
        echo "FAIL: the helper names '$tok' $seen time(s); its shape is pinned at $want." >&2
        echo "      One receive walk and one send assembly is the whole surface. A second" >&2
        echo "      walk in here would take its count from somewhere other than the clamp," >&2
        echo "      and neither the vocabulary rule (silent inside the helper) nor the read" >&2
        echo "      count (a walk need read nothing) would move." >&2
        echo "      If the shape changed on purpose, change HELPER_SHAPE in the same commit." >&2
        fail=1
    fi
done

helper_list="${helpers[0]}"
for h in "${helpers[@]:1}"; do
    helper_list+=", $h"
done

if [[ $fail -eq 0 ]]; then
    printf 'OK: %d production source(s) outside the test roots; the SCM_RIGHTS vocabulary appears only in %s (%d banned name(s) elsewhere), whose clamp reads the peer-supplied cmsg_len once, at %s\n' \
        "${#sources[@]}" "$helper_list" "$found" "${reads[0]}"
fi
exit $fail
