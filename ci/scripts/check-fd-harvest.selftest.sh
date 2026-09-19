#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-fd-harvest.selftest.sh — prove the fd-harvest gate discriminates.
#
# The gate is green the moment it lands, because the refactoring that confines
# the SCM_RIGHTS vocabulary to src/wire/FdHarvest.h lands with it. Its whole
# value is the next harvest somebody writes, and three earlier versions of this
# gate each passed rc=0 on a hand-written unclamped harvest -- so the cases here
# are not illustrations, they are the shapes that actually defeated it.
#
# Every case runs against a copy of `git archive HEAD` under /var/tmp (never
# /tmp, which is a RAM filesystem here), so each fixture starts from the real
# production tree and differs from it by exactly the one thing under test.
#
# Cases:
#   1   the tree as it is                                        -> 0
#   2   every banned name, one per fixture, in a new production
#       file (18 sub-cases)                                      -> 1, file:line
#   3   the hand pointer-arithmetic harvest that reads the
#       payload as `(char*)c + 16` and fills three header fields
#       in the same braces                                       -> 1
#   4   the same shape spelled `(c + 1)`, filling an OUTBOUND
#       ack header in the same braces                            -> 1
#   5   a walk whose cmsghdr* cast is split into its own
#       statement and which names no CMSG_ macro at all          -> 1
#   6   that shape moved INTO the helper with the clamp read
#       deleted                                                  -> 1 via rule 1
#   7   a second cmsg_len read added to the helper               -> 1 via rule 1
#   8   the helper deleted                                       -> 1
#   9   a new production file that CALLS the helper              -> 0
#  10   SCM_RIGHTS in a comment and in a string literal          -> 0
#  11   a test file that uses CMSG_DATA/msghdr freely            -> 0
#  12   a tree with no production source at all                  -> 1 (vacuum)
#  13   a harvest whose lines each begin with a digit separator,
#       which used to make the reader discard the rest of them   -> 1
#  14   a name split across a line continuation                  -> 1
#  15   real character literals, including '\'' and '"'          -> 0
#  16   a banned name after a real character literal on the
#       same line: the literal is skipped, the line is not       -> 1
#  17   the same harvest spelled through a token paste           -> 1 via rule 3
#  18   a call from another file to the one macro this tree
#       defines by pasting                                       -> 1 via rule 3
#  19   the harvest in a tracked .inl, an extension the walk
#       and its own git cross-check both used to miss            -> 1
#  20   a production source that includes a header from under
#       a tests/ directory                                       -> 1
#  21   an unclamped walk in src/wire/FdHarvest.cpp, which is
#       exempt from the vocabulary rule                          -> 1 via rule 4
#  22   a SECOND walk inside the helper that never reads
#       cmsg_len, so neither rule 1 nor rule 2 moves             -> 1 via rule 4
#  23   the helper genuinely split: declarations in the .h, the
#       clamp in the .cpp                                        -> 0
#  24   the same harvest in a tracked .c++                       -> 1
#  25   ...in a .cppm                                            -> 1
#  26   ...in a .C                                               -> 1
#  27   ...in a .inc, included from a production .cpp            -> 1
#  28   ...in a file with no extension at all                    -> 1
#  29   ...in a src/wire/Harvest.cpp.in template                 -> 1
#  30   a production .cpp parked under a src/wire/tests/
#       directory, which is not one of the named test roots      -> 1
#  31   a file under a REAL test root that a production CMake
#       file compiles                                            -> 1, rule 5
#  32   a named test root that no longer exists                  -> 1
#  33   a second cmsg_len read crammed onto the clamp's own
#       line, which a per-line count did not see                 -> 1 via rule 1
#  34   a second in-helper walk crammed onto the line of the
#       real one, which rule 4 counted as one                    -> 1 via rule 4
#  35   the whole vocabulary in a Markdown file                  -> 0
#  36   a root that does not exist: the gate did not run         -> 2, not a red
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK="$HERE/check-fd-harvest.sh"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d /var/tmp/fdharvest-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

HELPER="src/wire/FdHarvest.h"

pass=0
fail=0
cases=0
red=0

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$expected" != 0 ]; then red=$((red + 1)); fi
    if [ "$actual" = 2 ] && [ "$expected" != 2 ]; then
        # rc=2 means the gate could not run. A harness that reads that as a red
        # records a detection that never happened -- one round's evidence file
        # recorded eight of them, all of them a mistyped fixture path.
        echo "case $label: FAIL — exit 2: the gate did not run, so this is not a red"
        fail=$((fail + 1))
        return
    fi
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

# Message assertions count too: a run whose printed total moves only when a
# CASE is added or removed is a denominator nobody can diff between revisions.
names() {
    local label="$1" needle="$2" out="$3"
    case "$out" in
        *"$needle"*) pass=$((pass + 1)) ;;
        *) echo "  case $label: FAIL — the output does not name '$needle'"; fail=$((fail + 1)) ;;
    esac
}

mkdir -p "$WORK/base"
if ! git -C "$REPO" archive HEAD | tar -x -C "$WORK/base"; then
    echo "selftest: cannot extract 'git archive HEAD' from $REPO -- no fixture to measure" >&2
    exit 1
fi
if [ ! -f "$WORK/base/$HELPER" ]; then
    echo "selftest: $HELPER is not in HEAD -- the fixtures would prove nothing" >&2
    exit 1
fi

# A fresh copy of the extracted tree.
tree() {
    local root="$WORK/$1"
    rm -rf "$root"
    cp -r "$WORK/base" "$root"
    printf '%s' "$root"
}

run() {
    bash "$CHECK" "$1" 2>&1
}

# --- case 1: the tree as it stands
r="$(tree c1)"
out="$(run "$r")"; rc=$?
check 1 0 "$rc"
names 1 "the SCM_RIGHTS vocabulary appears only in $HELPER" "$out"
names 1 "(0 banned name(s) elsewhere)" "$out"

# --- case 2: each banned name on its own, in a new production file. One of them
# is all it takes to build a harvest, so each one is measured, not the set.
for tok in recvmsg recvmmsg SYS_recvmsg sendmsg sendmmsg msghdr cmsghdr \
           CMSG_FIRSTHDR CMSG_NXTHDR CMSG_DATA CMSG_LEN CMSG_SPACE SCM_RIGHTS \
           msg_control msg_controllen cmsg_len cmsg_level cmsg_type; do
    r="$(tree "c2-$tok")"
    {
        printf '// SPDX-License-Identifier: LGPL-2.1-or-later\n'
        printf 'int probe(void* p);\n'
        printf 'int probe(void* p) { return (int)(long)&%s; }\n' "$tok"
    } > "$r/src/wire/Probe.cpp"
    out="$(run "$r")"; rc=$?
    check "2/$tok" 1 "$rc"
    names "2/$tok" "src/wire/Probe.cpp:3 names '$tok'" "$out"
done

# --- case 3: the harvest that reads the payload by hand -- `(char*)c + 16` is
# byte-for-byte what CMSG_DATA expands to here -- while filling three header
# fields in the same braces. Under a gate that decided the exemption from what
# the surrounding statements said, this passed rc=0 AND vanished from the count
# of measured loops.
r="$(tree c3)"
cat >> "$r/src/wire/FrameReassembler.cpp" <<'EOF'

namespace LibreSCRS::Agent::Wire {
void sneak(msghdr& msg, std::deque<UniqueFd>& out)
{
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    while (c != nullptr) {
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = 0;
        const auto* fds = reinterpret_cast<const int*>(reinterpret_cast<const char*>(c) + 16);
        for (std::size_t i = 0; i < kMaxFrameFds; ++i) {
            ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
            out.emplace_back(fds[i]);
        }
        break;
    }
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 3 1 "$rc"
names 3 "src/wire/FrameReassembler.cpp" "$out"

# --- case 4: the same adoption spelled `(c + 1)`, adopting a count the PEER
# chose, with an OUTBOUND ack header filled in the same braces. The three
# assignments bought the amnesty; here they buy nothing.
r="$(tree c4)"
cat > "$r/src/wire/Relay.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sys/socket.h>
void relay(msghdr& msg, cmsghdr* ack, unsigned announced, int* out)
{
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr;) {
        const int* fds = reinterpret_cast<const int*>(c + 1);
        for (unsigned i = 0; i < announced; ++i) {
            out[i] = fds[i];
        }
        ack->cmsg_level = SOL_SOCKET;
        ack->cmsg_type = SCM_RIGHTS;
        ack->cmsg_len = CMSG_LEN(sizeof(int) * announced);
        break;
    }
}
EOF
out="$(run "$r")"; rc=$?
check 4 1 "$rc"
names 4 "src/wire/Relay.cpp:3 names 'msghdr'" "$out"

# --- case 5: a walk that names none of the CMSG_ macros, because the cast of
# msg_control sits in its own statement. Discovery by opener could not see it.
r="$(tree c5)"
cat > "$r/src/wire/EvilWalk2.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sys/socket.h>
void walk(msghdr& msg, int* out, unsigned announced)
{
    auto* raw = static_cast<unsigned char*>(msg.msg_control);
    auto* c = reinterpret_cast<cmsghdr*>(raw);
    const int* fds = reinterpret_cast<const int*>(c + 1);
    for (unsigned i = 0; i < announced; ++i) {
        out[i] = fds[i];
    }
}
EOF
out="$(run "$r")"; rc=$?
check 5 1 "$rc"
names 5 "src/wire/EvilWalk2.cpp:5 names 'msg_control'" "$out"

# --- case 6: the vocabulary rule cannot see inside the helper, which is the
# whole point of having one file that may name it. Rule 1 is what guards that
# file: put the hand-rolled harvest THERE and delete the clamp's one read, and
# the count of reads drops to zero.
r="$(tree c6)"
sed -i 's/^    const std::size_t claimed = c->cmsg_len;$/    const std::size_t claimed = 4096;/' "$r/$HELPER"
cat >> "$r/$HELPER" <<'EOF'

namespace LibreSCRS::Agent::Wire {
inline void sneak(msghdr& msg, int* out, unsigned announced)
{
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    const auto* fds = reinterpret_cast<const int*>(reinterpret_cast<const char*>(c) + 16);
    for (unsigned i = 0; i < announced; ++i) {
        out[i] = fds[i];
    }
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 6 1 "$rc"
names 6 "reads the peer-supplied cmsg_len 0 time(s)" "$out"

# --- case 7: the other direction. A second read is a second length, and the one
# that is not the clamp is the one nobody bounded.
r="$(tree c7)"
cat >> "$r/$HELPER" <<'EOF'

namespace LibreSCRS::Agent::Wire {
inline std::size_t rawPayload(const cmsghdr* c)
{
    return c->cmsg_len - CMSG_LEN(0);
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 7 1 "$rc"
names 7 "cmsg_len 2 time(s)" "$out"

# --- case 8: the file the whole rule confines the vocabulary TO, deleted.
r="$(tree c8)"
rm -f "$r/$HELPER"
out="$(run "$r")"; rc=$?
check 8 1 "$rc"
names 8 "does not exist" "$out"

# --- case 9: the legitimate way to receive descriptors from a new file. The
# rule bans the vocabulary, not the capability.
r="$(tree c9)"
cat > "$r/src/wire/Extra.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include "FdHarvest.h"

#include <array>

namespace LibreSCRS::Agent::Wire {
std::size_t drain(int fd)
{
    std::array<std::uint8_t, 64> chunk{};
    FdRecvResult got = receiveWithFds(fd, chunk.data(), chunk.size());
    return got.fds.size();
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 9 0 "$rc"

# --- case 10: prose is not code. The rule reads the source with comments and
# string literals removed, so documenting the wire format stays possible.
r="$(tree c10)"
cat > "$r/src/wire/Prose.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <string>

// Descriptors ride SCM_RIGHTS ancillary data; the recvmsg that harvests them
// and the cmsghdr walk that reads CMSG_DATA both live in FdHarvest.h.
std::string describe()
{
    /* msg_controllen, cmsg_len and CMSG_SPACE are named here on purpose. */
    return "SCM_RIGHTS via sendmsg";
}
EOF
out="$(run "$r")"; rc=$?
check 10 0 "$rc"

# --- case 11: tests forge these structures by hand on purpose -- the clamp is
# falsifiable on this host only because one of them builds the truncated control
# message Linux never produces. A rule that banned that would ban the proof.
r="$(tree c11)"
mkdir -p "$r/tests/wire"
cat > "$r/tests/wire/ExtraTest.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sys/socket.h>

int forge(msghdr& msg)
{
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    return *reinterpret_cast<int*>(CMSG_DATA(c));
}
EOF
out="$(run "$r")"; rc=$?
check 11 0 "$rc"

# --- case 12: an empty scope is not a clean one. Everything but the helper
# goes, so the ban has nothing left to be true of.
r="$(tree c12)"
find "$r" -type f ! -path "$r/$HELPER" -delete
out="$(run "$r")"; rc=$?
check 12 1 "$rc"
names 12 "cannot pass vacuously" "$out"

# --- case 13: a digit separator opens no character literal, but a reader that
# assumes it does throws away the rest of the line -- and this repository writes
# `60'000ms` in production, so the shape is not invented for this case.
r="$(tree c13)"
cat >> "$r/src/wire/FrameReassembler.cpp" <<'EOF'

namespace LibreSCRS::Agent::Wire {
void sneak3(int fd, unsigned announced, int* out)
{
    unsigned char control[256];
    const int pad = 1'000; msghdr msg{};
    const int pad2 = 1'000; msg.msg_control = control;
    const int pad3 = 1'000; msg.msg_controllen = sizeof(control);
    const int pad4 = 1'000; cmsghdr* c = CMSG_FIRSTHDR(&msg);
    const int pad5 = 1'000; const int* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
    (void)fd; (void)pad; (void)pad2; (void)pad3; (void)pad4; (void)pad5;
    for (unsigned i = 0; i < announced; ++i) {
        ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
        out[i] = fds[i];
    }
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 13 1 "$rc"
names 13 "names 'msghdr'" "$out"

# --- case 14: one token, two lines. The compiler splices them; a reader that
# does not, reads `msg` and `hdr`.
r="$(tree c14)"
printf '\nvoid spliced(void)\n{\n    struct msg\\\nhdr m;\n    (void)m;\n}\n' >> "$r/src/wire/FrameReassembler.cpp"
out="$(run "$r")"; rc=$?
check 14 1 "$rc"
names 14 "names 'msghdr'" "$out"

# --- case 15: the other direction. Real character literals -- an escaped quote,
# a double quote, a slash -- must not be read as anything but themselves.
r="$(tree c15)"
cat > "$r/src/wire/CharLit.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
bool quoting(char c)
{
    if (c == '\'') { return true; }
    if (c == '"') { return true; }
    if (c == '/') { return true; }
    return false;
}
EOF
out="$(run "$r")"; rc=$?
check 15 0 "$rc"

# --- case 16: and skipping a literal is not skipping the line it sits on.
r="$(tree c16)"
cat > "$r/src/wire/CharLit2.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
bool quoting(char c, void* p)
{
    if (c == '\'') { return reinterpret_cast<msghdr*>(p) != nullptr; }
    return false;
}
EOF
out="$(run "$r")"; rc=$?
check 16 1 "$rc"
names 16 "src/wire/CharLit2.cpp:4 names 'msghdr'" "$out"

# --- case 17: the paste. Every name here is a fragment; the preprocessor makes
# the banned ones. This compiles, so the rule that reads source text has to say
# something about it or it is a spelling rule again.
r="$(tree c17)"
cat > "$r/src/wire/Paste.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <fcntl.h>
#include <sys/socket.h>
#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)
void steal(int fd, unsigned announced, int* out)
{
    unsigned char control[256];
    CAT(msg, hdr) msg{};
    msg.CAT(msg_, control) = control;
    msg.CAT(msg_, controllen) = sizeof(control);
    const auto got = CAT(recv, msg)(fd, &msg, 0);
    (void)got;
    auto* c = reinterpret_cast<CAT(cmsg, hdr)*>(control);
    const int* fds = reinterpret_cast<const int*>(c + 1);
    for (unsigned i = 0; i < announced; ++i) {
        ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
        out[i] = fds[i];
    }
}
EOF
out="$(run "$r")"; rc=$?
check 17 1 "$rc"
names 17 "uses the token-paste operator" "$out"

# --- case 18: the paste macro this tree already has. Banning `##` in a file
# would mean nothing if the file could call somebody else's.
r="$(tree c18)"
cat > "$r/src/wire/UsePaste.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <LibreSCRS/Agent/pkcs11/oasis/pkcs11-oasis.h>
void steal(void* p)
{
    __PASTE(msg, hdr)* m = static_cast<__PASTE(msg, hdr)*>(p);
    (void)m;
}
EOF
out="$(run "$r")"; rc=$?
check 18 1 "$rc"
names 18 "calls '__PASTE'" "$out"

# --- case 19: an extension the walk did not list. The cross-check against git
# was fed the same list, so it could not report the file as unreached either.
r="$(tree c19)"
cat > "$r/src/wire/Harvest.inl" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
inline void harvest(msghdr& msg, cmsghdr* c, int* out)
{
    const std::size_t bytes = c->cmsg_len - CMSG_LEN(0);
    const int* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
    for (std::size_t i = 0; i < bytes / sizeof(int); ++i) {
        out[i] = fds[i];
    }
    (void)msg;
}
EOF
printf '#include "Harvest.inl"\n' >> "$r/src/wire/Framing.cpp"
out="$(run "$r")"; rc=$?
check 19 1 "$rc"
names 19 "src/wire/Harvest.inl:2 names 'msghdr'" "$out"

# --- case 20: tests/ is exempt because tests forge these structures on purpose.
# A production file that INCLUDES one is production code under that exemption.
r="$(tree c20)"
mkdir -p "$r/src/wire/tests"
cat > "$r/src/wire/tests/Harvest.h" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
inline void harvest(msghdr& msg, cmsghdr* c, int* out)
{
    const int* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
    out[0] = fds[0];
    (void)msg;
}
EOF
printf '#include "tests/Harvest.h"\n' >> "$r/src/wire/Framing.cpp"
out="$(run "$r")"; rc=$?
check 20 1 "$rc"
names 20 "under a test root" "$out"

# --- case 21: the .cpp half of the helper is exempt from the vocabulary rule as
# soon as it exists. Rule 1 reads it too, but a walk need read nothing.
r="$(tree c21)"
cat > "$r/src/wire/FdHarvest.cpp" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include "FdHarvest.h"

namespace LibreSCRS::Agent::Wire {
void announcedHarvest(msghdr& msg, unsigned announced, int* out)
{
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        const int* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
        for (unsigned i = 0; i < announced; ++i) {
            ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
            out[i] = fds[i];
        }
    }
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 21 1 "$rc"
names 21 "its shape is pinned" "$out"

# --- case 22: the same walk inside the helper itself, next to the real one. The
# vocabulary rule is silent there by design and the read count does not move,
# because this walk takes its count from what the peer announced.
r="$(tree c22)"
cat >> "$r/$HELPER" <<'EOF'

namespace LibreSCRS::Agent::Wire {
inline void harvestAnnounced(msghdr& msg, unsigned announced, std::vector<UniqueFd>& out)
{
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        const auto* const fds = reinterpret_cast<const int*>(CMSG_DATA(c));
        for (unsigned i = 0; i < announced; ++i) {
            ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
            out.emplace_back(fds[i]);
        }
    }
}
} // namespace LibreSCRS::Agent::Wire
EOF
out="$(run "$r")"; rc=$?
check 22 1 "$rc"
names 22 "its shape is pinned" "$out"

# --- case 23: the split the gate advertises, done honestly: the .h declares and
# the .cpp carries the clamp. One read across the pair, one walk, one assembly.
r="$(tree c23)"
python3 - "$r" <<'PYEOF'
import sys
root = sys.argv[1]
path = root + "/src/wire/FdHarvest.h"
text = open(path).read()
head, body = text.split("#pragma once", 1)
open(root + "/src/wire/FdHarvest.cpp", "w").write(
    "// SPDX-License-Identifier: LGPL-2.1-or-later\n#include \"FdHarvest.h\"\n" + body)
open(path, "w").write(head + "#pragma once\n\n// The implementation lives in FdHarvest.cpp.\n")
PYEOF
out="$(run "$r")"; rc=$?
check 23 0 "$rc"
names 23 "src/wire/FdHarvest.h, src/wire/FdHarvest.cpp" "$out"

# The seven shapes below are the same complete, compiling harvest: a walk that
# takes its count from what the peer announced and hands every int it finds to
# fcntl(). What differs between them is only where the file lives and what it is
# called -- which is exactly what the file set is, and what the file set has
# been wrong about twice.
harvest_file() {
    cat > "$1" <<'EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sys/socket.h>
#include <fcntl.h>
#include <cstddef>
namespace LibreSCRS::Agent::Wire {
inline void adopt(msghdr& msg, int* out)
{
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        const std::size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        const int* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
        for (std::size_t i = 0; i < n; ++i) {
            ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
            out[i] = fds[i];
        }
    }
}
} // namespace LibreSCRS::Agent::Wire
EOF
}

# --- cases 24-29: extensions a list of C/C++ extensions did not have. Each of
# these passed rc=0 against a gate whose walk AND whose git cross-check were
# both handed that list, with the file count unmoved, so nothing in the green
# line hinted at the file. `.inc` needs no build-system support at all.
for spec in "24:src/wire/Harvest.c++:" \
            "25:src/wire/Harvest.cppm:" \
            "26:src/wire/Harvest.C:" \
            "27:src/wire/Harvest.inc:include" \
            "28:src/wire/Harvest:include" \
            "29:src/wire/Harvest.cpp.in:"; do
    label="${spec%%:*}"; rest="${spec#*:}"
    relpath="${rest%%:*}"; how="${rest#*:}"
    r="$(tree "c$label")"
    harvest_file "$r/$relpath"
    if [ "$how" = include ]; then
        printf '#include "%s"\n' "$(basename "$relpath")" >> "$r/src/wire/Framing.cpp"
    fi
    out="$(run "$r")"; rc=$?
    check "$label" 1 "$rc"
    names "$label" "$relpath:6 names 'msghdr'" "$out"
done

# --- case 30: the exemption is keyed on a path, and it used to be keyed on the
# NAME of any directory in it. A production translation unit under a src/wire/
# directory called tests/ was neither scanned nor reported.
r="$(tree c30)"
mkdir -p "$r/src/wire/tests"
harvest_file "$r/src/wire/tests/Harvest.cpp"
out="$(run "$r")"; rc=$?
check 30 1 "$rc"
names 30 "src/wire/tests/Harvest.cpp:6 names 'msghdr'" "$out"

# --- case 31: under a REAL test root, so rule 2 is silent by design -- but a
# production target compiles it, which is what makes it production code. A .cpp
# needs no #include to be built, so the CMake reference is the only witness.
r="$(tree c31)"
harvest_file "$r/tests/Adopt.cpp"
printf 'target_sources(LibreAgentWire PRIVATE tests/Adopt.cpp)\n' >> "$r/CMakeLists.txt"
out="$(run "$r")"; rc=$?
check 31 1 "$rc"
names 31 "which is under a test root" "$out"

# --- case 32: the roots are named, so one that moves without this list moving
# with it must be a red and not a silently wider scope.
r="$(tree c32)"
rm -rf "$r/client/qt/tests"
out="$(run "$r")"; rc=$?
check 32 1 "$rc"
names 32 "the test root 'client/qt/tests' does not exist" "$out"

# --- case 33: a second read of the peer's length, on the clamp's OWN line. The
# statement splitter flushed a line at a time, so both reads were one statement
# and the count did not move.
r="$(tree c33)"
python3 - "$r/$HELPER" <<'PYEOF'
import sys
path = sys.argv[1]
lines = open(path).read().split("\n")
for i, line in enumerate(lines):
    if "const std::size_t claimed = c->cmsg_len;" in line:
        lines[i] = line + " gAnnouncedBytes = c->cmsg_len;"
        break
else:
    raise SystemExit("the clamp line moved: this fixture no longer measures anything")
open(path, "w").write("\n".join(lines))
PYEOF
out="$(run "$r")"; rc=$?
check 33 1 "$rc"
names 33 "cmsg_len 2 time(s)" "$out"

# --- case 34: a second walk inside the helper, on the line of the real one.
# Rule 4 counted at most one hit per token per line, so the shape it exists to
# measure moved none of its counters.
r="$(tree c34)"
python3 - "$r/$HELPER" <<'PYEOF'
import sys
path = sys.argv[1]
lines = open(path).read().split("\n")
extra = (" for (cmsghdr* d = CMSG_FIRSTHDR(&msg); d != nullptr; d = CMSG_NXTHDR(&msg, d))"
         " { const int* g = reinterpret_cast<const int*>(CMSG_DATA(d));"
         " for (unsigned k = 0; k < announced; ++k) { ::fcntl(g[k], F_SETFD, FD_CLOEXEC); } }")
for i, line in enumerate(lines):
    if "for (cmsghdr* c = CMSG_FIRSTHDR(&msg);" in line:
        lines[i] = line + extra
        break
else:
    raise SystemExit("the receive walk moved: this fixture no longer measures anything")
open(path, "w").write("\n".join(lines))
PYEOF
out="$(run "$r")"; rc=$?
check 34 1 "$rc"
names 34 "its shape is pinned" "$out"

# --- case 35: the file set is now an inverse, so the forms this repository
# keeps uncompiled have to stay out of it. Prose about the vocabulary is prose.
r="$(tree c35)"
cat > "$r/HARVEST-NOTES.md" <<'EOF'
# How the harvest works

recvmsg fills a msghdr, the cmsghdr walk uses CMSG_FIRSTHDR and CMSG_NXTHDR,
CMSG_DATA points at the SCM_RIGHTS payload, and cmsg_len is the length the
sender announced -- never the one msg_controllen delivered. sendmsg attaches
them with CMSG_LEN and CMSG_SPACE; cmsg_level and cmsg_type say what they are.
EOF
out="$(run "$r")"; rc=$?
check 35 0 "$rc"

# --- case 36: a root the gate cannot enter is not a defect in the tree. One
# round recorded eight rc=1 detections that were all this, from a relative path.
out="$(run "$WORK/no-such-tree")"; rc=$?
check 36 2 "$rc"
names 36 "this gate did not run" "$out"

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
