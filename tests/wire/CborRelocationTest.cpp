// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// A CborValue holding a Map must survive being moved. That sounds like nothing,
// and on most toolchains it is; on Apple Clang 17 / libc++ 19 it is not, and the
// way it fails is a use-after-free that no unit test noticed for three rounds.
//
// std::map is self-referential: the root node's parent points at an end node
// that lives INSIDE the map object. So when a vector<CborValue> grows past its
// capacity and relocates its elements, a map that is moved without that pointer
// being repaired is left addressing the buffer the growth is about to free. The
// damage is invisible until something walks the tree -- which is what copying
// the value does, which is what every reply builder does.
//
// Underneath sits the reason it is allowed to go wrong at all: Map is
// std::map<std::string, CborValue, ...> named while CborValue is still an
// incomplete type. std::vector supports that ([vector.overview]); std::map does
// not, and the standard gives no behaviour for it.
//
// These cases pass trivially on a healthy library. Their value is under
// AddressSanitizer on the affected toolchain, where the read of freed memory is
// reported rather than guessed at -- see the wire-asan macOS CI job.
#include <LibreSCRS/Agent/wire/Cbor.h>

#include <gtest/gtest.h>

#include <string>
#include <utility>

namespace {

using LibreSCRS::Agent::Wire::CborValue;

// A map big enough to have a root with children, so a broken parent pointer is
// actually reached by a tree walk rather than skipped.
CborValue::Map makeSource(int n)
{
    CborValue::Map m;
    m.emplace("url", CborValue(std::string("https://www.mit.gov.rs/TrustedList/TSL-RS.xml")));
    m.emplace("isLotl", CborValue(n % 2 == 1));
    m.emplace("eager", CborValue(false));
    return m;
}

} // namespace

// Growth WITHOUT reserve is the whole point: reserving hides the fault by
// removing the relocation, which is exactly why the first green run of this
// shape proved nothing.
TEST(CborRelocation, ArrayOfMapsSurvivesReallocation)
{
    CborValue::Array arr;
    for (int i = 0; i < 8; ++i) {
        arr.emplace_back(makeSource(i));
    }
    ASSERT_EQ(arr.size(), 8u);

    // Walk every relocated map. A root left pointing into a freed buffer is
    // read here, not at construction.
    for (std::size_t i = 0; i < arr.size(); ++i) {
        const auto* m = arr[i].asMap();
        ASSERT_NE(m, nullptr) << "element " << i;
        EXPECT_EQ(m->size(), 3u) << "element " << i;
        const auto* url = arr[i].find("url");
        ASSERT_NE(url, nullptr) << "element " << i;
        ASSERT_NE(url->asText(), nullptr) << "element " << i;
        EXPECT_EQ(*url->asText(), "https://www.mit.gov.rs/TrustedList/TSL-RS.xml");
    }
}

// The deep copy the reply builders perform: a map whose value is an array of
// maps, copied entry by entry. This is the exact shape that died on the agent's
// transport queue.
TEST(CborRelocation, DeepCopyOfAnArrayOfMapsIsIntact)
{
    CborValue::Array arr;
    for (int i = 0; i < 8; ++i) {
        arr.emplace_back(makeSource(i));
    }
    CborValue::Map entries;
    entries.emplace("TslSources", CborValue(std::move(arr)));

    CborValue::Map copied;
    for (const auto& [k, v] : entries) {
        copied.emplace(k, v); // copy ctor -> variant copy -> vector copy -> map copy
    }

    const auto it = copied.find("TslSources");
    ASSERT_NE(it, copied.end());
    const auto* out = it->second.asArray();
    ASSERT_NE(out, nullptr);
    ASSERT_EQ(out->size(), 8u);
    for (const auto& element : *out) {
        const auto* m = element.asMap();
        ASSERT_NE(m, nullptr);
        EXPECT_EQ(m->size(), 3u);
    }
}

// Encoding walks the same trees, and byte equality is a stronger statement than
// "it did not crash": a tree read through a stale pointer does not re-encode to
// the same bytes.
TEST(CborRelocation, EncodingIsStableAcrossRelocationAndCopy)
{
    CborValue::Array grown;
    for (int i = 0; i < 8; ++i) {
        grown.emplace_back(makeSource(i));
    }
    CborValue::Array reserved;
    reserved.reserve(8); // never relocates, so this side cannot be damaged
    for (int i = 0; i < 8; ++i) {
        reserved.emplace_back(makeSource(i));
    }

    const CborValue a(std::move(grown));
    const CborValue b(std::move(reserved));
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.encode(), b.encode());

    const CborValue copyOfA(a);
    EXPECT_EQ(copyOfA.encode(), b.encode());
}
