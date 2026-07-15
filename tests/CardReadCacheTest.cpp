// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>

#include <gtest/gtest.h>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

using LibreSCRS::Agent::CardReadCache;
using LibreSCRS::Agent::CardReadSnapshot;
using LibreSCRS::Agent::CertSnapshot;
using LibreSCRS::Agent::FieldType;
using namespace std::chrono_literals;

namespace {

std::vector<CertSnapshot> makeCerts(std::string certId)
{
    CertSnapshot cert;
    cert.certId = std::move(certId);
    cert.signingCapable = true;
    cert.ekuOids = {"1.3.6.1.5.5.7.3.4"};
    cert.chainSubjectCns = {"ANA ANIC"};
    // A field group with a text value so the cert scrub branch is exercised on drop.
    cert.fields.push_back({.groupKey = "subject",
                           .labelKey = "g.subject",
                           .labelFallback = "Subject",
                           .fields = {{.fieldKey = "cn",
                                       .labelKey = "f.cn",
                                       .labelFallback = "CN",
                                       .type = FieldType::Text,
                                       .textValue = "ANA ANIC",
                                       .binaryValue = {}}}});
    std::vector<CertSnapshot> certs;
    certs.push_back(std::move(cert));
    return certs;
}

CardReadSnapshot makeSnap(std::string cardType)
{
    CardReadSnapshot snap;
    snap.cardType = std::move(cardType);
    snap.groups.push_back({.groupKey = "personal",
                           .labelKey = "g.personal",
                           .labelFallback = "Personal",
                           .fields = {{.fieldKey = "name",
                                       .labelKey = "f.name",
                                       .labelFallback = "Name",
                                       .type = FieldType::Text,
                                       .textValue = "ANA",
                                       .binaryValue = {}},
                                      // A non-empty photo field so the binary
                                      // (photo) zeroize branch of scrub() is
                                      // actually exercised on drop.
                                      {.fieldKey = "photo",
                                       .labelKey = "f.photo",
                                       .labelFallback = "Photo",
                                       .type = FieldType::Photo,
                                       .textValue = {},
                                       .binaryValue = {0xFF, 0xD8, 0xFF, 0xE0}}}});
    return snap;
}

} // namespace

TEST(CardReadCache, GetReturnsNulloptWhenAbsent)
{
    CardReadCache cache(30s);
    EXPECT_FALSE(cache.get("missing").has_value());
}

TEST(CardReadCache, PutThenGetWithinTtlReturnsSnapshot)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    auto fetched = cache.get("card-A");
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->cardType, "rs-eid");
}

TEST(CardReadCache, GetAfterTtlReturnsNullopt)
{
    CardReadCache cache(10ms); // intentionally short for the test
    cache.put("card-A", makeSnap("rs-eid"));
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(cache.get("card-A").has_value()) << "entry past TTL must not be returned";
}

TEST(CardReadCache, InvalidateDropsEntry)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value());
}

TEST(CardReadCache, MultiCardIsolation)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.put("card-B", makeSnap("nam"));
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value());
    auto b = cache.get("card-B");
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->cardType, "nam");
}

TEST(CardReadCache, PutReplacesExistingEntry)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.put("card-A", makeSnap("nam"));
    auto a = cache.get("card-A");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->cardType, "nam") << "put must replace, not merge";
}

// --- sliding idle window + erase-on-expiry (injected clock) --------

TEST(CardReadCache, SlidingWindowRefreshesOnEachGet)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CardReadCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnap("rs-eid"));

    *now += 80ms; // within the window: get() returns AND refreshes the timer
    ASSERT_TRUE(cache.get("card-A").has_value());

    *now += 70ms; // 150 ms since put, but only 70 ms since the last get -> warm
    EXPECT_TRUE(cache.get("card-A").has_value()) << "sliding window: active use keeps the entry warm";
}

TEST(CardReadCache, IdleBeyondWindowExpiresAndErasesEntry)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CardReadCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnap("rs-eid"));

    *now += 200ms; // idle past the window
    EXPECT_FALSE(cache.get("card-A").has_value());

    // Rewinding the clock must NOT resurrect it: an expired entry is ERASED
    // (and zeroized), not merely hidden behind a timestamp check.
    *now -= 200ms;
    EXPECT_FALSE(cache.get("card-A").has_value()) << "expired entry is erased, not merely hidden";
}

// --- certificate caching (shares the per-card entry with identity) ---

TEST(CardReadCache, GetCertificatesReturnsNulloptWhenAbsent)
{
    CardReadCache cache(30s);
    EXPECT_FALSE(cache.getCertificates("missing").has_value());
}

TEST(CardReadCache, PutThenGetCertificatesWithinWindowReturnsCerts)
{
    CardReadCache cache(30s);
    cache.putCertificates("card-A", makeCerts("abc123"));
    auto fetched = cache.getCertificates("card-A");
    ASSERT_TRUE(fetched.has_value());
    ASSERT_EQ(fetched->size(), 1u);
    EXPECT_EQ(fetched->front().certId, "abc123");
}

TEST(CardReadCache, GetCertificatesAfterTtlReturnsNullopt)
{
    CardReadCache cache(10ms);
    cache.putCertificates("card-A", makeCerts("abc123"));
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(cache.getCertificates("card-A").has_value()) << "certs past TTL must not be returned";
}

TEST(CardReadCache, InvalidateDropsCertificates)
{
    CardReadCache cache(30s);
    cache.putCertificates("card-A", makeCerts("abc123"));
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.getCertificates("card-A").has_value());
}

TEST(CardReadCache, PutCertificatesReplacesExistingCerts)
{
    CardReadCache cache(30s);
    cache.putCertificates("card-A", makeCerts("first"));
    cache.putCertificates("card-A", makeCerts("second"));
    auto a = cache.getCertificates("card-A");
    ASSERT_TRUE(a.has_value());
    ASSERT_EQ(a->size(), 1u);
    EXPECT_EQ(a->front().certId, "second") << "putCertificates must replace, not append";
}

// Identity and certificates share ONE per-card entry: removal/invalidate drops
// both, and either read keeps the whole entry warm (same insertion, same card).
TEST(CardReadCache, IdentityAndCertificatesCoexistUnderOneKey)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.putCertificates("card-A", makeCerts("abc123"));

    auto id = cache.get("card-A");
    auto certs = cache.getCertificates("card-A");
    ASSERT_TRUE(id.has_value());
    ASSERT_TRUE(certs.has_value());
    EXPECT_EQ(id->cardType, "rs-eid");
    ASSERT_EQ(certs->size(), 1u);
    EXPECT_EQ(certs->front().certId, "abc123");

    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value()) << "invalidate drops the identity half too";
    EXPECT_FALSE(cache.getCertificates("card-A").has_value()) << "invalidate drops the cert half too";
}

TEST(CardReadCache, GettingCertificatesRefreshesTheSharedIdleWindow)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CardReadCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnap("rs-eid"));
    cache.putCertificates("card-A", makeCerts("abc123"));

    *now += 80ms; // within window: a cert get returns AND slides the shared timer
    ASSERT_TRUE(cache.getCertificates("card-A").has_value());

    // 150 ms since put, but only 70 ms since the cert get -> identity is STILL warm
    // because the two halves share one sliding window (same insertion).
    *now += 70ms;
    EXPECT_TRUE(cache.get("card-A").has_value()) << "a cert get keeps the identity half warm (shared window)";
}

// A partial entry (certs only, no identity yet) must not be destroyed by an
// identity miss: get() returns nullopt for the absent half without erasing the
// cached certs.
TEST(CardReadCache, IdentityMissDoesNotEraseCachedCertificates)
{
    CardReadCache cache(30s);
    cache.putCertificates("card-A", makeCerts("abc123"));

    EXPECT_FALSE(cache.get("card-A").has_value()) << "identity was never cached for this card";
    auto certs = cache.getCertificates("card-A");
    ASSERT_TRUE(certs.has_value()) << "the identity miss must not evict the cached certs";
    EXPECT_EQ(certs->front().certId, "abc123");
}

// The mirror of the certs-preservation coexist test: writing the IDENTITY half
// onto an entry that already holds certs must scrub+replace only identity and
// keep the cert half (an order-dependent contract the coexist test can't cover,
// since it puts identity first when no certs exist yet).
TEST(CardReadCache, PutIdentityPreservesCachedCertificates)
{
    CardReadCache cache(30s);
    cache.putCertificates("card-A", makeCerts("abc123"));
    cache.put("card-A", makeSnap("rs-eid")); // identity write AFTER certs
    auto certs = cache.getCertificates("card-A");
    ASSERT_TRUE(certs.has_value()) << "put(identity) must not clobber the cert half";
    EXPECT_EQ(certs->front().certId, "abc123");
    EXPECT_TRUE(cache.get("card-A").has_value()) << "the identity it just wrote is present";
}

TEST(CardReadCache, CertificatesIdleBeyondWindowExpiresAndErasesEntry)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CardReadCache cache(100ms, [now] { return *now; });
    cache.putCertificates("card-A", makeCerts("abc123"));

    *now += 200ms; // idle past the window
    EXPECT_FALSE(cache.getCertificates("card-A").has_value());

    // Rewinding the clock must NOT resurrect it: an expired entry is ERASED (and
    // zeroized), not merely hidden behind a timestamp check.
    *now -= 200ms;
    EXPECT_FALSE(cache.getCertificates("card-A").has_value()) << "expired cert entry is erased, not merely hidden";
}
