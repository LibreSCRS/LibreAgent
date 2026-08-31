// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The country-signing anchor import, away from D-Bus: what the agent believes
// after each import, and which of them it refuses.
//
// The two properties this file exists for:
//
//   * TRUST ON FIRST IMPORT, THEN PIN. Nothing can be chained to before the
//     first list arrives — a master list is what supplies anchors — so the
//     first accepted list establishes the signer, and every later one has to
//     be that signer or descend from an authority the PREVIOUS list carried.
//     The anchors a rotation is judged against come from the list already
//     trusted, never from the list being imported; a check against the
//     incoming list's own contents proves internal consistency and nothing
//     about authenticity. RotationJudgedAgainstThePreviouslyTrustedAnchors is
//     the test that fails if that is ever inverted.
//   * A LINK CERTIFICATE IS AN ANCHOR. See LinkCertificateSurvivesImport.
//   * A LIST MAY NOT BE ROLLED BACK. See the replay section at the foot of this
//     file, which has a case for each cell of the rule's table.

#include "SyntheticMasterList.h"
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>

#include <LibreSCRS/Plugin/CardPluginService.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace LibreSCRS::Agent;
using LibreSCRS::Agent::Test::makeCsca;
using LibreSCRS::Agent::Test::makeIndependentSigner;
using LibreSCRS::Agent::Test::makeLdifCollection;
using LibreSCRS::Agent::Test::makeLinkCertificate;
using LibreSCRS::Agent::Test::makeSignedNonMasterList;
using LibreSCRS::Agent::Test::makeSignerIssuedBy;
using LibreSCRS::Agent::Test::signMasterList;
using LibreSCRS::Agent::Test::signMasterListDated;
using LibreSCRS::Agent::Test::tamperWithSignedContent;

namespace {

constexpr std::int64_t kNow = 1'790'000'000;

// Two instants a publisher might have signed at, an hour apart. Deliberately
// unrelated to kNow: when a list was signed and when this agent took it in are
// different facts, and a test that let them share a value could not tell an
// implementation that confused them apart.
constexpr std::int64_t kSignedEarlier = 1'700'000'000;
constexpr std::int64_t kSignedLater = 1'700'003'600;

// A cache directory of its own per test, removed on the way in and out.
class CacheDir
{
public:
    explicit CacheDir(const char* tag) : m_path(fs::temp_directory_path() / (std::string{"ll-csca-"} + tag))
    {
        fs::remove_all(m_path);
    }
    ~CacheDir()
    {
        fs::remove_all(m_path);
    }
    CacheDir(const CacheDir&) = delete;
    CacheDir& operator=(const CacheDir&) = delete;

    [[nodiscard]] const fs::path& path() const
    {
        return m_path;
    }

private:
    fs::path m_path;
};

// The one publisher a single-list import records. Every case in this file but
// the collection section produces exactly one, and asserting the COUNT here is
// what keeps "the signer" from quietly coming to mean "the first of several"
// once a file may carry twenty-eight.
const Trust::AcceptedSigner& onlySigner(const Trust::AnchorState& state)
{
    EXPECT_EQ(state.signers.size(), 1u) << "one list must leave exactly one publisher on record";
    return state.signers.at(0);
}

bool holds(const std::vector<std::vector<std::uint8_t>>& haystack, const std::vector<std::uint8_t>& needle)
{
    return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
}

} // namespace

// --- trust on first import -------------------------------------------------

TEST(CscaAnchorImport, FirstImportEstablishesTheSigner)
{
    const CacheDir dir("first-import");
    Trust::AnchorCache cache(dir.path());
    ASSERT_FALSE(cache.state().present) << "an untouched cache must believe nothing";

    const auto list = signMasterList({makeCsca("CSCA A", "AA"), makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value()) << "the first list is trusted on import";
    EXPECT_EQ(onlySigner(*accepted).fingerprint, list.signerSpkiSha256);
    EXPECT_EQ(accepted->anchorCount, 2u);
    EXPECT_EQ(accepted->issuerCount, 2u);
    EXPECT_EQ(accepted->acceptedAt, kNow);

    // The pin survives into the cache, and so do the anchors themselves.
    const Trust::AnchorState stored = cache.state();
    EXPECT_TRUE(stored.present);
    EXPECT_EQ(onlySigner(stored).fingerprint, list.signerSpkiSha256);
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 2u);
    for (const auto& a : list.anchors) {
        EXPECT_TRUE(holds(anchors, a)) << "an anchor the list carried is missing from the cache";
    }
}

TEST(CscaAnchorImport, SameSignerReimportsSilently)
{
    const CacheDir dir("same-signer");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, signer);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The same publisher, a wider list. Nothing is asked of the caller.
    const auto second = signMasterList({makeCsca("CSCA B", "BB"), makeCsca("CSCA C", "CC")}, signer);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(onlySigner(*accepted).fingerprint, first.signerSpkiSha256) << "the same key signed both";
    EXPECT_EQ(accepted->anchorCount, 2u);
    // The import REPLACES the anchor set rather than merging into it.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 2u);
    EXPECT_FALSE(holds(anchors, first.anchors.front())) << "the previous anchor set was not replaced";
}

TEST(CscaAnchorImport, UnknownSignerIsRefusedAndAnchorsAreUntouched)
{
    const CacheDir dir("unknown-signer");
    Trust::AnchorCache cache(dir.path());

    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // A different publisher, chaining to nothing the agent holds. A lawful
    // rotation and an attack look identical from here, so this is refused.
    const auto stranger = signMasterList({makeCsca("CSCA X", "XX")}, makeIndependentSigner());
    const auto refused = Trust::importMasterList(stranger.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::SignerChanged);
    // BOTH fingerprints come back, because that is what a person needs shown.
    ASSERT_TRUE(refused.error().seenSigner.has_value());
    ASSERT_TRUE(refused.error().trustedSigner.has_value());
    EXPECT_EQ(*refused.error().seenSigner, stranger.signerSpkiSha256);
    EXPECT_EQ(*refused.error().trustedSigner, first.signerSpkiSha256);

    // A refused import changes nothing.
    EXPECT_EQ(onlySigner(cache.state()).fingerprint, first.signerSpkiSha256);
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, first.anchors.front()));
}

TEST(CscaAnchorImport, RotatedSignerIsAcceptedWhenItChainsToTheTrustedAnchors)
{
    const CacheDir dir("rotation-ok");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterList({anchorA, makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The publisher rotated its key. The new signer was issued by CSCA A, which
    // the list already trusted carried, so no person has to compare
    // fingerprints out of band.
    const auto rotated = makeSignerIssuedBy(anchorA);
    const auto second = signMasterList({anchorA, makeCsca("CSCA C", "CC")}, rotated);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "a signer descending from a trusted anchor is followed automatically";
    EXPECT_EQ(onlySigner(*accepted).fingerprint, second.signerSpkiSha256) << "the pin moves to the new key";
    EXPECT_EQ(onlySigner(cache.state()).fingerprint, second.signerSpkiSha256);
    // The rotation was JUDGED — against anchors the agent already held — rather
    // than merely observed, so it is not a trust-on-first-import.
    EXPECT_TRUE(onlySigner(*accepted).identityEstablished);
}

TEST(CscaAnchorImport, RotationJudgedAgainstThePreviouslyTrustedAnchors)
{
    const CacheDir dir("rotation-circular");
    Trust::AnchorCache cache(dir.path());

    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The forgery: a list of the attacker's own anchors, signed by a key the
    // attacker issued from one of THOSE anchors. It is internally consistent —
    // the signer chains perfectly to an anchor inside the very list being
    // imported — and it must still be refused, because the only anchors that
    // may vouch for a new signer are the ones already trusted.
    const auto plantedAnchor = makeCsca("CSCA Planted", "ZZ");
    const auto plantedSigner = makeSignerIssuedBy(plantedAnchor);
    const auto forgery = signMasterList({plantedAnchor}, plantedSigner);
    const auto refused = Trust::importMasterList(forgery.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "a list that vouches for its own signer is circular, not authentic";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::SignerChanged);
    EXPECT_EQ(cache.anchors().size(), 1u);
    EXPECT_TRUE(holds(cache.anchors(), first.anchors.front()));
}

TEST(CscaAnchorImport, TrustOnFirstImportIsRecordedAsUnchecked)
{
    const CacheDir dir("unchecked");
    Trust::AnchorCache cache(dir.path());

    const auto list = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value());
    // Nothing was compared: somebody signed this list and the agent cannot say
    // who. A surface that claims otherwise claims more than was measured.
    EXPECT_FALSE(onlySigner(*accepted).identityEstablished);
}

// --- link certificates -----------------------------------------------------

TEST(CscaAnchorImport, LinkCertificateSurvivesImport)
{
    const CacheDir dir("link-cert");
    Trust::AnchorCache cache(dir.path());

    // A country that has rotated its root publishes three things: the outgoing
    // self-signed CSCA, the incoming self-signed CSCA, and the LINK
    // certificate — the incoming subject and key signed by the OUTGOING key, so
    // a verifier holding only the old root can still reach the new one. The
    // link certificate is NOT self-signed, and a "keep only self-signed
    // certificates" filter would silently drop it: such a filter passes every
    // single-root country and breaks every country that has rotated.
    const auto outgoing = makeCsca("CSCA Outgoing", "RR");
    const auto incoming = makeCsca("CSCA Incoming", "RR");
    const auto link = makeLinkCertificate(outgoing, incoming);

    const auto list = signMasterList({outgoing, incoming, link}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->anchorCount, 3u) << "all three are anchors; the link certificate is not an extra";

    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 3u);
    EXPECT_TRUE(holds(anchors, outgoing));
    EXPECT_TRUE(holds(anchors, incoming));
    EXPECT_TRUE(holds(anchors, link)) << "the link certificate was filtered out of the cache";
}

TEST(CscaAnchorImport, IssuerCountIsDistinctCountriesNotAnchors)
{
    const CacheDir dir("issuer-count");
    Trust::AnchorCache cache(dir.path());

    // Two generations for one country plus one for another: three anchors, two
    // issuers. Reporting three would tell a person their trust store covers
    // three countries when it covers two.
    const auto list =
        signMasterList({makeCsca("CSCA One Old", "AA"), makeCsca("CSCA One New", "AA"), makeCsca("CSCA Two", "BB")},
                       makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->anchorCount, 3u);
    EXPECT_EQ(accepted->issuerCount, 2u);
}

// --- refusals --------------------------------------------------------------

TEST(CscaAnchorImport, GarbageIsNotAMasterList)
{
    const CacheDir dir("garbage");
    Trust::AnchorCache cache(dir.path());

    const std::vector<std::uint8_t> garbage{0x01, 0x02, 0x03, 0x04};
    const auto refused = Trust::importMasterList(garbage, cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::NotAMasterList);

    const auto empty = Trust::importMasterList({}, cache, kNow);
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error().reason, Trust::ImportRefusal::NotAMasterList);
}

TEST(CscaAnchorImport, ASignedObjectThatIsNotAMasterListIsRefused)
{
    const CacheDir dir("wrong-content-type");
    Trust::AnchorCache cache(dir.path());

    // Properly signed, verifies perfectly, carries a different content type.
    // Without this case, "not a master list" is only ever tested with bytes
    // that fail to decode, so an importer that never looks would pass.
    const auto refused = Trust::importMasterList(makeSignedNonMasterList(), cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::NotAMasterList);
}

TEST(CscaAnchorImport, TamperedContentFailsTheSignature)
{
    const CacheDir dir("tampered");
    Trust::AnchorCache cache(dir.path());

    const auto list = signMasterList({makeCsca("CSCA A", "AA"), makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    // One byte flipped inside the signed content, every length left alone.
    const auto tampered = tamperWithSignedContent(list);
    ASSERT_NE(tampered, list.der) << "the perturbation changed nothing";

    const auto refused = Trust::importMasterList(tampered, cache, kNow);
    ASSERT_FALSE(refused.has_value()) << "a flipped content byte must bring the list down";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::BadSignature);

    // And the untampered original still passes, so the perturbation is what
    // failed rather than the fixture.
    EXPECT_TRUE(Trust::importMasterList(list.der, cache, kNow).has_value());
}

TEST(CscaAnchorImport, AnEmptyListIsNotAValidTrustState)
{
    const CacheDir dir("empty-list");
    Trust::AnchorCache cache(dir.path());

    const auto list = signMasterList({}, makeIndependentSigner());
    const auto refused = Trust::importMasterList(list.der, cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Empty);
    EXPECT_FALSE(cache.state().present);
}

TEST(CscaAnchorImport, AnUnwritableCacheIsRefusedRatherThanIgnored)
{
    const CacheDir dir("unwritable");
    // A regular FILE where the cache directory should be: nothing can be
    // created under it, and the refusal has to say so rather than report a
    // successful import that stored nothing.
    fs::create_directories(dir.path().parent_path());
    {
        std::FILE* f = std::fopen(dir.path().c_str(), "wb");
        ASSERT_NE(f, nullptr);
        std::fclose(f);
    }

    Trust::AnchorCache cache(dir.path());
    const auto list = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto refused = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::CacheNotWritable);
}

// --- replay: a list may not be rolled back ---------------------------------
//
// The rule, one case per cell:
//
//   accepted   incoming   outcome
//   dated      dated      accept only if STRICTLY newer
//   dated      undated    REFUSE
//   undated    dated      accept
//   undated    undated    accept
//
// Row two is the asymmetric one and it is the point of the whole rule. A CMS
// signingTime is optional, so refusing every undated list could turn the feature
// off for a publisher that never dates anything — but letting an undated list
// replace a dated one hands an attacker a way to STRIP a protection the
// installation already had. The rule never refuses for a property the ecosystem
// may not provide, and never lets one be taken away.
//
// Every case below asserts on the PRESENCE of the recorded date, not on a value
// that happens to be zero: an implementation that never fills the field would
// otherwise pass the two undated rows without doing anything at all.

TEST(CscaAnchorImport, TheFixtureDatesAListOnlyWhenAskedTo)
{
    // The guard that keeps the rest of this section from passing vacuously. CMS
    // stamps a signingTime on everything it signs unless it is stopped, so an
    // "undated" fixture that quietly carried one would make every absent-date
    // assertion below meaningless — and an importer that never read a date at
    // all would sail through them.
    const CacheDir undatedDir("fixture-undated");
    Trust::AnchorCache undatedCache(undatedDir.path());
    const auto undated = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    EXPECT_FALSE(undated.signingTime.has_value()) << "the fixture dated a list nobody asked it to date";
    const auto afterUndated = Trust::importMasterList(undated.der, undatedCache, kNow);
    ASSERT_TRUE(afterUndated.has_value());
    EXPECT_FALSE(onlySigner(*afterUndated).signedAt.has_value()) << "a date was invented for a list that carries none";
    EXPECT_FALSE(afterUndated->replayRefusalActive());

    const CacheDir datedDir("fixture-dated");
    Trust::AnchorCache datedCache(datedDir.path());
    const auto dated = signMasterListDated({makeCsca("CSCA B", "BB")}, makeIndependentSigner(), kSignedEarlier);
    ASSERT_TRUE(dated.signingTime.has_value());
    EXPECT_EQ(*dated.signingTime, kSignedEarlier);
    const auto afterDated = Trust::importMasterList(dated.der, datedCache, kNow);
    ASSERT_TRUE(afterDated.has_value());
    ASSERT_TRUE(onlySigner(*afterDated).signedAt.has_value()) << "the list's own signing time was not carried through";
    EXPECT_EQ(*onlySigner(*afterDated).signedAt, kSignedEarlier);
    EXPECT_NE(onlySigner(*afterDated).signedAt, afterDated->acceptedAt)
        << "when it was signed and when it was accepted are different facts";
    EXPECT_TRUE(afterDated->replayRefusalActive());
    // And it survives into the cache, which is where the next import reads it.
    const Trust::AnchorState stored = datedCache.state();
    ASSERT_TRUE(onlySigner(stored).signedAt.has_value()) << "the signing time was not persisted";
    EXPECT_EQ(*onlySigner(stored).signedAt, kSignedEarlier);
}

// Row 1, the accepting half: dated over dated, strictly newer.
TEST(CscaAnchorImport, ADatedListIsAcceptedWhenItIsStrictlyNewer)
{
    const CacheDir dir("replay-newer");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterListDated({makeCsca("CSCA A", "AA")}, signer, kSignedEarlier);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, signer, kSignedLater);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "a newer list from the same publisher must be installable";
    ASSERT_TRUE(onlySigner(*accepted).signedAt.has_value());
    EXPECT_EQ(*onlySigner(*accepted).signedAt, kSignedLater) << "the stored date must move forward with the list";
    EXPECT_TRUE(accepted->replayRefusalActive());
}

// Row 1, the refusing half. Both an OLDER list and a list dated exactly as the
// accepted one: "strictly newer" is the rule, so re-offering the same instant
// buys nothing.
TEST(CscaAnchorImport, ADatedListIsRefusedWhenItIsNotStrictlyNewer)
{
    const CacheDir dir("replay-older");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterListDated({anchorA}, signer, kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The replay: the publisher's own earlier list, correctly signed, complete
    // and authentic. Accepting it would silently withdraw every anchor added
    // between the two.
    const auto older = signMasterListDated({makeCsca("CSCA Withdrawn", "ZZ")}, signer, kSignedEarlier);
    const auto refused = Trust::importMasterList(older.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "an older list from the trusted publisher rolled the anchors back";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Replayed);
    // BOTH dates come back, so a person can see which way round it is.
    ASSERT_TRUE(refused.error().seenSignedAt.has_value());
    ASSERT_TRUE(refused.error().trustedSignedAt.has_value());
    EXPECT_EQ(*refused.error().seenSignedAt, kSignedEarlier);
    EXPECT_EQ(*refused.error().trustedSignedAt, kSignedLater);

    // The refusal changed nothing.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, anchorA));
    ASSERT_TRUE(onlySigner(cache.state()).signedAt.has_value());
    EXPECT_EQ(*onlySigner(cache.state()).signedAt, kSignedLater);

    // Equal is not newer either.
    const auto sameInstant = signMasterListDated({makeCsca("CSCA C", "CC")}, signer, kSignedLater);
    const auto alsoRefused = Trust::importMasterList(sameInstant.der, cache, kNow + 120);
    ASSERT_FALSE(alsoRefused.has_value()) << "a list dated exactly as the accepted one is not newer";
    EXPECT_EQ(alsoRefused.error().reason, Trust::ImportRefusal::Replayed);
}

// Row 2, the asymmetric one: an undated list may not replace a dated one.
TEST(CscaAnchorImport, AnUndatedListCannotReplaceADatedOne)
{
    const CacheDir dir("replay-strip");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterListDated({anchorA}, signer, kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // Signed by the very publisher the agent follows, and carrying no date at
    // all. It cannot be shown to be newer, and accepting it would additionally
    // TAKE AWAY the ability to refuse anything afterwards — the installation
    // would go from protected to unprotected on an attacker's say-so.
    const auto undated = signMasterList({makeCsca("CSCA Withdrawn", "ZZ")}, signer);
    ASSERT_FALSE(undated.signingTime.has_value()) << "the fixture dated the list this case is about";
    const auto refused = Trust::importMasterList(undated.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "an undated list stripped the replay protection off a dated one";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Replayed);
    EXPECT_FALSE(refused.error().seenSignedAt.has_value()) << "the offered list has no date to report";
    ASSERT_TRUE(refused.error().trustedSignedAt.has_value());
    EXPECT_EQ(*refused.error().trustedSignedAt, kSignedLater);

    // Nothing moved, and the protection is still on.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, anchorA));
    EXPECT_TRUE(cache.state().replayRefusalActive());
}

// Row 3: a dated list may follow an undated one, and switches the protection on.
TEST(CscaAnchorImport, ADatedListMayFollowAnUndatedOne)
{
    const CacheDir dir("replay-undated-then-dated");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, signer);
    const auto initial = Trust::importMasterList(first.der, cache, kNow);
    ASSERT_TRUE(initial.has_value());
    EXPECT_FALSE(onlySigner(*initial).signedAt.has_value());
    EXPECT_FALSE(initial->replayRefusalActive()) << "nothing to compare against is not the same as safe";

    // Nothing is refused for a property the accepted list did not have.
    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, signer, kSignedEarlier);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "an undated installation must not refuse a dated list";
    ASSERT_TRUE(onlySigner(*accepted).signedAt.has_value());
    EXPECT_EQ(*onlySigner(*accepted).signedAt, kSignedEarlier);
    EXPECT_TRUE(accepted->replayRefusalActive()) << "the protection turns on the moment there is a date to hold";
}

// Row 4: undated over undated, which is a publisher that dates nothing.
TEST(CscaAnchorImport, AnUndatedListMayFollowAnUndatedOne)
{
    const CacheDir dir("replay-undated-twice");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, signer);
    const auto initial = Trust::importMasterList(first.der, cache, kNow);
    ASSERT_TRUE(initial.has_value());
    EXPECT_FALSE(onlySigner(*initial).signedAt.has_value());

    // Refusing here would turn the feature off outright for a publisher that
    // never dates its lists, and there is no ICAO sample in hand proving they do.
    const auto second = signMasterList({makeCsca("CSCA B", "BB")}, signer);
    ASSERT_FALSE(second.signingTime.has_value()) << "the fixture dated the list this case is about";
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "an undated publisher must not be locked out after its first list";
    EXPECT_FALSE(onlySigner(*accepted).signedAt.has_value()) << "a date was invented for a list that carries none";
    EXPECT_FALSE(accepted->replayRefusalActive());
    EXPECT_FALSE(cache.state().replayRefusalActive());
    // And the anchors really were replaced, so this is an acceptance rather than
    // a refusal that happened to leave a usable store behind.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, second.anchors.front()));
}

// The rule is about the LIST, not about the key that signed it: a publisher that
// rotates its key does not get to roll the anchors back on the way through.
TEST(CscaAnchorImport, ARotationCannotCarryAnOlderListIn)
{
    const CacheDir dir("replay-rotation");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterListDated({anchorA}, makeIndependentSigner(), kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // A lawful rotation — the new signer descends from an anchor the accepted
    // list carried — offering an older list.
    const auto rotated = makeSignerIssuedBy(anchorA);
    const auto older = signMasterListDated({anchorA, makeCsca("CSCA C", "CC")}, rotated, kSignedEarlier);
    const auto refused = Trust::importMasterList(older.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "a key rotation was a way around the replay rule";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Replayed);
    EXPECT_EQ(onlySigner(cache.state()).fingerprint, first.signerSpkiSha256)
        << "a refused import must not move the pin";
}

// --- collections: what the ICAO portal actually serves ---------------------
//
// The dialog that sends a reader to the ICAO Public Key Directory gets back a
// directory export: one LDIF file carrying dozens of master lists, each signed
// by a different country. It is ONE thing a person selects, so it has to be one
// import; it is MANY signed statements, so each has to be verified on its own.
//
// The cases below are about the seam between those two sentences. The synthetic
// ones can say exactly which list is which; the real-file ones at the foot are
// what proves the shapes a generator would never think to produce — a
// BER indefinite-length list, a base64 attribute that is not a list at all, and
// megabyte values folded across thousands of physical lines.

TEST(CscaAnchorImport, ACollectionOfSeparatelySignedListsIsOneImport)
{
    const CacheDir dir("collection-first");
    Trust::AnchorCache cache(dir.path());

    const auto one = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto two = signMasterList({makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    const auto three = signMasterList({makeCsca("CSCA C", "CC")}, makeIndependentSigner());
    const auto ldif = makeLdifCollection({one.der, two.der, three.der}, true);

    const auto accepted = Trust::importMasterList(ldif, cache, kNow);

    ASSERT_TRUE(accepted.has_value()) << "a collection the portal serves must import in ONE action";
    EXPECT_EQ(accepted->listsOffered, 3u);
    EXPECT_TRUE(accepted->refusedLists.empty());
    ASSERT_EQ(accepted->signers.size(), 3u) << "three publishers signed, so three records";
    EXPECT_EQ(accepted->signers[0].fingerprint, one.signerSpkiSha256) << "the file's own order is the record's";
    EXPECT_EQ(accepted->signers[1].fingerprint, two.signerSpkiSha256);
    EXPECT_EQ(accepted->signers[2].fingerprint, three.signerSpkiSha256);
    for (const auto& signer : accepted->signers) {
        EXPECT_FALSE(signer.identityEstablished) << "a first import compares nothing, however many lists it carries";
    }

    // The anchors are the UNION of what the accepted lists carried.
    EXPECT_EQ(accepted->anchorCount, 3u);
    EXPECT_EQ(accepted->issuerCount, 3u);
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 3u);
    EXPECT_TRUE(holds(anchors, one.anchors.front()));
    EXPECT_TRUE(holds(anchors, two.anchors.front()));
    EXPECT_TRUE(holds(anchors, three.anchors.front()));

    // And it all survives into the cache, which is where the next import reads it.
    const Trust::AnchorState stored = cache.state();
    ASSERT_TRUE(stored.present);
    EXPECT_EQ(stored.signers, accepted->signers);
    EXPECT_EQ(stored.listsOffered, 3u);
}

TEST(CscaAnchorImport, ABase64AttributeThatIsNotAListIsNotOfferedAsOne)
{
    // A real export carries a base64 `cn` beside the lists, because base64 is
    // how LDIF spells any value that would otherwise need escaping. Counting
    // every `::` value would offer one list too many, and the extra would then
    // be refused as "not a master list" — a refusal reported about a file that
    // has nothing wrong with it.
    const auto one = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto two = signMasterList({makeCsca("CSCA B", "BB")}, makeIndependentSigner());

    const auto withStray = Trust::masterListsIn(makeLdifCollection({one.der, two.der}, true));
    const auto without = Trust::masterListsIn(makeLdifCollection({one.der, two.der}, false));

    EXPECT_EQ(withStray.size(), 2u) << "a base64 attribute that is not a signed object was counted as a list";
    EXPECT_EQ(without, withStray) << "the stray attribute changed which bytes were taken";
    ASSERT_EQ(withStray.size(), 2u);
    EXPECT_EQ(withStray[0], one.der) << "the list must come back byte for byte; it is what a signature is over";
    EXPECT_EQ(withStray[1], two.der);
}

TEST(CscaAnchorImport, OnePublishedListIsStillOneList)
{
    // The shape that existed before collections, through the same door.
    const auto list = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto found = Trust::masterListsIn(list.der);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found.front(), list.der);

    // And text that is not a directory export yields nothing rather than a
    // guess, which is what lets importMasterList name the fault in the BYTES.
    const std::vector<std::uint8_t> prose{'h', 'e', 'l', 'l', 'o', '\n'};
    EXPECT_TRUE(Trust::masterListsIn(prose).empty());
}

TEST(CscaAnchorImport, OneListThatDoesNotVerifyDoesNotDenyTheOthers)
{
    const CacheDir dir("collection-partial");
    Trust::AnchorCache cache(dir.path());

    const auto one = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto two = signMasterList({makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    const auto three = signMasterList({makeCsca("CSCA C", "CC")}, makeIndependentSigner());
    const auto tampered = tamperWithSignedContent(two);
    ASSERT_NE(tampered, two.der) << "the perturbation changed nothing";

    const auto accepted =
        Trust::importMasterList(makeLdifCollection({one.der, tampered, three.der}, false), cache, kNow);

    // The decision this file is here to record: an import takes what verifies.
    // Refusing all three because one publisher's list is broken would leave a
    // person with nothing and no way forward, and there is no action they could
    // take about a country they do not control.
    ASSERT_TRUE(accepted.has_value()) << "one broken list denied a person the other two";
    EXPECT_EQ(accepted->listsOffered, 3u);
    ASSERT_EQ(accepted->signers.size(), 2u);
    EXPECT_EQ(accepted->signers[0].fingerprint, one.signerSpkiSha256);
    EXPECT_EQ(accepted->signers[1].fingerprint, three.signerSpkiSha256);

    // What did NOT make it is reported rather than swallowed, so a surface can
    // say "two of three" and say why instead of showing an unexplained number.
    ASSERT_EQ(accepted->refusedLists.size(), 1u);
    EXPECT_EQ(accepted->refusedLists.front().reason, Trust::ImportRefusal::BadSignature);
    EXPECT_FALSE(accepted->refusedLists.front().signer.has_value())
        << "a list whose signature does not hold resolves no signer to name";

    // Nothing is installed that was not verified.
    EXPECT_EQ(accepted->anchorCount, 2u);
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 2u);
    EXPECT_TRUE(holds(anchors, one.anchors.front()));
    EXPECT_TRUE(holds(anchors, three.anchors.front()));
    EXPECT_FALSE(holds(anchors, two.anchors.front())) << "an anchor nobody vouched for was installed";

    // And the refusals survive the round trip, so a surface reading the state
    // after a restart says the same thing the import reply said.
    EXPECT_EQ(cache.state().refusedLists, accepted->refusedLists);
}

TEST(CscaAnchorImport, NothingIsInstalledWhenNoListSurvives)
{
    const CacheDir dir("collection-all-bad");
    Trust::AnchorCache cache(dir.path());

    const auto one = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto two = signMasterList({makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    const auto ldif = makeLdifCollection({tamperWithSignedContent(one), tamperWithSignedContent(two)}, false);

    const auto refused = Trust::importMasterList(ldif, cache, kNow);

    ASSERT_FALSE(refused.has_value()) << "a collection in which nothing verified is a refusal, not an empty store";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::BadSignature);
    EXPECT_EQ(refused.error().listsOffered, 2u) << "a person has to be told the file held more than one";
    // No fingerprint is named: there were two lists, and picking one of them to
    // report would say something about the file that is not true of it.
    EXPECT_FALSE(refused.error().seenSigner.has_value());
    EXPECT_FALSE(cache.state().present);
    EXPECT_FALSE(cache.holdsAnchor());
}

TEST(CscaAnchorImport, AnLdifCarryingNoSignedListIsNotAMasterList)
{
    const CacheDir dir("collection-empty-ldif");
    Trust::AnchorCache cache(dir.path());

    const auto ldif = makeLdifCollection({}, false);
    EXPECT_TRUE(Trust::masterListsIn(ldif).empty());

    const auto refused = Trust::importMasterList(ldif, cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::NotAMasterList);
    EXPECT_FALSE(cache.state().present);
}

TEST(CscaAnchorImport, EachPublisherIsMeasuredAgainstItsOwnRecordAndNobodyElses)
{
    const CacheDir dir("collection-replay-per-signer");
    Trust::AnchorCache cache(dir.path());

    const auto alpha = makeIndependentSigner();
    const auto beta = makeIndependentSigner();
    const auto first = signMasterListDated({makeCsca("CSCA A", "AA")}, alpha, kSignedEarlier);
    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, beta, kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(makeLdifCollection({first.der, second.der}, false), cache, kNow).has_value());

    // Alpha publishes something newer; beta re-offers what it already published.
    // Measured against each other, alpha's new list is still OLDER than beta's
    // standing one — and refusing it on that ground would lock out whichever
    // country publishes least often, which is not a rollback and not a threat.
    const auto alphaNew = signMasterListDated({makeCsca("CSCA A2", "AA")}, alpha, kSignedEarlier + 1);
    const auto betaSame = signMasterListDated({makeCsca("CSCA B2", "BB")}, beta, kSignedLater);
    const auto accepted =
        Trust::importMasterList(makeLdifCollection({alphaNew.der, betaSame.der}, false), cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value());
    ASSERT_EQ(accepted->signers.size(), 1u) << "beta's re-offered list is not strictly newer and must not be taken";
    EXPECT_EQ(accepted->signers.front().fingerprint, alphaNew.signerSpkiSha256);
    ASSERT_TRUE(accepted->signers.front().signedAt.has_value());
    EXPECT_EQ(*accepted->signers.front().signedAt, kSignedEarlier + 1) << "the record moves with the list";
    ASSERT_EQ(accepted->refusedLists.size(), 1u);
    EXPECT_EQ(accepted->refusedLists.front().reason, Trust::ImportRefusal::Replayed);
    ASSERT_TRUE(accepted->refusedLists.front().signer.has_value());
    EXPECT_EQ(*accepted->refusedLists.front().signer, betaSame.signerSpkiSha256)
        << "a replay resolves a signer, and a person needs to be told which publisher it was";

    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, alphaNew.anchors.front()));
}

TEST(CscaAnchorImport, AnUnknownPublisherInACollectionIsRefusedAndTheRestAreNot)
{
    const CacheDir dir("collection-stranger");
    Trust::AnchorCache cache(dir.path());

    const auto alpha = makeIndependentSigner();
    const auto beta = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, alpha);
    const auto second = signMasterList({makeCsca("CSCA B", "BB")}, beta);
    ASSERT_TRUE(Trust::importMasterList(makeLdifCollection({first.der, second.der}, false), cache, kNow).has_value());

    // A third list appended by somebody nobody has vouched for. Trust on first
    // import covers the file that ESTABLISHES the store, not every later
    // addition to it — otherwise a stranger would only have to arrive in the
    // same download as twenty-seven genuine countries.
    const auto stranger = signMasterList({makeCsca("CSCA X", "XX")}, makeIndependentSigner());
    const auto alphaAgain = signMasterList({makeCsca("CSCA A2", "AA")}, alpha);
    const auto betaAgain = signMasterList({makeCsca("CSCA B2", "BB")}, beta);
    const auto accepted = Trust::importMasterList(
        makeLdifCollection({alphaAgain.der, stranger.der, betaAgain.der}, false), cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->signers.size(), 2u);
    ASSERT_EQ(accepted->refusedLists.size(), 1u);
    EXPECT_EQ(accepted->refusedLists.front().reason, Trust::ImportRefusal::SignerChanged);
    ASSERT_TRUE(accepted->refusedLists.front().signer.has_value());
    EXPECT_EQ(*accepted->refusedLists.front().signer, stranger.signerSpkiSha256);
    EXPECT_FALSE(holds(cache.anchors(), stranger.anchors.front())) << "a stranger's anchor was installed";
    for (const auto& signer : accepted->signers) {
        EXPECT_TRUE(signer.identityEstablished) << "each was matched against a record already held";
    }
}

TEST(CscaAnchorImport, ARotationInsideACollectionIsFollowedForThatPublisherAlone)
{
    const CacheDir dir("collection-rotation");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto alpha = makeIndependentSigner();
    const auto beta = makeIndependentSigner();
    const auto first = signMasterListDated({anchorA}, alpha, kSignedEarlier);
    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, beta, kSignedEarlier);
    ASSERT_TRUE(Trust::importMasterList(makeLdifCollection({first.der, second.der}, false), cache, kNow).has_value());

    // Alpha rotated: its new signer was issued by CSCA A, which the previously
    // accepted collection carried. Beta did not rotate and is untouched by it.
    const auto rotated = makeSignerIssuedBy(anchorA);
    const auto alphaNew = signMasterListDated({anchorA, makeCsca("CSCA A2", "AA")}, rotated, kSignedLater);
    const auto betaNew = signMasterListDated({makeCsca("CSCA B2", "BB")}, beta, kSignedLater);
    const auto accepted =
        Trust::importMasterList(makeLdifCollection({alphaNew.der, betaNew.der}, false), cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "a publisher's lawful rotation must be followed inside a collection too";
    EXPECT_TRUE(accepted->refusedLists.empty());
    ASSERT_EQ(accepted->signers.size(), 2u);
    EXPECT_EQ(accepted->signers[0].fingerprint, alphaNew.signerSpkiSha256) << "the record moves to the new key";
    EXPECT_EQ(accepted->signers[1].fingerprint, betaNew.signerSpkiSha256) << "beta did not rotate and must not move";
    EXPECT_TRUE(accepted->signers[0].identityEstablished);
    EXPECT_TRUE(accepted->signers[1].identityEstablished);
}

TEST(CscaAnchorImport, ARotationInsideACollectionCannotCarryAnOlderListIn)
{
    const CacheDir dir("collection-rotation-replay");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto alpha = makeIndependentSigner();
    const auto beta = makeIndependentSigner();
    const auto first = signMasterListDated({anchorA}, alpha, kSignedLater);
    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, beta, kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(makeLdifCollection({first.der, second.der}, false), cache, kNow).has_value());

    // A key nothing is on record about, chaining to an anchor the previous
    // import carried, offering a list from BEFORE the one it displaces. Judged
    // per signer alone there is nothing to compare it against — which is
    // exactly the gap a rotation would otherwise be a way through.
    const auto rotated = makeSignerIssuedBy(anchorA);
    const auto rolledBack = signMasterListDated({anchorA, makeCsca("CSCA Withdrawn", "ZZ")}, rotated, kSignedEarlier);
    const auto betaAgain = signMasterListDated({makeCsca("CSCA B2", "BB")}, beta, kSignedLater + 1);
    const auto accepted =
        Trust::importMasterList(makeLdifCollection({rolledBack.der, betaAgain.der}, false), cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "beta's current list is not alpha's problem";
    ASSERT_EQ(accepted->refusedLists.size(), 1u) << "a rotation was a way around the replay rule";
    EXPECT_EQ(accepted->refusedLists.front().reason, Trust::ImportRefusal::Replayed);
    ASSERT_EQ(accepted->signers.size(), 1u);
    EXPECT_EQ(accepted->signers.front().fingerprint, betaAgain.signerSpkiSha256);
    EXPECT_FALSE(holds(cache.anchors(), rolledBack.anchors.back())) << "a withdrawn anchor came back";
}

TEST(CscaAnchorImport, ReplayRefusalIsOnlyActiveWhenEveryAcceptedListCarriedADate)
{
    // The aggregate is the weakest of its parts, deliberately. One undated list
    // among the accepted ones is a publisher whose anchors can be rolled back
    // freely, and "a later collection can be checked for rollback" is then not
    // a true sentence about the store — so it must not be reported as one.
    const CacheDir mixedDir("collection-mixed-dates");
    Trust::AnchorCache mixed(mixedDir.path());
    const auto dated = signMasterListDated({makeCsca("CSCA A", "AA")}, makeIndependentSigner(), kSignedEarlier);
    const auto undated = signMasterList({makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    ASSERT_FALSE(undated.signingTime.has_value()) << "the fixture dated the list this case is about";
    const auto both = Trust::importMasterList(makeLdifCollection({dated.der, undated.der}, false), mixed, kNow);
    ASSERT_TRUE(both.has_value());
    ASSERT_EQ(both->signers.size(), 2u);
    EXPECT_TRUE(both->signers[0].signedAt.has_value());
    EXPECT_FALSE(both->signers[1].signedAt.has_value()) << "a date was invented for a list that carries none";
    EXPECT_FALSE(both->replayRefusalActive()) << "one undated list among two was reported as fully protected";
    EXPECT_FALSE(mixed.state().replayRefusalActive()) << "the aggregate did not survive the round trip";

    // And with every accepted list dated, it is true of the whole.
    const CacheDir allDir("collection-all-dated");
    Trust::AnchorCache all(allDir.path());
    const auto other = signMasterListDated({makeCsca("CSCA C", "CC")}, makeIndependentSigner(), kSignedLater);
    const auto every = Trust::importMasterList(makeLdifCollection({dated.der, other.der}, false), all, kNow);
    ASSERT_TRUE(every.has_value());
    EXPECT_TRUE(every->replayRefusalActive());
    EXPECT_TRUE(all.state().replayRefusalActive());
}

TEST(CscaAnchorImport, ASingleSignerStateFileWrittenBeforeCollectionsIsStillFollowed)
{
    const CacheDir dir("legacy-state");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterListDated({makeCsca("CSCA A", "AA")}, signer, kSignedEarlier);
    const auto initial = Trust::importMasterList(first.der, cache, kNow);
    ASSERT_TRUE(initial.has_value());

    // Rewrite the state in the spelling this cache used before a file could
    // carry more than one list. An upgrade that could not read it would forget
    // the publisher it was following, and the next list would be a
    // trust-on-first-import — which is the state an attacker would like the
    // store to be in.
    {
        std::ofstream out(dir.path() / "state", std::ios::trunc);
        ASSERT_TRUE(out);
        out << "signer=" << Trust::toHex(first.signerSpkiSha256) << "\n";
        out << "signerPinned=1\n";
        out << "anchors=1\n";
        out << "issuers=1\n";
        out << "acceptedAt=" << kNow << "\n";
        out << "signedAt=" << kSignedEarlier << "\n";
        out << "origin=import\n";
    }
    const Trust::AnchorState legacy = cache.state();
    ASSERT_TRUE(legacy.present) << "a state file this cache itself wrote became unreadable";
    ASSERT_EQ(legacy.signers.size(), 1u);
    EXPECT_EQ(legacy.signers.front().fingerprint, first.signerSpkiSha256);
    EXPECT_TRUE(legacy.signers.front().identityEstablished);
    ASSERT_TRUE(legacy.signers.front().signedAt.has_value());
    EXPECT_EQ(*legacy.signers.front().signedAt, kSignedEarlier);
    EXPECT_TRUE(legacy.replayRefusalActive());

    // And the pin still bites: the same publisher is followed, a stranger is not.
    const auto stranger = signMasterListDated({makeCsca("CSCA X", "XX")}, makeIndependentSigner(), kSignedLater);
    const auto refused = Trust::importMasterList(stranger.der, cache, kNow + 60);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::SignerChanged);

    const auto second = signMasterListDated({makeCsca("CSCA A2", "AA")}, signer, kSignedLater);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 120);
    ASSERT_TRUE(accepted.has_value());
    EXPECT_TRUE(onlySigner(*accepted).identityEstablished) << "the legacy pin was read as an unchecked first import";
}

// --- the file the portal actually serves -----------------------------------
//
// Everything above builds its own input, which is the only way to say "this
// list and not that one". None of it can produce what a real download does: a
// list encoded with an indefinite BER length, a base64 attribute that is not a
// list, megabyte values folded across thousands of physical lines, and
// twenty-eight signers who never agreed on anything. Point
// LIBRESCRS_TEST_MASTERLIST_LDIF at a collection from the ICAO Public Key
// Directory to run these; without one they skip, because the file may not live
// in this repository.

namespace {

std::optional<std::vector<std::uint8_t>> realCollection()
{
    const char* path = std::getenv("LIBRESCRS_TEST_MASTERLIST_LDIF");
    if (path == nullptr || !fs::exists(path)) {
        return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>{}};
}

} // namespace

TEST(CscaAnchorRealCollection, EveryListIsFoundIncludingTheOneWithAnIndefiniteLength)
{
    const auto bytes = realCollection();
    if (!bytes) {
        GTEST_SKIP() << "set LIBRESCRS_TEST_MASTERLIST_LDIF to an ICAO Public Key Directory collection";
    }

    const auto lists = Trust::masterListsIn(*bytes);
    ASSERT_GE(lists.size(), 2u) << "a directory export carrying one list is not the collection this is about";

    // A DER length is declared up front; a BER indefinite one is not, and is
    // closed by two zero octets instead. A real collection carries at least one
    // of the latter, so a scan that only understood definite lengths would
    // silently come up short — and would come up short by a number nobody could
    // notice without counting the attributes by hand.
    std::size_t indefinite = 0;
    for (const auto& list : lists) {
        ASSERT_GE(list.size(), 2u);
        EXPECT_EQ(list[0], 0x30u) << "every list must be a constructed SEQUENCE";
        if (list[1] == 0x80u) {
            ++indefinite;
            EXPECT_EQ(list[list.size() - 1], 0x00u);
            EXPECT_EQ(list[list.size() - 2], 0x00u);
        }
    }
    EXPECT_GT(indefinite, 0u) << "no BER indefinite-length list in this file; the shape is untested here";
    std::cout << "[ collection ] " << lists.size() << " lists, " << indefinite << " of them BER indefinite\n";
}

TEST(CscaAnchorRealCollection, TheWholeCollectionImportsInOneAction)
{
    const auto bytes = realCollection();
    if (!bytes) {
        GTEST_SKIP() << "set LIBRESCRS_TEST_MASTERLIST_LDIF to an ICAO Public Key Directory collection";
    }
    const std::size_t lists = Trust::masterListsIn(*bytes).size();

    const CacheDir dir("real-collection");
    Trust::AnchorCache cache(dir.path());
    const auto accepted = Trust::importMasterList(*bytes, cache, kNow);

    ASSERT_TRUE(accepted.has_value()) << "the file our own dialog sends a reader to download was refused";
    EXPECT_EQ(accepted->listsOffered, lists);
    EXPECT_TRUE(accepted->refusedLists.empty()) << "a list in a genuine collection did not survive its own check";
    EXPECT_EQ(accepted->signers.size(), lists) << "each country in the collection signs with a key of its own";
    EXPECT_GT(accepted->anchorCount, 100u);
    EXPECT_GT(accepted->issuerCount, 50u);
    EXPECT_LT(accepted->issuerCount, accepted->anchorCount) << "countries rotate, so anchors outnumber issuers";
    for (const auto& signer : accepted->signers) {
        EXPECT_FALSE(signer.identityEstablished) << "a first import compares nothing";
    }

    // The certificates really are on disk, in the directory a card plugin is
    // handed — the count is not a number the import made up.
    std::size_t files = 0;
    for (const auto& entry : fs::directory_iterator(cache.anchorsDirectory())) {
        files += entry.is_regular_file() ? 1u : 0u;
    }
    EXPECT_EQ(files, accepted->anchorCount);
    EXPECT_EQ(cache.state().signers, accepted->signers) << "the record did not survive the round trip";

    std::cout << "[ collection ] " << accepted->anchorCount << " anchors, " << accepted->issuerCount << " issuers, "
              << accepted->signers.size() << " publishers, replay refusal "
              << (accepted->replayRefusalActive() ? "active" : "inactive") << "\n";
}

TEST(CscaAnchorRealCollection, TheSameCollectionCannotBeInstalledTwice)
{
    const auto bytes = realCollection();
    if (!bytes) {
        GTEST_SKIP() << "set LIBRESCRS_TEST_MASTERLIST_LDIF to an ICAO Public Key Directory collection";
    }

    const CacheDir dir("real-collection-twice");
    Trust::AnchorCache cache(dir.path());
    const auto first = Trust::importMasterList(*bytes, cache, kNow);
    ASSERT_TRUE(first.has_value());
    if (!first->replayRefusalActive()) {
        GTEST_SKIP() << "this collection carries an undated list, so a rollback cannot be refused at all";
    }

    // Every list in it is dated exactly as the one already accepted, and
    // "strictly newer" is the rule — so every one of them is a replay and the
    // import as a whole has nothing left to admit.
    const auto again = Trust::importMasterList(*bytes, cache, kNow + 60);
    ASSERT_FALSE(again.has_value()) << "the same collection was installed a second time";
    EXPECT_EQ(again.error().reason, Trust::ImportRefusal::Replayed);
    EXPECT_EQ(again.error().listsOffered, first->listsOffered);
    EXPECT_EQ(cache.state().signers, first->signers) << "a refused import moved the record";
    EXPECT_EQ(cache.state().anchorCount, first->anchorCount);
}

// --- who is told where the anchors are -------------------------------------
//
// The two below close a gap that a real passport on a dogfood machine found.
// A person had imported a master list; this file's subject accepted it and
// wrote five certificates into the cache; the agent's own state property said
// five anchors, one issuer. The badge on the document still read "no country
// signing certificates have been imported", because the card plugin that
// judges a document was never told the directory existed. Every test in three
// repositories was green: each half was tested against itself, and nothing
// tested the seam between them — which did not exist.
//
// Only the first of the two is here. The second guarded that the composition
// root (AgentService::registerOnBus) actually calls publishAnchorDirectory
// with the configured cache directory — that wiring lives in the consumer
// that owns a bus service, not in this shared library, so its guard belongs
// there too.

// The directory the agent publishes to its plugins is the one an import really
// wrote into. Asserted against the FILES, not against a second spelling of the
// layout: two constants that agree is what this already had.
TEST(CscaAnchorPublication, ThePublishedDirectoryIsWhereAnImportReallyWrote)
{
    const CacheDir dir("publish-agreement");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto anchorB = makeCsca("CSCA B", "BB");
    const auto list = signMasterList({anchorA, anchorB}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);
    ASSERT_TRUE(accepted.has_value());
    ASSERT_EQ(accepted->anchorCount, 2u);

    // No plugin directory here, so the registry loads nothing — this is about
    // the VALUE that gets published. Which plugin receives it, and what it does
    // with it, is settled where the plugin lives.
    LibreSCRS::Plugin::CardPluginService plugins{fs::path{dir.path() / "no-plugins-here"}};
    const fs::path published = Trust::publishAnchorDirectory(plugins, dir.path());

    EXPECT_EQ(published, cache.anchorsDirectory());
    ASSERT_TRUE(fs::is_directory(published)) << "the published path is not a directory that exists: " << published;

    std::vector<fs::path> written;
    for (const auto& entry : fs::directory_iterator(published)) {
        if (entry.is_regular_file()) {
            written.push_back(entry.path());
        }
    }
    EXPECT_EQ(written.size(), 2u) << "the import's certificates are not in the directory the agent publishes";

    // And the bytes really are the anchors, so a directory of two unrelated
    // files could not pass.
    const auto held = cache.anchors();
    ASSERT_EQ(held.size(), 2u);
    EXPECT_TRUE(holds(held, anchorA));
    EXPECT_TRUE(holds(held, anchorB));
}

// --- reconciling a recorded report against the cache ------------------------
//
// The report a client reads follows the CONFIGURATION file; what it describes
// lives in the anchor CACHE. Two files, two lifetimes, and a person may empty
// either one behind the agent's back — so the report goes on describing an
// agent that is no longer there. The subject here is the reconciliation that
// refuses to serve such a report.
//
// It lives in this shared library rather than in a host because it touches
// only ConfigStore and AnchorCache and no bus at all: it was file-local to the
// D-Bus host until 2026-09-01 purely by where it was first written, and a
// second copy in the socket host would have been a second implementation of a
// trust-policy decision — the thing LibreKDE removed rather than kept.
//
// WHERE the reconciliation is CALLED FROM is a separate question with a
// separate answer, and it stays with each host: startup, before the object
// that serves the property exists. That wiring is guarded where it lives, in
// the same way and for the same reason as publishAnchorDirectory's above.

namespace {

// A configuration file and a cache root of its own per test. The two paths are
// SIBLINGS rather than one inside the other, which is the layout the fault
// this reconciliation exists for actually has: a person clears the cache and
// the configuration file survives it untouched.
class ConfiguredAgent
{
public:
    explicit ConfiguredAgent(const char* tag) : m_root(fs::temp_directory_path() / (std::string{"la-csca-"} + tag))
    {
        fs::remove_all(m_root);
        fs::create_directories(m_root / "cache");
        m_config = std::make_unique<Config::ConfigStore>(m_root / "config.conf", m_root / "cache");
    }
    ~ConfiguredAgent()
    {
        m_config.reset();
        fs::remove_all(m_root);
    }
    ConfiguredAgent(const ConfiguredAgent&) = delete;
    ConfiguredAgent& operator=(const ConfiguredAgent&) = delete;

    [[nodiscard]] Config::ConfigStore& config() const
    {
        return *m_config;
    }
    [[nodiscard]] fs::path cacheDir() const
    {
        return fs::path{m_config->cscaCacheDir()};
    }

    // Import a real list into the configured cache and record the report the
    // way a host does after an accepted import. A REAL import rather than a
    // hand-built cache: the reconciliation asks the cache questions, so a
    // fixture that only wrote the files it expects to be read would be
    // agreeing with itself.
    void importAndRecord()
    {
        Trust::AnchorCache cache{cacheDir()};
        const auto list = signMasterList({makeCsca("CSCA A", "AA"), makeCsca("CSCA B", "BB")}, makeIndependentSigner());
        const auto accepted = Trust::importMasterList(list.der, cache, kNow);
        ASSERT_TRUE(accepted.has_value()) << "the fixture's own import was refused";
        ASSERT_EQ(accepted->anchorCount, 2u);

        Config::CscaAnchorState recorded;
        recorded.anchors = accepted->anchorCount;
        recorded.issuers = accepted->issuerCount;
        recorded.replayRefusalActive = accepted->replayRefusalActive();
        recorded.signer = Trust::toHex(onlySigner(*accepted).fingerprint);
        recorded.signerPinned = true;
        recorded.acceptedAt = kNow;
        recorded.origin = "import";
        m_config->recordCscaAnchorState(recorded);
        ASSERT_TRUE(m_config->cscaAnchorState().has_value()) << "the fixture recorded nothing to reconcile";
    }

private:
    fs::path m_root;
    std::unique_ptr<Config::ConfigStore> m_config;
};

} // namespace

// The ordinary restart: everything the report describes is still on disk, so
// the report is left exactly as it was. Without this case a reconciliation
// that simply cleared the report every time would pass every other test here.
TEST(CscaAnchorReconcile, AReportTheCacheBearsOutIsLeftAlone)
{
    ConfiguredAgent agent("reconcile-intact");
    ASSERT_NO_FATAL_FAILURE(agent.importAndRecord());
    const auto before = agent.config().cscaAnchorState();

    Trust::discardStaleAnchorReport(agent.config());

    const auto after = agent.config().cscaAnchorState();
    ASSERT_TRUE(after.has_value()) << "a report whose anchors and signer are both still held was discarded";
    EXPECT_EQ(*after, *before) << "the report was rewritten rather than left alone";
}

// Half one: the anchors are gone, so the counts name certificates that are not
// there.
TEST(CscaAnchorReconcile, AReportIsDiscardedWhenTheAnchorsAreGone)
{
    ConfiguredAgent agent("reconcile-wiped");
    ASSERT_NO_FATAL_FAILURE(agent.importAndRecord());

    std::error_code ec;
    fs::remove_all(agent.cacheDir() / "anchors", ec);
    ASSERT_FALSE(ec);

    Trust::discardStaleAnchorReport(agent.config());

    EXPECT_FALSE(agent.config().cscaAnchorState().has_value())
        << "the agent kept serving counts for anchors it no longer holds";
}

// Half two, and the one an implementation that only asks "are there anchors"
// walks straight past: the anchors are all still there, so every COUNT in the
// report is true, but the cache's own state file is gone. With nothing left to
// read the pin from the agent follows nobody, so a report naming a publisher
// claims a NARROWER trust than the one actually in force.
TEST(CscaAnchorReconcile, AReportIsDiscardedWhenTheCacheStateIsGone)
{
    ConfiguredAgent agent("reconcile-unpinned");
    ASSERT_NO_FATAL_FAILURE(agent.importAndRecord());

    std::error_code ec;
    ASSERT_TRUE(fs::remove(agent.cacheDir() / "state", ec)) << "the fixture removed nothing";
    ASSERT_FALSE(ec);
    const Trust::AnchorCache cache{agent.cacheDir()};
    ASSERT_TRUE(cache.holdsAnchor()) << "the fixture removed more than the state file";

    Trust::discardStaleAnchorReport(agent.config());

    EXPECT_FALSE(agent.config().cscaAnchorState().has_value())
        << "the agent kept naming a publisher it no longer follows";
}

// This REPORTS; it does not tidy. The anchors it just declined to describe are
// still on disk — clearing them would turn a display fault into a trust one.
TEST(CscaAnchorReconcile, DiscardingAReportLeavesTheCacheAlone)
{
    ConfiguredAgent agent("reconcile-no-tidy");
    ASSERT_NO_FATAL_FAILURE(agent.importAndRecord());

    std::error_code ec;
    ASSERT_TRUE(fs::remove(agent.cacheDir() / "state", ec));
    ASSERT_FALSE(ec);

    Trust::discardStaleAnchorReport(agent.config());
    ASSERT_FALSE(agent.config().cscaAnchorState().has_value()) << "the precondition for this test did not hold";

    const Trust::AnchorCache cache{agent.cacheDir()};
    EXPECT_TRUE(cache.holdsAnchor()) << "the reconciliation deleted anchors it only had to stop describing";
    EXPECT_EQ(cache.anchors().size(), 2u);
}

// Nothing recorded is not a report to be wrong about, and the empty cache must
// not provoke a write: a store that persisted on every startup would rewrite a
// configuration file the agent was only ever asked to read.
TEST(CscaAnchorReconcile, NothingRecordedIsNotAReportToDiscard)
{
    ConfiguredAgent agent("reconcile-nothing");
    ASSERT_FALSE(agent.config().cscaAnchorState().has_value()) << "the fixture started with a report";

    Trust::discardStaleAnchorReport(agent.config());

    EXPECT_FALSE(agent.config().cscaAnchorState().has_value());
}
