// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// Turning signed ICAO country-signing master lists into the agent's trust
// anchors, and deciding whether to believe them.
//
// WHY THERE IS A DECISION TO MAKE. A master list is signed by a key that chains
// to a country's own authority, and the list is what supplies the anchors that
// authority would be checked against — so at the very first import there is
// nothing to check it with. Verifying a list against anchors carried INSIDE
// that same list proves internal consistency and says nothing whatever about
// authenticity; it must never be presented as a check.
//
// WHAT THIS DOES INSTEAD. The first list is trusted on import and its signer is
// remembered. Every later list must be signed by a key already recorded — or by
// a signer whose certificate chains to an anchor the PREVIOUS import carried,
// which is how a publisher's lawful key rotation is followed without a person
// having to compare fingerprints out of band. Anything else is refused, both
// fingerprints are reported, and the stored anchors are left alone. A lawful
// rotation and an attack look identical from here, so accepting one silently
// would accept the other.
//
// A FILE IS NOT A LIST. What the ICAO Public Key Directory actually serves is a
// directory export (RFC 2849 LDIF) carrying the collection: dozens of master
// lists, each published and signed by a different country, base64 under a
// `pkdMasterListContent;binary` attribute. So the unit a person hands in is a
// FILE and the unit that is verified is a LIST, and everything below is stated
// per list: each is verified against its own signer, each signer carries its
// own record, the rotation rule and the replay rule are applied to each. The
// anchors installed are the UNION of the lists that survived all of it. Reading
// the file happens HERE rather than in whatever client passed it: a client that
// decided what counts as a master list would be deciding what this agent may be
// asked to believe, and it is not the trust boundary.
//
// PARTIAL OUTCOMES ARE THE ORDINARY CASE, not an edge. Twenty-eight countries
// publish on their own schedules, so a collection in which two lists are stale
// and twenty-six are current is what a reader downloads on an ordinary Tuesday.
// An import therefore takes what verifies and reports the rest: nothing is
// installed that was not verified and admitted, and one publisher's stale list
// does not deny a person the other twenty-seven. The refusals are not
// swallowed — @ref AnchorState::refusedLists carries one record per list that
// did not make it, so a surface can say what actually happened rather than
// showing an unexplained smaller number. An import that admits NO list at all
// is a refusal like any other and leaves the store untouched.
//
// THE ROTATING SIGNER'S CERTIFICATE COMES OUT OF THE LIST, and specifically out
// of the signer a successful verification RESOLVED — never out of the CMS
// certificate bag, which is unauthenticated and which anybody may drop anybody's
// certificate into. Nothing has to be handed in beside the file: the certificate
// the path build needs is inside the bytes the caller already supplied.
//
// NO CRYPTO LIVES HERE. Every cryptographic judgement is made by the published
// LibreMiddleware trust API — the parse-and-verify, the fingerprint and the
// path build. In particular the fingerprint is NEVER recomputed locally: it is
// a hash of the re-encoded SubjectPublicKeyInfo, and the two plausible
// alternatives (hashing the certificate, or hashing the SubjectPublicKeyInfo
// slice as carried) both produce values that look right and never match.

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// Forward decls — only references appear below, in publishAnchorDirectory and
// discardStaleAnchorReport. The configuration store is deliberately not
// INCLUDED here: this header describes what the agent believes about anchors,
// and a consumer that only imports has no business compiling the whole
// configuration surface to do it.
namespace LibreSCRS::Plugin {
class CardPluginService;
}
namespace LibreSCRS::Agent::Config {
class ConfigStore;
}

namespace LibreSCRS::Agent::Trust {

// The largest master list the agent will ingest. A published ICAO list runs to a
// few megabytes; this leaves generous room and still bounds the synchronous read
// that a client can ask the bus thread to perform.
inline constexpr std::size_t kMaxMasterListBytes = 32ull * 1024 * 1024;

// SHA-256 over the DER of a signer's SubjectPublicKeyInfo.
inline constexpr std::size_t kSignerFingerprintSize = 32;
using SignerFingerprint = std::array<std::uint8_t, kSignerFingerprintSize>;

// Why an import, or one list inside a collection, was refused. Every value
// leaves the stored anchors untouched when it is the outcome of the whole
// import; as a per-list record it means that list contributed nothing.
enum class ImportRefusal : std::uint8_t {
    /// Not a master list: undecodable, or a signed object of some other content
    /// type. Empty input lands here too, as does a directory export carrying no
    /// signed master list at all.
    NotAMasterList,
    /// A master list that verified and carries no anchor. An empty trust store
    /// is not a valid state to import into one.
    Empty,
    /// A master list whose content cannot be read.
    Malformed,
    /// The signature over the list does not hold.
    BadSignature,
    /// The list is signed by a key the agent does not follow, and that key's
    /// certificate does not chain to any anchor the previous import carried.
    SignerChanged,
    /// The list is authentic and is not newer than the one already accepted
    /// FROM THAT SAME SIGNER: either it is dated no later, or it carries no date
    /// at all while the accepted one does. Installing it would withdraw anchors.
    Replayed,
    /// The anchors verified but could not be stored. Reported rather than
    /// swallowed: an import that silently kept nothing would leave a person
    /// believing anchors were installed. Never a per-list outcome — storage is
    /// attempted once, for the union.
    CacheNotWritable,
};

// One publisher whose list an import took in, and what that import established
// about it. The unit the rotation rule and the replay rule are both applied to:
// a collection of twenty-eight independently signed lists yields twenty-eight
// of these, and each later import is judged against the matching one.
struct AcceptedSigner
{
    /// SHA-256 over the DER of this publisher's SubjectPublicKeyInfo.
    SignerFingerprint fingerprint{};
    /// Whether the accepting import ESTABLISHED this publisher's identity —
    /// matched it against a record already held, or built a path from it to an
    /// anchor already held — as opposed to merely observing it. False on a
    /// trust-on-first-import, and a surface that says "authenticity verified"
    /// over a false here claims more than was measured.
    bool identityEstablished{false};
    /// When THIS publisher's list said it was SIGNED, from the CMS signingTime
    /// signed attribute. Empty when the list carried none, which CMS permits.
    /// Distinct from @ref AnchorState::acceptedAt, which is when this agent took
    /// the file in and is therefore under no publisher's control.
    ///
    /// When two lists in one file share a publisher, the LATER of their dates:
    /// both were accepted, so the record has to bound what may follow them.
    std::optional<std::int64_t> signedAt;

    bool operator==(const AcceptedSigner&) const = default;
};

// One list in an imported file that did not make it into the store, and as much
// as could be read about it. Carried so a surface can explain a smaller number
// than a person expected — "twenty-six of twenty-eight, two replays" — instead
// of leaving them to guess.
struct RefusedList
{
    ImportRefusal reason{ImportRefusal::NotAMasterList};
    /// The publisher that signed it, when the list verified far enough for one
    /// to be resolved. Empty when it did not.
    std::optional<SignerFingerprint> signer;

    bool operator==(const RefusedList&) const = default;
};

// What the agent remembers between imports, and what a client reads in order to
// have something to say about the trust store.
struct AnchorState
{
    bool present{false}; ///< false until at least one list has been accepted
    /// Every publisher whose list the accepting import took in, one record
    /// each, in the order the file carried them. Never empty when @ref present.
    ///
    /// This is the pin, generalised. A single published list leaves exactly one
    /// record here and behaves as it always did; the ICAO collection leaves one
    /// per participating country.
    std::vector<AcceptedSigner> signers;
    /// Anchors held: the UNION of what the accepted lists carried, with exact
    /// duplicates collapsed — the lists in a collection overlap heavily, and
    /// storing one file per repetition would multiply the store several times
    /// over for no added trust. Counts link certificates, which are anchors like
    /// any other — this is not a count of self-signed roots.
    std::uint32_t anchorCount{0};
    /// Distinct issuing countries among those anchors, by the subject's country
    /// attribute. Anchors that carry none, or that do not parse, share one
    /// bucket rather than each inventing an issuer.
    std::uint32_t issuerCount{0};
    /// How many signed master lists the imported FILE was read as carrying: one
    /// for a single published list, one per country for a directory export. The
    /// number ACCEPTED is this less @ref refusedLists size, which is at least
    /// @ref signers size — two lists in one file may share a publisher.
    std::uint32_t listsOffered{0};
    /// The lists in that same file that contributed nothing, one record each.
    /// Empty on an import where everything verified. The order is the order
    /// they were decided in, which is not quite the file's: a list can only be
    /// measured against what the whole file displaces once every list has been
    /// read, so the ones refused by that measure come last.
    std::vector<RefusedList> refusedLists;
    std::int64_t acceptedAt{0};   ///< seconds since the epoch
    std::string origin{"import"}; ///< where the anchors came from

    /// The record held for @p fingerprint, or nullptr when no accepted list was
    /// signed by that key. The lookup the rotation and replay rules both start
    /// from, so neither has to know how these are stored.
    [[nodiscard]] const AcceptedSigner* recordFor(const SignerFingerprint& fingerprint) const noexcept
    {
        for (const AcceptedSigner& s : signers) {
            if (s.fingerprint == fingerprint) {
                return &s;
            }
        }
        return nullptr;
    }

    /// Whether a later import can be refused for being a replay.
    ///
    /// True exactly when EVERY accepted list carried a signing time. The
    /// aggregate is deliberately the weakest of its parts: the sentence this
    /// answers is "a later collection can be checked for rollback", and one
    /// undated list among twenty-eight is a publisher whose anchors can be
    /// rolled back freely. Reporting true because most of them were dated would
    /// overstate exactly the protection a person cannot check for themselves.
    ///
    /// With nothing to compare against, "is this list older than the one
    /// installed" is not a question that can be answered at all, and a surface
    /// that stays silent about it leaves a person unable to tell "this is safe"
    /// from "this cannot be checked".
    [[nodiscard]] bool replayRefusalActive() const noexcept
    {
        if (signers.empty()) {
            return false;
        }
        for (const AcceptedSigner& s : signers) {
            if (!s.signedAt.has_value()) {
                return false;
            }
        }
        return true;
    }

    /// Whether EVERY publisher on record had its identity ESTABLISHED, as
    /// opposed to merely observed. What a surface renders as "pinned".
    ///
    /// The weakest of the parts, for the same reason as @ref
    /// replayRefusalActive above: "most of them were established" is not a
    /// statement a person can act on, because the unestablished one is
    /// precisely the publisher whose anchors got in on a first sighting, and it
    /// is the one they would want to be told about.
    ///
    /// Written over the whole set rather than over the first record, and not
    /// because a mixed set is easy to produce today — an import into an empty
    /// store establishes nobody and an import into a populated one admits only
    /// publishers it could check, so the two outcomes are uniform. This says
    /// what is true of any set an import may hand it, a claim that survives
    /// that rule changing; reading one record and calling it the aggregate
    /// would not.
    ///
    /// The empty set answers FALSE, and it is spelled out rather than left to
    /// a fold: `all_of` over an empty range is TRUE, so the obvious one-liner
    /// reports a state with no publisher at all as fully established — a record
    /// claiming an established publisher that does not exist. Both hosts that
    /// spelled this aggregate for themselves had to rediscover that.
    [[nodiscard]] bool everyPublisherEstablished() const noexcept
    {
        if (signers.empty()) {
            return false;
        }
        for (const AcceptedSigner& s : signers) {
            if (!s.identityEstablished) {
                return false;
            }
        }
        return true;
    }
};

// Why a whole import was refused: no list in the file was admitted, so nothing
// was stored. Reached only when EVERY list failed — a file in which one list
// verifies is an acceptance carrying the rest in
// @ref AnchorState::refusedLists.
struct Refusal
{
    /// The reason the FIRST refused list gave, in the file's own order. One
    /// reason is reported rather than a ranking invented over several: a
    /// priority order among refusals would have to claim that one publisher's
    /// failure matters more than another's, which nothing here knows.
    ImportRefusal reason{ImportRefusal::NotAMasterList};
    /// The signer of the list that was offered, when one could be read AND the
    /// file carried exactly one list. Shown beside @ref trustedSigner so a
    /// person can tell a rotation from an attack; the agent cannot. Empty for a
    /// collection, where naming one publisher out of twenty-eight would say
    /// something the reason does not.
    std::optional<SignerFingerprint> seenSigner;
    /// The publisher the agent follows, when it follows exactly one. Empty once
    /// several are recorded, for the same reason as @ref seenSigner.
    std::optional<SignerFingerprint> trustedSigner;
    /// For @ref ImportRefusal::Replayed: when the offered list says it was
    /// signed, empty when it does not say. Empty here beside a filled
    /// @ref trustedSignedAt is the strip attempt rather than the rollback.
    std::optional<std::int64_t> seenSignedAt;
    /// For @ref ImportRefusal::Replayed: when the list ALREADY ACCEPTED FROM
    /// THAT SIGNER said it was signed — the value the offered one had to beat.
    std::optional<std::int64_t> trustedSignedAt;
    /// How many signed master lists the file was read as carrying. One for a
    /// single published list — and one, too, for bytes that turned out to be
    /// no list at all, since they were judged as one. More for a collection,
    /// and then @ref reason describes the first of them rather than all.
    std::uint32_t listsOffered{0};
};

// The anchors and the trust state on disk, under the agent's configured
// country-signing cache directory.
//
// Anchors are stored one encoded certificate per file, exactly as the list
// carried them. Nothing is filtered on the way in: an ICAO master list carries
// CSCA link certificates beside the self-signed roots, and a
// "keep only self-signed" filter would pass every single-root country and break
// every country that has rotated its root.
//
// The directory is FLAT, and deliberately so: it is handed whole to card
// plugins (see publishAnchorDirectory), which read every certificate in it and
// have no business knowing which publisher vouched for which. That is why an
// import that admits some lists and refuses others stores the union of the
// admitted ones and nothing else — there is nowhere to keep a refused
// publisher's previous anchors apart, and quietly leaving them behind would
// make the store a merge of statements no single publisher ever made.
class AnchorCache
{
public:
    explicit AnchorCache(std::filesystem::path dir);

    // Where the anchor FILES are, under the cache directory this was built
    // with — the directory something outside this process has to be handed if
    // it is to judge a document against what was imported.
    //
    // A method rather than a name spelled again at each call site, and the
    // reason is a defect that reached a person's desk: the import wrote five
    // certificates here, a card plugin was never told the directory existed,
    // and the badge on a real passport read "no country signing certificates
    // have been imported" while five of them sat on disk. Two halves that each
    // knew the layout, and no seam where they had to agree.
    [[nodiscard]] std::filesystem::path anchorsDirectory() const;

    // Absent or unreadable state reads as "believes nothing", never as an error:
    // a first run and a wiped cache are the same situation.
    [[nodiscard]] AnchorState state() const;

    // The anchors currently held, in stored order. Empty when nothing has been
    // imported.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> anchors() const;

    // Whether the cache holds AT LEAST ONE anchor. Stops at the first one and
    // reads no bytes — the question is whether anything is here, not whether
    // what is here still verifies, and re-verifying a store to answer it would
    // put a full trust pass in the startup path. A missing or unreadable
    // directory answers false, for the same reason @ref state does: a first run
    // and a wiped cache are the same situation.
    [[nodiscard]] bool holdsAnchor() const;

    // REPLACES the anchor set — a master list is a complete statement of what a
    // publisher vouches for, so merging would keep anchors it has withdrawn.
    // For a collection the same holds of the union: it is the complete
    // statement of every publisher the import admitted, and a publisher whose
    // list was refused has vouched for nothing this time round.
    // Returns false if anything could not be written, in which case the previous
    // contents may be gone: the state file is written last and only on success,
    // so a torn write leaves the agent believing nothing rather than believing
    // the wrong thing.
    [[nodiscard]] bool replace(const std::vector<std::vector<std::uint8_t>>& anchors, const AnchorState& state);

private:
    std::filesystem::path m_dir;
};

// The signed master lists a downloaded FILE carries, in the order it carries
// them, each as the bytes that must be verified.
//
// Two shapes are recognised and nothing else is guessed at:
//
//   * ONE published master list, handed over as it was published — the bytes
//     are a single CMS ContentInfo carrying id-signedData, and they come back
//     unchanged as the only element;
//   * a DIRECTORY EXPORT (RFC 2849 LDIF), which is what the ICAO Public Key
//     Directory serves — line folding undone, and every base64 attribute value
//     that decodes to a CMS ContentInfo carrying id-signedData taken, in file
//     order.
//
// THE FILTER IS THE CONTENT, NEVER THE ATTRIBUTE NAME. The portal writes the
// lists under `pkdMasterListContent;binary`, but base64 is how LDIF carries any
// value that needs escaping, and a real export has a base64 `cn` sitting beside
// them — so a scan that took every `::` value would offer one more "list" than
// the file holds, and a scan that trusted the attribute name would break the
// day a directory spells it differently. What is taken is what parses as a
// signed object.
//
// This decides only what is WORTH VERIFYING. Nothing here checks a signature,
// reads a content type from inside the SignedData, or looks at an anchor: a
// value that survives this may still turn out to be a signed object of some
// other kind, and importMasterList refuses it then. The BER indefinite-length
// form is accepted alongside the definite one, because a real collection
// contains one.
//
// @param fileBytes whatever the person selected, as read.
// @return the lists found, or empty when the bytes are neither of the two
//         shapes — which is not an error here and is left for a caller to name.
[[nodiscard]] std::vector<std::vector<std::uint8_t>> masterListsIn(const std::vector<std::uint8_t>& fileBytes);

// Verify every master list @p der carries, decide which of them to believe, and
// on acceptance replace the cached anchors with the union of those.
//
// CALLER OBLIGATIONS THIS FUNCTION DOES NOT ENFORCE.
//
// Authorize and rate-limit the caller BEFORE reading @p der off whatever
// transport delivered it. A descriptor handed across a process boundary is a
// second reference to one open file description, so reading it advances the
// offset the sender can still observe on its own copy — a caller that was
// going to be refused must never have its bytes consumed first. Getting the
// order backwards is invisible from here: an unauthorized or rate-limited
// caller and an authorized one that happened to supply a bad list both end
// in the same refusal by name, so nothing this function returns tells the
// two cases apart. Only the side effect on the descriptor does.
//
// If a caller keeps its own record of the trust state and reconciles it
// against reality — for example at startup, to notice that the on-disk cache
// no longer matches what was remembered — that reconciliation must never
// write to @ref AnchorCache. The signer pin and the rotation rule this
// function applies are both read out of the very cache such a reconciliation
// would be touching, so a reconciliation that "helpfully" cleared or
// rewrote anchors to match a stale record would leave the store empty and
// the next comer able to establish trust from nothing, exactly as a first
// import would. Report what is stale; never tidy the store to agree with it.
//
// Neither obligation is checked by this function, and neither is exercised
// by any test that ships with this library. A caller must prove both hold,
// with tests of its own, before it relies on this API.
//
// WHAT IS JUDGED PER LIST, AND WHAT IS FIXED FOR THE WHOLE IMPORT. Each list is
// verified on its own, against its own signer, and measured against the record
// held for THAT signer — so a stale list from one country cannot deny another
// country's current one. What is fixed once, before anything is written, is the
// set of anchors a rotation may be judged against: they are read from the cache
// as it stood BEFORE this import. A list in the file may therefore never vouch
// for a signer in the same file, whichever order they arrive in. Letting it
// would be the circular check this whole design exists to avoid, one level up.
//
// @param der the bytes the person handed in: one signed master list as
//        published, or a directory export carrying a collection of them. See
//        masterListsIn. Everything the decision needs is in here, the rotating
//        signers' certificates included.
// @param now seconds since the epoch, injected rather than read, so the record
//        an import writes is testable.
// @return what the agent believes after the import — including, when some lists
//         were refused and others were not, the record of both. An error only
//         when NO list was admitted, in which case the store is untouched.
[[nodiscard]] std::expected<AnchorState, Refusal> importMasterList(const std::vector<std::uint8_t>& der,
                                                                   AnchorCache& cache, std::int64_t now);

// Lowercase hex, for showing a fingerprint to a person or putting one on the wire.
[[nodiscard]] std::string toHex(const SignerFingerprint& fingerprint);

// Tell every card plugin @p plugins loaded where this agent keeps the country
// signing certificates it has imported, and answer with the directory that was
// published.
//
// WHY THE AGENT HAS TO SAY IT. A plugin verifying a travel document's passive
// authentication needs country signing certificates, and it is not allowed to
// go looking for them: the directory used to be named by an environment
// variable, which anything running as the person at the keyboard can set, so a
// forged document could be reported as chaining to a national authority on the
// say-so of whoever set it. That read was removed and nothing replaced it —
// which is why anchors a person really had imported were reported as absent.
// The path has to arrive from the process that holds them, which is this one.
//
// @param cacheDir the agent's configured country-signing cache directory,
//        i.e. ConfigStore::cscaCacheDir(). The SAME value the import writes
//        under: pass the configured one and never a path rebuilt from the
//        cache root, or an installation that has set CscaCacheDir imports into
//        one directory and reads from another with nothing to say so.
// @return the directory published, which is @ref AnchorCache::anchorsDirectory
//         for @p cacheDir. Returned so a caller can log it and a test can
//         compare it against where an import really landed.
std::filesystem::path publishAnchorDirectory(LibreSCRS::Plugin::CardPluginService& plugins,
                                             const std::filesystem::path& cacheDir);

// Discard a recorded anchor report the anchor cache does not bear out.
//
// The report follows the CONFIGURATION file. What it describes lives in the
// anchor cache: the anchor files themselves, and beside them the cache's own
// state file, which carries the publishers this agent follows. A person may
// edit or delete either, and the configuration file survives it — so the report
// goes on describing an agent that is no longer there. Both halves overstate,
// which on a trust surface is the direction that matters:
//
//   * the ANCHORS are gone, and the counts name anchors that are not there;
//   * the cache's STATE is gone, and `signer` / `signerPinned` describe
//     publishers the agent no longer follows. With nothing left to read the
//     records from, the next list is a trust-on-first-import, so a surface
//     saying "pinned to X" is claiming a NARROWER trust than the one actually
//     in force. After a collection there is no `signer` to be wrong and
//     `signerPinned` overstates alone, which makes it thinner and no less
//     false. The counts beside it may still be perfectly true, which is what
//     makes this half the easy one to walk past.
//
// The harm is bounded and worth stating exactly: every verdict reads the cache
// itself and never this report, so no document can be accepted on the strength
// of a stale one. What breaks is a settings screen that contradicts what
// reading a passport says, which corrodes trust in the display without being a
// false green.
//
// CLEARED, not marked stale, and the two considerations that pull against each
// other turn out not to conflict here:
//
//   * the pin and the rotation rule read the CACHE — @ref AnchorCache::state for
//     the signer it follows, @ref AnchorCache::anchors for the path build a
//     lawful rotation is checked against. Neither has ever read this record.
//     Clearing it therefore cannot let any publisher re-establish trust on a
//     wiped cache, which would be a far worse bug than the display one being
//     fixed. Nothing in the cache is touched from here — this reports, it does
//     not tidy — so a pin that outlived its anchors goes on refusing a
//     stranger's list, and anchors that outlived the pin stay on disk;
//   * absence is the only honest spelling this vocabulary has. A zeroed report
//     means "a list was accepted and it vouched for nothing" — a different
//     claim, and a false one. Absence already means "nothing installed that can
//     be reported from here", which after either wipe is true.
//
// Both questions are cheap and neither re-verifies anything: an anchor probe
// that stops at the first file it finds, and the small state file the cache
// parses anyway. Startup latency is a real cost.
//
// WHY IT LIVES HERE rather than in the host that calls it. It touches
// @ref AnchorCache and the configuration store and no transport whatever —
// it was file-local to the D-Bus host until 2026-09-01 purely by where it was
// first written, and the socket host consequently served reports over a cache
// that had been wiped. The alternative was a second copy there, which is a
// second implementation of a trust-policy decision: one that happens to agree
// today is exactly what a consumer of this library has already removed once.
//
// WHERE IT IS CALLED FROM is a separate decision and belongs to each host:
// at STARTUP, before anything can read the property. Callers must honour that,
// and it is a deliberate trade a reader should not have to discover: a cache
// wiped while the agent is running reads stale until the next start. Catching
// that would mean watching the directory for the life of the process — a
// standing cost, and a race with every import, for a display that restarting
// already corrects.
//
// @param config the agent's configuration store, read for the recorded report
//        and for the cache directory it describes, and reset when the two
//        disagree. Nothing else in it is touched.
void discardStaleAnchorReport(Config::ConfigStore& config);

} // namespace LibreSCRS::Agent::Trust
