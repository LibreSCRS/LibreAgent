// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>

#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>

#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Trust/CscaMasterList.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace LibreSCRS::Agent::Trust {
namespace {

namespace fs = std::filesystem;
namespace lm = LibreSCRS::Trust;

constexpr const char* kAnchorsDirName = "anchors";
constexpr const char* kAnchorsStagingName = "anchors.incoming";
constexpr const char* kStateFileName = "state";
constexpr const char* kAnchorSuffix = ".cer";

ImportRefusal refusalFor(lm::MasterListError e) noexcept
{
    switch (e) {
    case lm::MasterListError::NotAMasterList:
        return ImportRefusal::NotAMasterList;
    case lm::MasterListError::Empty:
        return ImportRefusal::Empty;
    case lm::MasterListError::Malformed:
        return ImportRefusal::Malformed;
    case lm::MasterListError::BadSignature:
        return ImportRefusal::BadSignature;
    case lm::MasterListError::SignerMismatch:
        return ImportRefusal::SignerChanged;
    }
    return ImportRefusal::NotAMasterList;
}

// Distinct issuing countries among @p anchors, by the SUBJECT's country
// attribute — an anchor is a country's own authority, so its subject is who it
// belongs to. An anchor that does not parse, or that carries no country, shares
// the empty bucket rather than inventing an issuer of its own; over-counting
// here would tell a person their store covers more countries than it does.
std::uint32_t countIssuers(const std::vector<std::vector<std::uint8_t>>& anchors)
{
    std::set<std::string> countries;
    for (const auto& der : anchors) {
        auto parsed = Certificate::ParsedCertificate::fromDer(der);
        countries.insert(parsed ? parsed->subject().country() : std::string{});
    }
    return static_cast<std::uint32_t>(countries.size());
}

std::optional<std::vector<std::uint8_t>> readFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool writeFile(const fs::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
    return out.good();
}

// A whole decimal integer, or nothing. Deliberately strict: strtoll answers 0
// for text that is not a number at all, and a state file whose date read as
// "the epoch" would silently refuse every list a publisher has ever signed.
std::optional<std::int64_t> wholeInteger(const std::string& value)
{
    const std::size_t first = (!value.empty() && value.front() == '-') ? 1 : 0;
    if (value.size() == first) {
        return std::nullopt;
    }
    for (std::size_t i = first; i < value.size(); ++i) {
        if (value[i] < '0' || value[i] > '9') {
            return std::nullopt;
        }
    }
    errno = 0;
    char* end = nullptr;
    const long long parsed = std::strtoll(value.c_str(), &end, 10);
    if (errno == ERANGE || end != value.c_str() + value.size()) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(parsed);
}

// `id-signedData` (1.2.840.113549.1.7.2) as a complete DER OBJECT IDENTIFIER —
// tag, length and value — so it can be compared as a byte run at the one place
// a CMS ContentInfo puts it: immediately inside the outer SEQUENCE.
constexpr std::uint8_t kSignedDataOid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};

// Whether @p value is one complete CMS ContentInfo carrying id-signedData.
//
// The declared length has to cover the value EXACTLY, so a truncated blob and
// two blobs concatenated are both rejected — except under the BER indefinite
// form, where no length is declared up front and the end-of-contents octets are
// what close the object. A real ICAO collection contains one of those, so a
// definite-length-only check silently counts one list short.
bool isSignedObject(const std::vector<std::uint8_t>& value)
{
    constexpr std::size_t kOidSize = sizeof(kSignedDataOid);
    if (value.size() < 2 + kOidSize) {
        return false;
    }
    if (value[0] != 0x30) {
        return false; // not a constructed SEQUENCE, so not a ContentInfo
    }

    const std::uint8_t lengthByte = value[1];
    std::size_t header = 0;
    if (lengthByte == 0x80) {
        if (value[value.size() - 1] != 0x00 || value[value.size() - 2] != 0x00) {
            return false; // indefinite and never closed
        }
        header = 2;
    } else if (lengthByte < 0x80) {
        if (2 + static_cast<std::size_t>(lengthByte) != value.size()) {
            return false;
        }
        header = 2;
    } else {
        const std::size_t octets = static_cast<std::size_t>(lengthByte & 0x7F);
        // Eight would still fit a size_t on this platform; four bounds the
        // object at 4 GiB, which is far above kMaxMasterListBytes and keeps the
        // accumulation below from being able to overflow.
        if (octets < 1 || octets > 4 || value.size() < 2 + octets) {
            return false;
        }
        std::size_t length = 0;
        for (std::size_t i = 0; i < octets; ++i) {
            length = (length << 8) | static_cast<std::size_t>(value[2 + i]);
        }
        if (2 + octets + length != value.size()) {
            return false;
        }
        header = 2 + octets;
    }

    if (value.size() < header + kOidSize) {
        return false;
    }
    return std::equal(std::begin(kSignedDataOid), std::end(kSignedDataOid),
                      value.begin() + static_cast<std::ptrdiff_t>(header));
}

// RFC 4648 base64, which is what an LDIF `::` value carries. Strict: any
// character outside the alphabet, and any length that is not a multiple of
// four, is a decode failure rather than something to skip over. A tolerant
// decoder would turn a corrupted attribute into a shorter blob that then fails
// as "not a master list", which names the wrong fault.
std::optional<std::vector<std::uint8_t>> decodeBase64(std::string_view encoded)
{
    const auto digit = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        return -1;
    };

    if (encoded.empty() || (encoded.size() % 4) != 0) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> out;
    out.reserve((encoded.size() / 4) * 3);
    for (std::size_t i = 0; i < encoded.size(); i += 4) {
        int values[4] = {0, 0, 0, 0};
        std::size_t padding = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const char c = encoded[i + j];
            if (c == '=') {
                // Padding is legal only in the last group, and only as the last
                // one or two characters of it.
                if (i + 4 != encoded.size() || j < 2) {
                    return std::nullopt;
                }
                ++padding;
                continue;
            }
            if (padding != 0) {
                return std::nullopt; // a digit after padding
            }
            values[j] = digit(c);
            if (values[j] < 0) {
                return std::nullopt;
            }
        }
        const std::uint32_t triple =
            (static_cast<std::uint32_t>(values[0]) << 18) | (static_cast<std::uint32_t>(values[1]) << 12) |
            (static_cast<std::uint32_t>(values[2]) << 6) | static_cast<std::uint32_t>(values[3]);
        out.push_back(static_cast<std::uint8_t>((triple >> 16) & 0xFF));
        if (padding < 2) {
            out.push_back(static_cast<std::uint8_t>((triple >> 8) & 0xFF));
        }
        if (padding < 1) {
            out.push_back(static_cast<std::uint8_t>(triple & 0xFF));
        }
    }
    return out;
}

// The signed objects an RFC 2849 directory export carries, in file order.
//
// Returns nothing at all — not a partial answer — for text that is not LDIF, so
// the caller can fall back to treating the whole input as one published list.
// The grammar is what settles it: every record names a `dn`, and every other
// line is an attribute description followed by a colon.
std::vector<std::vector<std::uint8_t>> signedObjectsInLdif(const std::vector<std::uint8_t>& bytes)
{
    const auto isTypeStart = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    };
    // An attribute description is a type plus options: `pkdMasterListContent;binary`.
    // Numeric OIDs are legal types too, hence the dot.
    const auto isTypeChar = [&isTypeStart](char c) { return isTypeStart(c) || c == '-' || c == '.' || c == ';'; };

    bool sawDistinguishedName = false;
    std::vector<std::vector<std::uint8_t>> found;

    // One logical line at a time, with folding undone: RFC 2849 continues a
    // line by starting the next physical one with a single space. A 1.3 MB
    // value arrives as thousands of physical lines and one logical one.
    std::string logical;
    bool haveLogical = false;
    std::size_t at = 0;

    const auto consider = [&](const std::string& line) -> bool {
        if (line.empty() || line.front() == '#') {
            return true; // the record separator, and a comment
        }
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos || colon < 1 || !isTypeStart(line.front())) {
            return false; // no attribute description: this is not LDIF
        }
        for (std::size_t i = 1; i < colon; ++i) {
            if (!isTypeChar(line[i])) {
                return false;
            }
        }
        // Attribute types are case-insensitive, and this one is a gate on the
        // whole file: reading `DN` as some other attribute would answer "not a
        // directory export" about an export that is merely spelled differently.
        if (colon == 2 && (line[0] == 'd' || line[0] == 'D') && (line[1] == 'n' || line[1] == 'N')) {
            sawDistinguishedName = true;
        }
        // `::` is a base64 value, `:<` names a URL to fetch one from, and a
        // bare `:` is the value itself. Only the first can carry a signed
        // object: a URL is not content, and this agent does not follow one.
        if (colon + 1 >= line.size() || line[colon + 1] != ':') {
            return true;
        }
        std::string_view encoded{line};
        encoded.remove_prefix(colon + 2);
        while (!encoded.empty() && (encoded.front() == ' ' || encoded.front() == '\t')) {
            encoded.remove_prefix(1);
        }
        while (!encoded.empty() && (encoded.back() == ' ' || encoded.back() == '\t' || encoded.back() == '\r')) {
            encoded.remove_suffix(1);
        }
        auto decoded = decodeBase64(encoded);
        if (decoded && isSignedObject(*decoded)) {
            found.push_back(std::move(*decoded));
        }
        return true;
    };

    while (at <= bytes.size()) {
        std::size_t end = at;
        while (end < bytes.size() && bytes[end] != '\n') {
            ++end;
        }
        std::size_t stop = end;
        if (stop > at && bytes[stop - 1] == '\r') {
            --stop;
        }
        const char* first = reinterpret_cast<const char*>(bytes.data()) + at;
        const std::string_view physical{first, stop - at};

        if (!physical.empty() && physical.front() == ' ') {
            logical.append(physical.substr(1));
            haveLogical = true;
        } else {
            if (haveLogical && !consider(logical)) {
                return {};
            }
            logical.assign(physical);
            haveLogical = true;
        }
        if (end == bytes.size()) {
            break;
        }
        at = end + 1;
    }
    if (haveLogical && !consider(logical)) {
        return {};
    }
    if (!sawDistinguishedName) {
        return {}; // every LDIF record names a dn; without one this is other text
    }
    return found;
}

std::optional<SignerFingerprint> fingerprintFromHex(std::string_view hex)
{
    if (hex.size() != kSignerFingerprintSize * 2) {
        return std::nullopt;
    }
    SignerFingerprint out{};
    for (std::size_t i = 0; i < kSignerFingerprintSize; ++i) {
        int value = 0;
        for (std::size_t nibble = 0; nibble < 2; ++nibble) {
            const char c = hex[i * 2 + nibble];
            int digit = 0;
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else {
                return std::nullopt;
            }
            value = value * 16 + digit;
        }
        out[i] = static_cast<std::uint8_t>(value);
    }
    return out;
}

// The on-disk spelling of each refusal, so a state file stays readable by a
// person and survives a renumbering of the enum. A name this build does not
// know makes the whole state unreadable rather than being skipped — see
// AnchorCache::state.
struct RefusalName
{
    ImportRefusal reason;
    const char* name;
};
constexpr RefusalName kRefusalNames[] = {
    {ImportRefusal::NotAMasterList, "notAMasterList"},
    {ImportRefusal::Empty, "empty"},
    {ImportRefusal::Malformed, "malformed"},
    {ImportRefusal::BadSignature, "badSignature"},
    {ImportRefusal::SignerChanged, "signerChanged"},
    {ImportRefusal::Replayed, "replayed"},
    {ImportRefusal::CacheNotWritable, "cacheNotWritable"},
};

const char* refusalName(ImportRefusal reason) noexcept
{
    for (const RefusalName& entry : kRefusalNames) {
        if (entry.reason == reason) {
            return entry.name;
        }
    }
    return "notAMasterList";
}

std::optional<ImportRefusal> refusalFromName(std::string_view name)
{
    for (const RefusalName& entry : kRefusalNames) {
        if (name == entry.name) {
            return entry.reason;
        }
    }
    return std::nullopt;
}

// The fields of one comma-separated state-file value.
std::vector<std::string> commaFields(const std::string& value)
{
    std::vector<std::string> out;
    std::size_t at = 0;
    for (;;) {
        const std::size_t comma = value.find(',', at);
        if (comma == std::string::npos) {
            out.push_back(value.substr(at));
            return out;
        }
        out.push_back(value.substr(at, comma - at));
        at = comma + 1;
    }
}

} // namespace

std::string toHex(const SignerFingerprint& fingerprint)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(fingerprint.size() * 2);
    for (std::uint8_t b : fingerprint) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

AnchorCache::AnchorCache(fs::path dir) : m_dir(std::move(dir)) {}

AnchorState AnchorCache::state() const
{
    AnchorState out;
    std::ifstream in(m_dir / kStateFileName);
    if (!in) {
        return out; // no cache yet, or unreadable: the agent believes nothing
    }

    bool unreadable = false;
    // The single-signer spelling this file used before collections. Read so an
    // upgrade does not silently forget the publisher it was following: with the
    // pin gone the next list would be a trust-on-first-import, which is exactly
    // the state an attacker would like the store to be in.
    std::optional<SignerFingerprint> legacySigner;
    bool legacyPinned = false;
    std::optional<std::int64_t> legacySignedAt;
    bool legacySignedAtSeen = false;

    std::string line;
    while (std::getline(in, line)) {
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const std::string key = line.substr(0, eq);
        const std::string value = line.substr(eq + 1);
        if (key == "publisher") {
            // fingerprint, whether identity was established, and — when the
            // list carried one — the signing time. Three fields, because the
            // rotation rule and the replay rule both need this publisher's own.
            const std::vector<std::string> fields = commaFields(value);
            if (fields.size() < 2 || fields.size() > 3) {
                unreadable = true;
                continue;
            }
            auto fingerprint = fingerprintFromHex(fields[0]);
            if (!fingerprint || (fields[1] != "0" && fields[1] != "1")) {
                unreadable = true;
                continue;
            }
            AcceptedSigner signer;
            signer.fingerprint = *fingerprint;
            signer.identityEstablished = (fields[1] == "1");
            if (fields.size() == 3) {
                signer.signedAt = wholeInteger(fields[2]);
                if (!signer.signedAt) {
                    unreadable = true;
                    continue;
                }
            }
            out.signers.push_back(signer);
        } else if (key == "refused") {
            const std::vector<std::string> fields = commaFields(value);
            if (fields.empty() || fields.size() > 2) {
                unreadable = true;
                continue;
            }
            const auto reason = refusalFromName(fields[0]);
            if (!reason) {
                unreadable = true;
                continue;
            }
            RefusedList refused;
            refused.reason = *reason;
            if (fields.size() == 2 && fields[1] != "-") {
                refused.signer = fingerprintFromHex(fields[1]);
                if (!refused.signer) {
                    unreadable = true;
                    continue;
                }
            }
            out.refusedLists.push_back(refused);
        } else if (key == "signer") {
            legacySigner = fingerprintFromHex(value);
            if (!legacySigner) {
                unreadable = true;
            }
        } else if (key == "signerPinned") {
            legacyPinned = (value == "1");
        } else if (key == "anchors") {
            out.anchorCount = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (key == "issuers") {
            out.issuerCount = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (key == "offered") {
            out.listsOffered = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (key == "acceptedAt") {
            out.acceptedAt = static_cast<std::int64_t>(std::strtoll(value.c_str(), nullptr, 10));
        } else if (key == "signedAt") {
            // Legacy, and written only when the accepted list carried a date, so
            // ABSENT and UNREADABLE are different situations and only the first
            // is normal.
            legacySignedAt = wholeInteger(value);
            legacySignedAtSeen = true;
            if (!legacySignedAt) {
                unreadable = true;
            }
        } else if (key == "origin") {
            out.origin = value;
        }
    }

    if (out.signers.empty() && legacySigner) {
        AcceptedSigner signer;
        signer.fingerprint = *legacySigner;
        signer.identityEstablished = legacyPinned;
        signer.signedAt = legacySignedAtSeen ? legacySignedAt : std::nullopt;
        out.signers.push_back(signer);
        out.listsOffered = 1;
    }

    // A state file naming no publisher establishes nothing, so it is read as no
    // state at all rather than as a pin of all-zero bytes — which every list
    // would then fail to match, wedging the agent on a corrupt file.
    //
    // Anything PRESENT and unreadable is treated the same way, and for the
    // opposite reason: reading a mangled date as absent would quietly turn
    // replay refusal off, so a corrupt file would be a way to strip the
    // protection. Asking for the file again is the cheap end of that trade, and
    // the rule is applied to every field rather than only the dangerous one
    // because a file this code did not write is not a file to interpret.
    if (out.signers.empty() || unreadable) {
        return AnchorState{};
    }
    if (out.listsOffered < out.signers.size() + out.refusedLists.size()) {
        // The count has to be able to carry the records beside it. Anything
        // less was not written here.
        return AnchorState{};
    }
    out.present = true;
    return out;
}

fs::path AnchorCache::anchorsDirectory() const
{
    return m_dir / kAnchorsDirName;
}

std::vector<std::vector<std::uint8_t>> AnchorCache::anchors() const
{
    std::vector<fs::path> files;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(m_dir / kAnchorsDirName, ec)) {
        if (entry.is_regular_file(ec) && entry.path().extension() == kAnchorSuffix) {
            files.push_back(entry.path());
        }
    }
    // directory_iterator order is unspecified; the stored order is the list's
    // own, and it is the file names that carry it.
    std::sort(files.begin(), files.end());

    std::vector<std::vector<std::uint8_t>> out;
    out.reserve(files.size());
    for (const auto& file : files) {
        if (auto bytes = readFile(file)) {
            out.push_back(std::move(*bytes));
        }
    }
    return out;
}

bool AnchorCache::holdsAnchor() const
{
    std::error_code ec;
    // Constructed with an error_code, so a directory that is absent or cannot
    // be read yields nothing rather than throwing — and reads as "holds no
    // anchor", which is what the caller has to act on either way.
    for (const auto& entry : fs::directory_iterator(m_dir / kAnchorsDirName, ec)) {
        if (entry.is_regular_file(ec) && entry.path().extension() == kAnchorSuffix) {
            return true;
        }
    }
    return false;
}

bool AnchorCache::replace(const std::vector<std::vector<std::uint8_t>>& anchors, const AnchorState& state)
{
    std::error_code ec;
    const fs::path staging = m_dir / kAnchorsStagingName;
    const fs::path live = m_dir / kAnchorsDirName;

    fs::create_directories(m_dir, ec);
    if (ec) {
        return false;
    }
    fs::remove_all(staging, ec);
    if (ec || !fs::create_directory(staging, ec) || ec) {
        return false;
    }

    // Everything is written into a staging directory first, so a failure part
    // way through cannot leave a half-replaced trust store live.
    for (std::size_t i = 0; i < anchors.size(); ++i) {
        char name[32];
        std::snprintf(name, sizeof(name), "%06zu%s", i, kAnchorSuffix);
        if (!writeFile(staging / name, anchors[i])) {
            fs::remove_all(staging, ec);
            return false;
        }
    }

    fs::remove_all(live, ec);
    if (ec) {
        fs::remove_all(staging, ec);
        return false;
    }
    fs::rename(staging, live, ec);
    if (ec) {
        fs::remove_all(staging, ec);
        return false;
    }

    // The state file is written LAST. Until it lands the agent believes
    // nothing, which is the safe way for a torn import to end: better to have
    // to import again than to follow a signer whose anchors never arrived.
    std::string text;
    text += "anchors=" + std::to_string(state.anchorCount) + "\n";
    text += "issuers=" + std::to_string(state.issuerCount) + "\n";
    text += "offered=" + std::to_string(state.listsOffered) + "\n";
    text += "acceptedAt=" + std::to_string(state.acceptedAt) + "\n";
    text += "origin=" + state.origin + "\n";
    for (const AcceptedSigner& signer : state.signers) {
        text += "publisher=" + toHex(signer.fingerprint) + (signer.identityEstablished ? ",1" : ",0");
        if (signer.signedAt) {
            // Omitted, never written as a sentinel: a list that carries no date
            // and one signed at the epoch must not read back the same.
            text += "," + std::to_string(*signer.signedAt);
        }
        text += "\n";
    }
    for (const RefusedList& refused : state.refusedLists) {
        text += std::string{"refused="} + refusalName(refused.reason);
        text += refused.signer ? ("," + toHex(*refused.signer)) : std::string{",-"};
        text += "\n";
    }
    const std::vector<std::uint8_t> bytes(text.begin(), text.end());
    return writeFile(m_dir / kStateFileName, bytes);
}

std::vector<std::vector<std::uint8_t>> masterListsIn(const std::vector<std::uint8_t>& fileBytes)
{
    // One published list, handed over as it was published.
    if (isSignedObject(fileBytes)) {
        return {fileBytes};
    }
    // A master list is binary and full of zero octets; a directory export is
    // text. Settling that here stops a stray 0x0A inside DER from being read as
    // a line break, and answers the common case without walking the file twice.
    if (std::find(fileBytes.begin(), fileBytes.end(), std::uint8_t{0}) != fileBytes.end()) {
        return {};
    }
    return signedObjectsInLdif(fileBytes);
}

std::expected<AnchorState, Refusal> importMasterList(const std::vector<std::uint8_t>& der, AnchorCache& cache,
                                                     std::int64_t now)
{
    const AnchorState prior = cache.state();

    // The anchors a rotation may be judged against, read ONCE and BEFORE
    // anything is written. Judging a new signer against anchors carried by the
    // file being imported would be circular: an attacker signs a list of his
    // own anchors with a key he issued from one of them, and it comes out
    // internally consistent every time. Fixing the set here also makes the
    // outcome independent of the order the lists appear in, so no list in a
    // collection can vouch for a signer of another list beside it.
    const std::vector<std::vector<std::uint8_t>> vouchingAnchors =
        prior.present ? cache.anchors() : std::vector<std::vector<std::uint8_t>>{};

    // What the file carries. When it is neither of the two shapes masterListsIn
    // knows, the whole input is offered as the single candidate so the refusal
    // names what is wrong with the BYTES rather than with the container.
    std::vector<std::vector<std::uint8_t>> lists = masterListsIn(der);
    if (lists.empty()) {
        lists.push_back(der);
    }

    // Why one list did not make it, with as much as could be read about it. Held
    // separately from Refusal because a per-list refusal is not the import's
    // outcome: twenty-seven of these beside one acceptance is still an
    // acceptance.
    struct ListRefusal
    {
        ImportRefusal reason{ImportRefusal::NotAMasterList};
        std::optional<SignerFingerprint> signer;
        std::optional<std::int64_t> seenSignedAt;
        std::optional<std::int64_t> trustedSignedAt;
    };

    // Whether @p incoming may replace what has already been accepted FROM ITS
    // OWN SIGNER, on the ground of WHEN it was signed. The rule, one line per
    // case:
    //
    //   recorded   incoming   outcome
    //   dated      dated      accept only if STRICTLY newer
    //   dated      undated    REFUSE
    //   undated    dated      accept
    //   undated    undated    accept
    //
    // Row two is the asymmetric one and it is the whole point. signingTime is
    // OPTIONAL in CMS, so refusing every undated list would turn the feature off
    // for a publisher that does not date its lists — while letting an undated
    // list replace a dated one would hand an attacker a way to STRIP a
    // protection this installation already had, and every later rollback with
    // it. So: never refuse for a property the ecosystem may not provide, and
    // never let one be taken away.
    //
    // Strictly newer, not merely not-older. Two lists signed at the same instant
    // are the same statement as far as anything here can tell, and re-installing
    // one buys nothing that would justify accepting an attacker's copy.
    //
    // Per signer, because that is the only comparison that means anything: one
    // country's list being older than another country's is not a rollback, and
    // measuring across publishers would refuse whichever of them publishes least
    // often.
    const auto replayRefusal = [&](const lm::VerifiedMasterList& incoming) -> std::optional<ListRefusal> {
        const AcceptedSigner* record = prior.recordFor(incoming.signerSpkiSha256);
        if (record == nullptr || !record->signedAt) {
            return std::nullopt;
        }
        const std::optional<std::int64_t> offered = incoming.signingTimeEpochSeconds;
        if (offered && *offered > *record->signedAt) {
            return std::nullopt;
        }
        return ListRefusal{ImportRefusal::Replayed, incoming.signerSpkiSha256, offered, record->signedAt};
    };

    // One list, verified against its own signer and measured against the record
    // held for that signer. Everything this decides is about THIS list; nothing
    // it learns is carried to the next one.
    const auto judge =
        [&](const std::vector<std::uint8_t>& list) -> std::expected<lm::VerifiedMasterList, ListRefusal> {
        auto seen = lm::parseAndVerifyMasterList(list, nullptr);
        if (!seen) {
            return std::unexpected(ListRefusal{refusalFor(seen.error()), std::nullopt, std::nullopt, std::nullopt});
        }
        if (!prior.present) {
            // Trust on first import: there is nothing to check a first file
            // against, so whoever signed each list becomes a record and
            // identityEstablished says nothing was compared.
            if (auto refusal = replayRefusal(*seen)) {
                return std::unexpected(*refusal);
            }
            return std::move(*seen);
        }

        std::optional<lm::VerifiedMasterList> chosen;
        if (prior.recordFor(seen->signerSpkiSha256) != nullptr) {
            chosen = std::move(*seen);
        } else {
            // The unpinned call reports the FIRST SignerInfo in the object's own
            // encoded order, and SignerInfos are a DER SET OF — so a publisher
            // the agent does follow may be sitting behind one it does not.
            // Asking with each recorded fingerprint in turn is the only way to
            // find out, and it is what the single-signer form of this has always
            // done. Reached only when the first signer is unrecorded.
            for (const AcceptedSigner& record : prior.signers) {
                auto pinned = lm::parseAndVerifyMasterList(list, &record.fingerprint);
                if (pinned) {
                    chosen = std::move(*pinned);
                    break;
                }
            }
        }
        if (!chosen) {
            // The rotation rule, per publisher. A country that has rotated its
            // key is followed automatically when the certificate that SIGNED
            // this list chains to an anchor the previous import carried.
            //
            // The certificate is the one the verification resolved, so "it
            // signed this list" needs no separate proof — that is what made it
            // the signer. Handing the path build some other certificate that
            // merely chains would let a stranger ride in behind any certificate
            // the authority ever issued.
            if (!lm::signerChainsToAnyAnchor(seen->signerCertDer, vouchingAnchors)) {
                return std::unexpected(
                    ListRefusal{ImportRefusal::SignerChanged, seen->signerSpkiSha256, std::nullopt, std::nullopt});
            }
            chosen = std::move(*seen);
        }
        if (auto refusal = replayRefusal(*chosen)) {
            return std::unexpected(*refusal);
        }
        return std::move(*chosen);
    };

    // Pass one: every list judged on its own. The verified ones are kept whole
    // rather than folded straight into the store, because the bar below is a
    // property of the WHOLE file and cannot be applied while walking it.
    std::vector<lm::VerifiedMasterList> admitted;
    std::vector<RefusedList> refusedLists;
    std::optional<ListRefusal> firstRefusal;

    for (const std::vector<std::uint8_t>& list : lists) {
        auto verified = judge(list);
        if (!verified) {
            refusedLists.push_back(RefusedList{verified.error().reason, verified.error().signer});
            if (!firstRefusal) {
                firstRefusal = verified.error();
            }
            continue;
        }
        admitted.push_back(std::move(*verified));
    }

    // THE BAR FOR A SIGNER THERE IS NO RECORD OF, and the reason the replay rule
    // survives a key rotation.
    //
    // A signer admitted by the rotation rule is by definition one this agent has
    // never seen, so the per-signer comparison above has nothing to measure it
    // against — and without a second bar a publisher could rotate its key and
    // hand back a list from years ago, which is the rollback the whole rule
    // exists to refuse. The bar is the newest date among the publishers this
    // import DISPLACES: those on record whose list is not in this file at all.
    //
    // That is the honest comparison and not a store-wide one. A publisher's old
    // key is exactly what a rotation displaces, so its date is exactly what the
    // new key has to beat; a country that publishes rarely is not measured
    // against a country that publishes often, because a publisher still present
    // in the file displaces nobody. Undated records impose no bar — never refuse
    // for a property the ecosystem may not provide.
    std::optional<std::int64_t> displacedAt;
    if (prior.present) {
        for (const AcceptedSigner& record : prior.signers) {
            if (!record.signedAt) {
                continue;
            }
            const bool stillPublishing =
                std::any_of(admitted.begin(), admitted.end(), [&record](const lm::VerifiedMasterList& v) {
                    return v.signerSpkiSha256 == record.fingerprint;
                });
            if (stillPublishing) {
                continue;
            }
            if (!displacedAt || *record.signedAt > *displacedAt) {
                displacedAt = record.signedAt;
            }
        }
    }

    // Pass two, and it can only ever remove: every signer it measures was
    // unrecorded, so no record it read in pass one can move under it. That is
    // what keeps this one sweep rather than a fixed point, and what keeps the
    // outcome independent of the order the lists appear in.
    std::vector<AcceptedSigner> signers;
    std::vector<std::vector<std::uint8_t>> anchors;
    std::set<std::vector<std::uint8_t>> alreadyHeld;

    for (lm::VerifiedMasterList& verified : admitted) {
        if (displacedAt && prior.recordFor(verified.signerSpkiSha256) == nullptr) {
            const std::optional<std::int64_t> offered = verified.signingTimeEpochSeconds;
            if (!offered || *offered <= *displacedAt) {
                const ListRefusal refusal{ImportRefusal::Replayed, verified.signerSpkiSha256, offered, displacedAt};
                refusedLists.push_back(RefusedList{refusal.reason, refusal.signer});
                if (!firstRefusal) {
                    firstRefusal = refusal;
                }
                continue;
            }
        }

        // One record per PUBLISHER, not per list: two lists in one file may
        // share a signer, and the record has to bound what may follow BOTH of
        // them, so the later of their dates is the one kept.
        AcceptedSigner* existing = nullptr;
        for (AcceptedSigner& candidate : signers) {
            if (candidate.fingerprint == verified.signerSpkiSha256) {
                existing = &candidate;
                break;
            }
        }
        if (existing != nullptr) {
            if (verified.signingTimeEpochSeconds &&
                (!existing->signedAt || *verified.signingTimeEpochSeconds > *existing->signedAt)) {
                existing->signedAt = verified.signingTimeEpochSeconds;
            }
        } else {
            signers.push_back(
                AcceptedSigner{verified.signerSpkiSha256, prior.present, verified.signingTimeEpochSeconds});
        }

        // The union, in the order the file presents it, with exact repeats
        // collapsed. The lists in a real collection overlap heavily — one
        // download carries the same certificate from a dozen countries — and
        // storing each repetition would multiply the store several times over
        // without adding a single anchor. Repeats are collapsed on the encoded
        // BYTES and on nothing cleverer: two encodings of one certificate are
        // two anchors here, which costs a file and cannot lose one.
        for (std::vector<std::uint8_t>& anchor : verified.anchors) {
            if (alreadyHeld.insert(anchor).second) {
                anchors.push_back(std::move(anchor));
            }
        }
    }

    if (signers.empty()) {
        // Nothing was admitted, so nothing is stored and the store is untouched.
        const ListRefusal first =
            firstRefusal.value_or(ListRefusal{ImportRefusal::NotAMasterList, std::nullopt, std::nullopt, std::nullopt});
        Refusal out;
        out.reason = first.reason;
        // A fingerprint is shown only when there is ONE to show. Naming one
        // publisher out of a collection of them would read as a statement about
        // the file, which it is not.
        out.seenSigner = (lists.size() == 1) ? first.signer : std::nullopt;
        out.trustedSigner = (prior.present && prior.signers.size() == 1)
                                ? std::optional{prior.signers.front().fingerprint}
                                : std::nullopt;
        out.seenSignedAt = first.seenSignedAt;
        out.trustedSignedAt = first.trustedSignedAt;
        out.listsOffered = static_cast<std::uint32_t>(lists.size());
        return std::unexpected(out);
    }

    AnchorState next;
    next.present = true;
    next.signers = std::move(signers);
    next.anchorCount = static_cast<std::uint32_t>(anchors.size());
    next.issuerCount = countIssuers(anchors);
    next.listsOffered = static_cast<std::uint32_t>(lists.size());
    next.refusedLists = std::move(refusedLists);
    next.acceptedAt = now;
    next.origin = "import";
    if (!cache.replace(anchors, next)) {
        Refusal out;
        out.reason = ImportRefusal::CacheNotWritable;
        out.seenSigner = (next.signers.size() == 1) ? std::optional{next.signers.front().fingerprint} : std::nullopt;
        out.trustedSigner = (prior.present && prior.signers.size() == 1)
                                ? std::optional{prior.signers.front().fingerprint}
                                : std::nullopt;
        out.listsOffered = next.listsOffered;
        return std::unexpected(out);
    }
    return next;
}

fs::path publishAnchorDirectory(LibreSCRS::Plugin::CardPluginService& plugins, const fs::path& cacheDir)
{
    // Built through AnchorCache rather than by joining "anchors" here: the
    // cache owns its own layout, and a second spelling of it is exactly the
    // kind of near-agreement that reads as working until the day it does not.
    const AnchorCache cache{cacheDir};
    const fs::path dir = cache.anchorsDirectory();

    // The DIRECTORY, not its contents, and it is published whether or not it
    // exists yet. A person who imports a master list after the agent started
    // has to be believed by the next document read without a restart, and an
    // absent directory is answered "no anchors" by the reader on the other
    // side — which is the truth until the import lands.
    plugins.setCscaAnchorDirectory(dir);
    return dir;
}

bool AnchorCache::forget()
{
    // Each removal is judged on its own error_code rather than on the return
    // value: remove_all answers 0 both for "removed nothing because it was not
    // there" and, without the code, for a failure -- and the first of those is
    // success here.
    bool ok = true;
    for (const char* owned : {kAnchorsDirName, kAnchorsStagingName, kStateFileName}) {
        std::error_code ec;
        fs::remove_all(m_dir / owned, ec);
        if (ec) {
            log::warnf("country signing anchors: could not remove {}: {}", (m_dir / owned).string(), ec.message());
            ok = false;
        }
    }
    return ok;
}

void discardStaleAnchorReport(Config::ConfigStore& config)
{
    if (!config.cscaAnchorState()) {
        return; // nothing recorded, so there is no claim to be wrong about
    }
    const AnchorCache cache{fs::path{config.cscaCacheDir()}};
    const bool anchorsHeld = cache.holdsAnchor();
    // Reads false for an absent, unreadable or corrupt state file alike — every
    // one of which is the cache saying it establishes no signer, which is the
    // thing the report would otherwise keep claiming.
    const bool signerHeld = cache.state().present;
    if (anchorsHeld && signerHeld) {
        return;
    }
    log::warnf("country signing anchors: the recorded report is not borne out by the cache (anchors held={}, pinned "
               "signer held={}); discarding the report — nothing in the cache is touched by this",
               anchorsHeld, signerHeld);
    // Reset rather than a record of zeros, for the reason in the header. fromDbus
    // is false: the key is ReadOnly on the wire and this is the agent clearing
    // its own state, the same standing recordCscaAnchorState writes it under.
    (void)config.resetKey("CscaAnchorState", /*fromDbus=*/false);
}

std::optional<ForgottenAnchors> forgetCscaAnchors(Config::ConfigStore& config)
{
    AnchorCache cache{fs::path{config.cscaCacheDir()}};

    // Measured BEFORE anything is removed: afterwards there is nothing left to
    // read it from, and the caller has to be able to say what went.
    const AnchorState held = cache.state();
    ForgottenAnchors forgotten;
    forgotten.anchors = held.anchorCount;
    forgotten.hadPinnedSigner = held.present && !held.signers.empty();

    if (!cache.forget()) {
        // The report is left exactly as it was, deliberately: with anchors
        // still on disk it is the only thing describing them, and clearing it
        // here would produce the one inconsistent state nothing detects.
        return std::nullopt;
    }

    // Only now. See this function's header for why this order and not the
    // other one.
    (void)config.resetKey("CscaAnchorState", /*fromDbus=*/false);
    log::infof("country signing anchors: forgot {} anchor(s){}", forgotten.anchors,
               forgotten.hadPinnedSigner ? "; the agent now follows no publisher" : "");
    return forgotten;
}

} // namespace LibreSCRS::Agent::Trust
