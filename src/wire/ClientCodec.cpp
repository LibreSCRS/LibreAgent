// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Client-role (de)serialization over the Cbor seam: the inverse of
// Messages.cpp. parseReply/parseEvent are the untrusted inbound path (the
// agent could be a newer/older build); encodeRequest is the trusted
// outbound path, and reuses Messages.h's existing toCbor(RequestEnvelope)
// rather than re-implementing canonical encoding.
#include <LibreSCRS/Agent/wire/ClientCodec.h>

#include <limits>
#include <utility>

namespace LibreSCRS::Agent::Wire {
namespace {

using Map = CborValue::Map;
using Array = CborValue::Array;
using Bytes = CborValue::Bytes;

// --- generic field access, tracking an overall ok/malformed flag ------------
// Each accessor marks the reader malformed (ok() becomes false) when a
// REQUIRED field is missing or has the wrong CBOR type, or when a present
// OPTIONAL field has the wrong type. An absent optional field is not an
// error: it leaves ok() untouched and returns std::nullopt. Callers must
// check ok() before dereferencing any pointer-returning accessor (map/array)
// and before trusting any value-returning accessor.
class FieldReader
{
public:
    explicit FieldReader(const Map& m) noexcept : m_m(m) {}

    [[nodiscard]] bool ok() const noexcept
    {
        return m_ok;
    }

    std::string text(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            m_ok = false;
            return {};
        }
        const auto* s = it->second.asText();
        if (s == nullptr) {
            m_ok = false;
            return {};
        }
        return *s;
    }
    std::optional<std::string> optText(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            return std::nullopt;
        }
        const auto* s = it->second.asText();
        if (s == nullptr) {
            m_ok = false;
            return std::nullopt;
        }
        return *s;
    }
    std::uint64_t uint(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            m_ok = false;
            return 0;
        }
        const auto v = it->second.asUInt();
        if (!v) {
            m_ok = false;
            return 0;
        }
        return *v;
    }
    std::optional<std::uint64_t> optUint(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            return std::nullopt;
        }
        const auto v = it->second.asUInt();
        if (!v) {
            m_ok = false;
            return std::nullopt;
        }
        return *v;
    }
    // A uint field bounded to fit std::uint32_t (e.g. bitmasks / counters).
    std::uint32_t u32(std::string_view k)
    {
        const auto v = uint(k);
        if (v > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
            m_ok = false;
            return 0;
        }
        return static_cast<std::uint32_t>(v);
    }
    // An optional uint field bounded to fit int (CredentialRecord's counters).
    std::optional<int> optInt(std::string_view k)
    {
        const auto v = optUint(k);
        if (!v) {
            return std::nullopt;
        }
        if (*v > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
            m_ok = false;
            return std::nullopt;
        }
        return static_cast<int>(*v);
    }
    bool boolean(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            m_ok = false;
            return false;
        }
        const auto v = it->second.asBool();
        if (!v) {
            m_ok = false;
            return false;
        }
        return *v;
    }
    std::optional<bool> optBool(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            return std::nullopt;
        }
        const auto v = it->second.asBool();
        if (!v) {
            m_ok = false;
            return std::nullopt;
        }
        return *v;
    }
    std::optional<double> optDouble(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            return std::nullopt;
        }
        const auto v = it->second.asDouble();
        if (!v) {
            m_ok = false;
            return std::nullopt;
        }
        return *v;
    }
    Bytes bytes(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            m_ok = false;
            return {};
        }
        const auto* b = it->second.asBytes();
        if (b == nullptr) {
            m_ok = false;
            return {};
        }
        return *b;
    }
    const Map* map(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            m_ok = false;
            return nullptr;
        }
        const auto* mm = it->second.asMap();
        if (mm == nullptr) {
            m_ok = false;
            return nullptr;
        }
        return mm;
    }
    const Array* array(std::string_view k)
    {
        const auto it = m_m.find(k);
        if (it == m_m.end()) {
            m_ok = false;
            return nullptr;
        }
        const auto* a = it->second.asArray();
        if (a == nullptr) {
            m_ok = false;
            return nullptr;
        }
        return a;
    }

private:
    const Map& m_m;
    bool m_ok{true};
};

bool has(const Map& m, std::string_view k)
{
    return m.find(k) != m.end();
}

// Map::find is a heterogeneous-lookup TEMPLATE (CanonicalKeyLess::is_transparent);
// deducing its K from a raw string LITERAL argument is not the same well-trodden
// path as passing an already-typed std::string_view (what every other lookup in
// this file, and Messages.cpp's fText/fUint/etc., do). Route every by-value
// lookup through this std::string_view-typed helper instead of calling
// `m.find("literal")` directly, so the argument is always string_view before it
// reaches the template.
const CborValue* findKey(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    return it == m.end() ? nullptr : &it->second;
}

std::optional<std::vector<std::string>> textArray(const Array& a)
{
    std::vector<std::string> out;
    out.reserve(a.size());
    for (const auto& e : a) {
        const auto* s = e.asText();
        if (s == nullptr) {
            return std::nullopt;
        }
        out.push_back(*s);
    }
    return out;
}

// --- closed-enum token <-> wire value mapping (decode direction) ------------

std::optional<ErrorCode> decodeErrorCode(std::uint64_t v)
{
    // ErrorCode (ErrorCode.h) is WIRE-FROZEN APPEND-ONLY: new codes are only
    // ever appended with the next free value, never renumbered. A NEWER agent
    // may therefore send a value past this build's InvalidDocument=19 -- that
    // is not malformed, it is this build simply not knowing the name yet. The
    // enum's underlying type is uint32_t, so every value that fits uint32 is a
    // well-defined ErrorCode; only reject a value too wide for the wire field
    // to ever carry (mirrors u32()'s width check above). This tolerance is
    // ErrorCode-SPECIFIC: OperationStatus, OperationPhase, QuiesceReason and
    // PreReadAuth below stay fail-closed on an unrecognised value, because
    // those are semantically-branching closed enums, not opaque display data.
    if (v > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::nullopt;
    }
    return static_cast<ErrorCode>(static_cast<std::uint32_t>(v));
}

std::optional<SyncError> decodeSyncError(const std::string& s)
{
    static constexpr SyncError kAll[] = {
        SyncError::UnknownCard,
        SyncError::KeyNotFound,
        SyncError::NotAuthorized,
        SyncError::UserNotLoggedIn,
        SyncError::UnknownConfigKey,
        SyncError::ReadOnlyConfig,
        SyncError::InvalidConfigValue,
        SyncError::UnsupportedProtocol,
        SyncError::AuthFailed,
        SyncError::CommunicationError,
        SyncError::NotSupported,
        SyncError::UnsupportedOnThisCard,
        SyncError::UnsupportedSignatureParameter,
        SyncError::InputTooLarge,
        SyncError::RateLimited,
        SyncError::UnknownCredential,
        SyncError::InvalidRequest,
    };
    for (const auto e : kAll) {
        if (syncErrorName(e) == s) {
            return e;
        }
    }
    return std::nullopt;
}

std::optional<CredentialOutcome> decodeCredOutcome(const std::string& s)
{
    if (s == "unspecified") {
        return CredentialOutcome::Unspecified;
    }
    if (s == "ok") {
        return CredentialOutcome::Ok;
    }
    if (s == "userCancelled") {
        return CredentialOutcome::UserCancelled;
    }
    if (s == "missingFields") {
        return CredentialOutcome::MissingFields;
    }
    if (s == "invalidPin") {
        return CredentialOutcome::InvalidPin;
    }
    if (s == "blocked") {
        return CredentialOutcome::Blocked;
    }
    if (s == "pluginError") {
        return CredentialOutcome::PluginError;
    }
    if (s == "unsupported") {
        return CredentialOutcome::Unsupported;
    }
    if (s == "keyActivationFailed") {
        return CredentialOutcome::KeyActivationFailed;
    }
    if (s == "cardRemoved") {
        return CredentialOutcome::CardRemoved;
    }
    return std::nullopt;
}

// --- shared sub-type decoders -------------------------------------------------

std::optional<ReaderState> decodeReaderState(const Map& m)
{
    FieldReader r(m);
    ReaderState rs;
    rs.handle = r.text("handle");
    rs.name = r.text("name");
    rs.hasCard = r.boolean("hasCard");
    rs.card = r.optText("card");
    if (!r.ok()) {
        return std::nullopt;
    }
    return rs;
}

std::optional<CardState> decodeCardState(const Map& m)
{
    FieldReader r(m);
    CardState cs;
    cs.handle = r.text("handle");
    cs.reader = r.text("reader");
    cs.caps = r.u32("caps");
    const auto preAuthRaw = r.uint("preAuth");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (preAuthRaw > static_cast<std::uint64_t>(PreReadAuth::PaceCan)) {
        return std::nullopt;
    }
    cs.preAuth = static_cast<PreReadAuth>(preAuthRaw);
    return cs;
}

std::optional<CertField> decodeCertField(const Array& a)
{
    if (a.size() != 3) {
        return std::nullopt;
    }
    const auto* labelKey = a[0].asText();
    const auto* labelFallback = a[1].asText();
    const auto* value = a[2].asText();
    if (labelKey == nullptr || labelFallback == nullptr || value == nullptr) {
        return std::nullopt;
    }
    return CertField{*labelKey, *labelFallback, *value};
}

std::optional<CertInfo> decodeCertInfo(const Map& m)
{
    FieldReader r(m);
    CertInfo ci;
    ci.certId = r.text("certId");
    ci.signingCapable = r.boolean("signingCapable");
    const Map* fields = r.map("fields");
    ci.keyUsageBits = r.u32("keyUsageBits");
    const Array* ekus = r.array("ekus");
    const Array* chainSubjectCns = r.array("chainSubjectCns");
    ci.trustStatus = r.u32("trustStatus");
    if (!r.ok()) {
        return std::nullopt;
    }
    for (const auto& [group, groupVal] : *fields) {
        const auto* inner = groupVal.asMap();
        if (inner == nullptr) {
            return std::nullopt;
        }
        std::map<std::string, CertField> cells;
        for (const auto& [fieldKey, fieldVal] : *inner) {
            const auto* tuple = fieldVal.asArray();
            if (tuple == nullptr) {
                return std::nullopt;
            }
            auto cell = decodeCertField(*tuple);
            if (!cell) {
                return std::nullopt;
            }
            cells.emplace(fieldKey, std::move(*cell));
        }
        ci.fields.emplace(group, std::move(cells));
    }
    auto ekuList = textArray(*ekus);
    if (!ekuList) {
        return std::nullopt;
    }
    ci.ekus = std::move(*ekuList);
    auto cnList = textArray(*chainSubjectCns);
    if (!cnList) {
        return std::nullopt;
    }
    ci.chainSubjectCns = std::move(*cnList);
    return ci;
}

std::optional<SignMeta> decodeSignMeta(const Map& m)
{
    FieldReader r(m);
    SignMeta sm;
    sm.format = r.text("format");
    sm.level = r.text("level");
    sm.tsaUsed = r.boolean("tsaUsed");
    sm.chainComplete = r.boolean("chainComplete");
    if (!r.ok()) {
        return std::nullopt;
    }
    return sm;
}

// sign-result = { kind: "Sign", artifact: fd-index, meta: sign-meta } — shared
// by the sign-recovery reply arm and the Sign op-result-ready payload. The
// artifact fd-index must resolve within the frame's fd vector; out of range
// is malformed.
std::optional<SignResult> decodeSignResultFields(const Map& m, std::span<const int> fds)
{
    FieldReader r(m);
    const auto kind = r.text("kind");
    const auto artifact = r.uint("artifact");
    const Map* metaMap = r.map("meta");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (kind != "Sign") {
        return std::nullopt;
    }
    if (artifact >= fds.size()) {
        return std::nullopt;
    }
    auto meta = decodeSignMeta(*metaMap);
    if (!meta) {
        return std::nullopt;
    }
    return SignResult{artifact, std::move(*meta)};
}

std::optional<PhotoItem> decodePhotoItem(const Map& m, std::span<const int> fds)
{
    FieldReader r(m);
    auto key = r.text("key");
    const auto fd = r.uint("fd");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (fd >= fds.size()) {
        return std::nullopt;
    }
    return PhotoItem{std::move(key), fd};
}

std::optional<IdentityField> decodeIdField(const Array& a)
{
    if (a.size() != 4) {
        return std::nullopt;
    }
    const auto* labelKey = a[0].asText();
    const auto* labelFallback = a[1].asText();
    const auto* type = a[2].asText();
    if (labelKey == nullptr || labelFallback == nullptr || type == nullptr) {
        return std::nullopt;
    }
    if (const auto* s = a[3].asText()) {
        return IdentityField{*labelKey, *labelFallback, *type, std::string(*s)};
    }
    if (const auto* b = a[3].asBytes()) {
        return IdentityField{*labelKey, *labelFallback, *type, *b};
    }
    return std::nullopt;
}

std::optional<CredentialOpResult> decodeCredOpResult(const Map& m)
{
    FieldReader r(m);
    auto outcomeStr = r.text("outcome");
    const auto retriesLeft = r.optInt("retriesLeft");
    const auto blocked = r.boolean("blocked");
    const auto pinActivated = r.optBool("pinActivated");
    const auto keyActivated = r.optBool("keyActivated");
    if (!r.ok()) {
        return std::nullopt;
    }
    const auto outcome = decodeCredOutcome(outcomeStr);
    if (!outcome) {
        return std::nullopt;
    }
    CredentialOpResult cr;
    cr.outcome = *outcome;
    cr.retriesLeft = retriesLeft;
    cr.blocked = blocked;
    cr.pinActivated = pinActivated;
    cr.keyActivated = keyActivated;
    return cr;
}

// cred-record: 12 required + 11 optional keys (CDDL:220-228). The four
// enum-shaped fields (kind/state/unblockStyle/recovery) stay plain strings on
// this mirror type (Messages.h's CredentialRecord, see CredentialWire.h), so
// the codec copies the wire token through unvalidated against the closed
// CDDL set — exactly mirroring how the agent's own encodeCredRecord() writes
// them verbatim without an enum either. This keeps the client tolerant of a
// future cred-kind/-state/-unblockStyle/-recovery token it doesn't render.
std::optional<CredentialRecord> decodeCredentialRecord(const Map& m)
{
    FieldReader r(m);
    CredentialRecord rec;
    rec.id = r.text("id");
    rec.label = r.text("label");
    rec.kind = r.text("kind");
    rec.state = r.text("state");
    rec.retriesLeft = r.optInt("retriesLeft");
    rec.retriesMax = r.optInt("retriesMax");
    rec.usesLeft = r.optInt("usesLeft");
    rec.usesMax = r.optInt("usesMax");
    rec.unblocksLeft = r.optInt("unblocksLeft");
    rec.minLength = r.optInt("minLength");
    rec.maxLength = r.optInt("maxLength");
    rec.canChange = r.boolean("canChange");
    rec.unblockable = r.boolean("unblockable");
    rec.unblockStyle = r.text("unblockStyle");
    rec.activatable = r.boolean("activatable");
    rec.keyActivationPending = r.boolean("keyActivationPending");
    rec.keyActivatable = r.boolean("keyActivatable");
    rec.recovery = r.text("recovery");
    rec.probeSafe = r.boolean("probeSafe");
    rec.blockedGuidanceKey = r.optText("blockedGuidanceKey");
    rec.blockedGuidanceFallback = r.optText("blockedGuidanceFallback");
    rec.keyActivationGuidanceKey = r.optText("keyActivationGuidanceKey");
    rec.keyActivationGuidanceFallback = r.optText("keyActivationGuidanceFallback");
    if (!r.ok()) {
        return std::nullopt;
    }
    return rec;
}

// --- reply arm decoders --------------------------------------------------------

std::optional<HelloAck> decodeHelloAck(const Map& m)
{
    FieldReader r(m);
    auto agentVer = r.text("agentVer");
    const Array* featuresArr = r.array("features");
    if (!r.ok()) {
        return std::nullopt;
    }
    auto features = textArray(*featuresArr);
    if (!features) {
        return std::nullopt;
    }
    return HelloAck{std::move(agentVer), std::move(*features)};
}

std::optional<OpStarted> decodeOpStarted(const Map& m)
{
    FieldReader r(m);
    const auto op = r.uint("op");
    if (!r.ok()) {
        return std::nullopt;
    }
    return OpStarted{op};
}

std::optional<StateReply> decodeStateReply(const Map& m)
{
    FieldReader r(m);
    const Array* readersArr = r.array("readers");
    const Array* cardsArr = r.array("cards");
    if (!r.ok()) {
        return std::nullopt;
    }
    StateReply sr;
    sr.readers.reserve(readersArr->size());
    for (const auto& item : *readersArr) {
        const auto* rm = item.asMap();
        if (rm == nullptr) {
            return std::nullopt;
        }
        auto rs = decodeReaderState(*rm);
        if (!rs) {
            return std::nullopt;
        }
        sr.readers.push_back(std::move(*rs));
    }
    sr.cards.reserve(cardsArr->size());
    for (const auto& item : *cardsArr) {
        const auto* cm = item.asMap();
        if (cm == nullptr) {
            return std::nullopt;
        }
        auto cs = decodeCardState(*cm);
        if (!cs) {
            return std::nullopt;
        }
        sr.cards.push_back(std::move(*cs));
    }
    return sr;
}

std::optional<CertListReply> decodeCertListReply(const Map& m)
{
    FieldReader r(m);
    const Array* certsArr = r.array("certs");
    if (!r.ok()) {
        return std::nullopt;
    }
    CertListReply out;
    out.certs.reserve(certsArr->size());
    for (const auto& item : *certsArr) {
        const auto* cm = item.asMap();
        if (cm == nullptr) {
            return std::nullopt;
        }
        auto ci = decodeCertInfo(*cm);
        if (!ci) {
            return std::nullopt;
        }
        out.certs.push_back(std::move(*ci));
    }
    return out;
}

std::optional<CertDerReply> decodeCertDerReply(const Map& m)
{
    FieldReader r(m);
    auto der = r.bytes("der");
    if (!r.ok()) {
        return std::nullopt;
    }
    return CertDerReply{std::move(der)};
}

// public-key = ( kty: "RSA", n, e // kty: "EC", crv, x, y ) — the one
// genuinely structurally-ambiguous reply pair on this wire: both arms share
// the "kty" key, discriminated by its VALUE, not by key presence. An
// unrecognised kty value is malformed (this reply-ok arm is already
// selected by the caller via the "kty" key's mere presence), not a
// forward-compat UnknownReply escape.
std::optional<PublicKeyReply> decodePublicKeyReply(const Map& m)
{
    FieldReader kr(m);
    const auto kty = kr.text("kty");
    if (!kr.ok()) {
        return std::nullopt;
    }
    if (kty == "RSA") {
        FieldReader r(m);
        auto n = r.bytes("n");
        auto e = r.bytes("e");
        if (!r.ok()) {
            return std::nullopt;
        }
        return PublicKeyReply{RsaPublicKey{std::move(n), std::move(e)}};
    }
    if (kty == "EC") {
        FieldReader r(m);
        auto crv = r.text("crv");
        auto x = r.bytes("x");
        auto y = r.bytes("y");
        if (!r.ok()) {
            return std::nullopt;
        }
        return PublicKeyReply{EcPublicKey{std::move(crv), std::move(x), std::move(y)}};
    }
    return std::nullopt;
}

std::optional<ConfigReply> decodeConfigReply(const Map& m)
{
    FieldReader r(m);
    const Map* entries = r.map("entries");
    if (!r.ok()) {
        return std::nullopt;
    }
    ConfigReply out;
    for (const auto& [k, v] : *entries) {
        out.entries.emplace(k, v);
    }
    return out;
}

std::optional<AckReply> decodeAckReply(const Map& m)
{
    FieldReader r(m);
    const auto ok = r.boolean("ok");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (!ok) { // ack = ( ok: true ) is a literal, not a bool type
        return std::nullopt;
    }
    return AckReply{};
}

std::optional<RawSignatureReply> decodeRawSignatureReply(const Map& m)
{
    FieldReader r(m);
    auto sig = r.bytes("sig");
    if (!r.ok()) {
        return std::nullopt;
    }
    return RawSignatureReply{std::move(sig)};
}

// err-info = { ( code: error-code // name: sync-error ), ? msgKey, ? msgFallback }
// (CDDL:105-113): exactly one of code/name, never both, never neither.
std::optional<ErrInfo> decodeErrInfo(const Map& m)
{
    const bool hasCode = has(m, "code");
    const bool hasName = has(m, "name");
    if (hasCode == hasName) { // both or neither: the XOR is violated
        return std::nullopt;
    }
    FieldReader r(m);
    std::variant<ErrorCode, SyncError> code;
    if (hasCode) {
        const auto raw = r.uint("code");
        if (!r.ok()) {
            return std::nullopt;
        }
        const auto ec = decodeErrorCode(raw);
        if (!ec) {
            return std::nullopt;
        }
        code = *ec;
    } else {
        const auto raw = r.text("name");
        if (!r.ok()) {
            return std::nullopt;
        }
        const auto se = decodeSyncError(raw);
        if (!se) {
            return std::nullopt;
        }
        code = *se;
    }
    const auto msgKey = r.optText("msgKey");
    const auto msgFallback = r.optText("msgFallback");
    if (!r.ok()) {
        return std::nullopt;
    }
    return ErrInfo{code, msgKey, msgFallback};
}

// --- op-result (op-result-ready payload) decoder ------------------------------

std::optional<OpResult> decodeOpResult(const Map& m, std::span<const int> fds)
{
    FieldReader kr(m);
    const auto kind = kr.text("kind");
    if (!kr.ok()) {
        return std::nullopt;
    }
    if (kind == "Identity") {
        FieldReader r(m);
        const Map* fields = r.map("fields");
        if (!r.ok()) {
            return std::nullopt;
        }
        IdentityResult out;
        for (const auto& [group, groupVal] : *fields) {
            const auto* inner = groupVal.asMap();
            if (inner == nullptr) {
                return std::nullopt;
            }
            std::map<std::string, IdentityField> cells;
            for (const auto& [fieldKey, fieldVal] : *inner) {
                const auto* tuple = fieldVal.asArray();
                if (tuple == nullptr) {
                    return std::nullopt;
                }
                auto f = decodeIdField(*tuple);
                if (!f) {
                    return std::nullopt;
                }
                cells.emplace(fieldKey, std::move(*f));
            }
            out.fields.emplace(group, std::move(cells));
        }
        return OpResult{std::move(out)};
    }
    if (kind == "Photo") {
        FieldReader r(m);
        const Array* photos = r.array("photos");
        if (!r.ok()) {
            return std::nullopt;
        }
        PhotoResult out;
        out.photos.reserve(photos->size());
        for (const auto& item : *photos) {
            const auto* pm = item.asMap();
            if (pm == nullptr) {
                return std::nullopt;
            }
            auto p = decodePhotoItem(*pm, fds);
            if (!p) {
                return std::nullopt;
            }
            out.photos.push_back(std::move(*p));
        }
        return OpResult{std::move(out)};
    }
    if (kind == "Certificates") {
        FieldReader r(m);
        const Array* certs = r.array("certs");
        if (!r.ok()) {
            return std::nullopt;
        }
        CertListResult out;
        out.certs.reserve(certs->size());
        for (const auto& item : *certs) {
            const auto* cm = item.asMap();
            if (cm == nullptr) {
                return std::nullopt;
            }
            auto ci = decodeCertInfo(*cm);
            if (!ci) {
                return std::nullopt;
            }
            out.certs.push_back(std::move(*ci));
        }
        return OpResult{std::move(out)};
    }
    if (kind == "Sign") {
        auto sr = decodeSignResultFields(m, fds);
        if (!sr) {
            return std::nullopt;
        }
        return OpResult{std::move(*sr)};
    }
    if (kind == "Credentials") {
        FieldReader r(m);
        const Map* resultMap = r.map("result");
        const Array* records = r.array("records");
        if (!r.ok()) {
            return std::nullopt;
        }
        auto cr = decodeCredOpResult(*resultMap);
        if (!cr) {
            return std::nullopt;
        }
        CredentialsResult out;
        out.result = std::move(*cr);
        out.records.reserve(records->size());
        for (const auto& item : *records) {
            const auto* rm = item.asMap();
            if (rm == nullptr) {
                return std::nullopt;
            }
            auto rec = decodeCredentialRecord(*rm);
            if (!rec) {
                return std::nullopt;
            }
            out.records.push_back(std::move(*rec));
        }
        return OpResult{std::move(out)};
    }
    // A recognised event ("OpResultReady") whose result `kind` is not one of
    // the five closed alternatives is malformed, not a forward-compat
    // UnknownEvent escape — that tolerance covers unrecognised top-level `t`
    // tags (CDDL:120-128), not a novel discriminator nested inside an
    // otherwise-known shape.
    return std::nullopt;
}

// --- event decoders -------------------------------------------------------------

std::optional<ReaderAdded> decodeReaderAdded(const Map& m)
{
    FieldReader r(m);
    const Map* readerMap = r.map("reader");
    if (!r.ok()) {
        return std::nullopt;
    }
    auto rs = decodeReaderState(*readerMap);
    if (!rs) {
        return std::nullopt;
    }
    return ReaderAdded{std::move(*rs)};
}
std::optional<ReaderRemoved> decodeReaderRemoved(const Map& m)
{
    FieldReader r(m);
    auto handle = r.text("handle");
    if (!r.ok()) {
        return std::nullopt;
    }
    return ReaderRemoved{std::move(handle)};
}
std::optional<CardAdded> decodeCardAdded(const Map& m)
{
    FieldReader r(m);
    const Map* cardMap = r.map("card");
    if (!r.ok()) {
        return std::nullopt;
    }
    auto cs = decodeCardState(*cardMap);
    if (!cs) {
        return std::nullopt;
    }
    return CardAdded{std::move(*cs)};
}
std::optional<CardRemoved> decodeCardRemoved(const Map& m)
{
    FieldReader r(m);
    auto handle = r.text("handle");
    if (!r.ok()) {
        return std::nullopt;
    }
    return CardRemoved{std::move(handle)};
}
std::optional<PropertyChanged> decodePropertyChanged(const Map& m)
{
    FieldReader r(m);
    auto handle = r.text("handle");
    auto iface = r.text("iface");
    const Map* props = r.map("props");
    if (!r.ok()) {
        return std::nullopt;
    }
    PropertyChanged out;
    out.handle = std::move(handle);
    out.iface = std::move(iface);
    for (const auto& [k, v] : *props) {
        out.props.emplace(k, v);
    }
    return out;
}
std::optional<ConfigChanged> decodeConfigChanged(const Map& m)
{
    FieldReader r(m);
    auto key = r.text("key");
    if (!r.ok()) {
        return std::nullopt;
    }
    return ConfigChanged{std::move(key)};
}
std::optional<OpProgress> decodeOpProgress(const Map& m)
{
    FieldReader r(m);
    const auto op = r.uint("op");
    const auto phaseRaw = r.uint("phase");
    const auto progress = r.optDouble("progress");
    const auto indeterminate = r.optBool("indeterminate");
    const auto watchdogSecs = r.optUint("watchdogSecs");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (phaseRaw > static_cast<std::uint64_t>(OperationPhase::Done)) {
        return std::nullopt;
    }
    OpProgress out;
    out.op = op;
    out.phase = static_cast<OperationPhase>(phaseRaw);
    out.progress = progress;
    out.indeterminate = indeterminate;
    out.watchdogSecs = watchdogSecs;
    return out;
}
std::optional<OpResultReady> decodeOpResultReady(const Map& m, std::span<const int> fds)
{
    FieldReader r(m);
    const auto op = r.uint("op");
    const Map* resultMap = r.map("result");
    if (!r.ok()) {
        return std::nullopt;
    }
    auto res = decodeOpResult(*resultMap, fds);
    if (!res) {
        return std::nullopt;
    }
    return OpResultReady{op, std::move(*res)};
}
std::optional<OpFinished> decodeOpFinished(const Map& m)
{
    FieldReader r(m);
    const auto op = r.uint("op");
    const auto statusRaw = r.uint("status");
    const auto codeRaw = r.uint("code");
    auto msgKey = r.text("msgKey");
    auto msgFallback = r.text("msgFallback");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (statusRaw > static_cast<std::uint64_t>(OperationStatus::Error)) {
        return std::nullopt;
    }
    const auto code = decodeErrorCode(codeRaw);
    if (!code) {
        return std::nullopt;
    }
    OpFinished out;
    out.op = op;
    out.status = static_cast<OperationStatus>(statusRaw);
    out.code = *code;
    out.msgKey = std::move(msgKey);
    out.msgFallback = std::move(msgFallback);
    return out;
}
std::optional<AgentQuiesced> decodeAgentQuiesced(const Map& m)
{
    FieldReader r(m);
    const auto reasonRaw = r.uint("reason");
    if (!r.ok()) {
        return std::nullopt;
    }
    if (reasonRaw > static_cast<std::uint64_t>(QuiesceReason::Shutdown)) {
        return std::nullopt;
    }
    return AgentQuiesced{static_cast<QuiesceReason>(reasonRaw)};
}

} // namespace

std::optional<DecodedReply> parseReply(std::span<const std::uint8_t> body, std::span<const int> fds)
{
    const auto decoded = decode(body);
    if (!decoded) {
        return std::nullopt;
    }
    const auto* m = decoded->asMap();
    if (m == nullptr) {
        return std::nullopt;
    }

    FieldReader top(*m);
    const auto tag = top.text("t");
    const auto reqId = top.uint("req");
    if (!top.ok()) {
        return std::nullopt;
    }
    // Every reply shares the literal t:"Reply" (CDDL:105); the arms carry no
    // tag of their own. A different (or absent) `t` here means these bytes
    // are not a reply frame at all -- malformed for THIS function's contract,
    // not an unrecognised reply arm.
    if (tag != "Reply") {
        return std::nullopt;
    }

    // The error arm ( err: err-info ) is checked first: it is the only
    // alternative to reply-ok and has a key ("err") none of the ok arms use.
    if (const auto* errVal = findKey(*m, "err")) {
        const auto* errMap = errVal->asMap();
        if (errMap == nullptr) {
            return std::nullopt;
        }
        auto err = decodeErrInfo(*errMap);
        if (!err) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*err)};
    }
    if (const auto* kindVal = findKey(*m, "kind")) { // hello-ack = ( kind: "HelloAck", ... )
        const auto* k = kindVal->asText();
        if (k != nullptr && *k == "HelloAck") {
            auto v = decodeHelloAck(*m);
            if (!v) {
                return std::nullopt;
            }
            return DecodedReply{reqId, std::move(*v)};
        }
        return std::nullopt; // "kind" present but not the one reply arm that uses it
    }
    if (has(*m, "op")) {
        auto v = decodeOpStarted(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    // Both "readers" and "cards" are required for the state arm. A reply
    // carrying only "readers" (e.g. a truncated frame, or some future arm
    // that happens to reuse that key) can't be told apart from "an
    // unrecognised future shape" by key presence alone -- so it falls
    // through to the generic no-known-key match below (UnknownReply), not
    // nullopt: forward-compat tolerance wins over guessing at malformed-ness.
    if (has(*m, "readers") && has(*m, "cards")) {
        auto v = decodeStateReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (has(*m, "certs")) {
        auto v = decodeCertListReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (has(*m, "der")) {
        auto v = decodeCertDerReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (has(*m, "kty")) {
        auto v = decodePublicKeyReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (has(*m, "entries")) {
        auto v = decodeConfigReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (has(*m, "ok")) {
        auto v = decodeAckReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (has(*m, "sig")) {
        auto v = decodeRawSignatureReply(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    if (const auto* resultVal = findKey(*m, "result")) { // sign-recovery = ( result: sign-result )
        const auto* resultMap = resultVal->asMap();
        if (resultMap == nullptr) {
            return std::nullopt;
        }
        auto v = decodeSignResultFields(*resultMap, fds);
        if (!v) {
            return std::nullopt;
        }
        return DecodedReply{reqId, std::move(*v)};
    }
    // No known reply-ok key matched: a shape this client build does not
    // recognise (a future arm). Forward-compat, not an error.
    return DecodedReply{reqId, UnknownReply{}};
}

std::optional<DecodedEvent> parseEvent(std::span<const std::uint8_t> body, std::span<const int> fds)
{
    const auto decoded = decode(body);
    if (!decoded) {
        return std::nullopt;
    }
    const auto* m = decoded->asMap();
    if (m == nullptr) {
        return std::nullopt;
    }

    FieldReader top(*m);
    const auto tag = top.text("t");
    if (!top.ok()) {
        return std::nullopt;
    }

    if (tag == "ReaderAdded") {
        auto v = decodeReaderAdded(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "ReaderRemoved") {
        auto v = decodeReaderRemoved(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "CardAdded") {
        auto v = decodeCardAdded(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "CardRemoved") {
        auto v = decodeCardRemoved(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "PropertyChanged") {
        auto v = decodePropertyChanged(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "ConfigChanged") {
        auto v = decodeConfigChanged(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "OpProgress") {
        auto v = decodeOpProgress(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "OpResultReady") {
        auto v = decodeOpResultReady(*m, fds);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "OpFinished") {
        auto v = decodeOpFinished(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    if (tag == "AgentQuiesced") {
        auto v = decodeAgentQuiesced(*m);
        if (!v) {
            return std::nullopt;
        }
        return DecodedEvent{std::move(*v)};
    }
    // An unrecognised `t`: a future event this client build does not know
    // about yet. Forward-compat, not an error.
    return DecodedEvent{UnknownEvent{}};
}

std::vector<std::uint8_t> encodeRequest(const RequestVariant& req, std::uint64_t requestId)
{
    // Reuses the existing canonical encoder verbatim -- no encoding logic is
    // duplicated for the client side.
    return toCbor(RequestEnvelope{requestId, req}).encode();
}

} // namespace LibreSCRS::Agent::Wire
