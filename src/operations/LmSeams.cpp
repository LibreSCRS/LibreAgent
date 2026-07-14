// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/util/Sha256Hex.h> // sha256Hex (certId)
#include <LibreSCRS/Agent/util/HexEncode.h> // toHex (serial / extension presentation)
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/operations/SignGate.h>
#include <LibreSCRS/Agent/operations/SignatureParams.h> // timestampWasApplied (honest tsaUsed)
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // keyAmbiguous() — bind KeyAmbiguous to the LM key constant
#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/SigningResult.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// --- LmCardReader --------------------------------------------------------

namespace {

ReadOutcome::Status mapStatus(LibreSCRS::Plugin::ReadResult::Status s) noexcept
{
    using S = LibreSCRS::Plugin::ReadResult::Status;
    switch (s) {
    case S::Ok:
        return ReadOutcome::Status::Ok;
    case S::CommunicationError:
        return ReadOutcome::Status::CommunicationError;
    case S::ParseError:
        return ReadOutcome::Status::ParseError;
    case S::UnsupportedCard:
        return ReadOutcome::Status::UnsupportedCard;
    case S::AuthenticationFailed:
        return ReadOutcome::Status::AuthFailed;
    case S::Cancelled:
        return ReadOutcome::Status::Cancelled;
    }
    return ReadOutcome::Status::CommunicationError;
}

FieldType mapFieldType(LibreSCRS::Plugin::FieldType t) noexcept
{
    using FT = LibreSCRS::Plugin::FieldType;
    switch (t) {
    case FT::Text:
        return FieldType::Text;
    case FT::Date:
        return FieldType::Date;
    case FT::Binary:
        return FieldType::Binary;
    case FT::Photo:
        return FieldType::Photo;
    }
    return FieldType::Binary;
}

CardReadSnapshot toSnapshot(const LibreSCRS::Plugin::CardData& src)
{
    CardReadSnapshot dst;
    dst.cardType = src.cardType;
    dst.groups.reserve(src.groups.size());
    for (const auto& g : src.groups) {
        GroupSnapshot gs;
        gs.groupKey = g.groupKey;
        gs.labelKey = std::string{"group."} + g.groupKey;
        gs.labelFallback = g.groupLabel;
        gs.fields.reserve(g.fields.size());
        for (const auto& f : g.fields) {
            FieldSnapshot fs;
            fs.fieldKey = f.key;
            fs.labelKey = std::string{"field."} + f.key;
            fs.labelFallback = f.label;
            fs.type = mapFieldType(f.type);
            if (fs.type == FieldType::Text || fs.type == FieldType::Date) {
                fs.textValue.assign(f.value.begin(), f.value.end());
            } else {
                fs.binaryValue = f.value;
            }
            gs.fields.push_back(std::move(fs));
        }
        dst.groups.push_back(std::move(gs));
    }
    return dst;
}

// --- certificate parsing (LM ParsedCertificate -> agent CertSnapshot) ------
// LM/X.509 types stay inside this seam .cpp; the flow + wire see only CertSnapshot.

namespace cert = LibreSCRS::Certificate;

// Wire keyUsageBits bit i == RFC 5280 §4.2.1.3 KeyUsage bit i. Pin the LM enum
// ordinals so a reorder cannot silently shift the frozen wire mask.
static_assert(static_cast<int>(cert::KeyUsageBit::DigitalSignature) == 0);
static_assert(static_cast<int>(cert::KeyUsageBit::NonRepudiation) == 1);
static_assert(static_cast<int>(cert::KeyUsageBit::DecipherOnly) == 8);

std::string toIso8601Utc(std::chrono::system_clock::time_point tp)
{
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::time_point_cast<std::chrono::seconds>(tp));
}

const char* pubKeyAlgoName(cert::PublicKeyAlgorithm a) noexcept
{
    switch (a) {
    case cert::PublicKeyAlgorithm::RSA:
        return "RSA";
    case cert::PublicKeyAlgorithm::ECDSA:
        return "ECDSA";
    case cert::PublicKeyAlgorithm::EdDSA:
        return "EdDSA";
    case cert::PublicKeyAlgorithm::Other:
        return "Other";
    }
    return "Other";
}

// Non-canonical, parse-order, comma-joined DISPLAY string (NOT RFC 2253/4514;
// no escaping). Frozen as a display field; clients must not assume canonical DN.
std::string dnString(const cert::DistinguishedName& dn)
{
    std::string out;
    for (const auto& comp : dn.components) {
        if (!out.empty()) {
            out += ", ";
        }
        const std::string name = comp.oid.friendlyName();
        out += (name.empty() ? comp.oid.dottedDecimal : name);
        out += '=';
        out += comp.value;
    }
    return out;
}

// Append a Text field to a group only when the value is non-empty (keeps the
// wire clean; the client renders what is present). labelKey is the frozen i18n
// key "cert.<group>.<field>"; labelFallback is the English label.
void addText(GroupSnapshot& g, const std::string& fieldKey, std::string labelFallback, std::string value)
{
    if (value.empty()) {
        return;
    }
    FieldSnapshot f;
    f.fieldKey = fieldKey;
    f.labelKey = "cert." + g.groupKey + "." + fieldKey;
    f.labelFallback = std::move(labelFallback);
    f.type = FieldType::Text;
    f.textValue = std::move(value);
    g.fields.push_back(std::move(f));
}

GroupSnapshot makeGroup(std::string key, std::string labelFallback)
{
    GroupSnapshot g;
    g.groupKey = std::move(key);
    g.labelKey = "cert.group." + g.groupKey;
    g.labelFallback = std::move(labelFallback);
    return g;
}

CertSnapshot toCertSnapshot(const LibreSCRS::Plugin::CertificateData& cd)
{
    CertSnapshot snap;
    snap.certId = sha256Hex(cd.derBytes);
    snap.trustStatus = static_cast<std::uint32_t>(CertTrustStatus::Unknown); // chain verdict not yet wired
    // signingCapable is set AFTER parsing (it needs the keyUsage); it defaults
    // false so an unparseable cert is never reported as a usable signing handle.

    auto parsed = cert::ParsedCertificate::fromDer(cd.derBytes);
    if (!parsed) {
        // Surface the failure in a RESERVED diagnostic group (not the frozen
        // cert/* namespace). signingCapable stays false; chainSubjectCns stays
        // empty — uniform subject-CN semantics, never a PKCS#15 label.
        GroupSnapshot g = makeGroup("diagnostic", "Diagnostic");
        const std::string detail = parsed.error().userMessage.defaultText;
        addText(g, "parseError", "Parse error", detail.empty() ? std::string{"Failed to parse certificate"} : detail);
        snap.fields.push_back(std::move(g));
        return snap;
    }
    const auto& c = *parsed;

    GroupSnapshot subject = makeGroup("subject", "Subject");
    addText(subject, "cn", "Common Name", c.subject().commonName());
    addText(subject, "o", "Organization", c.subject().organization());
    addText(subject, "ou", "Organizational Unit", c.subject().organizationalUnit());
    addText(subject, "dn", "Distinguished Name", dnString(c.subject()));
    snap.fields.push_back(std::move(subject));

    GroupSnapshot issuer = makeGroup("issuer", "Issuer");
    addText(issuer, "cn", "Common Name", c.issuer().commonName());
    addText(issuer, "o", "Organization", c.issuer().organization());
    addText(issuer, "ou", "Organizational Unit", c.issuer().organizationalUnit());
    addText(issuer, "dn", "Distinguished Name", dnString(c.issuer()));
    snap.fields.push_back(std::move(issuer));

    GroupSnapshot validity = makeGroup("validity", "Validity");
    addText(validity, "notBefore", "Not Before", toIso8601Utc(c.notBefore()));
    addText(validity, "notAfter", "Not After", toIso8601Utc(c.notAfter()));
    snap.fields.push_back(std::move(validity));

    GroupSnapshot pub = makeGroup("publicKey", "Public Key");
    const auto pk = c.publicKey();
    addText(pub, "algorithm", "Algorithm", pubKeyAlgoName(pk.algorithm));
    if (pk.bitLength > 0) {
        addText(pub, "sizeBits", "Key Size", std::to_string(pk.bitLength));
    }
    addText(pub, "curveOid", "Curve", pk.curveOid);
    snap.fields.push_back(std::move(pub));

    GroupSnapshot certg = makeGroup("cert", "Certificate");
    addText(certg, "serial", "Serial Number", toHex(c.serialNumber(), ':', /*upper=*/true));
    // ParsedCertificate::version() already returns the human X.509 version
    // (1/2/3 — it wraps X509_get_version()+1 internally), so NO extra increment.
    addText(certg, "version", "Version", std::format("v{}", c.version()));
    addText(certg, "signatureAlgorithm", "Signature Algorithm", c.signatureAlgorithmDescription());
    snap.fields.push_back(std::move(certg));

    // Every extension as OID -> uppercase hex (reproduces LC's Details tab,
    // including unknown extensions). KeyUsage/EKU also appear here raw; the
    // typed keyUsageBits/ekuOids below are the client-localizable forms.
    GroupSnapshot ext = makeGroup("ext", "Extensions");
    for (const auto& e : c.extensions()) {
        const std::string name = e.oid.friendlyName();
        addText(ext, e.oid.dottedDecimal, name.empty() ? e.oid.dottedDecimal : name,
                toHex(e.value, /*separator=*/'\0', /*upper=*/true));
    }
    if (!ext.fields.empty()) {
        snap.fields.push_back(std::move(ext));
    }

    // keyUsage -> RFC 5280 wire bitmask (bit i == RFC bit i; pinned above) AND
    // signing suitability. An absent keyUsage extension is treated as permissive
    // (many signing cards omit it).
    bool kuSuitable = true;
    if (const auto ku = c.keyUsage()) {
        kuSuitable = false;
        for (const auto bit : *ku) {
            snap.keyUsageBits |= (1u << static_cast<std::uint32_t>(bit));
            if (bit == cert::KeyUsageBit::DigitalSignature || bit == cert::KeyUsageBit::NonRepudiation) {
                kuSuitable = true;
            }
        }
    }
    // signingCapable: pairs to an on-card private key AND the key
    // usage permits signing. keyFID comes from the card's CDF<->key pairing.
    snap.signingCapable = cd.keyFID.has_value() && kuSuitable;

    if (const auto eku = c.extendedKeyUsage()) {
        snap.ekuOids.reserve(eku->size());
        for (const auto& oid : *eku) {
            snap.ekuOids.push_back(oid.dottedDecimal);
        }
    }
    // The chain is not yet evaluated -> just the leaf's own CN; trustStatus
    // stays Unknown until the full chain walk + trust verdict are wired.
    snap.chainSubjectCns.push_back(c.subject().commonName());

    return snap;
}

} // namespace

// Exposed entry to the agent-side cert parser (the anon-namespace helpers stay
// internal). LmCertificateReader::read and the LmSeams KAT both call this.
CertSnapshot certSnapshotFromDer(const LibreSCRS::Plugin::CertificateData& cd)
{
    return toCertSnapshot(cd);
}

bool signingDiagnosticIsModuleLoadFailure(const std::optional<std::string>& diagnosticDetail) noexcept
{
    if (!diagnosticDetail.has_value()) {
        return false;
    }
    const std::string& d = *diagnosticDetail;
    // libresign's native AdES path reports a bare-name dlopen failure of the LM
    // PKCS#11 module, e.g. "Cannot load PKCS#11 module: librescrs-pkcs11.so:
    // cannot open shared object file". Matching either marker also routes the
    // wrong/foreign-module case (libresign's "…requires the LibreSCRS PKCS#11
    // module") here — INTENTIONAL: both a missing and a wrong module are
    // deployment faults the user fixes the same way (correct the installation),
    // which is exactly what EngineUnavailable tells them. find() does not
    // allocate, so this stays noexcept.
    return d.find("PKCS#11 module") != std::string::npos || d.find("cannot open shared object") != std::string::npos;
}

ReadOutcome LmCardReader::read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                               LibreSCRS::CancelToken token)
{
    if (candidates.empty()) {
        return ReadOutcome{ReadOutcome::Status::UnsupportedCard, std::nullopt, "no identity-capable plugin"};
    }
    // Lazy fallback: the first candidate that reports Ok is the active applet.
    // Candidate plugins switch applets via their own SM-wrapped SELECT on the
    // SAME session — never open a new one. Retain the last failure to surface.
    ReadOutcome last{ReadOutcome::Status::CommunicationError, std::nullopt, "no plugin produced data"};
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        if (token.isCancelled()) {
            return ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, {}};
        }
        auto result = cand->readCard(session, {}, token);
        const auto status = mapStatus(result.status);
        if (status == ReadOutcome::Status::Ok && result.data) {
            return ReadOutcome{status, toSnapshot(*result.data), {}};
        }
        last = ReadOutcome{status, std::nullopt, result.userMessage.defaultText};
    }
    return last;
}

// --- LmCertificateReader -------------------------------------------------
// CardPlugin::readCertificates returns by value (no status): an empty list on a
// PKI card means "no readable certs" — which may also be a failed pre-read
// unlock, indistinguishable at this API. The installed credential provider
// supplies the CAN for PACE cards (the plugin self-activates inside
// readCertificates, as readCard does); the token is a pre-dispatch check only.

// --- LmSigner ------------------------------------------------------------
namespace {

namespace sign = LibreSCRS::Signing;

std::optional<sign::SignatureFormat> mapFormat(const std::string& s) noexcept
{
    if (s == "pades")
        return sign::SignatureFormat::Pades;
    if (s == "cades")
        return sign::SignatureFormat::Cades;
    if (s == "xades")
        return sign::SignatureFormat::Xades;
    if (s == "jades")
        return sign::SignatureFormat::Jades;
    if (s == "asice")
        return sign::SignatureFormat::AsicE;
    return std::nullopt;
}

std::optional<sign::SignatureLevel> mapLevel(const std::string& s) noexcept
{
    if (s == "b-b")
        return sign::SignatureLevel::B_B;
    if (s == "b-t")
        return sign::SignatureLevel::B_T;
    if (s == "b-lt")
        return sign::SignatureLevel::B_LT;
    if (s == "b-lta")
        return sign::SignatureLevel::B_LTA;
    return std::nullopt;
}

std::optional<sign::PackagingMode> mapPackaging(const std::string& s) noexcept
{
    if (s == "enveloped")
        return sign::PackagingMode::Enveloped;
    if (s == "detached")
        return sign::PackagingMode::Detached;
    return std::nullopt;
}

SignOutcome signFailure(SignOutcome::Status status, std::string msg)
{
    SignOutcome out;
    out.status = status;
    out.msgFallback = std::move(msg);
    return out;
}

// Translate the SigningResult terminal status into the seam's hermetic
// SignOutcome status. KeyAmbiguous is a SigningEngineError on the LM wire
// distinguished only by its dedicated ErrorKey (set by the CKA_ID
// duplicate-detection); branch on that key here.
SignOutcome::Status mapResultStatus(const sign::SigningResult& r) noexcept
{
    using S = sign::SigningResult::Status;
    switch (r.status) {
    case S::Ok:
        return SignOutcome::Status::Ok;
    case S::UserCancelled:
    case S::Cancelled:
        return SignOutcome::Status::Cancelled;
    case S::PinVerificationFailed:
        return SignOutcome::Status::AuthFailed;
    case S::CardBlocked:
        return SignOutcome::Status::CardBlocked;
    case S::TsaUnreachable:
        return SignOutcome::Status::TsaUnreachable;
    case S::TrustStoreUnavailable:
        return SignOutcome::Status::ChainIncomplete;
    case S::InvalidRequest:
        return SignOutcome::Status::SigningEngineError;
    case S::SigningEngineError:
        // A signing engine that could not LOAD its security module is a
        // DEPLOYMENT fault, not a generic engine error — surface it as
        // EngineUnavailable so the client can tell the user to fix the
        // installation (BACKLOG item 72). The predicate is an exposed, unit-
        // tested bridge on libresign's fixed dlopen text.
        if (signingDiagnosticIsModuleLoadFailure(r.diagnosticDetail)) {
            return SignOutcome::Status::EngineUnavailable;
        }
        // KeyAmbiguous rides on SigningEngineError distinguished only by its
        // dedicated LM ErrorKey (set by the CKA_ID duplicate-detection); bind to
        // the LM constant (not a string literal) so an LM key rename is a
        // compile-time break, not a silent miss.
        return (r.userMessage.key == LibreSCRS::Auth::ErrorKeys::keyAmbiguous().key)
                   ? SignOutcome::Status::KeyAmbiguous
                   : SignOutcome::Status::SigningEngineError;
    }
    return SignOutcome::Status::SigningEngineError;
}

} // namespace

std::optional<SigningSelection> selectSigningCandidate(const CandidateList& candidates, const std::string& certId,
                                                       LibreSCRS::SmartCard::CardSession& session)
{
    // Route to the candidate that OWNS certId: the first whose readCertificates
    // contains a cert hashing to certId is the signing plugin. Applet switches
    // between candidates ride their own SM-wrapped SELECT on the SAME session —
    // never a new session.
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        std::vector<LibreSCRS::Plugin::CertificateData> certs;
        try {
            certs = cand->readCertificates(session);
        } catch (...) {
            // A candidate that fails to read cannot own the cert; skip it and
            // keep routing to the next.
            log::warn("sign: a signing candidate threw on readCertificates; skipping it");
            continue;
        }
        for (auto& cd : certs) {
            if (!cd.derBytes.empty() && sha256Hex(cd.derBytes) == certId) {
                return SigningSelection{.plugin = cand, .cert = std::move(cd)};
            }
        }
    }
    return std::nullopt;
}

SignOutcome LmSigner::sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session, const SignParams& params,
                           const CandidateList& candidates, LibreSCRS::Auth::CredentialProvider credentials,
                           LibreSCRS::CancelToken token)
{
    if (!session) {
        return signFailure(SignOutcome::Status::CommunicationError, "no session bound");
    }
    if (candidates.empty()) {
        // An empty signing-capable candidate set means the requested key/cert
        // cannot exist on this card; SignOutcome has no UnsupportedCard, so
        // KeyNotFound is the closest wire code.
        return signFailure(SignOutcome::Status::KeyNotFound, "no signing-capable plugin on this card");
    }
    // Capture the engine AND its bound TSA URL atomically: tsaUsed is derived and
    // LastTsaUrl is recorded from THIS pair below, never from the live ConfigStore
    // (which a concurrent admin reconfigure could mutate mid-sign — a metadata
    // TOCTOU that would otherwise false-negative tsaUsed or record a URL this sign
    // never contacted).
    const auto snap = m_engine.snapshot();
    const auto& engine = snap.engine;
    if (!engine || !*engine) {
        // Deployment fault (no engine wired) — a distinct code so the client
        // guides the user to the installation, not a generic engine error.
        return signFailure(SignOutcome::Status::EngineUnavailable,
                           "the signing service could not start its security module");
    }
    const auto format = mapFormat(params.format);
    const auto level = mapLevel(params.level);
    const auto packaging = mapPackaging(params.packaging);
    if (!format || !level || !packaging) {
        return signFailure(SignOutcome::Status::SigningEngineError, "unresolved signature parameters");
    }
    // Resolve certId -> the exact on-card cert by iterating the candidate list and
    // re-reading each candidate's certs off the live card, so the assertion is
    // against the card present NOW (anti-TOCTOU). The re-read also
    // (re)establishes the PACE channel for travel-document cards so the live
    // session is registered in SessionPresence for in-process adoption.
    // readCertificates takes no CancelToken (the card I/O — and any CAN prompt it
    // drives — is itself uncancellable); honour a cancel observed up to this point
    // before committing to the uncancellable readCertificates loop.
    if (token.isCancelled()) {
        return signFailure(SignOutcome::Status::Cancelled, "cancelled");
    }
    auto selection = selectSigningCandidate(candidates, params.certId, *session);
    if (!selection) {
        return signFailure(SignOutcome::Status::KeyNotFound, "certId did not resolve on the present card");
    }
    const auto& signingPlugin = selection->plugin;
    const auto& chosen = selection->cert;

    // Per-level expired-cert gate. Authority is the cert's own notAfter; the
    // policy itself is the pure, unit-tested evaluateExpiredGate.
    const bool qualifiedFamily = (level != sign::SignatureLevel::B_B);
    bool expired = false;
    if (auto parsed = LibreSCRS::Certificate::ParsedCertificate::fromDer(chosen.derBytes)) {
        expired = parsed->notAfter() < std::chrono::system_clock::now();
    }
    bool forwardAllowExpired = false;
    switch (evaluateExpiredGate(expired, qualifiedFamily, params.allowExpired)) {
    case ExpiredGate::Blocked:
        return signFailure(SignOutcome::Status::CertExpiredBlocked,
                           qualifiedFamily ? "signing certificate is expired (blocked for the timestamped/long-term "
                                             "family)"
                                           : "signing certificate is expired");
    case ExpiredGate::ProceedAllowingExpired:
        forwardAllowExpired = true;
        break;
    case ExpiredGate::Proceed:
        break;
    }

    sign::SigningRequest request = [&] {
        sign::SigningRequest::Builder b;
        b.format(*format).level(*level).packaging(*packaging).keyId(chosen.ckaId);
        if (!params.reason.empty()) {
            b.reason(params.reason);
        }
        if (!params.location.empty()) {
            b.location(params.location);
        }
        // Name hint only (never opened): drives the XAdES/JAdES detached
        // ds:Reference URI basename. Empty is fine.
        if (!params.displayName.empty()) {
            b.inputFile(params.displayName);
        }
        if (forwardAllowExpired) {
            b.allowExpiredCert(true);
        }
        return std::move(b).buildForBufferSign();
    }();

    // The watchdog (armed at Authenticating) trips a cooperative cancel, but no
    // CancelToken is threaded into the LM's RFC-3161 TSA HTTP call: a hung-but-
    // connected TSA round-trip here is bounded by libcurl's own CURLOPT_TIMEOUT,
    // NOT by the watchdog's cooperative cancel. Threading a CancelToken into the
    // LM TSA call so the watchdog can interrupt it is a later item.
    const sign::SigningResult result = engine->sign(request, std::span<const std::uint8_t>{params.inputDocument},
                                                    std::move(credentials), signingPlugin, session);

    SignOutcome out;
    out.status = mapResultStatus(result);
    out.resolvedFormat = params.format;
    out.resolvedLevel = params.level;
    // Honest tsaUsed (D-d): the installed SigningResult carries no per-token
    // timestamp flag, so derive it — a timestamp was applied iff the sign
    // succeeded at a qualified level AND a TSA was configured (the LM had a
    // non-empty provider to contact). Never a bare level guess: B-B is always
    // false, and a qualified level with no TSA configured fails closed upstream
    // (TsaUnreachable) rather than reporting a phantom timestamp.
    out.tsaUsed = SignatureParams::timestampWasApplied(out.status == SignOutcome::Status::Ok, params.level,
                                                       !snap.boundTsaUrl.empty());
    out.msgFallback = result.userMessage.defaultText;
    if (out.status != SignOutcome::Status::Ok) {
        // The LM engine's own message is the ONLY record of why the AdES wrap
        // failed after the card produced the raw signature — never swallow it.
        log::warnf("sign: LM engine failed: status={} format={} level={} packaging={} msg=\"{}\" diag=\"{}\"",
                   static_cast<int>(out.status), static_cast<int>(*format), static_cast<int>(*level),
                   static_cast<int>(*packaging), result.userMessage.defaultText,
                   result.diagnosticDetail.value_or("(none)"));
    }
    if (out.status == SignOutcome::Status::Ok) {
        if (result.signedDocumentBytes) {
            out.signedDocumentBytes = *result.signedDocumentBytes;
        } else {
            // Ok without bytes is a buffer-overload contract violation — fail
            // closed rather than emit an empty artifact.
            return signFailure(SignOutcome::Status::SigningEngineError, "signing returned Ok with no document bytes");
        }
        // Record the TSA URL actually used after a successful timestamped sign
        // (read-only LastTsaUrl; the agent is the sole writer). A no-op when no
        // TSA was contacted (tsaUsed false), so a plain B-B sign never touches it.
        // Skipped once the operation is cancelled: on shutdown an abandoned worker
        // that unblocks here must not mutate config, whose change notification would
        // re-enter the (by then torn-down) host wiring.
        if (out.tsaUsed && !token.isCancelled()) {
            m_engine.recordLastTsaUrlUsed(snap.boundTsaUrl);
        }
    }
    return out;
}

CertReadOutcome LmCertificateReader::read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                                          LibreSCRS::CancelToken token)
{
    if (candidates.empty()) {
        return CertReadOutcome{CertReadOutcome::Status::UnsupportedCard, {}, "no PKI-capable plugin"};
    }
    if (token.isCancelled()) {
        return CertReadOutcome{CertReadOutcome::Status::Cancelled, {}, {}};
    }
    // Lazy fallback: the first candidate that yields a non-empty cert list is the
    // active PKI applet. An empty list is Ok-with-no-certs (matching the prior
    // single-plugin behaviour), so it is returned only when every candidate is
    // empty. Candidate plugins switch applets via their own SM-wrapped SELECT on
    // the SAME session — never open a new one.
    CertReadOutcome last{CertReadOutcome::Status::Ok, {}, {}};
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        if (token.isCancelled()) {
            return CertReadOutcome{CertReadOutcome::Status::Cancelled, {}, {}};
        }
        std::vector<LibreSCRS::Plugin::CertificateData> raw;
        try {
            raw = cand->readCertificates(session);
        } catch (...) {
            log::warn("cert-read: a candidate threw on readCertificates; skipping it");
            last = CertReadOutcome{CertReadOutcome::Status::CommunicationError, {}, "readCertificates failed"};
            continue;
        }
        CertReadOutcome out;
        out.status = CertReadOutcome::Status::Ok;
        out.certs.reserve(raw.size());
        for (const auto& cd : raw) {
            if (token.isCancelled()) {
                return CertReadOutcome{CertReadOutcome::Status::Cancelled, {}, {}};
            }
            if (cd.derBytes.empty()) {
                log::warn("cert-read: skipping a card certificate with empty DER");
                continue; // never mint a certId that aliases the SHA-256("") constant
            }
            out.certs.push_back(certSnapshotFromDer(cd));
        }
        if (!out.certs.empty()) {
            return out; // first candidate with readable certs wins
        }
        last = std::move(out); // empty-but-Ok; keep looking for a non-empty one
    }
    return last;
}

} // namespace LibreSCRS::Agent::Operations
