// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/util/Sha256Hex.h>   // sha256Hex (certId)
#include <LibreSCRS/Agent/util/DisplayText.h> // isDisplayableUtf8 (text-field display safety)
#include <LibreSCRS/Agent/util/HexEncode.h>   // toHex (serial / extension presentation)
#include <LibreSCRS/Agent/backend/Logging.h>
#include "LmSigningRequestBuilder.h" // buildSigningRequest (extracted, unit-testable)
#include "LmSignResultMapping.h"     // mapSigningResultStatus (extracted, unit-testable)
#include <LibreSCRS/Agent/operations/SignGate.h>
#include <LibreSCRS/Agent/operations/SignatureParams.h> // timestampWasApplied (honest tsaUsed)
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // keyAmbiguous() — bind KeyAmbiguous to the LM key constant
#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/SigningResult.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/TsaProvider.h>           // staticTsa
#include <LibreSCRS/Signing/VisualSignatureLayout.h> // layoutVisualSignature, embeddedAppearanceFontData
#include <LibreSCRS/Signing/VisualSignatureParams.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>
#include <algorithm>
#include <chrono>
#include <cmath>   // std::lround (visual geometry float -> LM's integer Rect)
#include <cstddef> // std::byte (embeddedAppearanceFontData's span)
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
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

// M4 (agent half): a STRUCTURAL pre-read failure carries a distinct ErrorKey.
// Discriminate on the KEY, not the status LM tags it with, so a structural
// failure never lands on AuthFailed and gets the credential wrongly punished by
// the read flow's AuthFailed-only markCredentialWrong branch. Both keys map onto
// EXISTING ReadOutcome statuses -- zero ErrorCode growth:
//   paceUnsupported       -> UnsupportedCard (the flow's AuthFailed-only
//                            markCredentialWrong branch then skips it for free)
//   paceDowngradeDetected -> CommunicationError (never AuthFailed, so a detected
//                            downgrade attack never evicts/punishes a credential)
// The distinct msgKey/msgFallback still carries the reason to the user. Bind to
// the LM ErrorKeys constants (not string literals) so an LM key rename is a
// compile-time break, not a silent miss.
ReadOutcome::Status mapReadStatus(const LibreSCRS::Plugin::ReadResult& result) noexcept
{
    if (result.userMessage.key == LibreSCRS::Auth::ErrorKeys::paceUnsupported().key) {
        return ReadOutcome::Status::UnsupportedCard;
    }
    if (result.userMessage.key == LibreSCRS::Auth::ErrorKeys::paceDowngradeDetected().key) {
        return ReadOutcome::Status::CommunicationError;
    }
    return mapStatus(result.status);
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

// Shared per-field mapping (LM CardField -> agent FieldSnapshot), reused by
// toSnapshot's full-group loop below and by LmCardReader::readTokenInfo's
// single-group conversion, so the two call sites cannot drift apart.
std::vector<FieldSnapshot> mapFields(const std::vector<LibreSCRS::Plugin::CardField>& fields)
{
    std::vector<FieldSnapshot> out;
    out.reserve(fields.size());
    for (const auto& f : fields) {
        FieldSnapshot fs;
        fs.fieldKey = f.key;
        fs.labelKey = std::string{"field."} + f.key;
        fs.labelFallback = f.label;
        fs.type = mapFieldType(f.type);
        if (fs.type == FieldType::Text || fs.type == FieldType::Date) {
            // Display-safety law: Text/Date values feed GUI labels directly,
            // but LM deliberately keeps CardField::value as the card's raw
            // bytes (card-data integrity), and some cards put binary in
            // nominally-textual slots — e.g. a pkcs15 EF(TokenInfo) BCD
            // serialNumber. Pre-agent LibreCelik rendered printable-or-hex
            // client-side; the raw bytes no longer cross the wire, so this
            // seam is the only place left that can make that call. Same hex
            // rendering the certificate serial below already uses.
            if (isDisplayableUtf8(f.value)) {
                fs.textValue.assign(f.value.begin(), f.value.end());
            } else {
                fs.textValue = toHex(f.value, ':', /*upper=*/true);
            }
        } else {
            fs.binaryValue = f.value;
        }
        out.push_back(std::move(fs));
    }
    return out;
}

// Shared per-group mapping (LM CardFieldGroup -> agent GroupSnapshot), reused
// by toSnapshot's full-group loop below AND by the streaming onGroup
// callback wrapper in LmCardReader::read, so the two conversions of the
// SAME underlying group shape cannot drift apart.
GroupSnapshot mapGroup(const LibreSCRS::Plugin::CardFieldGroup& g)
{
    GroupSnapshot gs;
    gs.groupKey = g.groupKey;
    gs.labelKey = std::string{"group."} + g.groupKey;
    gs.labelFallback = g.groupLabel;
    gs.fields = mapFields(g.fields);
    return gs;
}

CardReadSnapshot toSnapshot(const LibreSCRS::Plugin::CardData& src)
{
    CardReadSnapshot dst;
    dst.cardType = src.cardType;
    dst.groups.reserve(src.groups.size());
    for (const auto& g : src.groups) {
        dst.groups.push_back(mapGroup(g));
    }
    return dst;
}

// Normalized empty "token" group: groupKey/labelKey/labelFallback are FIXED
// regardless of what (if anything) an unsupported/best-effort-miss plugin
// populated on its own CardFieldGroup — the flow always sees a well-formed
// single group with zero fields, never an absent/differently-keyed one.
GroupSnapshot emptyTokenInfoGroup()
{
    GroupSnapshot gs;
    gs.groupKey = "token";
    gs.labelKey = "group.token";
    gs.labelFallback = "Token Info";
    return gs;
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

// The marker a critical extension's LABEL carries, in one spelling. It applies
// to the two carriers whose label a client actually receives: the generic "ext"
// dump's per-extension cells, and the subjectKeyIdentifier/
// authorityKeyIdentifier cells of the "cert" group. An extension served by a
// typed GROUP has no such label on the wire -- see addCriticalFlag below.
constexpr std::string_view kCriticalSuffix = " (Critical)";

std::string withCriticalSuffix(std::string label, bool critical)
{
    if (critical) {
        label += kCriticalSuffix;
    }
    return label;
}

// Criticality for an extension served by a typed GROUP, carried as a data cell.
//
// It cannot ride the group's label: `fields` is `group -> field -> (labelKey,
// labelFallback, value)` on both transports, so a GroupSnapshot's own
// labelKey/labelFallback has no slot to be serialized into and never leaves
// this process. A field does — every field a group carries is moved
// generically by both emitters and both client decoders — so the flag is a
// field, and needs no transport change to reach anyone.
//
// The cell is emitted ONLY when the extension is critical: an absent cell is
// how a client tells "not critical" from "this agent does not report
// criticality at all", and a marker every group carried would mark nothing.
// Its labelKey is deliberately EMPTY, which is what says "group metadata, not
// a row": a client renders the group's own marker from it (a suffix, a bold
// row) instead of printing it as a field.
void addCriticalFlag(GroupSnapshot& g, bool critical)
{
    if (!critical) {
        return;
    }
    FieldSnapshot f;
    f.fieldKey = "critical";
    f.labelKey = "";
    f.labelFallback = "Critical";
    f.type = FieldType::Text;
    f.textValue = "true";
    g.fields.push_back(std::move(f));
}

// True iff @p c carries the extension @p dottedOid AND the issuer marked it
// critical. False for an extension the certificate does not carry at all,
// which is the same answer a caller wants: no extension, no marker.
bool extensionIsCritical(const cert::ParsedCertificate& c, std::string_view dottedOid)
{
    for (const auto& e : c.extensions()) {
        if (e.oid.dottedDecimal == dottedOid) {
            return e.critical;
        }
    }
    return false;
}

// Friendly name for an OID, falling back to its dotted-decimal form when the
// LM OID database has no entry -- the same fallback the generic "ext" group
// already applies per-extension, reused here for the typed groups below
// (signatureAlgorithm's OID fallback, certificate policies).
std::string oidLabel(const cert::ObjectIdentifier& oid)
{
    const std::string name = oid.friendlyName();
    return name.empty() ? oid.dottedDecimal : name;
}

// Append one ordinal-keyed field per value (fieldKey "0", "1", ... -- multiple
// URLs/OIDs of the same kind are common, e.g. more than one CRL distribution
// point or AIA URL). labelFallback is shared across the whole set; a client
// renders "<labelFallback> #<n>" or just lists the group's values, per its own
// taste. No-op for an empty list (addText's per-value emptiness check still
// applies to each individual value).
void addOrdinalList(GroupSnapshot& g, const std::string& keyPrefix, const std::string& labelFallback,
                    const std::vector<std::string>& values)
{
    for (std::size_t i = 0; i < values.size(); ++i) {
        addText(g, keyPrefix + std::to_string(i), labelFallback, values[i]);
    }
}

const char* generalNameTypeToken(cert::GeneralNameType t) noexcept
{
    using T = cert::GeneralNameType;
    switch (t) {
    case T::Rfc822Name:
        return "email";
    case T::DnsName:
        return "dns";
    case T::UniformResourceIdentifier:
        return "uri";
    case T::IpAddress:
        return "ip";
    case T::DirectoryName:
        return "directory";
    case T::RegisteredId:
        return "registeredId";
    case T::OtherName:
        return "otherName";
    case T::X400Address:
        return "x400Address";
    case T::EdiPartyName:
        return "ediPartyName";
    }
    return "otherName";
}

const char* generalNameTypeLabel(cert::GeneralNameType t) noexcept
{
    using T = cert::GeneralNameType;
    switch (t) {
    case T::Rfc822Name:
        return "Email";
    case T::DnsName:
        return "DNS";
    case T::UniformResourceIdentifier:
        return "URI";
    case T::IpAddress:
        return "IP";
    case T::DirectoryName:
        return "Directory";
    case T::RegisteredId:
        return "Registered ID";
    case T::OtherName:
        return "Other Name";
    case T::X400Address:
        return "X.400 Address";
    case T::EdiPartyName:
        return "EDI Party Name";
    }
    return "Other Name";
}

// Append one ordinal-keyed field per GeneralName (SAN/IAN entries): value is
// the decoded string form when present, else uppercase hex of the raw DER for
// composite variants the LM parser does not decode further (OtherName/
// X400Address/DirectoryName/EdiPartyName -- mirrors LibreCelik's own SAN/IAN
// rendering fallback). labelFallback carries the per-entry type name so a
// client can render "<Type>: <value>" without its own ASN.1 knowledge.
void addGeneralNames(GroupSnapshot& g, const std::vector<cert::GeneralName>& names)
{
    for (std::size_t i = 0; i < names.size(); ++i) {
        const auto& n = names[i];
        const std::string value = !n.value.empty() ? n.value : toHex(n.rawValue, /*separator=*/'\0', /*upper=*/true);
        FieldSnapshot f;
        f.fieldKey = std::string{generalNameTypeToken(n.type)} + std::to_string(i);
        f.labelKey = "cert." + g.groupKey + "." + generalNameTypeToken(n.type);
        f.labelFallback = generalNameTypeLabel(n.type);
        f.type = FieldType::Text;
        f.textValue = value;
        if (!f.textValue.empty()) {
            g.fields.push_back(std::move(f));
        }
    }
}

// Extension OIDs served by a dedicated typed group below -- skipped from the
// generic "ext" raw-hex dump so a client never sees the SAME extension twice
// (once decoded, once as an opaque hex blob), mirroring LibreCelik's own
// exhaustive known-OID handling (a raw fallback row only for OIDs its if/else
// chain does not otherwise recognise).
bool hasTypedGroup(const cert::ObjectIdentifier& oid)
{
    static const std::vector<std::string> kTypedOids{
        "2.5.29.15",         // KeyUsage (typed: keyUsageBits)
        "2.5.29.37",         // ExtendedKeyUsage (typed: ekuOids)
        "2.5.29.17",         // SubjectAltName (typed: "san" group)
        "2.5.29.18",         // IssuerAltName (typed: "ian" group)
        "2.5.29.19",         // BasicConstraints (typed: "basicConstraints" group)
        "2.5.29.14",         // SubjectKeyIdentifier (typed: "cert" group)
        "2.5.29.35",         // AuthorityKeyIdentifier (typed: "cert" group)
        "2.5.29.31",         // CRLDistributionPoints (typed: "crlDp" group)
        "1.3.6.1.5.5.7.1.1", // AuthorityInfoAccess (typed: "aia" group)
        "2.5.29.32",         // CertificatePolicies (typed: "certificatePolicies" group)
    };
    return std::find(kTypedOids.begin(), kTypedOids.end(), oid.dottedDecimal) != kTypedOids.end();
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
    // Signature algorithm falls back to the OID (friendly name, else dotted)
    // when the description is empty -- mirrors LibreCelik's Details tab, which
    // never renders a blank row for an unrecognised signature algorithm.
    {
        std::string sigAlg = c.signatureAlgorithmDescription();
        if (sigAlg.empty()) {
            sigAlg = oidLabel(c.signatureAlgorithmOid());
        }
        addText(certg, "signatureAlgorithm", "Signature Algorithm", sigAlg);
    }
    // Subject/Authority Key Identifier: the CLEAN key-id bytes from the typed
    // accessor (distinct from the raw ASN.1-wrapped extnValue the generic
    // "ext" dump below would otherwise show for these two OIDs -- SKI/AKI's
    // extnValue is itself a DER-encoded OCTET STRING, so the raw dump's hex
    // carries a tag+length prefix the typed accessor already strips).
    //
    // These two are the only typed OIDs whose value is a CELL of this group
    // rather than a group of its own, so their criticality marker rides the
    // FIELD label -- which, unlike a group's label, does reach a client. Every
    // other typed OID reports criticality through its group's "critical" cell
    // (see addCriticalFlag).
    if (const auto ski = c.subjectKeyIdentifier()) {
        addText(certg, "subjectKeyIdentifier",
                withCriticalSuffix("Subject Key Identifier", extensionIsCritical(c, "2.5.29.14")),
                toHex(*ski, ':', /*upper=*/true));
    }
    if (const auto aki = c.authorityKeyIdentifier()) {
        addText(certg, "authorityKeyIdentifier",
                withCriticalSuffix("Authority Key Identifier", extensionIsCritical(c, "2.5.29.35")),
                toHex(*aki, ':', /*upper=*/true));
    }
    snap.fields.push_back(std::move(certg));

    if (const auto bc = c.basicConstraints()) {
        GroupSnapshot g = makeGroup("basicConstraints", "Basic Constraints");
        addText(g, "isCa", "CA", bc->isCa ? "true" : "false");
        if (bc->pathLenConstraint) {
            addText(g, "pathLen", "Path Length Constraint", std::to_string(*bc->pathLenConstraint));
        }
        addCriticalFlag(g, extensionIsCritical(c, "2.5.29.19"));
        snap.fields.push_back(std::move(g));
    }

    if (const auto san = c.subjectAlternativeNames(); san && !san->empty()) {
        GroupSnapshot g = makeGroup("san", "Subject Alternative Name");
        addGeneralNames(g, *san);
        // The flag goes on AFTER the emptiness check: a group whose every
        // entry was dropped is not published at all, and a lone marker is not
        // a reason to publish one.
        if (!g.fields.empty()) {
            addCriticalFlag(g, extensionIsCritical(c, "2.5.29.17"));
            snap.fields.push_back(std::move(g));
        }
    }
    if (const auto ian = c.issuerAlternativeNames(); ian && !ian->empty()) {
        GroupSnapshot g = makeGroup("ian", "Issuer Alternative Name");
        addGeneralNames(g, *ian);
        if (!g.fields.empty()) {
            addCriticalFlag(g, extensionIsCritical(c, "2.5.29.18"));
            snap.fields.push_back(std::move(g));
        }
    }

    if (const auto crlDp = c.crlDistributionPoints(); crlDp && !crlDp->empty()) {
        GroupSnapshot g = makeGroup("crlDp", "CRL Distribution Points");
        addOrdinalList(g, "url", "CRL Distribution Point", *crlDp);
        addCriticalFlag(g, extensionIsCritical(c, "2.5.29.31"));
        snap.fields.push_back(std::move(g));
    }

    {
        const auto ocsp = c.ocspResponderUrls();
        const auto caIssuers = c.caIssuersUrls();
        if ((ocsp && !ocsp->empty()) || (caIssuers && !caIssuers->empty())) {
            GroupSnapshot g = makeGroup("aia", "Authority Information Access");
            if (ocsp) {
                addOrdinalList(g, "ocsp", "OCSP Responder", *ocsp);
            }
            if (caIssuers) {
                addOrdinalList(g, "caIssuers", "CA Issuers", *caIssuers);
            }
            addCriticalFlag(g, extensionIsCritical(c, "1.3.6.1.5.5.7.1.1"));
            snap.fields.push_back(std::move(g));
        }
    }

    if (const auto policies = c.certificatePolicies(); policies && !policies->empty()) {
        GroupSnapshot g = makeGroup("certificatePolicies", "Certificate Policies");
        std::vector<std::string> names;
        names.reserve(policies->size());
        for (const auto& oid : *policies) {
            names.push_back(oidLabel(oid));
        }
        addOrdinalList(g, "policy", "Certificate Policy", names);
        addCriticalFlag(g, extensionIsCritical(c, "2.5.29.32"));
        snap.fields.push_back(std::move(g));
    }

    // ExtendedKeyUsage, by NAME. The dotted OIDs have always ridden the typed
    // `ekuOids` member and still do -- that member is what a caller MATCHES on,
    // and re-spelling it here would be a second source of the same truth. This
    // group is the other half a renderer needs and could not derive: a client
    // has no OID database, so without this it prints "1.3.6.1.5.5.7.3.4" where
    // it means "E-mail Protection". Same oidLabel() treatment (and same dotted
    // fallback for an OID the database does not know) as certificatePolicies
    // above, for the same reason.
    if (const auto eku = c.extendedKeyUsage(); eku && !eku->empty()) {
        GroupSnapshot g = makeGroup("eku", "Extended Key Usage");
        std::vector<std::string> names;
        names.reserve(eku->size());
        for (const auto& oid : *eku) {
            names.push_back(oidLabel(oid));
        }
        addOrdinalList(g, "usage", "Extended Key Usage", names);
        addCriticalFlag(g, extensionIsCritical(c, "2.5.29.37"));
        snap.fields.push_back(std::move(g));
    }

    // Every OTHER extension as OID -> uppercase hex (reproduces LC's raw
    // fallback for an extension its known-OID chain does not decode,
    // including any genuinely unknown extension). The 10 OIDs served by a
    // typed group above are skipped here -- a client never sees the same
    // extension twice, once decoded and once as an opaque blob. A critical
    // extension's label gets a " (Critical)" suffix, mirroring LC's own
    // rendering convention exactly.
    GroupSnapshot ext = makeGroup("ext", "Extensions");
    for (const auto& e : c.extensions()) {
        if (hasTypedGroup(e.oid)) {
            continue;
        }
        const std::string name = e.oid.friendlyName();
        const std::string label = name.empty() ? e.oid.dottedDecimal : name;
        addText(ext, e.oid.dottedDecimal, withCriticalSuffix(label, e.critical),
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

// --- LmTrustVerifier --------------------------------------------------------

namespace {

namespace trust = LibreSCRS::Trust;

// Pin LM's Trust::TrustStore::ChainStatus ordinals to CertTrustStatus's own
// numbering (both are frozen; a future LM append-only addition to ChainStatus
// must not silently alias one of these five values without this failing to
// compile first).
static_assert(static_cast<int>(trust::TrustStore::ChainStatus::Trusted) == 0);
static_assert(static_cast<int>(trust::TrustStore::ChainStatus::UntrustedRoot) == 1);
static_assert(static_cast<int>(trust::TrustStore::ChainStatus::BrokenChain) == 2);
static_assert(static_cast<int>(trust::TrustStore::ChainStatus::InvalidCertificate) == 3);
static_assert(static_cast<int>(trust::TrustStore::ChainStatus::Expired) == 4);

CertTrustStatus mapChainStatus(trust::TrustStore::ChainStatus s) noexcept
{
    switch (s) {
    case trust::TrustStore::ChainStatus::Trusted:
        return CertTrustStatus::Trusted;
    case trust::TrustStore::ChainStatus::UntrustedRoot:
        return CertTrustStatus::UntrustedRoot;
    case trust::TrustStore::ChainStatus::BrokenChain:
        return CertTrustStatus::BrokenChain;
    case trust::TrustStore::ChainStatus::InvalidCertificate:
        return CertTrustStatus::InvalidCertificate;
    case trust::TrustStore::ChainStatus::Expired:
        return CertTrustStatus::Expired;
    }
    return CertTrustStatus::Unknown;
}

// The single security-status token for a resolved (non-offline) verdict.
// Mirrors mapChainStatus's cases 1:1; the closed vocabulary is pinned in
// CertSnapshot.h's CertTrustStatus comment.
const char* securityToken(CertTrustStatus s) noexcept
{
    switch (s) {
    case CertTrustStatus::Trusted:
        return "trusted";
    case CertTrustStatus::UntrustedRoot:
        return "untrusted-root";
    case CertTrustStatus::BrokenChain:
        return "broken-chain";
    case CertTrustStatus::InvalidCertificate:
        return "invalid";
    case CertTrustStatus::Expired:
        return "expired";
    case CertTrustStatus::Revoked:
        return "revoked";
    case CertTrustStatus::OfflineUnverified:
        return "offline-unverified";
    case CertTrustStatus::Unknown:
        break;
    }
    return "";
}

// Walk issuers upward from the last entry of @p chain via
// TrustStore::findIssuerOf, appending each found anchor's DER, until no
// further issuer is found or a self-signed root would duplicate the chain's
// current tail (identity check on DER bytes, mirroring LibreCelik's own
// certificate-hierarchy walk in certificatehierarchymodel.cpp). The card only
// ever supplies the leaf certificate -- LM's validateChain does not walk
// issuers itself, so this walk is required to reach a useful (non-BrokenChain)
// verdict at all. Bounded so a pathological/cyclic trust-store entry cannot
// loop forever; real chains are rarely more than a handful of certs deep.
void walkIssuersUp(const trust::TrustStore& store, std::vector<std::vector<std::uint8_t>>& chain)
{
    constexpr std::size_t kMaxChain = 16;
    while (chain.size() < kMaxChain) {
        const auto& tail = chain.back();
        const auto issuer = store.findIssuerOf(trust::CertificateView{tail});
        if (!issuer) {
            break;
        }
        if (issuer->certificateDer.size() == tail.size() &&
            std::equal(issuer->certificateDer.begin(), issuer->certificateDer.end(), tail.begin())) {
            break; // self-signed root already at the tail -- stop without duplicating it
        }
        chain.push_back(issuer->certificateDer);
    }
}

} // namespace

TrustVerdict LmTrustVerifier::verify(std::span<const std::uint8_t> leafDer,
                                     std::span<const std::vector<std::uint8_t>> chainDer)
{
    const auto trustService = m_engine.trustSnapshot();
    // No TSL source configured, or the trust store failed to build (network
    // down at startup, bad cache dir, ...): there is no meaningful verdict to
    // report. This is the ONLY branch that emits OfflineUnverified -- never an
    // error, per the TrustVerifier contract.
    if (!trustService || trustService->config().trustedListSources.empty()) {
        return TrustVerdict{CertTrustStatus::OfflineUnverified, {securityToken(CertTrustStatus::OfflineUnverified)}};
    }

    std::vector<std::vector<std::uint8_t>> chain;
    chain.reserve(1 + chainDer.size());
    chain.emplace_back(leafDer.begin(), leafDer.end());
    for (const auto& c : chainDer) {
        chain.push_back(c);
    }

    const auto store = trustService->trustStore();
    if (store) {
        walkIssuersUp(*store, chain);
    }

    std::vector<trust::CertificateView> views;
    views.reserve(chain.size());
    for (const auto& c : chain) {
        views.emplace_back(c);
    }
    const auto chainStatus = store ? store->validateChain(views) : trust::TrustStore::ChainStatus::UntrustedRoot;
    const auto status = mapChainStatus(chainStatus);
    // status is Unknown only if a future LM ChainStatus value falls through
    // mapChainStatus's switch unmapped (fails to compile first per the
    // static_asserts above; this is pure defense-in-depth) -- carry no stray
    // empty token in that case.
    if (status == CertTrustStatus::Unknown) {
        return TrustVerdict{status, {}};
    }
    return TrustVerdict{status, {securityToken(status)}};
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
                               LibreSCRS::CancelToken token, GroupReadCallback onGroup)
{
    if (candidates.empty()) {
        return ReadOutcome{ReadOutcome::Status::UnsupportedCard, std::nullopt, "no identity-capable plugin"};
    }
    // Wrap the agent-side onGroup (GroupSnapshot) into LM's own streaming
    // callback shape (cardType, CardFieldGroup) exactly once here, regardless
    // of how many candidates are tried below -- mapGroup is the SAME
    // conversion toSnapshot's full-group loop uses, so a streamed group and
    // its eventual appearance inside the final snapshot are never able to
    // diverge. Empty when onGroup itself is empty, so a non-streaming caller
    // costs LM nothing extra (readCard's own empty-callback fast path).
    LibreSCRS::Plugin::CardPlugin::GroupCallback lmCallback;
    if (onGroup) {
        lmCallback = [onGroup](const std::string& /*cardType*/, const LibreSCRS::Plugin::CardFieldGroup& g) {
            onGroup(mapGroup(g));
        };
    }
    // Lazy fallback: the first candidate that reports Ok is the active applet.
    // Candidate plugins switch applets via their own SM-wrapped SELECT on the
    // SAME session — never open a new one. Retain the last failure to surface.
    // NOTE: lmCallback is shared across every candidate attempted below, so a
    // candidate that streams a group and THEN fails (falling through to the
    // next candidate) has already forwarded that stray group as a hint. The
    // eventual Result stays authoritative regardless (the wire-level
    // contract this streaming feature is built on), and in practice at most
    // one candidate is ever identity-capable for a given card, so this is a
    // defensive note rather than an observed real-world path.
    ReadOutcome last{ReadOutcome::Status::CommunicationError, std::nullopt, "no plugin produced data"};
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        if (token.isCancelled()) {
            return ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, {}};
        }
        auto result = cand->readCard(session, lmCallback, token);
        const auto status = mapReadStatus(result);
        if (status == ReadOutcome::Status::Ok && result.data) {
            return ReadOutcome{status, toSnapshot(*result.data), {}};
        }
        last = ReadOutcome{status, std::nullopt, result.userMessage.defaultText};
    }
    return last;
}

GroupSnapshot LmCardReader::readTokenInfo(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                                          LibreSCRS::CancelToken token)
{
    // Route across the PKI-capable candidates (already filtered by the
    // flow), lazy-fallback style: the first candidate producing a non-empty
    // group is the active applet. All-empty (no candidates, every candidate
    // throws, or every candidate is the LM base default / found nothing)
    // normalizes to an empty "token" group — SUCCESS with zero fields, never
    // an error: this call cannot fail once a session is open (mirrors the
    // pkcs15 plugin's own documented defensive contract: every failure mode
    // degrades to a partial or empty group rather than escaping an
    // exception).
    for (const auto& cand : candidates) {
        if (token.isCancelled()) {
            break;
        }
        if (!cand) {
            continue;
        }
        LibreSCRS::Plugin::CardFieldGroup group;
        try {
            group = cand->readTokenInfo(session);
        } catch (...) {
            log::warn("token-info: a candidate threw on readTokenInfo; skipping it");
            continue;
        }
        if (!group.fields.empty()) {
            GroupSnapshot gs;
            gs.groupKey = "token";
            gs.labelKey = "group.token";
            gs.labelFallback = group.groupLabel.empty() ? "Token Info" : group.groupLabel;
            gs.fields = mapFields(group.fields);
            return gs;
        }
    }
    return emptyTokenInfoGroup();
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

} // namespace

// Translate the SigningResult terminal status into the seam's hermetic
// SignOutcome status. KeyAmbiguous is a SigningEngineError on the LM wire
// distinguished only by its dedicated ErrorKey (set by the CKA_ID
// duplicate-detection); branch on that key here. Extracted out of the
// anonymous namespace above (declared in LmSignResultMapping.h) so it is
// unit-testable against a hand-built SigningResult, independent of
// LmSigner::sign's live-engine call — see that header's own comment.
SignOutcome::Status mapSigningResultStatus(const sign::SigningResult& r) noexcept
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
        // installation. The predicate is an exposed, unit-
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
    case S::InvalidDocument:
        return SignOutcome::Status::InvalidDocument;
    }
    return SignOutcome::Status::SigningEngineError;
}

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

sign::SigningRequest buildSigningRequest(const SignParams& params, sign::SignatureFormat format,
                                         sign::SignatureLevel level, sign::PackagingMode packaging,
                                         const std::vector<std::uint8_t>& keyId, bool allowExpiredCert)
{
    sign::SigningRequest::Builder b;
    b.format(format).level(level).packaging(packaging).keyId(keyId);
    if (!params.reason.empty()) {
        b.reason(params.reason);
    }
    if (!params.location.empty()) {
        b.location(params.location);
    }
    // The document's identity INSIDE the produced artifact: it becomes the
    // ASiC-E container entry name and the basename of the XAdES/JAdES detached
    // ds:Reference. It is a NAME, never a location -- the document is never
    // opened, resolved or written through it (this is the buffer-sign path;
    // the bytes come from params.inputDocument). Forwarded verbatim: LM owns
    // the name policy (it strips any path components, honouring only the final
    // one, and treats a degenerate result -- "", "." or ".." -- as unset,
    // falling back to its inputFile derivation), so a second sanitisation
    // layer here would only be able to disagree with it. Empty is fine.
    if (!params.displayName.empty()) {
        b.documentName(params.displayName);
    }
    if (allowExpiredCert) {
        b.allowExpiredCert(true);
    }
    // Per-request TSA override: empty tsaUrl installs nothing, so the request
    // rides the engine's own service-level provider (Config's TsaUrls, bound
    // at SigningEngineProvider::rebuild() time). staticTsa (not the
    // validating staticTsaChecked) is deliberate — see this function's
    // declaration comment in LmSigningRequestBuilder.h.
    if (!params.tsaUrl.empty()) {
        b.tsaOverride(sign::staticTsa(params.tsaUrl));
    }
    // PAdES-only visual signature appearance. Float wire geometry rounds to
    // LM's integer Rect (PDF user units are integer quantities at that API
    // boundary); an out-of-scope combination (visual + non-PAdES) throws
    // std::invalid_argument out of Builder::build() below -- entry validation
    // is expected to have already rejected it (defense-in-depth here only).
    if (params.visual) {
        sign::VisualSignatureParams::Builder vb;
        vb.pageIndex(params.visual->page);
        vb.rect(sign::Rect{
            static_cast<int>(std::lround(params.visual->x)), static_cast<int>(std::lround(params.visual->y)),
            static_cast<int>(std::lround(params.visual->width)), static_cast<int>(std::lround(params.visual->height))});
        vb.textTemplate(params.visual->text);
        b.visualParams(std::move(vb).build());
    }
    return std::move(b).buildForBufferSign();
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

    // The effective TSA URL for THIS sign: a per-request override wins over the
    // engine's own config-bound provider (empty means no override was
    // requested, so the engine's service-level provider is what actually gets
    // contacted). Drives both tsaUsed's honesty and LastTsaUrl's recording
    // below -- NOT snap.boundTsaUrl alone, which would under-report a
    // per-request override as "no TSA configured".
    const std::string& effectiveTsaUrl = !params.tsaUrl.empty() ? params.tsaUrl : snap.boundTsaUrl;

    // SigningRequest is move-only with a private default ctor (Builder-only),
    // so a failed build cannot leave a variable default-constructed for later
    // assignment -- route the attempt through an optional instead.
    std::optional<sign::SigningRequest> requestBuild;
    std::string requestBuildError;
    try {
        requestBuild.emplace(
            buildSigningRequest(params, *format, *level, *packaging, chosen.ckaId, forwardAllowExpired));
    } catch (const std::invalid_argument& e) {
        // Entry validation (CardObject::Sign / SocketFrontend::handleSign) is
        // expected to have already rejected an invalid combination (visual +
        // non-PAdES); this is a defense-in-depth catch, not the primary
        // rejection path -- see buildSigningRequest's doc comment.
        requestBuildError = e.what();
    }
    if (!requestBuild) {
        return signFailure(SignOutcome::Status::SigningEngineError,
                           "invalid signature parameters: " + requestBuildError);
    }
    sign::SigningRequest request = std::move(*requestBuild);

    // The watchdog (armed at Authenticating) trips a cooperative cancel, but no
    // CancelToken is threaded into the LM's RFC-3161 TSA HTTP call: a hung-but-
    // connected TSA round-trip here is bounded by libcurl's own CURLOPT_TIMEOUT,
    // NOT by the watchdog's cooperative cancel. Threading a CancelToken into the
    // LM TSA call so the watchdog can interrupt it is a later item.
    const sign::SigningResult result = engine->sign(request, std::span<const std::uint8_t>{params.inputDocument},
                                                    std::move(credentials), signingPlugin, session);

    SignOutcome out;
    out.status = mapSigningResultStatus(result);
    out.resolvedFormat = params.format;
    out.resolvedLevel = params.level;
    // Honest tsaUsed (D-d): the installed SigningResult carries no per-token
    // timestamp flag, so derive it — a timestamp was applied iff the sign
    // succeeded at a qualified level AND a TSA was configured (the LM had a
    // non-empty provider to contact — the per-request override when present,
    // else the engine's own config-bound one). Never a bare level guess: B-B
    // is always false, and a qualified level with no TSA configured fails
    // closed upstream (TsaUnreachable) rather than reporting a phantom
    // timestamp.
    out.tsaUsed = SignatureParams::timestampWasApplied(out.status == SignOutcome::Status::Ok, params.level,
                                                       !effectiveTsaUrl.empty());
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
        // (read-only LastTsaUrl; the agent is the sole writer) — the per-request
        // override when this sign supplied one, else the engine's own bound
        // URL; see effectiveTsaUrl above. A no-op when no TSA was contacted
        // (tsaUsed false), so a plain B-B sign never touches it. Skipped once
        // the operation is cancelled: on shutdown an abandoned worker that
        // unblocks here must not mutate config, whose change notification
        // would re-enter the (by then torn-down) host wiring.
        if (out.tsaUsed && !token.isCancelled()) {
            m_engine.recordLastTsaUrlUsed(effectiveTsaUrl);
        }
    }
    return out;
}

// --- LmCredentialDepositor -----------------------------------------------
//
// See the seam's declaration for the rule this implementation obeys and why:
// the resolution below is registry-only, takes no session, and performs no card
// I/O of any kind.

std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>>
resolveDepositTargets(LibreSCRS::Plugin::CardPluginService& service, const CandidateList& candidates)
{
    std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>> targets;
    if (candidates.empty()) {
        return targets;
    }
    std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>> loaded;
    try {
        loaded = service.plugins();
    } catch (...) {
        return targets;
    }
    targets.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        if (!candidate) {
            continue;
        }
        for (const auto& plugin : loaded) {
            if (plugin && plugin->pluginId() == candidate->pluginId()) {
                targets.push_back(plugin);
                break;
            }
        }
    }
    return targets;
}

bool LmCredentialDepositor::depositMrz(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                                       const MrzParts& parts)
{
    bool accepted = false;
    for (const auto& plugin : resolveDepositTargets(m_service, candidates)) {
        try {
            // The three plugin-facing keys, check digits stripped: the plugin
            // re-pads the document number and derives the MRZ information
            // itself, so PACE and BAC can never key differently.
            plugin->setCredentials(session, "mrz_doc_number", parts.documentNumber);
            plugin->setCredentials(session, "mrz_dob", parts.dateOfBirth);
            plugin->setCredentials(session, "mrz_expiry", parts.dateOfExpiry);
            accepted = true;
        } catch (...) {
            // A plugin that refuses the deposit is skipped; another candidate
            // may still consume it, and the re-run's own auth failure is the
            // truthful outcome if none does.
            log::warn("credential deposit refused by plugin");
        }
    }
    return accepted;
}

CertReadOutcome LmCertificateReader::read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                                          LibreSCRS::CancelToken token)
{
    if (candidates.empty()) {
        return CertReadOutcome{CertReadOutcome::Status::UnsupportedCard, {}, "no PKI-capable plugin", {}};
    }
    if (token.isCancelled()) {
        return CertReadOutcome{CertReadOutcome::Status::Cancelled, {}, {}, {}};
    }
    // Lazy fallback: the first candidate that yields a non-empty cert list is the
    // active PKI applet. An empty list is Ok-with-no-certs (matching the prior
    // single-plugin behaviour), so it is returned only when every candidate is
    // empty. Candidate plugins switch applets via their own SM-wrapped SELECT on
    // the SAME session — never open a new one.
    CertReadOutcome last{CertReadOutcome::Status::Ok, {}, {}, {}};
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        if (token.isCancelled()) {
            return CertReadOutcome{CertReadOutcome::Status::Cancelled, {}, {}, {}};
        }
        std::vector<LibreSCRS::Plugin::CertificateData> raw;
        try {
            raw = cand->readCertificates(session);
        } catch (...) {
            log::warn("cert-read: a candidate threw on readCertificates; skipping it");
            last = CertReadOutcome{CertReadOutcome::Status::CommunicationError, {}, "readCertificates failed", {}};
            continue;
        }
        CertReadOutcome out;
        out.status = CertReadOutcome::Status::Ok;
        out.certs.reserve(raw.size());
        for (const auto& cd : raw) {
            if (token.isCancelled()) {
                return CertReadOutcome{CertReadOutcome::Status::Cancelled, {}, {}, {}};
            }
            if (cd.derBytes.empty()) {
                log::warn("cert-read: skipping a card certificate with empty DER");
                continue; // never mint a certId that aliases the SHA-256("") constant
            }
            out.certs.push_back(certSnapshotFromDer(cd));
            out.derBytes.push_back(cd.derBytes); // index-aligned with out.certs -- see CertReadOutcome::derBytes
        }
        if (!out.certs.empty()) {
            return out; // first candidate with readable certs wins
        }
        last = std::move(out); // empty-but-Ok; keep looking for a non-empty one
    }
    return last;
}

// --- LmCredentialManager ---------------------------------------------------

namespace {

// Route a MUTATING PIN operation across the candidate list. Only a REAL
// Unsupported (the LM base default — the plugin did not implement the flow, so
// no card interaction happened) falls through to the next candidate; any other
// outcome is the card's answer and returns immediately — a mutation is NEVER
// retried on another candidate, so a failed attempt cannot burn a second retry
// counter. A throwing candidate maps to PluginError and also stops routing:
// after a throw mid-mutation the card state is unknown, so retrying elsewhere
// would be unsafe. All-Unsupported (or an empty list) answers Unsupported —
// the valid outcome for a card that advertises no credential management.
template <typename Op>
LibreSCRS::Plugin::PINResult routePinMutation(const CandidateList& candidates, const char* opName, Op&& op)
{
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        LibreSCRS::Plugin::PINResult result;
        try {
            result = op(*cand);
        } catch (...) {
            log::warnf("credential: a candidate threw on {}; failing the operation", opName);
            result = {};
            result.outcome = LibreSCRS::Plugin::PINResultOutcome::PluginError;
            return result;
        }
        if (result.outcome != LibreSCRS::Plugin::PINResultOutcome::Unsupported) {
            return result;
        }
    }
    LibreSCRS::Plugin::PINResult unsupported;
    unsupported.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported;
    return unsupported;
}

} // namespace

CredentialListing LmCredentialManager::list(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates)
{
    // Lazy fallback, cert-reader style: the first candidate reporting a
    // non-empty PIN list is the active applet — its identity is returned with
    // the entries so the flow can bind the snapshot to the listing plugin.
    // Candidate plugins switch applets via their own SM-wrapped SELECT on the
    // SAME session — never open a new one. A throwing candidate is skipped
    // (read-only operation).
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        std::vector<LibreSCRS::Plugin::PinStatusEntry> entries;
        try {
            entries = cand->getPINList(session);
        } catch (...) {
            log::warn("credential: a candidate threw on getPINList; skipping it");
            continue;
        }
        if (!entries.empty()) {
            return {std::move(entries), cand->pluginId()};
        }
    }
    return {};
}

LibreSCRS::Plugin::PINResult LmCredentialManager::changePIN(LibreSCRS::SmartCard::CardSession& session,
                                                            const CandidateList& candidates, std::string_view pinLabel,
                                                            const LibreSCRS::Secure::String& oldPin,
                                                            const LibreSCRS::Secure::String& newPin)
{
    return routePinMutation(candidates, "changePIN", [&](const LibreSCRS::Plugin::CardPlugin& plugin) {
        return plugin.changePIN(session, pinLabel, oldPin, newPin);
    });
}

LibreSCRS::Plugin::PINResult LmCredentialManager::activateTransportPin(LibreSCRS::SmartCard::CardSession& session,
                                                                       const CandidateList& candidates,
                                                                       std::string_view pinLabel,
                                                                       const LibreSCRS::Secure::String& transportValue,
                                                                       const LibreSCRS::Secure::String& newPin)
{
    return routePinMutation(candidates, "activateTransportPin", [&](const LibreSCRS::Plugin::CardPlugin& plugin) {
        return plugin.activateTransportPin(session, pinLabel, transportValue, newPin);
    });
}

LibreSCRS::Plugin::PINResult LmCredentialManager::activateSigningKey(LibreSCRS::SmartCard::CardSession& session,
                                                                     const CandidateList& candidates,
                                                                     const LibreSCRS::Secure::String& signPin)
{
    return routePinMutation(candidates, "activateSigningKey", [&](const LibreSCRS::Plugin::CardPlugin& plugin) {
        return plugin.activateSigningKey(session, signPin);
    });
}

// --- Card-independent visual-signature layout preview --------------------

VisualLayoutResult layoutVisualSignature(std::string_view textUtf8, LayoutBox box)
{
    // The caller (each daemon's Manager1.LayoutVisualSignature handler) has
    // already validated @p box via SignatureParams::isValidLayoutRect, so this
    // narrowing mirrors buildSigningRequest's identical rounding of Sign's
    // `visualSignature` option -- see this function's declaration comment.
    const LibreSCRS::Signing::Rect rect{
        static_cast<int>(std::lround(box.x)),
        static_cast<int>(std::lround(box.y)),
        static_cast<int>(std::lround(box.width)),
        static_cast<int>(std::lround(box.height)),
    };
    LibreSCRS::Signing::VisualSignatureLayout lm = LibreSCRS::Signing::layoutVisualSignature(textUtf8, rect);
    VisualLayoutResult out;
    out.fontSize = static_cast<double>(lm.fontSize);
    out.lineHeight = static_cast<double>(lm.lineHeight);
    out.lines = std::move(lm.lines);
    out.clipped = lm.clipped;
    return out;
}

std::vector<std::uint8_t> appearanceFontBytes()
{
    const std::span<const std::byte> font = LibreSCRS::Signing::embeddedAppearanceFontData();
    std::vector<std::uint8_t> out(font.size());
    std::transform(font.begin(), font.end(), out.begin(), [](std::byte b) { return static_cast<std::uint8_t>(b); });
    return out;
}

} // namespace LibreSCRS::Agent::Operations
