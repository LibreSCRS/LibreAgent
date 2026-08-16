// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Known-answer test for the agent-side X.509 parser (certSnapshotFromDer). A
// self-signed v3 certificate is minted with OpenSSL at runtime, fed through the
// exposed parser, and the rendered CertSnapshot fields are asserted. This is the
// regression lock for the frozen Certificates1 field values — in particular the
// version rendering ("v3", not "v4": ParsedCertificate::version() already
// returns the human number) and the keyUsage -> bitmask / signingCapable logic.
#include <LibreSCRS/Agent/operations/LmSeams.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// Mint a self-signed v3 RSA cert with a keyUsage extension; return its DER.
std::vector<std::uint8_t> makeSelfSignedV3Der(const char* commonName, const char* keyUsageValue)
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    EXPECT_NE(x, nullptr);

    X509_set_version(x, 2); // 2 == v3 (raw OpenSSL field is 0-indexed)
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1234);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("LibreSCRS Test"), -1,
                               -1, 0);
    X509_set_issuer_name(x, name); // self-signed: issuer == subject

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, keyUsageValue)) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }

    EXPECT_GT(X509_sign(x, pkey, EVP_sha256()), 0);

    unsigned char* der = nullptr;
    const int len = i2d_X509(x, &der);
    std::vector<std::uint8_t> out;
    if (len > 0 && der != nullptr) {
        out.assign(der, der + len);
    }
    OPENSSL_free(der);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

// Mint a self-signed v3 RSA cert carrying the V10-audit extension set (SAN,
// IAN, basicConstraints, SKI, AKI, CRL DPs, AIA, certificate policies) so the
// vocabulary-append KAT below can assert each typed group agent-side. A
// helper local to this TU -- distinct from makeSelfSignedV3Der so the plain
// keyUsage KATs above stay minimal and unaffected by this richer extension set.
std::vector<std::uint8_t> makeRichV3Der(const char* commonName)
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    EXPECT_NE(x, nullptr);

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x5678);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    X509_set_issuer_name(x, name); // self-signed: issuer == subject

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);

    const auto addExt = [&](int nid, const char* value) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
        EXPECT_NE(ext, nullptr) << "failed to build extension nid=" << nid << " value=" << value;
        if (ext != nullptr) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
    };
    // SKI is minted CRITICAL, which RFC 5280 §4.2.1.2 says it must never be.
    // Deliberate: the criticality marker reaches a `cert`-group CELL's label
    // through a different code path than a typed GROUP's label, and SKI/AKI
    // are the only two typed OIDs that land in a cell -- neither of which any
    // conforming issuer ever marks critical. A KAT is the only place that path
    // can be exercised at all, so this certificate is odd on purpose.
    addExt(NID_subject_key_identifier, "critical,hash");
    // SKI must exist on the (self-)issuer cert BEFORE AKI's "keyid" lookup runs.
    addExt(NID_authority_key_identifier, "keyid:always");
    addExt(NID_basic_constraints, "critical,CA:TRUE,pathlen:1");
    // One EKU the OID database knows by name and one it cannot possibly know,
    // in that order -- the friendly-name treatment and its dotted fallback are
    // the same call, and only a pair proves the fallback is a fallback rather
    // than the whole behaviour.
    addExt(NID_ext_key_usage, "emailProtection,1.3.6.1.4.1.99999.1");
    addExt(NID_subject_alt_name, "DNS:example.org,email:pera@example.org");
    addExt(NID_issuer_alt_name, "DNS:issuer.example.org");
    addExt(NID_crl_distribution_points, "URI:https://example.org/crl.der");
    addExt(NID_info_access, "OCSP;URI:https://example.org/ocsp,caIssuers;URI:https://example.org/ca.crt");
    // certificatePolicies has no bare-OID X509V3_EXT_conf_nid shortcut (it
    // needs a CONF "@section" for anything beyond the plainest form) --
    // built directly via the ASN.1 stack API instead.
    if (CERTIFICATEPOLICIES* cp = sk_POLICYINFO_new_null()) {
        if (POLICYINFO* pi = POLICYINFO_new()) {
            pi->policyid = OBJ_txt2obj("2.23.140.1.2.1", 1);
            sk_POLICYINFO_push(cp, pi);
            X509_add1_ext_i2d(x, NID_certificate_policies, cp, 0, X509V3_ADD_APPEND);
        }
        CERTIFICATEPOLICIES_free(cp);
    }

    EXPECT_GT(X509_sign(x, pkey, EVP_sha256()), 0);

    unsigned char* der = nullptr;
    const int len = i2d_X509(x, &der);
    std::vector<std::uint8_t> out;
    if (len > 0 && der != nullptr) {
        out.assign(der, der + len);
    }
    OPENSSL_free(der);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

std::optional<std::string> field(const CertSnapshot& s, const std::string& group, const std::string& key)
{
    for (const auto& g : s.fields) {
        if (g.groupKey == group) {
            for (const auto& f : g.fields) {
                if (f.fieldKey == key) {
                    return f.textValue;
                }
            }
        }
    }
    return std::nullopt;
}

// The English label a client renders for a whole group when it has no
// catalogue entry for the group's labelKey.
std::optional<std::string> groupLabel(const CertSnapshot& s, const std::string& group)
{
    for (const auto& g : s.fields) {
        if (g.groupKey == group) {
            return g.labelFallback;
        }
    }
    return std::nullopt;
}

// The same, for one field inside a group.
std::optional<std::string> fieldLabel(const CertSnapshot& s, const std::string& group, const std::string& key)
{
    for (const auto& g : s.fields) {
        if (g.groupKey == group) {
            for (const auto& f : g.fields) {
                if (f.fieldKey == key) {
                    return f.labelFallback;
                }
            }
        }
    }
    return std::nullopt;
}

// The i18n key a client would look a field's label up under.
std::optional<std::string> fieldLabelKey(const CertSnapshot& s, const std::string& group, const std::string& key)
{
    for (const auto& g : s.fields) {
        if (g.groupKey == group) {
            for (const auto& f : g.fields) {
                if (f.fieldKey == key) {
                    return f.labelKey;
                }
            }
        }
    }
    return std::nullopt;
}

constexpr std::uint32_t kDigitalSignatureBit = 1u << 0; // RFC 5280 bit 0

} // namespace

TEST(LmCertReaderKat, ParsesV3SigningCert)
{
    const auto der = makeSelfSignedV3Der("Pera Peric", "critical,digitalSignature");
    ASSERT_FALSE(der.empty());

    LibreSCRS::Plugin::CertificateData cd;
    cd.label = "Signature";
    cd.derBytes = der;
    cd.keyFID = std::uint16_t{0x1234}; // pairs to an on-card key

    const CertSnapshot s = certSnapshotFromDer(cd);

    EXPECT_EQ(s.certId.size(), 64u) << "certId is lowercase-hex SHA-256(DER)";
    EXPECT_TRUE(s.signingCapable) << "keyFID present + digitalSignature usage";
    EXPECT_NE(s.keyUsageBits & kDigitalSignatureBit, 0u);

    EXPECT_EQ(field(s, "subject", "cn"), "Pera Peric");
    EXPECT_EQ(field(s, "issuer", "cn"), "Pera Peric"); // self-signed
    EXPECT_EQ(field(s, "publicKey", "algorithm"), "RSA");
    EXPECT_EQ(field(s, "publicKey", "sizeBits"), "2048");
    // THE version regression lock: human "v3", not "v4".
    EXPECT_EQ(field(s, "cert", "version"), "v3");
    ASSERT_TRUE(field(s, "validity", "notAfter").has_value());
    EXPECT_NE(field(s, "validity", "notAfter")->find('Z'), std::string::npos) << "ISO-8601 UTC";
    EXPECT_TRUE(field(s, "subject", "dn").has_value());
}

TEST(LmCertReaderKat, NonSigningKeyUsageIsNotSigningCapable)
{
    // keyEncipherment-only cert with a paired key must NOT be signingCapable.
    const auto der = makeSelfSignedV3Der("Enc Only", "critical,keyEncipherment");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    cd.keyFID = std::uint16_t{0x1};
    const CertSnapshot s = certSnapshotFromDer(cd);
    EXPECT_FALSE(s.signingCapable) << "keyUsage lacks digitalSignature/nonRepudiation";
}

TEST(LmCertReaderKat, NoPairedKeyIsNotSigningCapable)
{
    const auto der = makeSelfSignedV3Der("No Key", "critical,digitalSignature");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der; // keyFID unset
    const CertSnapshot s = certSnapshotFromDer(cd);
    EXPECT_FALSE(s.signingCapable) << "no on-card private key paired";
}

TEST(LmCertReaderKat, GarbageDerYieldsDiagnosticNotCrash)
{
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = {0xDE, 0xAD, 0xBE, 0xEF};
    cd.keyFID = std::uint16_t{0x1};
    const CertSnapshot s = certSnapshotFromDer(cd);
    EXPECT_EQ(s.certId.size(), 64u) << "certId still minted from the raw bytes";
    EXPECT_FALSE(s.signingCapable) << "unparseable cert is never a usable signing handle";
    EXPECT_TRUE(field(s, "diagnostic", "parseError").has_value()) << "failure surfaced in the reserved group";
    EXPECT_TRUE(s.chainSubjectCns.empty()) << "no PKCS#15 label leaks into chainSubjectCns";
}

// --- V10 vocabulary-append KATs -------------------------------------------
// The audit found these fields available agent-side (LM's ParsedCertificate
// already exposes them) but not yet on the wire; each assertion below is the
// regression lock for the append.

TEST(LmCertReaderKat, SanAndIanDecodePerType)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    EXPECT_EQ(field(s, "san", "dns0"), "example.org");
    EXPECT_EQ(field(s, "san", "email1"), "pera@example.org");
    EXPECT_EQ(field(s, "ian", "dns0"), "issuer.example.org");
}

TEST(LmCertReaderKat, BasicConstraintsDecodesCaAndPathLen)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    EXPECT_EQ(field(s, "basicConstraints", "isCa"), "true");
    EXPECT_EQ(field(s, "basicConstraints", "pathLen"), "1");
}

TEST(LmCertReaderKat, SubjectAndAuthorityKeyIdentifierAreCleanHex)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    const auto ski = field(s, "cert", "subjectKeyIdentifier");
    ASSERT_TRUE(ski.has_value());
    // Colon-separated upper-hex, no ASN.1 tag/length prefix bytes leaking in
    // (a raw extnValue dump would start with "0414" for a 20-byte SKI).
    EXPECT_EQ(ski->find("04:14:"), std::string::npos) << *ski;
    EXPECT_NE(ski->find(':'), std::string::npos) << *ski;

    const auto aki = field(s, "cert", "authorityKeyIdentifier");
    ASSERT_TRUE(aki.has_value());
    EXPECT_NE(aki->find(':'), std::string::npos) << *aki;
}

TEST(LmCertReaderKat, CrlDpAiaAndPoliciesDecode)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    EXPECT_EQ(field(s, "crlDp", "url0"), "https://example.org/crl.der");
    EXPECT_EQ(field(s, "aia", "ocsp0"), "https://example.org/ocsp");
    EXPECT_EQ(field(s, "aia", "caIssuers0"), "https://example.org/ca.crt");
    ASSERT_TRUE(field(s, "certificatePolicies", "policy0").has_value());
}

TEST(LmCertReaderKat, CriticalExtensionLabelSuffixAndNoDuplicateRawDump)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    // basicConstraints was minted "critical" above; the generic "ext" dump
    // must not carry a SECOND (raw hex) row for an OID already served by a
    // typed group -- the raw "ext" group, if present at all here, must not
    // contain the BasicConstraints OID.
    for (const auto& g : s.fields) {
        if (g.groupKey != "ext") {
            continue;
        }
        for (const auto& f : g.fields) {
            EXPECT_NE(f.fieldKey, "2.5.29.19") << "BasicConstraints must not duplicate into the raw ext dump";
        }
    }
}

// --- criticality on the typed groups + friendly extended key usage ---------
// The generic "ext" dump has always suffixed a critical extension's label with
// " (Critical)". The ten OIDs a typed group serves are skipped by that dump, so
// until now their criticality reached no client at all -- a viewer that renders
// critical extensions differently (a label suffix, a bold row) had nothing to
// render from for exactly the extensions most likely to BE critical.
//
// A typed group's criticality rides a FIELD, not the group's own label. The
// group label was the first shape tried and it never reached anybody: the wire
// carries group KEYS and per-field tuples only, so neither transport had a slot
// to serialize a group's label into, and this KAT -- which reads the snapshot
// BEFORE serialization -- passed while the marker died inside the daemon. A
// field is the one carrier both emitters already move generically, and these
// assertions are on the same field pipeline the decode tests prove end to end.

TEST(LmCertReaderKat, TypedGroupsCarryCriticalityAsADataCell)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    // basicConstraints is minted critical: the group grows a "critical" cell
    // whose value says so. The empty labelKey is the cell's own signature --
    // it is group metadata, not a row a client should look a catalogue entry
    // up for and print.
    EXPECT_EQ(field(s, "basicConstraints", "critical"), "true");
    EXPECT_EQ(fieldLabel(s, "basicConstraints", "critical"), "Critical");
    EXPECT_EQ(fieldLabelKey(s, "basicConstraints", "critical"), "");

    // The non-critical typed groups must NOT grow the cell at all -- a marker
    // every group carries marks nothing, and an absent cell is how a client
    // tells "not critical" from "this agent does not report criticality".
    EXPECT_FALSE(field(s, "san", "critical").has_value());
    EXPECT_FALSE(field(s, "ian", "critical").has_value());
    EXPECT_FALSE(field(s, "crlDp", "critical").has_value());
    EXPECT_FALSE(field(s, "aia", "critical").has_value());
    EXPECT_FALSE(field(s, "certificatePolicies", "critical").has_value());
    EXPECT_FALSE(field(s, "eku", "critical").has_value());

    // And the group labels stay plain: the suffix that never reached a client
    // is gone, so no consumer can be tempted to parse a label for a flag.
    EXPECT_EQ(groupLabel(s, "basicConstraints"), "Basic Constraints");
    EXPECT_EQ(groupLabel(s, "san"), "Subject Alternative Name");
    EXPECT_EQ(groupLabel(s, "ian"), "Issuer Alternative Name");
    EXPECT_EQ(groupLabel(s, "crlDp"), "CRL Distribution Points");
    EXPECT_EQ(groupLabel(s, "aia"), "Authority Information Access");
    EXPECT_EQ(groupLabel(s, "certificatePolicies"), "Certificate Policies");
    EXPECT_EQ(groupLabel(s, "eku"), "Extended Key Usage");
}

TEST(LmCertReaderKat, CriticalSuffixReachesCertGroupCellLabelsToo)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    // SKI and AKI are the two typed OIDs whose values are CELLS of the "cert"
    // group rather than groups of their own, so their marker rides the field
    // label. The fixture mints SKI critical and AKI not, which is the only way
    // one certificate pins both sides of the branch.
    EXPECT_EQ(fieldLabel(s, "cert", "subjectKeyIdentifier"), "Subject Key Identifier (Critical)");
    EXPECT_EQ(fieldLabel(s, "cert", "authorityKeyIdentifier"), "Authority Key Identifier");

    // A cell the marker has no business touching stays exactly as it was.
    EXPECT_EQ(fieldLabel(s, "cert", "serial"), "Serial Number");
}

TEST(LmCertReaderKat, ExtendedKeyUsageGroupCarriesFriendlyNamesWithDottedFallback)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    // The OID database resolves the first; the second cannot be resolved by
    // anything, and falls back to its dotted form rather than to an empty row.
    EXPECT_EQ(field(s, "eku", "usage0"), "E-mail Protection");
    EXPECT_EQ(field(s, "eku", "usage1"), "1.3.6.1.4.1.99999.1");

    // The typed member is untouched: it stays the machine-readable dotted list
    // a caller matches on, and the group is the human-readable rendering. One
    // is not a copy of the other, which is why both may exist.
    ASSERT_EQ(s.ekuOids.size(), 2u);
    EXPECT_EQ(s.ekuOids[0], "1.3.6.1.5.5.7.3.4");
    EXPECT_EQ(s.ekuOids[1], "1.3.6.1.4.1.99999.1");
}

TEST(LmCertReaderKat, ExtendedKeyUsageIsNotAlsoDumpedRaw)
{
    const auto der = makeRichV3Der("Rich Cert");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    // 2.5.29.37 has been on the typed-OID skip list all along; now that it also
    // owns a group, a client seeing it twice -- once named, once as opaque hex
    // -- would be the same duplicate the skip list exists to prevent.
    for (const auto& g : s.fields) {
        if (g.groupKey != "ext") {
            continue;
        }
        for (const auto& f : g.fields) {
            EXPECT_NE(f.fieldKey, "2.5.29.37") << "ExtendedKeyUsage must not duplicate into the raw ext dump";
        }
    }
}

// A certificate carrying NO extended key usage extension must carry no "eku"
// group at all -- an empty group is a row a viewer renders as a blank heading,
// and every other optional typed group already declines to emit one.
TEST(LmCertReaderKat, NoExtendedKeyUsageMeansNoEkuGroup)
{
    const auto der = makeSelfSignedV3Der("Plain Cert", "critical,digitalSignature");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    const CertSnapshot s = certSnapshotFromDer(cd);

    EXPECT_FALSE(groupLabel(s, "eku").has_value());
    EXPECT_TRUE(s.ekuOids.empty());
}
