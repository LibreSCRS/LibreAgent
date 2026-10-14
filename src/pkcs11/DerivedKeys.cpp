// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/pkcs11/DerivedKeys.h>

#include <LibreSCRS/Agent/SecureZero.h>

#include <cstddef>
#include <cstring>

namespace LibreSCRS::Pkcs11Agent {

namespace {

std::optional<CK_BBOOL> boolOf(const CK_ATTRIBUTE& a)
{
    if (a.pValue == nullptr || a.ulValueLen != sizeof(CK_BBOOL)) {
        return std::nullopt;
    }
    return *static_cast<const CK_BBOOL*>(a.pValue);
}

template <typename T>
std::optional<T> scalarOf(const CK_ATTRIBUTE& a)
{
    if (a.pValue == nullptr || a.ulValueLen != sizeof(T)) {
        return std::nullopt;
    }
    T v{};
    std::memcpy(&v, a.pValue, sizeof(T));
    return v;
}

bool isUsageAttribute(CK_ATTRIBUTE_TYPE t)
{
    return t == CKA_ENCRYPT || t == CKA_DECRYPT || t == CKA_WRAP || t == CKA_UNWRAP || t == CKA_SIGN ||
           t == CKA_VERIFY || t == CKA_DERIVE;
}

CK_BBOOL usageOf(const DerivedKeyTemplate& t, CK_ATTRIBUTE_TYPE type)
{
    CK_BBOOL v = CK_FALSE;
    for (const auto& [attr, value] : t.usage) {
        if (attr == type) {
            v = value; // the last one given wins
        }
    }
    return v;
}

CK_RV give(CK_ATTRIBUTE& attr, const void* src, std::size_t len)
{
    if (attr.pValue == nullptr) {
        attr.ulValueLen = static_cast<CK_ULONG>(len);
        return CKR_OK;
    }
    if (attr.ulValueLen < len) {
        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (len != 0) {
        std::memcpy(attr.pValue, src, len);
    }
    attr.ulValueLen = static_cast<CK_ULONG>(len);
    return CKR_OK;
}

} // namespace

std::expected<DerivedKeyTemplate, CK_RV> parseDerivedKeyTemplate(const CK_ATTRIBUTE* tmpl, CK_ULONG count)
{
    if (count > 0 && tmpl == nullptr) {
        return std::unexpected(CKR_ARGUMENTS_BAD);
    }
    DerivedKeyTemplate t;
    for (CK_ULONG i = 0; i < count; ++i) {
        const CK_ATTRIBUTE& a = tmpl[i];
        if (isUsageAttribute(a.type)) {
            const auto b = boolOf(a);
            if (!b) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            t.usage.emplace_back(a.type, *b);
            continue;
        }
        switch (a.type) {
        case CKA_CLASS: {
            const auto c = scalarOf<CK_OBJECT_CLASS>(a);
            if (!c) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (*c != CKO_SECRET_KEY) {
                return std::unexpected(CKR_TEMPLATE_INCONSISTENT);
            }
            break;
        }
        case CKA_KEY_TYPE: {
            const auto k = scalarOf<CK_KEY_TYPE>(a);
            if (!k) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (*k != CKK_GENERIC_SECRET && *k != CKK_AES) {
                return std::unexpected(CKR_TEMPLATE_INCONSISTENT);
            }
            t.keyType = *k;
            break;
        }
        case CKA_VALUE_LEN: {
            const auto n = scalarOf<CK_ULONG>(a);
            if (!n || *n == 0) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            t.valueLen = *n;
            break;
        }
        case CKA_TOKEN: {
            const auto b = boolOf(a);
            if (!b) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (*b != CK_FALSE) {
                return std::unexpected(CKR_TEMPLATE_INCONSISTENT); // no token storage
            }
            break;
        }
        case CKA_PRIVATE: {
            const auto b = boolOf(a);
            if (!b) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (*b == CK_FALSE) {
                return std::unexpected(CKR_TEMPLATE_INCONSISTENT); // a secret is never public
            }
            break;
        }
        case CKA_SENSITIVE:
        case CKA_EXTRACTABLE: {
            const auto b = boolOf(a);
            if (!b) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            (a.type == CKA_SENSITIVE ? t.sensitive : t.extractable) = (*b != CK_FALSE);
            break;
        }
        case CKA_LABEL:
            if (a.pValue == nullptr && a.ulValueLen != 0) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (a.pValue != nullptr) {
                t.label.assign(static_cast<const char*>(a.pValue), a.ulValueLen);
            }
            break;
        case CKA_ID:
            if (a.pValue == nullptr && a.ulValueLen != 0) {
                return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (a.pValue != nullptr) {
                t.id.assign(static_cast<const std::uint8_t*>(a.pValue),
                            static_cast<const std::uint8_t*>(a.pValue) + a.ulValueLen);
            }
            break;
        case CKA_LOCAL:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_NEVER_EXTRACTABLE:
        case CKA_KEY_GEN_MECHANISM:
        case CKA_VALUE:
            // The module decides these for a key it makes; a template does not.
            return std::unexpected(CKR_ATTRIBUTE_READ_ONLY);
        default:
            return std::unexpected(CKR_ATTRIBUTE_TYPE_INVALID);
        }
    }
    if (t.keyType == CKK_AES) {
        if (!t.valueLen) {
            return std::unexpected(CKR_TEMPLATE_INCOMPLETE);
        }
        if (*t.valueLen != 16 && *t.valueLen != 24 && *t.valueLen != 32) {
            return std::unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    return t;
}

std::expected<std::vector<std::uint8_t>, CK_RV> derivedKeyValue(std::span<const std::uint8_t> z,
                                                                const DerivedKeyTemplate& t)
{
    if (!t.valueLen) {
        return std::vector<std::uint8_t>(z.begin(), z.end());
    }
    if (*t.valueLen > z.size()) {
        return std::unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
    return std::vector<std::uint8_t>(z.end() - static_cast<std::ptrdiff_t>(*t.valueLen), z.end());
}

DerivedKey::~DerivedKey()
{
    LibreSCRS::Agent::secureZero(value);
}

CK_RV serveDerivedKeyAttribute(const DerivedKey& key, CK_ATTRIBUTE& attr)
{
    const CK_BBOOL ckTrue = CK_TRUE;
    const CK_BBOOL ckFalse = CK_FALSE;
    const auto flag = [&](bool b) { return give(attr, b ? &ckTrue : &ckFalse, sizeof(CK_BBOOL)); };
    const DerivedKeyTemplate& t = key.attributes;
    switch (attr.type) {
    case CKA_CLASS: {
        const CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        return give(attr, &cls, sizeof(cls));
    }
    case CKA_KEY_TYPE:
        return give(attr, &t.keyType, sizeof(t.keyType));
    case CKA_TOKEN:
    case CKA_LOCAL:
        return flag(false);
    case CKA_PRIVATE:
        return flag(true);
    case CKA_SENSITIVE:
    case CKA_ALWAYS_SENSITIVE: // the card key it came from is always sensitive
        return flag(t.sensitive);
    case CKA_EXTRACTABLE:
        return flag(t.extractable);
    case CKA_NEVER_EXTRACTABLE:
        return flag(!t.extractable);
    case CKA_VALUE_LEN: {
        const CK_ULONG len = key.value.size();
        return give(attr, &len, sizeof(len));
    }
    case CKA_VALUE:
        if (t.sensitive || !t.extractable) {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_SENSITIVE;
        }
        return give(attr, key.value.data(), key.value.size());
    case CKA_LABEL:
        return give(attr, t.label.data(), t.label.size());
    case CKA_ID:
        return give(attr, t.id.data(), t.id.size());
    default:
        if (isUsageAttribute(attr.type)) {
            return flag(usageOf(t, attr.type) != CK_FALSE);
        }
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
}

bool derivedKeyMatches(const DerivedKey& key, const CK_ATTRIBUTE* tmpl, CK_ULONG count)
{
    for (CK_ULONG i = 0; i < count && tmpl != nullptr; ++i) {
        const CK_ATTRIBUTE& a = tmpl[i];
        switch (a.type) {
        case CKA_CLASS:
            if (const auto c = scalarOf<CK_OBJECT_CLASS>(a); c && *c != CKO_SECRET_KEY)
                return false;
            break;
        case CKA_KEY_TYPE:
            if (const auto k = scalarOf<CK_KEY_TYPE>(a); k && *k != key.attributes.keyType)
                return false;
            break;
        case CKA_TOKEN:
            if (const auto b = boolOf(a); b && *b != CK_FALSE)
                return false;
            break;
        case CKA_PRIVATE:
            if (const auto b = boolOf(a); b && *b == CK_FALSE)
                return false;
            break;
        case CKA_ID:
            if (a.pValue != nullptr && std::vector<std::uint8_t>(static_cast<const std::uint8_t*>(a.pValue),
                                                                 static_cast<const std::uint8_t*>(a.pValue) +
                                                                     a.ulValueLen) != key.attributes.id)
                return false;
            break;
        case CKA_LABEL:
            if (a.pValue != nullptr &&
                std::string(static_cast<const char*>(a.pValue), a.ulValueLen) != key.attributes.label)
                return false;
            break;
        default:
            break; // permissive, as for the card's objects
        }
    }
    return true;
}

} // namespace LibreSCRS::Pkcs11Agent
