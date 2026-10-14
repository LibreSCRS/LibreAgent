// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The secret keys C_DeriveKey makes from an ECDH secret: session objects the
// module holds for the application that made them, by the module's own rules
// (no token storage, private, sensitive and unextractable unless the template
// asks otherwise). Pure functions over a template and a value; SessionState
// keeps them, Module.cpp serves them.
#pragma once

#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief What a C_DeriveKey template asks for, once checked.
struct DerivedKeyTemplate
{
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    std::optional<CK_ULONG> valueLen; ///< CKA_VALUE_LEN, when the template names one
    bool sensitive = true;            ///< safe default; SoftHSM 2.7.0 says FALSE
    bool extractable = false;
    std::string label;
    std::vector<std::uint8_t> id;
    /// CKA_ENCRYPT / DECRYPT / WRAP / UNWRAP / SIGN / VERIFY / DERIVE as given.
    /// Kept and served; no mechanism here runs on a derived key.
    std::vector<std::pair<CK_ATTRIBUTE_TYPE, CK_BBOOL>> usage;
};

/// @brief Check @p tmpl: CKO_SECRET_KEY, CKK_GENERIC_SECRET or CKK_AES (with
///        CKA_VALUE_LEN 16/24/32), never a token object, always private.
/// @return The template, or CKR_TEMPLATE_INCONSISTENT / CKR_TEMPLATE_INCOMPLETE /
///         CKR_ATTRIBUTE_VALUE_INVALID / CKR_ATTRIBUTE_READ_ONLY (an attribute
///         only the module sets: CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
///         CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM, CKA_VALUE) /
///         CKR_ATTRIBUTE_TYPE_INVALID.
[[nodiscard]] std::expected<DerivedKeyTemplate, CK_RV> parseDerivedKeyTemplate(const CK_ATTRIBUTE* tmpl,
                                                                               CK_ULONG count);

/// @brief The value a key derived from @p z holds under @p t: all of Z, or its
///        LAST CKA_VALUE_LEN bytes (as SoftHSM does). Longer than Z is
///        CKR_TEMPLATE_INCONSISTENT -- the template's fault, not the token's.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, CK_RV> derivedKeyValue(std::span<const std::uint8_t> z,
                                                                              const DerivedKeyTemplate& t);

/// @brief One derived secret key. The value is wiped when the key is destroyed.
struct DerivedKey
{
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE creator = 0;
    DerivedKeyTemplate attributes;
    std::vector<std::uint8_t> value;

    DerivedKey() = default;
    DerivedKey(DerivedKey&& other) noexcept = default;
    // Move-assignment would release the old value unwiped.
    DerivedKey& operator=(DerivedKey&&) = delete;
    DerivedKey(const DerivedKey&) = delete;
    DerivedKey& operator=(const DerivedKey&) = delete;
    ~DerivedKey();
};

/// @brief Serve one attribute of @p key by the module's buffer protocol.
///        CKA_VALUE of a sensitive or unextractable key is CKR_ATTRIBUTE_SENSITIVE.
[[nodiscard]] CK_RV serveDerivedKeyAttribute(const DerivedKey& key, CK_ATTRIBUTE& attr);

/// @brief True if @p key matches every attribute of @p tmpl this module
///        compares (class, key type, token, private, ID, label); any other is
///        permissive, as for the card's objects.
[[nodiscard]] bool derivedKeyMatches(const DerivedKey& key, const CK_ATTRIBUTE* tmpl, CK_ULONG count);

} // namespace LibreSCRS::Pkcs11Agent
