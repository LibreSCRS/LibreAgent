// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief INTERNAL — never installed. Shared D-Bus wire constants for the
///        client's D-Bus transport.
///
/// The single source of truth for the agent's bus name, the manager object
/// path, and every interface name the transport touches. Hand-spelling these
/// per translation unit turns a typo into a silent routing failure with no
/// compile error; declaring them once here keeps every call site referencing
/// the same literal. (The agent's D-Bus XML remains the cross-stack contract;
/// this header is the client-side mirror of those names. Timeout budgets live
/// in the PUBLIC ClientTimeouts.h — they are transport-neutral contract, not
/// D-Bus vocabulary.)

namespace LibreSCRS::AgentClient {

// Bus name + manager object path.
inline constexpr const char* kService = "org.librescrs.Agent";
inline constexpr const char* kRootPath = "/org/librescrs/Agent";

// Standard freedesktop interfaces.
inline constexpr const char* kObjectManagerIface = "org.freedesktop.DBus.ObjectManager";
inline constexpr const char* kPropertiesIface = "org.freedesktop.DBus.Properties";

// Agent object interfaces.
inline constexpr const char* kReaderIface = "org.librescrs.Agent.Reader1";
inline constexpr const char* kCardIface = "org.librescrs.Agent.Card1";
inline constexpr const char* kPkcs11Iface = "org.librescrs.Agent.Pkcs11_1";
inline constexpr const char* kCredentialsIface = "org.librescrs.Agent.Credentials1";

// Operation1 + its typed result interfaces.
inline constexpr const char* kOperationIface = "org.librescrs.Agent.Operation1";
inline constexpr const char* kSignIface = "org.librescrs.Agent.Operation.Sign1";
inline constexpr const char* kIdentityIface = "org.librescrs.Agent.Operation.Identity1";
inline constexpr const char* kCertificatesIface = "org.librescrs.Agent.Operation.Certificates1";
inline constexpr const char* kPhotoIface = "org.librescrs.Agent.Operation.Photo1";
inline constexpr const char* kOperationCredentialsIface = "org.librescrs.Agent.Operation.Credentials1";

// The agent's error-name namespace (see ErrorNameMap.h for the mapping into
// the public CallError/ErrorCode surface).
inline constexpr const char* kAgentErrorPrefix = "org.librescrs.Agent.Error.";

} // namespace LibreSCRS::AgentClient
