// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// One scripted certificate `fields` dict, in ONE shape both fakes accept.
//
// Its own header for the same two reasons FakeConfig.h has one. The build
// reason: FakeAgent.h pulls in QtDBus and the socket suite neither compiles
// that TU nor links Qt6::DBus, so anything the two fakes share has to sit in
// a QtDBus-free header. The contract reason: the client-side promise is that
// BOTH wires land this dict on `CertificateInfo::extra["fields"]` in one
// identical shape, so a parity scenario has to script the groups ONCE and let
// each fake re-encode them into its own wire form -- a nested `a{sa{s(ssv)}}`
// D-Bus map on one side, a CBOR map of 3-element arrays on the other. Two
// scripted shapes, one per fake, would let the thing under test be scripted
// differently on each side of the comparison it exists to make.
#include <QMap>
#include <QString>

namespace LibreSCRS::AgentClient::Fakes {

/// @brief One scripted `cert-field` cell -- the wire's `(ssv)` / 3-element
///        array triple, before either fake encodes it.
struct FakeCertField
{
    QString labelKey;
    QString labelFallback;
    QString value;
};

/// @brief group key -> field key -> cell, mirroring the wire's own nesting.
using FakeCertFieldGroups = QMap<QString, QMap<QString, FakeCertField>>;

} // namespace LibreSCRS::AgentClient::Fakes
