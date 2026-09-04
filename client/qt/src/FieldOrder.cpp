// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/AgentClient/FieldOrder.h>

#include <QLatin1String>

namespace LibreSCRS::AgentClient {

QStringList fieldOrderForGroup(const QString& groupKey)
{
    const bool isAnnex = groupKey.startsWith(QLatin1String("annex."));

    // The annex's substance is an address, and the wire hands it over sorted
    // by key. This is the order it is read in.
    if (isAnnex && groupKey.endsWith(QLatin1String(".personal"))) {
        return {
            QStringLiteral("address_label"),     QStringLiteral("street"),
            QStringLiteral("house_number"),      QStringLiteral("house_letter"),
            QStringLiteral("entrance"),          QStringLiteral("floor"),
            QStringLiteral("apartment_number"),  QStringLiteral("place"),
            QStringLiteral("community"),         QStringLiteral("state"),
            QStringLiteral("parent_given_name"), QStringLiteral("community_of_birth"),
            QStringLiteral("state_of_birth"),    QStringLiteral("document_serial"),
            QStringLiteral("address_date"),
        };
    }

    // The annex's verdict pair reads integrity-then-authenticity; the
    // key-sorted wire would put authenticity first. Fields outside the pair
    // keep delivery order, after the pinned two.
    if (isAnnex && groupKey.endsWith(QLatin1String(".security"))) {
        return {QStringLiteral("annex_integrity"), QStringLiteral("annex_authenticity")};
    }

    return {};
}

} // namespace LibreSCRS::AgentClient
