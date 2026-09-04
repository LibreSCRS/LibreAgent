// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// gtest main with a QCoreApplication: the client's queued terminal emits
// (entry refusals, ctor recovery) deliver through the thread's event loop, so
// suites that spin processEvents() need a live application object.

#include <LibreSCRS/AgentClient/OperationPhase.h>

#include <QCoreApplication>
#include <QMetaType>

#include <gtest/gtest.h>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    // The operation-phase enum is declared no metatype anywhere in this client,
    // so Qt knows it only through the type-based paths moc fills in
    // automatically; it is absent from the registry QMetaType::fromName() and
    // every other name-driven Qt API consult. Register it here, once per
    // process, rather than leaving each suite to find the gap for itself.
    //
    // Both spellings are registered because they are different strings: the
    // no-arg call files the enum under its canonical name, which is NOT the
    // `LibreSCRS::AgentClient::` alias this client's own signal signatures --
    // and therefore moc's recorded parameter type names -- are written with.
    qRegisterMetaType<LibreSCRS::AgentClient::OperationPhase>();
    qRegisterMetaType<LibreSCRS::AgentClient::OperationPhase>("LibreSCRS::AgentClient::OperationPhase");

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
