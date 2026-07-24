// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// gtest main with a QCoreApplication: the client's queued terminal emits
// (entry refusals, ctor recovery) deliver through the thread's event loop, so
// suites that spin processEvents() need a live application object.

#include <QCoreApplication>

#include <gtest/gtest.h>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
