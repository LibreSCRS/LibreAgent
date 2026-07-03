// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic coverage for the platform-neutral caller-label shaping: basename
// extraction and the untrusted-text anti-spoofing sanitiser. The backend's
// PID/token -> executable-path resolution is tested in the platform backend.

#include <LibreSCRS/Agent/util/CallerLabel.h>

#include <gtest/gtest.h>

#include <string>

using LibreSCRS::Agent::exeBasename;
using LibreSCRS::Agent::kMaxCallerLabelLength;
using LibreSCRS::Agent::sanitizeLabel;

TEST(CallerLabel, ExeBasenameStripsDirectory)
{
    EXPECT_EQ(exeBasename("/usr/lib/firefox/firefox"), "firefox");
    EXPECT_EQ(exeBasename("/usr/bin/seahorse"), "seahorse");
    EXPECT_EQ(exeBasename("plain"), "plain");
}

TEST(CallerLabel, ExeBasenameToleratesTrailingDeleted)
{
    // /proc/<pid>/exe of an exe whose file was replaced reads as
    // "<path> (deleted)". We keep only the file component; the " (deleted)"
    // suffix is part of the final path component and is preserved verbatim
    // (sanitisation handles any control bytes, not this benign marker).
    EXPECT_EQ(exeBasename("/usr/bin/app (deleted)"), "app (deleted)");
}

TEST(CallerLabel, ExeBasenameEmptyForEmptyPath)
{
    EXPECT_TRUE(exeBasename("").empty());
}

TEST(CallerLabel, SanitizeLabelDropsControlBytes)
{
    // A hostile process can name its executable with embedded newlines/escapes
    // to forge additional lines inside the prompter's client-chrome area. The
    // sanitiser collapses any C0 control byte (incl. newline, CR, ESC) and DEL
    // so the label can only ever render as a single inert line.
    EXPECT_EQ(sanitizeLabel("evil\nRequested by: bank"), "evil Requested by: bank");
    EXPECT_EQ(sanitizeLabel("tab\there"), "tab here");
    EXPECT_EQ(sanitizeLabel(std::string{"esc\x1b[2Jclear"}), "esc [2Jclear");
    EXPECT_EQ(sanitizeLabel(std::string{"del\x7fhere"}), "del here");
}

TEST(CallerLabel, SanitizeLabelPreservesNonAsciiBytes)
{
    // High-bit bytes are UTF-8 lead/continuation bytes, not control bytes: a
    // non-ASCII executable name must survive intact.
    const std::string utf8 = "N\xc3\xa4me"; // "Näme"
    EXPECT_EQ(sanitizeLabel(utf8), utf8);
}

TEST(CallerLabel, SanitizeLabelTruncatesOverlongInput)
{
    const std::string huge(4096, 'a');
    EXPECT_LE(sanitizeLabel(huge).size(), kMaxCallerLabelLength);
}

TEST(CallerLabel, SanitizeLabelPassesOrdinaryText)
{
    EXPECT_EQ(sanitizeLabel("Mozilla Firefox"), "Mozilla Firefox");
}
