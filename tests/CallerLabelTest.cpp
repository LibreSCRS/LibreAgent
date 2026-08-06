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

TEST(CallerLabel, SanitizeLabelCollapsesUnicodeLineSeparators)
{
    // U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR and U+0085 NEXT LINE
    // are honoured as mandatory line breaks by text engines but arrive as
    // multi-byte UTF-8 sequences the C0 byte test cannot see; each must
    // collapse to one space exactly like a raw newline.
    EXPECT_EQ(sanitizeLabel("evil\xE2\x80\xA8Requested by: bank"), "evil Requested by: bank");
    EXPECT_EQ(sanitizeLabel("evil\xE2\x80\xA9Requested by: bank"), "evil Requested by: bank");
    EXPECT_EQ(sanitizeLabel("evil\xC2\x85Requested by: bank"), "evil Requested by: bank");
}

TEST(CallerLabel, SanitizeLabelCollapsesBidiMarks)
{
    // U+200E LEFT-TO-RIGHT MARK / U+200F RIGHT-TO-LEFT MARK.
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\x8E"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\x8F"
                            "b"),
              "a b");
}

TEST(CallerLabel, SanitizeLabelCollapsesBidiEmbeddingsAndOverrides)
{
    // U+202A..U+202E: LRE, RLE, PDF, LRO, RLO — an RLO can visually reverse
    // the text that follows it, spoofing what the user reads in the prompt.
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\xAA"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\xAB"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\xAC"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\xAD"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x80\xAE"
                            "b"),
              "a b");
}

TEST(CallerLabel, SanitizeLabelCollapsesBidiIsolates)
{
    // U+2066..U+2069: LRI, RLI, FSI, PDI.
    EXPECT_EQ(sanitizeLabel("a\xE2\x81\xA6"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x81\xA7"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x81\xA8"
                            "b"),
              "a b");
    EXPECT_EQ(sanitizeLabel("a\xE2\x81\xA9"
                            "b"),
              "a b");
}

TEST(CallerLabel, SanitizeLabelTruncatesOverlongInput)
{
    const std::string huge(4096, 'a');
    EXPECT_LE(sanitizeLabel(huge).size(), kMaxCallerLabelLength);
}

TEST(CallerLabel, SanitizeLabelTruncationDoesNotSplitCodePoints)
{
    // Fill up to one byte short of the cap, then place a two-byte code point
    // ("ä", C3 A4) straddling the limit: byte kMaxCallerLabelLength-1 is the
    // lead byte, byte kMaxCallerLabelLength the continuation. Truncation must
    // back off the whole code point rather than keep a dangling lead byte.
    std::string input(kMaxCallerLabelLength - 1, 'a');
    input += "\xC3\xA4";
    input += "tail";
    const std::string out = sanitizeLabel(input);
    EXPECT_EQ(out.size(), kMaxCallerLabelLength - 1);
    EXPECT_EQ(out, std::string(kMaxCallerLabelLength - 1, 'a'));
}

TEST(CallerLabel, SanitizeLabelPassesOrdinaryText)
{
    EXPECT_EQ(sanitizeLabel("Mozilla Firefox"), "Mozilla Firefox");
}
