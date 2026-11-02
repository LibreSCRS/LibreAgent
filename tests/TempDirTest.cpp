// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/util/TempDir.h>

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

namespace {

class ScopedTmpdir
{
public:
    explicit ScopedTmpdir(const char* value)
    {
        if (const char* old = std::getenv("TMPDIR")) {
            m_saved = old;
            m_had = true;
        }
        if (value != nullptr) {
            ::setenv("TMPDIR", value, 1);
        } else {
            ::unsetenv("TMPDIR");
        }
    }
    ~ScopedTmpdir()
    {
        if (m_had) {
            ::setenv("TMPDIR", m_saved.c_str(), 1);
        } else {
            ::unsetenv("TMPDIR");
        }
    }

private:
    std::string m_saved;
    bool m_had = false;
};

TEST(TempDir, TmpdirWinsAndGetsATrailingSlash)
{
    ScopedTmpdir env("/var/tmp/somewhere");
    EXPECT_EQ(LibreSCRS::Agent::tempDirectory(), "/var/tmp/somewhere/");
}

TEST(TempDir, UnsetOrEmptyFallsBackToTmp)
{
    {
        ScopedTmpdir env(nullptr);
        EXPECT_EQ(LibreSCRS::Agent::tempDirectory(), "/tmp/");
    }
    ScopedTmpdir env("");
    EXPECT_EQ(LibreSCRS::Agent::tempDirectory(), "/tmp/");
}

TEST(TempDir, TheTemplateIsNulTerminatedAndEndsInSixX)
{
    ScopedTmpdir env("/x/");
    const auto tmpl = LibreSCRS::Agent::tempFileTemplate("pre-");
    ASSERT_FALSE(tmpl.empty());
    EXPECT_EQ(tmpl.back(), '\0');
    EXPECT_EQ(std::string(tmpl.data()), "/x/pre-XXXXXX");
}

} // namespace
