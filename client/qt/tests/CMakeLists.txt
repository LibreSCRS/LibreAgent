# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

# FdHandle's move-only RAII contract + default-value sanity for the plain
# value-type aggregates. Links the real LibreAgentClientQt shared library --
# FdHandle IS exported (LIBRESCRS_AGENTCLIENT_EXPORT), so its symbols are
# visible in the .so's dynamic symbol table despite the target's hidden
# CXX_VISIBILITY_PRESET.
add_executable(ClientQtTypesTest TypesTest.cpp)
target_link_libraries(ClientQtTypesTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtTypesTest COMMAND ClientQtTypesTest)

# TokenMap round-trip coverage. TokenMap.{h,cpp} is an INTERNAL, hidden-
# visibility TU with no export macro on any of its functions -- linking the
# shared library would not resolve its symbols. Compiling TokenMap.cpp
# directly into this test executable (a second, independent object file
# from the one folded into LibreAgentClientQt.so) is the standard way to
# unit-test a library's non-exported internals; still links
# LibreAgent::ClientQt for its public include dirs + Qt6::Core (SignOptions.h,
# which TokenMap.h depends on for the four enum types).
add_executable(ClientQtTokenMapTest
    TokenMapTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/TokenMap.cpp)
target_link_libraries(ClientQtTokenMapTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtTokenMapTest COMMAND ClientQtTokenMapTest)

# The header-self-sufficiency / no-Qt-DBus-KF6-LM-QCBOR-leak acceptance
# harness (brief Step 3) -- its own subdirectory, see that CMakeLists.txt.
add_subdirectory(HeaderAcceptance)
