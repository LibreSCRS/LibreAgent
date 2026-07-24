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

# Adapted from the KDE client's FakeAgent-free suite: the pure capability /
# UI-state resolvers plus the new public token vocabulary. Links the shared
# library (everything tested is a public inline/constexpr header surface).
add_executable(ClientQtCapabilitiesTest AgentCapabilitiesTest.cpp)
target_link_libraries(ClientQtCapabilitiesTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtCapabilitiesTest COMMAND ClientQtCapabilitiesTest)

# The credential record/result parsers (public, exported) including the
# contract-verbatim key-set drift guard and the extra pass-through.
add_executable(ClientQtCredentialTypesTest CredentialTypesTest.cpp)
target_link_libraries(ClientQtCredentialTypesTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtCredentialTypesTest COMMAND ClientQtCredentialTypesTest)

# The structural identity-row flatten (public, exported): skip-binary /
# stringify / empty-retained rules over the canonical Field::extra keys.
add_executable(ClientQtIdentityRowsTest IdentityRowsTest.cpp)
target_link_libraries(ClientQtIdentityRowsTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtIdentityRowsTest COMMAND ClientQtIdentityRowsTest)

# The public API driven over a minimal in-process TransportSeam fake (not the
# FakeAgent): request mapping, entry refusal, terminal recovery, availability
# sweeps. Needs the INTERNAL seam headers (-I src) and the exported
# ClientTestAccess factory; runs under a QCoreApplication main because the
# queued terminal emits deliver through the event loop.
add_executable(ClientQtSeamTest
    SeamMappingTest.cpp
    ClientTestMain.cpp)
target_include_directories(ClientQtSeamTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(ClientQtSeamTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest)
add_test(NAME ClientQtSeamTest COMMAND ClientQtSeamTest)

# The D-Bus error-name -> CallError/ErrorCode mapping table. ErrorNameMap.cpp
# is an INTERNAL, hidden-visibility TU (no export macro), so it is compiled
# directly into this test executable -- the same pattern as TokenMapTest
# above. Pure string classification: no bus, no QtDBus types.
add_executable(ClientQtErrorNameMapTest
    ErrorNameMapTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/ErrorNameMap.cpp)
target_include_directories(ClientQtErrorNameMapTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus)
target_link_libraries(ClientQtErrorNameMapTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtErrorNameMapTest COMMAND ClientQtErrorNameMapTest)

# The token-keyed DER-listener registration bookkeeping (the fix for the
# cancel + listener-pointer-reuse race that used to silently drop a second
# operation's delivery forever): pure QHash/QSet logic, no D-Bus, no event
# loop -- the cheapest layer where remove-by-identity vs remove-by-token is
# directly assertable. Needs the INTERNAL seam headers (-I src) for
# TransportSeam::DerListener.
add_executable(ClientQtDerListenerRegistryTest DerListenerRegistryTest.cpp)
target_include_directories(ClientQtDerListenerRegistryTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(ClientQtDerListenerRegistryTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtDerListenerRegistryTest COMMAND ClientQtDerListenerRegistryTest)

# The header-self-sufficiency / no-Qt-DBus-KF6-LM-QCBOR-leak acceptance
# harness (brief Step 3) -- its own subdirectory, see that CMakeLists.txt.
add_subdirectory(HeaderAcceptance)
