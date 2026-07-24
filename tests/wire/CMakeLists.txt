# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Standalone-compile guard: proves that LibreSCRS/Agent/wire/ErrorCode.h and
# LibreSCRS/Agent/OperationPhase.h build with an include path of ONLY this
# repo's include/ dir plus GTest — no LibreAgent::Core, no LibreMiddleware, no
# OpenSSL. Deliberately does NOT use the agent_core_test() helper (which links
# LibreAgent::Core and its PUBLIC LibreMiddleware include dirs); that
# restriction is the proof these two headers are dependency-free, ready for
# the future Wire/ClientQt targets to consume without pulling in LM.
add_executable(WireHeadersTest ErrorCodeHeaderTest.cpp)
target_include_directories(WireHeadersTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(WireHeadersTest PRIVATE GTest::gtest GTest::gtest_main)
add_test(NAME WireHeadersTest COMMAND WireHeadersTest)
