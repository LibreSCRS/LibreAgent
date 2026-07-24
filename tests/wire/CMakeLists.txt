# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Three targets, three different jobs:
#
# 1. WireHeadersTest (below) pins the *runtime values* of
#    LibreSCRS/Agent/wire/ErrorCode.h and LibreSCRS/Agent/OperationPhase.h via
#    GTest. It deliberately does NOT use the agent_core_test() helper (which
#    links LibreAgent::Core and its PUBLIC LibreMiddleware include dirs) —
#    but GTest::gtest itself is a find_package(GTest) result, and on this
#    machine/CI that resolves to the copy installed inside LibreMiddleware's
#    own install prefix, whose INTERFACE include dirs transitively land on
#    this target's compile line. So WireHeadersTest alone cannot prove these
#    headers are LM-independent — an LM include added to either header would
#    still compile here undetected.
#
# 2. WireHeaderPurityCheck is the actual isolation proof: an OBJECT library
#    compiling WireHeaderPurity.cpp with an include path of ONLY
#    ${CMAKE_SOURCE_DIR}/include and no linked libraries at all — not even
#    GTest — by construction. If either header ever grows an LM (or Qt, or
#    OpenSSL) include, this target fails to compile with a file-not-found
#    error, which WireHeadersTest cannot guarantee. It builds as part of the
#    default `all` target, so the proof runs on every build, not just ctest.
add_library(WireHeaderPurityCheck OBJECT WireHeaderPurity.cpp)
target_include_directories(WireHeaderPurityCheck PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_executable(WireHeadersTest ErrorCodeHeaderTest.cpp)
target_include_directories(WireHeadersTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(WireHeadersTest PRIVATE GTest::gtest GTest::gtest_main)
add_test(NAME WireHeadersTest COMMAND WireHeadersTest)

if(LIBREAGENT_BUILD_WIRE)
    # 3. CborRoundTripTest is the actual behavioural test of the canonical-CBOR
    #    codec this component ships: byte-stable round-trips + fail-closed
    #    rejection of non-canonical/malformed input. Unlike the two targets
    #    above it is NOT dependency-light by design — it links the real
    #    LibreAgent::Wire target (Cbor.cpp + qcbor folded in), so it only
    #    exists when that target does.
    add_executable(CborRoundTripTest CborRoundTripTest.cpp)
    target_link_libraries(CborRoundTripTest PRIVATE
        LibreAgent::Wire
        GTest::gtest
        GTest::gtest_main)
    add_test(NAME CborRoundTripTest COMMAND CborRoundTripTest)
endif()
