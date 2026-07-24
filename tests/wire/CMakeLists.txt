# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Six targets, six different jobs:
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

    # 4. Framing/FrameReassembler: the length-prefixed + SCM_RIGHTS frame codec
    #    and the non-blocking streaming reassembler, both re-based onto this
    #    component (originally LibreDarwin's macOS agent backend) and now
    #    std/POSIX-only — no LM, reachable from a Core-less build.
    foreach(wire_test FramingTest FrameReassemblerTest)
        add_executable(${wire_test} ${wire_test}.cpp)
        target_link_libraries(${wire_test} PRIVATE
            LibreAgent::Wire
            GTest::gtest
            GTest::gtest_main)
        add_test(NAME ${wire_test} COMMAND ${wire_test})
    endforeach()

    # 5. MessagesRoundTripTest: the typed request/reply/event model over the
    #    Cbor seam, re-based onto this component's std-only wire mirrors
    #    (wire/PreReadAuth.h, wire/CredentialWire.h) — no LM either. Supplies
    #    its own main() (unlike the targets above): besides the normal gtest
    #    run it doubles as the cross-implementation fixture generator for the
    #    LibreMac Swift client's decode tests (`--dump-fixtures <dir>` writes
    #    one canonical frame body per reply/event shape instead of running the
    #    test suite), so it links GTest::gtest, not GTest::gtest_main.
    add_executable(MessagesRoundTripTest MessagesRoundTripTest.cpp)
    target_link_libraries(MessagesRoundTripTest PRIVATE
        LibreAgent::Wire
        GTest::gtest)
    add_test(NAME MessagesRoundTripTest COMMAND MessagesRoundTripTest)
endif()

if(LIBREAGENT_BUILD_CORE AND LIBREAGENT_BUILD_WIRE)
    # 6. WireContractGuardTest: the cross-stack wire-contract drift guard. It
    #    ties the CDDL (wire/librescrs-agent.cddl) + this component's wire enums
    #    back to the upstream LibreMiddleware/LibreAgent symbols (LM
    #    CardCapabilities/PreReadAuthMethod, this repo's own ErrorCode/
    #    CredentialOutcome/OperationPhase), so it needs BOTH Core (for the LM +
    #    agent-side authoritative types) and Wire (for wire::Messages' SyncError
    #    + syncErrorName) — the only guard in this tree entitled to see both
    #    worlds at once.
    add_executable(WireContractGuardTest WireContractGuardTest.cpp)
    target_link_libraries(WireContractGuardTest
        PRIVATE
            LibreAgent::Core
            LibreAgent::Wire
            GTest::gtest
            GTest::gtest_main)
    target_compile_options(WireContractGuardTest PRIVATE -Werror=switch)
    # The CDDL is the wire contract of record; the guard parses its `error-code`
    # group and compares it value-for-value with the upstream taxonomy.
    target_compile_definitions(WireContractGuardTest PRIVATE
        LIBRESCRS_AGENT_WIRE_CDDL="${CMAKE_SOURCE_DIR}/wire/librescrs-agent.cddl")
    add_test(NAME WireContractGuardTest COMMAND WireContractGuardTest)
endif()
