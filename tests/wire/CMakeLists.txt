# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Seventeen targets (sixteen off macOS), each with its own job:
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
#    ${CMAKE_SOURCE_DIR}/include and no linked libraries at all -- not even
#    GTest -- by construction. If either header ever grows an LM (or Qt, or
#    OpenSSL) include, or includes a private header from src/, this target
#    fails to compile with a file-not-found error, which WireHeadersTest
#    cannot guarantee. tests/CMakeLists.txt puts src/ and tests/ on every
#    target below it through the directory property, so the target's own
#    INCLUDE_DIRECTORIES is replaced, not added to. It builds as part of the
#    default `all` target, so the proof runs on every build, not just ctest.
add_library(WireHeaderPurityCheck OBJECT WireHeaderPurity.cpp)
set_target_properties(WireHeaderPurityCheck PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/include")

# 2b. The same proof for the client-role codec, which is private: include/ and
#     src/, still no linked library and no LM, Qt or OpenSSL on the path.
add_library(WireClientCodecPurityCheck OBJECT WireClientCodecPurity.cpp)
set_target_properties(WireClientCodecPurityCheck PROPERTIES
    INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/include;${CMAKE_SOURCE_DIR}/src")

add_executable(WireHeadersTest ErrorCodeHeaderTest.cpp)
target_include_directories(WireHeadersTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(WireHeadersTest PRIVATE GTest::gtest GTest::gtest_main)
gtest_discover_tests(WireHeadersTest)

# 7. FeatureTokensGuardTest: ties LibreSCRS::Agent::kAgentFeatures
#    (FeatureTokens.h, std-only, no LM/Qt/sdbus-c++) back to the CDDL comment
#    documenting the same vocabulary. Dependency-light like WireHeadersTest
#    above -- no LibreAgent::Wire link needed -- so it stays reachable from a
#    Core-less (LIBREAGENT_BUILD_CORE=OFF) build too.
add_executable(FeatureTokensGuardTest FeatureTokensGuardTest.cpp)
target_include_directories(FeatureTokensGuardTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(FeatureTokensGuardTest PRIVATE LibreAgentCddlVocabulary GTest::gtest GTest::gtest_main)
target_compile_definitions(FeatureTokensGuardTest PRIVATE
    LIBRESCRS_AGENT_WIRE_CDDL="${CMAKE_SOURCE_DIR}/wire/librescrs-agent.cddl")
gtest_discover_tests(FeatureTokensGuardTest)

# Unit tests for the contract-grammar text helpers themselves. Link-light on
# purpose: the helpers must stay std-only so the generator can use them.
add_executable(CddlVocabularyTest CddlVocabularyTest.cpp)
target_link_libraries(CddlVocabularyTest PRIVATE
    LibreAgentCddlVocabulary GTest::gtest GTest::gtest_main)
# The union tests drive the real generator binary over scratch grammars: the
# emitted shape and the duplicate refusal live in the generator, not the header.
add_dependencies(CddlVocabularyTest wire-vocabulary-gen)
target_compile_definitions(CddlVocabularyTest PRIVATE
    LIBRESCRS_WIRE_VOCABULARY_GEN="$<TARGET_FILE:wire-vocabulary-gen>")
gtest_discover_tests(CddlVocabularyTest)

# 8. PropertyChangedVocabGuardTest: ties the CDDL comment documenting the
#    `property-changed` event's served `iface` vocabulary back to the set
#    this task hand-verified against the socket daemon (the only producer of
#    this event). CDDL-text-only like FeatureTokensGuardTest above -- no
#    LibreAgent library link needed.
add_executable(PropertyChangedVocabGuardTest PropertyChangedVocabGuardTest.cpp)
target_link_libraries(PropertyChangedVocabGuardTest PRIVATE LibreAgentCddlVocabulary GTest::gtest GTest::gtest_main)
target_compile_definitions(PropertyChangedVocabGuardTest PRIVATE
    LIBRESCRS_AGENT_WIRE_CDDL="${CMAKE_SOURCE_DIR}/wire/librescrs-agent.cddl")
gtest_discover_tests(PropertyChangedVocabGuardTest)

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
gtest_discover_tests(CborRoundTripTest)

# CborRelocationTest: a CborValue holding a Map must survive being moved out
# of a growing vector. Passes trivially where the library is healthy; its
# purpose is the ASan run on Apple Clang, where it reports the use-after-free
# instead of leaving it to be inferred from a bare "Bus error".
add_executable(CborRelocationTest CborRelocationTest.cpp)
target_link_libraries(CborRelocationTest PRIVATE
    LibreAgent::Wire
    GTest::gtest
    GTest::gtest_main)
gtest_discover_tests(CborRelocationTest)

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
    gtest_discover_tests(${wire_test})
endforeach()

# FdHarvestTest: the SCM_RIGHTS length clamp on its own. The two harvest
# loops above run over a real socketpair, and on Linux that cannot tell the
# clamped computation from the unclamped one -- the kernel rewrites cmsg_len
# down to what it delivered, so both suites stay green with the clamp
# removed. This one hand-builds the msghdr/cmsghdr pair the truncating
# kernel produces, so the clamp is falsifiable here rather than only on an
# Apple host. It reaches src/wire/FdHarvest.h, which is internal to the wire
# target and therefore not on LibreAgent::Wire's include interface; the
# helper is header-only, so nothing needs to be linked for it.
add_executable(FdHarvestTest FdHarvestTest.cpp)
target_include_directories(FdHarvestTest PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include)
target_compile_features(FdHarvestTest PRIVATE cxx_std_23)
target_link_libraries(FdHarvestTest PRIVATE
    GTest::gtest
    GTest::gtest_main)
gtest_discover_tests(FdHarvestTest)

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
gtest_discover_tests(MessagesRoundTripTest)

# ClientCodecTest: the client-role inverse of MessagesRoundTripTest --
# parseReply/parseEvent (decode what the agent sends) and encodeRequest
# (build what the client sends), over ClientCodec.h/.cpp. Same
# dependency-light rationale as the test above (LibreAgent::Wire only,
# no Core), so it stays reachable in a Core-less (CORE=OFF)
# configuration too.
add_executable(ClientCodecTest ClientCodecTest.cpp)
target_link_libraries(ClientCodecTest PRIVATE
    LibreAgent::Wire
    GTest::gtest
    GTest::gtest_main)
gtest_discover_tests(ClientCodecTest)

if(LIBREAGENT_BUILD_CORE)
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
            LibreAgentCddlVocabulary
            GTest::gtest
            GTest::gtest_main)
    target_compile_options(WireContractGuardTest PRIVATE -Werror=switch)
    # The CDDL is the wire contract of record; the guard parses its `error-code`
    # group and compares it value-for-value with the upstream taxonomy.
    target_compile_definitions(WireContractGuardTest PRIVATE
        LIBRESCRS_AGENT_WIRE_CDDL="${CMAKE_SOURCE_DIR}/wire/librescrs-agent.cddl")
    gtest_discover_tests(WireContractGuardTest)
endif()

# 9. The macOS peer check every end of the socket wire uses: who serves (or
#    connects to) agent.sock, by code signature. Apple-only -- SecTask,
#    SecCode and LOCAL_PEERTOKEN exist nowhere else. The test binary itself is
#    signed by no team, so the positive half of the designated requirement
#    waits for a Developer ID build; everything else runs here.
if(APPLE)
    add_executable(WirePeerCodeSigningTest PeerCodeSigningTest.cpp PeerIdentityTest.cpp)
    target_link_libraries(WirePeerCodeSigningTest PRIVATE LibreAgent::Wire GTest::gtest GTest::gtest_main)
    target_compile_definitions(WirePeerCodeSigningTest PRIVATE LIBRESCRS_TEAM_ID="${LIBRESCRS_TEAM_ID}")
    gtest_discover_tests(WirePeerCodeSigningTest)
endif()

# 10. Where the macOS agent socket lives (std-only, every platform).
add_executable(WireSocketLocationTest SocketLocationTest.cpp)
target_include_directories(WireSocketLocationTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(WireSocketLocationTest PRIVATE GTest::gtest GTest::gtest_main)
gtest_discover_tests(WireSocketLocationTest)

# 11. The fd guard every host reads a client-supplied document or master list
#     through (std + POSIX only, every platform).
add_executable(WireBoundedFdReadTest BoundedFdReadTest.cpp)
target_include_directories(WireBoundedFdReadTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(WireBoundedFdReadTest PRIVATE GTest::gtest GTest::gtest_main)
gtest_discover_tests(WireBoundedFdReadTest)
