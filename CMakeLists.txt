# SPDX-License-Identifier: LGPL-2.1-or-later
cmake_minimum_required(VERSION 3.24)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GitVersion)

set(PROJECT_VERSION_MAJOR ${GIT_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${GIT_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${GIT_VERSION_PATCH})
set(PROJECT_VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})

project(LibreAgent VERSION ${PROJECT_VERSION} LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(GNUInstallDirs)

# Component switches. Core is the platform-neutral agent library this repo
# has always built; Wire (a shared socket-wire protocol library) and
# ClientQt (a Qt client consuming it) are later additions, each independently
# buildable/exportable so a consumer that only wants the wire protocol does
# not have to pull in LM/OpenSSL, and one that wants neither Qt library
# doesn't pull in Qt.
option(LIBREAGENT_BUILD_CORE "Build the platform-neutral LibreAgent::Core library" ON)
option(LIBREAGENT_BUILD_WIRE "Build the LibreAgent::Wire socket-wire library" ON)
option(LIBREAGENT_BUILD_CLIENT_QT "Build the LibreAgent::ClientQt Qt client library" OFF)

if(LIBREAGENT_BUILD_CLIENT_QT AND NOT LIBREAGENT_BUILD_WIRE)
    message(FATAL_ERROR "LIBREAGENT_BUILD_CLIENT_QT requires LIBREAGENT_BUILD_WIRE (the Qt client library links the wire protocol library)")
endif()

# Strict warnings by default; treat as errors only in CI builds. Declared once,
# unconditionally, so a LIBREAGENT_BUILD_WIRE-only (Core-less) configuration
# still gets the option — every component target below opts into it.
option(LIBRESCRS_AGENT_WERROR "Treat compiler warnings as errors" OFF)

if(LIBREAGENT_BUILD_CORE)
    find_package(LibreMiddleware 4.2 REQUIRED CONFIG)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

    # Platform-neutral agent core: card-read/sign flows, scheduler, presence model,
    # caches, lease/broker policy, LM-backed seams, and the 5 backend interfaces.
    # No sdbus-c++ / systemd / polkit here — those live in the platform backend.
    add_library(LibreAgentCore STATIC
        # value/
        src/value/ErrorTaxonomy.cpp
        # util/
        src/util/Sha256Hex.cpp
        # cache/
        src/cache/CardReadCache.cpp
        src/cache/CredentialCache.cpp
        src/cache/CredentialSnapshotCache.cpp
        # presence/
        src/presence/ObjectRegistry.cpp
        src/presence/PresenceModel.cpp
        src/presence/PluginCapabilityResolver.cpp
        src/presence/MonitorBridge.cpp
        src/presence/CardKeyTracker.cpp
        # config/
        src/config/ConfigStore.cpp
        # pkcs11/
        src/pkcs11/LeaseManager.cpp
        src/pkcs11/Pkcs11Broker.cpp
        # operations/
        src/operations/LmSeams.cpp
        src/operations/LmRawCrypto.cpp
        src/operations/FlowPrelude.cpp
        src/operations/CardSessionHolder.cpp
        src/operations/IdentityReadFlow.cpp
        src/operations/CertReadFlow.cpp
        src/operations/TokenInfoReadFlow.cpp
        src/operations/CredentialListFlow.cpp
        src/operations/PinChangeFlow.cpp
        src/operations/KeyActivationFlow.cpp
        src/operations/SignFlow.cpp
        src/operations/BatchSignFlow.cpp
        src/operations/RawCryptoFlow.cpp
        src/operations/PropertyEmissionThrottler.cpp
        src/operations/RateLimiter.cpp
        src/operations/SigningEngineProvider.cpp
        src/operations/CertDerExport.cpp
        src/operations/RsaPublicKey.cpp
        src/operations/PromptSerializer.cpp
        src/operations/OperationBase.cpp
        src/operations/OperationManager.cpp
        # backend/ log facade
        src/backend/Logging.cpp
        # owning aggregate for the neutral core
        src/AgentCore.cpp)
    add_library(LibreAgent::Core ALIAS LibreAgentCore)
    target_include_directories(LibreAgentCore PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_compile_features(LibreAgentCore PUBLIC cxx_std_23)
    set_target_properties(LibreAgentCore PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(LibreAgentCore
        PUBLIC
            LibreMiddleware::SmartCard
            LibreMiddleware::Plugin
        PRIVATE
            # PRIVATE: only the Lm* seam .cpp files + SigningEngineProvider.cpp
            # consume LM X.509/Certificate + Signing/Trust types; no public header
            # includes them, which keeps consumers of this lib free of those symbols
            # (the seam-boundary invariant).
            LibreMiddleware::Certificate
            LibreMiddleware::Signing
            LibreMiddleware::Trust
            OpenSSL::Crypto)

    target_compile_options(LibreAgentCore PRIVATE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference
        -Wdouble-promotion -Wformat=2)
    if(LIBRESCRS_AGENT_WERROR)
        target_compile_options(LibreAgentCore PRIVATE -Werror)
    endif()
    # GCC 16's -Warray-bounds raises a false positive on the inlined
    # shared_ptr<std::atomic<bool>> control-block teardown in the credential-flow
    # TUs. It is emitted during optimization, so a source-level diagnostic pragma
    # cannot suppress it; disable the single warning for just these flows.
    set_source_files_properties(
        src/operations/IdentityReadFlow.cpp
        src/operations/CertReadFlow.cpp
        src/operations/TokenInfoReadFlow.cpp
        src/operations/CredentialListFlow.cpp
        src/operations/PinChangeFlow.cpp
        src/operations/KeyActivationFlow.cpp
        src/operations/SignFlow.cpp
        src/operations/BatchSignFlow.cpp
        src/operations/RawCryptoFlow.cpp
        # AgentCore.cpp inlines the raw-crypto flow (make_shared over the same
        # credential-flow teardown), so it inherits the same GCC 16 false positive.
        src/AgentCore.cpp
        PROPERTIES COMPILE_OPTIONS -Wno-array-bounds)

    # Compile-time-only lockstep proof between the std-only wire mirrors
    # (include/LibreSCRS/Agent/wire/{PreReadAuth,CredentialWire}.h — LM-free,
    # reachable from a Core-less LIBREAGENT_BUILD_WIRE-only build) and their
    # authoritative sources (LibreMiddleware's PreReadAuthMethod; this repo's
    # own CredentialOutcome/CredentialRecord/CredentialOpResult). It is its
    # own OBJECT target, deliberately NOT folded into LibreAgentWire's
    # sources above: Wire must stay LM-free, but this TU needs to see LM
    # through LibreAgent::Core to do the comparison, so it can only exist
    # when Core is built. No runtime code — every check is a static_assert,
    # so a passing compile of this target IS the test; see the file's own
    # header comment and tests/wire/WireHeaderPurity.cpp for the sibling
    # dependency-isolation proof.
    add_library(LibreAgentWireParityChecks OBJECT src/wire/WireParityChecks.cpp)
    target_link_libraries(LibreAgentWireParityChecks PRIVATE LibreAgent::Core)
    target_compile_features(LibreAgentWireParityChecks PRIVATE cxx_std_23)
endif() # LIBREAGENT_BUILD_CORE

if(LIBREAGENT_BUILD_WIRE)
    # Shared canonical-CBOR wire codec plus the socket framing + typed message
    # model — the CborValue seam over the vendored QCBOR C library, the
    # length-prefixed + SCM_RIGHTS frame codec, the non-blocking streaming
    # reassembler, and the CDDL-backed request/reply/event message model. No
    # LibreMiddleware, no OpenSSL: every wire-capable consumer (the LibreDarwin
    # agent daemon today, a future Qt client) shares this single library
    # instead of forking it. PrompterProtocol, PeerIdentity/BSM, and the
    # Darwin-only AnonFd stay host-specific (LibreDarwin), not here.
    include(cmake/FetchQCBOR.cmake) # provides the qcbor::qcbor imported target

    add_library(LibreAgentWire STATIC
        src/wire/Cbor.cpp
        src/wire/Framing.cpp
        src/wire/FrameReassembler.cpp
        src/wire/Messages.cpp
        src/wire/ClientCodec.cpp
        # Fold qcbor's compiled objects straight into this archive so an
        # installed libLibreAgentWire.a is self-contained: a consumer linking
        # only this archive + this repo's headers gets qcbor's symbols too,
        # with no separate libqcbor.a to also find and link.
        $<TARGET_OBJECTS:qcbor>)
    add_library(LibreAgent::Wire ALIAS LibreAgentWire)
    target_include_directories(LibreAgentWire PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_compile_features(LibreAgentWire PUBLIC cxx_std_23)
    set_target_properties(LibreAgentWire PROPERTIES POSITION_INDEPENDENT_CODE ON)
    # $<BUILD_INTERFACE:...>, not a plain PRIVATE: qcbor's headers are consumed
    # only by Cbor.cpp (no public header of this target includes <qcbor/...>),
    # and its objects are already folded into the archive above via
    # TARGET_OBJECTS. A plain PRIVATE link here would still get the include
    # dirs to that one TU during THIS build, but CMake's export machinery
    # exports even PRIVATE links of a STATIC library to consumers as an
    # INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:qcbor::qcbor>" usage requirement —
    # which would both defeat the point of folding qcbor in (a consumer would
    # be told to separately find + link qcbor::qcbor too) and break
    # find_package(LibreAgent COMPONENTS Wire) outright in a fresh consumer
    # tree where that target was never defined (LibreAgentWireTargets.cmake
    # fails its "referenced imported targets must exist" check). Wrapping in
    # BUILD_INTERFACE keeps the include dirs for this project's own build of
    # Cbor.cpp while making the requirement evaluate to nothing at export
    # time, so INSTALL_INTERFACE carries no qcbor reference at all.
    target_link_libraries(LibreAgentWire PRIVATE $<BUILD_INTERFACE:qcbor::qcbor>)

    target_compile_options(LibreAgentWire PRIVATE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference
        -Wdouble-promotion -Wformat=2)
    if(LIBRESCRS_AGENT_WERROR)
        target_compile_options(LibreAgentWire PRIVATE -Werror)
    endif()

    # AppleClang (Xcode 16/17, the macos-15 CI image) still gates the
    # std::expected that Cbor.h/.cpp use behind -fexperimental-library.
    # AppleClang pairs -fexperimental-library with libc++'s experimental ABI
    # surface (std::expected); the LibreDarwin daemon applies the same flag to
    # its wire consumers, so Wire must carry it PUBLIC for Darwin builds so
    # every Darwin consumer inherits it for free with no per-consumer
    # workaround. Not buildable/testable on this (Linux) machine — verify on
    # the next macOS session.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
        target_compile_options(LibreAgentWire PUBLIC -fexperimental-library)
        target_link_options(LibreAgentWire PUBLIC -fexperimental-library)
    endif()
endif() # LIBREAGENT_BUILD_WIRE

if(LIBREAGENT_BUILD_CLIENT_QT)
    # Qt enters this whole repo's build HERE and ONLY here: this is the one
    # and only find_package(Qt6 ...) call in this tree, so a WIRE-only or
    # CORE-only configuration never runs it (verified by
    # `grep Qt6 CMakeCache.txt` returning empty in such a build). DBus is
    # Linux-only (LibreLinux's socket transport backend); Test is required
    # now even though this task's own tests stay plain GTest, so a later
    # client task that needs QSignalSpy/QTest does not need a second
    # find_package call.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        find_package(Qt6 REQUIRED COMPONENTS Core DBus Test)
    else()
        find_package(Qt6 REQUIRED COMPONENTS Core Test)
    endif()

    add_subdirectory(client/qt)
endif() # LIBREAGENT_BUILD_CLIENT_QT

# The installed CONFIG package is only built when this repo is the top-level
# project. When it is pulled in as a subproject (FetchContent from a platform
# backend such as LibreLinux), the consumer wants just the enabled component
# libraries: the neutral tests run in this repo's own CI, and the backend
# provides its own install/export rules.
if(PROJECT_IS_TOP_LEVEL)
    # Installed CONFIG package: LibreAgent{,Config,ConfigVersion}.cmake plus a
    # per-component <Component>Targets.cmake for each of Core/Wire/ClientQt
    # that was actually built, so downstream find_package(LibreAgent CONFIG)
    # resolves the imported target(s) for whichever components it asked for.
    include(cmake/InstallExport.cmake)

    if(LIBREAGENT_BUILD_CORE OR LIBREAGENT_BUILD_WIRE)
        # Platform-neutral unit tests + the five shared backend fakes (Core
        # only) plus the dependency-light Wire/spike GTest targets, which stay
        # reachable in a Core-less (CORE=OFF, WIRE=ON) configuration too — see
        # tests/CMakeLists.txt for the Core/non-Core split.
        enable_testing()
        add_subdirectory(tests)
    endif()
endif()
