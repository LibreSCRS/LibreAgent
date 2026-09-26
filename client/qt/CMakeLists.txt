# SPDX-License-Identifier: LGPL-2.1-or-later
#
# LibreAgent::ClientQt -- the transport-neutral Qt client library LibreCelik
# and (later) other KDE-based clients consume: the public value types plus
# the lifted client API (AgentClient/AgentReader/AgentCard/AgentOperation/
# SharedAgentClient)
# over the internal TransportSeam. The D-Bus transport (src/dbus/, Linux-only)
# is the first seam implementation; the socket transport is a later task.
#
# Included from the root CMakeLists.txt's `if(LIBREAGENT_BUILD_CLIENT_QT)`
# block, AFTER that block's find_package(Qt6 ...) call -- Qt enters this
# whole repo's build ONLY there; LibreAgent::Core/::Wire never see it.

# The four public QObject headers are listed as target sources so AUTOMOC
# scans them (their generated moc TUs are compiled into this library -- the
# QObject types must never be duplicated across .so boundaries).
qt_add_library(LibreAgentClientQt SHARED
    src/AgentClient.cpp
    src/AgentCard.cpp
    src/AgentOperation.cpp
    src/AgentReader.cpp
    src/CredentialTypes.cpp
    src/FdHandle.cpp
    src/FieldOrder.cpp
    src/IdentityRows.cpp
    src/SealedPayload.cpp
    src/SealedPayloadInternal.cpp
    src/SecurityChecks.cpp
    src/SharedAgentClient.cpp
    src/TokenMap.cpp
    include/LibreSCRS/AgentClient/AgentClient.h
    include/LibreSCRS/AgentClient/AgentCard.h
    include/LibreSCRS/AgentClient/AgentOperation.h
    include/LibreSCRS/AgentClient/AgentReader.h)
add_library(LibreAgent::ClientQt ALIAS LibreAgentClientQt)

# The socket transport (AF_UNIX + canonical CBOR over LibreAgent::Wire):
# compiled on EVERY platform — it is the macOS production transport, written
# portably, and both Linux and Darwin are where it is testable against the
# fake socket agent. ErrorNameMap sits here too (not in the Linux-only D-Bus
# block): it is pure string classification with no QtDBus dependency, and its
# short-name half is the socket wire's sync-error vocabulary, so both
# transports share the one table. MemfdSource.{h,cpp} (same directory) is
# deliberately NOT a library source — it is the Linux/Darwin-test-only
# document source, compiled only into the socket test binary.
target_sources(LibreAgentClientQt PRIVATE
    src/dbus/ErrorNameMap.cpp
    src/socket/SocketPath.cpp
    src/socket/SocketTransport.cpp
    src/socket/SocketTransport.h)

# The D-Bus transport: Linux-only, matching the Linux-only Qt6::DBus
# dependency below (the socket transport above is the macOS production path).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(LibreAgentClientQt PRIVATE
        src/dbus/CappedCall.cpp
        src/dbus/DBusTransport.cpp
        src/dbus/DBusTransport.h
        src/dbus/Marshal.cpp)
endif()

set_target_properties(LibreAgentClientQt PROPERTIES
    OUTPUT_NAME librescrs-agentclient-qt
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    AUTOMOC ON
    POSITION_INDEPENDENT_CODE ON)

include(GenerateExportHeader)
# EXPORT_FILE_NAME is an addition beyond generate_export_header()'s default
# output -- a flat librescrs_agentclient_export.h next to the target's other
# build-tree files: this component's own public-header list names this file
# client/qt/include/LibreSCRS/AgentClient/Export.h, the same
# <LibreSCRS/AgentClient/...> spelling every hand-written header here uses,
# and client/qt/tests/HeaderAcceptance/ needs it to sit under that exact
# logical path to test it like every other public header. BASE_NAME (hence
# the LIBRESCRS_AGENTCLIENT_EXPORT macro FdHandle.h uses) is unchanged.
generate_export_header(LibreAgentClientQt
    BASE_NAME LIBRESCRS_AGENTCLIENT
    EXPORT_FILE_NAME include/LibreSCRS/AgentClient/Export.h)

# The repo's top-level include/ is on the PUBLIC surface too: the std-only
# wire enum headers (ErrorCode/OperationPhase/PreReadAuth) are re-exported by
# public client headers, so a consumer of THIS target must resolve them even
# though LibreAgent::Wire itself stays a PRIVATE link (its install rules put
# those headers under the same installed include root).
target_include_directories(LibreAgentClientQt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(LibreAgentClientQt PUBLIC cxx_std_23)

target_link_libraries(LibreAgentClientQt
    PUBLIC
        Qt6::Core
    PRIVATE
        $<$<PLATFORM_ID:Linux>:Qt6::DBus>
        LibreAgent::Wire)

target_compile_options(LibreAgentClientQt PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference
    -Wdouble-promotion -Wformat=2)
if(LIBRESCRS_AGENT_WERROR)
    target_compile_options(LibreAgentClientQt PRIVATE -Werror)
endif()

# Exposed to cmake/InstallExport.cmake (install() the generated header) and
# to client/qt/tests/HeaderAcceptance/ (the exact include-path set that
# harness requires) without either having to re-derive generate_export_header()'s
# output location by hand.
set(LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
set(LIBREAGENT_CLIENTQT_EXPORT_HEADER
    ${LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR}/LibreSCRS/AgentClient/Export.h)
# add_subdirectory() scoping is one-way (parent -> child): client/qt/tests/
# and its own HeaderAcceptance/ subdirectory automatically inherit the three
# variables above with no extra step, but cmake/InstallExport.cmake is
# include()'d back at the ROOT scope (the root CMakeLists.txt that called
# add_subdirectory(client/qt) in the first place) and would otherwise never
# see them -- PARENT_SCOPE pushes them back up one level to exactly that
# root scope. (Caught the hard way: a first pass at this file left Export.h
# out of every install tree with no configure/build-time error -- the
# install(FILES ${LIBREAGENT_CLIENTQT_EXPORT_HEADER} ...) call in
# InstallExport.cmake silently expanded to an empty path and installed
# nothing.)
set(LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR ${LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR} PARENT_SCOPE)
set(LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR ${LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR} PARENT_SCOPE)
set(LIBREAGENT_CLIENTQT_EXPORT_HEADER ${LIBREAGENT_CLIENTQT_EXPORT_HEADER} PARENT_SCOPE)

# This component's own tests (TypesTest/TokenMapTest/HeaderAcceptance) live
# under client/qt/tests/ rather than the top-level tests/ directory Core/Wire
# share -- ClientQt is meant to stay a self-contained subtree. Same
# FetchContent-consumer gate as the root CMakeLists.txt's own
# `if(PROJECT_IS_TOP_LEVEL) ... add_subdirectory(tests)`: a platform backend
# pulling this repo in via FetchContent gets the library, not its test suite.
# enable_testing() is safe to call again here even though the root
# CMakeLists.txt may already have called it -- add_subdirectory(client/qt)
# runs BEFORE that root call (this block sits above the WIRE-gated
# `if(PROJECT_IS_TOP_LEVEL)` block that includes InstallExport.cmake and
# enables testing), so this component needs its own call for ctest to
# discover add_test() registrations made below it.
if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
endif()

# The subdirectory is entered for a SECOND reason now: it also defines the
# exported agent doubles (LibreAgent::ClientQtTestSupport), which a consumer
# asks for without becoming the top-level project. The ctest registrations
# inside it stay behind their own PROJECT_IS_TOP_LEVEL guard -- entering the
# directory must not hand a FetchContent consumer this repo's test suite.
if(PROJECT_IS_TOP_LEVEL OR LIBREAGENT_BUILD_CLIENT_QT_TEST_SUPPORT)
    add_subdirectory(tests)
endif()

if(PROJECT_IS_TOP_LEVEL)
    # The public headers, read by the drift guard below.
    file(GLOB _clientqt_public_header_paths
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/include/LibreSCRS/AgentClient/*.h")

    # ---- drift guard: which shared headers the public surface re-exports ----
    #
    # A public client header that starts re-exporting a header from the shared
    # LibreSCRS/Agent/ tree creates obligations elsewhere, each of which has
    # already been missed once in this repository. They are NAMED rather than
    # numbered, because a count in prose goes stale the moment one is added:
    #
    #   * DOXYGEN INPUT -- Doxyfile.publicapi's INPUT must list the header, or
    #     the re-exported type's members never reach the published reference at
    #     all: the definition is simply never parsed, with no warning.
    #   * EXPORT ANNOTATION -- any FUNCTION it declares must carry
    #     LIBRESCRS_AGENTWIRE_EXPORT. The wire library compiles hidden, so an
    #     un-annotated function is absent from the shared library a consumer
    #     links against, while its public header still declares it.
    #   * EXPORT ALLOWLIST -- ci/scripts/check-wire-exports.sh's
    #     CLIENTQT_WIRE_PUBLIC must name those same functions: it is the list of
    #     wire functions the shared library may export, and it fails on any
    #     other and on a named one gone missing.
    #   * DOXYGEN PREDEFINED -- an export MACRO defined in the header must be
    #     predefined away in Doxyfile.publicapi, or the published reference
    #     carries a build detail as public API.
    #
    # None is derivable from another, and no tool notices its own omission, so
    # the checks live here, where the re-export is written. The two Doxygen ones
    # are enforced below; the other two announce themselves loudly enough (a
    # failed link, a failed export check) to need no configure-time twin.
    set(_clientqt_reexported_shared_headers
        OperationPhase.h
        wire/ErrorCode.h
        wire/PreReadAuth.h
        wire/SyncError.h)

    set(_clientqt_reexports_on_disk "")
    foreach(_hdr IN LISTS _clientqt_public_header_paths)
        file(STRINGS "${_hdr}" _include_lines
            REGEX "^#include <LibreSCRS/Agent/[A-Za-z0-9_/]+\\.h>$")
        foreach(_line IN LISTS _include_lines)
            string(REGEX REPLACE "^#include <LibreSCRS/Agent/(.*)>$" "\\1" _name "${_line}")
            list(APPEND _clientqt_reexports_on_disk "${_name}")
        endforeach()
    endforeach()
    list(REMOVE_DUPLICATES _clientqt_reexports_on_disk)
    list(SORT _clientqt_reexports_on_disk)

    set(_clientqt_reexports_expected ${_clientqt_reexported_shared_headers})
    list(SORT _clientqt_reexports_expected)

    if(NOT _clientqt_reexports_on_disk STREQUAL _clientqt_reexports_expected)
        message(FATAL_ERROR
            "ClientQt: the set of shared LibreSCRS/Agent/ headers re-exported by "
            "the public client headers has changed.\n"
            "  Re-exported on disk: ${_clientqt_reexports_on_disk}\n"
            "  Expected (this file): ${_clientqt_reexports_expected}\n"
            "Work through the obligations listed at the top of this guard for "
            "each added header:\n"
            "  DOXYGEN INPUT -- add it to Doxyfile.publicapi's INPUT, or its "
            "members are absent from the published API reference with no "
            "warning (enforced below, so it will tell you again);\n"
            "  EXPORT ANNOTATION + EXPORT ALLOWLIST -- if it declares FUNCTIONS "
            "(an enum/constant-only header emits no symbols and needs "
            "nothing), give each one LIBRESCRS_AGENTWIRE_EXPORT and add it to "
            "CLIENTQT_WIRE_PUBLIC in ci/scripts/check-wire-exports.sh;\n"
            "  DOXYGEN PREDEFINED -- if it defines an export MACRO, predefine "
            "it away in Doxyfile.publicapi (enforced below too).")
    endif()

    # The DOXYGEN INPUT obligation, enforced rather than merely described.
    # Doxygen's INPUT is a plain list of paths in a file we can read, so
    # "every re-exported shared header is in the reference's scope" is a
    # decidable question at configure time -- unlike the export allowlist, where
    # nothing can tell us which header declared a given exported symbol.
    # Checking it here means the message above is a reminder for the parts that
    # still need a human, not the only thing standing behind any of them.
    #
    # This is the omission that actually happened: a re-exported error
    # vocabulary shipped with its type documented and every one of its values
    # missing from the published reference, because doxygen documents what it
    # PARSES and a using-declaration does not pull in a definition from an
    # unlisted header. It produced no warning from any tool.
    set(_clientqt_doxyfile "${PROJECT_SOURCE_DIR}/Doxyfile.publicapi")
    if(EXISTS "${_clientqt_doxyfile}")
        file(STRINGS "${_clientqt_doxyfile}" _doxy_input_lines
            REGEX "include/LibreSCRS/Agent/")
        string(REPLACE ";" "\n" _doxy_input_text "${_doxy_input_lines}")

        set(_clientqt_reexports_missing_from_doxygen "")
        foreach(_reexport IN LISTS _clientqt_reexports_expected)
            string(FIND "${_doxy_input_text}" "include/LibreSCRS/Agent/${_reexport}" _found)
            if(_found EQUAL -1)
                list(APPEND _clientqt_reexports_missing_from_doxygen "${_reexport}")
            endif()
        endforeach()

        # Closes the transitive case. This guard reads the public client
        # headers' OWN include lines, so it sees a shared header re-exported
        # directly and not one re-exported through another shared header. That
        # is sound only while the pinned headers pull in nothing themselves --
        # they are leaf value-vocabulary headers today, with an empty include
        # closure. Assert that rather than rely on it: if one of them ever
        # starts including another, the set above stops being the whole
        # re-exported set and both obligations silently under-cover again.
        foreach(_reexport IN LISTS _clientqt_reexports_expected)
            set(_reexport_path "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Agent/${_reexport}")
            if(EXISTS "${_reexport_path}")
                file(STRINGS "${_reexport_path}" _nested_includes
                    REGEX "^#include <LibreSCRS/")
                if(_nested_includes)
                    message(FATAL_ERROR
                        "ClientQt: the re-exported shared header "
                        "'${_reexport}' now includes other first-party "
                        "header(s):\n"
                        "  ${_nested_includes}\n"
                        "The re-export check above reads only the PUBLIC CLIENT "
                        "headers' own include lines, so anything reached "
                        "transitively through this header is outside the set it "
                        "pins -- and would therefore be missing from both "
                        "Doxyfile.publicapi's INPUT and, if it declares "
                        "functions, the export allowlist, with nothing reporting "
                        "it. Either keep these headers leaf, or extend the "
                        "re-export check to follow the closure.")
                endif()
            endif()
        endforeach()

        if(_clientqt_reexports_missing_from_doxygen)
            message(FATAL_ERROR
                "ClientQt: shared header(s) re-exported by the public client "
                "headers but absent from Doxyfile.publicapi's INPUT:\n"
                "  ${_clientqt_reexports_missing_from_doxygen}\n"
                "Doxygen documents what it PARSES: a using-declaration in a "
                "listed header does NOT pull the definition in from an unlisted "
                "one, so the re-exported type's members would be missing from "
                "the published API reference with no warning from anything. Add "
                "'include/LibreSCRS/Agent/<header>' to that file's INPUT.")
        endif()

        # The DOXYGEN PREDEFINED obligation, likewise enforced. Measured: with
        # no entry the macro reached globals.html, the search index and every
        # signature that used it, and the docs run still exited 0. Its
        # EXCLUDE_SYMBOLS twin needs no check -- without that one the macro is
        # an undocumented member and the run fails on its own.
        #
        # Comment lines are dropped before searching, so prose that merely
        # MENTIONS a macro cannot stand in for the setting.
        file(STRINGS "${_clientqt_doxyfile}" _doxy_setting_lines REGEX "^[^#]")
        string(REPLACE ";" "\n" _doxy_settings "${_doxy_setting_lines}")
        foreach(_reexport IN LISTS _clientqt_reexports_expected)
            set(_reexport_path "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Agent/${_reexport}")
            if(NOT EXISTS "${_reexport_path}")
                continue()
            endif()
            file(STRINGS "${_reexport_path}" _export_defines
                REGEX "^#define +LIBRESCRS_[A-Z0-9_]+_EXPORT ")
            foreach(_line IN LISTS _export_defines)
                string(REGEX REPLACE "^#define +(LIBRESCRS_[A-Z0-9_]+_EXPORT) .*$" "\\1" _macro "${_line}")
                string(FIND "${_doxy_settings}" "${_macro}=" _predefined_at)
                if(_predefined_at EQUAL -1)
                    message(FATAL_ERROR
                        "ClientQt: '${_reexport}' defines ${_macro}, which is "
                        "absent from Doxyfile.publicapi's PREDEFINED. Add "
                        "'${_macro}=' there, and ${_macro} to EXCLUDE_SYMBOLS, "
                        "or the published API reference renders the macro in "
                        "every signature carrying it and lists it as public.")
                endif()
            endforeach()
        endforeach()
    endif()
endif()
