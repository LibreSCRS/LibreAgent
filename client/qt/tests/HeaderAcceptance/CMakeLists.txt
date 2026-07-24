# SPDX-License-Identifier: LGPL-2.1-or-later
#
# HeaderAcceptance: for EVERY public header this component ships, prove it
# compiles STANDALONE (`#include <LibreSCRS/AgentClient/X.h>` + `int main(){}`)
# with an include-path set of EXACTLY:
#   - this component's own public include dir (client/qt/include)
#   - the build-tree dir holding the generated Export.h
#   - the repo root's include/ dir (the std-only wire headers ErrorCode.h/
#     OperationPhase.h re-export)
#   - Qt6::Core's own INTERFACE_INCLUDE_DIRECTORIES
# AND that nothing in the resulting #include graph resolves to a
# QtDBus/KF6/LibreMiddleware/QCBOR header.
#
# Why this is a POST-COMPILE GRAPH AUDIT, not just an omitted -I path: on
# this (and every mainstream Linux) distro, Qt6's system packages install
# every module under ONE shared prefix (/usr/include/qt6/{QtCore,QtDBus,...}),
# and QtCore's OWN headers pervasively self-include via the module-qualified
# spelling `#include <QtCore/qfoo.h>` (verified: 275+ headers in
# /usr/include/qt6/QtCore/ do this). That means Qt6::Core's own
# INTERFACE_INCLUDE_DIRECTORIES necessarily contains the shared
# `/usr/include/qt6` umbrella directory, not just `.../QtCore` -- and that
# same umbrella entry makes `<QtDBus/QDBusConnection>` resolvable too,
# because QtDBus/ is a sibling directory under it. Proven empirically while
# building this harness: injecting `#include <QtDBus/QDBusConnection>` into
# Types.h still compiled clean under a naive "restrict the -I list" version
# of this test. A pure include-path restriction cannot distinguish "QtCore
# needs its own umbrella for self-includes" from "a public header reached
# into a sibling Qt module" when both live under the same prefix.
#
# So: compile each generated TU with `-fsyntax-only -H` (GCC/Clang; prints
# every header actually opened, one per line, nested paths prefixed with
# dots) and grep the FULL transcript for path markers that could only come
# from outside this library's declared dependency surface. KF6/LM/QCBOR are
# each installed under their OWN, separate prefix (not shared with Qt6's),
# so for those three families the plain -I restriction above already fails
# closed with a file-not-found error before -H even matters; the marker
# check is a second, belt-and-suspenders line of defense for them and the
# PRIMARY defense for any non-Core Qt module (QtDBus first; the same
# umbrella-sharing applies to QtWidgets/QtGui/QtNetwork/... too).

set(_agentclient_public_headers
    AgentCapabilities.h
    AgentCard.h
    AgentClient.h
    AgentOperation.h
    AgentReader.h
    CallError.h
    ClientTimeouts.h
    CredentialTypes.h
    ErrorCode.h
    Export.h
    FdHandle.h
    IdentityRows.h
    OperationPhase.h
    SharedAgentClient.h
    SignOptions.h
    Types.h)

# Drift guard: diff the explicit list above against what's actually on disk
# in client/qt/include/LibreSCRS/AgentClient/ (source headers only --
# Export.h is generated into the build tree and checked separately below).
# A header added to that directory without also being added to the list
# above fails the CONFIGURE step immediately, rather than silently never
# being covered by this harness.
file(GLOB _agentclient_actual_src_headers
    CONFIGURE_DEPENDS
    RELATIVE "${LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR}/LibreSCRS/AgentClient"
    "${LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR}/LibreSCRS/AgentClient/*.h")
list(SORT _agentclient_actual_src_headers)

set(_agentclient_expected_src_headers ${_agentclient_public_headers})
list(REMOVE_ITEM _agentclient_expected_src_headers Export.h)
list(SORT _agentclient_expected_src_headers)

if(NOT _agentclient_actual_src_headers STREQUAL _agentclient_expected_src_headers)
    message(FATAL_ERROR
        "HeaderAcceptance: the public header list has drifted from "
        "client/qt/include/LibreSCRS/AgentClient/.\n"
        "  On disk:                    ${_agentclient_actual_src_headers}\n"
        "  Expected (this CMakeLists): ${_agentclient_expected_src_headers}\n"
        "Add (or remove) the header in BOTH "
        "client/qt/include/LibreSCRS/AgentClient/ AND this file's "
        "_agentclient_public_headers list -- a header cannot dodge this "
        "harness by only doing one of the two.")
endif()

if(NOT EXISTS "${LIBREAGENT_CLIENTQT_EXPORT_HEADER}")
    message(FATAL_ERROR
        "HeaderAcceptance: expected the generated export header at "
        "${LIBREAGENT_CLIENTQT_EXPORT_HEADER} (set by client/qt/CMakeLists.txt's "
        "generate_export_header() call) -- it does not exist. Configure "
        "order problem, or that call's EXPORT_FILE_NAME was changed without "
        "updating this harness.")
endif()

# Resolve Qt6::Core's INTERFACE_INCLUDE_DIRECTORIES through a GENERATE-time
# genex (not a plain get_target_property() read) so this stays correct even
# if a future Qt/CMake version expresses that property with
# BUILD_INTERFACE/INSTALL_INTERFACE generator expressions -- on the current
# system Qt6 package it is already a plain two-entry path list, but this
# does not assume that.
set(_qt_core_includes_file "${CMAKE_CURRENT_BINARY_DIR}/qt_core_includes.txt")
file(GENERATE OUTPUT "${_qt_core_includes_file}"
    CONTENT "$<TARGET_PROPERTY:Qt6::Core,INTERFACE_INCLUDE_DIRECTORIES>")

set(_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${_generated_dir}")

add_test(NAME HeaderAcceptance
    COMMAND "${CMAKE_COMMAND}"
        -D "CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        -D "HEADERS=${_agentclient_public_headers}"
        -D "CLIENT_INCLUDE_DIR=${LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR}"
        -D "EXPORT_INCLUDE_DIR=${LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR}"
        -D "REPO_INCLUDE_DIR=${CMAKE_SOURCE_DIR}/include"
        -D "QT_CORE_INCLUDES_FILE=${_qt_core_includes_file}"
        -D "GENERATED_DIR=${_generated_dir}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/RunHeaderAcceptance.cmake")

unset(_agentclient_public_headers)
unset(_agentclient_actual_src_headers)
unset(_agentclient_expected_src_headers)
unset(_qt_core_includes_file)
unset(_generated_dir)
