# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs as this component's HeaderAcceptance ctest (see CMakeLists.txt in this
# directory for the full rationale). For every header named in -DHEADERS=...:
#   1. writes `#include <LibreSCRS/AgentClient/<header>>\nint main(){return 0;}`
#      to a fresh TU under -DGENERATED_DIR
#   2. compiles it with `-fsyntax-only -H` and EXACTLY the four include paths
#      this harness requires (client include dir, the generated Export.h's
#      dir, the repo's std-only include/, and Qt6::Core's own include dirs
#      read back from -DQT_CORE_INCLUDES_FILE)
#   3. fails this whole test (message(FATAL_ERROR), nonzero exit) if the
#      compile itself fails, OR if `-H`'s include transcript reaches any Qt
#      module other than QtCore -- a fail-closed ALLOWLIST, not a blocklist
#      of specific non-Core modules by name, so QtTest/QtSql/QtXml/... (never
#      enumerated anywhere) are rejected exactly like QtDBus/QtWidgets are --
#      OR a path that could only have come from KF6, LibreMiddleware, or
#      QCBOR (those three stay a blocklist: each lives under its own,
#      Qt-unrelated install prefix, so there is no umbrella-sharing problem
#      to allowlist against).
# All -D arguments are required; see the add_test() call in CMakeLists.txt in
# this directory for how they are populated.

foreach(_required IN ITEMS CXX_COMPILER HEADERS CLIENT_INCLUDE_DIR EXPORT_INCLUDE_DIR
                            REPO_INCLUDE_DIR QT_CORE_INCLUDES_FILE GENERATED_DIR)
    if(NOT DEFINED ${_required})
        message(FATAL_ERROR "RunHeaderAcceptance.cmake: missing required -D${_required}=...")
    endif()
endforeach()

file(READ "${QT_CORE_INCLUDES_FILE}" _qt_core_includes)
string(STRIP "${_qt_core_includes}" _qt_core_includes)

# Each marker is a regex fragment matched against the raw -H transcript
# (compiler diagnostics + the include trace share stderr). Path-shaped, not
# bare module names, so a coincidental substring elsewhere in a diagnostic
# (e.g. a warning message mentioning "qcbor" in prose) cannot false-positive.
# Qt modules are NOT enumerated here -- see the ALLOWLIST check below, which
# covers every Qt module (including ones nobody thought to list, e.g.
# QtTest/QtSql/QtXml/QtConcurrent) by construction. This list stays a
# blocklist only for the non-Qt families, which live under their own
# separate install prefixes and so have no umbrella-sharing problem to
# allowlist against.
set(_forbidden_markers
    "/KF6/"           # KDE Frameworks 6 -- a downstream KDE client's own layer, never this library's
    "/LibreSCRS/SmartCard/"   # LibreMiddleware's public headers -- Core/Wire never leak these either
    "/LibreSCRS/Plugin/"
    "/LibreSCRS/Certificate/"
    "/LibreSCRS/Signing/"
    "/LibreSCRS/Trust/"
    "/qcbor/")        # the vendored CBOR codec Wire folds in -- never a Qt client concern

set(_any_failed FALSE)

foreach(_hdr IN LISTS HEADERS)
    string(REPLACE "." "_" _hdr_safe "${_hdr}")
    set(_src "${GENERATED_DIR}/${_hdr_safe}_accept.cpp")
    file(WRITE "${_src}" "#include <LibreSCRS/AgentClient/${_hdr}>\nint main() { return 0; }\n")

    set(_cmd "${CXX_COMPILER}" -std=c++23 -fsyntax-only -H
        "-I${CLIENT_INCLUDE_DIR}" "-I${EXPORT_INCLUDE_DIR}" "-I${REPO_INCLUDE_DIR}")
    # Framework search paths, not just include paths. A framework Qt -- which is
    # what Apple platforms get, from Qt's own installer and from the CI action
    # alike -- reports its include directory as
    # <prefix>/lib/QtCore.framework/Headers, and the umbrella headers in there
    # say `#include <QtCore/qstring.h>`. That resolves through the FRAMEWORK
    # lookup, so -I alone leaves every public header of this library failing to
    # compile on a claim about the library that is not true. The directory
    # holding the .framework is what -F wants.
    #
    # SYSTEM include paths, not user ones. This harness asks whether OUR headers
    # stand on their own; a diagnostic raised inside Qt's headers is not that
    # question, and with -I it is fatal all the same. Measured: Qt 6.11's
    # qyieldcpu.h calls __yield() under `#if __has_builtin(__yield)`, which
    # clang answers true for while still wanting the ACLE declaration -- an
    # implicit declaration, an error in C++, in a file nobody here wrote. The
    # real targets never saw it because CMake marks an imported target's
    # includes SYSTEM, so this harness was the only place compiling Qt as if it
    # were ours.
    set(_qt_framework_dirs "")
    foreach(_qt_dir IN LISTS _qt_core_includes)
        list(APPEND _cmd "-isystem" "${_qt_dir}")
        if(_qt_dir MATCHES "^(.*)/[A-Za-z0-9]+\\.framework/Headers/?$")
            list(APPEND _qt_framework_dirs "${CMAKE_MATCH_1}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES _qt_framework_dirs)
    foreach(_fw_dir IN LISTS _qt_framework_dirs)
        list(APPEND _cmd "-iframework" "${_fw_dir}")
    endforeach()
    list(APPEND _cmd "${_src}")

    execute_process(COMMAND ${_cmd} RESULT_VARIABLE _rv OUTPUT_VARIABLE _ov ERROR_VARIABLE _ev)

    if(NOT _rv EQUAL 0)
        message("---- ${_hdr}: FAILED TO COMPILE (exit ${_rv}) ----")
        message("${_ev}")
        set(_any_failed TRUE)
        continue()
    endif()

    foreach(_marker IN LISTS _forbidden_markers)
        if(_ev MATCHES "${_marker}")
            message("---- ${_hdr}: forbidden header reachable via '${_marker}' ----")
            string(REGEX MATCHALL "[^\n]*${_marker}[^\n]*" _hits "${_ev}")
            foreach(_hit IN LISTS _hits)
                message("    ${_hit}")
            endforeach()
            set(_any_failed TRUE)
        endif()
    endforeach()

    # Qt-module ALLOWLIST: every path component shaped like /Qt<Name>/
    # anywhere in the transcript must name QtCore -- fail-closed for ANY Qt
    # module, not just the ones a hand-maintained blocklist happens to name
    # (QtTest is guaranteed installed alongside Qt6::Test; QtSql/QtXml/
    # QtConcurrent are commonly present too -- none of those were ever in
    # the old blocklist, so they used to pass silently). Extraction works at
    # module-NAME level (matched out of the path, not the full path string),
    # so QtCore's own internal subpaths (e.g. .../QtCore/private/...) are
    # still correctly recognized as QtCore and allowed.
    # Two path shapes, because Qt has two layouts and only one of them was
    # matched here. A framework Qt spells the component `QtGui.framework`, which
    # `/Qt[A-Za-z0-9]+/` does not match -- the dot is outside the class. On such
    # a build this loop found ZERO Qt modules and allowlisted every one of them
    # by finding nothing to check, which is the failure mode this guard was
    # written to prevent, arriving through the guard itself.
    string(REGEX MATCHALL "/Qt[A-Za-z0-9]+(\\.framework)?/" _qt_module_path_hits "${_ev}")
    unset(_qt_modules_seen)
    foreach(_path_hit IN LISTS _qt_module_path_hits)
        string(REGEX MATCH "Qt[A-Za-z0-9]+" _module "${_path_hit}")
        if(NOT _module IN_LIST _qt_modules_seen)
            list(APPEND _qt_modules_seen "${_module}")
        endif()
    endforeach()
    foreach(_module IN LISTS _qt_modules_seen)
        if(NOT _module STREQUAL "QtCore")
            message("---- ${_hdr}: forbidden Qt module reachable: ${_module} (only QtCore is allowlisted) ----")
            string(REGEX MATCHALL "[^\n]*/${_module}(\\.framework)?/[^\n]*" _hits "${_ev}")
            foreach(_hit IN LISTS _hits)
                message("    ${_hit}")
            endforeach()
            set(_any_failed TRUE)
        endif()
    endforeach()
    unset(_qt_module_path_hits)
    unset(_qt_modules_seen)
endforeach()

if(_any_failed)
    message(FATAL_ERROR
        "HeaderAcceptance: one or more public headers failed the standalone "
        "compile, reached a Qt module other than QtCore, or pulled in a "
        "KF6/LibreMiddleware/QCBOR header -- see the transcript above.")
endif()

list(LENGTH HEADERS _header_count)
message("HeaderAcceptance: all ${_header_count} headers compiled standalone with no forbidden includes.")
