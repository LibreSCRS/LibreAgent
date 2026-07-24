# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs as this component's HeaderAcceptance ctest (see CMakeLists.txt in this
# directory for the full rationale). For every header named in -DHEADERS=...:
#   1. writes `#include <LibreSCRS/AgentClient/<header>>\nint main(){return 0;}`
#      to a fresh TU under -DGENERATED_DIR
#   2. compiles it with `-fsyntax-only -H` and EXACTLY the four include paths
#      the brief specifies (client include dir, the generated Export.h's
#      dir, the repo's std-only include/, and Qt6::Core's own include dirs
#      read back from -DQT_CORE_INCLUDES_FILE)
#   3. fails this whole test (message(FATAL_ERROR), nonzero exit) if the
#      compile itself fails, OR if `-H`'s include transcript contains a path
#      that could only have come from QtDBus, KF6, LibreMiddleware, or QCBOR.
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
set(_forbidden_markers
    "/QtDBus/"        # Qt module this library never links PUBLIC-visibly to a public header
    "/QtWidgets/"      # any other non-Core Qt module sharing the same umbrella prefix
    "/QtGui/"
    "/QtNetwork/"
    "/QtQml/"
    "/KF6/"           # KDE Frameworks 6 -- LibreKDE's own layer, never this library's
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
    foreach(_qt_dir IN LISTS _qt_core_includes)
        list(APPEND _cmd "-I${_qt_dir}")
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
endforeach()

if(_any_failed)
    message(FATAL_ERROR
        "HeaderAcceptance: one or more public headers failed the standalone "
        "compile, or pulled in a QtDBus/KF6/LibreMiddleware/QCBOR header -- "
        "see the transcript above.")
endif()

list(LENGTH HEADERS _header_count)
message("HeaderAcceptance: all ${_header_count} headers compiled standalone with no forbidden includes.")
