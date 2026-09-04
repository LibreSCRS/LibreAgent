# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Pkcs11ModuleExport.cmake — the two link-time facts a PKCS#11 module must carry.
#
# Provided to every consumer on all three paths a host can reach this project by:
# this repo itself, a FetchContent subproject build, and an installed CONFIG
# package (LibreAgentConfig.cmake include()s the installed copy of this file
# when Pkcs11Facade is among the requested components).

# Link a MODULE target as a PKCS#11 provider.
#
# This is the ONLY sanctioned way to link LibreAgent::Pkcs11Facade. Linking it
# by bare name builds, installs and dlopens a file with no entry point in it,
# and no configure-time review can see that.
function(librescrs_pkcs11_module_link target)
    # Where the two linker statements live.
    #
    # Resolved INSIDE the function, from the function's own defining file, and
    # not by a set() next to it: a FetchContent consumer includes this file in
    # the agent's directory scope, which is a CHILD of the consumer's, so a
    # variable set there is simply not there when the consumer calls this. The
    # symptom was a module linked with an EMPTY `--version-script=`, which the
    # linker rejects outright -- and would, on a linker that tolerated it, have
    # produced a module exporting everything.
    #
    # An installed package overrides both, because there the files sit beside
    # the data directory rather than beside the sources; LibreAgentConfig sets
    # them before include()ing this file, in the CONSUMER's own scope.
    set(_map "${LIBREAGENT_PKCS11_EXPORTS_MAP}")
    set(_symbols "${LIBREAGENT_PKCS11_EXPORTS_SYMBOLS}")
    if(NOT _map)
        set(_map "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../src/pkcs11/exports.map")
    endif()
    if(NOT _symbols)
        set(_symbols "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../src/pkcs11/exports.symbols")
    endif()
    # Fail here rather than hand the linker a path it will not find. An export
    # statement that silently does not apply is the one failure this whole
    # helper exists to prevent.
    if(APPLE)
        if(NOT EXISTS "${_symbols}")
            message(FATAL_ERROR "librescrs_pkcs11_module_link: no exported-symbols list at ${_symbols}")
        endif()
    elseif(NOT EXISTS "${_map}")
        message(FATAL_ERROR "librescrs_pkcs11_module_link: no version script at ${_map}")
    endif()

    # 1. Pull the whole facade archive. Its entry point (C_GetFunctionList, in
    #    Module.o) resolves no undefined symbol of this module's own objects --
    #    the module DEFINES the client factory and the archive CALLS it, so the
    #    dependency runs the other way. Member-on-demand extraction therefore
    #    contributes nothing and the module exports no C_* at all.
    #    CMake >= 3.24 spells this per-linker: --whole-archive / -force_load.
    target_link_libraries(${target} PRIVATE
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,LibreAgent::Pkcs11Facade>")

    # 2. Publish exactly one symbol, spelled the way each linker spells it.
    #    Apple's ld64 has no --version-script; it takes an exported-symbols
    #    list, and the declaration macro in pkcs11.h gives that one symbol
    #    explicit default visibility so the list has something to publish.
    if(APPLE)
        target_link_options(${target} PRIVATE
            "-Wl,-exported_symbols_list,${_symbols}")
    else()
        target_link_options(${target} PRIVATE
            "-Wl,--version-script=${_map}")
    endif()

    # A module is a leaf: nothing links it, everything dlopens it. Hidden by
    # default keeps the two statements above from being the only thing standing
    # between an internal helper and a loader's symbol table.
    set_target_properties(${target} PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
endfunction()
