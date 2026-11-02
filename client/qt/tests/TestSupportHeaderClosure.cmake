# SPDX-License-Identifier: LGPL-2.1-or-later
#
# cmake -DMANIFEST=<file> -P TestSupportHeaderClosure.cmake
#
# MANIFEST lists the headers ClientQtTestSupport installs, one per line, as
# <installed path>=<source path>. A quoted include is looked up beside the
# including header first, which is how a consumer of the installed copies
# resolves it, so each one must name another installed header at the path it
# is installed under. An include of the client's internals, which are not
# installed, fails here instead of in the first host that compiles the doubles.

file(STRINGS "${MANIFEST}" entries)
set(installed "")
foreach(entry IN LISTS entries)
    string(REGEX MATCH "^([^=]+)=(.+)$" _ "${entry}")
    list(APPEND installed "${CMAKE_MATCH_1}")
    set(source_of_${CMAKE_MATCH_1} "${CMAKE_MATCH_2}")
endforeach()

set(missing "")
foreach(path IN LISTS installed)
    get_filename_component(dir "${path}" DIRECTORY)
    file(STRINGS "${source_of_${path}}" includes REGEX "^[ \t]*#[ \t]*include[ \t]+\"")
    foreach(line IN LISTS includes)
        string(REGEX MATCH "\"([^\"]+)\"" _ "${line}")
        set(target "${CMAKE_MATCH_1}")
        if(dir)
            set(target "${dir}/${target}")
        endif()
        cmake_path(NORMAL_PATH target)
        if(NOT target IN_LIST installed)
            list(APPEND missing "${path} includes \"${CMAKE_MATCH_1}\", which is not installed")
        endif()
    endforeach()
endforeach()

if(missing)
    list(JOIN missing "\n  " report)
    message(FATAL_ERROR "the installed test support does not compile on its own:\n  ${report}")
endif()
list(LENGTH installed count)
message(STATUS "${count} installed test-support headers, every quoted include among them")
