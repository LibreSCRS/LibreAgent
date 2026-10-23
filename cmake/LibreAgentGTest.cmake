# SPDX-License-Identifier: LGPL-2.1-or-later
#
# LibreAgentGTest.cmake — gtest_discover_tests() with a test environment that
# survives.
#
# Provided on every path a host reaches this project by: this repo itself, a
# FetchContent subproject build (the top-level CMakeLists.txt include()s it, and
# a function is global), and an installed CONFIG package (LibreAgentConfig.cmake
# include()s the installed copy).

include(GoogleTest)

# Discover <tgt>'s cases like gtest_discover_tests(), and give them ENVIRONMENT
# and ENVIRONMENT_MODIFICATION as whole lists.
#
#   libreagent_gtest_discover_tests(<tgt>
#       [ENVIRONMENT <var>=<value>...]
#       [ENVIRONMENT_MODIFICATION <var>=<op>:<value>...]
#       [<any other gtest_discover_tests() argument>...])
#
# Passed through gtest_discover_tests(... PROPERTIES ENVIRONMENT "A=1;B=2"),
# such a list reaches the cases as A=1 alone on CMake before 4.4, and every
# property after it is lost or garbled too: GoogleTestAddTests.cmake writes each
# entry as its own set_tests_properties() argument, which then pairs them as
# property names and values. The escaped "A=1\;B=2" mends 3.31 and 4.1 but
# arrives on 4.4 as the single variable A="1;B=2", so no spelling of a list
# passes through PROPERTIES on every CMake.
# The two properties are set instead from an include file ctest reads after the
# discovery one, where each list is one bracket argument.
function(libreagent_gtest_discover_tests tgt)
    # Each entry of either list holds a '=', so the first argument without one
    # ends it, whichever gtest_discover_tests() keyword that is. Iterating ARGN
    # also splits a quoted "A=1;B=2" into its two entries.
    set(forward "")
    set(collecting "")
    foreach(arg IN LISTS ARGN)
        if(arg STREQUAL "ENVIRONMENT" OR arg STREQUAL "ENVIRONMENT_MODIFICATION")
            set(collecting prop_${arg})
            set(prop_${arg} "")
        elseif(collecting AND arg MATCHES "=")
            list(APPEND ${collecting} "${arg}")
        else()
            set(collecting "")
            list(APPEND forward "${arg}")
        endif()
    endforeach()
    list(FIND forward TEST_LIST at)
    if(at EQUAL -1)
        set(list_var "${tgt}_TESTS")
        list(APPEND forward TEST_LIST ${list_var})
    else()
        math(EXPR at "${at} + 1")
        list(GET forward ${at} list_var)
    endif()
    gtest_discover_tests(${tgt} ${forward})

    set(props "")
    foreach(prop IN ITEMS ENVIRONMENT ENVIRONMENT_MODIFICATION)
        if(DEFINED prop_${prop})
            string(APPEND props " ${prop} [==[${prop_${prop}}]==]")
        endif()
    endforeach()
    if(props STREQUAL "")
        return()
    endif()
    set(env_file "${CMAKE_CURRENT_BINARY_DIR}/${list_var}_environment.cmake")
    file(WRITE "${env_file}"
        "if(${list_var})\n"
        "  set_tests_properties(\${${list_var}} PROPERTIES${props})\n"
        "endif()\n")
    set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES "${env_file}")
endfunction()
