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

# --- suites on a private session bus -----------------------------------------
#
# An address no bus can be listening on. ctest hands it to every bus-backed
# test in both variables below; dbus-run-session overwrites
# DBUS_SESSION_BUS_ADDRESS with the bus it starts, so the two are equal
# exactly when the wrapper did not run -- which is what
# PrivateSessionBusTest.cpp asserts against. Cache entries, so the function
# below finds them from whichever directory a consumer calls it in.
set(LIBREAGENT_PRIVATE_BUS_SENTINEL "unix:path=/nonexistent/librescrs-no-private-bus" CACHE INTERNAL "")
set(LIBREAGENT_PRIVATE_BUS_ENV
    "LIBRESCRS_OUTER_BUS=${LIBREAGENT_PRIVATE_BUS_SENTINEL};DBUS_SESSION_BUS_ADDRESS=${LIBREAGENT_PRIVATE_BUS_SENTINEL}"
    CACHE INTERNAL "ENVIRONMENT for a test wrapped by libreagent_private_session_bus()")
# Installed beside this file; in the source tree it lives in testsupport/.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/PrivateSessionBusTest.cpp")
    set(LIBREAGENT_PRIVATE_BUS_SOURCE "${CMAKE_CURRENT_LIST_DIR}/PrivateSessionBusTest.cpp" CACHE INTERNAL "")
else()
    set(LIBREAGENT_PRIVATE_BUS_SOURCE "${CMAKE_CURRENT_LIST_DIR}/../testsupport/PrivateSessionBusTest.cpp"
        CACHE INTERNAL "")
endif()

# Wraps <tgt> in its own session bus and compiles in the case that says so.
# The suite name carries the target's name because every bus-backed binary
# gets this case, and ctest entries are named after the case alone. Register
# its cases with libreagent_gtest_discover_tests(<tgt> ENVIRONMENT
# "${LIBREAGENT_PRIVATE_BUS_ENV}" ...).
#
#   libreagent_private_session_bus(<tgt> [SERVICE_DIR <dir>])
#
# The bus runs from a configuration of its own: the session bus's usual one
# minus every service directory. dbus-run-session's default reads the
# machine's, so on a machine with the agent installed the REAL agent is
# activatable on every private bus, and the first call that starts an installed
# agent -- a configuration read, a "try again" -- would launch it in the middle
# of a suite, against the real card; "no agent installed" could not be tested
# at all. SERVICE_DIR names the one directory a suite that wants something
# activatable puts its own .service files in.
function(libreagent_private_session_bus tgt)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "SERVICE_DIR" "")
    if(arg_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "libreagent_private_session_bus: unknown arguments: ${arg_UNPARSED_ARGUMENTS}")
    endif()
    # Resolved at call time: dbus-run-session is required only by the suites
    # that need a bus.
    find_program(DBUS_RUN_SESSION dbus-run-session REQUIRED)
    set(servicedir "")
    if(arg_SERVICE_DIR)
        set(servicedir "  <servicedir>${arg_SERVICE_DIR}</servicedir>\n")
    endif()
    set(config "${CMAKE_CURRENT_BINARY_DIR}/${tgt}-session-bus.conf")
    # The limits are the session bus's own, so a suite sees the bus it would
    # see at a desktop in everything but what it can start.
    file(CONFIGURE OUTPUT "${config}" @ONLY CONTENT [=[
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <keep_umask/>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
@servicedir@  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
  <limit name="max_incoming_bytes">1000000000</limit>
  <limit name="max_incoming_unix_fds">250000000</limit>
  <limit name="max_outgoing_bytes">1000000000</limit>
  <limit name="max_outgoing_unix_fds">250000000</limit>
  <limit name="max_message_size">1000000000</limit>
  <limit name="service_start_timeout">120000</limit>
  <limit name="auth_timeout">240000</limit>
  <limit name="pending_fd_timeout">150000</limit>
  <limit name="max_completed_connections">100000</limit>
  <limit name="max_incomplete_connections">10000</limit>
  <limit name="max_connections_per_user">100000</limit>
  <limit name="max_pending_service_starts">10000</limit>
  <limit name="max_names_per_connection">50000</limit>
  <limit name="max_match_rules_per_connection">50000</limit>
  <limit name="max_replies_per_connection">50000</limit>
</busconfig>
]=])
    set_target_properties(${tgt} PROPERTIES
        CROSSCOMPILING_EMULATOR "${DBUS_RUN_SESSION};--config-file=${config};--")
    target_sources(${tgt} PRIVATE "${LIBREAGENT_PRIVATE_BUS_SOURCE}")
    target_compile_definitions(${tgt} PRIVATE
        LIBRESCRS_PRIVATE_BUS_SUITE=${tgt}PrivateSessionBus)
endfunction()
