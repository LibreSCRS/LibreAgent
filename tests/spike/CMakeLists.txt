# SPDX-License-Identifier: LGPL-2.1-or-later
#
# ScmRightsSpikeTest is a pure POSIX exercise (socketpair/memfd_create/
# sendmsg/recvmsg/poll) with no LibreAgent::Core, no Qt, no LibreMiddleware —
# so it deliberately skips the agent_core_test() helper from the parent
# tests/CMakeLists.txt and links only GTest, same as tests/wire/'s
# WireHeadersTest. See ScmRightsSpikeTest.cpp for the spike's purpose.
#
# Linux only: the spike calls memfd_create, which Darwin does not have, so a
# standalone macOS configure of this repo failed to compile before it could
# build anything else. That went unnoticed because the only consumer on that
# platform reaches this repo through FetchContent, where PROJECT_IS_TOP_LEVEL is
# false and this directory is never added at all. Guarded rather than ported:
# the spike is about SCM_RIGHTS on Linux, and an anonymous-fd equivalent for
# Darwin already exists downstream.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ScmRightsSpikeTest ScmRightsSpikeTest.cpp)
    target_link_libraries(ScmRightsSpikeTest PRIVATE GTest::gtest GTest::gtest_main)
    add_test(NAME ScmRightsSpikeTest COMMAND ScmRightsSpikeTest)
endif()
