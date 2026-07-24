# SPDX-License-Identifier: LGPL-2.1-or-later
#
# ScmRightsSpikeTest is a pure POSIX exercise (socketpair/memfd_create/
# sendmsg/recvmsg/poll) with no LibreAgent::Core, no Qt, no LibreMiddleware —
# so it deliberately skips the agent_core_test() helper from the parent
# tests/CMakeLists.txt and links only GTest, same as tests/wire/'s
# WireHeadersTest. See ScmRightsSpikeTest.cpp for the spike's purpose.
add_executable(ScmRightsSpikeTest ScmRightsSpikeTest.cpp)
target_link_libraries(ScmRightsSpikeTest PRIVATE GTest::gtest GTest::gtest_main)
add_test(NAME ScmRightsSpikeTest COMMAND ScmRightsSpikeTest)
