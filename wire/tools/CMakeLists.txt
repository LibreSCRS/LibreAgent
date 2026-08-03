# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Build-time tooling for the wire contract. Deliberately NOT installed: this
# is how the contract is checked, not part of what the project ships.

add_library(LibreAgentCddlVocabulary INTERFACE)
target_include_directories(LibreAgentCddlVocabulary INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(LibreAgentCddlVocabulary INTERFACE cxx_std_23)

add_executable(wire-vocabulary-gen wire-vocabulary-gen.cpp)
target_link_libraries(wire-vocabulary-gen PRIVATE LibreAgentCddlVocabulary)

# The ONE way to regenerate the committed manifest. CI compares against this
# target's output; a developer runs the same target. Two ways to regenerate is
# how a generated artifact and its checker drift apart.
#
# Atomic by construction, via regen-manifest.cmake: the generator's stdout
# lands in a .tmp file first, and only a SUCCESSFUL run (exit 0) reaches the
# rename step. A refusal exits non-zero, leaves the committed manifest
# untouched -- a rejected regeneration must not corrupt the last-good one --
# and removes the .tmp file too, so a refusal leaves nothing behind at all.
add_custom_target(wire-vocabulary-regen
    COMMAND ${CMAKE_COMMAND}
            -DGENERATOR=$<TARGET_FILE:wire-vocabulary-gen>
            -DCDDL=${CMAKE_SOURCE_DIR}/wire/librescrs-agent.cddl
            -DOUT=${CMAKE_SOURCE_DIR}/wire/wire-vocabulary.json
            -P ${CMAKE_CURRENT_SOURCE_DIR}/regen-manifest.cmake
    DEPENDS wire-vocabulary-gen
    COMMENT "Regenerating the wire vocabulary manifest from the contract grammar")
