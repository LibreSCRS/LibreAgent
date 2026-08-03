# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs wire-vocabulary-gen and installs its output atomically. Invoked via
# `cmake -P` from the wire-vocabulary-regen custom target so the conditional
# cleanup below can run at build time, not configure time.
#
# On success: the generator's stdout (captured to GENERATED) becomes OUT.
# On failure (non-zero exit): OUT is left untouched -- see the target's own
# comment for why that matters -- and the tmp file is removed too, so a
# refused regeneration leaves nothing behind, successful or not.
#
# Expects GENERATOR, CDDL, OUT to be set via -D on the command line.

set(generated "${OUT}.tmp")

execute_process(
    COMMAND "${GENERATOR}" "${CDDL}"
    OUTPUT_FILE "${generated}"
    ERROR_VARIABLE stderrOutput
    RESULT_VARIABLE result)

if(NOT result EQUAL 0)
    file(REMOVE "${generated}")
    message(FATAL_ERROR "${stderrOutput}")
endif()

file(RENAME "${generated}" "${OUT}")
