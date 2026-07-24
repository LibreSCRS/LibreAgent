// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer target for the CBOR decoder (untrusted-parser hardening). The
// decoder must never crash / invoke UB on arbitrary input; it either returns a
// bounded CborValue or a CborError. A returned value must re-encode without
// crashing (exercises the encode path on fuzz-derived structures too).
//
// Not built by this repo's normal CMake configuration. Run it via
// ci/scripts/fuzz-cbor.sh, which builds this file standalone with a
// fuzzer-capable clang++ (-fsanitize=fuzzer,address) and runs it against a
// scratch copy of tests/corpus/cbor/. AppleClang ships no libFuzzer runtime,
// so this does not run on macOS.
#include <LibreSCRS/Agent/wire/Cbor.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const auto decoded = LibreSCRS::Agent::Wire::decode(std::span<const std::uint8_t>(data, size));
    if (decoded.has_value()) {
        // A successfully decoded (thus canonical) value must re-encode to exactly
        // the input — the decoder's own contract.
        const auto reencoded = decoded->encode();
        if (reencoded.size() != size) {
            __builtin_trap();
        }
    }
    return 0;
}
