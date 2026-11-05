// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Isolation proof for WireClientCodecPurityCheck in tests/wire/CMakeLists.txt:
// the client-role codec is a private header under src/, so this TU sees src/
// and include/ and nothing else, and links nothing. Its chain is Messages.h
// and Cbor.h; an LM, Qt or OpenSSL include added anywhere in it fails this
// target with a file-not-found error.
#include "wire/ClientCodec.h"
