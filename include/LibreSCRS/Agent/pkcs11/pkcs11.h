// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Self-contained PKCS#11 header for the agent-proxy module. Defines the five
// platform-specific macros the OASIS spec requires (CK_PTR / the function
// declaration + pointer macros / NULL_PTR) for a UNIX/ELF build, then pulls in
// the vendored OASIS v3.2 header set (pkcs11-oasis.h -> pkcs11t.h + pkcs11f.h).
// Consumers include ONLY this file:
//     #include <LibreSCRS/Agent/pkcs11/pkcs11.h>
//
// The vendored OASIS headers are a verbatim copy of LibreMiddleware's
// lib/pkcs11/include/pkcs11 set; this module advertises a v2.40 function list
// (CK_FUNCTION_LIST) for maximum loader compatibility (Java SunPKCS11 rejects
// 3.x), exactly as the LM native module does.

#ifndef LIBRESCRS_PKCS11_AGENT_PKCS11_H
#define LIBRESCRS_PKCS11_AGENT_PKCS11_H 1

// 1. CK_PTR — pointer indirection.
#define CK_PTR *

// 2. CK_DECLARE_FUNCTION — an importable/exportable Cryptoki function.
//
//    Marked default-visible, on every platform, and that is load-bearing rather
//    than defensive. The core is compiled into a static archive with hidden
//    default visibility -- so that the internals it folds into a module do not
//    reach a loader's symbol table -- and visibility is decided when an object
//    is COMPILED. A linker export statement can only publish a symbol the
//    object already made visible: with the entry point compiled hidden, the
//    version script has nothing to keep and the module exports NOTHING. That is
//    a file that builds, installs and dlopens, and has no C_GetFunctionList in
//    it. Measured, not feared.
//
//    So the two halves are: every Cryptoki entry point is visible here, and the
//    linker statement cuts that set down to the one the module publishes --
//    --version-script on ELF, -exported_symbols_list on Apple, both applied by
//    cmake/Pkcs11ModuleExport.cmake.
#define CK_DECLARE_FUNCTION(returnType, name) __attribute__((visibility("default"))) returnType name

// 3. CK_DECLARE_FUNCTION_POINTER — a Cryptoki API function pointer.
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)

// 4. CK_CALLBACK_FUNCTION — an application callback function pointer.
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

// 5. NULL_PTR — the null pointer value.
#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include <LibreSCRS/Agent/pkcs11/oasis/pkcs11-oasis.h>

#endif // LIBRESCRS_PKCS11_AGENT_PKCS11_H
