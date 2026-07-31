// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Prints the in-memory LAYOUT of this library's public value types, one line
// per type, for the ABI snapshot to record and diff.
//
// Why this exists at all: the rest of the ABI gate is a demangled SYMBOL diff,
// and a symbol name says nothing about the shape of the data behind it. Every
// type below is an aggregate a consumer holds, copies and passes BY VALUE, so
// its size and member offsets are compiled into that consumer's code. Add,
// remove or reorder a member and every already-built consumer keeps reading the
// old offsets against the new object -- silent, and the symbol surface does not
// move by a single line while it happens. That is not hypothetical: a member
// add to a public value type in this library changed its size by 56 bytes and
// the symbol diff reported nothing at all, because the type's name appears
// nowhere in the export table.
//
// So "0 added, 0 removed" is a statement about names, and this file is what
// makes the baseline also a statement about shape.
//
// Output format, one line per type, types sorted by name:
//
//   TypeName size=<sizeof> align=<alignof> members=<count> name@<offset> ...
//
// `members` is derived independently of the printed member list (see
// aggregateArity), which is the point: a member added into EXISTING PADDING
// changes neither `size` nor any existing offset, and would be invisible to
// this probe if the count were just the length of the list below. With the
// count computed from the type itself, adding such a member moves `members`
// and the gate fails.
//
// Offsets come from pointer differences on a real object rather than
// `offsetof`, which is only conditionally supported for these types and would
// need a diagnostic suppression at every use.
//
// Adding a public value type: add it to the LAYOUT list at the bottom, rebuild,
// and regenerate the baseline. Removing a member from one of these types is a
// consumer-visible break, not a refresh -- the regenerated baseline is the
// record that it was intended.

#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/CredentialTypes.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/IdentityRows.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <cstddef>
#include <cstdio>
#include <utility>

namespace {

using namespace LibreSCRS::AgentClient;

/// Converts to anything, in an unevaluated context only — the probe for
/// "does this aggregate accept N brace initialisers?".
struct AnyInit
{
    template <typename T>
    // NOLINTNEXTLINE(google-explicit-constructor) — implicit is the whole point
    constexpr operator T() const noexcept; // NOSONAR: declared, never defined
};

/// The number of members an aggregate accepts in a braced initialiser: the
/// largest N for which `T{N initialisers}` compiles. Independent of the member
/// list this file prints, so the two disagreeing is exactly the signal wanted
/// (a member was added or removed and nobody updated this file).
template <typename T, typename... Filled>
consteval std::size_t aggregateArity()
{
    if constexpr (requires { T{Filled{}..., AnyInit{}}; }) {
        return aggregateArity<T, Filled..., AnyInit>();
    } else {
        return sizeof...(Filled);
    }
}

template <typename S, typename M>
std::size_t offsetIn(const S& object, const M& member) noexcept
{
    const auto* base = reinterpret_cast<const char*>(&object);  // NOLINT
    const auto* field = reinterpret_cast<const char*>(&member); // NOLINT
    return static_cast<std::size_t>(field - base);
}

} // namespace

// One type's line. `v` names the live instance the LAYOUT_MEMBER uses.
#define LAYOUT_BEGIN(T)                                                                                                \
    {                                                                                                                  \
        const T v{};                                                                                                   \
        std::printf("%s size=%zu align=%zu members=%zu", #T, sizeof(T), alignof(T), aggregateArity<T>());
#define LAYOUT_MEMBER(m) std::printf(" " #m "@%zu", offsetIn(v, v.m));
#define LAYOUT_END()                                                                                                   \
    std::printf("\n");                                                                                                 \
    }

// A public value type whose data members are PRIVATE, so neither their offsets
// nor a braced-initialiser arity can be taken from outside. Size and alignment
// still can, and for a type embedded by value in other public types those are
// the numbers that reach a consumer's compiled code — a growth past its
// current slot silently changes every embedder's layout.
//
// Recording it here rather than exempting it is deliberate. Such a type is
// EASY to talk yourself out of gating ("nothing can see its members anyway"),
// and the argument is wrong for exactly the reason it sounds right: what
// escapes is not the members but the size they add up to.
#define LAYOUT_OPAQUE(T) std::printf("%s size=%zu align=%zu members=opaque\n", #T, sizeof(T), alignof(T));

int main()
{
    // Sorted by type name so the emitted section is stable without the caller
    // having to sort it.

    // Publicly CONSTRUCTIBLE, which is the whole reason this one is here and
    // its three sibling proxies are not. Their constructors are private, so a
    // consumer can only ever hold a pointer this library minted and its size
    // never enters consumer code. This one has a public constructor -- the
    // documented alternative to the shared accessor -- so a consumer that says
    // `new AgentClient(...)` compiles the size into its OWN object file, as the
    // operator-new argument. Growing the type without rebuilding that consumer
    // is then an allocation smaller than the object, which is memory
    // corruption with nothing pointing at this file. Its members are private,
    // so size and alignment are all that can be recorded -- and they are
    // exactly what leaks.
    LAYOUT_OPAQUE(AgentClient)

    LAYOUT_BEGIN(BatchDocument)
    LAYOUT_MEMBER(displayName)
    LAYOUT_MEMBER(fd)
    LAYOUT_END()

    LAYOUT_BEGIN(BatchSignRow)
    LAYOUT_MEMBER(displayName)
    LAYOUT_MEMBER(artifact)
    LAYOUT_MEMBER(meta)
    LAYOUT_MEMBER(error)
    LAYOUT_END()

    LAYOUT_BEGIN(CertificateInfo)
    LAYOUT_MEMBER(id)
    LAYOUT_MEMBER(subject)
    LAYOUT_MEMBER(issuer)
    LAYOUT_MEMBER(notBefore)
    LAYOUT_MEMBER(notAfter)
    LAYOUT_MEMBER(signingCapable)
    LAYOUT_MEMBER(trust)
    LAYOUT_MEMBER(securityStatus)
    LAYOUT_MEMBER(keyUsageBits)
    LAYOUT_MEMBER(extendedKeyUsageOids)
    LAYOUT_MEMBER(chainSubjectCns)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    LAYOUT_BEGIN(CredentialRecord)
    LAYOUT_MEMBER(id)
    LAYOUT_MEMBER(label)
    LAYOUT_MEMBER(kind)
    LAYOUT_MEMBER(state)
    LAYOUT_MEMBER(retriesLeft)
    LAYOUT_MEMBER(retriesMax)
    LAYOUT_MEMBER(usesLeft)
    LAYOUT_MEMBER(usesMax)
    LAYOUT_MEMBER(unblocksLeft)
    LAYOUT_MEMBER(minLength)
    LAYOUT_MEMBER(maxLength)
    LAYOUT_MEMBER(canChange)
    LAYOUT_MEMBER(unblockable)
    LAYOUT_MEMBER(activatable)
    LAYOUT_MEMBER(keyActivationPending)
    LAYOUT_MEMBER(keyActivatable)
    LAYOUT_MEMBER(probeSafe)
    LAYOUT_MEMBER(unblockStyle)
    LAYOUT_MEMBER(recovery)
    LAYOUT_MEMBER(blockedGuidanceKey)
    LAYOUT_MEMBER(blockedGuidanceFallback)
    LAYOUT_MEMBER(keyActivationGuidanceKey)
    LAYOUT_MEMBER(keyActivationGuidanceFallback)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    // Private single `int`, but embedded BY VALUE in PhotoItem, BatchDocument
    // and BatchSignRow, each of which currently gives it an eight-byte slot
    // with four bytes of padding. Growth within that padding is invisible in
    // every embedder's line -- measured, not assumed -- so without this line
    // the first four bytes it gains are unguarded everywhere.
    LAYOUT_OPAQUE(FdHandle)

    LAYOUT_BEGIN(Field)
    LAYOUT_MEMBER(key)
    LAYOUT_MEMBER(value)
    LAYOUT_MEMBER(detail)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    LAYOUT_BEGIN(FieldGroup)
    LAYOUT_MEMBER(key)
    LAYOUT_MEMBER(fields)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    LAYOUT_BEGIN(IdentityRow)
    LAYOUT_MEMBER(groupKey)
    LAYOUT_MEMBER(fieldKey)
    LAYOUT_MEMBER(labelKey)
    LAYOUT_MEMBER(labelFallback)
    LAYOUT_MEMBER(value)
    LAYOUT_END()

    LAYOUT_BEGIN(LayoutResult)
    LAYOUT_MEMBER(fontSize)
    LAYOUT_MEMBER(lineHeight)
    LAYOUT_MEMBER(lines)
    LAYOUT_MEMBER(clipped)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    LAYOUT_BEGIN(ManagePinOptions)
    LAYOUT_MEMBER(activateKey)
    LAYOUT_END()

    LAYOUT_BEGIN(PhotoItem)
    LAYOUT_MEMBER(key)
    LAYOUT_MEMBER(fd)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    LAYOUT_BEGIN(PinResult)
    LAYOUT_MEMBER(outcome)
    LAYOUT_MEMBER(retriesLeft)
    LAYOUT_MEMBER(blocked)
    LAYOUT_MEMBER(pinActivated)
    LAYOUT_MEMBER(keyActivated)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    LAYOUT_BEGIN(SignOptions)
    LAYOUT_MEMBER(format)
    LAYOUT_MEMBER(level)
    LAYOUT_MEMBER(packaging)
    LAYOUT_MEMBER(visualSignature)
    LAYOUT_MEMBER(tsaUrl)
    LAYOUT_MEMBER(extra)
    LAYOUT_END()

    return 0;
}
