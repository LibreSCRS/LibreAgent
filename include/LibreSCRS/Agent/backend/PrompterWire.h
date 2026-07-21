// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The neutral secret-KIND vocabulary the agent core's credential plumbing keys
// on. "pin"/"can"/"mrz" ARE the CredentialEntry field identifiers the LM Auth
// surface matches against AuthRequirement keys (see
// LibreSCRS::Auth::CredentialResult::find) — the prompter kind and the
// credential key are the same vocabulary by design, so CredentialCache and
// SignFlow key their entries off this table.
//
// This is NOT the full Prompter1 wire contract. The D-Bus option-dict KEYS and
// the RequestSecret STATUS strings are transport vocabulary and belong with the
// platform backend: they live in the backend's own PrompterWire copy, shared by
// that boundary's two D-Bus ends (the backend prompter client producer and the prompter
// service consumer). Only the neutral kinds belong in the Qt-free,
// transport-free core: the three single-secret kinds double as LM Auth
// credential keys; the multi-secret change_pin kind is request vocabulary
// only (a PIN is never a cache/credential key).
//
// Header-only, dependency-free (no Qt, no backend transport, no LM).

#pragma once

namespace LibreSCRS::PrompterWire {

// Secret kind the credential plumbing requests; ALSO the CredentialEntry field
// identifier the LM Auth surface matches.
inline constexpr const char* kKindPin = "pin";
inline constexpr const char* kKindCan = "can";
inline constexpr const char* kKindMrz = "mrz";

// Two-secret PIN-change prompt kind (current + new PIN in one modal). Request
// vocabulary ONLY — never a CredentialEntry/cache key: a PIN pair is prompted
// per use and never cached. Mirrored by design in the platform backend's
// PrompterWire copy (that boundary's own table).
inline constexpr const char* kKindChangePin = "change_pin";

} // namespace LibreSCRS::PrompterWire
