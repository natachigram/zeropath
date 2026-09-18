"""Heuristic detection of initializer-takeover mitigations (anti-conditions).

An *initializer takeover* is exploitable when an upgradeable/initializable
contract exposes an ``initialize`` function that an attacker can call (or
re-call) to seize ownership. It is *not* exploitable when the contract ships the
standard protections:

* the OpenZeppelin ``initializer`` / ``reinitializer`` modifier
* ``_disableInitializers()`` in the implementation constructor
* an explicit ``require(!initialized)`` re-initialization guard
* access control on ``initialize`` (``onlyOwner`` / ``onlyProxy`` / ``onlyRole``)

This module scans Solidity source for those protections and registers itself
with :mod:`zeropath.core.anti_conditions`, so the judge can block or downgrade a
takeover candidate whose target ``initialize`` is actually guarded. Detection is
heuristic (regex over source); hits are labelled ``confidence="heuristic"``.

Scope: simple initializable/upgradeable contracts. Not a full UUPS/Beacon proxy
analysis.
"""

from __future__ import annotations

import re

from zeropath.core.anti_conditions import (
    GuardHit,
    register_anti_conditions,
    summarize_guards,
)

INITIALIZER_BUG_CLASSES = {"access_control_initializer"}

INITIALIZER_MITIGATIONS = [
    "- Mark `initialize` with OpenZeppelin's `initializer` modifier (or "
    "`reinitializer(version)`), so it can run only once.",
    "- Call `_disableInitializers()` in the implementation contract's constructor "
    "so the logic contract itself cannot be initialized.",
    "- Guard re-initialization explicitly (e.g. `require(!initialized)`), and set "
    "the flag before external calls.",
    "- Restrict `initialize` to a trusted deployer/factory or initialize "
    "atomically in the deployment transaction to prevent front-running.",
]

# The `initialize` modifier list / body up to the opening brace or signature end.
_INITIALIZE_HEAD_RE = re.compile(r"function\s+initialize\w*\s*\([^)]*\)(?P<mods>[^{;]*)")
_REINIT_RE = re.compile(r"_disableinitializers|reinitializer")
_INIT_FLAG_GUARD_RE = re.compile(
    r"require\([^;]*!\s*_?initialized|require\([^;]*_?initialized\s*==\s*false|already\s*initialized"
)
_ACCESS_MOD_RE = re.compile(r"\bonly[a-z_]+\b|\binitializer\b")


def detect_initializer_takeover_guards(source: str) -> list[GuardHit]:
    """Return takeover-defeating protections detected in ``source``, if any.

    An empty list means no protection was recognised, i.e. ``initialize`` looks
    callable by an attacker. This does not prove exploitability -- only that none
    of the known guards were found.
    """

    if not source:
        return []
    text = source.lower()
    hits: list[GuardHit] = []

    head = _INITIALIZE_HEAD_RE.search(text)
    modifiers = head.group("mods") if head else ""

    if _REINIT_RE.search(text) or (head and "initializer" in modifiers):
        hits.append(
            GuardHit(
                "protected_initializer",
                "initialize is guarded by an initializer/reinitializer modifier or "
                "_disableInitializers(), so it cannot be (re-)called by an attacker.",
            )
        )
    if _INIT_FLAG_GUARD_RE.search(text):
        hits.append(
            GuardHit(
                "reinit_flag_guard",
                "A re-initialization flag guard (require(!initialized)) is present, "
                "preventing a second initialize call.",
            )
        )
    if head and _ACCESS_MOD_RE.search(modifiers.replace("initializer", "")):
        hits.append(
            GuardHit(
                "init_access_control",
                "initialize carries an access-control modifier (onlyOwner/"
                "onlyProxy/onlyRole), so an arbitrary caller cannot seize it.",
            )
        )
    return hits


register_anti_conditions(
    INITIALIZER_BUG_CLASSES, detect_initializer_takeover_guards, INITIALIZER_MITIGATIONS
)


__all__ = [
    "GuardHit",
    "INITIALIZER_BUG_CLASSES",
    "INITIALIZER_MITIGATIONS",
    "detect_initializer_takeover_guards",
    "summarize_guards",
]
