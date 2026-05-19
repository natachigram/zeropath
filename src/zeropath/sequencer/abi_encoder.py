"""
Pure-Python Solidity ABI encoder — Phase 4.

Produces directly executable calldata from a function signature and parameter
list, matching the encoding submitted to Anvil / Foundry in Phase 5. Avoids a
hard dependency on ``eth-abi``/``web3.py`` (which have native extensions and
platform install issues) by implementing Keccak-256 + ABI head/tail encoding
in pure Python.

Supported Solidity types:
  - uintN / intN          (N is a multiple of 8 in 8..256, default 256)
  - address
  - bool
  - bytesN                (1 <= N <= 32)
  - bytes (dynamic)
  - string (dynamic)
  - T[]                   (dynamic array)
  - T[K]                  (fixed array)
  - tuples are NOT supported — use raw bytes if needed

Reference: https://docs.soliditylang.org/en/latest/abi-spec.html
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Keccak-256 (pure Python)
# ---------------------------------------------------------------------------
#
# Keccak-256 differs from NIST SHA3-256 only in the padding domain byte:
#   - SHA3-256: 0x06
#   - Keccak-256 (Ethereum): 0x01
#
# Implementation follows the official Keccak-f[1600] permutation. Slow but
# more than adequate for 4-byte selectors and ABI typehash work.

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f1600(state: list[list[int]]) -> None:
    for rnd in range(24):
        # θ (theta)
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # ρ (rho) + π (pi)
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])

        # χ (chi)
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) & 0xFFFFFFFFFFFFFFFF

        # ι (iota)
        state[0][0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 (Ethereum variant) over ``data``."""
    rate = 136  # bytes — for Keccak-256
    state = [[0] * 5 for _ in range(5)]

    # Pad with domain byte 0x01, then zeros, with high bit 0x80 on last byte.
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)

    # Absorb
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            x, y = i % 5, i // 5
            state[x][y] ^= lane
        _keccak_f1600(state)

    # Squeeze 32 bytes
    out = bytearray()
    for i in range(4):  # 4 lanes × 8 bytes = 32
        x, y = i % 5, i // 5
        out.extend(state[x][y].to_bytes(8, "little"))
    return bytes(out)


def function_selector(signature: str) -> bytes:
    """First 4 bytes of keccak256(canonical signature)."""
    return keccak256(_canonicalize_signature(signature).encode("ascii"))[:4]


# ---------------------------------------------------------------------------
# Signature parsing
# ---------------------------------------------------------------------------


_SIG_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$")


def _canonicalize_signature(signature: str) -> str:
    """
    Normalise a signature: strip whitespace, expand uint → uint256, int → int256,
    drop parameter names. Accepts both ``foo(uint256,address)`` and
    ``foo(uint256 amount, address recipient)``.
    """
    m = _SIG_RE.match(signature)
    if not m:
        raise ValueError(f"Invalid function signature: {signature!r}")
    name, raw_args = m.group(1), m.group(2).strip()
    if not raw_args:
        return f"{name}()"
    types = _split_top_level_commas(raw_args)
    norm_types = [_canonicalize_type(t.strip().split()[0]) for t in types]
    return f"{name}({','.join(norm_types)})"


def _split_top_level_commas(s: str) -> list[str]:
    """Split on commas not nested inside parens/brackets."""
    out, buf, depth = [], [], 0
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


_TYPE_ARRAY_RE = re.compile(r"^(.+?)(\[(\d*)\])$")


def _canonicalize_type(t: str) -> str:
    # Strip trailing array suffix, recurse on base.
    m = _TYPE_ARRAY_RE.match(t)
    if m:
        base, suffix, _ = m.group(1), m.group(2), m.group(3)
        return _canonicalize_type(base) + suffix
    if t == "uint":
        return "uint256"
    if t == "int":
        return "int256"
    return t


# ---------------------------------------------------------------------------
# Single-value encoders
# ---------------------------------------------------------------------------


def _pad32(b: bytes) -> bytes:
    if len(b) > 32:
        raise ValueError(f"value too large for 32 bytes: {len(b)}")
    return b"\x00" * (32 - len(b)) + b


def _pad32_right(b: bytes) -> bytes:
    pad = (-len(b)) % 32
    return b + b"\x00" * pad


def _encode_uint(value: int, bits: int) -> bytes:
    if value < 0:
        raise ValueError(f"negative value for uint{bits}: {value}")
    if value.bit_length() > bits:
        raise ValueError(f"value 0x{value:x} exceeds uint{bits}")
    return _pad32(value.to_bytes(bits // 8, "big"))


def _encode_int(value: int, bits: int) -> bytes:
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if not (lo <= value <= hi):
        raise ValueError(f"int{bits} out of range: {value}")
    if value < 0:
        value += 1 << 256  # two's complement extension to 256 bits
    return _pad32(value.to_bytes(32, "big"))


def _encode_address(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"address must be hex string, got {type(value).__name__}")
    v = value.lower()
    if v.startswith("0x"):
        v = v[2:]
    if len(v) != 40 or not all(c in "0123456789abcdef" for c in v):
        raise ValueError(f"invalid address: {value!r}")
    return _pad32(bytes.fromhex(v))


def _encode_bool(value: Any) -> bytes:
    return _pad32(b"\x01" if value else b"\x00")


def _encode_bytes_fixed(value: bytes, size: int) -> bytes:
    if isinstance(value, str):
        v = value[2:] if value.startswith("0x") else value
        value = bytes.fromhex(v)
    if len(value) != size:
        raise ValueError(f"bytes{size} expects {size} bytes, got {len(value)}")
    return _pad32_right(value)


def _encode_bytes_dyn(value: bytes | str) -> bytes:
    if isinstance(value, str):
        v = value[2:] if value.startswith("0x") else value
        value = bytes.fromhex(v) if all(c in "0123456789abcdefABCDEF" for c in v) else value.encode("utf-8")
    return _encode_uint(len(value), 256) + _pad32_right(value)


def _encode_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _encode_uint(len(raw), 256) + _pad32_right(raw)


# ---------------------------------------------------------------------------
# Type dispatcher
# ---------------------------------------------------------------------------


def _is_dynamic(type_str: str) -> bool:
    if type_str in ("bytes", "string"):
        return True
    m = _TYPE_ARRAY_RE.match(type_str)
    if m:
        _, _, size = m.group(1), m.group(2), m.group(3)
        if size == "":      # T[]
            return True
        return _is_dynamic(m.group(1))  # T[K] dynamic only if T is dynamic
    return False


def _encode_single(type_str: str, value: Any) -> bytes:
    """Encode one value of a given Solidity type as head bytes (no offset wrapping)."""
    # Arrays
    m = _TYPE_ARRAY_RE.match(type_str)
    if m:
        base, _, size = m.group(1), m.group(2), m.group(3)
        if size == "":  # dynamic T[]
            count = len(value)
            head = _encode_uint(count, 256)
            inner = _encode_tuple([base] * count, list(value))
            return head + inner
        # Fixed T[K]
        k = int(size)
        if len(value) != k:
            raise ValueError(f"array {type_str} expects {k} elements, got {len(value)}")
        return _encode_tuple([base] * k, list(value))

    # Scalars
    if type_str == "address":
        return _encode_address(value)
    if type_str == "bool":
        return _encode_bool(value)
    if type_str == "bytes":
        return _encode_bytes_dyn(value)
    if type_str == "string":
        return _encode_string(value)
    if type_str.startswith("uint"):
        bits = int(type_str[4:]) if type_str != "uint" else 256
        return _encode_uint(int(value), bits)
    if type_str.startswith("int"):
        bits = int(type_str[3:]) if type_str != "int" else 256
        return _encode_int(int(value), bits)
    if type_str.startswith("bytes"):
        size = int(type_str[5:])
        return _encode_bytes_fixed(value, size)

    raise ValueError(f"unsupported ABI type: {type_str!r}")


def _encode_tuple(types: list[str], values: list[Any]) -> bytes:
    """
    Encode a tuple of (types, values) with head/tail layout per the ABI spec.

    Dynamic elements emit a 32-byte offset in the head; the actual data lives
    in the tail. Static elements live directly in the head.
    """
    if len(types) != len(values):
        raise ValueError(f"type/value length mismatch: {len(types)} vs {len(values)}")

    encoded = [_encode_single(t, v) for t, v in zip(types, values)]
    dynamic = [_is_dynamic(t) for t in types]

    # Head section size = sum of (32 for dynamic offsets, encoded len for static)
    head_size = sum(32 if d else len(e) for d, e in zip(dynamic, encoded))

    head_parts: list[bytes] = []
    tail_parts: list[bytes] = []
    tail_offset = head_size
    for d, e in zip(dynamic, encoded):
        if d:
            head_parts.append(_encode_uint(tail_offset, 256))
            tail_parts.append(e)
            tail_offset += len(e)
        else:
            head_parts.append(e)
    return b"".join(head_parts) + b"".join(tail_parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encode_call(signature: str, params: Iterable[Any]) -> bytes:
    """
    Encode a Solidity call: 4-byte selector || ABI-encoded args.

    Args:
        signature: ``"transfer(address,uint256)"``-style canonical signature
                   (parameter names are allowed and stripped).
        params:    Iterable of values matching the signature's argument types.

    Returns:
        Raw calldata bytes. Prefix with "0x" + ``.hex()`` for JSON-RPC use.
    """
    canonical = _canonicalize_signature(signature)
    m = _SIG_RE.match(canonical)
    assert m, f"canonicalisation produced invalid signature {canonical!r}"
    types_str = m.group(2)
    types = _split_top_level_commas(types_str) if types_str else []
    selector = keccak256(canonical.encode("ascii"))[:4]
    if not types:
        return selector
    return selector + _encode_tuple(types, list(params))


class ABIEncoder:
    """
    Convenience wrapper that populates ``TxCall.calldata_hex`` from
    ``function_signature`` and ``params`` in-place.

    Intended use::

        encoder = ABIEncoder()
        encoder.encode_sequence(transaction_sequence)
    """

    def encode_call(self, signature: str, params: list[Any]) -> str:
        """Return 0x-prefixed calldata hex string."""
        data = encode_call(signature, params)
        return "0x" + data.hex()

    def encode_sequence(self, sequence) -> int:
        """
        Walk a TransactionSequence and populate ``calldata_hex`` +
        ``function_selector`` on each TxCall that has a signature + params.

        Returns the number of calls successfully encoded. Encoding failures
        are logged but do not raise — builders sometimes emit template-only
        steps (with placeholders) and those simply remain unencoded.
        """
        encoded = 0
        for call in sequence.calls:
            if not call.function_signature:
                continue
            if not call.params and "(" in call.function_signature:
                # Has args in signature but no concrete params yet — skip
                m = _SIG_RE.match(call.function_signature)
                if m and m.group(2).strip():
                    continue
            try:
                call.function_selector = "0x" + function_selector(call.function_signature).hex()
                call.calldata_hex = self.encode_call(call.function_signature, call.params)
                encoded += 1
            except Exception as exc:
                logger.debug(
                    "ABIEncoder skipped step %d (%s): %s",
                    call.step, call.function_signature, exc,
                )
        return encoded
