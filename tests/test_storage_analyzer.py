"""
Tests for zeropath.storage_analyzer

Verifies the EVM storage layout algorithm against known correct slot
assignments from the Solidity specification.

Reference: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
"""

from unittest.mock import MagicMock

import pytest

from zeropath.storage_analyzer import StorageAnalyzer, _bytes_for_type, _is_packable


# ---------------------------------------------------------------------------
# _bytes_for_type unit tests
# ---------------------------------------------------------------------------


class TestBytesForType:
    """Pure type-size table tests — no mocks needed."""

    @pytest.mark.parametrize(
        "type_str, expected",
        [
            ("uint8", 1),
            ("uint16", 2),
            ("uint32", 4),
            ("uint64", 8),
            ("uint128", 16),
            ("uint256", 32),
            ("int8", 1),
            ("int256", 32),
            ("uint", 32),   # bare uint defaults to 256-bit
            ("int", 32),
            ("address", 20),
            ("address payable", 20),
            ("bool", 1),
            ("bytes1", 1),
            ("bytes16", 16),
            ("bytes32", 32),
            ("bytes", 32),    # dynamic — 1 slot reference
            ("string", 32),   # dynamic — 1 slot reference
        ],
    )
    def test_known_sizes(self, type_str: str, expected: int):
        assert _bytes_for_type(type_str) == expected

    def test_mapping_is_full_slot(self):
        assert _bytes_for_type("mapping(address => uint256)") == 32

    def test_dynamic_array_is_full_slot(self):
        assert _bytes_for_type("uint256[]") == 32

    def test_static_array_uint8_x4(self):
        # uint8[4] = 4 bytes, but rounds up to 32 (one full slot)
        result = _bytes_for_type("uint8[4]")
        assert result == 32

    def test_static_array_uint256_x4(self):
        # uint256[4] = 128 bytes = 4 slots = 128
        result = _bytes_for_type("uint256[4]")
        assert result == 128


class TestIsPackable:
    @pytest.mark.parametrize(
        "type_str, expected",
        [
            ("uint8", True),
            ("bool", True),
            ("address", True),      # 20 bytes < 32
            ("bytes16", True),
            ("uint256", False),     # exactly 32 bytes — NOT packable with others
            ("mapping(address => uint256)", False),
            ("uint256[]", False),
            ("bytes", False),
            ("string", False),
            ("uint128[2]", False),  # static array — not packable
        ],
    )
    def test_packability(self, type_str: str, expected: bool):
        assert _is_packable(type_str) == expected


# ---------------------------------------------------------------------------
# StorageAnalyzer.compute_layout tests
# ---------------------------------------------------------------------------


def _make_var(name: str, type_str: str, is_constant: bool = False) -> MagicMock:
    """Create a minimal Slither StateVariable mock."""
    var = MagicMock()
    var.name = name
    var.type = type_str
    var.is_constant = is_constant
    var.is_immutable = False
    # Make str(var.type) return the type string
    type_mock = MagicMock()
    type_mock.__str__ = lambda self: type_str
    var.type = type_mock
    return var


def _make_contract(vars_: list) -> MagicMock:
    contract = MagicMock()
    contract.name = "TestContract"
    contract.state_variables = vars_
    return contract


class TestComputeLayout:
    def _analyzer(self) -> StorageAnalyzer:
        return StorageAnalyzer()

    def test_single_uint256(self):
        """uint256 alone → slot 0, byte_offset 0."""
        analyzer = self._analyzer()
        contract = _make_contract([_make_var("total", "uint256")])
        layouts = analyzer.compute_layout(contract)
        assert len(layouts) == 1
        assert layouts[0].slot == 0
        assert layouts[0].byte_offset == 0
        assert layouts[0].size_bytes == 32
        assert layouts[0].is_packed is False

    def test_two_uint128_packed(self):
        """Two uint128 should pack into slot 0 (16+16=32 bytes)."""
        analyzer = self._analyzer()
        contract = _make_contract([
            _make_var("a", "uint128"),
            _make_var("b", "uint128"),
        ])
        layouts = analyzer.compute_layout(contract)
        assert layouts[0].slot == 0
        assert layouts[1].slot == 0
        assert layouts[1].is_packed is True

    def test_uint128_bool_packing(self):
        """uint128 (16 bytes) + bool (1 byte) pack together in slot 0."""
        analyzer = self._analyzer()
        contract = _make_contract([
            _make_var("amount", "uint128"),
            _make_var("active", "bool"),
        ])
        layouts = analyzer.compute_layout(contract)
        assert layouts[0].slot == 0
        assert layouts[1].slot == 0
        assert layouts[1].byte_offset == 16

    def test_overflow_to_next_slot(self):
        """uint128 + uint128 + uint8 — the uint8 should go to slot 1."""
        analyzer = self._analyzer()
        contract = _make_contract([
            _make_var("a", "uint128"),
            _make_var("b", "uint128"),
            _make_var("c", "uint8"),
        ])
        layouts = analyzer.compute_layout(contract)
        # a and b fill slot 0 (16+16=32)
        assert layouts[0].slot == 0
        assert layouts[1].slot == 0
        # c must start a new slot
        assert layouts[2].slot == 1

    def test_mapping_takes_own_slot(self):
        """Mapping cannot be packed; it always gets its own slot."""
        analyzer = self._analyzer()
        contract = _make_contract([
            _make_var("owner", "address"),
            _make_var("balances", "mapping(address => uint256)"),
        ])
        layouts = analyzer.compute_layout(contract)
        # address (20 bytes) is in slot 0
        assert layouts[0].slot == 0
        # mapping must start on a new slot — but address only used 20 bytes
        # So mapping starts at slot 1 (because mapping is non-packable)
        assert layouts[1].slot == 1
        assert layouts[1].is_packed is False

    def test_constants_skipped(self):
        """Constants / immutables do not occupy storage slots."""
        analyzer = self._analyzer()
        constant_var = _make_var("MAX", "uint256", is_constant=True)
        normal_var = _make_var("balance", "uint256")
        contract = _make_contract([constant_var, normal_var])
        layouts = analyzer.compute_layout(contract)
        assert len(layouts) == 1
        assert layouts[0].name == "balance"
        assert layouts[0].slot == 0

    def test_realistic_erc20_layout(self):
        """
        Simulate a realistic ERC-20 storage layout.
        string + uint256 + address + mapping + mapping
        """
        analyzer = self._analyzer()
        contract = _make_contract([
            _make_var("name", "string"),            # slot 0 (reference, 32 bytes)
            _make_var("totalSupply", "uint256"),    # slot 1
            _make_var("owner", "address"),          # slot 2 (20 bytes)
            _make_var("balances", "mapping(address => uint256)"),    # slot 3
            _make_var("allowances", "mapping(address => mapping(address => uint256))"),  # slot 4
        ])
        layouts = analyzer.compute_layout(contract)
        assert layouts[0].slot == 0   # string
        assert layouts[1].slot == 1   # totalSupply
        assert layouts[2].slot == 2   # owner
        assert layouts[3].slot == 3   # balances
        assert layouts[4].slot == 4   # allowances


# ---------------------------------------------------------------------------
# StorageAnalyzer.analyze_packing tests
# ---------------------------------------------------------------------------


class TestAnalyzePacking:
    def _analyzer(self) -> StorageAnalyzer:
        return StorageAnalyzer()

    def test_empty_contract(self):
        contract = _make_contract([])
        result = self._analyzer().analyze_packing(contract)
        assert result["total_slots"] == 0
        assert result["wasted_bytes"] == 0
        assert result["packing_efficiency_pct"] == 100.0

    def test_no_packing(self):
        """All uint256 — perfectly efficient, no wasted bytes."""
        contract = _make_contract([
            _make_var("a", "uint256"),
            _make_var("b", "uint256"),
        ])
        result = self._analyzer().analyze_packing(contract)
        assert result["total_slots"] == 2
        assert result["wasted_bytes"] == 0
        assert result["packing_efficiency_pct"] == 100.0

    def test_with_packing(self):
        """address (20 bytes) + bool (1 byte) should pack — 11 bytes wasted."""
        contract = _make_contract([
            _make_var("owner", "address"),
            _make_var("active", "bool"),
        ])
        result = self._analyzer().analyze_packing(contract)
        packed = result["packed_variables"]
        assert "active" in packed
        # Total used = 20 + 1 = 21 bytes in 1 slot (32 bytes), wasted = 11
        assert result["wasted_bytes"] == 11
