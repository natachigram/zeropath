"""
Tests for zeropath.models

Verifies that all Pydantic models construct correctly, serialize to the
right JSON shape (aliases intact), and enforce type constraints.
"""

import pytest

from zeropath.models import (
    AccessControl,
    AssetFlow,
    CallType,
    Contract,
    ContractLanguage,
    Event,
    ExternalDependency,
    Function,
    FunctionCall,
    FunctionSignature,
    Parameter,
    ProtocolGraph,
    ProxyRelationship,
    ProxyType,
    StateVariable,
    StateVariableType,
    StorageSlotInfo,
    Visibility,
    VersionDiff,
)


# ---------------------------------------------------------------------------
# Parameter
# ---------------------------------------------------------------------------


class TestParameter:
    def test_basic_construction_via_alias(self):
        p = Parameter(**{"name": "amount", "type": "uint256"})
        assert p.name == "amount"
        assert p.type_ == "uint256"

    def test_alias_serialization(self):
        p = Parameter(**{"name": "to", "type": "address"})
        d = p.model_dump(by_alias=True)
        assert d["type"] == "address"
        assert "type_" not in d

    def test_indexed_default_false(self):
        p = Parameter(**{"name": "x", "type": "bool"})
        assert p.indexed is False


# ---------------------------------------------------------------------------
# StateVariable
# ---------------------------------------------------------------------------


class TestStateVariable:
    def test_full_construction(self):
        sv = StateVariable(
            **{
                "type": "uint256",
                "name": "totalSupply",
                "visibility": Visibility.PUBLIC,
                "type_category": StateVariableType.PRIMITIVE,
            }
        )
        assert sv.name == "totalSupply"
        assert sv.type_ == "uint256"
        assert sv.visibility == Visibility.PUBLIC
        assert sv.is_constant is False
        assert sv.line_start == 0

    def test_with_storage_slot(self):
        storage = StorageSlotInfo(slot=2, byte_offset=0, size_bytes=32, is_packed=False)
        sv = StateVariable(
            **{
                "type": "address",
                "name": "owner",
                "visibility": Visibility.PUBLIC,
                "type_category": StateVariableType.ADDRESS,
                "storage": storage,
            }
        )
        assert sv.storage is not None
        assert sv.storage.slot == 2

    def test_python_attribute_access(self):
        """type_ (Python name) must be accessible; var.type should NOT be used."""
        sv = StateVariable(
            **{"type": "mapping(address => uint256)", "name": "balances",
               "visibility": Visibility.INTERNAL, "type_category": StateVariableType.MAPPING}
        )
        assert sv.type_ == "mapping(address => uint256)"

    def test_id_auto_generated(self):
        sv1 = StateVariable(
            **{"type": "bool", "name": "paused",
               "visibility": Visibility.PRIVATE, "type_category": StateVariableType.PRIMITIVE}
        )
        sv2 = StateVariable(
            **{"type": "bool", "name": "paused",
               "visibility": Visibility.PRIVATE, "type_category": StateVariableType.PRIMITIVE}
        )
        assert sv1.id != sv2.id


# ---------------------------------------------------------------------------
# Function
# ---------------------------------------------------------------------------


class TestFunction:
    def _make_function(self, **kwargs) -> Function:
        defaults = dict(
            name="transfer",
            contract_id="contract-uuid-001",
            visibility=Visibility.EXTERNAL,
            signature=FunctionSignature(name="transfer"),
            line_start=10,
            line_end=20,
        )
        defaults.update(kwargs)
        return Function(**defaults)

    def test_basic_function(self):
        f = self._make_function()
        assert f.name == "transfer"
        assert f.visibility == Visibility.EXTERNAL
        assert f.is_payable is False
        assert f.is_pure is False
        assert f.is_view is False

    def test_payable_function(self):
        f = self._make_function(name="deposit", is_payable=True)
        assert f.is_payable is True

    def test_view_function(self):
        f = self._make_function(name="balanceOf", is_view=True, visibility=Visibility.PUBLIC)
        assert f.is_view is True

    def test_constructor_flags(self):
        f = self._make_function(name="constructor", is_constructor=True)
        assert f.is_constructor is True

    def test_access_control(self):
        ac = AccessControl(modifiers=["onlyOwner"], onlyOwner=True)
        f = self._make_function(access_control=ac)
        assert f.access_control.only_owner is True
        assert "onlyOwner" in f.access_control.modifiers

    def test_state_var_tracking(self):
        f = self._make_function(
            state_vars_read=["totalSupply", "balances"],
            state_vars_written=["balances"],
        )
        assert "totalSupply" in f.state_vars_read
        assert "balances" in f.state_vars_written

    def test_selector_field(self):
        sig = FunctionSignature(name="transfer", selector="0xa9059cbb")
        f = self._make_function(signature=sig)
        assert f.signature.selector == "0xa9059cbb"


# ---------------------------------------------------------------------------
# FunctionCall
# ---------------------------------------------------------------------------


class TestFunctionCall:
    def test_internal_call(self):
        fc = FunctionCall(
            caller_id="fn-a",
            callee_id="fn-b",
            callee_name="_transfer",
            call_type=CallType.INTERNAL,
            line_number=42,
        )
        assert fc.call_type == CallType.INTERNAL
        assert fc.is_delegatecall is False

    def test_external_call(self):
        fc = FunctionCall(
            caller_id="fn-a",
            callee_name="transfer",
            call_type=CallType.EXTERNAL,
            line_number=55,
        )
        assert fc.callee_id is None

    def test_delegatecall(self):
        fc = FunctionCall(
            caller_id="fn-a",
            callee_name="",
            call_type=CallType.DELEGATECALL,
            is_delegatecall=True,
            line_number=0,
        )
        assert fc.is_delegatecall is True
        assert fc.call_type == CallType.DELEGATECALL


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_basic_contract(self):
        c = Contract(name="MyToken", file_path="/tmp/MyToken.sol")
        assert c.name == "MyToken"
        assert c.language == ContractLanguage.SOLIDITY
        assert c.is_library is False
        assert c.proxy_type == ProxyType.NONE

    def test_library_contract(self):
        c = Contract(name="SafeMath", file_path="/tmp/SafeMath.sol", is_library=True)
        assert c.is_library is True

    def test_inheritance(self):
        c = Contract(
            name="ERC20",
            file_path="/tmp/ERC20.sol",
            parent_contracts=["IERC20", "Context"],
            full_inheritance=["IERC20", "Context"],
        )
        assert "IERC20" in c.parent_contracts
        assert len(c.full_inheritance) == 2

    def test_proxy_type(self):
        c = Contract(
            name="MyProxy",
            file_path="/tmp/Proxy.sol",
            proxy_type=ProxyType.UUPS,
        )
        assert c.proxy_type == ProxyType.UUPS


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------


class TestEvent:
    def test_event_with_indexed_params(self):
        params = [
            Parameter(**{"name": "from", "type": "address", "indexed": True}),
            Parameter(**{"name": "to", "type": "address", "indexed": True}),
            Parameter(**{"name": "amount", "type": "uint256", "indexed": False}),
        ]
        ev = Event(name="Transfer", contract_id="contract-1", parameters=params)
        assert ev.name == "Transfer"
        assert ev.parameters[0].indexed is True
        assert ev.parameters[2].indexed is False


# ---------------------------------------------------------------------------
# AssetFlow
# ---------------------------------------------------------------------------


class TestAssetFlow:
    def test_eth_flow(self):
        af = AssetFlow(
            from_function_id="fn-deposit",
            to_function_id="fn-internal",
            asset_type="ETH",
            line_number=100,
        )
        assert af.asset_type == "ETH"
        assert af.is_conditional is False

    def test_erc20_flow(self):
        af = AssetFlow(
            from_function_id="fn-caller",
            to_function_id=None,
            asset_type="ERC20",
            line_number=50,
        )
        assert af.to_function_id is None


# ---------------------------------------------------------------------------
# ExternalDependency
# ---------------------------------------------------------------------------


class TestExternalDependency:
    def test_known_interface(self):
        dep = ExternalDependency(name="IERC20", interface="ERC20")
        assert dep.interface == "ERC20"
        assert dep.references == []


# ---------------------------------------------------------------------------
# ProxyRelationship
# ---------------------------------------------------------------------------


class TestProxyRelationship:
    def test_uups_proxy(self):
        pr = ProxyRelationship(
            proxy_contract_id="proxy-id",
            implementation_contract_id="impl-id",
            proxy_type=ProxyType.UUPS,
            is_upgradeable=True,
            upgrade_function="upgradeTo",
        )
        assert pr.proxy_type == ProxyType.UUPS
        assert pr.is_upgradeable is True

    def test_no_implementation(self):
        pr = ProxyRelationship(
            proxy_contract_id="proxy-id",
            proxy_type=ProxyType.CUSTOM,
            is_upgradeable=False,
        )
        assert pr.implementation_contract_id is None


# ---------------------------------------------------------------------------
# VersionDiff
# ---------------------------------------------------------------------------


class TestVersionDiff:
    def test_empty_diff(self):
        vd = VersionDiff()
        assert vd.added_contracts == []
        assert vd.attack_surface_delta == "unknown"

    def test_with_changes(self):
        vd = VersionDiff(
            added_functions=["LendingVault.setFee"],
            new_external_deps=["IFeeOracle"],
            attack_surface_delta="medium",
        )
        assert len(vd.added_functions) == 1
        assert vd.attack_surface_delta == "medium"


# ---------------------------------------------------------------------------
# ProtocolGraph
# ---------------------------------------------------------------------------


class TestProtocolGraph:
    def test_empty_graph(self):
        g = ProtocolGraph()
        assert g.contracts == []
        assert g.functions == []
        assert g.state_variables == []
        assert g.events == []
        assert g.asset_flows == []
        assert g.external_dependencies == []
        assert g.proxy_relationships == []
        assert g.source_available is True

    def test_json_serialization(self):
        c = Contract(name="Token", file_path="Token.sol")
        g = ProtocolGraph(contracts=[c])
        data = g.model_dump(by_alias=True)
        assert isinstance(data["contracts"], list)
        assert data["contracts"][0]["name"] == "Token"
        # language should serialize as string value, not enum object
        assert data["contracts"][0]["language"] == "solidity"
