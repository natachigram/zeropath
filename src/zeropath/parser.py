"""
Slither-based contract parser for extracting contract information.
"""

from pathlib import Path
from typing import Optional

from slither import Slither
from slither.core.solidity_types import ElementaryType
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable

from zeropath.exceptions import ASTExtractionError, ParsingError
from zeropath.logging_config import get_logger
from zeropath.models import (
    AccessControl,
    Contract,
    Function,
    FunctionCall,
    FunctionSignature,
    Parameter,
    StateVariableType,
    Visibility,
    CallType,
)

logger = get_logger(__name__)


class ContractParser:
    """
    Parses Solidity contracts using Slither.
    
    Extracts:
    - Contract metadata
    - Functions and their signatures
    - State variables
    - Function call relationships
    - Access control patterns
    """

    def __init__(self, solc_version: Optional[str] = None):
        """
        Initialize the parser.
        
        Args:
            solc_version: Optional specific Solidity compiler version to use
        """
        self.solc_version = solc_version

    def parse_contract(self, contract_path: Path) -> tuple[list[Contract], list[Function], list[StateVariable], list[FunctionCall]]:
        """
        Parse a single contract file.
        
        Args:
            contract_path: Path to the .sol file
            
        Returns:
            Tuple of (contracts, functions, state_variables, function_calls)
            
        Raises:
            ParsingError: If contract parsing fails
        """
        if not contract_path.exists():
            raise ParsingError(f"Contract file not found: {contract_path}")
        
        try:
            logger.info("parsing_contract", path=str(contract_path))
            
            slither = Slither(str(contract_path))
            
            contracts: list[Contract] = []
            functions: list[Function] = []
            state_variables: list[StateVariable] = []
            function_calls: list[FunctionCall] = []
            
            # Parse each contract in the file
            for contract in slither.contracts:
                contract_obj = self._parse_contract_metadata(contract, contract_path)
                contracts.append(contract_obj)
                
                # Parse state variables
                contract_state_vars = self._parse_state_variables(contract, contract_obj.id)
                state_variables.extend(contract_state_vars)
                
                # Parse functions
                contract_funcs = self._parse_functions(contract, contract_obj.id)
                functions.extend(contract_funcs)
                
                # Extract function calls
                contract_calls = self._extract_function_calls(contract, functions, contract_obj.id)
                function_calls.extend(contract_calls)
            
            logger.info(
                "contract_parsed",
                file=str(contract_path),
                contracts=len(contracts),
                functions=len(functions),
                state_vars=len(state_variables),
            )
            
            return contracts, functions, state_variables, function_calls
            
        except Exception as e:
            logger.error("parsing_failed", path=str(contract_path), error=str(e))
            raise ParsingError(f"Failed to parse {contract_path}: {str(e)}") from e

    def _parse_contract_metadata(self, contract, contract_path: Path) -> Contract:
        """Extract contract metadata."""
        return Contract(
            name=contract.name,
            file_path=str(contract_path),
            is_library=contract.is_library,
            is_abstract=contract.is_abstract,
            parent_contracts=[p.name for p in contract.inheritance],
        )

    def _parse_state_variables(
        self,
        contract,
        contract_id: str,
    ) -> list[StateVariable]:
        """Extract state variables from a contract."""
        variables: list[StateVariable] = []
        
        for var in contract.state_variables:
            var_type = self._categorize_variable_type(var)
            
            visibility = Visibility.INTERNAL  # Default for state vars
            if hasattr(var, "visibility"):
                vis_str = str(var.visibility)
                if "public" in vis_str:
                    visibility = Visibility.PUBLIC
                elif "private" in vis_str:
                    visibility = Visibility.PRIVATE
            
            state_var = StateVariable(
                name=var.name,
                type=str(var.type),
                visibility=visibility,
                is_constant=var.is_constant or var.is_immutable,
                type_category=var_type,
                line_start=var.source_mapping.get("start_line") if var.source_mapping else 0,
            )
            variables.append(state_var)
        
        return variables

    def _categorize_variable_type(self, var: StateVariable) -> StateVariableType:
        """Categorize a variable's type."""
        type_str = str(var.type)
        
        if "mapping" in type_str:
            return StateVariableType.MAPPING
        elif "[]" in type_str:
            return StateVariableType.ARRAY
        elif "address" in type_str:
            return StateVariableType.ADDRESS
        elif "bytes" in type_str:
            return StateVariableType.BYTES
        elif "string" in type_str:
            return StateVariableType.STRING
        elif "enum" in type_str or hasattr(var.type, "is_enum") and var.type.is_enum:
            return StateVariableType.ENUM
        elif hasattr(var.type, "is_struct") and var.type.is_struct:
            return StateVariableType.STRUCT
        else:
            return StateVariableType.PRIMITIVE

    def _parse_functions(
        self,
        contract,
        contract_id: str,
    ) -> list[Function]:
        """Extract functions from a contract."""
        functions: list[Function] = []
        
        for func in contract.functions:
            # Determine visibility
            visibility = Visibility.INTERNAL
            if func.visibility == "public":
                visibility = Visibility.PUBLIC
            elif func.visibility == "external":
                visibility = Visibility.EXTERNAL
            elif func.visibility == "private":
                visibility = Visibility.PRIVATE
            
            # Parse parameters
            parameters = []
            for param in func.parameters:
                parameters.append(Parameter(
                    name=param.name or f"param_{len(parameters)}",
                    type=str(param.type),
                ))
            
            # Parse return values
            returns = []
            for ret in func.return_values:
                returns.append(Parameter(
                    name=ret.name or f"return_{len(returns)}",
                    type=str(ret.type),
                ))
            
            signature = FunctionSignature(
                name=func.name,
                parameters=parameters,
                returns=returns,
                selector=func.selector if hasattr(func, "selector") else None,
            )
            
            # Extract access control
            modifiers = [m.name for m in func.modifiers]
            access_control = AccessControl(
                modifiers=modifiers,
                onlyOwner="onlyOwner" in modifiers,
            )
            
            # Track state variable accesses
            state_vars_read = [v.name for v in func.state_variables_read]
            state_vars_written = [v.name for v in func.state_variables_written]
            
            function = Function(
                name=func.name,
                contract_id=contract_id,
                visibility=visibility,
                signature=signature,
                is_pure=func.pure,
                is_view=func.view,
                is_payable=func.payable,
                is_constructor=func.is_constructor,
                is_fallback=func.is_fallback,
                is_receive=func.is_receive,
                state_vars_read=state_vars_read,
                state_vars_written=state_vars_written,
                access_control=access_control,
                line_start=func.source_mapping.get("start_line") if func.source_mapping else 0,
                line_end=func.source_mapping.get("end_line") if func.source_mapping else 0,
            )
            functions.append(function)
        
        return functions

    def _extract_function_calls(
        self,
        contract,
        all_functions: list[Function],
        contract_id: str,
    ) -> list[FunctionCall]:
        """Extract function call relationships."""
        calls: list[FunctionCall] = []
        
        # Create a map of function names to IDs for this contract
        func_name_to_id = {
            f.name: f.id for f in all_functions if f.contract_id == contract_id
        }
        
        for func in contract.functions:
            caller_func = next(
                (f for f in all_functions if f.name == func.name and f.contract_id == contract_id),
                None,
            )
            if not caller_func:
                continue
            
            # Internal function calls
            for internal_call in func.internal_calls:
                call_type = CallType.INTERNAL
                callee_id = func_name_to_id.get(internal_call.name)
                
                call = FunctionCall(
                    caller_id=caller_func.id,
                    callee_id=callee_id,
                    callee_name=internal_call.name,
                    call_type=call_type,
                    line_number=0,  # Would need to extract from source mapping
                )
                calls.append(call)
            
            # External calls
            for external_call in func.external_calls:
                call_type = CallType.EXTERNAL
                
                # Determine if it's a delegatecall
                is_delegatecall = "delegatecall" in str(external_call).lower()
                
                call = FunctionCall(
                    caller_id=caller_func.id,
                    callee_name=external_call.name if hasattr(external_call, "name") else str(external_call),
                    call_type=call_type,
                    is_delegatecall=is_delegatecall,
                    line_number=0,
                )
                calls.append(call)
        
        return calls
