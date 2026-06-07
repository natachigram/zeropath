"""Lightweight Solidity index models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SolidityFunction(BaseModel):
    name: str
    contract: str
    file: str
    visibility: str = "unknown"
    modifiers: list[str] = Field(default_factory=list)
    line_start: int | None = None
    line_end: int | None = None
    raw_signature: str = ""


class SolidityContract(BaseModel):
    name: str
    kind: str = "contract"
    file: str
    line_start: int | None = None
    functions: list[str] = Field(default_factory=list)
    modifiers: list[str] = Field(default_factory=list)


class SolidityFileIndex(BaseModel):
    path: str
    pragma: str | None = None
    imports: list[str] = Field(default_factory=list)
    contracts: list[SolidityContract] = Field(default_factory=list)
    functions: list[SolidityFunction] = Field(default_factory=list)
    state_variables: list[dict] = Field(default_factory=list)
    asset_flows: list[dict] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
