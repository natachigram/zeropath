"""Core engine exceptions."""

from __future__ import annotations


class ZeroPathCoreError(Exception):
    """Base exception for the evidence-first core."""


class ProjectNotInitializedError(ZeroPathCoreError):
    """Raised when a command requires .zeropath state."""


class ReportNotReadyError(ZeroPathCoreError):
    """Raised when report export is blocked by missing judge evidence."""
