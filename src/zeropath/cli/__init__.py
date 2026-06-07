"""ZeroPath CLI package.

The public import contract stays `from zeropath.cli import cli, main`, while
the implementation lives in `zeropath.cli.main` so commands can be split into
modules incrementally.
"""

from zeropath.cli.main import cli, main

__all__ = ["cli", "main"]
