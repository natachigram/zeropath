"""Per-platform submission formatters."""

from zeropath.contest.models import ContestPlatform
from zeropath.contest.platforms.base import BasePlatformFormatter
from zeropath.contest.platforms.cantina import CantinaFormatter
from zeropath.contest.platforms.code4rena import Code4renaFormatter
from zeropath.contest.platforms.immunefi import ImmunefiFormatter
from zeropath.contest.platforms.sherlock import SherlockFormatter


_FORMATTERS: dict[ContestPlatform, type[BasePlatformFormatter]] = {
    ContestPlatform.CANTINA: CantinaFormatter,
    ContestPlatform.CODE4RENA: Code4renaFormatter,
    ContestPlatform.SHERLOCK: SherlockFormatter,
    ContestPlatform.IMMUNEFI: ImmunefiFormatter,
}


def for_platform(platform: ContestPlatform) -> BasePlatformFormatter:
    """Pick the right formatter for the configured platform."""
    cls = _FORMATTERS.get(platform)
    if cls is None:
        # GENERIC falls back to Cantina shape — it's the most structured.
        return CantinaFormatter()
    return cls()


__all__ = [
    "BasePlatformFormatter",
    "CantinaFormatter", "Code4renaFormatter",
    "SherlockFormatter", "ImmunefiFormatter",
    "for_platform",
]
