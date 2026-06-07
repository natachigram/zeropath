"""EVM asset-flow heuristics."""

from __future__ import annotations

ASSET_FLOW_KEYWORDS = (
    "transfer(",
    "transferFrom(",
    "safeTransfer(",
    "safeTransferFrom(",
    "mint(",
    "burn(",
    "deposit(",
    "withdraw(",
    "redeem(",
    "borrow(",
    "repay(",
    "liquidate(",
    "swap(",
    "bridge(",
    "sendMessage(",
)


def detect_asset_flows(lines: list[str], *, file: str, contract: str | None = None) -> list[dict]:
    flows: list[dict] = []
    for idx, line in enumerate(lines, start=1):
        compact = line.replace(" ", "")
        for keyword in ASSET_FLOW_KEYWORDS:
            if keyword in compact:
                flows.append(
                    {
                        "keyword": keyword.rstrip("("),
                        "file": file,
                        "contract": contract,
                        "line": idx,
                        "snippet": line.strip()[:220],
                    }
                )
                break
    return flows
