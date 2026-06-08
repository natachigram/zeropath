import re
import subprocess
from pathlib import Path

GENERATED_TRACKED_RE = re.compile(
    r"(^\.venv|htmlcov|__pycache__|\.coverage|\.pytest_cache|\.ruff_cache|\.egg-info)"
)


def test_generated_cache_files_are_not_tracked():
    repo = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )

    tracked = [path for path in result.stdout.splitlines() if GENERATED_TRACKED_RE.search(path)]
    assert tracked == []
