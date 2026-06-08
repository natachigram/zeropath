from pathlib import Path

from zeropath.adapters.evm import forge
from zeropath.core.schemas import CandidateFinding, Impact, ProjectConfig
from zeropath.core.storage import Storage


def test_run_forge_test_scopes_absolute_match_path_relative_to_root(tmp_path, monkeypatch):
    captured = {}

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs["cwd"]
        return Completed()

    monkeypatch.setattr(forge.shutil, "which", lambda name: "/usr/bin/forge")
    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    test_path = tmp_path / "test" / "zeropath" / "ZP_001.t.sol"
    result = forge.run_forge_test(tmp_path, test_path)

    assert result["ok"] is True
    assert result["match_path"] == str(Path("test") / "zeropath" / "ZP_001.t.sol")
    assert captured["cmd"] == ["forge", "test", "--match-path", result["match_path"]]
    assert captured["cwd"] == str(tmp_path)


def test_save_forge_trace_writes_trace_artifact(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    candidate = CandidateFinding(
        id="ZP-020",
        project_id="demo",
        title="Trace target",
        impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
    )

    path = forge.save_forge_trace(
        storage,
        candidate,
        {
            "ok": False,
            "status": "failed",
            "returncode": 1,
            "command": ["forge", "test"],
            "stdout": "failing proof",
            "stderr": "revert",
        },
    )

    assert path.exists()
    text = path.read_text()
    assert '"candidate_id": "ZP-020"' in text
    assert '"status": "failed"' in text
    assert "failing proof" in text
