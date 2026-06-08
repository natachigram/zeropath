from pathlib import Path

from zeropath.adapters.evm import forge


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
