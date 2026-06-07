from zeropath.adapters.evm.detector import detect_evm_project


def test_evm_detector_detects_foundry_project(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}")

    detection = detect_evm_project(tmp_path)

    assert detection.adapter == "evm"
    assert detection.confidence == "high"
    assert detection.build_system == "foundry"


def test_evm_detector_detects_solidity_files_without_build_marker(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "Token.sol").write_text("pragma solidity ^0.8.20; contract Token {}")

    detection = detect_evm_project(tmp_path)

    assert detection.adapter == "evm"
    assert detection.confidence == "medium"
