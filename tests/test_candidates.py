from zeropath.core.candidates import generate_candidates
from zeropath.core.schemas import ProjectConfig
from zeropath.core.storage import Storage


def test_candidate_generation_and_lifecycle_update(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "vault",
            "signals": ["asset_accounting"],
            "contracts": [{"name": "Vault", "file": "src/Vault.sol"}],
            "functions": [
                {"name": "deposit", "contract": "Vault", "file": "src/Vault.sol", "line_start": 10},
                {"name": "withdraw", "contract": "Vault", "file": "src/Vault.sol", "line_start": 20},
                {"name": "totalAssets", "contract": "Vault", "file": "src/Vault.sol", "line_start": 30},
            ],
            "raw_signal_text": ["balanceOf totalAssets deposit withdraw"],
        },
    )

    candidates = generate_candidates(storage, mode="critical", limit=5)

    assert len(candidates) == 1
    assert candidates[0].status == "hypothesis"
    updated = storage.update_candidate_status(candidates[0].id, "rejected", "no reachable state")
    assert updated.status == "rejected"
