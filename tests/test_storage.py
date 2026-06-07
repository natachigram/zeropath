from zeropath.core.schemas import ProjectConfig, ProtocolIntent
from zeropath.core.storage import Storage


def test_storage_can_save_and_load_project_config(tmp_path):
    storage = Storage(tmp_path)
    config = ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm")
    storage.initialize(config)

    loaded = storage.load_project_config()

    assert loaded.project_id == "demo"
    assert loaded.adapter == "evm"


def test_storage_can_save_protocol_intent(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    intent = ProtocolIntent(project_id="demo", protocol_name="Demo", protocol_type="vault")

    storage.save_protocol_intent(intent)

    assert storage.load_protocol_intent().protocol_type == "vault"
    assert (storage.zp_dir / "artifacts/snapshots/protocol_intent.json").exists()
