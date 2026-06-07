from zeropath.core.project import init_project


def test_init_creates_zeropath(tmp_path):
    storage, config, detection = init_project(tmp_path)

    assert storage.zp_dir.exists()
    assert (storage.zp_dir / "zeropath.toml").exists()
    assert (storage.zp_dir / "project.sqlite").exists()
    assert config.project_id == tmp_path.name.lower().replace("_", "-")
    assert detection.confidence in {"low", "medium", "high"}
