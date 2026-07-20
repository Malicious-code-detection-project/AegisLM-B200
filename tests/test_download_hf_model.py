import json

from scripts.download_hf_model import _matches_patterns, _write_model_manifest


def test_matches_patterns_defaults():
    assert _matches_patterns("config.json", None, default=True) is True
    assert _matches_patterns("config.json", None, default=False) is False


def test_matches_patterns_with_globs():
    assert _matches_patterns("config.json", ["*.json"], default=False) is True
    assert _matches_patterns("model.safetensors", ["*.json"], default=False) is False


def test_write_model_manifest_records_revision_and_shards(tmp_path):
    (tmp_path / "model-00001-of-00001.safetensors").write_bytes(b"weights")
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"a": "model-00001-of-00001.safetensors"}}),
        encoding="utf-8",
    )

    _write_model_manifest(tmp_path, model_id="org/model", revision="abc123")

    manifest = json.loads(
        (tmp_path / "aegislm_model_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["model_id"] == "org/model"
    assert manifest["revision"] == "abc123"
    assert manifest["safetensors_shards"] == 1
    assert manifest["missing_shards"] == []
