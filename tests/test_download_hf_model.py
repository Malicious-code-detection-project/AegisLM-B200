import json

from scripts.download_hf_model import (
    MODEL_VARIANTS,
    _matches_patterns,
    _write_model_manifest,
)


def test_mistral_training_snapshot_variant_is_exact():
    assert MODEL_VARIANTS["mistral-small-4-119b-bf16"] == {
        "model_id": "axolotl-ai-co/Mistral-Small-4-119B-2603-BF16",
        "local_dir": "model/mistral-small-4-119b-2603-bf16",
    }


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
    assert manifest["schema_version"] == "aegislm.model-snapshot.v2"
    assert manifest["safetensors_shards"] == 1
    assert manifest["missing_shards"] == []
    assert [item["path"] for item in manifest["files"]] == [
        "model-00001-of-00001.safetensors",
        "model.safetensors.index.json",
    ]
    assert len(manifest["inventory_sha256"]) == 64
