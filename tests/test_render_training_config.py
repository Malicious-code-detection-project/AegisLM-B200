import yaml

from scripts.render_training_config import render_config


def test_render_training_config_sets_resume_and_run_suffix(tmp_path):
    source = tmp_path / "source.yaml"
    destination = tmp_path / "runtime.yaml"
    source.write_text("run_name: training\nnum_train_epochs: 1.0\n", encoding="utf-8")

    render_config(
        source,
        destination,
        resume_from_checkpoint="checkpoint-500",
        run_name_suffix="stable",
    )

    data = yaml.safe_load(destination.read_text(encoding="utf-8"))
    assert data["resume_from_checkpoint"] == "checkpoint-500"
    assert data["run_name"] == "training-stable"
    assert data["num_train_epochs"] == 1.0
