"""Train and evaluate the temporal EMBER2024 ELF LightGBM baseline."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegislm.evaluation.malware_classifier import (  # noqa: E402
    MalwareClassifierGates,
    evaluate_malware_classifier,
    select_threshold_at_fpr,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-manifest", type=Path, required=True)
    parser.add_argument("--test-manifest", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--pretrained-model",
        type=Path,
        help="Evaluate this fixed LightGBM model instead of training a new model.",
    )
    args = parser.parse_args()

    import lightgbm as lgb  # type: ignore[import-not-found]
    import numpy as np

    config = json.loads(args.config.read_text(encoding="utf-8"))
    train_manifest = _load_manifest(
        args.train_manifest,
        expected_role="classifier_train",
    )
    test_manifest = _load_manifest(
        args.test_manifest,
        expected_role="classifier_test",
    )
    trained_model_output = args.output_dir / "model.txt"
    outputs = {
        "calibration_predictions": (args.output_dir / "calibration-predictions.jsonl"),
        "test_predictions": args.output_dir / "test-predictions.jsonl",
        "report": args.output_dir / "evaluation-report.json",
    }
    if args.pretrained_model is None:
        outputs["model"] = trained_model_output
    existing = [path for path in outputs.values() if path.exists()]
    if existing:
        raise SystemExit(f"baseline output already exists: {existing[0]}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    vectorizer = EmberElfFeatureVectorizer(np)
    train_data = _load_vectors(train_manifest, vectorizer, np)
    test_data = _load_vectors(test_manifest, vectorizer, np)
    split = config["temporal_split"]
    fit_mask = (train_data["weeks"] >= int(split["fit_week_min"])) & (
        train_data["weeks"] <= int(split["fit_week_max"])
    )
    calibration_mask = (train_data["weeks"] >= int(split["calibration_week_min"])) & (
        train_data["weeks"] <= int(split["calibration_week_max"])
    )
    if bool(np.any(fit_mask & calibration_mask)):
        raise SystemExit("fit and calibration weeks overlap")
    if int(np.sum(fit_mask | calibration_mask)) != len(train_data["labels"]):
        raise SystemExit("train records fall outside fit/calibration split")
    expected_test_mask = (test_data["weeks"] >= int(split["test_week_min"])) & (
        test_data["weeks"] <= int(split["test_week_max"])
    )
    if not bool(np.all(expected_test_mask)):
        raise SystemExit("test records fall outside the fixed test weeks")

    if args.pretrained_model is None:
        params = dict(config["lightgbm"])
        categorical_features = [2, 3, 4, 5, 6, 701, 702]
        fit_set = lgb.Dataset(
            train_data["vectors"][fit_mask],
            train_data["labels"][fit_mask],
            categorical_feature=categorical_features,
        )
        calibration_set = lgb.Dataset(
            train_data["vectors"][calibration_mask],
            train_data["labels"][calibration_mask],
            reference=fit_set,
            categorical_feature=categorical_features,
        )
        model = lgb.train(
            params,
            fit_set,
            valid_sets=[calibration_set],
            valid_names=["calibration"],
        )
        model.save_model(str(trained_model_output))
        model_path = trained_model_output
        model_source = "trained_temporal_fit"
    else:
        if not args.pretrained_model.is_file():
            raise SystemExit("pretrained model does not exist")
        model = lgb.Booster(model_file=str(args.pretrained_model))
        if model.num_feature() != vectorizer.dim:
            raise SystemExit(
                "pretrained model feature dimension mismatch: "
                f"{model.num_feature()} != {vectorizer.dim}"
            )
        model_path = args.pretrained_model
        model_source = "fixed_pretrained"

    calibration_scores = model.predict(train_data["vectors"][calibration_mask]).tolist()
    test_scores = model.predict(test_data["vectors"]).tolist()
    calibration_labels = train_data["labels"][calibration_mask].tolist()
    threshold_result = select_threshold_at_fpr(
        calibration_labels,
        calibration_scores,
        fpr_max=float(config["threshold_selection"]["fpr_max"]),
    )
    threshold = float(threshold_result["threshold"])

    calibration_predictions = _prediction_records(
        train_data["observation_ids"][calibration_mask],
        calibration_scores,
    )
    test_predictions = _prediction_records(
        test_data["observation_ids"],
        test_scores,
    )
    _write_jsonl(outputs["calibration_predictions"], calibration_predictions)
    _write_jsonl(outputs["test_predictions"], test_predictions)

    test_gold = [
        {
            "observation_id": record_id,
            "label": int(label),
            "week_id": int(week),
        }
        for record_id, label, week in zip(
            test_data["observation_ids"].tolist(),
            test_data["labels"].tolist(),
            test_data["weeks"].tolist(),
        )
    ]
    gates = MalwareClassifierGates(**config["absolute_gates"])
    evaluation = evaluate_malware_classifier(
        test_gold,
        test_predictions,
        threshold=threshold,
        gates=gates,
        threshold_source="calibration",
    )
    report = {
        "schema_version": "aegislm.phase-f-ember2024-lgbm-baseline.v1",
        "profile": config["profile"],
        "seed": config["seed"],
        "model_source": model_source,
        "dataset": {
            "train_manifest_path": str(args.train_manifest.resolve()),
            "train_manifest_sha256": _sha256_file(args.train_manifest),
            "test_manifest_path": str(args.test_manifest.resolve()),
            "test_manifest_sha256": _sha256_file(args.test_manifest),
        },
        "split": {
            "fit_count": int(np.sum(fit_mask)),
            "calibration_count": int(np.sum(calibration_mask)),
            "test_count": len(test_data["labels"]),
            **split,
        },
        "feature_vector_dimension": int(vectorizer.dim),
        "feature_contract": {
            "common_feature_dimension": vectorizer.common_dim,
            "pe_only_padding_dimension": vectorizer.dim - vectorizer.common_dim,
            "official_declared_dimension": vectorizer.official_declared_dim,
            "actual_vector_dimension_delta": (
                vectorizer.dim - vectorizer.official_declared_dim
            ),
            "official_declared_string_count_dimension": 76,
            "actual_string_count_dimension": len(vectorizer.string_count_keys),
            "string_count_keys": vectorizer.string_count_keys,
            "source": "pinned thrember features.py AST plus zero-filled PE-only fields",
        },
        "threshold_selection": {
            **config["threshold_selection"],
            "selected_threshold": threshold,
            "calibration_metrics": threshold_result,
        },
        "evaluation": evaluation,
        "runtime": {
            "python": platform.python_version(),
            "lightgbm": importlib.metadata.version("lightgbm"),
            "numpy": importlib.metadata.version("numpy"),
            "scikit_learn": importlib.metadata.version("scikit-learn"),
            "thrember": importlib.metadata.version("thrember"),
        },
        "artifacts": {
            "model_path": str(model_path.resolve()),
            "model_sha256": _sha256_file(model_path),
            "calibration_predictions_path": str(
                outputs["calibration_predictions"].resolve()
            ),
            "calibration_predictions_sha256": _sha256_file(
                outputs["calibration_predictions"]
            ),
            "test_predictions_path": str(outputs["test_predictions"].resolve()),
            "test_predictions_sha256": _sha256_file(outputs["test_predictions"]),
        },
        "approved_for_qwen_sft_training": False,
        "approved_for_nurilab_signal_experiment": (
            evaluation["decision"] == "absolute_gate_pass"
        ),
    }
    outputs["report"].write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "EMBER2024 ELF LightGBM baseline: "
        f"decision={evaluation['decision']}, "
        f"precision={evaluation['aggregate']['precision']:.6f}, "
        f"recall={evaluation['aggregate']['recall']:.6f}, "
        f"fpr={evaluation['aggregate']['fpr']:.6f}"
    )


def _load_manifest(path: Path, *, expected_role: str) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("decision") != "materialization_pass":
        raise SystemExit("materialization manifest has not passed")
    contract = manifest.get("contract")
    outputs = manifest.get("outputs")
    if not isinstance(contract, dict) or not isinstance(outputs, dict):
        raise SystemExit("materialization manifest is incomplete")
    if contract.get("dataset_role") != expected_role:
        raise SystemExit("materialization dataset role mismatch")
    features_path = Path(str(outputs["features_path"]))
    gold_path = Path(str(outputs["gold_path"]))
    if _sha256_file(features_path) != outputs.get("features_sha256"):
        raise SystemExit("materialized feature hash mismatch")
    if _sha256_file(gold_path) != outputs.get("gold_sha256"):
        raise SystemExit("materialized gold hash mismatch")
    return manifest


def _load_vectors(
    manifest: dict[str, Any],
    vectorizer: Any,
    np: Any,
) -> dict[str, Any]:
    features_path = Path(manifest["outputs"]["features_path"])
    gold_path = Path(manifest["outputs"]["gold_path"])
    feature_lines = features_path.read_text(encoding="utf-8").splitlines()
    gold_lines = gold_path.read_text(encoding="utf-8").splitlines()
    if len(feature_lines) != len(gold_lines):
        raise SystemExit("feature/gold record count mismatch")
    vectors = np.empty((len(feature_lines), vectorizer.dim), dtype=np.float32)
    labels = np.empty(len(feature_lines), dtype=np.int32)
    weeks = np.empty(len(feature_lines), dtype=np.int32)
    observation_ids: list[str] = []
    for index, (feature_line, gold_line) in enumerate(zip(feature_lines, gold_lines)):
        feature_record = json.loads(feature_line)
        gold_record = json.loads(gold_line)
        if feature_record["observation_id"] != gold_record["observation_id"]:
            raise SystemExit("feature/gold observation order mismatch")
        if "label" in feature_record or "file_sha256" in feature_record:
            raise SystemExit("feature record contains gold leakage")
        vectors[index] = vectorizer.process_raw_features(feature_record["features"])
        labels[index] = int(gold_record["label"])
        weeks[index] = int(gold_record["week_id"])
        observation_ids.append(str(feature_record["observation_id"]))
    return {
        "vectors": vectors,
        "labels": labels,
        "weeks": weeks,
        "observation_ids": np.asarray(observation_ids),
    }


class EmberElfFeatureVectorizer:
    """Vectorize EMBER2024 ELF common features without importing PE dependencies."""

    common_dim = 696
    official_declared_dim = 2568
    dim = 2568

    def __init__(self, np: Any) -> None:
        self.np = np
        self.string_count_keys = _load_official_string_count_keys()
        if len(self.string_count_keys) != 77:
            raise SystemExit(
                "unexpected official string-count feature count: "
                f"{len(self.string_count_keys)}"
            )
        self.string_count_index = {
            key: index for index, key in enumerate(self.string_count_keys)
        }

    def process_raw_features(self, raw: dict[str, Any]) -> Any:
        general = raw["general"]
        strings = raw["strings"]
        general_vector = self.np.asarray(
            [
                float(general["size"]),
                float(general["entropy"]),
                float(general["is_pe"]),
                *[float(value) for value in general["start_bytes"]],
            ],
            dtype=self.np.float32,
        )
        if len(general_vector) != 7:
            raise SystemExit("unexpected general feature dimension")

        byte_histogram = _normalized_vector(
            raw["histogram"],
            expected_length=256,
            np=self.np,
        )
        byte_entropy_histogram = _normalized_vector(
            raw["byteentropy"],
            expected_length=256,
            np=self.np,
        )
        printable_distribution = self.np.asarray(
            strings["printabledist"],
            dtype=self.np.float32,
        )
        if len(printable_distribution) != 96:
            raise SystemExit("unexpected printable distribution dimension")
        printables = float(strings["printables"])
        if printables > 0:
            printable_distribution = printable_distribution / printables

        string_counts = self.np.zeros(
            len(self.string_count_keys),
            dtype=self.np.float32,
        )
        for key, value in strings["string_counts"].items():
            index = self.string_count_index.get(str(key))
            if index is not None:
                string_counts[index] = float(value)
        strings_vector = self.np.hstack(
            [
                float(strings["numstrings"]),
                float(strings["avlength"]),
                printables,
                printable_distribution,
                float(strings["entropy"]),
                string_counts,
            ]
        ).astype(self.np.float32, copy=False)
        if len(strings_vector) != 177:
            raise SystemExit("unexpected string feature dimension")

        common = self.np.hstack(
            [
                general_vector,
                byte_histogram,
                byte_entropy_histogram,
                strings_vector,
            ]
        ).astype(self.np.float32, copy=False)
        if len(common) != self.common_dim:
            raise SystemExit("unexpected common feature dimension")
        return self.np.pad(common, (0, self.dim - self.common_dim))


def _normalized_vector(values: list[int], *, expected_length: int, np: Any) -> Any:
    vector = np.asarray(values, dtype=np.float32)
    if len(vector) != expected_length:
        raise SystemExit("unexpected histogram feature dimension")
    total = float(vector.sum())
    if total > 0:
        vector = vector / total
    return vector


def _load_official_string_count_keys() -> list[str]:
    distribution = importlib.metadata.distribution("thrember")
    feature_source = Path(distribution.locate_file("thrember/features.py"))
    tree = ast.parse(feature_source.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "StringExtractor":
            continue
        for statement in ast.walk(node):
            if not isinstance(statement, ast.Assign):
                continue
            if not any(
                (
                    isinstance(target, ast.Name)
                    and target.id == "_regexes"
                    or isinstance(target, ast.Attribute)
                    and target.attr == "_regexes"
                )
                for target in statement.targets
            ):
                continue
            if not isinstance(statement.value, ast.Dict):
                break
            keys = [
                key.value
                for key in statement.value.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            ]
            return sorted(set(keys))
    raise SystemExit("could not read official StringExtractor keys")


def _prediction_records(
    observation_ids: Any,
    scores: list[float],
) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": "aegislm.malware-classifier-prediction.v1",
            "observation_id": str(record_id),
            "score": float(score),
        }
        for record_id, score in zip(observation_ids.tolist(), scores)
    ]


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
