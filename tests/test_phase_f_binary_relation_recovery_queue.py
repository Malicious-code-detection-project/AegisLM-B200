from scripts.build_phase_f_binary_relation_recovery_queue import (
    build_recovery_queue,
)


def test_relation_recovery_queue_preserves_order_and_excludes_reviewed() -> None:
    source = {
        "profile": "binary",
        "seed": 20260728,
        "source_split": "train",
        "policy": {"ordering": "frozen"},
        "metrics": {"primary_pair_count": 5},
        "structural_rejections": [],
        "candidates": [
            {"pair_id": pair_id, "queue_rank": index}
            for index, pair_id in enumerate(("a", "b", "c", "d", "e"), start=1)
        ],
    }
    exclusions = [
        {
            "accepted_canary_pair_ids": ["a"],
            "failed_canary_pair_ids": ["b"],
            "candidates": [{"pair_id": "c"}],
        }
    ]

    result = build_recovery_queue(
        source,
        exclusions,
        batch_pairs=1,
        round_id="r3",
    )

    assert [row["pair_id"] for row in result["candidates"]] == ["d"]
    assert result["excluded_pair_count"] == 3
    assert result["remaining_pair_count_after_selection"] == 1
