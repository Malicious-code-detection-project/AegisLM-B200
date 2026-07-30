import pytest

from scripts.build_phase_f_binary_b0_batch_queue import build_batch_queue


def test_batch_queue_uses_only_unreviewed_candidates() -> None:
    queue = {
        "profile": "test",
        "seed": 7,
        "candidates": [
            {"pair_id": "accepted", "queue": "primary", "queue_rank": 1},
            {"pair_id": "failed", "queue": "primary", "queue_rank": 2},
            {"pair_id": "next", "queue": "primary", "queue_rank": 3},
            {"pair_id": "reserve", "queue": "reserve", "queue_rank": 1},
        ],
    }
    reviews = [
        {"pair_decisions": {"accepted": True, "failed": False}},
    ]

    result = build_batch_queue(
        queue,
        reviews,
        required_accepted_canary_pairs=1,
        batch_pairs=2,
    )

    assert result["accepted_canary_pair_ids"] == ["accepted"]
    assert result["failed_canary_pair_ids"] == ["failed"]
    assert [row["pair_id"] for row in result["candidates"]] == [
        "next",
        "reserve",
    ]


def test_batch_queue_rejects_conflicting_reviews() -> None:
    queue = {
        "profile": "test",
        "seed": 7,
        "candidates": [{"pair_id": "a", "queue": "primary", "queue_rank": 1}],
    }
    with pytest.raises(ValueError, match="conflicting pair decision"):
        build_batch_queue(
            queue,
            [
                {"pair_decisions": {"a": True}},
                {"pair_decisions": {"a": False}},
            ],
            required_accepted_canary_pairs=1,
            batch_pairs=0,
        )
