from scripts.build_phase_f_binary_b0_replacement_queue import (
    build_replacement_queue,
)


def test_replacement_queue_promotes_reserve_in_rank_order() -> None:
    queue = {
        "profile": "test",
        "seed": 7,
        "candidates": [
            {"pair_id": "r2", "queue": "reserve", "queue_rank": 2},
            {"pair_id": "r1", "queue": "reserve", "queue_rank": 1},
        ],
    }
    review = {
        "scope": "canary",
        "pair_decisions": {"failed": False, "passed": True},
    }

    result = build_replacement_queue(queue, review)

    assert result["accepted_pair_ids"] == ["passed"]
    assert result["failed_pair_ids"] == ["failed"]
    assert [row["pair_id"] for row in result["candidates"]] == ["r1"]
    assert result["candidates"][0]["replaces_failed_pair_id"] == "failed"


def test_replacement_queue_skips_prior_replacements() -> None:
    queue = {
        "profile": "test",
        "seed": 7,
        "candidates": [
            {"pair_id": "r1", "queue": "reserve", "queue_rank": 1},
            {"pair_id": "r2", "queue": "reserve", "queue_rank": 2},
        ],
    }
    review = {"scope": "r1", "pair_decisions": {"failed": False}}

    result = build_replacement_queue(
        queue,
        review,
        excluded_pair_ids=frozenset({"r1"}),
    )

    assert [row["pair_id"] for row in result["candidates"]] == ["r2"]
