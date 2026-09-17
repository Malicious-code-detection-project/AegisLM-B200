import pytest

from scripts.preflight_phase_f_binary_f7 import build_f7_preflight


def _queue(pair_count: int) -> dict[str, object]:
    return {
        "seed": 20260728,
        "candidates": [
            {
                "pair_id": f"pair-{index}",
                "queue": "primary",
                "queue_rank": index + 1,
            }
            for index in range(pair_count)
        ],
    }


def _review(decisions: dict[str, bool]) -> dict[str, object]:
    return {"pair_decisions": decisions}


def test_f7_preflight_builds_unreviewed_deterministic_pilot() -> None:
    preflight, pilot = build_f7_preflight(
        _queue(20),
        [_review({"pair-0": True, "pair-1": False, "pair-2": True})],
        required_dataset_pairs=5,
        pilot_pairs=4,
    )

    assert preflight["accepted_pair_count"] == 2
    assert preflight["remaining_structural_pair_count"] == 17
    assert preflight["decision"] == "pilot_authorized"
    assert [row["pair_id"] for row in pilot["candidates"]] == [
        "pair-3",
        "pair-4",
        "pair-5",
        "pair-6",
    ]


def test_f7_preflight_blocks_when_conservative_supply_is_insufficient() -> None:
    preflight, _ = build_f7_preflight(
        _queue(10),
        [_review({"pair-0": True, "pair-1": False, "pair-2": False})],
        required_dataset_pairs=9,
        pilot_pairs=2,
    )

    assert preflight["supply_gate_pass"] is False
    assert preflight["decision"] == "supply_blocked"


def test_f7_preflight_rejects_duplicate_reviewed_pair() -> None:
    with pytest.raises(ValueError, match="duplicate reviewed pair"):
        build_f7_preflight(
            _queue(10),
            [_review({"pair-0": True}), _review({"pair-0": True})],
            required_dataset_pairs=2,
            pilot_pairs=2,
        )
