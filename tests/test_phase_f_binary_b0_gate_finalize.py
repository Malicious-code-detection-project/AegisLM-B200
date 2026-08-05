import pytest

from scripts.finalize_phase_f_binary_b0_gate import finalize_b0_gate


def _summary(
    scope: str,
    decisions: dict[str, bool],
) -> dict[str, object]:
    return {
        "scope": scope,
        "variant_count": len(decisions) * 4,
        "pair_decisions": decisions,
    }


def test_finalize_b0_gate_requires_exact_accepted_supply() -> None:
    result = finalize_b0_gate(
        [
            _summary("canary", {"pair-a": True, "pair-b": False}),
            _summary("replacement", {"pair-c": True}),
        ],
        required_accepted_pairs=2,
    )

    assert result["reviewed_pair_count"] == 3
    assert result["accepted_pair_ids"] == ["pair-a", "pair-c"]
    assert result["rejected_pair_ids"] == ["pair-b"]
    assert result["selected_variant_count"] == 8
    assert result["target_preservation"]["rate"] == 1.0
    assert result["gate_pass"] is True


def test_finalize_b0_gate_fails_on_insufficient_supply() -> None:
    result = finalize_b0_gate(
        [_summary("canary", {"pair-a": True})],
        required_accepted_pairs=2,
    )

    assert result["gate_pass"] is False
    assert result["decision"] == "insufficient_accepted_supply"


def test_finalize_b0_gate_selects_exact_supply_and_preserves_verified_reserve() -> None:
    result = finalize_b0_gate(
        [
            _summary(
                "scale",
                {
                    "pair-a": True,
                    "pair-b": True,
                    "pair-c": True,
                    "pair-d": False,
                },
            )
        ],
        required_accepted_pairs=2,
        selection_order=["pair-c", "pair-d", "pair-a", "pair-b"],
    )

    assert result["gate_pass"] is True
    assert result["qualified_pair_count"] == 3
    assert result["accepted_pair_ids"] == ["pair-c", "pair-a"]
    assert result["qualified_reserve_pair_ids"] == ["pair-b"]
    assert result["qualified_reserve_pair_count"] == 1


def test_finalize_b0_gate_rejects_incomplete_selection_order() -> None:
    with pytest.raises(ValueError, match="qualified pair missing"):
        finalize_b0_gate(
            [_summary("scale", {"pair-a": True, "pair-b": True})],
            required_accepted_pairs=1,
            selection_order=["pair-a"],
        )


def test_finalize_b0_gate_rejects_duplicate_pair_reviews() -> None:
    with pytest.raises(ValueError, match="duplicate reviewed pair"):
        finalize_b0_gate(
            [
                _summary("first", {"pair-a": False}),
                _summary("second", {"pair-a": True}),
            ],
            required_accepted_pairs=1,
        )
