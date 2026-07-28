"""Dataset formatting and validation helpers."""

from aegislm.datasets.validation import (
    ContaminationError,
    DatasetValidationError,
    SafetyPolicyViolationError,
    check_contamination,
    validate_record,
    validate_safety_policy,
)
from aegislm.datasets.formatting import (
    SFTFormattingError,
    SFTSafetyLevelError,
    SFTSplitError,
    SFTValidationError,
    check_sft_eligibility,
    format_sft_dataset,
    format_sft_record,
)
from aegislm.datasets.binary import (
    BINARY_SYSTEM_PROMPT,
    BinaryRecordValidationError,
    format_binary_prompt,
    validate_binary_output,
    validate_binary_record,
)
from aegislm.datasets.phase_f import (
    CATALOG_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    PHASE_F_BUILD_SEED,
    PHASE_F_SOURCE_PROFILE,
    PhaseFDatasetError,
    assert_no_model_visible_leakage,
    build_raw_catalog,
    build_source_profile,
    materialize_source_record,
)

__all__ = [
    "validate_record",
    "validate_safety_policy",
    "check_contamination",
    "DatasetValidationError",
    "SafetyPolicyViolationError",
    "ContaminationError",
    "format_sft_record",
    "format_sft_dataset",
    "check_sft_eligibility",
    "SFTFormattingError",
    "SFTValidationError",
    "SFTSplitError",
    "SFTSafetyLevelError",
    "BINARY_SYSTEM_PROMPT",
    "BinaryRecordValidationError",
    "validate_binary_record",
    "validate_binary_output",
    "format_binary_prompt",
    "CATALOG_SCHEMA_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "PHASE_F_BUILD_SEED",
    "PHASE_F_SOURCE_PROFILE",
    "PhaseFDatasetError",
    "assert_no_model_visible_leakage",
    "build_raw_catalog",
    "build_source_profile",
    "materialize_source_record",
]
