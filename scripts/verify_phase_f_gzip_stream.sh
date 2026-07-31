#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 INPUT_GZIP OUTPUT_JSON" >&2
  exit 2
fi

input_gzip="$1"
output_json="$2"

if [[ ! -f "$input_gzip" ]]; then
  echo "input gzip is not a regular file: $input_gzip" >&2
  exit 2
fi
if [[ -e "$output_json" ]]; then
  echo "output report already exists: $output_json" >&2
  exit 2
fi

started_epoch="$(date +%s)"
started_at="$(date --utc --iso-8601=seconds)"
input_bytes="$(stat --format=%s "$input_gzip")"
input_path="$(realpath "$input_gzip")"

set +e
gzip_error="$(gzip --test -- "$input_gzip" 2>&1)"
gzip_status="$?"
set -e

completed_epoch="$(date +%s)"
completed_at="$(date --utc --iso-8601=seconds)"
elapsed_seconds="$((completed_epoch - started_epoch))"
if [[ "$gzip_status" -eq 0 ]]; then
  decision="gzip_stream_pass"
  stream_valid=true
else
  decision="gzip_stream_fail"
  stream_valid=false
fi

output_dir="$(dirname "$output_json")"
mkdir -p "$output_dir"
temporary_report="${output_json}.tmp"
if [[ -e "$temporary_report" ]]; then
  echo "temporary report already exists: $temporary_report" >&2
  exit 2
fi

jq -n \
  --arg schema_version "aegislm.phase-f-gzip-stream-audit.v1" \
  --arg input_path "$input_path" \
  --argjson input_bytes "$input_bytes" \
  --arg started_at "$started_at" \
  --arg completed_at "$completed_at" \
  --argjson elapsed_seconds "$elapsed_seconds" \
  --arg decision "$decision" \
  --argjson stream_valid "$stream_valid" \
  --arg gzip_error "$gzip_error" \
  '{
    schema_version: $schema_version,
    input: {
      path: $input_path,
      bytes: $input_bytes
    },
    started_at: $started_at,
    completed_at: $completed_at,
    elapsed_seconds: $elapsed_seconds,
    gzip_error: $gzip_error,
    checks: {
      gzip_stream_crc_valid: $stream_valid
    },
    decision: $decision,
    approved_for_schema_audit: $stream_valid,
    approved_for_processing: false,
    approved_for_training: false,
    safety: {
      decompressed_output_write_count: 0,
      sql_execution_count: 0,
      object_execution_count: 0
    }
  }' > "$temporary_report"
mv "$temporary_report" "$output_json"

if [[ "$gzip_status" -ne 0 ]]; then
  echo "gzip stream validation failed: $gzip_error" >&2
  exit "$gzip_status"
fi

echo "Phase F gzip stream audit: decision=$decision, bytes=$input_bytes, elapsed_seconds=$elapsed_seconds"
