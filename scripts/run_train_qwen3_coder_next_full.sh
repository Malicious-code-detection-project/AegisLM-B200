#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

exec bash scripts/run_observed_llamafactory_train.sh "$@"
