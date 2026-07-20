#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${HF_TOKEN:?HF_TOKEN must already be exported in the shell}"
: "${WANDB_API_KEY:?WANDB_API_KEY must already be exported in the shell}"

umask 077
awk '
  /^HF_TOKEN=/ { print "HF_TOKEN=" ENVIRON["HF_TOKEN"]; next }
  /^WANDB_API_KEY=/ { print "WANDB_API_KEY=" ENVIRON["WANDB_API_KEY"]; next }
  { print }
' .env.example > .env
chmod 600 .env

echo "Created .env with mode $(stat -c %a .env); secret values were not printed."
